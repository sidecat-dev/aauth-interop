package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type fleetConfig struct {
	RecordsAddr          string `json:"records_addr"`
	RecordsCertPEM       string `json:"records_cert_pem"`
	RustFedRecordsAddr   string `json:"rust_fed_records_addr"`
	RustFedRecordsPEM    string `json:"rust_fed_records_cert_pem"`
	RustFedHeldAddr      string `json:"rust_fed_held_addr"`
	RustFedHeldPEM       string `json:"rust_fed_held_cert_pem"`
	QAControlAddr        string `json:"qa_control_addr"`
	QAControlCertPEM     string `json:"qa_control_cert_pem"`
	InitialNow           int64  `json:"initial_now"`
}

type runQARequest struct {
	GoAPAddr              string `json:"go_ap_addr"`
	GoAPCertHex           string `json:"go_ap_cert_hex"`
	GoPSAddr              string `json:"go_ps_addr"`
	GoPSCertHex           string `json:"go_ps_cert_hex"`
	FedPSAddr             string `json:"fed_ps_addr"`
	FedPSCertHex          string `json:"fed_ps_cert_hex"`
	FedASAddr             string `json:"fed_as_addr"`
	FedASCertHex          string `json:"fed_as_cert_hex"`
	FedRecordsAddr        string `json:"fed_records_addr"`
	FedRecordsCertHex     string `json:"fed_records_cert_hex"`
	GoAgentSeedHex        string `json:"go_agent_seed_hex"`
	GoAgentToken          string `json:"go_agent_token"`
	FedAgentToken         string `json:"fed_agent_token"`
	FedASAlternateSeedHex string `json:"fed_as_alternate_seed_hex"`
	GoEventsAPAddr        string `json:"go_events_ap_addr"`
	GoEventsAPCertHex     string `json:"go_events_ap_cert_hex"`
	GoEventsResAddr       string `json:"go_events_res_addr"`
	GoEventsResCertHex    string `json:"go_events_res_cert_hex"`
	GoRogueResAddr        string `json:"go_rogue_res_addr"`
	GoRogueResCertHex     string `json:"go_rogue_res_cert_hex"`
}

type fleetCounts struct {
	DirectPSFetchedDoc       bool `json:"direct_ps_fetched_doc"`
	DirectPSIssuances        int  `json:"direct_ps_issuances"`
	PSClassConsents          int  `json:"ps_class_consents"`
	PSProposalConsents       int  `json:"ps_proposal_consents"`
	PSProposalDenials        int  `json:"ps_proposal_denials"`
	ASClassAuthorizations    int  `json:"as_class_authorizations"`
	ASProposalAuthorizations int  `json:"as_proposal_authorizations"`
	ASIssuances              int  `json:"as_issuances"`
	GoFedClassReads          int  `json:"go_fed_class_reads"`
	GoFedRetryRuns           int  `json:"go_fed_retry_runs"`
	GoFedHeldRuns            int  `json:"go_fed_held_runs"`
	GoFedOtherRuns           int  `json:"go_fed_other_runs"`
}

type memoryTokenStore struct {
	mu                    sync.Mutex
	records               map[string]personserver.PersonTokenRecord
	presentations         map[string][]string
	presentationRetention map[string]time.Time
	failPresentErr        error
}

func (s *memoryTokenStore) Commit(_ context.Context, r personserver.PersonTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]personserver.PersonTokenRecord)
	}
	s.records[r.PersonServer+"|"+r.JTI] = r
	return nil
}

func (s *memoryTokenStore) Load(_ context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[issuer+"|"+jti]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return r, nil
}

func (s *memoryTokenStore) RecordPersonTokenPresentation(_ context.Context, p personserver.PersonTokenPresentation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failPresentErr != nil {
		return s.failPresentErr
	}
	if s.presentations == nil {
		s.presentations = make(map[string][]string)
	}
	if s.presentationRetention == nil {
		s.presentationRetention = make(map[string]time.Time)
	}
	key := p.PersonServer + "|" + p.JTI
	if !slices.Contains(s.presentations[key], p.AccessServer) {
		s.presentations[key] = append(s.presentations[key], p.AccessServer)
	}
	s.presentationRetention[key] = p.RetainUntil
	return nil
}

func (s *memoryTokenStore) LoadPersonTokenPresentations(_ context.Context, personServer, jti string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.presentations[personServer+"|"+jti]), nil
}

type memoryIssuanceStore struct {
	mu      sync.Mutex
	records []r3.IssuanceRecord
}

func (s *memoryIssuanceStore) Commit(_ context.Context, r r3.IssuanceRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}

func (s *memoryIssuanceStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

type memoryDocumentStore struct {
	mu      sync.Mutex
	records map[string]resource.R3DocumentRecord
}

func (s *memoryDocumentStore) Commit(_ context.Context, record resource.R3DocumentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]resource.R3DocumentRecord)
	}
	key := record.Reference.URI()
	if existing, ok := s.records[key]; ok {
		if !bytes.Equal(existing.ExactJSON, record.ExactJSON) ||
			existing.PersonServer != record.PersonServer ||
			existing.AuthTokenIssuer != record.AuthTokenIssuer ||
			existing.AuthTokenIssuerDocument != record.AuthTokenIssuerDocument {
			return resource.ErrR3DocumentConflict
		}
		return nil
	}
	s.records[key] = record.Clone()
	return nil
}

func (s *memoryDocumentStore) Load(_ context.Context, uri string) (resource.R3DocumentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[uri]
	if !ok {
		return resource.R3DocumentRecord{}, resource.ErrR3DocumentNotFound
	}
	return record.Clone(), nil
}

type memoryProposalStore struct {
	mu      sync.Mutex
	records map[string]resource.R3ProposalRecord
}

func (s *memoryProposalStore) Commit(_ context.Context, record resource.R3ProposalRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]resource.R3ProposalRecord)
	}
	key := record.Reference.URI()
	if _, ok := s.records[key]; ok {
		return resource.ErrR3ProposalConflict
	}
	cloned := record
	cloned.ExactJSON = append([]byte(nil), record.ExactJSON...)
	s.records[key] = cloned
	return nil
}

func (s *memoryProposalStore) Load(_ context.Context, uri string) (resource.R3ProposalRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[uri]
	if !ok {
		return resource.R3ProposalRecord{}, resource.ErrR3ProposalNotFound
	}
	record.ExactJSON = append([]byte(nil), record.ExactJSON...)
	return record, nil
}

type memoryRetryEntry struct {
	invocation resource.R3RetryInvocation
	state      string
	token      resource.R3RetryAuthToken
	fence      string
	response   resource.HeldResponse
}

type memoryRetryStore struct {
	mu      sync.Mutex
	records map[string]*memoryRetryEntry
}

func (s *memoryRetryStore) Prepare(_ context.Context, invocation resource.R3RetryInvocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]*memoryRetryEntry)
	}
	key := invocation.Reference.URI()
	if _, ok := s.records[key]; ok {
		return resource.ErrR3RetryConflict
	}
	cloned := invocation
	cloned.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	cloned.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	s.records[key] = &memoryRetryEntry{invocation: cloned, state: "pending"}
	return nil
}

func (s *memoryRetryStore) Load(_ context.Context, reference r3.Reference) (resource.R3RetryInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[reference.URI()]
	if !ok {
		return resource.R3RetryInvocation{}, resource.ErrR3RetryNotFound
	}
	invocation := entry.invocation
	invocation.ExactProposal = append([]byte(nil), invocation.ExactProposal...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	return invocation, nil
}

func (s *memoryRetryStore) Claim(_ context.Context, reference r3.Reference, token resource.R3RetryAuthToken) (resource.R3RetryClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[reference.URI()]
	if !ok {
		return resource.R3RetryClaim{}, resource.ErrR3RetryNotFound
	}
	switch entry.state {
	case "pending":
		if !token.PresentedAt.Before(entry.invocation.CompletionUntil) {
			return resource.R3RetryClaim{}, resource.ErrR3RetryExpired
		}
		entry.state = "executing"
		entry.token = token
		entry.fence = "fence-1"
		return resource.NewHeldExecution(resource.HeldExecution{
			InvocationID: reference.URI(),
			Fence:        entry.fence,
		}), nil
	case "executing":
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	case "completed":
		if entry.token.SHA256 != token.SHA256 {
			return resource.R3RetryClaim{}, resource.ErrR3RetryTokenMismatch
		}
		return resource.NewHeldReplay(entry.response), nil
	case "unresolved":
		return resource.R3RetryClaim{}, resource.ErrR3RetryUnresolved
	default:
		return resource.R3RetryClaim{}, resource.ErrR3RetryConflict
	}
}

func (s *memoryRetryStore) Retain(_ context.Context, execution resource.R3RetryExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.records[execution.InvocationID]
	if !ok || entry.state != "executing" || entry.fence != execution.Fence {
		return resource.HeldResponse{}, resource.ErrR3RetryCompletionStale
	}
	entry.response = resource.HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       append([]byte(nil), response.Body...),
		Trailer:    response.Trailer.Clone(),
	}
	entry.state = "completed"
	return resource.HeldResponse{
		StatusCode: entry.response.StatusCode,
		Header:     entry.response.Header.Clone(),
		Body:       append([]byte(nil), entry.response.Body...),
		Trailer:    entry.response.Trailer.Clone(),
	}, nil
}

const heldPendingID = "held-call-0123456789abcdef"

type memoryHeldStore struct {
	mu         sync.Mutex
	invocation resource.HeldInvocation
	state      string
	token      resource.HeldAuthToken
	response   resource.HeldResponse
}

func (s *memoryHeldStore) Create(_ context.Context, invocation resource.HeldInvocation) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invocation = cloneHeldInvocation(invocation)
	s.state = "pending"
	return heldPendingID, nil
}

func (s *memoryHeldStore) Load(_ context.Context, id string) (resource.HeldInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != heldPendingID || s.state == "" {
		return resource.HeldInvocation{}, resource.ErrHeldInvocationNotFound
	}
	return cloneHeldInvocation(s.invocation), nil
}

func (s *memoryHeldStore) Claim(_ context.Context, id string, token resource.HeldAuthToken) (resource.HeldClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != heldPendingID || s.state == "" {
		return resource.HeldClaim{}, resource.ErrHeldInvocationNotFound
	}
	switch s.state {
	case "pending":
		if !token.PresentedAt.Before(s.invocation.CompletionUntil) {
			s.state = "expired"
			return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
		}
		s.state = "executing"
		s.token = token
		return resource.NewHeldExecution(resource.HeldExecution{
			InvocationID: heldPendingID,
			Fence:        "held-fence-1",
		}), nil
	case "executing":
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	case "complete":
		if s.token.SHA256 != token.SHA256 {
			return resource.HeldClaim{}, resource.ErrHeldAuthTokenMismatch
		}
		return resource.NewHeldReplay(s.response), nil
	case "expired":
		return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
	default:
		return resource.HeldClaim{}, resource.ErrHeldExecutionUnresolved
	}
}

func (s *memoryHeldStore) Retain(_ context.Context, execution resource.HeldExecution, response resource.HeldResponse) (resource.HeldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != "executing" || execution != (resource.HeldExecution{InvocationID: heldPendingID, Fence: "held-fence-1"}) {
		return resource.HeldResponse{}, resource.ErrHeldCompletionStale
	}
	s.response = resource.HeldResponse{
		StatusCode: response.StatusCode,
		Header:     response.Header.Clone(),
		Body:       append([]byte(nil), response.Body...),
		Trailer:    response.Trailer.Clone(),
	}
	s.state = "complete"
	return resource.HeldResponse{
		StatusCode: s.response.StatusCode,
		Header:     s.response.Header.Clone(),
		Body:       append([]byte(nil), s.response.Body...),
		Trailer:    s.response.Trailer.Clone(),
	}, nil
}

func cloneHeldInvocation(invocation resource.HeldInvocation) resource.HeldInvocation {
	invocation.Header = invocation.Header.Clone()
	invocation.Body = append([]byte(nil), invocation.Body...)
	invocation.RequiredScopes = append([]string(nil), invocation.RequiredScopes...)
	if invocation.R3PerCall != nil {
		cloned := *invocation.R3PerCall
		cloned.ExactProposal = append([]byte(nil), invocation.R3PerCall.ExactProposal...)
		invocation.R3PerCall = &cloned
	}
	return invocation
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func bufferedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, vv := range rec.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		body := rec.Body.Bytes()
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body)
	})
}

func accessJWKSWithAlternate(next http.Handler, alternate jose.JWK) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/.well-known/jwks.json" {
			next.ServeHTTP(response, request)
			return
		}
		recorded := httptest.NewRecorder()
		next.ServeHTTP(recorded, request)
		if recorded.Code != http.StatusOK {
			for name, values := range recorded.Header() {
				for _, value := range values {
					response.Header().Add(name, value)
				}
			}
			response.WriteHeader(recorded.Code)
			_, _ = response.Write(recorded.Body.Bytes())
			return
		}
		var document struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &document); err != nil || len(document.Keys) != 1 {
			http.Error(response, "qa fleet: access JWKS", http.StatusInternalServerError)
			return
		}
		encoded, err := json.Marshal(alternate)
		if err != nil {
			http.Error(response, "qa fleet: alternate access key", http.StatusInternalServerError)
			return
		}
		document.Keys = append(document.Keys, encoded)
		for name, values := range recorded.Header() {
			if strings.EqualFold(name, "Content-Length") {
				continue
			}
			for _, value := range values {
				response.Header().Add(name, value)
			}
		}
		response.WriteHeader(http.StatusOK)
		encodedDocument, err := json.Marshal(document)
		if err != nil {
			return
		}
		_, _ = response.Write(encodedDocument)
	})
}

func startTLSServer(host string, handler http.Handler) (*httptest.Server, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	srv := httptest.NewUnstartedServer(bufferedHandler(handler))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
	}
	srv.StartTLS()
	return srv, der, nil
}

func must(err error, step string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
		os.Exit(1)
	}
}

const (
	goAPIssuer           = "https://go-ap.example"
	goPSIssuer           = "https://go-ps.example"
	fedPSIssuer          = "https://fed-ps.example"
	fedASIssuer          = "https://fed-as.example"
	fedResourceIssuer    = "https://fed-records.example"
	rustFedRecordsIssuer = "https://rust-fed-records.example"
	rustFedHeldIssuer    = "https://rust-fed-held.example"
	goEventsAPIssuer     = "https://go-events-ap.example"
	goEventsResIssuer    = "https://go-events-res.example"
	goRogueResIssuer     = "https://go-rogue-res.example"
)

const validGoAsyncAPIDoc = `{
  "asyncapi": "3.0.0",
  "info": {"title": "Go QA Events Service", "version": "1.0.0"},
  "channels": {
    "waitlist": {
      "address": "/events/subscribe",
      "messages": {"slotAvailable": {"$ref": "#/components/messages/SlotAvailable"}}
    }
  },
  "operations": {
    "subscribeWaitlist": {
      "action": "receive",
      "channel": {"$ref": "#/channels/waitlist"},
      "security": [{"$ref": "#/components/securitySchemes/aauth_subscribe"}]
    }
  },
  "components": {
    "messages": {
      "SlotAvailable": {
        "contentType": "application/json",
        "payload": {
          "type": "object",
          "properties": {"event_type": {"type": "string"}, "slot": {"type": "string"}},
          "required": ["event_type"]
        }
      }
    },
    "securitySchemes": {
      "aauth_subscribe": {
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token as Signature-Key JWT"
      }
    }
  }
}`

type goProviderEventStore struct {
	mu            sync.Mutex
	subscriptions map[string]agentprovider.EventSubscription
	deliveries    map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acceptances   map[events.DeliveryFingerprint]agentprovider.EventAcceptance
	order         map[string][]events.DeliveryFingerprint
	uses          map[string]int64
}

func newGoProviderEventStore() *goProviderEventStore {
	return &goProviderEventStore{
		subscriptions: make(map[string]agentprovider.EventSubscription),
		deliveries:    make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acceptances:   make(map[events.DeliveryFingerprint]agentprovider.EventAcceptance),
		order:         make(map[string][]events.DeliveryFingerprint),
		uses:          make(map[string]int64),
	}
}

func (s *goProviderEventStore) CommitSubscription(_ context.Context, record agentprovider.EventSubscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if retained, ok := s.subscriptions[record.EventID]; ok {
		if retained.Agent == record.Agent && retained.Resource == record.Resource &&
			retained.MaxUses == record.MaxUses && retained.TokenSHA256 == record.TokenSHA256 {
			return nil
		}
		return agentprovider.ErrEventDeliveryConflict
	}
	s.subscriptions[record.EventID] = record
	return nil
}

func (s *goProviderEventStore) AcceptEvent(_ context.Context, delivery agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	subscription, ok := s.subscriptions[delivery.EventID]
	if !ok {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventSubscriptionNotFound
	}
	if subscription.Resource != delivery.Resource {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventResourceMismatch
	}
	if subscription.Agent != delivery.Agent {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventAgentMismatch
	}
	if delivery.Fingerprint != events.Fingerprint(delivery.Token, delivery.ContentType, delivery.Payload) {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
	}
	if retained, ok := s.deliveries[delivery.Fingerprint]; ok {
		if retained.TokenSHA256 != delivery.TokenSHA256 || retained.PayloadSHA256 != delivery.PayloadSHA256 ||
			retained.ContentType != delivery.ContentType {
			return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
		}
		return s.acceptances[delivery.Fingerprint], nil
	}
	if subscription.MaxUses > 0 && s.uses[delivery.EventID] >= subscription.MaxUses {
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventUsesExceeded
	}
	delivery.Payload = append([]byte(nil), delivery.Payload...)
	s.deliveries[delivery.Fingerprint] = delivery
	s.order[delivery.EventID] = append(s.order[delivery.EventID], delivery.Fingerprint)
	s.uses[delivery.EventID]++
	remaining := int64(0)
	if subscription.MaxUses > 0 {
		remaining = subscription.MaxUses - s.uses[delivery.EventID]
	}
	accepted := agentprovider.EventAcceptance{
		MaximumUses:   subscription.MaxUses,
		RemainingUses: remaining,
	}
	s.acceptances[delivery.Fingerprint] = accepted
	return accepted, nil
}

func (s *goProviderEventStore) deliveriesFor(eventID string) ([]agentprovider.EventDelivery, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fps := s.order[eventID]
	out := make([]agentprovider.EventDelivery, 0, len(fps))
	for _, fp := range fps {
		if d, ok := s.deliveries[fp]; ok {
			d.Payload = append([]byte(nil), d.Payload...)
			out = append(out, d)
		}
	}
	return out, s.uses[eventID]
}

type goResourceEventStore struct {
	mu      sync.Mutex
	records map[string]resource.EventSubscription
	tickets map[string]resource.ProtectedSubscriptionTicket
}

func newGoResourceEventStore() *goResourceEventStore {
	return &goResourceEventStore{
		records: make(map[string]resource.EventSubscription),
		tickets: make(map[string]resource.ProtectedSubscriptionTicket),
	}
}

func (s *goResourceEventStore) CreateProtectedSubscriptionTicket(_ context.Context, ticket resource.ProtectedSubscriptionTicket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tickets[ticket.ID]; exists {
		return resource.ErrProtectedSubscriptionConflict
	}
	ticket.Context = append([]byte(nil), ticket.Context...)
	s.tickets[ticket.ID] = ticket
	return nil
}

func (s *goResourceEventStore) LoadProtectedSubscriptionTicket(_ context.Context, id string, keyThumbprint string, at time.Time) (resource.ProtectedSubscriptionTicket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, exists := s.tickets[id]
	if !exists || ticket.KeyThumbprint != keyThumbprint {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionNotFound
	}
	if !at.Before(ticket.ExpiresAt) && ticket.UsedAt.IsZero() {
		return resource.ProtectedSubscriptionTicket{}, resource.ErrProtectedSubscriptionExpired
	}
	ticket.Context = append([]byte(nil), ticket.Context...)
	return ticket, nil
}

func (s *goResourceEventStore) CommitProtectedSubscription(_ context.Context, expected resource.ProtectedSubscriptionTicket, candidate resource.EventSubscription) (resource.EventSubscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ticket, exists := s.tickets[expected.ID]
	if !exists || !reflect.DeepEqual(ticket, expected) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	key := candidate.AgentProvider + "\x00" + candidate.EventID
	if retained, exists := s.records[key]; exists {
		if retained.RegistrationSHA256 == candidate.RegistrationSHA256 &&
			ticket.RegistrationSHA256 == candidate.RegistrationSHA256 {
			retained.Parameters = append([]byte(nil), retained.Parameters...)
			return retained, nil
		}
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	if !ticket.UsedAt.IsZero() || ticket.RegistrationSHA256 != [32]byte{} ||
		!candidate.RegisteredAt.Before(ticket.ExpiresAt) {
		return resource.EventSubscription{}, resource.ErrProtectedSubscriptionConflict
	}
	candidate.Parameters = append([]byte(nil), candidate.Parameters...)
	s.records[key] = candidate
	ticket.UsedAt = candidate.RegisteredAt
	ticket.RegistrationSHA256 = candidate.RegistrationSHA256
	ticket.Context = append([]byte(nil), ticket.Context...)
	s.tickets[ticket.ID] = ticket
	return candidate, nil
}

func (s *goResourceEventStore) Commit(_ context.Context, record resource.EventSubscription) (resource.EventSubscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.AgentProvider + "\x00" + record.EventID
	if retained, ok := s.records[key]; ok {
		if retained.RegistrationSHA256 == record.RegistrationSHA256 {
			retained.Parameters = append([]byte(nil), retained.Parameters...)
			return retained, nil
		}
		return resource.EventSubscription{}, resource.ErrEventSubscriptionConflict
	}
	record.Parameters = append([]byte(nil), record.Parameters...)
	s.records[key] = record
	return record, nil
}

func (s *goResourceEventStore) Load(_ context.Context, ref resource.EventSubscriptionRef) (resource.EventSubscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[ref.AgentProvider+"\x00"+ref.EventID]
	if !ok {
		return resource.EventSubscription{}, resource.ErrEventSubscriptionNotFound
	}
	record.Parameters = append([]byte(nil), record.Parameters...)
	return record, nil
}

type goAgentEventStore struct {
	mu       sync.Mutex
	contexts map[string]clientagent.EventContext
	events   map[events.DeliveryFingerprint]clientagent.AcceptedEvent
}

func newGoAgentEventStore() *goAgentEventStore {
	return &goAgentEventStore{
		contexts: make(map[string]clientagent.EventContext),
		events:   make(map[events.DeliveryFingerprint]clientagent.AcceptedEvent),
	}
}

func (s *goAgentEventStore) BindContext(_ context.Context, record clientagent.EventContext) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.Resource + "\x00" + record.EventID
	if retained, ok := s.contexts[key]; ok {
		if retained.SubscribeTokenSHA256 == record.SubscribeTokenSHA256 && bytes.Equal(retained.Context, record.Context) {
			return nil
		}
		return clientagent.ErrEventContextConflict
	}
	record.Context = append([]byte(nil), record.Context...)
	s.contexts[key] = record
	return nil
}

func (s *goAgentEventStore) AcceptEvent(_ context.Context, candidate clientagent.AcceptedEvent) (clientagent.EventAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	contextRecord, ok := s.contexts[candidate.Resource+"\x00"+candidate.EventID]
	if !ok {
		return clientagent.EventAcceptance{}, clientagent.ErrEventContextNotFound
	}
	if retained, ok := s.events[candidate.Fingerprint]; ok {
		if retained.EventToken != candidate.EventToken || !bytes.Equal(retained.Payload, candidate.Payload) ||
			retained.ContentType != candidate.ContentType {
			return clientagent.EventAcceptance{}, clientagent.ErrEventReplayConflict
		}
		contextRecord.Context = append([]byte(nil), contextRecord.Context...)
		return clientagent.EventAcceptance{Context: contextRecord, Duplicate: true}, nil
	}
	candidate.Payload = append([]byte(nil), candidate.Payload...)
	s.events[candidate.Fingerprint] = candidate
	contextRecord.Context = append([]byte(nil), contextRecord.Context...)
	return clientagent.EventAcceptance{Context: contextRecord}, nil
}

func main() {
	if len(os.Args) < 2 {
		must(errors.New("config path argument is required"), "args")
	}
	rawCfg, err := os.ReadFile(os.Args[1])
	must(err, "read config")
	var cfg fleetConfig
	must(json.Unmarshal(rawCfg, &cfg), "decode config")

	var currentUnix atomic.Int64
	currentUnix.Store(cfg.InitialNow)
	clock := aauth.ClockFunc(func() time.Time {
		return time.Unix(currentUnix.Load(), 0).UTC()
	})

	certPool := x509.NewCertPool()
	for _, pemBytes := range []string{
		cfg.RecordsCertPEM,
		cfg.RustFedRecordsPEM,
		cfg.RustFedHeldPEM,
		cfg.QAControlCertPEM,
	} {
		if !certPool.AppendCertsFromPEM([]byte(pemBytes)) {
			must(errors.New("failed to append certificate PEM"), "cert pool")
		}
	}

	var hostMu sync.RWMutex
	hostMap := map[string]string{
		"records.example":          cfg.RecordsAddr,
		"rust-fed-records.example": cfg.RustFedRecordsAddr,
		"rust-fed-held.example":    cfg.RustFedHeldAddr,
		"qa-control.example":       cfg.QAControlAddr,
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			NextProtos: []string{"http/1.1"},
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			hostMu.RLock()
			target, ok := hostMap[host]
			hostMu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("unmapped host %q", host)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "http key resolver")

	registry, err := r3.NewRegistry(mcp.Vocabulary())
	must(err, "r3 registry")

	readMCPOp, err := mcp.NewOperation("records.read")
	must(err, "mcp read")
	deleteMCPOp, err := mcp.NewOperation("records.delete")
	must(err, "mcp delete")

	readR3Op, err := readMCPOp.ToR3()
	must(err, "read r3 op")
	deleteR3Op, err := deleteMCPOp.ToR3()
	must(err, "delete r3 op")

	deleteOnlySet, err := mcp.NewOperationSet(deleteMCPOp)
	must(err, "deleteOnlySet")
	readOnlySet, err := mcp.NewOperationSet(readMCPOp)
	must(err, "readOnlySet")
	bothSet, err := mcp.NewOperationSet(readMCPOp, deleteMCPOp)
	must(err, "bothSet")

	// ---- 1. Go Agent Provider & Go DirectR3 Person Server ----
	goAPSeed := bytes.Repeat([]byte{0x41}, ed25519.SeedSize)
	goAPKey, err := jose.NewEd25519SigningKey("go-ap-1", ed25519.NewKeyFromSeed(goAPSeed))
	must(err, "go ap key")
	goPSSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	goPSKey, err := jose.NewEd25519SigningKey("go-ps-1", ed25519.NewKeyFromSeed(goPSSeed))
	must(err, "go ps key")
	goAgentSeed := bytes.Repeat([]byte{0x43}, ed25519.SeedSize)
	goAgentKey, err := jose.NewEd25519SigningKey("go-agent-1", ed25519.NewKeyFromSeed(goAgentSeed))
	must(err, "go agent key")

	var goIDSeq atomic.Int64
	nextID := func() string {
		return fmt.Sprintf("go-%d", goIDSeq.Add(1))
	}

	goAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     goAPIssuer,
		SigningKey: goAPKey,
		Clock:      clock,
		NewID:      nextID,
	})
	must(err, "new go ap")
	goAPSrv, goAPDER, err := startTLSServer("go-ap.example", goAP.Handler())
	must(err, "start go ap tls")
	defer goAPSrv.Close()

	var psFetchedDoc atomic.Bool
	goIssuances := &memoryIssuanceStore{}
	var lastMu sync.Mutex
	var lastRef r3.Reference
	var lastDoc r3.Document
	var lastFetched []byte
	var lastExact []byte

	goPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      goPSIssuer,
		SigningKey:  goPSKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       nextID,
		Tokens:      &memoryTokenStore{},
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			if req.Agent != "aauth:clerk@go-ap.example" || req.Resource != "https://records.example" {
				return personserver.Person{}, personserver.ErrAccessDenied
			}
			return personserver.Person{
				Subject:  "go-pairwise-person",
				Lifetime: 30 * time.Minute,
			}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: registry,
			HTTPClient: &http.Client{
				Timeout: 5 * time.Second,
				Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					resp, rtErr := transport.RoundTrip(r)
					if rtErr != nil {
						return nil, rtErr
					}
					bodyBytes, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr != nil {
						return nil, readErr
					}
					lastMu.Lock()
					lastFetched = append([]byte(nil), bodyBytes...)
					lastMu.Unlock()
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					return resp, nil
				}),
			},
			Admit: func(_ context.Context, _ string) error {
				return nil
			},
			AuthorizeDocument: func(
				_ context.Context,
				_ personserver.AuthorizationRequest,
				ref r3.Reference,
				doc r3.Document,
			) (personserver.DirectR3Decision, error) {
				psFetchedDoc.Store(true)
				lastMu.Lock()
				lastRef = ref
				lastDoc = doc
				lastExact = append([]byte(nil), lastFetched...)
				lastMu.Unlock()
				granted, grantErr := r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
				if grantErr != nil {
					return personserver.DirectR3Decision{}, grantErr
				}
				grant, grantErr := r3.NewGrant(granted, doc)
				if grantErr != nil {
					return personserver.DirectR3Decision{}, grantErr
				}
				return personserver.DirectR3Decision{
					Lifetime: 10 * time.Minute,
					Grant:    grant,
				}, nil
			},
			Issuances: goIssuances,
		},
	})
	must(err, "new go ps")

	goPSMux := http.NewServeMux()
	goPSMux.HandleFunc("POST /__mint-per-call-class", func(w http.ResponseWriter, r *http.Request) {
		var reqBody struct {
			Audience string `json:"audience"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		if reqBody.Audience == "" {
			reqBody.Audience = "https://records.example"
		}
		lastMu.Lock()
		ref, doc, exact := lastRef, lastDoc, lastExact
		lastMu.Unlock()
		granted, gErr := r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
		must(gErr, "mint granted")
		perCall, pErr := r3.NewGrantedOperations(mcp.Vocabulary(), deleteR3Op)
		must(pErr, "mint per_call")
		authz, aErr := r3.NewAuthorization(granted, perCall, doc)
		must(aErr, "mint authorization")
		nowUnix := clock.Now().Unix()
		tok, mErr := r3.MintAuthToken(registry, goPSKey, aauth.AuthTokenClaims{
			Issuer:       goPSIssuer,
			DWK:          aauth.PersonDiscoveryDocument,
			Audience:     reqBody.Audience,
			JTI:          nextID(),
			PersonServer: goPSIssuer,
			Subject:      "go-pairwise-person",
			Confirmation: aauth.Confirmation{JWK: goAgentKey.PublicJWK()},
			IssuedAt:     nowUnix,
			ExpiresAt:    nowUnix + 600,
		}, ref, exact, authz)
		must(mErr, "mint class auth token with r3_per_call")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"auth_token": tok})
	})
	goPSMux.Handle("/", goPS.Handler())

	goPSSrv, goPSDER, err := startTLSServer("go-ps.example", goPSMux)
	must(err, "start go ps tls")
	defer goPSSrv.Close()

	// ---- 2. Go Federated Resource, Go Access Server, Go Federated Person Server ----
	fedResourceSeed := bytes.Repeat([]byte{0x51}, ed25519.SeedSize)
	fedResourceKey, err := jose.NewEd25519SigningKey("fed-resource-1", ed25519.NewKeyFromSeed(fedResourceSeed))
	must(err, "fed resource key")
	fedASSeed := bytes.Repeat([]byte{0x61}, ed25519.SeedSize)
	fedASKey, err := jose.NewEd25519SigningKey("fed-as-1", ed25519.NewKeyFromSeed(fedASSeed))
	must(err, "fed access key")
	fedASAltSeed := bytes.Repeat([]byte{0x62}, ed25519.SeedSize)
	fedASAltKey, err := jose.NewEd25519SigningKey("fed-as-2", ed25519.NewKeyFromSeed(fedASAltSeed))
	must(err, "fed alternate access key")
	fedPSSeed := bytes.Repeat([]byte{0x71}, ed25519.SeedSize)
	fedPSKey, err := jose.NewEd25519SigningKey("fed-ps-1", ed25519.NewKeyFromSeed(fedPSSeed))
	must(err, "fed person key")

	var fedIDs atomic.Int64
	nextFedID := func() string {
		return fmt.Sprintf("fed-%d", fedIDs.Add(1))
	}
	definitions, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	must(err, "fed definition registry")
	definitionSource := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}}]}`,
	)))
	definition, err := mcp.ParseDefinition(fedResourceIssuer+"/mcp", definitionSource)
	must(err, "fed mcp definition")

	var psClassConsents atomic.Int32
	var psProposalConsents atomic.Int32
	var psProposalDenials atomic.Int32
	var asClassAuthorizations atomic.Int32
	var asProposalAuthorizations atomic.Int32
	var goFedClassReads atomic.Int32
	var goFedRetryRuns atomic.Int32
	var goFedHeldRuns atomic.Int32
	var goFedOtherRuns atomic.Int32
	issuances := &memoryIssuanceStore{}

	admitResource := func(_ context.Context, endpoint string) error {
		if strings.HasPrefix(endpoint, fedResourceIssuer+"/r3/") ||
			strings.HasPrefix(endpoint, rustFedRecordsIssuer+"/r3/") ||
			strings.HasPrefix(endpoint, rustFedHeldIssuer+"/r3/") {
			return nil
		}
		return fmt.Errorf("qa fleet: unexpected R3 endpoint %q", endpoint)
	}

	fedResource, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:       fedResourceIssuer,
		AccessServer: fedASIssuer,
		SigningKey:   fedResourceKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID:        nextFedID,
		ResolvePerson: func(_ context.Context, identity resource.PersonIdentity, personContext resource.PersonContext) error {
			if identity.Issuer != fedPSIssuer || identity.Subject != "fed-person" || personContext.Tenant != "" {
				return errors.New("qa fleet: unexpected person")
			}
			return nil
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/records/") {
				goFedClassReads.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"read":true}`))
				return
			}
			switch r.URL.Path {
			case "/records/r-1":
				goFedRetryRuns.Add(1)
			case "/records/held-1":
				goFedHeldRuns.Add(1)
			default:
				goFedOtherRuns.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted":true}`))
		}),
		HeldInvocations: &memoryHeldStore{},
		HoldAuthTokenRequest: func(request *http.Request) bool {
			return request.Method == http.MethodPost && request.URL.Path == "/records/held-1"
		},
		MaxSignedBodyBytes:           1 << 20,
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
		R3: &resource.R3Config{
			Registry:    registry,
			Definitions: definitions,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition: definition,
			}},
			Documents: &memoryDocumentStore{},
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(request *http.Request) (r3.Operation, bool, error) {
					if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/records/") {
						return readR3Op, true, nil
					}
					if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/records/") {
						return deleteR3Op, true, nil
					}
					return r3.Operation{}, false, nil
				},
				PresentParameters: func(request *http.Request, op r3.Operation) (map[string]r3.PresentedParameter, error) {
					sameRead, _ := op.Equal(readR3Op)
					if sameRead {
						return nil, nil
					}
					record := strings.TrimPrefix(request.URL.Path, "/records/")
					if record == "" || record == request.URL.Path || strings.Contains(record, "/") {
						return nil, errors.New("qa fleet: unexpected record path")
					}
					encoded, marshalErr := json.Marshal(record)
					if marshalErr != nil {
						return nil, marshalErr
					}
					presented, presentErr := r3.NewPresentedInlineParameter(encoded)
					if presentErr != nil {
						return nil, presentErr
					}
					return map[string]r3.PresentedParameter{"record": presented}, nil
				},
			},
			PerCall: &resource.R3PerCallConfig{
				Proposals: &memoryProposalStore{},
				Retries:   &memoryRetryStore{},
				DescribeCall: func(_ context.Context, invocation r3.Invocation, account *string) (resource.R3CallDescription, error) {
					if account != nil {
						return resource.R3CallDescription{}, errors.New("qa fleet: account is not used")
					}
					presented, ok := invocation.PresentedParameters()["record"]
					if !ok {
						return resource.R3CallDescription{}, errors.New("qa fleet: missing record")
					}
					encoded, ok := presented.InlineJSON()
					if !ok {
						return resource.R3CallDescription{}, errors.New("qa fleet: record is not inline")
					}
					inline, inlineErr := r3.NewInlineParameter(encoded)
					if inlineErr != nil {
						return resource.R3CallDescription{}, inlineErr
					}
					parameters, paramErr := r3.NewParameters(map[string]r3.Parameter{"record": inline})
					if paramErr != nil {
						return resource.R3CallDescription{}, paramErr
					}
					return resource.R3CallDescription{Parameters: parameters}, nil
				},
			},
		},
	})
	must(err, "new federated resource")

	fedAS, err := accessserver.New(accessserver.Config{
		Issuer:      fedASIssuer,
		SigningKey:  fedASKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       nextFedID,
		TrustPersonServer: func(_ context.Context, issuer string) error {
			if issuer != fedPSIssuer {
				return errors.New("qa fleet: untrusted person server")
			}
			return nil
		},
		Authorize: func(context.Context, accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("qa fleet: core policy must not receive an R3 request")
		},
		R3: &accessserver.R3Config{
			Registry:   registry,
			HTTPClient: httpClient,
			Admit:      admitResource,
			AuthorizeDocument: func(_ context.Context, _ accessserver.AuthorizationRequest, _ r3.Reference, document r3.Document) (accessserver.R3DocumentDecision, error) {
				opSet := document.OperationSet()
				isDeleteOnly, _ := opSet.Equal(deleteOnlySet)
				isReadOnly, _ := opSet.Equal(readOnlySet)
				isBoth, _ := opSet.Equal(bothSet)

				var granted r3.GrantedOperations
				var perCall r3.GrantedOperations
				var gErr error
				switch {
				case isDeleteOnly:
					granted, gErr = r3.NewGrantedOperations(mcp.Vocabulary())
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
					perCall, gErr = r3.NewGrantedOperations(mcp.Vocabulary(), deleteR3Op)
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
				case isReadOnly:
					granted, gErr = r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
					perCall, gErr = r3.NewGrantedOperations(mcp.Vocabulary())
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
				case isBoth:
					granted, gErr = r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
					perCall, gErr = r3.NewGrantedOperations(mcp.Vocabulary(), deleteR3Op)
					if gErr != nil {
						return accessserver.R3DocumentDecision{}, gErr
					}
				default:
					return accessserver.R3DocumentDecision{}, errors.New("qa fleet: unexpected class document operations")
				}
				authorization, authErr := r3.NewAuthorization(granted, perCall, document)
				if authErr != nil {
					return accessserver.R3DocumentDecision{}, authErr
				}
				asClassAuthorizations.Add(1)
				return accessserver.R3DocumentDecision{
					Lifetime:      10 * time.Minute,
					Authorization: &authorization,
				}, nil
			},
			AuthorizeProposal: func(_ context.Context, _ accessserver.AuthorizationRequest, _ r3.Reference, proposal r3.Proposal) (accessserver.R3ProposalDecision, error) {
				same, equalErr := proposal.Operation().Equal(deleteR3Op)
				if equalErr != nil || !same {
					return accessserver.R3ProposalDecision{}, errors.New("qa fleet: proposal operation is not records.delete")
				}
				asProposalAuthorizations.Add(1)
				return accessserver.R3ProposalDecision{Lifetime: 5 * time.Minute}, nil
			},
			Issuances: issuances,
		},
	})
	must(err, "new federated access server")

	fedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      fedPSIssuer,
		SigningKey:  fedPSKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       nextFedID,
		HTTPClient:  httpClient,
		Tokens:      &memoryTokenStore{},
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			if issuer != fedASIssuer {
				return "", errors.New("qa fleet: unknown access server")
			}
			return fedASIssuer + "/token", nil
		},
		BindPerson: func(_ context.Context, request personserver.PersonTokenRequest) (personserver.Person, error) {
			if request.Agent != "aauth:federated@go-ap.example" {
				return personserver.Person{}, personserver.ErrAccessDenied
			}
			switch request.Resource {
			case fedResourceIssuer, rustFedRecordsIssuer, rustFedHeldIssuer:
				return personserver.Person{Subject: "fed-person", Lifetime: 30 * time.Minute}, nil
			default:
				return personserver.Person{}, personserver.ErrAccessDenied
			}
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("qa fleet: core consent must not receive an R3 request")
		},
		R3: &personserver.R3Config{
			Registry: registry,
			Admit:    admitResource,
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error {
				psClassConsents.Add(1)
				return nil
			},
			ConsentProposal: func(_ context.Context, _ personserver.AuthorizationRequest, _ r3.Reference, proposal r3.Proposal) error {
				if param, ok := proposal.Parameters().Get("record"); ok {
					if raw, inlineOK := param.InlineJSON(); inlineOK && string(raw) == `"deny-me"` {
						psProposalDenials.Add(1)
						return personserver.ErrAccessDenied
					}
				}
				psProposalConsents.Add(1)
				return nil
			},
		},
	})
	must(err, "new federated person server")

	fedRecordsMux := http.NewServeMux()
	fedRecordsMux.HandleFunc("GET /__counts", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fleetCounts{
			DirectPSFetchedDoc:       psFetchedDoc.Load(),
			DirectPSIssuances:        goIssuances.len(),
			PSClassConsents:          int(psClassConsents.Load()),
			PSProposalConsents:       int(psProposalConsents.Load()),
			PSProposalDenials:        int(psProposalDenials.Load()),
			ASClassAuthorizations:    int(asClassAuthorizations.Load()),
			ASProposalAuthorizations: int(asProposalAuthorizations.Load()),
			ASIssuances:              issuances.len(),
			GoFedClassReads:          int(goFedClassReads.Load()),
			GoFedRetryRuns:           int(goFedRetryRuns.Load()),
			GoFedHeldRuns:            int(goFedHeldRuns.Load()),
			GoFedOtherRuns:           int(goFedOtherRuns.Load()),
		})
	})
	fedRecordsMux.Handle("/", fedResource.Handler())

	fedPSSrv, fedPSDER, err := startTLSServer("fed-ps.example", fedPS.Handler())
	must(err, "start fed ps tls")
	defer fedPSSrv.Close()
	fedASSrv, fedASDER, err := startTLSServer("fed-as.example", accessJWKSWithAlternate(fedAS.Handler(), fedASAltKey.PublicJWK()))
	must(err, "start fed as tls")
	defer fedASSrv.Close()
	fedRecordsSrv, fedRecordsDER, err := startTLSServer("fed-records.example", fedRecordsMux)
	must(err, "start fed resource tls")
	defer fedRecordsSrv.Close()

	// ---- 3. Go Events Agent Provider, Go Events Resource, Go Rogue Resource ----
	goEventsAPSeed := bytes.Repeat([]byte{0x81}, ed25519.SeedSize)
	goEventsAPKey, err := jose.NewEd25519SigningKey("go-events-ap-1", ed25519.NewKeyFromSeed(goEventsAPSeed))
	must(err, "go events ap key")
	goEventsResSeed := bytes.Repeat([]byte{0x82}, ed25519.SeedSize)
	goEventsResKey, err := jose.NewEd25519SigningKey("go-events-res-1", ed25519.NewKeyFromSeed(goEventsResSeed))
	must(err, "go events res key")
	goRogueResSeed := bytes.Repeat([]byte{0x83}, ed25519.SeedSize)
	goRogueResKey, err := jose.NewEd25519SigningKey("go-rogue-res-1", ed25519.NewKeyFromSeed(goRogueResSeed))
	must(err, "go rogue res key")

	var goEventIDSeq atomic.Int64
	nextGoEventID := func() string {
		return fmt.Sprintf("go-eid-%d", goEventIDSeq.Add(1))
	}
	var goTicketIDSeq atomic.Int64
	nextGoTicketID := func() string {
		return fmt.Sprintf("go-ticket-%d", goTicketIDSeq.Add(1))
	}

	goEventsAPStore := newGoProviderEventStore()
	goEventsAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     goEventsAPIssuer,
		SigningKey: goEventsAPKey,
		Clock:      clock,
		NewID:      nextID,
		Events: &agentprovider.EventsConfig{
			EventEndpoint:      goEventsAPIssuer + "/events",
			NewEventID:         nextGoEventID,
			KeyResolver:        resolver,
			Store:              goEventsAPStore,
			MaxSignedBodyBytes: 1 << 20,
		},
	})
	must(err, "new go events ap")

	endpointResolver, err := resource.NewHTTPEventEndpointResolver(resource.HTTPEventEndpointResolverConfig{
		Client: httpClient,
		Admit:  func(context.Context, string) error { return nil },
	})
	must(err, "new http event endpoint resolver")

	goEventsResStore := newGoResourceEventStore()
	goEventService, err := resource.NewEventService(resource.EventServiceConfig{
		Issuer:               goEventsResIssuer,
		SigningKey:           goEventsResKey,
		KeyResolver:          resolver,
		Clock:                clock,
		SubscriptionEndpoint: goEventsResIssuer + "/events/subscribe",
		Store:                goEventsResStore,
		RegisterPublic: func(_ context.Context, request resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
			if request.Token.EventID == "" {
				return resource.PublicSubscriptionDecision{}, resource.ErrEventSubscriptionDenied
			}
			return resource.PublicSubscriptionDecision{ExpiresAt: clock.Now().Add(24 * time.Hour)}, nil
		},
		Protected: &resource.ProtectedSubscriptionConfig{
			EndpointPrefix:        goEventsResIssuer + "/events/protected/",
			NewTicketID:           nextGoTicketID,
			MaximumTicketLifetime: 5 * time.Minute,
			Register: func(_ context.Context, request resource.ProtectedSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				if len(request.Ticket.Context) == 0 || string(request.Ticket.Context) == "deny-ticket" {
					return resource.PublicSubscriptionDecision{}, resource.ErrEventSubscriptionDenied
				}
				return resource.PublicSubscriptionDecision{ExpiresAt: clock.Now().Add(24 * time.Hour)}, nil
			},
		},
		ResolveEventEndpoint: endpointResolver,
		AdmitEventEndpoint:   func(context.Context, string) error { return nil },
		HTTPClient:           httpClient,
		AsyncAPIDocument:     []byte(validGoAsyncAPIDoc),
	})
	must(err, "new go event service")

	var goAgentStoresMu sync.Mutex
	goAgentStores := make(map[string]*goAgentEventStore)
	getAgentStore := func(agentID string) *goAgentEventStore {
		goAgentStoresMu.Lock()
		defer goAgentStoresMu.Unlock()
		st, ok := goAgentStores[agentID]
		if !ok {
			st = newGoAgentEventStore()
			goAgentStores[agentID] = st
		}
		return st
	}

	makeGoAgentClient := func(ctx context.Context, agentID string, keySeedHex string, overrideAgentToken string) (*clientagent.Client, jose.SigningKey, error) {
		seedBytes, decErr := hex.DecodeString(keySeedHex)
		if decErr != nil || len(seedBytes) != ed25519.SeedSize {
			return nil, jose.SigningKey{}, fmt.Errorf("invalid key seed hex: %v", decErr)
		}
		agKey, kErr := jose.NewEd25519SigningKey("agent-key-1", ed25519.NewKeyFromSeed(seedBytes))
		if kErr != nil {
			return nil, jose.SigningKey{}, kErr
		}
		agTok := overrideAgentToken
		if agTok == "" {
			apDomain := "go-events-ap.example"
			if parts := strings.SplitN(agentID, "@", 2); len(parts) == 2 {
				apDomain = parts[1]
			}
			apIssuer := "https://" + apDomain
			agPayload, _ := json.Marshal(map[string]any{
				"iss": apIssuer,
				"dwk": aauth.AgentDiscoveryDocument,
				"sub": agentID,
				"jti": nextID(),
				"iat": clock.Now().Unix(),
				"exp": clock.Now().Add(time.Hour).Unix(),
				"cnf": map[string]any{"jwk": agKey.PublicJWK()},
			})
			var mErr error
			agTok, mErr = jose.SignCompact(goEventsAPKey, jose.Header{
				Algorithm: jose.Ed25519Algorithm,
				Type:      aauth.AgentTokenType,
				KeyID:     goEventsAPKey.ID(),
			}, agPayload)
			if mErr != nil {
				return nil, jose.SigningKey{}, mErr
			}
		}
		cli, cErr := clientagent.New(ctx, clientagent.Config{
			Identifier:  agentID,
			SigningKey:  agKey,
			AgentToken:  agTok,
			KeyResolver: resolver,
			HTTPClient:  httpClient,
			Clock:       clock,
			Events:      &clientagent.EventsConfig{Store: getAgentStore(agentID)},
		})
		return cli, agKey, cErr
	}

	goEventsAPMux := http.NewServeMux()
	goEventsAPMux.HandleFunc("POST /__register-host", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host    string `json:"host"`
			Addr    string `json:"addr"`
			CertPEM string `json:"cert_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.CertPEM != "" {
			certPool.AppendCertsFromPEM([]byte(req.CertPEM))
		}
		hostMu.Lock()
		hostMap[req.Host] = req.Addr
		hostMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	goEventsAPMux.HandleFunc("POST /__issue-subscribe-token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent       string `json:"agent"`
			Resource    string `json:"resource"`
			KeySeedHex  string `json:"key_seed_hex"`
			LifetimeSec int64  `json:"lifetime_sec"`
			MaxUses     int64  `json:"max_uses"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		seedBytes, err := hex.DecodeString(req.KeySeedHex)
		if err != nil || len(seedBytes) != ed25519.SeedSize {
			http.Error(w, "invalid key_seed_hex", http.StatusBadRequest)
			return
		}
		agKey, err := jose.NewEd25519SigningKey("ag-k", ed25519.NewKeyFromSeed(seedBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.LifetimeSec <= 0 {
			req.LifetimeSec = 600
		}
		issued, err := goEventsAP.IssueSubscribeToken(r.Context(), agentprovider.SubscribeRequest{
			Agent:           req.Agent,
			Resource:        req.Resource,
			ConfirmationKey: agKey.PublicJWK(),
			Lifetime:        time.Duration(req.LifetimeSec) * time.Second,
			MaxUses:         req.MaxUses,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		claims, vErr := events.VerifySubscribeToken(r.Context(), issued.Compact, resolver, clock)
		jti := ""
		if vErr == nil {
			jti = claims.JTI
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"compact":    issued.Compact,
			"eid":        issued.EventID,
			"jti":        jti,
			"expires_at": issued.ExpiresAt.Unix(),
		})
	})

	goEventsAPMux.HandleFunc("POST /__deliveries", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EID string `json:"eid"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		dels, uses := goEventsAPStore.deliveriesFor(req.EID)
		items := make([]map[string]any, 0, len(dels))
		for _, d := range dels {
			jti := ""
			if evClaims, vErr := events.VerifyEventToken(r.Context(), d.Token, resolver, clock); vErr == nil {
				jti = evClaims.JTI
			}
			items = append(items, map[string]any{
				"eid":          d.EventID,
				"agent":        d.Agent,
				"resource":     d.Resource,
				"jti":          jti,
				"token":        d.Token,
				"content_type": d.ContentType,
				"payload_b64":  base64.StdEncoding.EncodeToString(d.Payload),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"uses":       uses,
			"deliveries": items,
		})
	})

	goEventsAPMux.HandleFunc("POST /__go-agent-register-public", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent          string `json:"agent"`
			KeySeedHex     string `json:"key_seed_hex"`
			Endpoint       string `json:"endpoint"`
			SubscribeToken string `json:"subscribe_token"`
			ParametersB64  string `json:"parameters_b64"`
			ContentType    string `json:"content_type"`
			Context        string `json:"context"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cli, _, err := makeGoAgentClient(r.Context(), req.Agent, req.KeySeedHex, "")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		params, _ := base64.StdEncoding.DecodeString(req.ParametersB64)
		sub, err := cli.RegisterPublicSubscription(r.Context(), clientagent.PublicSubscriptionInput{
			Endpoint:       req.Endpoint,
			SubscribeToken: req.SubscribeToken,
			Parameters:     params,
			ContentType:    req.ContentType,
			Context:        []byte(req.Context),
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"eid":      sub.EventID,
			"resource": sub.Resource,
		})
	})

	goEventsAPMux.HandleFunc("POST /__go-agent-register-protected", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent          string `json:"agent"`
			KeySeedHex     string `json:"key_seed_hex"`
			TicketURL      string `json:"ticket_url"`
			SubscribeToken string `json:"subscribe_token"`
			ParametersB64  string `json:"parameters_b64"`
			ContentType    string `json:"content_type"`
			Context        string `json:"context"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cli, _, err := makeGoAgentClient(r.Context(), req.Agent, req.KeySeedHex, "")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		params, _ := base64.StdEncoding.DecodeString(req.ParametersB64)
		sub, err := cli.RegisterProtectedSubscription(r.Context(), clientagent.ProtectedSubscriptionInput{
			TicketURL:      req.TicketURL,
			SubscribeToken: req.SubscribeToken,
			Parameters:     params,
			ContentType:    req.ContentType,
			Context:        []byte(req.Context),
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":       true,
			"eid":      sub.EventID,
			"resource": sub.Resource,
		})
	})

	goEventsAPMux.HandleFunc("POST /__go-agent-bind-context", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent          string `json:"agent"`
			Resource       string `json:"resource"`
			EID            string `json:"eid"`
			SubscribeToken string `json:"subscribe_token"`
			Context        string `json:"context"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		st := getAgentStore(req.Agent)
		err := st.BindContext(r.Context(), clientagent.EventContext{
			EventID:              req.EID,
			Resource:             req.Resource,
			SubscribeTokenSHA256: sha256.Sum256([]byte(req.SubscribeToken)),
			Context:              []byte(req.Context),
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	goEventsAPMux.HandleFunc("POST /__go-agent-accept-event", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Agent       string `json:"agent"`
			KeySeedHex  string `json:"key_seed_hex"`
			AgentToken  string `json:"agent_token"`
			EventToken  string `json:"event_token"`
			PayloadB64  string `json:"payload_b64"`
			ContentType string `json:"content_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		cli, _, err := makeGoAgentClient(r.Context(), req.Agent, req.KeySeedHex, req.AgentToken)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
		rec, err := cli.AcceptEvent(r.Context(), clientagent.EventDeliveryInput{
			EventToken:  req.EventToken,
			Payload:     payload,
			ContentType: req.ContentType,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"duplicate":   rec.Duplicate,
			"eid":         rec.EventID,
			"resource":    rec.Resource,
			"context":     string(rec.Context),
			"payload_b64": base64.StdEncoding.EncodeToString(rec.Payload),
		})
	})

	goEventsAPMux.HandleFunc("POST /__run-j2", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// 1. ValidateAsyncAPIDocument & AsyncAPIHandler checks
		validAsyncErr := events.ValidateAsyncAPIDocument([]byte(validGoAsyncAPIDoc))
		missingSchemeErr := events.ValidateAsyncAPIDocument([]byte(`{"asyncapi":"3.0.0","components":{"securitySchemes":{}}}`))
		wrongSchemeErr := events.ValidateAsyncAPIDocument([]byte(`{"asyncapi":"3.0.0","components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"bearer"}}}}`))
		missingVersionErr := events.ValidateAsyncAPIDocument([]byte(`{"components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"aauth-subscribe"}}}}`))
		caseVariantErr := events.ValidateAsyncAPIDocument([]byte(`{"asyncapi":"3.0.0","components":{"securitySchemes":{"aauth_subscribe":{"type":"http","Scheme":"aauth-subscribe"}}}}`))
		_, badServiceErr := resource.NewEventService(resource.EventServiceConfig{
			Issuer:               goEventsResIssuer,
			SigningKey:           goEventsResKey,
			KeyResolver:          resolver,
			Clock:                clock,
			SubscriptionEndpoint: goEventsResIssuer + "/events/subscribe",
			Store:                goEventsResStore,
			RegisterPublic: func(_ context.Context, _ resource.PublicSubscriptionRequest) (resource.PublicSubscriptionDecision, error) {
				return resource.PublicSubscriptionDecision{ExpiresAt: clock.Now().Add(time.Hour)}, nil
			},
			ResolveEventEndpoint: endpointResolver,
			AdmitEventEndpoint:   func(context.Context, string) error { return nil },
			HTTPClient:           httpClient,
			AsyncAPIDocument:     []byte(`{"asyncapi":"3.0.0","components":{}}`),
		})
		asyncGetResp, err := httpClient.Get(goEventsResIssuer + "/asyncapi.json")
		must(err, "j2 get asyncapi.json")
		asyncGetBody, _ := io.ReadAll(asyncGetResp.Body)
		_ = asyncGetResp.Body.Close()
		asyncPostResp, err := httpClient.Post(goEventsResIssuer+"/asyncapi.json", "application/json", strings.NewReader(`{}`))
		must(err, "j2 post asyncapi.json")
		_ = asyncPostResp.Body.Close()

		// 2. Public subscription with MaxUses=2, JTI check, body + no-body deliveries, validation order, and max_uses exhaustion
		j2Seed := bytes.Repeat([]byte{0x91}, ed25519.SeedSize)
		j2SeedHex := hex.EncodeToString(j2Seed)
		j2AgentID := "aauth:j2-agent@go-events-ap.example"
		j2Cli, j2Key, err := makeGoAgentClient(ctx, j2AgentID, j2SeedHex, "")
		must(err, "j2 make go agent")

		j2SubIssued, err := goEventsAP.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
			Agent:           j2AgentID,
			Resource:        goEventsResIssuer,
			ConfirmationKey: j2Key.PublicJWK(),
			Lifetime:        10 * time.Minute,
			MaxUses:         2,
		})
		must(err, "j2 issue subscribe token")
		j2SubClaims, err := events.VerifySubscribeToken(ctx, j2SubIssued.Compact, resolver, clock)
		must(err, "j2 verify subscribe token")

		// Verify subscribe token without jti is rejected by VerifySubscribeToken
		noJTIPayload, _ := json.Marshal(map[string]any{
			"iss": goEventsAPIssuer,
			"dwk": aauth.AgentDiscoveryDocument,
			"sub": j2AgentID,
			"aud": goEventsResIssuer,
			"cnf": map[string]any{"jwk": j2Key.PublicJWK()},
			"eid": "eid-no-jti",
			"iat": clock.Now().Unix(),
			"exp": clock.Now().Add(10 * time.Minute).Unix(),
		})
		noJTISubCompact, err := jose.SignCompact(goEventsAPKey, jose.Header{
			Algorithm: jose.Ed25519Algorithm,
			Type:      events.SubscribeTokenType,
			KeyID:     goEventsAPKey.ID(),
		}, noJTIPayload)
		must(err, "j2 sign no-jti subscribe token")
		_, noJTIVerifyErr := events.VerifySubscribeToken(ctx, noJTISubCompact, resolver, clock)

		_, err = j2Cli.RegisterPublicSubscription(ctx, clientagent.PublicSubscriptionInput{
			Endpoint:       goEventsResIssuer + "/events/subscribe",
			SubscribeToken: j2SubIssued.Compact,
			Parameters:     []byte(`{"event_types":["slot.available"]}`),
			ContentType:    "application/json",
			Context:        []byte("j2-public-ctx"),
		})
		must(err, "j2 register public subscription")

		// Check AP validation order BEFORE consuming any of the 2 uses:
		// (a) Expired event token -> 401 expired_jwt
		nowTime := clock.Now().UTC().Truncate(time.Second)
		expPayload, _ := json.Marshal(map[string]any{
			"iss": goEventsResIssuer,
			"dwk": aauth.ResourceDiscoveryDocument,
			"aud": j2AgentID,
			"eid": j2SubIssued.EventID,
			"jti": "j2-exp-jti",
			"iat": nowTime.Add(-20 * time.Minute).Unix(),
			"exp": nowTime.Add(-1 * time.Second).Unix(),
		})
		expCompact, err := jose.SignCompact(goEventsResKey, jose.Header{
			Algorithm: jose.Ed25519Algorithm,
			Type:      events.EventTokenType,
			KeyID:     goEventsResKey.ID(),
		}, expPayload)
		must(err, "j2 sign expired event token")
		expReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, goEventsAPIssuer+"/events", nil)
		must(signaturekey.SignSelfJWTRequestWithOptions(expReq, goEventsResKey, expCompact, clock, signaturekey.SignOptions{}), "sign expReq")
		expResp, err := httpClient.Do(expReq)
		must(err, "do expReq")
		_ = expResp.Body.Close()

		// (b) Body mismatch -> 401 invalid_jwt
		mismatchPayload := []byte(`{"slot":"10:00"}`)
		mismatchTok, err := events.MintEventToken(goEventsResIssuer, goEventsResKey, events.EventTokenRequest{
			Agent:    j2AgentID,
			EventID:  j2SubIssued.EventID,
			JTI:      "j2-mismatch-jti",
			Payload:  []byte(`{"slot":"09:00"}`),
			Lifetime: 5 * time.Minute,
		}, nowTime)
		must(err, "mint mismatch token")
		mismatchReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, goEventsAPIssuer+"/events", bytes.NewReader(mismatchPayload))
		mismatchReq.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignSelfJWTRequestWithOptions(mismatchReq, goEventsResKey, mismatchTok, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type"},
		}), "sign mismatchReq")
		mismatchResp, err := httpClient.Do(mismatchReq)
		must(err, "do mismatchReq")
		_ = mismatchResp.Body.Close()

		// (c) Wrong Resource -> 403 without Signature-Error
		rogueTok, err := events.MintEventToken(goRogueResIssuer, goRogueResKey, events.EventTokenRequest{
			Agent:    j2AgentID,
			EventID:  j2SubIssued.EventID,
			JTI:      "j2-rogue-jti",
			Payload:  mismatchPayload,
			Lifetime: 5 * time.Minute,
		}, nowTime)
		must(err, "mint rogue token")
		rogueReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, goEventsAPIssuer+"/events", bytes.NewReader(mismatchPayload))
		rogueReq.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignSelfJWTRequestWithOptions(rogueReq, goRogueResKey, rogueTok, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type"},
		}), "sign rogueReq")
		rogueResp, err := httpClient.Do(rogueReq)
		must(err, "do rogueReq")
		_ = rogueResp.Body.Close()

		// (d) Wrong Agent (aud) -> 401 invalid_jwt and 0 uses spent
		wrongAudTok, err := events.MintEventToken(goEventsResIssuer, goEventsResKey, events.EventTokenRequest{
			Agent:    "aauth:someone-else@go-events-ap.example",
			EventID:  j2SubIssued.EventID,
			JTI:      "j2-wrong-aud-jti",
			Payload:  mismatchPayload,
			Lifetime: 5 * time.Minute,
		}, nowTime)
		must(err, "mint wrong aud token")
		wrongAudReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, goEventsAPIssuer+"/events", bytes.NewReader(mismatchPayload))
		wrongAudReq.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignSelfJWTRequestWithOptions(wrongAudReq, goEventsResKey, wrongAudTok, clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type"},
		}), "sign wrongAudReq")
		wrongAudResp, err := httpClient.Do(wrongAudReq)
		must(err, "do wrongAudReq")
		_ = wrongAudResp.Body.Close()

		_, usesBeforeValid := goEventsAPStore.deliveriesFor(j2SubIssued.EventID)

		// Now deliver Event #1 (with JSON body)
		bodyPayload := []byte(`{"event_type":"slot.available","slot":"10:00"}`)
		prep1, err := goEventService.PrepareEvent(ctx, resource.EventInput{
			AgentProvider: goEventsAPIssuer,
			EventID:       j2SubIssued.EventID,
			ContentType:   "application/json",
			Payload:       bodyPayload,
			Lifetime:      5 * time.Minute,
		})
		must(err, "j2 prepare event 1")
		delRes1, err := goEventService.DeliverEvent(ctx, prep1)
		must(err, "j2 deliver event 1")

		// Replay exact same PreparedEvent -> 202 duplicate without spending a use
		delRes1Replay, err := goEventService.DeliverEvent(ctx, prep1)
		must(err, "j2 replay event 1")

		// Deliver Event #2 (no body!)
		prep2, err := goEventService.PrepareEvent(ctx, resource.EventInput{
			AgentProvider: goEventsAPIssuer,
			EventID:       j2SubIssued.EventID,
			Lifetime:      5 * time.Minute,
		})
		must(err, "j2 prepare event 2 no body")
		delRes2, err := goEventService.DeliverEvent(ctx, prep2)
		must(err, "j2 deliver event 2 no body")

		// Deliver Event #3 -> refused with 404 (max_uses=2 exhausted)
		prep3, err := goEventService.PrepareEvent(ctx, resource.EventInput{
			AgentProvider: goEventsAPIssuer,
			EventID:       j2SubIssued.EventID,
			Lifetime:      5 * time.Minute,
		})
		must(err, "j2 prepare event 3")
		_, delErr3 := goEventService.DeliverEvent(ctx, prep3)
		var del3Status int
		var deliveryErr *resource.EventDeliveryError
		if errors.As(delErr3, &deliveryErr) {
			del3Status = deliveryErr.StatusCode
		}

		// Verify retained deliveries at Go Agent
		dels, usesAfter := goEventsAPStore.deliveriesFor(j2SubIssued.EventID)
		ev1Claims, err := events.VerifyEventToken(ctx, dels[0].Token, resolver, clock)
		must(err, "verify ev1 token")
		ev2Claims, err := events.VerifyEventToken(ctx, dels[1].Token, resolver, clock)
		must(err, "verify ev2 token")

		acc1, err := j2Cli.AcceptEvent(ctx, clientagent.EventDeliveryInput{
			EventToken:  dels[0].Token,
			Payload:     dels[0].Payload,
			ContentType: dels[0].ContentType,
		})
		must(err, "j2 accept event 1")
		acc1Dup, err := j2Cli.AcceptEvent(ctx, clientagent.EventDeliveryInput{
			EventToken:  dels[0].Token,
			Payload:     dels[0].Payload,
			ContentType: dels[0].ContentType,
		})
		must(err, "j2 accept event 1 dup")
		_, tamperedAccErr := j2Cli.AcceptEvent(ctx, clientagent.EventDeliveryInput{
			EventToken:  dels[0].Token,
			Payload:     []byte(`{"event_type":"slot.available","slot":"TAMPERED"}`),
			ContentType: dels[0].ContentType,
		})
		acc2, err := j2Cli.AcceptEvent(ctx, clientagent.EventDeliveryInput{
			EventToken:  dels[1].Token,
			Payload:     dels[1].Payload,
			ContentType: dels[1].ContentType,
		})
		must(err, "j2 accept event 2 no-body")

		// 3. Protected subscription ticket bound to ConfirmationKey JWK Thumbprint
		otherSeed := bytes.Repeat([]byte{0x92}, ed25519.SeedSize)
		otherCli, _, err := makeGoAgentClient(ctx, j2AgentID, hex.EncodeToString(otherSeed), "")
		must(err, "j2 make other key agent")

		ticket, err := goEventService.IssueProtectedSubscriptionTicket(ctx, resource.ProtectedSubscriptionTicketRequest{
			ConfirmationKey: j2Key.PublicJWK(),
			Context:         []byte("j2-ticket-context"),
			Lifetime:        2 * time.Minute,
		})
		must(err, "j2 issue protected ticket")

		wrongKeySub, err := goEventsAP.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
			Agent:           j2AgentID,
			Resource:        goEventsResIssuer,
			ConfirmationKey: otherKeyJWK(otherSeed),
			Lifetime:        10 * time.Minute,
			MaxUses:         1,
		})
		must(err, "j2 issue wrong-key subscribe token")
		_, wrongKeyRegErr := otherCli.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
			TicketURL:      ticket.URL,
			SubscribeToken: wrongKeySub.Compact,
			Parameters:     []byte(`{"event_types":["appointment.changed"]}`),
			ContentType:    "application/json",
			Context:        []byte("wrong-key-ctx"),
		})

		rightKeySub, err := goEventsAP.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
			Agent:           j2AgentID,
			Resource:        goEventsResIssuer,
			ConfirmationKey: j2Key.PublicJWK(),
			Lifetime:        10 * time.Minute,
			MaxUses:         1,
		})
		must(err, "j2 issue right-key subscribe token")
		protSub, err := j2Cli.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
			TicketURL:      ticket.URL,
			SubscribeToken: rightKeySub.Compact,
			Parameters:     []byte(`{"event_types":["appointment.changed"]}`),
			ContentType:    "application/json",
			Context:        []byte("j2-protected-ctx"),
		})
		must(err, "j2 register protected subscription with matching key")

		// Second distinct registration on already-used ticket -> refused
		reuseKeySub, err := goEventsAP.IssueSubscribeToken(ctx, agentprovider.SubscribeRequest{
			Agent:           j2AgentID,
			Resource:        goEventsResIssuer,
			ConfirmationKey: j2Key.PublicJWK(),
			Lifetime:        10 * time.Minute,
			MaxUses:         1,
		})
		must(err, "j2 issue reuse subscribe token")
		_, reuseTicketErr := j2Cli.RegisterProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
			TicketURL:      ticket.URL,
			SubscribeToken: reuseKeySub.Compact,
			Parameters:     []byte(`{"event_types":["appointment.changed"]}`),
			ContentType:    "application/json",
			Context:        []byte("j2-reuse-ctx"),
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"asyncapi_valid_ok":          validAsyncErr == nil,
			"asyncapi_missing_refused":   missingSchemeErr != nil,
			"asyncapi_wrong_refused":     wrongSchemeErr != nil,
			"asyncapi_no_ver_refused":    missingVersionErr != nil,
			"asyncapi_case_refused":      caseVariantErr != nil,
			"asyncapi_service_refused":   badServiceErr != nil,
			"asyncapi_get_status":        asyncGetResp.StatusCode,
			"asyncapi_get_exact_match":   string(asyncGetBody) == validGoAsyncAPIDoc,
			"asyncapi_post_status":       asyncPostResp.StatusCode,
			"subscribe_token_has_jti":    j2SubClaims.JTI != "",
			"subscribe_no_jti_refused":   noJTIVerifyErr != nil,
			"exp_event_status":           expResp.StatusCode,
			"exp_event_sig_err":          expResp.Header.Get("Signature-Error"),
			"mismatch_body_status":       mismatchResp.StatusCode,
			"mismatch_body_sig_err":      mismatchResp.Header.Get("Signature-Error"),
			"rogue_res_status":           rogueResp.StatusCode,
			"rogue_res_sig_err":          rogueResp.Header.Get("Signature-Error"),
			"wrong_aud_status":           wrongAudResp.StatusCode,
			"wrong_aud_sig_err":          wrongAudResp.Header.Get("Signature-Error"),
			"uses_before_valid":          usesBeforeValid,
			"del1_remaining_uses":        delRes1.RemainingUses,
			"del1_replay_remaining_uses": delRes1Replay.RemainingUses,
			"del2_remaining_uses":        delRes2.RemainingUses,
			"del3_exhausted_status":      del3Status,
			"uses_after":                 usesAfter,
			"ev1_body_s256":              ev1Claims.BodySHA256,
			"ev1_expected_body_s256":     events.BodySHA256(bodyPayload),
			"ev2_body_s256":              ev2Claims.BodySHA256,
			"acc1_context":               string(acc1.Context),
			"acc1_duplicate":             acc1.Duplicate,
			"acc1_dup_duplicate":         acc1Dup.Duplicate,
			"tampered_body_refused":      errors.Is(tamperedAccErr, events.ErrEventBodyMismatch),
			"acc2_nobody_ok":             len(acc2.Payload) == 0 && !acc2.Duplicate,
			"wrong_key_ticket_refused":   wrongKeyRegErr != nil,
			"right_key_ticket_eid":       protSub.EventID,
			"reuse_ticket_refused":       reuseTicketErr != nil,
		})
	})
	goEventsAPMux.HandleFunc("POST /__run-k-suite", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RustMissionS256    string `json:"rust_mission_s256"`
			RustMissionEncoded string `json:"rust_mission_encoded"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runKSuite(
			r.Context(),
			clock,
			httpClient,
			transport,
			certPool,
			resolver,
			registry,
			readR3Op,
			deleteR3Op,
			bothSet,
			registerTLS,
			req.RustMissionS256,
			req.RustMissionEncoded,
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-m-suite", func(w http.ResponseWriter, r *http.Request) {
		var in mSuiteInput
		_ = json.NewDecoder(r.Body).Decode(&in)
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runMSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-n-suite", func(w http.ResponseWriter, r *http.Request) {
		var in nSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runNSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-o-suite", func(w http.ResponseWriter, r *http.Request) {
		var in oSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runOSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-p-suite", func(w http.ResponseWriter, r *http.Request) {
		var in pSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runPSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-q-suite", func(w http.ResponseWriter, r *http.Request) {
		var in qSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runQSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-r-suite", func(w http.ResponseWriter, r *http.Request) {
		var in rSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runRSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-s-suite", func(w http.ResponseWriter, r *http.Request) {
		var in sSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runSSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.HandleFunc("POST /__run-t-suite", func(w http.ResponseWriter, r *http.Request) {
		var in tSuiteInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		registerTLS := func(host string, handler http.Handler) (*httptest.Server, []byte) {
			srv, der, sErr := startTLSServer(host, handler)
			must(sErr, "startTLSServer "+host)
			cert, pErr := x509.ParseCertificate(der)
			must(pErr, "parseCert "+host)
			certPool.AddCert(cert)
			hostMu.Lock()
			hostMap[host] = srv.Listener.Addr().String()
			hostMu.Unlock()
			return srv, der
		}
		out := runTSuite(r.Context(), clock, httpClient, registerTLS, in)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	goEventsAPMux.Handle("/", goEventsAP.Handler())

	goEventsResMux := http.NewServeMux()
	goEventsResMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   goEventsResIssuer,
			"jwks_uri": goEventsResIssuer + "/.well-known/jwks.json",
		})
	})
	goEventsResMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{goEventsResKey.PublicJWK()},
		})
	})
	goEventsResMux.HandleFunc("POST /__issue-ticket", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			KeySeedHex  string `json:"key_seed_hex"`
			Context     string `json:"context"`
			LifetimeSec int64  `json:"lifetime_sec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seedBytes, err := hex.DecodeString(req.KeySeedHex)
		if err != nil || len(seedBytes) != ed25519.SeedSize {
			http.Error(w, "invalid key_seed_hex", http.StatusBadRequest)
			return
		}
		if req.LifetimeSec <= 0 {
			req.LifetimeSec = 120
		}
		ticket, err := goEventService.IssueProtectedSubscriptionTicket(r.Context(), resource.ProtectedSubscriptionTicketRequest{
			ConfirmationKey: otherKeyJWK(seedBytes),
			Context:         []byte(req.Context),
			Lifetime:        time.Duration(req.LifetimeSec) * time.Second,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"url":        ticket.URL,
			"expires_at": ticket.ExpiresAt.Unix(),
		})
	})
	goEventsResMux.HandleFunc("POST /__deliver-event", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentProvider string `json:"agent_provider"`
			EID           string `json:"eid"`
			ContentType   string `json:"content_type"`
			PayloadB64    string `json:"payload_b64"`
			LifetimeSec   int64  `json:"lifetime_sec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
		if req.LifetimeSec <= 0 {
			req.LifetimeSec = 300
		}
		prep, err := goEventService.PrepareEvent(r.Context(), resource.EventInput{
			AgentProvider: req.AgentProvider,
			EventID:       req.EID,
			ContentType:   req.ContentType,
			Payload:       payload,
			Lifetime:      time.Duration(req.LifetimeSec) * time.Second,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		res, err := goEventService.DeliverEvent(r.Context(), prep)
		if err != nil {
			statusCode := 0
			var delErr *resource.EventDeliveryError
			if errors.As(err, &delErr) {
				statusCode = delErr.StatusCode
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":          false,
				"status_code": statusCode,
				"error":       err.Error(),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":             true,
			"status_code":    http.StatusAccepted,
			"limited":        res.Limited,
			"remaining_uses": res.RemainingUses,
		})
	})
	goEventsResMux.HandleFunc("POST /__rogue-deliver", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			EndpointURL string `json:"endpoint_url"`
			Agent       string `json:"agent"`
			EID         string `json:"eid"`
			PayloadB64  string `json:"payload_b64"`
			ContentType string `json:"content_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		payload, _ := base64.StdEncoding.DecodeString(req.PayloadB64)
		tok, err := events.MintEventToken(goRogueResIssuer, goRogueResKey, events.EventTokenRequest{
			Agent:    req.Agent,
			EventID:  req.EID,
			Payload:  payload,
			Lifetime: 5 * time.Minute,
		}, clock.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, req.EndpointURL, bytes.NewReader(payload))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var comps []string
		if req.ContentType != "" {
			httpReq.Header.Set("Content-Type", req.ContentType)
			comps = []string{"content-type"}
		}
		if err := signaturekey.SignSelfJWTRequestWithOptions(httpReq, goRogueResKey, tok, clock, signaturekey.SignOptions{
			AdditionalComponents: comps,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status_code":     resp.StatusCode,
			"signature_error": resp.Header.Get("Signature-Error"),
			"body":            string(respBody),
		})
	})
	goEventsResMux.HandleFunc("/asyncapi.json", func(w http.ResponseWriter, r *http.Request) {
		goEventService.AsyncAPIHandler().ServeHTTP(w, r)
	})
	goEventsResMux.Handle("/events/protected/", goEventService.ProtectedSubscriptionHandler())
	goEventsResMux.Handle("/events/subscribe", goEventService.PublicSubscriptionHandler())

	goRogueResMux := http.NewServeMux()
	goRogueResMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   goRogueResIssuer,
			"jwks_uri": goRogueResIssuer + "/.well-known/jwks.json",
		})
	})
	goRogueResMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{goRogueResKey.PublicJWK()},
		})
	})

	goEventsAPSrv, goEventsAPDER, err := startTLSServer("go-events-ap.example", goEventsAPMux)
	must(err, "start go events ap tls")
	defer goEventsAPSrv.Close()
	goEventsResSrv, goEventsResDER, err := startTLSServer("go-events-res.example", goEventsResMux)
	must(err, "start go events res tls")
	defer goEventsResSrv.Close()
	goRogueResSrv, goRogueResDER, err := startTLSServer("go-rogue-res.example", goRogueResMux)
	must(err, "start go rogue res tls")
	defer goRogueResSrv.Close()

	for _, der := range [][]byte{goAPDER, goPSDER, fedPSDER, fedASDER, fedRecordsDER, goEventsAPDER, goEventsResDER, goRogueResDER} {
		cert, parseErr := x509.ParseCertificate(der)
		must(parseErr, "parse cert")
		certPool.AddCert(cert)
	}
	hostMu.Lock()
	hostMap["go-ap.example"] = goAPSrv.Listener.Addr().String()
	hostMap["go-ps.example"] = goPSSrv.Listener.Addr().String()
	hostMap["fed-ps.example"] = fedPSSrv.Listener.Addr().String()
	hostMap["fed-as.example"] = fedASSrv.Listener.Addr().String()
	hostMap["fed-records.example"] = fedRecordsSrv.Listener.Addr().String()
	hostMap["go-events-ap.example"] = goEventsAPSrv.Listener.Addr().String()
	hostMap["go-events-res.example"] = goEventsResSrv.Listener.Addr().String()
	hostMap["go-rogue-res.example"] = goRogueResSrv.Listener.Addr().String()
	hostMu.Unlock()

	goAgentToken, err := goAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:clerk@go-ap.example",
		PersonServer: goPSIssuer,
		PublicKey:    goAgentKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	})
	must(err, "issue go agent token")

	fedAgentToken, err := goAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:federated@go-ap.example",
		PersonServer: fedPSIssuer,
		PublicKey:    goAgentKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	})
	must(err, "issue federated agent token")

	body, err := json.Marshal(runQARequest{
		GoAPAddr:              goAPSrv.Listener.Addr().String(),
		GoAPCertHex:           hex.EncodeToString(goAPDER),
		GoPSAddr:              goPSSrv.Listener.Addr().String(),
		GoPSCertHex:           hex.EncodeToString(goPSDER),
		FedPSAddr:             fedPSSrv.Listener.Addr().String(),
		FedPSCertHex:          hex.EncodeToString(fedPSDER),
		FedASAddr:             fedASSrv.Listener.Addr().String(),
		FedASCertHex:          hex.EncodeToString(fedASDER),
		FedRecordsAddr:        fedRecordsSrv.Listener.Addr().String(),
		FedRecordsCertHex:     hex.EncodeToString(fedRecordsDER),
		GoAgentSeedHex:        hex.EncodeToString(goAgentSeed),
		GoAgentToken:          goAgentToken,
		FedAgentToken:         fedAgentToken,
		FedASAlternateSeedHex: hex.EncodeToString(fedASAltSeed),
		GoEventsAPAddr:        goEventsAPSrv.Listener.Addr().String(),
		GoEventsAPCertHex:     hex.EncodeToString(goEventsAPDER),
		GoEventsResAddr:       goEventsResSrv.Listener.Addr().String(),
		GoEventsResCertHex:    hex.EncodeToString(goEventsResDER),
		GoRogueResAddr:        goRogueResSrv.Listener.Addr().String(),
		GoRogueResCertHex:     hex.EncodeToString(goRogueResDER),
	})
	must(err, "marshal run-qa request")

	qaClient := &http.Client{Transport: transport, Timeout: 180 * time.Second}
	resp, err := qaClient.Post("https://qa-control.example/run-qa", "application/json", bytes.NewReader(body))
	must(err, "post run-qa")
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	must(err, "read run-qa response")
	if resp.StatusCode != http.StatusOK {
		must(fmt.Errorf("run-qa failed (%d): %s", resp.StatusCode, string(respBody)), "run-qa status")
	}
	fmt.Println(string(respBody))
}

func otherKeyJWK(seed []byte) jose.JWK {
	k, err := jose.NewEd25519SigningKey("k", ed25519.NewKeyFromSeed(seed))
	must(err, "otherKeyJWK")
	return k.PublicJWK()
}

type commitOnlyTokenStore struct {
	inner personserver.TokenStore
}

func (s commitOnlyTokenStore) Commit(ctx context.Context, r personserver.PersonTokenRecord) error {
	return s.inner.Commit(ctx, r)
}

func (s commitOnlyTokenStore) Load(ctx context.Context, issuer, jti string) (personserver.PersonTokenRecord, error) {
	return s.inner.Load(ctx, issuer, jti)
}

type k3DeferredTokenStore struct {
	mu                sync.Mutex
	records           map[string]personserver.PersonTokenRecord
	pending           map[string]*k3PendingPersonToken
	byCode            map[[32]byte]string
	lastPresentations []personserver.PersonTokenCodePresentation
}

type k3PendingPersonToken struct {
	record         personserver.PendingPersonTokenRecord
	state          personserver.PersonTokenPollState
	approval       personserver.PersonTokenApproval
	failedAttempts int
	callback       string
}

func newK3DeferredTokenStore() *k3DeferredTokenStore {
	return &k3DeferredTokenStore{
		records: make(map[string]personserver.PersonTokenRecord),
		pending: make(map[string]*k3PendingPersonToken),
		byCode:  make(map[[32]byte]string),
	}
}

func (s *k3DeferredTokenStore) Commit(_ context.Context, record personserver.PersonTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.PersonServer + "\x00" + record.JTI
	if _, exists := s.records[key]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	s.records[key] = record
	return nil
}

func (s *k3DeferredTokenStore) Load(_ context.Context, issuer, tokenID string) (personserver.PersonTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[issuer+"\x00"+tokenID]
	if !ok {
		return personserver.PersonTokenRecord{}, personserver.ErrPersonTokenNotFound
	}
	return record, nil
}

func (s *k3DeferredTokenStore) CreatePendingPersonToken(_ context.Context, record personserver.PendingPersonTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[record.ID]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	if _, exists := s.byCode[record.CodeSHA256]; exists {
		return personserver.ErrPendingPersonTokenConflict
	}
	s.pending[record.ID] = &k3PendingPersonToken{
		record: record, state: personserver.PersonTokenPollWaiting,
	}
	s.byCode[record.CodeSHA256] = record.ID
	return nil
}

func (s *k3DeferredTokenStore) ConsumePersonTokenInteractionCode(
	_ context.Context,
	personServer string,
	reference string,
	presentation personserver.PersonTokenCodePresentation,
	now time.Time,
) (personserver.PendingPersonTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPresentations = append(s.lastPresentations, presentation)
	pending, ok := s.pending[reference]
	if !ok || pending.record.PersonServer != personServer {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeInvalid
	}
	if pending.failedAttempts >= personserver.MaximumPersonTokenCodeAttempts {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrPendingPersonTokenGone
	}
	if !presentation.SyntacticallyValid || pending.record.CodeSHA256 != presentation.CodeSHA256 {
		if pending.state == personserver.PersonTokenPollWaiting && now.Before(pending.record.ExpiresAt) {
			pending.failedAttempts++
			if pending.failedAttempts >= personserver.MaximumPersonTokenCodeAttempts {
				pending.state = personserver.PersonTokenPollGone
				return personserver.PendingPersonTokenRecord{}, personserver.ErrPendingPersonTokenGone
			}
		}
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeInvalid
	}
	if pending.state != personserver.PersonTokenPollWaiting {
		return personserver.PendingPersonTokenRecord{}, personserver.ErrInteractionCodeUsed
	}
	if !now.Before(pending.record.ExpiresAt) {
		pending.state = personserver.PersonTokenPollExpired
		return personserver.PendingPersonTokenRecord{}, personserver.ErrPendingPersonTokenExpired
	}
	pending.state = personserver.PersonTokenPollInteracting
	pending.callback = presentation.Callback
	return pending.record, nil
}

func (s *k3DeferredTokenStore) LoadPendingPersonToken(_ context.Context, id string) (personserver.PendingPersonTokenSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.PendingPersonTokenSnapshot{}, personserver.ErrPendingPersonTokenNotFound
	}
	snap := personserver.PendingPersonTokenSnapshot{Record: pending.record, State: pending.state, Callback: pending.callback}
	if pending.state == personserver.PersonTokenPollApproved {
		snap.ApprovedPerson = pending.approval.Person
	}
	return snap, nil
}

func (s *k3DeferredTokenStore) ApprovePendingPersonToken(_ context.Context, id string, approval personserver.PersonTokenApproval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollApproved && pending.approval.Person == approval.Person {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	s.records[approval.Record.PersonServer+"\x00"+approval.Record.JTI] = approval.Record
	pending.approval = approval
	pending.state = personserver.PersonTokenPollApproved
	return nil
}

func (s *k3DeferredTokenStore) DenyPendingPersonToken(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollDenied {
		return nil
	}
	if pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollDenied
	return nil
}

func (s *k3DeferredTokenStore) InvalidatePendingPersonToken(_ context.Context, id string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return nil
	}
	if pending.state != personserver.PersonTokenPollWaiting && pending.state != personserver.PersonTokenPollInteracting {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func (s *k3DeferredTokenStore) PollPendingPersonToken(
	_ context.Context,
	id string,
	identity personserver.PersonTokenPollIdentity,
	now time.Time,
) (personserver.PersonTokenPollRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	wantJKT, _ := pending.record.RequestingConfirmation.Thumbprint()
	if identity.PersonServer != pending.record.PersonServer || identity.Agent != pending.record.RequestingAgent ||
		identity.ConfirmationThumbprint != wantJKT {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.PersonTokenPollRecord{}, personserver.ErrPendingPersonTokenGone
	}
	if !now.Before(pending.record.ExpiresAt) &&
		(pending.state == personserver.PersonTokenPollWaiting || pending.state == personserver.PersonTokenPollInteracting) {
		pending.state = personserver.PersonTokenPollExpired
	}
	result := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	if pending.state == personserver.PersonTokenPollApproved {
		result.Token = pending.approval.Token
		result.Record = pending.approval.Record
		result.ExpiresIn = pending.approval.ExpiresIn
	}
	return result, nil
}

func (s *k3DeferredTokenStore) ConsumePendingPersonTokenResult(_ context.Context, id string, result personserver.PersonTokenPollRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending, ok := s.pending[id]
	if !ok {
		return personserver.ErrPendingPersonTokenNotFound
	}
	if pending.state == personserver.PersonTokenPollGone {
		return personserver.ErrPendingPersonTokenGone
	}
	want := personserver.PersonTokenPollRecord{State: pending.state, RetryAfter: pending.record.RetryAfter}
	switch pending.state {
	case personserver.PersonTokenPollApproved:
		want.Token = pending.approval.Token
		want.Record = pending.approval.Record
		want.ExpiresIn = pending.approval.ExpiresIn
	case personserver.PersonTokenPollDenied, personserver.PersonTokenPollExpired:
	default:
		return personserver.ErrPendingPersonTokenConflict
	}
	if !reflect.DeepEqual(result, want) {
		return personserver.ErrPendingPersonTokenConflict
	}
	pending.state = personserver.PersonTokenPollGone
	return nil
}

func runKSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	transport *http.Transport,
	certPool *x509.CertPool,
	resolver signaturekey.KeyResolver,
	registry r3.Registry,
	readR3Op r3.Operation,
	deleteR3Op r3.Operation,
	bothSet r3.OperationSet,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	rustMissionS256 string,
	rustMissionEncoded string,
) map[string]any {
	nowTime := clock.Now().UTC().Truncate(time.Second)
	var kSeq atomic.Int64
	nextKID := func() string {
		return fmt.Sprintf("k-id-%d", kSeq.Add(1))
	}
	newKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "newKey "+id)
		return k
	}

	// =========================================================================
	// QA-K1: /authorize Challenges & invalid_signature on Missing Signature Header
	// =========================================================================
	const (
		k1APIssuer  = "https://k1-ap.example"
		k1PSIssuer  = "https://k1-ps.example"
		k1ASIssuer  = "https://k1-as.example"
		k1ResIssuer = "https://k1-res.example"
		k1AgentID   = "aauth:k1-agent@k1-ap.example"
	)
	k1APKey := newKey("k1-ap-1", 0xa1)
	k1PSKey := newKey("k1-ps-1", 0xa2)
	k1ASKey := newKey("k1-as-1", 0xa3)
	k1ResKey := newKey("k1-res-1", 0xa4)
	k1AgentKey := newKey("k1-agent-1", 0xa5)
	k1WrongKey := newKey("k1-wrong-1", 0xa6)

	k1AP, err := agentprovider.New(agentprovider.Config{
		Issuer: k1APIssuer, SigningKey: k1APKey, Clock: clock, NewID: nextKID,
	})
	must(err, "k1 ap")
	registerTLS("k1-ap.example", k1AP.Handler())

	k1PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: k1PSIssuer, SigningKey: k1PSKey, KeyResolver: resolver, Clock: clock,
		NewID: nextKID, Tokens: &memoryTokenStore{},
		BindPerson: func(_ context.Context, _ personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "k1-person", Lifetime: 30 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "k1 ps")
	registerTLS("k1-ps.example", k1PS.Handler())

	k1AS, err := accessserver.New(accessserver.Config{
		Issuer: k1ASIssuer, SigningKey: k1ASKey, KeyResolver: resolver, Clock: clock, NewID: nextKID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss != k1PSIssuer {
				return errors.New("untrusted ps")
			}
			return nil
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "k1 as")
	registerTLS("k1-as.example", k1AS.Handler())

	var k1IssuedCount atomic.Int32
	k1Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:       k1ResIssuer,
		AccessServer: k1ASIssuer,
		SigningKey:   k1ResKey,
		KeyResolver:  resolver,
		Clock:        clock,
		NewID: func() string {
			k1IssuedCount.Add(1)
			return nextKID()
		},
		ScopeDescriptions:             map[string]string{"records.read": "Read records"},
		AdditionalSignatureComponents: []string{"content-type", "content-digest"},
		MaxSignedBodyBytes:            64 << 10,
		RequiredScopes:                func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                 func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	})
	must(err, "k1 res")
	k1ResSrv, k1ResDER := registerTLS("k1-res.example", k1Res.Handler())

	k1AgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k1AgentID, PersonServer: k1PSIssuer, PublicKey: k1AgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k1 issue agent token")
	k1AuthTok, err := aauth.MintAuthToken(k1ASKey, aauth.AuthTokenClaims{
		Issuer: k1ASIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: k1ResIssuer,
		JTI: nextKID(), PersonServer: k1PSIssuer, Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		Scope:        "records.read", IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(15 * time.Minute).Unix(),
	})
	must(err, "k1 mint auth token")
	k1PersonTok, err := aauth.MintPersonToken(k1PSKey, aauth.PersonTokenClaims{
		Issuer: k1PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k1ResIssuer,
		JTI: nextKID(), Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(15 * time.Minute).Unix(),
	})
	must(err, "k1 mint person token")
	k1ExpiredPersonTok, err := aauth.MintPersonToken(k1PSKey, aauth.PersonTokenClaims{
		Issuer: k1PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k1ResIssuer,
		JTI: nextKID(), Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Add(-20 * time.Minute).Unix(), ExpiresAt: nowTime.Add(-1 * time.Second).Unix(),
	})
	must(err, "k1 mint expired person token")

	doK1Authorize := func(signKey *jose.SigningKey, jwt string, delHeader string) (int, string, string, string) {
		bodyBytes := []byte(`{"scope":"records.read"}`)
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, k1ResIssuer+"/authorize", bytes.NewReader(bodyBytes))
		must(rErr, "new k1 authorize req")
		req.Header.Set("Content-Type", "application/json")
		if signKey != nil && jwt != "" {
			must(signaturekey.SignJWTRequestWithOptions(req, *signKey, jwt, clock, signaturekey.SignOptions{
				AdditionalComponents: []string{"content-type", "content-digest"},
			}), "sign k1 authorize req")
		}
		if delHeader != "" {
			req.Header.Del(delHeader)
		}
		resp, dErr := httpClient.Do(req)
		must(dErr, "do k1 authorize req")
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("AAuth-Requirement"), resp.Header.Get("Signature-Error"), string(b)
	}

	k1AgStatus, k1AgReq, k1AgSigErr, _ := doK1Authorize(&k1AgentKey, k1AgentTok, "")
	k1AuthStatus, k1AuthReq, k1AuthSigErr, _ := doK1Authorize(&k1AgentKey, k1AuthTok, "")
	k1UnsignedStatus, k1UnsignedReq, k1UnsignedSigErr, _ := doK1Authorize(nil, "", "")
	k1IssuedAfterChallenges := int(k1IssuedCount.Load())

	k1MissSigStatus, _, k1MissSigErr, _ := doK1Authorize(&k1AgentKey, k1AgentTok, "Signature")
	k1MissInputStatus, _, k1MissInputErr, _ := doK1Authorize(&k1AgentKey, k1AgentTok, "Signature-Input")
	k1MissKeyStatus, _, k1MissKeyErr, _ := doK1Authorize(&k1AgentKey, k1AgentTok, "Signature-Key")

	// Also verify missing Signature header on a protected GET route and PS /person route
	k1ProtReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, k1ResIssuer+"/records/1", nil)
	must(signaturekey.SignJWTRequestWithOptions(k1ProtReq, k1AgentKey, k1AuthTok, clock, signaturekey.SignOptions{
		AdditionalComponents: []string{"content-digest"},
	}), "sign k1ProtReq")
	k1ProtReq.Header.Del("Signature")
	k1ProtResp, err := httpClient.Do(k1ProtReq)
	must(err, "do k1ProtReq")
	_ = k1ProtResp.Body.Close()

	k1PSMissReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, k1PSIssuer+"/person", strings.NewReader(`{"resource":"https://k1-res.example"}`))
	k1PSMissReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequest(k1PSMissReq, k1AgentKey, k1AgentTok, clock), "sign k1PSMissReq")
	k1PSMissReq.Header.Del("Signature-Input")
	k1PSMissResp, err := httpClient.Do(k1PSMissReq)
	must(err, "do k1PSMissReq")
	_ = k1PSMissResp.Body.Close()

	k1WrongKeyAgStatus, k1WrongKeyAgReq, k1WrongKeyAgSigErr, _ := doK1Authorize(&k1WrongKey, k1AgentTok, "")
	k1ExpPTStatus, k1ExpPTReq, k1ExpPTSigErr, _ := doK1Authorize(&k1AgentKey, k1ExpiredPersonTok, "")
	k1WrongKeyPTStatus, k1WrongKeyPTReq, k1WrongKeyPTSigErr, _ := doK1Authorize(&k1WrongKey, k1PersonTok, "")
	k1ValidPTStatus, _, k1ValidPTSigErr, k1ValidPTBody := doK1Authorize(&k1AgentKey, k1PersonTok, "")
	var k1ValidPTOut struct {
		ResourceToken string `json:"resource_token"`
	}
	_ = json.Unmarshal([]byte(k1ValidPTBody), &k1ValidPTOut)
	k1RTClaims, k1RTVerifyErr := aauth.VerifyResourceToken(ctx, k1ValidPTOut.ResourceToken, resolver, clock)

	k1Caps, k1CapsErr := aauth.ParseCapabilities([]string{
		`interaction;unk-int=42;unk-str="v";unk-dec=1.5;unk-bytes=:AQID:;unk-bool=?0;unk-tok=abc, clarification;extra=1`,
	})

	// =========================================================================
	// QA-K2: Four-Party Expiry Recheck After Consent & PS Recording Presented AS
	// =========================================================================
	const (
		k2PSIssuer  = "https://k2-ps.example"
		k2AS1Issuer = "https://k2-as1.example"
		k2AS2Issuer = "https://k2-as2.example"
		k2ResIssuer = "https://k2-res.example"
	)
	k2PSKey := newKey("k2-ps-1", 0xb1)
	k2AS1Key := newKey("k2-as1-1", 0xb2)
	k2AS2Key := newKey("k2-as2-1", 0xb3)
	k2ResKey := newKey("k2-res-1", 0xb4)

	var k2ClockMu sync.Mutex
	k2Now := nowTime
	k2Clock := aauth.ClockFunc(func() time.Time {
		k2ClockMu.Lock()
		defer k2ClockMu.Unlock()
		return k2Now
	})
	k2Store := &memoryTokenStore{}

	// Verify four-party PS rejects a TokenStore that does not implement PersonTokenPresentationStore
	_, k2NoPresentationStoreErr := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      k2PSIssuer,
		SigningKey:  k2PSKey,
		KeyResolver: resolver,
		Clock:       k2Clock,
		NewID:       nextKID,
		HTTPClient:  httpClient,
		Tokens:      commitOnlyTokenStore{inner: k2Store},
		AccessServerEndpoint: func(context.Context, string) (string, error) {
			return k2AS1Issuer + "/token", nil
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "k2-person", Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
	})

	var k2AS1Calls atomic.Int32
	var k2AS2Calls atomic.Int32
	var k2RecordedAtAS1SendMu sync.Mutex
	var k2RecordedAtAS1Send [][]string

	k2AS1, err := accessserver.New(accessserver.Config{
		Issuer: k2AS1Issuer, SigningKey: k2AS1Key, KeyResolver: resolver, Clock: k2Clock, NewID: nextKID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss != k2PSIssuer {
				return errors.New("untrusted ps")
			}
			return nil
		},
		Authorize: func(c context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			k2AS1Calls.Add(1)
			rec, _ := k2Store.LoadPersonTokenPresentations(c, k2PSIssuer, "k2-pt-1")
			k2RecordedAtAS1SendMu.Lock()
			k2RecordedAtAS1Send = append(k2RecordedAtAS1Send, rec)
			k2RecordedAtAS1SendMu.Unlock()
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 10 * time.Minute}, nil
		},
	})
	must(err, "k2 as1")
	registerTLS("k2-as1.example", k2AS1.Handler())

	k2AS2, err := accessserver.New(accessserver.Config{
		Issuer: k2AS2Issuer, SigningKey: k2AS2Key, KeyResolver: resolver, Clock: k2Clock, NewID: nextKID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss != k2PSIssuer {
				return errors.New("untrusted ps")
			}
			return nil
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			k2AS2Calls.Add(1)
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 10 * time.Minute}, nil
		},
	})
	must(err, "k2 as2")
	registerTLS("k2-as2.example", k2AS2.Handler())

	k2Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: k2ResIssuer, AccessServer: k2AS1Issuer, SigningKey: k2ResKey,
		KeyResolver: resolver, Clock: k2Clock, NewID: nextKID,
		ScopeDescriptions: map[string]string{"records.read": "Read"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	must(err, "k2 res")
	registerTLS("k2-res.example", k2Res.Handler())

	var k2ConsentAdvance time.Duration
	k2PS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      k2PSIssuer,
		SigningKey:  k2PSKey,
		KeyResolver: resolver,
		Clock:       k2Clock,
		NewID:       nextKID,
		HTTPClient:  httpClient,
		Tokens:      k2Store,
		AccessServerEndpoint: func(_ context.Context, iss string) (string, error) {
			switch iss {
			case k2AS1Issuer, k2AS2Issuer:
				return iss + "/token", nil
			default:
				return "", errors.New("unknown as")
			}
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "k2-person", Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			k2ClockMu.Lock()
			k2Now = k2Now.Add(k2ConsentAdvance)
			k2ClockMu.Unlock()
			return nil
		},
	})
	must(err, "k2 ps")
	registerTLS("k2-ps.example", k2PS.Handler())

	k2AgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k1AgentID, PersonServer: k2PSIssuer, PublicKey: k1AgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k2 agent tok")
	k2AgentJKT, _ := k1AgentKey.PublicJWK().Thumbprint()

	mintK2Pair := func(ptJTI, rtJTI, asIss string, ptLife, rtLife time.Duration, base time.Time) (string, string) {
		pt, mErr := aauth.MintPersonToken(k2PSKey, aauth.PersonTokenClaims{
			Issuer: k2PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k2ResIssuer,
			JTI: ptJTI, Subject: "k2-person",
			Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
			IssuedAt:     base.Unix(), ExpiresAt: base.Add(ptLife).Unix(),
		})
		must(mErr, "mint k2 pt "+ptJTI)
		must(k2Store.Commit(ctx, personserver.PersonTokenRecord{
			JTI: ptJTI, PersonServer: k2PSIssuer, Resource: k2ResIssuer,
			Subject: "k2-person", AgentProvider: k1APIssuer, Agent: k1AgentID,
			Confirmation: k1AgentKey.PublicJWK(), AgentTokenJTI: "k2-ag-jti",
			ExpiresAt:   base.Add(ptLife),
			RetainUntil: base.Add(ptLife + time.Hour),
		}), "commit k2 pt "+ptJTI)
		rt, mErr := aauth.MintResourceToken(k2ResKey, aauth.ResourceTokenClaims{
			Issuer: k2ResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: asIss,
			JTI: rtJTI, AgentJKT: k2AgentJKT,
			IssuedAt: base.Unix(), ExpiresAt: base.Add(rtLife).Unix(),
			Scope: "records.read", PersonServer: k2PSIssuer, Subject: "k2-person",
			PresentedJTI: ptJTI,
		})
		must(mErr, "mint k2 rt "+rtJTI)
		return pt, rt
	}

	doK2Exchange := func(rt, pt string) (int, map[string]any) {
		b, _ := json.Marshal(map[string]string{
			"resource_token":  rt,
			"presented_token": pt,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, k2PSIssuer+"/token", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignJWTRequest(req, k1AgentKey, k2AgentTok, k2Clock), "sign k2 exchange")
		resp, dErr := httpClient.Do(req)
		must(dErr, "do k2 exchange")
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	k2PT1, k2RT1 := mintK2Pair("k2-pt-1", "k2-rt-1", k2AS1Issuer, 20*time.Minute, 5*time.Minute, nowTime)
	_, k2RT2 := mintK2Pair("k2-pt-1-dup", "k2-rt-2", k2AS1Issuer, 20*time.Minute, 5*time.Minute, nowTime)
	// Make k2RT2 reference k2-pt-1
	k2RT2, err = aauth.MintResourceToken(k2ResKey, aauth.ResourceTokenClaims{
		Issuer: k2ResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k2AS1Issuer,
		JTI: "k2-rt-2b", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: k2PSIssuer, Subject: "k2-person",
		PresentedJTI: "k2-pt-1",
	})
	must(err, "mint k2RT2b")
	k2RT3, err := aauth.MintResourceToken(k2ResKey, aauth.ResourceTokenClaims{
		Issuer: k2ResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k2AS2Issuer,
		JTI: "k2-rt-3", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: k2PSIssuer, Subject: "k2-person",
		PresentedJTI: "k2-pt-1",
	})
	must(err, "mint k2RT3")

	k2BeforePresentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-1")
	k2Ex1Status, _ := doK2Exchange(k2RT1, k2PT1)
	k2Ex2Status, _ := doK2Exchange(k2RT2, k2PT1)
	k2AfterAS1Presentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-1")
	k2Ex3Status, _ := doK2Exchange(k2RT3, k2PT1)
	k2AfterAS2Presentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-1")

	// Presentation store failure prevents contacting AS
	k2AS1BeforeFail := k2AS1Calls.Load()
	k2Store.mu.Lock()
	k2Store.failPresentErr = errors.New("presentation store write failed")
	k2Store.mu.Unlock()
	k2RT4, _ := aauth.MintResourceToken(k2ResKey, aauth.ResourceTokenClaims{
		Issuer: k2ResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k2AS1Issuer,
		JTI: "k2-rt-4", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: k2PSIssuer, Subject: "k2-person",
		PresentedJTI: "k2-pt-1",
	})
	k2FailPresStatus, _ := doK2Exchange(k2RT4, k2PT1)
	k2AS1AfterFail := k2AS1Calls.Load()
	k2Store.mu.Lock()
	k2Store.failPresentErr = nil
	k2Store.mu.Unlock()

	// Expiry recheck after consent sub-cases:
	// (a) PresentedToken expires during Consent (2m life, Consent advances +2m)
	k2ClockMu.Lock()
	k2Now = nowTime
	k2ClockMu.Unlock()
	k2ConsentAdvance = 2 * time.Minute
	k2ExpPT, k2ExpPTRT := mintK2Pair("k2-pt-exp-a", "k2-rt-exp-a", k2AS1Issuer, 2*time.Minute, 5*time.Minute, nowTime)
	k2ASCallsBeforeExpA := k2AS1Calls.Load()
	k2ExpAStatus, k2ExpABody := doK2Exchange(k2ExpPTRT, k2ExpPT)
	k2ASCallsAfterExpA := k2AS1Calls.Load()
	k2ExpAPresentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-exp-a")

	// (b) ResourceToken expires during Consent (20m PT life, 5m RT life, Consent advances +5m)
	k2ClockMu.Lock()
	k2Now = nowTime
	k2ClockMu.Unlock()
	k2ConsentAdvance = 5 * time.Minute
	k2ExpRTPT, k2ExpRT := mintK2Pair("k2-pt-exp-b", "k2-rt-exp-b", k2AS1Issuer, 20*time.Minute, 5*time.Minute, nowTime)
	k2ASCallsBeforeExpB := k2AS1Calls.Load()
	k2ExpBStatus, k2ExpBBody := doK2Exchange(k2ExpRT, k2ExpRTPT)
	k2ASCallsAfterExpB := k2AS1Calls.Load()
	k2ExpBPresentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-exp-b")

	// (c) Both tokens still current 1s before expiry after Consent (2m PT life, 5m RT life, Consent advances 2m-1s)
	k2ClockMu.Lock()
	k2Now = nowTime
	k2ClockMu.Unlock()
	k2ConsentAdvance = 2*time.Minute - time.Second
	k2CurrPT, k2CurrRT := mintK2Pair("k2-pt-curr-c", "k2-rt-curr-c", k2AS1Issuer, 2*time.Minute, 5*time.Minute, nowTime)
	k2CurrCStatus, k2CurrCBody := doK2Exchange(k2CurrRT, k2CurrPT)
	k2CurrCPresentations, _ := k2Store.LoadPersonTokenPresentations(ctx, k2PSIssuer, "k2-pt-curr-c")

	// =========================================================================
	// QA-K3: Person-Token Interaction Code-Consume Signature & 3 Failed Codes
	// =========================================================================
	const k3PSIssuer = "https://k3-ps.example"
	k3PSKey := newKey("k3-ps-1", 0xc1)
	k3Store := newK3DeferredTokenStore()
	k3PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      k3PSIssuer,
		SigningKey:  k3PSKey,
		KeyResolver: resolver,
		Clock:       clock,
		NewID:       nextKID,
		Tokens:      k3Store,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{}, errors.New("direct BindPerson must not run when interaction is required")
		},
		RequirePersonTokenInteraction: func(context.Context, personserver.PersonTokenRequest) (personserver.PersonTokenInteractionPolicy, bool, error) {
			return personserver.PersonTokenInteractionPolicy{
				URL:        k3PSIssuer + "/interact",
				Lifetime:   10 * time.Minute,
				RetryAfter: time.Second,
			}, true, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "k3 ps")
	registerTLS("k3-ps.example", k3PS.Handler())

	k3AgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k1AgentID, PersonServer: k3PSIssuer, PublicKey: k1AgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k3 agent tok")
	k3Cli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k1AgentID, SigningKey: k1AgentKey, AgentToken: k3AgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "k3 client")

	// Flow 1: 2 failed attempts (< MaximumPersonTokenCodeAttempts = 3), then valid code on 3rd attempt
	k3Start1, err := k3Cli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: k3PSIssuer, Resource: k1ResIssuer, Capabilities: []string{"interaction"},
	})
	must(err, "k3 start 1")
	k3Pend1, k3Pend1OK := k3Start1.Pending()
	if !k3Pend1OK {
		must(errors.New("k3 start 1 not pending"), "k3Pend1")
	}
	k3Ref1 := k3Pend1.InteractionURL()[strings.LastIndex(k3Pend1.InteractionURL(), "/")+1:]
	_, k3F1Attempt1Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref1, "bad!crockford!")
	_, k3F1Attempt2Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref1, "2345-6789")
	k3Inter1, k3F1Attempt3Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref1, k3Pend1.InteractionCode())
	must(k3F1Attempt3Err, "k3 flow1 attempt 3 valid code")
	must(k3PS.ApprovePersonTokenInteraction(ctx, k3Inter1, personserver.Person{
		Subject: "k3-person-1", Lifetime: 20 * time.Minute,
	}), "k3 approve 1")
	k3Poll1Res, err := k3Cli.PollPersonToken(ctx, k3Pend1)
	must(err, "k3 poll 1")
	k3Tok1, k3Tok1OK := k3Poll1Res.Token()

	// Flow 2: 3 failed attempts == MaximumPersonTokenCodeAttempts (3), then 4th attempt with valid code is refused
	k3Start2, err := k3Cli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: k3PSIssuer, Resource: k1ResIssuer, Capabilities: []string{"interaction"},
	})
	must(err, "k3 start 2")
	k3Pend2, _ := k3Start2.Pending()
	k3Ref2 := k3Pend2.InteractionURL()[strings.LastIndex(k3Pend2.InteractionURL(), "/")+1:]

	_, k3F2Attempt1Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref2, "invalid!!!")
	k3MidPoll1, err := k3Cli.PollPersonToken(ctx, k3Pend2)
	must(err, "k3 mid poll 1")
	_, k3MidPoll1Pending := k3MidPoll1.Pending()

	_, k3F2Attempt2Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref2, "2345-6789")
	k3MidPoll2, err := k3Cli.PollPersonToken(ctx, k3Pend2)
	must(err, "k3 mid poll 2")
	_, k3MidPoll2Pending := k3MidPoll2.Pending()

	_, k3F2Attempt3Err := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref2, "3456-789A")
	_, k3F2Attempt4ValidCodeErr := k3PS.ConsumePersonTokenInteractionCode(ctx, k3Ref2, k3Pend2.InteractionCode())
	_, k3FinalPollErr := k3Cli.PollPersonToken(ctx, k3Pend2)
	var k3FinalProblem *aauth.ProblemError
	k3FinalProblemCode := ""
	k3FinalProblemStatus := 0
	if errors.As(k3FinalPollErr, &k3FinalProblem) {
		k3FinalProblemCode = string(k3FinalProblem.Code)
		k3FinalProblemStatus = k3FinalProblem.Status
	}

	// =========================================================================
	// QA-K4: Key Resolver Refusing Private & Loopback + TransportEnforcesEgress
	// =========================================================================
	k4NonPublicCases := []struct {
		name  string
		addrs []string
	}{
		{"ipv4_loopback", []string{"127.0.0.1"}},
		{"ipv6_loopback", []string{"::1"}},
		{"rfc1918_10", []string{"10.0.0.7"}},
		{"rfc1918_172_16", []string{"172.16.4.4"}},
		{"rfc1918_192_168", []string{"192.168.1.1"}},
		{"ipv4_link_local", []string{"169.254.169.254"}},
		{"ipv6_link_local", []string{"fe80::1"}},
		{"ipv6_ula", []string{"fd00::1"}},
		{"unspecified", []string{"0.0.0.0"}},
		{"cgnat_100_64", []string{"100.64.0.1"}},
		{"ipv4_mapped_loopback", []string{"::ffff:127.0.0.1"}},
		{"nat64_private", []string{"64:ff9b::a00:7"}},
		{"mixed_public_and_private", []string{"203.0.113.10", "10.0.0.7"}},
	}
	k4AllDenied := true
	k4TotalDials := 0
	k4DeniedResults := make(map[string]bool)
	for _, tc := range k4NonPublicCases {
		dials := 0
		res, cErr := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
			Client: &http.Client{Transport: &http.Transport{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials++
					return nil, errors.New("unexpected dial")
				},
			}},
			Clock: clock,
			Admit: func(context.Context, string) error { return nil },
			LookupAddresses: func(_ context.Context, _ string) ([]netip.Addr, error) {
				out := make([]netip.Addr, 0, len(tc.addrs))
				for _, s := range tc.addrs {
					out = append(out, netip.MustParseAddr(s))
				}
				return out, nil
			},
		})
		must(cErr, "k4 resolver "+tc.name)
		_, rErr := res.ResolveKey(ctx, "https://issuer.example", aauth.AgentDiscoveryDocument, "k1")
		var denied *signaturekey.ResolutionError
		isDenied := errors.As(rErr, &denied) && denied.Code == signaturekey.ResolutionDenied && dials == 0
		k4DeniedResults[tc.name] = isDenied
		if !isDenied {
			k4AllDenied = false
		}
		k4TotalDials += dials
	}
	// Literal 127.0.0.1 URL
	k4LitRes, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{},
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})
	must(err, "k4 literal resolver")
	_, k4LitErr := k4LitRes.ResolveKey(ctx, "https://127.0.0.1", aauth.AgentDiscoveryDocument, "k1")
	var k4LitDenied *signaturekey.ResolutionError
	k4LiteralDeniedOK := errors.As(k4LitErr, &k4LitDenied) && k4LitDenied.Code == signaturekey.ResolutionDenied

	// Constructor rejection when TransportEnforcesEgress is false for custom RoundTripper or Proxy/DialTLSContext
	_, k4CustomRTErr := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, nil })},
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})
	_, k4ProxyErr := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}},
		Clock:  clock,
		Admit:  func(context.Context, string) error { return nil },
	})

	// Pinning checked address & DNS rebinding defense over real loopback TLS (k1-ap.example)
	var k4DialedAddrs []string
	var k4LookupCount int
	k4PinRes, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: certPool, NextProtos: []string{"http/1.1"}},
			DisableKeepAlives: true,
			DialContext: func(c context.Context, network, address string) (net.Conn, error) {
				k4DialedAddrs = append(k4DialedAddrs, address)
				target, _ := transport.DialContext(c, network, "k1-ap.example:443")
				return target, nil
			},
		}},
		Clock:            clock,
		Admit:            func(context.Context, string) error { return nil },
		AllowDestination: func(a netip.Addr) bool { return a.IsLoopback() },
		LookupAddresses: func(_ context.Context, _ string) ([]netip.Addr, error) {
			k4LookupCount++
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	must(err, "k4PinRes")
	k4ResolvedJWK, k4PinResolveErr := k4PinRes.ResolveKey(ctx, k1APIssuer, aauth.AgentDiscoveryDocument, k1APKey.ID())
	k4PinnedDialOK := k4PinResolveErr == nil && k4ResolvedJWK.Equal(k1APKey.PublicJWK()) &&
		len(k4DialedAddrs) == 2 && k4DialedAddrs[0] == "127.0.0.1:443" && k4DialedAddrs[1] == "127.0.0.1:443"

	// DNS rebinding on 2nd lookup (metadata -> 127.0.0.1 allowed, JWKS -> 10.0.0.99 private refused)
	k4RebindStep := 0
	k4RebindRes, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client: &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: certPool, NextProtos: []string{"http/1.1"}},
			DisableKeepAlives: true,
			DialContext: func(c context.Context, network, _ string) (net.Conn, error) {
				return transport.DialContext(c, network, "k1-ap.example:443")
			},
		}},
		Clock:            clock,
		Admit:            func(context.Context, string) error { return nil },
		AllowDestination: func(a netip.Addr) bool { return a.IsLoopback() },
		LookupAddresses: func(_ context.Context, _ string) ([]netip.Addr, error) {
			k4RebindStep++
			if k4RebindStep == 1 {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("10.0.0.99")}, nil
		},
	})
	must(err, "k4RebindRes")
	_, k4RebindErr := k4RebindRes.ResolveKey(ctx, k1APIssuer, aauth.AgentDiscoveryDocument, k1APKey.ID())
	var k4RebindDenied *signaturekey.ResolutionError
	k4RebindRefusedOK := errors.As(k4RebindErr, &k4RebindDenied) && k4RebindDenied.Code == signaturekey.ResolutionDenied

	// =========================================================================
	// QA-K5: PollAuthToken & PollR3Call Result Types, 429 Backoff, 503 & Reauthorize
	// =========================================================================
	const k5PollResIssuer = "https://k5-poll-res.example"
	k5PollResKey := newKey("k5-poll-res-1", 0xd1)
	k5PersonTok, err := aauth.MintPersonToken(k1PSKey, aauth.PersonTokenClaims{
		Issuer: k1PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k5PollResIssuer,
		JTI: "k5-pt-1", Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(30 * time.Minute).Unix(),
	})
	must(err, "k5 mint person tok")
	k5RT, err := aauth.MintResourceToken(k5PollResKey, aauth.ResourceTokenClaims{
		Issuer: k5PollResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k1PSIssuer,
		JTI: "k5-rt-1", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: k1PSIssuer, Subject: "k1-person",
		PresentedJTI: "k5-pt-1",
	})
	must(err, "k5 mint rt")
	k5ReqHeader, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: k5RT})
	must(err, "k5 format req header")
	k5AuthTok, err := aauth.MintAuthToken(k1PSKey, aauth.AuthTokenClaims{
		Issuer: k1PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k5PollResIssuer,
		JTI: "k5-auth-1", PersonServer: k1PSIssuer, Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		Scope:        "records.read", IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(20 * time.Minute).Unix(),
	})
	must(err, "k5 mint auth tok")

	// Prepare R3 class and proposal tokens for PollR3Call
	k5Doc, err := r3.NewDocument(bothSet, r3.DocumentOptions{})
	must(err, "k5 new doc")
	k5DocBytes, err := json.Marshal(k5Doc)
	must(err, "k5 marshal doc")
	k5DocRef, err := r3.NewReference(k5PollResIssuer+"/r3/docs/1", r3.Digest(k5DocBytes))
	must(err, "k5 doc ref")
	k5GrantedRead, _ := r3.NewGrantedOperations(mcp.Vocabulary(), readR3Op)
	k5PerCallDel, _ := r3.NewGrantedOperations(mcp.Vocabulary(), deleteR3Op)
	k5Authz, err := r3.NewAuthorization(k5GrantedRead, k5PerCallDel, k5Doc)
	must(err, "k5 new authz")
	k5ClassAuthTok, err := r3.MintAuthToken(registry, k1ASKey, aauth.AuthTokenClaims{
		Issuer: k1ASIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: k5PollResIssuer,
		JTI: "k5-class-1", PersonServer: k1PSIssuer, Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(20 * time.Minute).Unix(),
	}, k5DocRef, k5DocBytes, k5Authz)
	must(err, "k5 mint class auth tok")

	k5RecInline, err := r3.NewInlineParameter([]byte(`"alpha"`))
	must(err, "k5 inline param")
	k5Params, err := r3.NewParameters(map[string]r3.Parameter{"record": k5RecInline})
	must(err, "k5 params")
	k5Prop, err := r3.NewProposal(deleteR3Op, k5Params, r3.ProposalOptions{})
	must(err, "k5 new proposal")
	k5PropBytes, err := json.Marshal(k5Prop)
	must(err, "k5 marshal proposal")
	k5PropRT, k5PropRef, err := r3.MintProposalResourceToken(registry, k5PollResKey, aauth.ResourceTokenClaims{
		Issuer: k5PollResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k1ASIssuer,
		JTI: "k5-prop-rt-1", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		PersonServer: k1PSIssuer, Subject: "k1-person", PresentedJTI: "k5-class-1",
	}, k5PollResIssuer+"/r3/proposals/1", k5PropBytes)
	must(err, "k5 mint prop rt")
	k5R3ReqHeader, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: k5PropRT})
	must(err, "k5 format r3 req header")
	k5PropAuthTok, err := r3.MintPerCallAuthToken(registry, k1ASKey, aauth.AuthTokenClaims{
		Issuer: k1ASIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: k5PollResIssuer,
		JTI: "k5-prop-auth-1", PersonServer: k1PSIssuer, Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(20 * time.Minute).Unix(),
	}, k5PropRef, k5PropBytes)
	must(err, "k5 mint prop auth tok")

	// Step-up ResourceToken for PollAuthToken Reauthorize() (PresentedJTI == k5AuthTok.JTI == "k5-auth-1")
	k5StepUpRT, err := aauth.MintResourceToken(k5PollResKey, aauth.ResourceTokenClaims{
		Issuer: k5PollResIssuer, DWK: aauth.ResourceDiscoveryDocument, Audience: k1PSIssuer,
		JTI: "k5-stepup-rt-1", AgentJKT: k2AgentJKT,
		IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(5 * time.Minute).Unix(),
		Scope: "records.read", PersonServer: k1PSIssuer, Subject: "k1-person",
		PresentedJTI: "k5-auth-1",
	})
	must(err, "k5 mint stepup rt")
	k5StepUpReqHeader, err := aauth.FormatAuthTokenRequirement(aauth.AuthTokenRequirement{ResourceToken: k5StepUpRT})
	must(err, "k5 format stepup req header")

	type k5Step struct {
		status     int
		retryAfter string
		wantSec    int64
	}
	k5Steps := []k5Step{
		{http.StatusAccepted, "", 5},
		{http.StatusTooManyRequests, "", 10},
		{http.StatusTooManyRequests, "", 15},
		{http.StatusServiceUnavailable, "3", 3},
		{http.StatusTooManyRequests, "", 8},
		{http.StatusTooManyRequests, "30", 30},
		{http.StatusTooManyRequests, "soon", 35},
		{http.StatusAccepted, "2", 2},
		{http.StatusOK, "", 0},
	}
	var k5AuthPollIdx int
	var k5R3PollIdx int
	var k5SpecialMode string

	k5Mux := http.NewServeMux()
	k5Mux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   k5PollResIssuer,
			"jwks_uri": k5PollResIssuer + "/.well-known/jwks.json",
		})
	})
	k5Mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{k5PollResKey.PublicJWK()},
		})
	})
	k5Mux.HandleFunc("GET /r3/docs/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(k5DocBytes)
	})
	k5Mux.HandleFunc("GET /r3/proposals/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(k5PropBytes)
	})
	k5Mux.HandleFunc("GET /records/held-auth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("AAuth-Requirement", k5ReqHeader)
		w.Header().Set("Location", "/pending/auth-held")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	})
	k5Mux.HandleFunc("GET /pending/auth-held", func(w http.ResponseWriter, _ *http.Request) {
		if k5SpecialMode == "person-token" {
			w.Header().Set("Signature-Error", "error=revoked_jwt")
			w.Header().Set("AAuth-Requirement", "requirement=person-token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st := k5Steps[k5AuthPollIdx]
		k5AuthPollIdx++
		if st.retryAfter != "" {
			w.Header().Set("Retry-After", st.retryAfter)
		}
		switch st.status {
		case http.StatusAccepted:
			w.Header().Set("AAuth-Requirement", k5ReqHeader)
			w.Header().Set("Location", "/pending/auth-held")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case http.StatusOK:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"completed":true}`))
		default:
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(st.status)
			_, _ = w.Write([]byte("slow down"))
		}
	})
	k5Mux.HandleFunc("POST /records/held-r3", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("AAuth-Requirement", k5R3ReqHeader)
		w.Header().Set("Location", "/r3/pending/r3-held")
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	})
	k5Mux.HandleFunc("GET /r3/pending/r3-held", func(w http.ResponseWriter, _ *http.Request) {
		if k5SpecialMode == "person-token" {
			w.Header().Set("Signature-Error", "error=revoked_jwt")
			w.Header().Set("AAuth-Requirement", "requirement=person-token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st := k5Steps[k5R3PollIdx]
		k5R3PollIdx++
		if st.retryAfter != "" {
			w.Header().Set("Retry-After", st.retryAfter)
		}
		switch st.status {
		case http.StatusAccepted:
			w.Header().Set("AAuth-Requirement", k5R3ReqHeader)
			w.Header().Set("Location", "/r3/pending/r3-held")
			w.Header().Set("Cache-Control", "private, no-store")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case http.StatusOK:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(st.status)
			_, _ = w.Write([]byte("slow down"))
		}
	})
	registerTLS("k5-poll-res.example", k5Mux)

	k5Cli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k1AgentID, SigningKey: k1AgentKey, AgentToken: k1AgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: registry},
	})
	must(err, "k5 client")

	// Run PollAuthToken sequence
	k5InitReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, k5PollResIssuer+"/records/held-auth", nil)
	k5Started, err := k5Cli.Begin(ctx, clientagent.InitialCall{Request: k5InitReq, PersonToken: k5PersonTok})
	must(err, "k5 begin auth")
	k5AuthPend, k5AuthPendOK := k5Started.PendingAuthToken()
	if !k5AuthPendOK {
		must(errors.New("k5 begin did not return PendingAuthToken"), "k5AuthPend")
	}
	k5AuthPendInitial := k5AuthPend
	k5AuthInitialSec := int64(k5AuthPend.RetryAfter() / time.Second)
	var k5AuthObservedSec []int64
	k5AuthTerminalStatus := 0
	for i, st := range k5Steps {
		pollRes, pErr := k5Cli.PollAuthToken(ctx, clientagent.AuthTokenPoll{
			Pending: k5AuthPend, AuthToken: k5AuthTok,
		})
		must(pErr, fmt.Sprintf("k5 PollAuthToken step %d", i))
		resp, respOK := pollRes.Response()
		if !respOK || resp == nil {
			must(errors.New("k5 PollAuthToken missing response"), "k5AuthResp")
		}
		_ = resp.Body.Close()
		nextPend, hasPend := pollRes.Pending()
		if st.status == http.StatusOK {
			if hasPend {
				must(errors.New("k5 PollAuthToken 200 returned Pending"), "k5Auth200Pend")
			}
			k5AuthTerminalStatus = resp.StatusCode
		} else {
			if !hasPend {
				must(errors.New("k5 PollAuthToken non-terminal missing Pending"), "k5AuthHasPend")
			}
			k5AuthObservedSec = append(k5AuthObservedSec, int64(nextPend.RetryAfter()/time.Second))
			k5AuthPend = nextPend
		}
	}

	// Run PollR3Call sequence
	k5R3Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, k5PollResIssuer+"/records/held-r3", strings.NewReader(`{"record":"alpha"}`))
	k5R3Req.Header.Set("Content-Type", "application/json")
	k5R3Started, err := k5Cli.BeginR3Call(ctx, clientagent.R3Call{
		Request: k5R3Req, ClassAuthToken: k5ClassAuthTok, Operation: deleteR3Op,
	})
	must(err, "k5 begin r3")
	k5R3Pend, k5R3PendOK := k5R3Started.Pending()
	if !k5R3PendOK {
		must(errors.New("k5 BeginR3Call did not return Pending"), "k5R3Pend")
	}
	k5R3PendInitial := k5R3Pend
	k5R3InitialSec := int64(k5R3Pend.RetryAfter() / time.Second)
	var k5R3ObservedSec []int64
	k5R3TerminalStatus := 0
	for i, st := range k5Steps {
		pollRes, pErr := k5Cli.PollR3Call(ctx, clientagent.R3Poll{
			Pending: k5R3Pend, AuthToken: k5PropAuthTok,
		})
		must(pErr, fmt.Sprintf("k5 PollR3Call step %d", i))
		resp, respOK := pollRes.Response()
		if !respOK || resp == nil {
			must(errors.New("k5 PollR3Call missing response"), "k5R3Resp")
		}
		_ = resp.Body.Close()
		nextPend, hasPend := pollRes.Pending()
		if st.status == http.StatusOK {
			if hasPend {
				must(errors.New("k5 PollR3Call 200 returned Pending"), "k5R3200Pend")
			}
			k5R3TerminalStatus = resp.StatusCode
		} else {
			if !hasPend {
				must(errors.New("k5 PollR3Call non-terminal missing Pending"), "k5R3HasPend")
			}
			k5R3ObservedSec = append(k5R3ObservedSec, int64(nextPend.RetryAfter()/time.Second))
			k5R3Pend = nextPend
		}
	}

	// Verify PersonTokenRequiredError on 401 Signature-Error: error=revoked_jwt + requirement=person-token
	k5SpecialMode = "person-token"
	_, k5AuthPersonReqErr := k5Cli.PollAuthToken(ctx, clientagent.AuthTokenPoll{
		Pending: k5AuthPendInitial, AuthToken: k5AuthTok,
	})
	var k5AuthPTReq *clientagent.PersonTokenRequiredError
	k5AuthPersonReqOK := errors.As(k5AuthPersonReqErr, &k5AuthPTReq)

	_, k5R3PersonReqErr := k5Cli.PollR3Call(ctx, clientagent.R3Poll{
		Pending: k5R3PendInitial, AuthToken: k5PropAuthTok,
	})
	var k5R3PTReq *clientagent.PersonTokenRequiredError
	k5R3PersonReqOK := errors.As(k5R3PersonReqErr, &k5R3PTReq)
	k5SpecialMode = ""
	_ = k5StepUpReqHeader

	// Also exercise Client.Reauthorize after Agent key rotation over real HTTPS (against 3-party k5-direct-res / k1-ps)
	const k5DirectResIssuer = "https://k5-direct-res.example"
	k5DirectRes, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            k5DirectResIssuer,
		SigningKey:        k5PollResKey,
		KeyResolver:       resolver,
		Clock:             clock,
		NewID:             nextKID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
	})
	must(err, "k5 direct res")
	registerTLS("k5-direct-res.example", k5DirectRes.Handler())

	k5RotatedKey := newKey("k1-agent-rotated", 0xd2)
	k5RotatedAgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k1AgentID, PersonServer: k1PSIssuer, PublicKey: k5RotatedKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k5 issue rotated agent tok")
	k5RotatedCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k1AgentID, SigningKey: k5RotatedKey, AgentToken: k5RotatedAgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "k5 rotated client")
	k5RotatedPTRes, err := k5RotatedCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: k1PSIssuer, Resource: k5DirectResIssuer,
	})
	must(err, "k5 rotated person token")
	k5RotatedPT, _ := k5RotatedPTRes.Token()
	// Prior auth token minted by k1PSKey for k5DirectResIssuer bound to old k1AgentKey
	k5PriorAuthTok, err := aauth.MintAuthToken(k1PSKey, aauth.AuthTokenClaims{
		Issuer: k1PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k5DirectResIssuer,
		JTI: nextKID(), PersonServer: k1PSIssuer, Subject: "k1-person",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		Scope:        "records.read", IssuedAt: nowTime.Unix(), ExpiresAt: nowTime.Add(15 * time.Minute).Unix(),
	})
	must(err, "k5 prior auth tok")
	k5ReauthRes, err := k5RotatedCli.Reauthorize(ctx, clientagent.ReauthorizationRequest{
		PriorAuthToken: k5PriorAuthTok,
		PersonToken:    k5RotatedPT,
	})
	must(err, "k5 Reauthorize")
	k5ReauthTok, k5ReauthOK := k5ReauthRes.Token()
	k5ReauthClaims, k5ReauthVerifyErr := aauth.VerifyAuthToken(ctx, k5ReauthTok, resolver, clock)

	// =========================================================================
	// QA-K6: MissionBlob.Approver Removal & Mission Data Without approver
	// =========================================================================
	_, k6HasApproverField := reflect.TypeFor[aauth.MissionBlob]().FieldByName("Approver")
	k6RustDecoded, k6RustDecodeErr := aauth.DecodeMission(rustMissionS256, rustMissionEncoded)
	k6WithApproverRaw := []byte(`{"approver":"https://other-ps.example","agent":"aauth:k1-agent@k1-ap.example","approved_at":"2026-10-30T12:00:00Z","description":"Legacy mission with unrecognized approver member"}`)
	k6WithApproverDecoded, k6WithApproverErr := aauth.DecodeMission(
		aauth.MissionS256(k6WithApproverRaw),
		base64.RawURLEncoding.EncodeToString(k6WithApproverRaw),
	)

	const (
		k6PSIssuer  = "https://k6-ps.example"
		k6ResIssuer = "https://k6-res.example"
	)
	k6PSKey := newKey("k6-ps-1", 0xe1)
	k6ResKey := newKey("k6-res-1", 0xe2)
	k6MissionStore := testutil.NewMissionStore()
	k6PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: k6PSIssuer, SigningKey: k6PSKey, KeyResolver: resolver, Clock: clock,
		NewID: nextKID, Tokens: k6MissionStore,
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, req personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				exp := nowTime.Add(30 * time.Minute)
				return personserver.MissionDecision{
					Description:       req.Proposal.Description,
					ApprovedTools:     req.Proposal.Tools,
					ApprovedResources: req.Proposal.Resources,
					ExpiresAt:         &exp,
				}, nil
			},
		},
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			if req.Mission == nil {
				return personserver.Person{}, errors.New("mission required")
			}
			return personserver.Person{Subject: "k6-person", Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			if req.Mission == nil {
				return personserver.AuthorizationDecision{}, errors.New("mission required")
			}
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "k6 ps")
	registerTLS("k6-ps.example", k6PS.Handler())

	k6Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: k6ResIssuer, SigningKey: k6ResKey, KeyResolver: resolver, Clock: clock,
		NewID:             nextKID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := resource.AuthPrincipalFromContext(r.Context())
			if !ok || p.MissionS256 == "" {
				http.Error(w, "missing mission", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"mission_s256": p.MissionS256})
		}),
	})
	must(err, "k6 res")
	registerTLS("k6-res.example", k6Res.Handler())

	k6AgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k1AgentID, PersonServer: k6PSIssuer, PublicKey: k1AgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k6 agent tok")
	k6Cli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k1AgentID, SigningKey: k1AgentKey, AgentToken: k6AgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "k6 cli")
	k6Approval, err := k6Cli.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: k6PSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# Cross-PS Mission Without Approver\n\nExecute approved read.",
			Tools:       []aauth.MissionTool{{Name: "ReadRecords", Description: "Read records"}},
			Resources:   []string{k6ResIssuer},
		},
	})
	must(err, "k6 propose mission")
	k6ApprovedMission := k6Approval.Mission()
	var k6MissionMembers map[string]json.RawMessage
	_ = json.Unmarshal(k6ApprovedMission.ExactJSON, &k6MissionMembers)
	_, k6EncodedHasApprover := k6MissionMembers["approver"]
	k6MissionPT, k6HasMissionPT := k6Approval.PersonToken(k6ResIssuer)
	if !k6HasMissionPT {
		must(errors.New("k6 missing mission person token"), "k6MissionPT")
	}
	k6RT, err := k6Cli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: k6ResIssuer, PersonToken: k6MissionPT, Scopes: []string{"records.read"},
	})
	must(err, "k6 authorize")
	k6Ex, err := k6Cli.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: k6PSIssuer, ResourceToken: k6RT, PresentedToken: k6MissionPT,
	})
	must(err, "k6 exchange")
	k6AuthTok, _ := k6Ex.Token()
	k6CallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, k6ResIssuer+"/records/1", nil)
	k6CallResp, err := k6Cli.Do(ctx, clientagent.Call{Request: k6CallReq, AuthToken: k6AuthTok})
	must(err, "k6 do call")
	_ = k6CallResp.Body.Close()

	// =========================================================================
	// QA-K7: Upstream Person Token in Call Chaining Over HTTPS
	// =========================================================================
	const (
		k7PSIssuer   = "https://k7-ps.example"
		k7Res1Issuer = "https://k7-res1.example"
		k7Res2Issuer = "https://k7-res2.example"
		k7CallerID   = "aauth:k1-agent@k1-ap.example"
		k7RelayID    = "aauth:relay@k7-res1.example"
	)
	k7PSKey := newKey("k7-ps-1", 0xf1)
	k7Res1Key := newKey("k7-res1-1", 0xf2)
	k7RelayAgentKey := newKey("k7-relay-ag-1", 0xf3)
	k7Res2Key := newKey("k7-res2-1", 0xf4)
	k7OtherPSKey := newKey("k7-other-ps-1", 0xf5)

	k7OtherPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: "https://k7-other-ps.example", SigningKey: k7OtherPSKey, KeyResolver: resolver, Clock: clock,
		NewID: nextKID, Tokens: &memoryTokenStore{},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "other", Lifetime: time.Hour}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: time.Hour}, nil
		},
	})
	must(err, "k7 other ps")
	registerTLS("k7-other-ps.example", k7OtherPS.Handler())

	k7Res1AP, err := agentprovider.New(agentprovider.Config{
		Issuer: k7Res1Issuer, SigningKey: k7Res1Key, Clock: clock, NewID: nextKID,
	})
	must(err, "k7 res1 ap")
	registerTLS("k7-res1.example", k7Res1AP.Handler())

	k7TokenStore := &memoryTokenStore{}
	k7Revocations := testutil.NewAgentTokenRevocationStore()
	var k7ChainBindCalls atomic.Int32
	var k7ChainAuthCalls atomic.Int32
	var k7OrdinaryBindCalls atomic.Int32
	var k7SawUpstreamPersonAtBind atomic.Bool
	var k7SawUpstreamPersonAtAuth atomic.Bool

	k7PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:                k7PSIssuer,
		SigningKey:            k7PSKey,
		KeyResolver:           resolver,
		Clock:                 clock,
		NewID:                 nextKID,
		Tokens:                k7TokenStore,
		IssuedTokens:          testutil.NewIssuedAuthTokenStore(),
		AgentTokenRevocations: k7Revocations,
		BindPerson: func(_ context.Context, _ personserver.PersonTokenRequest) (personserver.Person, error) {
			k7OrdinaryBindCalls.Add(1)
			return personserver.Person{Subject: "k7-person-res1", Lifetime: 10 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 10 * time.Minute}, nil
		},
		CallChaining: &personserver.CallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				k7ChainBindCalls.Add(1)
				if req.Upstream == nil && req.UpstreamPerson != nil && req.UpstreamPerson.Subject == "k7-person-res1" {
					k7SawUpstreamPersonAtBind.Store(true)
				}
				return personserver.Person{Subject: "k7-person-res2", Lifetime: 30 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				k7ChainAuthCalls.Add(1)
				if req.Upstream == nil && req.UpstreamPerson != nil && req.UpstreamPerson.Subject == "k7-person-res1" {
					k7SawUpstreamPersonAtAuth.Store(true)
				}
				return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 20 * time.Minute}, nil
			},
		},
	})
	must(err, "k7 ps")
	registerTLS("k7-ps.example", k7PS.Handler())

	k7Res2, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer: k7Res2Issuer, SigningKey: k7Res2Key, KeyResolver: resolver, Clock: clock,
		NewID:             nextKID,
		ScopeDescriptions: map[string]string{"payments.charge": "Charge payment"},
		RequiredScopes:    func(*http.Request) []string { return []string{"payments.charge"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"charged":true}`))
		}),
	})
	must(err, "k7 res2")
	registerTLS("k7-res2.example", k7Res2.Handler())

	k7CallerAgentTok, err := k1AP.Issue(aauth.AgentTokenRequest{
		Agent: k7CallerID, PersonServer: k7PSIssuer, PublicKey: k1AgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k7 caller agent tok")
	k7CallerClaims, err := aauth.VerifyAgentToken(ctx, k7CallerAgentTok, resolver, clock)
	must(err, "verify k7CallerAgentTok")

	k7CallerCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k7CallerID, SigningKey: k1AgentKey, AgentToken: k7CallerAgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "k7 caller cli")
	k7UpstreamPTRes, err := k7CallerCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: k7PSIssuer, Resource: k7Res1Issuer,
	})
	must(err, "k7 upstream person token")
	k7UpstreamPT, _ := k7UpstreamPTRes.Token()
	k7UpstreamPTClaims, err := aauth.VerifyPersonToken(ctx, k7UpstreamPT, resolver, clock)
	must(err, "verify k7UpstreamPT")

	k7RelayAgentTok, err := k7Res1AP.Issue(aauth.AgentTokenRequest{
		Agent: k7RelayID, PersonServer: k7PSIssuer, PublicKey: k7RelayAgentKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "k7 relay agent tok")
	k7RelayCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier: k7RelayID, SigningKey: k7RelayAgentKey, AgentToken: k7RelayAgentTok,
		KeyResolver: resolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "k7 relay cli")

	// First verify whether agent.Client.PersonToken accepts UpstreamToken = PersonToken
	_, k7AgentClientUpstreamPTErr := k7RelayCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer:  k7PSIssuer,
		Resource:      k7Res2Issuer,
		UpstreamToken: k7UpstreamPT,
	})
	k7AgentClientErrMsg := ""
	if k7AgentClientUpstreamPTErr != nil {
		k7AgentClientErrMsg = k7AgentClientUpstreamPTErr.Error()
	}

	// Intermediary chains k7UpstreamPT at POST /person over HTTPS -> downstream PersonToken for k7-res2.example
	k7PersonBody, _ := json.Marshal(map[string]string{
		"resource":       k7Res2Issuer,
		"upstream_token": k7UpstreamPT,
	})
	k7PersonHTTPReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, k7PSIssuer+"/person", bytes.NewReader(k7PersonBody))
	k7PersonHTTPReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequest(k7PersonHTTPReq, k7RelayAgentKey, k7RelayAgentTok, clock), "sign k7PersonHTTPReq")
	k7PersonHTTPResp, err := httpClient.Do(k7PersonHTTPReq)
	must(err, "do k7PersonHTTPReq")
	var k7PersonOut struct {
		PersonToken string `json:"person_token"`
	}
	_ = json.NewDecoder(k7PersonHTTPResp.Body).Decode(&k7PersonOut)
	_ = k7PersonHTTPResp.Body.Close()
	k7DownstreamPT := k7PersonOut.PersonToken
	k7DownstreamPTClaims, err := aauth.VerifyPersonToken(ctx, k7DownstreamPT, resolver, clock)
	must(err, "verify k7DownstreamPT")
	k7DownstreamPTRecord, err := k7TokenStore.Load(ctx, k7PSIssuer, k7DownstreamPTClaims.JTI)
	must(err, "load k7DownstreamPTRecord")

	// Intermediary gets ResourceToken from k7-res2 and exchanges at POST /token with upstream_token = k7UpstreamPT
	k7Res2RT, err := k7RelayCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    k7Res2Issuer,
		PersonToken: k7DownstreamPT,
		Scopes:      []string{"payments.charge"},
	})
	must(err, "k7 authorize at res2")
	k7TokenBody, _ := json.Marshal(map[string]string{
		"resource_token":  k7Res2RT,
		"presented_token": k7DownstreamPT,
		"upstream_token":  k7UpstreamPT,
	})
	k7TokenHTTPReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, k7PSIssuer+"/token", bytes.NewReader(k7TokenBody))
	k7TokenHTTPReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequest(k7TokenHTTPReq, k7RelayAgentKey, k7RelayAgentTok, clock), "sign k7TokenHTTPReq")
	k7TokenHTTPResp, err := httpClient.Do(k7TokenHTTPReq)
	must(err, "do k7TokenHTTPReq")
	var k7TokenOut struct {
		AuthToken string `json:"auth_token"`
	}
	_ = json.NewDecoder(k7TokenHTTPResp.Body).Decode(&k7TokenOut)
	_ = k7TokenHTTPResp.Body.Close()
	k7DownstreamAuthTok := k7TokenOut.AuthToken
	k7DownstreamAuthClaims, err := aauth.VerifyAuthToken(ctx, k7DownstreamAuthTok, resolver, clock)
	must(err, "verify k7DownstreamAuthTok")

	k7Res2CallReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, k7Res2Issuer+"/charge", strings.NewReader(`{"amount":10}`))
	k7Res2CallReq.Header.Set("Content-Type", "application/json")
	k7Res2CallResp, err := k7RelayCli.Do(ctx, clientagent.Call{
		Request: k7Res2CallReq, AuthToken: k7DownstreamAuthTok,
	})
	must(err, "k7 call res2")
	_ = k7Res2CallResp.Body.Close()

	// Negative upstream PersonToken cases over HTTPS:
	doK7PersonReq := func(upstream string) (int, string) {
		b, _ := json.Marshal(map[string]string{
			"resource":       k7Res2Issuer,
			"upstream_token": upstream,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, k7PSIssuer+"/person", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignJWTRequest(req, k7RelayAgentKey, k7RelayAgentTok, clock), "sign k7 person req")
		resp, dErr := httpClient.Do(req)
		must(dErr, "do k7 person req")
		defer resp.Body.Close()
		var prob struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&prob)
		return resp.StatusCode, prob.Error
	}

	// 1. Other PS
	k7OtherPSPT, _ := aauth.MintPersonToken(k7OtherPSKey, aauth.PersonTokenClaims{
		Issuer: "https://k7-other-ps.example", DWK: aauth.PersonDiscoveryDocument, Audience: k7Res1Issuer,
		JTI: "k7-other-pt", Subject: "k7-person-res1",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(10 * time.Minute).Unix(),
	})
	k7OtherPSStatus, k7OtherPSErr := doK7PersonReq(k7OtherPSPT)

	// 2. Audience is not intermediary
	k7WrongAudPT, _ := aauth.MintPersonToken(k7PSKey, aauth.PersonTokenClaims{
		Issuer: k7PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k7Res2Issuer,
		JTI: "k7-wrong-aud-pt", Subject: "k7-person-res1",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(10 * time.Minute).Unix(),
	})
	k7WrongAudStatus, k7WrongAudErr := doK7PersonReq(k7WrongAudPT)

	// 3. Expired upstream PersonToken
	k7ExpPT, _ := aauth.MintPersonToken(k7PSKey, aauth.PersonTokenClaims{
		Issuer: k7PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k7Res1Issuer,
		JTI: "k7-exp-pt", Subject: "k7-person-res1",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Add(-20 * time.Minute).Unix(), ExpiresAt: nowTime.Add(-1 * time.Minute).Unix(),
	})
	k7ExpStatus, k7ExpErr := doK7PersonReq(k7ExpPT)

	// 4. No retained record in TokenStore
	k7UnrecordedPT, _ := aauth.MintPersonToken(k7PSKey, aauth.PersonTokenClaims{
		Issuer: k7PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k7Res1Issuer,
		JTI: "k7-unrecorded-pt", Subject: "k7-person-res1",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(10 * time.Minute).Unix(),
	})
	k7UnrecStatus, k7UnrecErr := doK7PersonReq(k7UnrecordedPT)

	// 5. Retained record has empty AgentTokenJTI
	k7NoAgJTIPT, _ := aauth.MintPersonToken(k7PSKey, aauth.PersonTokenClaims{
		Issuer: k7PSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: k7Res1Issuer,
		JTI: "k7-no-ag-jti-pt", Subject: "k7-person-res1",
		Confirmation: aauth.Confirmation{JWK: k1AgentKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(), ExpiresAt: nowTime.Add(10 * time.Minute).Unix(),
	})
	must(k7TokenStore.Commit(ctx, personserver.PersonTokenRecord{
		JTI: "k7-no-ag-jti-pt", PersonServer: k7PSIssuer, Resource: k7Res1Issuer,
		Subject: "k7-person-res1", AgentProvider: k1APIssuer, Agent: k7CallerID,
		Confirmation: k1AgentKey.PublicJWK(), AgentTokenJTI: "",
		ExpiresAt: nowTime.Add(10 * time.Minute), RetainUntil: nowTime.Add(time.Hour),
	}), "commit k7-no-ag-jti-pt")
	k7NoAgJTIStatus, k7NoAgJTIErr := doK7PersonReq(k7NoAgJTIPT)

	// 6. Calling Agent's AgentToken is revoked in AgentTokenRevocations
	must(k7Revocations.Revoke(ctx, aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: k1APIssuer, JTI: k7CallerClaims.JTI},
		ExpiresAt: time.Unix(k7CallerClaims.ExpiresAt, 0).UTC(),
	}), "revoke k7 caller agent token")
	k7RevokedStatus, k7RevokedErr := doK7PersonReq(k7UpstreamPT)

	return map[string]any{
		"k1": map[string]any{
			"res_addr":                  k1ResSrv.Listener.Addr().String(),
			"res_cert_hex":              hex.EncodeToString(k1ResDER),
			"ag_challenge_status":       k1AgStatus,
			"ag_challenge_req":          k1AgReq,
			"ag_challenge_sig_err":      k1AgSigErr,
			"auth_challenge_status":     k1AuthStatus,
			"auth_challenge_req":        k1AuthReq,
			"auth_challenge_sig_err":    k1AuthSigErr,
			"unsigned_challenge_status": k1UnsignedStatus,
			"unsigned_challenge_req":    k1UnsignedReq,
			"unsigned_challenge_sig":    k1UnsignedSigErr,
			"issued_after_challenges":   k1IssuedAfterChallenges,
			"miss_sig_status":           k1MissSigStatus,
			"miss_sig_err":              k1MissSigErr,
			"miss_input_status":         k1MissInputStatus,
			"miss_input_err":            k1MissInputErr,
			"miss_key_status":           k1MissKeyStatus,
			"miss_key_err":              k1MissKeyErr,
			"prot_miss_sig_status":      k1ProtResp.StatusCode,
			"prot_miss_sig_err":         k1ProtResp.Header.Get("Signature-Error"),
			"ps_miss_input_status":      k1PSMissResp.StatusCode,
			"ps_miss_input_err":         k1PSMissResp.Header.Get("Signature-Error"),
			"wrong_key_ag_status":       k1WrongKeyAgStatus,
			"wrong_key_ag_req":          k1WrongKeyAgReq,
			"wrong_key_ag_sig_err":      k1WrongKeyAgSigErr,
			"exp_pt_status":             k1ExpPTStatus,
			"exp_pt_req":                k1ExpPTReq,
			"exp_pt_sig_err":            k1ExpPTSigErr,
			"wrong_key_pt_status":       k1WrongKeyPTStatus,
			"wrong_key_pt_req":          k1WrongKeyPTReq,
			"wrong_key_pt_sig_err":      k1WrongKeyPTSigErr,
			"valid_pt_status":           k1ValidPTStatus,
			"valid_pt_sig_err":          k1ValidPTSigErr,
			"valid_pt_rt_ok":            k1RTVerifyErr == nil && k1RTClaims.Scope == "records.read",
			"caps_unknown_params_ok":    k1CapsErr == nil && slices.Equal(k1Caps, []string{"interaction", "clarification"}),
		},
		"k2": map[string]any{
			"no_presentation_store_refused": k2NoPresentationStoreErr != nil && strings.Contains(k2NoPresentationStoreErr.Error(), "PersonTokenPresentationStore"),
			"before_presentations":          k2BeforePresentations,
			"ex1_status":                    k2Ex1Status,
			"ex2_status":                    k2Ex2Status,
			"recorded_at_as1_send":          k2RecordedAtAS1Send,
			"after_as1_presentations":       k2AfterAS1Presentations,
			"ex3_status":                    k2Ex3Status,
			"after_as2_presentations":       k2AfterAS2Presentations,
			"fail_pres_status":              k2FailPresStatus,
			"fail_pres_as_not_called":       k2AS1AfterFail == k2AS1BeforeFail,
			"exp_pt_status":                 k2ExpAStatus,
			"exp_pt_error":                  k2ExpABody["error"],
			"exp_pt_as_not_called":          k2ASCallsAfterExpA == k2ASCallsBeforeExpA && len(k2ExpAPresentations) == 0,
			"exp_rt_status":                 k2ExpBStatus,
			"exp_rt_error":                  k2ExpBBody["error"],
			"exp_rt_as_not_called":          k2ASCallsAfterExpB == k2ASCallsBeforeExpB && len(k2ExpBPresentations) == 0,
			"curr_after_consent_status":     k2CurrCStatus,
			"curr_after_consent_has_token":  k2CurrCBody["auth_token"] != nil && slices.Equal(k2CurrCPresentations, []string{k2AS1Issuer}),
		},
		"k3": map[string]any{
			"max_attempts_const":            personserver.MaximumPersonTokenCodeAttempts,
			"flow1_attempt1_invalid":        errors.Is(k3F1Attempt1Err, personserver.ErrInteractionCodeInvalid),
			"flow1_attempt2_invalid":        errors.Is(k3F1Attempt2Err, personserver.ErrInteractionCodeInvalid),
			"flow1_attempt3_approved_token": k3Tok1OK && k3Tok1 != "",
			"flow2_attempt1_invalid":        errors.Is(k3F2Attempt1Err, personserver.ErrInteractionCodeInvalid) && k3MidPoll1Pending,
			"flow2_attempt2_invalid":        errors.Is(k3F2Attempt2Err, personserver.ErrInteractionCodeInvalid) && k3MidPoll2Pending,
			"flow2_attempt3_gone":           errors.Is(k3F2Attempt3Err, personserver.ErrPendingPersonTokenGone),
			"flow2_attempt4_valid_refused":  errors.Is(k3F2Attempt4ValidCodeErr, personserver.ErrPendingPersonTokenGone),
			"flow2_poll_status":             k3FinalProblemStatus,
			"flow2_poll_error":              k3FinalProblemCode,
		},
		"k4": map[string]any{
			"all_non_public_denied":    k4AllDenied,
			"total_dials_on_denied":    k4TotalDials,
			"denied_matrix":            k4DeniedResults,
			"literal_loopback_denied":  k4LiteralDeniedOK,
			"custom_rt_rejected":       k4CustomRTErr != nil,
			"proxy_transport_rejected": k4ProxyErr != nil,
			"pinned_dial_ok":           k4PinnedDialOK,
			"dialed_addrs":             k4DialedAddrs,
			"dns_rebind_refused_ok":    k4RebindRefusedOK,
		},
		"k5": map[string]any{
			"auth_initial_sec":     k5AuthInitialSec,
			"auth_observed_sec":    k5AuthObservedSec,
			"auth_terminal_status": k5AuthTerminalStatus,
			"auth_person_req_ok":   k5AuthPersonReqOK,
			"r3_initial_sec":       k5R3InitialSec,
			"r3_observed_sec":      k5R3ObservedSec,
			"r3_terminal_status":   k5R3TerminalStatus,
			"r3_person_req_ok":     k5R3PersonReqOK,
			"reauthorize_ok":       k5ReauthOK && k5ReauthVerifyErr == nil && k5ReauthClaims.Confirmation.JWK.Equal(k5RotatedKey.PublicJWK()),
		},
		"k6": map[string]any{
			"has_approver_field":      k6HasApproverField,
			"rust_mission_decoded_ok": k6RustDecodeErr == nil && k6RustDecoded.Blob.Agent == "aauth:k1-agent@k1-ap.example",
			"legacy_with_approver_ok": k6WithApproverErr == nil && string(k6WithApproverDecoded.ExactJSON) == string(k6WithApproverRaw),
			"go_encoded_has_approver": k6EncodedHasApprover,
			"go_mission_s256":         k6ApprovedMission.S256,
			"go_mission_exact_json":   string(k6ApprovedMission.ExactJSON),
			"go_mission_call_status":  k6CallResp.StatusCode,
		},
		"k7": map[string]any{
			"agent_client_upstream_pt_err":  k7AgentClientErrMsg,
			"person_status":                 k7PersonHTTPResp.StatusCode,
			"token_status":                  k7TokenHTTPResp.StatusCode,
			"chain_bind_calls":              k7ChainBindCalls.Load(),
			"chain_auth_calls":              k7ChainAuthCalls.Load(),
			"ordinary_bind_calls":           k7OrdinaryBindCalls.Load(),
			"saw_upstream_person_at_bind":   k7SawUpstreamPersonAtBind.Load(),
			"saw_upstream_person_at_auth":   k7SawUpstreamPersonAtAuth.Load(),
			"downstream_pt_clamped_exp":     k7DownstreamPTClaims.ExpiresAt == k7UpstreamPTClaims.ExpiresAt,
			"downstream_pt_record_ag_jti":   k7DownstreamPTRecord.AgentTokenJTI != "" && k7DownstreamPTRecord.UpstreamTokenReference == (aauth.TokenReference{Issuer: k7PSIssuer, JTI: k7UpstreamPTClaims.JTI}),
			"downstream_auth_clamped_exp":   k7DownstreamAuthClaims.ExpiresAt == k7UpstreamPTClaims.ExpiresAt,
			"res2_call_status":              k7Res2CallResp.StatusCode,
			"neg_other_ps":                  k7OtherPSStatus == 400 && k7OtherPSErr == "invalid_upstream_token",
			"neg_wrong_aud":                 k7WrongAudStatus == 400 && k7WrongAudErr == "invalid_upstream_token",
			"neg_expired":                   k7ExpStatus == 400 && k7ExpErr == "expired_upstream_token",
			"neg_unrecorded":                k7UnrecStatus == 400 && k7UnrecErr == "invalid_upstream_token",
			"neg_missing_agent_token_jti":   k7NoAgJTIStatus == 400 && k7NoAgJTIErr == "invalid_upstream_token",
			"neg_revoked_calling_agent_tok": k7RevokedStatus == 400 && k7RevokedErr == "revoked_upstream_token",
		},
	}
}
