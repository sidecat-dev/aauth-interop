package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	apstoretest "gitlab.com/sidecat-dev/aauth-go/agentprovider/storetest"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/events"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type pSuiteInput struct {
	RustDirectPSIssuer string `json:"rust_direct_ps_issuer"`
	RustInitResIssuer  string `json:"rust_init_res_issuer"`
	RustLinkResIssuer  string `json:"rust_link_res_issuer"`
	RustUsageResIssuer string `json:"rust_usage_res_issuer"`
	RustFedPSIssuer    string `json:"rust_fed_ps_issuer"`
	RustFedASIssuer    string `json:"rust_fed_as_issuer"`
	RustFedResIssuer   string `json:"rust_fed_res_issuer"`
}

type pNonReadableInboxStore struct{}

func (pNonReadableInboxStore) CommitSubscription(context.Context, agentprovider.EventSubscription) error {
	return nil
}

func (pNonReadableInboxStore) AcceptEvent(context.Context, agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	return agentprovider.EventAcceptance{}, nil
}

// pReadableInboxStore implements agentprovider.EventInboxStore and agentprovider.EventInboxReader.
type pReadableInboxStore struct {
	mu           sync.Mutex
	byFP         map[events.DeliveryFingerprint]agentprovider.EventDelivery
	acknowledged map[events.DeliveryFingerprint]bool
	order        []events.DeliveryFingerprint
	tamperAgent  string
	tamperMode   string
}

func newPReadableInboxStore() *pReadableInboxStore {
	return &pReadableInboxStore{
		byFP:         make(map[events.DeliveryFingerprint]agentprovider.EventDelivery),
		acknowledged: make(map[events.DeliveryFingerprint]bool),
	}
}

func clonePEventDelivery(d agentprovider.EventDelivery) agentprovider.EventDelivery {
	d.Payload = append([]byte(nil), d.Payload...)
	return d
}

func (s *pReadableInboxStore) CommitSubscription(_ context.Context, _ agentprovider.EventSubscription) error {
	return nil
}

func (s *pReadableInboxStore) AcceptEvent(_ context.Context, d agentprovider.EventDelivery) (agentprovider.EventAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byFP[d.Fingerprint]; ok {
		if existing.Agent == d.Agent && existing.TokenSHA256 == d.TokenSHA256 &&
			existing.PayloadSHA256 == d.PayloadSHA256 && existing.Fingerprint == d.Fingerprint {
			return agentprovider.EventAcceptance{Duplicate: true}, nil
		}
		return agentprovider.EventAcceptance{}, agentprovider.ErrEventDeliveryConflict
	}
	s.byFP[d.Fingerprint] = clonePEventDelivery(d)
	s.order = append(s.order, d.Fingerprint)
	return agentprovider.EventAcceptance{}, nil
}

func (s *pReadableInboxStore) PendingEvents(_ context.Context, agent string) ([]agentprovider.EventDelivery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []agentprovider.EventDelivery
	for _, fp := range s.order {
		if s.acknowledged[fp] {
			continue
		}
		d := s.byFP[fp]
		if d.Agent != agent && !(s.tamperAgent == agent && s.tamperMode == "agent") {
			continue
		}
		cp := clonePEventDelivery(d)
		if s.tamperAgent == agent {
			switch s.tamperMode {
			case "payload":
				cp.Payload = append(cp.Payload, '!')
			case "token":
				cp.Token = cp.Token + "x"
			case "agent":
				cp.Agent = "aauth:other@other.example"
			}
		}
		out = append(out, cp)
	}
	return out, nil
}

func (s *pReadableInboxStore) AcknowledgeEvent(_ context.Context, agent string, fp events.DeliveryFingerprint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.byFP[fp]; ok && d.Agent == agent {
		s.acknowledged[fp] = true
	}
	return nil
}
// pHeldBudgetEntry holds one pending/executing/complete invocation.
type pHeldBudgetEntry struct {
	invocation   resource.HeldInvocation
	state        string
	token        resource.HeldAuthToken
	response     resource.HeldResponse
	fence        string
	rechallenges int
}

type pHeldBudgetStore struct {
	mu      sync.Mutex
	nextSeq int
	entries map[string]*pHeldBudgetEntry
}

func newPHeldBudgetStore() *pHeldBudgetStore {
	return &pHeldBudgetStore{entries: make(map[string]*pHeldBudgetEntry)}
}

func clonePHeldResponse(r resource.HeldResponse) resource.HeldResponse {
	r.Header = r.Header.Clone()
	r.Body = append([]byte(nil), r.Body...)
	r.Trailer = r.Trailer.Clone()
	return r
}

func clonePHeldInvocation(inv resource.HeldInvocation) resource.HeldInvocation {
	inv.Header = inv.Header.Clone()
	inv.Body = append([]byte(nil), inv.Body...)
	inv.RequiredScopes = append([]string(nil), inv.RequiredScopes...)
	if inv.Budget != nil {
		b := *inv.Budget
		inv.Budget = &b
	}
	if inv.R3PerCall != nil {
		c := *inv.R3PerCall
		c.ExactProposal = append([]byte(nil), inv.R3PerCall.ExactProposal...)
		if c.Release != nil {
			rel := clonePHeldResponse(*c.Release)
			c.Release = &rel
		}
		inv.R3PerCall = &c
	}
	return inv
}

func (s *pHeldBudgetStore) Create(_ context.Context, inv resource.HeldInvocation) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSeq++
	id := "p-held-" + strconvItoa(int64(s.nextSeq)) + "-0123456789abcdef"
	s.entries[id] = &pHeldBudgetEntry{
		invocation: clonePHeldInvocation(inv),
		state:      "pending",
	}
	return id, nil
}

func (s *pHeldBudgetStore) Load(_ context.Context, id string) (resource.HeldInvocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return resource.HeldInvocation{}, resource.ErrHeldInvocationNotFound
	}
	return clonePHeldInvocation(e.invocation), nil
}

func (s *pHeldBudgetStore) Claim(_ context.Context, id string, token resource.HeldAuthToken) (resource.HeldClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return resource.HeldClaim{}, resource.ErrHeldInvocationNotFound
	}
	switch e.state {
	case "complete":
		if e.token.SHA256 != token.SHA256 {
			return resource.HeldClaim{}, resource.ErrHeldAuthTokenMismatch
		}
		return resource.NewHeldReplay(clonePHeldResponse(e.response)), nil
	case "expired":
		return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
	case "executing":
		return resource.HeldClaim{}, resource.ErrHeldInvocationConflict
	case "pending":
		if !token.PresentedAt.Before(e.invocation.CompletionUntil) {
			e.state = "expired"
			return resource.HeldClaim{}, resource.ErrHeldInvocationExpired
		}
		e.state = "executing"
		e.token = token
		e.fence = "fence-" + id
		return resource.NewHeldExecution(resource.HeldExecution{InvocationID: id, Fence: e.fence}), nil
	default:
		return resource.HeldClaim{}, resource.ErrHeldExecutionUnresolved
	}
}

func (s *pHeldBudgetStore) Retain(_ context.Context, exec resource.HeldExecution, resp resource.HeldResponse) (resource.HeldResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[exec.InvocationID]
	if !ok || e.state != "executing" || e.fence != exec.Fence {
		return resource.HeldResponse{}, resource.ErrHeldCompletionStale
	}
	e.response = clonePHeldResponse(resp)
	e.state = "complete"
	return clonePHeldResponse(e.response), nil
}

func (s *pHeldBudgetStore) Rechallenge(_ context.Context, id string, ch resource.HeldRechallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return resource.ErrHeldInvocationNotFound
	}
	switch e.state {
	case "pending":
	case "complete":
		return resource.ErrHeldAuthTokenMismatch
	case "expired":
		return resource.ErrHeldInvocationExpired
	default:
		return resource.ErrHeldInvocationConflict
	}
	if e.invocation.ResourceToken != ch.Previous {
		return resource.ErrHeldInvocationConflict
	}
	e.rechallenges++
	e.invocation.ResourceToken = ch.ResourceToken
	e.invocation.ResourceTokenIssuedAt = ch.ResourceTokenIssuedAt
	e.invocation.ExpiresAt = ch.ExpiresAt
	e.invocation.CompletionUntil = ch.CompletionUntil
	return nil
}
type pTokenLedger struct {
	grant        budgets.Value
	personServer string
	subject      string
	audience     string
	consumed     int64
	holds        map[string]int64
}

type pBudgetReserverStore struct {
	mu           sync.Mutex
	unit         budgets.Unit
	tokens       map[aauth.TokenReference]*pTokenLedger
	personLedger map[string]int64
	jktSpend     map[string]int64
}

func newPBudgetReserverStore(unit budgets.Unit) *pBudgetReserverStore {
	return &pBudgetReserverStore{
		unit:         unit,
		tokens:       make(map[aauth.TokenReference]*pTokenLedger),
		personLedger: make(map[string]int64),
		jktSpend:     make(map[string]int64),
	}
}

func (s *pBudgetReserverStore) getOrCreateLocked(tok aauth.TokenReference, ps, sub, aud string, grant budgets.Value) (*pTokenLedger, error) {
	tl, ok := s.tokens[tok]
	if !ok {
		tl = &pTokenLedger{
			grant:        grant,
			personServer: ps,
			subject:      sub,
			audience:     aud,
			holds:        make(map[string]int64),
		}
		s.tokens[tok] = tl
		return tl, nil
	}
	if tl.grant != grant || tl.personServer != ps || tl.subject != sub || tl.audience != aud {
		return nil, resource.ErrBudgetConflict
	}
	return tl, nil
}

func (s *pBudgetReserverStore) totalHeldLocked(tl *pTokenLedger) int64 {
	var total int64
	for _, h := range tl.holds {
		total += h
	}
	return total
}

func (s *pBudgetReserverStore) Charge(_ context.Context, ch resource.BudgetCharge) (resource.BudgetChargeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tl, err := s.getOrCreateLocked(ch.Token, ch.PersonServer, ch.Subject, ch.Audience, ch.Grant)
	if err != nil {
		return resource.BudgetChargeResult{}, err
	}
	held := s.totalHeldLocked(tl)
	rem := tl.grant.Amount() - tl.consumed - held
	if ch.Cost == 0 {
		if rem <= 0 {
			return resource.BudgetChargeResult{Cost: 0, Remaining: 0, Consumed: tl.consumed}, resource.ErrBudgetExhausted
		}
		return resource.BudgetChargeResult{Cost: 0, Remaining: rem, Consumed: tl.consumed}, nil
	}
	if rem <= 0 {
		return resource.BudgetChargeResult{Remaining: 0, Consumed: tl.consumed}, resource.ErrBudgetExhausted
	}
	if ch.Cost > rem {
		return resource.BudgetChargeResult{Remaining: rem, Consumed: tl.consumed}, resource.ErrBudgetInsufficient
	}
	tl.consumed += ch.Cost
	s.personLedger[ch.PersonServer+"\x00"+ch.Subject+"\x00"+ch.Audience] += ch.Cost
	if ch.AgentJKT != "" {
		s.jktSpend[ch.AgentJKT] += ch.Cost
	}
	return resource.BudgetChargeResult{
		Cost:      ch.Cost,
		Remaining: tl.grant.Amount() - tl.consumed - held,
		Consumed:  tl.consumed,
	}, nil
}

func (s *pBudgetReserverStore) Reserve(_ context.Context, r resource.BudgetReserve) (resource.BudgetReserveResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tl, err := s.getOrCreateLocked(r.Token, r.PersonServer, r.Subject, r.Audience, r.Grant)
	if err != nil {
		return resource.BudgetReserveResult{}, err
	}
	if _, exists := tl.holds[r.ID]; exists {
		return resource.BudgetReserveResult{}, resource.ErrBudgetReservation
	}
	held := s.totalHeldLocked(tl)
	rem := tl.grant.Amount() - tl.consumed - held
	if rem <= 0 {
		return resource.BudgetReserveResult{Remaining: 0, Consumed: tl.consumed}, resource.ErrBudgetExhausted
	}
	if r.Hold > rem {
		return resource.BudgetReserveResult{Remaining: rem, Consumed: tl.consumed}, resource.ErrBudgetInsufficient
	}
	tl.holds[r.ID] = r.Hold
	return resource.BudgetReserveResult{
		Reserved:  r.Hold,
		Remaining: rem - r.Hold,
		Consumed:  tl.consumed,
	}, nil
}

func (s *pBudgetReserverStore) Commit(_ context.Context, c resource.BudgetCommit) (resource.BudgetChargeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tl, ok := s.tokens[c.Token]
	if !ok {
		return resource.BudgetChargeResult{}, resource.ErrBudgetReservation
	}
	hold, exists := tl.holds[c.ID]
	if !exists || c.Cost < 0 || c.Cost > hold {
		return resource.BudgetChargeResult{}, resource.ErrBudgetReservation
	}
	delete(tl.holds, c.ID)
	tl.consumed += c.Cost
	s.personLedger[tl.personServer+"\x00"+tl.subject+"\x00"+tl.audience] += c.Cost
	held := s.totalHeldLocked(tl)
	return resource.BudgetChargeResult{
		Cost:      c.Cost,
		Remaining: tl.grant.Amount() - tl.consumed - held,
		Consumed:  tl.consumed,
	}, nil
}

func (s *pBudgetReserverStore) Release(_ context.Context, r resource.BudgetRelease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tl, ok := s.tokens[r.Token]
	if !ok {
		return resource.ErrBudgetReservation
	}
	if _, exists := tl.holds[r.ID]; !exists {
		return resource.ErrBudgetReservation
	}
	delete(tl.holds, r.ID)
	return nil
}

func (s *pBudgetReserverStore) QueryUsage(_ context.Context, q resource.BudgetUsageQuery) (resource.BudgetUsageResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ps := q.Caller.Identifier
	if q.PersonServer != "" {
		ps = q.PersonServer
	}
	var total int64
	for k, v := range s.personLedger {
		parts := strings.Split(k, "\x00")
		if len(parts) == 3 && parts[0] == ps && (q.Subject == "" || parts[1] == q.Subject) {
			total += v
		}
	}
	if total == 0 {
		total = 7
	}
	jkts := make(map[string]int64)
	for _, j := range q.JKTs {
		if sp, ok := s.jktSpend[j]; ok {
			jkts[j] = sp
		} else {
			jkts[j] = 7
		}
	}
	return resource.BudgetUsageResult{
		Unit:            s.unit,
		HasUnit:         true,
		ScopeRecognized: true,
		AllTime:         total,
		AllTimeOK:       true,
		Day:             total,
		DayOK:           true,
		JKTs:            jkts,
	}, nil
}
type pAuthTokenStatusEntry struct {
	sha256  [32]byte
	hasSHA  bool
	revoked bool
}

type pAuthTokenStatusStore struct {
	mu      sync.Mutex
	entries map[aauth.TokenReference]*pAuthTokenStatusEntry
}

func newPAuthTokenStatusStore() *pAuthTokenStatusStore {
	return &pAuthTokenStatusStore{entries: make(map[aauth.TokenReference]*pAuthTokenStatusEntry)}
}

func (s *pAuthTokenStatusStore) Observe(_ context.Context, obs resource.ObservedAuthToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[obs.Reference]
	if !ok {
		s.entries[obs.Reference] = &pAuthTokenStatusEntry{sha256: obs.CompactSHA256, hasSHA: true}
		return nil
	}
	if e.hasSHA && e.sha256 != obs.CompactSHA256 {
		return resource.ErrAuthTokenConflict
	}
	e.sha256 = obs.CompactSHA256
	e.hasSHA = true
	if e.revoked {
		return resource.ErrAuthTokenRevoked
	}
	return nil
}

func (s *pAuthTokenStatusStore) Revoke(_ context.Context, req aauth.RevocationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[req.Reference]
	if !ok {
		s.entries[req.Reference] = &pAuthTokenStatusEntry{revoked: true}
		return nil
	}
	e.revoked = true
	return nil
}

func runPSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in pSuiteInput,
) map[string]any {
	nowTime := clock.Now().UTC().Truncate(time.Second)

	if baseTr, ok := httpClient.Transport.(*http.Transport); ok {
		tr := baseTr.Clone()
		tr.DisableKeepAlives = false
		defer tr.CloseIdleConnections()
		cCopy := *httpClient
		cCopy.Transport = tr
		httpClient = &cCopy
	}

	newPKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var pIDSeq atomic.Int64
	nextPID := func() string {
		return "p-go-id-" + strconvItoa(pIDSeq.Add(1))
	}

	pResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver pResolver")

	// =========================================================================
	// QA-P1: Resource-Initiated Interaction (3-Party), Callbacks & Cross-Language
	// =========================================================================
	const (
		p1GoAPIssuer   = "https://p1-go-ap.example"
		p1GoAgentID    = "aauth:reader@p1-go-ap.example"
		p1GoPSIssuer   = "https://p1-go-ps.example"
		p1GoResIssuer  = "https://p1-go-res.example"
		p1GoRes2Issuer = "https://p1-go-res2.example"
		p1AgentCb      = "https://p1-go-ap.example/callback/flow-1"
	)
	p1APKey := newPKey("p1-ap-1", 0xb1)
	p1AgentKey := newPKey("p1-agent-1", 0xb2)
	p1PSKey := newPKey("p1-ps-1", 0xb3)
	p1ResKey := newPKey("p1-res-1", 0xb4)
	p1Res2Key := newPKey("p1-res2-1", 0xb5)

	p1AP, err := agentprovider.New(agentprovider.Config{
		Issuer:           p1GoAPIssuer,
		SigningKey:       p1APKey,
		Clock:            clock,
		NewID:            nextPID,
		CallbackEndpoint: p1GoAPIssuer + "/callback",
	})
	must(err, "agentprovider.New p1AP")
	p1APSrv, p1APDER := registerTLS("p1-go-ap.example", p1AP.Handler())

	var p1RefuseEgress atomic.Bool
	var p1AdmittedURLs []string
	var p1AdmitMu sync.Mutex
	p1PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      p1GoPSIssuer,
		SigningKey:  p1PSKey,
		KeyResolver: pResolver,
		Clock:       clock,
		Tokens:      &memoryTokenStore{},
		NewID:       nextPID,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-p1", Lifetime: 20 * time.Minute}, nil
		},
		AuthorizationInteractions: testutil.NewDeferredAuthorizationStore(),
		TokenRevocation:           &personserver.TokenRevocationConfig{Revocations: testutil.NewTokenRevocationStore()},
		ResourceInteraction: &personserver.ResourceInteractionConfig{
			Policy: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, error) {
				return personserver.AuthorizationInteractionPolicy{
					URL:      p1GoPSIssuer + "/consent",
					Lifetime: 4 * time.Minute,
				}, nil
			},
			CallbackURL: p1GoPSIssuer + "/from-resource",
			Admit: func(_ context.Context, endpoint string) error {
				p1AdmitMu.Lock()
				p1AdmittedURLs = append(p1AdmittedURLs, endpoint)
				p1AdmitMu.Unlock()
				if p1RefuseEgress.Load() {
					return errors.New("egress refused")
				}
				return nil
			},
		},
	})
	must(err, "personserver.NewPSAuthorization p1PS")
	p1PSMux := http.NewServeMux()
	p1PSMux.HandleFunc("GET /consent/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		visit, vErr := aauth.ParseInteractionVisit(r.URL.RawQuery, aauth.InteractionVisitOptions{})
		if vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
		inter, cErr := p1PS.ConsumeAuthorizationInteractionCode(r.Context(), ref, visit.Code)
		if cErr != nil {
			http.Error(w, cErr.Error(), http.StatusBadRequest)
			return
		}
		redirectURL, rErr := p1PS.RedirectToResourceInteraction(r.Context(), inter, visit.Callback)
		if rErr != nil {
			http.Error(w, rErr.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"redirect_url": redirectURL,
			"reference":    ref,
		})
	})
	p1PSMux.HandleFunc("GET /from-resource/{ref}/{flow}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		flow := r.PathValue("flow")
		afterRes, cbErr := p1PS.ReceiveResourceInteractionCallback(r.Context(), ref, flow, r.URL.RawQuery)
		if cbErr != nil {
			back, _ := p1PS.AuthorizationCallbackURL(r.Context(), ref)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"approved":       false,
				"callback_error": cbErr.Error(),
				"agent_callback": back,
			})
			return
		}
		decErr := p1PS.ApproveAuthorizationInteraction(r.Context(), afterRes, personserver.AuthorizationDecision{
			Scopes:   []string{"calendar.read"},
			Lifetime: 10 * time.Minute,
		})
		if decErr != nil {
			http.Error(w, decErr.Error(), http.StatusConflict)
			return
		}
		back, _ := p1PS.AuthorizationCallbackURL(r.Context(), ref)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"approved":       true,
			"agent_callback": back,
		})
	})
	p1PSMux.Handle("/", p1PS.Handler())
	p1PSSrv, p1PSDER := registerTLS("p1-go-ps.example", p1PSMux)

	var p1ResServed atomic.Int64
	p1Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            p1GoResIssuer,
		SigningKey:        p1ResKey,
		KeyResolver:       pResolver,
		Clock:             clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"calendar.read": "Read your calendar"},
		RequiredScopes:    func(*http.Request) []string { return []string{"calendar.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Revocation: &resource.RevocationConfig{
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
		},
		InitiatedInteraction: &resource.InitiatedInteractionConfig{
			URL: p1GoResIssuer + "/connect",
			Require: func(_ context.Context, req resource.InitiatedInteractionRequest) (bool, error) {
				return req.Person.Subject != "", nil
			},
			Store: testutil.NewInitiatedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p1ResServed.Add(1)
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"subject": p.Subject,
				"served":  p1ResServed.Load(),
			})
		}),
	})
	must(err, "resource.NewPSAuthorization p1Res")
	p1ResMux := http.NewServeMux()
	p1ResMux.HandleFunc("GET /connect/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		visit, vErr := aauth.ParseInteractionVisit(r.URL.RawQuery, aauth.InteractionVisitOptions{})
		if vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
		inter, cErr := p1Res.ConsumeInitiatedInteraction(r.Context(), ref, visit)
		if cErr != nil {
			http.Error(w, cErr.Error(), http.StatusBadRequest)
			return
		}
		compURL, uErr := inter.CompletionURL()
		must(uErr, "p1Res CompletionURL")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"completion_url": compURL,
			"person_issuer":  inter.Person().Issuer,
			"person_subject": inter.Person().Subject,
		})
	})
	p1ResMux.Handle("/", p1Res.Handler())
	p1ResSrv, p1ResDER := registerTLS("p1-go-res.example", p1ResMux)

	// p1Res2: Go Resource with InitiatedInteraction using NewPSAuthorization as well, for Rust Direct PS cross-language test
	var p1Res2Served atomic.Int64
	p1Res2, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            p1GoRes2Issuer,
		SigningKey:        p1Res2Key,
		KeyResolver:       pResolver,
		Clock:             clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"calendar.read": "Read your calendar"},
		RequiredScopes:    func(*http.Request) []string { return []string{"calendar.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		InitiatedInteraction: &resource.InitiatedInteractionConfig{
			URL: p1GoRes2Issuer + "/connect",
			Require: func(_ context.Context, req resource.InitiatedInteractionRequest) (bool, error) {
				return req.Person.Subject != "", nil
			},
			Store: testutil.NewInitiatedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p1Res2Served.Add(1)
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"subject": p.Subject,
				"served":  p1Res2Served.Load(),
			})
		}),
	})
	must(err, "resource.NewPersonConsent p1Res2")
	p1Res2Mux := http.NewServeMux()
	p1Res2Mux.HandleFunc("GET /connect/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		visit, vErr := aauth.ParseInteractionVisit(r.URL.RawQuery, aauth.InteractionVisitOptions{})
		if vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
		inter, cErr := p1Res2.ConsumeInitiatedInteraction(r.Context(), ref, visit)
		if cErr != nil {
			http.Error(w, cErr.Error(), http.StatusBadRequest)
			return
		}
		compURL, uErr := inter.CompletionURL()
		must(uErr, "p1Res2 CompletionURL")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"completion_url": compURL,
			"person_issuer":  inter.Person().Issuer,
			"person_subject": inter.Person().Subject,
		})
	})
	p1Res2Mux.Handle("/", p1Res2.Handler())
	p1Res2Srv, p1Res2DER := registerTLS("p1-go-res2.example", p1Res2Mux)
	p1AgentTok, err := p1AP.Issue(aauth.AgentTokenRequest{
		Agent:        p1GoAgentID,
		PersonServer: p1GoPSIssuer,
		PublicKey:    p1AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "p1AP.Issue")
	p1Cli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  p1GoAgentID,
		SigningKey:  p1AgentKey,
		AgentToken:  p1AgentTok,
		KeyResolver: pResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	must(err, "clientagent.New p1Cli")

	p1BeginAt := func(resIssuer string) (clientagent.PendingExchange, aauth.ResourceTokenClaims, string, string) {
		ptRes, bErr := p1Cli.PersonToken(ctx, clientagent.PersonTokenRequest{
			PersonServer: p1GoPSIssuer,
			Resource:     resIssuer,
		})
		must(bErr, "p1Cli.PersonToken")
		pt, _ := ptRes.Token()
		rt, bErr := p1Cli.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource:    resIssuer,
			PersonToken: pt,
			Scopes:      []string{"calendar.read"},
		})
		must(bErr, "p1Cli.Authorize")
		rtClaims, bErr := aauth.VerifyResourceToken(ctx, rt, pResolver, clock)
		must(bErr, "VerifyResourceToken p1")
		exRes, bErr := p1Cli.BeginExchange(ctx, clientagent.ExchangeRequest{
			PersonServer:   p1GoPSIssuer,
			ResourceToken:  rt,
			PresentedToken: pt,
			Capabilities:   []string{"interaction"},
		})
		must(bErr, "p1Cli.BeginExchange")
		pend, ok := exRes.Pending()
		if !ok {
			panic("p1 BeginExchange did not return pending")
		}
		return pend, rtClaims, rt, pt
	}

	// 1. Go-to-Go Happy Path + early consent guard + forged callback guard
	p1Pend1, p1RTClaims1, p1RT1, p1PT1 := p1BeginAt(p1GoResIssuer)
	_, p1ImmErr := p1Cli.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   p1GoPSIssuer,
		ResourceToken:  p1RT1,
		PresentedToken: p1PT1,
		Capabilities:   []string{"interaction"},
	})
	p1VisitURL1, err := aauth.FormatInteractionVisitURL(p1Pend1.InteractionURL(), p1Pend1.InteractionCode(), p1AgentCb)
	must(err, "FormatInteractionVisitURL p1")
	p1ParsedVisit1, _ := url.Parse(p1VisitURL1)
	p1Visit1, _ := aauth.ParseInteractionVisit(p1ParsedVisit1.RawQuery, aauth.InteractionVisitOptions{})
	p1Ref1 := strings.TrimPrefix(p1ParsedVisit1.Path, "/consent/")
	p1Consent1, err := p1PS.ConsumeAuthorizationInteractionCode(ctx, p1Ref1, p1Visit1.Code)
	must(err, "ConsumeAuthorizationInteractionCode p1")
	p1Dec := personserver.AuthorizationDecision{Scopes: []string{"calendar.read"}, Lifetime: 10 * time.Minute}
	p1EarlyApproveErr := p1PS.ApproveAuthorizationInteraction(ctx, p1Consent1, p1Dec)
	p1Redirect1, err := p1PS.RedirectToResourceInteraction(ctx, p1Consent1, p1Visit1.Callback)
	must(err, "RedirectToResourceInteraction p1")
	_, p1SecondRedirectErr := p1PS.RedirectToResourceInteraction(ctx, p1Consent1, "")
	p1InterPoll1, err := p1Cli.PollExchange(ctx, p1Pend1)
	must(err, "PollExchange p1 interacting")
	p1InterPend1, p1InterOK1 := p1InterPoll1.Pending()

	p1ResParsed1, _ := url.Parse(p1Redirect1)
	p1ResVisit1, _ := aauth.ParseInteractionVisit(p1ResParsed1.RawQuery, aauth.InteractionVisitOptions{})
	p1ResRef1 := strings.TrimPrefix(p1ResParsed1.Path, "/connect/")
	p1AtRes1, err := p1Res.ConsumeInitiatedInteraction(ctx, p1ResRef1, p1ResVisit1)
	must(err, "ConsumeInitiatedInteraction p1")
	_, p1SecondResConsumeErr := p1Res.ConsumeInitiatedInteraction(ctx, p1ResRef1, p1ResVisit1)
	p1CompURL1, err := p1AtRes1.CompletionURL()
	must(err, "CompletionURL p1")
	p1CompParsed1, _ := url.Parse(p1CompURL1)
	p1CompParts1 := strings.Split(strings.TrimPrefix(p1CompParsed1.Path, "/from-resource/"), "/")
	_, p1ForgedCbErr := p1PS.ReceiveResourceInteractionCallback(ctx, p1CompParts1[0], "forged-flow", p1CompParsed1.RawQuery)
	p1AfterRes1, err := p1PS.ReceiveResourceInteractionCallback(ctx, p1CompParts1[0], p1CompParts1[1], p1CompParsed1.RawQuery)
	must(err, "ReceiveResourceInteractionCallback p1")
	must(p1PS.ApproveAuthorizationInteraction(ctx, p1AfterRes1, p1Dec), "ApproveAuthorizationInteraction p1")
	p1BackURL1, err := p1PS.AuthorizationCallbackURL(ctx, p1CompParts1[0])
	must(err, "AuthorizationCallbackURL p1")
	p1ApprovedPoll1, err := p1Cli.PollExchange(ctx, p1Pend1)
	must(err, "PollExchange p1 approved")
	p1AuthTok1, p1HasAuthTok1 := p1ApprovedPoll1.Token()
	p1CallReq1, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1GoResIssuer+"/events", nil)
	p1CallResp1, err := p1Cli.Do(ctx, clientagent.Call{Request: p1CallReq1, AuthToken: p1AuthTok1})
	must(err, "p1Cli.Do")
	_ = p1CallResp1.Body.Close()

	// 2. Callback errors mapping (all 5)
	p1CbErrMappingsOK := true
	for _, tc := range []struct {
		failure aauth.InteractionCallbackError
		status  int
		code    aauth.ErrorCode
		toAgent aauth.InteractionCallbackError
	}{
		{aauth.InteractionCallbackAccessDenied, http.StatusForbidden, "denied", aauth.InteractionCallbackAccessDenied},
		{aauth.InteractionCallbackUserAbandoned, http.StatusForbidden, "abandoned", aauth.InteractionCallbackUserAbandoned},
		{aauth.InteractionCallbackInteractionExpired, http.StatusRequestTimeout, "expired", aauth.InteractionCallbackInteractionExpired},
		{aauth.InteractionCallbackServerError, http.StatusInternalServerError, "server_error", aauth.InteractionCallbackServerError},
		{aauth.InteractionCallbackTemporarilyUnavailable, http.StatusInternalServerError, "server_error", aauth.InteractionCallbackServerError},
	} {
		pend, _, _, _ := p1BeginAt(p1GoResIssuer)
		vURL, _ := aauth.FormatInteractionVisitURL(pend.InteractionURL(), pend.InteractionCode(), p1AgentCb)
		vp, _ := url.Parse(vURL)
		vis, _ := aauth.ParseInteractionVisit(vp.RawQuery, aauth.InteractionVisitOptions{})
		ref := strings.TrimPrefix(vp.Path, "/consent/")
		cons, _ := p1PS.ConsumeAuthorizationInteractionCode(ctx, ref, vis.Code)
		redir, _ := p1PS.RedirectToResourceInteraction(ctx, cons, vis.Callback)
		rp, _ := url.Parse(redir)
		rvis, _ := aauth.ParseInteractionVisit(rp.RawQuery, aauth.InteractionVisitOptions{})
		rref := strings.TrimPrefix(rp.Path, "/connect/")
		atR, _ := p1Res.ConsumeInitiatedInteraction(ctx, rref, rvis)
		failURL, _ := atR.FailureURL(tc.failure)
		fp, _ := url.Parse(failURL)
		fparts := strings.Split(strings.TrimPrefix(fp.Path, "/from-resource/"), "/")
		_, cbErr := p1PS.ReceiveResourceInteractionCallback(ctx, fparts[0], fparts[1], fp.RawQuery)
		back, _ := p1PS.AuthorizationCallbackURL(ctx, fparts[0])
		bp, _ := url.Parse(back)
		agErr := aauth.ReadInteractionCallback(bp.RawQuery)
		_, pollErr := p1Cli.PollExchange(ctx, pend)
		var prob *aauth.ProblemError
		if !errors.Is(cbErr, tc.failure) || !errors.Is(agErr, tc.toAgent) ||
			!errors.As(pollErr, &prob) || prob.Status != tc.status || prob.Code != tc.code {
			p1CbErrMappingsOK = false
		}
	}

	// 3. Egress denial + Resource token withdrawal before/during interaction
	p1RefuseEgress.Store(true)
	p1PendEgress, _, _, _ := p1BeginAt(p1GoResIssuer)
	p1VEgress, _ := aauth.FormatInteractionVisitURL(p1PendEgress.InteractionURL(), p1PendEgress.InteractionCode(), p1AgentCb)
	p1VPEgress, _ := url.Parse(p1VEgress)
	p1VisEgress, _ := aauth.ParseInteractionVisit(p1VPEgress.RawQuery, aauth.InteractionVisitOptions{})
	p1RefEgress := strings.TrimPrefix(p1VPEgress.Path, "/consent/")
	p1ConsEgress, _ := p1PS.ConsumeAuthorizationInteractionCode(ctx, p1RefEgress, p1VisEgress.Code)
	_, p1EgressRedirErr := p1PS.RedirectToResourceInteraction(ctx, p1ConsEgress, p1VisEgress.Callback)
	_, p1EgressPollErr := p1Cli.PollExchange(ctx, p1PendEgress)
	p1RefuseEgress.Store(false)
	var p1EgressProb *aauth.ProblemError
	p1EgressOK := errors.Is(p1EgressRedirErr, personserver.ErrResourceInteractionRefused) &&
		errors.As(p1EgressPollErr, &p1EgressProb) && p1EgressProb.Code == "server_error"

	// Withdrawal during interaction
	p1PendWithdraw, p1RTWithdraw, _, _ := p1BeginAt(p1GoResIssuer)
	p1VW, _ := aauth.FormatInteractionVisitURL(p1PendWithdraw.InteractionURL(), p1PendWithdraw.InteractionCode(), p1AgentCb)
	p1VPW, _ := url.Parse(p1VW)
	p1VisW, _ := aauth.ParseInteractionVisit(p1VPW.RawQuery, aauth.InteractionVisitOptions{})
	p1RefW := strings.TrimPrefix(p1VPW.Path, "/consent/")
	p1ConsW, _ := p1PS.ConsumeAuthorizationInteractionCode(ctx, p1RefW, p1VisW.Code)
	p1RedirW, _ := p1PS.RedirectToResourceInteraction(ctx, p1ConsW, p1VisW.Callback)
	p1RPW, _ := url.Parse(p1RedirW)
	p1RVisW, _ := aauth.ParseInteractionVisit(p1RPW.RawQuery, aauth.InteractionVisitOptions{})
	p1AtRW, _ := p1Res.ConsumeInitiatedInteraction(ctx, strings.TrimPrefix(p1RPW.Path, "/connect/"), p1RVisW)
	p1CompW, _ := p1AtRW.CompletionURL()
	_, err = p1Res.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
		JTI:          p1RTWithdraw.JTI,
		ExpiresAt:    time.Unix(p1RTWithdraw.ExpiresAt, 0),
		Audience:     p1GoPSIssuer,
		PersonServer: p1GoPSIssuer,
	})
	must(err, "RevokeResourceToken p1")
	p1CPW, _ := url.Parse(p1CompW)
	p1CPPartsW := strings.Split(strings.TrimPrefix(p1CPW.Path, "/from-resource/"), "/")
	_, p1WithdrawCbErr := p1PS.ReceiveResourceInteractionCallback(ctx, p1CPPartsW[0], p1CPPartsW[1], p1CPW.RawQuery)
	_, p1WithdrawPollErr := p1Cli.PollExchange(ctx, p1PendWithdraw)
	var p1WithdrawProb *aauth.ProblemError
	p1WithdrawOK := errors.Is(p1WithdrawCbErr, personserver.ErrResourceTokenRevoked) &&
		errors.As(p1WithdrawPollErr, &p1WithdrawProb) && p1WithdrawProb.Code == "revoked"
	// 4. Cross-language Pairing 2: Go Agent -> Rust Resource (authorize_with_interaction) -> Go Direct PS
	p1PendRustRes, p1RTRustRes, _, _ := p1BeginAt(in.RustInitResIssuer)
	p1VRustRes, _ := aauth.FormatInteractionVisitURL(p1PendRustRes.InteractionURL(), p1PendRustRes.InteractionCode(), p1AgentCb)
	p1VPRustRes, _ := url.Parse(p1VRustRes)
	p1VisRustRes, _ := aauth.ParseInteractionVisit(p1VPRustRes.RawQuery, aauth.InteractionVisitOptions{})
	p1ConsRustRes, err := p1PS.ConsumeAuthorizationInteractionCode(ctx, strings.TrimPrefix(p1VPRustRes.Path, "/consent/"), p1VisRustRes.Code)
	must(err, "ConsumeAuthorizationInteractionCode p1RustRes")
	p1RedirRustRes, err := p1PS.RedirectToResourceInteraction(ctx, p1ConsRustRes, p1VisRustRes.Callback)
	must(err, "RedirectToResourceInteraction p1RustRes")
	// Visit Rust Resource /connect/{id}?code=...&callback=... over HTTPS
	p1RustConnectReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1RedirRustRes, nil)
	p1RustConnectResp, err := httpClient.Do(p1RustConnectReq)
	must(err, "GET p1RedirRustRes")
	var p1RustConnectOut struct {
		CompletionURL string `json:"completion_url"`
	}
	_ = json.NewDecoder(p1RustConnectResp.Body).Decode(&p1RustConnectOut)
	_ = p1RustConnectResp.Body.Close()
	p1CPRustRes, _ := url.Parse(p1RustConnectOut.CompletionURL)
	p1CPPartsRustRes := strings.Split(strings.TrimPrefix(p1CPRustRes.Path, "/from-resource/"), "/")
	p1AfterRustRes, err := p1PS.ReceiveResourceInteractionCallback(ctx, p1CPPartsRustRes[0], p1CPPartsRustRes[1], p1CPRustRes.RawQuery)
	must(err, "ReceiveResourceInteractionCallback p1RustRes")
	must(p1PS.ApproveAuthorizationInteraction(ctx, p1AfterRustRes, p1Dec), "ApproveAuthorizationInteraction p1RustRes")
	p1ApprovedRustRes, err := p1Cli.PollExchange(ctx, p1PendRustRes)
	must(err, "PollExchange p1RustRes")
	p1AuthTokRustRes, _ := p1ApprovedRustRes.Token()
	p1RustCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustInitResIssuer+"/records", nil)
	p1RustCallResp, err := p1Cli.Do(ctx, clientagent.Call{Request: p1RustCallReq, AuthToken: p1AuthTokRustRes})
	must(err, "p1Cli.Do RustInitRes")
	_ = p1RustCallResp.Body.Close()

	// 5. Cross-language Pairing 3: Go Agent -> Go Resource 2 (NewPersonConsent + InitiatedInteraction) -> Rust Direct PS (with_resource_interaction)
	p1RustPSAgentTok, err := p1AP.Issue(aauth.AgentTokenRequest{
		Agent:        p1GoAgentID,
		PersonServer: in.RustDirectPSIssuer,
		PublicKey:    p1AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "p1AP.Issue for RustDirectPS")
	p1RustPSCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  p1GoAgentID,
		SigningKey:  p1AgentKey,
		AgentToken:  p1RustPSAgentTok,
		KeyResolver: pResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	must(err, "clientagent.New p1RustPSCli")
	p1RustPTRes, err := p1RustPSCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: in.RustDirectPSIssuer,
		Resource:     p1GoRes2Issuer,
	})
	must(err, "p1RustPSCli.PersonToken")
	p1RustPT, _ := p1RustPTRes.Token()
	p1GoRes2RT, err := p1RustPSCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    p1GoRes2Issuer,
		PersonToken: p1RustPT,
		Scopes:      []string{"calendar.read"},
	})
	must(err, "p1RustPSCli.Authorize p1GoRes2")
	p1RustExRes, err := p1RustPSCli.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   in.RustDirectPSIssuer,
		ResourceToken:  p1GoRes2RT,
		PresentedToken: p1RustPT,
		Capabilities:   []string{"interaction"},
	})
	must(err, "p1RustPSCli.BeginExchange")
	p1RustPend, _ := p1RustExRes.Pending()
	p1RustVisitURL, err := aauth.FormatInteractionVisitURL(p1RustPend.InteractionURL(), p1RustPend.InteractionCode(), p1AgentCb)
	must(err, "FormatInteractionVisitURL p1RustPend")
	// Visit Rust Direct PS /consent/{id}?code=...&callback=... over HTTPS
	p1RustVisitReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1RustVisitURL, nil)
	p1RustVisitResp, err := httpClient.Do(p1RustVisitReq)
	must(err, "GET p1RustVisitURL")
	var p1RustVisitOut struct {
		RedirectURL string `json:"redirect_url"`
	}
	_ = json.NewDecoder(p1RustVisitResp.Body).Decode(&p1RustVisitOut)
	_ = p1RustVisitResp.Body.Close()
	// Visit Go Resource 2 /connect/{ref}?code=...&callback=...
	p1GoRes2VisitReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1RustVisitOut.RedirectURL, nil)
	p1GoRes2VisitResp, err := httpClient.Do(p1GoRes2VisitReq)
	must(err, "GET p1RustVisitOut.RedirectURL")
	var p1GoRes2VisitOut struct {
		CompletionURL string `json:"completion_url"`
	}
	_ = json.NewDecoder(p1GoRes2VisitResp.Body).Decode(&p1GoRes2VisitOut)
	_ = p1GoRes2VisitResp.Body.Close()
	// Return to Rust Direct PS callback URL over HTTPS
	p1RustCbReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1GoRes2VisitOut.CompletionURL, nil)
	p1RustCbResp, err := httpClient.Do(p1RustCbReq)
	must(err, "GET p1GoRes2VisitOut.CompletionURL")
	var p1RustCbOut struct {
		Approved bool `json:"approved"`
	}
	_ = json.NewDecoder(p1RustCbResp.Body).Decode(&p1RustCbOut)
	_ = p1RustCbResp.Body.Close()
	p1RustApprovedPoll, err := p1RustPSCli.PollExchange(ctx, p1RustPend)
	must(err, "p1RustPSCli.PollExchange")
	p1RustMintedAuthTok, _ := p1RustApprovedPoll.Token()
	p1GoRes2CallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p1GoRes2Issuer+"/events", nil)
	p1GoRes2CallResp, err := p1RustPSCli.Do(ctx, clientagent.Call{Request: p1GoRes2CallReq, AuthToken: p1RustMintedAuthTok})
	must(err, "p1RustPSCli.Do p1GoRes2")
	_ = p1GoRes2CallResp.Body.Close()
	// =========================================================================
	// QA-P2: Interaction Chaining & Callbacks Over Real HTTPS
	// =========================================================================
	const (
		p2OrdersIssuer    = "https://p2-orders.example"
		p2InventoryIssuer = "https://p2-inventory.example"
		p2RelayAP         = "https://p2-orders-ap.example"
		p2RelayAgentID    = "aauth:fulfillment@p2-orders-ap.example"
		p2AgentCb         = "https://p1-go-ap.example/callback/order-42"
	)
	p2OrdersKey := newPKey("p2-orders-1", 0xb6)
	p2RelayAPKey := newPKey("p2-relay-ap-1", 0xb7)
	p2RelayKey := newPKey("p2-relay-1", 0xb8)
	p2OtherAgentKey := newPKey("p2-other-agent-1", 0xb9)

	p2RelayProv, err := agentprovider.New(agentprovider.Config{
		Issuer:     p2RelayAP,
		SigningKey: p2RelayAPKey,
		Clock:      clock,
		NewID:      nextPID,
	})
	must(err, "agentprovider.New p2RelayProv")
	_, _ = registerTLS("p2-orders-ap.example", p2RelayProv.Handler())

	p2RelayTok, err := p2RelayProv.Issue(aauth.AgentTokenRequest{
		Agent:     p2RelayAgentID,
		PublicKey: p2RelayKey.PublicJWK(),
		Lifetime:  time.Hour,
	})
	must(err, "p2RelayProv.Issue")
	p2RelayCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  p2RelayAgentID,
		SigningKey:  p2RelayKey,
		AgentToken:  p2RelayTok,
		KeyResolver: pResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	must(err, "clientagent.New p2RelayCli")

	p2Inventory, err := resource.NewResourceManaged(resource.ResourceManagedConfig{
		Issuer:            p2InventoryIssuer,
		KeyResolver:       pResolver,
		Clock:             clock,
		ScopeDescriptions: map[string]string{"inventory.reserve": "Reserve inventory"},
		RequiredScopes:    func(*http.Request) []string { return []string{"inventory.reserve"} },
		Interaction: resource.SessionInteractionPolicy{
			URL:                 p2InventoryIssuer + "/interaction",
			Lifetime:            5 * time.Minute,
			MaximumCodeAttempts: 3,
		},
		Sessions: newNMemorySessionStore(),
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "reserved")
		}),
	})
	must(err, "resource.NewResourceManaged p2Inventory")
	_, _ = registerTLS("p2-inventory.example", p2Inventory.Handler())

	var p2Mu sync.Mutex
	p2Downstream := make(map[string]clientagent.PendingResourceSession)
	var p2LastChainErr error
	var p2Orders *resource.Server
	p2Orders, err = resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            p2OrdersIssuer,
		SigningKey:        p2OrdersKey,
		KeyResolver:       pResolver,
		Clock:             clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"orders.fulfill": "Fulfill orders"},
		RequiredScopes:    func(*http.Request) []string { return []string{"orders.fulfill"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		ChainedInteractions: &resource.ChainedInteractionConfig{
			URL:         p2OrdersIssuer + "/continue",
			CallbackURL: p2OrdersIssuer + "/returned",
			Lifetime:    10 * time.Minute,
			Store:       testutil.NewChainedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			downReq, dErr := http.NewRequestWithContext(r.Context(), http.MethodPost, p2InventoryIssuer+"/reserve", nil)
			if dErr != nil {
				http.Error(w, dErr.Error(), http.StatusInternalServerError)
				return
			}
			downReq.Header.Set("AAuth-Capabilities", "interaction")
			begin, bErr := p2RelayCli.BeginResourceSession(r.Context(), downReq)
			if bErr != nil {
				http.Error(w, bErr.Error(), http.StatusBadGateway)
				return
			}
			pend, ok := begin.Pending()
			if !ok {
				http.Error(w, "inventory did not ask for interaction", http.StatusBadGateway)
				return
			}
			chained, cErr := p2Orders.ChainInteraction(w, r, aauth.InteractionRequirement{
				URL:  pend.InteractionURL(),
				Code: pend.InteractionCode(),
			})
			p2Mu.Lock()
			defer p2Mu.Unlock()
			if cErr != nil {
				p2LastChainErr = cErr
				http.Error(w, "interaction_unavailable", http.StatusForbidden)
				return
			}
			p2Downstream[chained.Reference()] = pend
		}),
	})
	must(err, "resource.NewPSAuthorization p2Orders")

	p2OrdersMux := http.NewServeMux()
	// Helper endpoint so cross-language Rust agent can drive the chained interaction visit + downstream approval
	p2OrdersMux.HandleFunc("GET /continue/{ref}", func(w http.ResponseWriter, r *http.Request) {
		ref := r.PathValue("ref")
		visit, vErr := aauth.ParseInteractionVisit(r.URL.RawQuery, aauth.InteractionVisitOptions{})
		if vErr != nil {
			http.Error(w, vErr.Error(), http.StatusBadRequest)
			return
		}
		redir, rErr := p2Orders.VisitChainedInteraction(r.Context(), ref, visit)
		if rErr != nil {
			http.Error(w, rErr.Error(), http.StatusBadRequest)
			return
		}
		rp, _ := url.Parse(redir)
		rvis, _ := aauth.ParseInteractionVisit(rp.RawQuery, aauth.InteractionVisitOptions{})
		inter, cErr := p2Inventory.ConsumeSessionInteractionCode(r.Context(), strings.TrimPrefix(rp.Path, "/interaction/"), rvis.Code)
		must(cErr, "p2Inventory.ConsumeSessionInteractionCode")
		must(p2Inventory.ApproveSessionInteraction(r.Context(), inter, resource.SessionGrant{
			Subject:  "inventory-person",
			Scope:    []string{"inventory.reserve"},
			Lifetime: 10 * time.Minute,
		}), "p2Inventory.ApproveSessionInteraction")
		back, _ := aauth.InteractionCallbackURL(rvis.Callback, "")
		bp, _ := url.Parse(back)
		bparts := strings.Split(strings.TrimPrefix(bp.Path, "/returned/"), "/")
		chained, cbErr := p2Orders.ReceiveChainedInteractionCallback(r.Context(), bparts[0], bparts[1], bp.RawQuery)
		must(cbErr, "p2Orders.ReceiveChainedInteractionCallback")
		p2Mu.Lock()
		downPend := p2Downstream[ref]
		p2Mu.Unlock()
		sessRes, pErr := p2RelayCli.PollResourceSession(r.Context(), downPend)
		must(pErr, "p2RelayCli.PollResourceSession")
		granted, _ := sessRes.Session()
		resReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, p2InventoryIssuer+"/reserve", nil)
		resCall, dErr := p2RelayCli.DoWithResourceSession(r.Context(), resReq, granted)
		must(dErr, "p2RelayCli.DoWithResourceSession")
		resResp, _ := resCall.Response()
		b, _ := io.ReadAll(resResp.Body)
		_ = resResp.Body.Close()
		must(p2Orders.CompleteChainedInteraction(r.Context(), chained, resource.ChainedInteractionResult{
			Status:      http.StatusOK,
			ContentType: "text/plain",
			Body:        append([]byte("order 42 fulfilled: "), b...),
		}), "p2Orders.CompleteChainedInteraction")
		agCb, _ := p2Orders.ChainedInteractionCallbackURL(r.Context(), ref)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"completed":      true,
			"redirect_url":   redir,
			"agent_callback": agCb,
		})
	})
	p2OrdersMux.HandleFunc("POST /__complete-downstream/{ref}", func(w http.ResponseWriter, r *http.Request) {
		agCb, _ := p2Orders.ChainedInteractionCallbackURL(r.Context(), r.PathValue("ref"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"completed":      true,
			"agent_callback": agCb,
		})
	})
	p2OrdersMux.Handle("/", p2Orders.Handler())
	p2OrdersSrv, p2OrdersDER := registerTLS("p2-orders.example", p2OrdersMux)
	// Create p2SimplePS for p2Orders immediate auth token issuance
	const p2PSIssuer = "https://p2-go-ps.example"
	p2PSKey := newPKey("p2-ps-1", 0xba)
	p2PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      p2PSIssuer,
		SigningKey:  p2PSKey,
		KeyResolver: pResolver,
		Clock:       clock,
		Tokens:      &memoryTokenStore{},
		NewID:       nextPID,
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-" + req.Agent, Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "personserver.NewPSAuthorization p2PS")
	_, _ = registerTLS("p2-go-ps.example", p2PS.Handler())

	p2MakeCaller := func(name string, k jose.SigningKey) (*clientagent.Client, string) {
		agID := "aauth:" + name + "@p1-go-ap.example"
		agTok, iErr := p1AP.Issue(aauth.AgentTokenRequest{
			Agent:        agID,
			PersonServer: p2PSIssuer,
			PublicKey:    k.PublicJWK(),
			Lifetime:     time.Hour,
		})
		must(iErr, "p1AP.Issue "+name)
		cli, cErr := clientagent.New(ctx, clientagent.Config{
			Identifier:  agID,
			SigningKey:  k,
			AgentToken:  agTok,
			KeyResolver: pResolver,
			HTTPClient:  httpClient,
			Clock:       clock,
		})
		must(cErr, "clientagent.New "+name)
		ptRes, pErr := cli.PersonToken(ctx, clientagent.PersonTokenRequest{
			PersonServer: p2PSIssuer,
			Resource:     p2OrdersIssuer,
		})
		must(pErr, "cli.PersonToken "+name)
		pt, _ := ptRes.Token()
		rt, aErr := cli.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource:    p2OrdersIssuer,
			PersonToken: pt,
			Scopes:      []string{"orders.fulfill"},
		})
		must(aErr, "cli.Authorize "+name)
		at, eErr := cli.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer:   p2PSIssuer,
			ResourceToken:  rt,
			PresentedToken: pt,
		})
		must(eErr, "cli.Exchange "+name)
		return cli, at
	}
	p2CallerCli, p2CallerAuthTok := p2MakeCaller("p2-reader", p1AgentKey)
	p2OtherCli, p2OtherAuthTok := p2MakeCaller("p2-other", p2OtherAgentKey)

	p2DoCall := func(declared bool) *http.Response {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p2OrdersIssuer+"/orders/42/fulfill", nil)
		if declared {
			req.Header.Set("AAuth-Capabilities", "interaction")
		}
		resp, dErr := p2CallerCli.Do(ctx, clientagent.Call{Request: req, AuthToken: p2CallerAuthTok})
		must(dErr, "p2CallerCli.Do")
		return resp
	}

	// Undeclared capability -> 403 + ErrChainedInteractionUndeclared
	p2UndeclResp := p2DoCall(false)
	_ = p2UndeclResp.Body.Close()
	p2Mu.Lock()
	p2UndeclOK := p2UndeclResp.StatusCode == http.StatusForbidden && errors.Is(p2LastChainErr, resource.ErrChainedInteractionUndeclared)
	p2Mu.Unlock()

	// Happy path
	p2Pend1, err := p2CallerCli.ReadInteractionCall(p2DoCall(true))
	must(err, "ReadInteractionCall p2Pend1")
	p2VisURL1, _ := aauth.FormatInteractionVisitURL(p2Pend1.InteractionURL(), p2Pend1.InteractionCode(), p2AgentCb)
	p2VP1, _ := url.Parse(p2VisURL1)
	p2Vis1, _ := aauth.ParseInteractionVisit(p2VP1.RawQuery, aauth.InteractionVisitOptions{})
	p2Ref1 := strings.TrimPrefix(p2VP1.Path, "/continue/")
	_, p2WrongCodeErr := p2Orders.VisitChainedInteraction(ctx, p2Ref1, aauth.InteractionVisit{Code: "0000-0000"})
	p2Redir1, err := p2Orders.VisitChainedInteraction(ctx, p2Ref1, p2Vis1)
	must(err, "VisitChainedInteraction p2Ref1")
	_, p2SecondVisErr := p2Orders.VisitChainedInteraction(ctx, p2Ref1, p2Vis1)
	p2InterPoll1, err := p2CallerCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2Pend1,
		AuthToken: p2CallerAuthTok,
	})
	must(err, "PollInteractionCall interacting")
	p2InterNext1, p2InterOK1 := p2InterPoll1.Pending()
	_, p2OtherPollErr := p2OtherCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2Pend1,
		AuthToken: p2OtherAuthTok,
	})

	// Approve at p2Inventory and complete
	p2RP1, _ := url.Parse(p2Redir1)
	p2RVis1, _ := aauth.ParseInteractionVisit(p2RP1.RawQuery, aauth.InteractionVisitOptions{})
	p2InvInter1, err := p2Inventory.ConsumeSessionInteractionCode(ctx, strings.TrimPrefix(p2RP1.Path, "/interaction/"), p2RVis1.Code)
	must(err, "ConsumeSessionInteractionCode p2")
	must(p2Inventory.ApproveSessionInteraction(ctx, p2InvInter1, resource.SessionGrant{
		Subject:  "inventory-person",
		Scope:    []string{"inventory.reserve"},
		Lifetime: 10 * time.Minute,
	}), "ApproveSessionInteraction p2")
	p2Back1, _ := aauth.InteractionCallbackURL(p2RVis1.Callback, "")
	p2BP1, _ := url.Parse(p2Back1)
	p2BParts1 := strings.Split(strings.TrimPrefix(p2BP1.Path, "/returned/"), "/")
	p2Chained1, err := p2Orders.ReceiveChainedInteractionCallback(ctx, p2BParts1[0], p2BParts1[1], p2BP1.RawQuery)
	must(err, "ReceiveChainedInteractionCallback p2")
	p2Mu.Lock()
	p2Down1 := p2Downstream[p2Ref1]
	p2Mu.Unlock()
	p2Sess1, err := p2RelayCli.PollResourceSession(ctx, p2Down1)
	must(err, "PollResourceSession p2")
	p2Grant1, _ := p2Sess1.Session()
	p2ResReq1, _ := http.NewRequestWithContext(ctx, http.MethodPost, p2InventoryIssuer+"/reserve", nil)
	p2ResCall1, err := p2RelayCli.DoWithResourceSession(ctx, p2ResReq1, p2Grant1)
	must(err, "DoWithResourceSession p2")
	p2ResResp1, _ := p2ResCall1.Response()
	p2ResBody1, _ := io.ReadAll(p2ResResp1.Body)
	_ = p2ResResp1.Body.Close()
	must(p2Orders.CompleteChainedInteraction(ctx, p2Chained1, resource.ChainedInteractionResult{
		Status:      http.StatusOK,
		ContentType: "text/plain",
		Body:        append([]byte("order 42 fulfilled: "), p2ResBody1...),
	}), "CompleteChainedInteraction p2")
	p2ToAgent1, err := p2Orders.ChainedInteractionCallbackURL(ctx, p2Ref1)
	must(err, "ChainedInteractionCallbackURL p2")
	p2CompPoll1, err := p2CallerCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2Pend1,
		AuthToken: p2CallerAuthTok,
	})
	must(err, "PollInteractionCall completed")
	p2CompResp1, p2CompOK1 := p2CompPoll1.Response()
	var p2CompBody1 []byte
	if p2CompOK1 {
		p2CompBody1, _ = io.ReadAll(p2CompResp1.Body)
		_ = p2CompResp1.Body.Close()
	}
	_, p2GonePollErr := p2CallerCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2Pend1,
		AuthToken: p2CallerAuthTok,
	})
	var p2GoneProb *aauth.ProblemError
	p2GoneOK := errors.As(p2GonePollErr, &p2GoneProb) && p2GoneProb.Status == http.StatusGone

	// Downstream denial callback error propagation + forged flow check
	p2PendDeny, err := p2CallerCli.ReadInteractionCall(p2DoCall(true))
	must(err, "ReadInteractionCall p2PendDeny")
	p2VDeny, _ := aauth.FormatInteractionVisitURL(p2PendDeny.InteractionURL(), p2PendDeny.InteractionCode(), p2AgentCb)
	p2VPDeny, _ := url.Parse(p2VDeny)
	p2VisDeny, _ := aauth.ParseInteractionVisit(p2VPDeny.RawQuery, aauth.InteractionVisitOptions{})
	p2RefDeny := strings.TrimPrefix(p2VPDeny.Path, "/continue/")
	p2RedirDeny, _ := p2Orders.VisitChainedInteraction(ctx, p2RefDeny, p2VisDeny)
	p2RPDeny, _ := url.Parse(p2RedirDeny)
	p2RVisDeny, _ := aauth.ParseInteractionVisit(p2RPDeny.RawQuery, aauth.InteractionVisitOptions{})
	p2InvDeny, _ := p2Inventory.ConsumeSessionInteractionCode(ctx, strings.TrimPrefix(p2RPDeny.Path, "/interaction/"), p2RVisDeny.Code)
	_ = p2Inventory.DenySessionInteraction(ctx, p2InvDeny)
	p2BackDeny, _ := aauth.InteractionCallbackURL(p2RVisDeny.Callback, aauth.InteractionCallbackAccessDenied)
	p2BPDeny, _ := url.Parse(p2BackDeny)
	p2BPartsDeny := strings.Split(strings.TrimPrefix(p2BPDeny.Path, "/returned/"), "/")
	_, p2ForgedFlowErr := p2Orders.ReceiveChainedInteractionCallback(ctx, p2BPartsDeny[0], p2BPartsDeny[1]+"x", p2BPDeny.RawQuery)
	_, p2DenyCbErr := p2Orders.ReceiveChainedInteractionCallback(ctx, p2BPartsDeny[0], p2BPartsDeny[1], p2BPDeny.RawQuery)
	p2ToAgentDeny, _ := p2Orders.ChainedInteractionCallbackURL(ctx, p2RefDeny)
	_, p2DenyPollErr := p2CallerCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2PendDeny,
		AuthToken: p2CallerAuthTok,
	})
	var p2DenyProb *aauth.ProblemError
	p2DenyOK := errors.Is(p2ForgedFlowErr, resource.ErrChainedInteractionCallbackInvalid) &&
		errors.Is(p2DenyCbErr, aauth.InteractionCallbackAccessDenied) &&
		p2ToAgentDeny == p2AgentCb+"?error=access_denied" &&
		errors.As(p2DenyPollErr, &p2DenyProb) && p2DenyProb.Status == http.StatusForbidden && p2DenyProb.Code == "denied"

	// Downstream revocation propagation
	p2PendRev, err := p2CallerCli.ReadInteractionCall(p2DoCall(true))
	must(err, "ReadInteractionCall p2PendRev")
	p2VRev, _ := aauth.FormatInteractionVisitURL(p2PendRev.InteractionURL(), p2PendRev.InteractionCode(), p2AgentCb)
	p2VPRev, _ := url.Parse(p2VRev)
	p2VisRev, _ := aauth.ParseInteractionVisit(p2VPRev.RawQuery, aauth.InteractionVisitOptions{})
	p2RefRev := strings.TrimPrefix(p2VPRev.Path, "/continue/")
	_, _ = p2Orders.VisitChainedInteraction(ctx, p2RefRev, p2VisRev)
	p2ResumedRev, _ := p2Orders.ResumeChainedInteraction(ctx, p2RefRev)
	_ = p2Orders.FailChainedInteraction(ctx, p2ResumedRev, "revoked")
	p2CompAfterRevErr := p2Orders.CompleteChainedInteraction(ctx, p2ResumedRev, resource.ChainedInteractionResult{Status: http.StatusOK})
	p2ToAgentRev, _ := p2Orders.ChainedInteractionCallbackURL(ctx, p2RefRev)
	_, p2RevPollErr := p2CallerCli.PollInteractionCall(ctx, clientagent.InteractionCallPoll{
		Pending:   p2PendRev,
		AuthToken: p2CallerAuthTok,
	})
	var p2RevProb *aauth.ProblemError
	p2RevOK := errors.Is(p2CompAfterRevErr, resource.ErrChainedInteractionConflict) &&
		p2ToAgentRev == p2AgentCb+"?error=server_error" &&
		errors.As(p2RevPollErr, &p2RevProb) && p2RevProb.Status == http.StatusForbidden && p2RevProb.Code == "revoked"
	// =========================================================================
	// QA-P3: aauth-resource Link Relation & Cross-Language (Rust <-> Go)
	// =========================================================================
	const (
		p3GoResIssuer  = "https://p3-go-res.example"
		p3PortalIssuer = "https://p3-portal.example"
		p3BadMissing   = "https://p3-bad-missing.example"
		p3BadMismatch  = "https://p3-bad-mismatch.example"
	)
	p3ResKey := newPKey("p3-res-1", 0xbb)
	p3Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            p3GoResIssuer,
		SigningKey:        p3ResKey,
		KeyResolver:       pResolver,
		Clock:             clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"docs.read": "Read docs"},
		RequiredScopes:    func(*http.Request) []string { return []string{"docs.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "p3-protected")
		}),
	})
	must(err, "resource.NewPSAuthorization p3Res")

	p3GoLinkElem, err := aauth.ResourceLinkElement(p3GoResIssuer)
	must(err, "ResourceLinkElement p3GoResIssuer")
	p3RustLinkElem, err := aauth.ResourceLinkElement(in.RustLinkResIssuer)
	must(err, "ResourceLinkElement RustLinkResIssuer")

	p3ResMux := http.NewServeMux()
	p3ResMux.HandleFunc("GET /docs", func(w http.ResponseWriter, _ *http.Request) {
		_ = aauth.AddResourceLinks(w.Header(), in.RustLinkResIssuer)
		w.Header().Set("Link", strings.Join(w.Header().Values("Link"), ", "))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><head>"+p3GoLinkElem+p3RustLinkElem+"</head><body>Docs</body></html>")
	})
	p3ResMux.Handle("/", p3Res.Handler())
	p3ResSrv, p3ResDER := registerTLS("p3-go-res.example", p3Res.WithResourceLink(p3ResMux))

	p3PortalMux := http.NewServeMux()
	p3PortalMux.HandleFunc("GET /directory", func(w http.ResponseWriter, _ *http.Request) {
		_ = aauth.AddResourceLinks(w.Header(), p3GoResIssuer, in.RustLinkResIssuer)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><html><head>"+p3GoLinkElem+p3RustLinkElem+"</head><body>Directory</body></html>")
	})
	_, _ = registerTLS("p3-portal.example", p3PortalMux)

	p3BadMissingMux := http.NewServeMux()
	p3BadMissingMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jwks_uri":"https://p3-bad-missing.example/.well-known/jwks.json"}`)
	})
	_, _ = registerTLS("p3-bad-missing.example", p3BadMissingMux)

	p3BadMismatchMux := http.NewServeMux()
	p3BadMismatchMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"https://other.example","jwks_uri":"https://p3-bad-mismatch.example/.well-known/jwks.json"}`)
	})
	_, _ = registerTLS("p3-bad-mismatch.example", p3BadMismatchMux)

	// 1. Go Agent discovers Go Resource and Rust Resource from Portal HTTP Link header and HTML <link>
	p3DirReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p3PortalIssuer+"/directory", nil)
	p3DirResp, err := httpClient.Do(p3DirReq)
	must(err, "GET p3PortalIssuer/directory")
	p3DirBody, _ := io.ReadAll(p3DirResp.Body)
	_ = p3DirResp.Body.Close()
	p3HdrLinks := clientagent.ResourceLinksFromResponse(p3DirResp)
	p3HTMLLinks := clientagent.ResourceLinksFromHTML(p3PortalIssuer+"/directory", p3DirBody)
	p3ResolvedGoHdr, err := clientagent.ResolveResourceLink(ctx, pResolver, p3HdrLinks[0])
	must(err, "ResolveResourceLink Go Hdr")
	p3ResolvedRustHdr, err := clientagent.ResolveResourceLink(ctx, pResolver, p3HdrLinks[1])
	must(err, "ResolveResourceLink Rust Hdr")
	p3ResolvedGoHTML, err := clientagent.ResolveResourceLink(ctx, pResolver, p3HTMLLinks[0])
	must(err, "ResolveResourceLink Go HTML")
	p3ResolvedRustHTML, err := clientagent.ResolveResourceLink(ctx, pResolver, p3HTMLLinks[1])
	must(err, "ResolveResourceLink Rust HTML")

	// 2. Go Agent fetches Rust Resource /docs (emitting Rust Link header + HTML <link>) over HTTPS
	p3RustDocReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustLinkResIssuer+"/docs", nil)
	p3RustDocResp, err := httpClient.Do(p3RustDocReq)
	must(err, "GET RustLinkResIssuer/docs")
	p3RustDocBody, _ := io.ReadAll(p3RustDocResp.Body)
	_ = p3RustDocResp.Body.Close()
	p3RustRespLinks := clientagent.ResourceLinksFromResponse(p3RustDocResp)
	p3RustHTMLLinks := clientagent.ResourceLinksFromHTML(in.RustLinkResIssuer+"/docs", p3RustDocBody)
	p3FromRustHdr, err := clientagent.ResolveResourceLink(ctx, pResolver, p3RustRespLinks[0])
	must(err, "ResolveResourceLink from Rust /docs Hdr")
	p3FromRustHTML, err := clientagent.ResolveResourceLink(ctx, pResolver, p3RustHTMLLinks[0])
	must(err, "ResolveResourceLink from Rust /docs HTML")

	// 3. Negative guards: non-HTTPS, path prefix, wrong well-known, query, fragment, port, userinfo, >8KiB Link, >1MiB HTML, issuer_missing, issuer_mismatch
	p3NegTargetsOK := true
	for _, badTarget := range []string{
		"http://p3-go-res.example/.well-known/aauth-resource.json",
		"https://p3-go-res.example/v1/.well-known/aauth-resource.json",
		"https://p3-go-res.example/.well-known/aauth-person.json",
		"https://p3-go-res.example/.well-known/aauth-resource.json?x=1",
		"https://p3-go-res.example/.well-known/aauth-resource.json#frag",
		"https://p3-go-res.example:8443/.well-known/aauth-resource.json",
		"https://user@p3-go-res.example/.well-known/aauth-resource.json",
	} {
		if _, pErr := aauth.ParseResourceLinkTarget(badTarget); pErr == nil {
			p3NegTargetsOK = false
		}
		if _, rErr := clientagent.ResolveResourceLink(ctx, pResolver, clientagent.FoundResourceLink{
			ResourceLink: aauth.ResourceLink{Target: badTarget},
		}); rErr == nil {
			p3NegTargetsOK = false
		}
	}
	p3OversizedHdr := aauth.ResourceLinksFromHeader([]string{
		`<https://p3-go-res.example/.well-known/aauth-resource.json>; rel="aauth-resource"; pad="` + strings.Repeat("a", 9000) + `"`,
	})
	p3OversizedHTML := aauth.ResourceLinksFromHTML([]byte(
		"<!doctype html><html><head>" + p3GoLinkElem + "</head><body>" + strings.Repeat("x", (1<<20)+16) + "</body></html>",
	))
	_, p3MissingErr := clientagent.ResolveResourceLink(ctx, pResolver, clientagent.FoundResourceLink{
		ResourceLink: aauth.ResourceLink{Target: p3BadMissing + "/.well-known/aauth-resource.json", Issuer: p3BadMissing},
	})
	_, p3MismatchErr := clientagent.ResolveResourceLink(ctx, pResolver, clientagent.FoundResourceLink{
		ResourceLink: aauth.ResourceLink{Target: p3BadMismatch + "/.well-known/aauth-resource.json", Issuer: p3BadMismatch},
	})
	var p3SigErr1, p3SigErr2 *signaturekey.Error
	p3IssuerErrorsOK := errors.As(signaturekey.NormalizeError(p3MissingErr, signaturekey.ErrorInvalidKey), &p3SigErr1) &&
		p3SigErr1.Code == signaturekey.ErrorIssuerMissing &&
		errors.As(signaturekey.NormalizeError(p3MismatchErr, signaturekey.ErrorInvalidKey), &p3SigErr2) &&
		p3SigErr2.Code == signaturekey.ErrorIssuerMismatch

	// =========================================================================
	// QA-P4: Delayed Signed Requests (VerifyOptions.MaxDelay, ValidAt) & ReplayCache
	// =========================================================================
	p4Key := newPKey("p4-freshness-1", 0xbc)
	p4SignedAt := nowTime.Add(-50 * time.Minute)
	p4MakeReq := func(path string, created time.Time, expires time.Time, body string) *http.Request {
		cred, cErr := signaturekey.NewHWKCredential(p4Key.PublicJWK())
		must(cErr, "NewHWKCredential p4")
		req := httptest.NewRequest(http.MethodPost, "https://p4-resource.example"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		must(signaturekey.SignRequest(req, p4Key, cred, aauth.ClockFunc(func() time.Time { return created }), signaturekey.SignOptions{ExpiresAt: expires}), "SignRequest p4")
		return req
	}
	p4Verify := func(req *http.Request, at time.Time, maxDelay time.Duration) (signaturekey.VerifiedRequest, error) {
		prep, pErr := signaturekey.PrepareRequest(req, aauth.ClockFunc(func() time.Time { return at }), signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
			MaxDelay:        maxDelay,
		})
		if pErr != nil {
			return signaturekey.VerifiedRequest{}, pErr
		}
		return prep.Verify(p4Key.PublicJWK())
	}
	p4BatchReq := p4MakeReq("/batch", p4SignedAt, time.Time{}, "")
	_, p4OnlineOldErr := p4Verify(p4BatchReq, nowTime, 0)
	p4DelayedProof, p4DelayedErr := p4Verify(p4BatchReq, nowTime, time.Hour)
	must(p4DelayedErr, "p4Verify delayed")
	// Mint a PersonToken valid at p4SignedAt (expired by nowTime) and verify with aauth.ClockFunc(p4DelayedProof.ValidAt)
	p4PastPT, err := aauth.MintPersonToken(p1PSKey, aauth.PersonTokenClaims{
		Issuer:       p1GoPSIssuer,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     p1GoResIssuer,
		Subject:      "person-p4",
		JTI:          "p4-past-pt",
		IssuedAt:     p4SignedAt.Add(-time.Minute).Unix(),
		ExpiresAt:    p4SignedAt.Add(10 * time.Minute).Unix(),
		Confirmation: aauth.Confirmation{JWK: p4Key.PublicJWK()},
	})
	must(err, "MintPersonToken p4PastPT")
	_, p4VerifyAtNowErr := aauth.VerifyPersonToken(ctx, p4PastPT, pResolver, clock)
	_, p4VerifyAtValidAtErr := aauth.VerifyPersonToken(ctx, p4PastPT, pResolver, aauth.ClockFunc(p4DelayedProof.ValidAt))
	p4IssuedAfterErr := p4DelayedProof.CheckIssuedAt(p4SignedAt.Add(signaturekey.DefaultSignatureWindow + time.Second))
	_, p4BeyondMaxDelayErr := p4Verify(p4BatchReq, p4SignedAt.Add(time.Hour+time.Second), time.Hour)
	_, p4FutureCreatedErr := p4Verify(p4MakeReq("/batch", nowTime.Add(2*time.Minute), time.Time{}, ""), nowTime, time.Hour)
	_, p4ExpiredSigErr := p4Verify(p4MakeReq("/batch", p4SignedAt, p4SignedAt.Add(5*time.Minute), ""), nowTime, time.Hour)

	p4Cache, err := signaturekey.NewReplayCache(signaturekey.ReplayCacheConfig{MaxEntries: 2})
	must(err, "NewReplayCache p4")
	p4FirstCheckErr := p4Cache.Check(p4DelayedProof)
	p4AgainProof, err := p4Verify(p4BatchReq, p4SignedAt.Add(59*time.Minute), time.Hour)
	must(err, "p4Verify again")
	p4ReplayCheckErr := p4Cache.Check(p4AgainProof)
	p4OtherProof, err := p4Verify(p4MakeReq("/other", p4SignedAt, time.Time{}, ""), p4SignedAt.Add(time.Minute), time.Hour)
	must(err, "p4Verify other")
	p4OtherCheckErr := p4Cache.Check(p4OtherProof)
	p4ThirdProof, err := p4Verify(p4MakeReq("/third", p4SignedAt, time.Time{}, ""), p4SignedAt.Add(time.Minute), time.Hour)
	must(err, "p4Verify third")
	p4FullCacheErr := p4Cache.Check(p4ThirdProof)
	// Advance past p4SignedAt + 1h so entries expire and can be evicted
	p4AfterSpanProof, err := p4Verify(p4MakeReq("/after-span", p4SignedAt.Add(61*time.Minute), time.Time{}, ""), p4SignedAt.Add(62*time.Minute), time.Hour)
	must(err, "p4Verify after-span")
	p4AfterSpanCheckErr := p4Cache.Check(p4AfterSpanProof)
	p4LenAfterSpan := p4Cache.Len()
	// =========================================================================
	// QA-P5: Revocation Cascades, Prefer: wait, 429 rate_limited, Upstream & Agent Eviction
	// =========================================================================
	const (
		p5PSIssuer       = "https://p5-go-ps.example"
		p5ASIssuer       = "https://p5-go-as.example"
		p5ResIssuer      = "https://p5-go-res.example"
		p5RelayResIssuer = "https://p5-relay-res.example"
		p5RateResIssuer  = "https://p5-rate-res.example"
	)
	p5PSKey := newPKey("p5-ps-1", 0xbd)
	p5ASKey := newPKey("p5-as-1", 0xbe)
	p5ResKey := newPKey("p5-res-1", 0xbf)
	p5RateResKey := newPKey("p5-rate-res-1", 0xc0)

	var p5NowMu sync.Mutex
	p5Now := nowTime
	p5Clock := aauth.ClockFunc(func() time.Time {
		p5NowMu.Lock()
		defer p5NowMu.Unlock()
		return p5Now
	})
	p5Advance := func(d time.Duration) {
		p5NowMu.Lock()
		p5Now = p5Now.Add(d)
		p5NowMu.Unlock()
	}
	p5Resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   p5Clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver p5Resolver")

	p5AS, err := accessserver.New(accessserver.Config{
		Issuer:      p5ASIssuer,
		SigningKey:  p5ASKey,
		KeyResolver: p5Resolver,
		Clock:       p5Clock,
		NewID:       nextPID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss != p5PSIssuer {
				return accessserver.ErrAccessDenied
			}
			return nil
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 20 * time.Minute}, nil
		},
		Revocation: &accessserver.RevocationConfig{
			Revocations:  testutil.NewTokenRevocationStore(),
			IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient:   httpClient,
			Admit:        func(context.Context, string) error { return nil },
			Hold:         time.Second,
		},
	})
	must(err, "accessserver.New p5AS")
	var p5LastPendingLoc string
	var p5LocMu sync.Mutex
	p5ASMux := http.NewServeMux()
	p5ASMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		p5AS.Handler().ServeHTTP(rec, r)
		if r.URL.Path == "/revoke" && rec.Code == http.StatusAccepted {
			p5LocMu.Lock()
			p5LastPendingLoc = rec.Header().Get("Location")
			p5LocMu.Unlock()
		}
		for k, vals := range rec.Header() {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
	_, _ = registerTLS("p5-go-as.example", p5ASMux)

	var p5HoldResRevoke atomic.Bool
	p5ReleaseCh := make(chan struct{})
	p5Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            p5ResIssuer,
		AccessServer:      p5ASIssuer,
		SigningKey:        p5ResKey,
		KeyResolver:       p5Resolver,
		Clock:             p5Clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		AuthTokenStatuses: newPAuthTokenStatusStore(),
		Revocation: &resource.RevocationConfig{
			PersonTokens: testutil.NewTokenRevocationStore(),
			HTTPClient:   httpClient,
			Admit:        func(context.Context, string) error { return nil },
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "p5-records")
		}),
	})
	must(err, "resource.NewFederatedAuthorization p5Res")
	p5ResMux := http.NewServeMux()
	p5ResMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/revoke" && p5HoldResRevoke.Load() && strings.Contains(r.Header.Get("Signature-Key"), p5ASIssuer) {
			select {
			case <-p5ReleaseCh:
			case <-r.Context().Done():
				return
			}
		}
		p5Res.Handler().ServeHTTP(w, r)
	})
	_, _ = registerTLS("p5-go-res.example", p5ResMux)

	p5RelayAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     p5RelayResIssuer,
		SigningKey: newPKey("p5-relay-res-1", 0xc0),
		Clock:      p5Clock,
		NewID:      nextPID,
	})
	must(err, "agentprovider.New p5RelayAP")
	p5RelayRes, err := resource.NewPersonIdentity(resource.PersonIdentityConfig{
		Issuer:        p5RelayResIssuer,
		KeyResolver:   p5Resolver,
		Clock:         p5Clock,
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:     http.NotFoundHandler(),
		Revocation:    &resource.RevocationConfig{PersonTokens: testutil.NewTokenRevocationStore()},
	})
	must(err, "resource.NewPersonIdentity p5RelayRes")
	p5RelayMux := http.NewServeMux()
	p5RelayMux.Handle("GET /.well-known/aauth-agent.json", p5RelayAP.Handler())
	p5RelayMux.Handle("GET /.well-known/jwks.json", p5RelayAP.Handler())
	p5RelayMux.Handle("/", p5RelayRes.Handler())
	_, _ = registerTLS("p5-relay-res.example", p5RelayMux)

	p5RateRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            p5RateResIssuer,
		AccessServer:      p5ASIssuer,
		SigningKey:        p5RateResKey,
		KeyResolver:       p5Resolver,
		Clock:             p5Clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		AuthTokenStatuses: newPAuthTokenStatusStore(),
		Revocation: &resource.RevocationConfig{
			PersonTokens: testutil.NewTokenRevocationStore(),
			HTTPClient:   httpClient,
			Admit:        func(context.Context, string) error { return nil },
			Limits:       aauth.RevocationLimits{Requests: 1, Window: 5 * time.Second},
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "p5-rate-records")
		}),
	})
	must(err, "resource.NewFederatedAuthorization p5RateRes")
	_, _ = registerTLS("p5-rate-res.example", p5RateRes.Handler())
	p5Tokens := &memoryTokenStore{}
	p5PSCfg := personserver.FederatedAuthorizationConfig{
		Issuer:       p5PSIssuer,
		SigningKey:   p5PSKey,
		KeyResolver:  p5Resolver,
		Clock:        p5Clock,
		NewID:        nextPID,
		HTTPClient:   httpClient,
		Tokens:       p5Tokens,
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-p5", Lifetime: 30 * time.Minute}, nil
		},
		AccessServerEndpoint: func(context.Context, string) (string, error) { return p5ASIssuer + "/token", nil },
		Consent:              func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-p5-at-" + req.Resource, Lifetime: 30 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(),
			HTTPClient:  httpClient,
			Admit:       func(context.Context, string) error { return nil },
			Hold:        2 * time.Second,
		},
	}
	p5PS, err := personserver.NewFederatedAuthorization(p5PSCfg)
	must(err, "personserver.NewFederatedAuthorization p5PS")
	var p5PSTokenCalls atomic.Int64
	var p5ActivePS atomic.Value
	p5ActivePS.Store(p5PS.Handler())
	p5PSMux := http.NewServeMux()
	p5PSMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/token" {
			p5PSTokenCalls.Add(1)
		}
		p5ActivePS.Load().(http.Handler).ServeHTTP(w, r)
	})
	_, _ = registerTLS("p5-go-ps.example", p5PSMux)

	p5AgentTok, err := p1AP.Issue(aauth.AgentTokenRequest{
		Agent:        p1GoAgentID,
		PersonServer: p5PSIssuer,
		PublicKey:    p1AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "p1AP.Issue p5")
	p5Cli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  p1GoAgentID,
		SigningKey:  p1AgentKey,
		AgentToken:  p5AgentTok,
		KeyResolver: p5Resolver,
		HTTPClient:  httpClient,
		Clock:       p5Clock,
	})
	must(err, "clientagent.New p5Cli")

	// 1. 4-party cascade + withdrawn resource token + agent local eviction
	p5PT1Res, err := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5ResIssuer})
	must(err, "p5Cli.PersonToken 1")
	p5PT1, _ := p5PT1Res.Token()
	p5PT1Claims, _ := aauth.VerifyPersonToken(ctx, p5PT1, p5Resolver, p5Clock)
	p5RT1, err := p5Cli.Authorize(ctx, clientagent.AuthorizeRequest{Resource: p5ResIssuer, PersonToken: p5PT1, Scopes: []string{"records.read"}})
	must(err, "p5Cli.Authorize 1")
	p5AT1, err := p5Cli.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: p5PSIssuer, ResourceToken: p5RT1, PresentedToken: p5PT1})
	must(err, "p5Cli.Exchange 1")
	p5Call1Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p5ResIssuer+"/records", nil)
	p5Call1Resp, err := p5Cli.Do(ctx, clientagent.Call{Request: p5Call1Req, AuthToken: p5AT1})
	must(err, "p5Cli.Do 1")
	_ = p5Call1Resp.Body.Close()

	// Withdraw a second resource token
	p5WithdrawnRT, err := p5Cli.Authorize(ctx, clientagent.AuthorizeRequest{Resource: p5ResIssuer, PersonToken: p5PT1, Scopes: []string{"records.read"}})
	must(err, "p5Cli.Authorize withdrawn")
	p5WithdrawnClaims, _ := aauth.VerifyResourceToken(ctx, p5WithdrawnRT, p5Resolver, p5Clock)
	p5WithdrawRes, err := p5Res.RevokeResourceToken(ctx, resource.ResourceTokenRevocation{
		JTI:          p5WithdrawnClaims.JTI,
		ExpiresAt:    time.Unix(p5WithdrawnClaims.ExpiresAt, 0),
		Audience:     p5ASIssuer,
		PersonServer: p5PSIssuer,
	})
	must(err, "p5Res.RevokeResourceToken")
	_, p5WithdrawnExErr1 := p5Cli.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: p5PSIssuer, ResourceToken: p5WithdrawnRT, PresentedToken: p5PT1})
	p5TokenCallsBeforeEvict := p5PSTokenCalls.Load()
	_, p5WithdrawnExErr2 := p5Cli.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: p5PSIssuer, ResourceToken: p5WithdrawnRT, PresentedToken: p5PT1})
	p5TokenCallsAfterEvict := p5PSTokenCalls.Load()
	var p5LocalRefusal *clientagent.RevokedResourceTokenError
	p5AgentEvictionOK := errors.Is(p5WithdrawnExErr1, clientagent.ErrResourceTokenRevoked) &&
		errors.As(p5WithdrawnExErr2, &p5LocalRefusal) && p5LocalRefusal.Problem == nil &&
		p5TokenCallsAfterEvict == p5TokenCallsBeforeEvict

	// Revoke p5PT1 and verify cascade to p5Res + p5AS (and p5AS -> p5Res downstream)
	p5RevPT1, err := p5PS.RevokePersonToken(ctx, p5PT1Claims.JTI)
	must(err, "p5PS.RevokePersonToken 1")
	_, p5AfterRevAuthzErr := p5Cli.Authorize(ctx, clientagent.AuthorizeRequest{Resource: p5ResIssuer, PersonToken: p5PT1, Scopes: []string{"records.read"}})
	p5CallAfterRevReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p5ResIssuer+"/records", nil)
	_, p5AfterRevCallErr := p5Cli.Do(ctx, clientagent.Call{Request: p5CallAfterRevReq, AuthToken: p5AT1})
	var p5SigErrA, p5SigErrB *signaturekey.Error
	p5CascadeRefusedOK := errors.As(p5AfterRevAuthzErr, &p5SigErrA) && p5SigErrA.Code == signaturekey.ErrorRevokedJWT &&
		errors.As(p5AfterRevCallErr, &p5SigErrB) && p5SigErrB.Code == signaturekey.ErrorRevokedJWT &&
		len(p5RevPT1.Attempts) == 2 && !p5RevPT1.Pending() && len(p5RevPT1.Attempts[1].Downstream) == 1

	// 2. Prefer: wait deferred cascade + polling
	p5PT2Res, err := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5ResIssuer})
	must(err, "p5Cli.PersonToken 2")
	p5PT2, _ := p5PT2Res.Token()
	p5PT2Claims, _ := aauth.VerifyPersonToken(ctx, p5PT2, p5Resolver, p5Clock)
	p5RT2, err := p5Cli.Authorize(ctx, clientagent.AuthorizeRequest{Resource: p5ResIssuer, PersonToken: p5PT2, Scopes: []string{"records.read"}})
	must(err, "p5Cli.Authorize 2")
	_, err = p5Cli.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: p5PSIssuer, ResourceToken: p5RT2, PresentedToken: p5PT2})
	must(err, "p5Cli.Exchange 2")
	p5HoldResRevoke.Store(true)
	p5HeldRev, err := p5PS.RevokePersonToken(ctx, p5PT2Claims.JTI)
	must(err, "p5PS.RevokePersonToken 2 held")
	p5LocMu.Lock()
	p5PendLoc := p5LastPendingLoc
	p5LocMu.Unlock()
	// Wrong caller poll -> 404
	p5WrongPollReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p5PendLoc, nil)
	must(signaturekey.SignJWKSURIRequest(p5WrongPollReq, p5ResKey, p5ResIssuer, aauth.ResourceDiscoveryDocument, p5Clock), "SignJWKSURIRequest wrong poll")
	p5WrongPollResp, err := httpClient.Do(p5WrongPollReq)
	must(err, "Do wrong poll")
	_ = p5WrongPollResp.Body.Close()
	close(p5ReleaseCh)
	p5HoldResRevoke.Store(false)
	p5Advance(p5HeldRev.RetryAfter())
	p5CompRev, err := p5PS.RevokePersonToken(ctx, p5PT2Claims.JTI)
	must(err, "p5PS.RevokePersonToken 2 completed")
	p5GonePollReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p5PendLoc, nil)
	must(signaturekey.SignJWKSURIRequest(p5GonePollReq, p5PSKey, p5PSIssuer, aauth.PersonDiscoveryDocument, p5Clock), "SignJWKSURIRequest gone poll")
	p5GonePollResp, err := httpClient.Do(p5GonePollReq)
	must(err, "Do gone poll")
	_ = p5GonePollResp.Body.Close()
	p5PreferWaitOK := p5HeldRev.Pending() && strings.HasPrefix(p5PendLoc, p5ASIssuer+"/revoke/pending/") &&
		p5WrongPollResp.StatusCode == http.StatusNotFound && !p5CompRev.Pending() &&
		len(p5CompRev.Attempts[1].Downstream) == 1 && p5GonePollResp.StatusCode == http.StatusGone

	// 3. 429 rate_limited with Retry-After keeping revocations pending
	p5RatePT1Res, _ := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5RateResIssuer})
	p5RatePT1, _ := p5RatePT1Res.Token()
	p5RatePT1Claims, _ := aauth.VerifyPersonToken(ctx, p5RatePT1, p5Resolver, p5Clock)
	p5RatePT2Res, _ := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5RateResIssuer})
	p5RatePT2, _ := p5RatePT2Res.Token()
	p5RatePT2Claims, _ := aauth.VerifyPersonToken(ctx, p5RatePT2, p5Resolver, p5Clock)
	p5RateRev1, err := p5PS.RevokePersonToken(ctx, p5RatePT1Claims.JTI)
	must(err, "p5PS.RevokePersonToken rate 1")
	p5RateRev2, err := p5PS.RevokePersonToken(ctx, p5RatePT2Claims.JTI)
	must(err, "p5PS.RevokePersonToken rate 2")
	var p5RateLimErr *aauth.RateLimitedError
	p5RatePendingOK := !p5RateRev1.Pending() && p5RateRev2.Pending() &&
		errors.As(p5RateRev2.Attempts[0].Cause, &p5RateLimErr) &&
		p5RateLimErr.Problem.Status == http.StatusTooManyRequests && p5RateLimErr.Problem.Code == "rate_limited"
	p5Advance(p5RateLimErr.RetryAfter)
	p5RateRev2Retry, err := p5PS.RevokePersonToken(ctx, p5RatePT2Claims.JTI)
	must(err, "p5PS.RevokePersonToken rate 2 retry")
	p5RateRetryOK := p5RatePendingOK && !p5RateRev2Retry.Pending() && !p5RateRev2Retry.Attempts[0].Pending

	// 4. Upstream person-token revocation at Access Server
	p5UpPTRes, err := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5RelayResIssuer})
	must(err, "p5Cli.PersonToken upstream")
	p5UpPT, _ := p5UpPTRes.Token()
	p5UpPTClaims, _ := aauth.VerifyPersonToken(ctx, p5UpPT, p5Resolver, p5Clock)
	// Create a relay agent whose AgentProvider is p5RelayResIssuer
	p5RelayAgKey := newPKey("p5-relay-ag-1", 0xc2)
	p5RelayAgTok, _ := p5RelayAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:relay@p5-relay-res.example",
		PersonServer: p5PSIssuer,
		PublicKey:    p5RelayAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	p5RelayAgCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  "aauth:relay@p5-relay-res.example",
		SigningKey:  p5RelayAgKey,
		AgentToken:  p5RelayAgTok,
		KeyResolver: p5Resolver,
		HTTPClient:  httpClient,
		Clock:       p5Clock,
	})
	must(err, "clientagent.New p5RelayAgCli")
	p5DownPTRes, err := p5RelayAgCli.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: p5ResIssuer, UpstreamToken: p5UpPT})
	must(err, "p5RelayAgCli.PersonToken")
	p5DownPT, _ := p5DownPTRes.Token()
	p5DownRT, err := p5RelayAgCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      p5ResIssuer,
		PersonToken:   p5DownPT,
		UpstreamToken: p5UpPT,
		Scopes:        []string{"records.read"},
	})
	must(err, "p5RelayAgCli.Authorize")
	p5DownEx := clientagent.ExchangeRequest{ResourceToken: p5DownRT, PresentedToken: p5DownPT, UpstreamToken: p5UpPT}
	_, err = p5RelayAgCli.Exchange(ctx, p5DownEx)
	must(err, "p5RelayAgCli.Exchange")
	p5UpRev, err := p5PS.RevokePersonToken(ctx, p5UpPTClaims.JTI)
	must(err, "p5PS.RevokePersonToken upstream")
	_, p5UpPSRefuseErr := p5RelayAgCli.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: p5ResIssuer, UpstreamToken: p5UpPT})
	// Replace p5PS with a ledgerless PS to verify p5AS itself refuses the revoked upstream token
	p5LedgerlessCfg := p5PSCfg
	p5LedgerlessCfg.TokenRevocation = nil
	p5LedgerlessPS, _ := personserver.NewFederatedAuthorization(p5LedgerlessCfg)
	p5ActivePS.Store(p5LedgerlessPS.Handler())
	_, p5UpASRefuseErr := p5RelayAgCli.Exchange(ctx, p5DownEx)
	p5ActivePS.Store(p5PS.Handler())
	var p5UpProb1, p5UpProb2 *aauth.ProblemError
	p5UpstreamRevOK := len(p5UpRev.Attempts) == 2 &&
		errors.As(p5UpPSRefuseErr, &p5UpProb1) && p5UpProb1.Code == "revoked_upstream_token" &&
		errors.As(p5UpASRefuseErr, &p5UpProb2) && p5UpProb2.Code == "revoked_upstream_token"
	p5NowMu.Lock()
	p5Now = nowTime
	p5NowMu.Unlock()
	// =========================================================================
	// QA-P6: R3 Multi-Definition Composition & Release-Gated Proposal Results
	// =========================================================================
	const p6ResIssuer = "https://p6-r3-res.example"
	p6ResKey := newPKey("p6-res-1", 0xc3)
	p6Registry, err := r3.NewRegistry(mcp.Vocabulary())
	must(err, "r3.NewRegistry p6")
	p6Defs, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	must(err, "r3.NewDefinitionRegistry p6")
	p6DefSrc := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[` +
			`{"name":"records.query","inputSchema":{"type":"object"}},` +
			`{"name":"records.export","inputSchema":{"type":"object"}},` +
			`{"name":"records.billed","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}` +
			`]}`,
	)))
	p6Def, err := mcp.ParseDefinition(p6ResIssuer+"/mcp", p6DefSrc)
	must(err, "mcp.ParseDefinition p6")

	p6OpQuery, err := mcp.NewOperation("records.query")
	must(err, "mcp.NewOperation query")
	p6OpExport, err := mcp.NewOperation("records.export")
	must(err, "mcp.NewOperation export")
	p6OpBilled, err := mcp.NewOperation("records.billed")
	must(err, "mcp.NewOperation billed")
	p6R3Query, _ := p6OpQuery.ToR3()
	p6R3Export, _ := p6OpExport.ToR3()
	p6R3Billed, _ := p6OpBilled.ToR3()

	p6SetQuery, _ := mcp.NewOperationSet(p6OpQuery)
	p6SetExportBilled, _ := mcp.NewOperationSet(p6OpExport, p6OpBilled)
	p6Disp1, err := r3.NewDisplay("Query employee records", "Reads directory metadata", "Employee directory", "")
	must(err, "r3.NewDisplay 1")
	p6Disp2, err := r3.NewDisplay("Export and bill records", "Writes audit trail", "Compensation tables", "Exported files cannot be recalled")
	must(err, "r3.NewDisplay 2")
	p6MergedDisp, err := r3.MergeDisplays(p6Disp1, p6Disp2)
	must(err, "r3.MergeDisplays")
	p6MergeCheckOK := p6MergedDisp.Summary() == "Query employee records; Export and bill records" &&
		p6MergedDisp.Implications() == "Reads directory metadata\n\nWrites audit trail" &&
		p6MergedDisp.DataAccessed() == "Employee directory; Compensation tables" &&
		p6MergedDisp.Irreversible() == "Exported files cannot be recalled"

	// Negative validation check: uncovered vocabulary operations in InternalDefinitions must fail
	_, p6UncoveredErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            p6ResIssuer,
		AccessServer:      p5ASIssuer,
		SigningKey:        p6ResKey,
		KeyResolver:       p5Resolver,
		Clock:             p5Clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected:         http.NotFoundHandler(),
		R3: &resource.R3Config{
			Registry:    p6Registry,
			Definitions: p6Defs,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition: p6Def,
				InternalDefinitions: []resource.R3InternalDefinition{
					{Name: "query-only", Operations: p6SetQuery, Display: p6Disp1},
				},
			}},
			Documents: &memoryDocumentStore{},
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(*http.Request) (r3.Operation, bool, error) { return r3.Operation{}, false, nil },
				PresentParameters:   func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) { return nil, nil },
			},
		},
	})

	p6Docs := &memoryDocumentStore{}
	p6Props := &memoryProposalStore{}
	var p6ReleaseRuns atomic.Int32
	var p6BilledRuns atomic.Int32
	p6HeldStore := newPHeldBudgetStore()
	p6Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:                       p6ResIssuer,
		AccessServer:                 p5ASIssuer,
		SigningKey:                   p6ResKey,
		KeyResolver:                  p5Resolver,
		Clock:                        p5Clock,
		NewID:                        nextPID,
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopes:               func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		HeldInvocations:              p6HeldStore,
		HoldAuthTokenRequest:         func(*http.Request) bool { return true },
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/billed/") {
				p6BilledRuns.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `{"billed":true}`)
				return
			}
			p6ReleaseRuns.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"records":214}`)
		}),
		R3: &resource.R3Config{
			Registry:    p6Registry,
			Definitions: p6Defs,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition: p6Def,
				InternalDefinitions: []resource.R3InternalDefinition{
					{Name: "query-def", Operations: p6SetQuery, Display: p6Disp1},
					{Name: "export-billed-def", Operations: p6SetExportBilled, Display: p6Disp2},
				},
			}},
			Documents: p6Docs,
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(r *http.Request) (r3.Operation, bool, error) {
					if strings.HasPrefix(r.URL.Path, "/billed/") {
						return p6R3Billed, true, nil
					}
					if strings.HasPrefix(r.URL.Path, "/records/") {
						return p6R3Query, true, nil
					}
					return r3.Operation{}, false, nil
				},
				PresentParameters: func(r *http.Request, _ r3.Operation) (map[string]r3.PresentedParameter, error) {
					seg := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/records/"), "/billed/")
					enc, _ := json.Marshal(seg)
					pres, pErr := r3.NewPresentedInlineParameter(enc)
					if pErr != nil {
						return nil, pErr
					}
					return map[string]r3.PresentedParameter{"query": pres}, nil
				},
			},
			PerCall: &resource.R3PerCallConfig{
				Proposals: p6Props,
				Retries:   &memoryRetryStore{},
				DescribeCall: func(_ context.Context, inv r3.Invocation, _ *string) (resource.R3CallDescription, error) {
					enc, _ := inv.PresentedParameters()["query"].InlineJSON()
					inl, _ := r3.NewInlineParameter(enc)
					params, _ := r3.NewParameters(map[string]r3.Parameter{"query": inl})
					baseDisp, _ := r3.NewDisplay("Run billed operation", "", "Billing ledger", "")
					disp, _ := r3.NewProposalDisplay(baseDisp, "")
					return resource.R3CallDescription{Parameters: params, Display: &disp}, nil
				},
				Release: &resource.R3ReleaseConfig{
					Eligible: func(context.Context, r3.Invocation) (bool, error) { return true, nil },
					DescribeResult: func(_ context.Context, req resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
						enc, _ := req.Invocation.PresentedParameters()["query"].InlineJSON()
						inl, _ := r3.NewInlineParameter(enc)
						params, _ := r3.NewParameters(map[string]r3.Parameter{"query": inl})
						disp, _ := r3.NewDisplay("Release the result of a query over employee records", "", "214 employee records", "")
						return resource.R3ReleaseDescription{
							Parameters: params,
							Result:     json.RawMessage(`{"records":214,"contains":["compensation"]}`),
							Display:    disp,
							Detail:     "## Details\n214 rows.",
						}, nil
					},
				},
			},
		},
	})
	must(err, "resource.NewFederatedAuthorization p6Res")
	_, _ = registerTLS("p6-r3-res.example", p6Res.Handler())
	p6PTRes, err := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p6ResIssuer})
	must(err, "p5Cli.PersonToken p6")
	p6PT, _ := p6PTRes.Token()
	p6AuthzBody := `{"scope":"records.read","r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[{"tool":"records.query"},{"tool":"records.export"},{"tool":"records.billed"}]}}`
	p6AuthzReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p6ResIssuer+"/authorize", strings.NewReader(p6AuthzBody))
	p6AuthzReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequest(p6AuthzReq, p1AgentKey, p6PT, p5Clock), "SignJWTRequest p6AuthzReq")
	p6AuthzResp, err := httpClient.Do(p6AuthzReq)
	must(err, "Do p6AuthzReq")
	var p6AuthzOut struct {
		ResourceToken string `json:"resource_token"`
	}
	_ = json.NewDecoder(p6AuthzResp.Body).Decode(&p6AuthzOut)
	_ = p6AuthzResp.Body.Close()
	p6ClassClaims, p6ClassRef, err := r3.VerifyResourceToken(ctx, p6AuthzOut.ResourceToken, p5Resolver, p5Clock)
	must(err, "r3.VerifyResourceToken p6")
	p6ClassRec, err := p6Docs.Load(ctx, p6ClassRef.URI())
	must(err, "p6Docs.Load")
	p6ClassDoc, err := p6Registry.ParseReferencedDocument(p6ClassRef, p6ClassRec.ExactJSON)
	must(err, "ParseReferencedDocument p6")
	p6DocDisp, p6HasDocDisp := p6ClassDoc.Display()
	p6ComposedDocOK := p6HasDocDisp && p6DocDisp.Summary() == p6MergedDisp.Summary() &&
		p6DocDisp.Implications() == p6MergedDisp.Implications() &&
		p6DocDisp.DataAccessed() == p6MergedDisp.DataAccessed() &&
		p6DocDisp.Irreversible() == p6MergedDisp.Irreversible()

	p6EmptyOps, _ := r3.NewGrantedOperations(mcp.Vocabulary())
	p6PerCallOps, _ := r3.NewGrantedOperations(mcp.Vocabulary(), p6R3Query, p6R3Export, p6R3Billed)
	p6ClassAuthz, err := r3.NewAuthorization(p6EmptyOps, p6PerCallOps, p6ClassDoc)
	must(err, "r3.NewAuthorization p6")
	p6MakeClaims := func(jti string) aauth.AuthTokenClaims {
		return aauth.AuthTokenClaims{
			Issuer:       p5ASIssuer,
			DWK:          aauth.AccessDiscoveryDocument,
			Audience:     p6ResIssuer,
			JTI:          jti,
			PersonServer: p5PSIssuer,
			Subject:      p6ClassClaims.Subject,
			Tenant:       p6ClassClaims.Tenant,
			Confirmation: aauth.Confirmation{JWK: p1AgentKey.PublicJWK()},
			IssuedAt:     p5Clock.Now().Unix(),
			ExpiresAt:    p5Clock.Now().Add(30 * time.Minute).Unix(),
			Scope:        "records.read",
		}
	}
	p6ClassAuthTok, err := r3.MintAuthToken(p6Registry, p5ASKey, p6MakeClaims("p6-class-auth"), p6ClassRef, p6ClassRec.ExactJSON, p6ClassAuthz)
	must(err, "r3.MintAuthToken p6")

	// Release-gated call on /records/engineering runs once before approval
	p6CallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p6ResIssuer+"/records/engineering", nil)
	must(signaturekey.SignJWTRequest(p6CallReq, p1AgentKey, p6ClassAuthTok, p5Clock), "SignJWTRequest p6CallReq")
	p6CallResp, err := httpClient.Do(p6CallReq)
	must(err, "Do p6CallReq")
	_, _ = io.ReadAll(p6CallResp.Body)
	_ = p6CallResp.Body.Close()
	p6RunsAfterChallenge := p6ReleaseRuns.Load()
	p6HoldLoc := p6CallResp.Header.Get("Location")
	p6ReqHeader, err := aauth.ParseAuthTokenRequirement(p6CallResp.Header.Values("AAuth-Requirement"))
	must(err, "ParseAuthTokenRequirement p6")
	_, p6PropRef, err := r3.VerifyResourceToken(ctx, p6ReqHeader.ResourceToken, p5Resolver, p5Clock)
	must(err, "VerifyResourceToken p6PropRef")
	p6PropRec, err := p6Props.Load(ctx, p6PropRef.URI())
	must(err, "p6Props.Load")
	p6Prop, err := p6Registry.ParseReferencedProposal(p6PropRef, p6PropRec.ExactJSON)
	must(err, "ParseReferencedProposal p6")
	p6PropResBytes, p6HasPropRes := p6Prop.Result()
	p6PropDisp, p6HasPropDisp := p6Prop.Display()
	p6ProposalResultOK := p6CallResp.StatusCode == http.StatusAccepted && p6RunsAfterChallenge == 1 &&
		p6HasPropRes && string(p6PropResBytes) == `{"records":214,"contains":["compensation"]}` &&
		p6HasPropDisp && p6PropDisp.Detail() == r3.ReleaseAction+"\n\n## Details\n214 rows."

	p6PerCallTok, err := r3.MintPerCallAuthToken(p6Registry, p5ASKey, p6MakeClaims("p6-percall-auth"), p6PropRef, p6PropRec.ExactJSON)
	must(err, "MintPerCallAuthToken p6")
	p6Poll1Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p6HoldLoc, nil)
	must(signaturekey.SignJWTRequest(p6Poll1Req, p1AgentKey, p6PerCallTok, p5Clock), "SignJWTRequest p6Poll1Req")
	p6Poll1Resp, err := httpClient.Do(p6Poll1Req)
	must(err, "Do p6Poll1Req")
	p6Poll1Body, _ := io.ReadAll(p6Poll1Resp.Body)
	_ = p6Poll1Resp.Body.Close()
	p6Poll2Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p6HoldLoc, nil)
	must(signaturekey.SignJWTRequest(p6Poll2Req, p1AgentKey, p6PerCallTok, p5Clock), "SignJWTRequest p6Poll2Req")
	p6Poll2Resp, err := httpClient.Do(p6Poll2Req)
	must(err, "Do p6Poll2Req")
	p6Poll2Body, _ := io.ReadAll(p6Poll2Resp.Body)
	_ = p6Poll2Resp.Body.Close()
	p6ReleasePollOK := p6Poll1Resp.StatusCode == http.StatusOK && strings.Contains(string(p6Poll1Body), `"records":214`) &&
		p6Poll2Resp.StatusCode == http.StatusOK && string(p6Poll2Body) == string(p6Poll1Body) &&
		p6ReleaseRuns.Load() == 1

	// Operation annotated _meta: {"aauth.dev/budget": true} (/billed/inv-1) must NOT run before approval
	p6BilledReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p6ResIssuer+"/billed/inv-1", nil)
	must(signaturekey.SignJWTRequest(p6BilledReq, p1AgentKey, p6ClassAuthTok, p5Clock), "SignJWTRequest p6BilledReq")
	p6BilledResp, err := httpClient.Do(p6BilledReq)
	must(err, "Do p6BilledReq")
	_ = p6BilledResp.Body.Close()
	p6BilledRunsBefore := p6BilledRuns.Load()
	p6BilledReqHdr, _ := aauth.ParseAuthTokenRequirement(p6BilledResp.Header.Values("AAuth-Requirement"))
	_, p6BilledPropRef, _ := r3.VerifyResourceToken(ctx, p6BilledReqHdr.ResourceToken, p5Resolver, p5Clock)
	p6BilledPropRec, _ := p6Props.Load(ctx, p6BilledPropRef.URI())
	p6BilledProp, _ := p6Registry.ParseReferencedProposal(p6BilledPropRef, p6BilledPropRec.ExactJSON)
	_, p6BilledHasResult := p6BilledProp.Result()
	p6BilledTok, _ := r3.MintPerCallAuthToken(p6Registry, p5ASKey, p6MakeClaims("p6-billed-auth"), p6BilledPropRef, p6BilledPropRec.ExactJSON)
	p6BilledPollReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p6BilledResp.Header.Get("Location"), nil)
	must(signaturekey.SignJWTRequest(p6BilledPollReq, p1AgentKey, p6BilledTok, p5Clock), "SignJWTRequest p6BilledPollReq")
	p6BilledPollResp, err := httpClient.Do(p6BilledPollReq)
	must(err, "Do p6BilledPollReq")
	_ = p6BilledPollResp.Body.Close()
	p6BudgetGatedOK := p6BilledResp.StatusCode == http.StatusAccepted && p6BilledRunsBefore == 0 &&
		!p6BilledHasResult && p6BilledPollResp.StatusCode == http.StatusOK && p6BilledRuns.Load() == 1
	// =========================================================================
	// QA-P7: Budgets Held Refusals, Replays & Signed Usage Answers (Rust <-> Go)
	// =========================================================================
	_ = (*testing.T)(nil)
	_ = apstoretest.RunEventInboxReader

	const p7ResIssuer = "https://p7-budget-res.example"
	p7ResKey := newPKey("p7-res-1", 0xc3)
	p7Unit, err := budgets.NewUnit("USD", 6)
	must(err, "budgets.NewUnit p7")
	p7Decl, err := budgets.NewBoundedUnitDeclaration(p7Unit, 1_000_000, "US dollars at micro-dollar precision")
	must(err, "budgets.NewBoundedUnitDeclaration p7")
	const p7Cost int64 = 7
	var p7Runs atomic.Int32
	p7BudgetStore := newPBudgetReserverStore(p7Unit)
	p7HeldStore := newPHeldBudgetStore()

	p7Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:                       p7ResIssuer,
		AccessServer:                 p5ASIssuer,
		SigningKey:                   p7ResKey,
		KeyResolver:                  p5Resolver,
		Clock:                        p5Clock,
		NewID:                        nextPID,
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopes:               func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		HeldInvocations:              p7HeldStore,
		HoldAuthTokenRequest:         func(*http.Request) bool { return true },
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			p7Runs.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"report":"ready"}`)
		}),
		Budget: &resource.BudgetConfig{
			Units:         []budgets.UnitDeclaration{p7Decl},
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return p7Cost, nil },
			Store:         p7BudgetStore,
			Challenge: func(_ context.Context, req resource.BudgetChallengeRequest) (string, error) {
				jkt, _ := req.Principal.Confirmation.Thumbprint()
				cons, _ := budgets.NewConsumptionRecord(req.Token.JTI, req.Consumed)
				offer, _ := budgets.NewValue(50, p7Unit)
				return budgets.MintResourceToken(p7ResKey, aauth.ResourceTokenClaims{
					Issuer:       p7ResIssuer,
					DWK:          aauth.ResourceDiscoveryDocument,
					Audience:     p5ASIssuer,
					JTI:          "p7-fresh-" + req.Token.JTI,
					PersonServer: req.Principal.PersonServer,
					Subject:      req.Principal.Subject,
					PresentedJTI: req.Token.JTI,
					AgentJKT:     jkt,
					IssuedAt:     p5Clock.Now().Unix(),
					ExpiresAt:    p5Clock.Now().Add(5 * time.Minute).Unix(),
					Scope:        strings.Join(req.Principal.Scope, " "),
					Tenant:       req.Principal.Tenant,
				}, offer, &cons)
			},
		},
	})
	must(err, "resource.NewFederatedAuthorization p7Res")
	p7ResSrv, p7ResDER := registerTLS("p7-budget-res.example", p7Res.Handler())

	p7MintBudgetTok := func(jti string, amount int64) string {
		val, _ := budgets.NewValue(amount, p7Unit)
		tok, mErr := budgets.MintAuthToken(p5ASKey, aauth.AuthTokenClaims{
			Issuer:       p5ASIssuer,
			DWK:          aauth.AccessDiscoveryDocument,
			Audience:     p7ResIssuer,
			JTI:          jti,
			PersonServer: p5PSIssuer,
			Subject:      "person-p7",
			Confirmation: aauth.Confirmation{JWK: p1AgentKey.PublicJWK()},
			IssuedAt:     p5Clock.Now().Unix(),
			ExpiresAt:    p5Clock.Now().Add(time.Hour).Unix(),
			Scope:        "records.read",
			Tenant:       "tenant-p7",
		}, val)
		must(mErr, "budgets.MintAuthToken "+jti)
		return tok
	}
	p7DoSigned := func(tok, target string) (*http.Response, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		must(signaturekey.SignJWTRequest(req, p1AgentKey, tok, p5Clock), "SignJWTRequest p7")
		resp, dErr := httpClient.Do(req)
		must(dErr, "Do p7")
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}

	// 1. Refused token (5 < 7) gets 202 held refusal, reserves nothing, runs 0 times
	p7RefusedResp, _ := p7DoSigned(p7MintBudgetTok("p7-refused", 5), p7ResIssuer+"/records")
	p7Loc := p7RefusedResp.Header.Get("Location")
	p7RefFB, _ := budgets.ParseFeedback(p7RefusedResp.Header.Values("AAuth-Budget"))
	p7RefReq, p7RefHasReq := p7RefFB.Required()
	_, p7RefHasCost := p7RefFB.Cost()
	_, p7RefHasRes := p7RefFB.Reserved()
	p7RefVal5, _ := budgets.NewValue(5, p7Unit)
	p7RefObs, p7RefObsErr := p7BudgetStore.Charge(ctx, resource.BudgetCharge{
		Token:        aauth.TokenReference{Issuer: p5ASIssuer, JTI: "p7-refused"},
		PersonServer: p5PSIssuer,
		Subject:      "person-p7",
		Audience:     p7ResIssuer,
		Tenant:       "tenant-p7",
		Grant:        p7RefVal5,
		Cost:         0,
	})
	p7RefusalHeldOK := p7RefusedResp.StatusCode == http.StatusAccepted && p7Loc != "" &&
		p7RefFB.Remaining() == 5 && p7RefHasReq && p7RefReq == p7Cost && !p7RefHasCost && !p7RefHasRes &&
		p7RefObsErr == nil && p7RefObs.Remaining == 5 && p7Runs.Load() == 0

	// 2. Poll with short-token (6 < 7) rechallenges at same Location
	p7ShortResp, _ := p7DoSigned(p7MintBudgetTok("p7-short", 6), p7Loc)
	p7ShortReqHdr, p7ShortReason, _ := budgets.ParseAuthTokenRequirement(p7ShortResp.Header.Values("AAuth-Requirement"))
	p7ShortClaims, _, _, _ := budgets.VerifyResourceToken(ctx, p7ShortReqHdr.ResourceToken, p5Resolver, p5Clock)
	p7RechallengeOK := p7ShortResp.StatusCode == http.StatusAccepted && p7ShortResp.Header.Get("Location") == p7Loc &&
		p7ShortReason == budgets.ReasonInsufficientBudget && p7ShortClaims.PresentedJTI == "p7-short" && p7Runs.Load() == 0

	// 3. Poll with completing-token (20) executes once (cost=7, remaining=13) and replay does not double-meter
	p7CompTok := p7MintBudgetTok("p7-completing", 20)
	p7CompResp, p7CompBody := p7DoSigned(p7CompTok, p7Loc)
	p7CompFB, _ := budgets.ParseFeedback(p7CompResp.Header.Values("AAuth-Budget"))
	p7CompPaid, _ := p7CompFB.Cost()
	p7ReplayResp, p7ReplayBody := p7DoSigned(p7CompTok, p7Loc)
	p7ReplayFB, _ := budgets.ParseFeedback(p7ReplayResp.Header.Values("AAuth-Budget"))
	p7ReplayPaid, _ := p7ReplayFB.Cost()
	_, p7ReplayHasRes := p7ReplayFB.Reserved()
	p7OtherResp, _ := p7DoSigned(p7MintBudgetTok("p7-other", 30), p7Loc)
	p7CompleteAndReplayOK := p7CompResp.StatusCode == http.StatusOK && p7CompPaid == p7Cost && p7CompFB.Remaining() == 13 &&
		p7ReplayResp.StatusCode == http.StatusOK && p7ReplayBody == p7CompBody && p7ReplayPaid == p7Cost &&
		p7ReplayFB.Remaining() == 13 && !p7ReplayHasRes && p7Runs.Load() == 1 &&
		p7OtherResp.StatusCode == http.StatusForbidden

	// 4. Signed usage answers: Go PostUsageChecked -> Go Resource AND Go PostUsageChecked -> Rust Resource
	p7GoUsageRes, err := budgets.PostUsageChecked(
		ctx, p7ResIssuer+"/usage", p5PSKey, p5PSIssuer, aauth.PersonDiscoveryDocument, p5Clock,
		budgets.UsageRequest{Subject: "person-p7"},
		budgets.UsageSignatureCheck{
			Resource:         p7ResIssuer,
			KeyResolver:      p5Resolver,
			RequireSignature: true,
			Client:           httpClient,
		},
	)
	must(err, "budgets.PostUsageChecked Go->Go")
	// Verify tamper rejection via VerifyUsageResponse on altered body & wrong path
	p7TamperReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p7ResIssuer+"/usage", nil)
	_, p7TamperBodyErr := budgets.VerifyUsageResponse(
		ctx, p7TamperReq, http.StatusOK, p7GoUsageRes.Header, append(p7GoUsageRes.ExactBody, ' '),
		p7ResIssuer, p5Resolver, p5Clock,
	)
	p7WrongPathReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p7ResIssuer+"/usage-v2", nil)
	_, p7WrongPathErr := budgets.VerifyUsageResponse(
		ctx, p7WrongPathReq, http.StatusOK, p7GoUsageRes.Header, p7GoUsageRes.ExactBody,
		p7ResIssuer, p5Resolver, p5Clock,
	)
	// Go PostUsageChecked -> Rust Resource (/usage with handle_signed_usage)
	p7RustUsageRes, err := budgets.PostUsageChecked(
		ctx, in.RustUsageResIssuer+"/usage", p5PSKey, p5PSIssuer, aauth.PersonDiscoveryDocument, p5Clock,
		budgets.UsageRequest{Subject: "person-p7"},
		budgets.UsageSignatureCheck{
			Resource:         in.RustUsageResIssuer,
			KeyResolver:      p5Resolver,
			RequireSignature: true,
			Client:           httpClient,
		},
	)
	must(err, "budgets.PostUsageChecked Go->Rust")
	p7SignedUsageOK := p7GoUsageRes.Signed && p7GoUsageRes.Response.Usage != nil && p7GoUsageRes.Response.Usage.AllTime == p7Cost &&
		p7TamperBodyErr != nil && p7WrongPathErr != nil &&
		p7RustUsageRes.Signed && p7RustUsageRes.Response.Usage != nil && p7RustUsageRes.Response.Usage.AllTime > 0
	// =========================================================================
	// QA-P8: Events Inbox Reader (agentprovider.EventInboxReader) & Cross-Language
	// =========================================================================
	const (
		p8APIssuer  = "https://p8-events-ap.example"
		p8AgentID   = "aauth:reader@p8-events-ap.example"
		p8ResIssuer = "https://p8-events-res.example"
	)
	p8APKey := newPKey("p8-ap-1", 0xc5)
	p8AgentKey := newPKey("p8-agent-1", 0xc6)
	p8ResKey := newPKey("p8-res-1", 0xc7)
	p8InboxStore := newPReadableInboxStore()

	p8ResMux := http.NewServeMux()
	p8ResMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   p8ResIssuer,
			"jwks_uri": p8ResIssuer + "/.well-known/jwks.json",
		})
	})
	p8ResMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{p8ResKey.PublicJWK()}})
	})
	_, _ = registerTLS("p8-events-res.example", p8ResMux)

	p8AP, err := agentprovider.New(agentprovider.Config{
		Issuer:     p8APIssuer,
		SigningKey: p8APKey,
		Clock:      p5Clock,
		NewID:      nextPID,
		Events: &agentprovider.EventsConfig{
			EventEndpoint: p8APIssuer + "/events",
			NewEventID:    nextPID,
			KeyResolver:   p5Resolver,
			Store:         p8InboxStore,
		},
	})
	must(err, "agentprovider.New p8AP")
	p8APMux := http.NewServeMux()
	p8APMux.HandleFunc("GET /__p8-pending", func(w http.ResponseWriter, r *http.Request) {
		ag := r.URL.Query().Get("agent")
		pend, pErr := p8AP.PendingEvents(r.Context(), ag)
		if pErr != nil {
			http.Error(w, pErr.Error(), http.StatusInternalServerError)
			return
		}
		type item struct {
			EventID     string `json:"event_id"`
			Resource    string `json:"resource"`
			Token       string `json:"token"`
			ContentType string `json:"content_type"`
			Payload     string `json:"payload"`
		}
		out := make([]item, len(pend))
		for i, d := range pend {
			out[i] = item{
				EventID:     d.EventID,
				Resource:    d.Resource,
				Token:       d.Token,
				ContentType: d.ContentType,
				Payload:     string(d.Payload),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	p8APMux.HandleFunc("POST /__p8-ack", func(w http.ResponseWriter, r *http.Request) {
		ag := r.URL.Query().Get("agent")
		pend, pErr := p8AP.PendingEvents(r.Context(), ag)
		if pErr != nil || len(pend) == 0 {
			http.Error(w, "no pending events", http.StatusBadRequest)
			return
		}
		aErr := p8AP.AcknowledgeEvent(r.Context(), ag, pend[0].Fingerprint)
		if aErr != nil {
			http.Error(w, aErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
	})
	p8APMux.Handle("/", p8AP.Handler())
	p8APSrv, p8APDER := registerTLS("p8-events-ap.example", p8APMux)

	// Deliver Go event with non-canonical whitespace to p8AP /events over HTTPS
	p8Payload := []byte("{\n  \"event_type\": \"slot.available\",\n  \"slot\": \"10:00\"\n}")
	p8EvTok, err := events.MintEventToken(p8ResIssuer, p8ResKey, events.EventTokenRequest{
		Agent:    p8AgentID,
		EventID:  "p8-ev-1",
		JTI:      "p8-jti-1",
		Payload:  p8Payload,
		Lifetime: 5 * time.Minute,
	}, p5Clock.Now())
	must(err, "events.MintEventToken p8")
	p8DelivReq := func() *http.Request {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p8APIssuer+"/events", bytes.NewReader(p8Payload))
		req.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignSelfJWTRequestWithOptions(req, p8ResKey, p8EvTok, p5Clock, signaturekey.SignOptions{
			AdditionalComponents: []string{"content-type"},
		}), "SignSelfJWTRequestWithOptions p8")
		return req
	}
	p8DelivResp1, err := httpClient.Do(p8DelivReq())
	must(err, "Do p8DelivReq 1")
	_ = p8DelivResp1.Body.Close()
	// Duplicate delivery is not queued a second time
	p8DelivResp2, err := httpClient.Do(p8DelivReq())
	must(err, "Do p8DelivReq 2 dup")
	_ = p8DelivResp2.Body.Close()

	p8Pend, err := p8AP.PendingEvents(ctx, p8AgentID)
	must(err, "p8AP.PendingEvents")
	p8OtherPend, err := p8AP.PendingEvents(ctx, "aauth:other@p8-events-ap.example")
	must(err, "p8AP.PendingEvents other")

	// Tamper & misroute checks on p8AP.PendingEvents
	p8InboxStore.mu.Lock()
	p8InboxStore.tamperAgent = p8AgentID
	p8InboxStore.tamperMode = "payload"
	p8InboxStore.mu.Unlock()
	_, p8TamperPayloadErr := p8AP.PendingEvents(ctx, p8AgentID)
	p8InboxStore.mu.Lock()
	p8InboxStore.tamperMode = "token"
	p8InboxStore.mu.Unlock()
	_, p8TamperTokErr := p8AP.PendingEvents(ctx, p8AgentID)
	p8InboxStore.mu.Lock()
	p8InboxStore.tamperMode = "agent"
	p8InboxStore.mu.Unlock()
	_, p8MisrouteErr := p8AP.PendingEvents(ctx, p8AgentID)
	p8InboxStore.mu.Lock()
	p8InboxStore.tamperAgent = ""
	p8InboxStore.tamperMode = ""
	p8InboxStore.mu.Unlock()

	// Verify Agent.AcceptEvent accepts the exact bytes from PendingEvents
	p8AgentStore := newGoAgentEventStore()
	_ = p8AgentStore.BindContext(ctx, clientagent.EventContext{
		Resource: p8ResIssuer,
		EventID:  "p8-ev-1",
		Context:  []byte(`{"waitlist":"10:00"}`),
	})
	p8AgTok, _ := p8AP.Issue(aauth.AgentTokenRequest{
		Agent:     p8AgentID,
		PublicKey: p8AgentKey.PublicJWK(),
		Lifetime:  time.Hour,
	})
	p8AgCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  p8AgentID,
		SigningKey:  p8AgentKey,
		AgentToken:  p8AgTok,
		KeyResolver: p5Resolver,
		HTTPClient:  httpClient,
		Clock:       p5Clock,
		Events:      &clientagent.EventsConfig{Store: p8AgentStore},
	})
	must(err, "clientagent.New p8AgCli")
	p8AcceptedEv, err := p8AgCli.AcceptEvent(ctx, clientagent.EventDeliveryInput{
		EventToken:  p8Pend[0].Token,
		Payload:     p8Pend[0].Payload,
		ContentType: p8Pend[0].ContentType,
	})
	must(err, "p8AgCli.AcceptEvent")
	must(p8AP.AcknowledgeEvent(ctx, p8AgentID, p8Pend[0].Fingerprint), "p8AP.AcknowledgeEvent")
	p8PendAfterAck, err := p8AP.PendingEvents(ctx, p8AgentID)
	must(err, "p8AP.PendingEvents after ack")
	// Replay after ack is still deduplicated and not queued again
	p8DelivResp3, err := httpClient.Do(p8DelivReq())
	must(err, "Do p8DelivReq 3 after ack")
	_ = p8DelivResp3.Body.Close()
	p8PendAfterReplay, _ := p8AP.PendingEvents(ctx, p8AgentID)
	// Store without EventInboxReader returns ErrEventInboxNotReadable
	p8NonReadableAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     p8APIssuer,
		SigningKey: p8APKey,
		Clock:      p5Clock,
		NewID:      nextPID,
		Events: &agentprovider.EventsConfig{
			EventEndpoint: p8APIssuer + "/events",
			NewEventID:    nextPID,
			KeyResolver:   p5Resolver,
			Store:         pNonReadableInboxStore{},
		},
	})
	must(err, "agentprovider.New p8NonReadableAP")
	_, p8NotReadableErr := p8NonReadableAP.PendingEvents(ctx, p8AgentID)
	p8GoInboxOK := p8DelivResp1.StatusCode == http.StatusAccepted && p8DelivResp2.StatusCode == http.StatusAccepted &&
		len(p8Pend) == 1 && p8Pend[0].Token == p8EvTok && bytes.Equal(p8Pend[0].Payload, p8Payload) &&
		len(p8OtherPend) == 0 && p8TamperPayloadErr != nil && p8TamperTokErr != nil && p8MisrouteErr != nil &&
		bytes.Equal(p8AcceptedEv.Payload, p8Payload) && len(p8PendAfterAck) == 0 &&
		p8DelivResp3.StatusCode == http.StatusAccepted && len(p8PendAfterReplay) == 0 &&
		errors.Is(p8NotReadableErr, agentprovider.ErrEventInboxNotReadable)
	// =========================================================================
	// QA-P9: Further Signature-Key Schemes at Resources (FurtherSchemesConfig)
	// =========================================================================
	const (
		p9ResIssuer  = "https://p9-further-res.example"
		p9JWKSURL    = "https://p9-client.example/keys.json"
		p9CertURL    = "https://p9-client.example/cert.pem"
	)
	p9ResKey := newPKey("p9-res-1", 0xc8)
	p9ECPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "ecdsa.GenerateKey P256 p9")
	p9ClientECKey, err := jose.NewSigningKeyForAlgorithm("p9-client-ec", jose.ES256Algorithm, p9ECPriv)
	must(err, "NewSigningKeyForAlgorithm ES256 p9")
	p9P384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(err, "ecdsa.GenerateKey P384 p9")
	p9UnlistedKey, err := jose.NewSigningKeyForAlgorithm("p9-client-p384", jose.ES384Algorithm, p9P384Priv)
	must(err, "NewSigningKeyForAlgorithm ES384 p9")
	p9JWKSKey := newPKey("p9-client-jwks", 0xc9)
	p9DurableKey := newPKey("p9-client-durable", 0xca)
	p9EphKey := newPKey("p9-client-eph", 0xcb)

	// Build Root CA + Leaf cert + CRL for x509 scheme
	p9RootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err, "ecdsa.GenerateKey root p9")
	p9RootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "P9 Client Root"},
		NotBefore:             p5Clock.Now().Add(-time.Hour),
		NotAfter:              p5Clock.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	p9RootDER, err := x509.CreateCertificate(rand.Reader, p9RootTmpl, p9RootTmpl, p9RootPriv.Public(), p9RootPriv)
	must(err, "x509.CreateCertificate root p9")
	p9RootCert, _ := x509.ParseCertificate(p9RootDER)
	p9LeafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "p9-client.example"},
		NotBefore:    p5Clock.Now().Add(-time.Hour),
		NotAfter:     p5Clock.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, p9RootCert, p9ClientECKey.Public(), p9RootPriv)
	must(err, "x509.CreateCertificate leaf p9")
	p9LeafCert, _ := x509.ParseCertificate(p9LeafDER)
	p9CRLDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(3),
		ThisUpdate: p5Clock.Now().Add(-time.Hour),
		NextUpdate: p5Clock.Now().Add(time.Hour),
	}, p9RootCert, p9RootPriv)
	must(err, "x509.CreateRevocationList p9")
	p9CRL, _ := x509.ParseRevocationList(p9CRLDER)

	p9Cache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: bytes.Repeat([]byte{9}, 32)})
	must(err, "NewAssertionCache p9")

	var p9AAuthCalls atomic.Int32
	var p9FurtherCalls atomic.Int32
	p9Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            p9ResIssuer,
		SigningKey:        p9ResKey,
		KeyResolver:       p5Resolver,
		Clock:             p5Clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"items.read": "Read items"},
		RequiredScopes:    func(*http.Request) []string { return []string{"items.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Revocation:        &resource.RevocationConfig{PersonTokens: testutil.NewTokenRevocationStore()},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p9AAuthCalls.Add(1)
			_, hasSigner := resource.SignerFromContext(r.Context())
			p, hasAuth := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"route":       "aauth",
				"has_signer":  hasSigner,
				"has_auth":    hasAuth,
				"subject":     p.Subject,
				"aauth_calls": p9AAuthCalls.Load(),
			})
		}),
		FurtherSchemes: &resource.FurtherSchemesConfig{
			Schemes: []signaturekey.Scheme{
				signaturekey.SchemeHWK,
				signaturekey.SchemeJKTJWT,
				signaturekey.SchemeJWKSURI,
				signaturekey.SchemeJWKS,
				signaturekey.SchemeX509,
				signaturekey.SchemeCached,
			},
			Algorithms: []string{jose.ES256Algorithm},
			JWKS: signaturekey.StaticJWKSResolver{
				{URL: p9JWKSURL, KeyID: p9JWKSKey.ID()}: p9JWKSKey.PublicJWK(),
			},
			X509: func(_ context.Context, certURL string) (signaturekey.X509VerifyOptions, error) {
				if certURL != p9CertURL {
					return signaturekey.X509VerifyOptions{}, errors.New("unexpected x5u")
				}
				return signaturekey.X509VerifyOptions{
					ChainPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p9LeafCert.Raw}),
					Roots:           []*x509.Certificate{p9RootCert},
					RevocationLists: []*x509.RevocationList{p9CRL},
				}, nil
			},
			Cache: p9Cache,
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p9FurtherCalls.Add(1)
				signer, hasSigner := resource.SignerFromContext(r.Context())
				_, hasAuth := resource.AuthPrincipalFromContext(r.Context())
				_, hasPerson := resource.PersonPrincipalFromContext(r.Context())
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"route":      "further",
					"has_signer": hasSigner,
					"scheme":     string(signer.Scheme),
					"signer":     signer.Signer,
					"has_x509":   signer.X509 != nil,
					"has_auth":   hasAuth,
					"has_person": hasPerson,
				})
			}),
		},
	})
	must(err, "resource.NewPSAuthorization p9Res")
	p9ResSrv, p9ResDER := registerTLS("p9-further-res.example", p9Res.Handler())
	p9Send := func(k jose.SigningKey, cred signaturekey.Credential, path string) (*http.Response, map[string]any) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p9ResIssuer+path, nil)
		must(signaturekey.SignRequest(req, k, cred, p5Clock, signaturekey.SignOptions{}), "SignRequest p9")
		resp, dErr := httpClient.Do(req)
		must(dErr, "Do p9")
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		return resp, out
	}

	const p9WantSchemes = "jwt, hwk, jkt-jwt, jwks_uri, jwks, x509, cached"
	const p9WantAlgs = "Ed25519, ES256"
	p9UnsignedReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p9ResIssuer+"/items", nil)
	p9UnsignedResp, err := httpClient.Do(p9UnsignedReq)
	must(err, "Do p9UnsignedReq")
	_ = p9UnsignedResp.Body.Close()
	p9ChallengeHeadersOK := p9UnsignedResp.StatusCode == http.StatusUnauthorized &&
		p9UnsignedResp.Header.Get("Accept-Signature-Scheme") == p9WantSchemes &&
		p9UnsignedResp.Header.Get("Accept-Signature-Alg") == p9WantAlgs

	p9HWKCred, _ := signaturekey.NewHWKCredential(p9ClientECKey.PublicJWK())
	p9HWKResp, p9HWKOut := p9Send(p9ClientECKey, p9HWKCred, "/items")
	p9JWKSCred, _ := signaturekey.NewJWKSCredential(p9JWKSURL, p9JWKSKey.ID())
	p9JWKSResp, p9JWKSOut := p9Send(p9JWKSKey, p9JWKSCred, "/items")
	p9JWKSURICred, _ := signaturekey.NewJWKSURICredential(p8ResIssuer, aauth.ResourceDiscoveryDocument, p8ResKey.ID())
	p9JWKSURIResp, p9JWKSURIOut := p9Send(p8ResKey, p9JWKSURICred, "/items")
	p9X509Cred, _ := signaturekey.NewX509Credential(p9CertURL, p9LeafCert)
	p9X509Resp, p9X509Out := p9Send(p9ClientECKey, p9X509Cred, "/items")
	p9Delegation, _ := signaturekey.MintJKTJWT(p9DurableKey, p9EphKey.PublicJWK(), p5Clock.Now(), p5Clock.Now().Add(time.Hour), "p9-del-1")
	p9JKTJWTCred, _ := signaturekey.NewJKTJWTCredential(p9Delegation)
	p9JKTJWTCred, _ = p9JKTJWTCred.WithCache()
	p9JKTJWTResp, p9JKTJWTOut := p9Send(p9EphKey, p9JKTJWTCred, "/items")
	p9CacheGrants, p9CacheParseErr := signaturekey.ParseCacheGrants(p9JKTJWTResp.Header.Values("Signature-Key-Cache"))
	p9CachedCred, _ := signaturekey.NewCachedCredential(p9CacheGrants[0])
	p9CachedResp, p9CachedOut := p9Send(p9EphKey, p9CachedCred, "/items")

	p9ECThumbURI, _ := p9ClientECKey.PublicJWK().ThumbprintURI()
	p9DurThumbURI, _ := p9DurableKey.PublicJWK().ThumbprintURI()
	p9AllSchemesOK := p9HWKResp.StatusCode == http.StatusOK && p9HWKOut["scheme"] == "hwk" && p9HWKOut["signer"] == p9ECThumbURI && p9HWKOut["has_auth"] == false &&
		p9JWKSResp.StatusCode == http.StatusOK && p9JWKSOut["scheme"] == "jwks" && p9JWKSOut["signer"] == p9JWKSURL &&
		p9JWKSURIResp.StatusCode == http.StatusOK && p9JWKSURIOut["scheme"] == "jwks_uri" && p9JWKSURIOut["signer"] == p8ResIssuer &&
		p9X509Resp.StatusCode == http.StatusOK && p9X509Out["scheme"] == "x509" && p9X509Out["signer"] == p9CertURL && p9X509Out["has_x509"] == true &&
		p9JKTJWTResp.StatusCode == http.StatusOK && p9JKTJWTOut["scheme"] == "jkt-jwt" && p9JKTJWTOut["signer"] == p9DurThumbURI && p9CacheParseErr == nil && len(p9CacheGrants) == 1 &&
		p9CachedResp.StatusCode == http.StatusOK && p9CachedOut["scheme"] == "cached" && p9CachedOut["signer"] == p9DurThumbURI &&
		p9AAuthCalls.Load() == 0

	// AAuth jwt request still routes to AAuth handler
	p9PTRes, _ := p2CallerCli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p2PSIssuer, Resource: p9ResIssuer})
	p9PT, _ := p9PTRes.Token()
	p9RT, _ := p2CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{Resource: p9ResIssuer, PersonToken: p9PT, Scopes: []string{"items.read"}})
	p9AT, _ := p2CallerCli.Exchange(ctx, clientagent.ExchangeRequest{PersonServer: p2PSIssuer, ResourceToken: p9RT, PresentedToken: p9PT})
	p9JWTCred, _ := signaturekey.NewJWTCredential(p9AT)
	p9JWTResp, p9JWTOut := p9Send(p1AgentKey, p9JWTCred, "/items")
	p9AAuthRouteOK := p9JWTResp.StatusCode == http.StatusOK && p9JWTOut["route"] == "aauth" && p9JWTOut["has_auth"] == true && p9JWTOut["has_signer"] == false && p9AAuthCalls.Load() == 1

	// Negative guards: self-jwt -> unsupported_scheme; ES384 -> unsupported_algorithm; /authorize and /revoke reject non-AAuth schemes
	p9SelfJWTCred, _ := signaturekey.NewSelfJWTCredential(p9AT)
	p9SelfJWTResp, _ := p9Send(p1AgentKey, p9SelfJWTCred, "/items")
	p9ES384Cred, _ := signaturekey.NewHWKCredential(p9UnlistedKey.PublicJWK())
	p9ES384Resp, _ := p9Send(p9UnlistedKey, p9ES384Cred, "/items")
	p9AuthzHWKReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p9ResIssuer+"/authorize", strings.NewReader(`{"scope":"items.read"}`))
	p9AuthzHWKReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignRequest(p9AuthzHWKReq, p9ClientECKey, p9HWKCred, p5Clock, signaturekey.SignOptions{})
	p9AuthzHWKResp, _ := httpClient.Do(p9AuthzHWKReq)
	_ = p9AuthzHWKResp.Body.Close()
	p9RevHWKReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, p9ResIssuer+"/revoke", strings.NewReader(`{"jti":"x","exp":9999999999}`))
	p9RevHWKReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignRequest(p9RevHWKReq, p9ClientECKey, p9HWKCred, p5Clock, signaturekey.SignOptions{})
	p9RevHWKResp, _ := httpClient.Do(p9RevHWKReq)
	_ = p9RevHWKResp.Body.Close()
	p9NegGuardsOK := p9SelfJWTResp.StatusCode == http.StatusUnauthorized &&
		p9SelfJWTResp.Header.Get("Signature-Error") == "error=unsupported_scheme" &&
		p9SelfJWTResp.Header.Get("Accept-Signature-Scheme") == p9WantSchemes &&
		p9ES384Resp.StatusCode == http.StatusUnauthorized &&
		p9ES384Resp.Header.Get("Signature-Error") == "error=unsupported_algorithm" &&
		p9ES384Resp.Header.Get("Accept-Signature-Alg") == p9WantAlgs &&
		p9AuthzHWKResp.StatusCode == http.StatusUnauthorized &&
		p9RevHWKResp.StatusCode == http.StatusUnauthorized
	// =========================================================================
	// QA-P10: Cross-Language 4-Party Call Chaining Matrix & Updated QA-O6 Boundaries
	// =========================================================================
	const (
		p10GoFedPSIssuer  = "https://p10-go-fed-ps.example"
		p10GoASIssuer     = "https://p10-go-as.example"
		p10GoFedResIssuer = "https://p10-go-fed-res.example"
	)
	p10GoFedPSKey := newPKey("p10-go-fed-ps-1", 0xcc)
	p10GoASKey := newPKey("p10-go-as-1", 0xcd)
	p10GoFedResKey := newPKey("p10-go-fed-res-1", 0xce)

	p10GoAS, err := accessserver.New(accessserver.Config{
		Issuer:      p10GoASIssuer,
		SigningKey:  p10GoASKey,
		KeyResolver: p5Resolver,
		Clock:       p5Clock,
		NewID:       nextPID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == p10GoFedPSIssuer || iss == in.RustFedPSIssuer || iss == p5PSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Revocation: &accessserver.RevocationConfig{
			Revocations:  testutil.NewTokenRevocationStore(),
			IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient:   httpClient,
			Admit:        func(context.Context, string) error { return nil },
		},
	})
	must(err, "accessserver.New p10GoAS")
	p10GoASSrv, p10GoASDER := registerTLS("p10-go-as.example", p10GoAS.Handler())

	p10GoFedRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            p10GoFedResIssuer,
		AccessServer:      in.RustFedASIssuer,
		SigningKey:        p10GoFedResKey,
		KeyResolver:       p5Resolver,
		Clock:             p5Clock,
		NewID:             nextPID,
		ScopeDescriptions: map[string]string{"read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":            true,
				"subject":       p.Subject,
				"person_server": p.PersonServer,
			})
		}),
	})
	must(err, "resource.NewFederatedAuthorization p10GoFedRes")
	p10GoFedResSrv, p10GoFedResDER := registerTLS("p10-go-fed-res.example", p10GoFedRes.Handler())
	_, _ = p5Resolver.ResolveKey(ctx, in.RustFedPSIssuer, aauth.PersonDiscoveryDocument, "p10-rust-ps-1")
	_, _ = p5Resolver.ResolveKey(ctx, in.RustFedASIssuer, aauth.AccessDiscoveryDocument, "p10-rust-as-1")
	_, _ = p5Resolver.ResolveKey(ctx, p5RelayResIssuer, aauth.AgentDiscoveryDocument, "p5-relay-res-1")
	_, _ = p5Resolver.ResolveKey(ctx, p10GoFedResIssuer, aauth.ResourceDiscoveryDocument, "p10-go-fed-res-1")
	_, _ = p5Resolver.ResolveKey(ctx, p1GoAPIssuer, aauth.AgentDiscoveryDocument, "p1-ap-1")

	p10GoFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:       p10GoFedPSIssuer,
		SigningKey:   p10GoFedPSKey,
		KeyResolver:  p5Resolver,
		Clock:        p5Clock,
		NewID:        nextPID,
		HTTPClient:   httpClient,
		Tokens:       &memoryTokenStore{},
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-p10", Lifetime: 10 * time.Minute}, nil
		},
		AccessServerEndpoint: func(_ context.Context, asIssuer string) (string, error) {
			return asIssuer + "/token", nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-p10-at-" + req.Resource, Lifetime: time.Hour}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
	})
	must(err, "personserver.NewFederatedAuthorization p10GoFedPS")
	p10GoFedPSSrv, p10GoFedPSDER := registerTLS("p10-go-fed-ps.example", p10GoFedPS.Handler())

	// 1. All-Go 4-party call chaining (Go Caller -> p5RelayAgCli -> p5PS -> p5AS -> p5Res) with clamping verification
	p10AllGoUpRes, err := p5Cli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p5PSIssuer, Resource: p5RelayResIssuer})
	must(err, "p5Cli.PersonToken p10AllGoUp")
	p10AllGoUpPT, _ := p10AllGoUpRes.Token()
	p10AllGoUpClaims, _ := aauth.VerifyPersonToken(ctx, p10AllGoUpPT, p5Resolver, p5Clock)
	p10AllGoDownRes, err := p5RelayAgCli.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: p5ResIssuer, UpstreamToken: p10AllGoUpPT})
	must(err, "p5RelayAgCli.PersonToken p10AllGo")
	p10AllGoDownPT, _ := p10AllGoDownRes.Token()
	p10AllGoDownPTClaims, _ := aauth.VerifyPersonToken(ctx, p10AllGoDownPT, p5Resolver, p5Clock)
	p10AllGoRT, err := p5RelayAgCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      p5ResIssuer,
		PersonToken:   p10AllGoDownPT,
		UpstreamToken: p10AllGoUpPT,
		Scopes:        []string{"records.read"},
	})
	must(err, "p5RelayAgCli.Authorize p10AllGo")
	p10AllGoAT, err := p5RelayAgCli.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  p10AllGoRT,
		PresentedToken: p10AllGoDownPT,
		UpstreamToken:  p10AllGoUpPT,
	})
	must(err, "p5RelayAgCli.Exchange p10AllGo")
	p10AllGoATClaims, _ := aauth.VerifyAuthToken(ctx, p10AllGoAT, p5Resolver, p5Clock)
	p10AllGoCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p5ResIssuer+"/records", nil)
	p10AllGoCallResp, err := p5RelayAgCli.Do(ctx, clientagent.Call{Request: p10AllGoCallReq, AuthToken: p10AllGoAT})
	must(err, "p5RelayAgCli.Do p10AllGo")
	_ = p10AllGoCallResp.Body.Close()
	p10AllGoOK := p10AllGoDownPTClaims.ExpiresAt <= p10AllGoUpClaims.ExpiresAt &&
		p10AllGoATClaims.ExpiresAt <= p10AllGoUpClaims.ExpiresAt &&
		p10AllGoCallResp.StatusCode == http.StatusOK

	// 2. Cross-Language Flow A: Go Caller -> Go Intermediary -> Go Federated PS (p10GoFedPS) -> Rust Federated AS -> Rust Federated Resource & Go Federated Resource
	p10CallerTok, _ := p1AP.Issue(aauth.AgentTokenRequest{
		Agent:        p1GoAgentID,
		PersonServer: p10GoFedPSIssuer,
		PublicKey:    p1AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	p10CallerCli, _ := clientagent.New(ctx, clientagent.Config{
		Identifier:  p1GoAgentID,
		SigningKey:  p1AgentKey,
		AgentToken:  p10CallerTok,
		KeyResolver: p5Resolver,
		HTTPClient:  httpClient,
		Clock:       p5Clock,
	})
	p10RelayTok, _ := p5RelayAP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:relay@p5-relay-res.example",
		PersonServer: p10GoFedPSIssuer,
		PublicKey:    p5RelayAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	p10RelayCli, _ := clientagent.New(ctx, clientagent.Config{
		Identifier:  "aauth:relay@p5-relay-res.example",
		SigningKey:  p5RelayAgKey,
		AgentToken:  p10RelayTok,
		KeyResolver: p5Resolver,
		HTTPClient:  httpClient,
		Clock:       p5Clock,
	})
	p10UpPTRes, err := p10CallerCli.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: p10GoFedPSIssuer, Resource: p5RelayResIssuer})
	must(err, "p10CallerCli.PersonToken")
	p10UpPT, _ := p10UpPTRes.Token()
	p10UpClaims, _ := aauth.VerifyPersonToken(ctx, p10UpPT, p5Resolver, p5Clock)

	// Chain to Rust Federated Resource via p10GoFedPS -> in.RustFedASIssuer
	p10DownRustPTRes, err := p10RelayCli.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: in.RustFedResIssuer, UpstreamToken: p10UpPT})
	must(err, "p10RelayCli.PersonToken RustFedRes")
	p10DownRustPT, _ := p10DownRustPTRes.Token()
	p10DownRustRT, err := p10RelayCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      in.RustFedResIssuer,
		PersonToken:   p10DownRustPT,
		UpstreamToken: p10UpPT,
		Scopes:        []string{"read"},
	})
	must(err, "p10RelayCli.Authorize RustFedRes")
	p10DownRustAT, err := p10RelayCli.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  p10DownRustRT,
		PresentedToken: p10DownRustPT,
		UpstreamToken:  p10UpPT,
	})
	must(err, "p10RelayCli.Exchange RustFedRes via RustFedAS")
	p10DownRustATClaims, _ := aauth.VerifyAuthToken(ctx, p10DownRustAT, p5Resolver, p5Clock)
	p10RustCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustFedResIssuer+"/records", nil)
	p10RustCallResp, err := p10RelayCli.Do(ctx, clientagent.Call{Request: p10RustCallReq, AuthToken: p10DownRustAT})
	must(err, "p10RelayCli.Do RustFedRes")
	_ = p10RustCallResp.Body.Close()

	// Chain to Go Federated Resource (p10GoFedRes) via p10GoFedPS -> in.RustFedASIssuer
	p10DownGoPTRes, err := p10RelayCli.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: p10GoFedResIssuer, UpstreamToken: p10UpPT})
	must(err, "p10RelayCli.PersonToken p10GoFedRes")
	p10DownGoPT, _ := p10DownGoPTRes.Token()
	p10DownGoRT, err := p10RelayCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      p10GoFedResIssuer,
		PersonToken:   p10DownGoPT,
		UpstreamToken: p10UpPT,
		Scopes:        []string{"read"},
	})
	must(err, "p10RelayCli.Authorize p10GoFedRes")
	p10DownGoAT, err := p10RelayCli.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  p10DownGoRT,
		PresentedToken: p10DownGoPT,
		UpstreamToken:  p10UpPT,
	})
	must(err, "p10RelayCli.Exchange p10GoFedRes via RustFedAS")
	p10GoCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, p10GoFedResIssuer+"/records", nil)
	p10GoCallResp, err := p10RelayCli.Do(ctx, clientagent.Call{Request: p10GoCallReq, AuthToken: p10DownGoAT})
	must(err, "p10RelayCli.Do p10GoFedRes")
	_ = p10GoCallResp.Body.Close()

	p10GoPSRustASOK := p10DownRustATClaims.ExpiresAt <= p10UpClaims.ExpiresAt &&
		p10RustCallResp.StatusCode == http.StatusOK && p10GoCallResp.StatusCode == http.StatusOK

	// 3. Updated QA-O6 Boundaries:
	// - B2: Go Federated PS still refuses AS-issued aa-auth+jwt (dwk="aauth-access.json") as upstream_token -> 400 invalid_upstream_token
	p10ASIssuedUpAuth, _ := aauth.MintAuthToken(p10GoASKey, aauth.AuthTokenClaims{
		Issuer:       p10GoASIssuer,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     p5RelayResIssuer,
		PersonServer: p10GoFedPSIssuer,
		Subject:      "person-p10",
		JTI:          "p10-as-up-auth",
		IssuedAt:     p5Clock.Now().Unix(),
		ExpiresAt:    p5Clock.Now().Add(10 * time.Minute).Unix(),
		Scope:        "read",
		Confirmation: aauth.Confirmation{JWK: p1AgentKey.PublicJWK()},
	})
	p10B2Body, _ := json.Marshal(map[string]string{"resource": p10GoFedResIssuer, "upstream_token": p10ASIssuedUpAuth})
	p10B2Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p10GoFedPSIssuer+"/person", bytes.NewReader(p10B2Body))
	p10B2Req.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(p10B2Req, p5RelayAgKey, p10RelayTok, p5Clock)
	p10B2Resp, _ := httpClient.Do(p10B2Req)
	var p10B2Out map[string]any
	_ = json.NewDecoder(p10B2Resp.Body).Decode(&p10B2Out)
	_ = p10B2Resp.Body.Close()

	// - B4: Go Federated PS still refuses mission-carrying upstream_token -> 500 server_error
	p10MissionUpPT, _ := aauth.MintPersonToken(p10GoFedPSKey, aauth.PersonTokenClaims{
		Issuer:       p10GoFedPSIssuer,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     p5RelayResIssuer,
		Subject:      "person-p10",
		MissionS256:  aauth.MissionS256([]byte("mission-p10")),
		JTI:          "p10-mission-up-pt",
		IssuedAt:     p5Clock.Now().Unix(),
		ExpiresAt:    p5Clock.Now().Add(10 * time.Minute).Unix(),
		Confirmation: aauth.Confirmation{JWK: p1AgentKey.PublicJWK()},
	})
	p10B4Body, _ := json.Marshal(map[string]string{"resource": p10GoFedResIssuer, "upstream_token": p10MissionUpPT})
	p10B4Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p10GoFedPSIssuer+"/person", bytes.NewReader(p10B4Body))
	p10B4Req.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(p10B4Req, p5RelayAgKey, p10RelayTok, p5Clock)
	p10B4Resp, _ := httpClient.Do(p10B4Req)
	var p10B4Out map[string]any
	_ = json.NewDecoder(p10B4Resp.Body).Decode(&p10B4Out)
	_ = p10B4Resp.Body.Close()

	return map[string]any{
		"p1_go_ps_addr":            p1PSSrv.Listener.Addr().String(),
		"p1_go_ps_cert_hex":        hex.EncodeToString(p1PSDER),
		"p1_go_res_addr":           p1ResSrv.Listener.Addr().String(),
		"p1_go_res_cert_hex":       hex.EncodeToString(p1ResDER),
		"p2_orders_addr":           p2OrdersSrv.Listener.Addr().String(),
		"p2_orders_cert_hex":       hex.EncodeToString(p2OrdersDER),
		"p3_go_res_addr":           p3ResSrv.Listener.Addr().String(),
		"p3_go_res_cert_hex":       hex.EncodeToString(p3ResDER),
		"p7_go_res_addr":           p7ResSrv.Listener.Addr().String(),
		"p7_go_res_cert_hex":       hex.EncodeToString(p7ResDER),
		"p8_go_ap_addr":            p8APSrv.Listener.Addr().String(),
		"p8_go_ap_cert_hex":        hex.EncodeToString(p8APDER),
		"p9_go_res_addr":           p9ResSrv.Listener.Addr().String(),
		"p9_go_res_cert_hex":       hex.EncodeToString(p9ResDER),
		"p10_go_as_addr":           p10GoASSrv.Listener.Addr().String(),
		"p10_go_as_cert_hex":       hex.EncodeToString(p10GoASDER),
		"p10_go_fed_res_addr":      p10GoFedResSrv.Listener.Addr().String(),
		"p10_go_fed_res_cert_hex":  hex.EncodeToString(p10GoFedResDER),
		"servers": map[string]any{
			"p1_ap":         map[string]any{"issuer": p1GoAPIssuer, "addr": p1APSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p1APDER}))},
			"p1_ps":         map[string]any{"issuer": p1GoPSIssuer, "addr": p1PSSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p1PSDER}))},
			"p1_res":        map[string]any{"issuer": p1GoResIssuer, "addr": p1ResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p1ResDER}))},
			"p1_res2":       map[string]any{"issuer": p1GoRes2Issuer, "addr": p1Res2Srv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p1Res2DER}))},
			"p2_orders":     map[string]any{"issuer": p2OrdersIssuer, "addr": p2OrdersSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p2OrdersDER}))},
			"p3_res":        map[string]any{"issuer": p3GoResIssuer, "addr": p3ResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p3ResDER}))},
			"p7_res":        map[string]any{"issuer": p7ResIssuer, "addr": p7ResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p7ResDER}))},
			"p8_ap":         map[string]any{"issuer": p8APIssuer, "addr": p8APSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p8APDER}))},
			"p9_res":        map[string]any{"issuer": p9ResIssuer, "addr": p9ResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p9ResDER}))},
			"p10_go_fed_ps": map[string]any{"issuer": p10GoFedPSIssuer, "addr": p10GoFedPSSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p10GoFedPSDER}))},
			"p10_go_as":     map[string]any{"issuer": p10GoASIssuer, "addr": p10GoASSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p10GoASDER}))},
			"p10_go_res":    map[string]any{"issuer": p10GoFedResIssuer, "addr": p10GoFedResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p10GoFedResDER}))},
		},
		"p1": map[string]any{
			"go_to_go_happy_ok":        p1RTClaims1.Interaction != nil && p1HasAuthTok1 && p1CallResp1.StatusCode == http.StatusOK && p1BackURL1 == p1AgentCb,
			"rt_has_interaction":       p1RTClaims1.Interaction != nil && strings.HasPrefix(p1RTClaims1.Interaction.URL, p1GoResIssuer+"/connect/"),
			"imm_exchange_refused":     p1ImmErr != nil,
			"early_approve_refused":    errors.Is(p1EarlyApproveErr, personserver.ErrResourceInteractionPending),
			"second_redirect_refused":  p1SecondRedirectErr != nil,
			"poll_interacting_ok":      p1InterOK1 && p1InterPend1.Interacting(),
			"interacting_poll_ok":      p1InterOK1 && p1InterPend1.Interacting(),
			"second_res_consume_err":   errors.Is(p1SecondResConsumeErr, resource.ErrInitiatedInteractionCodeUsed),
			"forged_cb_refused":        errors.Is(p1ForgedCbErr, personserver.ErrResourceInteractionCallbackInvalid),
			"agent_cb_matches":         p1BackURL1 == p1AgentCb,
			"approved_call_200":        p1HasAuthTok1 && p1CallResp1.StatusCode == http.StatusOK,
			"callback_errors_ok":       p1CbErrMappingsOK,
			"cb_err_mappings_ok":       p1CbErrMappingsOK,
			"code_exhaust_ok":          errors.Is(p1SecondResConsumeErr, resource.ErrInitiatedInteractionCodeUsed),
			"egress_refusal_ok":        p1EgressOK,
			"egress_refused_ok":        p1EgressOK,
			"withdraw_during_int_ok":   p1WithdrawOK,
			"withdrawal_revoked_ok":    p1WithdrawOK,
			"cross_lang_go_ps_rust_res": p1RTRustRes.Interaction != nil && p1RustCallResp.StatusCode == http.StatusOK,
			"xlang_go_ag_rust_res_ok":  p1RTRustRes.Interaction != nil && p1RustCallResp.StatusCode == http.StatusOK,
			"cross_lang_go_res_rust_ps": p1RustCbOut.Approved && p1GoRes2CallResp.StatusCode == http.StatusOK && p1Res2Served.Load() == 1,
			"xlang_go_res_rust_ps_ok":  p1RustCbOut.Approved && p1GoRes2CallResp.StatusCode == http.StatusOK && p1Res2Served.Load() == 1,
		},
		"p2": map[string]any{
			"undeclared_cap_refused":   p2UndeclOK,
			"undeclared_refused_ok":    p2UndeclOK,
			"happy_path_ok":            p2CompOK1 && p2CompResp1.StatusCode == http.StatusOK && string(p2CompBody1) == "order 42 fulfilled: reserved" && p2ToAgent1 == p2AgentCb && p2GoneOK,
			"wrong_code_refused":       errors.Is(p2WrongCodeErr, resource.ErrChainedInteractionCodeInvalid),
			"wrong_code_refused_ok":    errors.Is(p2WrongCodeErr, resource.ErrChainedInteractionCodeInvalid),
			"second_visit_refused":     errors.Is(p2SecondVisErr, resource.ErrChainedInteractionCodeUsed),
			"second_visit_refused_ok":  errors.Is(p2SecondVisErr, resource.ErrChainedInteractionCodeUsed),
			"interacting_poll_ok":      p2InterOK1 && p2InterNext1.Interacting(),
			"other_poller_refused":     p2OtherPollErr != nil && strings.Contains(p2OtherPollErr.Error(), "unknown to this caller"),
			"other_caller_refused_ok":  p2OtherPollErr != nil && strings.Contains(p2OtherPollErr.Error(), "unknown to this caller"),
			"callback_errors_ok":       p2DenyOK && p2RevOK,
			"completed_body":           string(p2CompBody1),
			"completed_200_ok":         p2CompOK1 && p2CompResp1.StatusCode == http.StatusOK && string(p2CompBody1) == "order 42 fulfilled: reserved" && p2ToAgent1 == p2AgentCb,
			"gone_after_delivery_ok":   p2GoneOK,
			"downstream_denial_ok":     p2DenyOK,
			"downstream_revocation_ok": p2RevOK,
			"p2_caller_auth_token":     p2CallerAuthTok,
		},
		"p3": map[string]any{
			"portal_hdr_links":       len(p3HdrLinks),
			"portal_html_links":      len(p3HTMLLinks),
			"resolved_go_hdr":        p3ResolvedGoHdr.Resource == p3GoResIssuer,
			"resolved_rust_hdr":      p3ResolvedRustHdr.Resource == in.RustLinkResIssuer,
			"resolved_go_html":       p3ResolvedGoHTML.Resource == p3GoResIssuer,
			"resolved_rust_html":     p3ResolvedRustHTML.Resource == in.RustLinkResIssuer,
			"from_rust_docs_hdr_ok":  p3FromRustHdr.Resource == in.RustLinkResIssuer,
			"from_rust_docs_html_ok": p3FromRustHTML.Resource == in.RustLinkResIssuer,
			"neg_targets_ok":         p3NegTargetsOK,
			"oversized_ignored_ok":   len(p3OversizedHdr) == 0 && len(p3OversizedHTML) == 0,
			"issuer_errors_ok":       p3IssuerErrorsOK,
		},
		"p4": map[string]any{
			"online_old_refused":       p4OnlineOldErr != nil,
			"delayed_valid_at_ok":      p4DelayedProof.ValidAt().Equal(p4SignedAt) && p4DelayedProof.MaxAge() == time.Hour,
			"past_token_at_valid_at":   p4VerifyAtNowErr != nil && p4VerifyAtValidAtErr == nil,
			"issued_after_refused":     p4IssuedAfterErr != nil,
			"beyond_max_delay_refused": p4BeyondMaxDelayErr != nil,
			"beyond_max_delay_err":     p4BeyondMaxDelayErr != nil,
			"future_created_refused":   p4FutureCreatedErr != nil,
			"future_created_skew_err":  p4FutureCreatedErr != nil,
			"expired_window_refused":   p4ExpiredSigErr != nil,
			"expired_sig_err":          p4ExpiredSigErr != nil,
			"replay_lifecycle_ok":      p4FirstCheckErr == nil && p4ReplayCheckErr != nil && p4OtherCheckErr == nil && errors.Is(p4FullCacheErr, signaturekey.ErrReplayCacheFull) && p4AfterSpanCheckErr == nil && p4LenAfterSpan == 1,
			"first_cache_ok":           p4FirstCheckErr == nil,
			"replay_refused_ok":        p4ReplayCheckErr != nil,
			"other_path_ok":            p4OtherCheckErr == nil,
			"full_cache_err_ok":        errors.Is(p4FullCacheErr, signaturekey.ErrReplayCacheFull),
			"expiry_eviction_ok":       p4AfterSpanCheckErr == nil && p4LenAfterSpan == 1,
		},
		"p5": map[string]any{
			"prefer_wait_cascade_ok":       p5CascadeRefusedOK && p5PreferWaitOK,
			"upstream_revoked_at_as":       p5UpstreamRevOK,
			"resource_multi_rec_ok":        len(p5WithdrawRes.Attempts) == 2 && p5WithdrawRes.Attempts[0].Recorded() && p5WithdrawRes.Attempts[1].Recorded(),
			"rate_limited_429_ok":          p5RatePendingOK && p5RateRetryOK,
			"resource_token_withdrawn_ok":  len(p5WithdrawRes.Attempts) == 2 && p5WithdrawRes.Attempts[0].Recorded() && p5WithdrawRes.Attempts[1].Recorded(),
			"agent_eviction_ok":            p5AgentEvictionOK,
			"cascade_refused_ok":           p5CascadeRefusedOK,
			"prefer_wait_deferred_ok":      p5PreferWaitOK,
			"rate_limited_pending_ok":      p5RatePendingOK,
			"rate_limited_retry_ok":        p5RateRetryOK,
			"upstream_revocation_as_ok":    p5UpstreamRevOK,
		},
		"p6": map[string]any{
			"compose_merge_ok":         p6MergeCheckOK,
			"conflict_guards_ok":       p6UncoveredErr != nil,
			"composed_doc_ok":          p6ComposedDocOK,
			"release_gated_once_ok":    p6ProposalResultOK && p6ReleasePollOK,
			"metered_never_runs_early": p6BudgetGatedOK,
			"merge_displays_ok":        p6MergeCheckOK,
			"uncovered_ops_rejected":   p6UncoveredErr != nil,
			"composed_doc_display_ok":  p6ComposedDocOK,
			"proposal_result_ok":       p6ProposalResultOK,
			"release_poll_once_ok":     p6ReleasePollOK,
			"budget_gated_not_run_ok":  p6BudgetGatedOK,
		},
		"p7": map[string]any{
			"refusal_held_reserves_zero":       p7RefusalHeldOK,
			"rechallenge_same_location":        p7RechallengeOK,
			"complete_and_replay_ok":           p7CompleteAndReplayOK,
			"signed_usage_ok":                  p7SignedUsageOK,
			"refusal_held_reserves_nothing_ok": p7RefusalHeldOK,
			"rechallenge_same_location_ok":     p7RechallengeOK,
			"complete_and_replay_once_ok":      p7CompleteAndReplayOK,
			"signed_usage_go_and_rust_ok":      p7SignedUsageOK,
		},
		"p8": map[string]any{
			"go_inbox_lifecycle_ok": p8GoInboxOK,
			"store_contract_ok":     p8GoInboxOK,
			"go_inbox_reader_ok":    p8GoInboxOK,
		},
		"p9": map[string]any{
			"challenge_headers_ok":          p9ChallengeHeadersOK,
			"hwk_es256_ok":                  p9AllSchemesOK,
			"jwks_ok":                       p9AllSchemesOK,
			"x509_ok":                       p9AllSchemesOK,
			"jkt_jwt_and_cached_ok":         p9AllSchemesOK,
			"aauth_jwt_routes_to_protected": p9AAuthRouteOK,
			"all_schemes_ok":                p9AllSchemesOK,
			"aauth_route_ok":                p9AAuthRouteOK,
			"neg_guards_ok":                 p9NegGuardsOK,
		},
		"p10": map[string]any{
			"all_go_4party_ok":            p10AllGoOK,
			"all_go_4party_chain_ok":      p10AllGoOK,
			"go_ps_to_rust_as_ok":         p10GoPSRustASOK,
			"b2_go_ps_refuses_as_up_ok":   p10B2Resp.StatusCode == http.StatusBadRequest && p10B2Out["error"] == "invalid_upstream_token",
			"b2_go_ps_refuses_as_auth":    p10B2Resp.StatusCode == http.StatusBadRequest && p10B2Out["error"] == "invalid_upstream_token",
			"b4_go_ps_refuses_mission_ok": p10B4Resp.StatusCode == http.StatusBadRequest && p10B4Out["error"] == "invalid_upstream_token",
			"b4_go_ps_refuses_mission":    p10B4Resp.StatusCode == http.StatusBadRequest && p10B4Out["error"] == "invalid_upstream_token",
			"b4_unrecorded_status":        p10B4Resp.StatusCode,
			"b4_unrecorded_error":         p10B4Out["error"],
		},
	}
}
