package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type nSuiteInput struct {
	RustAgentJKT string `json:"rust_agent_jkt"`
}

type nMemorySessionStore struct {
	mu       sync.Mutex
	next     int
	sessions map[string]resource.SessionRecord
	pending  map[string]*nPendingSession
}

type nPendingSession struct {
	record   resource.PendingSessionRecord
	state    resource.SessionPollState
	attempts int
	approval resource.SessionApproval
	callback string
}

func newNMemorySessionStore() *nMemorySessionStore {
	return &nMemorySessionStore{
		sessions: make(map[string]resource.SessionRecord),
		pending:  make(map[string]*nPendingSession),
	}
}

func (s *nMemorySessionStore) Create(_ context.Context, record resource.SessionRecord) (resource.SessionApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.create(record), nil
}

func (s *nMemorySessionStore) create(record resource.SessionRecord) resource.SessionApproval {
	s.next++
	tok := fmt.Sprintf("n-session-%d", s.next)
	s.sessions[tok] = record
	return resource.SessionApproval{Token: tok, Record: record}
}

func (s *nMemorySessionStore) Load(_ context.Context, token string, now time.Time) (resource.SessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[token]
	if !ok {
		return resource.SessionRecord{}, resource.ErrSessionNotFound
	}
	if !now.Before(rec.ExpiresAt) {
		return resource.SessionRecord{}, resource.ErrSessionExpired
	}
	return rec, nil
}

func (s *nMemorySessionStore) CreatePending(_ context.Context, record resource.PendingSessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[record.ID]; exists {
		return resource.ErrPendingSessionConflict
	}
	s.pending[record.ID] = &nPendingSession{record: record, state: resource.SessionPollPending}
	return nil
}

func (s *nMemorySessionStore) ConsumeInteractionCode(
	_ context.Context,
	issuer string,
	reference string,
	presentation resource.SessionCodePresentation,
	now time.Time,
) (resource.PendingSessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeInvalid
	}
	if p.state == resource.SessionPollGone {
		return resource.PendingSessionRecord{}, resource.ErrPendingSessionGone
	}
	if p.state != resource.SessionPollPending {
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeUsed
	}
	if !now.Before(p.record.ExpiresAt) {
		p.state = resource.SessionPollExpired
		return resource.PendingSessionRecord{}, resource.ErrPendingSessionExpired
	}
	if p.record.Resource != issuer || p.record.CodeSHA256 != presentation.CodeSHA256 {
		p.attempts++
		if p.attempts >= p.record.MaximumCodeAttempts {
			p.state = resource.SessionPollGone
			return resource.PendingSessionRecord{}, resource.ErrPendingSessionGone
		}
		return resource.PendingSessionRecord{}, resource.ErrSessionInteractionCodeInvalid
	}
	p.state = resource.SessionPollInteracting
	p.callback = presentation.Callback
	return p.record, nil
}

func (s *nMemorySessionStore) LoadPending(_ context.Context, reference string) (resource.PendingSessionSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.PendingSessionSnapshot{}, resource.ErrPendingSessionNotFound
	}
	return resource.PendingSessionSnapshot{Record: p.record, State: p.state, Approval: p.approval, Callback: p.callback}, nil
}

func (s *nMemorySessionStore) Approve(
	_ context.Context,
	reference string,
	record resource.SessionRecord,
	now time.Time,
) (resource.SessionApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.SessionApproval{}, resource.ErrPendingSessionNotFound
	}
	if p.state == resource.SessionPollApproved {
		if reflect.DeepEqual(p.approval.Record, record) {
			return p.approval, nil
		}
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if p.state != resource.SessionPollInteracting {
		return resource.SessionApproval{}, resource.ErrPendingSessionConflict
	}
	if !now.Before(p.record.ExpiresAt) {
		p.state = resource.SessionPollExpired
		return resource.SessionApproval{}, resource.ErrPendingSessionExpired
	}
	p.approval = s.create(record)
	p.state = resource.SessionPollApproved
	return p.approval, nil
}

func (s *nMemorySessionStore) Deny(_ context.Context, reference string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	if p.state == resource.SessionPollDenied {
		return nil
	}
	if p.state != resource.SessionPollInteracting {
		return resource.ErrPendingSessionConflict
	}
	p.state = resource.SessionPollDenied
	return nil
}

func (s *nMemorySessionStore) Invalidate(_ context.Context, reference string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	if p.state == resource.SessionPollGone {
		return nil
	}
	if p.state != resource.SessionPollPending && p.state != resource.SessionPollInteracting {
		return resource.ErrPendingSessionConflict
	}
	p.state = resource.SessionPollGone
	return nil
}

func (s *nMemorySessionStore) Poll(
	_ context.Context,
	reference string,
	identity resource.SessionPollIdentity,
	now time.Time,
) (resource.SessionPollRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	principal := p.record.Request.AgentPrincipal
	if identity.Resource != p.record.Resource || identity.AgentProvider != principal.AgentProvider ||
		identity.Agent != principal.Agent || identity.ParentAgent != principal.ParentAgent {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionNotFound
	}
	if p.state == resource.SessionPollGone {
		return resource.SessionPollRecord{}, resource.ErrPendingSessionGone
	}
	if !now.Before(p.record.ExpiresAt) &&
		(p.state == resource.SessionPollPending || p.state == resource.SessionPollInteracting) {
		p.state = resource.SessionPollExpired
	}
	return resource.SessionPollRecord{
		State: p.state, Approval: p.approval, RetryAfter: p.record.RetryAfter,
	}, nil
}

func (s *nMemorySessionStore) ConsumeResult(
	_ context.Context,
	reference string,
	result resource.SessionPollRecord,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[reference]
	if !ok {
		return resource.ErrPendingSessionNotFound
	}
	want := resource.SessionPollRecord{
		State: p.state, Approval: p.approval, RetryAfter: p.record.RetryAfter,
	}
	if !reflect.DeepEqual(result, want) ||
		(result.State != resource.SessionPollApproved && result.State != resource.SessionPollDenied && result.State != resource.SessionPollExpired) {
		return resource.ErrPendingSessionConflict
	}
	p.state = resource.SessionPollGone
	return nil
}

func runNSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in nSuiteInput,
) map[string]any {
	nowTime := clock.Now().UTC().Truncate(time.Second)

	const nGoIssuer = "https://n-go-interop.example"
	nGoKey, err := jose.NewEd25519SigningKey("n-go-key-1", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x81}, ed25519.SeedSize)))
	must(err, "NewEd25519SigningKey nGoKey")
	nGoJWKSKey, err := jose.NewEd25519SigningKey("n-go-jwks-1", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x82}, ed25519.SeedSize)))
	must(err, "NewEd25519SigningKey nGoJWKSKey")

	nGoKeyResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver nGoKeyResolver")

	// Set up Go ResourceManagedServer for QA-N3 (requires AAuth-Capabilities: interaction to raise 202)
	nSessionStore := newNMemorySessionStore()
	nManagedSrv, err := resource.NewResourceManaged(resource.ResourceManagedConfig{
		Issuer:            nGoIssuer,
		KeyResolver:       nGoKeyResolver,
		Clock:             clock,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		AuthorizeImmediately: func(context.Context, resource.SessionAuthorizationRequest) (resource.SessionGrant, bool, error) {
			return resource.SessionGrant{}, false, nil
		},
		Interaction: resource.SessionInteractionPolicy{
			URL:                 nGoIssuer + "/interact",
			Lifetime:            5 * time.Minute,
			RetryAfter:          2 * time.Second,
			MaximumCodeAttempts: 3,
		},
		Sessions: nSessionStore,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
	})
	must(err, "resource.NewResourceManaged for nManagedSrv")

	// Set up Go metered resource.Server for QA-N7 (serving POST /usage to Rust PersonServer and AccessServer)
	usdUnit, err := budgets.NewUnit("USD", 6)
	must(err, "budgets.NewUnit USD")
	usdDecl, err := budgets.NewBoundedUnitDeclaration(usdUnit, 10_000_000, "US dollars at micro-dollar precision")
	must(err, "budgets.NewBoundedUnitDeclaration USD")
	nGoBudgetStore := testutil.NewBudgetStore()
	nGoMeteredSrv, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            nGoIssuer,
		SigningKey:        nGoKey,
		KeyResolver:       nGoKeyResolver,
		Clock:             clock,
		NewID:             func() string { return "n-go-rt-1" },
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}),
		Budget: &resource.BudgetConfig{
			Units:         []budgets.UnitDeclaration{usdDecl},
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return 125_000, nil },
			Store:         nGoBudgetStore,
			Challenge:     func(context.Context, resource.BudgetChallengeRequest) (string, error) { return "", nil },
		},
	})
	must(err, "resource.NewPSAuthorization for nGoMeteredSrv")

	// Pre-record metered charges on nGoBudgetStore for QA-N7 (Rust PS and AS querying Go /usage over HTTPS)
	nGrantVal, err := budgets.NewValue(2_000_000, usdUnit)
	must(err, "budgets.NewValue nGrantVal")
	const nRustPSIssuer = "https://n-rust-ps.example"
	const nRustASIssuer = "https://n-rust-as.example"
	const nMissionS256 = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA"
	// 1. Direct PS-issued token charge: 300_000 USD micro-dollars
	_, err = nGoBudgetStore.Charge(ctx, resource.BudgetCharge{
		Token:        aauth.TokenReference{Issuer: nRustPSIssuer, JTI: "n7-ps-tok-1"},
		PersonServer: nRustPSIssuer,
		Subject:      "person-n7",
		Audience:     nGoIssuer,
		MissionS256:  nMissionS256,
		Tenant:       "acme-n7",
		Grant:        nGrantVal,
		Cost:         300_000,
		AgentJKT:     in.RustAgentJKT,
		ChargedAt:    nowTime,
	})
	must(err, "nGoBudgetStore.Charge direct PS")
	// 2. Federated AS-issued token charge: 450_000 USD micro-dollars
	_, err = nGoBudgetStore.Charge(ctx, resource.BudgetCharge{
		Token:        aauth.TokenReference{Issuer: nRustASIssuer, JTI: "n7-as-tok-1"},
		PersonServer: nRustPSIssuer,
		Subject:      "person-n7",
		Audience:     nGoIssuer,
		MissionS256:  nMissionS256,
		Tenant:       "acme-n7",
		Grant:        nGrantVal,
		Cost:         450_000,
		AgentJKT:     in.RustAgentJKT,
		ChargedAt:    nowTime,
	})
	must(err, "nGoBudgetStore.Charge federated AS")

	nGoMux := http.NewServeMux()
	// QA-N2: Valid Go Access Server metadata with https:// display fields
	nGoMux.HandleFunc("GET /.well-known/aauth-access.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":            nGoIssuer,
			"jwks_uri":          nGoIssuer + "/.well-known/jwks.json",
			"token_endpoint":    nGoIssuer + "/token",
			"name":              "Go Interop Access Server",
			"description":       "Access Server with HTTPS display metadata",
			"logo_uri":          nGoIssuer + "/assets/logo.svg",
			"logo_dark_uri":     nGoIssuer + "/assets/logo-dark.svg",
			"documentation_uri": nGoIssuer + "/docs",
			"tos_uri":           nGoIssuer + "/tos",
			"policy_uri":        nGoIssuer + "/privacy",
		})
	})
	// QA-N2: Invalid Go Access Server metadata with http:// logo_uri
	nGoMux.HandleFunc("GET /insecure-display/.well-known/aauth-access.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         nGoIssuer + "/insecure-display",
			"jwks_uri":       nGoIssuer + "/.well-known/jwks.json",
			"token_endpoint": nGoIssuer + "/insecure-display/token",
			"name":           "Insecure Display AS",
			"logo_uri":       "http://insecure.example/logo.svg",
		})
	})
	nGoMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{nGoKey.PublicJWK(), nGoJWKSKey.PublicJWK()},
		})
	})
	// QA-N4: Go jwks_uri caller metadata & JWKS
	nGoMux.HandleFunc("GET /client-jwks/.well-known/aauth-agent.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   nGoIssuer + "/client-jwks",
			"jwks_uri": nGoIssuer + "/client-jwks/.well-known/jwks.json",
		})
	})
	nGoMux.HandleFunc("GET /client-jwks/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{nGoJWKSKey.PublicJWK()},
		})
	})
	// QA-N3: Go ResourceManagedServer endpoint requiring AAuth-Capabilities: interaction
	nGoMux.Handle("POST /managed-action", nManagedSrv.Handler())
	// QA-N7: Go metered Resource endpoints (/.well-known/aauth-resource.json and POST /usage)
	nGoMux.Handle("GET /.well-known/aauth-resource.json", nGoMeteredSrv.Handler())
	nGoMux.Handle("POST /usage", nGoMeteredSrv.Handler())

	nGoSrv, nGoDER := registerTLS("n-go-interop.example", nGoMux)

	// =========================================================================
	// QA-N2 (Go -> Rust): HTTPKeyResolver accepts https:// display metadata and
	// rejects http:// logo_uri in Rust metadata with ResolutionInvalid
	// =========================================================================
	_, n2ValidErr := nGoKeyResolver.ResolveKey(ctx, "https://n-rust-ap.example", aauth.AgentDiscoveryDocument, "n-rust-ap-key-1")
	_, n2InvalidErr := nGoKeyResolver.ResolveKey(ctx, "https://n-rust-ap.example", "aauth-bad-display.json", "n-rust-ap-key-1")
	var n2ResErr *signaturekey.ResolutionError
	n2InvalidIsResInvalid := errors.As(n2InvalidErr, &n2ResErr) && n2ResErr.Code == signaturekey.ResolutionInvalid

	// =========================================================================
	// QA-N3 (Go unit + Go -> Rust): FormatCapabilities, ParseCapabilities, and
	// Go HTTPS client calling Rust ChainedInteraction::open endpoint
	// =========================================================================
	n3Formatted, n3FmtErr := aauth.FormatCapabilities([]string{"interaction", "clarification", "payment", "budget"})
	_, n3BadFmtErr := aauth.FormatCapabilities([]string{"Bad Token!"})
	n3Parsed, n3ParseErr := aauth.ParseCapabilities([]string{
		"unknown_cap, interaction;q=1",
		"clarification, budget",
	})
	_, n3BadParseErr := aauth.ParseCapabilities([]string{`"not-a-token"`})
	hasCap := func(caps []string, want string) bool {
		for _, c := range caps {
			if c == want {
				return true
			}
		}
		return false
	}
	n3UnitOK := n3FmtErr == nil &&
		n3Formatted == "interaction, clarification, payment, budget" &&
		n3BadFmtErr != nil &&
		n3ParseErr == nil &&
		n3BadParseErr != nil &&
		hasCap(n3Parsed, "interaction") &&
		hasCap(n3Parsed, "clarification") &&
		hasCap(n3Parsed, "budget") &&
		!hasCap(n3Parsed, "payment")

	doN3RustCheck := func(hdrs []string) (int, string, string, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://n-rust-ps.example/__chained-cap-check", strings.NewReader(`{"step":"n3"}`))
		for _, h := range hdrs {
			req.Header.Add("AAuth-Capabilities", h)
		}
		resp, dErr := httpClient.Do(req)
		must(dErr, "doN3RustCheck")
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Location"), resp.Header.Get("AAuth-Requirement"), string(b)
	}
	n3NoneStatus, _, _, n3NoneBody := doN3RustCheck(nil)
	n3NoIntStatus, _, _, n3NoIntBody := doN3RustCheck([]string{"payment, clarification"})
	n3WithIntStatus, n3WithIntLoc, n3WithIntReq, _ := doN3RustCheck([]string{"interaction, clarification"})
	n3MultiStatus, n3MultiLoc, n3MultiReq, _ := doN3RustCheck([]string{"unknown_cap", "interaction;q=1, budget"})

	n3GoToRustOK := n3UnitOK &&
		n3NoneStatus == http.StatusForbidden && strings.Contains(n3NoneBody, `"interaction_unavailable"`) &&
		n3NoIntStatus == http.StatusForbidden && strings.Contains(n3NoIntBody, `"interaction_unavailable"`) &&
		n3WithIntStatus == http.StatusAccepted && n3WithIntLoc != "" && strings.Contains(n3WithIntReq, "requirement=interaction") &&
		n3MultiStatus == http.StatusAccepted && n3MultiLoc != "" && strings.Contains(n3MultiReq, "requirement=interaction")

	// =========================================================================
	// QA-N4 (Go -> Rust): AgentIdentityResource::with_further_schemes over HTTPS
	// =========================================================================
	n4HWKES256Key, _ := newMAlgSigningKey("n4-hwk-es256", jose.ES256Algorithm)
	n4HWKEdKey, _ := newMAlgSigningKey("n4-hwk-ed25519", jose.Ed25519Algorithm)

	doN4Call := func(path string, signFn func(*http.Request)) (int, string, string, string, map[string]any) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://n-rust-agent-res.example"+path, nil)
		if signFn != nil {
			signFn(req)
		}
		resp, dErr := httpClient.Do(req)
		must(dErr, "doN4Call "+path)
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, resp.Header.Get("Signature-Error"), resp.Header.Get("Accept-Signature-Scheme"), resp.Header.Get("AAuth-Requirement"), out
	}

	// 1. HWK ES256 -> 200 Decision::OtherScheme verified by host
	n4HWKESStatus, _, _, _, n4HWKESOut := doN4Call("/agent-op", func(r *http.Request) {
		must(signaturekey.SignHWKRequest(r, n4HWKES256Key, clock), "SignHWKRequest n4HWKES256Key")
	})
	// 2. HWK Ed25519 -> 200 Decision::OtherScheme verified by host
	n4HWKEdStatus, _, _, _, n4HWKEdOut := doN4Call("/agent-op", func(r *http.Request) {
		must(signaturekey.SignHWKRequest(r, n4HWKEdKey, clock), "SignHWKRequest n4HWKEdKey")
	})
	// 3. jwks_uri -> 200 Decision::OtherScheme verified by host fetching Go JWKS over HTTPS
	n4JWKSCred, err := signaturekey.NewJWKSURICredential(nGoIssuer, aauth.AgentDiscoveryDocument, nGoJWKSKey.ID())
	must(err, "NewJWKSURICredential n4JWKSCred")
	n4JWKSStatus, _, _, _, n4JWKSOut := doN4Call("/agent-op", func(r *http.Request) {
		must(signaturekey.SignRequest(r, nGoJWKSKey, n4JWKSCred, clock, signaturekey.SignOptions{}), "SignRequest n4JWKSCred")
	})
	// 4. Decision::OtherScheme.into_response() unhandled -> 403 Forbidden
	n4UnhandledStatus, _, _, _, _ := doN4Call("/agent-op?unhandled=1", func(r *http.Request) {
		must(signaturekey.SignHWKRequest(r, n4HWKEdKey, clock), "SignHWKRequest unhandled")
	})
	// 5. Unlisted scheme (jwks) -> 401 Signature-Error: error=unsupported_scheme + Accept-Signature-Scheme: jwt, hwk, jwks_uri, cached
	n4UnlistedCred, err := signaturekey.NewJWKSCredential(nGoIssuer+"/.well-known/jwks.json", nGoJWKSKey.ID())
	must(err, "NewJWKSCredential n4UnlistedCred")
	n4UnlistedStatus, n4UnlistedSigErr, n4UnlistedAcceptScheme, _, _ := doN4Call("/agent-op", func(r *http.Request) {
		must(signaturekey.SignRequest(r, nGoJWKSKey, n4UnlistedCred, clock, signaturekey.SignOptions{}), "SignRequest n4UnlistedCred")
	})
	// 6. Unsigned -> 401 AAuth-Requirement: requirement=agent-token
	n4UnsignedStatus, _, _, n4UnsignedReq, _ := doN4Call("/agent-op", nil)

	n4GoToRustOK := n4HWKESStatus == http.StatusOK && n4HWKESOut["scheme"] == "hwk" && n4HWKESOut["alg"] == "ES256" &&
		n4HWKEdStatus == http.StatusOK && n4HWKEdOut["scheme"] == "hwk" && n4HWKEdOut["alg"] == "Ed25519" &&
		n4JWKSStatus == http.StatusOK && n4JWKSOut["scheme"] == "jwks_uri" &&
		n4UnhandledStatus == http.StatusForbidden &&
		n4UnlistedStatus == http.StatusUnauthorized && strings.Contains(n4UnlistedSigErr, "error=unsupported_scheme") &&
		n4UnlistedAcceptScheme == "jwt, hwk, jwks_uri, cached" &&
		n4UnsignedStatus == http.StatusUnauthorized && strings.Contains(n4UnsignedReq, "requirement=agent-token")

	return map[string]any{
		"n_go_addr":     nGoSrv.Listener.Addr().String(),
		"n_go_cert_hex": hex.EncodeToString(nGoDER),
		"n2": map[string]any{
			"valid_display_resolved":         n2ValidErr == nil,
			"invalid_http_display_rejected":  n2InvalidIsResInvalid,
			"invalid_http_display_error_str": fmt.Sprintf("%v", n2InvalidErr),
		},
		"n3": map[string]any{
			"unit_ok":           n3UnitOK,
			"go_to_rust_ok":     n3GoToRustOK,
			"none_status":       n3NoneStatus,
			"no_int_status":     n3NoIntStatus,
			"with_int_status":   n3WithIntStatus,
			"with_int_location": n3WithIntLoc,
			"multi_status":      n3MultiStatus,
		},
		"n4": map[string]any{
			"go_to_rust_ok":          n4GoToRustOK,
			"hwk_es256_status":       n4HWKESStatus,
			"hwk_ed25519_status":     n4HWKEdStatus,
			"jwks_status":            n4JWKSStatus,
			"unhandled_status":       n4UnhandledStatus,
			"unlisted_status":        n4UnlistedStatus,
			"unlisted_sig_err":       n4UnlistedSigErr,
			"unlisted_accept_scheme": n4UnlistedAcceptScheme,
			"unsigned_status":        n4UnsignedStatus,
			"unsigned_requirement":   n4UnsignedReq,
		},
	}
}
