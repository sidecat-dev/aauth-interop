package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/budgets"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/r3"
	"gitlab.com/sidecat-dev/aauth-go/r3/vocab/mcp"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type qSuiteInput struct {
	RustFedPSIssuer        string `json:"rust_fed_ps_issuer"`
	RustFedASIssuer        string `json:"rust_fed_as_issuer"`
	RustFedResGoASIssuer   string `json:"rust_fed_res_go_as_issuer"`
	RustFedResRustASIssuer string `json:"rust_fed_res_rust_as_issuer"`
	RustRelayResIssuer     string `json:"rust_relay_res_issuer"`
	RustMeteredResIssuer   string `json:"rust_metered_res_issuer"`
	RustProposalRTDirect   string `json:"rust_proposal_rt_direct"`
	RustProposalRTFed      string `json:"rust_proposal_rt_fed"`
}

func deterministicKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}

func runQSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in qSuiteInput,
) map[string]any {
	if baseTr, ok := httpClient.Transport.(*http.Transport); ok {
		tr := baseTr.Clone()
		tr.DisableKeepAlives = false
		defer tr.CloseIdleConnections()
		cCopy := *httpClient
		cCopy.Transport = tr
		httpClient = &cCopy
	}

	newQKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var qIDSeq atomic.Int64
	nextQID := func() string {
		return "q-go-id-0123456789abcdef-" + strconvItoa(qIDSeq.Add(1))
	}

	qResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver qResolver")

	// =========================================================================
	// QA-Q4: Cross-Language 4-Party Missions (Rust <-> Go main 445af350)
	// =========================================================================
	const (
		q4GoAPIssuer        = "https://q4-go-ap.example"
		q4GoAgentID         = "aauth:caller@q4-go-ap.example"
		q4GoRelayIssuer     = "https://q4-go-relay.example"
		q4GoRelayAgentID    = "aauth:relay@q4-go-relay.example"
		q4GoFedPSIssuer     = "https://q4-go-fed-ps.example"
		q4GoASIssuer        = "https://q4-go-as.example"
		q4GoResGoASIssuer   = "https://q4-go-res-go-as.example"
		q4GoResRustASIssuer = "https://q4-go-res-rust-as.example"
	)

	q4APKey := newQKey("q4-ap-1", 0xd1)
	q4AgentKey := newQKey("q4-agent-1", 0xd2)
	q4RelayAPKey := newQKey("q4-relay-ap-1", 0xd3)
	q4RelayAgKey := newQKey("q4-relay-ag-1", 0xd4)
	q4GoFedPSKey := newQKey("q4-go-fed-ps-1", 0xd5)
	q4GoASKey := newQKey("q4-go-as-1", 0xd6)
	q4GoResGoASKey := newQKey("q4-go-res-go-as-1", 0xd7)
	q4GoResRustASKey := newQKey("q4-go-res-rust-as-1", 0xd8)

	q4AP, err := agentprovider.New(agentprovider.Config{
		Issuer:     q4GoAPIssuer,
		SigningKey: q4APKey,
		Clock:      clock,
		NewID:      nextQID,
	})
	must(err, "agentprovider.New q4AP")
	q4APSrv, q4APDER := registerTLS("q4-go-ap.example", q4AP.Handler())

	q4RelayAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     q4GoRelayIssuer,
		SigningKey: q4RelayAPKey,
		Clock:      clock,
		NewID:      nextQID,
	})
	must(err, "agentprovider.New q4RelayAP")
	q4RelayAPSrv, q4RelayAPDER := registerTLS("q4-go-relay.example", q4RelayAP.Handler())

	var (
		q4ASMu           sync.Mutex
		q4ASDeferMode    atomic.Bool
		q4ASLastMission  string
		q4ASHadUpstream  bool
		q4ASAuthorizeCnt atomic.Int64
	)

	q4GoAS, err := accessserver.New(accessserver.Config{
		Issuer:      q4GoASIssuer,
		SigningKey:  q4GoASKey,
		KeyResolver: qResolver,
		Clock:       clock,
		NewID:       nextQID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == q4GoFedPSIssuer || iss == in.RustFedPSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			q4ASAuthorizeCnt.Add(1)
			q4ASMu.Lock()
			q4ASLastMission = req.MissionS256
			q4ASHadUpstream = req.Upstream != nil
			q4ASMu.Unlock()
			if q4ASDeferMode.Load() {
				return accessserver.Decision{
					Pending: &accessserver.PendingDecision{RetryAfter: time.Second},
				}, nil
			}
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{
			Store:    testutil.NewAccessAuthorizationStore(),
			Lifetime: 5 * time.Minute,
		},
	})
	must(err, "accessserver.New q4GoAS")
	q4GoASMux := http.NewServeMux()
	q4GoASMux.HandleFunc("/__q4-as-mode", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Defer bool `json:"defer"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		q4ASDeferMode.Store(body.Defer)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"defer": q4ASDeferMode.Load()})
	})
	q4GoASMux.HandleFunc("/__q4-as-seen", func(w http.ResponseWriter, r *http.Request) {
		q4ASMu.Lock()
		lastMission := q4ASLastMission
		hadUp := q4ASHadUpstream
		q4ASMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"last_mission_s256": lastMission,
			"had_upstream":      hadUp,
			"authorize_count":   q4ASAuthorizeCnt.Load(),
		})
	})
	q4GoASMux.Handle("/", q4GoAS.Handler())
	q4GoASSrv, q4GoASDER := registerTLS("q4-go-as.example", q4GoASMux)

	q4GoResGoAS, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            q4GoResGoASIssuer,
		AccessServer:      q4GoASIssuer,
		SigningKey:        q4GoResGoASKey,
		KeyResolver:       qResolver,
		Clock:             clock,
		NewID:             nextQID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":            true,
				"subject":       p.Subject,
				"person_server": p.PersonServer,
				"mission_s256":  p.MissionS256,
			})
		}),
	})
	must(err, "resource.NewFederatedAuthorization q4GoResGoAS")
	q4GoResGoASSrv, q4GoResGoASDER := registerTLS("q4-go-res-go-as.example", q4GoResGoAS.Handler())

	q4GoResRustAS, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            q4GoResRustASIssuer,
		AccessServer:      in.RustFedASIssuer,
		SigningKey:        q4GoResRustASKey,
		KeyResolver:       qResolver,
		Clock:             clock,
		NewID:             nextQID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":            true,
				"subject":       p.Subject,
				"person_server": p.PersonServer,
				"mission_s256":  p.MissionS256,
			})
		}),
	})
	must(err, "resource.NewFederatedAuthorization q4GoResRustAS")
	q4GoResRustASSrv, q4GoResRustASDER := registerTLS("q4-go-res-rust-as.example", q4GoResRustAS.Handler())

	var (
		q4GoPSMu            sync.Mutex
		q4GoPSConsentMisS256 string
	)
	q4MissionStore := testutil.NewMissionStore()
	q4GoFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:       q4GoFedPSIssuer,
		SigningKey:   q4GoFedPSKey,
		KeyResolver:  qResolver,
		Clock:        clock,
		NewID:        nextQID,
		HTTPClient:   httpClient,
		Tokens:       q4MissionStore,
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-q4-go", Lifetime: 15 * time.Minute}, nil
		},
		AccessServerEndpoint: func(_ context.Context, asIssuer string) (string, error) {
			return asIssuer + "/token", nil
		},
		Consent: func(_ context.Context, req personserver.AuthorizationRequest) error {
			q4GoPSMu.Lock()
			if req.Mission != nil {
				q4GoPSConsentMisS256 = req.Mission.S256
			} else {
				q4GoPSConsentMisS256 = ""
			}
			q4GoPSMu.Unlock()
			return nil
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, req personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				exp := clock.Now().UTC().Add(30 * time.Minute)
				return personserver.MissionDecision{
					Description:       req.Proposal.Description,
					ApprovedTools:     req.Proposal.Tools,
					ApprovedResources: req.Proposal.Resources,
					ExpiresAt:         &exp,
					Capabilities:      []string{"interaction"},
				}, nil
			},
		},
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-q4-go-at-" + req.Resource, Lifetime: 15 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		Deferred: &personserver.FederatedDeferredConfig{
			Store:    testutil.NewFederatedAuthorizationStore(),
			Lifetime: 5 * time.Minute,
		},
	})
	must(err, "personserver.NewFederatedAuthorization q4GoFedPS")
	q4CallerTok, err := q4AP.Issue(aauth.AgentTokenRequest{
		Agent:        q4GoAgentID,
		PersonServer: q4GoFedPSIssuer,
		PublicKey:    q4AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "q4AP.Issue q4CallerTok")

	q4RelayTok, err := q4RelayAP.Issue(aauth.AgentTokenRequest{
		Agent:        q4GoRelayAgentID,
		PersonServer: q4GoFedPSIssuer,
		PublicKey:    q4RelayAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "q4RelayAP.Issue q4RelayTok")

	q4GoFedPSMux := http.NewServeMux()
	q4GoFedPSMux.HandleFunc("/__q4-go-ps-exchange", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ResourceToken  string `json:"resource_token"`
			PresentedToken string `json:"presented_token"`
			UpstreamToken  string `json:"upstream_token,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		reqMap := map[string]string{
			"resource_token":  body.ResourceToken,
			"presented_token": body.PresentedToken,
		}
		if body.UpstreamToken != "" {
			reqMap["upstream_token"] = body.UpstreamToken
		}
		raw, _ := json.Marshal(reqMap)
		tokReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, q4GoFedPSIssuer+"/token", bytes.NewReader(raw))
		tokReq.Header.Set("Content-Type", "application/json")
		_ = signaturekey.SignJWTRequest(tokReq, q4AgentKey, q4CallerTok, clock)
		resp, err := httpClient.Do(tokReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": resp.StatusCode,
			"body":   out,
		})
	})
	q4GoFedPSMux.Handle("/", q4GoFedPS.Handler())
	q4GoFedPSSrv, q4GoFedPSDER := registerTLS("q4-go-fed-ps.example", q4GoFedPSMux)

	q4CallerCli, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  q4GoAgentID,
		SigningKey:  q4AgentKey,
		AgentToken:  q4CallerTok,
		KeyResolver: qResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	must(err, "clientagent.New q4CallerCli")

	// Propose a mission at Go Federated PS covering Rust & Go Federated Resources
	q4MisRes, err := q4CallerCli.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: q4GoFedPSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# Cross-Language 4-Party Mission\nRead records across Rust and Go federated resources.",
			Resources: []string{
				in.RustFedResRustASIssuer,
				in.RustFedResGoASIssuer,
				q4GoResRustASIssuer,
				q4GoResGoASIssuer,
				q4GoRelayIssuer,
				in.RustRelayResIssuer,
			},
		},
	})
	must(err, "q4CallerCli.ProposeMission")
	q4GoMissionS256 := q4MisRes.Mission().S256
	q4PTForRustResRustAS, _ := q4MisRes.PersonToken(in.RustFedResRustASIssuer)
	q4PTForGoResRustAS, _ := q4MisRes.PersonToken(q4GoResRustASIssuer)
	q4PTForRustResGoAS, _ := q4MisRes.PersonToken(in.RustFedResGoASIssuer)
	q4PTForGoResGoAS, _ := q4MisRes.PersonToken(q4GoResGoASIssuer)
	q4PTForRelay, _ := q4MisRes.PersonToken(q4GoRelayIssuer)

	// Flow 1: Go Federated PS -> Rust AS -> Rust Federated Resource (with_mission_context)
	q4RT1, err := q4CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    in.RustFedResRustASIssuer,
		PersonToken: q4PTForRustResRustAS,
		Scopes:      []string{"records.read"},
	})
	must(err, "q4CallerCli.Authorize RustFedResRustAS")
	q4AT1, err := q4CallerCli.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   q4GoFedPSIssuer,
		ResourceToken:  q4RT1,
		PresentedToken: q4PTForRustResRustAS,
	})
	must(err, "q4CallerCli.Exchange GoFedPS -> RustAS (RustRes)")
	q4AT1Claims, err := aauth.VerifyAuthToken(ctx, q4AT1, qResolver, clock)
	must(err, "VerifyAuthToken q4AT1")
	q4Call1Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustFedResRustASIssuer+"/records", nil)
	q4Call1Resp, err := q4CallerCli.Do(ctx, clientagent.Call{Request: q4Call1Req, AuthToken: q4AT1})
	must(err, "q4CallerCli.Do RustFedResRustAS")
	var q4Call1Body map[string]any
	_ = json.NewDecoder(q4Call1Resp.Body).Decode(&q4Call1Body)
	_ = q4Call1Resp.Body.Close()

	// Flow 2: Go Federated PS -> Rust AS -> Go Federated Resource
	q4RT2, err := q4CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    q4GoResRustASIssuer,
		PersonToken: q4PTForGoResRustAS,
		Scopes:      []string{"records.read"},
	})
	must(err, "q4CallerCli.Authorize q4GoResRustAS")
	q4AT2, err := q4CallerCli.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   q4GoFedPSIssuer,
		ResourceToken:  q4RT2,
		PresentedToken: q4PTForGoResRustAS,
	})
	must(err, "q4CallerCli.Exchange GoFedPS -> RustAS (GoRes)")
	q4AT2Claims, err := aauth.VerifyAuthToken(ctx, q4AT2, qResolver, clock)
	must(err, "VerifyAuthToken q4AT2")
	q4Call2Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, q4GoResRustASIssuer+"/records", nil)
	q4Call2Resp, err := q4CallerCli.Do(ctx, clientagent.Call{Request: q4Call2Req, AuthToken: q4AT2})
	must(err, "q4CallerCli.Do q4GoResRustAS")
	var q4Call2Body map[string]any
	_ = json.NewDecoder(q4Call2Resp.Body).Decode(&q4Call2Body)
	_ = q4Call2Resp.Body.Close()
	// Flow 3: Go Federated PS -> Go AS -> Rust Federated Resource (with_mission_context)
	q4RT3, err := q4CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    in.RustFedResGoASIssuer,
		PersonToken: q4PTForRustResGoAS,
		Scopes:      []string{"records.read"},
	})
	must(err, "q4CallerCli.Authorize RustFedResGoAS")
	q4AT3, err := q4CallerCli.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   q4GoFedPSIssuer,
		ResourceToken:  q4RT3,
		PresentedToken: q4PTForRustResGoAS,
	})
	must(err, "q4CallerCli.Exchange GoFedPS -> GoAS (RustRes)")
	q4AT3Claims, err := aauth.VerifyAuthToken(ctx, q4AT3, qResolver, clock)
	must(err, "VerifyAuthToken q4AT3")
	q4Call3Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustFedResGoASIssuer+"/records", nil)
	q4Call3Resp, err := q4CallerCli.Do(ctx, clientagent.Call{Request: q4Call3Req, AuthToken: q4AT3})
	must(err, "q4CallerCli.Do RustFedResGoAS")
	var q4Call3Body map[string]any
	_ = json.NewDecoder(q4Call3Resp.Body).Decode(&q4Call3Body)
	_ = q4Call3Resp.Body.Close()

	// Flow 4: Go Federated PS -> Go AS -> Go Federated Resource
	q4RT4, err := q4CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    q4GoResGoASIssuer,
		PersonToken: q4PTForGoResGoAS,
		Scopes:      []string{"records.read"},
	})
	must(err, "q4CallerCli.Authorize q4GoResGoAS")
	q4AT4, err := q4CallerCli.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   q4GoFedPSIssuer,
		ResourceToken:  q4RT4,
		PresentedToken: q4PTForGoResGoAS,
	})
	must(err, "q4CallerCli.Exchange GoFedPS -> GoAS (GoRes)")
	q4AT4Claims, err := aauth.VerifyAuthToken(ctx, q4AT4, qResolver, clock)
	must(err, "VerifyAuthToken q4AT4")
	q4Call4Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, q4GoResGoASIssuer+"/records", nil)
	q4Call4Resp, err := q4CallerCli.Do(ctx, clientagent.Call{Request: q4Call4Req, AuthToken: q4AT4})
	must(err, "q4CallerCli.Do q4GoResGoAS")
	var q4Call4Body map[string]any
	_ = json.NewDecoder(q4Call4Resp.Body).Decode(&q4Call4Body)
	_ = q4Call4Resp.Body.Close()

	q4GoPSMu.Lock()
	q4GoPSConsentSeen := q4GoPSConsentMisS256
	q4GoPSMu.Unlock()

	// Also mint a fresh mission-bound ResourceToken for RustFedResRustAS so Rust can test
	// Go Federated PS -> Rust AS when Rust AS is switched to deferred (202) mode.
	q4RTForDeferTest, err := q4CallerCli.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    in.RustFedResRustASIssuer,
		PersonToken: q4PTForRustResRustAS,
		Scopes:      []string{"records.read"},
	})
	must(err, "q4CallerCli.Authorize q4RTForDeferTest")

	// Mixed-deployment boundary checks on Go Federated PS (chained mission attempts):
	// (a) POST /person with mission-bound PersonToken as upstream_token -> 500 server_error
	q4B4PersonBody, _ := json.Marshal(map[string]string{
		"resource":       in.RustFedResRustASIssuer,
		"upstream_token": q4PTForRelay,
	})
	q4B4PersonReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q4GoFedPSIssuer+"/person", bytes.NewReader(q4B4PersonBody))
	q4B4PersonReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q4B4PersonReq, q4RelayAgKey, q4RelayTok, clock)
	q4B4PersonResp, err := httpClient.Do(q4B4PersonReq)
	must(err, "httpClient.Do q4B4PersonReq")
	var q4B4PersonOut map[string]any
	_ = json.NewDecoder(q4B4PersonResp.Body).Decode(&q4B4PersonOut)
	_ = q4B4PersonResp.Body.Close()

	// (b) POST /person with AS-issued AuthToken (dwk="aauth-access.json", carrying mission_s256) as upstream_token -> 400 invalid_upstream_token
	q4B2PersonBody, _ := json.Marshal(map[string]string{
		"resource":       in.RustFedResRustASIssuer,
		"upstream_token": q4AT1,
	})
	q4B2PersonReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q4GoFedPSIssuer+"/person", bytes.NewReader(q4B2PersonBody))
	q4B2PersonReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q4B2PersonReq, q4RelayAgKey, q4RelayTok, clock)
	q4B2PersonResp, err := httpClient.Do(q4B2PersonReq)
	must(err, "httpClient.Do q4B2PersonReq")
	var q4B2PersonOut map[string]any
	_ = json.NewDecoder(q4B2PersonResp.Body).Decode(&q4B2PersonOut)
	_ = q4B2PersonResp.Body.Close()

	// (c) POST /person with both upstream_token and mission_s256 body field -> 400 invalid_request
	q4BothPersonBody, _ := json.Marshal(map[string]string{
		"resource":       in.RustFedResRustASIssuer,
		"upstream_token": q4PTForRelay,
		"mission_s256":   q4GoMissionS256,
	})
	q4BothPersonReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q4GoFedPSIssuer+"/person", bytes.NewReader(q4BothPersonBody))
	q4BothPersonReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q4BothPersonReq, q4RelayAgKey, q4RelayTok, clock)
	q4BothPersonResp, err := httpClient.Do(q4BothPersonReq)
	must(err, "httpClient.Do q4BothPersonReq")
	var q4BothPersonOut map[string]any
	_ = json.NewDecoder(q4BothPersonResp.Body).Decode(&q4BothPersonOut)
	_ = q4BothPersonResp.Body.Close()

	// (d) POST /token with upstream_token and mission-bound resource_token -> 400 invalid_request
	q4BothTokBody, _ := json.Marshal(map[string]string{
		"resource_token":  q4RTForDeferTest,
		"presented_token": q4PTForRustResRustAS,
		"upstream_token":  q4PTForRelay,
	})
	q4BothTokReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q4GoFedPSIssuer+"/token", bytes.NewReader(q4BothTokBody))
	q4BothTokReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q4BothTokReq, q4RelayAgKey, q4RelayTok, clock)
	q4BothTokResp, err := httpClient.Do(q4BothTokReq)
	must(err, "httpClient.Do q4BothTokReq")
	var q4BothTokOut map[string]any
	_ = json.NewDecoder(q4BothTokResp.Body).Decode(&q4BothTokOut)
	_ = q4BothTokResp.Body.Close()
	// =========================================================================
	// QA-Q5: Cross-Language Metered Release Wire Check Against aauth-go main
	// =========================================================================
	const (
		q5GoDirectPSIssuer  = "https://q5-go-direct-ps.example"
		q5GoFedPSIssuer     = "https://q5-go-fed-ps.example"
		q5GoASIssuer        = "https://q5-go-as.example"
		q5GoHeldR3ResIssuer = "https://q5-go-held-r3-res.example"
	)
	q5DirectPSKey := newQKey("q5-direct-ps-1", 0xd9)
	q5FedPSKey := newQKey("q5-fed-ps-1", 0xda)
	q5ASKey := newQKey("q5-as-1", 0xdb)
	q5HeldResKey := newQKey("q5-held-res-1", 0xdc)

	q5Registry, err := r3.NewRegistry(mcp.Vocabulary())
	must(err, "r3.NewRegistry q5")
	q5Defs, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	must(err, "r3.NewDefinitionRegistry q5")
	q5Unit, err := budgets.NewUnit("USD", 2)
	must(err, "budgets.NewUnit q5")
	q5UnitDecl, err := budgets.NewUnitDeclaration(q5Unit, "US dollars")
	must(err, "budgets.NewUnitDeclaration q5")
	q5CapVal, err := budgets.NewValue(5000, q5Unit)
	must(err, "budgets.NewValue q5CapVal")
	q5OfferVal, err := budgets.NewValue(250, q5Unit)
	must(err, "budgets.NewValue q5OfferVal")
	q5OpQuery, _ := mcp.NewOperation("records.query")
	q5R3Query, _ := q5OpQuery.ToR3()

	q5DirectPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      q5GoDirectPSIssuer,
		SigningKey:  q5DirectPSKey,
		KeyResolver: qResolver,
		Clock:       clock,
		NewID:       nextQID,
		Tokens:      &memoryTokenStore{},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-q5", Lifetime: 30 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Budget: req.Budget}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry:   q5Registry,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
			AuthorizeDocument: func(_ context.Context, req personserver.AuthorizationRequest, _ r3.Reference, doc r3.Document) (personserver.DirectR3Decision, error) {
				granted, gErr := r3.NewGrantedOperations(mcp.Vocabulary(), q5R3Query)
				if gErr != nil {
					return personserver.DirectR3Decision{}, gErr
				}
				g, gErr := r3.NewGrant(granted, doc)
				if gErr != nil {
					return personserver.DirectR3Decision{}, gErr
				}
				return personserver.DirectR3Decision{
					Scopes:   req.Scopes,
					Lifetime: 30 * time.Minute,
					Grant:    g,
					Budget:   req.Budget,
				}, nil
			},
			Issuances: &memoryIssuanceStore{},
		},
		Budget: &personserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
				return []budgets.UnitDeclaration{q5UnitDecl}, nil
			},
		},
	})
	must(err, "personserver.NewPSAuthorization q5DirectPS")
	q5DirectPSSrv, q5DirectPSDER := registerTLS("q5-go-direct-ps.example", q5DirectPS.Handler())

	q5GoAS, err := accessserver.New(accessserver.Config{
		Issuer:      q5GoASIssuer,
		SigningKey:  q5ASKey,
		KeyResolver: qResolver,
		Clock:       clock,
		NewID:       nextQID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == q5GoFedPSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Budget: req.Budget}, nil
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
				return []budgets.UnitDeclaration{q5UnitDecl}, nil
			},
		},
		R3: &accessserver.R3Config{
			Registry:   q5Registry,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
			AuthorizeDocument: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, doc r3.Document) (accessserver.R3DocumentDecision, error) {
				grantedOps, _ := r3.NewGrantedOperations(mcp.Vocabulary(), q5R3Query)
				emptyOps, _ := r3.NewGrantedOperations(mcp.Vocabulary())
				authz, aErr := r3.NewAuthorization(grantedOps, emptyOps, doc)
				if aErr != nil {
					return accessserver.R3DocumentDecision{}, aErr
				}
				return accessserver.R3DocumentDecision{
					Scopes:        req.Scopes,
					Lifetime:      30 * time.Minute,
					Authorization: &authz,
					Budget:        req.Budget,
				}, nil
			},
			AuthorizeProposal: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, _ r3.Proposal) (accessserver.R3ProposalDecision, error) {
				return accessserver.R3ProposalDecision{
					Scopes:   req.Scopes,
					Lifetime: 5 * time.Minute,
				}, nil
			},
			Issuances: &memoryIssuanceStore{},
		},
	})
	must(err, "accessserver.New q5GoAS")
	q5GoASSrv, q5GoASDER := registerTLS("q5-go-as.example", q5GoAS.Handler())

	q5GoFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      q5GoFedPSIssuer,
		SigningKey:  q5FedPSKey,
		KeyResolver: qResolver,
		Clock:       clock,
		NewID:       nextQID,
		HTTPClient:  httpClient,
		Tokens:      &memoryTokenStore{},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-q5", Lifetime: 30 * time.Minute}, nil
		},
		AccessServerEndpoint: func(_ context.Context, asIssuer string) (string, error) {
			return asIssuer + "/token", nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		R3: &personserver.R3Config{
			Registry:        q5Registry,
			Admit:           func(context.Context, string) error { return nil },
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error { return nil },
			ConsentProposal: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Proposal) error { return nil },
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) {
				return []budgets.UnitDeclaration{q5UnitDecl}, nil
			},
			Ceiling: func(context.Context, personserver.AuthorizationRequest) (*budgets.Value, error) {
				v := q5CapVal
				return &v, nil
			},
		},
	})
	must(err, "personserver.NewFederatedAuthorization q5GoFedPS")
	q5GoFedPSSrv, q5GoFedPSDER := registerTLS("q5-go-fed-ps.example", q5GoFedPS.Handler())
	q5DefSrc := mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"records.query","inputSchema":{"type":"object"}}]}`,
	)))
	q5Def, err := mcp.ParseDefinition(q5GoHeldR3ResIssuer+"/mcp", q5DefSrc)
	must(err, "mcp.ParseDefinition q5")
	q5SetQuery, _ := mcp.NewOperationSet(q5OpQuery)
	q5Disp, _ := r3.NewDisplay("Query records", "", "Records", "")
	q5Docs := &memoryDocumentStore{}
	q5Props := &memoryProposalStore{}
	q5HeldStore := newPHeldBudgetStore()

	q5HeldRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:                       q5GoHeldR3ResIssuer,
		AccessServer:                 in.RustFedASIssuer,
		SigningKey:                   q5HeldResKey,
		KeyResolver:                  qResolver,
		Clock:                        clock,
		NewID:                        nextQID,
		ScopeDescriptions:            map[string]string{"records.read": "Read records"},
		RequiredScopes:               func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:                func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		HeldInvocations:              q5HeldStore,
		HoldAuthTokenRequest:         func(*http.Request) bool { return true },
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"records":99}`)
		}),
		R3: &resource.R3Config{
			Registry:    q5Registry,
			Definitions: q5Defs,
			Vocabularies: []resource.R3VocabularyConfig{{
				Definition:          q5Def,
				InternalDefinitions: []resource.R3InternalDefinition{{Name: "q5-query", Operations: q5SetQuery, Display: q5Disp}},
			}},
			Documents: q5Docs,
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(r *http.Request) (r3.Operation, bool, error) {
					if strings.HasPrefix(r.URL.Path, "/records/") {
						return q5R3Query, true, nil
					}
					return r3.Operation{}, false, nil
				},
				PresentParameters: func(r *http.Request, _ r3.Operation) (map[string]r3.PresentedParameter, error) {
					enc, _ := json.Marshal(strings.TrimPrefix(r.URL.Path, "/records/"))
					pres, _ := r3.NewPresentedInlineParameter(enc)
					return map[string]r3.PresentedParameter{"query": pres}, nil
				},
			},
			PerCall: &resource.R3PerCallConfig{
				Proposals: q5Props,
				Retries:   &memoryRetryStore{},
				DescribeCall: func(_ context.Context, inv r3.Invocation, _ *string) (resource.R3CallDescription, error) {
					enc, _ := inv.PresentedParameters()["query"].InlineJSON()
					inl, _ := r3.NewInlineParameter(enc)
					params, _ := r3.NewParameters(map[string]r3.Parameter{"query": inl})
					return resource.R3CallDescription{Parameters: params}, nil
				},
				Release: &resource.R3ReleaseConfig{
					Eligible: func(context.Context, r3.Invocation) (bool, error) { return true, nil },
					DescribeResult: func(_ context.Context, req resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
						enc, _ := req.Invocation.PresentedParameters()["query"].InlineJSON()
						inl, _ := r3.NewInlineParameter(enc)
						params, _ := r3.NewParameters(map[string]r3.Parameter{"query": inl})
						return resource.R3ReleaseDescription{
							Parameters: params,
							Result:     json.RawMessage(`{"records":99}`),
							Display:    q5Disp,
						}, nil
					},
				},
			},
		},
	})
	must(err, "resource.NewFederatedAuthorization q5HeldRes")
	q5HeldResSrv, q5HeldResDER := registerTLS("q5-go-held-r3-res.example", q5HeldRes.Handler())

	// 1. Send Rust metered-release proposal ResourceToken (carrying r3_uri, r3_s256, budget) to Go Direct PS (/token)
	q5RustResKey := newQKey("q5-rust-metered-res-1", 0x76)
	q5AgentJKT, err := q4AgentKey.PublicJWK().Thumbprint()
	must(err, "q4AgentKey.PublicJWK().Thumbprint")
	q5OfferRaw, _ := json.Marshal(q5OfferVal)
	q5PropInl, _ := r3.NewInlineParameter([]byte(`"r-1"`))
	q5PropParams, _ := r3.NewParameters(map[string]r3.Parameter{"record": q5PropInl})
	q5OpMetered, _ := mcp.NewOperation("records.metered_query")
	q5R3Metered, _ := q5OpMetered.ToR3()
	q5PropDoc, err := r3.NewProposal(q5R3Metered, q5PropParams, r3.ProposalOptions{})
	must(err, "r3.NewProposal q5PropDoc")
	q5PropExact, err := json.Marshal(q5PropDoc)
	must(err, "json.Marshal q5PropDoc")
	q5PropS256 := r3.Digest(q5PropExact)
	q5PropURIDirRaw, _ := json.Marshal(in.RustMeteredResIssuer + "/r3/proposals/prop-dir-1")
	q5PropURIFedRaw, _ := json.Marshal(in.RustMeteredResIssuer + "/r3/proposals/prop-fed-1")
	q5PropS256Raw, _ := json.Marshal(q5PropS256)

	q5DirAgentTok, _ := q4AP.Issue(aauth.AgentTokenRequest{
		Agent:        q4GoAgentID,
		PersonServer: q5GoDirectPSIssuer,
		PublicKey:    q4AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	q5DirCli, _ := clientagent.New(ctx, clientagent.Config{
		Identifier:  q4GoAgentID,
		SigningKey:  q4AgentKey,
		AgentToken:  q5DirAgentTok,
		KeyResolver: qResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	q5DirPTRes, err := q5DirCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: q5GoDirectPSIssuer,
		Resource:     in.RustMeteredResIssuer,
	})
	must(err, "q5DirCli.PersonToken")
	q5DirPT, _ := q5DirPTRes.Token()
	q5DirPTClaims, err := aauth.VerifyPersonToken(ctx, q5DirPT, qResolver, clock)
	must(err, "VerifyPersonToken q5DirPT")
	q5ProposalRTDirect, err := aauth.MintResourceTokenCore(q5RustResKey, aauth.ResourceTokenClaims{
		Issuer:       in.RustMeteredResIssuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     q5GoDirectPSIssuer,
		PersonServer: q5GoDirectPSIssuer,
		Subject:      q5DirPTClaims.Subject,
		AgentJKT:     q5AgentJKT,
		JTI:          "q5-prop-rt-dir-1",
		IssuedAt:     clock.Now().Unix(),
		ExpiresAt:    clock.Now().Add(5 * time.Minute).Unix(),
		PresentedJTI: q5DirPTClaims.JTI,
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri":  q5PropURIDirRaw,
			"r3_s256": q5PropS256Raw,
			"budget":  q5OfferRaw,
		},
	})
	must(err, "MintResourceTokenCore q5ProposalRTDirect")
	q5DirExBody, _ := json.Marshal(map[string]string{
		"resource_token":  q5ProposalRTDirect,
		"presented_token": q5DirPT,
	})
	q5DirExReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q5GoDirectPSIssuer+"/token", bytes.NewReader(q5DirExBody))
	q5DirExReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q5DirExReq, q4AgentKey, q5DirAgentTok, clock)
	q5DirExResp, err := httpClient.Do(q5DirExReq)
	must(err, "httpClient.Do q5DirExReq")
	var q5DirExOut map[string]any
	_ = json.NewDecoder(q5DirExResp.Body).Decode(&q5DirExOut)
	_ = q5DirExResp.Body.Close()

	// 2. Send Rust metered-release proposal ResourceToken (carrying r3_uri, r3_s256, budget) to Go Federated PS -> Go AS (/token)
	q5FedAgentTok, _ := q4AP.Issue(aauth.AgentTokenRequest{
		Agent:        q4GoAgentID,
		PersonServer: q5GoFedPSIssuer,
		PublicKey:    q4AgentKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	q5FedCli, _ := clientagent.New(ctx, clientagent.Config{
		Identifier:  q4GoAgentID,
		SigningKey:  q4AgentKey,
		AgentToken:  q5FedAgentTok,
		KeyResolver: qResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	q5FedPTRes, err := q5FedCli.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: q5GoFedPSIssuer,
		Resource:     in.RustMeteredResIssuer,
	})
	must(err, "q5FedCli.PersonToken")
	q5FedPT, _ := q5FedPTRes.Token()
	q5FedPTClaims, err := aauth.VerifyPersonToken(ctx, q5FedPT, qResolver, clock)
	must(err, "VerifyPersonToken q5FedPT")
	q5ProposalRTFed, err := aauth.MintResourceTokenCore(q5RustResKey, aauth.ResourceTokenClaims{
		Issuer:       in.RustMeteredResIssuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     q5GoASIssuer,
		PersonServer: q5GoFedPSIssuer,
		Subject:      q5FedPTClaims.Subject,
		AgentJKT:     q5AgentJKT,
		JTI:          "q5-prop-rt-fed-1",
		IssuedAt:     clock.Now().Unix(),
		ExpiresAt:    clock.Now().Add(5 * time.Minute).Unix(),
		PresentedJTI: q5FedPTClaims.JTI,
		AdditionalClaims: map[string]json.RawMessage{
			"r3_uri":  q5PropURIFedRaw,
			"r3_s256": q5PropS256Raw,
			"budget":  q5OfferRaw,
		},
	})
	must(err, "MintResourceTokenCore q5ProposalRTFed")
	q5FedExBody, _ := json.Marshal(map[string]string{
		"resource_token":  q5ProposalRTFed,
		"presented_token": q5FedPT,
	})
	q5FedExReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q5GoFedPSIssuer+"/token", bytes.NewReader(q5FedExBody))
	q5FedExReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWTRequest(q5FedExReq, q4AgentKey, q5FedAgentTok, clock)
	q5FedExResp, err := httpClient.Do(q5FedExReq)
	must(err, "httpClient.Do q5FedExReq")
	var q5FedExOut map[string]any
	_ = json.NewDecoder(q5FedExResp.Body).Decode(&q5FedExOut)
	_ = q5FedExResp.Body.Close()

	// Also send the PS->AS request directly to q5GoAS to verify q5GoAS returns 500 server_error
	q5ASDirectBody, _ := json.Marshal(map[string]any{
		"resource_token":  q5ProposalRTFed,
		"presented_token": q5FedPT,
		"agent_token":     q5FedAgentTok,
		"budget":          q5OfferVal,
	})
	q5ASDirectReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, q5GoASIssuer+"/token", bytes.NewReader(q5ASDirectBody))
	q5ASDirectReq.Header.Set("Content-Type", "application/json")
	_ = signaturekey.SignJWKSURIRequest(q5ASDirectReq, q5FedPSKey, q5GoFedPSIssuer, aauth.PersonDiscoveryDocument, clock)
	q5ASDirectResp, err := httpClient.Do(q5ASDirectReq)
	must(err, "httpClient.Do q5ASDirectReq")
	var q5ASDirectOut map[string]any
	_ = json.NewDecoder(q5ASDirectResp.Body).Decode(&q5ASDirectOut)
	_ = q5ASDirectResp.Body.Close()
	return map[string]any{
		"servers": map[string]any{
			"q4_go_ap":          map[string]any{"issuer": q4GoAPIssuer, "addr": q4APSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4APDER}))},
			"q4_go_relay":       map[string]any{"issuer": q4GoRelayIssuer, "addr": q4RelayAPSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4RelayAPDER}))},
			"q4_go_fed_ps":      map[string]any{"issuer": q4GoFedPSIssuer, "addr": q4GoFedPSSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4GoFedPSDER}))},
			"q4_go_as":          map[string]any{"issuer": q4GoASIssuer, "addr": q4GoASSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4GoASDER}))},
			"q4_go_res_go_as":   map[string]any{"issuer": q4GoResGoASIssuer, "addr": q4GoResGoASSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4GoResGoASDER}))},
			"q4_go_res_rust_as": map[string]any{"issuer": q4GoResRustASIssuer, "addr": q4GoResRustASSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q4GoResRustASDER}))},
			"q5_go_direct_ps":   map[string]any{"issuer": q5GoDirectPSIssuer, "addr": q5DirectPSSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q5DirectPSDER}))},
			"q5_go_fed_ps":      map[string]any{"issuer": q5GoFedPSIssuer, "addr": q5GoFedPSSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q5GoFedPSDER}))},
			"q5_go_as":          map[string]any{"issuer": q5GoASIssuer, "addr": q5GoASSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q5GoASDER}))},
			"q5_go_held_res":    map[string]any{"issuer": q5GoHeldR3ResIssuer, "addr": q5HeldResSrv.Listener.Addr().String(), "cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: q5HeldResDER}))},
		},
		"q4": map[string]any{
			"go_mission_s256":             q4GoMissionS256,
			"go_ps_consent_mission_s256":  q4GoPSConsentSeen,
			"pt_for_rust_res_rust_as":     q4PTForRustResRustAS,
			"rt_for_defer_test":           q4RTForDeferTest,
			"flow1_go_ps_rust_as_rust_res": map[string]any{
				"status":          q4Call1Resp.StatusCode,
				"at_mission_s256": q4AT1Claims.MissionS256,
				"at_exp":          q4AT1Claims.ExpiresAt,
				"res_body":        q4Call1Body,
				"ok":              q4Call1Resp.StatusCode == http.StatusOK && q4AT1Claims.MissionS256 == q4GoMissionS256 && q4Call1Body["mission_s256"] == q4GoMissionS256,
			},
			"flow2_go_ps_rust_as_go_res": map[string]any{
				"status":          q4Call2Resp.StatusCode,
				"at_mission_s256": q4AT2Claims.MissionS256,
				"at_exp":          q4AT2Claims.ExpiresAt,
				"res_body":        q4Call2Body,
				"ok":              q4Call2Resp.StatusCode == http.StatusOK && q4AT2Claims.MissionS256 == q4GoMissionS256 && q4Call2Body["mission_s256"] == q4GoMissionS256,
			},
			"flow3_go_ps_go_as_rust_res": map[string]any{
				"status":          q4Call3Resp.StatusCode,
				"at_mission_s256": q4AT3Claims.MissionS256,
				"at_exp":          q4AT3Claims.ExpiresAt,
				"res_body":        q4Call3Body,
				"ok":              q4Call3Resp.StatusCode == http.StatusOK && q4AT3Claims.MissionS256 == q4GoMissionS256 && q4Call3Body["mission_s256"] == q4GoMissionS256,
			},
			"flow4_go_ps_go_as_go_res": map[string]any{
				"status":          q4Call4Resp.StatusCode,
				"at_mission_s256": q4AT4Claims.MissionS256,
				"at_exp":          q4AT4Claims.ExpiresAt,
				"res_body":        q4Call4Body,
				"ok":              q4Call4Resp.StatusCode == http.StatusOK && q4AT4Claims.MissionS256 == q4GoMissionS256 && q4Call4Body["mission_s256"] == q4GoMissionS256,
			},
			"boundaries": map[string]any{
				"b4_person_upstream_mission_pt": map[string]any{
					"status":       q4B4PersonResp.StatusCode,
					"error":        q4B4PersonOut["error"],
					"person_token": q4B4PersonOut["person_token"],
					"ok":           q4B4PersonResp.StatusCode == http.StatusOK && q4B4PersonOut["person_token"] != nil,
				},
				"b2_person_upstream_as_auth": map[string]any{
					"status": q4B2PersonResp.StatusCode,
					"error":  q4B2PersonOut["error"],
					"ok":     q4B2PersonResp.StatusCode == http.StatusBadRequest && q4B2PersonOut["error"] == "invalid_upstream_token",
				},
				"b4_person_upstream_and_mission_field": map[string]any{
					"status": q4BothPersonResp.StatusCode,
					"error":  q4BothPersonOut["error"],
					"ok":     q4BothPersonResp.StatusCode == http.StatusBadRequest && q4BothPersonOut["error"] == "invalid_request",
				},
				"b4_token_upstream_and_mission_rt": map[string]any{
					"status": q4BothTokResp.StatusCode,
					"error":  q4BothTokOut["error"],
					"ok":     q4BothTokResp.StatusCode == http.StatusBadRequest,
				},
			},
		},
		"q5": map[string]any{
			"direct_ps_proposal_rt_refusal": map[string]any{
				"status": q5DirExResp.StatusCode,
				"error":  q5DirExOut["error"],
				"ok":     q5DirExResp.StatusCode == http.StatusBadRequest && q5DirExOut["error"] == "invalid_resource_token",
			},
			"fed_ps_go_as_proposal_rt_refusal": map[string]any{
				"ps_status": q5FedExResp.StatusCode,
				"ps_error":  q5FedExOut["error"],
				"as_status": q5ASDirectResp.StatusCode,
				"as_error":  q5ASDirectOut["error"],
				"ok":        q5FedExResp.StatusCode == http.StatusInternalServerError && q5FedExOut["error"] == "server_error" && q5ASDirectResp.StatusCode == http.StatusInternalServerError && q5ASDirectOut["error"] == "server_error",
			},
		},
	}
}
