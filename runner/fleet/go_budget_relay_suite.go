package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
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
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type tSuiteInput struct {
	GoModDir               string `json:"go_mod_dir"`
	T4RustASIssuer         string `json:"t4_rust_as_issuer"`
	T4RustResIssuer        string `json:"t4_rust_res_issuer"`
	T4RustFedPSIssuer      string `json:"t4_rust_fed_ps_issuer"`
	T4RustHeldResIssuer    string `json:"t4_rust_held_res_issuer"`
	T4RustHeldDirectIssuer string `json:"t4_rust_held_direct_issuer"`
	T4RustIntermAgID       string `json:"t4_rust_interm_ag_id"`
}

func tDeferredRef(loc string) string {
	idx := strings.LastIndex(loc, "/")
	if idx < 0 {
		return loc
	}
	return loc[idx+1:]
}

func tValidInteractionCodeFormat(code string) bool {
	if len(code) != 9 || code[4] != '-' {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < 9; i++ {
		if i == 4 {
			continue
		}
		if !strings.ContainsRune(alphabet, rune(code[i])) {
			return false
		}
	}
	return aauth.MatchInteractionCode(code, code)
}

func runTSuite(
	ctx context.Context,
	baseClock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in tSuiteInput,
) map[string]any {
	ctx = context.Background()
	var tClockMu sync.Mutex
	tClockNow := baseClock.Now()
	clock := aauth.ClockFunc(func() time.Time {
		tClockMu.Lock()
		defer tClockMu.Unlock()
		return tClockNow
	})
	tAdvance := func(d time.Duration) {
		tClockMu.Lock()
		tClockNow = tClockNow.Add(d)
		tClockMu.Unlock()
	}

	if baseTr, ok := httpClient.Transport.(*http.Transport); ok {
		tr := baseTr.Clone()
		tr.DisableKeepAlives = false
		cCopy := *httpClient
		cCopy.Transport = tr
		httpClient = &cCopy
	}

	newTKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var tIDSeq atomic.Int64
	nextTID := func() string {
		return "t-go-id-0123456789abcdef-" + strconvItoa(tIDSeq.Add(1))
	}

	tResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver tResolver")

	// =========================================================================
	// QA-T1: All-Go Access Server Interaction Relayed to the Agent Over HTTPS
	// =========================================================================
	t1ASStoreCmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", "TestAccessAuthorizationStore", "./testutil/...")
	t1ASStoreCmd.Dir = in.GoModDir
	_, t1ASStoreErr := t1ASStoreCmd.CombinedOutput()
	t1ASStoreOK := t1ASStoreErr == nil
	t1PSStoreCmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", "TestFederatedAuthorizationStore", "./testutil/...")
	t1PSStoreCmd.Dir = in.GoModDir
	_, t1PSStoreErr := t1PSStoreCmd.CombinedOutput()
	t1PSStoreOK := t1PSStoreErr == nil

	const (
		t1APIssuer     = "https://t1-ap.example"
		t1AgID         = "aauth:caller@t1-ap.example"
		t1IntermIssuer = "https://t1-interm.example"
		t1IntermAgID   = "aauth:relay@t1-interm.example"
		t1PSIssuer     = "https://t1-ps.example"
		t1ASIssuer     = "https://t1-as.example"
		t1ResIssuer    = "https://t1-res.example"
	)
	t1APKey := newTKey("t1-ap-1", 0xd1)
	t1AgKey := newTKey("t1-ag-1", 0xd2)
	t1IntermAPKey := newTKey("t1-interm-ap-1", 0xd3)
	t1IntermAgKey := newTKey("t1-interm-ag-1", 0xd4)
	t1PSKey := newTKey("t1-ps-1", 0xd5)
	t1ASKey := newTKey("t1-as-1", 0xd6)
	t1ResKey := newTKey("t1-res-1", 0xd7)

	t1AP, err := agentprovider.New(agentprovider.Config{
		Issuer: t1APIssuer, SigningKey: t1APKey, Clock: clock, NewID: nextTID,
	})
	must(err, "t1AP")
	_, _ = registerTLS("t1-ap.example", t1AP.Handler())
	t1AgTok, err := t1AP.Issue(aauth.AgentTokenRequest{
		Agent: t1AgID, PersonServer: t1PSIssuer, PublicKey: t1AgKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t1AgTok")

	var (
		t1ASStage         atomic.Int32
		t1ASDeletes       atomic.Int32
		t1ASPolls         atomic.Int32
		t1ASMalformedCode atomic.Bool
		t1ASCodeMu        sync.Mutex
		t1ASSeenCodes     []string
	)
	t1ASStore := testutil.NewAccessAuthorizationStore()
	t1ASIssued := testutil.NewAccessIssuedAuthTokenStore()
	t1PSFedStore := testutil.NewFederatedAuthorizationStore()

	t1AS, err := accessserver.New(accessserver.Config{
		Issuer: t1ASIssuer, SigningKey: t1ASKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == t1PSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Deferred:   &accessserver.DeferredConfig{Store: t1ASStore, Lifetime: 10 * time.Minute},
		Revocation: &accessserver.RevocationConfig{Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: t1ASIssued, HTTPClient: httpClient, Admit: func(context.Context, string) error { return nil }},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			t1ASCodeMu.Lock()
			if req.InteractionCode != "" {
				t1ASSeenCodes = append(t1ASSeenCodes, req.InteractionCode)
			}
			t1ASCodeMu.Unlock()
			switch t1ASStage.Load() {
			case 1:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{RetryAfter: time.Second}}, nil
			case 2:
				return accessserver.Decision{Pending: &accessserver.PendingDecision{
					RetryAfter:     time.Second,
					InteractionURL: t1ASIssuer + "/consent",
				}}, nil
			default:
				return accessserver.Decision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
			}
		},
	})
	must(err, "t1AS")
	_, _ = registerTLS("t1-as.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/token/pending/") {
			t1ASDeletes.Add(1)
		}
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/token/pending/") {
			t1ASPolls.Add(1)
		}
		if t1ASMalformedCode.Load() && r.Method == http.MethodPost && r.URL.Path == "/token" {
			w.Header().Set("Location", t1ASIssuer+"/token/pending/bad-code-1")
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("AAuth-Requirement", `requirement=interaction; url="`+t1ASIssuer+`/consent"; code="abcd-efgh"`)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		t1AS.Handler().ServeHTTP(w, r)
	}))

	t1MissExp := clock.Now().Add(30 * time.Minute)
	t1MissStore := testutil.NewMissionStore()
	t1PS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: t1PSIssuer, SigningKey: t1PSKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		HTTPClient: httpClient, Tokens: t1MissStore, IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(_ context.Context, asIss string) (string, error) { return asIss + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-t1", Lifetime: 30 * time.Minute}, nil
		},
		Consent:  func(context.Context, personserver.AuthorizationRequest) error { return nil },
		Deferred: &personserver.FederatedDeferredConfig{Store: t1PSFedStore, Lifetime: 10 * time.Minute},
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-t1-chained", Lifetime: 30 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(),
			HTTPClient:  httpClient, Admit: func(context.Context, string) error { return nil },
		},
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, req personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{
					Description:       req.Proposal.Description,
					ApprovedResources: req.Proposal.Resources,
					ExpiresAt:         &t1MissExp,
					Capabilities:      []string{"interaction"},
				}, nil
			},
		},
	})
	must(err, "t1PS")
	_, _ = registerTLS("t1-ps.example", t1PS.Handler())

	t1Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: t1ResIssuer, AccessServer: t1ASIssuer, SigningKey: t1ResKey, KeyResolver: tResolver,
		Clock: clock, NewID: nextTID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		}),
	})
	must(err, "t1Res")
	_, _ = registerTLS("t1-res.example", t1Res.Handler())

	t1IntermRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: t1IntermIssuer, AccessServer: t1ASIssuer, SigningKey: t1IntermAPKey, KeyResolver: tResolver,
		Clock: clock, NewID: nextTID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	must(err, "t1IntermRes")
	t1IntermTok, err := aauth.MintAgentToken(t1IntermIssuer, t1IntermAPKey, aauth.AgentTokenRequest{
		Agent: t1IntermAgID, PersonServer: "https://t1-interm-own-ps.example", PublicKey: t1IntermAgKey.PublicJWK(), Lifetime: time.Hour,
	}, clock.Now(), nextTID())
	must(err, "t1IntermTok")
	t1IntermMux := http.NewServeMux()
	t1IntermMux.HandleFunc("GET /.well-known/aauth-agent.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"issuer":"`+t1IntermIssuer+`","jwks_uri":"`+t1IntermIssuer+`/.well-known/jwks.json"}`)
	})
	t1IntermMux.Handle("/", t1IntermRes.Handler())
	_, _ = registerTLS("t1-interm.example", t1IntermMux)

	t1Caller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t1AgID, SigningKey: t1AgKey, AgentToken: t1AgTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t1Caller")
	t1Relay, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t1IntermAgID, SigningKey: t1IntermAgKey, AgentToken: t1IntermTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t1Relay")

	// Flow 1a: Top-level 4-party initial 202 requirement=interaction + code immutability across polls
	t1PTRes, err := t1Caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: t1PSIssuer, Resource: t1ResIssuer})
	must(err, "t1PTRes")
	t1PT, _ := t1PTRes.Token()
	t1RT1, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1PT, Scopes: []string{"records.read"}})
	must(err, "t1RT1")

	t1ASStage.Store(2)
	t1ASCodeMu.Lock()
	t1ASSeenCodes = nil
	t1ASCodeMu.Unlock()
	t1Begun1, err := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1RT1, PresentedToken: t1PT, Capabilities: []string{"interaction"},
	})
	must(err, "t1Begun1")
	t1Wait1, t1Wait1OK := t1Begun1.Pending()
	t1Ref1 := tDeferredRef(t1Wait1.Location())
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, t1Ref1), "t1PS.AdvanceFederation 1a poll 1")
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, t1Ref1), "t1PS.AdvanceFederation 1a poll 2")
	t1MidPoll1, err := t1Caller.PollExchange(ctx, t1Wait1)
	must(err, "t1MidPoll1")
	t1Wait1Mid, t1Wait1MidOK := t1MidPoll1.Pending()
	t1ASCodeMu.Lock()
	t1Codes1a := append([]string(nil), t1ASSeenCodes...)
	t1ASCodeMu.Unlock()
	t1Code1a := t1Wait1.InteractionCode()
	t1CodeImmutOK := len(t1Codes1a) == 3 && t1Codes1a[0] == t1Code1a && t1Codes1a[1] == t1Code1a && t1Codes1a[2] == t1Code1a &&
		t1Wait1MidOK && t1Wait1Mid.InteractionCode() == t1Code1a && tValidInteractionCodeFormat(t1Code1a) &&
		aauth.MatchInteractionCode(t1Code1a, strings.ToLower(strings.ReplaceAll(t1Code1a, "-", "")))
	t1ASStage.Store(0)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, t1Ref1), "t1PS.AdvanceFederation 1a finish")
	t1Fin1, err := t1Caller.PollExchange(ctx, t1Wait1Mid)
	must(err, "t1Fin1")
	t1AT1, t1AT1OK := t1Fin1.Token()
	t1Call1Req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t1ResIssuer+"/data", nil)
	t1Call1Resp, err := t1Caller.Do(ctx, clientagent.Call{Request: t1Call1Req, AuthToken: t1AT1})
	must(err, "t1Call1Resp")
	_ = t1Call1Resp.Body.Close()
	t1Flow1aOK := t1Wait1OK && strings.HasPrefix(t1Wait1.Location(), t1PSIssuer+"/token/federated/") &&
		t1Wait1.Requirement() == aauth.RequirementInteraction && t1Wait1.InteractionURL() == t1ASIssuer+"/consent" &&
		t1CodeImmutOK && t1AT1OK && t1Call1Resp.StatusCode == http.StatusOK

	// Flow 1b: Approval -> AdvanceFederation -> Interaction -> Approve -> AdvanceFederation -> 200 OK
	t1RT2, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1PT, Scopes: []string{"records.read"}})
	must(err, "t1RT2")
	t1ASStage.Store(1)
	t1Begun2, err := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1RT2, PresentedToken: t1PT, Capabilities: []string{"interaction"},
	})
	must(err, "t1Begun2")
	t1Wait2, _ := t1Begun2.Pending()
	t1InitApprovalOK := t1Wait2.Requirement() == aauth.RequirementApproval && t1Wait2.InteractionURL() == "" && t1Wait2.InteractionCode() == ""
	t1ASStage.Store(2)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, tDeferredRef(t1Wait2.Location())), "t1PS.AdvanceFederation 1b to int")
	t1Mid2, err := t1Caller.PollExchange(ctx, t1Wait2)
	must(err, "t1Mid2")
	t1Wait2Int, _ := t1Mid2.Pending()
	t1MidIntOK := t1Wait2Int.Requirement() == aauth.RequirementInteraction &&
		t1Wait2Int.InteractionURL() == t1ASIssuer+"/consent" && tValidInteractionCodeFormat(t1Wait2Int.InteractionCode())
	t1ASStage.Store(0)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, tDeferredRef(t1Wait2Int.Location())), "t1PS.AdvanceFederation 1b finish")
	t1Fin2, err := t1Caller.PollExchange(ctx, t1Wait2Int)
	must(err, "t1Fin2")
	_, t1AT2OK := t1Fin2.Token()
	t1Flow1bOK := t1InitApprovalOK && t1MidIntOK && t1AT2OK

	// Flow 1c: Chained 4-party (UpstreamToken) AS interaction relay
	t1IntermPTRes, err := t1Caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: t1PSIssuer, Resource: t1IntermIssuer})
	must(err, "t1IntermPTRes")
	t1IntermPT, _ := t1IntermPTRes.Token()
	t1IntermRT, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1IntermIssuer, PersonToken: t1IntermPT, Scopes: []string{"records.read"}})
	must(err, "t1IntermRT")
	t1ASStage.Store(0)
	t1CallerIntermAT, err := t1Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1IntermRT, PresentedToken: t1IntermPT,
	})
	must(err, "t1CallerIntermAT")
	t1ChainPTRes, err := t1Relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: t1ResIssuer, UpstreamToken: t1CallerIntermAT})
	must(err, "t1ChainPTRes")
	t1ChainPT, _ := t1ChainPTRes.Token()
	t1ChainRT, err := t1Relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t1ResIssuer, PersonToken: t1ChainPT, UpstreamToken: t1CallerIntermAT, Scopes: []string{"records.read"},
	})
	must(err, "t1ChainRT")
	t1ASStage.Store(2)
	t1ChainBegun, err := t1Relay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t1ChainRT, PresentedToken: t1ChainPT, UpstreamToken: t1CallerIntermAT, Capabilities: []string{"interaction"},
	})
	must(err, "t1ChainBegun")
	t1ChainWait, t1ChainWaitOK := t1ChainBegun.Pending()
	t1ASStage.Store(0)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, tDeferredRef(t1ChainWait.Location())), "t1PS.AdvanceFederation 1c")
	t1ChainFin, err := t1Relay.PollExchange(ctx, t1ChainWait)
	must(err, "t1ChainFin")
	t1ChainAT, t1ChainATOK := t1ChainFin.Token()
	t1ChainCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t1ResIssuer+"/data", nil)
	t1ChainCallResp, err := t1Relay.Do(ctx, clientagent.Call{Request: t1ChainCallReq, AuthToken: t1ChainAT, UpstreamToken: t1CallerIntermAT})
	must(err, "t1ChainCallResp")
	_ = t1ChainCallResp.Body.Close()
	t1Flow1cOK := t1ChainWaitOK && t1ChainWait.Requirement() == aauth.RequirementInteraction &&
		t1ChainWait.InteractionURL() == t1ASIssuer+"/consent" && tValidInteractionCodeFormat(t1ChainWait.InteractionCode()) &&
		t1ChainATOK && t1ChainCallResp.StatusCode == http.StatusOK

	// Flow 1d: 403 user_unreachable (initial + poll advance) with 1 signed DELETE withdrawal + mission capability inheritance
	t1ASDeletes.Store(0)
	t1RTNoCap1, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1PT, Scopes: []string{"records.read"}})
	must(err, "t1RTNoCap1")
	t1ASStage.Store(2)
	_, t1NoCapInitErr := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1RTNoCap1, PresentedToken: t1PT,
	})
	var t1NoCapProb1 *aauth.ProblemError
	t1NoCapInit403OK := errors.As(t1NoCapInitErr, &t1NoCapProb1) && t1NoCapProb1.Status == http.StatusForbidden &&
		t1NoCapProb1.Code == "user_unreachable" && t1ASDeletes.Load() == 1

	t1ASDeletes.Store(0)
	t1RTNoCap2, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1PT, Scopes: []string{"records.read"}})
	must(err, "t1RTNoCap2")
	t1ASStage.Store(1)
	t1NoCapPollBegun, err := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1RTNoCap2, PresentedToken: t1PT,
	})
	must(err, "t1NoCapPollBegun")
	t1NoCapWait, _ := t1NoCapPollBegun.Pending()
	t1ASStage.Store(2)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, tDeferredRef(t1NoCapWait.Location())), "t1PS.AdvanceFederation 1d poll")
	_, t1NoCapPollErr := t1Caller.PollExchange(ctx, t1NoCapWait)
	var t1NoCapProb2 *aauth.ProblemError
	t1NoCapPoll403OK := errors.As(t1NoCapPollErr, &t1NoCapProb2) && t1NoCapProb2.Status == http.StatusForbidden &&
		t1NoCapProb2.Code == "user_unreachable" && t1ASDeletes.Load() == 1

	// Mission-bound request omitting Capabilities inherits mission's Capabilities: ["interaction"]
	t1MissRes, err := t1Caller.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: t1PSIssuer,
		Proposal:     aauth.MissionProposal{Description: "# QA-T1 Mission", Resources: []string{t1ResIssuer}},
	})
	must(err, "t1MissRes")
	t1MissPT, ok := t1MissRes.PersonToken(t1ResIssuer)
	if !ok {
		panic("t1MissPT missing")
	}
	t1MissRT, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1MissPT, Scopes: []string{"records.read"}})
	must(err, "t1MissRT")
	t1ASDeletes.Store(0)
	t1ASStage.Store(2)
	t1MissBegun, err := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1MissRT, PresentedToken: t1MissPT,
	})
	must(err, "t1MissBegun")
	t1MissWait, t1MissWaitOK := t1MissBegun.Pending()
	t1ASStage.Store(0)
	tAdvance(2 * time.Second)
	must(t1PS.AdvanceFederation(ctx, tDeferredRef(t1MissWait.Location())), "t1PS.AdvanceFederation 1d mission")
	t1MissFin, err := t1Caller.PollExchange(ctx, t1MissWait)
	must(err, "t1MissFin")
	_, t1MissATOK := t1MissFin.Token()
	t1MissionInheritOK := t1MissWaitOK && t1MissWait.Requirement() == aauth.RequirementInteraction && t1MissATOK && t1ASDeletes.Load() == 0

	// Flow 1e: Malformed AS interaction requirement (lowercase code) -> 502 as_unreachable
	t1RTMalformed, err := t1Caller.Authorize(ctx, clientagent.AuthorizeRequest{Resource: t1ResIssuer, PersonToken: t1PT, Scopes: []string{"records.read"}})
	must(err, "t1RTMalformed")
	t1ASMalformedCode.Store(true)
	_, t1MalformedErr := t1Caller.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t1PSIssuer, ResourceToken: t1RTMalformed, PresentedToken: t1PT, Capabilities: []string{"interaction"},
	})
	t1ASMalformedCode.Store(false)
	var t1MalformedProb *aauth.ProblemError
	t1Malformed502OK := errors.As(t1MalformedErr, &t1MalformedProb) && t1MalformedProb.Status == http.StatusBadGateway &&
		t1MalformedProb.Code == "as_unreachable"

	// =========================================================================
	// QA-T2: All-Go Four-Party Chained Budget Over Real HTTPS (3-Hop Chain)
	// =========================================================================
	tClockMu.Lock()
	tClockNow = baseClock.Now()
	tClockMu.Unlock()
	const (
		t2APIssuer   = "https://t2-ap.example"
		t2CallerID   = "aauth:caller@t2-ap.example"
		t2Hop1Issuer = "https://t2-hop1.example"
		t2Hop1AgID   = "aauth:relay1@t2-hop1.example"
		t2Hop2Issuer = "https://t2-hop2.example"
		t2Hop2AgID   = "aauth:relay2@t2-hop2.example"
		t2Hop3Issuer = "https://t2-hop3.example"
		t2PSIssuer   = "https://t2-ps.example"
		t2AS1Issuer  = "https://t2-as1.example"
		t2AS2Issuer  = "https://t2-as2.example"
		t2AS3Issuer  = "https://t2-as3.example"
	)
	t2APKey := newTKey("t2-ap-1", 0xd8)
	t2CallerKey := newTKey("t2-caller-1", 0xd9)
	t2Hop1Key := newTKey("t2-hop1-1", 0xda)
	t2Hop1AgKey := newTKey("t2-hop1-ag-1", 0xdb)
	t2Hop2Key := newTKey("t2-hop2-1", 0xdc)
	t2Hop2AgKey := newTKey("t2-hop2-ag-1", 0xdd)
	t2Hop3Key := newTKey("t2-hop3-1", 0xde)
	t2PSKey := newTKey("t2-ps-1", 0xdf)
	t2AS1Key := newTKey("t2-as1-1", 0xe0)
	t2AS2Key := newTKey("t2-as2-1", 0xe1)
	t2AS3Key := newTKey("t2-as3-1", 0xe2)

	t2Unit, err := budgets.NewUnit("credits", 0)
	must(err, "t2Unit")
	t2UnitDecl, err := budgets.NewBoundedUnitDeclaration(t2Unit, 1000, "Credits")
	must(err, "t2UnitDecl")
	t2Units := []budgets.UnitDeclaration{t2UnitDecl}
	t2Val := func(amount int64) budgets.Value {
		v, vErr := budgets.NewValue(amount, t2Unit)
		must(vErr, "t2Val")
		return v
	}

	t2AP, err := agentprovider.New(agentprovider.Config{
		Issuer: t2APIssuer, SigningKey: t2APKey, Clock: clock, NewID: nextTID,
	})
	must(err, "t2AP")
	_, _ = registerTLS("t2-ap.example", t2AP.Handler())
	t2CallerTok, err := t2AP.Issue(aauth.AgentTokenRequest{
		Agent: t2CallerID, PersonServer: t2PSIssuer, PublicKey: t2CallerKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t2CallerTok")

	var (
		t2Mu          sync.Mutex
		t2PSCeilings  []personserver.AuthorizationRequest
		t2ASRequests  = map[string][]accessserver.AuthorizationRequest{}
		t2ASOverGrant atomic.Bool
	)
	makeT2AS := func(issuer, host string, key jose.SigningKey, grantAmt int64) {
		as, asErr := accessserver.New(accessserver.Config{
			Issuer: issuer, SigningKey: key, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
			TrustPersonServer: func(_ context.Context, iss string) error {
				if iss == t2PSIssuer {
					return nil
				}
				return accessserver.ErrAccessDenied
			},
			Budget: &accessserver.BudgetConfig{
				ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
			},
			Revocation: &accessserver.RevocationConfig{
				Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
				HTTPClient: httpClient, Admit: func(context.Context, string) error { return nil },
			},
			Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
				t2Mu.Lock()
				t2ASRequests[issuer] = append(t2ASRequests[issuer], req)
				t2Mu.Unlock()
				if req.Budget == nil {
					return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
				}
				g := t2Val(grantAmt)
				return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Budget: &g}, nil
			},
		})
		must(asErr, "makeT2AS "+issuer)
		_, _ = registerTLS(host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if t2ASOverGrant.Load() && r.Method == http.MethodPost && r.URL.Path == "/token" {
				// Mint a budget auth token exceeding PS ceiling (350 > 300)
				var raw map[string]any
				_ = json.NewDecoder(r.Body).Decode(&raw)
				rtStr, _ := raw["resource_token"].(string)
				rtClaims, _, _, _ := budgets.VerifyResourceToken(r.Context(), rtStr, tResolver, clock)
				over := t2Val(350)
				badAT, _ := budgets.MintAuthToken(key, aauth.AuthTokenClaims{
					Issuer: issuer, DWK: aauth.AccessDiscoveryDocument, Audience: rtClaims.Issuer, JTI: nextTID(),
					PersonServer: rtClaims.PersonServer, Subject: rtClaims.Subject, Tenant: rtClaims.Tenant,
					Scope: "work.run", Confirmation: aauth.Confirmation{JWK: t2Hop1AgKey.PublicJWK()},
					IssuedAt: clock.Now().Unix(), ExpiresAt: clock.Now().Add(10 * time.Minute).Unix(),
				}, over)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = io.WriteString(w, `{"auth_token":"`+badAT+`"}`)
				return
			}
			as.Handler().ServeHTTP(w, r)
		}))
	}
	makeT2AS(t2AS1Issuer, "t2-as1.example", t2AS1Key, 250)
	makeT2AS(t2AS2Issuer, "t2-as2.example", t2AS2Key, 200)
	makeT2AS(t2AS3Issuer, "t2-as3.example", t2AS3Key, 150)

	makeT2Hop := func(issuer, host, asIssuer string, key jose.SigningKey, isInterm bool, defaultCost int64) {
		res, rErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: issuer, AccessServer: asIssuer, SigningKey: key, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
			ScopeDescriptions: map[string]string{"work.run": "Run work"},
			RequiredScopes:    func(*http.Request) []string { return []string{"work.run"} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Budget: &resource.BudgetConfig{
				Units:         t2Units,
				Offer:         func(_ context.Context, req resource.BudgetOfferRequest) (budgets.Value, error) { return req.Requested, nil },
				RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
				Cost: func(_ context.Context, req resource.BudgetCostRequest) (int64, error) {
					if req.Request.URL.Path == "/expensive" {
						return 100, nil
					}
					return defaultCost, nil
				},
				Store: testutil.NewBudgetStore(),
				Challenge: func(_ context.Context, req resource.BudgetChallengeRequest) (string, error) {
					jkt, _ := req.Principal.Confirmation.Thumbprint()
					rec, _ := budgets.NewConsumptionRecord(req.Token.JTI, req.Consumed)
					return budgets.MintResourceToken(key, aauth.ResourceTokenClaims{
						Issuer: issuer, DWK: aauth.ResourceDiscoveryDocument, Audience: asIssuer, JTI: nextTID(),
						PersonServer: req.Principal.PersonServer, Subject: req.Principal.Subject,
						PresentedJTI: req.Token.JTI, AgentJKT: jkt,
						IssuedAt: clock.Now().Unix(), ExpiresAt: clock.Now().Add(5 * time.Minute).Unix(),
						Scope: strings.Join(req.Principal.Scope, " "), Tenant: req.Principal.Tenant,
					}, t2Val(500), &rec)
				},
			},
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, _ := resource.AuthPrincipalFromContext(r.Context())
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"hop":"`+issuer+`","sub":"`+p.Subject+`"}`)
			}),
		})
		must(rErr, "makeT2Hop "+issuer)
		resCore, rcErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: issuer, AccessServer: asIssuer, SigningKey: key, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
			ScopeDescriptions: map[string]string{"work.run": "Run work"},
			RequiredScopes:    func(*http.Request) []string { return []string{"work.run"} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, _ := resource.AuthPrincipalFromContext(r.Context())
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"hop":"`+issuer+`","sub":"`+p.Subject+`"}`)
			}),
		})
		must(rcErr, "makeT2HopCore "+issuer)
		mux := http.NewServeMux()
		if isInterm {
			mux.HandleFunc("GET /.well-known/aauth-agent.json", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"issuer":"`+issuer+`","jwks_uri":"`+issuer+`/.well-known/jwks.json"}`)
			})
		}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/authorize" && r.Method == http.MethodPost {
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				if !bytes.Contains(bodyBytes, []byte(`"budget"`)) {
					resCore.Handler().ServeHTTP(w, r)
					return
				}
			}
			res.Handler().ServeHTTP(w, r)
		})
		_, _ = registerTLS(host, mux)
	}
	makeT2Hop(t2Hop1Issuer, "t2-hop1.example", t2AS1Issuer, t2Hop1Key, true, 25)
	makeT2Hop(t2Hop2Issuer, "t2-hop2.example", t2AS2Issuer, t2Hop2Key, true, 40)
	makeT2Hop(t2Hop3Issuer, "t2-hop3.example", t2AS3Issuer, t2Hop3Key, false, 60)

	t2PS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: t2PSIssuer, SigningKey: t2PSKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		HTTPClient: httpClient, Tokens: testutil.NewMissionStore(), IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(_ context.Context, asIss string) (string, error) { return asIss + "/token", nil },
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-t2-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: 30 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "chained-t2-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: 30 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
			Ceiling: func(_ context.Context, req personserver.AuthorizationRequest) (*budgets.Value, error) {
				t2Mu.Lock()
				t2PSCeilings = append(t2PSCeilings, req)
				t2Mu.Unlock()
				c := t2Val(300)
				return &c, nil
			},
		},
	})
	must(err, "t2PS")
	_, _ = registerTLS("t2-ps.example", t2PS.Handler())

	t2Caller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t2CallerID, SigningKey: t2CallerKey, AgentToken: t2CallerTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t2Caller")
	t2Hop1Tok, err := aauth.MintAgentToken(t2Hop1Issuer, t2Hop1Key, aauth.AgentTokenRequest{
		Agent: t2Hop1AgID, PersonServer: "https://t2-hop1-own-ps.example", PublicKey: t2Hop1AgKey.PublicJWK(), Lifetime: time.Hour,
	}, clock.Now(), nextTID())
	must(err, "t2Hop1Tok")
	t2Hop1Relay, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t2Hop1AgID, SigningKey: t2Hop1AgKey, AgentToken: t2Hop1Tok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t2Hop1Relay")
	t2Hop2Tok, err := aauth.MintAgentToken(t2Hop2Issuer, t2Hop2Key, aauth.AgentTokenRequest{
		Agent: t2Hop2AgID, PersonServer: "https://t2-hop2-own-ps.example", PublicKey: t2Hop2AgKey.PublicJWK(), Lifetime: time.Hour,
	}, clock.Now(), nextTID())
	must(err, "t2Hop2Tok")
	t2Hop2Relay, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t2Hop2AgID, SigningKey: t2Hop2AgKey, AgentToken: t2Hop2Tok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t2Hop2Relay")

	t2Offer500 := t2Val(500)
	// Hop 1 (Caller -> Hop 1): obtain both a budgeted AuthToken (t2AT1) and an unbudgeted Core AuthToken (t2UpAT1) for chaining
	t2PT1Res, err := t2Caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: t2PSIssuer, Resource: t2Hop1Issuer})
	must(err, "t2PT1Res")
	t2PT1, _ := t2PT1Res.Token()
	t2RT1, err := t2Caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop1Issuer, PersonToken: t2PT1, Scopes: []string{"work.run"}, Budget: &t2Offer500,
	})
	must(err, "t2RT1")
	t2AT1, err := t2Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t2PSIssuer, ResourceToken: t2RT1, PresentedToken: t2PT1,
	})
	must(err, "t2AT1")
	t2RT1Core, err := t2Caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop1Issuer, PersonToken: t2PT1, Scopes: []string{"work.run"},
	})
	must(err, "t2RT1Core")
	t2UpAT1, err := t2Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t2PSIssuer, ResourceToken: t2RT1Core, PresentedToken: t2PT1,
	})
	must(err, "t2UpAT1")
	// Verify that passing a budgeted AuthToken (t2AT1) as UpstreamToken is refused per INTERPRETATIONS.md:2229
	_, t2BudgetedUpErr := t2Hop1Relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: t2Hop2Issuer, UpstreamToken: t2AT1})
	t2BudgetedUpstreamRefusedOK := t2BudgetedUpErr != nil && strings.Contains(t2BudgetedUpErr.Error(), "unsupported budget claim")

	t2Req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop1Issuer+"/work", nil)
	t2Call1, err := t2Caller.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: t2Req1, AuthToken: t2AT1})
	must(err, "t2Call1")
	t2Resp1, t2Resp1OK := t2Call1.Response()
	if t2Resp1OK {
		_ = t2Resp1.Body.Close()
	}
	t2Cost1, _ := t2Call1.Cost()
	t2FB1, _ := t2Call1.Feedback()
	t2Rem1 := t2FB1.Remaining()

	// Hop 2 (Hop 1 Intermediary -> Hop 2 with UpstreamToken: t2UpAT1)
	t2PT2Res, err := t2Hop1Relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: t2Hop2Issuer, UpstreamToken: t2UpAT1})
	must(err, "t2PT2Res")
	t2PT2, _ := t2PT2Res.Token()
	t2RT2, err := t2Hop1Relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop2Issuer, PersonToken: t2PT2, UpstreamToken: t2UpAT1, Scopes: []string{"work.run"}, Budget: &t2Offer500,
	})
	must(err, "t2RT2")
	t2AT2, err := t2Hop1Relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t2RT2, PresentedToken: t2PT2, UpstreamToken: t2UpAT1,
	})
	must(err, "t2AT2")
	t2RT2Core, err := t2Hop1Relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop2Issuer, PersonToken: t2PT2, UpstreamToken: t2UpAT1, Scopes: []string{"work.run"},
	})
	must(err, "t2RT2Core")
	t2UpAT2, err := t2Hop1Relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t2RT2Core, PresentedToken: t2PT2, UpstreamToken: t2UpAT1,
	})
	must(err, "t2UpAT2")
	t2Req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop2Issuer+"/work", nil)
	t2Call2, err := t2Hop1Relay.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: t2Req2, AuthToken: t2AT2, UpstreamToken: t2UpAT1,
	})
	must(err, "t2Call2")
	t2Resp2, t2Resp2OK := t2Call2.Response()
	if t2Resp2OK {
		_ = t2Resp2.Body.Close()
	}
	t2Cost2, _ := t2Call2.Cost()
	t2FB2, _ := t2Call2.Feedback()
	t2Rem2 := t2FB2.Remaining()

	// Hop 3 (Hop 2 Intermediary -> Hop 3 with UpstreamToken: t2UpAT2)
	t2PT3Res, err := t2Hop2Relay.PersonToken(ctx, clientagent.PersonTokenRequest{Resource: t2Hop3Issuer, UpstreamToken: t2UpAT2})
	must(err, "t2PT3Res")
	t2PT3, _ := t2PT3Res.Token()
	t2RT3, err := t2Hop2Relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop3Issuer, PersonToken: t2PT3, UpstreamToken: t2UpAT2, Scopes: []string{"work.run"}, Budget: &t2Offer500,
	})
	must(err, "t2RT3")
	t2AT3, err := t2Hop2Relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t2RT3, PresentedToken: t2PT3, UpstreamToken: t2UpAT2,
	})
	must(err, "t2AT3")
	t2Req3, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop3Issuer+"/work", nil)
	t2Call3, err := t2Hop2Relay.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: t2Req3, AuthToken: t2AT3, UpstreamToken: t2UpAT2,
	})
	must(err, "t2Call3")
	t2Resp3, t2Resp3OK := t2Call3.Response()
	if t2Resp3OK {
		_ = t2Resp3.Body.Close()
	}
	t2Cost3, _ := t2Call3.Cost()
	t2FB3, _ := t2Call3.Feedback()
	t2Rem3 := t2FB3.Remaining()

	// Verify nothing was drawn from upstream budgeted tokens t2AT1 and t2AT2
	t2Req1b, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop1Issuer+"/work", nil)
	t2Call1b, err := t2Caller.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: t2Req1b, AuthToken: t2AT1})
	must(err, "t2Call1b")
	if r, ok := t2Call1b.Response(); ok {
		_ = r.Body.Close()
	}
	t2FB1b, _ := t2Call1b.Feedback()
	t2Rem1b := t2FB1b.Remaining() // 250 - 25 - 25 = 200 (not affected by Hop 2's 40 or Hop 3's 60)

	t2Req2b, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop2Issuer+"/work", nil)
	t2Call2b, err := t2Hop1Relay.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: t2Req2b, AuthToken: t2AT2, UpstreamToken: t2UpAT1})
	must(err, "t2Call2b")
	if r, ok := t2Call2b.Response(); ok {
		_ = r.Body.Close()
	}
	t2FB2b, _ := t2Call2b.Feedback()
	t2Rem2b := t2FB2b.Remaining() // 200 - 40 - 40 = 120 (not affected by Hop 3's 60)

	// Verify Hop 3 over-budget call (cost=100 > remaining=90) triggers 401 step-up with AAuth-Budget remaining=90
	t2Req3Over, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop3Issuer+"/expensive", nil)
	t2OverCall, err := t2Hop2Relay.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: t2Req3Over, AuthToken: t2AT3, UpstreamToken: t2UpAT2})
	must(err, "t2OverCall")
	_, t2OverStepUpOK := t2OverCall.AuthorizationRequired()
	t2OverFB, t2OverFBOK := t2OverCall.Feedback()
	t2Hop3OverRefusedOK := t2OverStepUpOK && t2OverFBOK && t2OverFB.Remaining() == 90

	// Negative checks: UpstreamToken without AuthToken + AS grant exceeding PS ceiling (350 > 300)
	t2ReqNoAT, _ := http.NewRequestWithContext(ctx, http.MethodPost, t2Hop2Issuer+"/work", nil)
	_, t2NoATErr := t2Hop1Relay.BeginBudgetCall(ctx, clientagent.BudgetCall{Request: t2ReqNoAT, UpstreamToken: t2UpAT1})
	t2NoATGuardOK := t2NoATErr != nil && strings.Contains(t2NoATErr.Error(), "auth token is required")

	t2RTOver, err := t2Hop1Relay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t2Hop2Issuer, PersonToken: t2PT2, UpstreamToken: t2UpAT1, Scopes: []string{"work.run"}, Budget: &t2Offer500,
	})
	must(err, "t2RTOver")
	t2ASOverGrant.Store(true)
	_, t2ASOverErr := t2Hop1Relay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t2RTOver, PresentedToken: t2PT2, UpstreamToken: t2UpAT1,
	})
	t2ASOverGrant.Store(false)
	var t2ASOverProb *aauth.ProblemError
	t2ASOver502OK := errors.As(t2ASOverErr, &t2ASOverProb) && t2ASOverProb.Status == http.StatusBadGateway &&
		t2ASOverProb.Code == "as_unreachable"

	t2Mu.Lock()
	t2CeilingChecksOK := t2BudgetedUpstreamRefusedOK && len(t2PSCeilings) >= 3 &&
		t2PSCeilings[1].Upstream != nil && t2PSCeilings[1].Budget != nil && t2PSCeilings[1].Budget.Amount() == 500 &&
		t2PSCeilings[2].Upstream != nil && t2PSCeilings[2].Budget != nil && t2PSCeilings[2].Budget.Amount() == 500 &&
		len(t2ASRequests[t2AS2Issuer]) >= 1 && t2ASRequests[t2AS2Issuer][0].Upstream != nil &&
		t2ASRequests[t2AS2Issuer][0].Budget != nil && t2ASRequests[t2AS2Issuer][0].Budget.Amount() == 300 &&
		len(t2ASRequests[t2AS3Issuer]) >= 1 && t2ASRequests[t2AS3Issuer][0].Upstream != nil &&
		t2ASRequests[t2AS3Issuer][0].Budget != nil && t2ASRequests[t2AS3Issuer][0].Budget.Amount() == 300
	t2Mu.Unlock()

	// =========================================================================
	// QA-T3: All-Go Four-Party Metered Release of Held R3 Results Over HTTPS
	// =========================================================================
	const (
		t3APIssuer  = "https://t3-ap.example"
		t3AgID      = "aauth:analyst@t3-ap.example"
		t3PSIssuer  = "https://t3-ps.example"
		t3ASIssuer  = "https://t3-as.example"
		t3ResIssuer = "https://t3-res.example"
	)
	t3APKey := newTKey("t3-ap-1", 0xe3)
	t3AgKey := newTKey("t3-ag-1", 0xe4)
	t3PSKey := newTKey("t3-ps-1", 0xe5)
	t3ASKey := newTKey("t3-as-1", 0xe6)
	t3ResKey := newTKey("t3-res-1", 0xe7)

	t3Reg, err := r3.NewRegistry(mcp.Vocabulary())
	must(err, "t3Reg")
	t3Defs, err := r3.NewDefinitionRegistry(mcp.DefinitionRegistration())
	must(err, "t3Defs")
	t3ExportOp, err := mcp.NewOperation("reports.export")
	must(err, "t3ExportOp")
	t3ExportR3, err := t3ExportOp.ToR3()
	must(err, "t3ExportR3")
	t3ClassOps, err := r3.NewOperationSet(t3ExportR3)
	must(err, "t3ClassOps")
	t3NoOps, err := r3.NewGrantedOperations(mcp.Vocabulary())
	must(err, "t3NoOps")
	t3PerCallOps, err := r3.NewGrantedOperations(mcp.Vocabulary(), t3ExportR3)
	must(err, "t3PerCallOps")

	t3Cost40 := t2Val(40)
	t3Short15 := t2Val(15)
	t3Def, err := mcp.ParseDefinition(t3ResIssuer+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
		`{"tools":[{"name":"reports.export","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]}`,
	))))
	must(err, "t3Def")

	t3AP, err := agentprovider.New(agentprovider.Config{
		Issuer: t3APIssuer, SigningKey: t3APKey, Clock: clock, NewID: nextTID,
	})
	must(err, "t3AP")
	_, _ = registerTLS("t3-ap.example", t3AP.Handler())
	t3AgTok, err := t3AP.Issue(aauth.AgentTokenRequest{
		Agent: t3AgID, PersonServer: t3PSIssuer, PublicKey: t3AgKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t3AgTok")

	var (
		t3Runs          atomic.Int32
		t3PSDeclineProp atomic.Bool
		t3ASGrantShort  atomic.Bool
		t3Mu            sync.Mutex
		t3PSCeilings    []personserver.AuthorizationRequest
		t3ASAsked       []accessserver.AuthorizationRequest
	)
	t3Docs := &memoryDocumentStore{}
	t3Props := &memoryProposalStore{}
	t3Ledger := testutil.NewBudgetStore()
	t3Disp, err := r3.NewDisplay("Release the quarterly report", "", "One report", "")
	must(err, "t3Disp")
	t3EmptyParams, err := r3.NewParameters(nil)
	must(err, "t3EmptyParams")

	t3Res, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer: t3ResIssuer, AccessServer: t3ASIssuer, SigningKey: t3ResKey, KeyResolver: tResolver,
		Clock: clock, NewID: nextTID,
		ScopeDescriptions: map[string]string{"reports.read": "Read reports"},
		RequiredScopes:    func(*http.Request) []string { return []string{"reports.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t3Runs.Add(1)
			_, _ = io.WriteString(w, "quarterly report")
		}),
		R3: &resource.R3Config{
			Registry: t3Reg, Definitions: t3Defs,
			Vocabularies: []resource.R3VocabularyConfig{{Definition: t3Def}},
			Documents:    t3Docs,
			HTTP: resource.R3HTTPAdapter{
				OperationForRequest: func(*http.Request) (r3.Operation, bool, error) { return t3ExportR3, true, nil },
				PresentParameters:   func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) { return nil, nil },
			},
			PerCall: &resource.R3PerCallConfig{
				Proposals: t3Props, Retries: &memoryRetryStore{},
				DescribeCall: func(context.Context, r3.Invocation, *string) (resource.R3CallDescription, error) {
					return resource.R3CallDescription{}, errors.New("metered release is never proposed for execution")
				},
				Release: &resource.R3ReleaseConfig{
					Eligible:     func(context.Context, r3.Invocation) (bool, error) { return true, nil },
					MeterRelease: true,
					DescribeResult: func(context.Context, resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
						return resource.R3ReleaseDescription{
							Parameters: t3EmptyParams, Result: json.RawMessage(`{"reports":1}`),
							Display: t3Disp, Cost: &t3Cost40,
						}, nil
					},
				},
			},
		},
		Budget: &resource.BudgetConfig{
			Units:         t2Units,
			Metered:       func(*http.Request) bool { return false },
			RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
			Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return 0, nil },
			Store:         t3Ledger,
			Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
				return "", errors.New("no budget step-up")
			},
		},
		HeldInvocations:              newPHeldBudgetStore(),
		HoldAuthTokenRequest:         func(*http.Request) bool { return true },
		MaxRetainedRequestBodyBytes:  64 << 10,
		MaxRetainedResponseBodyBytes: 64 << 10,
		MaxRetainedHeaderBytes:       16 << 10,
	})
	must(err, "t3Res")
	_, _ = registerTLS("t3-res.example", t3Res.Handler())

	t3Admit := func(context.Context, string) error { return nil }
	t3AS, err := accessserver.New(accessserver.Config{
		Issuer: t3ASIssuer, SigningKey: t3ASKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(context.Context, accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{}, errors.New("Core policy must not receive R3 request")
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
		},
		R3: &accessserver.R3Config{
			Registry: t3Reg, HTTPClient: httpClient, Admit: t3Admit,
			AuthorizeDocument: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, doc r3.Document) (accessserver.R3DocumentDecision, error) {
				authz, aErr := r3.NewAuthorization(t3NoOps, t3PerCallOps, doc)
				if aErr != nil {
					return accessserver.R3DocumentDecision{}, aErr
				}
				return accessserver.R3DocumentDecision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Authorization: &authz}, nil
			},
			AuthorizeProposal: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, _ r3.Proposal) (accessserver.R3ProposalDecision, error) {
				t3Mu.Lock()
				t3ASAsked = append(t3ASAsked, req)
				t3Mu.Unlock()
				b := req.Budget
				if t3ASGrantShort.Load() {
					s := t3Short15
					b = &s
				}
				return accessserver.R3ProposalDecision{Scopes: req.Scopes, Lifetime: 5 * time.Minute, Budget: b}, nil
			},
			Issuances: &memoryIssuanceStore{},
		},
	})
	must(err, "t3AS")
	_, _ = registerTLS("t3-as.example", t3AS.Handler())

	t3PS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: t3PSIssuer, SigningKey: t3PSKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		HTTPClient: httpClient, Tokens: testutil.NewMissionStore(), IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(context.Context, string) (string, error) { return t3ASIssuer + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-t3", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return errors.New("Core consent must not receive R3 request")
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
			Ceiling: func(_ context.Context, req personserver.AuthorizationRequest) (*budgets.Value, error) {
				t3Mu.Lock()
				t3PSCeilings = append(t3PSCeilings, req)
				t3Mu.Unlock()
				return req.Budget, nil
			},
		},
		R3: &personserver.R3Config{
			Registry: t3Reg, Admit: t3Admit,
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error { return nil },
			ConsentProposal: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Proposal) error {
				if t3PSDeclineProp.Load() {
					return personserver.ErrAccessDenied
				}
				return nil
			},
		},
	})
	must(err, "t3PS")
	_, _ = registerTLS("t3-ps.example", t3PS.Handler())

	t3Agent, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t3AgID, SigningKey: t3AgKey, AgentToken: t3AgTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: t3Reg},
	})
	must(err, "t3Agent")

	t3PTRes, err := t3Agent.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: t3PSIssuer, Resource: t3ResIssuer})
	must(err, "t3PTRes")
	t3PT, _ := t3PTRes.Token()
	t3ClassRT, err := t3Agent.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t3ResIssuer, PersonToken: t3PT, Scopes: []string{"reports.read"}, R3Operations: &t3ClassOps,
	})
	must(err, "t3ClassRT")
	t3ClassAT, err := t3Agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t3PSIssuer, ResourceToken: t3ClassRT, PresentedToken: t3PT,
	})
	must(err, "t3ClassAT")

	t3CallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t3ResIssuer+"/reports/q3", nil)
	t3Begun, err := t3Agent.BeginR3Call(ctx, clientagent.R3Call{
		Request: t3CallReq, ClassAuthToken: t3ClassAT, Operation: t3ExportR3,
	})
	must(err, "t3Begun")
	t3Pending, t3PendingOK := t3Begun.Pending()
	t3PropRTClaims, t3PropRef, t3PropOffer, t3PropConsumed, err := r3.VerifyBudgetResourceToken(
		ctx, t3Reg, t3Pending.ResourceToken(), tResolver, clock,
	)
	must(err, "VerifyBudgetResourceToken t3Pending")
	t3PropRec, err := t3Props.Load(ctx, t3PropRef.URI())
	must(err, "t3Props.Load")
	t3Art, err := t3Reg.ParseReferencedArtifact(t3PropRef, t3PropRec.ExactJSON)
	must(err, "ParseReferencedArtifact")
	t3ParsedProp, _ := t3Art.Proposal()
	_, t3ReleaseResultPresent := t3ParsedProp.Result()
	t3PropOfferOK := t3PendingOK && t3Runs.Load() == 1 && t3PropOffer.Amount() == 40 &&
		t3PropOffer.Unit().Name() == "credits" && t3PropConsumed == nil &&
		t3Art.Kind() == r3.ArtifactProposal && t3ReleaseResultPresent

	// 1) Declined release -> 403 access_denied, meters nothing
	t3PSDeclineProp.Store(true)
	_, t3DeclineErr := t3Agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t3PSIssuer, ResourceToken: t3Pending.ResourceToken(), PresentedToken: t3ClassAT,
	})
	t3PSDeclineProp.Store(false)
	var t3DeclineProb *aauth.ProblemError
	t3Decline403OK := errors.As(t3DeclineErr, &t3DeclineProb) && t3DeclineProb.Status == http.StatusForbidden &&
		t3DeclineProb.Code == "access_denied"

	// 2) Unbudgeted per-call token -> rejected by Agent client AND rejected with 403 by Resource, result stays held
	t3UnfundedAT, err := r3.MintPerCallAuthToken(t3Reg, t3ASKey, aauth.AuthTokenClaims{
		Issuer: t3ASIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: t3ResIssuer, JTI: nextTID(),
		PersonServer: t3PSIssuer, Subject: t3PropRTClaims.Subject, Tenant: t3PropRTClaims.Tenant,
		Confirmation: aauth.Confirmation{JWK: t3AgKey.PublicJWK()},
		IssuedAt: clock.Now().Unix(), ExpiresAt: clock.Now().Add(5 * time.Minute).Unix(), Scope: "reports.read",
	}, t3PropRef, t3PropRec.ExactJSON)
	must(err, "t3UnfundedAT")
	_, t3UnfundedCliErr := t3Agent.PollR3Call(ctx, clientagent.R3Poll{Pending: t3Pending, AuthToken: t3UnfundedAT})
	t3UnfundedReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t3Pending.Location(), nil)
	must(signaturekey.SignJWTRequestWithOptions(t3UnfundedReq, t3AgKey, t3UnfundedAT, clock, signaturekey.SignOptions{}), "sign unfunded poll")
	t3UnfundedResp, err := httpClient.Do(t3UnfundedReq)
	must(err, "t3UnfundedResp")
	_ = t3UnfundedResp.Body.Close()
	t3UnfundedRefusedOK := t3UnfundedCliErr != nil && t3UnfundedResp.StatusCode == http.StatusForbidden &&
		t3UnfundedResp.Header.Get("AAuth-Budget") == ""

	// 3) Short per-call token (grant=15 < 40) -> 403 access_denied with AAuth-Budget (remaining=15, required=40), result stays held
	t3ASGrantShort.Store(true)
	t3ShortAT, err := t3Agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t3PSIssuer, ResourceToken: t3Pending.ResourceToken(), PresentedToken: t3ClassAT,
	})
	t3ASGrantShort.Store(false)
	must(err, "t3ShortAT")
	_, t3ShortPollErr := t3Agent.PollR3Call(ctx, clientagent.R3Poll{Pending: t3Pending, AuthToken: t3ShortAT})
	var t3ShortProb *aauth.ProblemError
	t3ShortReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t3Pending.Location(), nil)
	must(signaturekey.SignJWTRequestWithOptions(t3ShortReq, t3AgKey, t3ShortAT, clock, signaturekey.SignOptions{}), "sign short poll")
	t3ShortResp, err := httpClient.Do(t3ShortReq)
	must(err, "t3ShortResp")
	_ = t3ShortResp.Body.Close()
	t3ShortFB, t3ShortFBErr := budgets.ParseFeedback(t3ShortResp.Header.Values("AAuth-Budget"))
	t3ShortReqAmt, t3ShortHasReq := t3ShortFB.Required()
	t3ShortRefusedOK := errors.As(t3ShortPollErr, &t3ShortProb) && t3ShortProb.Status == http.StatusForbidden &&
		t3ShortResp.StatusCode == http.StatusForbidden && t3ShortFBErr == nil &&
		t3ShortFB.Remaining() == 15 && t3ShortHasReq && t3ShortReqAmt == 40

	// 4) Sufficient per-call token (grant=40) on the SAME held result -> 200 OK ("quarterly report") + replay -> 200 OK (0 extra drawdown)
	t3FitAT, err := t3Agent.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t3PSIssuer, ResourceToken: t3Pending.ResourceToken(), PresentedToken: t3ClassAT,
	})
	must(err, "t3FitAT")
	_, _, _, t3FitGrant, err := r3.VerifyBudgetAuthToken(ctx, t3Reg, t3FitAT, tResolver, clock)
	must(err, "VerifyBudgetAuthToken t3FitAT")
	t3RelPoll1, err := t3Agent.PollR3Call(ctx, clientagent.R3Poll{Pending: t3Pending, AuthToken: t3FitAT})
	must(err, "t3RelPoll1")
	t3RelResp1, _ := t3RelPoll1.Response()
	t3RelBody1, _ := io.ReadAll(t3RelResp1.Body)
	_ = t3RelResp1.Body.Close()
	t3RelFB1, err := budgets.ParseFeedback(t3RelResp1.Header.Values("AAuth-Budget"))
	must(err, "t3RelFB1")
	t3RelCost1, _ := t3RelFB1.Cost()

	t3RelPoll2, err := t3Agent.PollR3Call(ctx, clientagent.R3Poll{Pending: t3Pending, AuthToken: t3FitAT})
	must(err, "t3RelPoll2")
	t3RelResp2, _ := t3RelPoll2.Response()
	t3RelBody2, _ := io.ReadAll(t3RelResp2.Body)
	_ = t3RelResp2.Body.Close()
	t3RelFB2, err := budgets.ParseFeedback(t3RelResp2.Header.Values("AAuth-Budget"))
	must(err, "t3RelFB2")
	t3RelCost2, _ := t3RelFB2.Cost()

	t3ReleaseAndReplayOK := t3FitGrant.Amount() == 40 &&
		t3RelResp1.StatusCode == http.StatusOK && string(t3RelBody1) == "quarterly report" &&
		t3RelCost1 == 40 && t3RelFB1.Remaining() == 0 &&
		t3RelResp2.StatusCode == http.StatusOK && string(t3RelBody2) == "quarterly report" &&
		t3RelCost2 == 40 && t3RelFB2.Remaining() == 0 && t3Runs.Load() == 1

	// =========================================================================
	// QA-T4: Cross-Language (aauth-go 9b14543 <-> aauth-rust v0.1.0-alpha.17)
	// =========================================================================
	const (
		t4GoAPIssuer          = "https://t4-go-ap.example"
		t4GoCallerID          = "aauth:caller@t4-go-ap.example"
		t4GoIntermIssuer      = "https://t4-go-interm.example"
		t4GoIntermAgID        = "aauth:relay@t4-go-interm.example"
		t4GoFedPSIssuer       = "https://t4-go-fed-ps.example"
		t4GoDirectPSIssuer    = "https://t4-go-direct-ps.example"
		t4GoASIssuer          = "https://t4-go-as.example"
		t4GoResIssuer         = "https://t4-go-res.example"
		t4GoHeldResIssuer     = "https://t4-go-held-res.example"
		t4GoHeldRustASIssuer  = "https://t4-go-held-rust-as.example"
	)
	t4GoAPKey := newTKey("t4-go-ap-1", 0xe8)
	t4GoCallerKey := newTKey("t4-go-caller-1", 0xe9)
	t4GoIntermKey := newTKey("t4-go-interm-1", 0xea)
	t4GoIntermAgKey := newTKey("t4-go-interm-ag-1", 0xeb)
	t4GoFedPSKey := newTKey("t4-go-fed-ps-1", 0xec)
	t4GoDirectPSKey := newTKey("t4-go-direct-ps-1", 0xed)
	t4GoASKey := newTKey("t4-go-as-1", 0xee)
	t4GoResKey := newTKey("t4-go-res-1", 0xef)
	t4GoHeldResKey := newTKey("t4-go-held-res-1", 0xf0)
	t4GoHeldRustASKey := newTKey("t4-go-held-rust-as-1", 0xf1)
	t4RustASSigningKey := newTKey("t4-rust-as-1", 0xf2)

	t4McpQueryOp, err := mcp.NewOperation("records.query")
	must(err, "t4McpQueryOp")
	t4McpMeteredOp, err := mcp.NewOperation("records.metered_query")
	must(err, "t4McpMeteredOp")
	t4R3QueryOp, _ := t4McpQueryOp.ToR3()
	t4R3MeteredOp, _ := t4McpMeteredOp.ToR3()
	t4RustClassOps, err := r3.NewOperationSet(t4R3QueryOp, t4R3MeteredOp)
	must(err, "t4RustClassOps")

	t4GoAP, err := agentprovider.New(agentprovider.Config{
		Issuer: t4GoAPIssuer, SigningKey: t4GoAPKey, Clock: clock, NewID: nextTID,
	})
	must(err, "t4GoAP")
	t4GoAPSrv, t4GoAPDER := registerTLS("t4-go-ap.example", t4GoAP.Handler())
	t4GoCallerTok, err := t4GoAP.Issue(aauth.AgentTokenRequest{
		Agent: t4GoCallerID, PersonServer: t4GoFedPSIssuer, PublicKey: t4GoCallerKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t4GoCallerTok")
	t4GoDirectCallerTok, err := t4GoAP.Issue(aauth.AgentTokenRequest{
		Agent: t4GoCallerID, PersonServer: t4GoDirectPSIssuer, PublicKey: t4GoCallerKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t4GoDirectCallerTok")

	var (
		t4GoASDeferInt     atomic.Bool
		t4GoASShortRelease atomic.Bool
	)
	t4GoAS, err := accessserver.New(accessserver.Config{
		Issuer: t4GoASIssuer, SigningKey: t4GoASKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == t4GoFedPSIssuer || iss == in.T4RustFedPSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 10 * time.Minute},
		Revocation: &accessserver.RevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(), IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient: httpClient, Admit: t3Admit,
		},
		Budget: &accessserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if t4GoASDeferInt.Load() {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{
					RetryAfter: time.Second, InteractionURL: t4GoASIssuer + "/consent",
				}}, nil
			}
			var b *budgets.Value
			if req.Budget != nil {
				g := t2Val(220)
				b = &g
			}
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Budget: b}, nil
		},
		R3: &accessserver.R3Config{
			Registry: t3Reg, HTTPClient: httpClient, Admit: t3Admit,
			AuthorizeDocument: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, doc r3.Document) (accessserver.R3DocumentDecision, error) {
				perCall, pErr := r3.NewGrantedOperations(mcp.Vocabulary(), doc.OperationSet().Operations()...)
				if pErr != nil {
					return accessserver.R3DocumentDecision{}, pErr
				}
				authz, aErr := r3.NewAuthorization(t3NoOps, perCall, doc)
				if aErr != nil {
					return accessserver.R3DocumentDecision{}, aErr
				}
				return accessserver.R3DocumentDecision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Authorization: &authz}, nil
			},
			AuthorizeProposal: func(_ context.Context, req accessserver.AuthorizationRequest, _ r3.Reference, _ r3.Proposal) (accessserver.R3ProposalDecision, error) {
				b := req.Budget
				if t4GoASShortRelease.Load() {
					s := t3Short15
					b = &s
				}
				return accessserver.R3ProposalDecision{Scopes: req.Scopes, Lifetime: 5 * time.Minute, Budget: b}, nil
			},
			Issuances: &memoryIssuanceStore{},
		},
	})
	must(err, "t4GoAS")
	t4GoASMux := http.NewServeMux()
	t4GoASMux.HandleFunc("POST /__set-defer", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DeferInt     bool `json:"defer_int"`
			ShortRelease bool `json:"short_release"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		t4GoASDeferInt.Store(body.DeferInt)
		t4GoASShortRelease.Store(body.ShortRelease)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	t4GoASMux.Handle("/", t4GoAS.Handler())
	t4GoASSrv, t4GoASDER := registerTLS("t4-go-as.example", t4GoASMux)

	t4GoFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer: t4GoFedPSIssuer, SigningKey: t4GoFedPSKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		HTTPClient: httpClient, Tokens: testutil.NewMissionStore(), IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(_ context.Context, asIss string) (string, error) { return asIss + "/token", nil },
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-t4-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: 30 * time.Minute}, nil
		},
		Consent:  func(context.Context, personserver.AuthorizationRequest) error { return nil },
		Deferred: &personserver.FederatedDeferredConfig{Store: testutil.NewFederatedAuthorizationStore(), Lifetime: 10 * time.Minute},
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "chained-t4-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: 30 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		Budget: &personserver.FederatedBudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
			Ceiling: func(_ context.Context, req personserver.AuthorizationRequest) (*budgets.Value, error) {
				if req.Budget != nil && req.Budget.Amount() <= 40 {
					return req.Budget, nil
				}
				c := t2Val(300)
				return &c, nil
			},
		},
		R3: &personserver.R3Config{
			Registry: t3Reg, Admit: t3Admit,
			ConsentDocument: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Document) error { return nil },
			ConsentProposal: func(context.Context, personserver.AuthorizationRequest, r3.Reference, r3.Proposal) error { return nil },
		},
	})
	must(err, "t4GoFedPS")
	t4GoFedPSMux := http.NewServeMux()
	t4GoFedPSMux.HandleFunc("POST /__advance", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Ref string `json:"ref"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		tAdvance(2 * time.Second)
		advErr := t4GoFedPS.AdvanceFederation(r.Context(), body.Ref)
		w.Header().Set("Content-Type", "application/json")
		if advErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": advErr.Error()})
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	t4GoFedPSMux.Handle("/", t4GoFedPS.Handler())
	t4GoFedPSSrv, t4GoFedPSDER := registerTLS("t4-go-fed-ps.example", t4GoFedPSMux)

	t4GoDirectPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer: t4GoDirectPSIssuer, SigningKey: t4GoDirectPSKey, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
		Tokens: testutil.NewMissionStore(), IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-t4-direct", Lifetime: 30 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Budget: req.Budget}, nil
		},
		R3: &personserver.DirectR3Config{
			Registry: t3Reg, HTTPClient: httpClient, Admit: t3Admit,
			AuthorizeDocument: func(_ context.Context, req personserver.AuthorizationRequest, _ r3.Reference, doc r3.Document) (personserver.DirectR3Decision, error) {
				docOps, pErr := r3.NewGrantedOperations(mcp.Vocabulary(), doc.OperationSet().Operations()...)
				if pErr != nil {
					return personserver.DirectR3Decision{}, pErr
				}
				g, gErr := r3.NewGrant(docOps, doc)
				if gErr != nil {
					return personserver.DirectR3Decision{}, gErr
				}
				return personserver.DirectR3Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute, Grant: g, Budget: req.Budget}, nil
			},
			Issuances: &memoryIssuanceStore{},
		},
		Budget: &personserver.BudgetConfig{
			ResolveResourceUnits: func(context.Context, string) ([]budgets.UnitDeclaration, error) { return t2Units, nil },
		},
	})
	must(err, "t4GoDirectPS")
	t4GoDirectPSSrv, t4GoDirectPSDER := registerTLS("t4-go-direct-ps.example", t4GoDirectPS.Handler())

	makeT4GoRes := func(issuer, host, asIssuer string, key jose.SigningKey, isInterm bool, costAmt int64) (*httptest.Server, []byte) {
		res, rErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: issuer, AccessServer: asIssuer, SigningKey: key, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
			ScopeDescriptions: map[string]string{"records.read": "Read records", "work.run": "Run work"},
			RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Budget: &resource.BudgetConfig{
				Units:         t2Units,
				Metered:       func(r *http.Request) bool { return r.URL.Path == "/metered" },
				Offer:         func(_ context.Context, req resource.BudgetOfferRequest) (budgets.Value, error) { return req.Requested, nil },
				RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
				Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return costAmt, nil },
				Store:         testutil.NewBudgetStore(),
				Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
					return "", errors.New("no challenge")
				},
			},
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, _ := resource.AuthPrincipalFromContext(r.Context())
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"ok":true,"sub":"`+p.Subject+`"}`)
			}),
		})
		must(rErr, "makeT4GoRes "+issuer)
		mux := http.NewServeMux()
		if isInterm {
			mux.HandleFunc("GET /.well-known/aauth-agent.json", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"issuer":"`+issuer+`","jwks_uri":"`+issuer+`/.well-known/jwks.json"}`)
			})
		}
		mux.Handle("/", res.Handler())
		return registerTLS(host, mux)
	}
	t4GoIntermSrv, t4GoIntermDER := makeT4GoRes(t4GoIntermIssuer, "t4-go-interm.example", t4GoASIssuer, t4GoIntermKey, true, 20)
	t4GoResSrv, t4GoResDER := makeT4GoRes(t4GoResIssuer, "t4-go-res.example", t4GoASIssuer, t4GoResKey, false, 45)

	var t4GoHeldRustASRuns atomic.Int32
	t4GoHeldRustASDocs := &memoryDocumentStore{}
	t4GoHeldRustASProps := &memoryProposalStore{}
	makeT4GoHeldRes := func(issuer, host, asIssuer string, key jose.SigningKey, docs *memoryDocumentStore, props *memoryProposalStore, runs *atomic.Int32) (*httptest.Server, []byte) {
		def, dErr := mcp.ParseDefinition(issuer+"/mcp", mcp.NewToolsListSnapshot(mcp.NewInitialToolsListPage([]byte(
			`{"tools":[{"name":"reports.export","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}]}`,
		))))
		must(dErr, "makeT4GoHeldRes def")
		res, rErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer: issuer, AccessServer: asIssuer, SigningKey: key, KeyResolver: tResolver, Clock: clock, NewID: nextTID,
			ScopeDescriptions: map[string]string{"reports.read": "Read reports"},
			RequiredScopes:    func(*http.Request) []string { return []string{"reports.read"} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if runs != nil {
					runs.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"reports":1}`)
			}),
			R3: &resource.R3Config{
				Registry: t3Reg, Definitions: t3Defs,
				Vocabularies: []resource.R3VocabularyConfig{{Definition: def}},
				Documents:    docs,
				HTTP: resource.R3HTTPAdapter{
					OperationForRequest: func(*http.Request) (r3.Operation, bool, error) { return t3ExportR3, true, nil },
					PresentParameters:   func(*http.Request, r3.Operation) (map[string]r3.PresentedParameter, error) { return nil, nil },
				},
				PerCall: &resource.R3PerCallConfig{
					Proposals: props, Retries: &memoryRetryStore{},
					DescribeCall: func(context.Context, r3.Invocation, *string) (resource.R3CallDescription, error) {
						return resource.R3CallDescription{}, errors.New("not execution")
					},
					Release: &resource.R3ReleaseConfig{
						Eligible: func(context.Context, r3.Invocation) (bool, error) { return true, nil },
						MeterRelease: true,
						DescribeResult: func(context.Context, resource.R3ReleaseRequest) (resource.R3ReleaseDescription, error) {
							return resource.R3ReleaseDescription{
								Parameters: t3EmptyParams, Result: json.RawMessage(`{"reports":1}`),
								Display: t3Disp, Cost: &t3Cost40,
							}, nil
						},
					},
				},
			},
			Budget: &resource.BudgetConfig{
				Units:         t2Units,
				Metered:       func(*http.Request) bool { return false },
				RetainLineage: func(context.Context, resource.BudgetLineage) error { return nil },
				Cost:          func(context.Context, resource.BudgetCostRequest) (int64, error) { return 0, nil },
				Store:         testutil.NewBudgetStore(),
				Challenge: func(context.Context, resource.BudgetChallengeRequest) (string, error) {
					return "", errors.New("no challenge")
				},
			},
			HeldInvocations:              newPHeldBudgetStore(),
			HoldAuthTokenRequest:         func(*http.Request) bool { return true },
			MaxRetainedRequestBodyBytes:  64 << 10,
			MaxRetainedResponseBodyBytes: 64 << 10,
			MaxRetainedHeaderBytes:       16 << 10,
		})
		must(rErr, "makeT4GoHeldRes "+issuer)
		return registerTLS(host, res.Handler())
	}
	t4GoHeldResSrv, t4GoHeldResDER := makeT4GoHeldRes(
		t4GoHeldResIssuer, "t4-go-held-res.example", t4GoASIssuer, t4GoHeldResKey,
		&memoryDocumentStore{}, &memoryProposalStore{}, nil,
	)
	t4GoHeldRustASSrv, t4GoHeldRustASDER := makeT4GoHeldRes(
		t4GoHeldRustASIssuer, "t4-go-held-rust-as.example", in.T4RustASIssuer, t4GoHeldRustASKey,
		t4GoHeldRustASDocs, t4GoHeldRustASProps, &t4GoHeldRustASRuns,
	)

	certPEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	t4RegisterWithRustPS := func(issuer, host string, srv *httptest.Server, der []byte) {
		b, _ := json.Marshal(map[string]any{
			"issuer":   issuer,
			"host":     host,
			"addr":     srv.Listener.Addr().String(),
			"cert_pem": certPEM(der),
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustFedPSIssuer+"/__register-go", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, rErr := httpClient.Do(req)
		must(rErr, "t4RegisterWithRustPS "+issuer)
		_ = resp.Body.Close()
	}
	t4RegisterWithRustPS(t4GoASIssuer, "t4-go-as.example", t4GoASSrv, t4GoASDER)
	t4RegisterWithRustPS(t4GoHeldResIssuer, "t4-go-held-res.example", t4GoHeldResSrv, t4GoHeldResDER)

	t4RustPSCallerTok, err := t4GoAP.Issue(aauth.AgentTokenRequest{
		Agent: t4GoCallerID, PersonServer: in.T4RustFedPSIssuer, PublicKey: t4GoCallerKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "t4RustPSCallerTok")
	t4RustPSCaller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t4GoCallerID, SigningKey: t4GoCallerKey, AgentToken: t4RustPSCallerTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: t3Reg},
	})
	must(err, "t4RustPSCaller")

	t4Caller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t4GoCallerID, SigningKey: t4GoCallerKey, AgentToken: t4GoCallerTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: t3Reg},
	})
	must(err, "t4Caller")
	t4DirectCaller, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t4GoCallerID, SigningKey: t4GoCallerKey, AgentToken: t4GoDirectCallerTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
		R3: &clientagent.R3Config{Registry: t3Reg},
	})
	must(err, "t4DirectCaller")
	t4GoIntermTok, err := aauth.MintAgentToken(t4GoIntermIssuer, t4GoIntermKey, aauth.AgentTokenRequest{
		Agent: t4GoIntermAgID, PersonServer: "https://t4-go-interm-own-ps.example", PublicKey: t4GoIntermAgKey.PublicJWK(), Lifetime: time.Hour,
	}, clock.Now(), nextTID())
	must(err, "t4GoIntermTok")
	t4GoInterm, err := clientagent.New(ctx, clientagent.Config{
		Identifier: t4GoIntermAgID, SigningKey: t4GoIntermAgKey, AgentToken: t4GoIntermTok,
		KeyResolver: tResolver, HTTPClient: httpClient, Clock: clock,
	})
	must(err, "t4GoInterm")

	// Hop 1 AT for t4GoInterm
	t4PT1Res, err := t4Caller.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: t4GoFedPSIssuer, Resource: t4GoIntermIssuer})
	must(err, "t4PT1Res")
	t4PT1, _ := t4PT1Res.Token()
	t4RT1, err := t4Caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t4GoIntermIssuer, PersonToken: t4PT1, Scopes: []string{"records.read"},
	})
	must(err, "t4RT1")
	t4Hop1AT, err := t4Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoFedPSIssuer, ResourceToken: t4RT1, PresentedToken: t4PT1,
	})
	must(err, "t4Hop1AT")

	// Track 4A (Go Intermediary -> Go Fed PS -> Rust AS returning 202 requirement=interaction -> Rust Resource)
	t4SetRustMode := func(deferInt bool) {
		b, _ := json.Marshal(map[string]any{"defer_interaction": deferInt})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustASIssuer+"/__mode", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, dErr := httpClient.Do(req)
		must(dErr, "t4SetRustMode")
		_ = resp.Body.Close()
	}
	t4ApproveRustAS := func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustASIssuer+"/__approve-all", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		resp, dErr := httpClient.Do(req)
		must(dErr, "t4ApproveRustAS")
		_ = resp.Body.Close()
	}

	t4ChainPTRes, err := t4GoInterm.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource: in.T4RustResIssuer, UpstreamToken: t4Hop1AT,
	})
	must(err, "t4ChainPTRes")
	t4ChainPT, _ := t4ChainPTRes.Token()
	t4ChainRTInt, err := t4GoInterm.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: in.T4RustResIssuer, PersonToken: t4ChainPT, UpstreamToken: t4Hop1AT, Scopes: []string{"records.read"},
	})
	must(err, "t4ChainRTInt")
	t4SetRustMode(true)
	t4BegunRustInt, err := t4GoInterm.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t4ChainRTInt, PresentedToken: t4ChainPT, UpstreamToken: t4Hop1AT, Capabilities: []string{"interaction"},
	})
	must(err, "t4BegunRustInt")
	t4WaitRustInt, t4WaitRustIntOK := t4BegunRustInt.Pending()
	t4SetRustMode(false)
	t4ApproveRustAS()
	tAdvance(2 * time.Second)
	must(t4GoFedPS.AdvanceFederation(ctx, tDeferredRef(t4WaitRustInt.Location())), "t4GoFedPS.AdvanceFederation RustAS")
	t4FinRustInt, err := t4GoInterm.PollExchange(ctx, t4WaitRustInt)
	must(err, "t4FinRustInt")
	t4ATRustInt, t4ATRustIntOK := t4FinRustInt.Token()
	t4RustCallReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.T4RustResIssuer+"/data", nil)
	t4RustCallResp, err := t4GoInterm.Do(ctx, clientagent.Call{Request: t4RustCallReq, AuthToken: t4ATRustInt, UpstreamToken: t4Hop1AT})
	must(err, "t4RustCallResp")
	_ = t4RustCallResp.Body.Close()
	t4GoIntermRustASIntOK := t4WaitRustIntOK && t4WaitRustInt.Requirement() == aauth.RequirementInteraction &&
		strings.HasPrefix(t4WaitRustInt.InteractionURL(), in.T4RustASIssuer+"/") &&
		tValidInteractionCodeFormat(t4WaitRustInt.InteractionCode()) && t4ATRustIntOK &&
		t4RustCallResp.StatusCode == http.StatusOK
	tClockMu.Lock()
	tClockNow = baseClock.Now()
	tClockMu.Unlock()

	// Track 4B Dir 1 (Go Intermediary -> Go Fed PS -> Rust AS -> Rust Resource with Budget + UpstreamToken)
	t4ChainRTBud, err := t4GoInterm.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: in.T4RustResIssuer, PersonToken: t4ChainPT, UpstreamToken: t4Hop1AT,
		Scopes: []string{"records.read"}, Budget: &t2Offer500,
	})
	must(err, "t4ChainRTBud")
	t4Dir1AT, err := t4GoInterm.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken: t4ChainRTBud, PresentedToken: t4ChainPT, UpstreamToken: t4Hop1AT,
	})
	must(err, "t4Dir1AT")
	_, t4Dir1Grant, err := budgets.VerifyAuthToken(ctx, t4Dir1AT, tResolver, clock)
	must(err, "VerifyAuthToken t4Dir1AT")
	t4Dir1CallReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustResIssuer+"/metered", nil)
	t4Dir1Call, err := t4GoInterm.BeginBudgetCall(ctx, clientagent.BudgetCall{
		Request: t4Dir1CallReq, AuthToken: t4Dir1AT, UpstreamToken: t4Hop1AT,
	})
	must(err, "t4Dir1Call")
	t4Dir1Resp, t4Dir1RespOK := t4Dir1Call.Response()
	if t4Dir1RespOK {
		_ = t4Dir1Resp.Body.Close()
	}
	t4Dir1Cost, _ := t4Dir1Call.Cost()
	t4Dir1FB, _ := t4Dir1Call.Feedback()
	t4Dir1Rem := t4Dir1FB.Remaining()
	t4Dir1BudgetChainOK := t4Dir1Grant.Amount() == 200 && t4Dir1RespOK &&
		t4Dir1Resp.StatusCode == http.StatusOK && t4Dir1Cost == 35 && t4Dir1Rem == 165

	// Track 4C Dir 1a (Go Resource MeterRelease + Rust Fed PS + Go AS -> 400 invalid_resource_token on budgeted proposal at Rust Fed PS)
	t4Dir1aPTRes, err := t4RustPSCaller.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: in.T4RustFedPSIssuer, Resource: t4GoHeldResIssuer,
	})
	must(err, "t4Dir1aPTRes")
	t4Dir1aPT, _ := t4Dir1aPTRes.Token()
	t4Dir1aClassRT, err := t4RustPSCaller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t4GoHeldResIssuer, PersonToken: t4Dir1aPT, Scopes: []string{"reports.read"}, R3Operations: &t3ClassOps,
	})
	must(err, "t4Dir1aClassRT")
	t4Dir1aClassAT, err := t4RustPSCaller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: in.T4RustFedPSIssuer, ResourceToken: t4Dir1aClassRT, PresentedToken: t4Dir1aPT,
	})
	must(err, "t4Dir1aClassAT")
	t4Dir1aHoldReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t4GoHeldResIssuer+"/reports/q3", nil)
	t4Dir1aBegun, err := t4RustPSCaller.BeginR3Call(ctx, clientagent.R3Call{
		Request: t4Dir1aHoldReq, ClassAuthToken: t4Dir1aClassAT, Operation: t3ExportR3,
	})
	must(err, "t4Dir1aBegun")
	t4Dir1aPending, t4Dir1aPendingOK := t4Dir1aBegun.Pending()
	_, t4Dir1aPropExErr := t4RustPSCaller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: in.T4RustFedPSIssuer, ResourceToken: t4Dir1aPending.ResourceToken(), PresentedToken: t4Dir1aClassAT,
	})
	var t4Dir1aProb *aauth.ProblemError
	t4Dir1aRustFedPS400OK := t4Dir1aPendingOK &&
		errors.As(t4Dir1aPropExErr, &t4Dir1aProb) && t4Dir1aProb.Status == http.StatusBadRequest &&
		t4Dir1aProb.Code == "invalid_resource_token"

	// Track 4C Dir 1b (Go Resource MeterRelease + Go Fed PS + Rust AS -> 400 invalid_resource_token at Rust AS)
	t4PTGoHeldRustASRes, err := t4Caller.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: t4GoFedPSIssuer, Resource: t4GoHeldRustASIssuer,
	})
	must(err, "t4PTGoHeldRustASRes")
	t4PTGoHeldRustAS, _ := t4PTGoHeldRustASRes.Token()
	t4ClassRTGoHeldRustAS, err := t4Caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: t4GoHeldRustASIssuer, PersonToken: t4PTGoHeldRustAS, Scopes: []string{"reports.read"}, R3Operations: &t3ClassOps,
	})
	must(err, "t4ClassRTGoHeldRustAS")
	_, t4Dir1b4PartyErr := t4Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoFedPSIssuer, ResourceToken: t4ClassRTGoHeldRustAS, PresentedToken: t4PTGoHeldRustAS,
	})
	var t4Dir1bProb *aauth.ProblemError
	t4Dir1b4Party400OK := errors.As(t4Dir1b4PartyErr, &t4Dir1bProb) && t4Dir1bProb.Status == http.StatusBadRequest &&
		t4Dir1bProb.Code == "invalid_resource_token"

	// Create a held release challenge on t4GoHeldRustAS (using t4RustASSigningKey) and on t4GoHeldRes (for Dir 1a & Dir 1b wire tests)
	t4ClassClaims, t4ClassRef, err := r3.VerifyResourceToken(ctx, t4ClassRTGoHeldRustAS, tResolver, clock)
	must(err, "VerifyResourceToken t4ClassRTGoHeldRustAS")
	t4ClassDocRec, err := t4GoHeldRustASDocs.Load(ctx, t4ClassRef.URI())
	must(err, "t4GoHeldRustASDocs.Load")
	t4ClassDoc, err := t3Reg.ParseReferencedDocument(t4ClassRef, t4ClassDocRec.ExactJSON)
	must(err, "ParseReferencedDocument t4ClassDoc")
	t4ClassAuthz, err := r3.NewAuthorization(t3NoOps, t3PerCallOps, t4ClassDoc)
	must(err, "NewAuthorization t4ClassAuthz")
	t4ClassATGoHeldRustAS, err := r3.MintAuthToken(t3Reg, t4RustASSigningKey, aauth.AuthTokenClaims{
		Issuer: in.T4RustASIssuer, DWK: aauth.AccessDiscoveryDocument, Audience: t4GoHeldRustASIssuer, JTI: nextTID(),
		PersonServer: t4GoFedPSIssuer, Subject: t4ClassClaims.Subject, Tenant: t4ClassClaims.Tenant,
		Confirmation: aauth.Confirmation{JWK: t4GoCallerKey.PublicJWK()},
		IssuedAt: clock.Now().Unix(), ExpiresAt: clock.Now().Add(30 * time.Minute).Unix(), Scope: "reports.read",
	}, t4ClassRef, t4ClassDocRec.ExactJSON, t4ClassAuthz)
	must(err, "MintAuthToken t4ClassATGoHeldRustAS")
	t4HeldRustASReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t4GoHeldRustASIssuer+"/reports/q3", nil)
	t4HeldRustASBegun, err := t4Caller.BeginR3Call(ctx, clientagent.R3Call{
		Request: t4HeldRustASReq, ClassAuthToken: t4ClassATGoHeldRustAS, Operation: t3ExportR3,
	})
	must(err, "t4HeldRustASBegun")
	t4HeldRustASPending, _ := t4HeldRustASBegun.Pending()
	_, t4HeldRustASPropRef, _, _, err := r3.VerifyBudgetResourceToken(ctx, t3Reg, t4HeldRustASPending.ResourceToken(), tResolver, clock)
	must(err, "VerifyBudgetResourceToken t4HeldRustASPending")
	t4HeldRustASPropRec, err := t4GoHeldRustASProps.Load(ctx, t4HeldRustASPropRef.URI())
	must(err, "t4GoHeldRustASProps.Load")

	// Track 4C Dir 2 (3-party: Rust Resource with_release_metering + Go Direct PS -> 400 invalid_resource_token on proposal exchange)
	t4DirPTRes, err := t4DirectCaller.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: t4GoDirectPSIssuer, Resource: in.T4RustHeldDirectIssuer,
	})
	must(err, "t4DirPTRes")
	t4DirPT, _ := t4DirPTRes.Token()
	t4DirClassRT, err := t4DirectCaller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: in.T4RustHeldDirectIssuer, PersonToken: t4DirPT, Scopes: []string{"records.read"}, R3Operations: &t4RustClassOps,
	})
	must(err, "t4DirClassRT")
	_, err = t4DirectCaller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoDirectPSIssuer, ResourceToken: t4DirClassRT, PresentedToken: t4DirPT,
	})
	must(err, "t4DirClassAT")
	// Mint 3-party per_call class AuthToken to obtain the 202 Accepted held release proposal from t4-rust-held-direct.example
	t4DirRTClaims, t4DirRTRef, err := r3.VerifyResourceToken(ctx, t4DirClassRT, tResolver, clock)
	if err != nil {
		t4DirRTClaims, t4DirRTRef, _, _, err = r3.VerifyBudgetResourceToken(ctx, t3Reg, t4DirClassRT, tResolver, clock)
	}
	must(err, "VerifyResourceToken t4DirClassRT")
	t4DirDocReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t4DirRTRef.URI(), nil)
	must(signaturekey.SignJWKSURIRequest(t4DirDocReq, t4GoDirectPSKey, t4GoDirectPSIssuer, aauth.PersonDiscoveryDocument, clock), "sign t4DirDocReq")
	t4DirDocResp, err := httpClient.Do(t4DirDocReq)
	must(err, "t4DirDocResp")
	t4DirDocBytes, _ := io.ReadAll(t4DirDocResp.Body)
	_ = t4DirDocResp.Body.Close()
	t4DirDoc, err := t3Reg.ParseReferencedDocument(t4DirRTRef, t4DirDocBytes)
	must(err, "ParseReferencedDocument t4DirDoc")
	t4DirPerCallOps, err := r3.NewGrantedOperations(mcp.Vocabulary(), t4DirDoc.OperationSet().Operations()...)
	must(err, "t4DirPerCallOps")
	t4DirAuthz, err := r3.NewAuthorization(t3NoOps, t4DirPerCallOps, t4DirDoc)
	must(err, "t4DirAuthz")
	t4DirPerCallClassAT, err := r3.MintAuthToken(t3Reg, t4GoDirectPSKey, aauth.AuthTokenClaims{
		Issuer: t4GoDirectPSIssuer, DWK: aauth.PersonDiscoveryDocument, Audience: in.T4RustHeldDirectIssuer, JTI: nextTID(),
		PersonServer: t4GoDirectPSIssuer, Subject: t4DirRTClaims.Subject, Tenant: t4DirRTClaims.Tenant,
		Confirmation: aauth.Confirmation{JWK: t4GoCallerKey.PublicJWK()},
		IssuedAt: clock.Now().Unix(), ExpiresAt: clock.Now().Add(30 * time.Minute).Unix(), Scope: "records.read",
	}, t4DirRTRef, t4DirDocBytes, t4DirAuthz)
	must(err, "MintAuthToken t4DirPerCallClassAT")
	// Call Rust Direct Held Resource directly with signed POST /records/metered-query
	t4DirHoldReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustHeldDirectIssuer+"/records/metered-query", bytes.NewReader([]byte(`{"record":"r-1"}`)))
	t4DirHoldReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequestWithOptions(t4DirHoldReq, t4GoCallerKey, t4DirPerCallClassAT, clock, signaturekey.SignOptions{}), "sign t4DirHoldReq")
	t4DirHoldResp, err := httpClient.Do(t4DirHoldReq)
	must(err, "t4DirHoldResp")
	_ = t4DirHoldResp.Body.Close()
	t4DirHoldReqHdr, err := aauth.ParseAuthTokenRequirement(t4DirHoldResp.Header.Values("AAuth-Requirement"))
	must(err, "ParseAuthTokenRequirement t4DirHoldResp")
	_, t4DirPropExErr := t4DirectCaller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoDirectPSIssuer, ResourceToken: t4DirHoldReqHdr.ResourceToken, PresentedToken: t4DirPerCallClassAT,
	})
	var t4DirPropProb *aauth.ProblemError
	t4Dir2DirectPS400OK := t4DirHoldResp.StatusCode == http.StatusAccepted &&
		errors.As(t4DirPropExErr, &t4DirPropProb) && t4DirPropProb.Status == http.StatusBadRequest &&
		t4DirPropProb.Code == "invalid_resource_token"

	// Track 4C Dir 2 (4-party: Rust Resource new_federated + with_release_metering + Go Fed PS + Go AS -> 403 short, 200 OK release & replay!)
	t4FedPTRes, err := t4Caller.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: t4GoFedPSIssuer, Resource: in.T4RustHeldResIssuer,
	})
	must(err, "t4FedPTRes")
	t4FedPT, _ := t4FedPTRes.Token()
	t4FedClassRT, err := t4Caller.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: in.T4RustHeldResIssuer, PersonToken: t4FedPT, Scopes: []string{"records.read"}, R3Operations: &t4RustClassOps,
	})
	must(err, "t4FedClassRT")
	t4FedClassAT, err := t4Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoFedPSIssuer, ResourceToken: t4FedClassRT, PresentedToken: t4FedPT,
	})
	must(err, "t4FedClassAT")
	t4FedHoldReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, in.T4RustHeldResIssuer+"/records/metered-query", bytes.NewReader([]byte(`{"record":"r-1"}`)))
	t4FedHoldReq.Header.Set("Content-Type", "application/json")
	t4FedBegun, err := t4Caller.BeginR3Call(ctx, clientagent.R3Call{
		Request: t4FedHoldReq, ClassAuthToken: t4FedClassAT, Operation: t4R3MeteredOp,
	})
	must(err, "t4FedBegun")
	t4FedPending, t4FedPendingOK := t4FedBegun.Pending()
	// Short grant (15 < 40) from Go AS -> Rust Resource refuses with 403 and keeps result held
	t4GoASShortRelease.Store(true)
	t4FedShortAT, err := t4Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoFedPSIssuer, ResourceToken: t4FedPending.ResourceToken(), PresentedToken: t4FedClassAT,
	})
	t4GoASShortRelease.Store(false)
	must(err, "t4FedShortAT")
	_, t4FedShortErr := t4Caller.PollR3Call(ctx, clientagent.R3Poll{Pending: t4FedPending, AuthToken: t4FedShortAT})
	var t4FedShortProb *aauth.ProblemError
	t4FedShortReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, t4FedPending.Location(), nil)
	must(signaturekey.SignJWTRequestWithOptions(t4FedShortReq, t4GoCallerKey, t4FedShortAT, clock, signaturekey.SignOptions{}), "sign t4FedShortReq")
	t4FedShortResp, err := httpClient.Do(t4FedShortReq)
	must(err, "t4FedShortResp")
	_ = t4FedShortResp.Body.Close()
	t4FedShortFB, t4FedShortFBErr := budgets.ParseFeedback(t4FedShortResp.Header.Values("AAuth-Budget"))
	t4FedShortReqAmt, t4FedShortHasReq := t4FedShortFB.Required()

	// Sufficient grant (40) from Go AS -> Rust Resource releases 200 OK + replay 200 OK
	t4FedFitAT, err := t4Caller.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: t4GoFedPSIssuer, ResourceToken: t4FedPending.ResourceToken(), PresentedToken: t4FedClassAT,
	})
	must(err, "t4FedFitAT")
	t4FedRel1, err := t4Caller.PollR3Call(ctx, clientagent.R3Poll{Pending: t4FedPending, AuthToken: t4FedFitAT})
	must(err, "t4FedRel1")
	t4FedResp1, _ := t4FedRel1.Response()
	t4FedBody1, _ := io.ReadAll(t4FedResp1.Body)
	_ = t4FedResp1.Body.Close()
	t4FedFB1, err := budgets.ParseFeedback(t4FedResp1.Header.Values("AAuth-Budget"))
	must(err, "t4FedFB1")
	t4FedCost1, _ := t4FedFB1.Cost()

	t4FedRel2, err := t4Caller.PollR3Call(ctx, clientagent.R3Poll{Pending: t4FedPending, AuthToken: t4FedFitAT})
	must(err, "t4FedRel2")
	t4FedResp2, _ := t4FedRel2.Response()
	t4FedBody2, _ := io.ReadAll(t4FedResp2.Body)
	_ = t4FedBody2
	_ = t4FedResp2.Body.Close()
	t4FedFB2, err := budgets.ParseFeedback(t4FedResp2.Header.Values("AAuth-Budget"))
	must(err, "t4FedFB2")
	t4FedCost2, _ := t4FedFB2.Cost()

	t4Dir2Fed4PartyOK := t4FedPendingOK &&
		errors.As(t4FedShortErr, &t4FedShortProb) && t4FedShortProb.Status == http.StatusForbidden &&
		t4FedShortFBErr == nil && t4FedShortFB.Remaining() == 15 && t4FedShortHasReq && t4FedShortReqAmt == 40 &&
		t4FedResp1.StatusCode == http.StatusOK && strings.Contains(string(t4FedBody1), `"metered":true`) &&
		t4FedCost1 == 40 && t4FedFB1.Remaining() == 0 &&
		t4FedResp2.StatusCode == http.StatusOK && t4FedCost2 == 40 && t4FedFB2.Remaining() == 0

	// =========================================================================
	// QA-T5: Re-Check of OBS-S6-1 (supervision.Clarification.Validate Timeout)
	// =========================================================================
	t5SubSecondRefused := true
	for _, badDur := range []time.Duration{time.Nanosecond, 500 * time.Millisecond, 1500 * time.Millisecond, -time.Second} {
		c := supervision.Clarification{Question: "Is the fare refundable?", Timeout: badDur}
		if c.Validate() == nil {
			t5SubSecondRefused = false
		}
	}
	t5ValidC := supervision.Clarification{Question: "Is the fare refundable?", Timeout: 2 * time.Second}
	t5ValidEnc, t5ValidErr := supervision.EncodePending("pending", &t5ValidC)
	t5WholeSecondsOK := t5ValidC.Validate() == nil && t5ValidErr == nil && strings.Contains(string(t5ValidEnc), `"timeout":2`)

	t5Cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-run", "TestClarificationTimeoutIsWholeSeconds", "./supervision/...")
	t5Cmd.Dir = in.GoModDir
	t5Out, t5TestErr := t5Cmd.CombinedOutput()
	t5UnitTestOK := t5TestErr == nil && strings.Contains(string(t5Out), "ok")

	return map[string]any{
		"servers": map[string]any{
			"t4_go_ap":           map[string]any{"addr": t4GoAPSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoAPDER)},
			"t4_go_interm":       map[string]any{"addr": t4GoIntermSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoIntermDER)},
			"t4_go_fed_ps":       map[string]any{"addr": t4GoFedPSSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoFedPSDER)},
			"t4_go_direct_ps":    map[string]any{"addr": t4GoDirectPSSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoDirectPSDER)},
			"t4_go_as":           map[string]any{"addr": t4GoASSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoASDER)},
			"t4_go_res":          map[string]any{"addr": t4GoResSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoResDER)},
			"t4_go_held_res":     map[string]any{"addr": t4GoHeldResSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoHeldResDER)},
			"t4_go_held_rust_as": map[string]any{"addr": t4GoHeldRustASSrv.Listener.Addr().String(), "cert_pem": certPEM(t4GoHeldRustASDER)},
		},
		"t1": map[string]any{
			"as_store_suite_ok":     t1ASStoreOK,
			"ps_store_suite_ok":     t1PSStoreOK,
			"flow1a_top_initial_ok": t1Flow1aOK,
			"code_immutability_ok":  t1CodeImmutOK,
			"flow1b_poll_advance":   t1Flow1bOK,
			"flow1c_chained_int_ok": t1Flow1cOK,
			"no_cap_initial_403_ok": t1NoCapInit403OK,
			"no_cap_poll_403_ok":    t1NoCapPoll403OK,
			"mission_inherit_ok":    t1MissionInheritOK,
			"malformed_code_502_ok": t1Malformed502OK,
		},
		"t2": map[string]any{
			"hop1_ok":                t2Resp1OK && t2Resp1.StatusCode == 200 && t2Cost1 == 25 && t2Rem1 == 225,
			"hop2_ok":                t2Resp2OK && t2Resp2.StatusCode == 200 && t2Cost2 == 40 && t2Rem2 == 160,
			"hop3_ok":                t2Resp3OK && t2Resp3.StatusCode == 200 && t2Cost3 == 60 && t2Rem3 == 90,
			"upstream_unconsumed_ok": t2Rem1b == 200 && t2Rem2b == 120,
			"hop3_over_budget_403":   t2Hop3OverRefusedOK,
			"no_at_guard_ok":         t2NoATGuardOK,
			"as_over_ceiling_502_ok": t2ASOver502OK,
			"ceiling_checks_ok":      t2CeilingChecksOK,
		},
		"t3": map[string]any{
			"proposal_offer_ok":     t3PropOfferOK,
			"declined_403_ok":       t3Decline403OK,
			"unfunded_403_ok":       t3UnfundedRefusedOK,
			"short_403_held_ok":     t3ShortRefusedOK,
			"release_and_replay_ok": t3ReleaseAndReplayOK,
			"handler_runs":          t3Runs.Load(),
		},
		"t4": map[string]any{
			"go_interm_rust_as_int_ok":      t4GoIntermRustASIntOK,
			"dir1_budget_chain_ok":          t4Dir1BudgetChainOK,
			"dir1a_rust_fed_ps_400_ok":      t4Dir1aRustFedPS400OK,
			"dir1b_4party_rust_as_400_ok":   t4Dir1b4Party400OK,
			"dir2_3party_direct_ps_400_ok":  t4Dir2DirectPS400OK,
			"dir2_4party_fed_release_ok":    t4Dir2Fed4PartyOK,
			"go_held_rust_as_pending_url":   t4HeldRustASPending.Location(),
			"go_held_rust_as_prop_rt":       t4HeldRustASPending.ResourceToken(),
			"go_held_rust_as_prop_uri":      t4HeldRustASPropRef.URI(),
			"go_held_rust_as_prop_s256":     t4HeldRustASPropRef.Digest(),
			"go_held_rust_as_prop_json_b64": string(t4HeldRustASPropRec.ExactJSON),
			"go_held_rust_as_subject":       t4ClassClaims.Subject,
		},
		"t5": map[string]any{
			"sub_second_refused_ok": t5SubSecondRefused,
			"whole_seconds_ok":      t5WholeSecondsOK,
			"unit_test_ok":          t5UnitTestOK,
		},
	}
}
