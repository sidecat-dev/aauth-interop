package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
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

type rSuiteInput struct {
	RustFedPSIssuer        string `json:"rust_fed_ps_issuer"`
	RustFedASIssuer        string `json:"rust_fed_as_issuer"`
	RustIntermGoASIssuer   string `json:"rust_interm_go_as_issuer"`
	RustIntermRustASIssuer string `json:"rust_interm_rust_as_issuer"`
	RustDownGoASIssuer     string `json:"rust_down_go_as_issuer"`
	RustDownRustASIssuer   string `json:"rust_down_rust_as_issuer"`
}

func runRSuite(
	ctx context.Context,
	baseClock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in rSuiteInput,
) map[string]any {
	ctx = context.Background()
	var rClockMu sync.Mutex
	rClockNow := baseClock.Now()
	clock := aauth.ClockFunc(func() time.Time {
		rClockMu.Lock()
		defer rClockMu.Unlock()
		return rClockNow
	})
	rAdvanceClock := func(d time.Duration) {
		rClockMu.Lock()
		rClockNow = rClockNow.Add(d)
		rClockMu.Unlock()
	}
	rResetClock := func() {
		rClockMu.Lock()
		rClockNow = baseClock.Now()
		rClockMu.Unlock()
	}
	if baseTr, ok := httpClient.Transport.(*http.Transport); ok {
		tr := baseTr.Clone()
		tr.DisableKeepAlives = false
		cCopy := *httpClient
		cCopy.Transport = tr
		httpClient = &cCopy
	}

	newRKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var rIDSeq atomic.Int64
	nextRID := func() string {
		return "r-go-id-0123456789abcdef-" + strconvItoa(rIDSeq.Add(1))
	}

	rResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver rResolver")

	// =========================================================================
	// QA-R1: Breaking API Changes Migration & Store Contracts
	// =========================================================================
	r1PSKey := newRKey("r1-ps-1", 0xa1)
	_, r1MissingIssuedErr := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      "https://r1-ps.example",
		SigningKey:  r1PSKey,
		KeyResolver: rResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
		NewID:       nextRID,
		Tokens:      testutil.NewMissionStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			return issuer + "/token", nil
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-r1"}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return nil
		},
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "person-r1"}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error {
				return nil
			},
		},
	})
	r1MissingIssuedErrMsg := ""
	if r1MissingIssuedErr != nil {
		r1MissingIssuedErrMsg = r1MissingIssuedErr.Error()
	}

	r1IssuedStore := testutil.NewIssuedAuthTokenStore()
	r1LineageStore, r1ImplementsLineage := any(r1IssuedStore).(personserver.AuthTokenLineageStore)
	r1Now := clock.Now()
	r1Rec := personserver.IssuedAuthTokenRecord{
		Reference:               aauth.TokenReference{Issuer: "https://r1-ps.example", JTI: "r1-at-1"},
		Resource:                "https://r1-res.example",
		MissionS256:             "r1-mission-s256",
		CompactSHA256:           sha256.Sum256([]byte("r1-at-1-compact")),
		IssuedAt:                r1Now,
		ExpiresAt:               r1Now.Add(10 * time.Minute),
		AgentProvider:           "https://r1-ap.example",
		Agent:                   "aauth:caller@r1-ap.example",
		AgentTokenJTI:           "r1-ag-jti-1",
		AgentJKT:                "r1-ag-jkt-1",
		UpstreamTokenReference:  aauth.TokenReference{Issuer: "https://r1-as.example", JTI: "r1-up-1"},
		UpstreamTokenSHA256:     sha256.Sum256([]byte("r1-up-1-compact")),
		PresentedTokenReference: aauth.TokenReference{Issuer: "https://r1-ps.example", JTI: "r1-pt-1"},
	}
	must(r1IssuedStore.CommitIssuedAuthToken(ctx, r1Rec), "r1 CommitIssuedAuthToken")
	must(r1IssuedStore.CommitIssuedAuthToken(ctx, r1Rec), "r1 replay CommitIssuedAuthToken")
	r1LoadedRec, err := r1IssuedStore.LoadIssuedAuthToken(ctx, r1Rec.Reference)
	must(err, "r1 LoadIssuedAuthToken")
	r1ConflictRec := r1Rec
	r1ConflictRec.PresentedTokenReference.JTI = "r1-pt-other"
	r1ConflictErr := r1IssuedStore.CommitIssuedAuthToken(ctx, r1ConflictRec)
	r1LineageRecs, r1LineageErr := r1LineageStore.LoadAuthTokensIssuedAgainst(ctx, r1Rec.PresentedTokenReference)
	r1FedStore := testutil.NewFederatedAuthorizationStore()
	r1FedRec := personserver.FederatedAuthorizationRecord{
		ID:             "r1-fed-1",
		PersonServer:   "https://r1-ps.example",
		ResourceToken:  "r1-rt-1",
		AgentToken:     "r1-at-1",
		AgentIssuer:    "https://r1-ap.example",
		Agent:          "aauth:caller@r1-ap.example",
		AgentJKT:       "r1-jkt-1",
		PresentedToken: "r1-pt-1",
		UpstreamToken:  "r1-upstream-compact-jwt",
		Location:       "https://r1-as.example/pending/1",
		CreatedAt:      r1Now,
		ExpiresAt:      r1Now.Add(5 * time.Minute),
		Revision:       1,
		Response: personserver.FederatedResponse{
			Status: http.StatusAccepted,
			Header: http.Header{"Location": []string{"https://r1-as.example/pending/1"}},
			Body:   []byte(`{"status":"pending"}`),
		},
	}
	must(r1FedStore.CreateFederatedAuthorization(ctx, r1FedRec), "r1 CreateFederatedAuthorization")
	r1LoadedFed, err := r1FedStore.LoadFederatedAuthorization(ctx, "r1-fed-1")
	must(err, "r1 LoadFederatedAuthorization")
	r1MutFed := r1LoadedFed
	r1MutFed.Revision++
	r1MutFed.UpstreamToken = "r1-changed-upstream"
	r1FedImmutableErr := r1FedStore.ReplaceFederatedAuthorization(ctx, r1LoadedFed, r1MutFed)

	r1SessStore := newNMemorySessionStore()
	r1CodeGood := sha256.Sum256([]byte("R1CODE01"))
	r1CodeBad := sha256.Sum256([]byte("R1WRONG1"))
	r1PendingSess := resource.PendingSessionRecord{
		ID:                  "r1-sess-1",
		Resource:            "https://r1-res.example",
		CodeSHA256:          r1CodeGood,
		MaximumCodeAttempts: 3,
		CreatedAt:           r1Now,
		ExpiresAt:           r1Now.Add(5 * time.Minute),
	}
	must(r1SessStore.CreatePending(ctx, r1PendingSess), "r1 CreatePending")
	_, r1BadCodeErr := r1SessStore.ConsumeInteractionCode(ctx, "https://r1-res.example", "r1-sess-1", resource.SessionCodePresentation{
		CodeSHA256: r1CodeBad,
		Callback:   "https://agent.example/wrong-cb",
	}, r1Now)
	r1SnapAfterBad, err := r1SessStore.LoadPending(ctx, "r1-sess-1")
	must(err, "r1 LoadPending after bad code")
	_, r1GoodCodeErr := r1SessStore.ConsumeInteractionCode(ctx, "https://r1-res.example", "r1-sess-1", resource.SessionCodePresentation{
		CodeSHA256: r1CodeGood,
		Callback:   "https://agent.example/good-cb",
	}, r1Now)
	r1SnapAfterGood, err := r1SessStore.LoadPending(ctx, "r1-sess-1")
	must(err, "r1 LoadPending after good code")
	_, r1ReuseCodeErr := r1SessStore.ConsumeInteractionCode(ctx, "https://r1-res.example", "r1-sess-1", resource.SessionCodePresentation{
		CodeSHA256: r1CodeGood,
		Callback:   "https://agent.example/reuse-cb",
	}, r1Now)
	r1SnapAfterReuse, err := r1SessStore.LoadPending(ctx, "r1-sess-1")
	must(err, "r1 LoadPending after reuse code")

	// =========================================================================
	// QA-R2: All-Go 4-Party Call Chaining Over Real HTTPS (3 Hops, Missions,
	// Chained Waits, Root PersonToken & AgentToken Revocation)
	// =========================================================================
	const (
		r2CallerAPIssuer  = "https://r2-caller-ap.example"
		r2CallerAgentID   = "aauth:caller@r2-caller-ap.example"
		r2OrdersIssuer    = "https://r2-orders.example"
		r2OrdersAgentID   = "aauth:worker@r2-orders.example"
		r2InventoryIssuer = "https://r2-inventory.example"
		r2InvAgentID      = "aauth:worker@r2-inventory.example"
		r2WarehouseIssuer = "https://r2-warehouse.example"
		r2OrdersASIssuer  = "https://r2-orders-as.example"
		r2StockASIssuer   = "https://r2-stock-as.example"
		r2PSIssuer        = "https://r2-ps.example"
	)

	r2CallerAPKey := newRKey("r2-caller-ap-1", 0xb1)
	r2CallerAgKey := newRKey("r2-caller-ag-1", 0xb2)
	r2OrdersResKey := newRKey("r2-orders-res-1", 0xb3)
	r2OrdersAPKey := newRKey("r2-orders-ap-1", 0xb4)
	r2OrdersAgKey := newRKey("r2-orders-ag-1", 0xb5)
	r2InvResKey := newRKey("r2-inv-res-1", 0xb6)
	r2InvAPKey := newRKey("r2-inv-ap-1", 0xb7)
	r2InvAgKey := newRKey("r2-inv-ag-1", 0xb8)
	r2WhResKey := newRKey("r2-wh-res-1", 0xb9)
	r2OrdersASKey := newRKey("r2-orders-as-1", 0xba)
	r2StockASKey := newRKey("r2-stock-as-1", 0xbb)
	r2PSKey := newRKey("r2-ps-1", 0xbc)

	r2CallerAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     r2CallerAPIssuer,
		SigningKey: r2CallerAPKey,
		Clock:      clock,
		NewID:      nextRID,
	})
	must(err, "r2CallerAP")
	r2CallerAPSrv, _ := registerTLS("r2-caller-ap.example", r2CallerAP.Handler())
	defer r2CallerAPSrv.Close()

	r2CallerTok1, err := r2CallerAP.Issue(aauth.AgentTokenRequest{
		Agent:        r2CallerAgentID,
		PersonServer: r2PSIssuer,
		PublicKey:    r2CallerAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "r2CallerTok1")
	r2CallerClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r2CallerAgentID,
		AgentToken:  r2CallerTok1,
		SigningKey:  r2CallerAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r2CallerClient")
	var (
		r2Mu               sync.Mutex
		r2HoldStock        bool
		r2StockRateLimit   bool
		r2ChainedBindings  []personserver.PersonTokenRequest
		r2ChainedConsents  []personserver.AuthorizationRequest
		r2AccessRequests   []accessserver.AuthorizationRequest
		r2MissionCompleted int
	)

	r2Admit := func(context.Context, string) error { return nil }

	r2OrdersAS, err := accessserver.New(accessserver.Config{
		Issuer:      r2OrdersASIssuer,
		SigningKey:  r2OrdersASKey,
		KeyResolver: rResolver,
		Clock:       clock,
		NewID:       nextRID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == r2PSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			r2Mu.Lock()
			r2AccessRequests = append(r2AccessRequests, req)
			r2Mu.Unlock()
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Minute},
		Revocation: &accessserver.RevocationConfig{
			Revocations:  testutil.NewTokenRevocationStore(),
			IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient:   httpClient,
			Admit:        r2Admit,
		},
	})
	must(err, "r2OrdersAS")
	r2OrdersASSrv, _ := registerTLS("r2-orders-as.example", r2OrdersAS.Handler())
	defer r2OrdersASSrv.Close()

	r2StockAS, err := accessserver.New(accessserver.Config{
		Issuer:      r2StockASIssuer,
		SigningKey:  r2StockASKey,
		KeyResolver: rResolver,
		Clock:       clock,
		NewID:       nextRID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == r2PSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			r2Mu.Lock()
			r2AccessRequests = append(r2AccessRequests, req)
			hold := r2HoldStock
			r2Mu.Unlock()
			if hold {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{RetryAfter: time.Second}}, nil
			}
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Minute},
		Revocation: &accessserver.RevocationConfig{
			Revocations:  testutil.NewTokenRevocationStore(),
			IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient:   httpClient,
			Admit:        r2Admit,
		},
	})
	must(err, "r2StockAS")
	r2StockASMux := http.NewServeMux()
	r2StockASMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r2Mu.Lock()
		rl := r2StockRateLimit
		r2Mu.Unlock()
		if rl && r.Method == http.MethodPost && r.URL.Path == "/revoke" {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"type":"about:blank","title":"Too Many Requests","status":429,"error":"rate_limited"}`)
			return
		}
		r2StockAS.Handler().ServeHTTP(w, r)
	})
	r2StockASSrv, _ := registerTLS("r2-stock-as.example", r2StockASMux)
	defer r2StockASSrv.Close()

	makeR2FedRes := func(issuer, host, asIssuer, scope string, resKey jose.SigningKey, apKey *jose.SigningKey) *httptest.Server {
		res, rErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer:            issuer,
			AccessServer:      asIssuer,
			SigningKey:        resKey,
			KeyResolver:       rResolver,
			Clock:             clock,
			NewID:             nextRID,
			ScopeDescriptions: map[string]string{scope: scope, scope + ".extra": scope + ".extra"},
			RequiredScopes:    func(*http.Request) []string { return []string{scope} },
			ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
			Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, _ := resource.AuthPrincipalFromContext(r.Context())
				_, _ = io.WriteString(w, "served "+p.Subject)
			}),
			AuthTokenStatuses: testutil.NewAuthTokenStatusStore(),
			Revocation: &resource.RevocationConfig{
				PersonTokens: testutil.NewTokenRevocationStore(),
				HTTPClient:   httpClient,
				Admit:        r2Admit,
			},
		})
		must(rErr, "makeR2FedRes "+issuer)
		mux := http.NewServeMux()
		if apKey != nil {
			ap, aErr := agentprovider.New(agentprovider.Config{
				Issuer:     issuer,
				SigningKey: *apKey,
				Clock:      clock,
				NewID:      nextRID,
			})
			must(aErr, "agentprovider "+issuer)
			mux.Handle("GET /.well-known/aauth-agent.json", ap.Handler())
			mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"keys": []jose.JWK{resKey.PublicJWK(), apKey.PublicJWK()},
				})
			})
		}
		mux.Handle("/", res.Handler())
		srv, _ := registerTLS(host, mux)
		return srv
	}
	r2OrdersSrv := makeR2FedRes(r2OrdersIssuer, "r2-orders.example", r2OrdersASIssuer, "orders.fulfill", r2OrdersResKey, &r2OrdersAPKey)
	defer r2OrdersSrv.Close()
	r2InvSrv := makeR2FedRes(r2InventoryIssuer, "r2-inventory.example", r2StockASIssuer, "inventory.reserve", r2InvResKey, &r2InvAPKey)
	defer r2InvSrv.Close()
	r2WhSrv := makeR2FedRes(r2WarehouseIssuer, "r2-warehouse.example", r2StockASIssuer, "warehouse.pick", r2WhResKey, nil)
	defer r2WhSrv.Close()

	r2OrdersTok, err := aauth.MintAgentToken(r2OrdersIssuer, r2OrdersAPKey, aauth.AgentTokenRequest{
		Agent:        r2OrdersAgentID,
		PersonServer: "https://r2-relay-own-ps.example",
		PublicKey:    r2OrdersAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, clock.Now(), "r2-orders-ag-tok-1")
	must(err, "r2OrdersTok")
	r2OrdersRelay, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r2OrdersAgentID,
		AgentToken:  r2OrdersTok,
		SigningKey:  r2OrdersAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r2OrdersRelay")

	r2InvTok, err := aauth.MintAgentToken(r2InventoryIssuer, r2InvAPKey, aauth.AgentTokenRequest{
		Agent:        r2InvAgentID,
		PersonServer: "https://r2-relay-own-ps.example",
		PublicKey:    r2InvAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, clock.Now(), "r2-inv-ag-tok-1")
	must(err, "r2InvTok")
	r2InvRelay, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r2InvAgentID,
		AgentToken:  r2InvTok,
		SigningKey:  r2InvAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r2InvRelay")

	r2Directed := func(res string) string { return "person-at-" + strings.TrimPrefix(res, "https://") }
	r2MissionExpiry := clock.Now().Add(15 * time.Minute)
	r2PSIssuedStore := testutil.NewIssuedAuthTokenStore()
	r2PS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:       r2PSIssuer,
		SigningKey:   r2PSKey,
		KeyResolver:  rResolver,
		Clock:        clock,
		NewID:        nextRID,
		HTTPClient:   httpClient,
		Tokens:       testutil.NewMissionStore(),
		IssuedTokens: r2PSIssuedStore,
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			return issuer + "/token", nil
		},
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: r2Directed(req.Resource), Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				r2Mu.Lock()
				r2ChainedBindings = append(r2ChainedBindings, req)
				r2Mu.Unlock()
				return personserver.Person{Subject: r2Directed(req.Resource), Lifetime: time.Hour}, nil
			},
			Consent: func(_ context.Context, req personserver.AuthorizationRequest) error {
				r2Mu.Lock()
				r2ChainedConsents = append(r2ChainedConsents, req)
				r2Mu.Unlock()
				return nil
			},
		},
		Deferred: &personserver.FederatedDeferredConfig{
			Store:    testutil.NewFederatedAuthorizationStore(),
			Lifetime: 30 * time.Minute,
		},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(),
			HTTPClient:  httpClient,
			Admit:       r2Admit,
			Hold:        2 * time.Second,
		},
		AgentTokenRevocations: testutil.NewTokenRevocationStore(),
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, req personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{
					Description:       req.Proposal.Description,
					ApprovedResources: req.Proposal.Resources,
					ExpiresAt:         &r2MissionExpiry,
				}, nil
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
				r2Mu.Lock()
				r2MissionCompleted++
				r2Mu.Unlock()
				return nil
			},
		},
	})
	must(err, "r2PS")
	r2PSSrv, _ := registerTLS("r2-ps.example", r2PS.Handler())
	defer r2PSSrv.Close()

	r2CallProtected := func(ag *clientagent.Client, origin, authTok, upstreamTok string) (int, string, error) {
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/work", nil)
		must(rErr, "NewRequest "+origin)
		resp, dErr := ag.Do(ctx, clientagent.Call{Request: req, AuthToken: authTok, UpstreamToken: upstreamTok})
		if dErr != nil {
			var sigErr *signaturekey.Error
			if errors.As(dErr, &sigErr) {
				return http.StatusUnauthorized, string(sigErr.Code), dErr
			}
			var prob *aauth.ProblemError
			if errors.As(dErr, &prob) {
				return prob.Status, string(prob.Code), dErr
			}
			return 0, dErr.Error(), dErr
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), nil
	}
	// 1) 3-Hop All-Go 4-Party Call Chain over real HTTPS exchanges
	r2Hop1PTRes, err := r2CallerClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: r2PSIssuer,
		Resource:     r2OrdersIssuer,
	})
	must(err, "r2Hop1PTRes")
	r2Hop1PT, _ := r2Hop1PTRes.Token()
	r2Hop1RT, err := r2CallerClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r2OrdersIssuer,
		PersonToken: r2Hop1PT,
		Scopes:      []string{"orders.fulfill"},
	})
	must(err, "r2Hop1RT")
	r2Hop1AT, err := r2CallerClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r2PSIssuer,
		ResourceToken:  r2Hop1RT,
		PresentedToken: r2Hop1PT,
	})
	must(err, "r2Hop1AT")
	r2Hop1CallStatus, r2Hop1CallBody, _ := r2CallProtected(r2CallerClient, r2OrdersIssuer, r2Hop1AT, "")

	r2Hop2PTRes, err := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2InventoryIssuer,
		UpstreamToken: r2Hop1AT,
	})
	must(err, "r2Hop2PTRes")
	r2Hop2PT, _ := r2Hop2PTRes.Token()
	r2Hop2RT, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2Hop2PT,
		UpstreamToken: r2Hop1AT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2Hop2RT")
	r2Hop2AT, err := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2Hop2RT,
		PresentedToken: r2Hop2PT,
		UpstreamToken:  r2Hop1AT,
	})
	must(err, "r2Hop2AT")
	r2Hop2CallStatus, r2Hop2CallBody, _ := r2CallProtected(r2OrdersRelay, r2InventoryIssuer, r2Hop2AT, r2Hop1AT)

	r2Hop2ATClaims, err := aauth.VerifyAuthToken(ctx, r2Hop2AT, rResolver, clock)
	must(err, "VerifyAuthToken r2Hop2AT")

	// Step-up tying through receipt on Hop 2: presenting r2Hop2AT for step-up
	r2Hop1RTAlt, err := r2CallerClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r2OrdersIssuer,
		PersonToken: r2Hop1PT,
		Scopes:      []string{"orders.fulfill"},
	})
	must(err, "r2Hop1RTAlt")
	r2Hop1ATAlt, err := r2CallerClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r2PSIssuer,
		ResourceToken:  r2Hop1RTAlt,
		PresentedToken: r2Hop1PT,
	})
	must(err, "r2Hop1ATAlt")
	r2OrdersAgJKT, _ := r2OrdersAgKey.PublicJWK().Thumbprint()
	r2StepUpRT, err := aauth.MintResourceToken(r2InvResKey, aauth.ResourceTokenClaims{
		Issuer:       r2InventoryIssuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     r2StockASIssuer,
		PersonServer: r2PSIssuer,
		Subject:      r2Hop2ATClaims.Subject,
		JTI:          "r2-inv-stepup-rt-1",
		PresentedJTI: r2Hop2ATClaims.JTI,
		AgentJKT:     r2OrdersAgJKT,
		Scope:        "inventory.reserve inventory.reserve.extra",
		IssuedAt:     clock.Now().Unix(),
		ExpiresAt:    clock.Now().Add(4 * time.Minute).Unix(),
	})
	must(err, "r2StepUpRT")
	_, r2StepUpOmitErr := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2StepUpRT,
		PresentedToken: r2Hop2AT,
		UpstreamToken:  r2Hop1ATAlt,
	})
	var r2StepUpOmitProb *aauth.ProblemError
	r2StepUpOmitStatus := 0
	r2StepUpOmitCode := ""
	if errors.As(r2StepUpOmitErr, &r2StepUpOmitProb) {
		r2StepUpOmitStatus = r2StepUpOmitProb.Status
		r2StepUpOmitCode = string(r2StepUpOmitProb.Code)
	}
	r2StepUpRT2, err := aauth.MintResourceToken(r2InvResKey, aauth.ResourceTokenClaims{
		Issuer:       r2InventoryIssuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     r2StockASIssuer,
		PersonServer: r2PSIssuer,
		Subject:      r2Hop2ATClaims.Subject,
		JTI:          "r2-inv-stepup-rt-2",
		PresentedJTI: r2Hop2ATClaims.JTI,
		AgentJKT:     r2OrdersAgJKT,
		Scope:        "inventory.reserve inventory.reserve.extra",
		IssuedAt:     clock.Now().Unix(),
		ExpiresAt:    clock.Now().Add(4 * time.Minute).Unix(),
	})
	must(err, "r2StepUpRT2")
	r2StepUpOKAT, r2StepUpOKErr := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2StepUpRT2,
		PresentedToken: r2Hop2AT,
		UpstreamToken:  r2Hop1AT,
	})

	r2Hop3PTRes, err := r2InvRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2WarehouseIssuer,
		UpstreamToken: r2Hop2AT,
	})
	must(err, "r2Hop3PTRes")
	r2Hop3PT, _ := r2Hop3PTRes.Token()
	r2Hop3RT, err := r2InvRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2WarehouseIssuer,
		PersonToken:   r2Hop3PT,
		UpstreamToken: r2Hop2AT,
		Scopes:        []string{"warehouse.pick"},
	})
	must(err, "r2Hop3RT")
	r2Hop3AT, err := r2InvRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2Hop3RT,
		PresentedToken: r2Hop3PT,
		UpstreamToken:  r2Hop2AT,
	})
	must(err, "r2Hop3AT")
	r2Hop3CallStatus, r2Hop3CallBody, _ := r2CallProtected(r2InvRelay, r2WarehouseIssuer, r2Hop3AT, r2Hop2AT)

	r2Hop1PTClaims, err := aauth.VerifyPersonToken(ctx, r2Hop1PT, rResolver, clock)
	must(err, "VerifyPersonToken r2Hop1PT")
	r2Hop1ATClaims, err := aauth.VerifyAuthToken(ctx, r2Hop1AT, rResolver, clock)
	must(err, "VerifyAuthToken r2Hop1AT")
	r2Hop2PTClaims, err := aauth.VerifyPersonToken(ctx, r2Hop2PT, rResolver, clock)
	must(err, "VerifyPersonToken r2Hop2PT")
	r2Hop3PTClaims, err := aauth.VerifyPersonToken(ctx, r2Hop3PT, rResolver, clock)
	must(err, "VerifyPersonToken r2Hop3PT")
	r2Hop3ATClaims, err := aauth.VerifyAuthToken(ctx, r2Hop3AT, rResolver, clock)
	must(err, "VerifyAuthToken r2Hop3AT")

	// Revoke root PersonToken (r2Hop1PT) and verify cascade across all 3 hops
	r2RevokeRes, err := r2PS.RevokePersonToken(ctx, r2Hop1PTClaims.JTI)
	must(err, "RevokePersonToken r2Hop1PT")
	r2Hop1AfterRevStatus, r2Hop1AfterRevCode, _ := r2CallProtected(r2CallerClient, r2OrdersIssuer, r2Hop1AT, "")
	r2Hop2AfterRevStatus, r2Hop2AfterRevCode, _ := r2CallProtected(r2OrdersRelay, r2InventoryIssuer, r2Hop2AT, r2Hop1AT)
	r2Hop3AfterRevStatus, r2Hop3AfterRevCode, _ := r2CallProtected(r2InvRelay, r2WarehouseIssuer, r2Hop3AT, r2Hop2AT)

	_, r2ChainAfterRevErr := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2InventoryIssuer,
		UpstreamToken: r2Hop1AT,
	})
	var r2ChainAfterRevProb *aauth.ProblemError
	r2ChainAfterRevStatus := 0
	r2ChainAfterRevCode := ""
	if errors.As(r2ChainAfterRevErr, &r2ChainAfterRevProb) {
		r2ChainAfterRevStatus = r2ChainAfterRevProb.Status
		r2ChainAfterRevCode = string(r2ChainAfterRevProb.Code)
	}
	// 2) Chained wait at Access Server ending in approval, then second wait ending in revocation
	r2WaitCallerPTRes, err := r2CallerClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: r2PSIssuer,
		Resource:     r2OrdersIssuer,
	})
	must(err, "r2WaitCallerPTRes")
	r2WaitCallerPT, _ := r2WaitCallerPTRes.Token()
	r2WaitCallerRT, err := r2CallerClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r2OrdersIssuer,
		PersonToken: r2WaitCallerPT,
		Scopes:      []string{"orders.fulfill"},
	})
	must(err, "r2WaitCallerRT")
	r2WaitCallerAT, err := r2CallerClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r2PSIssuer,
		ResourceToken:  r2WaitCallerRT,
		PresentedToken: r2WaitCallerPT,
	})
	must(err, "r2WaitCallerAT")
	r2WaitCallerPTClaims, err := aauth.VerifyPersonToken(ctx, r2WaitCallerPT, rResolver, clock)
	must(err, "VerifyPersonToken r2WaitCallerPT")

	r2WaitInvPTRes, err := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2InventoryIssuer,
		UpstreamToken: r2WaitCallerAT,
	})
	must(err, "r2WaitInvPTRes")
	r2WaitInvPT, _ := r2WaitInvPTRes.Token()
	r2WaitInvRT1, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2WaitInvPT,
		UpstreamToken: r2WaitCallerAT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2WaitInvRT1")

	r2Mu.Lock()
	r2HoldStock = true
	r2Mu.Unlock()
	_, r2WaitExErr := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2WaitInvRT1,
		PresentedToken: r2WaitInvPT,
		UpstreamToken:  r2WaitCallerAT,
	})
	var r2PendingExErr *clientagent.PendingExchangeError
	r2WaitGotPending := errors.As(r2WaitExErr, &r2PendingExErr)
	r2Waiting1 := r2PendingExErr.Pending()
	r2Poll1Still, err := r2OrdersRelay.PollExchange(ctx, r2Waiting1)
	must(err, "r2Poll1Still")
	_, r2Poll1StillPending := r2Poll1Still.Pending()

	r2Mu.Lock()
	r2HoldStock = false
	r2Mu.Unlock()
	rAdvanceClock(2 * time.Second)
	r2Ref1 := r2Waiting1.Location()[strings.LastIndex(r2Waiting1.Location(), "/")+1:]
	must(r2PS.AdvanceFederation(ctx, r2Ref1), "AdvanceFederation r2Ref1")
	r2Delivered1, err := r2OrdersRelay.PollExchange(ctx, r2Waiting1)
	must(err, "r2Delivered1")
	r2WaitApprovedAT, r2WaitApprovedOK := r2Delivered1.Token()

	// Second chained wait: revoke caller's PersonToken while waiting -> 403 revoked -> 410 Gone
	r2Mu.Lock()
	r2HoldStock = true
	r2Mu.Unlock()
	r2WaitInvRT2, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2WaitInvPT,
		UpstreamToken: r2WaitCallerAT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2WaitInvRT2")
	r2Begun2, err := r2OrdersRelay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2WaitInvRT2,
		PresentedToken: r2WaitInvPT,
		UpstreamToken:  r2WaitCallerAT,
	})
	must(err, "r2Begun2")
	r2Waiting2, _ := r2Begun2.Pending()
	_, err = r2PS.RevokePersonToken(ctx, r2WaitCallerPTClaims.JTI)
	must(err, "RevokePersonToken r2WaitCallerPT")
	_, r2PollRevErr := r2OrdersRelay.PollExchange(ctx, r2Waiting2)
	var r2PollRevProb *aauth.ProblemError
	r2PollRevStatus := 0
	r2PollRevCode := ""
	r2PollRevDetail := ""
	if errors.As(r2PollRevErr, &r2PollRevProb) {
		r2PollRevStatus = r2PollRevProb.Status
		r2PollRevCode = string(r2PollRevProb.Code)
		r2PollRevDetail = r2PollRevProb.Detail
	}
	_, r2PollGoneErr := r2OrdersRelay.PollExchange(ctx, r2Waiting2)
	var r2PollGoneProb *aauth.ProblemError
	r2PollGoneStatus := 0
	if errors.As(r2PollGoneErr, &r2PollGoneProb) {
		r2PollGoneStatus = r2PollGoneProb.Status
	}
	r2Mu.Lock()
	r2HoldStock = false
	r2Mu.Unlock()
	// 3) Mission carried through 4-party Go chain + mission-bound wait + mission termination
	r2PropRes, err := r2CallerClient.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: r2PSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# Fulfil Order 99",
			Resources:   []string{r2OrdersIssuer, r2InventoryIssuer},
		},
	})
	must(err, "r2PropRes")
	r2Mission := r2PropRes.Mission()
	r2MissOrdersPT, _ := r2PropRes.PersonToken(r2OrdersIssuer)
	r2MissOrdersRT, err := r2CallerClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r2OrdersIssuer,
		PersonToken: r2MissOrdersPT,
		Scopes:      []string{"orders.fulfill"},
	})
	must(err, "r2MissOrdersRT")
	r2MissOrdersRTClaims, err := aauth.VerifyResourceToken(ctx, r2MissOrdersRT, rResolver, clock)
	must(err, "VerifyResourceToken r2MissOrdersRT")
	r2MissOrdersAT, err := r2CallerClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r2PSIssuer,
		ResourceToken:  r2MissOrdersRT,
		PresentedToken: r2MissOrdersPT,
	})
	must(err, "r2MissOrdersAT")
	r2MissOrdersATClaims, err := aauth.VerifyAuthToken(ctx, r2MissOrdersAT, rResolver, clock)
	must(err, "VerifyAuthToken r2MissOrdersAT")

	// Chained hop under mission
	r2MissInvPTRes, err := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2InventoryIssuer,
		UpstreamToken: r2MissOrdersAT,
	})
	must(err, "r2MissInvPTRes")
	r2MissInvPT, _ := r2MissInvPTRes.Token()
	r2MissInvPTClaims, err := aauth.VerifyPersonToken(ctx, r2MissInvPT, rResolver, clock)
	must(err, "VerifyPersonToken r2MissInvPT")
	r2MissInvRT, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2MissInvPT,
		UpstreamToken: r2MissOrdersAT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2MissInvRT")
	r2MissInvAT, err := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2MissInvRT,
		PresentedToken: r2MissInvPT,
		UpstreamToken:  r2MissOrdersAT,
	})
	must(err, "r2MissInvAT")
	r2MissInvATClaims, err := aauth.VerifyAuthToken(ctx, r2MissInvAT, rResolver, clock)
	must(err, "VerifyAuthToken r2MissInvAT")

	// Intermediary naming its own mission_s256 alongside upstream_token is refused
	_, r2IntermOwnMissErr := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2WarehouseIssuer,
		UpstreamToken: r2MissOrdersAT,
		MissionS256:   r2Mission.S256,
	})

	// Chained mission-bound wait that ends in 403 mission_terminated ("completed") then 410 Gone
	r2Mu.Lock()
	r2HoldStock = true
	r2Mu.Unlock()
	r2MissWaitRT, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2MissInvPT,
		UpstreamToken: r2MissOrdersAT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2MissWaitRT")
	r2MissBegun, err := r2OrdersRelay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2MissWaitRT,
		PresentedToken: r2MissInvPT,
		UpstreamToken:  r2MissOrdersAT,
	})
	must(err, "r2MissBegun")
	r2MissWaiting, _ := r2MissBegun.Pending()
	must(r2CallerClient.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: r2PSIssuer,
		MissionS256:  r2Mission.S256,
		Summary:      "Order 99 fulfilled",
	}), "CompleteMission r2Mission")
	_, r2MissTermErr := r2OrdersRelay.PollExchange(ctx, r2MissWaiting)
	var r2MissTermProb *aauth.ProblemError
	r2MissTermStatus := 0
	r2MissTermCode := ""
	r2MissTermReason := ""
	if errors.As(r2MissTermErr, &r2MissTermProb) {
		r2MissTermStatus = r2MissTermProb.Status
		r2MissTermCode = string(r2MissTermProb.Code)
		r2MissTermReason = r2MissTermProb.TerminationReason
	}
	_, r2MissGoneErr := r2OrdersRelay.PollExchange(ctx, r2MissWaiting)
	var r2MissGoneProb *aauth.ProblemError
	r2MissGoneStatus := 0
	if errors.As(r2MissGoneErr, &r2MissGoneProb) {
		r2MissGoneStatus = r2MissGoneProb.Status
	}
	r2Mu.Lock()
	r2HoldStock = false
	r2Mu.Unlock()
	// 4) Agent token revocation cascade with 202 RevocationPendingError then 200 OK
	r2AgRevPTRes, err := r2CallerClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: r2PSIssuer,
		Resource:     r2OrdersIssuer,
	})
	must(err, "r2AgRevPTRes")
	r2AgRevPT, _ := r2AgRevPTRes.Token()
	r2AgRevRT, err := r2CallerClient.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r2OrdersIssuer,
		PersonToken: r2AgRevPT,
		Scopes:      []string{"orders.fulfill"},
	})
	must(err, "r2AgRevRT")
	r2AgRevAT, err := r2CallerClient.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r2PSIssuer,
		ResourceToken:  r2AgRevRT,
		PresentedToken: r2AgRevPT,
	})
	must(err, "r2AgRevAT")
	r2AgRevChainPTRes, err := r2OrdersRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r2InventoryIssuer,
		UpstreamToken: r2AgRevAT,
	})
	must(err, "r2AgRevChainPTRes")
	r2AgRevChainPT, _ := r2AgRevChainPTRes.Token()
	r2AgRevChainRT, err := r2OrdersRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r2InventoryIssuer,
		PersonToken:   r2AgRevChainPT,
		UpstreamToken: r2AgRevAT,
		Scopes:        []string{"inventory.reserve"},
	})
	must(err, "r2AgRevChainRT")
	r2AgRevChainAT, err := r2OrdersRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r2AgRevChainRT,
		PresentedToken: r2AgRevChainPT,
		UpstreamToken:  r2AgRevAT,
	})
	must(err, "r2AgRevChainAT")

	r2Revoker, err := agentprovider.NewRevocationClient(agentprovider.RevocationClientConfig{
		Provider:   r2CallerAP,
		HTTPClient: httpClient,
		Admit:      r2Admit,
	})
	must(err, "r2Revoker")
	r2CallerTokClaims, err := aauth.VerifyAgentToken(ctx, r2CallerTok1, rResolver, clock)
	must(err, "VerifyAgentToken r2CallerTok1")
	r2AgRevReq := aauth.RevocationRequest{
		Reference: aauth.TokenReference{Issuer: r2CallerAPIssuer, JTI: r2CallerTokClaims.JTI},
		ExpiresAt: time.Unix(r2CallerTokClaims.ExpiresAt, 0),
	}
	r2Mu.Lock()
	r2StockRateLimit = true
	r2Mu.Unlock()
	r2AgRev202Err := r2Revoker.RevokeAgentToken(ctx, r2PSIssuer, r2AgRevReq)
	var r2AgRevPendingErr *agentprovider.RevocationPendingError
	r2AgRevGot202 := errors.As(r2AgRev202Err, &r2AgRevPendingErr)
	r2AgRevPendingLoc := ""
	if r2AgRevGot202 {
		r2AgRevPendingLoc = r2AgRevPendingErr.Location
	}
	r2Mu.Lock()
	r2StockRateLimit = false
	r2Mu.Unlock()
	rAdvanceClock(2 * time.Second)
	r2AgRev200Err := r2Revoker.RevokeAgentToken(ctx, r2PSIssuer, r2AgRevReq)
	r2AgRevHop1Status, r2AgRevHop1Code, _ := r2CallProtected(r2CallerClient, r2OrdersIssuer, r2AgRevAT, "")
	r2AgRevHop2Status, r2AgRevHop2Code, _ := r2CallProtected(r2OrdersRelay, r2InventoryIssuer, r2AgRevChainAT, r2AgRevAT)

	// =========================================================================
	// QA-R3: Cross-Language 4-Party Call Chaining & Chain Revocation
	// (aauth-go 8a3734dd <-> aauth-rust v0.1.0-alpha.16)
	// =========================================================================
	rResetClock()
	// Pre-warm rResolver for Rust servers while their single-worker TlsServers are idle
	_, err = rResolver.ResolveKey(ctx, "https://r3-rust-ap.example", aauth.AgentDiscoveryDocument, "r3-rust-ap-1")
	must(err, "rResolver warm r3-rust-ap")
	_, err = rResolver.ResolveKey(ctx, in.RustFedPSIssuer, aauth.PersonDiscoveryDocument, "r3-rust-ps-1")
	must(err, "rResolver warm r3-rust-ps")
	_, err = rResolver.ResolveKey(ctx, in.RustFedASIssuer, aauth.AccessDiscoveryDocument, "r3-rust-as-1")
	must(err, "rResolver warm r3-rust-as")
	_, err = rResolver.ResolveKey(ctx, in.RustIntermGoASIssuer, aauth.AgentDiscoveryDocument, "r3-rust-ig-1")
	must(err, "rResolver warm r3-rust-ig-ag")
	_, err = rResolver.ResolveKey(ctx, in.RustIntermGoASIssuer, aauth.ResourceDiscoveryDocument, "r3-rust-ig-1")
	must(err, "rResolver warm r3-rust-ig-res")
	_, err = rResolver.ResolveKey(ctx, in.RustIntermRustASIssuer, aauth.AgentDiscoveryDocument, "r3-rust-ir-1")
	must(err, "rResolver warm r3-rust-ir-ag")
	_, err = rResolver.ResolveKey(ctx, in.RustIntermRustASIssuer, aauth.ResourceDiscoveryDocument, "r3-rust-ir-1")
	must(err, "rResolver warm r3-rust-ir-res")
	_, err = rResolver.ResolveKey(ctx, in.RustDownGoASIssuer, aauth.ResourceDiscoveryDocument, "r3-rust-dg-1")
	must(err, "rResolver warm r3-rust-dg")
	_, err = rResolver.ResolveKey(ctx, in.RustDownRustASIssuer, aauth.ResourceDiscoveryDocument, "r3-rust-dr-1")
	must(err, "rResolver warm r3-rust-dr")

	const (
		r3GoAPIssuer           = "https://r3-go-ap.example"
		r3GoCallerID           = "aauth:caller@r3-go-ap.example"
		r3GoFedPSIssuer        = "https://r3-go-fed-ps.example"
		r3GoASIssuer           = "https://r3-go-as.example"
		r3GoIntermGoASIssuer   = "https://r3-go-interm-go-as.example"
		r3GoIntermGoASAgID     = "aauth:worker@r3-go-interm-go-as.example"
		r3GoIntermRustASIssuer = "https://r3-go-interm-rust-as.example"
		r3GoIntermRustASAgID   = "aauth:worker@r3-go-interm-rust-as.example"
		r3GoDownGoASIssuer     = "https://r3-go-down-go-as.example"
		r3GoDownRustASIssuer   = "https://r3-go-down-rust-as.example"
	)

	r3GoAPKey := newRKey("r3-go-ap-1", 0xc1)
	r3GoCallerKey := newRKey("r3-go-caller-1", 0xc2)
	r3GoPSKey := newRKey("r3-go-ps-1", 0xc3)
	r3GoASKey := newRKey("r3-go-as-1", 0xc4)
	r3GoIGKey := newRKey("r3-go-ig-1", 0xc5)
	r3GoIGAgKey := newRKey("r3-go-ig-ag-1", 0xc6)
	r3GoIRKey := newRKey("r3-go-ir-1", 0xc7)
	r3GoIRAgKey := newRKey("r3-go-ir-ag-1", 0xc8)
	r3GoDGKey := newRKey("r3-go-dg-1", 0xc9)
	r3GoDRKey := newRKey("r3-go-dr-1", 0xca)

	r3GoAP, err := agentprovider.New(agentprovider.Config{
		Issuer:     r3GoAPIssuer,
		SigningKey: r3GoAPKey,
		Clock:      clock,
		NewID:      nextRID,
	})
	must(err, "r3GoAP")
	r3GoAPSrv, r3GoAPDER := registerTLS("r3-go-ap.example", r3GoAP.Handler())
	_ = r3GoAPSrv
	var (
		r3ASRequireInteraction atomic.Bool
		r3CopyUpstreamSub      atomic.Bool
	)
	r3GoAS, err := accessserver.New(accessserver.Config{
		Issuer:      r3GoASIssuer,
		SigningKey:  r3GoASKey,
		KeyResolver: rResolver,
		Clock:       clock,
		NewID:       nextRID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss == r3GoFedPSIssuer || iss == in.RustFedPSIssuer {
				return nil
			}
			return accessserver.ErrAccessDenied
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{Store: testutil.NewAccessAuthorizationStore(), Lifetime: 30 * time.Minute},
		Revocation: &accessserver.RevocationConfig{
			Revocations:  testutil.NewTokenRevocationStore(),
			IssuedTokens: testutil.NewAccessIssuedAuthTokenStore(),
			HTTPClient:   httpClient,
			Admit:        r2Admit,
		},
	})
	must(err, "r3GoAS")
	r3GoASSrv, r3GoASDER := registerTLS("r3-go-as.example", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/token" && r3ASRequireInteraction.Load() {
			w.Header().Set("Location", r3GoASIssuer+"/pending/r3-as-int-1")
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("AAuth-Requirement", `requirement=interaction; url="`+r3GoASIssuer+`/interact/1"; code="2345-6789"`)
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
			return
		}
		if r.Method == http.MethodDelete && r.URL.Path == "/pending/r3-as-int-1" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r3GoAS.Handler().ServeHTTP(w, r)
	}))
	_ = r3GoASSrv

	makeR3FedRes := func(issuer, host, asIssuer string, key jose.SigningKey, isInterm bool) (*httptest.Server, []byte) {
		res, rErr := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
			Issuer:            issuer,
			AccessServer:      asIssuer,
			SigningKey:        key,
			KeyResolver:       rResolver,
			Clock:             clock,
			NewID:             nextRID,
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
			AuthTokenStatuses: testutil.NewAuthTokenStatusStore(),
			Revocation: &resource.RevocationConfig{
				PersonTokens: testutil.NewTokenRevocationStore(),
				HTTPClient:   httpClient,
				Admit:        r2Admit,
			},
		})
		must(rErr, "makeR3FedRes "+issuer)
		mux := http.NewServeMux()
		if isInterm {
			ap, aErr := agentprovider.New(agentprovider.Config{
				Issuer:     issuer,
				SigningKey: key,
				Clock:      clock,
				NewID:      nextRID,
			})
			must(aErr, "agentprovider "+issuer)
			mux.Handle("GET /.well-known/aauth-agent.json", ap.Handler())
		}
		mux.Handle("/", res.Handler())
		return registerTLS(host, mux)
	}

	r3GoIGSrv, r3GoIGDER := makeR3FedRes(r3GoIntermGoASIssuer, "r3-go-interm-go-as.example", r3GoASIssuer, r3GoIGKey, true)
	r3GoIRSrv, r3GoIRDER := makeR3FedRes(r3GoIntermRustASIssuer, "r3-go-interm-rust-as.example", in.RustFedASIssuer, r3GoIRKey, true)
	r3GoDGSrv, r3GoDGDER := makeR3FedRes(r3GoDownGoASIssuer, "r3-go-down-go-as.example", r3GoASIssuer, r3GoDGKey, false)
	r3GoDRSrv, r3GoDRDER := makeR3FedRes(r3GoDownRustASIssuer, "r3-go-down-rust-as.example", in.RustFedASIssuer, r3GoDRKey, false)
	_, _, _, _ = r3GoIGSrv, r3GoIRSrv, r3GoDGSrv, r3GoDRSrv

	r3Directed := func(res string) string { return "r3-person-at-" + strings.TrimPrefix(res, "https://") }
	r3MissionExp := clock.Now().Add(20 * time.Minute)
	r3GoFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:       r3GoFedPSIssuer,
		SigningKey:   r3GoPSKey,
		KeyResolver:  rResolver,
		Clock:        clock,
		NewID:        nextRID,
		HTTPClient:   httpClient,
		Tokens:       testutil.NewMissionStore(),
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		AccessServerEndpoint: func(_ context.Context, issuer string) (string, error) {
			return issuer + "/token", nil
		},
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: r3Directed(req.Resource), Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		CallChaining: &personserver.FederatedCallChainingConfig{
			BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
				if r3CopyUpstreamSub.Load() && req.Upstream != nil {
					return personserver.Person{Subject: req.Upstream.Subject, Lifetime: 20 * time.Minute}, nil
				}
				return personserver.Person{Subject: r3Directed(req.Resource), Lifetime: 20 * time.Minute}, nil
			},
			Consent: func(context.Context, personserver.AuthorizationRequest) error { return nil },
		},
		Deferred: &personserver.FederatedDeferredConfig{
			Store:    testutil.NewFederatedAuthorizationStore(),
			Lifetime: 30 * time.Minute,
		},
		TokenRevocation: &personserver.TokenRevocationConfig{
			Revocations: testutil.NewTokenRevocationStore(),
			HTTPClient:  httpClient,
			Admit:       r2Admit,
			Hold:        2 * time.Second,
		},
		AgentTokenRevocations: testutil.NewTokenRevocationStore(),
		Missions: &personserver.MissionConfig{
			Approve: func(_ context.Context, req personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				return personserver.MissionDecision{
					Description:       req.Proposal.Description,
					ApprovedResources: req.Proposal.Resources,
					ExpiresAt:         &r3MissionExp,
				}, nil
			},
		},
	})
	must(err, "r3GoFedPS")
	r3CallerTok, err := r3GoAP.Issue(aauth.AgentTokenRequest{
		Agent:        r3GoCallerID,
		PersonServer: r3GoFedPSIssuer,
		PublicKey:    r3GoCallerKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "r3CallerTok")
	r3CallerClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r3GoCallerID,
		AgentToken:  r3CallerTok,
		SigningKey:  r3GoCallerKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r3CallerClient")

	r3IGTok, err := aauth.MintAgentToken(r3GoIntermGoASIssuer, r3GoIGKey, aauth.AgentTokenRequest{
		Agent:        r3GoIntermGoASAgID,
		PersonServer: "https://r3-relay-own-ps.example",
		PublicKey:    r3GoIGAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, clock.Now(), "r3-ig-ag-tok-1")
	must(err, "r3IGTok")
	r3IGRelay, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r3GoIntermGoASAgID,
		AgentToken:  r3IGTok,
		SigningKey:  r3GoIGAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r3IGRelay")

	r3IRTok, err := aauth.MintAgentToken(r3GoIntermRustASIssuer, r3GoIRKey, aauth.AgentTokenRequest{
		Agent:        r3GoIntermRustASAgID,
		PersonServer: "https://r3-relay-own-ps.example",
		PublicKey:    r3GoIRAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, clock.Now(), "r3-ir-ag-tok-1")
	must(err, "r3IRTok")
	r3IRRelay, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r3GoIntermRustASAgID,
		AgentToken:  r3IRTok,
		SigningKey:  r3GoIRAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r3IRRelay")

	r3HopWith := func(ag *clientagent.Client, psIss, resIss, upstreamTok, missionS256 string) (string, string, string, int, map[string]any, error) {
		var pt string
		if upstreamTok == "" {
			ptRes, pErr := ag.PersonToken(ctx, clientagent.PersonTokenRequest{
				PersonServer: psIss,
				Resource:     resIss,
				MissionS256:  missionS256,
			})
			if pErr != nil {
				return "", "", "", 0, nil, pErr
			}
			pt, _ = ptRes.Token()
		} else {
			ptRes, pErr := ag.PersonToken(ctx, clientagent.PersonTokenRequest{
				Resource:      resIss,
				UpstreamToken: upstreamTok,
			})
			if pErr != nil {
				return "", "", "", 0, nil, pErr
			}
			pt, _ = ptRes.Token()
		}
		rt, aErr := ag.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource:      resIss,
			PersonToken:   pt,
			UpstreamToken: upstreamTok,
			Scopes:        []string{"records.read"},
		})
		if aErr != nil {
			return pt, "", "", 0, nil, aErr
		}
		at, eErr := ag.Exchange(ctx, clientagent.ExchangeRequest{
			PersonServer:   psIss,
			ResourceToken:  rt,
			PresentedToken: pt,
			UpstreamToken:  upstreamTok,
		})
		if eErr != nil {
			return pt, rt, "", 0, nil, eErr
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, resIss+"/records", nil)
		resp, dErr := ag.Do(ctx, clientagent.Call{Request: req, AuthToken: at, UpstreamToken: upstreamTok})
		if dErr != nil {
			var prob *aauth.ProblemError
			if errors.As(dErr, &prob) {
				return pt, rt, at, prob.Status, map[string]any{"error": prob.Code}, dErr
			}
			return pt, rt, at, 0, nil, dErr
		}
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return pt, rt, at, resp.StatusCode, body, nil
	}

	r3GoFedPSMux := http.NewServeMux()
	r3GoFedPSMux.HandleFunc("POST /__r3-go-revoke-pt", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			JTI string `json:"jti"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		res, revErr := r3GoFedPS.RevokePersonToken(r.Context(), body.JTI)
		w.Header().Set("Content-Type", "application/json")
		if revErr != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": revErr.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "attempts": len(res.Attempts)})
	})
	r3GoFedPSMux.HandleFunc("POST /__r3-go-chain-hop", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Interm      string `json:"interm"`
			Downstream  string `json:"downstream"`
			UpstreamTok string `json:"upstream_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		relay := r3IGRelay
		if body.Interm == "rust_as" {
			relay = r3IRRelay
		}
		pt, rt, at, st, callBody, hErr := r3HopWith(relay, "", body.Downstream, body.UpstreamTok, "")
		w.Header().Set("Content-Type", "application/json")
		if hErr != nil {
			var prob *aauth.ProblemError
			pSt, pCode := 0, hErr.Error()
			if errors.As(hErr, &prob) {
				pSt, pCode = prob.Status, string(prob.Code)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "status": pSt, "error": pCode})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "person_token": pt, "resource_token": rt, "auth_token": at,
			"call_status": st, "call_body": callBody,
		})
	})
	r3GoFedPSMux.HandleFunc("POST /__r3-go-call", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Interm      string `json:"interm"`
			Origin      string `json:"origin"`
			AuthToken   string `json:"auth_token"`
			UpstreamTok string `json:"upstream_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ag := r3CallerClient
		if body.Interm == "go_as" {
			ag = r3IGRelay
		} else if body.Interm == "rust_as" {
			ag = r3IRRelay
		}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, body.Origin+"/records", nil)
		resp, dErr := ag.Do(r.Context(), clientagent.Call{Request: req, AuthToken: body.AuthToken, UpstreamToken: body.UpstreamTok})
		w.Header().Set("Content-Type", "application/json")
		if dErr != nil {
			var sigErr *signaturekey.Error
			if errors.As(dErr, &sigErr) {
				_ = json.NewEncoder(w).Encode(map[string]any{"status": http.StatusUnauthorized, "error": string(sigErr.Code)})
				return
			}
			var prob *aauth.ProblemError
			pSt, pCode := 0, dErr.Error()
			if errors.As(dErr, &prob) {
				pSt, pCode = prob.Status, string(prob.Code)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": pSt, "error": pCode})
			return
		}
		defer resp.Body.Close()
		var cb map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&cb)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": resp.StatusCode, "body": cb})
	})
	r3GoFedPSMux.Handle("/", r3GoFedPS.Handler())
	r3GoFedPSSrv, r3GoFedPSDER := registerTLS("r3-go-fed-ps.example", r3GoFedPSMux)
	_ = r3GoFedPSSrv

	// Direction 1 (No Mission): Caller -> Hop 1 Go Intermediary (behind Go AS & Rust AS) -> Go Federated PS -> Hop 2 Rust Downstream (behind Rust AS & Go AS)
	r3D1NoMissHop1PT, _, r3D1NoMissHop1AT, r3D1NoMissHop1St, _, err := r3HopWith(r3CallerClient, r3GoFedPSIssuer, r3GoIntermGoASIssuer, "", "")
	must(err, "r3D1NoMissHop1")
	_, _, r3D1NoMissHop2RustASAT, r3D1NoMissHop2RustASSt, _, err := r3HopWith(r3IGRelay, "", in.RustDownRustASIssuer, r3D1NoMissHop1AT, "")
	must(err, "r3D1NoMissHop2RustAS")
	_, _, r3D1NoMissHop2GoASAT, r3D1NoMissHop2GoASSt, _, err := r3HopWith(r3IGRelay, "", in.RustDownGoASIssuer, r3D1NoMissHop1AT, "")
	must(err, "r3D1NoMissHop2GoAS")

	// Also Hop 1 behind Rust AS -> Go Federated PS -> Hop 2 Rust Downstream
	_, _, r3D1RustASHop1AT, r3D1RustASHop1St, _, err := r3HopWith(r3CallerClient, r3GoFedPSIssuer, r3GoIntermRustASIssuer, "", "")
	must(err, "r3D1RustASHop1")
	_, _, _, r3D1RustASHop2St, _, err := r3HopWith(r3IRRelay, "", in.RustDownRustASIssuer, r3D1RustASHop1AT, "")
	must(err, "r3D1RustASHop2")

	// Cross-language root PersonToken revocation at Go Federated PS cascades to Go & Rust AS/Resources
	r3D1NoMissHop1PTClaims, err := aauth.VerifyPersonToken(ctx, r3D1NoMissHop1PT, rResolver, clock)
	must(err, "VerifyPersonToken r3D1NoMissHop1PT")
	_, err = r3GoFedPS.RevokePersonToken(ctx, r3D1NoMissHop1PTClaims.JTI)
	must(err, "RevokePersonToken r3D1NoMissHop1PT")
	r3D1AfterRevHop1St, r3D1AfterRevHop1Code, _ := r2CallProtected(r3CallerClient, r3GoIntermGoASIssuer, r3D1NoMissHop1AT, "")
	r3D1AfterRevHop2RustASSt, r3D1AfterRevHop2RustASCode, _ := r2CallProtected(r3IGRelay, in.RustDownRustASIssuer, r3D1NoMissHop2RustASAT, r3D1NoMissHop1AT)
	r3D1AfterRevHop2GoASSt, r3D1AfterRevHop2GoASCode, _ := r2CallProtected(r3IGRelay, in.RustDownGoASIssuer, r3D1NoMissHop2GoASAT, r3D1NoMissHop1AT)

	// Direction 1 (With Mission): ProposeMission at r3GoFedPS -> Hop 1 -> Hop 2 (Rust Downstream behind Rust AS & Go AS)
	r3PropRes, err := r3CallerClient.ProposeMission(ctx, clientagent.MissionRequest{
		PersonServer: r3GoFedPSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# Cross-Language 4-Party Chain Mission",
			Resources: []string{
				r3GoIntermGoASIssuer, r3GoIntermRustASIssuer,
				in.RustDownGoASIssuer, in.RustDownRustASIssuer,
			},
		},
	})
	must(err, "r3PropRes")
	r3GoMission := r3PropRes.Mission()
	_, _, r3D1MissHop1AT, r3D1MissHop1St, _, err := r3HopWith(r3CallerClient, r3GoFedPSIssuer, r3GoIntermGoASIssuer, "", r3GoMission.S256)
	must(err, "r3D1MissHop1")
	_, _, r3D1MissHop2RustASAT, r3D1MissHop2RustASSt, r3D1MissHop2RustASBody, err := r3HopWith(r3IGRelay, "", in.RustDownRustASIssuer, r3D1MissHop1AT, "")
	must(err, "r3D1MissHop2RustAS")
	r3D1MissHop2Claims, err := aauth.VerifyAuthToken(ctx, r3D1MissHop2RustASAT, rResolver, clock)
	must(err, "VerifyAuthToken r3D1MissHop2RustASAT")

	// Mixed-deployment boundary checks on r3GoFedPS:
	// 1) AS requirement=interaction -> Go 4-party PS refuses with 500 server_error
	_, _, r3BndHop1AT, _, _, err := r3HopWith(r3CallerClient, r3GoFedPSIssuer, r3GoIntermGoASIssuer, "", "")
	must(err, "r3BndHop1")
	r3BndPTRes, err := r3IGRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r3GoDownGoASIssuer,
		UpstreamToken: r3BndHop1AT,
	})
	must(err, "r3BndPTRes")
	r3BndPT, _ := r3BndPTRes.Token()
	r3BndRT, err := r3IGRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r3GoDownGoASIssuer,
		PersonToken:   r3BndPT,
		UpstreamToken: r3BndHop1AT,
		Scopes:        []string{"records.read"},
	})
	must(err, "r3BndRT")
	r3BndRT2, err := r3IGRelay.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:      r3GoDownGoASIssuer,
		PersonToken:   r3BndPT,
		UpstreamToken: r3BndHop1AT,
		Scopes:        []string{"records.read"},
	})
	must(err, "r3BndRT2")
	r3ASRequireInteraction.Store(true)
	_, r3BndASIntErr := r3IGRelay.Exchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r3BndRT,
		PresentedToken: r3BndPT,
		UpstreamToken:  r3BndHop1AT,
	})
	r3BndASIntRelayed, err := r3IGRelay.BeginExchange(ctx, clientagent.ExchangeRequest{
		ResourceToken:  r3BndRT2,
		PresentedToken: r3BndPT,
		UpstreamToken:  r3BndHop1AT,
		Capabilities:   []string{"interaction"},
	})
	must(err, "r3BndASIntRelayed")
	r3ASRequireInteraction.Store(false)
	var r3BndASIntProb *aauth.ProblemError
	r3BndASIntSt, r3BndASIntCode := 0, ""
	if errors.As(r3BndASIntErr, &r3BndASIntProb) {
		r3BndASIntSt, r3BndASIntCode = r3BndASIntProb.Status, string(r3BndASIntProb.Code)
	}
	r3BndASIntWaiting, r3BndASIntWaitingOK := r3BndASIntRelayed.Pending()
	r3BndASIntRelayOK := r3BndASIntWaitingOK &&
		r3BndASIntWaiting.Requirement() == aauth.RequirementInteraction &&
		r3BndASIntWaiting.InteractionURL() == r3GoASIssuer+"/interact/1" &&
		r3BndASIntWaiting.InteractionCode() == "2345-6789" &&
		strings.HasPrefix(r3BndASIntWaiting.Location(), r3GoFedPSIssuer+"/token/federated/")
	// 2) Sub-agent intermediary (parent_agent set) -> 500 server_error in Go
	r3SubAgKey := newRKey("r3-subag-1", 0xcb)
	r3SubAgTok, err := aauth.MintAgentToken(r3GoIntermGoASIssuer, r3GoIGKey, aauth.AgentTokenRequest{
		Agent:        "aauth:worker+child@r3-go-interm-go-as.example",
		ParentAgent:  r3GoIntermGoASAgID,
		PersonServer: "https://r3-relay-own-ps.example",
		PublicKey:    r3SubAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, clock.Now(), "r3-subag-tok-1")
	must(err, "r3SubAgTok")
	r3SubAgClient, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  "aauth:worker+child@r3-go-interm-go-as.example",
		AgentToken:  r3SubAgTok,
		SigningKey:  r3SubAgKey,
		HTTPClient:  httpClient,
		KeyResolver: rResolver,
		Clock:       clock,
	})
	must(err, "r3SubAgClient")
	_, r3BndSubAgErr := r3SubAgClient.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r3GoDownGoASIssuer,
		UpstreamToken: r3BndHop1AT,
	})
	_ = r3BndSubAgErr
	r3SubAgBody, _ := json.Marshal(map[string]string{
		"resource":       r3GoDownGoASIssuer,
		"upstream_token": r3BndHop1AT,
	})
	r3SubAgReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, r3GoFedPSIssuer+"/person", bytes.NewReader(r3SubAgBody))
	r3SubAgReq.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignJWTRequest(r3SubAgReq, r3SubAgKey, r3SubAgTok, clock), "SignJWTRequest r3SubAgReq")
	r3SubAgResp, err := httpClient.Do(r3SubAgReq)
	must(err, "Do r3SubAgReq")
	var r3SubAgOut map[string]any
	_ = json.NewDecoder(r3SubAgResp.Body).Decode(&r3SubAgOut)
	_ = r3SubAgResp.Body.Close()
	r3BndSubAgSt := r3SubAgResp.StatusCode
	r3BndSubAgCode, _ := r3SubAgOut["error"].(string)

	// 3) Policy copying upstream sub -> 500 server_error in Go
	r3CopyUpstreamSub.Store(true)
	_, r3BndCopySubErr := r3IGRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r3GoDownGoASIssuer,
		UpstreamToken: r3BndHop1AT,
	})
	r3CopyUpstreamSub.Store(false)
	var r3BndCopySubProb *aauth.ProblemError
	r3BndCopySubSt, r3BndCopySubCode := 0, ""
	if errors.As(r3BndCopySubErr, &r3BndCopySubProb) {
		r3BndCopySubSt, r3BndCopySubCode = r3BndCopySubProb.Status, string(r3BndCopySubProb.Code)
	}

	// 4) Hand-minted AS upstream_token with no delivery receipt at Go Federated PS -> 400 invalid_upstream_token
	r3CallerJKT, _ := r3GoCallerKey.PublicJWK().Thumbprint()
	r3UnrecASAT, err := aauth.MintAuthToken(r3GoASKey, aauth.AuthTokenClaims{
		Issuer:       r3GoASIssuer,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     r3GoIntermGoASIssuer,
		JTI:          "r3-unrecorded-as-at-1",
		PersonServer: r3GoFedPSIssuer,
		Subject:      "r3-person-at-r3-go-interm-go-as.example",
		IssuedAt:     clock.Now().Unix(),
		ExpiresAt:    clock.Now().Add(10 * time.Minute).Unix(),
		Scope:        "records.read",
		Confirmation: aauth.Confirmation{JWK: r3GoCallerKey.PublicJWK()},
	})
	must(err, "r3UnrecASAT")
	_ = r3CallerJKT
	_, r3BndUnrecErr := r3IGRelay.PersonToken(ctx, clientagent.PersonTokenRequest{
		Resource:      r3GoDownGoASIssuer,
		UpstreamToken: r3UnrecASAT,
	})
	var r3BndUnrecProb *aauth.ProblemError
	r3BndUnrecSt, r3BndUnrecCode := 0, ""
	if errors.As(r3BndUnrecErr, &r3BndUnrecProb) {
		r3BndUnrecSt, r3BndUnrecCode = r3BndUnrecProb.Status, string(r3BndUnrecProb.Code)
	}

	// =========================================================================
	// QA-R4: Shared agent.Pending[T] Polling Across All 11 Deferred Agent Flows
	// Over Real HTTPS
	// =========================================================================
	const (
		r4APIssuer  = "https://r4-ap.example"
		r4AgentID   = "aauth:caller@r4-ap.example"
		r4PSIssuer  = "https://r4-ps.example"
		r4ResIssuer = "https://r4-res.example"
	)
	r4APKey := newRKey("r4-ap-1", 0xd1)
	r4AgKey := newRKey("r4-ag-1", 0xd2)
	r4DurableKey := newRKey("r4-durable-1", 0xd3)
	r4EphemKey := newRKey("r4-ephem-1", 0xd4)
	r4ChildKey := newRKey("r4-child-1", 0xd5)
	r4PSKey := newRKey("r4-ps-1", 0xd6)
	r4ResKey := newRKey("r4-res-1", 0xd7)

	r4NowMu := sync.Mutex{}
	r4Now := clock.Now()
	r4Clock := aauth.ClockFunc(func() time.Time {
		r4NowMu.Lock()
		defer r4NowMu.Unlock()
		return r4Now
	})
	r4Advance := func(d time.Duration) {
		r4NowMu.Lock()
		r4Now = r4Now.Add(d)
		r4NowMu.Unlock()
	}
	r4Resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   r4Clock,
		Admit:                   r2Admit,
	})
	must(err, "r4Resolver")
	type r4DeferStage struct {
		mu       sync.Mutex
		polls    int
		deleted  bool
		lastPref string
		lastSch  string
		answers  []string
		terminal func(w http.ResponseWriter, r *http.Request)
	}
	r4Stages := map[string]*r4DeferStage{}
	r4StagesMu := sync.Mutex{}
	newR4Stage := func(id string, term func(w http.ResponseWriter, r *http.Request)) *r4DeferStage {
		st := &r4DeferStage{terminal: term}
		r4StagesMu.Lock()
		r4Stages[id] = st
		r4StagesMu.Unlock()
		return st
	}
	writeR4202 := func(w http.ResponseWriter, loc, retryAfter, status, reqHdr string, extra map[string]any) {
		w.Header().Set("Location", loc)
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Cache-Control", "no-store")
		if reqHdr != "" {
			w.Header().Set("AAuth-Requirement", reqHdr)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		body := map[string]any{"status": status}
		for k, v := range extra {
			body[k] = v
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	serveR4Pending := func(w http.ResponseWriter, r *http.Request, id string) {
		r4StagesMu.Lock()
		st := r4Stages[id]
		r4StagesMu.Unlock()
		if st == nil {
			http.Error(w, "unknown pending "+id, http.StatusNotFound)
			return
		}
		if prep, pErr := signaturekey.PrepareRequest(r, r4Clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{
				signaturekey.SchemeJWT,
				signaturekey.SchemeHWK,
				signaturekey.SchemeJKTJWT,
			},
		}); pErr == nil {
			st.mu.Lock()
			st.lastSch = string(prep.Credential().Scheme())
			st.mu.Unlock()
		}
		if r.Method == http.MethodDelete {
			st.mu.Lock()
			st.deleted = true
			st.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost {
			var body struct {
				Action                string `json:"action"`
				ClarificationResponse string `json:"clarification_response"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			st.mu.Lock()
			st.answers = append(st.answers, body.ClarificationResponse)
			st.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		st.mu.Lock()
		st.polls++
		pNum := st.polls
		st.lastPref = r.Header.Get("Prefer")
		term := st.terminal
		st.mu.Unlock()
		switch pNum {
		case 1:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"type":"about:blank","title":"Too Many Requests","status":429,"error":"slow_down"}`)
		case 2:
			writeR4202(w, "/pending/"+id, "0", "interacting", "", nil)
		case 3:
			w.Header().Set("Retry-After", "3")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"type":"about:blank","title":"Service Unavailable","status":503,"error":"temporarily_unavailable"}`)
		default:
			w.Header().Set("Cache-Control", "no-store")
			term(w, r)
		}
	}

	r4IntHdr, err := aauth.FormatInteractionRequirement(aauth.InteractionRequirement{
		URL:  "https://interact.example/review",
		Code: "2345-6789",
	})
	must(err, "FormatInteractionRequirement")

	r4APMux := http.NewServeMux()
	r4APMux.HandleFunc("GET /.well-known/aauth-agent.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   r4APIssuer,
			"jwks_uri": r4APIssuer + "/.well-known/jwks.json",
		})
	})
	r4APMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{r4APKey.PublicJWK()},
		})
	})
	r4APMux.HandleFunc("POST /subagents", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/subagent", "2", "pending", r4IntHdr, nil)
	})
	r4APMux.HandleFunc("POST /enroll", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/enroll", "2", "pending", r4IntHdr, nil)
	})
	var r4RefreshMode atomic.Int32
	r4APMux.HandleFunc("POST /refresh", func(w http.ResponseWriter, _ *http.Request) {
		if r4RefreshMode.Load() == 1 {
			writeR4202(w, "/pending/refresh-single", "2", "pending", r4IntHdr, nil)
			return
		}
		writeR4202(w, "/pending/refresh-jkt", "2", "pending", r4IntHdr, nil)
	})
	r4APMux.HandleFunc("/pending/", func(w http.ResponseWriter, r *http.Request) {
		serveR4Pending(w, r, strings.TrimPrefix(r.URL.Path, "/pending/"))
	})
	r4APSrv, _ := registerTLS("r4-ap.example", r4APMux)
	defer r4APSrv.Close()
	r4MissS256 := aauth.MissionS256([]byte("r4-approved-mission"))
	r4UpdS256 := aauth.MissionS256([]byte("r4-updated-mission"))

	var r4PSClarifyMode atomic.Bool
	r4PSMux := http.NewServeMux()
	r4PSMux.HandleFunc("GET /.well-known/aauth-person.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                r4PSIssuer,
			"jwks_uri":              r4PSIssuer + "/.well-known/jwks.json",
			"person_token_endpoint": r4PSIssuer + "/person",
			"auth_token_endpoint":   r4PSIssuer + "/token",
			"mission_endpoint":      r4PSIssuer + "/missions",
			"audit_endpoint":        r4PSIssuer + "/audit",
		})
	})
	r4PSMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{r4PSKey.PublicJWK()},
		})
	})
	r4PSMux.HandleFunc("POST /missions/"+r4MissS256, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["summary"] != nil {
			if r4PSClarifyMode.Load() {
				writeR4202(w, "/pending/mission-complete-clarify", "0", "pending", "requirement=clarification", map[string]any{
					"clarification": "Did you archive the receipt?",
					"timeout":       60,
					"options":       []string{"yes", "no"},
				})
				return
			}
			writeR4202(w, "/pending/mission-complete", "2", "pending", r4IntHdr, nil)
			return
		}
		writeR4202(w, "/pending/mission-update", "2", "pending", r4IntHdr, nil)
	})
	r4PSMux.HandleFunc("POST /audit", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/audit", "2", "pending", r4IntHdr, nil)
	})
	r4PSMux.HandleFunc("/pending/", func(w http.ResponseWriter, r *http.Request) {
		serveR4Pending(w, r, strings.TrimPrefix(r.URL.Path, "/pending/"))
	})
	r4PSSrv, _ := registerTLS("r4-ps.example", r4PSMux)
	defer r4PSSrv.Close()

	var r4AuthMode atomic.Int32
	r4ResMux := http.NewServeMux()
	r4ResMux.HandleFunc("GET /.well-known/aauth-resource.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 r4ResIssuer,
			"jwks_uri":               r4ResIssuer + "/.well-known/jwks.json",
			"authorization_endpoint": r4ResIssuer + "/authorize",
			"scope_descriptions":     map[string]string{"records.read": "Read records"},
		})
	})
	r4ResMux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{r4ResKey.PublicJWK()},
		})
	})
	r4ResMux.HandleFunc("POST /authorize", func(w http.ResponseWriter, _ *http.Request) {
		if r4AuthMode.Load() == 1 {
			writeR4202(w, "/pending/auth-session", "2", "pending", r4IntHdr, nil)
			return
		}
		writeR4202(w, "/pending/auth-rt", "2", "pending", r4IntHdr, nil)
	})
	r4ResMux.HandleFunc("POST /events/subscribe", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/ev-pub", "2", "pending", r4IntHdr, nil)
	})
	r4ResMux.HandleFunc("POST /events/tickets/t-1", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/ev-prot", "2", "pending", r4IntHdr, nil)
	})
	r4ResMux.HandleFunc("/pending/", func(w http.ResponseWriter, r *http.Request) {
		serveR4Pending(w, r, strings.TrimPrefix(r.URL.Path, "/pending/"))
	})
	r4ResSrv, _ := registerTLS("r4-res.example", r4ResMux)
	defer r4ResSrv.Close()

	r4AgTok, err := aauth.MintAgentToken(r4APIssuer, r4APKey, aauth.AgentTokenRequest{
		Agent:        r4AgentID,
		PersonServer: r4PSIssuer,
		PublicKey:    r4AgKey.PublicJWK(),
		Lifetime:     time.Hour,
	}, r4Clock.Now(), "r4-ag-tok-1")
	must(err, "r4AgTok")
	r4Client, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r4AgentID,
		AgentToken:  r4AgTok,
		SigningKey:  r4AgKey,
		HTTPClient:  httpClient,
		KeyResolver: r4Resolver,
		Clock:       r4Clock,
		Events:      &clientagent.EventsConfig{Store: newGoAgentEventStore()},
	})
	must(err, "r4Client")
	r4DrivePending := func(pending any, stage *r4DeferStage, pollFn func(wait time.Duration) (any, bool, *clientagent.Pending[any], error)) bool {
		_ = pending
		_ = stage
		return true
	}
	_ = r4DrivePending

	// Generic driver helper over clientagent.Result[T]
	r4RunFlow := func(id string, term func(w http.ResponseWriter, r *http.Request), run func(st *r4DeferStage) bool) (bool, string) {
		st := newR4Stage(id, term)
		ok := run(st)
		st.mu.Lock()
		sch := st.lastSch
		st.mu.Unlock()
		return ok, sch
	}

	// Flow 1: Mission Update (BeginMissionUpdate + UpdateMission -> *PendingError)
	r4Flow1OK, r4Flow1Sch := r4RunFlow("mission-update", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(aauth.MissionUpdateResponse{S256: r4UpdS256})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginMissionUpdate(ctx, clientagent.MissionUpdateRequest{
			PersonServer: r4PSIssuer, MissionS256: r4MissS256, Description: "Updated scope",
		})
		must(bErr, "BeginMissionUpdate")
		pend, ok := res.Pending()
		if !ok || pend.RetryAfter() != 2*time.Second || pend.InteractionCode() != "2345-6789" {
			return false
		}
		var early *clientagent.PollTooEarlyError
		if _, pErr := pend.Poll(ctx, clientagent.PollOptions{}); !errors.As(pErr, &early) {
			return false
		}
		r4Advance(2 * time.Second)
		r1, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "flow1 poll1 429")
		p1, _ := r1.Pending()
		if p1.RetryAfter() != 7*time.Second {
			return false
		}
		r4Advance(7 * time.Second)
		r2, pErr := p1.Poll(ctx, clientagent.PollOptions{Wait: 30 * time.Second})
		must(pErr, "flow1 poll2 interacting")
		p2, _ := r2.Pending()
		if !p2.Interacting() {
			return false
		}
		r3, pErr := p2.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "flow1 poll3 503")
		p3, _ := r3.Pending()
		if p3.RetryAfter() != 3*time.Second {
			return false
		}
		r4Advance(3 * time.Second)
		r4, pErr := p3.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "flow1 poll4 terminal")
		val, done := r4.Value()
		if !done || val.S256() != r4UpdS256 {
			return false
		}
		if _, finErr := p3.Poll(ctx, clientagent.PollOptions{}); !errors.Is(finErr, clientagent.ErrPendingFinished) {
			return false
		}
		_, immErr := r4Client.UpdateMission(ctx, clientagent.MissionUpdateRequest{
			PersonServer: r4PSIssuer, MissionS256: r4MissS256, Description: "Updated again",
		})
		var pendErr *clientagent.PendingError[clientagent.MissionUpdateResult]
		return errors.As(immErr, &pendErr)
	})

	// Flow 2: Mission Completion + Clarification before/after deadline + Pending.Cancel
	r4Flow2OK, _ := r4RunFlow("mission-complete", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}, func(st *r4DeferStage) bool {
		immErr := r4Client.CompleteMission(ctx, clientagent.MissionCompletionRequest{
			PersonServer: r4PSIssuer, MissionS256: r4MissS256, Summary: "Done",
		})
		var pendErr *clientagent.PendingError[clientagent.MissionCompletionResult]
		if !errors.As(immErr, &pendErr) {
			return false
		}
		pend := pendErr.Pending()
		r4Advance(2 * time.Second)
		if cErr := pend.Cancel(ctx); cErr != nil {
			return false
		}
		_, afterCancelErr := pend.Poll(ctx, clientagent.PollOptions{})
		return errors.Is(afterCancelErr, clientagent.ErrPendingFinished) && st.deleted
	})

	r4PSClarifyMode.Store(true)
	r4Flow2ClarifyOK, _ := r4RunFlow("mission-complete-clarify", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginMissionCompletion(ctx, clientagent.MissionCompletionRequest{
			PersonServer: r4PSIssuer, MissionS256: r4MissS256, Summary: "Completed with receipt",
		})
		must(bErr, "BeginMissionCompletion clarify")
		pend, _ := res.Pending()
		q, hasQ := pend.Clarification()
		if !hasQ || q.Question() != "Did you archive the receipt?" {
			return false
		}
		if aErr := pend.AnswerClarification(ctx, "yes"); aErr != nil {
			return false
		}
		r4Advance(61 * time.Second)
		lateErr := pend.AnswerClarification(ctx, "no")
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Poll clarify terminal")
		val, done := termRes.Value()
		return lateErr != nil && done && val.MissionS256() == r4MissS256 && len(st.answers) == 1 && st.answers[0] == "yes"
	})
	r4PSClarifyMode.Store(false)
	// Flow 3: Audit (BeginAudit + SubmitAudit)
	r4Flow3OK, _ := r4RunFlow("audit", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{})
	}, func(st *r4DeferStage) bool {
		entry := aauth.AuditEntry{
			MissionS256: r4MissS256,
			Action:      "WebSearch",
			Description: "Searched inventory records.",
			Parameters:  json.RawMessage(`{"q":"item-1"}`),
			Result:      json.RawMessage(`{"found":1}`),
		}
		res, bErr := r4Client.BeginAudit(ctx, clientagent.AuditRequest{
			PersonServer: r4PSIssuer, Entry: entry,
		})
		must(bErr, "BeginAudit")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Audit Poll")
		_, done := termRes.Value()
		immErr := r4Client.SubmitAudit(ctx, clientagent.AuditRequest{
			PersonServer: r4PSIssuer, Entry: entry,
		})
		var pendErr *clientagent.PendingError[clientagent.AuditResult]
		return done && errors.As(immErr, &pendErr)
	})

	// Mint PersonToken + ResourceToken for Flow 4 & Flow 5
	r4AgJKT, _ := r4AgKey.PublicJWK().Thumbprint()
	r4PT, err := aauth.MintPersonToken(r4PSKey, aauth.PersonTokenClaims{
		Issuer:       r4PSIssuer,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     r4ResIssuer,
		Subject:      "person-r4",
		JTI:          "r4-pt-1",
		IssuedAt:     r4Clock.Now().Unix(),
		ExpiresAt:    r4Clock.Now().Add(30 * time.Minute).Unix(),
		Confirmation: aauth.Confirmation{JWK: r4AgKey.PublicJWK()},
	})
	must(err, "r4PT")
	r4RT, err := aauth.MintResourceToken(r4ResKey, aauth.ResourceTokenClaims{
		Issuer:       r4ResIssuer,
		DWK:          aauth.ResourceDiscoveryDocument,
		Audience:     r4PSIssuer,
		JTI:          "r4-rt-1",
		AgentJKT:     r4AgJKT,
		IssuedAt:     r4Clock.Now().Unix(),
		ExpiresAt:    r4Clock.Now().Add(30 * time.Minute).Unix(),
		Scope:        "records.read",
		PersonServer: r4PSIssuer,
		Subject:      "person-r4",
		PresentedJTI: "r4-pt-1",
	})
	must(err, "r4RT")

	// Flow 4: /authorize with resource token
	r4AuthMode.Store(0)
	r4Flow4OK, _ := r4RunFlow("auth-rt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"resource_token": r4RT})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginAuthorize(ctx, clientagent.AuthorizeRequest{
			Resource: r4ResIssuer, PersonToken: r4PT, Scopes: []string{"records.read"},
		})
		must(bErr, "BeginAuthorize rt")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Authorize Poll rt")
		val, done := termRes.Value()
		rtTok, hasRT := val.ResourceToken()
		_, immErr := r4Client.Authorize(ctx, clientagent.AuthorizeRequest{
			Resource: r4ResIssuer, PersonToken: r4PT, Scopes: []string{"records.read"},
		})
		var pendErr *clientagent.PendingError[clientagent.AuthorizationResult]
		return done && hasRT && rtTok == r4RT && errors.As(immErr, &pendErr)
	})

	// Flow 5: /authorize with Resource-managed session (AAuth-Access)
	r4AuthMode.Store(1)
	r4Flow5OK, _ := r4RunFlow("auth-session", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("AAuth-Access", "r4-opaque-session-tok-1")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "scope": "records.read"})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginAuthorize(ctx, clientagent.AuthorizeRequest{
			Resource: r4ResIssuer, PersonToken: r4PT, Scopes: []string{"records.read"},
		})
		must(bErr, "BeginAuthorize session")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Authorize Poll session")
		val, done := termRes.Value()
		sess, hasSess := val.Session()
		return done && hasSess && sess.Token() == "r4-opaque-session-tok-1" && sess.Resource() == r4ResIssuer
	})
	// Flow 6: Sub-agent token (BeginSubagentToken + RequestSubagentToken)
	r4ChildTok, err := aauth.MintAgentToken(r4APIssuer, r4APKey, aauth.AgentTokenRequest{
		Agent:        "aauth:caller+review@r4-ap.example",
		ParentAgent:  r4AgentID,
		PersonServer: r4PSIssuer,
		PublicKey:    r4ChildKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	}, r4Clock.Now(), "r4-child-tok-1")
	must(err, "r4ChildTok")
	r4Flow6OK, _ := r4RunFlow("subagent", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_token": r4ChildTok})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginSubagentToken(ctx, clientagent.SubagentTokenRequest{
			Endpoint: r4APIssuer + "/subagents", PublicKey: r4ChildKey.PublicJWK(),
		})
		must(bErr, "BeginSubagentToken")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Subagent Poll")
		val, done := termRes.Value()
		_, immErr := r4Client.RequestSubagentToken(ctx, clientagent.SubagentTokenRequest{
			Endpoint: r4APIssuer + "/subagents", PublicKey: r4ChildKey.PublicJWK(),
		})
		var pendErr *clientagent.PendingError[string]
		return done && val == r4ChildTok && errors.As(immErr, &pendErr)
	})

	// Flow 7: Public and Protected event subscriptions
	r4SubTok, err := events.MintSubscribeToken(r4APIssuer, r4APKey, events.SubscribeTokenRequest{
		Agent:           r4AgentID,
		Resource:        r4ResIssuer,
		ConfirmationKey: r4AgKey.PublicJWK(),
		EventID:         "r4-ev-1",
		Lifetime:        time.Hour,
	}, r4Clock.Now())
	must(err, "r4SubTok")
	r4Flow7PubOK, _ := r4RunFlow("ev-pub", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginPublicSubscription(ctx, clientagent.PublicSubscriptionInput{
			Endpoint: r4ResIssuer + "/events/subscribe", SubscribeToken: r4SubTok, Context: []byte(`{"topic":"orders"}`),
		})
		must(bErr, "BeginPublicSubscription")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "EvPub Poll")
		val, done := termRes.Value()
		return done && val.EventID == "r4-ev-1" && val.Resource == r4ResIssuer
	})
	r4Flow7ProtOK, _ := r4RunFlow("ev-prot", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, func(st *r4DeferStage) bool {
		res, bErr := r4Client.BeginProtectedSubscription(ctx, clientagent.ProtectedSubscriptionInput{
			TicketURL: r4ResIssuer + "/events/tickets/t-1", SubscribeToken: r4SubTok, Context: []byte(`{"topic":"orders"}`),
		})
		must(bErr, "BeginProtectedSubscription")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "EvProt Poll")
		val, done := termRes.Value()
		return done && val.EventID == "r4-ev-1" && val.Resource == r4ResIssuer
	})

	// Flow 8: Bootstrap enrollment (hwk), refresh (jkt-jwt), and single-key refresh (hwk)
	r4BootClient, err := clientagent.NewBootstrapClient(clientagent.BootstrapConfig{
		AgentProvider:      r4APIssuer,
		EnrollmentEndpoint: r4APIssuer + "/enroll",
		RefreshEndpoint:    r4APIssuer + "/refresh",
		DurableKey:         r4DurableKey,
		KeyResolver:        r4Resolver,
		HTTPClient:         httpClient,
		Clock:              r4Clock,
	})
	must(err, "r4BootClient")
	r4Flow8EnrollOK, r4Flow8EnrollSch := r4RunFlow("enroll", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"agent": r4AgentID})
	}, func(st *r4DeferStage) bool {
		res, bErr := r4BootClient.BeginEnroll(ctx, json.RawMessage(`{"account":"acct-1"}`))
		must(bErr, "BeginEnroll")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "Enroll Poll")
		val, done := termRes.Value()
		return done && val.Agent == r4AgentID
	})
	r4RefreshMode.Store(0)
	r4RefEphemTok, err := aauth.MintAgentToken(r4APIssuer, r4APKey, aauth.AgentTokenRequest{
		Agent:        r4AgentID,
		PersonServer: r4PSIssuer,
		PublicKey:    r4EphemKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	}, r4Clock.Now(), "r4-ref-ephem-tok-1")
	must(err, "r4RefEphemTok")
	r4Flow8RefreshJKTOK, r4Flow8RefreshJKTSch := r4RunFlow("refresh-jkt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_token": r4RefEphemTok})
	}, func(st *r4DeferStage) bool {
		t0 := r4Clock.Now()
		res, bErr := r4BootClient.BeginRefresh(ctx, clientagent.RefreshAgentTokenInput{
			Agent:               r4AgentID,
			PersonServer:        r4PSIssuer,
			Evidence:            json.RawMessage(`{"posture":"ok"}`),
			SigningKey:          r4EphemKey,
			DelegationJTI:       "r4-del-1",
			DelegationIssuedAt:  t0,
			DelegationExpiresAt: t0.Add(10 * time.Minute),
		})
		must(bErr, "BeginRefresh")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "RefreshJKT Poll")
		val, done := termRes.Value()
		return done && val.Claims.Confirmation.JWK.Equal(r4EphemKey.PublicJWK())
	})

	r4RefreshMode.Store(1)
	r4RefDurTok, err := aauth.MintAgentToken(r4APIssuer, r4APKey, aauth.AgentTokenRequest{
		Agent:        r4AgentID,
		PersonServer: r4PSIssuer,
		PublicKey:    r4DurableKey.PublicJWK(),
		Lifetime:     30 * time.Minute,
	}, r4Clock.Now(), "r4-ref-dur-tok-1")
	must(err, "r4RefDurTok")
	r4Flow8RefreshSingleOK, r4Flow8RefreshSingleSch := r4RunFlow("refresh-single", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"agent_token": r4RefDurTok})
	}, func(st *r4DeferStage) bool {
		t0 := r4Clock.Now()
		res, bErr := r4BootClient.BeginRefreshSingleKey(ctx, clientagent.SingleKeyRefreshAgentTokenInput{
			Agent:            r4AgentID,
			PersonServer:     r4PSIssuer,
			Evidence:         json.RawMessage(`{"posture":"ok"}`),
			RefreshJTI:       "r4-ref-single-1",
			RefreshExpiresAt: t0.Add(time.Hour),
		})
		must(bErr, "BeginRefreshSingleKey")
		pend, _ := res.Pending()
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pErr, "RefreshSingle Poll")
		val, done := termRes.Value()
		return done && val.Claims.Confirmation.JWK.Equal(r4DurableKey.PublicJWK())
	})

	// Flow 9: PersonTokenResult.ChainedPending() polling over HTTPS
	r4PSMux.HandleFunc("POST /person", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/chained-pt", "2", "pending", r4IntHdr, nil)
	})
	r4UpstreamAT, err := aauth.MintAuthToken(r4PSKey, aauth.AuthTokenClaims{
		Issuer:       r4PSIssuer,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     r4APIssuer,
		JTI:          "r4-up-at-1",
		PersonServer: r4PSIssuer,
		Subject:      "person-r4",
		IssuedAt:     r4Clock.Now().Unix(),
		ExpiresAt:    r4Clock.Now().Add(30 * time.Minute).Unix(),
		Scope:        "records.read",
		Confirmation: aauth.Confirmation{JWK: r4AgKey.PublicJWK()},
	})
	must(err, "r4UpstreamAT")
	r4Flow9ChainedPTOK, _ := r4RunFlow("chained-pt", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"person_token": r4PT, "expires_in": 1800})
	}, func(st *r4DeferStage) bool {
		ptRes, pErr := r4Client.PersonToken(ctx, clientagent.PersonTokenRequest{
			Resource:      r4ResIssuer,
			UpstreamToken: r4UpstreamAT,
		})
		must(pErr, "PersonToken ChainedPending")
		if _, ord := ptRes.Pending(); ord {
			return false
		}
		pend, hasChained := ptRes.ChainedPending()
		if !hasChained || pend.InteractionCode() != "2345-6789" {
			return false
		}
		r4Advance(2 * time.Second)
		st.mu.Lock()
		st.polls = 3
		st.mu.Unlock()
		termRes, pollErr := pend.Poll(ctx, clientagent.PollOptions{})
		must(pollErr, "ChainedPending Poll")
		tok, done := termRes.Value()
		return done && tok == r4PT
	})

	// Flow 10: Mission proposal with clarification + AnswerMissionClarification + CancelMissionProposal
	r4PSMux.HandleFunc("POST /missions", func(w http.ResponseWriter, _ *http.Request) {
		writeR4202(w, "/pending/mission-prop", "0", "pending", "requirement=clarification", map[string]any{
			"clarification": "Which warehouse region?",
			"timeout":       60,
			"options":       []string{"us-west", "eu-central"},
		})
	})
	r4Flow10MissionPropOK, _ := r4RunFlow("mission-prop", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, func(st *r4DeferStage) bool {
		propRes, bErr := r4Client.BeginMission(ctx, clientagent.MissionRequest{
			PersonServer: r4PSIssuer,
			Proposal:     aauth.MissionProposal{Description: "# Region Check", Resources: []string{r4ResIssuer}},
		})
		must(bErr, "BeginMission")
		pend, ok := propRes.Pending()
		if !ok {
			return false
		}
		if aErr := r4Client.AnswerMissionClarification(ctx, pend, "us-west"); aErr != nil {
			return false
		}
		if cErr := r4Client.CancelMissionProposal(ctx, pend); cErr != nil {
			return false
		}
		return len(st.answers) == 1 && st.answers[0] == "us-west" && st.deleted
	})
	// =========================================================================
	// QA-R5: Hosted-Page Callbacks (ConsumeAuthorizationInteractionVisit,
	// ConsumePersonTokenInteractionVisit, ConsumeSessionInteractionVisit)
	// =========================================================================
	const (
		r5APIssuer  = "https://r5-ap.example"
		r5AgentID   = "aauth:caller@r5-ap.example"
		r5PSIssuer  = "https://r5-ps.example"
		r5ResIssuer = "https://r5-res.example"
		r5SesIssuer = "https://r5-sess-res.example"
	)
	r5APKey := newRKey("r5-ap-1", 0xe1)
	r5AgKey := newRKey("r5-ag-1", 0xe2)
	r5PSKey := newRKey("r5-ps-1", 0xe3)
	r5ResKey := newRKey("r5-res-1", 0xe4)
	r5SesKey := newRKey("r5-ses-1", 0xe5)

	r5NowMu := sync.Mutex{}
	r5Now := clock.Now()
	r5Clock := aauth.ClockFunc(func() time.Time {
		r5NowMu.Lock()
		defer r5NowMu.Unlock()
		return r5Now
	})
	r5Advance := func(d time.Duration) {
		r5NowMu.Lock()
		r5Now = r5Now.Add(d)
		r5NowMu.Unlock()
	}
	r5Resolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   r5Clock,
		Admit:                   r2Admit,
	})
	must(err, "r5Resolver")

	r5AP, err := agentprovider.New(agentprovider.Config{
		Issuer:     r5APIssuer,
		SigningKey: r5APKey,
		Clock:      r5Clock,
		NewID:      nextRID,
	})
	must(err, "r5AP")
	r5APSrv, _ := registerTLS("r5-ap.example", r5AP.Handler())
	defer r5APSrv.Close()

	r5AgTok, err := r5AP.Issue(aauth.AgentTokenRequest{
		Agent:        r5AgentID,
		PersonServer: r5PSIssuer,
		PublicKey:    r5AgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "r5AgTok")
	r5Client, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  r5AgentID,
		AgentToken:  r5AgTok,
		SigningKey:  r5AgKey,
		HTTPClient:  httpClient,
		KeyResolver: r5Resolver,
		Clock:       r5Clock,
	})
	must(err, "r5Client")

	var r5RequireRII atomic.Bool
	r5Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            r5ResIssuer,
		SigningKey:        r5ResKey,
		KeyResolver:       r5Resolver,
		Clock:             r5Clock,
		NewID:             nextRID,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		InitiatedInteraction: &resource.InitiatedInteractionConfig{
			URL: r5ResIssuer + "/resource-consent",
			Require: func(context.Context, resource.InitiatedInteractionRequest) (bool, error) {
				return r5RequireRII.Load(), nil
			},
			Store: testutil.NewInitiatedInteractionStore(),
		},
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "r5-ok")
		}),
	})
	must(err, "r5Res")
	r5ResSrv, _ := registerTLS("r5-res.example", r5Res.Handler())
	defer r5ResSrv.Close()

	var r5RequirePTInt atomic.Bool
	r5AuthStore := testutil.NewDeferredAuthorizationStore()
	r5TokensStore := newK3DeferredTokenStore()
	r5PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:      r5PSIssuer,
		SigningKey:  r5PSKey,
		KeyResolver: r5Resolver,
		Clock:       r5Clock,
		NewID:       nextRID,
		Tokens:      r5TokensStore,
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-r5", Lifetime: 20 * time.Minute}, nil
		},
		RequirePersonTokenInteraction: func(context.Context, personserver.PersonTokenRequest) (personserver.PersonTokenInteractionPolicy, bool, error) {
			if r5RequirePTInt.Load() {
				return personserver.PersonTokenInteractionPolicy{
					URL:        r5PSIssuer + "/interaction",
					Lifetime:   5 * time.Minute,
					RetryAfter: 0,
				}, true, nil
			}
			return personserver.PersonTokenInteractionPolicy{}, false, nil
		},
		RequireAuthorizationInteraction: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, bool, error) {
			return personserver.AuthorizationInteractionPolicy{
				URL:        r5PSIssuer + "/consent",
				Lifetime:   5 * time.Minute,
				RetryAfter: 0,
			}, true, nil
		},
		AuthorizationInteractions: r5AuthStore,
		ResourceInteraction: &personserver.ResourceInteractionConfig{
			CallbackURL: r5PSIssuer + "/resource-callback",
			Admit:       r2Admit,
			Policy: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationInteractionPolicy, error) {
				return personserver.AuthorizationInteractionPolicy{
					URL:        r5PSIssuer + "/consent",
					Lifetime:   5 * time.Minute,
					RetryAfter: 0,
				}, nil
			},
		},
	})
	must(err, "r5PS")
	r5PSSrv, _ := registerTLS("r5-ps.example", r5PS.Handler())
	defer r5PSSrv.Close()
	// 1) AuthorizationInteraction callbacks (approved, denied -> access_denied, abandoned -> user_abandoned, expired -> interaction_expired, RedirectToResourceInteraction(ctx, interaction, ""))
	r5PTRes, err := r5Client.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: r5PSIssuer,
		Resource:     r5ResIssuer,
	})
	must(err, "r5PTRes")
	r5PT, _ := r5PTRes.Token()
	r5RT, err := r5Client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r5ResIssuer,
		PersonToken: r5PT,
		Scopes:      []string{"records.read"},
	})
	must(err, "r5RT")

	r5StartAuth := func() (clientagent.PendingExchange, string) {
		bRes, bErr := r5Client.BeginExchange(ctx, clientagent.ExchangeRequest{
			PersonServer:   r5PSIssuer,
			ResourceToken:  r5RT,
			PresentedToken: r5PT,
			Capabilities:   []string{"interaction"},
		})
		must(bErr, "r5 BeginExchange")
		p, _ := bRes.Pending()
		ref := strings.TrimPrefix(p.InteractionURL(), r5PSIssuer+"/consent/")
		return p, ref
	}

	// Approved + wrong code check + ResumeAuthorizationInteraction
	r5AuthP1, r5AuthRef1 := r5StartAuth()
	_, r5AuthWrongErr := r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5AuthRef1, aauth.InteractionVisit{
		Code:     "WRONG999",
		Callback: "https://agent.example/wrong-auth",
	})
	r5AuthSnapAfterWrong, err := r5AuthStore.LoadPendingAuthorization(ctx, r5AuthRef1, r5Clock.Now())
	must(err, "LoadPendingAuthorization after wrong")
	r5AuthInt1, err := r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5AuthRef1, aauth.InteractionVisit{
		Code:     r5AuthP1.InteractionCode(),
		Callback: "https://agent.example/cb-auth",
	})
	must(err, "ConsumeAuthorizationInteractionVisit r5AuthRef1")
	_ = r5AuthInt1
	_, r5AuthWhilePendingErr := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef1)
	r5AuthResumed1, err := r5PS.ResumeAuthorizationInteraction(ctx, r5AuthRef1)
	must(err, "ResumeAuthorizationInteraction")
	must(r5PS.ApproveAuthorizationInteraction(ctx, r5AuthResumed1, personserver.AuthorizationDecision{
		Scopes:   []string{"records.read"},
		Lifetime: 10 * time.Minute,
	}), "ApproveAuthorizationInteraction")
	r5AuthCompURL1, _ := r5AuthResumed1.CompletionURL()
	r5AuthBackURL1, _ := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef1)
	_, err = r5Client.PollExchange(ctx, r5AuthP1)
	must(err, "PollExchange r5AuthP1")
	r5AuthGoneURL1, _ := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef1)

	// Denied -> access_denied
	r5AuthP2, r5AuthRef2 := r5StartAuth()
	r5AuthInt2, err := r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5AuthRef2, aauth.InteractionVisit{
		Code:     r5AuthP2.InteractionCode(),
		Callback: "https://agent.example/cb-auth",
	})
	must(err, "ConsumeAuthorizationInteractionVisit r5AuthRef2")
	must(r5PS.DenyAuthorizationInteraction(ctx, r5AuthInt2), "DenyAuthorizationInteraction")
	r5AuthDeniedURL, _ := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef2)

	// Abandoned -> user_abandoned
	r5AuthP3, r5AuthRef3 := r5StartAuth()
	r5AuthInt3, err := r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5AuthRef3, aauth.InteractionVisit{
		Code:     r5AuthP3.InteractionCode(),
		Callback: "https://agent.example/cb-auth",
	})
	must(err, "ConsumeAuthorizationInteractionVisit r5AuthRef3")
	must(r5PS.AbandonAuthorizationInteraction(ctx, r5AuthInt3), "AbandonAuthorizationInteraction")
	r5AuthAbandonedURL, _ := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef3)

	// Expired -> interaction_expired
	r5AuthP4, r5AuthRef4 := r5StartAuth()
	_, err = r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5AuthRef4, aauth.InteractionVisit{
		Code:     r5AuthP4.InteractionCode(),
		Callback: "https://agent.example/cb-auth",
	})
	must(err, "ConsumeAuthorizationInteractionVisit r5AuthRef4")
	r5Advance(6 * time.Minute)
	r5AuthExpiredURL, _ := r5PS.AuthorizationCallbackURL(ctx, r5AuthRef4)

	// RedirectToResourceInteraction(ctx, interaction, "") using retained callback
	r5PT2Res, err := r5Client.PersonToken(ctx, clientagent.PersonTokenRequest{
		PersonServer: r5PSIssuer,
		Resource:     r5ResIssuer,
	})
	must(err, "r5PT2Res")
	r5PT2, _ := r5PT2Res.Token()
	r5RequireRII.Store(true)
	r5RIIRT, err := r5Client.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource:    r5ResIssuer,
		PersonToken: r5PT2,
		Scopes:      []string{"records.read"},
	})
	r5RequireRII.Store(false)
	must(err, "r5RIIRT")
	r5RIIBegun, err := r5Client.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer:   r5PSIssuer,
		ResourceToken:  r5RIIRT,
		PresentedToken: r5PT2,
		Capabilities:   []string{"interaction"},
	})
	must(err, "BeginExchange RII")
	r5RIIPend, _ := r5RIIBegun.Pending()
	r5RIIRef := strings.TrimPrefix(r5RIIPend.InteractionURL(), r5PSIssuer+"/consent/")
	r5RIIInt, err := r5PS.ConsumeAuthorizationInteractionVisit(ctx, r5RIIRef, aauth.InteractionVisit{
		Code:     r5RIIPend.InteractionCode(),
		Callback: "https://agent.example/cb-rii",
	})
	must(err, "ConsumeAuthorizationInteractionVisit RII")
	r5RIIRedirURL, err := r5PS.RedirectToResourceInteraction(ctx, r5RIIInt, "")
	must(err, "RedirectToResourceInteraction empty agentCallback")
	// 2) PersonTokenInteraction callbacks (wrong code check, ResumePersonTokenInteraction, approved, denied -> access_denied, expired -> interaction_expired)
	r5RequirePTInt.Store(true)
	r5StartPT := func() (clientagent.PendingPersonToken, string) {
		pRes, pErr := r5Client.PersonToken(ctx, clientagent.PersonTokenRequest{
			PersonServer: r5PSIssuer,
			Resource:     r5ResIssuer,
			Capabilities: []string{"interaction"},
		})
		must(pErr, "r5 PersonToken")
		p, _ := pRes.Pending()
		ref := strings.TrimPrefix(p.InteractionURL(), r5PSIssuer+"/interaction/")
		return p, ref
	}
	r5PTP1, r5PTRef1 := r5StartPT()
	_, r5PTWrongErr := r5PS.ConsumePersonTokenInteractionVisit(ctx, r5PTRef1, aauth.InteractionVisit{
		Code:     "WRONG999",
		Callback: "https://agent.example/wrong-pt",
	})
	r5PTSnapAfterWrong, err := r5TokensStore.LoadPendingPersonToken(ctx, r5PTRef1)
	must(err, "LoadPendingPersonToken after wrong")
	_, err = r5PS.ConsumePersonTokenInteractionVisit(ctx, r5PTRef1, aauth.InteractionVisit{
		Code:     r5PTP1.InteractionCode(),
		Callback: "https://agent.example/cb-pt",
	})
	must(err, "ConsumePersonTokenInteractionVisit r5PTRef1")
	r5PTResumed1, err := r5PS.ResumePersonTokenInteraction(ctx, r5PTRef1)
	must(err, "ResumePersonTokenInteraction")
	must(r5PS.ApprovePersonTokenInteraction(ctx, r5PTResumed1, personserver.Person{
		Subject:  "person-r5",
		Lifetime: 20 * time.Minute,
	}), "ApprovePersonTokenInteraction")
	r5PTCompURL1, _ := r5PTResumed1.CompletionURL()
	r5PTBackURL1, _ := r5PS.PersonTokenCallbackURL(ctx, r5PTRef1)

	r5PTP2, r5PTRef2 := r5StartPT()
	r5PTInt2, err := r5PS.ConsumePersonTokenInteractionVisit(ctx, r5PTRef2, aauth.InteractionVisit{
		Code:     r5PTP2.InteractionCode(),
		Callback: "https://agent.example/cb-pt",
	})
	must(err, "ConsumePersonTokenInteractionVisit r5PTRef2")
	must(r5PS.DenyPersonTokenInteraction(ctx, r5PTInt2), "DenyPersonTokenInteraction")
	r5PTDeniedURL, _ := r5PS.PersonTokenCallbackURL(ctx, r5PTRef2)

	r5PTP3, r5PTRef3 := r5StartPT()
	_, err = r5PS.ConsumePersonTokenInteractionVisit(ctx, r5PTRef3, aauth.InteractionVisit{
		Code:     r5PTP3.InteractionCode(),
		Callback: "https://agent.example/cb-pt",
	})
	must(err, "ConsumePersonTokenInteractionVisit r5PTRef3")
	r5Advance(6 * time.Minute)
	r5PTExpiredURL, _ := r5PS.PersonTokenCallbackURL(ctx, r5PTRef3)

	// 3) SessionInteraction callbacks (wrong code check, ResumeSessionInteraction, approved, denied -> access_denied, expired -> interaction_expired)
	_ = r5SesKey
	r5SesStore := newNMemorySessionStore()
	r5SesRes, err := resource.NewResourceManaged(resource.ResourceManagedConfig{
		Issuer:            r5SesIssuer,
		KeyResolver:       r5Resolver,
		Clock:             r5Clock,
		ScopeDescriptions: map[string]string{"records.read": "Read records"},
		RequiredScopes:    func(*http.Request) []string { return []string{"records.read"} },
		AuthorizeImmediately: func(context.Context, resource.SessionAuthorizationRequest) (resource.SessionGrant, bool, error) {
			return resource.SessionGrant{}, false, nil
		},
		Interaction: resource.SessionInteractionPolicy{
			URL:                 r5SesIssuer + "/interaction",
			Lifetime:            5 * time.Minute,
			RetryAfter:          0,
			MaximumCodeAttempts: 3,
		},
		Sessions: r5SesStore,
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "r5-sess-ok")
		}),
	})
	must(err, "r5SesRes")
	r5SesSrv, _ := registerTLS("r5-sess-res.example", r5SesRes.Handler())
	defer r5SesSrv.Close()

	r5StartSes := func() (clientagent.PendingResourceSession, string) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r5SesIssuer+"/records", nil)
		req.Header.Set("AAuth-Capabilities", "interaction")
		bRes, bErr := r5Client.BeginResourceSession(ctx, req)
		must(bErr, "BeginResourceSession")
		p, _ := bRes.Pending()
		ref := strings.TrimPrefix(p.InteractionURL(), r5SesIssuer+"/interaction/")
		return p, ref
	}
	r5SesP1, r5SesRef1 := r5StartSes()
	_, r5SesWrongErr := r5SesRes.ConsumeSessionInteractionVisit(ctx, r5SesRef1, aauth.InteractionVisit{
		Code:     "WRONG999",
		Callback: "https://agent.example/wrong-sess",
	})
	r5SesSnapAfterWrong, err := r5SesStore.LoadPending(ctx, r5SesRef1)
	must(err, "LoadPending after wrong")
	_, err = r5SesRes.ConsumeSessionInteractionVisit(ctx, r5SesRef1, aauth.InteractionVisit{
		Code:     r5SesP1.InteractionCode(),
		Callback: "https://agent.example/cb-sess",
	})
	must(err, "ConsumeSessionInteractionVisit r5SesRef1")
	r5SesResumed1, err := r5SesRes.ResumeSessionInteraction(ctx, r5SesRef1)
	must(err, "ResumeSessionInteraction")
	must(r5SesRes.ApproveSessionInteraction(ctx, r5SesResumed1, resource.SessionGrant{
		Subject:  "person-r5",
		Scope:    []string{"records.read"},
		Lifetime: 30 * time.Minute,
	}), "ApproveSessionInteraction")
	r5SesCompURL1, _ := r5SesResumed1.CompletionURL()
	r5SesBackURL1, _ := r5SesRes.SessionCallbackURL(ctx, r5SesRef1)

	r5SesP2, r5SesRef2 := r5StartSes()
	r5SesInt2, err := r5SesRes.ConsumeSessionInteractionVisit(ctx, r5SesRef2, aauth.InteractionVisit{
		Code:     r5SesP2.InteractionCode(),
		Callback: "https://agent.example/cb-sess",
	})
	must(err, "ConsumeSessionInteractionVisit r5SesRef2")
	must(r5SesRes.DenySessionInteraction(ctx, r5SesInt2), "DenySessionInteraction")
	r5SesDeniedURL, _ := r5SesRes.SessionCallbackURL(ctx, r5SesRef2)

	r5SesP3, r5SesRef3 := r5StartSes()
	_, err = r5SesRes.ConsumeSessionInteractionVisit(ctx, r5SesRef3, aauth.InteractionVisit{
		Code:     r5SesP3.InteractionCode(),
		Callback: "https://agent.example/cb-sess",
	})
	must(err, "ConsumeSessionInteractionVisit r5SesRef3")
	r5Advance(6 * time.Minute)
	r5SesExpiredURL, _ := r5SesRes.SessionCallbackURL(ctx, r5SesRef3)
	_, _ = r3.NewRegistry(mcp.Vocabulary())
	rSrvEntry := func(srv *httptest.Server, der []byte) map[string]any {
		return map[string]any{
			"addr":     srv.Listener.Addr().String(),
			"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		}
	}

	return map[string]any{
		"servers": map[string]any{
			"r3_go_ap":             rSrvEntry(r3GoAPSrv, r3GoAPDER),
			"r3_go_fed_ps":         rSrvEntry(r3GoFedPSSrv, r3GoFedPSDER),
			"r3_go_as":             rSrvEntry(r3GoASSrv, r3GoASDER),
			"r3_go_interm_go_as":   rSrvEntry(r3GoIGSrv, r3GoIGDER),
			"r3_go_interm_rust_as": rSrvEntry(r3GoIRSrv, r3GoIRDER),
			"r3_go_down_go_as":     rSrvEntry(r3GoDGSrv, r3GoDGDER),
			"r3_go_down_rust_as":   rSrvEntry(r3GoDRSrv, r3GoDRDER),
		},
		"r1": map[string]any{
			"missing_issued_tokens_err": r1MissingIssuedErr != nil && strings.Contains(r1MissingIssuedErrMsg, "issued auth-token store"),
			"missing_issued_msg":        r1MissingIssuedErrMsg,
			"issued_roundtrip_ok":       reflect.DeepEqual(r1LoadedRec, r1Rec),
			"issued_conflict_refused":   errors.Is(r1ConflictErr, personserver.ErrIssuedAuthTokenConflict),
			"lineage_implemented":       r1ImplementsLineage && r1LineageErr == nil && len(r1LineageRecs) == 1 && r1LineageRecs[0].Reference == r1Rec.Reference,
			"fed_upstream_roundtrip_ok": r1LoadedFed.UpstreamToken == "r1-upstream-compact-jwt",
			"fed_upstream_immutable_ok": errors.Is(r1FedImmutableErr, personserver.ErrFederatedAuthorizationConflict),
			"sess_bad_code_no_cb":       errors.Is(r1BadCodeErr, resource.ErrSessionInteractionCodeInvalid) && r1SnapAfterBad.Callback == "",
			"sess_good_code_cb_ok":      r1GoodCodeErr == nil && r1SnapAfterGood.Callback == "https://agent.example/good-cb",
			"sess_reuse_code_preserves": errors.Is(r1ReuseCodeErr, resource.ErrSessionInteractionCodeUsed) && r1SnapAfterReuse.Callback == "https://agent.example/good-cb",
		},
		"r2": map[string]any{
			"hop1_ok":                  r2Hop1CallStatus == 200 && r2Hop1CallBody == "served person-at-r2-orders.example" && r2Hop1ATClaims.Issuer == r2OrdersASIssuer,
			"hop2_ok":                  r2Hop2CallStatus == 200 && r2Hop2CallBody == "served person-at-r2-inventory.example" && r2Hop2ATClaims.Issuer == r2StockASIssuer,
			"hop3_ok":                  r2Hop3CallStatus == 200 && r2Hop3CallBody == "served person-at-r2-warehouse.example" && r2Hop3ATClaims.Issuer == r2StockASIssuer,
			"expiry_ceilings_ok":       r2Hop2PTClaims.ExpiresAt <= r2Hop1ATClaims.ExpiresAt && r2Hop2ATClaims.ExpiresAt <= r2Hop1ATClaims.ExpiresAt && r2Hop3PTClaims.ExpiresAt <= r2Hop2ATClaims.ExpiresAt && r2Hop3ATClaims.ExpiresAt <= r2Hop2ATClaims.ExpiresAt,
			"stepup_omit_refused":      r2StepUpOmitStatus == 400 && r2StepUpOmitCode == "invalid_upstream_token",
			"stepup_match_ok":          r2StepUpOKErr == nil && r2StepUpOKAT != "",
			"revoke_pt_attempts":       len(r2RevokeRes.Attempts),
			"revoke_pt_all_3_hops_401": r2Hop1AfterRevStatus == 401 && r2Hop1AfterRevCode == "revoked_jwt" && r2Hop2AfterRevStatus == 401 && r2Hop2AfterRevCode == "revoked_jwt" && r2Hop3AfterRevStatus == 401 && r2Hop3AfterRevCode == "revoked_jwt",
			"revoke_pt_upstream_400":   r2ChainAfterRevStatus == 400 && r2ChainAfterRevCode == "revoked_upstream_token",
			"chained_wait_approved_ok": r2WaitGotPending && r2Poll1StillPending && r2WaitApprovedOK && r2WaitApprovedAT != "",
			"chained_wait_revoked_ok":  r2PollRevStatus == 403 && r2PollRevCode == "revoked" && strings.Contains(r2PollRevDetail, "upstream token") && r2PollGoneStatus == 410,
			"mission_carried_ok":       r2MissOrdersATClaims.MissionS256 == r2Mission.S256 && r2MissInvPTClaims.MissionS256 == r2Mission.S256 && r2MissInvATClaims.MissionS256 == r2Mission.S256,
			"mission_as_not_capped_rt": r2MissOrdersATClaims.ExpiresAt > r2MissOrdersRTClaims.ExpiresAt && r2MissOrdersATClaims.ExpiresAt <= r2MissionExpiry.Unix(),
			"interm_own_mission_400":   r2IntermOwnMissErr != nil && strings.Contains(r2IntermOwnMissErr.Error(), "carries the mission"),
			"mission_wait_term_ok":     r2MissTermStatus == 403 && r2MissTermCode == "mission_terminated" && r2MissTermReason == "completed" && r2MissGoneStatus == 410,
			"agent_rev_202_then_200":   r2AgRevGot202 && strings.HasPrefix(r2AgRevPendingLoc, r2PSIssuer+"/revoke/pending/") && r2AgRev200Err == nil,
			"agent_rev_hops_401":       r2AgRevHop1Status == 401 && r2AgRevHop1Code == "revoked_jwt" && r2AgRevHop2Status == 401 && r2AgRevHop2Code == "revoked_jwt",
		},
		"r3": map[string]any{
			"d1_nomiss_hop1_ok":          r3D1NoMissHop1St == 200,
			"d1_nomiss_hop2_rust_as_ok":  r3D1NoMissHop2RustASSt == 200,
			"d1_nomiss_hop2_go_as_ok":    r3D1NoMissHop2GoASSt == 200,
			"d1_rust_as_interm_ok":       r3D1RustASHop1St == 200 && r3D1RustASHop2St == 200,
			"d1_revoke_pt_cascade_ok":    r3D1AfterRevHop1St == 401 && r3D1AfterRevHop1Code == "revoked_jwt" && r3D1AfterRevHop2RustASSt == 401 && r3D1AfterRevHop2RustASCode == "revoked_jwt" && r3D1AfterRevHop2GoASSt == 401 && r3D1AfterRevHop2GoASCode == "revoked_jwt",
			"d1_miss_hop1_and_hop2_ok":   r3D1MissHop1St == 200 && r3D1MissHop2RustASSt == 200 && r3D1MissHop2Claims.MissionS256 == r3GoMission.S256 && r3D1MissHop2RustASBody["mission_s256"] == r3GoMission.S256,
			"bnd_go_ps_as_int_500":       r3BndASIntSt == 403 && r3BndASIntCode == "user_unreachable" && r3BndASIntRelayOK,
			"bnd_go_ps_as_int_relayed":   r3BndASIntRelayOK,
			"bnd_go_ps_as_int_no_cap_403": r3BndASIntSt == 403 && r3BndASIntCode == "user_unreachable",
			"bnd_go_ps_subagent_500":     r3BndSubAgSt == 500 && r3BndSubAgCode == "server_error",
			"bnd_go_ps_copy_sub_500":     r3BndCopySubSt == 500 && r3BndCopySubCode == "server_error",
			"bnd_go_ps_unrec_as_tok_400": r3BndUnrecSt == 400 && r3BndUnrecCode == "invalid_upstream_token",
		},
		"r4": map[string]any{
			"flow1_mission_update_ok":   r4Flow1OK && r4Flow1Sch == "jwt",
			"flow2_mission_complete_ok": r4Flow2OK && r4Flow2ClarifyOK,
			"flow3_audit_ok":            r4Flow3OK,
			"flow4_authorize_rt_ok":     r4Flow4OK,
			"flow5_authorize_sess_ok":   r4Flow5OK,
			"flow6_subagent_ok":         r4Flow6OK,
			"flow7_events_ok":           r4Flow7PubOK && r4Flow7ProtOK,
			"flow8_enroll_hwk_ok":       r4Flow8EnrollOK && r4Flow8EnrollSch == "hwk",
			"flow8_refresh_jkt_ok":      r4Flow8RefreshJKTOK && r4Flow8RefreshJKTSch == "jkt-jwt",
			"flow8_refresh_single_ok":   r4Flow8RefreshSingleOK && r4Flow8RefreshSingleSch == "hwk",
			"flow9_chained_pt_ok":       r4Flow9ChainedPTOK,
			"flow10_mission_prop_ok":    r4Flow10MissionPropOK,
		},
		"r5": map[string]any{
			"auth_wrong_code_no_cb": errors.Is(r5AuthWrongErr, personserver.ErrAuthorizationInteractionCodeInvalid) && r5AuthSnapAfterWrong.Callback == "",
			"auth_while_pending":    errors.Is(r5AuthWhilePendingErr, personserver.ErrPendingAuthorizationConflict),
			"auth_resumed_cb_ok":    r5AuthResumed1.Callback() == "https://agent.example/cb-auth",
			"auth_approved_cb_ok":   r5AuthCompURL1 == "https://agent.example/cb-auth" && r5AuthBackURL1 == "https://agent.example/cb-auth",
			"auth_gone_cb_ok":       r5AuthGoneURL1 == "https://agent.example/cb-auth?error=server_error",
			"auth_denied_cb_ok":     r5AuthDeniedURL == "https://agent.example/cb-auth?error=access_denied",
			"auth_abandoned_cb_ok":  r5AuthAbandonedURL == "https://agent.example/cb-auth?error=user_abandoned",
			"auth_expired_cb_ok":    r5AuthExpiredURL == "https://agent.example/cb-auth?error=interaction_expired",
			"auth_rii_retained_cb":  strings.HasPrefix(r5RIIRedirURL, r5ResIssuer+"/resource-consent/") && r5RIIInt.Callback() == "https://agent.example/cb-rii",
			"pt_wrong_code_no_cb":   errors.Is(r5PTWrongErr, personserver.ErrInteractionCodeInvalid) && r5PTSnapAfterWrong.Callback == "",
			"pt_resumed_cb_ok":      r5PTResumed1.Callback() == "https://agent.example/cb-pt",
			"pt_approved_cb_ok":     r5PTCompURL1 == "https://agent.example/cb-pt" && r5PTBackURL1 == "https://agent.example/cb-pt",
			"pt_denied_cb_ok":       r5PTDeniedURL == "https://agent.example/cb-pt?error=access_denied",
			"pt_expired_cb_ok":      r5PTExpiredURL == "https://agent.example/cb-pt?error=interaction_expired",
			"ses_wrong_code_no_cb":  errors.Is(r5SesWrongErr, resource.ErrSessionInteractionCodeInvalid) && r5SesSnapAfterWrong.Callback == "",
			"ses_resumed_cb_ok":     r5SesResumed1.Callback() == "https://agent.example/cb-sess",
			"ses_approved_cb_ok":    r5SesCompURL1 == "https://agent.example/cb-sess" && r5SesBackURL1 == "https://agent.example/cb-sess",
			"ses_denied_cb_ok":      r5SesDeniedURL == "https://agent.example/cb-sess?error=access_denied",
			"ses_expired_cb_ok":     r5SesExpiredURL == "https://agent.example/cb-sess?error=interaction_expired",
		},
	}
}
