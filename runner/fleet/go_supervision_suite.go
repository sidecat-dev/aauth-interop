package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	clientagent "gitlab.com/sidecat-dev/aauth-go/agent"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/supervision"
	"gitlab.com/sidecat-dev/aauth-go/supervisionserver"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type sSuiteInput struct {
	S5RustSS1Issuer string `json:"s5_rust_ss1_issuer"`
	S5RustSS2Issuer string `json:"s5_rust_ss2_issuer"`
	GoModDir        string `json:"go_mod_dir"`
}

type sGoSSHost struct {
	issuer   string
	key      jose.SigningKey
	clock    aauth.Clock
	resolver signaturekey.KeyResolver

	mu         sync.Mutex
	server     *supervisionserver.Server
	handler    http.Handler
	offline    bool
	deferAll   bool
	narrowAuth bool
	authMode   string
	asked      map[string]string
	allowed    map[string]bool
	requests   []supervisionserver.DecisionRequest
	observed   []supervisionserver.Observation
	makeServer func() *supervisionserver.Server
}

func newSGoSSHost(
	issuer string,
	key jose.SigningKey,
	clock aauth.Clock,
	resolver signaturekey.KeyResolver,
	requireConfirm bool,
) *sGoSSHost {
	h := &sGoSSHost{
		issuer:   issuer,
		key:      key,
		clock:    clock,
		resolver: resolver,
		asked:    make(map[string]string),
		allowed:  make(map[string]bool),
	}
	h.makeServer = func() *supervisionserver.Server {
		k := h.key
		srv, err := supervisionserver.New(supervisionserver.Config{
			Issuer:      issuer,
			Name:        "Supervisor " + issuer,
			SigningKey:  &k,
			KeyResolver: resolver,
			Clock:       clock,
			Store:       testutil.NewSupervisorStore(),
			Connect: func(_ context.Context, req supervisionserver.ConnectRequest) (supervisionserver.ConnectResult, error) {
				if requireConfirm {
					return supervisionserver.ConnectResult{
						Interaction: &supervisionserver.ConnectInteraction{URL: issuer + "/confirm"},
					}, nil
				}
				return supervisionserver.ConnectResult{Accept: req.Tenant == "acme.example" || req.Tenant == ""}, nil
			},
			Decide: func(_ context.Context, req supervisionserver.DecisionRequest) (supervisionserver.DecisionResult, error) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.requests = append(h.requests, req)
				if h.deferAll {
					return supervisionserver.DecisionResult{Defer: &supervisionserver.Deferral{}}, nil
				}
				switch req.Request.Kind {
				case supervision.KindMissionProposal:
					desc := req.Request.Description
					if !strings.HasSuffix(desc, "Keep work data inside the organization.") {
						desc = desc + "\n\nKeep work data inside the organization."
					}
					var tools []aauth.MissionTool
					if len(req.Request.Tools) > 0 {
						tools = append(tools, req.Request.Tools[0])
					}
					return supervisionserver.DecisionResult{
						Decision: &supervision.Decision{
							Verdict: supervision.VerdictAllow,
							Mission: &supervision.MissionTerms{
								Description:       desc,
								ApprovedTools:     tools,
								ApprovedResources: req.Request.Resources,
							},
						},
					}, nil
				case supervision.KindMissionUpdate:
					return supervisionserver.DecisionResult{
						Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
					}, nil
				case supervision.KindMissionCompletion:
					if req.Request.Summary == "AskOnComplete" {
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict: supervision.VerdictAsk,
								Summary: "Confirm mission completion?",
							},
						}, nil
					}
					return supervisionserver.DecisionResult{
						Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
					}, nil
				case supervision.KindPermission:
					switch req.Request.Action {
					case "DeleteMailbox":
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict: supervision.VerdictDeny,
								Reason:  "Deleting a mailbox is never delegated.",
							},
						}, nil
					case "BookFlight":
						if len(req.Rounds) == 0 {
							return supervisionserver.DecisionResult{
								Clarify: &supervision.Clarification{
									Question: "Is the fare refundable?",
									Timeout:  120 * time.Second,
								},
							}, nil
						}
						if strings.Contains(strings.ToLower(req.Rounds[len(req.Rounds)-1].Answer), "refundable") {
							return supervisionserver.DecisionResult{
								Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
							}, nil
						}
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict: supervision.VerdictDeny,
								Reason:  "Only refundable fares.",
							},
						}, nil
					case "SendEmail":
						if h.allowed[req.Request.Agent+"|permission SendEmail"] ||
							(req.Request.MissionS256 != "" && h.allowed[req.Request.Agent+"|"+req.Request.MissionS256+"|permission SendEmail"]) {
							return supervisionserver.DecisionResult{
								Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
							}, nil
						}
						h.asked[req.Request.SDI] = req.Request.Agent + "|permission SendEmail"
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict:        supervision.VerdictAsk,
								Summary:        "Send an email for you?",
								Recommendation: supervision.VerdictAllow,
								ApplyOptions: []supervision.ApplyOption{
									{Value: supervision.ApplyOnce, Label: "This email only"},
									{Value: supervision.ApplyAlways, Label: "Any email this agent sends"},
								},
							},
						}, nil
					default:
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
						}, nil
					}
				case supervision.KindAuthToken:
					mode := h.authMode
					switch {
					case mode == "deny" || req.Request.Justification == "deny-token":
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{Verdict: supervision.VerdictDeny},
						}, nil
					case mode == "ask" || req.Request.Justification == "ask-token":
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict:        supervision.VerdictAsk,
								Summary:        "The agent wants to change your records.",
								Recommendation: supervision.VerdictAllow,
							},
						}, nil
					case mode == "clarify" || req.Request.Justification == "clarify-token":
						if len(req.Rounds) == 0 {
							return supervisionserver.DecisionResult{
								Clarify: &supervision.Clarification{Question: "Which records, and why?"},
							}, nil
						}
						lastRound := req.Rounds[len(req.Rounds)-1]
						if lastRound.Updated != nil || strings.Contains(lastRound.Answer, "invoices") {
							return supervisionserver.DecisionResult{
								Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
							}, nil
						}
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{Verdict: supervision.VerdictDeny},
						}, nil
					case h.narrowAuth || mode == "narrow" || strings.HasPrefix(req.Request.Justification, "narrow-"):
						scope := "records.read"
						if strings.Contains(req.Request.Justification, "calendar.read") {
							scope = "calendar.read"
						}
						exp := clock.Now().Unix() + 900
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{
								Verdict: supervision.VerdictAllow,
								Scope:   scope,
								ExpiresAt: exp,
							},
						}, nil
					default:
						return supervisionserver.DecisionResult{
							Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
						}, nil
					}
				default:
					return supervisionserver.DecisionResult{
						Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
					}, nil
				}
			},
			Observe: func(_ context.Context, obs supervisionserver.Observation) error {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.observed = append(h.observed, obs)
				if obs.Event != nil && obs.Event.Name == supervision.EventDecisionResolved && obs.Event.Answer == supervision.AnswerAllow {
					if key, ok := h.asked[obs.Event.SDI]; ok {
						if obs.Event.Apply == supervision.ApplyAlways {
							h.allowed[key] = true
						} else if obs.Event.Apply == supervision.ApplyMission && obs.Event.MissionS256 != "" {
							parts := strings.SplitN(key, "|", 2)
							if len(parts) == 2 {
								h.allowed[parts[0]+"|"+obs.Event.MissionS256+"|"+parts[1]] = true
							}
						}
					}
				}
				return nil
			},
		})
		must(err, "supervisionserver.New "+issuer)
		return srv
	}
	h.server = h.makeServer()
	h.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/__qa-ctl" {
			h.handleQACtl(w, r)
			return
		}
		h.mu.Lock()
		off := h.offline
		srv := h.server
		h.mu.Unlock()
		if off {
			http.Error(w, "supervision server offline", http.StatusServiceUnavailable)
			return
		}
		srv.Handler().ServeHTTP(w, r)
	})
	return h
}

func (h *sGoSSHost) forgetEverything() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.server = h.makeServer()
}

func (h *sGoSSHost) setOffline(off bool) {
	h.mu.Lock()
	h.offline = off
	h.mu.Unlock()
}

func (h *sGoSSHost) setDefer(def bool) {
	h.mu.Lock()
	h.deferAll = def
	h.mu.Unlock()
}

func (h *sGoSSHost) setNarrowAuth(n bool) {
	h.mu.Lock()
	h.narrowAuth = n
	h.mu.Unlock()
}

func (h *sGoSSHost) setAuthMode(m string) {
	h.mu.Lock()
	h.authMode = m
	h.mu.Unlock()
}

func (h *sGoSSHost) toldNames() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, obs := range h.observed {
		if obs.Event != nil {
			out = append(out, string(obs.Event.Name))
		} else if obs.Report != nil {
			out = append(out, string(obs.Report.Action))
		}
	}
	return out
}

func (h *sGoSSHost) sawAgent(agentID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, req := range h.requests {
		if req.Request.Agent == agentID {
			return true
		}
	}
	return false
}

func (h *sGoSSHost) handleQACtl(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action, _ := body["action"].(string)
	w.Header().Set("Content-Type", "application/json")
	switch action {
	case "set_offline":
		off, _ := body["offline"].(bool)
		h.setOffline(off)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "set_defer":
		def, _ := body["defer"].(bool)
		h.setDefer(def)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "set_narrow":
		n, _ := body["narrow"].(bool)
		h.setNarrowAuth(n)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "forget_everything":
		h.forgetEverything()
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "confirm_connect":
		rawURL, _ := body["url"].(string)
		code, _ := body["code"].(string)
		ref := path.Base(strings.TrimSuffix(rawURL, "/"))
		h.mu.Lock()
		srv := h.server
		h.mu.Unlock()
		conf, err := srv.ConsumeConnectCode(r.Context(), ref, code)
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := srv.ConfirmConnect(r.Context(), ref, "person-1"); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ps": conf.PersonServer})
	case "resolve_decision":
		ps, _ := body["ps"].(string)
		sdi, _ := body["sdi"].(string)
		verdictStr, _ := body["verdict"].(string)
		verdict := supervision.VerdictAllow
		if verdictStr == "deny" {
			verdict = supervision.VerdictDeny
		}
		h.mu.Lock()
		srv := h.server
		h.mu.Unlock()
		err := srv.ResolveDecision(r.Context(), ps, sdi, supervisionserver.DecisionResult{
			Decision: &supervision.Decision{Verdict: verdict},
		})
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	case "inspect":
		agentID, _ := body["agent"].(string)
		var lastSDI string
		h.mu.Lock()
		for _, obs := range h.observed {
			if obs.Event != nil && obs.Event.SDI != "" {
				lastSDI = obs.Event.SDI
			}
		}
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"told":      h.toldNames(),
			"saw_agent": h.sawAgent(agentID),
			"last_sdi":  lastSDI,
		})
	case "verify_exchange":
		ex, err := decodeExchangeJSON(body["exchange"])
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		verified, vErr := supervision.VerifyExchange(r.Context(), ex, h.resolver)
		if vErr != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": vErr.Error()})
			return
		}
		reqHTTP, _ := http.NewRequestWithContext(r.Context(), ex.Request.Method, ex.Request.URL, bytes.NewReader(ex.Request.Body))
		reqHTTP.Header = ex.Request.Header.Clone()
		_, dErr := supervision.VerifyDecision(r.Context(), ex.Response.Status, ex.Response.Header, ex.Response.Body, reqHTTP, ex.Supervisor, h.resolver, h.clock)
		mutResp := ex.Clone()
		mutResp.Response.Body = []byte(strings.Replace(string(mutResp.Response.Body), `"allow"`, `"deny"`, 1))
		_, mutRespErr := supervision.VerifyExchange(r.Context(), mutResp, h.resolver)
		mutReq := ex.Clone()
		mutReq.Request.Header.Set("Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
		_, mutReqErr := supervision.VerifyExchange(r.Context(), mutReq, h.resolver)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":               dErr == nil,
			"signer":           verified.Signer(),
			"verify_decision":  dErr == nil,
			"mut_resp_failed":  mutRespErr != nil,
			"mut_req_failed":   mutReqErr != nil,
		})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

func encodeExchangeJSON(ex supervision.Exchange) map[string]any {
	reqHdr := make([][2]string, 0)
	for k, vals := range ex.Request.Header {
		for _, v := range vals {
			reqHdr = append(reqHdr, [2]string{strings.ToLower(k), v})
		}
	}
	respHdr := make([][2]string, 0)
	status := 0
	var respBody string
	if ex.Response != nil {
		status = ex.Response.Status
		respBody = base64.RawURLEncoding.EncodeToString(ex.Response.Body)
		for k, vals := range ex.Response.Header {
			for _, v := range vals {
				respHdr = append(respHdr, [2]string{strings.ToLower(k), v})
			}
		}
	}
	return map[string]any{
		"supervisor": ex.Supervisor,
		"request": map[string]any{
			"method":  ex.Request.Method,
			"uri":     ex.Request.URL,
			"headers": reqHdr,
			"body":    base64.RawURLEncoding.EncodeToString(ex.Request.Body),
		},
		"response": map[string]any{
			"status":  status,
			"headers": respHdr,
			"body":    respBody,
		},
		"received_at": ex.ReceivedAt.Unix(),
	}
}

func decodeExchangeJSON(raw any) (supervision.Exchange, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return supervision.Exchange{}, err
	}
	var m struct {
		Supervisor string `json:"supervisor"`
		Request    struct {
			Method  string      `json:"method"`
			URI     string      `json:"uri"`
			Headers [][2]string `json:"headers"`
			Body    string      `json:"body"`
		} `json:"request"`
		Response struct {
			Status  int         `json:"status"`
			Headers [][2]string `json:"headers"`
			Body    string      `json:"body"`
		} `json:"response"`
		ReceivedAt int64 `json:"received_at"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return supervision.Exchange{}, err
	}
	reqBody, err := base64.RawURLEncoding.DecodeString(m.Request.Body)
	if err != nil {
		return supervision.Exchange{}, err
	}
	respBody, err := base64.RawURLEncoding.DecodeString(m.Response.Body)
	if err != nil {
		return supervision.Exchange{}, err
	}
	reqHdr := make(http.Header)
	for _, kv := range m.Request.Headers {
		reqHdr.Add(kv[0], kv[1])
	}
	respHdr := make(http.Header)
	for _, kv := range m.Response.Headers {
		respHdr.Add(kv[0], kv[1])
	}
	return supervision.Exchange{
		Supervisor: m.Supervisor,
		Request: supervision.RecordedRequest{
			Method: m.Request.Method,
			URL:    m.Request.URI,
			Header: reqHdr,
			Body:   reqBody,
		},
		Response: &supervision.RecordedResponse{
			Status: m.Response.Status,
			Header: respHdr,
			Body:   respBody,
		},
		ReceivedAt: time.Unix(m.ReceivedAt, 0).UTC(),
		Signed:     true,
	}, nil
}

func runSSuite(
	ctx context.Context,
	baseClock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in sSuiteInput,
) map[string]any {
	ctx = context.Background()
	var sClockMu sync.Mutex
	sClockNow := baseClock.Now()
	clock := aauth.ClockFunc(func() time.Time {
		sClockMu.Lock()
		defer sClockMu.Unlock()
		return sClockNow
	})
	sAdvanceClock := func(d time.Duration) {
		sClockMu.Lock()
		sClockNow = sClockNow.Add(d)
		sClockMu.Unlock()
	}

	if baseTr, ok := httpClient.Transport.(*http.Transport); ok {
		tr := baseTr.Clone()
		tr.DisableKeepAlives = false
		cCopy := *httpClient
		cCopy.Transport = tr
		httpClient = &cCopy
	}

	newSKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var sIDSeq atomic.Int64
	nextSID := func() string {
		return "s-go-id-0123456789abcdef-" + strconvItoa(sIDSeq.Add(1))
	}

	sResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver sResolver")

	// =========================================================================
	// QA-S3 Part A: Store Conformance (testutil.NewSupervisionStore &
	// testutil.NewSupervisorStore + go test ./supervision ./supervisionserver)
	// =========================================================================
	psStore := testutil.NewSupervisionStore()
	_, notFoundConnErr := psStore.LoadSupervisorConnection(ctx, "https://ss.example", "sub-1")
	saveConnErr := psStore.SaveSupervisorConnection(ctx, personserver.SupervisorConnection{
		Supervisor: personserver.Supervisor{Issuer: "https://ss.example", Subject: "sub-1"},
		State:      personserver.SupervisorConnected,
	})
	loadedConn, loadConnErr := psStore.LoadSupervisorConnection(ctx, "https://ss.example", "sub-1")
	_ = psStore.SaveAgentSupervisor(ctx, "aauth:ag@ap.example", personserver.Supervisor{Issuer: "https://ss.example", Subject: "sub-1"})
	loadedRoute, loadRouteErr := psStore.LoadAgentSupervisor(ctx, "aauth:ag@ap.example")
	_ = psStore.RecordTokenAgent(ctx, aauth.TokenReference{Issuer: "https://ap.example", JTI: "tok-1"}, "aauth:ag@ap.example", clock.Now().Add(time.Hour))
	loadedTokAgent, loadTokAgentErr := psStore.LoadTokenAgent(ctx, aauth.TokenReference{Issuer: "https://ap.example", JTI: "tok-1"})
	_ = psStore.AppendSupervisionNotices(ctx, []personserver.SupervisionNotice{
		{
			ID:         "e-notice-1",
			Supervisor: personserver.Supervisor{Issuer: "https://ss.example", Subject: "sub-1"},
			Name:       "agent.bound",
			Body:       []byte(`{"event":"agent.bound"}`),
		},
		{
			ID:         "e-notice-2",
			Supervisor: personserver.Supervisor{Issuer: "https://ss.example", Subject: "sub-1"},
			Name:       "person_token.issued",
			Body:       []byte(`{"event":"person_token.issued"}`),
		},
	})
	pendingNotices, _ := psStore.PendingSupervisionNotices(ctx, "https://ss.example", "sub-1", 10)
	_ = psStore.MarkSupervisionNoticeDelivered(ctx, "https://ss.example", "sub-1", "e-notice-1")
	pendingAfterComplete, _ := psStore.PendingSupervisionNotices(ctx, "https://ss.example", "sub-1", 10)
	supReq := personserver.SupervisedRequest{
		Reference: "ref-1",
		SDI:       "d-0123456789abcdefghijkl",
		Kind:      supervision.KindPermission,
		Supervisor: personserver.Supervisor{
			Issuer:  "https://ss.example",
			Subject: "sub-1",
		},
		Agent:     "aauth:ag@ap.example",
		State:     personserver.SupervisedWaitingForPerson,
		CreatedAt: clock.Now(),
		ExpiresAt: clock.Now().Add(10 * time.Minute),
		Revision:  1,
	}
	createReqErr := psStore.CreateSupervisedRequest(ctx, supReq)
	dupReqErr := psStore.CreateSupervisedRequest(ctx, supReq)
	mutReq := supReq
	mutReq.Revision = 2
	mutReq.Agent = "aauth:other@ap.example"
	mutReplaceErr := psStore.ReplaceSupervisedRequest(ctx, supReq, mutReq)
	validAfter := supReq
	validAfter.Revision = 2
	validAfter.State = personserver.SupervisedDecided
	validReplaceErr := psStore.ReplaceSupervisedRequest(ctx, supReq, validAfter)
	s3PSStoreOK := errors.Is(notFoundConnErr, personserver.ErrSupervisionNotFound) &&
		saveConnErr == nil && loadConnErr == nil && loadedConn.State == personserver.SupervisorConnected &&
		loadRouteErr == nil && loadedRoute.Issuer == "https://ss.example" &&
		loadTokAgentErr == nil && loadedTokAgent == "aauth:ag@ap.example" &&
		len(pendingNotices) == 2 && pendingNotices[0].Sequence == 1 && pendingNotices[1].Sequence == 2 &&
		len(pendingAfterComplete) == 1 && pendingAfterComplete[0].Sequence == 2 &&
		createReqErr == nil && errors.Is(dupReqErr, personserver.ErrSupervisionConflict) &&
		errors.Is(mutReplaceErr, personserver.ErrSupervisionConflict) && validReplaceErr == nil

	ssStore := testutil.NewSupervisorStore()
	_ = ssStore.PutConnection(ctx, supervisionserver.Connection{PersonServer: "https://ps.example", Subject: "sub-1", ConnectedAt: clock.Now()})
	_, loadSSConnErr := ssStore.LoadConnection(ctx, "https://ps.example", "sub-1")
	_ = ssStore.DeleteConnection(ctx, "https://ps.example", "sub-1")
	_, delSSConnErr := ssStore.LoadConnection(ctx, "https://ps.example", "sub-1")
	decRec := supervisionserver.DecisionRecord{
		PersonServer: "https://ps.example",
		SDI:          "d-0123456789abcdefghijkl",
		Kind:         supervision.KindPermission,
		Subject:      "sub-1",
		Agent:        "aauth:ag@ap.example",
		Request:      []byte(`{"sdi":"d-0123456789abcdefghijkl"}`),
		Pending:      "pend-1",
		State:        supervisionserver.DecisionDeciding,
		CreatedAt:    clock.Now(),
		Revision:     1,
	}
	_, created1, createDecErr1 := ssStore.CreateDecision(ctx, decRec)
	_, created2, createDecErr2 := ssStore.CreateDecision(ctx, decRec)
	_, loadPendDecErr := ssStore.LoadPendingDecision(ctx, "pend-1")
	delivErr1 := ssStore.RecordDelivery(ctx, supervisionserver.Delivery{PersonServer: "https://ps.example", ID: "e-1", ReceivedAt: clock.Now()})
	delivErr2 := ssStore.RecordDelivery(ctx, supervisionserver.Delivery{PersonServer: "https://ps.example", ID: "e-1", ReceivedAt: clock.Now()})
	s3SSStoreOK := loadSSConnErr == nil && errors.Is(delSSConnErr, supervisionserver.ErrNotFound) &&
		createDecErr1 == nil && created1 && createDecErr2 == nil && !created2 && loadPendDecErr == nil &&
		delivErr1 == nil && errors.Is(delivErr2, supervisionserver.ErrConflict)

	goTestCmd := exec.Command("go", "test", "-mod=readonly", "-count=1", "./supervision", "./supervisionserver", "./example/supervision")
	goTestCmd.Dir = in.GoModDir
	goTestOut, goTestErr := goTestCmd.CombinedOutput()
	s3GoPkgTestsOK := goTestErr == nil
	_ = goTestOut

	// =========================================================================
	// QA-S3 Part B: Four Draft Use Cases Over Real HTTPS (Go PS + Go SS)
	// =========================================================================
	const (
		s3APIssuer     = "https://s3-go-ap.example"
		s3PSIssuer     = "https://s3-go-ps.example"
		s3ResIssuer    = "https://s3-go-res.example"
		s3OrgSSIssuer  = "https://s3-org-ss.example"
		s3HomeSSIssuer = "https://s3-home-ss.example"
	)
	s3AP, err := agentprovider.New(agentprovider.Config{
		Issuer:     s3APIssuer,
		SigningKey: newSKey("s3-ap-1", 0xb1),
		Clock:      clock,
		NewID:      nextSID,
	})
	must(err, "s3AP")
	registerTLS("s3-go-ap.example", s3AP.Handler())

	s3Res, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:      s3ResIssuer,
		SigningKey:  newSKey("s3-res-1", 0xb2),
		KeyResolver: sResolver,
		Clock:       clock,
		NewID:       nextSID,
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		RequiredScopes: func(*http.Request) []string { return []string{"records.read"} },
		ResolvePerson:  func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "s3-records-ok")
		}),
	})
	must(err, "s3Res")
	registerTLS("s3-go-res.example", s3Res.Handler())

	s3OrgSS := newSGoSSHost(s3OrgSSIssuer, newSKey("s3-org-1", 0xb3), clock, sResolver, false)
	registerTLS("s3-org-ss.example", s3OrgSS.handler)
	s3HomeSS := newSGoSSHost(s3HomeSSIssuer, newSKey("s3-home-1", 0xb4), clock, sResolver, true)
	registerTLS("s3-home-ss.example", s3HomeSS.handler)

	var s3RoutesMu sync.Mutex
	s3Routes := map[string]personserver.Supervisor{}
	s3SetRoute := func(agentID string, sup personserver.Supervisor) {
		s3RoutesMu.Lock()
		s3Routes[agentID] = sup
		s3RoutesMu.Unlock()
	}

	var s3HostPolicyCalls atomic.Int64
	s3SupStore := testutil.NewSupervisionStore()
	s3TokStore := testutil.NewMissionStore()
	s3PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:                s3PSIssuer,
		SigningKey:            newSKey("s3-ps-1", 0xb5),
		KeyResolver:           sResolver,
		Clock:                 clock,
		NewID:                 nextSID,
		Tokens:                s3TokStore,
		AgentTokenRevocations: testutil.NewAgentTokenRevocationStore(),
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: time.Hour}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			s3HostPolicyCalls.Add(1)
			return personserver.AuthorizationDecision{}, errors.New("host Authorize must not be called for supervised agent")
		},
		Missions: &personserver.MissionConfig{
			Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				s3HostPolicyCalls.Add(1)
				return personserver.MissionDecision{}, errors.New("host Missions.Approve must not be called")
			},
			AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error {
				s3HostPolicyCalls.Add(1)
				return errors.New("host AcceptUpdate must not be called")
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
				s3HostPolicyCalls.Add(1)
				return errors.New("host ConfirmPersonAcceptedCompletion must not be called")
			},
		},
		Permission: &personserver.PermissionConfig{
			Policy: func(context.Context, personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				s3HostPolicyCalls.Add(1)
				return personserver.PermissionPolicyResult{}, errors.New("host Permission.Policy must not be called")
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, ag personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				s3RoutesMu.Lock()
				defer s3RoutesMu.Unlock()
				sup, ok := s3Routes[ag.Agent]
				return sup, ok, nil
			},
			Store:      s3SupStore,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
		},
	})
	must(err, "s3PS")
	registerTLS("s3-go-ps.example", s3PS.Handler())

	s3NewAgent := func(local string, seed byte) (*clientagent.Client, string, string) {
		agID := "aauth:" + local + "@s3-go-ap.example"
		agKey := newSKey("s3-ag-"+local, seed)
		tok, iErr := s3AP.Issue(aauth.AgentTokenRequest{
			Agent:        agID,
			PersonServer: s3PSIssuer,
			PublicKey:    agKey.PublicJWK(),
			Lifetime:     time.Hour,
		})
		must(iErr, "s3AP.Issue "+local)
		cl, cErr := clientagent.New(ctx, clientagent.Config{
			Identifier:  agID,
			SigningKey:  agKey,
			AgentToken:  tok,
			KeyResolver: sResolver,
			HTTPClient:  httpClient,
			Clock:       clock,
		})
		must(cErr, "clientagent.New "+local)
		return cl, agID, tok
	}

	s3Alpha, s3AlphaID, s3AlphaTok := s3NewAgent("alpha", 0xb6)
	s3Beta, s3BetaID, _ := s3NewAgent("beta", 0xb7)
	s3OrgRoute := personserver.Supervisor{Issuer: s3OrgSSIssuer, Subject: "org-person-1", Tenant: "acme.example"}
	s3HomeRoute := personserver.Supervisor{Issuer: s3HomeSSIssuer, Subject: "home-person-1"}
	s3SetRoute(s3AlphaID, s3OrgRoute)
	s3SetRoute(s3BetaID, s3HomeRoute)

	// Connect s3HomeRoute interactively
	s3Conn1, s3ConnErr1 := s3PS.ConnectSupervisor(ctx, s3HomeRoute)
	s3HomeRef := path.Base(strings.TrimSuffix(s3Conn1.InteractionURL, "/"))
	s3Conf, s3ConfErr := s3HomeSS.server.ConsumeConnectCode(ctx, s3HomeRef, s3Conn1.InteractionCode)
	s3ConfirmErr := s3HomeSS.server.ConfirmConnect(ctx, s3HomeRef, "person-1")
	s3Conn2, s3ConnErr2 := s3PS.PollSupervisorConnect(ctx, s3HomeRoute)
	s3HomeConnectedOK := s3ConnErr1 == nil && s3Conn1.State == personserver.SupervisorConnecting &&
		s3ConfErr == nil && s3Conf.PersonServer == s3PSIssuer && s3ConfirmErr == nil &&
		s3ConnErr2 == nil && s3Conn2.State == personserver.SupervisorConnected

	// Use Case 1: Standing policy + ask + always remembered
	s3PTRes1, err := s3Alpha.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s3PSIssuer, Resource: s3ResIssuer})
	must(err, "s3Alpha.PersonToken")
	s3AlphaPT, s3AlphaPTOK := s3PTRes1.Token()
	s3RT1, err := s3Alpha.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s3AlphaPT, Scopes: []string{"records.read"},
	})
	must(err, "s3Alpha.Authorize")
	s3AT1, err := s3Alpha.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s3PSIssuer, ResourceToken: s3RT1, PresentedToken: s3AlphaPT,
	})
	must(err, "s3Alpha.Exchange")
	s3Perm1, err := s3Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "ArchiveEmail",
	})
	must(err, "s3Alpha.RequestPermission ArchiveEmail")
	s3Perm1Dec, s3Perm1OK := s3Perm1.Decision()
	s3StandingAllowOK := s3AlphaPTOK && s3AT1 != "" && s3Perm1OK && s3Perm1Dec.Permission() == aauth.PermissionGranted

	// Exception -> Ask -> Person approves with ApplyAlways -> SS remembers -> Next identical act allowed immediately
	s3AskPerm, err := s3Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "SendEmail", Description: "Quarterly update",
	})
	must(err, "s3Alpha.RequestPermission SendEmail 1")
	s3AskPending, s3AskWasPending := s3AskPerm.Pending()
	s3Reviews, err := s3PS.PendingSupervision(ctx, 10)
	must(err, "s3PS.PendingSupervision")
	s3AskReviewOK := s3AskWasPending && len(s3Reviews) == 1 && s3Reviews[0].Ask != nil &&
		s3Reviews[0].Ask.Summary == "Send an email for you?" && len(s3Reviews[0].ApplyOptions) == 2
	err = s3PS.ResolveSupervision(ctx, s3Reviews[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow,
		Apply:  supervision.ApplyAlways,
	})
	must(err, "s3PS.ResolveSupervision SendEmail")
	sAdvanceClock(5 * time.Second)
	s3AskPolled, err := s3Alpha.PollPermission(ctx, s3AskPending)
	must(err, "s3Alpha.PollPermission SendEmail")
	s3AskPolledDec, s3AskPolledOK := s3AskPolled.Decision()
	_, err = s3PS.DeliverSupervisionEvents(ctx, s3OrgRoute)
	must(err, "s3PS.DeliverSupervisionEvents s3OrgRoute")
	s3AgainPerm, err := s3Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "SendEmail", Description: "Follow-up email",
	})
	must(err, "s3Alpha.RequestPermission SendEmail 2")
	s3AgainDec, s3AgainImmediateOK := s3AgainPerm.Decision()
	s3UseCase1OK := s3StandingAllowOK && s3AskReviewOK && s3AskPolledOK &&
		s3AskPolledDec.Permission() == aauth.PermissionGranted &&
		s3AgainImmediateOK && s3AgainDec.Permission() == aauth.PermissionGranted

	// Use Case 2: Multi-SS routing per agent (each SS sees only its own agent)
	s3BetaPTRes, err := s3Beta.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s3PSIssuer, Resource: s3ResIssuer})
	must(err, "s3Beta.PersonToken")
	_, s3BetaPTOK := s3BetaPTRes.Token()
	s3UseCase2OK := s3HomeConnectedOK && s3BetaPTOK &&
		s3OrgSS.sawAgent(s3AlphaID) && !s3OrgSS.sawAgent(s3BetaID) &&
		s3HomeSS.sawAgent(s3BetaID) && !s3HomeSS.sawAgent(s3AlphaID)

	// Use Case 3: Supervision server down -> fallback to person -> outbox replay in order
	s3HomeSS.setOffline(true)
	s3OfflinePerm, err := s3Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "BookTrain",
	})
	must(err, "s3Beta.RequestPermission BookTrain offline")
	s3OfflinePending, s3OfflineWasPending := s3OfflinePerm.Pending()
	s3OfflineReviews, err := s3PS.PendingSupervision(ctx, 10)
	must(err, "s3PS.PendingSupervision offline")
	s3OfflineReviewOK := s3OfflineWasPending && len(s3OfflineReviews) == 1 && s3OfflineReviews[0].SupervisorUnavailable
	err = s3PS.ResolveSupervision(ctx, s3OfflineReviews[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow,
	})
	must(err, "s3PS.ResolveSupervision offline")
	sAdvanceClock(5 * time.Second)
	s3OfflinePolled, err := s3Beta.PollPermission(ctx, s3OfflinePending)
	must(err, "s3Beta.PollPermission offline")
	s3OfflineDec, s3OfflineDecOK := s3OfflinePolled.Decision()
	s3ToldBeforeWake := len(s3HomeSS.toldNames())
	s3HomeSS.setOffline(false)
	_, err = s3PS.DeliverSupervisionEvents(ctx, s3HomeRoute)
	must(err, "s3PS.DeliverSupervisionEvents s3HomeRoute wake")
	s3ToldAfterWake := s3HomeSS.toldNames()[s3ToldBeforeWake:]
	s3UseCase3OK := s3OfflineReviewOK && s3OfflineDecOK && s3OfflineDec.Permission() == aauth.PermissionGranted &&
		slices.Equal(s3ToldAfterWake, []string{"person_token.issued", "decision.resolved"})

	// Use Case 4: Offline public-key verification of stored decisions & mutation rejection
	var s3SignedEx *supervision.Exchange
	for _, entry := range s3SupStore.Log() {
		if entry.Exchange != nil && entry.Exchange.Signed && entry.Supervisor.Issuer == s3OrgSSIssuer {
			exCopy := entry.Exchange.Clone()
			s3SignedEx = &exCopy
			break
		}
	}
	sAdvanceClock(time.Hour)
	var s3VerifyExOK, s3VerifyDecOK, s3MutRespRejected, s3MutReqRejected, s3MutSigRejected bool
	if s3SignedEx != nil {
		verResp, vErr := supervision.VerifyExchange(ctx, *s3SignedEx, sResolver)
		s3VerifyExOK = vErr == nil && verResp.Signer() == s3OrgSSIssuer
		reqHTTP, _ := http.NewRequestWithContext(ctx, s3SignedEx.Request.Method, s3SignedEx.Request.URL, bytes.NewReader(s3SignedEx.Request.Body))
		reqHTTP.Header = s3SignedEx.Request.Header.Clone()
		_, dErr := supervision.VerifyDecision(ctx, s3SignedEx.Response.Status, s3SignedEx.Response.Header, s3SignedEx.Response.Body, reqHTTP, s3SignedEx.Supervisor, sResolver, aauth.ClockFunc(func() time.Time { return s3SignedEx.ReceivedAt }))
		s3VerifyDecOK = dErr == nil

		mutResp := s3SignedEx.Clone()
		mutResp.Response.Body = []byte(strings.Replace(string(mutResp.Response.Body), `"allow"`, `"deny"`, 1))
		_, mutRespErr := supervision.VerifyExchange(ctx, mutResp, sResolver)
		s3MutRespRejected = mutRespErr != nil

		mutReq := s3SignedEx.Clone()
		mutReq.Request.Header.Set("Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
		_, mutReqErr := supervision.VerifyExchange(ctx, mutReq, sResolver)
		s3MutReqRejected = mutReqErr != nil

		mutSig := s3SignedEx.Clone()
		mutSig.Response.Header.Set("Signature", "sig=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==:")
		_, mutSigErr := supervision.VerifyExchange(ctx, mutSig, sResolver)
		s3MutSigRejected = mutSigErr != nil
	}
	s3UseCase4OK := s3VerifyExOK && s3VerifyDecOK && s3MutRespRejected && s3MutReqRejected && s3MutSigRejected

	// =========================================================================
	// QA-S4: Go Supervision Answer Types, Missions, Four-Party & Recovery
	// =========================================================================
	// Re-issue fresh agent tokens after advancing clock 1h
	s3Alpha, s3AlphaID, s3AlphaTok = s3NewAgent("alpha", 0xb6)
	s3Beta, s3BetaID, _ = s3NewAgent("beta", 0xb7)
	_ = s3AlphaTok

	// 1. Answer Types:
	// (a) Narrowing allow (scope + exp)
	s3BetaPT2Res, err := s3Beta.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s3PSIssuer, Resource: s3ResIssuer})
	must(err, "s3Beta.PersonToken 2")
	s3BetaPT2, _ := s3BetaPT2Res.Token()
	s3BetaRT2, err := s3Beta.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s3BetaPT2, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s3Beta.Authorize narrow")
	s3NarrowBefore := clock.Now().Unix()
	s3HomeSS.setAuthMode("narrow")
	s3NarrowAT, err := s3Beta.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s3PSIssuer, ResourceToken: s3BetaRT2, PresentedToken: s3BetaPT2,
	})
	s3HomeSS.setAuthMode("")
	must(err, "s3Beta.Exchange narrow")
	s3NarrowClaims, err := aauth.VerifyAuthToken(ctx, s3NarrowAT, sResolver, clock)
	must(err, "VerifyAuthToken s3NarrowAT")
	s4NarrowAllowOK := s3NarrowClaims.Scope == "records.read" && s3NarrowClaims.ExpiresAt == s3NarrowBefore+900

	// (b) Deny on permission (with reason) & deny on token (403 access_denied) & person deny after ask
	s4DenyPerm, err := s3Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "DeleteMailbox",
	})
	must(err, "s3Alpha.RequestPermission DeleteMailbox")
	s4DenyPermDec, s4DenyPermHasDec := s4DenyPerm.Decision()
	s3AlphaPT2Res, err := s3Alpha.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s3PSIssuer, Resource: s3ResIssuer})
	must(err, "s3Alpha.PersonToken 2")
	s3AlphaPT2, _ := s3AlphaPT2Res.Token()
	s3AlphaRT2, err := s3Alpha.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s3AlphaPT2, Scopes: []string{"records.read"},
	})
	must(err, "s3Alpha.Authorize deny-token")
	s3OrgSS.setAuthMode("deny")
	_, s4DenyTokErr := s3Alpha.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s3PSIssuer, ResourceToken: s3AlphaRT2, PresentedToken: s3AlphaPT2,
	})
	s3OrgSS.setAuthMode("")
	var s4DenyTokProb *aauth.ProblemError
	s4DenyOK := s4DenyPermHasDec && s4DenyPermDec.Permission() == aauth.PermissionDenied &&
		s4DenyPermDec.Reason() == "Deleting a mailbox is never delegated." &&
		errors.As(s4DenyTokErr, &s4DenyTokProb) && s4DenyTokProb.Status == 403

	// (c) SS 202 deferral -> AdvanceSupervision -> ResolveDecision -> PollPermission
	s3HomeSS.setDefer(true)
	s4DeferPerm, err := s3Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, Action: "PayInvoice",
	})
	must(err, "s3Beta.RequestPermission PayInvoice defer")
	s3HomeSS.setDefer(false)
	s4DeferPend, s4DeferWasPend := s4DeferPerm.Pending()
	s4DeferRevs, err := s3PS.PendingSupervision(ctx, 10)
	must(err, "s3PS.PendingSupervision defer")
	s4EarlyAdvErr := s3PS.AdvanceSupervision(ctx, s4DeferRevs[0].Reference)
	s4ResDecErr := s3HomeSS.server.ResolveDecision(ctx, s3PSIssuer, s4DeferRevs[0].SDI, supervisionserver.DecisionResult{
		Decision: &supervision.Decision{Verdict: supervision.VerdictAllow},
	})
	sAdvanceClock(5 * time.Second)
	s4AdvErr := s3PS.AdvanceSupervision(ctx, s4DeferRevs[0].Reference)
	s4DeferPolled, err := s3Beta.PollPermission(ctx, s4DeferPend)
	must(err, "s3Beta.PollPermission defer")
	s4DeferDec, s4DeferDecOK := s4DeferPolled.Decision()
	s4DeferOK := s4DeferWasPend && len(s4DeferRevs) == 1 &&
		s4DeferRevs[0].State == personserver.SupervisedWaitingForSupervisor &&
		errors.Is(s4EarlyAdvErr, personserver.ErrSupervisionNotReady) &&
		s4ResDecErr == nil && s4AdvErr == nil && s4DeferDecOK && s4DeferDec.Permission() == aauth.PermissionGranted

	// (d) Clarification: SS-initiated on /token & /permission, plus person-initiated AskSupervisedAgent
	s3BetaRTClar, err := s3Beta.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s3BetaPT2, Scopes: []string{"records.read"},
	})
	must(err, "s3Beta.Authorize clarify-token")
	s3HomeSS.setAuthMode("clarify")
	s4ClarEx, err := s3Beta.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s3PSIssuer, ResourceToken: s3BetaRTClar, PresentedToken: s3BetaPT2,
		Capabilities: []string{"clarification"},
	})
	must(err, "s3Beta.BeginExchange clarify-token")
	s4ClarPend, s4ClarWasPend := s4ClarEx.Pending()
	s4ClarQ, s4ClarHasQ := s4ClarPend.Clarification()
	s4AnsClarErr := s3Beta.AnswerClarification(ctx, s4ClarPend, "Only this week invoices.")
	sAdvanceClock(5 * time.Second)
	s4ClarPolled, err := s3Beta.PollExchange(ctx, s4ClarPend)
	s3HomeSS.setAuthMode("")
	must(err, "s3Beta.PollExchange clarify-token")
	s4ClarTok, s4ClarTokOK := s4ClarPolled.Token()

	// Person-initiated AskSupervisedAgent after an ask
	s3BetaRTAsk, err := s3Beta.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s3BetaPT2, Scopes: []string{"records.read"},
	})
	must(err, "s3Beta.Authorize ask-token")
	s3HomeSS.setAuthMode("ask")
	s4PClarEx, err := s3Beta.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s3PSIssuer, ResourceToken: s3BetaRTAsk, PresentedToken: s3BetaPT2,
		Capabilities: []string{"clarification"},
	})
	s3HomeSS.setAuthMode("")
	must(err, "s3Beta.BeginExchange ask-token")
	s4PClarPend1, _ := s4PClarEx.Pending()
	s4PClarRevs, _ := s3PS.PendingSupervision(ctx, 10)
	_ = s3PS.AskSupervisedAgent(ctx, s4PClarRevs[0].Reference, supervision.Clarification{Question: "Why now?"})
	sAdvanceClock(5 * time.Second)
	s4PClarPolled1, err := s3Beta.PollExchange(ctx, s4PClarPend1)
	must(err, "s3Beta.PollExchange ask-token 1")
	s4PClarPend2, _ := s4PClarPolled1.Pending()
	s4PClarQ2, s4PClarHasQ2 := s4PClarPend2.Clarification()
	_ = s3Beta.AnswerClarification(ctx, s4PClarPend2, "Quarter close.")
	_ = s3PS.ResolveSupervision(ctx, s4PClarRevs[0].Reference, personserver.SupervisionAnswer{Answer: supervision.AnswerDeny})
	sAdvanceClock(5 * time.Second)
	_, s4PClarDenyErr := s3Beta.PollExchange(ctx, s4PClarPend2)
	s4ClarifyOK := s4ClarWasPend && s4ClarHasQ && s4ClarQ.Question() == "Which records, and why?" &&
		s4AnsClarErr == nil && s4ClarTokOK && s4ClarTok != "" &&
		s4PClarHasQ2 && s4PClarQ2.Question() == "Why now?" && s4PClarDenyErr != nil

	// 2. Missions under supervision (proposal, update, completion, approved & terminated reports)
	s4MissProp, err := s3Alpha.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: s3PSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# Quarterly report\n\nCollect the figures.",
			Tools: []aauth.MissionTool{
				{Name: "WebSearch", Description: "Search the web"},
				{Name: "SendEmail", Description: "Send email"},
			},
			Resources: []string{s3ResIssuer},
		},
	})
	must(err, "s3Alpha.BeginMission")
	s4MissApp, s4MissAppOK := s4MissProp.Approval()
	s4Miss := s4MissApp.Mission()
	_, s4UpdErr := s3Alpha.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: s3PSIssuer, MissionS256: s4Miss.S256, Description: "Figures arrive a day late.",
	})
	s4CompErr := s3Alpha.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: s3PSIssuer, MissionS256: s4Miss.S256, Summary: "Report sent.",
	})
	_, err = s3PS.DeliverSupervisionEvents(ctx, s3OrgRoute)
	must(err, "s3PS.DeliverSupervisionEvents mission")
	s4OrgTold := s3OrgSS.toldNames()
	s4AppIdx := slices.Index(s4OrgTold, "approved")
	s4TermIdx := slices.Index(s4OrgTold, "terminated")
	_, s4AfterCompErr := s3Alpha.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: s3PSIssuer, MissionS256: s4Miss.S256, Description: "After completion",
	})
	s4MissionsOK := s4MissAppOK && strings.HasSuffix(s4Miss.Blob.Description, "Keep work data inside the organization.") &&
		len(s4Miss.Blob.ApprovedTools) == 1 && s4Miss.Blob.ApprovedTools[0].Name == "WebSearch" &&
		s4UpdErr == nil && s4CompErr == nil && s4AppIdx >= 0 && s4TermIdx > s4AppIdx && s4AfterCompErr != nil

	// 3. Recovery:
	// (a) Routing change to a second Go SS replays journal (agent.bound + approved mission) before /decision
	s4RecProp, err := s3Beta.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: s3PSIssuer,
		Proposal:     aauth.MissionProposal{Description: "# Plan the offsite"},
	})
	must(err, "s3Beta.BeginMission recovery")
	s4RecApp, _ := s4RecProp.Approval()
	s4RecMiss := s4RecApp.Mission()
	s3SetRoute(s3BetaID, s3OrgRoute)
	s4MovedPerm, err := s3Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, MissionS256: s4RecMiss.S256, Action: "ReserveRoom",
	})
	must(err, "s3Beta.RequestPermission after routing change")
	s4MovedDec, s4MovedOK := s4MovedPerm.Decision()
	s3OrgSS.mu.Lock()
	var s4MovedLastReq supervisionserver.DecisionRequest
	if len(s3OrgSS.requests) > 0 {
		s4MovedLastReq = s3OrgSS.requests[len(s3OrgSS.requests)-1]
	}
	s3OrgSS.mu.Unlock()
	s4RoutingReplayOK := s4MovedOK && s4MovedDec.Permission() == aauth.PermissionGranted &&
		s4MovedLastReq.Request.Agent == s3BetaID && s4MovedLastReq.Mission != nil &&
		string(s4MovedLastReq.Mission.Blob) == string(s4RecMiss.ExactJSON)

	// (b) Supervision server loses its records -> 404 unknown_sub + 404 unknown_mission -> reconnect + mission replay + retry
	s3OrgSS.forgetEverything()
	s4LostPerm, err := s3Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s3PSIssuer, MissionS256: s4RecMiss.S256, Action: "ReserveCatering",
	})
	must(err, "s3Beta.RequestPermission after forgetEverything")
	s4LostDec, s4LostOK := s4LostPerm.Decision()
	s4UnknownRecoveryOK := s4LostOK && s4LostDec.Permission() == aauth.PermissionGranted &&
		slices.Contains(s3OrgSS.toldNames(), "approved")

	// 4. Four-Party under supervision in Go
	const (
		s4FedPSIssuer  = "https://s4-go-fed-ps.example"
		s4ASIssuer     = "https://s4-go-as.example"
		s4FedResIssuer = "https://s4-go-fed-res.example"
	)
	var s4ASDefer atomic.Bool
	s4ASDefStore := testutil.NewAccessAuthorizationStore()
	s4AS, err := accessserver.New(accessserver.Config{
		Issuer:            s4ASIssuer,
		SigningKey:        newSKey("s4-as-1", 0xb8),
		KeyResolver:       sResolver,
		Clock:             clock,
		NewID:             nextSID,
		TrustPersonServer: func(context.Context, string) error { return nil },
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			if s4ASDefer.Load() {
				return accessserver.Decision{Pending: &accessserver.PendingDecision{RetryAfter: time.Second}}, nil
			}
			return accessserver.Decision{Scopes: append([]string(nil), req.Scopes...), Lifetime: 30 * time.Minute}, nil
		},
		Deferred: &accessserver.DeferredConfig{
			Store:    s4ASDefStore,
			Lifetime: 30 * time.Minute,
		},
	})
	must(err, "s4AS")
	registerTLS("s4-go-as.example", s4AS.Handler())

	s4FedRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:       s4FedResIssuer,
		AccessServer: s4ASIssuer,
		SigningKey:   newSKey("s4-fed-res-1", 0xb9),
		KeyResolver:  sResolver,
		Clock:        clock,
		NewID:        nextSID,
		ScopeDescriptions: map[string]string{
			"records.read":  "Read records",
			"records.write": "Write records",
		},
		RequiredScopes: func(*http.Request) []string { return []string{"records.read", "records.write"} },
		ResolvePerson:  func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "s4-fed-records")
		}),
	})
	must(err, "s4FedRes")
	registerTLS("s4-go-fed-res.example", s4FedRes.Handler())

	s4FedSupStore := testutil.NewSupervisionStore()
	s4FedDefStore := testutil.NewFederatedAuthorizationStore()
	s4FedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:               s4FedPSIssuer,
		SigningKey:           newSKey("s4-fed-ps-1", 0xba),
		KeyResolver:          sResolver,
		HTTPClient:           httpClient,
		Clock:                clock,
		NewID:                nextSID,
		Tokens:               testutil.NewMissionStore(),
		Deferred:             &personserver.FederatedDeferredConfig{Store: s4FedDefStore, Lifetime: 30 * time.Minute},
		AccessServerEndpoint: func(context.Context, string) (string, error) { return s4ASIssuer + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-s4-fed", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			s3HostPolicyCalls.Add(1)
			return errors.New("host Consent must not be called")
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(context.Context, personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				return s3OrgRoute, true, nil
			},
			Store:      s4FedSupStore,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
		},
	})
	must(err, "s4FedPS")
	registerTLS("s4-go-fed-ps.example", s4FedPS.Handler())

	s4FedAgKey := newSKey("s4-fed-ag", 0xbb)
	s4FedAgTok, err := s3AP.Issue(aauth.AgentTokenRequest{
		Agent:        "aauth:fed-ag@s3-go-ap.example",
		PersonServer: s4FedPSIssuer,
		PublicKey:    s4FedAgKey.PublicJWK(),
		Lifetime:     time.Hour,
	})
	must(err, "s3AP.Issue fed-ag")
	s4FedAg, err := clientagent.New(ctx, clientagent.Config{
		Identifier:  "aauth:fed-ag@s3-go-ap.example",
		SigningKey:  s4FedAgKey,
		AgentToken:  s4FedAgTok,
		KeyResolver: sResolver,
		HTTPClient:  httpClient,
		Clock:       clock,
	})
	must(err, "clientagent.New s4FedAg")

	s4FedPTRes, err := s4FedAg.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s4FedPSIssuer, Resource: s4FedResIssuer})
	must(err, "s4FedAg.PersonToken")
	s4FedPT, _ := s4FedPTRes.Token()
	s4FedRT1, err := s4FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s4FedPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s4FedAg.Authorize 1")
	s4FedAT1, err := s4FedAg.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s4FedPSIssuer, ResourceToken: s4FedRT1, PresentedToken: s4FedPT,
	})
	must(err, "s4FedAg.Exchange 1")
	s4FedClaims1, err := aauth.VerifyAuthToken(ctx, s4FedAT1, sResolver, clock)
	must(err, "VerifyAuthToken s4FedAT1")
	s4FourPartyAllowOK := s4FedClaims1.Issuer == s4ASIssuer

	// Narrowing allow on 4-party is refused (403)
	s4FedRT2, err := s4FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s4FedPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s4FedAg.Authorize 2")
	s3OrgSS.setAuthMode("narrow")
	_, s4FedNarrowErr := s4FedAg.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s4FedPSIssuer, ResourceToken: s4FedRT2, PresentedToken: s4FedPT,
	})
	s3OrgSS.setAuthMode("")
	var s4FedNarrowProb *aauth.ProblemError
	s4FourPartyNarrowRefusedOK := errors.As(s4FedNarrowErr, &s4FedNarrowProb) && s4FedNarrowProb.Status == 403

	// Immediate SS allow + AS 202 deferral -> AdvanceFederation -> 200 OK
	s4ASDefer.Store(true)
	s4FedRT3, err := s4FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s4FedPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s4FedAg.Authorize 3")
	s4FedDefEx, err := s4FedAg.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s4FedPSIssuer, ResourceToken: s4FedRT3, PresentedToken: s4FedPT,
	})
	must(err, "s4FedAg.BeginExchange AS defer")
	s4FedDefPend, s4FedDefWasPend := s4FedDefEx.Pending()
	s4ASDefer.Store(false)
	sAdvanceClock(5 * time.Second)
	s4FedDefLoc := strings.TrimSuffix(s4FedDefPend.Location(), "/")
	s4FedDefRef := s4FedDefLoc[strings.LastIndex(s4FedDefLoc, "/")+1:]
	_ = s4FedPS.AdvanceFederation(ctx, s4FedDefRef)
	s4FedDefPolled, err := s4FedAg.PollExchange(ctx, s4FedDefPend)
	must(err, "s4FedAg.PollExchange AS defer")
	s4FedDefTok, s4FedDefTokOK := s4FedDefPolled.Token()

	// Deferred SS ask + AS 202 deferral -> DeferredCompositionError{Reason: "supervision"}
	s4ASDefer.Store(true)
	s3OrgSS.setAuthMode("ask")
	s4FedRT4, err := s4FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s4FedPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s4FedAg.Authorize 4")
	s4FedAskASEx, err := s4FedAg.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s4FedPSIssuer, ResourceToken: s4FedRT4, PresentedToken: s4FedPT,
	})
	s3OrgSS.setAuthMode("")
	must(err, "s4FedAg.BeginExchange ask+AS defer")
	s4FedAskASPend, s4FedAskASWasPend := s4FedAskASEx.Pending()
	s4FedAskRevs, _ := s4FedPS.PendingSupervision(ctx, 10)
	if len(s4FedAskRevs) > 0 {
		_ = s4FedPS.ResolveSupervision(ctx, s4FedAskRevs[0].Reference, personserver.SupervisionAnswer{
			Answer: supervision.AnswerAllow,
		})
	}
	sAdvanceClock(5 * time.Second)
	_, s4AskASPollErr := s4FedAg.PollExchange(ctx, s4FedAskASPend)
	s4ASDefer.Store(false)
	var s4AskASProb *aauth.ProblemError
	s4FourPartyAskASDeferBoundaryOK := s4FedDefWasPend && s4FedDefTokOK && s4FedDefTok != "" &&
		s4FedAskASWasPend && errors.As(s4AskASPollErr, &s4AskASProb) && s4AskASProb.Status == 500 &&
		s4AskASProb.Code == "server_error"

	s4HostNeverCalledOK := s3HostPolicyCalls.Load() == 0

	// =========================================================================
	// QA-S5: Cross-Language Direction 1 (Go Person Server <-> Rust Supervision Server)
	// =========================================================================
	s5Ctl := func(ssIssuer string, payload map[string]any) map[string]any {
		b, _ := json.Marshal(payload)
		req, rErr := http.NewRequestWithContext(ctx, http.MethodPost, ssIssuer+"/__qa-ctl", bytes.NewReader(b))
		must(rErr, "s5Ctl NewRequest")
		req.Header.Set("Content-Type", "application/json")
		resp, dErr := httpClient.Do(req)
		must(dErr, "s5Ctl Do "+ssIssuer)
		defer resp.Body.Close()
		var out map[string]any
		must(json.NewDecoder(resp.Body).Decode(&out), "s5Ctl Decode")
		return out
	}

	const (
		s5PSIssuer    = "https://s5-go-ps.example"
		s5FedPSIssuer = "https://s5-go-fed-ps.example"
	)
	s5PSKey := newSKey("s5-ps-1", 0xc1)
	s5FedPSKey := newSKey("s5-fed-ps-1", 0xc2)

	var s5RoutesMu sync.Mutex
	s5Routes := map[string]personserver.Supervisor{}
	s5SetRoute := func(agentID string, sup personserver.Supervisor) {
		s5RoutesMu.Lock()
		s5Routes[agentID] = sup
		s5RoutesMu.Unlock()
	}

	var s5HostPolicyCalls atomic.Int64
	s5SupStore := testutil.NewSupervisionStore()
	s5PS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:                s5PSIssuer,
		SigningKey:            s5PSKey,
		KeyResolver:           sResolver,
		Clock:                 clock,
		NewID:                 nextSID,
		Tokens:                testutil.NewMissionStore(),
		AgentTokenRevocations: testutil.NewAgentTokenRevocationStore(),
		BindPerson: func(_ context.Context, req personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-" + strings.TrimPrefix(req.Resource, "https://"), Lifetime: time.Hour}, nil
		},
		Authorize: func(context.Context, personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			s5HostPolicyCalls.Add(1)
			return personserver.AuthorizationDecision{}, errors.New("host Authorize must not be called")
		},
		Missions: &personserver.MissionConfig{
			Approve: func(context.Context, personserver.MissionApprovalRequest) (personserver.MissionDecision, error) {
				s5HostPolicyCalls.Add(1)
				return personserver.MissionDecision{}, errors.New("host Missions.Approve must not be called")
			},
			AcceptUpdate: func(context.Context, personserver.MissionUpdatePolicyRequest) error {
				s5HostPolicyCalls.Add(1)
				return errors.New("host AcceptUpdate must not be called")
			},
			ConfirmPersonAcceptedCompletion: func(context.Context, personserver.MissionCompletionPolicyRequest) error {
				s5HostPolicyCalls.Add(1)
				return errors.New("host ConfirmPersonAcceptedCompletion must not be called")
			},
		},
		Permission: &personserver.PermissionConfig{
			Policy: func(context.Context, personserver.PermissionPolicyRequest) (personserver.PermissionPolicyResult, error) {
				s5HostPolicyCalls.Add(1)
				return personserver.PermissionPolicyResult{}, errors.New("host Permission.Policy must not be called")
			},
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, ag personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				s5RoutesMu.Lock()
				defer s5RoutesMu.Unlock()
				sup, ok := s5Routes[ag.Agent]
				return sup, ok, nil
			},
			Store:      s5SupStore,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
		},
	})
	must(err, "s5PS")
	s5PSSrv, s5PSCer := registerTLS("s5-go-ps.example", s5PS.Handler())

	s5FedSupStore := testutil.NewSupervisionStore()
	s5FedDefStore := testutil.NewFederatedAuthorizationStore()
	s5FedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:               s5FedPSIssuer,
		SigningKey:           s5FedPSKey,
		KeyResolver:          sResolver,
		HTTPClient:           httpClient,
		Clock:                clock,
		NewID:                nextSID,
		Tokens:               testutil.NewMissionStore(),
		Deferred:             &personserver.FederatedDeferredConfig{Store: s5FedDefStore, Lifetime: 30 * time.Minute},
		AccessServerEndpoint: func(context.Context, string) (string, error) { return s4ASIssuer + "/token", nil },
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "person-at-s5-fed", Lifetime: time.Hour}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			s5HostPolicyCalls.Add(1)
			return errors.New("host Consent must not be called")
		},
		Supervision: &personserver.SupervisionConfig{
			Route: func(_ context.Context, ag personserver.SupervisedAgent) (personserver.Supervisor, bool, error) {
				s5RoutesMu.Lock()
				defer s5RoutesMu.Unlock()
				sup, ok := s5Routes[ag.Agent]
				return sup, ok, nil
			},
			Store:      s5FedSupStore,
			HTTPClient: httpClient,
			Admit:      func(context.Context, string) error { return nil },
		},
	})
	must(err, "s5FedPS")
	s5FedPSSrv, s5FedPSCer := registerTLS("s5-go-fed-ps.example", s5FedPS.Handler())

	// Register s5-go-ps.example and s5-go-fed-ps.example with Rust SS1 & SS2
	for _, ss := range []string{in.S5RustSS1Issuer, in.S5RustSS2Issuer} {
		s5Ctl(ss, map[string]any{
			"action":   "trust_ps",
			"issuer":   s5PSIssuer,
			"addr":     s5PSSrv.Listener.Addr().String(),
			"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s5PSCer})),
		})
		s5Ctl(ss, map[string]any{
			"action":   "trust_ps",
			"issuer":   s5FedPSIssuer,
			"addr":     s5FedPSSrv.Listener.Addr().String(),
			"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s5FedPSCer})),
		})
	}
	s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})

	s5NewAgent := func(local string, psIssuer string, seed byte) (*clientagent.Client, string) {
		agID := "aauth:" + local + "@s3-go-ap.example"
		agKey := newSKey("s5-ag-"+local, seed)
		tok, iErr := s3AP.Issue(aauth.AgentTokenRequest{
			Agent:        agID,
			PersonServer: psIssuer,
			PublicKey:    agKey.PublicJWK(),
			Lifetime:     time.Hour,
		})
		must(iErr, "s3AP.Issue s5 "+local)
		cl, cErr := clientagent.New(ctx, clientagent.Config{
			Identifier:  agID,
			SigningKey:  agKey,
			AgentToken:  tok,
			KeyResolver: sResolver,
			HTTPClient:  httpClient,
			Clock:       clock,
		})
		must(cErr, "clientagent.New s5 "+local)
		return cl, agID
	}

	s5Alpha, s5AlphaID := s5NewAgent("s5-alpha", s5PSIssuer, 0xc3)
	s5Beta, s5BetaID := s5NewAgent("s5-beta", s5PSIssuer, 0xc4)
	s5FedAg, s5FedAgID := s5NewAgent("s5-fed", s5FedPSIssuer, 0xc5)

	s5SS1Route := personserver.Supervisor{Issuer: in.S5RustSS1Issuer, Subject: "rust-ss1-sub-1", Tenant: "acme.example"}
	s5SS2Route := personserver.Supervisor{Issuer: in.S5RustSS2Issuer, Subject: "rust-ss2-sub-1"}
	s5SetRoute(s5AlphaID, s5SS1Route)
	s5SetRoute(s5BetaID, s5SS2Route)
	s5SetRoute(s5FedAgID, s5SS1Route)

	// Interactive connect of s5SS2Route (Go PS -> Rust SS2)
	s5Conn1, s5ConnErr1 := s5PS.ConnectSupervisor(ctx, s5SS2Route)
	s5ConfRes := s5Ctl(in.S5RustSS2Issuer, map[string]any{
		"action": "confirm_connect",
		"code":   s5Conn1.InteractionCode,
	})
	s5Conn2, s5ConnErr2 := s5PS.PollSupervisorConnect(ctx, s5SS2Route)
	s5ConnectOK := s5ConnErr1 == nil && s5Conn1.State == personserver.SupervisorConnecting &&
		s5ConfRes["ok"] == true && s5ConfRes["ps"] == s5PSIssuer &&
		s5ConnErr2 == nil && s5Conn2.State == personserver.SupervisorConnected

	// S5 Use Case 1: Standing policy + ask + always remembered by Rust SS
	s5PTRes1, err := s5Alpha.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s5PSIssuer, Resource: s3ResIssuer})
	must(err, "s5Alpha.PersonToken")
	_, s5AlphaPTOK := s5PTRes1.Token()
	s5Perm1, err := s5Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "ArchiveEmail",
	})
	must(err, "s5Alpha.RequestPermission ArchiveEmail")
	s5Perm1Dec, s5Perm1OK := s5Perm1.Decision()

	s5AskPerm, err := s5Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "SendEmail",
	})
	must(err, "s5Alpha.RequestPermission SendEmail 1")
	s5AskPend, s5AskWasPend := s5AskPerm.Pending()
	s5Revs, err := s5PS.PendingSupervision(ctx, 10)
	must(err, "s5PS.PendingSupervision")
	s5AskRevOK := s5AskWasPend && len(s5Revs) == 1 && s5Revs[0].Ask != nil && len(s5Revs[0].ApplyOptions) == 2
	err = s5PS.ResolveSupervision(ctx, s5Revs[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow,
		Apply:  supervision.ApplyAlways,
	})
	must(err, "s5PS.ResolveSupervision SendEmail")
	sAdvanceClock(5 * time.Second)
	s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5AskPolled, err := s5Alpha.PollPermission(ctx, s5AskPend)
	must(err, "s5Alpha.PollPermission SendEmail")
	s5AskPolledDec, s5AskPolledOK := s5AskPolled.Decision()
	_, err = s5PS.DeliverSupervisionEvents(ctx, s5SS1Route)
	must(err, "s5PS.DeliverSupervisionEvents s5SS1Route")
	s5AgainPerm, err := s5Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "SendEmail",
	})
	must(err, "s5Alpha.RequestPermission SendEmail 2")
	s5AgainDec, s5AgainOK := s5AgainPerm.Decision()
	s5UseCase1OK := s5AlphaPTOK && s5Perm1OK && s5Perm1Dec.Permission() == aauth.PermissionGranted &&
		s5AskRevOK && s5AskPolledOK && s5AskPolledDec.Permission() == aauth.PermissionGranted &&
		s5AgainOK && s5AgainDec.Permission() == aauth.PermissionGranted

	// S5 Use Case 2: Multi-SS routing (Rust SS1 sees only s5-alpha, Rust SS2 sees only s5-beta)
	s5BetaPTRes, err := s5Beta.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s5PSIssuer, Resource: s3ResIssuer})
	must(err, "s5Beta.PersonToken")
	s5BetaPT, s5BetaPTOK := s5BetaPTRes.Token()
	s5SS1InspectAlpha := s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "inspect", "agent": s5AlphaID, "ps": s5PSIssuer, "sub": "rust-ss1-sub-1"})
	s5SS1InspectBeta := s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "inspect", "agent": s5BetaID, "ps": s5PSIssuer, "sub": "rust-ss1-sub-1"})
	s5SS2InspectBeta := s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "inspect", "agent": s5BetaID, "ps": s5PSIssuer, "sub": "rust-ss2-sub-1"})
	s5SS2InspectAlpha := s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "inspect", "agent": s5AlphaID, "ps": s5PSIssuer, "sub": "rust-ss2-sub-1"})
	s5UseCase2OK := s5ConnectOK && s5BetaPTOK &&
		s5SS1InspectAlpha["saw_agent"] == true && s5SS1InspectBeta["saw_agent"] == false &&
		s5SS2InspectBeta["saw_agent"] == true && s5SS2InspectAlpha["saw_agent"] == false

	// S5 Use Case 3: Rust SS2 down -> Go PS fallback to person -> outbox replay in order when Rust SS2 wakes
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_offline", "offline": true})
	s5OffPerm, err := s5Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "BookTrain",
	})
	must(err, "s5Beta.RequestPermission BookTrain offline")
	s5OffPend, s5OffWasPend := s5OffPerm.Pending()
	s5OffRevs, err := s5PS.PendingSupervision(ctx, 10)
	must(err, "s5PS.PendingSupervision offline")
	s5OffRevOK := s5OffWasPend && len(s5OffRevs) == 1 && s5OffRevs[0].SupervisorUnavailable
	err = s5PS.ResolveSupervision(ctx, s5OffRevs[0].Reference, personserver.SupervisionAnswer{
		Answer: supervision.AnswerAllow,
	})
	must(err, "s5PS.ResolveSupervision offline")
	sAdvanceClock(5 * time.Second)
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5OffPolled, err := s5Beta.PollPermission(ctx, s5OffPend)
	must(err, "s5Beta.PollPermission offline")
	s5OffDec, s5OffDecOK := s5OffPolled.Decision()
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_offline", "offline": false})
	_, err = s5PS.DeliverSupervisionEvents(ctx, s5SS2Route)
	must(err, "s5PS.DeliverSupervisionEvents s5SS2Route")
	s5SS2AfterWake := s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "inspect", "agent": s5BetaID, "ps": s5PSIssuer, "sub": "rust-ss2-sub-1"})
	s5ToldRaw, _ := s5SS2AfterWake["told"].([]any)
	var s5Told []string
	for _, v := range s5ToldRaw {
		if s, ok := v.(string); ok {
			s5Told = append(s5Told, s)
		}
	}
	s5UseCase3OK := s5OffRevOK && s5OffDecOK && s5OffDec.Permission() == aauth.PermissionGranted &&
		slices.Equal(s5Told, []string{"agent.bound", "person_token.issued", "decision.resolved"})

	// S5 Use Case 4: Offline verification of Go PS + Rust SS decision in Go (and exported for Rust)
	var s5SignedEx *supervision.Exchange
	var s5SignedSDI string
	var s5SignedAct string
	var s5SignedAgent string
	var s5SignedAgentIssuer string
	for _, entry := range s5SupStore.Log() {
		if entry.Exchange != nil && entry.Exchange.Signed && entry.Supervisor.Issuer == in.S5RustSS1Issuer && entry.Kind == supervision.KindPermission {
			exCopy := entry.Exchange.Clone()
			s5SignedEx = &exCopy
			s5SignedSDI = entry.SDI
			s5SignedAct = string(entry.Kind)
			s5SignedAgent = entry.Agent
			s5SignedAgentIssuer = s3APIssuer
			break
		}
	}
	var s5VerifyGoOK, s5VerifyGoDecOK, s5GoMutRespFailed, s5GoMutReqFailed bool
	var s5ExportedEx map[string]any
	if s5SignedEx != nil {
		verResp, vErr := supervision.VerifyExchange(ctx, *s5SignedEx, sResolver)
		s5VerifyGoOK = vErr == nil && verResp.Signer() == in.S5RustSS1Issuer
		reqHTTP, _ := http.NewRequestWithContext(ctx, s5SignedEx.Request.Method, s5SignedEx.Request.URL, bytes.NewReader(s5SignedEx.Request.Body))
		reqHTTP.Header = s5SignedEx.Request.Header.Clone()
		_, dErr := supervision.VerifyDecision(ctx, s5SignedEx.Response.Status, s5SignedEx.Response.Header, s5SignedEx.Response.Body, reqHTTP, s5SignedEx.Supervisor, sResolver, aauth.ClockFunc(func() time.Time { return s5SignedEx.ReceivedAt }))
		s5VerifyGoDecOK = dErr == nil

		mutResp := s5SignedEx.Clone()
		mutResp.Response.Body = []byte(strings.Replace(string(mutResp.Response.Body), `"allow"`, `"deny"`, 1))
		_, mutRespErr := supervision.VerifyExchange(ctx, mutResp, sResolver)
		s5GoMutRespFailed = mutRespErr != nil

		mutReq := s5SignedEx.Clone()
		mutReq.Request.Header.Set("Content-Digest", "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:")
		_, mutReqErr := supervision.VerifyExchange(ctx, mutReq, sResolver)
		s5GoMutReqFailed = mutReqErr != nil

		s5ExportedEx = encodeExchangeJSON(*s5SignedEx)
		s5ExportedEx["sdi"] = s5SignedSDI
		s5ExportedEx["act"] = s5SignedAct
		s5ExportedEx["agent_sub"] = s5SignedAgent
		s5ExportedEx["agent_iss"] = s5SignedAgentIssuer
	}
	s5UseCase4GoOK := s5VerifyGoOK && s5VerifyGoDecOK && s5GoMutRespFailed && s5GoMutReqFailed

	// S5 Answer Types (Narrowing allow, Deny, Deferral, Clarification)
	s5BetaRT1, err := s5Beta.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s5BetaPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s5Beta.Authorize narrow")
	s5NarrowExp := clock.Now().Unix() + 900
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_narrow", "narrow": true, "scope": "records.read", "exp": s5NarrowExp})
	s5NarrowAT, err := s5Beta.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s5PSIssuer, ResourceToken: s5BetaRT1, PresentedToken: s5BetaPT,
	})
	must(err, "s5Beta.Exchange narrow")
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_narrow", "narrow": false})
	s5NarrowClaims, err := aauth.VerifyAuthToken(ctx, s5NarrowAT, sResolver, clock)
	must(err, "VerifyAuthToken s5NarrowAT")
	s5NarrowOK := s5NarrowClaims.Scope == "records.read" && s5NarrowClaims.ExpiresAt == s5NarrowExp

	s5DenyPerm, err := s5Alpha.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "DeleteMailbox",
	})
	must(err, "s5Alpha.RequestPermission DeleteMailbox")
	s5DenyDec, s5DenyHasDec := s5DenyPerm.Decision()
	s5DenyOK := s5DenyHasDec && s5DenyDec.Permission() == aauth.PermissionDenied &&
		s5DenyDec.Reason() == "Deleting a mailbox is never delegated."

	// S5 Deferral (Rust SS2 returns 202 pending -> decide_pending -> Go AdvanceSupervision -> 200)
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_defer", "defer": true})
	s5DefPerm, err := s5Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, Action: "PayInvoice",
	})
	must(err, "s5Beta.RequestPermission PayInvoice defer")
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_defer", "defer": false})
	s5DefPend, s5DefWasPend := s5DefPerm.Pending()
	s5DefRevs, _ := s5PS.PendingSupervision(ctx, 10)
	s5DecPendRes := s5Ctl(in.S5RustSS2Issuer, map[string]any{
		"action":  "decide_pending",
		"ps":      s5PSIssuer,
		"sdi":     s5DefRevs[0].SDI,
		"verdict": "allow",
	})
	sAdvanceClock(5 * time.Second)
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5AdvErr := s5PS.AdvanceSupervision(ctx, s5DefRevs[0].Reference)
	s5DefPolled, err := s5Beta.PollPermission(ctx, s5DefPend)
	must(err, "s5Beta.PollPermission defer")
	s5DefDec, s5DefDecOK := s5DefPolled.Decision()
	s5DeferOK := s5DefWasPend && s5DecPendRes["ok"] == true && s5AdvErr == nil &&
		s5DefDecOK && s5DefDec.Permission() == aauth.PermissionGranted

	// S5 Clarification (Rust SS2 returns Clarify on token exchange -> Go PS relays -> Go Agent answers -> Rust SS2 allows)
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_clarify", "clarify": true})
	s5BetaClarPTRes, err := s5Beta.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s5PSIssuer, Resource: s3ResIssuer})
	must(err, "s5Beta.PersonToken clarify")
	s5BetaClarPT, _ := s5BetaClarPTRes.Token()
	s5BetaClarRT, err := s5Beta.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s3ResIssuer, PersonToken: s5BetaClarPT, Scopes: []string{"records.read"},
	})
	must(err, "s5Beta.Authorize clarify")
	s5ClarEx, err := s5Beta.BeginExchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s5PSIssuer, ResourceToken: s5BetaClarRT, PresentedToken: s5BetaClarPT,
		Capabilities: []string{"clarification"},
	})
	must(err, "s5Beta.BeginExchange clarify")
	s5ClarPend, s5ClarWasPend := s5ClarEx.Pending()
	s5ClarQ, s5ClarHasQ := s5ClarPend.Clarification()
	s5ClarAnsErr := s5Beta.AnswerClarification(ctx, s5ClarPend, "Yes, fully refundable fare.")
	sAdvanceClock(5 * time.Second)
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_time", "now": clock.Now().Unix()})
	s5ClarPolled, err := s5Beta.PollExchange(ctx, s5ClarPend)
	must(err, "s5Beta.PollExchange clarify")
	s5Ctl(in.S5RustSS2Issuer, map[string]any{"action": "set_clarify", "clarify": false})
	s5ClarTok, s5ClarTokOK := s5ClarPolled.Token()
	s5ClarifyOK := s5ClarWasPend && s5ClarHasQ && s5ClarQ.Question() == "Is the fare refundable?" &&
		s5ClarAnsErr == nil && s5ClarTokOK && s5ClarTok != "" 

	// S5 Missions under supervision (Go PS <-> Rust SS1)
	s5MissProp, err := s5Alpha.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: s5PSIssuer,
		Proposal: aauth.MissionProposal{
			Description: "# S5 Cross-Language Mission",
			Tools: []aauth.MissionTool{
				{Name: "WebSearch", Description: "Search the web"},
			},
			Resources: []string{s3ResIssuer},
		},
	})
	must(err, "s5Alpha.BeginMission")
	s5MissApp, s5MissAppOK := s5MissProp.Approval()
	s5Miss := s5MissApp.Mission()
	_, s5UpdErr := s5Alpha.UpdateMission(ctx, clientagent.MissionUpdateRequest{
		PersonServer: s5PSIssuer, MissionS256: s5Miss.S256, Description: "S5 Mission updated.",
	})
	s5CompErr := s5Alpha.CompleteMission(ctx, clientagent.MissionCompletionRequest{
		PersonServer: s5PSIssuer, MissionS256: s5Miss.S256, Summary: "S5 Mission done.",
	})
	_, err = s5PS.DeliverSupervisionEvents(ctx, s5SS1Route)
	must(err, "s5PS.DeliverSupervisionEvents mission")
	s5SS1MissionsInsp := s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "inspect", "agent": s5AlphaID, "ps": s5PSIssuer, "sub": "rust-ss1-sub-1"})
	s5SS1ToldRaw, _ := s5SS1MissionsInsp["told"].([]any)
	var s5SS1Told []string
	for _, v := range s5SS1ToldRaw {
		if s, ok := v.(string); ok {
			s5SS1Told = append(s5SS1Told, s)
		}
	}
	s5MissionsOK := s5MissAppOK && strings.HasSuffix(s5Miss.Blob.Description, "Keep work data inside the organization.") &&
		s5UpdErr == nil && s5CompErr == nil &&
		slices.Contains(s5SS1Told, "approved") && slices.Contains(s5SS1Told, "terminated")

	// S5 Recovery:
	// (a) Routing change of s5Beta (with active mission) from Rust SS2 to Rust SS1
	s5RecProp, err := s5Beta.BeginMission(ctx, clientagent.MissionRequest{
		PersonServer: s5PSIssuer,
		Proposal:     aauth.MissionProposal{Description: "# S5 Offsite Mission"},
	})
	must(err, "s5Beta.BeginMission recovery")
	s5RecApp, _ := s5RecProp.Approval()
	s5RecMiss := s5RecApp.Mission()
	s5SetRoute(s5BetaID, s5SS1Route)
	s5MovedPerm, err := s5Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, MissionS256: s5RecMiss.S256, Action: "ReserveRoom",
	})
	must(err, "s5Beta.RequestPermission after routing change")
	s5MovedDec, s5MovedOK := s5MovedPerm.Decision()
	s5RoutingReplayOK := s5MovedOK && s5MovedDec.Permission() == aauth.PermissionGranted

	// (b) Rust SS1 loses its records -> 404 unknown_sub + 404 unknown_mission -> Go PS reconnects + replays mission + retries
	s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "forget_everything"})
	s5LostPerm, err := s5Beta.RequestPermission(ctx, clientagent.PermissionRequest{
		PersonServer: s5PSIssuer, MissionS256: s5RecMiss.S256, Action: "ReserveCatering",
	})
	must(err, "s5Beta.RequestPermission after forget_everything")
	s5LostDec, s5LostOK := s5LostPerm.Decision()
	s5UnknownRecoveryOK := s5LostOK && s5LostDec.Permission() == aauth.PermissionGranted

	// S5 Four-Party under supervision (Go Federated PS + Rust SS1)
	s5FedPTRes, err := s5FedAg.PersonToken(ctx, clientagent.PersonTokenRequest{PersonServer: s5FedPSIssuer, Resource: s4FedResIssuer})
	must(err, "s5FedAg.PersonToken")
	s5FedPT, _ := s5FedPTRes.Token()
	s5FedRT1, err := s5FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s5FedPT, Scopes: []string{"records.read"},
	})
	must(err, "s5FedAg.Authorize 1")
	s5FedAT1, err := s5FedAg.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s5FedPSIssuer, ResourceToken: s5FedRT1, PresentedToken: s5FedPT,
	})
	must(err, "s5FedAg.Exchange 1")
	s5FedClaims1, err := aauth.VerifyAuthToken(ctx, s5FedAT1, sResolver, clock)
	must(err, "VerifyAuthToken s5FedAT1")
	s5FourPartyAllowOK := s5FedClaims1.Issuer == s4ASIssuer

	// S5 Four-Party narrowing allow refused (403)
	s5FedRT2, err := s5FedAg.Authorize(ctx, clientagent.AuthorizeRequest{
		Resource: s4FedResIssuer, PersonToken: s5FedPT, Scopes: []string{"records.read", "records.write"},
	})
	must(err, "s5FedAg.Authorize 2")
	s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "set_narrow", "narrow": true, "scope": "records.read"})
	_, s5FedNarrowErr := s5FedAg.Exchange(ctx, clientagent.ExchangeRequest{
		PersonServer: s5FedPSIssuer, ResourceToken: s5FedRT2, PresentedToken: s5FedPT,
	})
	s5Ctl(in.S5RustSS1Issuer, map[string]any{"action": "set_narrow", "narrow": false})
	var s5FedNarrowProb *aauth.ProblemError
	s5FourPartyNarrowRefusedOK := errors.As(s5FedNarrowErr, &s5FedNarrowProb) && s5FedNarrowProb.Status == 403

	s5HostNeverCalledOK := s5HostPolicyCalls.Load() == 0

	// =========================================================================
	// Start Live Go Supervision Servers (s6-go-ss1.example & s6-go-ss2.example)
	// for QA-S6 (Rust Person Server <-> Go Supervision Server)
	// =========================================================================
	const (
		s6GoSS1Issuer = "https://s6-go-ss1.example"
		s6GoSS2Issuer = "https://s6-go-ss2.example"
	)
	s6GoSS1 := newSGoSSHost(s6GoSS1Issuer, newSKey("s6-go-ss1-key", 0xd1), clock, sResolver, false)
	s6SS1Srv, s6SS1Der := registerTLS("s6-go-ss1.example", s6GoSS1.handler)
	s6GoSS2 := newSGoSSHost(s6GoSS2Issuer, newSKey("s6-go-ss2-key", 0xd2), clock, sResolver, true)
	s6SS2Srv, s6SS2Der := registerTLS("s6-go-ss2.example", s6GoSS2.handler)

	return map[string]any{
		"s3": map[string]any{
			"ps_store_conformance_ok": s3PSStoreOK,
			"ss_store_conformance_ok": s3SSStoreOK,
			"go_pkg_tests_ok":         s3GoPkgTestsOK,
			"use_case_1_ok":           s3UseCase1OK,
			"use_case_2_ok":           s3UseCase2OK,
			"use_case_3_ok":           s3UseCase3OK,
			"use_case_4_ok":           s3UseCase4OK,
			"told_after_wake":         s3ToldAfterWake,
		},
		"s4": map[string]any{
			"narrow_allow_ok":                  s4NarrowAllowOK,
			"deny_ok":                          s4DenyOK,
			"defer_ok":                         s4DeferOK,
			"clarify_ok":                       s4ClarifyOK,
			"missions_ok":                      s4MissionsOK,
			"routing_replay_ok":                s4RoutingReplayOK,
			"unknown_recovery_ok":              s4UnknownRecoveryOK,
			"four_party_allow_ok":              s4FourPartyAllowOK,
			"four_party_narrow_refused_ok":     s4FourPartyNarrowRefusedOK,
			"four_party_ask_as_defer_bound_ok": s4FourPartyAskASDeferBoundaryOK,
			"host_never_called_ok":             s4HostNeverCalledOK,
		},
		"s5": map[string]any{
			"use_case_1_ok":                s5UseCase1OK,
			"use_case_2_ok":                s5UseCase2OK,
			"use_case_3_ok":                s5UseCase3OK,
			"use_case_4_go_ok":             s5UseCase4GoOK,
			"narrow_allow_ok":              s5NarrowOK,
			"deny_ok":                      s5DenyOK,
			"defer_ok":                     s5DeferOK,
			"clarify_ok":                   s5ClarifyOK,
			"missions_ok":                  s5MissionsOK,
			"routing_replay_ok":            s5RoutingReplayOK,
			"unknown_recovery_ok":          s5UnknownRecoveryOK,
			"four_party_allow_ok":          s5FourPartyAllowOK,
			"four_party_narrow_refused_ok": s5FourPartyNarrowRefusedOK,
			"host_never_called_ok":         s5HostNeverCalledOK,
			"exported_exchange":            s5ExportedEx,
		},
		"s6_go_ss": map[string]any{
			"ss1_issuer":   s6GoSS1Issuer,
			"ss1_addr":     s6SS1Srv.Listener.Addr().String(),
			"ss1_cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s6SS1Der})),
			"ss2_issuer":   s6GoSS2Issuer,
			"ss2_addr":     s6SS2Srv.Listener.Addr().String(),
			"ss2_cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s6SS2Der})),
		},
	}
}
