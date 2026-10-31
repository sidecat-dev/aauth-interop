package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/accessserver"
	"gitlab.com/sidecat-dev/aauth-go/agentprovider"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/personserver"
	"gitlab.com/sidecat-dev/aauth-go/resource"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
	"gitlab.com/sidecat-dev/aauth-go/testutil"
)

type oSuiteInput struct {
	RustPSIssuer       string `json:"rust_ps_issuer"`
	RustASIssuer       string `json:"rust_as_issuer"`
	RustDirectPSIssuer string `json:"rust_direct_ps_issuer"`
	RustResIssuer      string `json:"rust_res_issuer"`
}

func runOSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in oSuiteInput,
) map[string]any {
	nowTime := clock.Now().UTC().Truncate(time.Second)

	newOKey := func(id string, seedByte byte) jose.SigningKey {
		k, err := jose.NewEd25519SigningKey(id, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)))
		must(err, "NewEd25519SigningKey "+id)
		return k
	}

	var oIDSeq atomic.Int64
	nextOID := func() string {
		return "o-go-id-" + strconvItoa(oIDSeq.Add(1))
	}

	oResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver oResolver")

	// 1. Go Federated Downstream Resource (https://o-go-fed-res.example) trusting Rust Federated AS (in.RustASIssuer)
	const oGoFedResIssuer = "https://o-go-fed-res.example"
	oGoFedResKey := newOKey("o-go-fed-res-1", 0xa1)
	oGoFedRes, err := resource.NewFederatedAuthorization(resource.FederatedAuthorizationConfig{
		Issuer:            oGoFedResIssuer,
		AccessServer:      in.RustASIssuer,
		SigningKey:        oGoFedResKey,
		KeyResolver:       oResolver,
		Clock:             clock,
		NewID:             nextOID,
		ScopeDescriptions: map[string]string{"read": "Read inventory", "write": "Write inventory"},
		RequiredScopes: func(r *http.Request) []string {
			if r.URL.Query().Get("step") == "write" {
				return []string{"read", "write"}
			}
			return []string{"read"}
		},
		ResolvePerson: func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":            true,
				"role":          "go_federated_downstream_resource",
				"subject":       p.Subject,
				"person_server": p.PersonServer,
			})
		}),
	})
	must(err, "resource.NewFederatedAuthorization oGoFedRes")
	oGoFedResSrv, oGoFedResDER := registerTLS("o-go-fed-res.example", oGoFedRes.Handler())

	// 2. Go Direct (3-party) Downstream Resource (https://o-go-direct-res.example) trusting Rust Direct PS (with MissionS256 inspection)
	const oGoDirectResIssuer = "https://o-go-direct-res.example"
	oGoDirectResKey := newOKey("o-go-direct-res-1", 0xa2)
	oGoDirectRes, err := resource.NewPSAuthorization(resource.PSAuthorizationConfig{
		Issuer:            oGoDirectResIssuer,
		SigningKey:        oGoDirectResKey,
		KeyResolver:       oResolver,
		Clock:             clock,
		NewID:             nextOID,
		ScopeDescriptions: map[string]string{"read": "Read stock"},
		RequiredScopes:    func(*http.Request) []string { return []string{"read"} },
		ResolvePerson:     func(context.Context, resource.PersonIdentity, resource.PersonContext) error { return nil },
		Protected: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := resource.AuthPrincipalFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"role":         "go_direct_downstream_resource",
				"subject":      p.Subject,
				"mission_s256": p.MissionS256,
			})
		}),
	})
	must(err, "resource.NewPSAuthorization oGoDirectRes")
	oGoDirectResSrv, oGoDirectResDER := registerTLS("o-go-direct-res.example", oGoDirectRes.Handler())

	// 3. Go Access Server (https://o-go-as.example) trusting Rust Federated PS (in.RustPSIssuer)
	const oGoASIssuer = "https://o-go-as.example"
	oGoASKey := newOKey("o-go-as-1", 0xa3)
	oGoASResolver := signaturekey.StaticKeyResolver{
		{Issuer: "https://o-rust-ap.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: "o-ap-1"}:            newOKey("o-ap-1", 0xc1).PublicJWK(),
		{Issuer: "https://o-rust-interm1.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: "o-interm1-ap-1"}: newOKey("o-interm1-ap-1", 0xc2).PublicJWK(),
		{Issuer: "https://o-rust-interm2.example", DiscoveryDocument: aauth.AgentDiscoveryDocument, KeyID: "o-interm2-ap-1"}: newOKey("o-interm2-ap-1", 0xc3).PublicJWK(),
		{Issuer: "https://o-rust-as.example", DiscoveryDocument: aauth.AccessDiscoveryDocument, KeyID: "o-as1-1"}:            newOKey("o-as1-1", 0xc5).PublicJWK(),
		{Issuer: "https://o-rust-res.example", DiscoveryDocument: aauth.ResourceDiscoveryDocument, KeyID: "o-res2-1"}:        newOKey("o-res2-1", 0xc9).PublicJWK(),
		{Issuer: "https://o-rust-ps.example", DiscoveryDocument: aauth.PersonDiscoveryDocument, KeyID: "o-ps-1"}:             newOKey("o-ps-1", 0xcb).PublicJWK(),
	}
	oGoAS, err := accessserver.New(accessserver.Config{
		Issuer:      oGoASIssuer,
		SigningKey:  oGoASKey,
		KeyResolver: oGoASResolver,
		Clock:       clock,
		NewID:       nextOID,
		TrustPersonServer: func(_ context.Context, iss string) error {
			if iss != in.RustPSIssuer && iss != "https://o-go-fed-ps.example" {
				return errors.New("untrusted person server: " + iss)
			}
			return nil
		},
		Authorize: func(_ context.Context, req accessserver.AuthorizationRequest) (accessserver.Decision, error) {
			return accessserver.Decision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
		},
	})
	must(err, "accessserver.New oGoAS")
	oGoASSrv, oGoASDER := registerTLS("o-go-as.example", oGoAS.Handler())

	// 4. Go Direct PS with CallChainingConfig (https://o-go-direct-ps.example) & Go Federated PS (https://o-go-fed-ps.example)
	const (
		oGoAP      = "https://o-go-ap.example"
		oGoInterm  = "https://o-go-intermediary.example"
		oGoDirPS   = "https://o-go-direct-ps.example"
		oGoFedPS   = "https://o-go-fed-ps.example"
		oCallerID  = "aauth:caller@o-go-ap.example"
		oIntermID  = "aauth:interm@o-go-intermediary.example"
	)
	oGoAPKey := newOKey("o-go-ap-1", 0xa4)
	oGoIntermAPKey := newOKey("o-go-interm-ap-1", 0xa5)
	oGoCallerKey := newOKey("o-go-caller-1", 0xa6)
	oGoIntermKey := newOKey("o-go-interm-1", 0xa7)
	oGoDirPSKey := newOKey("o-go-dir-ps-1", 0xa8)
	oGoFedPSKey := newOKey("o-go-fed-ps-1", 0xa9)

	oAP, err := agentprovider.New(agentprovider.Config{Issuer: oGoAP, SigningKey: oGoAPKey, Clock: clock, NewID: nextOID})
	must(err, "oAP")
	registerTLS("o-go-ap.example", oAP.Handler())

	oIntermAP, err := agentprovider.New(agentprovider.Config{Issuer: oGoInterm, SigningKey: oGoIntermAPKey, Clock: clock, NewID: nextOID})
	must(err, "oIntermAP")
	registerTLS("o-go-intermediary.example", oIntermAP.Handler())

	oDirTokenStore := &memoryTokenStore{}
	oDirPS, err := personserver.NewPSAuthorization(personserver.PSAuthorizationConfig{
		Issuer:       oGoDirPS,
		SigningKey:   oGoDirPSKey,
		KeyResolver:  oResolver,
		Clock:        clock,
		NewID:        nextOID,
		Tokens:       oDirTokenStore,
		IssuedTokens: testutil.NewIssuedAuthTokenStore(),
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "o-person-interm", Lifetime: 20 * time.Minute}, nil
		},
		Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
			return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 20 * time.Minute}, nil
		},
		CallChaining: &personserver.CallChainingConfig{
			BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
				return personserver.Person{Subject: "o-person-rust-res", Lifetime: 15 * time.Minute}, nil
			},
			Authorize: func(_ context.Context, req personserver.AuthorizationRequest) (personserver.AuthorizationDecision, error) {
				return personserver.AuthorizationDecision{Scopes: req.Scopes, Lifetime: 15 * time.Minute}, nil
			},
		},
	})
	must(err, "oDirPS")
	registerTLS("o-go-direct-ps.example", oDirPS.Handler())

	oFedPS, err := personserver.NewFederatedAuthorization(personserver.FederatedAuthorizationConfig{
		Issuer:      oGoFedPS,
		SigningKey:  oGoFedPSKey,
		KeyResolver: oResolver,
		Clock:       clock,
		NewID:       nextOID,
		Tokens:      &memoryTokenStore{},
		HTTPClient:  httpClient,
		AccessServerEndpoint: func(_ context.Context, iss string) (string, error) {
			return iss + "/token", nil
		},
		BindPerson: func(context.Context, personserver.PersonTokenRequest) (personserver.Person, error) {
			return personserver.Person{Subject: "o-fed-person", Lifetime: 20 * time.Minute}, nil
		},
		Consent: func(context.Context, personserver.AuthorizationRequest) error {
			return nil
		},
	})
	must(err, "oFedPS")
	registerTLS("o-go-fed-ps.example", oFedPS.Handler())

	oCallerAT, err := oAP.Issue(aauth.AgentTokenRequest{
		Agent: oCallerID, PersonServer: oGoDirPS, PublicKey: oGoCallerKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "oCallerAT")
	oIntermAT, err := oIntermAP.Issue(aauth.AgentTokenRequest{
		Agent: oIntermID, PersonServer: oGoDirPS, PublicKey: oGoIntermKey.PublicJWK(), Lifetime: time.Hour,
	})
	must(err, "oIntermAT")

	doSignedJSON := func(key jose.SigningKey, jwtTok, url string, body any) (int, map[string]any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		must(signaturekey.SignJWTRequest(req, key, jwtTok, clock), "SignJWTRequest "+url)
		resp, dErr := httpClient.Do(req)
		must(dErr, "Do "+url)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		if out == nil {
			out = map[string]any{"raw": string(raw)}
		}
		return resp.StatusCode, out
	}

	// Working Cross-Language Chain 3: Caller -> Go Direct PS -> Intermediary -> Go Direct PS -> Rust Downstream Resource
	_, oUpPTOut := doSignedJSON(oGoCallerKey, oCallerAT, oGoDirPS+"/person", map[string]string{
		"resource": oGoInterm,
	})
	oUpstreamPT, _ := oUpPTOut["person_token"].(string)

	oChainPTStatus, oChainPTOut := doSignedJSON(oGoIntermKey, oIntermAT, oGoDirPS+"/person", map[string]string{
		"resource":       in.RustResIssuer,
		"upstream_token": oUpstreamPT,
	})
	oChainedPT, _ := oChainPTOut["person_token"].(string)

	// Intermediary challenges Rust Downstream Resource (POST /authorize) with oChainedPT
	oAuthzStatus, oAuthzOut := doSignedJSON(oGoIntermKey, oChainedPT, in.RustResIssuer+"/authorize", map[string]any{
		"scope": "read",
	})
	oRustRT, _ := oAuthzOut["resource_token"].(string)

	// Intermediary exchanges oRustRT + oChainedPT + oUpstreamPT at Go Direct PS (/token)
	oChainTokStatus, oChainTokOut := doSignedJSON(oGoIntermKey, oIntermAT, oGoDirPS+"/token", map[string]string{
		"resource_token":  oRustRT,
		"presented_token": oChainedPT,
		"upstream_token":  oUpstreamPT,
	})
	oChainedAuthTok, _ := oChainTokOut["auth_token"].(string)

	// Intermediary presents oChainedAuthTok to Rust Downstream Resource (GET /stock) over HTTPS
	oCallRustReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, in.RustResIssuer+"/stock", nil)
	must(signaturekey.SignJWTRequest(oCallRustReq, oGoIntermKey, oChainedAuthTok, clock), "sign oCallRustReq")
	oCallRustResp, err := httpClient.Do(oCallRustReq)
	must(err, "do oCallRustReq")
	var oCallRustOut map[string]any
	_ = json.NewDecoder(oCallRustResp.Body).Decode(&oCallRustOut)
	_ = oCallRustResp.Body.Close()

	// Pinned Boundary 1a: Go Federated PS refuses upstream_token at /person -> 400 invalid_request
	oFedIntermAT, _ := oIntermAP.Issue(aauth.AgentTokenRequest{
		Agent: oIntermID, PersonServer: oGoFedPS, PublicKey: oGoIntermKey.PublicJWK(), Lifetime: time.Hour,
	})
	oBound1aStatus, oBound1aOut := doSignedJSON(oGoIntermKey, oFedIntermAT, oGoFedPS+"/person", map[string]string{
		"resource":       in.RustResIssuer,
		"upstream_token": oUpstreamPT,
	})

	// Pinned Boundary 1b: Go Direct PS refuses POST /token with upstream_token when resource_token.aud == AS != PS -> 500 server_error
	oChainPTClaims, _ := aauth.VerifyPersonToken(ctx, oChainedPT, oResolver, clock)
	oIntermJKT, _ := oGoIntermKey.PublicJWK().Thumbprint()
	oASChallengeRT, err := aauth.MintResourceToken(oGoFedResKey, aauth.ResourceTokenClaims{
		Issuer:        oGoFedResIssuer,
		DWK:           aauth.ResourceDiscoveryDocument,
		Audience:      oGoASIssuer,
		PersonServer:  oGoDirPS,
		Subject:       oChainPTClaims.Subject,
		JTI:           "o-as-challenge-rt",
		PresentedJTI:  oChainPTClaims.JTI,
		AgentJKT:      oIntermJKT,
		Scope:         "inventory.read",
		IssuedAt:      nowTime.Unix(),
		ExpiresAt:     nowTime.Add(5 * time.Minute).Unix(),
	})
	must(err, "MintResourceToken oASChallengeRT")
	oBound1bStatus, oBound1bOut := doSignedJSON(oGoIntermKey, oIntermAT, oGoDirPS+"/token", map[string]string{
		"resource_token":  oASChallengeRT,
		"presented_token": oChainedPT,
		"upstream_token":  oUpstreamPT,
	})

	// Pinned Boundary 2: Go Direct PS refuses federated AS-issued AuthToken (dwk="aauth-access.json") as upstream_token -> 400 invalid_upstream_token
	oASIssuedAuthTok, err := aauth.MintAuthToken(oGoASKey, aauth.AuthTokenClaims{
		Issuer:       oGoASIssuer,
		DWK:          aauth.AccessDiscoveryDocument,
		Audience:     oGoInterm,
		PersonServer: oGoDirPS,
		Subject:      "o-person-interm",
		JTI:          "o-as-upstream-auth",
		Confirmation: aauth.Confirmation{JWK: oGoCallerKey.PublicJWK()},
		Scope:        "read",
		IssuedAt:     nowTime.Unix(),
		ExpiresAt:    nowTime.Add(10 * time.Minute).Unix(),
	})
	must(err, "MintAuthToken oASIssuedAuthTok")
	oBound2Status, oBound2Out := doSignedJSON(oGoIntermKey, oIntermAT, oGoDirPS+"/person", map[string]string{
		"resource":       in.RustResIssuer,
		"upstream_token": oASIssuedAuthTok,
	})

	// Pinned Boundary 4: Go Direct PS refuses mission-bound upstream_token -> 500 server_error
	oMissionUpPT, err := aauth.MintPersonToken(oGoDirPSKey, aauth.PersonTokenClaims{
		Issuer:       oGoDirPS,
		DWK:          aauth.PersonDiscoveryDocument,
		Audience:     oGoInterm,
		Subject:      "o-person-interm",
		JTI:          "o-mission-up-pt",
		MissionS256:  "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA",
		Confirmation: aauth.Confirmation{JWK: oGoCallerKey.PublicJWK()},
		IssuedAt:     nowTime.Unix(),
		ExpiresAt:    nowTime.Add(10 * time.Minute).Unix(),
	})
	must(err, "MintPersonToken oMissionUpPT")
	oBound4Status, oBound4Out := doSignedJSON(oGoIntermKey, oIntermAT, oGoDirPS+"/person", map[string]string{
		"resource":       in.RustResIssuer,
		"upstream_token": oMissionUpPT,
	})

	// 5. Go Signature-Key Verifier (https://o-go-sigkey.example) for QA-O1, QA-O4, QA-O5
	oCacheHolderKey := newOKey("o1-holder-1", 0xa2)
	oAssertionCache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{
		Key:       bytes.Repeat([]byte{0xab}, 32),
		Retention: 10 * time.Minute,
	})
	must(err, "NewAssertionCache oAssertionCache")

	oSigKeyMux := http.NewServeMux()
	oSigKeyMux.HandleFunc("POST /hwk", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
			AcceptedAlgorithms: jose.SignatureAlgorithms(),
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		jwk, ok := prep.Credential().InlineJWK()
		if !ok {
			http.Error(w, "missing inline JWK", http.StatusBadRequest)
			return
		}
		proof, vErr := prep.Verify(jwk)
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		jktURI, _ := proof.PublicKey().ThumbprintURI()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"scheme":  string(proof.Scheme()),
			"alg":     proof.PublicKey().Alg,
			"kty":     proof.PublicKey().Kty,
			"jkt_uri": jktURI,
		})
	})
	oSigKeyMux.HandleFunc("POST /x509-custom-bundle", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		var bundle struct {
			ChainPEM   string `json:"chain_pem"`
			RootDERB64 string `json:"root_der_b64"`
			CRLDERB64  string `json:"crl_der_b64"`
		}
		_ = json.NewDecoder(r.Body).Decode(&bundle)
		rootRaw, _ := base64.StdEncoding.DecodeString(bundle.RootDERB64)
		rootCert, err := x509.ParseCertificate(rootRaw)
		if err != nil {
			http.Error(w, "parse root: "+err.Error(), http.StatusBadRequest)
			return
		}
		crlRaw, _ := base64.StdEncoding.DecodeString(bundle.CRLDERB64)
		crlObj, err := x509.ParseRevocationList(crlRaw)
		if err != nil {
			http.Error(w, "parse crl: "+err.Error(), http.StatusBadRequest)
			return
		}
		proof, id, vErr := prep.VerifyX509(signaturekey.X509VerifyOptions{
			ChainPEM:        []byte(bundle.ChainPEM),
			Roots:           []*x509.Certificate{rootCert},
			RevocationLists: []*x509.RevocationList{crlObj},
		})
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"scheme":    string(proof.Scheme()),
			"alg":       proof.PublicKey().Alg,
			"url":       id.URL(),
			"chain_len": len(id.Chain()),
		})
	})
	oSigKeyMux.HandleFunc("POST /cached-resource", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		if prep.Credential().Scheme() == signaturekey.SchemeCached {
			proof, assertion, vErr := prep.VerifyCached(oAssertionCache)
			if vErr != nil {
				writeMSigError(w, vErr)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":          true,
				"scheme_used": string(proof.Scheme()),
				"orig_scheme": string(assertion.Scheme()),
				"jti":         assertion.JTI(),
				"issuer":      assertion.Issuer(),
			})
			return
		}
		proof, vErr := prep.Verify(oCacheHolderKey.PublicJWK())
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		grant, issued, iErr := oAssertionCache.Issue(proof)
		if iErr != nil {
			writeMSigError(w, iErr)
			return
		}
		if issued {
			if field, fErr := signaturekey.FormatCacheGrants(grant); fErr == nil {
				w.Header().Set("Signature-Key-Cache", field)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"scheme_used": string(proof.Scheme()),
			"issued_cid":  issued,
		})
	})
	oGoSigKeySrv, oGoSigKeyDER := registerTLS("o-go-sigkey.example", oSigKeyMux)

	return map[string]any{
		"o_go_fed_res_addr":        oGoFedResSrv.Listener.Addr().String(),
		"o_go_fed_res_cert_hex":    hex.EncodeToString(oGoFedResDER),
		"o_go_direct_res_addr":     oGoDirectResSrv.Listener.Addr().String(),
		"o_go_direct_res_cert_hex": hex.EncodeToString(oGoDirectResDER),
		"o_go_as_addr":             oGoASSrv.Listener.Addr().String(),
		"o_go_as_cert_hex":         hex.EncodeToString(oGoASDER),
		"o_go_sigkey_addr":         oGoSigKeySrv.Listener.Addr().String(),
		"o_go_sigkey_cert_hex":     hex.EncodeToString(oGoSigKeyDER),
		"go_direct_ps_to_rust_res_chain": map[string]any{
			"person_status":   oChainPTStatus,
			"authorize_status": oAuthzStatus,
			"token_status":    oChainTokStatus,
			"call_status":     oCallRustResp.StatusCode,
			"call_body":       oCallRustOut,
			"ok":              oChainPTStatus == 200 && oAuthzStatus == 200 && oChainTokStatus == 200 && oCallRustResp.StatusCode == 200,
		},
		"pinned_boundaries": map[string]any{
			"b1a_go_fed_ps_refuses_upstream": map[string]any{
				"status": oBound1aStatus,
				"body":   oBound1aOut,
				"ok":     oBound1aStatus == 400 && oBound1aOut["error"] == "invalid_request",
			},
			"b1b_go_direct_ps_refuses_as_aud_chain": map[string]any{
				"status": oBound1bStatus,
				"body":   oBound1bOut,
				"ok":     (oBound1bStatus == 400 && oBound1bOut["error"] == "invalid_resource_token") || (oBound1bStatus == 500 && oBound1bOut["error"] == "server_error"),
			},
			"b2_go_direct_ps_refuses_as_upstream_auth": map[string]any{
				"status": oBound2Status,
				"body":   oBound2Out,
				"ok":     oBound2Status == 400 && oBound2Out["error"] == "invalid_upstream_token",
			},
			"b4_go_direct_ps_refuses_mission_upstream": map[string]any{
				"status": oBound4Status,
				"body":   oBound4Out,
				"ok":     (oBound4Status == 500 && oBound4Out["error"] == "server_error") || (oBound4Status == 400 && oBound4Out["error"] == "invalid_upstream_token"),
			},
		},
	}
}
