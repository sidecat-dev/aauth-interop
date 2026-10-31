package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aauth "gitlab.com/sidecat-dev/aauth-go"
	"gitlab.com/sidecat-dev/aauth-go/jose"
	"gitlab.com/sidecat-dev/aauth-go/signaturekey"
)

type mClock struct {
	now time.Time
}

func newMClock(t time.Time) *mClock {
	return &mClock{now: t}
}

func (c *mClock) Now() time.Time {
	return c.now
}

func (c *mClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func grantCID(g signaturekey.CacheGrant) string {
	c, err := signaturekey.NewCachedCredential(g)
	must(err, "grantCID NewCachedCredential")
	id, _ := c.CacheIdentifier()
	return id
}

type mAuthority struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var mSerialSeq atomic.Int64

func nextMSerial() *big.Int {
	return big.NewInt(mSerialSeq.Add(1))
}

func newMAuthority(name string, parent *mAuthority, signer crypto.Signer, now time.Time) mAuthority {
	if signer == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err, "newMAuthority generate P256")
		signer = k
	}
	tpl := &x509.Certificate{
		SerialNumber:          nextMSerial(),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	issuerCert := tpl
	issuerKey := signer
	if parent != nil {
		issuerCert = parent.cert
		issuerKey = parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuerCert, signer.Public(), issuerKey)
	must(err, "newMAuthority CreateCertificate")
	cert, err := x509.ParseCertificate(der)
	must(err, "newMAuthority ParseCertificate")
	return mAuthority{cert: cert, key: signer}
}

func (a mAuthority) issueLeaf(commonName string, pub crypto.PublicKey, now time.Time) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: nextMSerial(),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, pub, a.key)
	must(err, "issueLeaf CreateCertificate")
	cert, err := x509.ParseCertificate(der)
	must(err, "issueLeaf ParseCertificate")
	return cert
}

func (a mAuthority) crl(nextUpdate time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   c.SerialNumber,
			RevocationTime: nextUpdate.Add(-2 * time.Hour),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    nextMSerial(),
		ThisUpdate:                nextUpdate.Add(-2 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, a.cert, a.key)
	must(err, "crl CreateRevocationList")
	list, err := x509.ParseRevocationList(der)
	must(err, "crl ParseRevocationList")
	return list
}

func encodeMPEMChain(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

func newMAlgSigningKey(id, alg string) (jose.SigningKey, crypto.Signer) {
	var signer crypto.Signer
	var err error
	switch alg {
	case jose.Ed25519Algorithm:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case jose.ES256Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384Algorithm:
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.RS256Algorithm, jose.PS256Algorithm:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		must(errors.New("unsupported alg "+alg), "newMAlgSigningKey")
	}
	must(err, "newMAlgSigningKey generate "+alg)
	k, err := jose.NewSigningKeyForAlgorithm(id, alg, signer)
	must(err, "NewSigningKeyForAlgorithm "+alg)
	return k, signer
}

func sigErrCodeOf(err error) string {
	var sigErr *signaturekey.Error
	if errors.As(err, &sigErr) {
		return string(sigErr.Code)
	}
	return ""
}

func writeMSigError(w http.ResponseWriter, err error) {
	var sigErr *signaturekey.Error
	if errors.As(err, &sigErr) {
		if hdr, fErr := signaturekey.FormatError(*sigErr); fErr == nil {
			w.Header().Set("Signature-Error", hdr)
		}
		if len(sigErr.AcceptedSchemes) > 0 {
			if hdr, fErr := signaturekey.FormatAcceptSchemes(sigErr.AcceptedSchemes); fErr == nil {
				w.Header().Set("Accept-Signature-Scheme", hdr)
			}
		}
		if len(sigErr.AcceptedAlgorithms) > 0 {
			if hdr, fErr := signaturekey.FormatAcceptAlgorithms(sigErr.AcceptedAlgorithms); fErr == nil {
				w.Header().Set("Accept-Signature-Alg", hdr)
			}
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":   "urn:ietf:params:sig-error:" + string(sigErr.Code),
			"title":  string(sigErr.Code),
			"status": http.StatusUnauthorized,
		})
		return
	}
	http.Error(w, err.Error(), http.StatusUnauthorized)
}

type mSuiteInput struct {
	RustX509RootDERB64 string `json:"rust_x509_root_der_b64"`
	RustX509MidCRLB64  string `json:"rust_x509_mid_crl_b64"`
	RustX509RootCRLB64 string `json:"rust_x509_root_crl_b64"`
	RustX509RevCRLB64  string `json:"rust_x509_rev_crl_b64"`
}

func runMSuite(
	ctx context.Context,
	clock aauth.Clock,
	httpClient *http.Client,
	registerTLS func(host string, handler http.Handler) (*httptest.Server, []byte),
	in mSuiteInput,
) map[string]any {
	nowTime := clock.Now().UTC().Truncate(time.Second)

	// Parse Rust X509 Root CA & CRLs so Go's /x509 endpoint can verify Rust-signed x509 requests over HTTPS
	var rustRootCert *x509.Certificate
	var rustMidCRL, rustRootCRL, rustRevCRL *x509.RevocationList
	if raw, err := base64.StdEncoding.DecodeString(in.RustX509RootDERB64); err == nil && len(raw) > 0 {
		rustRootCert, _ = x509.ParseCertificate(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(in.RustX509MidCRLB64); err == nil && len(raw) > 0 {
		rustMidCRL, _ = x509.ParseRevocationList(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(in.RustX509RootCRLB64); err == nil && len(raw) > 0 {
		rustRootCRL, _ = x509.ParseRevocationList(raw)
	}
	if raw, err := base64.StdEncoding.DecodeString(in.RustX509RevCRLB64); err == nil && len(raw) > 0 {
		rustRevCRL, _ = x509.ParseRevocationList(raw)
	}

	// Keys & PKI for Go's live HTTPS server https://m-go-sigkey.example
	const mGoIssuer = "https://m-go-sigkey.example"
	goJWKSClientKey, _ := newMAlgSigningKey("go-jwks-1", jose.Ed25519Algorithm)
	goJWTIssuerKey, err := jose.NewEd25519SigningKey("go-jwt-issuer-1", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x70}, ed25519.SeedSize)))
	must(err, "NewEd25519SigningKey goJWTIssuerKey")
	goJWTHolderKey, err := jose.NewEd25519SigningKey("go-jwt-holder-1", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize)))
	must(err, "NewEd25519SigningKey goJWTHolderKey")

	goX509Root := newMAuthority("m-go-x509-root.example", nil, nil, nowTime)
	goX509Mid := newMAuthority("m-go-x509-mid.example", &goX509Root, nil, nowTime)
	goX509RootCRL := goX509Root.crl(nowTime.Add(time.Hour))
	goX509MidCRL := goX509Mid.crl(nowTime.Add(time.Hour))

	goX509Leaves := make(map[string]*x509.Certificate)
	goX509Keys := make(map[string]jose.SigningKey)
	for _, alg := range []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm} {
		k, _ := newMAlgSigningKey("go-x509-"+strings.ToLower(alg), alg)
		leaf := goX509Mid.issueLeaf("client-"+strings.ToLower(alg)+".example", k.Public(), nowTime)
		goX509Keys[alg] = k
		goX509Leaves[alg] = leaf
	}
	goX509RevokedCRL := goX509Mid.crl(nowTime.Add(time.Hour), goX509Leaves[jose.ES256Algorithm])

	mGoJWKSResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   clock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver for mGoJWKSResolver")

	mGoFleetKey := bytes.Repeat([]byte{0x7a}, 32)
	mGoAssertionCache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{
		Key:       mGoFleetKey,
		Retention: 10 * time.Minute,
	})
	must(err, "NewAssertionCache for mGoAssertionCache")
	var mGoLastIssuedCIDMu sync.Mutex
	var mGoLastIssuedCID string

	mGoMux := http.NewServeMux()
	// 1. /hwk accepts all 5 SignatureAlgorithms
	mGoMux.HandleFunc("POST /hwk", func(w http.ResponseWriter, r *http.Request) {
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

	// 2. /hwk-ed25519-only uses default AcceptedAlgorithms (Ed25519)
	mGoMux.HandleFunc("POST /hwk-ed25519-only", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		jwk, _ := prep.Credential().InlineJWK()
		proof, vErr := prep.Verify(jwk)
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":  true,
			"alg": proof.PublicKey().Alg,
		})
	})

	// 3. /.well-known/go-client.jwks serves Go client's JWKS for Go -> Rust jwks interop
	mGoMux.HandleFunc("GET /.well-known/go-client.jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []jose.JWK{goJWKSClientKey.PublicJWK()},
		})
	})

	// 4. /jwks verifies direct jwks scheme by fetching caller's JWKS over HTTPS
	mGoMux.HandleFunc("POST /jwks", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		urlStr, kidStr, _ := prep.Credential().JWKS()
		proof, vErr := prep.VerifyJWKS(r.Context(), mGoJWKSResolver)
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		jktURI, _ := proof.PublicKey().ThumbprintURI()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"scheme":  string(proof.Scheme()),
			"signer":  proof.Signer(),
			"url":     urlStr,
			"kid":     kidStr,
			"jkt_uri": jktURI,
		})
	})

	// 5. /certs/*.pem serves Go's PEM chains for Go -> Rust x509 interop
	for _, alg := range []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm} {
		algCopy := alg
		path := "/certs/" + strings.ToLower(algCopy) + ".pem"
		mGoMux.HandleFunc("GET "+path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-pem-file")
			_, _ = w.Write(encodeMPEMChain(goX509Leaves[algCopy], goX509Mid.cert))
		})
	}

	// 6. /x509 verifies Rust-signed x509 requests by fetching x5u over HTTPS
	mGoMux.HandleFunc("POST /x509", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
			AcceptedAlgorithms: []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		x5u, _, ok := prep.Credential().X509()
		if !ok {
			http.Error(w, "missing x509 credential", http.StatusBadRequest)
			return
		}
		certResp, fErr := httpClient.Get(x5u)
		if fErr != nil {
			http.Error(w, fErr.Error(), http.StatusBadGateway)
			return
		}
		chainPEM, _ := io.ReadAll(certResp.Body)
		_ = certResp.Body.Close()

		midCRL := rustMidCRL
		if r.Header.Get("X-Use-Revoked-CRL") == "1" && rustRevCRL != nil {
			midCRL = rustRevCRL
		}
		var roots []*x509.Certificate
		if rustRootCert != nil {
			roots = []*x509.Certificate{rustRootCert}
		}
		var crls []*x509.RevocationList
		if midCRL != nil && rustRootCRL != nil {
			crls = []*x509.RevocationList{midCRL, rustRootCRL}
		}
		proof, id, vErr := prep.VerifyX509(signaturekey.X509VerifyOptions{
			ChainPEM:        chainPEM,
			Roots:           roots,
			RevocationLists: crls,
		})
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"scheme":     string(proof.Scheme()),
			"alg":        proof.PublicKey().Alg,
			"url":        id.URL(),
			"chain_len":  len(id.Chain()),
			"thumbprint": hex.EncodeToString(id.Thumbprint()),
		})
	})

	// 7. /x509-custom-bundle verifies an x509 request with caller-supplied Root DER, CRL DER, and Chain PEM in JSON body
	mGoMux.HandleFunc("POST /x509-custom-bundle", func(w http.ResponseWriter, r *http.Request) {
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

	// 8. /cached-resource accepts jwt (with ;cache) and cached schemes using mGoAssertionCache
	mGoMux.HandleFunc("POST /cached-resource", func(w http.ResponseWriter, r *http.Request) {
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		cred := prep.Credential()
		if cred.Scheme() == signaturekey.SchemeCached {
			proof, assertion, vErr := prep.VerifyCached(mGoAssertionCache)
			if vErr != nil {
				writeMSigError(w, vErr)
				return
			}
			compact, retained := assertion.Compact()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"scheme_used":  string(proof.Scheme()),
				"orig_scheme":  string(assertion.Scheme()),
				"jti":          assertion.JTI(),
				"issuer":       assertion.Issuer(),
				"retained":     retained,
				"compact_len":  len(compact),
			})
			return
		}
		proof, vErr := prep.Verify(goJWTHolderKey.PublicJWK())
		if vErr != nil {
			writeMSigError(w, vErr)
			return
		}
		grant, issued, iErr := mGoAssertionCache.Issue(proof)
		if iErr != nil {
			writeMSigError(w, iErr)
			return
		}
		if issued {
			if field, fErr := signaturekey.FormatCacheGrants(grant); fErr == nil {
				w.Header().Set("Signature-Key-Cache", field)
			}
			mGoLastIssuedCIDMu.Lock()
			mGoLastIssuedCID = grantCID(grant)
			mGoLastIssuedCIDMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"scheme_used":  string(proof.Scheme()),
			"cache_issued": issued,
			"jti":          grant.JTI(),
		})
	})

	mGoMux.HandleFunc("POST /cached-evict", func(w http.ResponseWriter, _ *http.Request) {
		mGoLastIssuedCIDMu.Lock()
		cid := mGoLastIssuedCID
		mGoLastIssuedCIDMu.Unlock()
		evicted := false
		if cid != "" {
			evicted = mGoAssertionCache.Evict(cid)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "evicted": evicted, "cid": cid})
	})

	// 9. /multi-sig verifies BOTH sig1 (hwk) and sig2 (jwks) on the same HTTP request
	mGoMux.HandleFunc("POST /multi-sig", func(w http.ResponseWriter, r *http.Request) {
		prep1, err1 := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			SignatureLabel:     "sig1",
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
			AcceptedAlgorithms: jose.SignatureAlgorithms(),
		})
		if err1 != nil {
			writeMSigError(w, err1)
			return
		}
		jwk1, _ := prep1.Credential().InlineJWK()
		proof1, vErr1 := prep1.Verify(jwk1)
		if vErr1 != nil {
			writeMSigError(w, vErr1)
			return
		}
		prep2, err2 := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			SignatureLabel:  "sig2",
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
		})
		if err2 != nil {
			writeMSigError(w, err2)
			return
		}
		proof2, vErr2 := prep2.VerifyJWKS(r.Context(), mGoJWKSResolver)
		if vErr2 != nil {
			writeMSigError(w, vErr2)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"sig1_scheme": string(proof1.Scheme()),
			"sig1_alg":    proof1.PublicKey().Alg,
			"sig2_scheme": string(proof2.Scheme()),
			"sig2_signer": proof2.Signer(),
		})
	})

	// 10. /jwt-only accepts only SchemeJWT (to test unsupported_scheme precedence over malformed unaccepted members)
	mGoMux.HandleFunc("POST /jwt-only", func(w http.ResponseWriter, r *http.Request) {
		label := r.Header.Get("X-Select-Label")
		if label == "" {
			label = "sig"
		}
		prep, pErr := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			SignatureLabel:  label,
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT},
		})
		if pErr != nil {
			writeMSigError(w, pErr)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"scheme": string(prep.Credential().Scheme()),
		})
	})

	mGoSrv, mGoDER := registerTLS("m-go-sigkey.example", mGoMux)

	// Register m-go-sigkey.example with m-rust-sigkey.example so Rust can fetch Go JWKS & X509 chains over TLS
	peerBody, _ := json.Marshal(map[string]any{
		"addr":               mGoSrv.Listener.Addr().String(),
		"cert_hex":           hex.EncodeToString(mGoDER),
		"x509_root_der_b64":  base64.StdEncoding.EncodeToString(goX509Root.cert.Raw),
		"x509_mid_crl_b64":   base64.StdEncoding.EncodeToString(goX509MidCRL.Raw),
		"x509_root_crl_b64":  base64.StdEncoding.EncodeToString(goX509RootCRL.Raw),
		"x509_rev_crl_b64":   base64.StdEncoding.EncodeToString(goX509RevokedCRL.Raw),
		"jwt_issuer_jwk":     goJWTIssuerKey.PublicJWK(),
		"jwt_holder_jwk":     goJWTHolderKey.PublicJWK(),
	})
	peerResp, err := httpClient.Post("https://m-rust-sigkey.example/__set-go-peer", "application/json", bytes.NewReader(peerBody))
	must(err, "post m-rust-sigkey.example/__set-go-peer")
	_ = peerResp.Body.Close()

	// =========================================================================
	// M1: Go-side hwk & jose multi-algorithm checks + Go -> Rust HTTPS hwk interop
	// =========================================================================
	algList := jose.SignatureAlgorithms()
	wantAlgs := []string{"Ed25519", "ES256", "ES384", "RS256", "PS256"}
	m1AlgListOK := slices.Equal(algList, wantAlgs)

	m1PerAlgOK := true
	m1GoToRustHWK := make(map[string]any)
	for _, alg := range algList {
		k, _ := newMAlgSigningKey(alg+"-id", alg)
		pub := k.PublicJWK()
		sigBytes, sErr := k.SignMessage(rand.Reader, []byte("m1-message"))
		sz, szErr := pub.SignatureSize()
		vErr := pub.VerifySignature([]byte("m1-message"), sigBytes)
		badVErr := pub.VerifySignature([]byte("other-message"), sigBytes)
		_, pubKeyErr := pub.PublicKey()
		edOnlyOK := (pubKeyErr == nil) == (alg == jose.Ed25519Algorithm)
		jktURI, jktErr := pub.ThumbprintURI()
		if sErr != nil || szErr != nil || sz != len(sigBytes) || vErr != nil || badVErr == nil || !edOnlyOK || jktErr != nil {
			m1PerAlgOK = false
		}

		// Sign HTTPS request with SignHWKRequest and send to Rust https://m-rust-sigkey.example/hwk
		hReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/hwk", strings.NewReader(`{"hello":"rust"}`))
		must(signaturekey.SignHWKRequest(hReq, k, clock), "SignHWKRequest "+alg)
		hResp, dErr := httpClient.Do(hReq)
		must(dErr, "Do Go->Rust hwk "+alg)
		var rOut struct {
			OK     bool   `json:"ok"`
			Alg    string `json:"alg"`
			JKTURI string `json:"jkt_uri"`
		}
		_ = json.NewDecoder(hResp.Body).Decode(&rOut)
		_ = hResp.Body.Close()
		matchOK := hResp.StatusCode == http.StatusOK && rOut.OK && rOut.Alg == alg && rOut.JKTURI == jktURI
		if !matchOK {
			m1PerAlgOK = false
		}
		m1GoToRustHWK[alg] = map[string]any{
			"status":        hResp.StatusCode,
			"alg":           rOut.Alg,
			"jkt_uri_match": rOut.JKTURI == jktURI,
			"sig_bytes_len": len(sigBytes),
		}
	}

	// Unknown parameters in hwk ignored by Go PrepareRequest + Verify
	es256Key, _ := newMAlgSigningKey("es256-unk", jose.ES256Algorithm)
	unkReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	must(signaturekey.SignHWKRequest(unkReq, es256Key, clock), "sign unkReq")
	origSigKey := unkReq.Header.Get("Signature-Key")
	// Re-sign with extra unknown parameters ;use="sig";x5t="ignored";custom_ext="1" in Signature-Key
	unkSigKey := origSigKey + `;use="sig";x5t="ignored";custom_ext="1"`
	unkReq.Header.Set("Signature-Key", unkSigKey)
	// Recompute signature over updated Signature-Key by using PrepareRequest or signing manually:
	// Wait: SignHWKRequest writes Signature-Key; to sign a custom Signature-Key in Go, let's test PrepareRequest on unkReq:
	// PrepareRequest checks Signature-Key BEFORE Verify checks signature bytes! And we can also sign the exact base with es256Key.SignMessage!
	unkPrepTmp, unkPrepErr := signaturekey.PrepareRequest(unkReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	m1UnknownParamsAcceptedOnPrepare := unkPrepErr == nil && unkPrepTmp.Credential().Scheme() == signaturekey.SchemeHWK

	// M1 Negative & AcceptedAlgorithms checks in Go
	_, defaultUnacceptedErr := signaturekey.PrepareRequest(unkReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeHWK},
	})
	var defaultUnacceptedSigErr *signaturekey.Error
	m1DefaultEd25519NegotiationOK := errors.As(defaultUnacceptedErr, &defaultUnacceptedSigErr) &&
		defaultUnacceptedSigErr.Code == signaturekey.ErrorUnsupportedAlgorithm &&
		reflect.DeepEqual(defaultUnacceptedSigErr.AcceptedAlgorithms, []string{jose.Ed25519Algorithm})

	// hwk refuses kid and private parameters before alg
	kidHWKReq := unkReq.Clone(ctx)
	kidHWKReq.Header.Set("Signature-Key", origSigKey+`;kid="k-1"`)
	_, kidHWKErr := signaturekey.PrepareRequest(kidHWKReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	privHWKReq := unkReq.Clone(ctx)
	privHWKReq.Header.Set("Signature-Key", origSigKey+`;d="secret"`)
	_, privHWKErr := signaturekey.PrepareRequest(privHWKReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	// Polymorphic EdDSA / absent alg -> unsupported_algorithm
	polyHWKReq := unkReq.Clone(ctx)
	polyHWKReq.Header.Set("Signature-Key", strings.Replace(origSigKey, `alg="ES256"`, `alg="EdDSA"`, 1))
	_, polyHWKErr := signaturekey.PrepareRequest(polyHWKReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: jose.SignatureAlgorithms(),
	})
	m1NegGuardsOK := sigErrCodeOf(kidHWKErr) == string(signaturekey.ErrorInvalidKey) &&
		sigErrCodeOf(privHWKErr) == string(signaturekey.ErrorInvalidKey) &&
		sigErrCodeOf(polyHWKErr) == string(signaturekey.ErrorUnsupportedAlgorithm)

	// =========================================================================
	// M2: Direct jwks scheme Go-side + Go -> Rust HTTPS jwks interop
	// =========================================================================
	// 1. Exact byte-for-byte URL identity & StaticJWKSResolver
	exactJWKSURL := "https://Client.example/keys/jwks.json?b=2&a=1"
	jwksCred, jwksCredErr := signaturekey.NewJWKSCredential(exactJWKSURL, goJWKSClientKey.ID())
	must(jwksCredErr, "NewJWKSCredential")
	staticReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	must(signaturekey.SignRequest(staticReq, goJWKSClientKey, jwksCred, clock, signaturekey.SignOptions{}), "SignRequest static jwks")
	staticPrep, err := signaturekey.PrepareRequest(staticReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
	})
	must(err, "PrepareRequest static jwks")
	staticProof, err := staticPrep.VerifyJWKS(ctx, signaturekey.StaticJWKSResolver{
		{URL: exactJWKSURL, KeyID: goJWKSClientKey.ID()}: goJWKSClientKey.PublicJWK(),
	})
	must(err, "VerifyJWKS static exact")
	_, caseDiffErr := staticPrep.VerifyJWKS(ctx, signaturekey.StaticJWKSResolver{
		{URL: strings.ToLower(exactJWKSURL), KeyID: goJWKSClientKey.ID()}: goJWKSClientKey.PublicJWK(),
	})
	// Invalid URLs refused by NewJWKSCredential
	_, badHTTPJWKS := signaturekey.NewJWKSCredential("http://client.example/jwks", "k1")
	_, badFragJWKS := signaturekey.NewJWKSCredential("https://client.example/jwks#frag", "k1")
	_, badUserJWKS := signaturekey.NewJWKSCredential("https://user@client.example/jwks", "k1")
	m2ByteForByteAndGuardsOK := staticProof.Signer() == exactJWKSURL &&
		sigErrCodeOf(caseDiffErr) == string(signaturekey.ErrorUnknownKey) &&
		badHTTPJWKS != nil && badFragJWKS != nil && badUserJWKS != nil

	// 2. HTTPKeyResolver same-KID rotation & 1-minute refresh floor over HTTPS
	rotKey1A, _ := newMAlgSigningKey("rot-1", jose.Ed25519Algorithm)
	rotKey1B, _ := newMAlgSigningKey("rot-1", jose.Ed25519Algorithm)
	var rotMu sync.Mutex
	curRotKey := rotKey1A.PublicJWK()
	var rotFetches atomic.Int64
	rotMux := http.NewServeMux()
	rotMux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		rotFetches.Add(1)
		rotMu.Lock()
		k := curRotKey
		rotMu.Unlock()
		w.Header().Set("Cache-Control", "max-age=300")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JWK{k}})
	})
	registerTLS("m-go-rot-jwks.example", rotMux)
	rotURL := "https://m-go-rot-jwks.example/jwks.json"
	rotCred, _ := signaturekey.NewJWKSCredential(rotURL, "rot-1")
	rotClock := newMClock(nowTime)
	rotResolver, err := signaturekey.NewHTTPKeyResolver(signaturekey.HTTPKeyResolverConfig{
		Client:                  httpClient,
		TransportEnforcesEgress: true,
		Clock:                   rotClock,
		Admit:                   func(context.Context, string) error { return nil },
	})
	must(err, "NewHTTPKeyResolver rotResolver")

	verifyRot := func(k jose.SigningKey) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://m-go-sigkey.example/items", nil)
		must(signaturekey.SignRequest(req, k, rotCred, rotClock, signaturekey.SignOptions{}), "sign rot req")
		prep, pErr := signaturekey.PrepareRequest(req, rotClock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWKS},
		})
		if pErr != nil {
			return pErr
		}
		_, vErr := prep.VerifyJWKS(ctx, rotResolver)
		return vErr
	}
	errRotInitial := verifyRot(rotKey1A)
	fetchesAfterInitial := rotFetches.Load()
	// Rotate same-KID key to rotKey1B
	rotMu.Lock()
	curRotKey = rotKey1B.PublicJWK()
	rotMu.Unlock()
	rotClock.Advance(30 * time.Second)
	errRotInsideFloor := verifyRot(rotKey1B)
	fetchesInsideFloor := rotFetches.Load()
	rotClock.Advance(31 * time.Second)
	errRotAfterFloor := verifyRot(rotKey1B)
	fetchesAfterFloor := rotFetches.Load()
	m2RotationFloorOK := errRotInitial == nil && fetchesAfterInitial == 1 &&
		sigErrCodeOf(errRotInsideFloor) == string(signaturekey.ErrorInvalidSignature) && fetchesInsideFloor == 1 &&
		errRotAfterFloor == nil && fetchesAfterFloor == 2

	// 3. Go -> Rust HTTPS jwks interop: Go signs with https://m-go-sigkey.example/.well-known/go-client.jwks -> Rust fetches & verifies
	goToRustJWKSCred, _ := signaturekey.NewJWKSCredential(mGoIssuer+"/.well-known/go-client.jwks", goJWKSClientKey.ID())
	goToRustJWKSReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/jwks", strings.NewReader(`{"from":"go"}`))
	must(signaturekey.SignRequest(goToRustJWKSReq, goJWKSClientKey, goToRustJWKSCred, clock, signaturekey.SignOptions{}), "sign goToRustJWKSReq")
	goToRustJWKSResp, err := httpClient.Do(goToRustJWKSReq)
	must(err, "do goToRustJWKSReq")
	var goToRustJWKSOut struct {
		OK     bool   `json:"ok"`
		Signer string `json:"signer"`
		KID    string `json:"kid"`
	}
	_ = json.NewDecoder(goToRustJWKSResp.Body).Decode(&goToRustJWKSOut)
	_ = goToRustJWKSResp.Body.Close()

	// Unknown kid from Go -> Rust jwks endpoint -> 401 unknown_key
	unkKIDCed, _ := signaturekey.NewJWKSCredential(mGoIssuer+"/.well-known/go-client.jwks", "missing-kid")
	unkKIDReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/jwks", nil)
	must(signaturekey.SignRequest(unkKIDReq, goJWKSClientKey, unkKIDCed, clock, signaturekey.SignOptions{}), "sign unkKIDReq")
	unkKIDResp, err := httpClient.Do(unkKIDReq)
	must(err, "do unkKIDReq")
	unkKIDSigErr := unkKIDResp.Header.Get("Signature-Error")
	_ = unkKIDResp.Body.Close()
	m2GoToRustOK := goToRustJWKSResp.StatusCode == http.StatusOK && goToRustJWKSOut.OK &&
		goToRustJWKSOut.Signer == mGoIssuer+"/.well-known/go-client.jwks" &&
		unkKIDResp.StatusCode == http.StatusUnauthorized && strings.Contains(unkKIDSigErr, "error=unknown_key")

	// =========================================================================
	// M3: x509 scheme Go-side + Go -> Rust HTTPS x509 interop
	// =========================================================================
	m3GoSideAlgsOK := true
	m3VerifyRefusedX509 := true
	m3GoToRustX509 := make(map[string]any)
	for _, alg := range []string{jose.Ed25519Algorithm, jose.ES256Algorithm, jose.ES384Algorithm} {
		k := goX509Keys[alg]
		leaf := goX509Leaves[alg]
		certURL := mGoIssuer + "/certs/" + strings.ToLower(alg) + ".pem"
		cred, cErr := signaturekey.NewX509Credential(certURL, leaf)
		must(cErr, "NewX509Credential "+alg)
		xReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/x509", strings.NewReader(`{"x509":"go"}`))
		must(signaturekey.SignRequest(xReq, k, cred, clock, signaturekey.SignOptions{}), "SignRequest x509 "+alg)

		// Verify Go-side PrepareRequest + Verify refusal + VerifyX509 success
		prep, pErr := signaturekey.PrepareRequest(xReq, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
			AcceptedAlgorithms: []string{alg},
		})
		must(pErr, "PrepareRequest x509 "+alg)
		if _, directErr := prep.Verify(k.PublicJWK()); directErr == nil {
			m3VerifyRefusedX509 = false
		}
		proof, id, vErr := prep.VerifyX509(signaturekey.X509VerifyOptions{
			ChainPEM:        encodeMPEMChain(leaf, goX509Mid.cert),
			Roots:           []*x509.Certificate{goX509Root.cert},
			RevocationLists: []*x509.RevocationList{goX509MidCRL, goX509RootCRL},
		})
		if vErr != nil || proof.Scheme() != signaturekey.SchemeX509 || proof.PublicKey().Alg != alg || id.URL() != certURL || len(id.Chain()) != 3 {
			m3GoSideAlgsOK = false
		}

		// Send xReq over HTTPS to Rust https://m-rust-sigkey.example/x509
		xResp, dErr := httpClient.Do(xReq)
		must(dErr, "Do Go->Rust x509 "+alg)
		var xOut struct {
			OK  bool   `json:"ok"`
			Alg string `json:"alg"`
			URL string `json:"url"`
		}
		_ = json.NewDecoder(xResp.Body).Decode(&xOut)
		_ = xResp.Body.Close()
		if xResp.StatusCode != http.StatusOK || !xOut.OK || xOut.Alg != alg || xOut.URL != certURL {
			m3GoSideAlgsOK = false
		}
		m3GoToRustX509[alg] = map[string]any{
			"status": xResp.StatusCode,
			"alg":    xOut.Alg,
			"url":    xOut.URL,
		}
	}

	// Go -> Rust x509 with revoked ES256 leaf -> 401 invalid_key
	revX509Cred, _ := signaturekey.NewX509Credential(mGoIssuer+"/certs/es256.pem", goX509Leaves[jose.ES256Algorithm])
	revX509Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/x509", nil)
	revX509Req.Header.Set("X-Use-Revoked-CRL", "1")
	must(signaturekey.SignRequest(revX509Req, goX509Keys[jose.ES256Algorithm], revX509Cred, clock, signaturekey.SignOptions{}), "sign revX509Req")
	revX509Resp, err := httpClient.Do(revX509Req)
	must(err, "do revX509Req")
	revX509SigErr := revX509Resp.Header.Get("Signature-Error")
	_ = revX509Resp.Body.Close()
	m3GoToRustRevokedOK := revX509Resp.StatusCode == http.StatusUnauthorized && strings.Contains(revX509SigErr, "error=invalid_key")

	// Go-side negative x509 checks: missing CRL, revoked leaf, revoked intermediate, expired CRL, RSA leaf -> unsupported_algorithm
	esPrep := func() signaturekey.PreparedRequest {
		c, _ := signaturekey.NewX509Credential(mGoIssuer+"/certs/es256.pem", goX509Leaves[jose.ES256Algorithm])
		r, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
		_ = signaturekey.SignRequest(r, goX509Keys[jose.ES256Algorithm], c, clock, signaturekey.SignOptions{})
		p, _ := signaturekey.PrepareRequest(r, clock, signaturekey.VerifyOptions{
			AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
			AcceptedAlgorithms: []string{jose.ES256Algorithm},
		})
		return p
	}
	esChainPEM := encodeMPEMChain(goX509Leaves[jose.ES256Algorithm], goX509Mid.cert)
	_, _, noCRLErr := esPrep().VerifyX509(signaturekey.X509VerifyOptions{
		ChainPEM: esChainPEM,
		Roots:    []*x509.Certificate{goX509Root.cert},
	})
	_, _, revLeafErr := esPrep().VerifyX509(signaturekey.X509VerifyOptions{
		ChainPEM:        esChainPEM,
		Roots:           []*x509.Certificate{goX509Root.cert},
		RevocationLists: []*x509.RevocationList{goX509RevokedCRL, goX509RootCRL},
	})
	_, _, expCRLErr := esPrep().VerifyX509(signaturekey.X509VerifyOptions{
		ChainPEM:        esChainPEM,
		Roots:           []*x509.Certificate{goX509Root.cert},
		RevocationLists: []*x509.RevocationList{goX509Mid.crl(nowTime), goX509RootCRL},
	})
	// RSA leaf certificate -> unsupported_algorithm even when all SignatureAlgorithms() are accepted
	rsaLeafKey, _ := newMAlgSigningKey("rsa-leaf", jose.PS256Algorithm)
	rsaLeafCert := goX509Root.issueLeaf("rsa-leaf.example", rsaLeafKey.Public(), nowTime)
	rsaLeafCred, _ := signaturekey.NewX509Credential(mGoIssuer+"/certs/rsa.pem", rsaLeafCert)
	rsaLeafReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(rsaLeafReq, rsaLeafKey, rsaLeafCred, clock, signaturekey.SignOptions{})
	rsaLeafPrep, _ := signaturekey.PrepareRequest(rsaLeafReq, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
		AcceptedAlgorithms: jose.SignatureAlgorithms(),
	})
	_, _, rsaLeafErr := rsaLeafPrep.VerifyX509(signaturekey.X509VerifyOptions{
		ChainPEM:        encodeMPEMChain(rsaLeafCert),
		Roots:           []*x509.Certificate{goX509Root.cert},
		RevocationLists: []*x509.RevocationList{goX509RootCRL},
	})
	m3NegGuardsOK := sigErrCodeOf(noCRLErr) == string(signaturekey.ErrorInvalidKey) &&
		sigErrCodeOf(revLeafErr) == string(signaturekey.ErrorInvalidKey) &&
		sigErrCodeOf(expCRLErr) == string(signaturekey.ErrorInvalidKey) &&
		sigErrCodeOf(rsaLeafErr) == string(signaturekey.ErrorUnsupportedAlgorithm)

	// =========================================================================
	// M4: Pinned Cross-Language x509 Chain Boundary (RSA-Signed Root CA + RSA CRL Issuing EC P-256 Leaf)
	// =========================================================================
	rsaCASigner, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err, "generate rsaCASigner")
	rsaRootCA := newMAuthority("m4-rsa-root-ca.example", nil, rsaCASigner, nowTime)
	rsaRootCRL := rsaRootCA.crl(nowTime.Add(time.Hour))
	m4LeafKey, _ := newMAlgSigningKey("m4-ec-leaf", jose.ES256Algorithm)
	m4LeafCert := rsaRootCA.issueLeaf("m4-ec-leaf.example", m4LeafKey.Public(), nowTime)
	m4LeafPEM := encodeMPEMChain(m4LeafCert)

	m4Cred, err := signaturekey.NewX509Credential(mGoIssuer+"/certs/m4-ec-under-rsa-ca.pem", m4LeafCert)
	must(err, "NewX509Credential m4")
	m4BodyBytes, _ := json.Marshal(map[string]any{
		"chain_pem":    string(m4LeafPEM),
		"root_der_b64": base64.StdEncoding.EncodeToString(rsaRootCA.cert.Raw),
		"crl_der_b64":  base64.StdEncoding.EncodeToString(rsaRootCRL.Raw),
	})
	m4Req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/x509-custom-bundle", bytes.NewReader(m4BodyBytes))
	m4Req.Header.Set("Content-Type", "application/json")
	must(signaturekey.SignRequest(m4Req, m4LeafKey, m4Cred, clock, signaturekey.SignOptions{}), "SignRequest m4Req")

	// 1. Verify in aauth-go: Go ACCEPTS the P-256 leaf signed by the RSA-2048 Root CA + RSA-signed CRL!
	m4GoPrep, err := signaturekey.PrepareRequest(m4Req, clock, signaturekey.VerifyOptions{
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeX509},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	must(err, "PrepareRequest m4GoPrep")
	m4GoProof, m4GoID, m4GoVerifyErr := m4GoPrep.VerifyX509(signaturekey.X509VerifyOptions{
		ChainPEM:        m4LeafPEM,
		Roots:           []*x509.Certificate{rsaRootCA.cert},
		RevocationLists: []*x509.RevocationList{rsaRootCRL},
	})
	m4GoAccepted := m4GoVerifyErr == nil && m4GoProof.Scheme() == signaturekey.SchemeX509 &&
		m4GoProof.PublicKey().Alg == jose.ES256Algorithm && len(m4GoID.Chain()) == 2

	// 2. Send the exact same request + chain + root + CRL to aauth-rust: in alpha.15+, Rust ACCEPTS with 200 OK!
	m4RustResp, err := httpClient.Do(m4Req)
	must(err, "do m4Req to Rust")
	var m4RustOut struct {
		OK  bool   `json:"ok"`
		Alg string `json:"alg"`
	}
	_ = json.NewDecoder(m4RustResp.Body).Decode(&m4RustOut)
	m4RustSigErr := m4RustResp.Header.Get("Signature-Error")
	_ = m4RustResp.Body.Close()
	m4RustAccepted := m4RustResp.StatusCode == http.StatusOK && m4RustOut.OK && m4RustOut.Alg == jose.ES256Algorithm

	// =========================================================================
	// M5: cached scheme & AssertionCache lifecycle in Go
	// =========================================================================
	mintMJWT := func(jti string, lifetime time.Duration, cnf jose.JWK) string {
		claims := map[string]any{
			"iss": "https://m-issuer.example",
			"sub": "agent-m5",
			"exp": nowTime.Add(lifetime).Unix(),
			"cnf": map[string]any{"jwk": cnf},
		}
		if jti != "" {
			claims["jti"] = jti
		}
		raw, _ := json.Marshal(claims)
		compact, sErr := jose.SignCompact(goJWTIssuerKey, jose.Header{
			Algorithm: jose.Ed25519Algorithm,
			Type:      "example+jwt",
			KeyID:     goJWTIssuerKey.ID(),
		}, raw)
		must(sErr, "mintMJWT")
		return compact
	}
	m5Compact := mintMJWT("m5-jti-1", time.Hour, goJWTHolderKey.PublicJWK())
	m5FullCred, err := signaturekey.NewJWTCredential(m5Compact)
	must(err, "NewJWTCredential m5")
	m5FullCacheCred, err := m5FullCred.WithCache()
	must(err, "WithCache m5")

	m5CacheClock := newMClock(nowTime)
	m5Cache, err := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{
		Key:       mGoFleetKey,
		Retention: 10 * time.Minute,
	})
	must(err, "NewAssertionCache m5Cache")
	m5InitReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	must(signaturekey.SignRequest(m5InitReq, goJWTHolderKey, m5FullCacheCred, m5CacheClock, signaturekey.SignOptions{}), "sign m5InitReq")
	m5InitPrep, err := signaturekey.PrepareRequest(m5InitReq, m5CacheClock, signaturekey.VerifyOptions{})
	must(err, "PrepareRequest m5InitPrep")
	m5InitProof, err := m5InitPrep.Verify(goJWTHolderKey.PublicJWK())
	must(err, "Verify m5InitPrep")
	m5Grant1, m5Issued1, err := m5Cache.Issue(m5InitProof)
	must(err, "m5Cache.Issue 1")
	m5Grant2, m5Issued2, err := m5Cache.Issue(m5InitProof)
	must(err, "m5Cache.Issue 2")
	m5Field1, err := signaturekey.FormatCacheGrants(m5Grant1)
	must(err, "FormatCacheGrants m5")
	m5ParsedGrants, err := signaturekey.ParseCacheGrants([]string{m5Field1})
	must(err, "ParseCacheGrants m5")
	m5CachedCred, err := signaturekey.NewCachedCredential(m5ParsedGrants[0])
	must(err, "NewCachedCredential m5")

	m5CachedReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	must(signaturekey.SignRequest(m5CachedReq, goJWTHolderKey, m5CachedCred, m5CacheClock, signaturekey.SignOptions{}), "sign m5CachedReq")
	m5CachedPrep, err := signaturekey.PrepareRequest(m5CachedReq, m5CacheClock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached},
	})
	must(err, "PrepareRequest m5CachedPrep")
	_, m5DirectVerifyErr := m5CachedPrep.Verify(goJWTHolderKey.PublicJWK())
	m5VerifyRefusedCached := m5DirectVerifyErr != nil

	m5ResolvedProof, m5Assertion, err := m5CachedPrep.VerifyCached(m5Cache)
	must(err, "VerifyCached m5Cache")
	m5RetainedCompact, m5RetainedOK := m5Assertion.Compact()

	// Fleet peer (Fleet: true) vs Standalone peer (Fleet: false) vs Wrong-Key peer
	m5FleetPeer, _ := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: mGoFleetKey, Fleet: true})
	_, m5FleetAssertion, m5FleetErr := m5CachedPrep.VerifyCached(m5FleetPeer)
	_, m5FleetRetained := m5FleetAssertion.Compact()
	m5StandalonePeer, _ := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: mGoFleetKey, Fleet: false})
	_, _, m5StandaloneErr := m5CachedPrep.VerifyCached(m5StandalonePeer)
	m5WrongKeyPeer, _ := signaturekey.NewAssertionCache(signaturekey.AssertionCacheConfig{Key: bytes.Repeat([]byte{0x7b}, 32), Fleet: true})
	_, _, m5WrongKeyErr := m5CachedPrep.VerifyCached(m5WrongKeyPeer)

	// Wrong confirmation key signature -> invalid_signature (not cache_miss)
	m5WrongSignerReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(m5WrongSignerReq, goJWTIssuerKey, m5CachedCred, m5CacheClock, signaturekey.SignOptions{})
	m5WrongSignerPrep, _ := signaturekey.PrepareRequest(m5WrongSignerReq, m5CacheClock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeCached},
	})
	_, _, m5WrongSignerErr := m5WrongSignerPrep.VerifyCached(m5Cache)

	// Held assertion past its exp -> expired_jwt (not cache_miss)
	m5ShortCompact := mintMJWT("m5-short-jti", 5*time.Minute, goJWTHolderKey.PublicJWK())
	m5ShortCred, _ := signaturekey.NewJWTCredential(m5ShortCompact)
	m5ShortCred, _ = m5ShortCred.WithCache()
	m5ShortReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(m5ShortReq, goJWTHolderKey, m5ShortCred, m5CacheClock, signaturekey.SignOptions{})
	m5ShortPrep, _ := signaturekey.PrepareRequest(m5ShortReq, m5CacheClock, signaturekey.VerifyOptions{})
	m5ShortProof, _ := m5ShortPrep.Verify(goJWTHolderKey.PublicJWK())
	m5ShortGrant, _, _ := m5Cache.Issue(m5ShortProof)
	m5ShortCachedCred, _ := signaturekey.NewCachedCredential(m5ShortGrant)
	m5ExpClock := newMClock(nowTime.Add(5 * time.Minute))
	m5AtExpReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(m5AtExpReq, goJWTHolderKey, m5ShortCachedCred, m5ExpClock, signaturekey.SignOptions{})
	m5AtExpPrep, _ := signaturekey.PrepareRequest(m5AtExpReq, m5ExpClock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeCached},
	})
	_, _, m5AtExpErr := m5AtExpPrep.VerifyCached(m5Cache)

	// Evict entry (m5Grant1) while still within retention -> cache_miss
	m5EvictedOK := m5Cache.Evict(grantCID(m5Grant1))
	_, _, m5AfterEvictErr := m5CachedPrep.VerifyCached(m5Cache)

	// Entry (m5Grant2) past its cache retention (10m + 1s while assertion lives 1h) -> cache_miss
	m5CachedCred2, err := signaturekey.NewCachedCredential(m5Grant2)
	must(err, "NewCachedCredential m5Grant2")
	m5PastRetClock := newMClock(nowTime.Add(10*time.Minute + time.Second))
	m5PastRetReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(m5PastRetReq, goJWTHolderKey, m5CachedCred2, m5PastRetClock, signaturekey.SignOptions{})
	m5PastRetPrep, _ := signaturekey.PrepareRequest(m5PastRetReq, m5PastRetClock, signaturekey.VerifyOptions{
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeCached},
	})
	_, _, m5PastRetErr := m5PastRetPrep.VerifyCached(m5Cache)

	// Long-lived (>24h) assertion is not cached (issued == false, err == nil)
	m5LongCompact := mintMJWT("m5-long-jti", 25*time.Hour, goJWTHolderKey.PublicJWK())
	m5LongCred, _ := signaturekey.NewJWTCredential(m5LongCompact)
	m5LongCred, _ = m5LongCred.WithCache()
	m5LongReq, _ := http.NewRequest(http.MethodGet, "https://m-go-sigkey.example/items", nil)
	_ = signaturekey.SignRequest(m5LongReq, goJWTHolderKey, m5LongCred, m5CacheClock, signaturekey.SignOptions{})
	m5LongPrep, _ := signaturekey.PrepareRequest(m5LongReq, m5CacheClock, signaturekey.VerifyOptions{})
	m5LongProof, _ := m5LongPrep.Verify(goJWTHolderKey.PublicJWK())
	_, m5LongIssued, m5LongErr := m5Cache.Issue(m5LongProof)

	// SelectScheme before and after issuance
	m5SelBefore, m5SelBeforeOK := signaturekey.SelectScheme(
		[]signaturekey.Scheme{signaturekey.SchemeCached, "future", signaturekey.SchemeJWT},
		[]signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached},
		false,
	)
	m5SelAfter, m5SelAfterOK := signaturekey.SelectScheme(
		[]signaturekey.Scheme{signaturekey.SchemeCached, "future", signaturekey.SchemeJWT},
		[]signaturekey.Scheme{signaturekey.SchemeJWT, signaturekey.SchemeCached},
		true,
	)
	m5AllOK := m5Issued1 && m5Issued2 && grantCID(m5Grant1) != grantCID(m5Grant2) &&
		!strings.Contains(grantCID(m5Grant1), "m5-jti-1") &&
		m5VerifyRefusedCached &&
		m5ResolvedProof.Scheme() == signaturekey.SchemeCached &&
		m5Assertion.JTI() == "m5-jti-1" && m5RetainedOK && m5RetainedCompact == m5Compact &&
		m5FleetErr == nil && !m5FleetRetained && m5FleetAssertion.JTI() == "m5-jti-1" &&
		sigErrCodeOf(m5StandaloneErr) == string(signaturekey.ErrorCacheMiss) &&
		sigErrCodeOf(m5WrongKeyErr) == string(signaturekey.ErrorCacheMiss) &&
		sigErrCodeOf(m5WrongSignerErr) == string(signaturekey.ErrorInvalidSignature) &&
		sigErrCodeOf(m5AtExpErr) == string(signaturekey.ErrorExpiredJWT) &&
		sigErrCodeOf(m5PastRetErr) == string(signaturekey.ErrorCacheMiss) &&
		m5EvictedOK && sigErrCodeOf(m5AfterEvictErr) == string(signaturekey.ErrorCacheMiss) &&
		!m5LongIssued && m5LongErr == nil &&
		m5SelBeforeOK && m5SelBefore == signaturekey.SchemeJWT &&
		m5SelAfterOK && m5SelAfter == signaturekey.SchemeCached

	// =========================================================================
	// M6 Direction 1: Go CachingCredential client <-> Rust HTTPS AssertionCache server
	// =========================================================================
	m6Compact := mintMJWT("m6-rust-srv-jti-1", time.Hour, goJWTHolderKey.PublicJWK())
	m6BaseCred, err := signaturekey.NewJWTCredential(m6Compact)
	must(err, "NewJWTCredential m6")
	m6Caching, err := signaturekey.NewCachingCredential(m6BaseCred)
	must(err, "NewCachingCredential m6")
	m6SchemeBeforeCall1 := string(m6Caching.Credential().Scheme())

	doM6Call := func(evictFirst bool) (int, string, string, string, bool) {
		if evictFirst {
			evReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/cached-evict", nil)
			evResp, eErr := httpClient.Do(evReq)
			must(eErr, "do cached-evict on Rust")
			_ = evResp.Body.Close()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/cached-resource", strings.NewReader(`{"step":"m6"}`))
		must(signaturekey.SignRequest(req, goJWTHolderKey, m6Caching.Credential(), clock, signaturekey.SignOptions{}), "sign m6 call")
		resp, dErr := httpClient.Do(req)
		must(dErr, "do m6 call")
		defer resp.Body.Close()
		var out struct {
			SchemeUsed string `json:"scheme_used"`
			Type       string `json:"type"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resend, hErr := m6Caching.HandleResponse(resp, "sig")
		must(hErr, "m6Caching.HandleResponse")
		return resp.StatusCode, resp.Header.Get("Signature-Key-Cache"), resp.Header.Get("Signature-Error"), out.SchemeUsed, resend
	}

	// Call 1: presents jwt;cache -> Rust server issues Signature-Key-Cache -> m6Caching transitions to cached
	m6Call1Status, m6Call1CacheHdr, _, m6Call1SchemeUsed, m6Call1Resend := doM6Call(false)
	m6SchemeAfterCall1 := string(m6Caching.Credential().Scheme())
	m6CIDAfterCall1, _ := m6Caching.Credential().CacheIdentifier()

	// Call 2: presents cached;cid="..." -> Rust server resolves from AssertionCache -> 200 OK
	m6Call2Status, _, _, m6Call2SchemeUsed, m6Call2Resend := doM6Call(false)

	// Call 3: Rust server evicts cid -> Go sends cached -> Rust returns 401 Signature-Error: error=cache_miss -> HandleResponse returns resend=true and falls back to jwt;cache!
	m6Call3MissStatus, _, m6Call3MissSigErr, _, m6Call3Resend := doM6Call(true)
	m6SchemeAfterMiss := string(m6Caching.Credential().Scheme())
	m6CacheReqAfterMiss := m6Caching.Credential().CacheRequested()

	// Call 3b (automatic retry with full jwt;cache): Rust verifies full jwt;cache, issues fresh Signature-Key-Cache -> 200 OK!
	m6Call3RetryStatus, m6Call3RetryCacheHdr, _, m6Call3RetrySchemeUsed, m6Call3RetryResend := doM6Call(false)
	m6SchemeAfterRetry := string(m6Caching.Credential().Scheme())

	m6GoClientToRustServerOK := m6SchemeBeforeCall1 == "jwt" &&
		m6Call1Status == http.StatusOK && m6Call1CacheHdr != "" && m6Call1SchemeUsed == "jwt" && !m6Call1Resend &&
		m6SchemeAfterCall1 == "cached" && m6CIDAfterCall1 != "" &&
		m6Call2Status == http.StatusOK && m6Call2SchemeUsed == "cached" && !m6Call2Resend &&
		m6Call3MissStatus == http.StatusUnauthorized && strings.Contains(m6Call3MissSigErr, "error=cache_miss") &&
		m6Call3Resend && m6SchemeAfterMiss == "jwt" && m6CacheReqAfterMiss &&
		m6Call3RetryStatus == http.StatusOK && m6Call3RetryCacheHdr != "" && m6Call3RetrySchemeUsed == "jwt" && !m6Call3RetryResend &&
		m6SchemeAfterRetry == "cached"

	// =========================================================================
	// M7: Multiple Signatures (SignRequests) & unsupported_scheme Precedence
	// =========================================================================
	m7Key1, _ := newMAlgSigningKey("m7-es256-1", jose.ES256Algorithm)
	m7Cred1, err := signaturekey.NewHWKCredential(m7Key1.PublicJWK())
	must(err, "NewHWKCredential m7Cred1")
	m7Compact := mintMJWT("m7-jwt-jti-2", time.Hour, goJWTHolderKey.PublicJWK())
	m7Cred2, err := signaturekey.NewJWTCredential(m7Compact)
	must(err, "NewJWTCredential m7Cred2")
	m7Cred2, _ = m7Cred2.WithCache()

	m7MultiReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://m-rust-sigkey.example/multi-sig", strings.NewReader(`{"multi":"go"}`))
	must(signaturekey.SignRequests(m7MultiReq, []signaturekey.RequestSignature{
		{Label: "sig1", Key: m7Key1, Credential: m7Cred1},
		{Label: "sig2", Key: goJWTHolderKey, Credential: m7Cred2},
	}, clock, signaturekey.SignOptions{}), "SignRequests m7MultiReq")

	// 1. Go-side verification of both sig1 and sig2 + tamper check on unselected member
	m7Prep1, err := signaturekey.PrepareRequest(m7MultiReq, clock, signaturekey.VerifyOptions{
		SignatureLabel:     "sig1",
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	must(err, "PrepareRequest m7Prep1")
	_, m7Ver1Err := m7Prep1.Verify(m7Key1.PublicJWK())
	m7Prep2, err := signaturekey.PrepareRequest(m7MultiReq, clock, signaturekey.VerifyOptions{
		SignatureLabel:  "sig2",
		AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT},
	})
	must(err, "PrepareRequest m7Prep2")
	_, m7Ver2Err := m7Prep2.Verify(goJWTHolderKey.PublicJWK())

	// Tamper with sig2 in Signature-Key -> invalidates sig1 because SignRequests writes all members before signing
	m7TamperedReq := m7MultiReq.Clone(ctx)
	m7TamperedReq.Body = io.NopCloser(strings.NewReader(`{"multi":"go"}`))
	m7TamperedReq.Header.Set("Signature-Key", strings.Replace(m7MultiReq.Header.Get("Signature-Key"), ";cache", "", 1))
	m7TamperedPrep1, _ := signaturekey.PrepareRequest(m7TamperedReq, clock, signaturekey.VerifyOptions{
		SignatureLabel:     "sig1",
		AcceptedSchemes:    []signaturekey.Scheme{signaturekey.SchemeHWK},
		AcceptedAlgorithms: []string{jose.ES256Algorithm},
	})
	_, m7TamperedVer1Err := m7TamperedPrep1.Verify(m7Key1.PublicJWK())

	// Send m7MultiReq over HTTPS to Rust https://m-rust-sigkey.example/multi-sig
	m7MultiReq.Body = io.NopCloser(strings.NewReader(`{"multi":"go"}`))
	m7RustResp, err := httpClient.Do(m7MultiReq)
	must(err, "do m7MultiReq to Rust")
	var m7RustOut struct {
		OK            bool   `json:"ok"`
		Sig1Scheme    string `json:"sig1_scheme"`
		Sig1Alg       string `json:"sig1_alg"`
		Sig2Scheme    string `json:"sig2_scheme"`
		Sig2CacheReq  bool   `json:"sig2_cache_req"`
		TamperRefused bool   `json:"tamper_refused"`
	}
	_ = json.NewDecoder(m7RustResp.Body).Decode(&m7RustOut)
	_ = m7RustResp.Body.Close()

	// Precedence: malformed member of an unaccepted scheme returns unsupported_scheme (not invalid_key)
	m7PrecedenceOK := true
	for _, hdr := range []string{
		`sig=hwk`,
		`sig=hwk;kty="EC"`,
		`sig=x509;bad=1`,
		`sig=cached`,
		`sig=unknown;foo=?1`,
	} {
		pReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://m-go-sigkey.example/items", nil)
		pReq.Header.Set("Signature-Key", hdr)
		pReq.Header.Set("Signature-Input", `sig=("@method" "@authority" "@path" "@query" "signature-key");created=`+strconvItoa(nowTime.Unix()))
		pReq.Header.Set("Signature", `sig=:AQID:`)
		_, pErr := signaturekey.PrepareRequest(pReq, clock, signaturekey.VerifyOptions{
			AcceptedSchemes: []signaturekey.Scheme{signaturekey.SchemeJWT},
		})
		if sigErrCodeOf(pErr) != string(signaturekey.ErrorUnsupportedScheme) {
			m7PrecedenceOK = false
		}
	}

	m7GoAllOK := m7Ver1Err == nil && m7Ver2Err == nil &&
		sigErrCodeOf(m7TamperedVer1Err) == string(signaturekey.ErrorInvalidSignature) &&
		m7RustResp.StatusCode == http.StatusOK && m7RustOut.OK &&
		m7RustOut.Sig1Scheme == "hwk" && m7RustOut.Sig1Alg == "ES256" &&
		m7RustOut.Sig2Scheme == "jwt" && m7RustOut.Sig2CacheReq && m7RustOut.TamperRefused &&
		m7PrecedenceOK

	return map[string]any{
		"m_go_addr":     mGoSrv.Listener.Addr().String(),
		"m_go_cert_hex": hex.EncodeToString(mGoDER),
		"m6_rust_jwt":   m5Compact,
		"m1": map[string]any{
			"alg_list_ok":             m1AlgListOK,
			"per_alg_ok":              m1PerAlgOK,
			"unknown_params_accepted": m1UnknownParamsAcceptedOnPrepare,
			"default_ed25519_neg_ok":  m1DefaultEd25519NegotiationOK,
			"neg_guards_ok":           m1NegGuardsOK,
			"go_to_rust_hwk":          m1GoToRustHWK,
		},
		"m2": map[string]any{
			"byte_for_byte_and_guards_ok": m2ByteForByteAndGuardsOK,
			"rotation_floor_ok":           m2RotationFloorOK,
			"go_to_rust_ok":               m2GoToRustOK,
		},
		"m3": map[string]any{
			"go_side_algs_ok":       m3GoSideAlgsOK,
			"verify_refused_x509":   m3VerifyRefusedX509,
			"go_to_rust_x509":       m3GoToRustX509,
			"go_to_rust_revoked_ok": m3GoToRustRevokedOK,
			"neg_guards_ok":         m3NegGuardsOK,
		},
		"m4": map[string]any{
			"go_accepted_rsa_ca_chain":     m4GoAccepted,
			"rust_accepted_rsa_ca_chain":   m4RustAccepted,
			"rust_status":                  m4RustResp.StatusCode,
			"rust_alg":                     m4RustOut.Alg,
			"rust_signature_error":         m4RustSigErr,
		},
		"m5": map[string]any{
			"all_ok":                m5AllOK,
			"verify_refused_cached": m5VerifyRefusedCached,
			"grant1_cid":            grantCID(m5Grant1),
			"grant2_cid":            grantCID(m5Grant2),
			"field1":                m5Field1,
		},
		"m6": map[string]any{
			"go_client_to_rust_server_ok": m6GoClientToRustServerOK,
			"call1_status":                m6Call1Status,
			"call1_cache_hdr":             m6Call1CacheHdr,
			"call2_status":                m6Call2Status,
			"call2_scheme_used":           m6Call2SchemeUsed,
			"call3_miss_status":           m6Call3MissStatus,
			"call3_miss_sig_err":          m6Call3MissSigErr,
			"call3_resend":                m6Call3Resend,
			"call3_retry_status":          m6Call3RetryStatus,
			"call3_retry_cache_hdr":       m6Call3RetryCacheHdr,
		},
		"m7": map[string]any{
			"go_all_ok":      m7GoAllOK,
			"precedence_ok":  m7PrecedenceOK,
			"go_to_rust_out": m7RustOut,
		},
	}
}

func strconvItoa(v int64) string {
	return big.NewInt(v).String()
}
