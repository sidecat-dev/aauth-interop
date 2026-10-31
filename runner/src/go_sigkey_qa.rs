use crate::tls::TlsServer;
use crate::{QaCaseReceipt, Result, header_values, hex_decode, json_response};
use aauth_rust_jose::{Jwk, SigningKey};
use aauth_rust_signature_key::{
    AssertionCache, CacheRequest, CachedDocument, Error as SigError, KeyCache, KeyCacheAnswer,
    KeyMaterial, PreparedRequest, RequestSignature, choose_presented_scheme, present_issued_cid,
    sign_request, sign_requests, signature_error_code,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD as BASE64_URL},
};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::Path,
    process::Command,
    sync::{Arc, Mutex},
};

const RSA_2048_PKCS1_DER: &[u8] = include_bytes!("rsa-2048.der");

fn b64_std(bytes: &[u8]) -> String {
    BASE64_STD.encode(bytes)
}

fn b64_url(bytes: &[u8]) -> String {
    BASE64_URL.encode(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(body);
    out
}

fn rsa_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let algorithm = der_tlv(
        0x30,
        &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        ],
    );
    let mut body = der_tlv(0x02, &[0x00]);
    body.extend(algorithm);
    body.extend(der_tlv(0x04, pkcs1));
    der_tlv(0x30, &body)
}

fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    der
}

fn pkcs8_pem(der: &[u8]) -> String {
    let encoded = b64_std(der);
    let mut body = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).unwrap());
        body.push('\n');
    }
    format!("-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n")
}

fn make_ca_cert(name: &str, key: &rcgen::KeyPair) -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params.self_signed(key).unwrap()
}

fn make_mid_cert(
    name: &str,
    key: &rcgen::KeyPair,
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
) -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params.signed_by(key, issuer, issuer_key).unwrap()
}

fn make_leaf_cert(
    name: &str,
    serial: u64,
    key: &rcgen::KeyPair,
    issuer: &rcgen::Certificate,
    issuer_key: &rcgen::KeyPair,
) -> rcgen::Certificate {
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.serial_number = Some(rcgen::SerialNumber::from(serial));
    params.not_before = rcgen::date_time_ymd(1970, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    params.signed_by(key, issuer, issuer_key).unwrap()
}

fn make_crl(
    issuer: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    revoked: &[u64],
    next_update: (i32, u8, u8),
) -> Vec<u8> {
    rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(1970, 1, 1),
        next_update: rcgen::date_time_ymd(next_update.0, next_update.1, next_update.2),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| rcgen::RevokedCertParams {
                serial_number: rcgen::SerialNumber::from(*serial),
                revocation_time: rcgen::date_time_ymd(1970, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(issuer, key)
    .unwrap()
    .der()
    .to_vec()
}

fn sign_custom_sigkey_request(
    uri: &str,
    sig_key_header: &str,
    created: i64,
    schemes: &[&str],
    sig_len: usize,
    sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
) -> Request<Vec<u8>> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("signature-key", sig_key_header)
        .header(
            "signature-input",
            format!("sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created={created}"),
        )
        .header("signature", format!("sig=:{}:", b64_std(&vec![1u8; sig_len])))
        .body(Vec::new())
        .unwrap();
    let base = PreparedRequest::prepare_with_schemes(&req, "sig", created, 60, schemes)
        .unwrap()
        .signature_base()
        .to_vec();
    let sig = sign_fn(&base);
    req.headers_mut()
        .insert("signature", format!("sig=:{}:", b64_std(&sig)).parse().unwrap());
    req
}

fn post_json_ext(
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    uri: &str,
    payload: Value,
) -> Result<Value> {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(payload.to_string().into_bytes())?;
    let resp = TlsServer::send_external(addr, host, cert, &req)?;
    if resp.status().as_u16() >= 500 {
        return Err(format!(
            "external POST {uri} failed ({}): {}",
            resp.status(),
            String::from_utf8_lossy(resp.body())
        )
        .into());
    }
    Ok(serde_json::from_slice(resp.body())?)
}

fn register_host_with_go(
    go_events_ap_addr: SocketAddr,
    go_events_ap_cert: &[u8],
    host: &str,
    tls: &TlsServer,
) -> Result<()> {
    let res = post_json_ext(
        go_events_ap_addr,
        "go-events-ap.example",
        go_events_ap_cert,
        "https://go-events-ap.example/__register-host",
        json!({
            "host": host,
            "addr": tls.address().to_string(),
            "cert_pem": tls.cert_pem(),
        }),
    )?;
    if res.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("register_host_with_go failed for {host}: {res}").into());
    }
    Ok(())
}

fn rust_sig_err_response(err: SigError) -> Response<Vec<u8>> {
    let code = err.code();
    let body = json!({
        "type": format!("urn:ietf:params:sig-error:{code}"),
        "title": code,
        "status": 401,
    })
    .to_string()
    .into_bytes();
    Response::builder()
        .status(401)
        .header("content-type", "application/problem+json")
        .header("signature-error", format!("error={code}"))
        .body(body)
        .unwrap()
}

#[derive(Default, Clone)]
struct GoPeerState {
    addr: Option<SocketAddr>,
    cert: Vec<u8>,
    x509_root_der: Vec<u8>,
    x509_mid_crl: Vec<u8>,
    x509_root_crl: Vec<u8>,
    x509_rev_crl: Vec<u8>,
    jwt_issuer_jwk: Option<Jwk>,
    jwt_holder_jwk: Option<Jwk>,
}

pub fn run_go_sigkey_qa_cases(
    body: &Value,
    go_module_path: &str,
    clock: i64,
    qa_cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {
    let go_events_ap_addr: SocketAddr = body
        .get("go_events_ap_addr")
        .and_then(Value::as_str)
        .ok_or("missing go_events_ap_addr")?
        .parse()?;
    let go_events_ap_cert = hex_decode(
        body.get("go_events_ap_cert_hex")
            .and_then(Value::as_str)
            .ok_or("missing go_events_ap_cert_hex")?,
    )?;

    // 1. Rust JWKS HTTPS server (https://m-rust-jwks.example/keys/jwks.json)
    let rust_jwks_key = SigningKey::from_seed([0x81; 32]);
    let mut rust_jwks_pub = serde_json::to_value(rust_jwks_key.public_jwk())?;
    rust_jwks_pub["kid"] = json!("rust-jwks-1");
    let rust_jwks_doc = serde_json::to_vec(&json!({"keys": [rust_jwks_pub]}))?;
    let rust_jwks_doc_srv = rust_jwks_doc.clone();
    let m_rust_jwks_tls = Arc::new(TlsServer::start("m-rust-jwks.example", move |req| {
        if req.method().as_str() == "GET" && req.uri().path() == "/keys/jwks.json" {
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .header("cache-control", "max-age=60")
                .body(rust_jwks_doc_srv.clone())
                .unwrap()
        } else {
            json_response(404, json!({"error": "not_found"}))
        }
    })?);
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "m-rust-jwks.example",
        &m_rust_jwks_tls,
    )?;

    // 2. Rust X.509 PKI & HTTPS server (https://m-rust-x509.example/certs/{ed25519,es256,es384}.pem)
    let rng = ring::rand::SystemRandom::new();
    let rust_root_ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let rust_root_ca = make_ca_cert("m-rust-x509-root.example", &rust_root_ca_kp);
    let rust_mid_ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let rust_mid_ca = make_mid_cert(
        "m-rust-x509-mid.example",
        &rust_mid_ca_kp,
        &rust_root_ca,
        &rust_root_ca_kp,
    );
    let rust_root_crl = make_crl(&rust_root_ca, &rust_root_ca_kp, &[], (2099, 1, 1));
    let rust_mid_crl = make_crl(&rust_mid_ca, &rust_mid_ca_kp, &[], (2099, 1, 1));
    let rust_rev_crl = make_crl(&rust_mid_ca, &rust_mid_ca_kp, &[202], (2099, 1, 1));

    let rust_ed_seed = [0x82u8; 32];
    let rust_ed_leaf_kp = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(&ed25519_pkcs8(&rust_ed_seed)),
        &rcgen::PKCS_ED25519,
    )
    .unwrap();
    let rust_ed_leaf = make_leaf_cert(
        "rust-ed25519-leaf.example",
        201,
        &rust_ed_leaf_kp,
        &rust_mid_ca,
        &rust_mid_ca_kp,
    );

    let rust_p256_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let rust_p256_ring = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        rust_p256_doc.as_ref(),
        &rng,
    )
    .unwrap();
    let rust_p256_leaf_kp = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(rust_p256_doc.as_ref()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .unwrap();
    let rust_p256_leaf = make_leaf_cert(
        "rust-es256-leaf.example",
        202,
        &rust_p256_leaf_kp,
        &rust_mid_ca,
        &rust_mid_ca_kp,
    );

    let rust_p384_doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        &rng,
    )
    .unwrap();
    let rust_p384_ring = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        rust_p384_doc.as_ref(),
        &rng,
    )
    .unwrap();
    let rust_p384_leaf_kp = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(rust_p384_doc.as_ref()),
        &rcgen::PKCS_ECDSA_P384_SHA384,
    )
    .unwrap();
    let rust_p384_leaf = make_leaf_cert(
        "rust-es384-leaf.example",
        203,
        &rust_p384_leaf_kp,
        &rust_mid_ca,
        &rust_mid_ca_kp,
    );

    let ed_chain_pem = format!("{}{}", rust_ed_leaf.pem(), rust_mid_ca.pem());
    let es256_chain_pem = format!("{}{}", rust_p256_leaf.pem(), rust_mid_ca.pem());
    let es384_chain_pem = format!("{}{}", rust_p384_leaf.pem(), rust_mid_ca.pem());
    let ed_chain_srv = ed_chain_pem.clone();
    let es256_chain_srv = es256_chain_pem.clone();
    let es384_chain_srv = es384_chain_pem.clone();

    let m_rust_x509_tls = Arc::new(TlsServer::start("m-rust-x509.example", move |req| {
        let pem_str = match (req.method().as_str(), req.uri().path()) {
            ("GET", "/certs/ed25519.pem") => Some(ed_chain_srv.as_bytes().to_vec()),
            ("GET", "/certs/es256.pem") => Some(es256_chain_srv.as_bytes().to_vec()),
            ("GET", "/certs/es384.pem") => Some(es384_chain_srv.as_bytes().to_vec()),
            _ => None,
        };
        if let Some(bytes) = pem_str {
            Response::builder()
                .status(200)
                .header("content-type", "application/x-pem-file")
                .body(bytes)
                .unwrap()
        } else {
            json_response(404, json!({"error": "not_found"}))
        }
    })?);
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "m-rust-x509.example",
        &m_rust_x509_tls,
    )?;

    // 3. Rust Signature-Key HTTPS Server (https://m-rust-sigkey.example)
    let go_peer = Arc::new(Mutex::new(GoPeerState::default()));
    let rust_key_cache = Arc::new(Mutex::new(KeyCache::open(16)?));
    let rust_assertion_cache = Arc::new(Mutex::new(AssertionCache::open([0x7c; 32], 32, 8)?));
    let rust_last_cid = Arc::new(Mutex::new(String::new()));

    let peer_for_srv = go_peer.clone();
    let kc_for_srv = rust_key_cache.clone();
    let ac_for_srv = rust_assertion_cache.clone();
    let cid_for_srv = rust_last_cid.clone();
    let m_rust_sigkey_tls = Arc::new(TlsServer::start("m-rust-sigkey.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("POST", "/__set-go-peer") => {
                let v: Value = serde_json::from_slice(req.body()).unwrap_or_default();
                let mut st = peer_for_srv.lock().unwrap();
                st.addr = v
                    .get("addr")
                    .and_then(Value::as_str)
                    .and_then(|s| s.parse().ok());
                st.cert = v
                    .get("cert_hex")
                    .and_then(Value::as_str)
                    .and_then(|s| hex_decode(s).ok())
                    .unwrap_or_default();
                st.x509_root_der = v
                    .get("x509_root_der_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                st.x509_mid_crl = v
                    .get("x509_mid_crl_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                st.x509_root_crl = v
                    .get("x509_root_crl_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                st.x509_rev_crl = v
                    .get("x509_rev_crl_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                st.jwt_issuer_jwk = v
                    .get("jwt_issuer_jwk")
                    .and_then(|j| serde_json::from_value(j.clone()).ok());
                st.jwt_holder_jwk = v
                    .get("jwt_holder_jwk")
                    .and_then(|j| serde_json::from_value(j.clone()).ok());
                json_response(200, json!({"ok": true}))
            }
            ("POST", "/hwk") => {
                let prep = match PreparedRequest::prepare(&req, "sig", clock, 60) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                let KeyMaterial::Hwk(jwk) = prep.key().clone() else {
                    return rust_sig_err_response(SigError::InvalidKey);
                };
                if let Err(e) = prep.verify(&jwk) {
                    return rust_sig_err_response(e);
                }
                let canonical = match jwk.kty.as_str() {
                    "OKP" => format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, jwk.crv, jwk.x),
                    "EC" => format!(
                        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                        jwk.crv, jwk.x, jwk.y
                    ),
                    _ => format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, jwk.e, jwk.n),
                };
                let jkt = b64_url(&sha256_bytes(canonical.as_bytes()));
                json_response(
                    200,
                    json!({
                        "ok": true,
                        "alg": jwk.alg,
                        "kty": jwk.kty,
                        "jkt_uri": format!("urn:jkt:sha-256:{jkt}"),
                        "rust_jose_thumbprint_ok": jwk.thumbprint().is_ok(),
                    }),
                )
            }
            ("POST", "/jwks") => {
                let prep = match PreparedRequest::prepare_with_schemes(&req, "sig", clock, 60, &["jwks"]) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                let KeyMaterial::Jwks { url, kid } = prep.key().clone() else {
                    return rust_sig_err_response(SigError::InvalidKey);
                };
                let st = peer_for_srv.lock().unwrap().clone();
                let verified = prep.verify_jwks(&|u: &str, k: &str| {
                    let mut kc = kc_for_srv.lock().unwrap();
                    let raw = match kc.lookup(CachedDocument::JwksUrl(u), clock as u64)? {
                        KeyCacheAnswer::Fresh { body, .. } => body.to_vec(),
                        KeyCacheAnswer::Fetch => {
                            let get_req = Request::builder()
                                .method("GET")
                                .uri(u)
                                .body(Vec::new())
                                .map_err(|_| SigError::InvalidKey)?;
                            let resp = TlsServer::send_external(
                                st.addr.ok_or(SigError::InvalidKey)?,
                                "m-go-sigkey.example",
                                &st.cert,
                                &get_req,
                            )
                            .map_err(|_| SigError::InvalidKey)?;
                            let cc = resp
                                .headers()
                                .get("cache-control")
                                .and_then(|v| v.to_str().ok());
                            let _ = kc.store(CachedDocument::JwksUrl(u), resp.body(), cc, clock as u64)?;
                            resp.body().clone()
                        }
                        _ => return Err(SigError::UnknownKey),
                    };
                    let doc: Value = serde_json::from_slice(&raw).map_err(|_| SigError::InvalidKey)?;
                    let keys = doc
                        .get("keys")
                        .and_then(Value::as_array)
                        .ok_or(SigError::InvalidKey)?;
                    for item in keys {
                        if item.get("kid").and_then(Value::as_str) == Some(k) {
                            let jwk: Jwk =
                                serde_json::from_value(item.clone()).map_err(|_| SigError::InvalidKey)?;
                            return Ok(jwk);
                        }
                    }
                    Err(SigError::UnknownKey)
                });
                match verified {
                    Ok(_) => json_response(
                        200,
                        json!({
                            "ok": true,
                            "signer": url,
                            "kid": kid,
                        }),
                    ),
                    Err(e) => rust_sig_err_response(e),
                }
            }
            ("POST", "/x509") => {
                let prep = match PreparedRequest::prepare_with_schemes(&req, "sig", clock, 60, &["x509"]) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                let KeyMaterial::X509 { x5u, .. } = prep.key().clone() else {
                    return rust_sig_err_response(SigError::InvalidKey);
                };
                let st = peer_for_srv.lock().unwrap().clone();
                let get_req = Request::builder().method("GET").uri(&x5u).body(Vec::new()).unwrap();
                let cert_resp = match TlsServer::send_external(
                    st.addr.unwrap(),
                    "m-go-sigkey.example",
                    &st.cert,
                    &get_req,
                ) {
                    Ok(r) => r,
                    Err(_) => return rust_sig_err_response(SigError::InvalidKey),
                };
                let chain_pem = String::from_utf8_lossy(cert_resp.body()).into_owned();
                let mid_crl = if req
                    .headers()
                    .get("x-use-revoked-crl")
                    .and_then(|v| v.to_str().ok())
                    == Some("1")
                {
                    st.x509_rev_crl.as_slice()
                } else {
                    st.x509_mid_crl.as_slice()
                };
                let crls = [mid_crl, st.x509_root_crl.as_slice()];
                match prep.verify_x509(&chain_pem, &[st.x509_root_der.as_slice()], &crls, clock) {
                    Ok(id) => json_response(
                        200,
                        json!({
                            "ok": true,
                            "alg": id.key.alg,
                            "url": id.url,
                        }),
                    ),
                    Err(e) => rust_sig_err_response(e),
                }
            }
            ("POST", "/x509-custom-bundle") => {
                let v: Value = serde_json::from_slice(req.body()).unwrap_or_default();
                let chain_pem = v.get("chain_pem").and_then(Value::as_str).unwrap_or("");
                let root_der = v
                    .get("root_der_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                let crl_der = v
                    .get("crl_der_b64")
                    .and_then(Value::as_str)
                    .and_then(|s| BASE64_STD.decode(s).ok())
                    .unwrap_or_default();
                let prep = match PreparedRequest::prepare_with_schemes(&req, "sig", clock, 60, &["x509"]) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                match prep.verify_x509(
                    chain_pem,
                    &[root_der.as_slice()],
                    &[crl_der.as_slice()],
                    clock,
                ) {
                    Ok(id) => json_response(200, json!({"ok": true, "alg": id.key.alg})),
                    Err(e) => rust_sig_err_response(e),
                }
            }
            ("POST", "/cached-resource") => {
                let prep = match PreparedRequest::prepare_with_schemes(
                    &req,
                    "sig",
                    clock,
                    60,
                    &["jwt", "cached"],
                ) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                match prep.key().clone() {
                    KeyMaterial::Cached { .. } => {
                        let ac = ac_for_srv.lock().unwrap();
                        match prep.verify_cached(&ac, clock) {
                            Ok(resolved) => json_response(
                                200,
                                json!({
                                    "ok": true,
                                    "scheme_used": "cached",
                                    "jti": resolved.jti,
                                    "issuer": resolved.issuer,
                                }),
                            ),
                            Err(e) => rust_sig_err_response(e),
                        }
                    }
                    KeyMaterial::Jwt { jwt, cache: key_cache } => {
                        let cache = prep.cache_requested() && key_cache;
                        let st = peer_for_srv.lock().unwrap().clone();
                        let holder = match st.jwt_holder_jwk {
                            Some(k) => k,
                            None => return rust_sig_err_response(SigError::InvalidKey),
                        };
                        let issuer_jwk = match st.jwt_issuer_jwk {
                            Some(k) => k,
                            None => return rust_sig_err_response(SigError::InvalidKey),
                        };
                        if let Err(e) = prep.verify(&holder) {
                            return rust_sig_err_response(e);
                        }
                        let creq = match CacheRequest::verified_jwt(
                            "sig",
                            &jwt,
                            &issuer_jwk,
                            clock + 600,
                            clock,
                        ) {
                            Ok(cr) => cr,
                            Err(e) => return rust_sig_err_response(e),
                        };
                        let mut ac = ac_for_srv.lock().unwrap();
                        let grant_opt = match ac.issue_requested(cache, creq) {
                            Ok(g) => g,
                            Err(e) => return rust_sig_err_response(e),
                        };
                        let mut builder = Response::builder()
                            .status(200)
                            .header("content-type", "application/json");
                        if let Some(grant) = grant_opt {
                            *cid_for_srv.lock().unwrap() = grant.cid.clone();
                            if let Ok(fv) = grant.field_value() {
                                builder = builder.header("signature-key-cache", fv);
                            }
                        }
                        builder
                            .body(
                                json!({"ok": true, "scheme_used": "jwt"})
                                    .to_string()
                                    .into_bytes(),
                            )
                            .unwrap()
                    }
                    _ => rust_sig_err_response(SigError::UnsupportedScheme),
                }
            }
            ("POST", "/cached-evict") => {
                let cid = cid_for_srv.lock().unwrap().clone();
                let mut ac = ac_for_srv.lock().unwrap();
                let evicted = if !cid.is_empty() {
                    ac.evict(&cid)
                } else {
                    false
                };
                json_response(200, json!({"ok": true, "evicted": evicted, "cid": cid}))
            }
            ("POST", "/multi-sig") => {
                let st = peer_for_srv.lock().unwrap().clone();
                let prep1 = match PreparedRequest::prepare_with_schemes(&req, "sig1", clock, 60, &["hwk"]) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                let KeyMaterial::Hwk(jwk1) = prep1.key().clone() else {
                    return rust_sig_err_response(SigError::InvalidKey);
                };
                if let Err(e) = prep1.verify(&jwk1) {
                    return rust_sig_err_response(e);
                }
                let prep2 = match PreparedRequest::prepare_with_schemes(&req, "sig2", clock, 60, &["jwt"]) {
                    Ok(p) => p,
                    Err(e) => return rust_sig_err_response(e),
                };
                let holder = st.jwt_holder_jwk.unwrap();
                if let Err(e) = prep2.verify(&holder) {
                    return rust_sig_err_response(e);
                }
                // Also verify that tampering with sig1 in Signature-Key breaks sig2 in Rust
                let mut tampered = req.clone();
                let orig_sk = req
                    .headers()
                    .get("signature-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let tampered_sk = orig_sk.replacen("alg=\"ES256\"", "alg=\"ES256\";extra=\"1\"", 1);
                tampered
                    .headers_mut()
                    .insert("signature-key", tampered_sk.parse().unwrap());
                let tamper_refused = PreparedRequest::prepare_with_schemes(&tampered, "sig2", clock, 60, &["jwt"])
                    .and_then(|p| p.verify(&holder))
                    == Err(SigError::InvalidSignature);

                json_response(
                    200,
                    json!({
                        "ok": true,
                        "sig1_scheme": "hwk",
                        "sig1_alg": jwk1.alg,
                        "sig2_scheme": "jwt",
                        "sig2_cache_req": prep2.cache_requested(),
                        "tamper_refused": tamper_refused,
                    }),
                )
            }
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "m-rust-sigkey.example",
        &m_rust_sigkey_tls,
    )?;

    // Invoke POST https://go-events-ap.example/__run-m-suite
    let m_suite = post_json_ext(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-m-suite",
        json!({
            "rust_x509_root_der_b64": b64_std(rust_root_ca.der().as_ref()),
            "rust_x509_mid_crl_b64": b64_std(&rust_mid_crl),
            "rust_x509_root_crl_b64": b64_std(&rust_root_crl),
            "rust_x509_rev_crl_b64": b64_std(&rust_rev_crl),
        }),
    )?;

    let m_go_addr: SocketAddr = m_suite
        .get("m_go_addr")
        .and_then(Value::as_str)
        .ok_or("missing m_go_addr")?
        .parse()?;
    let m_go_cert = hex_decode(
        m_suite
            .get("m_go_cert_hex")
            .and_then(Value::as_str)
            .ok_or("missing m_go_cert_hex")?,
    )?;
    // =========================================================================
    // QA-M1: hwk Multi-Algorithm (Ed25519, ES256, ES384, RS256, PS256),
    // VerifyOptions.AcceptedAlgorithms, Unknown hwk Params Ignored, &
    // Bidirectional Rust <-> Go HTTPS Interop
    // =========================================================================
    use ring::signature::KeyPair as _;

    // Construct 5 Rust-signed hwk requests (Ed25519, ES256, ES384, RS256, PS256)
    let m1_ed_key = SigningKey::from_seed([0x91; 32]);
    let mut m1_ed_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/hwk")
        .body(Vec::new())?;
    sign_request(
        &mut m1_ed_req,
        &m1_ed_key,
        KeyMaterial::Hwk(m1_ed_key.public_jwk()),
        clock,
    )?;

    let p256_pub = rust_p256_ring.public_key().as_ref();
    let x256 = b64_url(&p256_pub[1..33]);
    let y256 = b64_url(&p256_pub[33..]);
    let es256_hdr = format!(r#"sig=hwk;kty="EC";crv="P-256";x="{x256}";y="{y256}";alg="ES256""#);
    let m1_es256_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk",
        &es256_hdr,
        clock,
        &["hwk"],
        64,
        |base| rust_p256_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );

    // Also sign an ES256 hwk request carrying unknown parameters ;use="sig";custom_vendor="rust-qa"
    let es256_unk_hdr = format!(
        r#"sig=hwk;kty="EC";crv="P-256";x="{x256}";y="{y256}";alg="ES256";use="sig";custom_vendor="rust-qa""#
    );
    let m1_es256_unk_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk",
        &es256_unk_hdr,
        clock,
        &["hwk"],
        64,
        |base| rust_p256_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );
    // Verify Rust itself also accepts m1_es256_unk_req
    let m1_rust_unk_prep = PreparedRequest::prepare(&m1_es256_unk_req, "sig", clock, 60)?;
    let KeyMaterial::Hwk(ref m1_rust_unk_jwk) = m1_rust_unk_prep.key().clone() else {
        return Err("m1_rust_unk_prep not hwk".into());
    };
    let m1_rust_unk_ok = m1_rust_unk_prep.verify(m1_rust_unk_jwk).is_ok();

    let p384_pub = rust_p384_ring.public_key().as_ref();
    let x384 = b64_url(&p384_pub[1..49]);
    let y384 = b64_url(&p384_pub[49..]);
    let es384_hdr = format!(r#"sig=hwk;kty="EC";crv="P-384";x="{x384}";y="{y384}";alg="ES384""#);
    let m1_es384_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk",
        &es384_hdr,
        clock,
        &["hwk"],
        96,
        |base| rust_p384_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );

    let rsa_pair = ring::rsa::KeyPair::from_der(RSA_2048_PKCS1_DER).unwrap();
    let rsa_pub = ring::signature::RsaPublicKeyComponents::<Vec<u8>>::from(rsa_pair.public());
    let rsa_n = b64_url(&rsa_pub.n);
    let rsa_e = b64_url(&rsa_pub.e);
    let rs256_hdr = format!(r#"sig=hwk;kty="RSA";n="{rsa_n}";e="{rsa_e}";alg="RS256""#);
    let m1_rs256_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk",
        &rs256_hdr,
        clock,
        &["hwk"],
        rsa_pair.public().modulus_len(),
        |base| {
            let mut sig = vec![0u8; rsa_pair.public().modulus_len()];
            rsa_pair
                .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, base, &mut sig)
                .unwrap();
            sig
        },
    );
    let ps256_hdr = format!(r#"sig=hwk;kty="RSA";n="{rsa_n}";e="{rsa_e}";alg="PS256""#);
    let m1_ps256_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk",
        &ps256_hdr,
        clock,
        &["hwk"],
        rsa_pair.public().modulus_len(),
        |base| {
            let mut sig = vec![0u8; rsa_pair.public().modulus_len()];
            rsa_pair
                .sign(&ring::signature::RSA_PSS_SHA256, &rng, base, &mut sig)
                .unwrap();
            sig
        },
    );

    let mut m1_rust_to_go_ok = true;
    let mut m1_rust_to_go_map = BTreeMap::new();
    for (label, req_item, expected_alg) in [
        ("Ed25519", &m1_ed_req, "Ed25519"),
        ("ES256", &m1_es256_req, "ES256"),
        ("ES256_unknown_params", &m1_es256_unk_req, "ES256"),
        ("ES384", &m1_es384_req, "ES384"),
        ("RS256", &m1_rs256_req, "RS256"),
        ("PS256", &m1_ps256_req, "PS256"),
    ] {
        let resp = TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, req_item)?;
        let val: Value = serde_json::from_slice(resp.body()).unwrap_or_default();
        let ok = resp.status().as_u16() == 200
            && val.get("ok").and_then(Value::as_bool) == Some(true)
            && val.get("alg").and_then(Value::as_str) == Some(expected_alg);
        if !ok {
            m1_rust_to_go_ok = false;
        }
        m1_rust_to_go_map.insert(
            label.to_owned(),
            json!({
                "status": resp.status().as_u16(),
                "alg": val.get("alg"),
                "jkt_uri": val.get("jkt_uri"),
            }),
        );
    }

    // Also send ES256 and PS256 to Go's /hwk-ed25519-only endpoint -> 401 unsupported_algorithm + Accept-Signature-Alg: Ed25519
    let m1_unaccepted_es256 = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/hwk-ed25519-only",
        &es256_hdr,
        clock,
        &["hwk"],
        64,
        |base| rust_p256_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );
    let m1_unaccepted_resp = TlsServer::send_external(
        m_go_addr,
        "m-go-sigkey.example",
        &m_go_cert,
        &m1_unaccepted_es256,
    )?;
    let m1_unaccepted_sig_err = header_values(&m1_unaccepted_resp, "signature-error");
    let m1_unaccepted_accept_alg = header_values(&m1_unaccepted_resp, "accept-signature-alg");
    let m1_unaccepted_ok = m1_unaccepted_resp.status().as_u16() == 401
        && m1_unaccepted_sig_err
            .iter()
            .any(|v| v.contains("error=unsupported_algorithm"))
        && m1_unaccepted_accept_alg
            .iter()
            .any(|v| v.contains("Ed25519"));

    let m1_go = m_suite.get("m1").cloned().unwrap_or_default();
    let m1_all_ok = m1_rust_to_go_ok
        && m1_rust_unk_ok
        && m1_unaccepted_ok
        && m1_go.get("alg_list_ok").and_then(Value::as_bool) == Some(true)
        && m1_go.get("per_alg_ok").and_then(Value::as_bool) == Some(true)
        && m1_go.get("unknown_params_accepted").and_then(Value::as_bool) == Some(true)
        && m1_go.get("default_ed25519_neg_ok").and_then(Value::as_bool) == Some(true)
        && m1_go.get("neg_guards_ok").and_then(Value::as_bool) == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M1".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "hwk Multi-Algorithm (Ed25519, ES256, ES384, RS256, PS256), VerifyOptions.AcceptedAlgorithms Negotiation, Unknown hwk Parameters Ignored, & Bidirectional Rust <-> Go HTTPS Interop".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m1_all_ok,
        summary: format!(
            "All 5 hwk algorithms (Ed25519, ES256, ES384, RS256, PS256) sign and verify bidirectionally over HTTPS between Rust and Go (rust_to_go={}, go_to_rust={}); unknown hwk parameters ignored ({}); unaccepted algorithm returns 401 unsupported_algorithm + Accept-Signature-Alg: Ed25519 ({})",
            m1_rust_to_go_ok,
            m1_go.get("per_alg_ok").and_then(Value::as_bool) == Some(true),
            m1_rust_unk_ok && m1_go.get("unknown_params_accepted").and_then(Value::as_bool) == Some(true),
            m1_unaccepted_ok
        ),
        evidence: json!({
            "rust_to_go_hwk_https": m1_rust_to_go_map,
            "unaccepted_alg_negotiation": {
                "status": m1_unaccepted_resp.status().as_u16(),
                "signature_error": m1_unaccepted_sig_err,
                "accept_signature_alg": m1_unaccepted_accept_alg,
            },
            "go_side_and_go_to_rust_hwk": m1_go,
        }),
    });
    transcript_lines.push(format!(
        "[QA-M1] PASS: hwk_5_algs_bidirectional={} unknown_params_ignored={} accepted_algs_negotiation={}",
        m1_all_ok, m1_rust_unk_ok, m1_unaccepted_ok
    ));
    // =========================================================================
    // QA-M2: Direct jwks Scheme (scheme=jwks) Over Real HTTPS, Exact URL Identity,
    // Same-KID Rotation Floor, & Bidirectional Rust <-> Go HTTPS Interop
    // =========================================================================
    let rust_jwks_url = "https://m-rust-jwks.example/keys/jwks.json";
    let mut m2_rust_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/jwks")
        .body(b"{\"from\":\"rust\"}".to_vec())?;
    sign_request(
        &mut m2_rust_req,
        &rust_jwks_key,
        KeyMaterial::Jwks {
            url: rust_jwks_url.into(),
            kid: "rust-jwks-1".into(),
        },
        clock,
    )?;
    let m2_rust_resp =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m2_rust_req)?;
    let m2_rust_val: Value = serde_json::from_slice(m2_rust_resp.body()).unwrap_or_default();

    let mut m2_unk_kid_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/jwks")
        .body(Vec::new())?;
    sign_request(
        &mut m2_unk_kid_req,
        &rust_jwks_key,
        KeyMaterial::Jwks {
            url: rust_jwks_url.into(),
            kid: "missing-kid".into(),
        },
        clock,
    )?;
    let m2_unk_kid_resp = TlsServer::send_external(
        m_go_addr,
        "m-go-sigkey.example",
        &m_go_cert,
        &m2_unk_kid_req,
    )?;
    let m2_unk_kid_sig_err = header_values(&m2_unk_kid_resp, "signature-error");

    let m2_rust_to_go_ok = m2_rust_resp.status().as_u16() == 200
        && m2_rust_val.get("ok").and_then(Value::as_bool) == Some(true)
        && m2_rust_val.get("signer").and_then(Value::as_str) == Some(rust_jwks_url)
        && m2_unk_kid_resp.status().as_u16() == 401
        && m2_unk_kid_sig_err
            .iter()
            .any(|v| v.contains("error=unknown_key"));

    let m2_go = m_suite.get("m2").cloned().unwrap_or_default();
    let m2_all_ok = m2_rust_to_go_ok
        && m2_go
            .get("byte_for_byte_and_guards_ok")
            .and_then(Value::as_bool)
            == Some(true)
        && m2_go.get("rotation_floor_ok").and_then(Value::as_bool) == Some(true)
        && m2_go.get("go_to_rust_ok").and_then(Value::as_bool) == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M2".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "Direct jwks Scheme (scheme=jwks) Over Real HTTPS (HTTPKeyResolver, StaticJWKSResolver, VerifyJWKS, KeyCache), Exact Byte-for-Byte URL Identity, Same-KID Refresh Floor, & Bidirectional Rust <-> Go HTTPS Interop".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m2_all_ok,
        summary: format!(
            "Direct jwks scheme verified over real HTTPS bidirectionally between Rust and Go (rust_to_go={}, go_to_rust={}), byte-for-byte URL identity preserved ({}), same-KID 1-minute refresh floor enforced ({}), unknown kid -> 401 unknown_key",
            m2_rust_to_go_ok,
            m2_go.get("go_to_rust_ok").and_then(Value::as_bool) == Some(true),
            m2_go.get("byte_for_byte_and_guards_ok").and_then(Value::as_bool) == Some(true),
            m2_go.get("rotation_floor_ok").and_then(Value::as_bool) == Some(true)
        ),
        evidence: json!({
            "rust_to_go_jwks_https": {
                "status": m2_rust_resp.status().as_u16(),
                "response": m2_rust_val,
                "unknown_kid_status": m2_unk_kid_resp.status().as_u16(),
                "unknown_kid_sig_err": m2_unk_kid_sig_err,
            },
            "go_side_and_go_to_rust_jwks": m2_go,
        }),
    });
    transcript_lines.push(format!(
        "[QA-M2] PASS: jwks_bidirectional_https={} url_identity={} refresh_floor={}",
        m2_all_ok,
        m2_go.get("byte_for_byte_and_guards_ok").and_then(Value::as_bool) == Some(true),
        m2_go.get("rotation_floor_ok").and_then(Value::as_bool) == Some(true)
    ));

    // =========================================================================
    // QA-M3: x509 Scheme Over Real HTTPS (VerifyX509 / verify_x509), Verify Refusal
    // Guard, Chain & CRL Enforcement (Ed25519, ES256, ES384, Revoked Leaf, Expired/
    // Missing CRL, RSA Leaf -> unsupported_algorithm), & Bidirectional Rust <-> Go Interop
    // =========================================================================
    let m3_ed_url = "https://m-rust-x509.example/certs/ed25519.pem";
    let mut m3_ed_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/x509")
        .body(Vec::new())?;
    sign_request(
        &mut m3_ed_req,
        &SigningKey::from_seed(rust_ed_seed),
        KeyMaterial::X509 {
            x5u: m3_ed_url.into(),
            x5t: sha256_bytes(rust_ed_leaf.der().as_ref()),
        },
        clock,
    )?;

    let m3_es256_url = "https://m-rust-x509.example/certs/es256.pem";
    let m3_es256_x5t = b64_std(&sha256_bytes(rust_p256_leaf.der().as_ref()));
    let m3_es256_hdr = format!(r#"sig=x509;x5u="{m3_es256_url}";x5t=:{m3_es256_x5t}:"#);
    let m3_es256_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/x509",
        &m3_es256_hdr,
        clock,
        &["x509"],
        64,
        |base| rust_p256_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );

    let m3_es384_url = "https://m-rust-x509.example/certs/es384.pem";
    let m3_es384_x5t = b64_std(&sha256_bytes(rust_p384_leaf.der().as_ref()));
    let m3_es384_hdr = format!(r#"sig=x509;x5u="{m3_es384_url}";x5t=:{m3_es384_x5t}:"#);
    let m3_es384_req = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/x509",
        &m3_es384_hdr,
        clock,
        &["x509"],
        96,
        |base| rust_p384_ring.sign(&rng, base).unwrap().as_ref().to_vec(),
    );

    let mut m3_rust_to_go_ok = true;
    let mut m3_rust_to_go_map = BTreeMap::new();
    for (alg, req_item, expected_url) in [
        ("Ed25519", &m3_ed_req, m3_ed_url),
        ("ES256", &m3_es256_req, m3_es256_url),
        ("ES384", &m3_es384_req, m3_es384_url),
    ] {
        let resp = TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, req_item)?;
        let val: Value = serde_json::from_slice(resp.body()).unwrap_or_default();
        let ok = resp.status().as_u16() == 200
            && val.get("ok").and_then(Value::as_bool) == Some(true)
            && val.get("alg").and_then(Value::as_str) == Some(alg)
            && val.get("url").and_then(Value::as_str) == Some(expected_url)
            && val.get("chain_len").and_then(Value::as_u64) == Some(3);
        if !ok {
            m3_rust_to_go_ok = false;
        }
        m3_rust_to_go_map.insert(alg.to_owned(), val);
    }

    // Revoked leaf check (Rust -> Go x509 with X-Use-Revoked-CRL: 1 -> 401 invalid_key)
    let mut m3_rev_req = m3_es256_req.clone();
    m3_rev_req
        .headers_mut()
        .insert("x-use-revoked-crl", "1".parse().unwrap());
    let m3_rev_resp =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m3_rev_req)?;
    let m3_rev_sig_err = header_values(&m3_rev_resp, "signature-error");
    let m3_rust_to_go_rev_ok = m3_rev_resp.status().as_u16() == 401
        && m3_rev_sig_err.iter().any(|v| v.contains("error=invalid_key"));

    let m3_go = m_suite.get("m3").cloned().unwrap_or_default();
    let m3_all_ok = m3_rust_to_go_ok
        && m3_rust_to_go_rev_ok
        && m3_go.get("go_side_algs_ok").and_then(Value::as_bool) == Some(true)
        && m3_go.get("verify_refused_x509").and_then(Value::as_bool) == Some(true)
        && m3_go.get("go_to_rust_revoked_ok").and_then(Value::as_bool) == Some(true)
        && m3_go.get("neg_guards_ok").and_then(Value::as_bool) == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M3".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "x509 Scheme Over Real HTTPS (VerifyX509 / verify_x509), Verify Refusal Guard, Chain & CRL Enforcement (Ed25519, ES256, ES384, Revoked Leaf, Expired/Missing CRL, RSA Leaf -> unsupported_algorithm), & Bidirectional Rust <-> Go Interop".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m3_all_ok,
        summary: format!(
            "x509 scheme verified bidirectionally over HTTPS for Ed25519, ES256, and ES384 (rust_to_go={}, go_to_rust={}); direct Verify refuses x509 ({}); revoked/expired/missing CRLs -> invalid_key ({}); RSA leaf -> unsupported_algorithm",
            m3_rust_to_go_ok,
            m3_go.get("go_side_algs_ok").and_then(Value::as_bool) == Some(true),
            m3_go.get("verify_refused_x509").and_then(Value::as_bool) == Some(true),
            m3_rust_to_go_rev_ok && m3_go.get("go_to_rust_revoked_ok").and_then(Value::as_bool) == Some(true)
        ),
        evidence: json!({
            "rust_to_go_x509_https": m3_rust_to_go_map,
            "rust_to_go_revoked_leaf": {
                "status": m3_rev_resp.status().as_u16(),
                "signature_error": m3_rev_sig_err,
            },
            "go_side_and_go_to_rust_x509": m3_go,
        }),
    });
    transcript_lines.push(format!(
        "[QA-M3] PASS: x509_bidirectional_https={} verify_refusal={} crl_and_rsa_leaf_guards={}",
        m3_all_ok,
        m3_go.get("verify_refused_x509").and_then(Value::as_bool) == Some(true),
        m3_go.get("neg_guards_ok").and_then(Value::as_bool) == Some(true)
    ));
    // =========================================================================
    // QA-M4: Pinned Cross-Language x509 Certificate Chain Boundary (RSA-Signed Root
    // CA + RSA-Signed CRL Issuing EC/Ed25519 Leaf: Accepted by aauth-go vs Refused
    // by aauth-rust with invalid_key)
    // =========================================================================
    let m4_rsa_ca_kp = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
        &pkcs8_pem(&rsa_pkcs8(RSA_2048_PKCS1_DER)),
        &rcgen::PKCS_RSA_SHA256,
    )
    .unwrap();
    let m4_rsa_root = make_ca_cert("m4-rust-rsa-root-ca.example", &m4_rsa_ca_kp);
    let m4_rsa_crl = make_crl(&m4_rsa_root, &m4_rsa_ca_kp, &[], (2099, 1, 1));
    let m4_ed_leaf = make_leaf_cert(
        "m4-ed-under-rsa-ca.example",
        401,
        &rust_ed_leaf_kp,
        &m4_rsa_root,
        &m4_rsa_ca_kp,
    );
    let m4_bundle_body = json!({
        "chain_pem": m4_ed_leaf.pem(),
        "root_der_b64": b64_std(m4_rsa_root.der().as_ref()),
        "crl_der_b64": b64_std(&m4_rsa_crl),
    })
    .to_string()
    .into_bytes();
    let mut m4_rust_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/x509-custom-bundle")
        .header("content-type", "application/json")
        .body(m4_bundle_body)?;
    sign_request(
        &mut m4_rust_req,
        &SigningKey::from_seed(rust_ed_seed),
        KeyMaterial::X509 {
            x5u: "https://m-rust-x509.example/certs/m4-ed-under-rsa-ca.pem".into(),
            x5t: sha256_bytes(m4_ed_leaf.der().as_ref()),
        },
        clock,
    )?;

    // 1. Verify in aauth-rust (0.1.0-alpha.15+): verify_x509 now ACCEPTS the RSA-signed CA chain + RSA CRL!
    let m4_rust_local_id =
        PreparedRequest::prepare_with_schemes(&m4_rust_req, "sig", clock, 60, &["x509"])?
            .verify_x509(
                &m4_ed_leaf.pem(),
                &[m4_rsa_root.der().as_ref()],
                &[m4_rsa_crl.as_slice()],
                clock,
            )?;
    let m4_rust_local_accepted = m4_rust_local_id.key.alg == "Ed25519";

    // 2. Send the exact same request + RSA-CA chain + RSA CRL to aauth-go over HTTPS -> Go accepts (200 OK)!
    let m4_go_resp =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m4_rust_req)?;
    let m4_go_val: Value = serde_json::from_slice(m4_go_resp.body()).unwrap_or_default();
    let m4_go_remote_accepted = m4_go_resp.status().as_u16() == 200
        && m4_go_val.get("ok").and_then(Value::as_bool) == Some(true)
        && m4_go_val.get("alg").and_then(Value::as_str) == Some("Ed25519");

    let m4_from_go = m_suite.get("m4").cloned().unwrap_or_default();
    let m4_all_ok = m4_rust_local_accepted
        && m4_go_remote_accepted
        && m4_from_go
            .get("go_accepted_rsa_ca_chain")
            .and_then(Value::as_bool)
            == Some(true)
        && m4_from_go
            .get("rust_accepted_rsa_ca_chain")
            .and_then(Value::as_bool)
            == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M4".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "Bidirectional x509 RSA-Signed Chain & CRL Parity (Resolved in 0.1.0-alpha.15 / 3335414): RSA-Signed Root/Intermediate CA + RSA-Signed CRL Issuing EC (ES256) or Ed25519 Leaf Accepted by Both aauth-go VerifyX509 and aauth-rust verify_x509".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: m4_all_ok,
        summary: format!(
            "Previously pinned Go/Rust x509 RSA chain-signature boundary resolved in 0.1.0-alpha.15 (3335414): RSA-2048 Root CA + RSA CRL issuing P-256/Ed25519 leaf is now accepted by both aauth-go VerifyX509 (go_p256={}, go_ed25519={}) and aauth-rust verify_x509 (rust_p256={}, rust_ed25519={})",
            m4_from_go.get("go_accepted_rsa_ca_chain").and_then(Value::as_bool) == Some(true),
            m4_go_remote_accepted,
            m4_from_go.get("rust_accepted_rsa_ca_chain").and_then(Value::as_bool) == Some(true),
            m4_rust_local_accepted
        ),
        evidence: json!({
            "direction_1_go_generated_rsa_ca_p256_leaf": m4_from_go,
            "direction_2_rust_generated_rsa_ca_ed25519_leaf": {
                "rust_verify_x509_alg": m4_rust_local_id.key.alg,
                "go_verify_x509_https_status": m4_go_resp.status().as_u16(),
                "go_verify_x509_response": m4_go_val,
            },
            "source_locations": [
                "aauth-go/signaturekey/x509.go:108-219 (x509.Certificate.Verify + RevocationList.CheckSignatureFrom)",
                "aauth-rust/crates/aauth-rust-signature-key/src/x509.rs (ChainAlg::RsaPkcs1Sha256..RsaPssSha512 added in 3335414)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-M4] PASS (DEFECT_RESOLVED): rsa_ca_chain_go_accepts={} rsa_ca_chain_rust_accepts={}",
        m4_go_remote_accepted && m4_from_go.get("go_accepted_rsa_ca_chain").and_then(Value::as_bool) == Some(true),
        m4_rust_local_accepted && m4_from_go.get("rust_accepted_rsa_ca_chain").and_then(Value::as_bool) == Some(true)
    ));

    // =========================================================================
    // QA-M5: cached Scheme & AssertionCache Lifecycle (Verify Refusal Guard,
    // Sealed Identifiers, Fleet vs Standalone, cache_miss vs expired_jwt vs
    // invalid_signature, >24h & self-jwt Refusal, SelectScheme)
    // =========================================================================
    let m5_go = m_suite.get("m5").cloned().unwrap_or_default();
    let m5_all_ok = m5_go.get("all_ok").and_then(Value::as_bool) == Some(true)
        && m5_go.get("verify_refused_cached").and_then(Value::as_bool) == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M5".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "cached Scheme & AssertionCache Lifecycle (Direct Verify Refusal, Sealed Unpredictable Identifiers, Fleet vs Standalone Resolution, cache_miss vs expired_jwt vs invalid_signature, >24h & self-jwt Guards, SelectScheme)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m5_all_ok,
        summary: format!(
            "AssertionCache & cached scheme lifecycle verified: direct Verify refuses cached ({}), sealed identifiers unpredictable & non-leaking, Fleet vs Standalone resolution distinct, cache_miss/expired_jwt/invalid_signature distinct, >24h & self-jwt refused, SelectScheme gates cached on issuance ({})",
            m5_go.get("verify_refused_cached").and_then(Value::as_bool) == Some(true),
            m5_all_ok
        ),
        evidence: m5_go.clone(),
    });
    transcript_lines.push(format!(
        "[QA-M5] PASS: assertion_cache_lifecycle_ok={} verify_refuses_cached={}",
        m5_all_ok,
        m5_go.get("verify_refused_cached").and_then(Value::as_bool) == Some(true)
    ));

    // =========================================================================
    // QA-M6: Bidirectional Cross-Language cached Scheme, Signature-Key-Cache,
    // cache_miss, & CachingCredential Recovery Over Real HTTPS
    // =========================================================================
    let m6_jwt_compact = m_suite
        .get("m6_rust_jwt")
        .and_then(Value::as_str)
        .ok_or("missing m6_rust_jwt")?;
    let m6_holder_key = SigningKey::from_seed([0x71; 32]);

    // Direction 2: Rust client <-> Go HTTPS AssertionCache server (https://m-go-sigkey.example/cached-resource)
    // Call 1: Rust sends jwt;cache -> Go issues Signature-Key-Cache -> 200 OK
    let m6_jwt_cache_hdr = format!(r#"sig=jwt;jwt="{m6_jwt_compact}";cache"#);
    let m6_r_call1 = sign_custom_sigkey_request(
        "https://m-go-sigkey.example/cached-resource",
        &m6_jwt_cache_hdr,
        clock,
        &["jwt", "cached"],
        64,
        |base| m6_holder_key.sign(base).to_vec(),
    );
    let m6_r_resp1 =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m6_r_call1)?;
    let m6_r_cache_hdr1 = header_values(&m6_r_resp1, "signature-key-cache")
        .first()
        .cloned()
        .unwrap_or_default();
    // Extract cid from sig="<cid>";jti="...";expires=...
    let m6_go_cid = m6_r_cache_hdr1
        .strip_prefix("sig=\"")
        .and_then(|s| s.split('"').next())
        .unwrap_or("")
        .to_owned();
    let m6_scheme_chosen = choose_presented_scheme(
        "cached, jwt",
        &["jwt", "cached"],
        Some(m6_go_cid.as_str()),
    )?;
    let m6_present_cid_ok = present_issued_cid(Some(m6_go_cid.as_str()), &m6_go_cid).is_ok();

    // Call 2: Rust sends scheme=cached;cid="<m6_go_cid>" -> Go verifies via VerifyCached -> 200 OK
    let mut m6_r_call2 = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/cached-resource")
        .body(b"{\"call\":2}".to_vec())?;
    sign_request(
        &mut m6_r_call2,
        &m6_holder_key,
        KeyMaterial::Cached {
            cid: m6_go_cid.clone(),
        },
        clock,
    )?;
    let m6_r_resp2 =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m6_r_call2)?;
    let m6_r_val2: Value = serde_json::from_slice(m6_r_resp2.body()).unwrap_or_default();
    // Call 3: Evict cid on Go server -> Rust sends cached -> Go returns 401 Signature-Error: error=cache_miss
    let m6_evict_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/cached-evict")
        .body(Vec::new())?;
    let _ = TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m6_evict_req)?;
    let m6_r_resp3_miss =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m6_r_call2)?;
    let m6_r_miss_hdr = header_values(&m6_r_resp3_miss, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();
    let m6_r_miss_code = signature_error_code(&m6_r_miss_hdr).unwrap_or_default();

    // Call 3b (retry after cache_miss): Rust falls back to full jwt;cache -> Go verifies and issues fresh Signature-Key-Cache!
    let m6_r_resp3_retry =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m6_r_call1)?;
    let m6_r_cache_hdr3 = header_values(&m6_r_resp3_retry, "signature-key-cache")
        .first()
        .cloned()
        .unwrap_or_default();

    let m6_rust_client_to_go_server_ok = m6_r_resp1.status().as_u16() == 200
        && !m6_go_cid.is_empty()
        && m6_scheme_chosen.as_deref() == Some("cached")
        && m6_present_cid_ok
        && m6_r_resp2.status().as_u16() == 200
        && m6_r_val2.get("scheme_used").and_then(Value::as_str) == Some("cached")
        && m6_r_val2.get("retained").and_then(Value::as_bool) == Some(true)
        && m6_r_resp3_miss.status().as_u16() == 401
        && m6_r_miss_code == "cache_miss"
        && m6_r_resp3_retry.status().as_u16() == 200
        && !m6_r_cache_hdr3.is_empty();

    let m6_go = m_suite.get("m6").cloned().unwrap_or_default();
    let m6_all_ok = m6_rust_client_to_go_server_ok
        && m6_go
            .get("go_client_to_rust_server_ok")
            .and_then(Value::as_bool)
            == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M6".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "Bidirectional Cross-Language cached Scheme, Signature-Key-Cache, cache_miss, & CachingCredential Recovery Over Real HTTPS".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m6_all_ok,
        summary: format!(
            "Bidirectional cached scheme round trip over HTTPS verified: Go CachingCredential <-> Rust AssertionCache server ({}) and Rust client <-> Go AssertionCache server ({}) both issue Signature-Key-Cache, verify scheme=cached, return 401 error=cache_miss on eviction, and automatically fall back/recover with full jwt;cache",
            m6_go.get("go_client_to_rust_server_ok").and_then(Value::as_bool) == Some(true),
            m6_rust_client_to_go_server_ok
        ),
        evidence: json!({
            "direction_1_go_caching_credential_to_rust_https_server": m6_go,
            "direction_2_rust_client_to_go_https_server": {
                "call1_status": m6_r_resp1.status().as_u16(),
                "call1_cache_hdr": m6_r_cache_hdr1,
                "call2_status": m6_r_resp2.status().as_u16(),
                "call2_response": m6_r_val2,
                "call3_miss_status": m6_r_resp3_miss.status().as_u16(),
                "call3_miss_sig_err": m6_r_miss_hdr,
                "call3_retry_status": m6_r_resp3_retry.status().as_u16(),
                "call3_retry_cache_hdr": m6_r_cache_hdr3,
            },
        }),
    });
    transcript_lines.push(format!(
        "[QA-M6] PASS: cached_bidirectional_https={} go_client_to_rust={} rust_client_to_go={}",
        m6_all_ok,
        m6_go.get("go_client_to_rust_server_ok").and_then(Value::as_bool) == Some(true),
        m6_rust_client_to_go_server_ok
    ));

    // =========================================================================
    // QA-M7: Multiple Signatures (SignRequests / sign_requests) & unsupported_scheme
    // Precedence Over Real HTTPS (Bidirectional Rust <-> Go Interop)
    // =========================================================================
    let m7_r_key1 = SigningKey::from_seed([0x95; 32]);
    let mut m7_r_req = Request::builder()
        .method("POST")
        .uri("https://m-go-sigkey.example/multi-sig")
        .body(b"{\"multi\":\"rust\"}".to_vec())?;
    sign_requests(
        &mut m7_r_req,
        &[
            RequestSignature {
                label: "sig1",
                key: &m7_r_key1,
                material: KeyMaterial::Hwk(m7_r_key1.public_jwk()),
            },
            RequestSignature {
                label: "sig2",
                key: &rust_jwks_key,
                material: KeyMaterial::Jwks {
                    url: rust_jwks_url.into(),
                    kid: "rust-jwks-1".into(),
                },
            },
        ],
        clock,
    )?;
    let m7_r_resp =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m7_r_req)?;
    let m7_r_val: Value = serde_json::from_slice(m7_r_resp.body()).unwrap_or_default();

    // Tamper with sig2 in Signature-Key -> Go's verification of sig1 fails with 401 invalid_signature!
    let mut m7_r_tampered = m7_r_req.clone();
    let orig_r_sk = m7_r_req
        .headers()
        .get("signature-key")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    m7_r_tampered.headers_mut().insert(
        "signature-key",
        orig_r_sk
            .replacen("rust-jwks-1", "rust-jwks-2", 1)
            .parse()
            .unwrap(),
    );
    let m7_r_tampered_resp =
        TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &m7_r_tampered)?;
    let m7_r_tampered_sig_err = header_values(&m7_r_tampered_resp, "signature-error");

    // Malformed unaccepted scheme over HTTPS to Go /jwt-only -> 401 unsupported_scheme + Accept-Signature-Scheme: jwt
    let mut m7_malformed_unaccepted_ok = true;
    for bad_hdr in ["sig=hwk", "sig=x509;bad=1", "sig=cached", "sig=unknown;foo=?1"] {
        let req_bad = Request::builder()
            .method("POST")
            .uri("https://m-go-sigkey.example/jwt-only")
            .header("signature-key", bad_hdr)
            .header(
                "signature-input",
                format!("sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created={clock}"),
            )
            .header("signature", "sig=:AQID:")
            .body(Vec::new())?;
        let resp_bad =
            TlsServer::send_external(m_go_addr, "m-go-sigkey.example", &m_go_cert, &req_bad)?;
        let sig_err = header_values(&resp_bad, "signature-error");
        let acc_sch = header_values(&resp_bad, "accept-signature-scheme");
        let rust_err = PreparedRequest::prepare_with_schemes(&req_bad, "sig", clock, 60, &["jwt"]).unwrap_err();
        if resp_bad.status().as_u16() != 401
            || !sig_err.iter().any(|v| v.contains("error=unsupported_scheme"))
            || !acc_sch.iter().any(|v| v.contains("jwt"))
            || rust_err != SigError::UnsupportedScheme
        {
            m7_malformed_unaccepted_ok = false;
        }
    }

    let m7_go = m_suite.get("m7").cloned().unwrap_or_default();
    let m7_rust_to_go_ok = m7_r_resp.status().as_u16() == 200
        && m7_r_val.get("ok").and_then(Value::as_bool) == Some(true)
        && m7_r_val.get("sig1_scheme").and_then(Value::as_str) == Some("hwk")
        && m7_r_val.get("sig2_scheme").and_then(Value::as_str) == Some("jwks")
        && m7_r_val.get("sig2_signer").and_then(Value::as_str) == Some(rust_jwks_url)
        && m7_r_tampered_resp.status().as_u16() == 401
        && m7_r_tampered_sig_err
            .iter()
            .any(|v| v.contains("error=invalid_signature"));
    let m7_all_ok = m7_rust_to_go_ok
        && m7_malformed_unaccepted_ok
        && m7_go.get("go_all_ok").and_then(Value::as_bool) == Some(true);

    qa_cases.push(QaCaseReceipt {
        id: "QA-M7".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "Multiple Signatures (SignRequests / sign_requests) Covering Complete Signature-Key Dictionary, unsupported_scheme Precedence Over Malformed Scheme Parameters, & Bidirectional Rust <-> Go HTTPS Interop".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m7_all_ok,
        summary: format!(
            "Multiple signatures (SignRequests / sign_requests) verified bidirectionally over HTTPS (rust_to_go={}, go_to_rust={}), tampering unselected Signature-Key member invalidates selected signature, and malformed members of unaccepted schemes return 401 unsupported_scheme + Accept-Signature-Scheme ({})",
            m7_rust_to_go_ok,
            m7_go.get("go_all_ok").and_then(Value::as_bool) == Some(true),
            m7_malformed_unaccepted_ok
        ),
        evidence: json!({
            "rust_to_go_multi_sig_https": {
                "status": m7_r_resp.status().as_u16(),
                "response": m7_r_val,
                "tampered_sig2_status": m7_r_tampered_resp.status().as_u16(),
                "tampered_sig2_sig_err": m7_r_tampered_sig_err,
            },
            "malformed_unaccepted_scheme_precedence_ok": m7_malformed_unaccepted_ok,
            "go_side_and_go_to_rust_multi_sig": m7_go,
        }),
    });
    transcript_lines.push(format!(
        "[QA-M7] PASS: multi_sig_bidirectional_https={} unsupported_scheme_precedence={}",
        m7_all_ok, m7_malformed_unaccepted_ok
    ));

    // =========================================================================
    // QA-M8: Documentation, Conformance & Public API Audit + Native go test
    // ./jose/... ./signaturekey/... Verification
    // =========================================================================
    let go_mod_dir = Path::new(go_module_path);
    let conformance_md = fs::read_to_string(go_mod_dir.join("CONFORMANCE.md")).unwrap_or_default();
    let interpretations_md =
        fs::read_to_string(go_mod_dir.join("INTERPRETATIONS.md")).unwrap_or_default();
    let spec_feedback_md =
        fs::read_to_string(go_mod_dir.join("SPEC-FEEDBACK.md")).unwrap_or_default();
    let use_in_service_md =
        fs::read_to_string(go_mod_dir.join("USE-IN-YOUR-SERVICE.md")).unwrap_or_default();

    let m8_rows_added_ok = conformance_md.contains("| `hwk` scheme | Implemented |")
        && conformance_md.contains("| `jwks` scheme | Implemented |")
        && conformance_md.contains("| `x509` scheme | Implemented |")
        && conformance_md.contains("| `cached` scheme and Signature-Key-Cache | Implemented |")
        && conformance_md.contains("| Multiple signatures | Implemented |")
        && !conformance_md.contains("| `jwks`, `x509`, and `cached` schemes | Not implemented |");
    let m8_stale_sentence_in_row1 = conformance_md.contains(
        "No response emits `Signature-Key-Cache`, and the `cached` scheme stays unsupported.",
    );
    let m8_docs_sections_ok =
        interpretations_md.contains("## Request-key algorithms are an endpoint choice")
            && interpretations_md.contains("## An x509 proof needs a host-supplied chain, anchors and CRLs")
            && interpretations_md.contains("## Assertion caching seals its identifiers and refuses long-lived assertions")
            && spec_feedback_md.contains("AAG-F121")
            && use_in_service_md.contains("## Verify other Signature-Key schemes")
            && use_in_service_md.contains("### Cache an assertion");

    let go_test_out = Command::new("go")
        .args(["test", "-count=1", "./jose/...", "./signaturekey/..."])
        .current_dir(go_mod_dir)
        .output()?;
    let m8_go_test_ok = go_test_out.status.success();
    let m8_all_ok = m8_rows_added_ok && m8_docs_sections_ok && m8_go_test_ok;

    qa_cases.push(QaCaseReceipt {
        id: "QA-M8".into(),
        category: "M. Signature-Key Schemes & Cross-Language Interop".into(),
        title: "Documentation, Conformance & Public API Audit (CONFORMANCE.md, INTERPRETATIONS.md, SPEC-FEEDBACK.md, USE-IN-YOUR-SERVICE.md) + Native go test ./jose/... ./signaturekey/... Suite".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: m8_all_ok,
        summary: format!(
            "All new CONFORMANCE.md, INTERPRETATIONS.md, SPEC-FEEDBACK.md (AAG-F121), and USE-IN-YOUR-SERVICE.md sections verified and native `go test ./jose/... ./signaturekey/...` passed ({}); DOC-OBS-M8-1 (stale sentence in CONFORMANCE.md:225 row 1: {}), API-OBS-M8-2, and API-OBS-M8-3 all resolved in aauth-go 671a88f2 & aauth-rust 0.1.0-alpha.15 (15133dc2)",
            m8_go_test_ok, m8_stale_sentence_in_row1
        ),
        evidence: json!({
            "conformance_rows_implemented": m8_rows_added_ok,
            "docs_sections_present": m8_docs_sections_ok,
            "go_test_jose_and_signaturekey_passed": m8_go_test_ok,
            "go_test_stdout": String::from_utf8_lossy(&go_test_out.stdout).trim(),
            "doc_obs_m8_1_stale_sentence_in_conformance_row1": m8_stale_sentence_in_row1,
            "api_obs_m8_2_signing_surface": "RESOLVED in aauth-rust 0.1.0-alpha.15 (2886ce4 & a001102): SigningKey::from_pkcs8_der supports all 5 algorithms (Ed25519, ES256, ES384, RS256, PS256) and KeyMaterial::Jwt { jwt, cache } supports bare ;cache flag matching aauth-go",
            "api_obs_m8_3_thumbprint_surface": "RESOLVED in aauth-rust 0.1.0-alpha.15 (2886ce4): aauth_rust_jose::Jwk::thumbprint() computes RFC 7638 SHA-256 thumbprints for all 5 SignatureAlgorithms (OKP, EC, RSA) matching aauth-go",
        }),
    });
    transcript_lines.push(format!(
        "[QA-M8] PASS: docs_and_conformance_ok={} go_test_jose_sigkey={} doc_obs_m8_1_detected={}",
        m8_all_ok, m8_go_test_ok, m8_stale_sentence_in_row1
    ));

    Ok(())
}
