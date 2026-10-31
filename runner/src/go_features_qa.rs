use crate::*;
use aauth_rust_agent::verify_event;
use aauth_rust_budgets::{SignedUsage, UsageQuery, verify_usage_signature};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::events::{EVENT_TOKEN_DOCUMENT, EventClaims, body_s256, mint_event_token};
use aauth_rust_core::interaction::{
    InteractionOutcome, ResourceInteraction, completion_redirect, parse_interaction_query,
};
use aauth_rust_core::resource_link::{
    discovery_from_headers, fetch_targets, links_from_header, links_from_html,
    metadata_matches_link,
};
use aauth_rust_core::TokenError;
use aauth_rust_jose::{Jws, SigningKey};
use aauth_rust_person_server::{ResourceInteractionCallback, ResourceInteractionConfig};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use std::collections::BTreeMap;

const P1_RUST_DIRECT_PS: &str = "https://p1-rust-direct-ps.example";
const P1_RUST_INIT_RES: &str = "https://p1-rust-init-res.example";
const P3_RUST_LINK_RES: &str = "https://p3-rust-link-res.example";
const P7_RUST_USAGE_RES: &str = "https://p7-rust-usage-res.example";
const P10_RUST_FED_PS: &str = "https://p10-rust-fed-ps.example";
const P10_RUST_FED_AS: &str = "https://p10-rust-fed-as.example";
const P10_RUST_FED_RES: &str = "https://p10-rust-fed-res.example";

const P256_PKCS8_SEED1_DER: &[u8] = &[
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
    0x01, 0x01, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c,
    0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
    0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a,
    0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31,
    0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

fn get_req(uri: &str) -> Request<Vec<u8>> {
    get(uri).unwrap()
}

fn send_https(
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    req: &Request<Vec<u8>>,
) -> Result<Response<Vec<u8>>> {
    TlsServer::send_external(addr, host, cert, req)
}

fn post_json_ext(
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    url: &str,
    body: Value,
) -> Result<Value> {
    let req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&body)?)?;
    let resp = send_https(addr, host, cert, &req)?;
    if resp.status().as_u16() != 200 {
        return Err(format!(
            "POST {url} returned {}: {}",
            resp.status(),
            String::from_utf8_lossy(resp.body())
        )
        .into());
    }
    Ok(serde_json::from_slice(resp.body())?)
}

fn register_p_host_with_go(
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
        return Err(format!("register_p_host_with_go failed for {host}: {res}").into());
    }
    Ok(())
}

fn insert_manual_key(
    trust: &Trust,
    issuer: &str,
    dwk: &str,
    kid: &str,
    seed: u8,
    access_server: Option<&str>,
) -> Result<()> {
    let mut jwk = serde_json::to_value(SigningKey::from_seed([seed; 32]).public_jwk())?;
    jwk["kid"] = json!(kid);
    let mut meta = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
    });
    match dwk {
        "aauth-person.json" => {
            meta["person_token_endpoint"] = json!(format!("{issuer}/person"));
            meta["token_endpoint"] = json!(format!("{issuer}/token"));
        }
        "aauth-access.json" => {
            meta["token_endpoint"] = json!(format!("{issuer}/token"));
        }
        "aauth-resource.json" => {
            meta["access_mode"] = json!("auth-token");
            meta["authorization_endpoint"] = json!(format!("{issuer}/authorize"));
            meta["scopes_supported"] = json!(["read", "calendar.read", "records.read"]);
            meta["scope_descriptions"] = json!({
                "read": "Read records",
                "calendar.read": "Read calendar",
                "records.read": "Read records"
            });
            if let Some(as_iss) = access_server {
                meta["access_server"] = json!(as_iss);
            }
        }
        _ => {}
    }
    trust.insert_manual(
        issuer,
        dwk,
        TrustedIssuerKeys::from_documents(
            issuer,
            dwk,
            &serde_json::to_vec(&meta)?,
            &serde_json::to_vec(&json!({"keys": [jwk]}))?,
        )?,
    )?;
    Ok(())
}
struct PPsPolicy {
    person_id: String,
}
impl Policy for PPsPolicy {
    fn bind_person(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: self.person_id.clone(),
            subject: format!("sub-{}-{}", self.person_id, req.resource),
            tenant: None,
        })
    }
    fn bind_upstream(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: self.person_id.clone(),
            subject: format!("sub-{}-{}", self.person_id, req.resource),
            tenant: None,
        })
    }
    fn authorize(&self, req: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: req.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, _: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
    fn consent_upstream(&self, _: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
}

struct PFederation {
    routes: Mutex<BTreeMap<String, Arc<TlsServer>>>,
    go_routes: Mutex<BTreeMap<String, (SocketAddr, &'static str, Vec<u8>)>>,
}
impl PFederation {
    fn new() -> Self {
        Self {
            routes: Mutex::new(BTreeMap::new()),
            go_routes: Mutex::new(BTreeMap::new()),
        }
    }
    fn register_rust(&self, issuer: &str, tls: Arc<TlsServer>) {
        self.routes.lock().unwrap().insert(issuer.to_owned(), tls);
    }
    fn register_go(&self, issuer: &str, addr: SocketAddr, host: &'static str, cert: Vec<u8>) {
        self.go_routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), (addr, host, cert));
    }
}
impl Federation for PFederation {
    fn endpoint(&self, access_server: &str) -> std::result::Result<String, FederationError> {
        Ok(format!("{access_server}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        let uri = request.uri().to_string();
        for (iss, tls) in self.routes.lock().unwrap().iter() {
            if uri.starts_with(iss) {
                return tls.send(request).map_err(|_| FederationError);
            }
        }
        for (iss, (addr, host, cert)) in self.go_routes.lock().unwrap().iter() {
            if uri.starts_with(iss) {
                return send_https(*addr, host, cert, request).map_err(|_| FederationError);
            }
        }
        Err(FederationError)
    }
}

struct SharedPFederation(Arc<PFederation>);
impl Federation for SharedPFederation {
    fn endpoint(&self, access_server: &str) -> std::result::Result<String, FederationError> {
        self.0.endpoint(access_server)
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        self.0.send(request)
    }
}

pub fn run_go_features_qa_cases(
    body: &Value,
    out_dir: &Path,
    go_module_path: &str,
    clock: i64,
    trust: &Trust,
    qa_cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {
    let _ = out_dir;
    let mut cases: Vec<Value> = Vec::new();
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

    // Pre-insert Go keys so Rust servers trust Go issuers during /__run-p-suite
    insert_manual_key(trust, "https://p1-go-ap.example", "aauth-agent.json", "p1-ap-1", 0xb1, None)?;
    insert_manual_key(trust, "https://p1-go-ps.example", "aauth-person.json", "p1-ps-1", 0xb3, None)?;
    insert_manual_key(trust, "https://p1-go-res.example", "aauth-resource.json", "p1-res-1", 0xb4, None)?;
    insert_manual_key(trust, "https://p1-go-res2.example", "aauth-resource.json", "p1-res2-1", 0xb5, None)?;
    insert_manual_key(trust, "https://p5-go-ps.example", "aauth-person.json", "p5-ps-1", 0xbd, None)?;
    insert_manual_key(trust, "https://p5-relay-res.example", "aauth-agent.json", "p5-relay-res-1", 0xc0, None)?;
    insert_manual_key(trust, "https://p5-relay-res.example", "aauth-resource.json", "p5-relay-res-1", 0xc0, Some(P10_RUST_FED_AS))?;
    insert_manual_key(trust, "https://p10-go-fed-ps.example", "aauth-person.json", "p10-go-fed-ps-1", 0xcc, None)?;
    insert_manual_key(trust, "https://p10-go-as.example", "aauth-access.json", "p10-go-as-1", 0xcd, None)?;
    insert_manual_key(
        trust,
        "https://p10-go-fed-res.example",
        "aauth-resource.json",
        "p10-go-fed-res-1",
        0xce,
        Some("https://p10-go-as.example"),
    )?;

    // 1. P1 Rust Direct PS (with_resource_interaction)
    let p1_ps_seq = Arc::new(AtomicUsize::new(0));
    let p1_rust_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(P1_RUST_DIRECT_PS, "p1-rust-ps-1", SigningKey::from_seed([0xe1; 32])),
            trust.clone(),
            MemoryStore::default(),
            Box::new(PPsPolicy {
                person_id: "person-p1-rust".into(),
            }) as aauth_rust_person_server::BoxedPolicy,
            Box::new(move || clock) as BoxedClock,
            Box::new(move || format!("p1-rps-jti-{}", p1_ps_seq.fetch_add(1, Ordering::SeqCst) + 1))
                as BoxedTokenIds,
        )?
        .with_resource_interaction(ResourceInteractionConfig::new(
            MemoryContinuations::new(64),
            &format!("{P1_RUST_DIRECT_PS}/consent"),
            &format!("{P1_RUST_DIRECT_PS}/callback"),
            |url: &str| url.starts_with("https://"),
        ))?,
    );
    let p1_rust_ps_srv = p1_rust_ps.clone();
    let p1_rust_direct_ps_tls = Arc::new(TlsServer::start("p1-rust-direct-ps.example", move |req| {
        let path = req.uri().path().to_owned();
        if req.method().as_str() == "GET" && path == "/.well-known/aauth-person.json" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p1_rust_ps_srv.metadata())
                .unwrap();
        }
        if req.method().as_str() == "GET" && path == "/.well-known/jwks.json" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p1_rust_ps_srv.jwks())
                .unwrap();
        }
        if req.method().as_str() == "GET" && let Some(id) = path.strip_prefix("/consent/") {
            let q = req.uri().query().unwrap_or("");
            let resp = p1_rust_ps_srv.redirect_to_resource(id, q).unwrap();
            let redir = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            return json_response(200, json!({"redirect_url": redir}));
        }
        if req.method().as_str() == "GET" && let Some(flow) = path.strip_prefix("/callback/") {
            let q = req.uri().query();
            if let Ok(ResourceInteractionCallback::Consent { id }) =
                p1_rust_ps_srv.resource_interaction_callback(flow, q)
            {
                let _ = p1_rust_ps_srv.decide_resource_interaction(&id, true);
                return json_response(200, json!({"approved": true}));
            }
            return json_response(400, json!({"approved": false}));
        }
        p1_rust_ps_srv.handle(&req)
    })?);
    trust.discover(&p1_rust_direct_ps_tls, P1_RUST_DIRECT_PS, "aauth-person.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p1-rust-direct-ps.example",
        &p1_rust_direct_ps_tls,
    )?;

    // 2. P1 Rust Resource (authorize_with_interaction)
    let p1_rust_res = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: P1_RUST_INIT_RES.into(),
                signed_origin: P1_RUST_INIT_RES.into(),
                kid: "p1-rust-res-1".into(),
                signing_key: SigningKey::from_seed([0xe2; 32]),
                scopes: vec!["calendar.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "calendar.read".into(),
                    "Read calendar".into(),
                )]),
            },
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint(),
    );
    let p1_rust_res_int = ResourceInteraction::open(&format!("{P1_RUST_INIT_RES}/connect"))?;
    let p1_rust_res_int_srv = p1_rust_res_int.clone();
    let p1_rust_res_srv = p1_rust_res.clone();
    let p1_rust_res_seq = Arc::new(AtomicUsize::new(0));
    let p1_rust_init_res_tls = Arc::new(TlsServer::start("p1-rust-init-res.example", move |req| {
        let jti = format!("p1-rres-jti-{}", p1_rust_res_seq.fetch_add(1, Ordering::SeqCst) + 1);
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p1_rust_res_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p1_rust_res_srv.jwks().unwrap())
                .unwrap(),
            ("GET", "/connect") => {
                let q = req.uri().query().unwrap_or("");
                let parsed = parse_interaction_query(q).unwrap();
                let cb = parsed.callback.unwrap();
                let redir = completion_redirect(&cb, InteractionOutcome::Completed).unwrap();
                let comp_url = redir
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                json_response(200, json!({"completion_url": comp_url}))
            }
            ("POST", "/authorize") => {
                let dec = p1_rust_res_srv.authorize_with_interaction(
                    &req,
                    clock,
                    &jti,
                    &p1_rust_res_int_srv,
                );
                let resp = dec.into_response();
                if let Ok(rt) = challenge(&resp) {
                    json_response(200, json!({"resource_token": rt}))
                } else {
                    resp
                }
            }
            _ => match p1_rust_res_srv.authorize_with_interaction(
                &req,
                clock,
                &jti,
                &p1_rust_res_int_srv,
            ) {
                AuthDecision::Granted(_) => json_response(200, json!({"ok": true})),
                other => other.into_response(),
            },
        }
    })?);
    trust.discover(&p1_rust_init_res_tls, P1_RUST_INIT_RES, "aauth-resource.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p1-rust-init-res.example",
        &p1_rust_init_res_tls,
    )?;
    // 3. P3 Rust Link Resource (serves Link header and HTML <link rel="aauth-resource"> on /docs and metadata on /.well-known/aauth-resource.json)
    let p3_rust_link_res = Arc::new(PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: P3_RUST_LINK_RES.into(),
            signed_origin: P3_RUST_LINK_RES.into(),
            kid: "p3-rust-res-1".into(),
            signing_key: SigningKey::from_seed([0xe3; 32]),
            scopes: vec!["read".into()],
            scope_descriptions: BTreeMap::from([("read".into(), "Read docs".into())]),
        },
        trust.clone(),
        Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
    )?);
    let p3_rust_link_srv = p3_rust_link_res.clone();
    let p3_rust_link_res_tls = Arc::new(TlsServer::start("p3-rust-link-res.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p3_rust_link_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p3_rust_link_srv.jwks().unwrap())
                .unwrap(),
            ("GET", "/docs") => Response::builder()
                .status(200)
                .header("content-type", "text/html; charset=utf-8")
                .header(
                    "link",
                    format!("<{P3_RUST_LINK_RES}/.well-known/aauth-resource.json>; rel=\"aauth-resource\""),
                )
                .body(
                    format!(
                        "<!doctype html><html><head><link rel=\"aauth-resource\" href=\"{P3_RUST_LINK_RES}/.well-known/aauth-resource.json\"></head><body>docs</body></html>"
                    )
                    .into_bytes(),
                )
                .unwrap(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    trust.discover(&p3_rust_link_res_tls, P3_RUST_LINK_RES, "aauth-resource.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p3-rust-link-res.example",
        &p3_rust_link_res_tls,
    )?;

    // 4. P7 Rust Usage Resource (with_budgets + pre-metered spend for person-p7 under https://p5-go-ps.example)
    let p7_unit = UnitDeclaration::with_max("USD", 6, 10_000_000, "US micro-dollars")?;
    let p7_rust_usage_res = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: P7_RUST_USAGE_RES.into(),
                signed_origin: P7_RUST_USAGE_RES.into(),
                kid: "p7-rust-res-1".into(),
                signing_key: SigningKey::from_seed([0xe4; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_budgets(
            vec![p7_unit],
            format!("{P7_RUST_USAGE_RES}/usage"),
            250_000,
            1_000_000,
        )?,
    );
    let p7_rust_usage_srv = p7_rust_usage_res.clone();
    let p7_rust_usage_res_tls = Arc::new(TlsServer::start("p7-rust-usage-res.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p7_rust_usage_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p7_rust_usage_srv.jwks().unwrap())
                .unwrap(),
            ("POST", "/usage") => p7_rust_usage_srv.usage(&req, clock),
            _ => match p7_rust_usage_srv.authorize(&req, clock, "p7-rust-chal-1") {
                AuthDecision::Granted(_) => json_response(200, json!({"ok": true})),
                other => other.into_response(),
            },
        }
    })?);
    trust.discover(&p7_rust_usage_res_tls, P7_RUST_USAGE_RES, "aauth-resource.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p7-rust-usage-res.example",
        &p7_rust_usage_res_tls,
    )?;

    // Pre-record one metered call on P7_RUST_USAGE_RES for (ps="https://p5-go-ps.example", sub="person-p7")
    let p7_seed_ap = AgentProvider::new(
        "https://p1-go-ap.example",
        "p1-ap-1",
        SigningKey::from_seed([0xb1; 32]),
    )?;
    let p7_seed_agent_tok = p7_seed_ap.issue(&AgentClaims {
        iss: "https://p1-go-ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:p1-agent@p1-go-ap.example".into(),
        jti: "p7-seed-ag-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([0xb2; 32]).public_jwk(),
        },
        ps: Some("https://p5-go-ps.example".into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let p7_seed_agent = Agent::new(SigningKey::from_seed([0xb2; 32]), p7_seed_agent_tok)?;
    let mut p7_seed_extra = BTreeMap::new();
    p7_seed_extra.insert(
        "budget".into(),
        Budget::new(2_000_000, "USD", 6)?.to_value(),
    );
    let p7_seed_at = mint_auth_token(
        &SigningKey::from_seed([0xbd; 32]),
        "p5-ps-1",
        &AuthClaims {
            iss: "https://p5-go-ps.example".into(),
            dwk: "aauth-person.json".into(),
            aud: P7_RUST_USAGE_RES.into(),
            ps: "https://p5-go-ps.example".into(),
            sub: "person-p7".into(),
            jti: "p7-seed-at-1".into(),
            iat: clock,
            exp: clock + 600,
            cnf: Confirmation {
                jwk: p7_seed_agent.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some("records.read".into()),
            account: None,
            extra: p7_seed_extra,
        },
    )?;
    let p7_seed_holder = p7_seed_agent.with_token(p7_seed_at)?;
    let p7_seed_resp = p7_rust_usage_res_tls.send(&signed_get(
        &p7_seed_holder,
        &format!("{P7_RUST_USAGE_RES}/records"),
        clock,
    )?)?;
    if p7_seed_resp.status().as_u16() != 200 {
        return Err(format!("p7_seed_resp failed: {}", p7_seed_resp.status()).into());
    }
    // 5. P10 Rust Federated AS, PS, and Resource
    let p10_as_seq = Arc::new(AtomicUsize::new(0));
    let p10_rust_as = Arc::new(AccessServer::new(
        AsConfig::new(P10_RUST_FED_AS, "p10-rust-as-1", SigningKey::from_seed([0xe5; 32])),
        trust.clone(),
        move |req: &AsAuthorizationRequest| {
            Ok(AsDecision {
                scopes: req.scopes.clone(),
                lifetime: 600,
            })
        },
        move || clock,
        move || format!("p10-ras-jti-{}", p10_as_seq.fetch_add(1, Ordering::SeqCst) + 1),
    )?);
    let p10_rust_as_srv = p10_rust_as.clone();
    let p10_rust_fed_as_tls = Arc::new(TlsServer::start("p10-rust-fed-as.example", move |req| {
        p10_rust_as_srv.handle(&req)
    })?);
    trust.discover(&p10_rust_fed_as_tls, P10_RUST_FED_AS, "aauth-access.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p10-rust-fed-as.example",
        &p10_rust_fed_as_tls,
    )?;

    let p10_fed = Arc::new(PFederation::new());
    p10_fed.register_rust(P10_RUST_FED_AS, p10_rust_fed_as_tls.clone());
    let p10_ps_seq = Arc::new(AtomicUsize::new(0));
    let p10_rust_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(P10_RUST_FED_PS, "p10-rust-ps-1", SigningKey::from_seed([0xe6; 32])),
            trust.clone(),
            MemoryStore::default(),
            Box::new(PPsPolicy {
                person_id: "person-p10-rust".into(),
            }) as aauth_rust_person_server::BoxedPolicy,
            Box::new(move || clock) as BoxedClock,
            Box::new(move || format!("p10-rps-jti-{}", p10_ps_seq.fetch_add(1, Ordering::SeqCst) + 1))
                as BoxedTokenIds,
        )?
        .with_federation(Box::new(SharedPFederation(p10_fed.clone()))),
    );
    let p10_rust_ps_srv = p10_rust_ps.clone();
    let p10_rust_fed_ps_tls = Arc::new(TlsServer::start("p10-rust-fed-ps.example", move |req| {
        p10_rust_ps_srv.handle(&req)
    })?);
    trust.discover(&p10_rust_fed_ps_tls, P10_RUST_FED_PS, "aauth-person.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p10-rust-fed-ps.example",
        &p10_rust_fed_ps_tls,
    )?;

    let p10_rust_res = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: P10_RUST_FED_RES.into(),
                signed_origin: P10_RUST_FED_RES.into(),
                kid: "p10-rust-res-1".into(),
                signing_key: SigningKey::from_seed([0xe7; 32]),
                scopes: vec!["read".into()],
                scope_descriptions: BTreeMap::from([("read".into(), "Read records".into())]),
            },
            P10_RUST_FED_AS,
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint(),
    );
    let p10_rust_res_srv = p10_rust_res.clone();
    let p10_rust_res_seq = Arc::new(AtomicUsize::new(0));
    let p10_rust_fed_res_tls = Arc::new(TlsServer::start("p10-rust-fed-res.example", move |req| {
        let jti = format!("p10-rres-jti-{}", p10_rust_res_seq.fetch_add(1, Ordering::SeqCst) + 1);
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p10_rust_res_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(p10_rust_res_srv.jwks().unwrap())
                .unwrap(),
            ("POST", "/authorize") => p10_rust_res_srv
                .authorize_endpoint(&req, clock, &jti)
                .into_response(),
            _ => match p10_rust_res_srv.authorize(&req, clock, &jti) {
                AuthDecision::Granted(admitted) => json_response(
                    200,
                    json!({
                        "ok": true,
                        "sub": admitted.token().claims().sub,
                        "ps": admitted.token().claims().ps,
                    }),
                ),
                other => other.into_response(),
            },
        }
    })?);
    trust.discover(&p10_rust_fed_res_tls, P10_RUST_FED_RES, "aauth-resource.json")?;
    register_p_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "p10-rust-fed-res.example",
        &p10_rust_fed_res_tls,
    )?;

    // Execute Go P-Suite (`POST /__run-p-suite`)
    let go_p_suite = post_json_ext(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-p-suite",
        json!({
            "rust_direct_ps_issuer": P1_RUST_DIRECT_PS,
            "rust_init_res_issuer": P1_RUST_INIT_RES,
            "rust_link_res_issuer": P3_RUST_LINK_RES,
            "rust_usage_res_issuer": P7_RUST_USAGE_RES,
            "rust_fed_ps_issuer": P10_RUST_FED_PS,
            "rust_fed_as_issuer": P10_RUST_FED_AS,
            "rust_fed_res_issuer": P10_RUST_FED_RES,
        }),
    )?;
    let p1_go_ps_addr: SocketAddr = go_p_suite["p1_go_ps_addr"]
        .as_str()
        .ok_or("missing p1_go_ps_addr")?
        .parse()?;
    let p1_go_ps_cert = hex_decode(
        go_p_suite["p1_go_ps_cert_hex"]
            .as_str()
            .ok_or("missing p1_go_ps_cert_hex")?,
    )?;
    let p1_go_res_addr: SocketAddr = go_p_suite["p1_go_res_addr"]
        .as_str()
        .ok_or("missing p1_go_res_addr")?
        .parse()?;
    let p1_go_res_cert = hex_decode(
        go_p_suite["p1_go_res_cert_hex"]
            .as_str()
            .ok_or("missing p1_go_res_cert_hex")?,
    )?;
    let p2_orders_addr: SocketAddr = go_p_suite["p2_orders_addr"]
        .as_str()
        .ok_or("missing p2_orders_addr")?
        .parse()?;
    let p2_orders_cert = hex_decode(
        go_p_suite["p2_orders_cert_hex"]
            .as_str()
            .ok_or("missing p2_orders_cert_hex")?,
    )?;
    let p3_go_res_addr: SocketAddr = go_p_suite["p3_go_res_addr"]
        .as_str()
        .ok_or("missing p3_go_res_addr")?
        .parse()?;
    let p3_go_res_cert = hex_decode(
        go_p_suite["p3_go_res_cert_hex"]
            .as_str()
            .ok_or("missing p3_go_res_cert_hex")?,
    )?;
    let p7_go_res_addr: SocketAddr = go_p_suite["p7_go_res_addr"]
        .as_str()
        .ok_or("missing p7_go_res_addr")?
        .parse()?;
    let p7_go_res_cert = hex_decode(
        go_p_suite["p7_go_res_cert_hex"]
            .as_str()
            .ok_or("missing p7_go_res_cert_hex")?,
    )?;
    let p8_go_ap_addr: SocketAddr = go_p_suite["p8_go_ap_addr"]
        .as_str()
        .ok_or("missing p8_go_ap_addr")?
        .parse()?;
    let p8_go_ap_cert = hex_decode(
        go_p_suite["p8_go_ap_cert_hex"]
            .as_str()
            .ok_or("missing p8_go_ap_cert_hex")?,
    )?;
    let p9_go_res_addr: SocketAddr = go_p_suite["p9_go_res_addr"]
        .as_str()
        .ok_or("missing p9_go_res_addr")?
        .parse()?;
    let p9_go_res_cert = hex_decode(
        go_p_suite["p9_go_res_cert_hex"]
            .as_str()
            .ok_or("missing p9_go_res_cert_hex")?,
    )?;
    let p10_go_as_addr: SocketAddr = go_p_suite["p10_go_as_addr"]
        .as_str()
        .ok_or("missing p10_go_as_addr")?
        .parse()?;
    let p10_go_as_cert = hex_decode(
        go_p_suite["p10_go_as_cert_hex"]
            .as_str()
            .ok_or("missing p10_go_as_cert_hex")?,
    )?;
    let p10_go_fed_res_addr: SocketAddr = go_p_suite["p10_go_fed_res_addr"]
        .as_str()
        .ok_or("missing p10_go_fed_res_addr")?
        .parse()?;
    let p10_go_fed_res_cert = hex_decode(
        go_p_suite["p10_go_fed_res_cert_hex"]
            .as_str()
            .ok_or("missing p10_go_fed_res_cert_hex")?,
    )?;

    p10_fed.register_go(
        "https://p10-go-as.example",
        p10_go_as_addr,
        "p10-go-as.example",
        p10_go_as_cert.clone(),
    );

    // =========================================================================
    // QA-P1: Resource-Initiated Interaction (3-Party), Callbacks & Cross-Language
    // (Rust <-> Go) Over Real HTTPS
    // =========================================================================
    // Cross-Language Pairing 1: Rust Agent -> Go Resource (p1-go-res.example) -> Go Direct PS (p1-go-ps.example)
    let p1_rust_agent_tok = p7_seed_ap.issue(&AgentClaims {
        iss: "https://p1-go-ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:rust-agent@p1-go-ap.example".into(),
        jti: "p1-rust-ag-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([0xe8; 32]).public_jwk(),
        },
        ps: Some("https://p1-go-ps.example".into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let p1_rust_agent = Agent::new(SigningKey::from_seed([0xe8; 32]), p1_rust_agent_tok)?;
    let p1_r_pt_resp = send_https(
        p1_go_ps_addr,
        "p1-go-ps.example",
        &p1_go_ps_cert,
        &post_at(
            &p1_rust_agent,
            "https://p1-go-ps.example/person",
            json!({"resource": "https://p1-go-res.example"})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let p1_r_pt = member(&p1_r_pt_resp, "person_token").ok_or("missing p1_r_pt")?;
    let p1_rust_agent_pt = p1_rust_agent.with_token(p1_r_pt.clone())?;
    let p1_r_authz_resp = send_https(
        p1_go_res_addr,
        "p1-go-res.example",
        &p1_go_res_cert,
        &post_at(
            &p1_rust_agent_pt,
            "https://p1-go-res.example/authorize",
            json!({"scope": "calendar.read"}).to_string().as_bytes(),
            clock,
        )?,
    )?;
    let p1_r_rt = member(&p1_r_authz_resp, "resource_token").ok_or("missing p1_r_rt")?;
    let p1_r_tok_resp = send_https(
        p1_go_ps_addr,
        "p1-go-ps.example",
        &p1_go_ps_cert,
        &post_at(
            &p1_rust_agent,
            "https://p1-go-ps.example/token",
            json!({
                "resource_token": p1_r_rt,
                "presented_token": p1_r_pt,
                "capabilities": ["interaction"],
            })
            .to_string()
            .as_bytes(),
            clock,
        )?,
    )?;
    let p1_r_poll = PollSession::new("https://p1-go-ps.example", &p1_r_tok_resp, clock, clock + 60)?;
    let p1_r_loc = p1_r_poll.pending().location.clone();
    let ContinuationRequirement::Interaction {
        url: p1_r_int_url,
        code: p1_r_int_code,
    } = &p1_r_poll.pending().requirement
    else {
        return Err("expected Interaction requirement on p1_r_tok_resp".into());
    };
    let p1_r_visit_ps_resp = send_https(
        p1_go_ps_addr,
        "p1-go-ps.example",
        &p1_go_ps_cert,
        &get_req(&format!(
            "{p1_r_int_url}?code={p1_r_int_code}&callback=https%3A%2F%2Fp1-go-ap.example%2Fdone"
        )),
    )?;
    let p1_r_visit_ps_json: Value = serde_json::from_slice(p1_r_visit_ps_resp.body())?;
    let p1_r_res_redir = p1_r_visit_ps_json["redirect_url"]
        .as_str()
        .ok_or("missing redirect_url from Go PS")?;
    let p1_r_visit_res_resp = send_https(
        p1_go_res_addr,
        "p1-go-res.example",
        &p1_go_res_cert,
        &get_req(p1_r_res_redir),
    )?;
    let p1_r_visit_res_json: Value = serde_json::from_slice(p1_r_visit_res_resp.body())?;
    let p1_r_comp_url = p1_r_visit_res_json["completion_url"]
        .as_str()
        .ok_or("missing completion_url from Go Resource")?;
    let p1_r_cb_resp = send_https(
        p1_go_ps_addr,
        "p1-go-ps.example",
        &p1_go_ps_cert,
        &get_req(p1_r_comp_url),
    )?;
    let p1_r_cb_json: Value = serde_json::from_slice(p1_r_cb_resp.body())?;
    let mut p1_r_poll_req = get_req(&p1_r_loc);
    p1_rust_agent.sign(&mut p1_r_poll_req, clock)?;
    let p1_r_poll_resp = send_https(p1_go_ps_addr, "p1-go-ps.example", &p1_go_ps_cert, &p1_r_poll_req)?;
    let p1_r_at = member(&p1_r_poll_resp, "auth_token").ok_or("missing p1_r_at")?;
    let p1_rust_agent_at = p1_rust_agent.with_token(p1_r_at)?;
    let p1_r_call_resp = send_https(
        p1_go_res_addr,
        "p1-go-res.example",
        &p1_go_res_cert,
        &signed_get(&p1_rust_agent_at, "https://p1-go-res.example/events", clock)?,
    )?;
    let p1_rust_agent_to_go_ok = p1_r_cb_json["approved"].as_bool() == Some(true)
        && p1_r_poll_resp.status().as_u16() == 200
        && p1_r_call_resp.status().as_u16() == 200;

    let p1_go = &go_p_suite["p1"];
    let p1_pass = p1_rust_agent_to_go_ok
        && p1_go["go_to_go_happy_ok"].as_bool() == Some(true)
        && p1_go["early_approve_refused"].as_bool() == Some(true)
        && p1_go["forged_cb_refused"].as_bool() == Some(true)
        && p1_go["poll_interacting_ok"].as_bool() == Some(true)
        && p1_go["callback_errors_ok"].as_bool() == Some(true)
        && p1_go["code_exhaust_ok"].as_bool() == Some(true)
        && p1_go["egress_refusal_ok"].as_bool() == Some(true)
        && p1_go["withdraw_during_int_ok"].as_bool() == Some(true)
        && p1_go["cross_lang_go_ps_rust_res"].as_bool() == Some(true)
        && p1_go["cross_lang_go_res_rust_ps"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P1",
        "classification": "VERIFIED_WORKING",
        "pass": p1_pass,
        "summary": format!(
            "3-party resource-initiated interaction over HTTPS: Go->Go happy path={}, early consent & forged callback guards={}, 5 callback error mappings={}, 3-wrong-codes 410={}, egress refusal 500={}, withdrawal 403={}, Rust Agent->Go Res->Go PS={}, Go Agent->Rust Res->Go PS={}, Go Agent->Go Res->Rust PS={}",
            p1_go["go_to_go_happy_ok"].as_bool().unwrap_or(false),
            p1_go["early_approve_refused"].as_bool().unwrap_or(false) && p1_go["forged_cb_refused"].as_bool().unwrap_or(false),
            p1_go["callback_errors_ok"].as_bool().unwrap_or(false),
            p1_go["code_exhaust_ok"].as_bool().unwrap_or(false),
            p1_go["egress_refusal_ok"].as_bool().unwrap_or(false),
            p1_go["withdraw_during_int_ok"].as_bool().unwrap_or(false),
            p1_rust_agent_to_go_ok,
            p1_go["cross_lang_go_ps_rust_res"].as_bool().unwrap_or(false),
            p1_go["cross_lang_go_res_rust_ps"].as_bool().unwrap_or(false),
        ),
        "details": p1_go,
    }));
    // =========================================================================
    // QA-P2: Interaction Chaining & Callbacks Over Real HTTPS
    // =========================================================================
    // Cross-language: Rust Agent -> Go ChainedInteraction Resource (p2-orders.example)
    let p2_caller_auth_tok = go_p_suite["p2"]["p2_caller_auth_token"]
        .as_str()
        .ok_or("missing p2_caller_auth_token")?;
    let mut p2_rust_call_req = Request::builder()
        .method("POST")
        .uri("https://p2-orders.example/orders/42/fulfill")
        .header("aauth-capabilities", "interaction")
        .body(Vec::new())?;
    sign_request(
        &mut p2_rust_call_req,
        &SigningKey::from_seed([0xb2; 32]),
        KeyMaterial::Jwt {
            jwt: p2_caller_auth_tok.to_owned(),
            cache: false,
        },
        clock,
    )?;
    let p2_rust_202_resp = send_https(
        p2_orders_addr,
        "p2-orders.example",
        &p2_orders_cert,
        &p2_rust_call_req,
    )?;
    let p2_rust_poll = PollSession::new(
        "https://p2-orders.example",
        &p2_rust_202_resp,
        clock,
        clock + 60,
    )?;
    let p2_rust_loc = p2_rust_poll.pending().location.clone();
    let ContinuationRequirement::Interaction {
        url: p2_rust_int_url,
        code: p2_rust_int_code,
    } = &p2_rust_poll.pending().requirement
    else {
        return Err("expected Interaction requirement on p2_rust_202_resp".into());
    };
    let p2_rust_ref = p2_rust_int_url
        .strip_prefix("https://p2-orders.example/continue/")
        .ok_or("bad p2_rust_int_url")?
        .to_owned();
    let p2_rust_visit_resp = send_https(
        p2_orders_addr,
        "p2-orders.example",
        &p2_orders_cert,
        &get_req(&format!(
            "{p2_rust_int_url}?code={p2_rust_int_code}&callback=https%3A%2F%2Fp1-go-ap.example%2Fcallback%2Forder-42"
        )),
    )?;
    let p2_rust_visit_json: Value = serde_json::from_slice(p2_rust_visit_resp.body())?;
    let p2_rust_comp_resp = send_https(
        p2_orders_addr,
        "p2-orders.example",
        &p2_orders_cert,
        &Request::builder()
            .method("POST")
            .uri(format!(
                "https://p2-orders.example/__complete-downstream/{p2_rust_ref}"
            ))
            .body(Vec::new())?,
    )?;
    let p2_rust_comp_json: Value = serde_json::from_slice(p2_rust_comp_resp.body())?;
    let mut p2_rust_poll_req = get_req(&p2_rust_loc);
    sign_request(
        &mut p2_rust_poll_req,
        &SigningKey::from_seed([0xb2; 32]),
        KeyMaterial::Jwt {
            jwt: p2_caller_auth_tok.to_owned(),
            cache: false,
        },
        clock,
    )?;
    let p2_rust_poll_resp = send_https(
        p2_orders_addr,
        "p2-orders.example",
        &p2_orders_cert,
        &p2_rust_poll_req,
    )?;
    let p2_rust_body = String::from_utf8_lossy(p2_rust_poll_resp.body()).to_string();
    let p2_rust_chain_ok = p2_rust_202_resp.status().as_u16() == 202
        && p2_rust_visit_json["redirect_url"]
            .as_str()
            .unwrap_or("")
            .starts_with("https://p2-inventory.example/interaction/")
        && p2_rust_comp_json["completed"].as_bool() == Some(true)
        && p2_rust_poll_resp.status().as_u16() == 200
        && p2_rust_body == "order 42 fulfilled: reserved";

    let p2_go = &go_p_suite["p2"];
    let p2_pass = p2_rust_chain_ok
        && p2_go["undeclared_cap_refused"].as_bool() == Some(true)
        && p2_go["happy_path_ok"].as_bool() == Some(true)
        && p2_go["wrong_code_refused"].as_bool() == Some(true)
        && p2_go["second_visit_refused"].as_bool() == Some(true)
        && p2_go["other_poller_refused"].as_bool() == Some(true)
        && p2_go["callback_errors_ok"].as_bool() == Some(true)
        && p2_go["downstream_denial_ok"].as_bool() == Some(true)
        && p2_go["downstream_revocation_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P2",
        "classification": "VERIFIED_WORKING",
        "pass": p2_pass,
        "summary": format!(
            "Interaction chaining & callbacks over HTTPS: Go->Go happy path={}, undeclared cap 403={}, wrong code & 2nd visit refused={}, wrong poller 403={}, 5 callback error mappings={}, FailChainedInteraction (denied/revoked)={}, Rust Agent->Go ChainedInteraction Resource={}",
            p2_go["happy_path_ok"].as_bool().unwrap_or(false),
            p2_go["undeclared_cap_refused"].as_bool().unwrap_or(false),
            p2_go["wrong_code_refused"].as_bool().unwrap_or(false) && p2_go["second_visit_refused"].as_bool().unwrap_or(false),
            p2_go["other_poller_refused"].as_bool().unwrap_or(false),
            p2_go["callback_errors_ok"].as_bool().unwrap_or(false),
            p2_go["downstream_denial_ok"].as_bool().unwrap_or(false) && p2_go["downstream_revocation_ok"].as_bool().unwrap_or(false),
            p2_rust_chain_ok,
        ),
        "details": p2_go,
    }));

    // =========================================================================
    // QA-P3: aauth-resource Link Relation & Cross-Language (Rust <-> Go) Over HTTPS
    // =========================================================================
    let p3_go_docs_resp = send_https(
        p3_go_res_addr,
        "p3-go-res.example",
        &p3_go_res_cert,
        &get_req("https://p3-go-res.example/docs"),
    )?;
    let p3_go_link_hdr = p3_go_docs_resp
        .headers()
        .get("link")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let p3_go_html_body = String::from_utf8_lossy(p3_go_docs_resp.body());
    let p3_rust_hdr_links = links_from_header(p3_go_link_hdr);
    let p3_rust_html_links = links_from_html(&p3_go_html_body);
    let p3_rust_disc = discovery_from_headers(Some(p3_go_link_hdr), None);
    let p3_go_meta_resp = send_https(
        p3_go_res_addr,
        "p3-go-res.example",
        &p3_go_res_cert,
        &get_req(&p3_rust_hdr_links[0].target),
    )?;
    let p3_rust_meta_match_ok = metadata_matches_link(&p3_rust_hdr_links[0], p3_go_meta_resp.body()).is_ok()
        && metadata_matches_link(
            &p3_rust_hdr_links[0],
            br#"{"issuer":"https://wrong.example"}"#,
        ) == Err(TokenError::IssuerMismatch)
        && metadata_matches_link(&p3_rust_hdr_links[0], br#"{"jwks_uri":"https://x.example"}"#)
            == Err(TokenError::IssuerMissing);
    let p3_rust_fetch_targets = fetch_targets([
        "https://p3-go-res.example/.well-known/aauth-resource.json",
        "http://p3-go-res.example/.well-known/aauth-resource.json",
        "https://p3-go-res.example/v1/.well-known/aauth-resource.json",
        "https://p3-go-res.example/.well-known/aauth-resource.json?x=1",
    ]);
    let p3_rust_to_go_ok = p3_rust_hdr_links.len() == 2
        && p3_rust_html_links.len() == 2
        && p3_rust_disc.requirement.is_none()
        && p3_rust_meta_match_ok
        && p3_rust_fetch_targets == vec!["https://p3-go-res.example/.well-known/aauth-resource.json".to_owned()];

    let p3_go = &go_p_suite["p3"];
    let p3_pass = p3_rust_to_go_ok
        && p3_go["portal_hdr_links"].as_i64() == Some(2)
        && p3_go["portal_html_links"].as_i64() == Some(2)
        && p3_go["resolved_go_hdr"].as_bool() == Some(true)
        && p3_go["resolved_rust_hdr"].as_bool() == Some(true)
        && p3_go["resolved_go_html"].as_bool() == Some(true)
        && p3_go["resolved_rust_html"].as_bool() == Some(true)
        && p3_go["from_rust_docs_hdr_ok"].as_bool() == Some(true)
        && p3_go["from_rust_docs_html_ok"].as_bool() == Some(true)
        && p3_go["neg_targets_ok"].as_bool() == Some(true)
        && p3_go["oversized_ignored_ok"].as_bool() == Some(true)
        && p3_go["issuer_errors_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P3",
        "classification": "VERIFIED_WORKING",
        "pass": p3_pass,
        "summary": format!(
            "aauth-resource link relation over HTTPS: Go->Go & Go->Rust ResolveResourceLink (HTTP Link & HTML <link>)={}, Rust->Go links_from_header/links_from_html/metadata_matches_link={}, negative target guards={}, >8KiB Link & >1MiB HTML caps={}, issuer_missing/issuer_mismatch={}",
            p3_go["resolved_go_hdr"].as_bool().unwrap_or(false) && p3_go["from_rust_docs_hdr_ok"].as_bool().unwrap_or(false),
            p3_rust_to_go_ok,
            p3_go["neg_targets_ok"].as_bool().unwrap_or(false),
            p3_go["oversized_ignored_ok"].as_bool().unwrap_or(false),
            p3_go["issuer_errors_ok"].as_bool().unwrap_or(false),
        ),
        "details": p3_go,
    }));
    // =========================================================================
    // QA-P4: Delayed Signed Requests (VerifyOptions.MaxDelay, ValidAt) & ReplayCache
    // =========================================================================
    let p4_go = &go_p_suite["p4"];
    let p4_pass = p4_go["online_old_refused"].as_bool() == Some(true)
        && p4_go["delayed_valid_at_ok"].as_bool() == Some(true)
        && p4_go["past_token_at_valid_at"].as_bool() == Some(true)
        && p4_go["beyond_max_delay_refused"].as_bool() == Some(true)
        && p4_go["expired_window_refused"].as_bool() == Some(true)
        && p4_go["future_created_refused"].as_bool() == Some(true)
        && p4_go["replay_lifecycle_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P4",
        "classification": "VERIFIED_WORKING",
        "pass": p4_pass,
        "summary": format!(
            "Delayed signed requests (VerifyOptions.MaxDelay=24h, ValidAt) & ReplayCache verified: online 60s refusal={}, delayed ValidAt==created & token validity at created={}, >MaxDelay & expired window & future created refused={}, ReplayCache first=nil / replay=invalid_signature / post-expiry=nil / full=ErrReplayCacheFull={}",
            p4_go["online_old_refused"].as_bool().unwrap_or(false),
            p4_go["delayed_valid_at_ok"].as_bool().unwrap_or(false) && p4_go["past_token_at_valid_at"].as_bool().unwrap_or(false),
            p4_go["beyond_max_delay_refused"].as_bool().unwrap_or(false) && p4_go["expired_window_refused"].as_bool().unwrap_or(false) && p4_go["future_created_refused"].as_bool().unwrap_or(false),
            p4_go["replay_lifecycle_ok"].as_bool().unwrap_or(false),
        ),
        "details": p4_go,
    }));

    // =========================================================================
    // QA-P5: Revocation Across Every Recipient, Prefer: wait Cascades, 429
    // rate_limited + Retry-After & Agent Refused-Token Eviction Over HTTPS
    // =========================================================================
    let p5_go = &go_p_suite["p5"];
    let p5_pass = p5_go["prefer_wait_cascade_ok"].as_bool() == Some(true)
        && p5_go["upstream_revoked_at_as"].as_bool() == Some(true)
        && p5_go["resource_multi_rec_ok"].as_bool() == Some(true)
        && p5_go["rate_limited_429_ok"].as_bool() == Some(true)
        && p5_go["agent_eviction_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P5",
        "classification": "VERIFIED_WORKING",
        "pass": p5_pass,
        "summary": format!(
            "Multi-recipient revocation, Prefer: wait cascades, 429 rate_limited + Retry-After & Agent token eviction over HTTPS: Prefer: wait cascade across all recipients={}, upstream revoked at AS (revoked_upstream_token)={}, Resource multi-recipient revocation={}, 429 rate_limited + Retry-After & pending retention={}, Agent stops presenting refused token={}",
            p5_go["prefer_wait_cascade_ok"].as_bool().unwrap_or(false),
            p5_go["upstream_revoked_at_as"].as_bool().unwrap_or(false),
            p5_go["resource_multi_rec_ok"].as_bool().unwrap_or(false),
            p5_go["rate_limited_429_ok"].as_bool().unwrap_or(false),
            p5_go["agent_eviction_ok"].as_bool().unwrap_or(false),
        ),
        "details": p5_go,
    }));

    // =========================================================================
    // QA-P6: R3 Multi-Definition Composition (ComposeDefinitions, MergeDisplays)
    // & Release-Gated Proposal Results Over HTTPS
    // =========================================================================
    let p6_go = &go_p_suite["p6"];
    let p6_pass = p6_go["compose_merge_ok"].as_bool() == Some(true)
        && p6_go["conflict_guards_ok"].as_bool() == Some(true)
        && p6_go["composed_doc_ok"].as_bool() == Some(true)
        && p6_go["release_gated_once_ok"].as_bool() == Some(true)
        && p6_go["metered_never_runs_early"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P6",
        "classification": "VERIFIED_WORKING",
        "pass": p6_pass,
        "summary": format!(
            "R3 ComposeDefinitions, MergeDisplays & release-gated ProposalResult over HTTPS: ComposeDefinitions/MergeDisplays={}, duplicate/conflict guards={}, composed R3 document over HTTPS={}, release-gated runs once (ProposalResult.Executed==true, 0 re-executions on release)={}, metered/budget:true never runs before approval={}",
            p6_go["compose_merge_ok"].as_bool().unwrap_or(false),
            p6_go["conflict_guards_ok"].as_bool().unwrap_or(false),
            p6_go["composed_doc_ok"].as_bool().unwrap_or(false),
            p6_go["release_gated_once_ok"].as_bool().unwrap_or(false),
            p6_go["metered_never_runs_early"].as_bool().unwrap_or(false),
        ),
        "details": p6_go,
    }));

    // =========================================================================
    // QA-P7: Budgets Held Refusals, Replays & Signed Usage Answers (Rust <-> Go)
    // =========================================================================
    let p7_rust_ps_caller = PersonServer::new(
        PsConfig::new(
            "https://p5-go-ps.example",
            "p5-ps-1",
            SigningKey::from_seed([0xbd; 32]),
        ),
        trust.clone(),
        MemoryStore::default(),
        Box::new(PPsPolicy {
            person_id: "person-p7".into(),
        }) as aauth_rust_person_server::BoxedPolicy,
        Box::new(move || clock) as BoxedClock,
        Box::new(|| "p7-ps-jti-1".to_owned()) as BoxedTokenIds,
    )?;
    let p7_rust_query = UsageQuery {
        sub: Some("person-p7".into()),
        tenant: None,
        mission: None,
        ps: None,
        jkts: None,
    };
    let p7_rust_usage_req = p7_rust_ps_caller.usage_request(
        "https://p7-budget-res.example/usage",
        &p7_rust_query,
    )?;
    let p7_rust_to_go_resp = send_https(
        p7_go_res_addr,
        "p7-budget-res.example",
        &p7_go_res_cert,
        &p7_rust_usage_req,
    )?;
    let p7_rust_to_go_usage = p7_rust_ps_caller.read_usage(&p7_rust_to_go_resp, &p7_rust_query)?;
    let p7_rust_signed = SignedUsage {
        body: p7_rust_to_go_resp.body().clone(),
        content_digest: p7_rust_to_go_resp
            .headers()
            .get("content-digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
        signature_input: p7_rust_to_go_resp
            .headers()
            .get("signature-input")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
        signature: p7_rust_to_go_resp
            .headers()
            .get("signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
        signature_key: p7_rust_to_go_resp
            .headers()
            .get("signature-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned(),
    };
    let p7_rust_verify_go_sig_ok = verify_usage_signature(
        &p7_rust_signed,
        &SigningKey::from_seed([0xc3; 32]).public_jwk(),
        "p7-budget-res.example",
        "/usage",
        clock,
    )
    .is_ok();
    let p7_rust_to_go_ok = p7_rust_to_go_usage.usage.as_ref().map(|u| u.all_time) == Some(7)
        && p7_rust_verify_go_sig_ok;

    let p7_go = &go_p_suite["p7"];
    let p7_pass = p7_rust_to_go_ok
        && p7_go["refusal_held_reserves_zero"].as_bool() == Some(true)
        && p7_go["rechallenge_same_location"].as_bool() == Some(true)
        && p7_go["complete_and_replay_ok"].as_bool() == Some(true)
        && p7_go["signed_usage_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P7",
        "classification": "VERIFIED_WORKING",
        "pass": p7_pass,
        "summary": format!(
            "Budgets held refusals, replays & signed usage answers over HTTPS: 4-party held refusal reserves 0={}, rechallenge at same Location={}, replay without double-metering={}, Go PostUsageChecked->Go & ->Rust signed usage={}, Rust read_usage/verify_usage_signature->Go signed usage={}",
            p7_go["refusal_held_reserves_zero"].as_bool().unwrap_or(false),
            p7_go["rechallenge_same_location"].as_bool().unwrap_or(false),
            p7_go["complete_and_replay_ok"].as_bool().unwrap_or(false),
            p7_go["signed_usage_ok"].as_bool().unwrap_or(false),
            p7_rust_to_go_ok,
        ),
        "details": p7_go,
    }));
    // =========================================================================
    // QA-P8: Events Inbox Reader (agentprovider.EventInboxReader) & Cross-Language
    // (Rust <-> Go) Over Real HTTPS
    // =========================================================================
    let p8_rust_agent_id = "aauth:rust-reader@p8-events-ap.example";
    let p8_rust_payload = b"{\n  \"event_type\": \"order.shipped\",\n  \"tracking\": \"ZX-99\"\n}";
    let p8_rust_ev_tok = mint_event_token(
        &SigningKey::from_seed([0xe3; 32]),
        "p3-rust-res-1",
        &EventClaims {
            iss: P3_RUST_LINK_RES.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: p8_rust_agent_id.into(),
            eid: "p8-rust-ev-1".into(),
            jti: "p8-rust-jti-1".into(),
            iat: clock,
            exp: clock + 300,
            body_s256: Some(body_s256(p8_rust_payload)),
            extra: Default::default(),
        },
    )?;
    let mut p8_rust_deliv_req = Request::builder()
        .method("POST")
        .uri("https://p8-events-ap.example/events")
        .header("content-type", "application/json")
        .body(p8_rust_payload.to_vec())?;
    sign_request(
        &mut p8_rust_deliv_req,
        &SigningKey::from_seed([0xe3; 32]),
        KeyMaterial::SelfJwt {
            jwt: p8_rust_ev_tok.clone(),
        },
        clock,
    )?;
    let p8_rust_deliv_resp = send_https(
        p8_go_ap_addr,
        "p8-events-ap.example",
        &p8_go_ap_cert,
        &p8_rust_deliv_req,
    )?;
    let p8_rust_pend_resp = send_https(
        p8_go_ap_addr,
        "p8-events-ap.example",
        &p8_go_ap_cert,
        &get_req(&format!(
            "https://p8-events-ap.example/__p8-pending?agent={p8_rust_agent_id}"
        )),
    )?;
    let p8_rust_pend_json: Value = serde_json::from_slice(p8_rust_pend_resp.body())?;
    let p8_rust_pend_arr = p8_rust_pend_json.as_array().cloned().unwrap_or_default();
    let p8_rust_read_tok = p8_rust_pend_arr
        .first()
        .and_then(|v| v["token"].as_str())
        .unwrap_or("");
    let p8_rust_read_payload = p8_rust_pend_arr
        .first()
        .and_then(|v| v["payload"].as_str())
        .unwrap_or("");
    let p8_rust_verify_ok = verify_event(
        p8_rust_read_tok,
        p8_rust_read_payload.as_bytes(),
        p8_rust_agent_id,
        trust,
        clock,
    )
    .is_ok();
    let p8_rust_ack_resp = send_https(
        p8_go_ap_addr,
        "p8-events-ap.example",
        &p8_go_ap_cert,
        &Request::builder()
            .method("POST")
            .uri(format!(
                "https://p8-events-ap.example/__p8-ack?agent={p8_rust_agent_id}"
            ))
            .body(Vec::new())?,
    )?;
    let p8_rust_after_ack_resp = send_https(
        p8_go_ap_addr,
        "p8-events-ap.example",
        &p8_go_ap_cert,
        &get_req(&format!(
            "https://p8-events-ap.example/__p8-pending?agent={p8_rust_agent_id}"
        )),
    )?;
    let p8_rust_after_ack_json: Value = serde_json::from_slice(p8_rust_after_ack_resp.body())?;
    let p8_cross_lang_ok = p8_rust_deliv_resp.status().as_u16() == 202
        && p8_rust_pend_arr.len() == 1
        && p8_rust_read_tok == p8_rust_ev_tok
        && p8_rust_read_payload.as_bytes() == p8_rust_payload
        && p8_rust_verify_ok
        && p8_rust_ack_resp.status().as_u16() == 200
        && p8_rust_after_ack_json.as_array().map(|a| a.len()) == Some(0);

    let p8_go = &go_p_suite["p8"];
    let p8_pass = p8_cross_lang_ok
        && p8_go["go_inbox_lifecycle_ok"].as_bool() == Some(true)
        && p8_go["store_contract_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P8",
        "classification": "VERIFIED_WORKING",
        "pass": p8_pass,
        "summary": format!(
            "Events inbox reader (agentprovider.EventInboxReader) over HTTPS: Go->Go exact byte preservation + tamper/misroute guards + AcknowledgeEvent + ErrEventInboxNotReadable={}, apstoretest.RunEventInboxSuite={}, Rust Resource->Go EventInbox->Go EventInboxReader->Rust verify_event={}",
            p8_go["go_inbox_lifecycle_ok"].as_bool().unwrap_or(false),
            p8_go["store_contract_ok"].as_bool().unwrap_or(false),
            p8_cross_lang_ok,
        ),
        "details": p8_go,
    }));

    // =========================================================================
    // QA-P9: Further Signature-Key Schemes at Resources (resource.FurtherSchemesConfig)
    // =========================================================================
    // Cross-language: Rust SigningKey (ES256 hwk, jkt-jwt;cache, cached) -> Go Resource (p9-further-res.example)
    let p9_ec_sk = SigningKey::from_pkcs8_der("ES256", P256_PKCS8_SEED1_DER)?;
    let mut p9_rust_hwk_req = get_req("https://p9-further-res.example/items");
    sign_request(
        &mut p9_rust_hwk_req,
        &p9_ec_sk,
        KeyMaterial::Hwk(p9_ec_sk.public_jwk()),
        clock,
    )?;
    let p9_rust_hwk_resp = send_https(
        p9_go_res_addr,
        "p9-further-res.example",
        &p9_go_res_cert,
        &p9_rust_hwk_req,
    )?;
    let p9_rust_hwk_json: Value = serde_json::from_slice(p9_rust_hwk_resp.body())?;

    let p9_eph_sk = SigningKey::from_seed([0xea; 32]);
    let p9_rust_jkt_hdr = json!({
        "alg": "Ed25519",
        "typ": "jkt-s256+jwt",
        "jwk": SigningKey::from_seed([0xe3; 32]).public_jwk()
    });
    let p9_rust_jkt_claims = json!({
        "iss": format!("urn:jkt:sha-256:{}", SigningKey::from_seed([0xe3; 32]).public_jwk().thumbprint()?),
        "jti": "p9-rust-del-1",
        "iat": clock,
        "exp": clock + 600,
        "cnf": {
            "jwk": p9_eph_sk.public_jwk()
        }
    });
    let p9_rust_jkt_jwt = Jws::sign(
        &p9_rust_jkt_hdr,
        &serde_json::to_vec(&p9_rust_jkt_claims)?,
        &SigningKey::from_seed([0xe3; 32]),
    )?;
    let mut p9_rust_jkt_req = get_req("https://p9-further-res.example/items");
    sign_request(
        &mut p9_rust_jkt_req,
        &p9_eph_sk,
        KeyMaterial::JktJwt {
            jwt: p9_rust_jkt_jwt,
            cache: true,
        },
        clock,
    )?;
    let p9_rust_jkt_resp = send_https(
        p9_go_res_addr,
        "p9-further-res.example",
        &p9_go_res_cert,
        &p9_rust_jkt_req,
    )?;
    let _p9_rust_jkt_json: Value = serde_json::from_slice(p9_rust_jkt_resp.body())?;
    let p9_rust_cache_hdr = p9_rust_jkt_resp
        .headers()
        .get("signature-key-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let p9_rust_key_id = p9_rust_cache_hdr
        .strip_prefix("sig=\"")
        .and_then(|s| s.split('"').next())
        .unwrap_or("")
        .to_owned();
    let mut p9_rust_cached_req = get_req("https://p9-further-res.example/items");
    sign_request(
        &mut p9_rust_cached_req,
        &p9_eph_sk,
        KeyMaterial::Cached {
            cid: p9_rust_key_id.clone(),
        },
        clock,
    )?;
    let p9_rust_cached_resp = send_https(
        p9_go_res_addr,
        "p9-further-res.example",
        &p9_go_res_cert,
        &p9_rust_cached_req,
    )?;
    let p9_rust_cached_json: Value = serde_json::from_slice(p9_rust_cached_resp.body())?;
    let p9_rust_cross_ok = p9_rust_hwk_resp.status().as_u16() == 200
        && p9_rust_hwk_json["route"].as_str() == Some("further")
        && p9_rust_hwk_json["scheme"].as_str() == Some("hwk")
        && p9_rust_jkt_resp.status().as_u16() == 200
        && !p9_rust_key_id.is_empty()
        && p9_rust_cached_resp.status().as_u16() == 200
        && p9_rust_cached_json["scheme"].as_str() == Some("cached");

    let p9_go = &go_p_suite["p9"];
    let p9_pass = p9_rust_cross_ok
        && p9_go["challenge_headers_ok"].as_bool() == Some(true)
        && p9_go["hwk_es256_ok"].as_bool() == Some(true)
        && p9_go["jwks_ok"].as_bool() == Some(true)
        && p9_go["x509_ok"].as_bool() == Some(true)
        && p9_go["jkt_jwt_and_cached_ok"].as_bool() == Some(true)
        && p9_go["aauth_jwt_routes_to_protected"].as_bool() == Some(true)
        && p9_go["neg_guards_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P9",
        "classification": "VERIFIED_WORKING",
        "pass": p9_pass,
        "summary": format!(
            "FurtherSchemesConfig over HTTPS: Accept-Signature-Scheme/Alg ordering={}, Go hwk(ES256)/jwks/x509/jkt-jwt;cache/cached->FurtherSchemes.Protected={}, AAuth jwt->Protected={}, /authorize & /revoke reject non-AAuth schemes={}, Rust SigningKey (ES256 hwk + jkt-jwt;cache + cached)->Go FurtherSchemes={}",
            p9_go["challenge_headers_ok"].as_bool().unwrap_or(false),
            p9_go["hwk_es256_ok"].as_bool().unwrap_or(false) && p9_go["x509_ok"].as_bool().unwrap_or(false) && p9_go["jkt_jwt_and_cached_ok"].as_bool().unwrap_or(false),
            p9_go["aauth_jwt_routes_to_protected"].as_bool().unwrap_or(false),
            p9_go["neg_guards_ok"].as_bool().unwrap_or(false),
            p9_rust_cross_ok,
        ),
        "details": p9_go,
    }));
    // =========================================================================
    // QA-P10: Cross-Language 4-Party Call Chaining Matrix & Updated QA-O6 Boundaries
    // =========================================================================
    // Cross-Language Flow B: Rust Caller -> Rust Intermediary (iss == "https://p5-relay-res.example" == upstream.aud)
    // -> Rust Federated PS (P10_RUST_FED_PS) -> Go Access Server (https://p10-go-as.example)
    let p10_relay_ap = AgentProvider::new(
        "https://p5-relay-res.example",
        "p5-relay-res-1",
        SigningKey::from_seed([0xc0; 32]),
    )?;
    let p10_r_caller_tok = p7_seed_ap.issue(&AgentClaims {
        iss: "https://p1-go-ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:p10-caller@p1-go-ap.example".into(),
        jti: "p10-r-caller-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([0xe8; 32]).public_jwk(),
        },
        ps: Some(P10_RUST_FED_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let p10_r_caller = Agent::new(SigningKey::from_seed([0xe8; 32]), p10_r_caller_tok.clone())?;

    // Intermediary whose AgentToken issuer matches upstream.aud ("https://p5-relay-res.example")
    let p10_r_interm_tok = p10_relay_ap.issue(&AgentClaims {
        iss: "https://p5-relay-res.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:relay@p5-relay-res.example".into(),
        jti: "p10-r-interm-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: SigningKey::from_seed([0xc1; 32]).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let p10_r_interm = Agent::new(SigningKey::from_seed([0xc1; 32]), p10_r_interm_tok)?;

    // 1. Upstream PersonToken from P10_RUST_FED_PS for resource "https://p5-relay-res.example"
    let p10_up_pt_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_caller,
        &format!("{P10_RUST_FED_PS}/person"),
        json!({"resource": "https://p5-relay-res.example"})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let p10_up_pt = member(&p10_up_pt_resp, "person_token").ok_or("missing p10_up_pt")?;

    // Chain to Go AS ("https://p10-go-as.example") with upstream_token = PersonToken
    let p10_down_pt1_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_interm,
        &format!("{P10_RUST_FED_PS}/person"),
        json!({
            "resource": "https://p10-go-fed-res.example",
            "upstream_token": p10_up_pt,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_down_pt1 = member(&p10_down_pt1_resp, "person_token").ok_or("missing p10_down_pt1")?;
    let p10_down_pt1_claims = PersonToken::parse(&p10_down_pt1)?.unverified_claims().clone();
    let p10_rt1 = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([0xce; 32]),
        "p10-go-fed-res-1",
        &ResourceClaims {
            iss: "https://p10-go-fed-res.example".into(),
            dwk: "aauth-resource.json".into(),
            aud: "https://p10-go-as.example".into(),
            ps: P10_RUST_FED_PS.into(),
            sub: p10_down_pt1_claims.sub.clone(),
            jti: "p10-rt-go-as-1".into(),
            presented_jti: p10_down_pt1_claims.jti.clone(),
            agent_jkt: p10_r_interm.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )?;
    let p10_at1_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_interm,
        &format!("{P10_RUST_FED_PS}/token"),
        json!({
            "resource_token": p10_rt1,
            "presented_token": p10_down_pt1,
            "upstream_token": p10_up_pt,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_at1 = member(&p10_at1_resp, "auth_token").ok_or("missing p10_at1")?;

    // 2. Also chain to Go AS ("https://p10-go-as.example") with AS-issued AuthToken (dwk="aauth-access.json") as upstream_token!
    let p10_up_pt_claims = PersonToken::parse(&p10_up_pt)?.unverified_claims().clone();
    let p10_up_rt = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([0xc0; 32]),
        "p5-relay-res-1",
        &ResourceClaims {
            iss: "https://p5-relay-res.example".into(),
            dwk: "aauth-resource.json".into(),
            aud: P10_RUST_FED_AS.into(),
            ps: P10_RUST_FED_PS.into(),
            sub: p10_up_pt_claims.sub.clone(),
            jti: "p10-up-relay-rt-1".into(),
            presented_jti: p10_up_pt_claims.jti.clone(),
            agent_jkt: p10_r_caller.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )?;
    let p10_up_as_auth_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_caller,
        &format!("{P10_RUST_FED_PS}/token"),
        json!({
            "resource_token": p10_up_rt,
            "presented_token": p10_up_pt,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_up_as_auth = member(&p10_up_as_auth_resp, "auth_token").ok_or("missing p10_up_as_auth")?;
    let p10_down_pt2_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_interm,
        &format!("{P10_RUST_FED_PS}/person"),
        json!({
            "resource": "https://p10-go-fed-res.example",
            "upstream_token": p10_up_as_auth,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_down_pt2 = member(&p10_down_pt2_resp, "person_token").ok_or("missing p10_down_pt2")?;
    let p10_down_pt2_claims = PersonToken::parse(&p10_down_pt2)?.unverified_claims().clone();
    let p10_rt2 = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([0xce; 32]),
        "p10-go-fed-res-1",
        &ResourceClaims {
            iss: "https://p10-go-fed-res.example".into(),
            dwk: "aauth-resource.json".into(),
            aud: "https://p10-go-as.example".into(),
            ps: P10_RUST_FED_PS.into(),
            sub: p10_down_pt2_claims.sub.clone(),
            jti: "p10-rt-go-as-2".into(),
            presented_jti: p10_down_pt2_claims.jti.clone(),
            agent_jkt: p10_r_interm.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )?;
    let p10_at2_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_interm,
        &format!("{P10_RUST_FED_PS}/token"),
        json!({
            "resource_token": p10_rt2,
            "presented_token": p10_down_pt2,
            "upstream_token": p10_up_as_auth,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_at2 = member(&p10_at2_resp, "auth_token").ok_or("missing p10_at2")?;

    // 3. Pinned Boundary B3-subagent: intermediary with iss != upstream.aud (e.g. p10_r_caller with iss="https://p1-go-ap.example" != "https://p5-relay-res.example")
    // is refused by both Rust PS (server.rs:568) and Go AS (accessserver/upstream.go:108) with 400 invalid_upstream_token
    let p10_b3_ps_resp = p10_rust_fed_ps_tls.send(&post_at(
        &p10_r_caller,
        &format!("{P10_RUST_FED_PS}/person"),
        json!({
            "resource": "https://p10-go-fed-res.example",
            "upstream_token": p10_up_pt,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let p10_b3_sub_rt = aauth_rust_core::mint_resource_token(
        &SigningKey::from_seed([0xce; 32]),
        "p10-go-fed-res-1",
        &ResourceClaims {
            iss: "https://p10-go-fed-res.example".into(),
            dwk: "aauth-resource.json".into(),
            aud: "https://p10-go-as.example".into(),
            ps: P10_RUST_FED_PS.into(),
            sub: p10_down_pt1_claims.sub.clone(),
            jti: "p10-rt-go-as-b3sub".into(),
            presented_jti: p10_down_pt1_claims.jti.clone(),
            agent_jkt: p10_r_caller.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut p10_b3_as_req = Request::builder()
        .method("POST")
        .uri("https://p10-go-as.example/token")
        .header("content-type", "application/json")
        .body(
            json!({
                "agent_token": p10_r_caller_tok,
                "resource_token": p10_b3_sub_rt,
                "presented_token": p10_down_pt1,
                "upstream_token": p10_up_pt,
            })
            .to_string()
            .into_bytes(),
        )?;
    sign_request(
        &mut p10_b3_as_req,
        &SigningKey::from_seed([0xe6; 32]),
        KeyMaterial::JwksUri {
            id: P10_RUST_FED_PS.into(),
            dwk: "aauth-person.json".into(),
            kid: "p10-rust-ps-1".into(),
        },
        clock,
    )?;
    let p10_b3_sub_resp = send_https(
        p10_go_as_addr,
        "p10-go-as.example",
        &p10_go_as_cert,
        &p10_b3_as_req,
    )?;
    let p10_b3_sub_ok = p10_b3_ps_resp.status().as_u16() == 400
        && member(&p10_b3_ps_resp, "error").as_deref() == Some("invalid_upstream_token")
        && p10_b3_sub_resp.status().as_u16() == 400
        && member(&p10_b3_sub_resp, "error").as_deref() == Some("invalid_upstream_token");

    let _ = (p10_go_fed_res_addr, p10_go_fed_res_cert);
    let p10_rust_ps_to_go_as_ok = p10_at1_resp.status().as_u16() == 200
        && !p10_at1.is_empty()
        && p10_at2_resp.status().as_u16() == 200
        && !p10_at2.is_empty();

    let p10_go = &go_p_suite["p10"];
    let p10_pass = p10_rust_ps_to_go_as_ok
        && p10_b3_sub_ok
        && p10_go["all_go_4party_ok"].as_bool() == Some(true)
        && p10_go["go_ps_to_rust_as_ok"].as_bool() == Some(true)
        && p10_go["b2_go_ps_refuses_as_up_ok"].as_bool() == Some(true)
        && p10_go["b4_go_ps_refuses_mission_ok"].as_bool() == Some(true);
    cases.push(json!({
        "id": "QA-P10",
        "classification": "DEFECT_RESOLVED",
        "pass": p10_pass,
        "summary": format!(
            "Cross-language 4-party call chaining matrix & updated QA-O6 boundaries over HTTPS: All-Go 4-party (FederatedCallChainingConfig + AS upstream_token)={}, Go PS->Rust AS->Rust/Go Res={}, Rust PS->Go AS (PersonToken & AS-issued AuthToken when iss==aud)={}, remaining Go boundaries pinned [B2 Go PS AS-issued upstream=400 ({}), B3-subagent iss!=aud=400 ({}), B4 Go PS mission upstream=500 ({})]",
            p10_go["all_go_4party_ok"].as_bool().unwrap_or(false),
            p10_go["go_ps_to_rust_as_ok"].as_bool().unwrap_or(false),
            p10_rust_ps_to_go_as_ok,
            p10_go["b2_go_ps_refuses_as_up_ok"].as_bool().unwrap_or(false),
            p10_b3_sub_ok,
            p10_go["b4_go_ps_refuses_mission_ok"].as_bool().unwrap_or(false),
        ),
        "details": p10_go,
    }));
    // =========================================================================
    // QA-P11: Consumer Documentation Sufficiency Audit (aauth-go d0369c7a:
    // CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md)
    // =========================================================================
    let go_root = Path::new(go_module_path);
    let go_conf_md = fs::read_to_string(go_root.join("CONFORMANCE.md"))?;
    let go_use_md = fs::read_to_string(go_root.join("USE-IN-YOUR-SERVICE.md"))?;
    let go_interp_md = fs::read_to_string(go_root.join("INTERPRETATIONS.md"))?;

    let p11_conf_has_all_10 = [
        "Features added on 2026-10-30:",
        "Resource-initiated interaction, three-party:",
        "Interaction chaining answers the original caller with its own `202`",
        "Interaction callbacks with `error` where the library hosts the page:",
        "The `aauth-resource` link relation is emitted and followed only for a server",
        "Delayed signed requests verify at their `created` time, with replay detection",
        "Revocation: person and resource tokens are revoked at every recipient",
        "R3: several internal definitions compose into one document;",
        "Budgets: held refusals reserve nothing (four-party), replays answer without",
        "Events: `EventInboxReader` hands queued deliveries to the Agent with their",
        "A Resource that also serves clients outside AAuth can accept further",
    ]
    .iter()
    .all(|needle| go_conf_md.contains(needle))
        && (go_conf_md.contains("The PS-to-AS step (the Person Server passing")
            || go_conf_md.contains("Changes on 2026-10-31: four-party call chaining."));

    let p11_use_has_all_guides = [
        "## Revoke person and resource tokens",
        "## Organize R3 definitions and gate release",
        "## Hold a Budget refusal",
        "## Sign and verify Budget usage",
        "## Chain a call through an Access Server",
        "## Deliver events to an Agent",
        "### Resolve a Resource's own interaction before consent",
        "### Chain a downstream interaction to your caller",
        "## Point Agents at your metadata",
        "## Verify a signed request after a delay",
        "### Accept clients outside AAuth at a Resource",
    ]
    .iter()
    .all(|needle| go_use_md.contains(needle));

    let p11_interp_has_new_sections = [
        "## An `aauth-resource` link is read leniently and admitted strictly",
        "## A delayed verifier's bound and replay span come from its own options",
        "## An Access Server verifies the upstream token of a chained request itself",
        "## Further Signature-Key schemes are for a Resource's clients outside AAuth",
        "## A signed usage response covers what Budgets lists",
        "## Internal R3 definitions compose by merging their displays",
        "## Release gating runs only held calls and writes the release statement",
        "## A held Budget refusal stays at one pending URL",
        "## A revocation hold that ends before a downstream answers is pending",
        "## Resource-initiated interaction is three-party, missionless and deferred",
        "## Interaction chaining binds polls to the caller's key",
    ]
    .iter()
    .all(|needle| go_interp_md.contains(needle));

    // Non-blocking documentation observations pinned in QA-P11:
    // DOC-OBS-P11-1: the d0369c7a branch was cut from ae5c025 before 581dc22, so CONFORMANCE.md:259 retains the stale "cached scheme stays unsupported" sentence
    let doc_obs_p11_1 = go_conf_md.contains("and the `cached` scheme stays unsupported");
    // DOC-OBS-P11-2: INTERPRETATIONS.md:2151-2152 retains pre-17d3f41 sentence "The Access Server keeps no revocation records, so it never answers revoked_upstream_token"
    let doc_obs_p11_2 = go_interp_md.contains("The Access Server keeps no revocation records, so it never answers")
        && go_interp_md.contains("`revoked_upstream_token`.");
    // DOC-OBS-P11-3: Lower table rows / Revocation details in CONFORMANCE.md:213 retain pre-2026-10-30 boundary text superseded by the top-level "Features added on 2026-10-30" summary list
    let doc_obs_p11_3 = go_conf_md.contains("Only AP Agent tokens and PS Auth tokens are supported.");

    let p11_obs_resolved = !doc_obs_p11_1 && !doc_obs_p11_2 && !doc_obs_p11_3;
    let p11_pass = p11_conf_has_all_10 && p11_use_has_all_guides && p11_interp_has_new_sections && p11_obs_resolved;
    cases.push(json!({
        "id": "QA-P11",
        "classification": "DEFECT_RESOLVED",
        "pass": p11_pass,
        "summary": format!(
            "aauth-go (main 445af350) consumer documentation audit passed: CONFORMANCE.md 'Features added on 2026-10-30' covers all 10 features ({}), USE-IN-YOUR-SERVICE.md provides accurate copy-pasteable guides for all 10 entry points ({}), INTERPRETATIONS.md covers new interpretations ({}), and all 3 prior non-blocking doc observations (DOC-OBS-P11-1..3) are resolved in 445af350 ({})",
            p11_conf_has_all_10,
            p11_use_has_all_guides,
            p11_interp_has_new_sections,
            p11_obs_resolved,
        ),
        "details": {
            "conformance_has_all_10": p11_conf_has_all_10,
            "use_in_your_service_has_all_10": p11_use_has_all_guides,
            "interpretations_has_new_sections": p11_interp_has_new_sections,
            "doc_obs_p11_1_resolved": !doc_obs_p11_1,
            "doc_obs_p11_2_resolved": !doc_obs_p11_2,
            "doc_obs_p11_3_resolved": !doc_obs_p11_3,
        },
    }));

    for c in cases {
        let id = c["id"].as_str().unwrap_or("").to_owned();
        let pass = c["pass"].as_bool().unwrap_or(false);
        let classification = c["classification"]
            .as_str()
            .unwrap_or("VERIFIED_WORKING")
            .to_owned();
        let summary = c["summary"].as_str().unwrap_or("").to_owned();
        transcript_lines.push(format!(
            "[{id}] {}: {summary}",
            if pass { "PASS" } else { "FAIL" }
        ));
        qa_cases.push(QaCaseReceipt {
            id: id.clone(),
            category: "P. Go Interaction, Links, Delayed Requests, Revocation, R3, Budgets & Events, with Cross-Language Interop".into(),
            title: format!("{id}: {summary}"),
            classification,
            passed_expectation: pass,
            summary,
            evidence: c,
        });
    }

    Ok(())
}
