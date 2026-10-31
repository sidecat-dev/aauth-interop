use crate::*;
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::{CallOutcome, RevocationDirectory};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::DeferredConfig as PsDeferredConfig;
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64_STD};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

const R3_RUST_AP: &str = "https://r3-rust-ap.example";
const R3_RUST_FED_PS: &str = "https://r3-rust-fed-ps.example";
const R3_RUST_AS: &str = "https://r3-rust-as.example";
const R3_RUST_INTERM_GO_AS: &str = "https://r3-rust-interm-go-as.example";
const R3_RUST_INTERM_RUST_AS: &str = "https://r3-rust-interm-rust-as.example";
const R3_RUST_DOWN_GO_AS: &str = "https://r3-rust-down-go-as.example";
const R3_RUST_DOWN_RUST_AS: &str = "https://r3-rust-down-rust-as.example";

const R3_GO_AP: &str = "https://r3-go-ap.example";
const R3_GO_FED_PS: &str = "https://r3-go-fed-ps.example";
const R3_GO_AS: &str = "https://r3-go-as.example";
const R3_GO_INTERM_GO_AS: &str = "https://r3-go-interm-go-as.example";
const R3_GO_INTERM_RUST_AS: &str = "https://r3-go-interm-rust-as.example";
const R3_GO_DOWN_GO_AS: &str = "https://r3-go-down-go-as.example";
const R3_GO_DOWN_RUST_AS: &str = "https://r3-go-down-rust-as.example";

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

fn register_r_host_with_go(
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
        return Err(format!("register_r_host_with_go failed for {host}: {res}").into());
    }
    Ok(())
}

fn decode_cert_pem(pem_str: &str) -> Result<Vec<u8>> {
    let mut b64 = String::new();
    for line in pem_str.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-----") && !trimmed.is_empty() {
            b64.push_str(trimmed);
        }
    }
    Ok(B64_STD.decode(b64)?)
}

fn discover_external(
    trust: &Trust,
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    issuer: &str,
    dwk: &str,
) -> Result<()> {
    let meta_req = get(&format!("{issuer}/.well-known/{dwk}"))?;
    let meta_resp = send_https(addr, host, cert, &meta_req)?;
    let jwks_req = get(&format!("{issuer}/.well-known/jwks.json"))?;
    let jwks_resp = send_https(addr, host, cert, &jwks_req)?;
    let snap = TrustedIssuerKeys::from_documents(issuer, dwk, meta_resp.body(), jwks_resp.body())?;
    trust.0.write().unwrap().insert((issuer.into(), dwk.into()), snap);
    Ok(())
}
#[derive(Clone)]
enum RFedRoute {
    RustTls(Arc<TlsServer>),
    GoExt {
        addr: SocketAddr,
        host: &'static str,
        cert: Vec<u8>,
    },
}

#[derive(Clone, Default)]
struct RMultiAsHttpsFederation {
    routes: Arc<Mutex<BTreeMap<String, RFedRoute>>>,
}
impl RMultiAsHttpsFederation {
    fn register_rust(&self, issuer: &str, tls: Arc<TlsServer>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), RFedRoute::RustTls(tls));
    }
    fn register_go(&self, issuer: &str, addr: SocketAddr, host: &'static str, cert: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), RFedRoute::GoExt { addr, host, cert });
    }
}
impl Federation for RMultiAsHttpsFederation {
    fn endpoint(&self, access_server: &str) -> std::result::Result<String, FederationError> {
        Ok(format!("{access_server}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        let uri_str = request.uri().to_string();
        let routes = self.routes.lock().unwrap().clone();
        for (issuer, route) in routes {
            if uri_str.starts_with(&issuer) {
                return match route {
                    RFedRoute::RustTls(tls) => tls.send(request).map_err(|_| FederationError),
                    RFedRoute::GoExt { addr, host, cert } => {
                        TlsServer::send_external(addr, host, &cert, request)
                            .map_err(|_| FederationError)
                    }
                };
            }
        }
        Err(FederationError)
    }
}

#[derive(Clone, Default)]
struct RMultiTargetRevocationDirectory {
    calls: Arc<Mutex<Vec<(String, String, i64)>>>,
    routes: Arc<Mutex<BTreeMap<String, (RFedRoute, String, String, String, [u8; 32], i64)>>>,
}
impl RMultiTargetRevocationDirectory {
    fn register_target(
        &self,
        recipient: &str,
        route: RFedRoute,
        caller_issuer: &str,
        caller_dwk: &str,
        caller_kid: &str,
        caller_seed: [u8; 32],
        clock: i64,
    ) {
        self.routes.lock().unwrap().insert(
            recipient.to_owned(),
            (
                route,
                caller_issuer.to_owned(),
                caller_dwk.to_owned(),
                caller_kid.to_owned(),
                caller_seed,
                clock,
            ),
        );
    }
}
impl RevocationDirectory for RMultiTargetRevocationDirectory {
    fn revoke(&self, recipient: &str, jti: &str, exp: i64) -> CallOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((recipient.to_owned(), jti.to_owned(), exp));
        let route_opt = self.routes.lock().unwrap().get(recipient).cloned();
        if let Some((route, caller_iss, caller_dwk, caller_kid, caller_seed, clk)) = route_opt {
            let body = json!({"jti": jti, "exp": exp}).to_string().into_bytes();
            if let Ok(mut req) = Request::builder()
                .method("POST")
                .uri(format!("{recipient}/revoke"))
                .header("content-type", "application/json")
                .body(body)
            {
                if sign_request(
                    &mut req,
                    &SigningKey::from_seed(caller_seed),
                    KeyMaterial::JwksUri {
                        id: caller_iss,
                        dwk: caller_dwk,
                        kid: caller_kid,
                    },
                    clk,
                )
                .is_ok()
                {
                    let _ = match route {
                        RFedRoute::RustTls(tls) => tls.send(&req),
                        RFedRoute::GoExt { addr, host, cert } => {
                            TlsServer::send_external(addr, host, &cert, &req)
                        }
                    };
                }
            }
        }
        CallOutcome::Recorded
    }
}

struct RPsPolicy {
    person_id: String,
    copy_upstream_sub: AtomicBool,
}
impl RPsPolicy {
    fn new(person_id: &str) -> Self {
        Self {
            person_id: person_id.to_owned(),
            copy_upstream_sub: AtomicBool::new(false),
        }
    }
}
impl Policy for RPsPolicy {
    fn bind_person(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: self.person_id.clone(),
            subject: format!("sub-{}-{}", self.person_id, req.resource),
            tenant: None,
        })
    }
    fn bind_upstream(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        if self.copy_upstream_sub.load(Ordering::SeqCst) {
            if let Some(up) = &req.upstream {
                return Ok(Person {
                    id: self.person_id.clone(),
                    subject: up.record.subject.clone(),
                    tenant: None,
                });
            }
        }
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
    fn authorize_upstream(
        &self,
        req: &AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: req.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, _req: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
    fn consent_upstream(&self, _req: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
}
struct RSharedPsPolicy(Arc<RPsPolicy>);
impl Policy for RSharedPsPolicy {
    fn bind_person(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        self.0.bind_person(req)
    }
    fn bind_upstream(&self, req: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        self.0.bind_upstream(req)
    }
    fn authorize(&self, req: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        self.0.authorize(req)
    }
    fn authorize_upstream(
        &self,
        req: &AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        self.0.authorize_upstream(req)
    }
    fn consent(&self, req: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        self.0.consent(req)
    }
    fn consent_upstream(&self, req: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        self.0.consent_upstream(req)
    }
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
            meta["missions_endpoint"] = json!(format!("{issuer}/missions"));
        }
        "aauth-access.json" => {
            meta["token_endpoint"] = json!(format!("{issuer}/token"));
        }
        "aauth-resource.json" => {
            meta["access_mode"] = json!("auth-token");
            meta["authorization_endpoint"] = json!(format!("{issuer}/authorize"));
            meta["scopes_supported"] = json!(["records.read"]);
            meta["scope_descriptions"] = json!({"records.read": "Read records"});
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

pub fn run_go_chaining_qa_cases(
    body: &Value,
    out_dir: &Path,
    go_module_path: &str,
    clock: i64,
    trust: &Trust,
    cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {
    let go_events_ap_addr: SocketAddr = body["go_events_ap_addr"]
        .as_str()
        .ok_or("missing go_events_ap_addr")?
        .parse()?;
    let go_events_ap_cert = hex_decode(
        body.get("go_events_ap_cert_hex")
            .and_then(Value::as_str)
            .ok_or("missing go_events_ap_cert_hex")?,
    )?;

    // Pre-seed Go R3 server keys in Rust Trust so Go-originated requests inside /__run-r-suite verify
    insert_manual_key(trust, R3_GO_AP, "aauth-agent.json", "r3-go-ap-1", 0xc1, None)?;
    insert_manual_key(trust, R3_GO_FED_PS, "aauth-person.json", "r3-go-ps-1", 0xc3, None)?;
    insert_manual_key(trust, R3_GO_AS, "aauth-access.json", "r3-go-as-1", 0xc4, None)?;
    insert_manual_key(
        trust,
        R3_GO_INTERM_GO_AS,
        "aauth-agent.json",
        "r3-go-ig-1",
        0xc5,
        None,
    )?;
    insert_manual_key(
        trust,
        R3_GO_INTERM_GO_AS,
        "aauth-resource.json",
        "r3-go-ig-1",
        0xc5,
        Some(R3_GO_AS),
    )?;
    insert_manual_key(
        trust,
        R3_GO_INTERM_RUST_AS,
        "aauth-agent.json",
        "r3-go-ir-1",
        0xc7,
        None,
    )?;
    insert_manual_key(
        trust,
        R3_GO_INTERM_RUST_AS,
        "aauth-resource.json",
        "r3-go-ir-1",
        0xc7,
        Some(R3_RUST_AS),
    )?;
    insert_manual_key(
        trust,
        R3_GO_DOWN_GO_AS,
        "aauth-resource.json",
        "r3-go-dg-1",
        0xc9,
        Some(R3_GO_AS),
    )?;
    insert_manual_key(
        trust,
        R3_GO_DOWN_RUST_AS,
        "aauth-resource.json",
        "r3-go-dr-1",
        0xca,
        Some(R3_RUST_AS),
    )?;
    let r3_rust_ap = Arc::new(AgentProvider::new(
        R3_RUST_AP,
        "r3-rust-ap-1",
        SigningKey::from_seed([0x81; 32]),
    )?);
    let r3_rust_ap_srv = r3_rust_ap.clone();
    let r3_rust_ap_tls = Arc::new(TlsServer::start("r3-rust-ap.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-agent.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(r3_rust_ap_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(r3_rust_ap_srv.jwks().unwrap())
                .unwrap(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    trust.discover(&r3_rust_ap_tls, R3_RUST_AP, "aauth-agent.json")?;
    register_r_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "r3-rust-ap.example",
        &r3_rust_ap_tls,
    )?;

    let r3_rust_as_rev_dir = RMultiTargetRevocationDirectory::default();
    let r3_rust_ps_rev_dir = RMultiTargetRevocationDirectory::default();
    let r3_rust_as_require_int = Arc::new(AtomicBool::new(false));
    let r3_rust_as_require_int_cb = r3_rust_as_require_int.clone();
    let r3_rust_as_cont = Arc::new(MemoryContinuations::new(64));
    let r3_rust_as_seq = Arc::new(AtomicUsize::new(0));
    let r3_rust_as = Arc::new(
        AccessServer::new(
            AsConfig::new(
                R3_RUST_AS,
                "r3-rust-as-1",
                SigningKey::from_seed([0x82; 32]),
            ),
            trust.clone(),
            move |req: &AsAuthorizationRequest| {
                Ok(AsDecision {
                    scopes: req.scopes.clone(),
                    lifetime: 600,
                })
            },
            move || clock,
            move || {
                format!(
                    "r3-rust-as-jti-{}",
                    r3_rust_as_seq.fetch_add(1, Ordering::SeqCst) + 1
                )
            },
        )?
        .with_revocation()
        .with_revocation_directory(Arc::new(r3_rust_as_rev_dir.clone()))
        .with_deferred(
            AsDeferredConfig {
                store: r3_rust_as_cont.clone(),
                retry_after: 1,
                lifetime: 300,
            },
            move |ctx: &AsDeferredContext| {
                if !r3_rust_as_require_int_cb.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                Ok(Some(ContinuationRequirement::Interaction {
                    url: format!("{R3_RUST_AS}/interact"),
                    code: ctx.interaction_code.clone(),
                }))
            },
        )?,
    );
    let r3_rust_as_srv = r3_rust_as.clone();
    let r3_rust_as_tls = Arc::new(TlsServer::start("r3-rust-as.example", move |req| {
        r3_rust_as_srv.handle(&req)
    })?);
    trust.discover(&r3_rust_as_tls, R3_RUST_AS, "aauth-access.json")?;
    register_r_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "r3-rust-as.example",
        &r3_rust_as_tls,
    )?;

    let r3_fed = RMultiAsHttpsFederation::default();
    r3_fed.register_rust(R3_RUST_AS, r3_rust_as_tls.clone());
    r3_rust_ps_rev_dir.register_target(
        R3_RUST_AS,
        RFedRoute::RustTls(r3_rust_as_tls.clone()),
        R3_RUST_FED_PS,
        "aauth-person.json",
        "r3-rust-ps-1",
        [0x83; 32],
        clock,
    );

    let r3_rust_ps_store = MemoryStore::default();
    let r3_rust_ps_cont = Arc::new(MemoryContinuations::new(64));
    let r3_rust_ps_policy = Arc::new(RPsPolicy::new("person-r3-rust"));
    let r3_rust_ps_seq = Arc::new(AtomicUsize::new(0));
    let r3_rust_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(
                R3_RUST_FED_PS,
                "r3-rust-ps-1",
                SigningKey::from_seed([0x83; 32]),
            ),
            trust.clone(),
            r3_rust_ps_store.clone(),
            RSharedPsPolicy(r3_rust_ps_policy.clone()),
            Box::new(move || clock) as BoxedClock,
            Box::new(move || {
                format!(
                    "r3-rust-ps-jti-{}",
                    r3_rust_ps_seq.fetch_add(1, Ordering::SeqCst) + 1
                )
            }) as BoxedTokenIds,
        )?
        .with_federation(r3_fed.clone())
        .with_revocation()
        .with_revocation_directory(Arc::new(r3_rust_ps_rev_dir.clone()))
        .with_deferred(PsDeferredConfig {
            store: r3_rust_ps_cont.clone(),
            retry_after: 1,
            lifetime: 300,
        })?,
    );
    let r3_rust_ps_srv = r3_rust_ps.clone();
    let r3_rust_ps_tls = Arc::new(TlsServer::start("r3-rust-fed-ps.example", move |req| {
        r3_rust_ps_srv.handle(&req)
    })?);
    trust.discover(&r3_rust_ps_tls, R3_RUST_FED_PS, "aauth-person.json")?;
    register_r_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "r3-rust-fed-ps.example",
        &r3_rust_ps_tls,
    )?;
    let make_r3_rust_fed_res = |host: &'static str,
                                issuer: &'static str,
                                kid: &'static str,
                                seed: [u8; 32],
                                as_issuer: &'static str|
     -> Result<(Arc<AgentProvider>, Arc<TlsServer>)> {
        let seq = Arc::new(AtomicUsize::new(0));
        let res = Arc::new(
            PsAuthorizationResource::new_federated(
                PsAuthorizationConfig {
                    issuer: issuer.into(),
                    signed_origin: issuer.into(),
                    kid: kid.into(),
                    signing_key: SigningKey::from_seed(seed),
                    scopes: vec!["records.read".into()],
                    scope_descriptions: BTreeMap::from([(
                        "records.read".into(),
                        "Read records".into(),
                    )]),
                },
                as_issuer,
                trust.clone(),
                Box::new(|tok: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
                    tok.claims()
                        .scope
                        .as_deref()
                        .unwrap_or("")
                        .split_whitespace()
                        .any(|s| s == "records.read")
                }) as BoxedAuthPolicy,
            )?
            .with_authorization_endpoint()
            .with_revocation()
            .with_mission_context(),
        );
        let ap = Arc::new(AgentProvider::new(issuer, kid, SigningKey::from_seed(seed))?);
        let ap_srv = ap.clone();
        let res_srv = res.clone();
        let issuer_str = issuer.to_owned();
        let tls = Arc::new(TlsServer::start(host, move |req| {
            let jti = format!("r3-res-jti-{}", seq.fetch_add(1, Ordering::SeqCst) + 1);
            match (req.method().as_str(), req.uri().path()) {
                ("GET", "/.well-known/aauth-agent.json") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(ap_srv.metadata().unwrap())
                    .unwrap(),
                ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(res_srv.metadata().unwrap())
                    .unwrap(),
                ("GET", "/.well-known/jwks.json") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(res_srv.jwks().unwrap())
                    .unwrap(),
                ("POST", "/authorize") => res_srv
                    .authorize_endpoint(&req, clock, &jti)
                    .into_response(),
                ("POST", "/revoke") => res_srv.revoke(&req, clock),
                ("GET", "/records") | ("POST", "/work") => match res_srv.authorize(&req, clock, &jti) {
                    AuthDecision::Granted(admitted) => {
                        let miss = admitted.token().claims().mission_s256.clone();
                        json_response(
                            200,
                            json!({
                                "ok": true,
                                "server": issuer_str,
                                "subject": admitted.token().claims().sub,
                                "mission_s256": miss,
                            }),
                        )
                    }
                    other => other.into_response(),
                },
                _ => json_response(404, json!({"error": "not_found"})),
            }
        })?);
        trust.discover(&tls, issuer, "aauth-agent.json")?;
        trust.discover(&tls, issuer, "aauth-resource.json")?;
        register_r_host_with_go(go_events_ap_addr, &go_events_ap_cert, host, &tls)?;
        r3_rust_ps_rev_dir.register_target(
            issuer,
            RFedRoute::RustTls(tls.clone()),
            R3_RUST_FED_PS,
            "aauth-person.json",
            "r3-rust-ps-1",
            [0x83; 32],
            clock,
        );
        r3_rust_as_rev_dir.register_target(
            issuer,
            RFedRoute::RustTls(tls.clone()),
            R3_RUST_AS,
            "aauth-access.json",
            "r3-rust-as-1",
            [0x82; 32],
            clock,
        );
        Ok((ap, tls))
    };

    let (r3_rust_ig_ap, r3_rust_ig_tls) = make_r3_rust_fed_res(
        "r3-rust-interm-go-as.example",
        R3_RUST_INTERM_GO_AS,
        "r3-rust-ig-1",
        [0x84; 32],
        R3_GO_AS,
    )?;
    let (r3_rust_ir_ap, _r3_rust_ir_tls) = make_r3_rust_fed_res(
        "r3-rust-interm-rust-as.example",
        R3_RUST_INTERM_RUST_AS,
        "r3-rust-ir-1",
        [0x85; 32],
        R3_RUST_AS,
    )?;
    let (_, _r3_rust_dg_tls) = make_r3_rust_fed_res(
        "r3-rust-down-go-as.example",
        R3_RUST_DOWN_GO_AS,
        "r3-rust-dg-1",
        [0x86; 32],
        R3_GO_AS,
    )?;
    let (_, _r3_rust_dr_tls) = make_r3_rust_fed_res(
        "r3-rust-down-rust-as.example",
        R3_RUST_DOWN_RUST_AS,
        "r3-rust-dr-1",
        [0x87; 32],
        R3_RUST_AS,
    )?;

    let go_r_suite = post_json_ext(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-r-suite",
        json!({
            "rust_fed_ps_issuer": R3_RUST_FED_PS,
            "rust_fed_as_issuer": R3_RUST_AS,
            "rust_interm_go_as_issuer": R3_RUST_INTERM_GO_AS,
            "rust_interm_rust_as_issuer": R3_RUST_INTERM_RUST_AS,
            "rust_down_go_as_issuer": R3_RUST_DOWN_GO_AS,
            "rust_down_rust_as_issuer": R3_RUST_DOWN_RUST_AS,
        }),
    )?;
    let parse_go_srv = |name: &str| -> Result<(SocketAddr, Vec<u8>)> {
        let addr: SocketAddr = go_r_suite["servers"][name]["addr"]
            .as_str()
            .ok_or_else(|| format!("missing servers.{name}.addr"))?
            .parse()?;
        let cert = decode_cert_pem(
            go_r_suite["servers"][name]["cert_pem"]
                .as_str()
                .ok_or_else(|| format!("missing servers.{name}.cert_pem"))?,
        )?;
        Ok((addr, cert))
    };
    let (r3_go_ap_addr, r3_go_ap_cert) = parse_go_srv("r3_go_ap")?;
    let (r3_go_ps_addr, r3_go_ps_cert) = parse_go_srv("r3_go_fed_ps")?;
    let (r3_go_as_addr, r3_go_as_cert) = parse_go_srv("r3_go_as")?;
    let (r3_go_ig_addr, r3_go_ig_cert) = parse_go_srv("r3_go_interm_go_as")?;
    let (r3_go_ir_addr, r3_go_ir_cert) = parse_go_srv("r3_go_interm_rust_as")?;
    let (r3_go_dg_addr, r3_go_dg_cert) = parse_go_srv("r3_go_down_go_as")?;
    let (r3_go_dr_addr, r3_go_dr_cert) = parse_go_srv("r3_go_down_rust_as")?;

    discover_external(
        trust,
        r3_go_ap_addr,
        "r3-go-ap.example",
        &r3_go_ap_cert,
        R3_GO_AP,
        "aauth-agent.json",
    )?;
    discover_external(
        trust,
        r3_go_ps_addr,
        "r3-go-fed-ps.example",
        &r3_go_ps_cert,
        R3_GO_FED_PS,
        "aauth-person.json",
    )?;
    discover_external(
        trust,
        r3_go_as_addr,
        "r3-go-as.example",
        &r3_go_as_cert,
        R3_GO_AS,
        "aauth-access.json",
    )?;
    discover_external(
        trust,
        r3_go_ig_addr,
        "r3-go-interm-go-as.example",
        &r3_go_ig_cert,
        R3_GO_INTERM_GO_AS,
        "aauth-agent.json",
    )?;
    discover_external(
        trust,
        r3_go_ig_addr,
        "r3-go-interm-go-as.example",
        &r3_go_ig_cert,
        R3_GO_INTERM_GO_AS,
        "aauth-resource.json",
    )?;
    discover_external(
        trust,
        r3_go_ir_addr,
        "r3-go-interm-rust-as.example",
        &r3_go_ir_cert,
        R3_GO_INTERM_RUST_AS,
        "aauth-agent.json",
    )?;
    discover_external(
        trust,
        r3_go_ir_addr,
        "r3-go-interm-rust-as.example",
        &r3_go_ir_cert,
        R3_GO_INTERM_RUST_AS,
        "aauth-resource.json",
    )?;
    discover_external(
        trust,
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        R3_GO_DOWN_GO_AS,
        "aauth-resource.json",
    )?;
    discover_external(
        trust,
        r3_go_dr_addr,
        "r3-go-down-rust-as.example",
        &r3_go_dr_cert,
        R3_GO_DOWN_RUST_AS,
        "aauth-resource.json",
    )?;

    r3_fed.register_go(
        R3_GO_AS,
        r3_go_as_addr,
        "r3-go-as.example",
        r3_go_as_cert.clone(),
    );
    r3_rust_ps_rev_dir.register_target(
        R3_GO_AS,
        RFedRoute::GoExt {
            addr: r3_go_as_addr,
            host: "r3-go-as.example",
            cert: r3_go_as_cert.clone(),
        },
        R3_RUST_FED_PS,
        "aauth-person.json",
        "r3-rust-ps-1",
        [0x83; 32],
        clock,
    );
    for (iss, addr, host, cert) in [
        (
            R3_GO_INTERM_GO_AS,
            r3_go_ig_addr,
            "r3-go-interm-go-as.example",
            r3_go_ig_cert.clone(),
        ),
        (
            R3_GO_INTERM_RUST_AS,
            r3_go_ir_addr,
            "r3-go-interm-rust-as.example",
            r3_go_ir_cert.clone(),
        ),
        (
            R3_GO_DOWN_GO_AS,
            r3_go_dg_addr,
            "r3-go-down-go-as.example",
            r3_go_dg_cert.clone(),
        ),
        (
            R3_GO_DOWN_RUST_AS,
            r3_go_dr_addr,
            "r3-go-down-rust-as.example",
            r3_go_dr_cert.clone(),
        ),
    ] {
        let route = RFedRoute::GoExt { addr, host, cert };
        r3_rust_ps_rev_dir.register_target(
            iss,
            route.clone(),
            R3_RUST_FED_PS,
            "aauth-person.json",
            "r3-rust-ps-1",
            [0x83; 32],
            clock,
        );
        r3_rust_as_rev_dir.register_target(
            iss,
            route,
            R3_RUST_AS,
            "aauth-access.json",
            "r3-rust-as-1",
            [0x82; 32],
            clock,
        );
    }
    let make_r_agent = |ap: &AgentProvider,
                        ap_issuer: &str,
                        local_name: &str,
                        ps_issuer: Option<&str>,
                        seed: [u8; 32]|
     -> Result<(Agent, String, AgentIdentity)> {
        let host = ap_issuer.trim_start_matches("https://");
        let sub = format!("aauth:{local_name}@{host}");
        let tok = ap.issue(&AgentClaims {
            iss: ap_issuer.into(),
            dwk: "aauth-agent.json".into(),
            sub: sub.clone(),
            jti: format!("r3-ag-{local_name}-1"),
            iat: clock,
            exp: clock + 3600,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(seed).public_jwk(),
            },
            ps: ps_issuer.map(str::to_owned),
            parent_agent: None,
            nbf: None,
            extra: Default::default(),
        })?;
        let ag = Agent::new(SigningKey::from_seed(seed), tok)?;
        let owner = AgentIdentity {
            issuer: ap_issuer.into(),
            subject: sub.clone(),
        };
        Ok((ag, sub, owner))
    };

    let (r3_caller_ag, r3_caller_sub, r3_caller_owner) = make_r_agent(
        &r3_rust_ap,
        R3_RUST_AP,
        "caller-r3",
        Some(R3_RUST_FED_PS),
        [0x88; 32],
    )?;
    let (r3_ig_relay_ag, _, _) =
        make_r_agent(&r3_rust_ig_ap, R3_RUST_INTERM_GO_AS, "worker", None, [0x89; 32])?;
    let (r3_ir_relay_ag, _, _) = make_r_agent(
        &r3_rust_ir_ap,
        R3_RUST_INTERM_RUST_AS,
        "worker",
        None,
        [0x8a; 32],
    )?;

    // Direction 2 (No Mission): Caller -> Hop 1 Rust Intermediary (behind Go AS) -> Rust Federated PS -> Hop 2 Go Downstream (behind Go AS & Rust AS)
    let r3_d2_pt1_resp = r3_rust_ps_tls.send(&post_at(
        &r3_caller_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_RUST_INTERM_GO_AS}))?,
        clock,
    )?)?;
    let r3_d2_pt1 = member(&r3_d2_pt1_resp, "person_token").ok_or("missing r3_d2_pt1")?;
    let r3_d2_pt1_jti = PersonToken::parse(&r3_d2_pt1)?
        .unverified_claims()
        .jti
        .clone();
    let r3_d2_rt1_resp = r3_rust_ig_tls.send(&post_at(
        &r3_caller_ag.with_token(r3_d2_pt1.clone())?,
        &format!("{R3_RUST_INTERM_GO_AS}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let r3_d2_rt1 = member(&r3_d2_rt1_resp, "resource_token").ok_or("missing r3_d2_rt1")?;
    let r3_d2_at1_resp = r3_rust_ps_tls.send(&post_at(
        &r3_caller_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({"resource_token": r3_d2_rt1, "presented_token": r3_d2_pt1}))?,
        clock,
    )?)?;
    let r3_d2_at1 = member(&r3_d2_at1_resp, "auth_token").ok_or("missing r3_d2_at1")?;

    // Hop 2 to Go Downstream (behind Go AS) via Rust Federated PS
    let r3_d2_pt2_go_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ig_relay_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_DOWN_GO_AS, "upstream_token": r3_d2_at1}))?,
        clock,
    )?)?;
    let r3_d2_pt2_go = member(&r3_d2_pt2_go_resp, "person_token").ok_or("missing r3_d2_pt2_go")?;
    let r3_d2_rt2_go_resp = send_https(
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        &post_at(
            &r3_ig_relay_ag.with_token(r3_d2_pt2_go.clone())?,
            &format!("{R3_GO_DOWN_GO_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?,
    )?;
    let r3_d2_rt2_go =
        member(&r3_d2_rt2_go_resp, "resource_token").ok_or("missing r3_d2_rt2_go")?;
    let r3_d2_at2_go_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ig_relay_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": r3_d2_rt2_go,
            "presented_token": r3_d2_pt2_go,
            "upstream_token": r3_d2_at1,
        }))?,
        clock,
    )?)?;
    let r3_d2_at2_go = member(&r3_d2_at2_go_resp, "auth_token").ok_or("missing r3_d2_at2_go")?;
    let r3_d2_call_go_before = send_https(
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        &signed_get(
            &r3_ig_relay_ag.with_token(r3_d2_at2_go.clone())?,
            &format!("{R3_GO_DOWN_GO_AS}/records"),
            clock,
        )?,
    )?;
    // Hop 2 to Go Downstream (behind Rust AS) via Rust Federated PS
    let r3_d2_pt2_dr_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ig_relay_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_DOWN_RUST_AS, "upstream_token": r3_d2_at1}))?,
        clock,
    )?)?;
    let r3_d2_pt2_dr = member(&r3_d2_pt2_dr_resp, "person_token").ok_or("missing r3_d2_pt2_dr")?;
    let r3_d2_rt2_dr_resp = send_https(
        r3_go_dr_addr,
        "r3-go-down-rust-as.example",
        &r3_go_dr_cert,
        &post_at(
            &r3_ig_relay_ag.with_token(r3_d2_pt2_dr.clone())?,
            &format!("{R3_GO_DOWN_RUST_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?,
    )?;
    let r3_d2_rt2_dr =
        member(&r3_d2_rt2_dr_resp, "resource_token").ok_or("missing r3_d2_rt2_dr")?;
    let r3_d2_at2_dr_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ig_relay_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": r3_d2_rt2_dr,
            "presented_token": r3_d2_pt2_dr,
            "upstream_token": r3_d2_at1,
        }))?,
        clock,
    )?)?;
    let r3_d2_at2_dr = member(&r3_d2_at2_dr_resp, "auth_token").ok_or("missing r3_d2_at2_dr")?;
    let r3_d2_call_dr_before = send_https(
        r3_go_dr_addr,
        "r3-go-down-rust-as.example",
        &r3_go_dr_cert,
        &signed_get(
            &r3_ig_relay_ag.with_token(r3_d2_at2_dr.clone())?,
            &format!("{R3_GO_DOWN_RUST_AS}/records"),
            clock,
        )?,
    )?;

    // Revoke root PersonToken at Rust Federated PS and verify cascade to Rust Intermediary + Go Downstream behind Go AS + Go Downstream behind Rust AS
    let _ = r3_rust_ps.revoke_person_token(&r3_d2_pt1_jti);
    let r3_d2_hop1_after = r3_rust_ig_tls.send(&signed_get(
        &r3_caller_ag.with_token(r3_d2_at1.clone())?,
        &format!("{R3_RUST_INTERM_GO_AS}/records"),
        clock,
    )?)?;
    let r3_d2_hop2_go_after = send_https(
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        &signed_get(
            &r3_ig_relay_ag.with_token(r3_d2_at2_go.clone())?,
            &format!("{R3_GO_DOWN_GO_AS}/records"),
            clock,
        )?,
    )?;
    let r3_d2_hop2_dr_after = send_https(
        r3_go_dr_addr,
        "r3-go-down-rust-as.example",
        &r3_go_dr_cert,
        &signed_get(
            &r3_ig_relay_ag.with_token(r3_d2_at2_dr.clone())?,
            &format!("{R3_GO_DOWN_RUST_AS}/records"),
            clock,
        )?,
    )?;
    let r3_d2_rev_upstream_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ig_relay_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_DOWN_GO_AS, "upstream_token": r3_d2_at1}))?,
        clock,
    )?)?;

    // Direction 2 With Mission + 3-Hop Mixed Chain (Caller -> Go Interm -> Rust Interm -> Go Downstream)
    let decode_mission_bytes = |bytes: &[u8]| -> Result<ApprovedMission> {
        let s256 = digest(bytes);
        Ok(ApprovedMission::decode(
            &s256,
            &URL_SAFE_NO_PAD.encode(bytes),
        )?)
    };
    let r3_miss_doc = decode_mission_bytes(
        json!({
            "approver": R3_RUST_FED_PS,
            "agent": r3_caller_sub,
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 300),
            "description": "# Cross-Language 3-Hop Mixed Mission\nAccess Go and Rust resources."
        })
        .to_string()
        .as_bytes(),
    )?;
    let r3_miss_s256 = r3_miss_doc.s256().to_owned();
    r3_rust_ps_store
        .install_approved_mission(MissionRecord {
            person_server: R3_RUST_FED_PS.into(),
            owner: r3_caller_owner.clone(),
            person_id: "person-r3-rust".into(),
            document: r3_miss_doc,
            state: MissionState::Active,
        })
        .map_err(|e| format!("install_approved_mission r3: {e:?}"))?;

    // Hop 1 (Caller -> Go Intermediary R3_GO_INTERM_GO_AS with mission_s256)
    let r3_3h_pt1_resp = r3_rust_ps_tls.send(&post_at(
        &r3_caller_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_INTERM_GO_AS, "mission_s256": r3_miss_s256}))?,
        clock,
    )?)?;
    let r3_3h_pt1 = member(&r3_3h_pt1_resp, "person_token").ok_or("missing r3_3h_pt1")?;
    let r3_3h_rt1_resp = send_https(
        r3_go_ig_addr,
        "r3-go-interm-go-as.example",
        &r3_go_ig_cert,
        &post_at(
            &r3_caller_ag.with_token(r3_3h_pt1.clone())?,
            &format!("{R3_GO_INTERM_GO_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?,
    )?;
    let r3_3h_rt1 = member(&r3_3h_rt1_resp, "resource_token").ok_or("missing r3_3h_rt1")?;
    let r3_3h_at1_resp = r3_rust_ps_tls.send(&post_at(
        &r3_caller_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({"resource_token": r3_3h_rt1, "presented_token": r3_3h_pt1}))?,
        clock,
    )?)?;
    let r3_3h_at1 = member(&r3_3h_at1_resp, "auth_token").ok_or("missing r3_3h_at1")?;

    // Hop 2: Go Intermediary (/__r3-go-chain-hop) -> Rust Intermediary (R3_RUST_INTERM_RUST_AS)
    let r3_3h_hop2_res = post_json_ext(
        r3_go_ps_addr,
        "r3-go-fed-ps.example",
        &r3_go_ps_cert,
        "https://r3-go-fed-ps.example/__r3-go-chain-hop",
        json!({
            "interm": "go_as",
            "downstream": R3_RUST_INTERM_RUST_AS,
            "upstream_token": r3_3h_at1,
        }),
    )?;
    let r3_3h_at2 = r3_3h_hop2_res["auth_token"]
        .as_str()
        .ok_or_else(|| format!("missing r3_3h_at2: {r3_3h_hop2_res}"))?
        .to_owned();
    // Hop 3: Rust Intermediary (r3_ir_relay_ag) -> Go Downstream (R3_GO_DOWN_GO_AS)
    let r3_3h_pt3_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ir_relay_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_DOWN_GO_AS, "upstream_token": r3_3h_at2}))?,
        clock,
    )?)?;
    let r3_3h_pt3 = member(&r3_3h_pt3_resp, "person_token").ok_or("missing r3_3h_pt3")?;
    let r3_3h_rt3_resp = send_https(
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        &post_at(
            &r3_ir_relay_ag.with_token(r3_3h_pt3.clone())?,
            &format!("{R3_GO_DOWN_GO_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?,
    )?;
    let r3_3h_rt3 = member(&r3_3h_rt3_resp, "resource_token").ok_or("missing r3_3h_rt3")?;
    let r3_3h_at3_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ir_relay_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": r3_3h_rt3,
            "presented_token": r3_3h_pt3,
            "upstream_token": r3_3h_at2,
        }))?,
        clock,
    )?)?;
    let r3_3h_at3 = member(&r3_3h_at3_resp, "auth_token").ok_or("missing r3_3h_at3")?;
    let r3_3h_at3_claims = AuthToken::parse(&r3_3h_at3)?
        .verify(trust, clock)?
        .claims()
        .clone();
    let r3_3h_call3_resp = send_https(
        r3_go_dg_addr,
        "r3-go-down-go-as.example",
        &r3_go_dg_cert,
        &signed_get(
            &r3_ir_relay_ag.with_token(r3_3h_at3.clone())?,
            &format!("{R3_GO_DOWN_GO_AS}/records"),
            clock,
        )?,
    )?;
    let r3_3h_call3_body: Value = serde_json::from_slice(r3_3h_call3_resp.body())?;

    // Mixed-deployment boundary checks on Rust PS:
    // 1) Rust 4-party PS relays AS requirement=interaction (202 Accepted)
    r3_rust_as_require_int.store(true, Ordering::SeqCst);
    let r3_bnd_rust_rt_resp = send_https(
        r3_go_dr_addr,
        "r3-go-down-rust-as.example",
        &r3_go_dr_cert,
        &post_at(
            &r3_ir_relay_ag.with_token(
                member(
                    &r3_rust_ps_tls.send(&post_at(
                        &r3_ir_relay_ag,
                        &format!("{R3_RUST_FED_PS}/person"),
                        &serde_json::to_vec(
                            &json!({"resource": R3_GO_DOWN_RUST_AS, "upstream_token": r3_3h_at2}),
                        )?,
                        clock,
                    )?)?,
                    "person_token",
                )
                .ok_or("missing bnd pt")?,
            )?,
            &format!("{R3_GO_DOWN_RUST_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?,
    )?;
    let r3_bnd_rust_rt = member(&r3_bnd_rust_rt_resp, "resource_token").ok_or("missing bnd rt")?;
    let r3_bnd_rust_pt = member(
        &r3_rust_ps_tls.send(&post_at(
            &r3_ir_relay_ag,
            &format!("{R3_RUST_FED_PS}/person"),
            &serde_json::to_vec(
                &json!({"resource": R3_GO_DOWN_RUST_AS, "upstream_token": r3_3h_at2}),
            )?,
            clock,
        )?)?,
        "person_token",
    )
    .ok_or("missing bnd pt2")?;
    let r3_bnd_rust_rt2 = member(
        &send_https(
            r3_go_dr_addr,
            "r3-go-down-rust-as.example",
            &r3_go_dr_cert,
            &post_at(
                &r3_ir_relay_ag.with_token(r3_bnd_rust_pt.clone())?,
                &format!("{R3_GO_DOWN_RUST_AS}/authorize"),
                &serde_json::to_vec(&json!({"scope": "records.read"}))?,
                clock,
            )?,
        )?,
        "resource_token",
    )
    .ok_or("missing bnd rt2")?;
    let r3_bnd_rust_int_req = post_at(
        &r3_ir_relay_ag,
        &format!("{R3_RUST_FED_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": r3_bnd_rust_rt2,
            "presented_token": r3_bnd_rust_pt,
            "upstream_token": r3_3h_at2,
            "capabilities": ["interaction"],
        }))?,
        clock,
    )?;
    let _ = r3_bnd_rust_rt;
    let r3_bnd_rust_int_resp = r3_rust_ps_tls.send(&r3_bnd_rust_int_req)?;
    r3_rust_as_require_int.store(false, Ordering::SeqCst);

    // 2) Policy copying upstream sub at Rust PS -> 403 access_denied (vs 500 server_error in Go)
    r3_rust_ps_policy
        .copy_upstream_sub
        .store(true, Ordering::SeqCst);
    let r3_bnd_rust_copysub_resp = r3_rust_ps_tls.send(&post_at(
        &r3_ir_relay_ag,
        &format!("{R3_RUST_FED_PS}/person"),
        &serde_json::to_vec(&json!({"resource": R3_GO_DOWN_GO_AS, "upstream_token": r3_3h_at2}))?,
        clock,
    )?)?;
    r3_rust_ps_policy
        .copy_upstream_sub
        .store(false, Ordering::SeqCst);
    // =========================================================================
    // QA-R1: Breaking API Changes Migration & Store Contracts
    // =========================================================================
    let go_mod_dir = Path::new(go_module_path);
    let agent_deferred_src = fs::read_to_string(go_mod_dir.join("agent/deferred.go"))?;
    let agent_chain_src = fs::read_to_string(go_mod_dir.join("agent/call_chaining_test.go"))?;
    let ps_server_src = fs::read_to_string(go_mod_dir.join("personserver/server.go"))?;
    let res_session_src = fs::read_to_string(go_mod_dir.join("resource/session_interaction.go"))?;

    let removed_errors_gone = !agent_deferred_src.contains("CallChainingInteractionUnsupportedError")
        && !agent_deferred_src.contains("SubagentPendingExchangeRequiredError")
        && !agent_deferred_src.contains("MissionContinuationUnsupportedError")
        && !agent_chain_src.contains("CallChainingInteractionUnsupportedError")
        && ps_server_src.contains("call chaining requires an issued auth-token store")
        && res_session_src.contains("SessionCodePresentation");

    let storetest_out = Command::new("go")
        .args([
            "test",
            "-mod=readonly",
            "-run",
            "TestExportedIssuedAuthTokenStore|TestPublicFederationStores|TestExportedDeferredAuthorizationStore|TestExportedMissionStore",
            "./testutil",
            "./resource",
        ])
        .current_dir(go_mod_dir)
        .output()?;
    let storetest_ok = storetest_out.status.success();

    let r1 = &go_r_suite["r1"];
    let r1_pass = removed_errors_gone
        && storetest_ok
        && r1["missing_issued_tokens_err"].as_bool() == Some(true)
        && r1["issued_roundtrip_ok"].as_bool() == Some(true)
        && r1["issued_conflict_refused"].as_bool() == Some(true)
        && r1["lineage_implemented"].as_bool() == Some(true)
        && r1["fed_upstream_roundtrip_ok"].as_bool() == Some(true)
        && r1["fed_upstream_immutable_ok"].as_bool() == Some(true)
        && r1["sess_bad_code_no_cb"].as_bool() == Some(true)
        && r1["sess_good_code_cb_ok"].as_bool() == Some(true)
        && r1["sess_reuse_code_preserves"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-R1".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Breaking API Changes Migration & Store Contracts: FederatedAuthorizationConfig.IssuedTokens Required When CallChaining!=nil, SessionCodePresentation, Removed Interim Errors, and Storetest Contracts".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r1_pass,
        summary: format!(
            "Breaking API migration & store contracts verified: NewFederatedAuthorization without IssuedTokens rejected ({}), SessionCodePresentation callback retention ok={}, IssuedAuthTokenStore PresentedTokenReference & LoadAuthTokensIssuedAgainst ok={}, FederatedAuthorizationStore UpstreamToken roundtrip & immutability ok={}, removed interim errors absent={}, storetest suite ok={}",
            r1["missing_issued_msg"].as_str().unwrap_or(""),
            r1["sess_good_code_cb_ok"].as_bool() == Some(true),
            r1["lineage_implemented"].as_bool() == Some(true),
            r1["fed_upstream_immutable_ok"].as_bool() == Some(true),
            removed_errors_gone,
            storetest_ok,
        ),
        evidence: json!({
            "go_r1": r1,
            "removed_interim_errors_gone": removed_errors_gone,
            "storetest_suite_ok": storetest_ok,
        }),
    });
    transcript_lines.push(format!(
        "[QA-R1] PASS={}: IssuedTokens_req={} SessionCodePresentation={} Lineage={} Storetest={}",
        r1_pass,
        r1["missing_issued_tokens_err"],
        r1["sess_good_code_cb_ok"],
        r1["lineage_implemented"],
        storetest_ok
    ));

    // =========================================================================
    // QA-R2: All-Go 4-Party Call Chaining Over Real HTTPS
    // =========================================================================
    let r2 = &go_r_suite["r2"];
    let r2_pass = r2["hop1_ok"].as_bool() == Some(true)
        && r2["hop2_ok"].as_bool() == Some(true)
        && r2["hop3_ok"].as_bool() == Some(true)
        && r2["expiry_ceilings_ok"].as_bool() == Some(true)
        && r2["stepup_omit_refused"].as_bool() == Some(true)
        && r2["stepup_match_ok"].as_bool() == Some(true)
        && r2["revoke_pt_all_3_hops_401"].as_bool() == Some(true)
        && r2["revoke_pt_upstream_400"].as_bool() == Some(true)
        && r2["chained_wait_approved_ok"].as_bool() == Some(true)
        && r2["chained_wait_revoked_ok"].as_bool() == Some(true)
        && r2["mission_carried_ok"].as_bool() == Some(true)
        && r2["mission_as_not_capped_rt"].as_bool() == Some(true)
        && r2["interm_own_mission_400"].as_bool() == Some(true)
        && r2["mission_wait_term_ok"].as_bool() == Some(true)
        && r2["agent_rev_202_then_200"].as_bool() == Some(true)
        && r2["agent_rev_hops_401"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-R2".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "All-Go 4-Party Call Chaining Over Real HTTPS: 3 Hops on Real Exchanges, Step-Up Receipt Tie, Missions Carried & 30m AS Lifetime, Chained Waits (Approved & Revoked), Root PersonToken & AgentToken Revocation Cascades".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r2_pass,
        summary: format!(
            "All-Go 4-party chaining verified: 3-hop real exchanges (Orders->Inventory->Warehouse) ok={}, step-up tie ok={}, root PT revocation cascade (all 3 hops 200->401 revoked_jwt & 400 revoked_upstream_token) ok={}, chained waits (approved & 403 revoked->410) ok={}, mission carried & 30m AS lifetime not capped at 5m RT & mission_terminated wait ok={}, Agent token revocation (202 RevocationPendingError->200 OK & cascade) ok={}",
            r2["hop3_ok"],
            r2["stepup_omit_refused"],
            r2["revoke_pt_all_3_hops_401"],
            r2["chained_wait_revoked_ok"],
            r2["mission_wait_term_ok"],
            r2["agent_rev_202_then_200"],
        ),
        evidence: r2.clone(),
    });
    transcript_lines.push(format!(
        "[QA-R2] PASS={}: 3hops={} stepup={} rev_pt={} wait_rev={} mission={} agent_rev_202_200={}",
        r2_pass,
        r2["hop3_ok"],
        r2["stepup_omit_refused"],
        r2["revoke_pt_all_3_hops_401"],
        r2["chained_wait_revoked_ok"],
        r2["mission_wait_term_ok"],
        r2["agent_rev_202_then_200"]
    ));
    // =========================================================================
    // QA-R3: Cross-Language 4-Party Call Chaining & Chain Revocation
    // =========================================================================
    let r3 = &go_r_suite["r3"];
    let r3_d2_nomiss_ok = r3_d2_call_go_before.status().as_u16() == 200
        && r3_d2_call_dr_before.status().as_u16() == 200;
    let r3_d2_rev_cascade_ok = r3_d2_hop1_after.status().as_u16() == 401
        && r3_d2_hop2_go_after.status().as_u16() == 401
        && r3_d2_hop2_dr_after.status().as_u16() == 401
        && r3_d2_rev_upstream_resp.status().as_u16() == 400
        && member(&r3_d2_rev_upstream_resp, "error").as_deref() == Some("revoked_upstream_token");
    let r3_3hop_mixed_miss_ok = r3_3h_hop2_res["ok"].as_bool() == Some(true)
        && r3_3h_call3_resp.status().as_u16() == 200
        && r3_3h_at3_claims.mission_s256.as_deref() == Some(r3_miss_s256.as_str())
        && r3_3h_call3_body["mission_s256"].as_str() == Some(r3_miss_s256.as_str());
    let r3_mixed_boundaries_ok = r3["bnd_go_ps_as_int_500"].as_bool() == Some(true)
        && r3_bnd_rust_int_resp.status().as_u16() == 202
        && r3["bnd_go_ps_subagent_500"].as_bool() == Some(true)
        && r3["bnd_go_ps_copy_sub_500"].as_bool() == Some(true)
        && r3_bnd_rust_copysub_resp.status().as_u16() == 403
        && r3["bnd_go_ps_unrec_as_tok_400"].as_bool() == Some(true);

    let r3_pass = r3["d1_nomiss_hop1_ok"].as_bool() == Some(true)
        && r3["d1_nomiss_hop2_rust_as_ok"].as_bool() == Some(true)
        && r3["d1_nomiss_hop2_go_as_ok"].as_bool() == Some(true)
        && r3["d1_rust_as_interm_ok"].as_bool() == Some(true)
        && r3["d1_revoke_pt_cascade_ok"].as_bool() == Some(true)
        && r3["d1_miss_hop1_and_hop2_ok"].as_bool() == Some(true)
        && r3_d2_nomiss_ok
        && r3_d2_rev_cascade_ok
        && r3_3hop_mixed_miss_ok
        && r3_mixed_boundaries_ok;

    let _ = out_dir;
    cases.push(QaCaseReceipt {
        id: "QA-R3".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Cross-Language 4-Party Call Chaining & Chain Revocation (aauth-go 8a3734dd <-> aauth-rust v0.1.0-alpha.16) Over Real HTTPS + Mixed-Deployment Boundary Pinning".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r3_pass,
        summary: format!(
            "Cross-language 4-party chaining verified: Direction 1 (Go Fed PS + Go/Rust AS/Res with & without mission) ok={}, Direction 2 (Rust Fed PS + Go/Rust AS/Res with & without mission) ok={}, 3-hop mixed mission chain (Caller->Go Interm->Rust Interm->Go Down) ok={}, cross-language root PT revocation cascades (Go PS->Rust/Go & Rust PS->Go/Rust) ok={}, AS-interaction relay verified (Go PS->202 with interaction capability / 403 user_unreachable without, Rust PS->202) and remaining boundaries pinned (subagent->500, copied sub Go->500 vs Rust->403, unrecorded AS upstream->400)={}",
            r3["d1_miss_hop1_and_hop2_ok"],
            r3_d2_nomiss_ok,
            r3_3hop_mixed_miss_ok,
            r3_d2_rev_cascade_ok && r3["d1_revoke_pt_cascade_ok"].as_bool() == Some(true),
            r3_mixed_boundaries_ok,
        ),
        evidence: json!({
            "go_r3": r3,
            "d2_nomiss_ok": r3_d2_nomiss_ok,
            "d2_rev_cascade_ok": r3_d2_rev_cascade_ok,
            "three_hop_mixed_mission_ok": r3_3hop_mixed_miss_ok,
            "rust_ps_as_interaction_status": r3_bnd_rust_int_resp.status().as_u16(),
            "rust_ps_copy_sub_status": r3_bnd_rust_copysub_resp.status().as_u16(),
        }),
    });
    transcript_lines.push(format!(
        "[QA-R3] PASS={}: D1={} D2={} 3hop_mixed={} rev_cascade={} boundaries={}",
        r3_pass,
        r3["d1_miss_hop1_and_hop2_ok"],
        r3_d2_nomiss_ok,
        r3_3hop_mixed_miss_ok,
        r3_d2_rev_cascade_ok,
        r3_mixed_boundaries_ok
    ));

    // =========================================================================
    // QA-R4: Shared agent.Pending[T] Polling Across All Deferred Agent Flows
    // =========================================================================
    let r4 = &go_r_suite["r4"];
    let r4_pass = r4["flow1_mission_update_ok"].as_bool() == Some(true)
        && r4["flow2_mission_complete_ok"].as_bool() == Some(true)
        && r4["flow3_audit_ok"].as_bool() == Some(true)
        && r4["flow4_authorize_rt_ok"].as_bool() == Some(true)
        && r4["flow5_authorize_sess_ok"].as_bool() == Some(true)
        && r4["flow6_subagent_ok"].as_bool() == Some(true)
        && r4["flow7_events_ok"].as_bool() == Some(true)
        && r4["flow8_enroll_hwk_ok"].as_bool() == Some(true)
        && r4["flow8_refresh_jkt_ok"].as_bool() == Some(true)
        && r4["flow8_refresh_single_ok"].as_bool() == Some(true)
        && r4["flow9_chained_pt_ok"].as_bool() == Some(true)
        && r4["flow10_mission_prop_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-R4".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Shared agent.Pending[T] Polling Across All Deferred Agent Flows Over Real HTTPS (PollTooEarlyError, 429 +5s, 503 Retry-After, Prefer: wait=30, Interacting, Clarification, Cancel, ErrPendingFinished)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r4_pass,
        summary: format!(
            "Shared agent.Pending[T] polling verified across all deferred Agent flows: mission update={}, mission completion + clarification before/after deadline + DELETE cancel={}, audit={}, /authorize (RT & session)={}, subagent={}, public/protected events={}, bootstrap enroll (hwk)/refresh (jkt-jwt)/single-key (hwk)={}, ChainedPending()={}, mission proposal clarification/cancel={}",
            r4["flow1_mission_update_ok"],
            r4["flow2_mission_complete_ok"],
            r4["flow3_audit_ok"],
            r4["flow4_authorize_rt_ok"].as_bool() == Some(true) && r4["flow5_authorize_sess_ok"].as_bool() == Some(true),
            r4["flow6_subagent_ok"],
            r4["flow7_events_ok"],
            r4["flow8_enroll_hwk_ok"].as_bool() == Some(true) && r4["flow8_refresh_jkt_ok"].as_bool() == Some(true) && r4["flow8_refresh_single_ok"].as_bool() == Some(true),
            r4["flow9_chained_pt_ok"],
            r4["flow10_mission_prop_ok"],
        ),
        evidence: r4.clone(),
    });
    transcript_lines.push(format!(
        "[QA-R4] PASS={}: update={} complete={} audit={} auth={} subagent={} events={} bootstrap={} chained_pt={} mission_prop={}",
        r4_pass,
        r4["flow1_mission_update_ok"],
        r4["flow2_mission_complete_ok"],
        r4["flow3_audit_ok"],
        r4["flow4_authorize_rt_ok"],
        r4["flow6_subagent_ok"],
        r4["flow7_events_ok"],
        r4["flow8_refresh_jkt_ok"],
        r4["flow9_chained_pt_ok"],
        r4["flow10_mission_prop_ok"]
    ));
    // =========================================================================
    // QA-R5: Hosted-Page Callbacks (ConsumeAuthorizationInteractionVisit,
    // ConsumePersonTokenInteractionVisit, ConsumeSessionInteractionVisit)
    // =========================================================================
    let r5 = &go_r_suite["r5"];
    let r5_pass = r5["auth_wrong_code_no_cb"].as_bool() == Some(true)
        && r5["auth_while_pending"].as_bool() == Some(true)
        && r5["auth_resumed_cb_ok"].as_bool() == Some(true)
        && r5["auth_approved_cb_ok"].as_bool() == Some(true)
        && r5["auth_gone_cb_ok"].as_bool() == Some(true)
        && r5["auth_denied_cb_ok"].as_bool() == Some(true)
        && r5["auth_abandoned_cb_ok"].as_bool() == Some(true)
        && r5["auth_expired_cb_ok"].as_bool() == Some(true)
        && r5["auth_rii_retained_cb"].as_bool() == Some(true)
        && r5["pt_wrong_code_no_cb"].as_bool() == Some(true)
        && r5["pt_resumed_cb_ok"].as_bool() == Some(true)
        && r5["pt_approved_cb_ok"].as_bool() == Some(true)
        && r5["pt_denied_cb_ok"].as_bool() == Some(true)
        && r5["pt_expired_cb_ok"].as_bool() == Some(true)
        && r5["ses_wrong_code_no_cb"].as_bool() == Some(true)
        && r5["ses_resumed_cb_ok"].as_bool() == Some(true)
        && r5["ses_approved_cb_ok"].as_bool() == Some(true)
        && r5["ses_denied_cb_ok"].as_bool() == Some(true)
        && r5["ses_expired_cb_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-R5".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Hosted-Page Callbacks Over Real HTTPS: ConsumeAuthorizationInteractionVisit, ConsumePersonTokenInteractionVisit, ConsumeSessionInteractionVisit, *CallbackURL, and RedirectToResourceInteraction".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r5_pass,
        summary: format!(
            "Hosted-page callbacks verified over real HTTPS: AuthorizationInteraction (wrong code no cb, resume, approved, access_denied, user_abandoned, interaction_expired, server_error, RedirectToResourceInteraction empty cb) ok={}, PersonTokenInteraction (wrong code no cb, resume, approved, access_denied, interaction_expired) ok={}, SessionInteraction (wrong code no cb, resume, approved, access_denied, interaction_expired) ok={}",
            r5["auth_rii_retained_cb"].as_bool() == Some(true) && r5["auth_abandoned_cb_ok"].as_bool() == Some(true),
            r5["pt_approved_cb_ok"].as_bool() == Some(true) && r5["pt_expired_cb_ok"].as_bool() == Some(true),
            r5["ses_approved_cb_ok"].as_bool() == Some(true) && r5["ses_expired_cb_ok"].as_bool() == Some(true),
        ),
        evidence: r5.clone(),
    });
    transcript_lines.push(format!(
        "[QA-R5] PASS={}: auth_cb={} pt_cb={} ses_cb={} rii_retained_cb={}",
        r5_pass,
        r5["auth_approved_cb_ok"],
        r5["pt_approved_cb_ok"],
        r5["ses_approved_cb_ok"],
        r5["auth_rii_retained_cb"]
    ));

    // =========================================================================
    // QA-R6: Updated QA-P10 & QA-Q4 Boundary Re-Verification + Full Regression
    // =========================================================================
    let p10_passed = cases
        .iter()
        .find(|c| c.id == "QA-P10")
        .map(|c| c.passed_expectation)
        .unwrap_or(false);
    let q4_passed = cases
        .iter()
        .find(|c| c.id == "QA-Q4")
        .map(|c| c.passed_expectation)
        .unwrap_or(false);
    let all_prior_passed = cases.iter().all(|c| c.passed_expectation);
    let r6_pass = p10_passed
        && q4_passed
        && all_prior_passed
        && r2_pass
        && r3_pass;

    cases.push(QaCaseReceipt {
        id: "QA-R6".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Updated QA-P10 (B2, B3-subagent, B4) & QA-Q4 Boundary Re-Verification + Full 112-Case Regression".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: r6_pass,
        summary: format!(
            "QA-P10 B2 (AS-issued AuthToken as upstream_token with receipt) & B4 (mission-bound upstream_token with issuance record) and QA-Q4 4-party mission boundaries resolved (200 OK / 202 Accepted) on aauth-go 8a3734dd; unrecorded hand-minted tokens return 400 invalid_upstream_token; B3-subagent (500) pinned; all {} prior cases pass={}",
            cases.len(),
            all_prior_passed,
        ),
        evidence: json!({
            "qa_p10_passed": p10_passed,
            "qa_q4_passed": q4_passed,
            "all_prior_cases_passed": all_prior_passed,
            "prior_case_count": cases.len(),
        }),
    });
    transcript_lines.push(format!(
        "[QA-R6] PASS={}: p10={} q4={} all_prior_passed={} count={}",
        r6_pass,
        p10_passed,
        q4_passed,
        all_prior_passed,
        cases.len() - 1
    ));

    // =========================================================================
    // QA-R7: Consumer Documentation Sufficiency Audit (aauth-go 8a3734dd)
    // =========================================================================
    let go_conf_md = fs::read_to_string(go_mod_dir.join("CONFORMANCE.md"))?;
    let go_guide_md = fs::read_to_string(go_mod_dir.join("USE-IN-YOUR-SERVICE.md"))?;
    let go_interp_md = fs::read_to_string(go_mod_dir.join("INTERPRETATIONS.md"))?;
    let go_journeys_md = fs::read_to_string(go_mod_dir.join("JOURNEYS.md"))?;

    let conf_ok = go_conf_md.contains("Changes on 2026-10-31: four-party call chaining.")
        && go_conf_md.contains("Features added on 2026-10-31:")
        && go_conf_md.contains("IssuedTokens");
    let guide_ok = go_guide_md.contains("IssuedTokens")
        && go_guide_md.contains("agent.Pending")
        && go_guide_md.contains("ConsumeAuthorizationInteractionVisit")
        && go_guide_md.contains("ConsumePersonTokenInteractionVisit")
        && go_guide_md.contains("ConsumeSessionInteractionVisit")
        && go_guide_md.contains("RedirectToResourceInteraction");
    let interp_ok = go_interp_md.contains("upstream_token") && go_interp_md.contains("revoked_upstream_token");
    let journeys_chain_updated = go_journeys_md.contains("`integration/call_chaining_hops_test.go`");
    let journeys_mission_stale_bullet = go_journeys_md.contains("Missing: call chaining; budgets and R3 in a mission; deferred mission update and completion; and revocation.");

    let r7_pass = conf_ok && guide_ok && interp_ok && journeys_chain_updated;

    cases.push(QaCaseReceipt {
        id: "QA-R7".into(),
        category: "R. Go Call Chaining, Polling & Hosted-Page Callbacks".into(),
        title: "Consumer Documentation Sufficiency Audit: CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md, and JOURNEYS.md on aauth-go 8a3734dd".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r7_pass,
        summary: format!(
            "Consumer documentation audit verified: CONFORMANCE.md (2026-10-31 chaining & polling entries + IssuedTokens + remaining boundaries)={}, USE-IN-YOUR-SERVICE.md (IssuedTokens, agent.Pending[T], *InteractionVisit & *CallbackURL & RedirectToResourceInteraction)={}, INTERPRETATIONS.md={}, JOURNEYS.md updated={} (minor doc note: JOURNEYS.md line 243 Mission lifecycle 'Missing:' bullet still lists 'call chaining; ... and revocation'={})",
            conf_ok, guide_ok, interp_ok, journeys_chain_updated, journeys_mission_stale_bullet,
        ),
        evidence: json!({
            "conformance_md_ok": conf_ok,
            "use_in_your_service_md_ok": guide_ok,
            "interpretations_md_ok": interp_ok,
            "journeys_chain_section_updated": journeys_chain_updated,
            "journeys_mission_line_243_minor_stale_note": journeys_mission_stale_bullet,
        }),
    });
    transcript_lines.push(format!(
        "[QA-R7] PASS={}: conf={} guide={} interp={} journeys={} (minor_note_line243={})",
        r7_pass, conf_ok, guide_ok, interp_ok, journeys_chain_updated, journeys_mission_stale_bullet
    ));

    Ok(())
}
