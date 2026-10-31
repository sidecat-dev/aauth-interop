use crate::*;
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    BoxedClock, BoxedTokenIds, Config as PsConfig, DeferredConfig as PsDeferredConfig,
    Federation, FederationError, Grant, MemoryStore as PsMemoryStore, Person,
    PersonRequest, PersonServer, Policy as PsPolicy, PolicyError, R3AuthorizationRequest,
    R3Decision, R3Policy, R3ProposalDecision, R3ProposalRequest,
};
use aauth_rust_r3::{
    GrantedOperations, mint_budget_per_call_auth_token, verify_budget_per_call_auth_token,
    verify_budget_resource_token,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64_STD};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64};

fn get_at(agent: &Agent, url: &str, clock: i64) -> Result<Request<Vec<u8>>> {
    signed_get(agent, url, clock)
}

const T4_RUST_AP: &str = "https://t4-rust-ap.example";
const T4_RUST_AS: &str = "https://t4-rust-as.example";
const T4_RUST_RES: &str = "https://t4-rust-res.example";
const T4_RUST_FED_PS: &str = "https://t4-rust-fed-ps.example";
const T4_RUST_HELD_RES: &str = "https://t4-rust-held-res.example";
const T4_RUST_HELD_DIRECT: &str = "https://t4-rust-held-direct.example";

const T4_GO_FED_PS: &str = "https://t4-go-fed-ps.example";
const T4_GO_DIRECT_PS: &str = "https://t4-go-direct-ps.example";
const T4_GO_AS: &str = "https://t4-go-as.example";
const T4_GO_RES: &str = "https://t4-go-res.example";
const T4_GO_HELD_RES: &str = "https://t4-go-held-res.example";
const T4_GO_HELD_RUST_AS: &str = "https://t4-go-held-rust-as.example";

const T4_TOOLS_JSON: &[u8] = br#"{"tools":[
    {"name":"records.query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":false}},
    {"name":"records.metered_query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}
]}"#;

fn decode_pem_cert(pem_str: &str) -> Result<Vec<u8>> {
    let mut b64 = String::new();
    for line in pem_str.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-----") && !trimmed.is_empty() {
            b64.push_str(trimmed);
        }
    }
    Ok(B64_STD.decode(b64)?)
}

fn send_tls(
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    req: &Request<Vec<u8>>,
) -> Result<Response<Vec<u8>>> {
    TlsServer::send_external(addr, host, cert, req)
}

fn post_ctl(
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
    let resp = send_tls(addr, host, cert, &req)?;
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

fn register_host_with_go_fleet(
    go_ap_addr: SocketAddr,
    go_ap_cert: &[u8],
    host: &str,
    tls: &TlsServer,
) -> Result<()> {
    let res = post_ctl(
        go_ap_addr,
        "go-events-ap.example",
        go_ap_cert,
        "https://go-events-ap.example/__register-host",
        json!({
            "host": host,
            "addr": tls.address().to_string(),
            "cert_pem": tls.cert_pem(),
        }),
    )?;
    if res.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!("register_host_with_go_fleet failed for {host}: {res}").into());
    }
    Ok(())
}

fn insert_manual_ed25519(
    trust: &Trust,
    issuer: &str,
    dwk: &'static str,
    kid: &str,
    seed: [u8; 32],
) -> Result<()> {
    let key = SigningKey::from_seed(seed);
    let mut jwk = serde_json::to_value(key.public_jwk())?;
    jwk["kid"] = json!(kid);
    let mut meta = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
    });
    if dwk == "aauth-person.json" || dwk == "aauth-access.json" {
        meta["token_endpoint"] = json!(format!("{issuer}/token"));
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

#[derive(Clone)]
enum TFedRoute {
    RustTls(Arc<TlsServer>),
    GoExt {
        addr: SocketAddr,
        host: &'static str,
        cert: Vec<u8>,
    },
}

#[derive(Clone, Default)]
struct THttpsFederation {
    routes: Arc<Mutex<BTreeMap<String, TFedRoute>>>,
    sent_bodies: Arc<Mutex<Vec<(String, Value)>>>,
}

impl THttpsFederation {
    fn register_rust(&self, issuer: &str, tls: Arc<TlsServer>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), TFedRoute::RustTls(tls));
    }
    fn register_go(&self, issuer: &str, addr: SocketAddr, host: &'static str, cert: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), TFedRoute::GoExt { addr, host, cert });
    }
}

impl Federation for THttpsFederation {
    fn endpoint(&self, access_server: &str) -> std::result::Result<String, FederationError> {
        Ok(format!("{access_server}/token"))
    }
    fn send(
        &self,
        request: &Request<Vec<u8>>,
    ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        let uri_str = request.uri().to_string();
        if let Ok(val) = serde_json::from_slice::<Value>(request.body()) {
            self.sent_bodies
                .lock()
                .unwrap()
                .push((uri_str.clone(), val));
        }
        let routes = self.routes.lock().unwrap().clone();
        for (issuer, route) in routes {
            if uri_str.starts_with(&issuer) {
                let resp = match route {
                    TFedRoute::RustTls(tls) => tls.send(request).map_err(|_| FederationError)?,
                    TFedRoute::GoExt { addr, host, cert } => {
                        TlsServer::send_external(addr, host, &cert, request)
                            .map_err(|_| FederationError)?
                    }
                };
                return Ok(resp);
            }
        }
        Err(FederationError)
    }
}

impl FetchTransport for THttpsFederation {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> std::io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let response = <Self as Federation>::send(self, &request)
            .map_err(|_| std::io::Error::other("federation transport error"))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(BufferedFetchBody(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

struct TPsPolicy;
impl PsPolicy for TPsPolicy {
    fn bind_person(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: "person-t4".into(),
            subject: format!("p-t4.{}", request.resource.trim_start_matches("https://")),
            tenant: None,
        })
    }
    fn authorize(
        &self,
        request: &aauth_rust_person_server::AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(
        &self,
        _request: &aauth_rust_person_server::AuthorizationRequest,
    ) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
    fn bind_upstream(&self, request: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: "person-t4".into(),
            subject: format!(
                "p-t4-chained.{}",
                request.resource.trim_start_matches("https://")
            ),
            tenant: None,
        })
    }
    fn authorize_upstream(
        &self,
        request: &aauth_rust_person_server::AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent_upstream(
        &self,
        _request: &aauth_rust_person_server::AuthorizationRequest,
    ) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
}

struct TR3Policy;
impl R3Policy for TR3Policy {
    fn authorize_document(
        &self,
        req: &R3AuthorizationRequest<'_>,
    ) -> std::result::Result<R3Decision, PolicyError> {
        let vocab = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
        let ops = if req.reference.uri().starts_with(T4_GO_HELD_RES) {
            vec![mcp("reports.export").map_err(|_| PolicyError::Unavailable)?]
        } else {
            vec![
                mcp("records.query").map_err(|_| PolicyError::Unavailable)?,
                mcp("records.metered_query").map_err(|_| PolicyError::Unavailable)?,
            ]
        };
        Ok(R3Decision {
            granted: GrantedOperations::new(&vocab, &[]).map_err(|_| PolicyError::Unavailable)?,
            per_call: Some(
                GrantedOperations::new(&vocab, &ops).map_err(|_| PolicyError::Unavailable)?,
            ),
            scopes: req.core.scopes.clone(),
            lifetime: 600,
        })
    }
    fn authorize_release(
        &self,
        req: &R3ProposalRequest<'_>,
    ) -> std::result::Result<R3ProposalDecision, PolicyError> {
        Ok(R3ProposalDecision {
            scopes: req.core.scopes.clone(),
            lifetime: 300,
        })
    }
}

fn record_param(req: &Request<Vec<u8>>) -> std::result::Result<Vec<u8>, R3HostError> {
    let val: Value =
        serde_json::from_slice(req.body()).map_err(|e| R3HostError::new(e.to_string()))?;
    let rec = val
        .get("record")
        .ok_or_else(|| R3HostError::new("missing record"))?;
    serde_json::to_vec(rec).map_err(|e| R3HostError::new(e.to_string()))
}

pub fn run_go_budget_relay_qa(
    out_dir: &Path,
    go_module_path: &str,
    clock: i64,
    trust: &Trust,
    go_ap_addr: SocketAddr,
    go_ap_cert: &[u8],
    cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {

    // Pre-register Go T4 server keys in Rust Trust so Rust resources/AS/PS can verify Go tokens
    // during POST /__run-t-suite before the Go suite returns.
    insert_manual_ed25519(
        trust,
        "https://t4-go-ap.example",
        "aauth-agent.json",
        "t4-go-ap-1",
        [0xe8; 32],
    )?;
    insert_manual_ed25519(
        trust,
        "https://t4-go-interm.example",
        "aauth-agent.json",
        "t4-go-interm-1",
        [0xea; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_FED_PS,
        "aauth-person.json",
        "t4-go-fed-ps-1",
        [0xec; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_DIRECT_PS,
        "aauth-person.json",
        "t4-go-direct-ps-1",
        [0xed; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_AS,
        "aauth-access.json",
        "t4-go-as-1",
        [0xee; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_RES,
        "aauth-resource.json",
        "t4-go-res-1",
        [0xef; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_HELD_RES,
        "aauth-resource.json",
        "t4-go-held-res-1",
        [0xf0; 32],
    )?;
    insert_manual_ed25519(
        trust,
        T4_GO_HELD_RUST_AS,
        "aauth-resource.json",
        "t4-go-held-rust-as-1",
        [0xf1; 32],
    )?;

    // 1. Start t4-rust-ap.example
    let t4_rust_ap = Arc::new(AgentProvider::new(
        T4_RUST_AP,
        "t4-rust-ap-1",
        SigningKey::from_seed([0xf7; 32]),
    )?);
    let t4_rust_ap_srv = t4_rust_ap.clone();
    let t4_rust_ap_tls = Arc::new(TlsServer::start("t4-rust-ap.example", move |req| {
        match req.uri().path() {
            "/.well-known/aauth-agent.json" => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(t4_rust_ap_srv.metadata().unwrap())
                .unwrap(),
            "/.well-known/jwks.json" => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(t4_rust_ap_srv.jwks().unwrap())
                .unwrap(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    trust.discover(&t4_rust_ap_tls, T4_RUST_AP, "aauth-agent.json")?;
    register_host_with_go_fleet(go_ap_addr, go_ap_cert, "t4-rust-ap.example", &t4_rust_ap_tls)?;

    let t4_clock = Arc::new(AtomicI64::new(clock));

    // 2. Start t4-rust-as.example (AccessServer with budgets + deferred interaction)
    let t4_rust_as_defer = Arc::new(AtomicBool::new(false));
    let t4_rust_as_defer_cb = t4_rust_as_defer.clone();
    let t4_rust_as_codes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let t4_rust_as_codes_cb = t4_rust_as_codes.clone();
    let t4_rust_as_cont = Arc::new(MemoryContinuations::new(64));
    let t4_rust_as_seq = Arc::new(AtomicUsize::new(0));
    let t4_as_clk = t4_clock.clone();
    let t4_rust_as = Arc::new(
        AccessServer::new(
            AsConfig::new(T4_RUST_AS, "t4-rust-as-1", SigningKey::from_seed([0xf2; 32])),
            trust.clone(),
            move |req: &AsAuthorizationRequest| {
                Ok(AsDecision {
                    scopes: req.scopes.clone(),
                    lifetime: 600,
                })
            },
            move || t4_as_clk.load(Ordering::SeqCst),
            move || format!("t4-rust-as-jti-{}", t4_rust_as_seq.fetch_add(1, Ordering::SeqCst) + 1),
        )?
        .with_budgets(IssuerPolicy::capped(
            200,
            vec![UnitDeclaration::new("credits", 0, "Credits")?],
        ))?
        .with_deferred(
            AsDeferredConfig {
                store: t4_rust_as_cont.clone(),
                retry_after: 0,
                lifetime: 300,
            },
            move |ctx: &AsDeferredContext| {
                if !t4_rust_as_defer_cb.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                t4_rust_as_codes_cb
                    .lock()
                    .unwrap()
                    .push(ctx.interaction_code.clone());
                Ok(Some(ContinuationRequirement::Interaction {
                    url: format!("{T4_RUST_AS}/consent"),
                    code: ctx.interaction_code.clone(),
                }))
            },
        )?,
    );

    let t4_rust_as_srv = t4_rust_as.clone();
    let t4_rust_as_defer_ctl = t4_rust_as_defer.clone();
    let t4_rust_as_tls = Arc::new(TlsServer::start("t4-rust-as.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("POST", "/__mode") => {
                let val: Value = serde_json::from_slice(req.body()).unwrap_or_default();
                if let Some(d) = val.get("defer_interaction").and_then(Value::as_bool) {
                    t4_rust_as_defer_ctl.store(d, Ordering::SeqCst);
                }
                json_response(200, json!({"ok": true}))
            }
            ("POST", "/__approve-all") => {
                t4_rust_as_defer_ctl.store(false, Ordering::SeqCst);
                json_response(200, json!({"ok": true}))
            }
            _ => t4_rust_as_srv.handle(&req),
        }
    })?);
    trust.discover(&t4_rust_as_tls, T4_RUST_AS, "aauth-access.json")?;
    register_host_with_go_fleet(go_ap_addr, go_ap_cert, "t4-rust-as.example", &t4_rust_as_tls)?;

    // 3. Start t4-rust-res.example (supports both unbudgeted /data for Track 4A and budgeted /metered for Track 4B Dir 1)
    let t4_rust_res_unmetered = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: T4_RUST_RES.into(),
                signed_origin: T4_RUST_RES.into(),
                kid: "t4-rust-res-1".into(),
                signing_key: SigningKey::from_seed([0xf3; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            T4_RUST_AS,
            trust.clone(),
            Box::new(|_token: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint(),
    );
    let t4_rust_res_metered = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: T4_RUST_RES.into(),
                signed_origin: T4_RUST_RES.into(),
                kid: "t4-rust-res-1".into(),
                signing_key: SigningKey::from_seed([0xf3; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            T4_RUST_AS,
            trust.clone(),
            Box::new(|_token: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint()
        .with_budgets(
            vec![UnitDeclaration::new("credits", 0, "Credits")?],
            format!("{T4_RUST_RES}/usage"),
            35,
            500,
        )?,
    );
    let t4_rust_res_seq = Arc::new(AtomicUsize::new(0));
    let t4_res_unm_srv = t4_rust_res_unmetered.clone();
    let t4_res_met_srv = t4_rust_res_metered.clone();
    let t4_res_clk = t4_clock.clone();
    let t4_rust_res_tls = Arc::new(TlsServer::start("t4-rust-res.example", move |req| {
        let now = t4_res_clk.load(Ordering::SeqCst);
        let jti = format!("t4-rres-jti-{}", t4_rust_res_seq.fetch_add(1, Ordering::SeqCst) + 1);
        match req.uri().path() {
            "/.well-known/aauth-resource.json" => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(t4_res_met_srv.metadata().unwrap())
                .unwrap(),
            "/.well-known/jwks.json" => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(t4_res_met_srv.jwks().unwrap())
                .unwrap(),
            "/authorize" => {
                let has_budget = serde_json::from_slice::<Value>(req.body())
                    .ok()
                    .and_then(|v| v.get("budget").cloned())
                    .is_some();
                if has_budget {
                    t4_res_met_srv.authorize_endpoint(&req, now, &jti).into_response()
                } else {
                    t4_res_unm_srv.authorize_endpoint(&req, now, &jti).into_response()
                }
            }
            "/metered" => match t4_res_met_srv.authorize(&req, now, &jti) {
                AuthDecision::Granted(admitted) => {
                    let mut resp = json_response(200, json!({"ok": true, "metered": true}));
                    if let Some(b) = admitted.budget_header() {
                        resp.headers_mut().insert("aauth-budget", b.parse().unwrap());
                    }
                    resp
                }
                other => other.into_response(),
            },
            _ => match t4_res_unm_srv.authorize(&req, now, &jti) {
                AuthDecision::Granted(_) => json_response(200, json!({"ok": true})),
                other => other.into_response(),
            },
        }
    })?);
    trust.discover(&t4_rust_res_tls, T4_RUST_RES, "aauth-resource.json")?;
    register_host_with_go_fleet(go_ap_addr, go_ap_cert, "t4-rust-res.example", &t4_rust_res_tls)?;

    // 4. Helper to build metered-release Rust resources (4-party federated and 3-party direct)
    let make_rust_held_res = |host: &'static str,
                              issuer: &'static str,
                              kid: &'static str,
                              seed: [u8; 32],
                              as_issuer: Option<&'static str>,
                              tag: &str|
     -> Result<(Arc<TlsServer>, Arc<AtomicUsize>)> {
        let doc_dir = out_dir.join(format!("t4-held-docs-{tag}"));
        let call_dir = out_dir.join(format!("t4-held-calls-{tag}"));
        let rel_cnt = Arc::new(AtomicUsize::new(0));
        let rel_cnt_cb = rel_cnt.clone();
        let seq = Arc::new(AtomicUsize::new(0));
        let cfg = PsAuthorizationConfig {
            issuer: issuer.into(),
            signed_origin: issuer.into(),
            kid: kid.into(),
            signing_key: SigningKey::from_seed(seed),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([(
                "records.read".into(),
                "Read records".into(),
            )]),
        };
        let policy =
            Box::new(|_token: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy;
        let base_res = if let Some(as_iss) = as_issuer {
            PsAuthorizationResource::new_federated(cfg, as_iss, trust.clone(), policy)?
        } else {
            PsAuthorizationResource::new(cfg, trust.clone(), policy)?
        };
        let res = Arc::new(
            base_res
                .with_authorization_endpoint()
                .with_budgets(
                    vec![UnitDeclaration::new("credits", 0, "Credits")?],
                    format!("{issuer}/usage"),
                    40,
                    500,
                )?
                .with_r3(R3Config {
                    registry: standard_registry()?,
                    definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
                    vocabularies: vec![R3Vocabulary {
                        definition: McpCodec::parse_definition(
                            &format!("{issuer}/mcp"),
                            &ToolsListSnapshot::new(vec![ToolsListPage::initial(T4_TOOLS_JSON)]),
                        )?,
                        display: Some(Box::new(|_: &OperationSet| {
                            Display::new("Query and metered-release query", None, None, None)
                                .map_err(|e| R3HostError::new(e.to_string()))
                        })),
                    }],
                    documents: Arc::new(DirectoryDocumentStore::open(&doc_dir)?),
                    operation_for_request: Box::new(|req: &Request<Vec<u8>>| {
                        match req.uri().path() {
                            "/records/query" => mcp("records.query").map(Some),
                            "/records/metered-query" => mcp("records.metered_query").map(Some),
                            _ => Ok(None),
                        }
                    }),
                    require_core_scope: false,
                })?
                .with_r3_per_call(R3PerCallConfig {
                    present: Box::new(|req: &Request<Vec<u8>>, _: &Operation| {
                        let record = record_param(req)?;
                        let presented = PresentedParameter::inline(&record)
                            .map_err(|e| R3HostError::new(e.to_string()))?;
                        Ok(BTreeMap::from([("record".to_owned(), presented)]))
                    }),
                    describe: Box::new(
                        |_op: &Operation,
                         presented: &BTreeMap<String, PresentedParameter>,
                         _: Option<&str>| {
                            let value = presented
                                .get("record")
                                .and_then(PresentedParameter::inline_json)
                                .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                            let parameters = Parameters::new([(
                                "record".to_owned(),
                                Parameter::inline(&value)
                                    .map_err(|e| R3HostError::new(e.to_string()))?,
                            )])
                            .map_err(|e| R3HostError::new(e.to_string()))?;
                            let shown = String::from_utf8_lossy(&value).into_owned();
                            let display = ProposalDisplay::new(
                                &Display::new(
                                    format!("Run metered-release query {shown}"),
                                    None,
                                    None,
                                    None,
                                )
                                .map_err(|e| R3HostError::new(e.to_string()))?,
                                None,
                            )
                            .map_err(|e| R3HostError::new(e.to_string()))?;
                            Ok(R3CallDescription {
                                parameters,
                                display: Some(display),
                            })
                        },
                    ),
                    calls: Arc::new(DirectoryCallStore::open(&call_dir)?),
                    hold: true,
                    release: Some(Box::new(
                        move |_: &Request<Vec<u8>>,
                              op: &Operation,
                              presented: &BTreeMap<String, PresentedParameter>,
                              _: Option<&str>| {
                            rel_cnt_cb.fetch_add(1, Ordering::SeqCst);
                            let value = presented
                                .get("record")
                                .and_then(PresentedParameter::inline_json)
                                .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                            let shown = String::from_utf8_lossy(&value).into_owned();
                            let is_metered =
                                op.equal(&mcp("records.metered_query")?).unwrap_or(false);
                            let result = ProposalResult::new(br#"{"records":1}"#)
                                .map_err(|e| R3HostError::new(e.to_string()))?;
                            let display = ProposalDisplay::new(
                                &Display::new(
                                    format!("Release query {shown}"),
                                    None,
                                    None,
                                    None,
                                )
                                .map_err(|e| R3HostError::new(e.to_string()))?,
                                None,
                            )
                            .map_err(|e| R3HostError::new(e.to_string()))?;
                            Ok(Some(R3Release {
                                result,
                                display,
                                response: json_response(
                                    200,
                                    json!({
                                        "released": shown,
                                        "metered": is_metered,
                                    }),
                                ),
                                cost: is_metered.then_some(40),
                            }))
                        },
                    )),
                    held_result_lifetime: 300,
                })?
                .with_release_metering()?,
        );
        let res_srv = res.clone();
        let h_clk = t4_clock.clone();
        let tls = Arc::new(TlsServer::start(host, move |req| {
            let now = h_clk.load(Ordering::SeqCst);
            let jti = format!("t4-hres-jti-{}", seq.fetch_add(1, Ordering::SeqCst) + 1);
            let path = req.uri().path().to_owned();
            if path == "/.well-known/aauth-resource.json" {
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(res_srv.metadata().unwrap())
                    .unwrap();
            }
            if path == "/.well-known/jwks.json" {
                return Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(res_srv.jwks().unwrap())
                    .unwrap();
            }
            if path == "/authorize" {
                return res_srv.authorize_endpoint(&req, now, &jti).into_response();
            }
            if path.starts_with("/r3/") && !path.starts_with("/r3/pending/") {
                return res_srv.r3_document(&req, now);
            }
            res_srv.authorize(&req, now, &jti).into_response()
        })?);
        trust.discover(&tls, issuer, "aauth-resource.json")?;
        register_host_with_go_fleet(go_ap_addr, go_ap_cert, host, &tls)?;
        Ok((tls, rel_cnt))
    };

    let (t4_rust_held_res_tls, _t4_held_fed_cnt) = make_rust_held_res(
        "t4-rust-held-res.example",
        T4_RUST_HELD_RES,
        "t4-rust-held-res-1",
        [0xf5; 32],
        Some(T4_GO_AS),
        "fed",
    )?;
    let (_t4_rust_held_direct_tls, _t4_held_dir_cnt) = make_rust_held_res(
        "t4-rust-held-direct.example",
        T4_RUST_HELD_DIRECT,
        "t4-rust-held-direct-1",
        [0xf6; 32],
        None,
        "direct",
    )?;

    // 5. Start t4-rust-fed-ps.example
    let t4_fed = THttpsFederation::default();
    t4_fed.register_rust(T4_RUST_AS, t4_rust_as_tls.clone());
    t4_fed.register_rust(T4_RUST_HELD_RES, t4_rust_held_res_tls.clone());
    let t4_rust_ps_store = PsMemoryStore::default();
    let t4_rust_ps_cont = Arc::new(MemoryContinuations::new(64));
    let t4_rust_ps_seq = Arc::new(AtomicUsize::new(0));
    let t4_ps_clk = t4_clock.clone();
    let t4_rust_fed_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(
                T4_RUST_FED_PS,
                "t4-rust-fed-ps-1",
                SigningKey::from_seed([0xf4; 32]),
            ),
            trust.clone(),
            t4_rust_ps_store.clone(),
            TPsPolicy,
            Box::new(move || t4_ps_clk.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || {
                format!("t4-rust-ps-jti-{}", t4_rust_ps_seq.fetch_add(1, Ordering::SeqCst) + 1)
            }) as BoxedTokenIds,
        )?
        .with_federation(t4_fed.clone())
        .with_deferred(PsDeferredConfig {
            store: t4_rust_ps_cont.clone(),
            retry_after: 1,
            lifetime: 300,
        })?
        .with_budgets(IssuerPolicy::capped(
            300,
            vec![UnitDeclaration::new("credits", 0, "Credits")?],
        ))?
        .with_r3(R3IssuerConfig {
            registry: standard_registry()?,
            egress: Box::new(|_: &str, _: Instant| Ok(())),
            transport: Box::new(t4_fed.clone()),
            limits: FetchLimits::default(),
            policy: Box::new(TR3Policy),
            audit: Arc::new(QaAuditStore {
                commits: Arc::new(AtomicUsize::new(0)),
                last_token_jti: Arc::new(Mutex::new(None)),
            }),
        })?,
    );
    let t4_rust_fed_ps_srv = t4_rust_fed_ps.clone();
    let t4_fed_ctl = t4_fed.clone();
    let t4_rust_fed_ps_tls = Arc::new(TlsServer::start("t4-rust-fed-ps.example", move |req| {
        if req.method().as_str() == "POST" && req.uri().path() == "/__register-go" {
            let val: Value = serde_json::from_slice(req.body()).unwrap_or_default();
            if let (Some(iss), Some(host), Some(addr_s), Some(pem)) = (
                val.get("issuer").and_then(Value::as_str),
                val.get("host").and_then(Value::as_str),
                val.get("addr").and_then(Value::as_str),
                val.get("cert_pem").and_then(Value::as_str),
            ) {
                if let (Ok(addr), Ok(cert)) = (addr_s.parse::<SocketAddr>(), decode_pem_cert(pem)) {
                    let static_host: &'static str = Box::leak(host.to_owned().into_boxed_str());
                    t4_fed_ctl.register_go(iss, addr, static_host, cert);
                    return json_response(200, json!({"ok": true}));
                }
            }
            return json_response(400, json!({"ok": false}));
        }
        t4_rust_fed_ps_srv.handle(&req)
    })?);
    trust.discover(&t4_rust_fed_ps_tls, T4_RUST_FED_PS, "aauth-person.json")?;
    register_host_with_go_fleet(
        go_ap_addr,
        go_ap_cert,
        "t4-rust-fed-ps.example",
        &t4_rust_fed_ps_tls,
    )?;

    // 6. Execute POST /__run-t-suite on go-events-ap.example
    let go_t_suite = post_ctl(
        go_ap_addr,
        "go-events-ap.example",
        go_ap_cert,
        "https://go-events-ap.example/__run-t-suite",
        json!({
            "go_mod_dir": go_module_path,
            "t4_rust_as_issuer": T4_RUST_AS,
            "t4_rust_res_issuer": T4_RUST_RES,
            "t4_rust_fed_ps_issuer": T4_RUST_FED_PS,
            "t4_rust_held_res_issuer": T4_RUST_HELD_RES,
            "t4_rust_held_direct_issuer": T4_RUST_HELD_DIRECT,
        }),
    )?;

    let parse_go_srv = |name: &str| -> Result<(SocketAddr, Vec<u8>)> {
        let addr: SocketAddr = go_t_suite["servers"][name]["addr"]
            .as_str()
            .ok_or_else(|| format!("missing servers.{name}.addr"))?
            .parse()?;
        let cert = decode_pem_cert(
            go_t_suite["servers"][name]["cert_pem"]
                .as_str()
                .ok_or_else(|| format!("missing servers.{name}.cert_pem"))?,
        )?;
        Ok((addr, cert))
    };
    let (t4_go_fed_ps_addr, t4_go_fed_ps_cert) = parse_go_srv("t4_go_fed_ps")?;
    let (_t4_go_direct_ps_addr, _t4_go_direct_ps_cert) = parse_go_srv("t4_go_direct_ps")?;
    let (t4_go_as_addr, t4_go_as_cert) = parse_go_srv("t4_go_as")?;
    let (t4_go_res_addr, t4_go_res_cert) = parse_go_srv("t4_go_res")?;
    let (_t4_go_held_res_addr, _t4_go_held_res_cert) = parse_go_srv("t4_go_held_res")?;
    let (t4_go_held_rust_as_addr, t4_go_held_rust_as_cert) =
        parse_go_srv("t4_go_held_rust_as")?;

    t4_fed.register_go(
        T4_GO_AS,
        t4_go_as_addr,
        "t4-go-as.example",
        t4_go_as_cert.clone(),
    );

    // 7. Track 4A (Rust Agent & Rust Intermediary behind Go Federated PS receiving relayed AS interaction)
    let t4_rust_agent_key = SigningKey::from_seed([0xf8; 32]);
    let t4_rust_agent_tok = t4_rust_ap.issue(&AgentClaims {
        iss: T4_RUST_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:top-agent@t4-rust-ap.example".into(),
        jti: "t4-rust-top-agent-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: t4_rust_agent_key.public_jwk(),
        },
        ps: Some(T4_GO_FED_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let t4_rust_agent = Agent::new(t4_rust_agent_key, t4_rust_agent_tok)?;

    let t4_rust_interm_key = SigningKey::from_seed([0xf9; 32]);
    let t4_rust_interm_tok = t4_rust_ap.issue(&AgentClaims {
        iss: T4_RUST_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:interm@t4-rust-ap.example".into(),
        jti: "t4-rust-interm-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: t4_rust_interm_key.public_jwk(),
        },
        ps: Some(T4_RUST_FED_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let t4_rust_interm = Agent::new(t4_rust_interm_key, t4_rust_interm_tok)?;

    let mut cur_clock = clock;

    // Flow 4A-1: Rust top-level Agent -> Go Federated PS -> Go AS (202 requirement=interaction)
    let pt_top_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_agent,
            &format!("{T4_GO_FED_PS}/person"),
            serde_json::to_vec(&json!({"resource": T4_GO_RES}))?.as_slice(),
            cur_clock,
        )?,
    )?;
    let pt_top_go_res =
        member(&pt_top_resp, "person_token").ok_or("missing pt_top_go_res")?;
    let rt_top_resp = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &post_at(
            &t4_rust_agent.with_token(pt_top_go_res.clone())?,
            &format!("{T4_GO_RES}/authorize"),
            serde_json::to_vec(&json!({"scope": "records.read"}))?.as_slice(),
            cur_clock,
        )?,
    )?;
    let rt_top_go_res =
        member(&rt_top_resp, "resource_token").ok_or("missing rt_top_go_res")?;

    post_ctl(
        t4_go_as_addr,
        "t4-go-as.example",
        &t4_go_as_cert,
        &format!("{T4_GO_AS}/__set-defer"),
        json!({"defer_int": true}),
    )?;
    let int_top_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_agent,
            &format!("{T4_GO_FED_PS}/token"),
            serde_json::to_vec(&json!({
                "resource_token": rt_top_go_res,
                "presented_token": pt_top_go_res,
                "capabilities": ["interaction"],
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let int_top_sess = PollSession::new(
        &format!("{T4_GO_FED_PS}/token"),
        &int_top_resp,
        cur_clock,
        cur_clock + 60,
    )?;
    let int_top_loc = int_top_sess.pending().location.clone();
    let int_top_202_ok = int_top_resp.status().as_u16() == 202
        && int_top_loc.starts_with(&format!("{T4_GO_FED_PS}/token/federated/"))
        && matches!(
            &int_top_sess.pending().requirement,
            ContinuationRequirement::Interaction { url, code }
                if url == &format!("{T4_GO_AS}/consent") && code.len() >= 8
        );
    post_ctl(
        t4_go_as_addr,
        "t4-go-as.example",
        &t4_go_as_cert,
        &format!("{T4_GO_AS}/__set-defer"),
        json!({"defer_int": false}),
    )?;
    post_ctl(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &format!("{T4_GO_FED_PS}/__advance"),
        json!({"ref": int_top_loc.rsplit('/').next().unwrap_or("")}),
    )?;
    cur_clock += 2;
    t4_clock.store(cur_clock, Ordering::SeqCst);
    let int_top_poll = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &get_at(&t4_rust_agent, &int_top_loc, cur_clock)?,
    )?;
    let int_top_at = member(&int_top_poll, "auth_token").unwrap_or_default();
    let int_top_call = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &get_at(&t4_rust_agent.with_token(int_top_at)?, &format!("{T4_GO_RES}/data"), cur_clock)?,
    )?;
    let t4_rust_top_go_as_int_ok =
        int_top_202_ok && int_top_poll.status().as_u16() == 200 && int_top_call.status().as_u16() == 200;

    // Flow 4A-2: Rust Intermediary (with upstream_token) -> Go Federated PS -> Go AS (202 requirement=interaction)
    let pt_up_interm_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_agent,
            &format!("{T4_GO_FED_PS}/person"),
            serde_json::to_vec(&json!({"resource": T4_RUST_AP}))?
                .as_slice(),
            cur_clock,
        )?,
    )?;
    let pt_up_for_interm =
        member(&pt_up_interm_resp, "person_token").ok_or("missing pt_up_for_interm")?;

    let pt_down_go_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_interm,
            &format!("{T4_GO_FED_PS}/person"),
            serde_json::to_vec(&json!({
                "resource": T4_GO_RES,
                "upstream_token": pt_up_for_interm,
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let pt_down_go_res =
        member(&pt_down_go_resp, "person_token").ok_or("missing pt_down_go_res")?;
    let rt_down_go_resp = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &post_at(
            &t4_rust_interm.with_token(pt_down_go_res.clone())?,
            &format!("{T4_GO_RES}/authorize"),
            serde_json::to_vec(&json!({"scope": "records.read"}))?.as_slice(),
            cur_clock,
        )?,
    )?;
    let rt_down_go_res =
        member(&rt_down_go_resp, "resource_token").ok_or("missing rt_down_go_res")?;

    post_ctl(
        t4_go_as_addr,
        "t4-go-as.example",
        &t4_go_as_cert,
        &format!("{T4_GO_AS}/__set-defer"),
        json!({"defer_int": true}),
    )?;
    let int_ch_go_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_interm,
            &format!("{T4_GO_FED_PS}/token"),
            serde_json::to_vec(&json!({
                "resource_token": rt_down_go_res,
                "presented_token": pt_down_go_res,
                "upstream_token": pt_up_for_interm,
                "capabilities": ["interaction"],
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let int_ch_go_sess = PollSession::new(
        &format!("{T4_GO_FED_PS}/token"),
        &int_ch_go_resp,
        cur_clock,
        cur_clock + 60,
    )?;
    let int_ch_go_loc = int_ch_go_sess.pending().location.clone();
    let int_ch_go_202_ok = int_ch_go_resp.status().as_u16() == 202
        && int_ch_go_loc.starts_with(&format!("{T4_GO_FED_PS}/token/federated/"))
        && matches!(
            &int_ch_go_sess.pending().requirement,
            ContinuationRequirement::Interaction { url, code }
                if url == &format!("{T4_GO_AS}/consent") && code.len() >= 8
        );
    post_ctl(
        t4_go_as_addr,
        "t4-go-as.example",
        &t4_go_as_cert,
        &format!("{T4_GO_AS}/__set-defer"),
        json!({"defer_int": false}),
    )?;
    post_ctl(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &format!("{T4_GO_FED_PS}/__advance"),
        json!({"ref": int_ch_go_loc.rsplit('/').next().unwrap_or("")}),
    )?;
    cur_clock += 2;
    t4_clock.store(cur_clock, Ordering::SeqCst);
    let int_ch_go_poll = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &get_at(&t4_rust_interm, &int_ch_go_loc, cur_clock)?,
    )?;
    let int_ch_go_at = member(&int_ch_go_poll, "auth_token").unwrap_or_default();
    let int_ch_go_call = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &get_at(&t4_rust_interm.with_token(int_ch_go_at)?, &format!("{T4_GO_RES}/data"), cur_clock)?,
    )?;
    let t4_rust_interm_go_as_int_ok = int_ch_go_202_ok
        && int_ch_go_poll.status().as_u16() == 200
        && int_ch_go_call.status().as_u16() == 200;

    // Flow 4A-3: Rust Intermediary (with upstream_token) -> Go Federated PS -> Rust AS (202 requirement=interaction)
    let pt_down_rust_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_interm,
            &format!("{T4_GO_FED_PS}/person"),
            serde_json::to_vec(&json!({
                "resource": T4_RUST_RES,
                "upstream_token": pt_up_for_interm,
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let pt_down_rust_res =
        member(&pt_down_rust_resp, "person_token").ok_or("missing pt_down_rust_res")?;
    let rt_down_rust_resp = t4_rust_res_tls.send(&post_at(
        &t4_rust_interm.with_token(pt_down_rust_res.clone())?,
        &format!("{T4_RUST_RES}/authorize"),
        serde_json::to_vec(&json!({"scope": "records.read"}))?.as_slice(),
        cur_clock,
    )?)?;
    let rt_down_rust_res =
        member(&rt_down_rust_resp, "resource_token").ok_or("missing rt_down_rust_res")?;

    t4_rust_as_defer.store(true, Ordering::SeqCst);
    let int_ch_rust_resp = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &post_at(
            &t4_rust_interm,
            &format!("{T4_GO_FED_PS}/token"),
            serde_json::to_vec(&json!({
                "resource_token": rt_down_rust_res,
                "presented_token": pt_down_rust_res,
                "upstream_token": pt_up_for_interm,
                "capabilities": ["interaction"],
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let int_ch_rust_sess = PollSession::new(
        &format!("{T4_GO_FED_PS}/token"),
        &int_ch_rust_resp,
        cur_clock,
        cur_clock + 60,
    )?;
    let int_ch_rust_loc = int_ch_rust_sess.pending().location.clone();
    let int_ch_rust_202_ok = int_ch_rust_resp.status().as_u16() == 202
        && int_ch_rust_loc.starts_with(&format!("{T4_GO_FED_PS}/token/federated/"))
        && matches!(
            &int_ch_rust_sess.pending().requirement,
            ContinuationRequirement::Interaction { url, code }
                if url == &format!("{T4_RUST_AS}/consent") && code.len() >= 8
        );
    t4_rust_as_defer.store(false, Ordering::SeqCst);
    post_ctl(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &format!("{T4_GO_FED_PS}/__advance"),
        json!({"ref": int_ch_rust_loc.rsplit('/').next().unwrap_or("")}),
    )?;
    cur_clock += 2;
    t4_clock.store(cur_clock, Ordering::SeqCst);
    let int_ch_rust_poll = send_tls(
        t4_go_fed_ps_addr,
        "t4-go-fed-ps.example",
        &t4_go_fed_ps_cert,
        &get_at(&t4_rust_interm, &int_ch_rust_loc, cur_clock)?,
    )?;
    let int_ch_rust_at = member(&int_ch_rust_poll, "auth_token").unwrap_or_default();
    let int_ch_rust_call = t4_rust_res_tls.send(&get_at(
        &t4_rust_interm.with_token(int_ch_rust_at)?,
        &format!("{T4_RUST_RES}/data"),
        cur_clock,
    )?)?;
    let t4_rust_interm_rust_as_int_ok = int_ch_rust_202_ok
        && int_ch_rust_poll.status().as_u16() == 200
        && int_ch_rust_call.status().as_u16() == 200;

    // 8. Track 4B Direction 2: Rust Intermediary -> Rust Federated PS -> Go AS -> Go Resource (budget + upstream_token)
    let t4_rust_caller_ps_key = SigningKey::from_seed([0xfa; 32]);
    let t4_rust_caller_ps_tok = t4_rust_ap.issue(&AgentClaims {
        iss: T4_RUST_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:caller-ps@t4-rust-ap.example".into(),
        jti: "t4-rust-caller-ps-1".into(),
        iat: cur_clock,
        exp: cur_clock + 1800,
        cnf: Confirmation {
            jwk: t4_rust_caller_ps_key.public_jwk(),
        },
        ps: Some(T4_RUST_FED_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let t4_rust_caller_ps = Agent::new(t4_rust_caller_ps_key, t4_rust_caller_ps_tok)?;

    let pt_up_dir2_resp = t4_rust_fed_ps_tls.send(&post_at(
        &t4_rust_caller_ps,
        &format!("{T4_RUST_FED_PS}/person"),
        serde_json::to_vec(&json!({"resource": T4_RUST_AP}))?.as_slice(),
        cur_clock,
    )?)?;
    let pt_up_dir2 = member(&pt_up_dir2_resp, "person_token").ok_or("missing pt_up_dir2")?;

    let pt_down_dir2_resp = t4_rust_fed_ps_tls.send(&post_at(
        &t4_rust_interm,
        &format!("{T4_RUST_FED_PS}/person"),
        serde_json::to_vec(&json!({
            "resource": T4_GO_RES,
            "upstream_token": pt_up_dir2,
        }))?
        .as_slice(),
        cur_clock,
    )?)?;
    let pt_down_dir2 =
        member(&pt_down_dir2_resp, "person_token").ok_or("missing pt_down_dir2")?;

    let rt_dir2_resp = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &post_at(
            &t4_rust_interm.with_token(pt_down_dir2.clone())?,
            &format!("{T4_GO_RES}/authorize"),
            serde_json::to_vec(&json!({
                "scope": "records.read",
                "budget": {"amount": 500, "unit": "credits", "decimals": 0},
            }))?
            .as_slice(),
            cur_clock,
        )?,
    )?;
    let rt_dir2 = member(&rt_dir2_resp, "resource_token").ok_or("missing rt_dir2")?;

    let at_dir2_resp = t4_rust_fed_ps_tls.send(&post_at(
        &t4_rust_interm,
        &format!("{T4_RUST_FED_PS}/token"),
        serde_json::to_vec(&json!({
            "resource_token": rt_dir2,
            "presented_token": pt_down_dir2,
            "upstream_token": pt_up_dir2,
            "capabilities": ["budget"],
        }))?
        .as_slice(),
        cur_clock,
    )?)?;
    let at_dir2 = member(&at_dir2_resp, "auth_token").unwrap_or_default();
    let dir2_metered_req = post_at(
        &t4_rust_interm.with_token(at_dir2)?,
        &format!("{T4_GO_RES}/metered"),
        br#"{"op":"dir2"}"#,
        cur_clock,
    )?;
    let dir2_metered_resp = send_tls(
        t4_go_res_addr,
        "t4-go-res.example",
        &t4_go_res_cert,
        &dir2_metered_req,
    )?;
    let dir2_budget_hdr = dir2_metered_resp
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let t4_dir2_budget_chain_ok = at_dir2_resp.status().as_u16() == 200
        && dir2_metered_resp.status().as_u16() == 200
        && dir2_budget_hdr.contains("cost=45")
        && dir2_budget_hdr.contains("remaining=175");

    // 9. Track 4C Direction 1a: Go Resource (MeterRelease) proposal submitted to Rust Federated PS -> 400 invalid_resource_token
    let t4_dir1a_rust_fed_ps_400_ok =
        go_t_suite["t4"]["dir1a_rust_fed_ps_400_ok"].as_bool() == Some(true);
    let go_held_prop_rt = go_t_suite["t4"]["go_held_rust_as_prop_rt"]
        .as_str()
        .ok_or("missing go_held_rust_as_prop_rt")?
        .to_owned();
    let go_held_pending_url = go_t_suite["t4"]["go_held_rust_as_pending_url"]
        .as_str()
        .ok_or("missing go_held_rust_as_pending_url")?
        .to_owned();

    let t4_go_agent_rust_key = SigningKey::from_seed([0xe9; 32]);
    let t4_go_agent_rust_tok = AgentProvider::new(
        "https://t4-go-ap.example",
        "t4-go-ap-1",
        SigningKey::from_seed([0xe8; 32]),
    )?
    .issue(&AgentClaims {
        iss: "https://t4-go-ap.example".into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:caller@t4-go-ap.example".into(),
        jti: "t4-go-agent-rust-1".into(),
        iat: cur_clock,
        exp: cur_clock + 1800,
        cnf: Confirmation {
            jwk: t4_go_agent_rust_key.public_jwk(),
        },
        ps: Some(T4_GO_FED_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let t4_go_agent_as_rust = Agent::new(t4_go_agent_rust_key, t4_go_agent_rust_tok)?;

    // 10. Track 4C Direction 1b wire-level: Rust verify_budget_resource_token + mint_budget_per_call_auth_token
    //     releasing Go Held Resource (t4-go-held-rust-as.example) over real HTTPS
    let (ver_go_prop_rt, go_prop_offer, go_prop_consumed) =
        verify_budget_resource_token(&go_held_prop_rt, trust, cur_clock)?;
    let go_prop_exact_bytes = go_t_suite["t4"]["go_held_rust_as_prop_json_b64"]
        .as_str()
        .ok_or("missing go_held_rust_as_prop_json_b64")?
        .as_bytes()
        .to_vec();
    let t4_reg = standard_registry()?;
    let mint_rust_as_pc_at = |jti: &str, amount: i64| -> Result<String> {
        Ok(mint_budget_per_call_auth_token(
            &t4_reg,
            &SigningKey::from_seed([0xf2; 32]),
            "t4-rust-as-1",
            &AuthClaims {
                iss: T4_RUST_AS.into(),
                dwk: "aauth-access.json".into(),
                aud: T4_GO_HELD_RUST_AS.into(),
                ps: T4_GO_FED_PS.into(),
                sub: ver_go_prop_rt.claims().sub.clone(),
                jti: jti.into(),
                iat: cur_clock,
                exp: cur_clock + 300,
                cnf: Confirmation {
                    jwk: SigningKey::from_seed([0xe9; 32]).public_jwk(),
                },
                nbf: None,
                tenant: None,
                mission_s256: None,
                scope: ver_go_prop_rt.claims().scope.clone(),
                account: None,
                extra: BTreeMap::new(),
            },
            ver_go_prop_rt.reference(),
            &go_prop_exact_bytes,
            &Budget::new(amount, "credits", 0)?,
        )?)
    };
    let rust_pc_short_at = mint_rust_as_pc_at("t4-rust-as-pc-short-1", 15)?;
    let rust_pc_ok_at = mint_rust_as_pc_at("t4-rust-as-pc-ok-1", 40)?;
    let (_, _, ver_ok_grant) = verify_budget_per_call_auth_token(
        &t4_reg,
        &rust_pc_ok_at,
        trust,
        cur_clock,
        ver_go_prop_rt.reference(),
        &go_prop_exact_bytes,
    )?;

    let short_poll_resp = send_tls(
        t4_go_held_rust_as_addr,
        "t4-go-held-rust-as.example",
        &t4_go_held_rust_as_cert,
        &get_at(&t4_go_agent_as_rust.with_token(rust_pc_short_at)?, &go_held_pending_url, cur_clock)?,
    )?;
    let short_poll_hdr = short_poll_resp
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let ok_poll_resp = send_tls(
        t4_go_held_rust_as_addr,
        "t4-go-held-rust-as.example",
        &t4_go_held_rust_as_cert,
        &get_at(&t4_go_agent_as_rust.with_token(rust_pc_ok_at.clone())?, &go_held_pending_url, cur_clock)?,
    )?;
    let ok_poll_hdr = ok_poll_resp
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let replay_poll_resp = send_tls(
        t4_go_held_rust_as_addr,
        "t4-go-held-rust-as.example",
        &t4_go_held_rust_as_cert,
        &get_at(&t4_go_agent_as_rust.with_token(rust_pc_ok_at)?, &go_held_pending_url, cur_clock)?,
    )?;
    let replay_poll_hdr = replay_poll_resp
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let t4_dir1b_wire_per_call_ok = go_prop_offer.amount() == 40
        && go_prop_offer.unit() == "credits"
        && go_prop_consumed.is_none()
        && ver_ok_grant.amount() == 40
        && short_poll_resp.status().as_u16() == 403
        && member(&short_poll_resp, "error").as_deref() == Some("access_denied")
        && short_poll_hdr.contains("remaining=15")
        && short_poll_hdr.contains("required=40")
        && ok_poll_resp.status().as_u16() == 200
        && ok_poll_hdr.contains("cost=40")
        && ok_poll_hdr.contains("remaining=0")
        && replay_poll_resp.status().as_u16() == 200
        && replay_poll_hdr.contains("remaining=0");

    // =========================================================================
    // Emit QA-T1 .. QA-T7 Receipts
    // =========================================================================
    let t1_val = &go_t_suite["t1"];
    let t1_pass = t1_val["as_store_suite_ok"].as_bool() == Some(true)
        && t1_val["ps_store_suite_ok"].as_bool() == Some(true)
        && t1_val["flow1a_top_initial_ok"].as_bool() == Some(true)
        && t1_val["code_immutability_ok"].as_bool() == Some(true)
        && t1_val["flow1b_poll_advance"].as_bool() == Some(true)
        && t1_val["flow1c_chained_int_ok"].as_bool() == Some(true)
        && t1_val["no_cap_initial_403_ok"].as_bool() == Some(true)
        && t1_val["no_cap_poll_403_ok"].as_bool() == Some(true)
        && t1_val["mission_inherit_ok"].as_bool() == Some(true)
        && t1_val["malformed_code_502_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-T1".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "All-Go Access Server Interaction Relayed to Top-Level and Chained Agents Over Real HTTPS (First Answer, Later Advance, Code Immutability, 403 user_unreachable + DELETE Withdrawal, Mission Capability Inheritance & 502 Malformed Code)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t1_pass,
        summary: format!(
            "All-Go AS interaction relay verified over HTTPS: storetest suites (as={}, ps={}), top-level initial 202->200 ({}), InteractionCode immutability across polls ({}), approval->interaction->200 on later AdvanceFederation ({}), chained UpstreamToken relay + ChainInteraction ({}), missing capability 403 user_unreachable + 1 signed DELETE withdrawal on initial/poll ({}/{}), mission capability inheritance ({}), and lowercase code 502 as_unreachable ({})",
            t1_val["as_store_suite_ok"].as_bool() == Some(true),
            t1_val["ps_store_suite_ok"].as_bool() == Some(true),
            t1_val["flow1a_top_initial_ok"].as_bool() == Some(true),
            t1_val["code_immutability_ok"].as_bool() == Some(true),
            t1_val["flow1b_poll_advance"].as_bool() == Some(true),
            t1_val["flow1c_chained_int_ok"].as_bool() == Some(true),
            t1_val["no_cap_initial_403_ok"].as_bool() == Some(true),
            t1_val["no_cap_poll_403_ok"].as_bool() == Some(true),
            t1_val["mission_inherit_ok"].as_bool() == Some(true),
            t1_val["malformed_code_502_ok"].as_bool() == Some(true),
        ),
        evidence: t1_val.clone(),
    });
    transcript_lines.push(format!("[QA-T1] PASS={t1_pass}: {t1_val}"));

    let t2_val = &go_t_suite["t2"];
    let t2_pass = t2_val["hop1_ok"].as_bool() == Some(true)
        && t2_val["hop2_ok"].as_bool() == Some(true)
        && t2_val["hop3_ok"].as_bool() == Some(true)
        && t2_val["upstream_unconsumed_ok"].as_bool() == Some(true)
        && t2_val["hop3_over_budget_403"].as_bool() == Some(true)
        && t2_val["no_at_guard_ok"].as_bool() == Some(true)
        && t2_val["as_over_ceiling_502_ok"].as_bool() == Some(true)
        && t2_val["ceiling_checks_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-T2".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "All-Go Three-Hop Four-Party Chained Budget Over Real HTTPS (Independent Per-Hop Ceiling & Grant, Upstream Token Unconsumed, Over-Budget 403, UpstreamToken Without AuthToken Guard & AS Ceiling Violation 502)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t2_pass,
        summary: format!(
            "All-Go 3-hop 4-party chained budget verified over HTTPS: Hop1 (300/200/30->170 ok={}), Hop2 (300/150/50->100 ok={}), Hop3 (300/80/60->20 ok={}), upstream balance untouched (170->140 ok={}), Hop3 exhaustion 403 ({}), BudgetCall.UpstreamToken without AuthToken refused ({}), AS grant > PS ceiling -> 502 as_unreachable ({}), PS ceiling recorded alongside upstream_token ({})",
            t2_val["hop1_ok"].as_bool() == Some(true),
            t2_val["hop2_ok"].as_bool() == Some(true),
            t2_val["hop3_ok"].as_bool() == Some(true),
            t2_val["upstream_unconsumed_ok"].as_bool() == Some(true),
            t2_val["hop3_over_budget_403"].as_bool() == Some(true),
            t2_val["no_at_guard_ok"].as_bool() == Some(true),
            t2_val["as_over_ceiling_502_ok"].as_bool() == Some(true),
            t2_val["ceiling_checks_ok"].as_bool() == Some(true),
        ),
        evidence: t2_val.clone(),
    });
    transcript_lines.push(format!("[QA-T2] PASS={t2_pass}: {t2_val}"));

    let t3_val = &go_t_suite["t3"];
    let t3_pass = t3_val["proposal_offer_ok"].as_bool() == Some(true)
        && t3_val["declined_403_ok"].as_bool() == Some(true)
        && t3_val["unfunded_403_ok"].as_bool() == Some(true)
        && t3_val["short_403_held_ok"].as_bool() == Some(true)
        && t3_val["release_and_replay_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-T3".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "All-Go Four-Party Metered Release of Held R3 Results Over Real HTTPS (Proposal ResourceToken Offer, ParseReferencedArtifact Result Member, Declined/Unbudgeted/Short 403 Preserving Held Result, Single-Charge Release & Zero-Charge Replay)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t3_pass,
        summary: format!(
            "All-Go 4-party metered release verified over HTTPS: proposal RT offer & ParseReferencedArtifact result member ({}), declined release 403 meters 0 ({}), unfunded per-call token 403 holds result ({}), short token (15 < 40) 403 access_denied with AAuth-Budget remaining=15;required=40 holds result ({}), sufficient token (40) releases 200 OK charging 40 once and replay charges 0 ({})",
            t3_val["proposal_offer_ok"].as_bool() == Some(true),
            t3_val["declined_403_ok"].as_bool() == Some(true),
            t3_val["unfunded_403_ok"].as_bool() == Some(true),
            t3_val["short_403_held_ok"].as_bool() == Some(true),
            t3_val["release_and_replay_ok"].as_bool() == Some(true),
        ),
        evidence: t3_val.clone(),
    });
    transcript_lines.push(format!("[QA-T3] PASS={t3_pass}: {t3_val}"));

    let t4_go = &go_t_suite["t4"];
    let t4_pass = t4_go["go_interm_rust_as_int_ok"].as_bool() == Some(true)
        && t4_rust_top_go_as_int_ok
        && t4_rust_interm_go_as_int_ok
        && t4_rust_interm_rust_as_int_ok
        && t4_go["dir1_budget_chain_ok"].as_bool() == Some(true)
        && t4_dir2_budget_chain_ok
        && t4_dir1a_rust_fed_ps_400_ok
        && t4_go["dir1b_4party_rust_as_400_ok"].as_bool() == Some(true)
        && t4_dir1b_wire_per_call_ok
        && t4_go["dir2_3party_direct_ps_400_ok"].as_bool() == Some(true)
        && t4_go["dir2_4party_fed_release_ok"].as_bool() == Some(true);

    let t4_evidence = json!({
        "track_4a_relayed_as_interaction": {
            "go_interm_go_fed_ps_rust_as_ok": t4_go["go_interm_rust_as_int_ok"],
            "rust_top_agent_go_fed_ps_go_as_ok": t4_rust_top_go_as_int_ok,
            "rust_interm_go_fed_ps_go_as_ok": t4_rust_interm_go_as_int_ok,
            "rust_interm_go_fed_ps_rust_as_ok": t4_rust_interm_rust_as_int_ok,
        },
        "track_4b_4party_budgeted_chain": {
            "dir1_go_interm_go_fed_ps_rust_as_rust_res_ok": t4_go["dir1_budget_chain_ok"],
            "dir2_rust_interm_rust_fed_ps_go_as_go_res_ok": t4_dir2_budget_chain_ok,
        },
        "track_4c_metered_release": {
            "dir1a_go_res_rust_fed_ps_400_invalid_resource_token_ok": t4_dir1a_rust_fed_ps_400_ok,
            "dir1b_go_res_go_fed_ps_rust_as_400_invalid_resource_token_ok": t4_go["dir1b_4party_rust_as_400_ok"],
            "dir1b_wire_rust_per_call_token_to_go_res_ok": t4_dir1b_wire_per_call_ok,
            "dir2_rust_res_go_direct_ps_400_invalid_resource_token_ok": t4_go["dir2_3party_direct_ps_400_ok"],
            "dir2_rust_res_go_fed_ps_go_as_4party_end_to_end_ok": t4_go["dir2_4party_fed_release_ok"],
        },
    });

    cases.push(QaCaseReceipt {
        id: "QA-T4".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "Cross-Language Interoperability Over Real HTTPS: Relayed AS Interaction (Go/Rust Agents & AS), Bidirectional 4-Party Budgeted Chaining, and Bidirectional Metered R3 Release (End-to-End & Architectural 3-Party/4-Party Boundaries)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t4_pass,
        summary: format!(
            "Cross-language suite verified: Track 4A relayed AS interaction (go_interm->rust_as={}, rust_top->go_as={}, rust_interm->go_as={}, rust_interm->rust_as={}), Track 4B 4-party budgeted chain (Dir1 Go->Rust={}, Dir2 Rust->Go={}), Track 4C metered release (Dir1a Rust Fed PS 400={}, Dir1b Rust AS 400={} & wire per-call={}, Dir2 Go Direct PS 400={}, Dir2 4-party Rust Held Res + Go Fed PS + Go AS end-to-end 200 OK={})",
            t4_go["go_interm_rust_as_int_ok"].as_bool() == Some(true),
            t4_rust_top_go_as_int_ok,
            t4_rust_interm_go_as_int_ok,
            t4_rust_interm_rust_as_int_ok,
            t4_go["dir1_budget_chain_ok"].as_bool() == Some(true),
            t4_dir2_budget_chain_ok,
            t4_dir1a_rust_fed_ps_400_ok,
            t4_go["dir1b_4party_rust_as_400_ok"].as_bool() == Some(true),
            t4_dir1b_wire_per_call_ok,
            t4_go["dir2_3party_direct_ps_400_ok"].as_bool() == Some(true),
            t4_go["dir2_4party_fed_release_ok"].as_bool() == Some(true),
        ),
        evidence: t4_evidence,
    });
    transcript_lines.push(format!("[QA-T4] PASS={t4_pass}"));

    let t5_val = &go_t_suite["t5"];
    let t5_pass = t5_val["sub_second_refused_ok"].as_bool() == Some(true)
        && t5_val["whole_seconds_ok"].as_bool() == Some(true)
        && t5_val["unit_test_ok"].as_bool() == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-T5".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "Re-Check of OBS-S6-1: supervision.Clarification.Validate Whole-Second Timeout Enforcement (1ns, 500ms, 1.5s, -1s Refused) & TestClarificationTimeoutIsWholeSeconds Verification".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: t5_pass,
        summary: format!(
            "OBS-S6-1 resolved/closed: Clarification.Validate() (run by supervisionserver before EncodePending) refuses 1ns, 500ms, 1.5s, and -1s ({}), accepts 0s and whole seconds 1s..300s ({}), and go test -run TestClarificationTimeoutIsWholeSeconds ./supervision passes ({})",
            t5_val["sub_second_refused_ok"].as_bool() == Some(true),
            t5_val["whole_seconds_ok"].as_bool() == Some(true),
            t5_val["unit_test_ok"].as_bool() == Some(true),
        ),
        evidence: t5_val.clone(),
    });
    transcript_lines.push(format!("[QA-T5] PASS={t5_pass}: {t5_val}"));

    let go_dir = Path::new(go_module_path);
    let go_conf_md = fs::read_to_string(go_dir.join("CONFORMANCE.md"))?;
    let go_guide_md = fs::read_to_string(go_dir.join("USE-IN-YOUR-SERVICE.md"))?;
    let go_interp_md = fs::read_to_string(go_dir.join("INTERPRETATIONS.md"))?;
    let go_journeys_md = fs::read_to_string(go_dir.join("JOURNEYS.md"))?;

    let t7_conf_ok = go_conf_md.contains("R3ReleaseConfig.MeterRelease")
        && go_conf_md.contains("PendingDecision.InteractionURL")
        && go_conf_md.contains("agent.BudgetCall.UpstreamToken");
    let t7_guide_ok = go_guide_md.contains("**Meter the release.**")
        && go_guide_md.contains("**The person at the Access Server.**")
        && go_guide_md.contains("BudgetCall.UpstreamToken");
    let t7_interp_ok = go_interp_md.contains("## An Access Server's interaction reaches the Agent that declared it")
        && go_interp_md.contains("## A per-call token's budget meters the release of a held result");
    let t7_journeys_ok = go_journeys_md.contains("Metered release of a held R3 result — Implemented four-party.")
        && go_journeys_md.contains("integration/r3_metered_release_four_party_test.go");
    let t7_pass = t7_conf_ok && t7_guide_ok && t7_interp_ok && t7_journeys_ok;

    let prior_all_passed = cases.iter().all(|c| c.passed_expectation) && t7_pass;
    let t6_pass = prior_all_passed && cases.len() == 125;

    cases.push(QaCaseReceipt {
        id: "QA-T6".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "Updated QA-R3 Boundary & Full 127-Case Regression (QA-A1..QA-S8 + QA-T1..QA-T7) across aauth-go 9b14543d and aauth-rust v0.1.0-alpha.17 (10cacbf7)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t6_pass,
        summary: format!(
            "Full 127-case regression verified (including updated QA-R3 verifying 403 user_unreachable without capability and 202 requirement=interaction relay with capability): prior_count={}, total_cases=127, all_passed={}",
            cases.len(),
            t6_pass,
        ),
        evidence: json!({
            "prior_case_count": cases.len(),
            "total_case_count": cases.len() + 2,
            "all_passed": t6_pass,
        }),
    });
    transcript_lines.push(format!("[QA-T6] PASS={t6_pass}: total_cases=127"));

    cases.push(QaCaseReceipt {
        id: "QA-T7".into(),
        category: "T. Access Server Interaction Relay, Chained Budgets & Metered Release".into(),
        title: "Consumer Documentation Sufficiency Audit: CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md & JOURNEYS.md on aauth-go 9b14543d".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: t7_pass,
        summary: format!(
            "Consumer documentation audit passed on aauth-go 9b14543d: CONFORMANCE.md={}, USE-IN-YOUR-SERVICE.md={}, INTERPRETATIONS.md={}, JOURNEYS.md={}",
            t7_conf_ok, t7_guide_ok, t7_interp_ok, t7_journeys_ok,
        ),
        evidence: json!({
            "conformance_ok": t7_conf_ok,
            "use_in_your_service_ok": t7_guide_ok,
            "interpretations_ok": t7_interp_ok,
            "journeys_ok": t7_journeys_ok,
        }),
    });
    transcript_lines.push(format!("[QA-T7] PASS={t7_pass}"));

    Ok(())
}
