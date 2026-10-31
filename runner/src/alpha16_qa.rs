use crate::*;
use aauth_rust_budgets::{Budget, IssuerPolicy, UnitDeclaration};
use aauth_rust_core::continuation::MemoryContinuations;
use aauth_rust_core::{CallOutcome, ResourceToken, RevocationDirectory};
use aauth_rust_jose::SigningKey;
use aauth_rust_person_server::{
    DeferredConfig as PsDeferredConfig, R3Policy, R3ProposalDecision, R3ProposalRequest,
    TokenTie as PsTokenTie, storetest,
};
use aauth_rust_r3::{
    Proposal, ProposalOptions, mint_budget_per_call_auth_token,
    mint_budget_proposal_resource_token, verify_budget_per_call_auth_token,
    verify_budget_resource_token,
};
use aauth_rust_resource::{PsAuthorizationConfig, PsAuthorizationResource};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64_STD};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

const Q2_AP: &str = "https://q2-rust-ap.example";
const Q2_PS: &str = "https://q2-rust-fed-ps.example";
const Q2_AS: &str = "https://q2-rust-as.example";
const Q2_RES: &str = "https://q2-rust-fed-res.example";
const Q2_RES_NOMISS: &str = "https://q2-rust-fed-res-nomiss.example";

const Q3_INTERM: &str = "https://q3-rust-interm.example";
const Q3_INTERM2: &str = "https://q3-rust-interm2.example";
const Q3_DOWN_RES: &str = "https://q3-rust-down-res.example";

const Q4_RUST_FED_PS: &str = "https://q4-rust-fed-ps.example";
const Q4_RUST_AS: &str = "https://q4-rust-as.example";
const Q4_RUST_RES_GO_AS: &str = "https://q4-rust-res-go-as.example";
const Q4_RUST_RES_RUST_AS: &str = "https://q4-rust-res-rust-as.example";
const Q4_RUST_RELAY: &str = "https://q4-rust-relay.example";

const Q5_RUST_DIRECT_PS: &str = "https://q5-rust-direct-ps.example";
const Q5_RUST_METERED_RES: &str = "https://q5-rust-metered-res.example";

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

fn register_q_host_with_go(
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
        return Err(format!("register_q_host_with_go failed for {host}: {res}").into());
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
            meta["scopes_supported"] = json!(["read", "records.read", "records.write"]);
            meta["scope_descriptions"] = json!({
                "read": "Read records",
                "records.read": "Read records",
                "records.write": "Write records"
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
fn discover_external(
    trust: &Trust,
    addr: SocketAddr,
    host: &'static str,
    cert: &[u8],
    issuer: &str,
    dwk: &str,
) -> Result<()> {
    let meta = send_https(addr, host, cert, &get_req(&format!("{issuer}/.well-known/{dwk}")))?;
    let uri = metadata_jwks_uri(issuer, meta.body())?;
    let jwks = send_https(addr, host, cert, &get_req(&uri))?;
    let snap = TrustedIssuerKeys::from_documents(issuer, dwk, meta.body(), jwks.body())?;
    trust.0.write().unwrap().insert((issuer.into(), dwk.into()), snap);
    Ok(())
}

fn get_at(agent: &Agent, url: &str, clock: i64) -> Result<Request<Vec<u8>>> {
    signed_get(agent, url, clock)
}

fn make_q_agent(
    ap_issuer: &str,
    ap_kid: &str,
    ap_seed: [u8; 32],
    local_name: &str,
    ps_issuer: &str,
    agent_seed: [u8; 32],
    clock: i64,
) -> Result<(Agent, String, String, AgentIdentity)> {
    let ap_host = ap_issuer.trim_start_matches("https://");
    let sub = format!("aauth:{local_name}@{ap_host}");
    let ap = AgentProvider::new(ap_issuer, ap_kid, SigningKey::from_seed(ap_seed))?;
    let tok = ap.issue(&AgentClaims {
        iss: ap_issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: sub.clone(),
        jti: format!("q-ag-{local_name}-1"),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(agent_seed).public_jwk(),
        },
        ps: Some(ps_issuer.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let agent = Agent::new(SigningKey::from_seed(agent_seed), tok.clone())?;
    let owner = AgentIdentity {
        issuer: ap_issuer.into(),
        subject: sub.clone(),
    };
    Ok((agent, tok, sub, owner))
}

fn signed_post_jwt(
    url: &str,
    body: &[u8],
    seed: [u8; 32],
    jwt: &str,
    clock: i64,
) -> Result<Request<Vec<u8>>> {
    let mut req = Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .body(body.to_vec())?;
    sign_request(
        &mut req,
        &SigningKey::from_seed(seed),
        KeyMaterial::Jwt {
            jwt: jwt.to_owned(),
            cache: false,
        },
        clock,
    )?;
    Ok(req)
}

fn signed_get_jwt(
    url: &str,
    seed: [u8; 32],
    jwt: &str,
    clock: i64,
) -> Result<Request<Vec<u8>>> {
    let mut req = Request::builder()
        .method("GET")
        .uri(url)
        .body(Vec::new())?;
    sign_request(
        &mut req,
        &SigningKey::from_seed(seed),
        KeyMaterial::Jwt {
            jwt: jwt.to_owned(),
            cache: false,
        },
        clock,
    )?;
    Ok(req)
}

#[derive(Clone)]
enum QFedRoute {
    RustTls(Arc<TlsServer>),
    GoExt {
        addr: SocketAddr,
        host: &'static str,
        cert: Vec<u8>,
    },
}

#[derive(Clone, Default)]
struct QMultiAsHttpsFederation {
    routes: Arc<Mutex<BTreeMap<String, QFedRoute>>>,
    sent_bodies: Arc<Mutex<Vec<(String, Value)>>>,
    override_auth_token: Arc<Mutex<Option<String>>>,
    after_send_hook: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
}
impl QMultiAsHttpsFederation {
    fn register_rust(&self, issuer: &str, tls: Arc<TlsServer>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), QFedRoute::RustTls(tls));
    }
    fn register_go(&self, issuer: &str, addr: SocketAddr, host: &'static str, cert: Vec<u8>) {
        self.routes
            .lock()
            .unwrap()
            .insert(issuer.to_owned(), QFedRoute::GoExt { addr, host, cert });
    }
}
impl Federation for QMultiAsHttpsFederation {
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
        if let Some(override_tok) = self.override_auth_token.lock().unwrap().take() {
            return Ok(json_response(200, json!({ "auth_token": override_tok })));
        }
        let routes = self.routes.lock().unwrap().clone();
        for (issuer, route) in routes {
            if uri_str.starts_with(&issuer) {
                let resp = match route {
                    QFedRoute::RustTls(tls) => tls.send(request).map_err(|_| FederationError)?,
                    QFedRoute::GoExt { addr, host, cert } => {
                        TlsServer::send_external(addr, host, &cert, request)
                            .map_err(|_| FederationError)?
                    }
                };
                if let Some(hook) = self.after_send_hook.lock().unwrap().take() {
                    hook();
                }
                return Ok(resp);
            }
        }
        Err(FederationError)
    }
}
#[derive(Clone, Default)]
struct QMultiTargetRevocationDirectory {
    calls: Arc<Mutex<Vec<(String, String, i64)>>>,
    routes: Arc<Mutex<BTreeMap<String, (Arc<TlsServer>, String, String, String, [u8; 32], i64)>>>,
}
impl QMultiTargetRevocationDirectory {
    fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
    fn snapshot(&self) -> Vec<(String, String, i64)> {
        self.calls.lock().unwrap().clone()
    }
    fn register_https_target(
        &self,
        recipient: &str,
        tls: Arc<TlsServer>,
        caller_issuer: &str,
        caller_dwk: &str,
        caller_kid: &str,
        caller_seed: [u8; 32],
        clock: i64,
    ) {
        self.routes.lock().unwrap().insert(
            recipient.to_owned(),
            (
                tls,
                caller_issuer.to_owned(),
                caller_dwk.to_owned(),
                caller_kid.to_owned(),
                caller_seed,
                clock,
            ),
        );
    }
}
impl RevocationDirectory for QMultiTargetRevocationDirectory {
    fn revoke(&self, recipient: &str, jti: &str, exp: i64) -> CallOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((recipient.to_owned(), jti.to_owned(), exp));
        let route_opt = self.routes.lock().unwrap().get(recipient).cloned();
        if let Some((tls, caller_iss, caller_dwk, caller_kid, caller_seed, clk)) = route_opt {
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
                    let _ = tls.send(&req);
                }
            }
        }
        CallOutcome::Recorded
    }
}

struct QMissionPsPolicy {
    person_id: String,
    seen_missions: Mutex<Vec<Option<String>>>,
    seen_upstream_missions: Mutex<Vec<Option<String>>>,
    on_consent: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    defer_next: AtomicBool,
}
impl QMissionPsPolicy {
    fn new(person_id: &str) -> Self {
        Self {
            person_id: person_id.to_owned(),
            seen_missions: Mutex::new(Vec::new()),
            seen_upstream_missions: Mutex::new(Vec::new()),
            on_consent: Mutex::new(None),
            defer_next: AtomicBool::new(false),
        }
    }
}
impl Policy for QMissionPsPolicy {
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
    fn authorize(&self, request: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        self.seen_missions
            .lock()
            .unwrap()
            .push(request.mission.as_ref().map(|m| m.document.s256().to_owned()));
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn authorize_upstream(
        &self,
        request: &AuthorizationRequest,
    ) -> std::result::Result<Grant, PolicyError> {
        self.seen_upstream_missions
            .lock()
            .unwrap()
            .push(request.mission.as_ref().map(|m| m.document.s256().to_owned()));
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, request: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        self.seen_missions
            .lock()
            .unwrap()
            .push(request.mission.as_ref().map(|m| m.document.s256().to_owned()));
        if let Some(hook) = self.on_consent.lock().unwrap().take() {
            hook();
        }
        let _ = self.defer_next.load(Ordering::SeqCst);
        Ok(())
    }
    fn consent_upstream(
        &self,
        request: &AuthorizationRequest,
    ) -> std::result::Result<(), PolicyError> {
        self.seen_upstream_missions
            .lock()
            .unwrap()
            .push(request.mission.as_ref().map(|m| m.document.s256().to_owned()));
        if let Some(hook) = self.on_consent.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }
}

struct QSharedMissionPsPolicy(Arc<QMissionPsPolicy>);
impl Policy for QSharedMissionPsPolicy {
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
pub fn run_alpha16_qa_cases(
    body: &Value,
    out_dir: &Path,
    go_module_path: &str,
    clock: i64,
    trust: &Trust,
    qa_cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {
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

    // =========================================================================
    // QA-Q1: Breaking API Migration (`R3Release::cost` & `MissionStore::commit_mission_token`)
    // & MemoryStore / RedbStore Store Contracts
    // =========================================================================
    storetest::check_store_contract(MemoryStore::default)
        .map_err(|e| format!("MemoryStore contract: {e:?}"))?;
    let q1_redb_seq = AtomicUsize::new(0);
    storetest::check_store_contract(|| {
        let p = out_dir.join(format!(
            "q1-contract-{}.redb",
            q1_redb_seq.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_file(&p);
        RedbStore::open(&p).expect("open RedbStore")
    })
    .map_err(|e| format!("RedbStore contract: {e:?}"))?;

    let q1_persist_seq = AtomicUsize::new(0);
    let q1_persist_paths: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let q1_persist_paths_f = q1_persist_paths.clone();
    let q1_persist_paths_r = q1_persist_paths.clone();
    storetest::check_persistence_contract(
        move || {
            let p = out_dir.join(format!(
                "q1-persist-{}.redb",
                q1_persist_seq.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = fs::remove_file(&p);
            q1_persist_paths_f.lock().unwrap().push(p.clone());
            RedbStore::open(&p).expect("open RedbStore for persistence")
        },
        move |store| {
            drop(store);
            let p = q1_persist_paths_r
                .lock()
                .unwrap()
                .last()
                .cloned()
                .ok_or_else(|| "missing persistence path".to_owned())?;
            RedbStore::open(&p).map_err(|e| e.to_string())
        },
    )
    .map_err(|e| format!("RedbStore persistence contract: {e:?}"))?;

    // Direct verification of `MissionStore::commit_mission_token` accepting federated receipts
    // (person_server: Some(...), issued_at on AS clock > at) and rejecting invalid bounds
    let decode_mission_bytes = |bytes: &[u8]| -> Result<ApprovedMission> {
        let s256 = digest(bytes);
        Ok(ApprovedMission::decode(
            &s256,
            &URL_SAFE_NO_PAD.encode(bytes),
        )?)
    };

    let q1_mem = MemoryStore::default();
    let q1_owner = AgentIdentity {
        issuer: Q2_AP.into(),
        subject: "aauth:caller@q2-rust-ap.example".into(),
    };
    let q1_mis_doc = decode_mission_bytes(
        json!({
            "approver": Q2_PS,
            "agent": "aauth:caller@q2-rust-ap.example",
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 1000),
            "description": "# Q1 Mission\nVerify federated mission receipt commit."
        })
        .to_string()
        .as_bytes(),
    )?;
    let q1_mis_rec = MissionRecord {
        person_server: Q2_PS.into(),
        owner: q1_owner.clone(),
        person_id: "alice-q1".into(),
        document: q1_mis_doc.clone(),
        state: MissionState::Active,
    };
    let q1_parent_pt = PsTokenRecord {
        kind: PsTokenKind::Person,
        token: PsTokenTie {
            reference: PsTokenReference {
                issuer: Q2_PS.into(),
                jti: "q1-pt-1".into(),
            },
            compact_sha256: "q1-pt-sha-1".into(),
        },
        person_server: None,
        person_id: "alice-q1".into(),
        subject: "sub-alice-q1".into(),
        resource: Q2_RES.into(),
        tenant: None,
        agent: q1_owner.clone(),
        principal: q1_owner.clone(),
        parent_agent: None,
        binding_generation: 0,
        agent_token_jti: "q1-ag-1".into(),
        agent_jkt: "q1-jkt-1".into(),
        issued_at: clock,
        expires_at: clock + 600,
        retain_until: clock + 3600,
        presented: None,
        upstream: None,
        r3: None,
    };
    q1_mem.commit(q1_parent_pt.clone(), true)?;
    q1_mem
        .install_approved_mission(q1_mis_rec.clone())
        .map_err(|e| format!("install_approved_mission q1: {e:?}"))?;

    // Federated receipt with `person_server: Some(Q2_PS)` and `issued_at = clock + 15` (AS clock skew)
    let mut q1_fed_receipt = q1_parent_pt.clone();
    q1_fed_receipt.kind = PsTokenKind::Auth;
    q1_fed_receipt.token.reference = PsTokenReference {
        issuer: Q2_AS.into(),
        jti: "q1-as-auth-1".into(),
    };
    q1_fed_receipt.token.compact_sha256 = "q1-as-auth-sha-1".into();
    q1_fed_receipt.person_server = Some(Q2_PS.into());
    q1_fed_receipt.issued_at = clock + 15;
    q1_fed_receipt.expires_at = clock + 600;
    q1_fed_receipt.presented = Some(q1_parent_pt.token.clone());

    let q1_fed_commit_ok = q1_mem
        .commit_mission_token(&q1_mis_rec, clock, q1_fed_receipt.clone(), false)
        .is_ok()
        && q1_mem.token(&q1_fed_receipt.token.reference)? == Some(q1_fed_receipt.clone());

    // Direct (non-federated) token with `issued_at > at` is still rejected with Conflict
    let mut q1_direct_future = q1_parent_pt.clone();
    q1_direct_future.token.reference.jti = "q1-pt-future".into();
    q1_direct_future.token.compact_sha256 = "q1-pt-sha-future".into();
    q1_direct_future.issued_at = clock + 1;
    let q1_direct_future_refused = q1_mem
        .commit_mission_token(&q1_mis_rec, clock, q1_direct_future, false)
        .is_err();

    // Federated receipt outliving mission.expires_at (clock + 1000) is rejected with Conflict
    let mut q1_fed_outlives = q1_fed_receipt.clone();
    q1_fed_outlives.token.reference.jti = "q1-as-auth-outlives".into();
    q1_fed_outlives.token.compact_sha256 = "q1-as-auth-sha-outlives".into();
    q1_fed_outlives.expires_at = clock + 1001;
    let q1_fed_outlives_refused = q1_mem
        .commit_mission_token(&q1_mis_rec, clock, q1_fed_outlives, false)
        .is_err();

    // Verify `R3Release` struct with `cost: Some(42)` and `cost: None`
    let q1_r3_res = ProposalResult::new(br#"{"ok":true}"#)?;
    let q1_r3_disp = ProposalDisplay::new(&Display::new("Release Q1", None, None, None)?, None)?;
    let q1_rel_some = R3Release {
        result: q1_r3_res.clone(),
        display: q1_r3_disp.clone(),
        response: json_response(200, json!({"ok": true})),
        cost: Some(42),
    };
    let q1_rel_none = R3Release {
        result: q1_r3_res,
        display: q1_r3_disp,
        response: json_response(200, json!({"ok": true})),
        cost: None,
    };
    let q1_r3_release_ok = q1_rel_some.cost == Some(42) && q1_rel_none.cost.is_none();

    let q1_pass = q1_fed_commit_ok
        && q1_direct_future_refused
        && q1_fed_outlives_refused
        && q1_r3_release_ok;
    cases.push(json!({
        "id": "QA-Q1",
        "classification": "VERIFIED_WORKING",
        "pass": q1_pass,
        "summary": format!(
            "Breaking API migration (R3Release::cost & MissionStore::commit_mission_token) & store contracts verified: MemoryStore & RedbStore check_store_contract + check_persistence_contract=true, commit_mission_token federated receipt (person_server=Some, AS clock iat>at)={}, direct future iat refused={}, outliving mission.expires_at refused={}, R3Release::cost Some(42)/None={}",
            q1_fed_commit_ok,
            q1_direct_future_refused,
            q1_fed_outlives_refused,
            q1_r3_release_ok,
        ),
        "details": {
            "memory_store_contract_ok": true,
            "redb_store_contract_ok": true,
            "redb_persistence_contract_ok": true,
            "federated_mission_receipt_commit_ok": q1_fed_commit_ok,
            "direct_future_iat_refused": q1_direct_future_refused,
            "federated_outliving_mission_refused": q1_fed_outlives_refused,
            "r3_release_cost_field_ok": q1_r3_release_ok,
        },
    }));
    // =========================================================================
    // QA-Q2: 4-Party Missions End-to-End Over Real HTTPS (Top-Level & Termination Points)
    // =========================================================================
    let q2_ap = Arc::new(AgentProvider::new(
        Q2_AP,
        "q2-ap-1",
        SigningKey::from_seed([0x61; 32]),
    )?);
    let q2_ap_srv = q2_ap.clone();
    let q2_ap_tls = Arc::new(TlsServer::start("q2-rust-ap.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-agent.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q2_ap_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q2_ap_srv.jwks().unwrap())
                .unwrap(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    trust.discover(&q2_ap_tls, Q2_AP, "aauth-agent.json")?;
    register_q_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "q2-rust-ap.example",
        &q2_ap_tls,
    )?;

    let q2_as_rev_dir = QMultiTargetRevocationDirectory::default();
    let q2_as_seen_missions: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let q2_as_seen_missions_cb = q2_as_seen_missions.clone();
    let q2_as_defer = Arc::new(AtomicBool::new(false));
    let q2_as_defer_cb = q2_as_defer.clone();
    let q2_as_cont = Arc::new(MemoryContinuations::new(64));
    let q2_as_def_cfg = AsDeferredConfig {
        store: q2_as_cont.clone(),
        retry_after: 1,
        lifetime: 300,
    };
    let q2_clock = Arc::new(std::sync::atomic::AtomicI64::new(clock));
    let q2_as_clock = q2_clock.clone();
    let q2_as_seq = Arc::new(AtomicUsize::new(0));
    let q2_as = Arc::new(
        AccessServer::new(
            AsConfig::new(Q2_AS, "q2-as-1", SigningKey::from_seed([0x62; 32])),
            trust.clone(),
            move |req: &AsAuthorizationRequest| {
                q2_as_seen_missions_cb
                    .lock()
                    .unwrap()
                    .push(req.resource.claims().mission_s256.clone());
                Ok(AsDecision {
                    scopes: req.scopes.clone(),
                    lifetime: 600,
                })
            },
            move || q2_as_clock.load(Ordering::SeqCst),
            move || format!("q2-as-jti-{}", q2_as_seq.fetch_add(1, Ordering::SeqCst) + 1),
        )?
        .with_revocation()
        .with_revocation_directory(Arc::new(q2_as_rev_dir.clone()))
        .with_deferred(q2_as_def_cfg, move |_ctx: &AsDeferredContext| {
            if !q2_as_defer_cb.load(Ordering::SeqCst) {
                return Ok(None);
            }
            Ok(Some(ContinuationRequirement::Approval))
        })?,
    );
    let q2_as_srv = q2_as.clone();
    let q2_as_tls = Arc::new(TlsServer::start("q2-rust-as.example", move |req| {
        q2_as_srv.handle(&req)
    })?);
    trust.discover(&q2_as_tls, Q2_AS, "aauth-access.json")?;

    let q2_fed = QMultiAsHttpsFederation::default();
    q2_fed.register_rust(Q2_AS, q2_as_tls.clone());

    let q2_ps_store = MemoryStore::default();
    let q2_ps_policy = Arc::new(QMissionPsPolicy::new("alice-q2"));
    let q2_ps_rev_dir = QMultiTargetRevocationDirectory::default();
    let q2_ps_cont = Arc::new(MemoryContinuations::new(64));
    let q2_ps_def_cfg = PsDeferredConfig {
        store: q2_ps_cont.clone(),
        retry_after: 1,
        lifetime: 300,
    };
    let q2_ps_clock = q2_clock.clone();
    let q2_ps_seq = Arc::new(AtomicUsize::new(0));
    let q2_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(Q2_PS, "q2-ps-1", SigningKey::from_seed([0x63; 32])),
            trust.clone(),
            q2_ps_store.clone(),
            QSharedMissionPsPolicy(q2_ps_policy.clone()),
            Box::new(move || q2_ps_clock.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || {
                format!("q2-ps-jti-{}", q2_ps_seq.fetch_add(1, Ordering::SeqCst) + 1)
            }) as BoxedTokenIds,
        )?
        .with_federation(q2_fed.clone())
        .with_deferred(q2_ps_def_cfg)?
        .with_revocation()
        .with_revocation_directory(Arc::new(q2_ps_rev_dir.clone())),
    );
    let q2_ps_srv = q2_ps.clone();
    let q2_ps_tls = Arc::new(TlsServer::start("q2-rust-fed-ps.example", move |req| {
        q2_ps_srv.handle(&req)
    })?);
    trust.discover(&q2_ps_tls, Q2_PS, "aauth-person.json")?;
    q2_ps_rev_dir.register_https_target(
        Q2_AS,
        q2_as_tls.clone(),
        Q2_PS,
        "aauth-person.json",
        "q2-ps-1",
        [0x63; 32],
        clock,
    );

    let q2_res_seen_missions: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let q2_res_seen_cb = q2_res_seen_missions.clone();
    let q2_res_seq = Arc::new(AtomicUsize::new(0));
    let q2_res = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: Q2_RES.into(),
                signed_origin: Q2_RES.into(),
                kid: "q2-res-1".into(),
                signing_key: SigningKey::from_seed([0x64; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            Q2_AS,
            trust.clone(),
            Box::new(move |tok: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
                q2_res_seen_cb
                    .lock()
                    .unwrap()
                    .push(tok.claims().mission_s256.clone());
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
    let q2_res_srv = q2_res.clone();
    let q2_res_tls = Arc::new(TlsServer::start("q2-rust-fed-res.example", move |req| {
        let jti = format!("q2-res-jti-{}", q2_res_seq.fetch_add(1, Ordering::SeqCst) + 1);
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q2_res_srv.metadata().unwrap())
                .unwrap(),
            ("GET", "/.well-known/jwks.json") => Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q2_res_srv.jwks().unwrap())
                .unwrap(),
            ("POST", "/authorize") => q2_res_srv
                .authorize_endpoint(&req, clock, &jti)
                .into_response(),
            ("POST", "/revoke") => q2_res_srv.revoke(&req, clock),
            ("GET", "/records/read") => match q2_res_srv.authorize(&req, clock, &jti) {
                AuthDecision::Granted(admitted) => json_response(
                    200,
                    json!({
                        "ok": true,
                        "sub": admitted.token().claims().sub,
                        "mission_s256": admitted.token().claims().mission_s256,
                    }),
                ),
                other => other.into_response(),
            },
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?);
    trust.discover(&q2_res_tls, Q2_RES, "aauth-resource.json")?;
    q2_as_rev_dir.register_https_target(
        Q2_RES,
        q2_res_tls.clone(),
        Q2_AS,
        "aauth-access.json",
        "q2-as-1",
        [0x62; 32],
        clock,
    );
    let q2_res_nomiss_seq = Arc::new(AtomicUsize::new(0));
    let q2_res_nomiss = Arc::new(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: Q2_RES_NOMISS.into(),
                signed_origin: Q2_RES_NOMISS.into(),
                kid: "q2-res-nomiss-1".into(),
                signing_key: SigningKey::from_seed([0x65; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            Q2_AS,
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
        .with_revocation(),
    );
    let q2_res_nomiss_srv = q2_res_nomiss.clone();
    let q2_res_nomiss_tls = Arc::new(TlsServer::start(
        "q2-rust-fed-res-nomiss.example",
        move |req| {
            let jti = format!(
                "q2-nomiss-jti-{}",
                q2_res_nomiss_seq.fetch_add(1, Ordering::SeqCst) + 1
            );
            match (req.method().as_str(), req.uri().path()) {
                ("GET", "/.well-known/aauth-resource.json") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(q2_res_nomiss_srv.metadata().unwrap())
                    .unwrap(),
                ("GET", "/.well-known/jwks.json") => Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(q2_res_nomiss_srv.jwks().unwrap())
                    .unwrap(),
                ("POST", "/authorize") => q2_res_nomiss_srv
                    .authorize_endpoint(&req, clock, &jti)
                    .into_response(),
                ("GET", "/records/read") => match q2_res_nomiss_srv.authorize(&req, clock, &jti) {
                    AuthDecision::Granted(_) => json_response(200, json!({"ok": true})),
                    other => other.into_response(),
                },
                _ => json_response(404, json!({"error": "not_found"})),
            }
        },
    )?);
    trust.discover(&q2_res_nomiss_tls, Q2_RES_NOMISS, "aauth-resource.json")?;

    let q2_caller_seed = [0x66; 32];
    let q2_caller_jwk = SigningKey::from_seed(q2_caller_seed).public_jwk();
    let q2_caller_tok = q2_ap.issue(&AgentClaims {
        iss: Q2_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:caller@q2-rust-ap.example".into(),
        jti: "q2-caller-ag-1".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: q2_caller_jwk.clone(),
        },
        ps: Some(Q2_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let q2_caller = Agent::new(
        SigningKey::from_seed(q2_caller_seed),
        q2_caller_tok.clone(),
    )?;
    let q2_owner = AgentIdentity {
        issuer: Q2_AP.into(),
        subject: "aauth:caller@q2-rust-ap.example".into(),
    };

    // Seed active mission M1 (expires at clock + 500)
    let q2_m1_doc = decode_mission_bytes(
        json!({
            "approver": Q2_PS,
            "agent": "aauth:caller@q2-rust-ap.example",
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 500),
            "description": "# Q2 Mission 1\nFour-party mission end-to-end verification."
        })
        .to_string()
        .as_bytes(),
    )?;
    let q2_m1_s256 = q2_m1_doc.s256().to_owned();
    let q2_m1_exp = q2_m1_doc.expires_at().unwrap_or(clock + 500);
    q2_ps_store
        .install_approved_mission(MissionRecord {
            person_server: Q2_PS.into(),
            owner: q2_owner.clone(),
            person_id: "alice-q2".into(),
            document: q2_m1_doc.clone(),
            state: MissionState::Active,
        })
        .map_err(|e| format!("install_approved_mission q2_m1: {e:?}"))?;

    // Obtain mission-bound PersonTokens for Q2_RES and Q2_RES_NOMISS
    let q2_pt_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/person"),
        json!({"resource": Q2_RES, "mission_s256": q2_m1_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_pt = member(&q2_pt_resp, "person_token").ok_or("missing q2_pt")?;
    let q2_pt_ver = PersonToken::parse(&q2_pt)?.verify(trust, clock)?;
    let q2_pt_claims_ok = q2_pt_ver.claims().mission_s256.as_deref() == Some(q2_m1_s256.as_str())
        && q2_pt_ver.claims().exp <= q2_m1_exp;

    let q2_pt_nomiss_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/person"),
        json!({"resource": Q2_RES_NOMISS, "mission_s256": q2_m1_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_pt_nomiss = member(&q2_pt_nomiss_resp, "person_token").ok_or("missing q2_pt_nomiss")?;

    // Federated Resource WITHOUT with_mission_context refuses mission-bound PersonToken on /authorize -> 401
    let q2_nomiss_authz_req = post_at(
        &q2_caller.with_token(q2_pt_nomiss.clone())?,
        &format!("{Q2_RES_NOMISS}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?;
    let q2_nomiss_authz_resp = q2_res_nomiss_tls.send(&q2_nomiss_authz_req)?;
    let q2_nomiss_refuses_pt = q2_nomiss_authz_resp.status().as_u16() == 401;

    // Federated Resource WITH with_mission_context issues AS-addressed ResourceToken carrying mission_s256
    let q2_authz_req = post_at(
        &q2_caller.with_token(q2_pt.clone())?,
        &format!("{Q2_RES}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?;
    let q2_authz_resp = q2_res_tls.send(&q2_authz_req)?;
    let q2_rt = member(&q2_authz_resp, "resource_token").ok_or("missing q2_rt")?;
    let q2_rt_ver = ResourceToken::parse(&q2_rt)?.verify(trust, clock)?;
    let q2_rt_claims_ok = q2_rt_ver.claims().aud == Q2_AS
        && q2_rt_ver.claims().mission_s256.as_deref() == Some(q2_m1_s256.as_str())
        && q2_rt_ver.claims().exp <= q2_pt_ver.claims().exp;

    // PS refuses a missionless ResourceToken or one for another mission_s256 before contacting AS (400 invalid_resource_token)
    let q2_rt_no_mis = mint_core_resource_token(
        &SigningKey::from_seed([0x64; 32]),
        "q2-res-1",
        &ResourceClaims {
            iss: Q2_RES.into(),
            dwk: "aauth-resource.json".into(),
            aud: Q2_AS.into(),
            ps: Q2_PS.into(),
            sub: q2_pt_ver.claims().sub.clone(),
            jti: "q2-rt-nomis".into(),
            presented_jti: q2_pt_ver.claims().jti.clone(),
            agent_jkt: q2_caller_jwk.thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("records.read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: Default::default(),
        },
    )?;
    let q2_sent_before = q2_fed.sent_bodies.lock().unwrap().len();
    let q2_no_mis_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_rt_no_mis, "presented_token": q2_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_rt_mismatch_refused = q2_no_mis_resp.status().as_u16() == 400
        && member(&q2_no_mis_resp, "error").as_deref() == Some("invalid_resource_token")
        && q2_fed.sent_bodies.lock().unwrap().len() == q2_sent_before;
    // Happy path 4-party mission exchange over HTTPS (PS -> AS -> PS -> Resource)
    let q2_tok_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_rt, "presented_token": q2_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_at = member(&q2_tok_resp, "auth_token").ok_or("missing q2_at")?;
    let q2_at_ver = AuthToken::parse(&q2_at)?.verify(trust, clock)?;
    let q2_at_claims = q2_at_ver.claims();
    let q2_receipt = q2_ps_store
        .token(&PsTokenReference {
            issuer: Q2_AS.into(),
            jti: q2_at_claims.jti.clone(),
        })?
        .ok_or("missing q2 federated mission receipt in store")?;
    let q2_res_call_req = signed_get_jwt(
        &format!("{Q2_RES}/records/read"),
        q2_caller_seed,
        &q2_at,
        clock,
    )?;
    let q2_res_call_resp = q2_res_tls.send(&q2_res_call_req)?;

    // Also mint a mission-bound AuthToken targeting Q2_RES_NOMISS and verify it is refused (401)
    let q2_at_nomiss = mint_auth_token(
        &SigningKey::from_seed([0x62; 32]),
        "q2-as-1",
        &AuthClaims {
            iss: Q2_AS.into(),
            dwk: "aauth-access.json".into(),
            aud: Q2_RES_NOMISS.into(),
            ps: Q2_PS.into(),
            sub: q2_pt_ver.claims().sub.clone(),
            cnf: Confirmation {
                jwk: q2_caller_jwk.clone(),
            },
            jti: "q2-at-nomiss-1".into(),
            iat: clock,
            exp: q2_m1_exp,
            scope: Some("records.read".into()),
            nbf: None,
            mission_s256: Some(q2_m1_s256.clone()),
            tenant: None,
            account: None,
            extra: Default::default(),
        },
    )?;
    let q2_nomiss_call_req = signed_get_jwt(
        &format!("{Q2_RES_NOMISS}/records/read"),
        q2_caller_seed,
        &q2_at_nomiss,
        clock,
    )?;
    let q2_nomiss_call_resp = q2_res_nomiss_tls.send(&q2_nomiss_call_req)?;
    let q2_nomiss_refuses_at = q2_nomiss_call_resp.status().as_u16() == 401;

    let q2_happy_ok = q2_tok_resp.status().as_u16() == 200
        && q2_at_claims.mission_s256.as_deref() == Some(q2_m1_s256.as_str())
        && q2_at_claims.exp <= q2_m1_exp
        && q2_receipt.token.reference.issuer == Q2_AS
        && q2_receipt.person_server.as_deref() == Some(Q2_PS)
        && q2_ps_policy
            .seen_missions
            .lock()
            .unwrap()
            .contains(&Some(q2_m1_s256.clone()))
        && q2_as_seen_missions
            .lock()
            .unwrap()
            .contains(&Some(q2_m1_s256.clone()))
        && q2_res_call_resp.status().as_u16() == 200
        && member(&q2_res_call_resp, "mission_s256").as_deref() == Some(q2_m1_s256.as_str())
        && q2_res_seen_missions
            .lock()
            .unwrap()
            .contains(&Some(q2_m1_s256.clone()))
        && q2_nomiss_refuses_pt
        && q2_nomiss_refuses_at;

    // PS refuses AS AuthToken for another mission_s256 or one whose exp outlives mission.expires_at (502 as_unreachable)
    let q2_rt_wrong_at = member(
        &q2_res_tls.send(&post_at(
            &q2_caller.with_token(q2_pt.clone())?,
            &format!("{Q2_RES}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?)?,
        "resource_token",
    )
    .ok_or("missing q2_rt_wrong_at")?;
    let q2_bad_mis_at = mint_auth_token(
        &SigningKey::from_seed([0x62; 32]),
        "q2-as-1",
        &AuthClaims {
            iss: Q2_AS.into(),
            dwk: "aauth-access.json".into(),
            aud: Q2_RES.into(),
            ps: Q2_PS.into(),
            sub: q2_pt_ver.claims().sub.clone(),
            cnf: Confirmation {
                jwk: q2_caller_jwk.clone(),
            },
            jti: "q2-bad-mis-at".into(),
            iat: clock,
            exp: q2_m1_exp,
            scope: Some("records.read".into()),
            nbf: None,
            mission_s256: Some("0000000000000000000000000000000000000000000".into()),
            tenant: None,
            account: None,
            extra: Default::default(),
        },
    )?;
    *q2_fed.override_auth_token.lock().unwrap() = Some(q2_bad_mis_at);
    let q2_bad_mis_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_rt_wrong_at, "presented_token": q2_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_bad_mis_refused = q2_bad_mis_resp.status().as_u16() == 502
        && member(&q2_bad_mis_resp, "error").as_deref() == Some("as_unreachable")
        && q2_ps_store
            .token(&PsTokenReference {
                issuer: Q2_AS.into(),
                jti: "q2-bad-mis-at".into(),
            })?
            .is_none();

    let q2_rt_outlives_at = member(
        &q2_res_tls.send(&post_at(
            &q2_caller.with_token(q2_pt.clone())?,
            &format!("{Q2_RES}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?)?,
        "resource_token",
    )
    .ok_or("missing q2_rt_outlives_at")?;
    let q2_outlives_at = mint_auth_token(
        &SigningKey::from_seed([0x62; 32]),
        "q2-as-1",
        &AuthClaims {
            iss: Q2_AS.into(),
            dwk: "aauth-access.json".into(),
            aud: Q2_RES.into(),
            ps: Q2_PS.into(),
            sub: q2_pt_ver.claims().sub.clone(),
            cnf: Confirmation {
                jwk: q2_caller_jwk.clone(),
            },
            jti: "q2-outlives-at".into(),
            iat: clock,
            exp: q2_m1_exp + 1,
            scope: Some("records.read".into()),
            nbf: None,
            mission_s256: Some(q2_m1_s256.clone()),
            tenant: None,
            account: None,
            extra: Default::default(),
        },
    )?;
    *q2_fed.override_auth_token.lock().unwrap() = Some(q2_outlives_at);
    let q2_outlives_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_rt_outlives_at, "presented_token": q2_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_outlives_refused = q2_outlives_resp.status().as_u16() == 502
        && member(&q2_outlives_resp, "error").as_deref() == Some("as_unreachable")
        && q2_ps_store
            .token(&PsTokenReference {
                issuer: Q2_AS.into(),
                jti: "q2-outlives-at".into(),
            })?
            .is_none();
    // Helper to seed a fresh mission and obtain a (PersonToken, ResourceToken) pair on Q2
    let make_q2_mission_pair = |tag: &str| -> Result<(String, String, String)> {
        let doc = decode_mission_bytes(
            json!({
                "approver": Q2_PS,
                "agent": "aauth:caller@q2-rust-ap.example",
                "approved_at": unix_to_rfc3339(clock - 10),
                "expires_at": unix_to_rfc3339(clock + 500),
                "description": format!("# Q2 Mission {tag}\nTermination point test {tag}.")
            })
            .to_string()
            .as_bytes(),
        )?;
        let s256 = doc.s256().to_owned();
        q2_ps_store
            .install_approved_mission(MissionRecord {
                person_server: Q2_PS.into(),
                owner: q2_owner.clone(),
                person_id: "alice-q2".into(),
                document: doc,
                state: MissionState::Active,
            })
            .map_err(|e| format!("install_approved_mission {tag}: {e:?}"))?;
        let pt_resp = q2_ps_tls.send(&post_at(
            &q2_caller,
            &format!("{Q2_PS}/person"),
            json!({"resource": Q2_RES, "mission_s256": s256})
                .to_string()
                .as_bytes(),
            clock,
        )?)?;
        let pt = member(&pt_resp, "person_token").ok_or("missing pt")?;
        let rt_resp = q2_res_tls.send(&post_at(
            &q2_caller.with_token(pt.clone())?,
            &format!("{Q2_RES}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            clock,
        )?)?;
        let rt = member(&rt_resp, "resource_token").ok_or("missing rt")?;
        Ok((s256, pt, rt))
    };

    // 1. Termination before AS is contacted (during Policy::consent, caught by recheck_mission before AS send)
    let (q2_m2_s256, q2_m2_pt, q2_m2_rt) = make_q2_mission_pair("term-before-as")?;
    let q2_store_m2 = q2_ps_store.clone();
    let q2_owner_m2 = q2_owner.clone();
    let q2_m2_s256_cb = q2_m2_s256.clone();
    *q2_ps_policy.on_consent.lock().unwrap() = Some(Arc::new(move || {
        let _ = q2_store_m2.terminate_mission(
            Q2_PS,
            &q2_owner_m2,
            &q2_m2_s256_cb,
            "stopped before AS",
        );
    }));
    let q2_sent_before_m2 = q2_fed.sent_bodies.lock().unwrap().len();
    let q2_m2_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_m2_rt, "presented_token": q2_m2_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_term_before_as_ok = q2_m2_resp.status().as_u16() == 403
        && member(&q2_m2_resp, "error").as_deref() == Some("mission_terminated")
        && member(&q2_m2_resp, "termination_reason").as_deref() == Some("stopped before AS")
        && q2_fed.sent_bodies.lock().unwrap().len() == q2_sent_before_m2;

    // 2. Termination while AS decides / after AS responds before PS releases response
    let (q2_m3_s256, q2_m3_pt, q2_m3_rt) = make_q2_mission_pair("term-during-as")?;
    let q2_store_m3 = q2_ps_store.clone();
    let q2_owner_m3 = q2_owner.clone();
    let q2_m3_s256_cb = q2_m3_s256.clone();
    *q2_fed.after_send_hook.lock().unwrap() = Some(Arc::new(move || {
        let _ = q2_store_m3.terminate_mission(
            Q2_PS,
            &q2_owner_m3,
            &q2_m3_s256_cb,
            "stopped while AS decided",
        );
    }));
    let q2_m3_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_m3_rt, "presented_token": q2_m3_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let q2_term_during_as_ok = q2_m3_resp.status().as_u16() == 403
        && member(&q2_m3_resp, "error").as_deref() == Some("mission_terminated")
        && member(&q2_m3_resp, "termination_reason").as_deref() == Some("stopped while AS decided");

    // 3. Termination while request waits at PS (202 pending approval -> terminate -> poll 1 = 403 mission_terminated, poll 2 = 410 Gone)
    let (q2_m4_s256, q2_m4_pt, q2_m4_rt) = make_q2_mission_pair("term-while-ps-waits")?;
    q2_as_defer.store(true, Ordering::SeqCst);
    let q2_m4_init_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_m4_rt, "presented_token": q2_m4_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    q2_as_defer.store(false, Ordering::SeqCst);
    let q2_m4_loc = q2_m4_init_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing q2_m4_loc")?
        .to_owned();
    q2_ps_store.terminate_mission(Q2_PS, &q2_owner, &q2_m4_s256, "stopped while PS waited")?;
    let q2_m4_poll1 = q2_ps_tls.send(&signed_get_jwt(
        &q2_m4_loc,
        q2_caller_seed,
        &q2_caller_tok,
        clock,
    )?)?;
    let q2_m4_poll2 = q2_ps_tls.send(&signed_get_jwt(
        &q2_m4_loc,
        q2_caller_seed,
        &q2_caller_tok,
        clock,
    )?)?;
    let q2_term_ps_wait_ok = q2_m4_init_resp.status().as_u16() == 202
        && q2_m4_poll1.status().as_u16() == 403
        && member(&q2_m4_poll1, "error").as_deref() == Some("mission_terminated")
        && member(&q2_m4_poll1, "termination_reason").as_deref() == Some("stopped while PS waited")
        && q2_m4_poll2.status().as_u16() == 410;

    // 4. Termination while request waits on AS deferred 202 continuation and host advances federation
    //    (AS 202 -> PS 202 -> terminate -> advance_federation(Poll) = 403 mission_terminated -> poll 1 = 403 mission_terminated, poll 2 = 410 Gone)
    let (q2_m5_s256, q2_m5_pt, q2_m5_rt) = make_q2_mission_pair("term-while-as-202-waits")?;
    q2_as_defer.store(true, Ordering::SeqCst);
    let q2_m5_init_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        json!({"resource_token": q2_m5_rt, "presented_token": q2_m5_pt})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    q2_as_defer.store(false, Ordering::SeqCst);
    let q2_m5_loc = q2_m5_init_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing q2_m5_loc")?
        .to_owned();
    q2_ps_store.terminate_mission(Q2_PS, &q2_owner, &q2_m5_s256, "stopped while AS 202 waited")?;
    let q2_now_adv = q2_clock.fetch_add(2, Ordering::SeqCst) + 2;
    let q2_m5_adv = q2_ps.advance_federation(
        &q2_m5_loc,
        aauth_rust_person_server::FederationInput::Poll,
    )?;
    let q2_m5_poll1 = q2_ps_tls.send(&signed_get_jwt(
        &q2_m5_loc,
        q2_caller_seed,
        &q2_caller_tok,
        q2_now_adv,
    )?)?;
    let q2_m5_poll2 = q2_ps_tls.send(&signed_get_jwt(
        &q2_m5_loc,
        q2_caller_seed,
        &q2_caller_tok,
        q2_now_adv,
    )?)?;
    let q2_term_as_wait_ok = q2_m5_init_resp.status().as_u16() == 202
        && q2_m5_adv.status().as_u16() == 403
        && member(&q2_m5_adv, "error").as_deref() == Some("mission_terminated")
        && q2_m5_poll1.status().as_u16() == 403
        && member(&q2_m5_poll1, "error").as_deref() == Some("mission_terminated")
        && member(&q2_m5_poll1, "termination_reason").as_deref()
            == Some("stopped while AS 202 waited")
        && q2_m5_poll2.status().as_u16() == 410;

    let q2_pass = q2_pt_claims_ok
        && q2_rt_claims_ok
        && q2_rt_mismatch_refused
        && q2_happy_ok
        && q2_bad_mis_refused
        && q2_outlives_refused
        && q2_term_before_as_ok
        && q2_term_during_as_ok
        && q2_term_ps_wait_ok
        && q2_term_as_wait_ok;
    cases.push(json!({
        "id": "QA-Q2",
        "classification": "VERIFIED_WORKING",
        "pass": q2_pass,
        "summary": format!(
            "4-party missions end-to-end over HTTPS verified: Resource with_mission_context challenge & AuthToken admission={}, happy path PS->AS->Resource with federated receipt retention={}, PS refuses AS AuthToken with wrong mission_s256/outliving exp (502 as_unreachable)={}, termination before AS (403)={}, while AS decides (403)={}, while PS/AS 202 waits (403 then 410 Gone)={}",
            q2_rt_claims_ok && q2_happy_ok,
            q2_happy_ok,
            q2_bad_mis_refused && q2_outlives_refused,
            q2_term_before_as_ok,
            q2_term_during_as_ok,
            q2_term_ps_wait_ok && q2_term_as_wait_ok,
        ),
        "details": {
            "pt_claims_ok": q2_pt_claims_ok,
            "rt_claims_ok": q2_rt_claims_ok,
            "rt_mismatch_refused_400": q2_rt_mismatch_refused,
            "happy_path_ok": q2_happy_ok,
            "ps_refuses_wrong_mission_at_502": q2_bad_mis_refused,
            "ps_refuses_outliving_exp_at_502": q2_outlives_refused,
            "termination_before_as_403": q2_term_before_as_ok,
            "termination_during_as_403": q2_term_during_as_ok,
            "termination_while_ps_202_waits_403_410": q2_term_ps_wait_ok,
            "termination_while_as_202_waits_403_410": q2_term_as_wait_ok,
        },
    }));
    // =========================================================================
    // QA-Q3: 4-Party Mission Call Chaining & Caller `PersonToken` Chain Revocation Over Real HTTPS
    // =========================================================================
    let make_q3_node = |issuer: &'static str,
                        host: &'static str,
                        kid: &'static str,
                        seed: u8|
     -> Result<(Arc<AgentProvider>, Arc<TlsServer>)> {
        let ap = Arc::new(AgentProvider::new(
            issuer,
            kid,
            SigningKey::from_seed([seed; 32]),
        )?);
        let seq = Arc::new(AtomicUsize::new(0));
        let res = Arc::new(
            PsAuthorizationResource::new_federated(
                PsAuthorizationConfig {
                    issuer: issuer.into(),
                    signed_origin: issuer.into(),
                    kid: kid.into(),
                    signing_key: SigningKey::from_seed([seed; 32]),
                    scopes: vec!["records.read".into()],
                    scope_descriptions: BTreeMap::from([(
                        "records.read".into(),
                        "Read records".into(),
                    )]),
                },
                Q2_AS,
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
        let ap_srv = ap.clone();
        let res_srv = res.clone();
        let tls = Arc::new(TlsServer::start(host, move |req| {
            let jti = format!("{kid}-jti-{}", seq.fetch_add(1, Ordering::SeqCst) + 1);
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
                ("GET", "/records/read") => match res_srv.authorize(&req, clock, &jti) {
                    AuthDecision::Granted(admitted) => json_response(
                        200,
                        json!({
                            "ok": true,
                            "sub": admitted.token().claims().sub,
                            "mission_s256": admitted.token().claims().mission_s256,
                        }),
                    ),
                    other => other.into_response(),
                },
                _ => json_response(404, json!({"error": "not_found"})),
            }
        })?);
        trust.discover(&tls, issuer, "aauth-agent.json")?;
        trust.discover(&tls, issuer, "aauth-resource.json")?;
        q2_ps_rev_dir.register_https_target(
            issuer,
            tls.clone(),
            Q2_PS,
            "aauth-person.json",
            "q2-ps-1",
            [0x63; 32],
            clock,
        );
        q2_as_rev_dir.register_https_target(
            issuer,
            tls.clone(),
            Q2_AS,
            "aauth-access.json",
            "q2-as-1",
            [0x62; 32],
            clock,
        );
        Ok((ap, tls))
    };

    let (q3_interm1_ap, q3_interm1_tls) =
        make_q3_node(Q3_INTERM, "q3-rust-interm.example", "q3-int1-1", 0x67)?;
    let (q3_interm2_ap, q3_interm2_tls) =
        make_q3_node(Q3_INTERM2, "q3-rust-interm2.example", "q3-int2-1", 0x68)?;
    let (_, q3_down_tls) =
        make_q3_node(Q3_DOWN_RES, "q3-rust-down-res.example", "q3-down-1", 0x69)?;

    let q3_int1_seed = [0x6a; 32];
    let q3_int1_tok = q3_interm1_ap.issue(&AgentClaims {
        iss: Q3_INTERM.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:relay@q3-rust-interm.example".into(),
        jti: "q3-int1-ag-1".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(q3_int1_seed).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let q3_int1_agent = Agent::new(SigningKey::from_seed(q3_int1_seed), q3_int1_tok)?;

    let q3_int2_seed = [0x6b; 32];
    let q3_int2_tok = q3_interm2_ap.issue(&AgentClaims {
        iss: Q3_INTERM2.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:relay@q3-rust-interm2.example".into(),
        jti: "q3-int2-ag-1".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(q3_int2_seed).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let q3_int2_agent = Agent::new(SigningKey::from_seed(q3_int2_seed), q3_int2_tok)?;

    // Seed active mission Q3-M1 (expires at clock + 450)
    let q3_m1_doc = decode_mission_bytes(
        json!({
            "approver": Q2_PS,
            "agent": "aauth:caller@q2-rust-ap.example",
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 450),
            "description": "# Q3 Mission 1\nMulti-hop 4-party mission call chain and revocation cascade."
        })
        .to_string()
        .as_bytes(),
    )?;
    let q3_m1_s256 = q3_m1_doc.s256().to_owned();
    let q3_m1_exp = q3_m1_doc.expires_at().unwrap_or(clock + 450);
    q2_ps_store
        .install_approved_mission(MissionRecord {
            person_server: Q2_PS.into(),
            owner: q2_owner.clone(),
            person_id: "alice-q2".into(),
            document: q3_m1_doc,
            state: MissionState::Active,
        })
        .map_err(|e| format!("install_approved_mission q3_m1: {e:?}"))?;
    // Hop 1: q2_caller -> Q3_INTERM (mission-bound q3_pt_hop1 -> /authorize -> AS-issued q3_at_hop1)
    let q3_pt_hop1_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_INTERM, "mission_s256": q3_m1_s256}))?,
        clock,
    )?)?;
    let q3_pt_hop1 = member(&q3_pt_hop1_resp, "person_token").ok_or("missing q3_pt_hop1")?;
    let q3_pt_hop1_jti = PersonToken::parse(&q3_pt_hop1)?
        .unverified_claims()
        .jti
        .clone();
    let q3_rt_hop1_resp = q3_interm1_tls.send(&post_at(
        &q2_caller.with_token(q3_pt_hop1.clone())?,
        &format!("{Q3_INTERM}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q3_rt_hop1 = member(&q3_rt_hop1_resp, "resource_token").ok_or("missing q3_rt_hop1")?;
    let q3_at_hop1_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({"resource_token": q3_rt_hop1, "presented_token": q3_pt_hop1}))?,
        clock,
    )?)?;
    let q3_at_hop1 = member(&q3_at_hop1_resp, "auth_token").ok_or("missing q3_at_hop1")?;
    let q3_at_hop1_claims = AuthToken::parse(&q3_at_hop1)?
        .verify(trust, clock)?
        .claims()
        .clone();

    // Hop 2: q3_int1_agent (upstream_token = q3_at_hop1) -> Q2_PS (/person) -> Q3_INTERM2 (/authorize) -> Q2_PS (/token) -> Q2_AS -> q3_at_hop2
    let q3_pt_hop2_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_INTERM2, "upstream_token": q3_at_hop1}))?,
        clock,
    )?)?;
    let q3_pt_hop2 = member(&q3_pt_hop2_resp, "person_token").ok_or("missing q3_pt_hop2")?;
    let q3_pt_hop2_claims = PersonToken::parse(&q3_pt_hop2)?
        .verify(trust, clock)?
        .claims()
        .clone();
    let q3_rt_hop2_resp = q3_interm2_tls.send(&post_at(
        &q3_int1_agent.with_token(q3_pt_hop2.clone())?,
        &format!("{Q3_INTERM2}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q3_rt_hop2 = member(&q3_rt_hop2_resp, "resource_token").ok_or("missing q3_rt_hop2")?;
    let q3_at_hop2_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q3_rt_hop2,
            "presented_token": q3_pt_hop2,
            "upstream_token": q3_at_hop1
        }))?,
        clock,
    )?)?;
    let q3_at_hop2 = member(&q3_at_hop2_resp, "auth_token").ok_or("missing q3_at_hop2")?;
    let q3_at_hop2_claims = AuthToken::parse(&q3_at_hop2)?
        .verify(trust, clock)?
        .claims()
        .clone();

    // Hop 3: q3_int2_agent (upstream_token = q3_at_hop2) -> Q2_PS (/person) -> Q3_DOWN_RES (/authorize) -> Q2_PS (/token) -> Q2_AS -> q3_at_hop3
    let q3_pt_hop3_resp = q2_ps_tls.send(&post_at(
        &q3_int2_agent,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_DOWN_RES, "upstream_token": q3_at_hop2}))?,
        clock,
    )?)?;
    let q3_pt_hop3 = member(&q3_pt_hop3_resp, "person_token").ok_or("missing q3_pt_hop3")?;
    let q3_pt_hop3_claims = PersonToken::parse(&q3_pt_hop3)?
        .verify(trust, clock)?
        .claims()
        .clone();
    let q3_rt_hop3_resp = q3_down_tls.send(&post_at(
        &q3_int2_agent.with_token(q3_pt_hop3.clone())?,
        &format!("{Q3_DOWN_RES}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q3_rt_hop3 = member(&q3_rt_hop3_resp, "resource_token").ok_or("missing q3_rt_hop3")?;
    let q3_at_hop3_resp = q2_ps_tls.send(&post_at(
        &q3_int2_agent,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q3_rt_hop3,
            "presented_token": q3_pt_hop3,
            "upstream_token": q3_at_hop2
        }))?,
        clock,
    )?)?;
    let q3_at_hop3 = member(&q3_at_hop3_resp, "auth_token").ok_or("missing q3_at_hop3")?;
    let q3_at_hop3_claims = AuthToken::parse(&q3_at_hop3)?
        .verify(trust, clock)?
        .claims()
        .clone();

    // Verify all 3 hops succeed on GET /records/read before revocation
    let q3_hop1_before = q3_interm1_tls.send(&signed_get(
        &q2_caller.with_token(q3_at_hop1.clone())?,
        &format!("{Q3_INTERM}/records/read"),
        clock,
    )?)?;
    let q3_hop2_before = q3_interm2_tls.send(&signed_get(
        &q3_int1_agent.with_token(q3_at_hop2.clone())?,
        &format!("{Q3_INTERM2}/records/read"),
        clock,
    )?)?;
    let q3_hop3_before = q3_down_tls.send(&signed_get(
        &q3_int2_agent.with_token(q3_at_hop3.clone())?,
        &format!("{Q3_DOWN_RES}/records/read"),
        clock,
    )?)?;

    let q3_chain_claims_ok = q3_at_hop1_claims.mission_s256.as_deref()
        == Some(q3_m1_s256.as_str())
        && q3_at_hop1_claims.exp <= q3_m1_exp
        && q3_pt_hop2_claims.mission_s256.as_deref() == Some(q3_m1_s256.as_str())
        && q3_pt_hop2_claims.exp <= q3_m1_exp
        && q3_at_hop2_claims.mission_s256.as_deref() == Some(q3_m1_s256.as_str())
        && q3_at_hop2_claims.exp <= q3_m1_exp
        && q3_pt_hop3_claims.mission_s256.as_deref() == Some(q3_m1_s256.as_str())
        && q3_pt_hop3_claims.exp <= q3_m1_exp
        && q3_at_hop3_claims.mission_s256.as_deref() == Some(q3_m1_s256.as_str())
        && q3_at_hop3_claims.exp <= q3_m1_exp
        && q2_ps_policy
            .seen_upstream_missions
            .lock()
            .unwrap()
            .contains(&Some(q3_m1_s256.clone()))
        && q3_hop1_before.status().as_u16() == 200
        && q3_hop2_before.status().as_u16() == 200
        && q3_hop3_before.status().as_u16() == 200
        && member(&q3_hop3_before, "mission_s256").as_deref() == Some(q3_m1_s256.as_str());
    // Revoke caller's PersonToken at the Federated PS and verify hop-by-hop cascade revokes
    // intermediary and downstream AuthTokens so downstream calls transition 200 OK -> 401 Unauthorized
    q2_ps_rev_dir.clear();
    q2_as_rev_dir.clear();
    let _q3_rev_out = q2_ps.revoke_person_token(&q3_pt_hop1_jti);
    let q3_ps_rev_calls = q2_ps_rev_dir.snapshot();
    let q3_as_rev_calls = q2_as_rev_dir.snapshot();

    let q3_hop1_after = q3_interm1_tls.send(&signed_get(
        &q2_caller.with_token(q3_at_hop1.clone())?,
        &format!("{Q3_INTERM}/records/read"),
        clock,
    )?)?;
    let q3_hop2_after = q3_interm2_tls.send(&signed_get(
        &q3_int1_agent.with_token(q3_at_hop2.clone())?,
        &format!("{Q3_INTERM2}/records/read"),
        clock,
    )?)?;
    let q3_hop3_after = q3_down_tls.send(&signed_get(
        &q3_int2_agent.with_token(q3_at_hop3.clone())?,
        &format!("{Q3_DOWN_RES}/records/read"),
        clock,
    )?)?;

    // Further chaining with the revoked upstream token is refused with 400 revoked_upstream_token
    let q3_rev_person_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_INTERM2, "upstream_token": q3_at_hop1}))?,
        clock,
    )?)?;
    let q3_rev_token_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q3_rt_hop2,
            "presented_token": q3_pt_hop2,
            "upstream_token": q3_at_hop1
        }))?,
        clock,
    )?)?;

    let q3_revocation_cascade_ok = q3_hop1_after.status().as_u16() == 401
        && q3_hop2_after.status().as_u16() == 401
        && q3_hop3_after.status().as_u16() == 401
        && q3_rev_person_resp.status().as_u16() == 400
        && member(&q3_rev_person_resp, "error").as_deref() == Some("revoked_upstream_token")
        && q3_rev_token_resp.status().as_u16() == 400
        && member(&q3_rev_token_resp, "error").as_deref() == Some("revoked_upstream_token")
        && !q3_ps_rev_calls.is_empty()
        && !q3_as_rev_calls.is_empty();

    // Mid-chain mission termination on a second 4-party mission Q3-M2 refuses further downstream hops with 403 mission_terminated
    let q3_m2_doc = decode_mission_bytes(
        json!({
            "approver": Q2_PS,
            "agent": "aauth:caller@q2-rust-ap.example",
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 450),
            "description": "# Q3 Mission 2\nMid-chain mission termination test."
        })
        .to_string()
        .as_bytes(),
    )?;
    let q3_m2_s256 = q3_m2_doc.s256().to_owned();
    q2_ps_store
        .install_approved_mission(MissionRecord {
            person_server: Q2_PS.into(),
            owner: q2_owner.clone(),
            person_id: "alice-q2".into(),
            document: q3_m2_doc,
            state: MissionState::Active,
        })
        .map_err(|e| format!("install_approved_mission q3_m2: {e:?}"))?;

    let q3_m2_pt1_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_INTERM, "mission_s256": q3_m2_s256}))?,
        clock,
    )?)?;
    let q3_m2_pt1 = member(&q3_m2_pt1_resp, "person_token").ok_or("missing q3_m2_pt1")?;
    let q3_m2_rt1_resp = q3_interm1_tls.send(&post_at(
        &q2_caller.with_token(q3_m2_pt1.clone())?,
        &format!("{Q3_INTERM}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q3_m2_rt1 = member(&q3_m2_rt1_resp, "resource_token").ok_or("missing q3_m2_rt1")?;
    let q3_m2_at1_resp = q2_ps_tls.send(&post_at(
        &q2_caller,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({"resource_token": q3_m2_rt1, "presented_token": q3_m2_pt1}))?,
        clock,
    )?)?;
    let q3_m2_at1 = member(&q3_m2_at1_resp, "auth_token").ok_or("missing q3_m2_at1")?;

    // Obtain Hop 2 PersonToken and ResourceToken before terminating Q3-M2
    let q3_m2_pt2_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_DOWN_RES, "upstream_token": q3_m2_at1}))?,
        clock,
    )?)?;
    let q3_m2_pt2 = member(&q3_m2_pt2_resp, "person_token").ok_or("missing q3_m2_pt2")?;
    let q3_m2_rt2_resp = q3_down_tls.send(&post_at(
        &q3_int1_agent.with_token(q3_m2_pt2.clone())?,
        &format!("{Q3_DOWN_RES}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q3_m2_rt2 = member(&q3_m2_rt2_resp, "resource_token").ok_or("missing q3_m2_rt2")?;

    // Terminate Q3-M2 mid-chain and verify both /person and /token refuse further hops with 403 mission_terminated
    q2_ps_store.terminate_mission(Q2_PS, &q2_owner, &q3_m2_s256, "stopped mid-chain")?;
    let q3_m2_term_pt_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q3_DOWN_RES, "upstream_token": q3_m2_at1}))?,
        clock,
    )?)?;
    let q3_m2_term_at_resp = q2_ps_tls.send(&post_at(
        &q3_int1_agent,
        &format!("{Q2_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q3_m2_rt2,
            "presented_token": q3_m2_pt2,
            "upstream_token": q3_m2_at1
        }))?,
        clock,
    )?)?;
    let q3_mid_chain_term_ok = q3_m2_term_pt_resp.status().as_u16() == 403
        && member(&q3_m2_term_pt_resp, "error").as_deref() == Some("mission_terminated")
        && q3_m2_term_at_resp.status().as_u16() == 403
        && member(&q3_m2_term_at_resp, "error").as_deref() == Some("mission_terminated");

    let q3_pass = q3_chain_claims_ok && q3_revocation_cascade_ok && q3_mid_chain_term_ok;
    cases.push(json!({
        "id": "QA-Q3",
        "classification": "VERIFIED_WORKING",
        "pass": q3_pass,
        "summary": format!(
            "4-party mission call chaining & caller PersonToken chain revocation over HTTPS verified: 3-hop 4-party chain preserves mission_s256 & exp<=mission.expires_at across all hops={}, mid-chain mission termination refuses further /person & /token hops with 403 mission_terminated={}, caller PersonToken revocation cascades across PS & AS so all 3 hops transition 200 OK -> 401 Unauthorized & further chaining returns 400 revoked_upstream_token={}",
            q3_chain_claims_ok,
            q3_mid_chain_term_ok,
            q3_revocation_cascade_ok,
        ),
        "details": {
            "three_hop_chain_claims_ok": q3_chain_claims_ok,
            "mid_chain_termination_403_ok": q3_mid_chain_term_ok,
            "caller_person_token_revocation_cascade_ok": q3_revocation_cascade_ok,
            "ps_revocation_deliveries": q3_ps_rev_calls.len(),
            "as_revocation_deliveries": q3_as_rev_calls.len(),
        },
    }));

    // =========================================================================
    // QA-Q4: Cross-Language 4-Party Missions (Rust <-> Go main 445af350) Over Real HTTPS
    // =========================================================================
    const Q4_RUST_PS: &str = Q4_RUST_FED_PS;
    const Q4_GO_AP: &str = "https://q4-go-ap.example";
    const Q4_GO_RELAY: &str = "https://q4-go-relay.example";
    const Q4_GO_AS: &str = "https://q4-go-as.example";
    const Q4_GO_PS: &str = "https://q4-go-fed-ps.example";
    const Q4_GO_RES_GO_AS: &str = "https://q4-go-res-go-as.example";
    const Q4_GO_RES_RUST_AS: &str = "https://q4-go-res-rust-as.example";
    const Q5_GO_DIRECT_PS: &str = "https://q5-go-direct-ps.example";
    const Q5_GO_FED_PS: &str = "https://q5-go-fed-ps.example";
    const Q5_GO_AS: &str = "https://q5-go-as.example";
    const Q5_GO_HELD_R3_RES: &str = "https://q5-go-held-r3-res.example";

    // Pre-insert Go Q4/Q5 keys into `trust` so Rust servers trust Go requests during /__run-q-suite
    insert_manual_key(trust, Q4_GO_AP, "aauth-agent.json", "q4-ap-1", 0xd1, None)?;
    insert_manual_key(trust, Q4_GO_RELAY, "aauth-agent.json", "q4-relay-ap-1", 0xd3, None)?;
    insert_manual_key(trust, Q4_GO_PS, "aauth-person.json", "q4-go-fed-ps-1", 0xd5, None)?;
    insert_manual_key(trust, Q4_GO_AS, "aauth-access.json", "q4-go-as-1", 0xd6, None)?;
    insert_manual_key(
        trust,
        Q4_GO_RES_GO_AS,
        "aauth-resource.json",
        "q4-go-res-go-as-1",
        0xd7,
        Some(Q4_GO_AS),
    )?;
    insert_manual_key(
        trust,
        Q4_GO_RES_RUST_AS,
        "aauth-resource.json",
        "q4-go-res-rust-as-1",
        0xd8,
        Some(Q4_RUST_AS),
    )?;
    insert_manual_key(
        trust,
        Q5_GO_DIRECT_PS,
        "aauth-person.json",
        "q5-direct-ps-1",
        0xd9,
        None,
    )?;
    insert_manual_key(trust, Q5_GO_FED_PS, "aauth-person.json", "q5-fed-ps-1", 0xda, None)?;
    insert_manual_key(trust, Q5_GO_AS, "aauth-access.json", "q5-as-1", 0xdb, None)?;
    insert_manual_key(
        trust,
        Q5_GO_HELD_R3_RES,
        "aauth-resource.json",
        "q5-held-res-1",
        0xdc,
        Some(Q4_RUST_AS),
    )?;

    let q4_rust_as_rev_dir = QMultiTargetRevocationDirectory::default();
    let q4_rust_as_seen: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let q4_rust_as_seen_cb = q4_rust_as_seen.clone();
    let q4_rust_as_defer = Arc::new(AtomicBool::new(false));
    let q4_rust_as_defer_cb = q4_rust_as_defer.clone();
    let q4_rust_as_cont = Arc::new(MemoryContinuations::new(64));
    let q4_rust_as_seq = Arc::new(AtomicUsize::new(0));
    let q4_rust_as_key = SigningKey::from_seed([0x71; 32]);
    let q4_rust_as = Arc::new(
        AccessServer::new(
            AsConfig::new(Q4_RUST_AS, "q4-rust-as-1", SigningKey::from_seed([0x71; 32])),
            trust.clone(),
            move |req: &AsAuthorizationRequest| {
                q4_rust_as_seen_cb.lock().unwrap().push(json!({
                    "mission_s256": req.resource.claims().mission_s256.clone(),
                    "had_upstream": req.upstream.is_some(),
                    "person_server": req.person_server.clone(),
                }));
                Ok(AsDecision {
                    scopes: req.scopes.clone(),
                    lifetime: 600,
                })
            },
            move || clock,
            move || format!("q4-rust-as-jti-{}", q4_rust_as_seq.fetch_add(1, Ordering::SeqCst) + 1),
        )?
        .with_revocation()
        .with_revocation_directory(Arc::new(q4_rust_as_rev_dir.clone()))
        .with_deferred(
            AsDeferredConfig {
                store: q4_rust_as_cont.clone(),
                retry_after: 1,
                lifetime: 300,
            },
            move |_ctx: &AsDeferredContext| {
                if !q4_rust_as_defer_cb.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                Ok(Some(ContinuationRequirement::Approval))
            },
        )?,
    );
    let q4_rust_as_srv = q4_rust_as.clone();
    let q4_rust_as_tls = Arc::new(TlsServer::start("q4-rust-as.example", move |req| {
        q4_rust_as_srv.handle(&req)
    })?);
    trust.discover(&q4_rust_as_tls, Q4_RUST_AS, "aauth-access.json")?;
    register_q_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "q4-rust-as.example",
        &q4_rust_as_tls,
    )?;

    let q4_fed = QMultiAsHttpsFederation::default();
    q4_fed.register_rust(Q4_RUST_AS, q4_rust_as_tls.clone());

    let q4_rust_ps_store = MemoryStore::default();
    let q4_rust_ps_cont = Arc::new(MemoryContinuations::new(64));
    let q4_rust_ps_policy = Arc::new(QMissionPsPolicy::new("person-q4-rust"));
    let q4_rust_ps_seq = Arc::new(AtomicUsize::new(0));
    let q4_rust_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(Q4_RUST_PS, "q4-rust-ps-1", SigningKey::from_seed([0x72; 32])),
            trust.clone(),
            q4_rust_ps_store.clone(),
            QSharedMissionPsPolicy(q4_rust_ps_policy.clone()),
            Box::new(move || clock) as BoxedClock,
            Box::new(move || {
                format!("q4-rust-ps-jti-{}", q4_rust_ps_seq.fetch_add(1, Ordering::SeqCst) + 1)
            }) as BoxedTokenIds,
        )?
        .with_federation(q4_fed.clone())
        .with_deferred(PsDeferredConfig {
            store: q4_rust_ps_cont.clone(),
            retry_after: 1,
            lifetime: 300,
        })?,
    );
    let q4_rust_ps_srv = q4_rust_ps.clone();
    let q4_rust_ps_tls = Arc::new(TlsServer::start("q4-rust-fed-ps.example", move |req| {
        q4_rust_ps_srv.handle(&req)
    })?);
    trust.discover(&q4_rust_ps_tls, Q4_RUST_PS, "aauth-person.json")?;
    register_q_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "q4-rust-fed-ps.example",
        &q4_rust_ps_tls,
    )?;

    let make_q4_rust_fed_res = |host: &'static str,
                                issuer: &'static str,
                                kid: &'static str,
                                seed: [u8; 32],
                                as_issuer: &'static str,
                                route_path: &'static str|
     -> Result<Arc<TlsServer>> {
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
        let ap = Arc::new(AgentProvider::new(
            issuer,
            kid,
            SigningKey::from_seed(seed),
        )?);
        let ap_srv = ap.clone();
        let res_srv = res.clone();
        let issuer_str = issuer.to_owned();
        let tls = Arc::new(TlsServer::start(host, move |req| {
            let jti = format!("q4-res-jti-{}", seq.fetch_add(1, Ordering::SeqCst) + 1);
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
                ("GET", p) if p == route_path => match res_srv.authorize(&req, clock, &jti) {
                    AuthDecision::Granted(admitted) => {
                        let miss = admitted.token().claims().mission_s256.clone();
                        json_response(
                            200,
                            json!({
                                "ok": true,
                                "server": issuer_str,
                                "mission": miss.as_ref().map(|s| json!({"s256": s})),
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
        register_q_host_with_go(go_events_ap_addr, &go_events_ap_cert, host, &tls)?;
        Ok(tls)
    };

    let q4_rust_res_go_as_tls = make_q4_rust_fed_res(
        "q4-rust-res-go-as.example",
        Q4_RUST_RES_GO_AS,
        "q4-rust-res-go-as-1",
        [0x73; 32],
        Q4_GO_AS,
        "/records",
    )?;
    let _q4_rust_res_rust_as_tls = make_q4_rust_fed_res(
        "q4-rust-res-rust-as.example",
        Q4_RUST_RES_RUST_AS,
        "q4-rust-res-rust-as-1",
        [0x74; 32],
        Q4_RUST_AS,
        "/records",
    )?;
    let q4_rust_relay_tls = make_q4_rust_fed_res(
        "q4-rust-relay.example",
        Q4_RUST_RELAY,
        "q4-rust-relay-1",
        [0x75; 32],
        Q4_RUST_AS,
        "/relay",
    )?;

    const Q5_RELEASE_COST: i64 = 250;
    const Q5_TOOLS_JSON: &[u8] = br#"{"tools":[
        {"name":"records.query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":false}},
        {"name":"records.metered_query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}
    ]}"#;
    let q5_doc_dir = out_dir.join("q5-metered-docs");
    let q5_call_dir = out_dir.join("q5-metered-calls");
    let q5_rel_cnt = Arc::new(AtomicUsize::new(0));
    let q5_rel_cnt_cb = q5_rel_cnt.clone();
    let q5_res_seq = Arc::new(AtomicUsize::new(0));
    let q5_metered_res = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: Q5_RUST_METERED_RES.into(),
                signed_origin: Q5_RUST_METERED_RES.into(),
                kid: "q5-rust-metered-res-1".into(),
                signing_key: SigningKey::from_seed([0x76; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([(
                    "records.read".into(),
                    "Read records".into(),
                )]),
            },
            trust.clone(),
            Box::new(|_token: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint()
        .with_budgets(
            vec![UnitDeclaration::new("USD", 2, "US dollars")?],
            &format!("{Q5_RUST_METERED_RES}/usage"),
            1_000,
            1_000,
        )?
        .with_r3(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{Q5_RUST_METERED_RES}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(Q5_TOOLS_JSON)]),
                )?,
                display: Some(Box::new(|_: &OperationSet| {
                    Display::new("Query and metered-release query", None, None, None)
                        .map_err(|e| R3HostError::new(e.to_string()))
                })),
            }],
            documents: Arc::new(DirectoryDocumentStore::open(&q5_doc_dir)?),
            operation_for_request: Box::new(|req: &Request<Vec<u8>>| match req.uri().path() {
                "/records/query" => mcp("records.query").map(Some),
                "/records/metered-query" => mcp("records.metered_query").map(Some),
                _ => Ok(None),
            }),
            require_core_scope: false,
        })?
        .with_r3_per_call(R3PerCallConfig {
            present: Box::new(|req: &Request<Vec<u8>>, _: &Operation| {
                let record = record_parameter(req)?;
                let presented = PresentedParameter::inline(&record)
                    .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(BTreeMap::from([("record".to_owned(), presented)]))
            }),
            describe: Box::new(
                |op: &Operation,
                 presented: &BTreeMap<String, PresentedParameter>,
                 _: Option<&str>| {
                    let value = presented
                        .get("record")
                        .and_then(PresentedParameter::inline_json)
                        .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                    let parameters = Parameters::new([(
                        "record".to_owned(),
                        Parameter::inline(&value).map_err(|e| R3HostError::new(e.to_string()))?,
                    )])
                    .map_err(|e| R3HostError::new(e.to_string()))?;
                    let shown = String::from_utf8_lossy(&value).into_owned();
                    let is_metered = op.equal(&mcp("records.metered_query")?).unwrap_or(false);
                    let display = ProposalDisplay::new(
                        &Display::new(
                            if is_metered {
                                format!("Run metered-release query {shown}")
                            } else {
                                format!("Run query {shown}")
                            },
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
            calls: Arc::new(DirectoryCallStore::open(&q5_call_dir)?),
            hold: true,
            release: Some(Box::new(
                move |_: &Request<Vec<u8>>,
                      op: &Operation,
                      presented: &BTreeMap<String, PresentedParameter>,
                      _: Option<&str>| {
                    q5_rel_cnt_cb.fetch_add(1, Ordering::SeqCst);
                    let value = presented
                        .get("record")
                        .and_then(PresentedParameter::inline_json)
                        .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                    let shown = String::from_utf8_lossy(&value).into_owned();
                    let is_metered = op.equal(&mcp("records.metered_query")?).unwrap_or(false);
                    let result = ProposalResult::new(br#"{"records":1}"#)
                        .map_err(|e| R3HostError::new(e.to_string()))?;
                    let display = ProposalDisplay::new(
                        &Display::new(format!("Release query {shown}"), None, None, None)
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
                        cost: is_metered.then_some(Q5_RELEASE_COST),
                    }))
                },
            )),
            held_result_lifetime: 300,
        })?
        .with_release_metering()?,
    );
    let q5_prop_op = mcp("records.metered_query")?;
    let q5_prop_params = Parameters::new([(
        "record".to_owned(),
        Parameter::inline(br#""r-1""#)?,
    )])?;
    let q5_prop_doc = Proposal::new(&q5_prop_op, &q5_prop_params, ProposalOptions::default())?;
    let q5_prop_exact = serde_json::to_vec(&q5_prop_doc)?;
    let q5_prop_exact_srv = q5_prop_exact.clone();

    let q5_metered_res_srv = q5_metered_res.clone();
    let q5_metered_res_tls = Arc::new(TlsServer::start("q5-rust-metered-res.example", move |req| {
        let jti = format!("q5-mres-jti-{}", q5_res_seq.fetch_add(1, Ordering::SeqCst) + 1);
        let path = req.uri().path().to_owned();
        if path == "/.well-known/aauth-resource.json" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q5_metered_res_srv.metadata().unwrap())
                .unwrap();
        }
        if path == "/.well-known/jwks.json" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q5_metered_res_srv.jwks().unwrap())
                .unwrap();
        }
        if path == "/authorize" {
            return q5_metered_res_srv
                .authorize_endpoint(&req, clock, &jti)
                .into_response();
        }
        if path == "/r3/proposals/prop-dir-1" || path == "/r3/proposals/prop-fed-1" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(q5_prop_exact_srv.clone())
                .unwrap();
        }
        if path.starts_with("/r3/") && !path.starts_with("/r3/pending/") {
            return q5_metered_res_srv.r3_document(&req, clock);
        }
        q5_metered_res_srv.authorize(&req, clock, &jti).into_response()
    })?);
    trust.discover(&q5_metered_res_tls, Q5_RUST_METERED_RES, "aauth-resource.json")?;
    register_q_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "q5-rust-metered-res.example",
        &q5_metered_res_tls,
    )?;

    let go_q_suite = post_json_ext(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-q-suite",
        json!({
            "rust_fed_ps_issuer": Q4_RUST_PS,
            "rust_fed_as_issuer": Q4_RUST_AS,
            "rust_fed_res_go_as_issuer": Q4_RUST_RES_GO_AS,
            "rust_fed_res_rust_as_issuer": Q4_RUST_RES_RUST_AS,
            "rust_relay_res_issuer": Q4_RUST_RELAY,
            "rust_metered_res_issuer": Q5_RUST_METERED_RES,
            "rust_proposal_rt_direct": "",
            "rust_proposal_rt_fed": "",
        }),
    )?;

    let parse_go_srv = |name: &str| -> Result<(SocketAddr, Vec<u8>)> {
        let addr: SocketAddr = go_q_suite["servers"][name]["addr"]
            .as_str()
            .ok_or_else(|| format!("missing servers.{name}.addr"))?
            .parse()?;
        let cert = decode_cert_pem(
            go_q_suite["servers"][name]["cert_pem"]
                .as_str()
                .ok_or_else(|| format!("missing servers.{name}.cert_pem"))?,
        )?;
        Ok((addr, cert))
    };
    let (q4_go_ap_addr, q4_go_ap_cert) = parse_go_srv("q4_go_ap")?;
    let (q4_go_relay_addr, q4_go_relay_cert) = parse_go_srv("q4_go_relay")?;
    let (q4_go_ps_addr, q4_go_ps_cert) = parse_go_srv("q4_go_fed_ps")?;
    let (q4_go_as_addr, q4_go_as_cert) = parse_go_srv("q4_go_as")?;
    let (q4_go_res_go_as_addr, q4_go_res_go_as_cert) = parse_go_srv("q4_go_res_go_as")?;
    let (q4_go_res_rust_as_addr, q4_go_res_rust_as_cert) = parse_go_srv("q4_go_res_rust_as")?;
    let (q5_go_direct_ps_addr, q5_go_direct_ps_cert) = parse_go_srv("q5_go_direct_ps")?;
    let (q5_go_fed_ps_addr, q5_go_fed_ps_cert) = parse_go_srv("q5_go_fed_ps")?;
    let (q5_go_as_addr, q5_go_as_cert) = parse_go_srv("q5_go_as")?;
    let (q5_go_held_res_addr, q5_go_held_res_cert) = parse_go_srv("q5_go_held_res")?;

    // Discover the Go Q4/Q5 servers from live HTTPS metadata and register Go AS in `q4_fed`
    discover_external(trust, q4_go_ap_addr, "q4-go-ap.example", &q4_go_ap_cert, Q4_GO_AP, "aauth-agent.json")?;
    discover_external(trust, q4_go_relay_addr, "q4-go-relay.example", &q4_go_relay_cert, Q4_GO_RELAY, "aauth-agent.json")?;
    discover_external(trust, q4_go_ps_addr, "q4-go-fed-ps.example", &q4_go_ps_cert, Q4_GO_PS, "aauth-person.json")?;
    discover_external(trust, q4_go_as_addr, "q4-go-as.example", &q4_go_as_cert, Q4_GO_AS, "aauth-access.json")?;
    discover_external(trust, q4_go_res_go_as_addr, "q4-go-res-go-as.example", &q4_go_res_go_as_cert, Q4_GO_RES_GO_AS, "aauth-resource.json")?;
    discover_external(trust, q4_go_res_rust_as_addr, "q4-go-res-rust-as.example", &q4_go_res_rust_as_cert, Q4_GO_RES_RUST_AS, "aauth-resource.json")?;
    discover_external(trust, q5_go_direct_ps_addr, "q5-go-direct-ps.example", &q5_go_direct_ps_cert, Q5_GO_DIRECT_PS, "aauth-person.json")?;
    discover_external(trust, q5_go_fed_ps_addr, "q5-go-fed-ps.example", &q5_go_fed_ps_cert, Q5_GO_FED_PS, "aauth-person.json")?;
    discover_external(trust, q5_go_as_addr, "q5-go-as.example", &q5_go_as_cert, Q5_GO_AS, "aauth-access.json")?;
    discover_external(trust, q5_go_held_res_addr, "q5-go-held-r3-res.example", &q5_go_held_res_cert, Q5_GO_HELD_R3_RES, "aauth-resource.json")?;

    q4_fed.register_go(Q4_GO_AS, q4_go_as_addr, "q4-go-as.example", q4_go_as_cert.clone());

    // Verify Go-originated QA-Q4 flows (Go Federated PS -> Rust AS & Go AS -> Rust & Go Federated Resources)
    let q4_go_to_rust_as_rust_res_ok =
        go_q_suite["q4"]["flow1_go_ps_rust_as_rust_res"]["ok"].as_bool() == Some(true);
    let q4_go_to_rust_as_go_res_ok =
        go_q_suite["q4"]["flow2_go_ps_rust_as_go_res"]["ok"].as_bool() == Some(true);
    let q4_go_to_go_as_rust_res_ok =
        go_q_suite["q4"]["flow3_go_ps_go_as_rust_res"]["ok"].as_bool() == Some(true);
    let q4_go_to_go_as_go_res_ok =
        go_q_suite["q4"]["flow4_go_ps_go_as_go_res"]["ok"].as_bool() == Some(true);
    let q4_go_ps_b4_person_ok =
        go_q_suite["q4"]["boundaries"]["b4_person_upstream_mission_pt"]["ok"].as_bool()
            == Some(true);
    let q4_go_ps_b2_person_ok =
        go_q_suite["q4"]["boundaries"]["b2_person_upstream_as_auth"]["ok"].as_bool()
            == Some(true);
    let q4_go_ps_both_fields_ok =
        go_q_suite["q4"]["boundaries"]["b4_person_upstream_and_mission_field"]["ok"].as_bool()
            == Some(true)
            && go_q_suite["q4"]["boundaries"]["b4_token_upstream_and_mission_rt"]["ok"].as_bool()
                == Some(true);

    // Now run Rust-originated QA-Q4 flows:
    // 1. Propose and approve a mission at `q4-rust-fed-ps.example` covering `Q4_GO_RES_GO_AS`, `Q4_RUST_RES_GO_AS`, `Q4_RUST_RELAY`, `Q4_GO_RES_RUST_AS`, `Q4_RUST_RES_RUST_AS`
    let (q4_caller_agent, _, q4_caller_sub, q4_owner) =
        make_q_agent(Q2_AP, "q2-ap-1", [0x61; 32], "caller-q4", Q4_RUST_PS, [0x77; 32], clock)?;
    let (q4_relay_agent, _, _q4_relay_sub, _) = make_q_agent(
        Q4_RUST_RELAY,
        "q4-rust-relay-1",
        [0x75; 32],
        "worker-1",
        Q4_RUST_PS,
        [0x78; 32],
        clock,
    )?;
    let q4_mission_doc = decode_mission_bytes(
        json!({
            "approver": Q4_RUST_PS,
            "agent": q4_caller_sub,
            "approved_at": unix_to_rfc3339(clock - 10),
            "expires_at": unix_to_rfc3339(clock + 240),
            "description": "# Cross-Language Rust-PS Mission\nAccess Go and Rust federated resources via Go AS and Rust AS."
        })
        .to_string()
        .as_bytes(),
    )?;
    let q4_rust_mission_s256 = q4_mission_doc.s256().to_owned();
    let q4_mission_exp = q4_mission_doc.expires_at().unwrap_or(clock + 240);
    q4_rust_ps_store
        .install_approved_mission(MissionRecord {
            person_server: Q4_RUST_PS.into(),
            owner: q4_owner.clone(),
            person_id: "person-q4-rust".into(),
            document: q4_mission_doc,
            state: MissionState::Active,
        })
        .map_err(|e| format!("install_approved_mission q4: {e:?}"))?;

    // Top-level immediate: Rust Federated PS -> Go AS -> Go Federated Resource (`Q4_GO_RES_GO_AS`)
    let q4_pt_go_res_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q4_GO_RES_GO_AS, "mission_s256": q4_rust_mission_s256}))?,
        clock,
    )?)?;
    let q4_pt_go_res = member(&q4_pt_go_res_resp, "person_token").ok_or("missing q4_pt_go_res")?;
    let q4_rt_go_res_resp = send_https(
        q4_go_res_go_as_addr,
        "q4-go-res-go-as.example",
        &q4_go_res_go_as_cert,
        &signed_post_jwt(
            &format!("{Q4_GO_RES_GO_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            [0x77; 32],
            &q4_pt_go_res,
            clock,
        )?,
    )?;
    let q4_rt_go_res = member(&q4_rt_go_res_resp, "resource_token").ok_or("missing q4_rt_go_res")?;
    let q4_at_go_res_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q4_rt_go_res,
            "presented_token": q4_pt_go_res,
        }))?,
        clock,
    )?)?;
    let q4_at_go_res = member(&q4_at_go_res_resp, "auth_token").ok_or_else(|| {
        format!(
            "missing q4_at_go_res ({}): {}",
            q4_at_go_res_resp.status(),
            String::from_utf8_lossy(q4_at_go_res_resp.body())
        )
    })?;
    let q4_at_go_res_ver = AuthToken::parse(&q4_at_go_res)?.verify(trust, clock)?;
    let q4_call_go_res_resp = send_https(
        q4_go_res_go_as_addr,
        "q4-go-res-go-as.example",
        &q4_go_res_go_as_cert,
        &signed_get_jwt(
            &format!("{Q4_GO_RES_GO_AS}/records"),
            [0x77; 32],
            &q4_at_go_res,
            clock,
        )?,
    )?;
    let q4_call_go_res_body: Value = serde_json::from_slice(q4_call_go_res_resp.body())?;
    let q4_rust_ps_to_go_as_go_res_ok = q4_at_go_res_resp.status().as_u16() == 200
        && q4_at_go_res_ver.claims().mission_s256.as_deref() == Some(q4_rust_mission_s256.as_str())
        && q4_at_go_res_ver.claims().exp <= q4_mission_exp
        && q4_call_go_res_resp.status().as_u16() == 200
        && q4_call_go_res_body["mission_s256"].as_str() == Some(q4_rust_mission_s256.as_str());

    // Top-level immediate: Rust Federated PS -> Go AS -> Rust Federated Resource (`Q4_RUST_RES_GO_AS`)
    let q4_pt_rust_res_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q4_RUST_RES_GO_AS, "mission_s256": q4_rust_mission_s256}))?,
        clock,
    )?)?;
    let q4_pt_rust_res = member(&q4_pt_rust_res_resp, "person_token").ok_or("missing q4_pt_rust_res")?;
    let q4_rt_rust_res_resp = q4_rust_res_go_as_tls.send(&post_at(
        &q4_caller_agent.with_token(q4_pt_rust_res.clone())?,
        &format!("{Q4_RUST_RES_GO_AS}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q4_rt_rust_res = member(&q4_rt_rust_res_resp, "resource_token").ok_or("missing q4_rt_rust_res")?;
    let q4_at_rust_res_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q4_rt_rust_res,
            "presented_token": q4_pt_rust_res,
        }))?,
        clock,
    )?)?;
    let q4_at_rust_res = member(&q4_at_rust_res_resp, "auth_token").ok_or("missing q4_at_rust_res")?;
    let q4_at_rust_res_ver = AuthToken::parse(&q4_at_rust_res)?.verify(trust, clock)?;
    let q4_call_rust_res_resp = q4_rust_res_go_as_tls.send(&get_at(
        &q4_caller_agent.with_token(q4_at_rust_res.clone())?,
        &format!("{Q4_RUST_RES_GO_AS}/records"),
        clock,
    )?)?;
    let q4_call_rust_res_body: Value = serde_json::from_slice(q4_call_rust_res_resp.body())?;
    let q4_rust_ps_to_go_as_rust_res_ok = q4_at_rust_res_resp.status().as_u16() == 200
        && q4_at_rust_res_ver.claims().mission_s256.as_deref() == Some(q4_rust_mission_s256.as_str())
        && q4_at_rust_res_ver.claims().exp <= q4_mission_exp
        && q4_call_rust_res_resp.status().as_u16() == 200
        && q4_call_rust_res_body["mission_s256"].as_str() == Some(q4_rust_mission_s256.as_str());

    // Chained immediate: Caller Agent -> Rust Relay (`Q4_RUST_RELAY`) -> Rust Federated PS -> Go AS -> Go & Rust Federated Resources
    let q4_pt_relay_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q4_RUST_RELAY, "mission_s256": q4_rust_mission_s256}))?,
        clock,
    )?)?;
    let q4_pt_relay = member(&q4_pt_relay_resp, "person_token").ok_or("missing q4_pt_relay")?;
    let q4_rt_relay_resp = q4_rust_relay_tls.send(&post_at(
        &q4_caller_agent.with_token(q4_pt_relay.clone())?,
        &format!("{Q4_RUST_RELAY}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q4_rt_relay = member(&q4_rt_relay_resp, "resource_token").ok_or("missing q4_rt_relay")?;
    let q4_at_relay_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q4_rt_relay,
            "presented_token": q4_pt_relay,
        }))?,
        clock,
    )?)?;
    let q4_at_relay = member(&q4_at_relay_resp, "auth_token").ok_or("missing q4_at_relay")?;

    // Relay Agent chains `q4_at_relay` to obtain a mission-bound PersonToken for `Q4_GO_RES_GO_AS`
    let q4_chain_pt_go_resp = q4_rust_ps_tls.send(&post_at(
        &q4_relay_agent,
        &format!("{Q4_RUST_PS}/person"),
        &serde_json::to_vec(&json!({
            "resource": Q4_GO_RES_GO_AS,
            "upstream_token": q4_at_relay,
        }))?,
        clock,
    )?)?;
    let q4_chain_pt_go =
        member(&q4_chain_pt_go_resp, "person_token").ok_or("missing q4_chain_pt_go")?;
    let q4_chain_rt_go_resp = send_https(
        q4_go_res_go_as_addr,
        "q4-go-res-go-as.example",
        &q4_go_res_go_as_cert,
        &signed_post_jwt(
            &format!("{Q4_GO_RES_GO_AS}/authorize"),
            &serde_json::to_vec(&json!({"scope": "records.read"}))?,
            [0x78; 32],
            &q4_chain_pt_go,
            clock,
        )?,
    )?;
    let q4_chain_rt_go =
        member(&q4_chain_rt_go_resp, "resource_token").ok_or("missing q4_chain_rt_go")?;
    let q4_chain_at_go_resp = q4_rust_ps_tls.send(&post_at(
        &q4_relay_agent,
        &format!("{Q4_RUST_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q4_chain_rt_go,
            "presented_token": q4_chain_pt_go,
            "upstream_token": q4_at_relay,
        }))?,
        clock,
    )?)?;
    let q4_chain_at_go =
        member(&q4_chain_at_go_resp, "auth_token").ok_or("missing q4_chain_at_go")?;
    let q4_chain_at_go_ver = AuthToken::parse(&q4_chain_at_go)?.verify(trust, clock)?;
    let q4_chain_call_go_resp = send_https(
        q4_go_res_go_as_addr,
        "q4-go-res-go-as.example",
        &q4_go_res_go_as_cert,
        &signed_get_jwt(
            &format!("{Q4_GO_RES_GO_AS}/records"),
            [0x78; 32],
            &q4_chain_at_go,
            clock,
        )?,
    )?;
    let q4_chain_call_go_body: Value = serde_json::from_slice(q4_chain_call_go_resp.body())?;
    let q4_go_as_seen_resp = send_https(
        q4_go_as_addr,
        "q4-go-as.example",
        &q4_go_as_cert,
        &get_req(&format!("{Q4_GO_AS}/__q4-as-seen")),
    )?;
    let q4_go_as_seen_body: Value = serde_json::from_slice(q4_go_as_seen_resp.body())?;
    let q4_chained_rust_ps_to_go_as_ok = q4_chain_at_go_resp.status().as_u16() == 200
        && q4_chain_at_go_ver.claims().mission_s256.as_deref()
            == Some(q4_rust_mission_s256.as_str())
        && q4_chain_at_go_ver.claims().exp <= q4_mission_exp
        && q4_chain_call_go_resp.status().as_u16() == 200
        && q4_chain_call_go_body["mission_s256"].as_str() == Some(q4_rust_mission_s256.as_str())
        && q4_go_as_seen_body["had_upstream"].as_bool() == Some(true)
        && q4_go_as_seen_body["last_mission_s256"].as_str() == Some(q4_rust_mission_s256.as_str());

    // Boundary check 1: Deferred (202) mission-bound request on Rust Federated PS -> Go AS
    // Go AS (`accessserver/server.go:472`) refuses `Pending` when `MissionS256 != ""` with `500 server_error`,
    // which Rust Federated PS maps to `502 as_unreachable`.
    let _ = post_json_ext(
        q4_go_as_addr,
        "q4-go-as.example",
        &q4_go_as_cert,
        &format!("{Q4_GO_AS}/__q4-as-mode"),
        json!({"defer": true}),
    )?;
    let q4_rt_go_defer_resp = q4_rust_res_go_as_tls.send(&post_at(
        &q4_caller_agent.with_token(q4_pt_rust_res.clone())?,
        &format!("{Q4_RUST_RES_GO_AS}/authorize"),
        &serde_json::to_vec(&json!({"scope": "records.read"}))?,
        clock,
    )?)?;
    let q4_rt_go_defer =
        member(&q4_rt_go_defer_resp, "resource_token").ok_or("missing q4_rt_go_defer")?;
    let q4_defer_go_as_resp = q4_rust_ps_tls.send(&post_at(
        &q4_caller_agent,
        &format!("{Q4_RUST_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q4_rt_go_defer,
            "presented_token": q4_pt_rust_res,
        }))?,
        clock,
    )?)?;
    let _ = post_json_ext(
        q4_go_as_addr,
        "q4-go-as.example",
        &q4_go_as_cert,
        &format!("{Q4_GO_AS}/__q4-as-mode"),
        json!({"defer": false}),
    )?;
    let q4_go_as_defer_boundary_ok = q4_defer_go_as_resp.status().as_u16() == 202;

    // Deferred (202) mission-bound request on Go Federated PS -> Rust AS:
    // Rust AS returns `202 Accepted` for the mission-bound request, and Go Federated PS from 8a3734dd on
    // defers the mission-bound request with `202 Accepted` (previously 500 server_error on main 445af350).
    q4_rust_as_defer.store(true, Ordering::SeqCst);
    let q4_go_pt_for_defer = go_q_suite["q4"]["pt_for_rust_res_rust_as"]
        .as_str()
        .ok_or("missing pt_for_rust_res_rust_as")?;
    let q4_go_rt_for_defer = go_q_suite["q4"]["rt_for_defer_test"]
        .as_str()
        .ok_or("missing rt_for_defer_test")?;
    let q4_go_ps_defer_out = post_json_ext(
        q4_go_ps_addr,
        "q4-go-fed-ps.example",
        &q4_go_ps_cert,
        &format!("{Q4_GO_PS}/__q4-go-ps-exchange"),
        json!({
            "resource_token": q4_go_rt_for_defer,
            "presented_token": q4_go_pt_for_defer,
        }),
    )?;
    q4_rust_as_defer.store(false, Ordering::SeqCst);
    let q4_go_ps_defer_boundary_ok = q4_go_ps_defer_out["status"].as_u64() == Some(202);

    let q4_pass = q4_go_to_rust_as_rust_res_ok
        && q4_go_to_rust_as_go_res_ok
        && q4_go_to_go_as_rust_res_ok
        && q4_go_to_go_as_go_res_ok
        && q4_rust_ps_to_go_as_go_res_ok
        && q4_rust_ps_to_go_as_rust_res_ok
        && q4_chained_rust_ps_to_go_as_ok
        && q4_go_ps_b4_person_ok
        && q4_go_ps_b2_person_ok
        && q4_go_ps_both_fields_ok
        && q4_go_as_defer_boundary_ok
        && q4_go_ps_defer_boundary_ok;
    cases.push(json!({
        "id": "QA-Q4",
        "classification": "VERIFIED_WORKING",
        "pass": q4_pass,
        "summary": format!(
            "Cross-language 4-party missions (Rust <-> Go main 445af350) over HTTPS verified: Go Fed PS -> Rust AS & Go AS (Rust & Go Resources)={}/{}/{}/{}, Rust Fed PS -> Go AS top-level (Go & Rust Resources)={}/{}, Rust Fed PS -> Go AS chained mission={}, mixed-deployment boundaries (Go PS B4/B2/both={}, Go AS defer=502/500={}, Go PS defer=500={})",
            q4_go_to_rust_as_rust_res_ok,
            q4_go_to_rust_as_go_res_ok,
            q4_go_to_go_as_rust_res_ok,
            q4_go_to_go_as_go_res_ok,
            q4_rust_ps_to_go_as_go_res_ok,
            q4_rust_ps_to_go_as_rust_res_ok,
            q4_chained_rust_ps_to_go_as_ok,
            q4_go_ps_b4_person_ok && q4_go_ps_b2_person_ok && q4_go_ps_both_fields_ok,
            q4_go_as_defer_boundary_ok,
            q4_go_ps_defer_boundary_ok,
        ),
        "details": {
            "go_ps_to_rust_as_rust_res_ok": q4_go_to_rust_as_rust_res_ok,
            "go_ps_to_rust_as_go_res_ok": q4_go_to_rust_as_go_res_ok,
            "go_ps_to_go_as_rust_res_ok": q4_go_to_go_as_rust_res_ok,
            "go_ps_to_go_as_go_res_ok": q4_go_to_go_as_go_res_ok,
            "rust_ps_to_go_as_go_res_ok": q4_rust_ps_to_go_as_go_res_ok,
            "rust_ps_to_go_as_rust_res_ok": q4_rust_ps_to_go_as_rust_res_ok,
            "chained_rust_ps_to_go_as_ok": q4_chained_rust_ps_to_go_as_ok,
            "go_ps_b4_chained_mission_boundary_ok": q4_go_ps_b4_person_ok,
            "go_ps_b2_as_auth_upstream_boundary_ok": q4_go_ps_b2_person_ok,
            "go_ps_both_upstream_and_mission_boundary_ok": q4_go_ps_both_fields_ok,
            "go_as_defer_mission_boundary_ok": q4_go_as_defer_boundary_ok,
            "go_ps_defer_mission_boundary_ok": q4_go_ps_defer_boundary_ok,
        },
    }));

    // =========================================================================
    // QA-Q5: Metered Release of a Held R3 Result (`with_release_metering`, `R3Release::cost`)
    // & Cross-Language Wire Check Over Real HTTPS
    // =========================================================================
    // 1. Verify configuration preconditions for `PsAuthorizationResource::with_release_metering()`:
    //    - Before `with_budgets` -> Err(PsConfigurationError::InvalidBudgetProfile)
    //    - Before `with_r3_per_call` -> Err(PsConfigurationError::InvalidR3Profile)
    let q5_cfg_no_budgets = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: Q5_RUST_METERED_RES.into(),
            signed_origin: Q5_RUST_METERED_RES.into(),
            kid: "q5-rust-metered-res-1".into(),
            signing_key: SigningKey::from_seed([0x76; 32]),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        trust.clone(),
        Box::new(|_t: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
    )?
    .with_release_metering();
    let q5_cfg_no_per_call = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: Q5_RUST_METERED_RES.into(),
            signed_origin: Q5_RUST_METERED_RES.into(),
            kid: "q5-rust-metered-res-1".into(),
            signing_key: SigningKey::from_seed([0x76; 32]),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        trust.clone(),
        Box::new(|_t: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
    )?
    .with_budgets(
        vec![UnitDeclaration::new("USD", 2, "US dollars")?],
        &format!("{Q5_RUST_METERED_RES}/usage"),
        1_000,
        1_000,
    )?
    .with_release_metering();
    let q5_config_guards_ok = matches!(
        q5_cfg_no_budgets,
        Err(PsConfigurationError::InvalidBudgetProfile)
    ) && matches!(
        q5_cfg_no_per_call,
        Err(PsConfigurationError::InvalidR3Profile)
    );

    // 2. Stand up two 3-party Rust PersonServers for `Q5_RUST_DIRECT_PS` (sharing the same signing key/kid so
    //    `Q5_RUST_METERED_RES` trusts both, one capped at `Q5_RELEASE_COST - 1 = 249` cents and one capped at `500` cents)
    struct Q5ReleaseR3Policy;
    impl R3Policy for Q5ReleaseR3Policy {
        fn authorize_document(
            &self,
            req: &R3AuthorizationRequest<'_>,
        ) -> std::result::Result<R3Decision, PolicyError> {
            let vocab = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
            let q_op = mcp("records.query").map_err(|_| PolicyError::Unavailable)?;
            let mq_op = mcp("records.metered_query").map_err(|_| PolicyError::Unavailable)?;
            Ok(R3Decision {
                granted: GrantedOperations::new(&vocab, &[])
                    .map_err(|_| PolicyError::Unavailable)?,
                per_call: Some(
                    GrantedOperations::new(&vocab, &[q_op, mq_op])
                        .map_err(|_| PolicyError::Unavailable)?,
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

    let q5_ps_store = MemoryStore::default();
    let q5_ps_policy = Arc::new(QMissionPsPolicy::new("person-q5"));
    let q5_ps_key = SigningKey::from_seed([0x79; 32]);
    let q5_ps_seq = Arc::new(AtomicUsize::new(0));
    let q5_ps_seq_short = q5_ps_seq.clone();
    let q5_ps_short = Arc::new(
        PersonServer::new(
            PsConfig::new(Q5_RUST_DIRECT_PS, "q5-rust-ps-1", SigningKey::from_seed([0x79; 32])),
            trust.clone(),
            q5_ps_store.clone(),
            QSharedMissionPsPolicy(q5_ps_policy.clone()),
            Box::new(move || clock) as BoxedClock,
            Box::new(move || {
                format!(
                    "q5-ps-jti-{}",
                    q5_ps_seq_short.fetch_add(1, Ordering::SeqCst) + 1
                )
            }) as BoxedTokenIds,
        )?
        .with_budgets(IssuerPolicy::capped(
            Q5_RELEASE_COST - 1,
            vec![UnitDeclaration::new("USD", 2, "US dollars")?],
        ))?
        .with_r3(R3IssuerConfig {
            registry: standard_registry()?,
            egress: Box::new(|_: &str, _: Instant| Ok(())),
            transport: Box::new(TlsFetch(q5_metered_res_tls.clone())),
            limits: FetchLimits::default(),
            policy: Box::new(Q5ReleaseR3Policy),
            audit: Arc::new(QaAuditStore {
                commits: Arc::new(AtomicUsize::new(0)),
                last_token_jti: Arc::new(Mutex::new(None)),
            }),
        })?,
    );
    let q5_ps_full = Arc::new(
        PersonServer::new(
            PsConfig::new(Q5_RUST_DIRECT_PS, "q5-rust-ps-1", SigningKey::from_seed([0x79; 32])),
            trust.clone(),
            q5_ps_store.clone(),
            QSharedMissionPsPolicy(q5_ps_policy.clone()),
            Box::new(move || clock) as BoxedClock,
            Box::new(move || {
                format!("q5-ps-jti-{}", q5_ps_seq.fetch_add(1, Ordering::SeqCst) + 1)
            }) as BoxedTokenIds,
        )?
        .with_budgets(IssuerPolicy::capped(
            500,
            vec![UnitDeclaration::new("USD", 2, "US dollars")?],
        ))?
        .with_r3(R3IssuerConfig {
            registry: standard_registry()?,
            egress: Box::new(|_: &str, _: Instant| Ok(())),
            transport: Box::new(TlsFetch(q5_metered_res_tls.clone())),
            limits: FetchLimits::default(),
            policy: Box::new(Q5ReleaseR3Policy),
            audit: Arc::new(QaAuditStore {
                commits: Arc::new(AtomicUsize::new(0)),
                last_token_jti: Arc::new(Mutex::new(None)),
            }),
        })?,
    );
    let q5_ps_full_srv = q5_ps_full.clone();
    let q5_ps_tls = Arc::new(TlsServer::start("q5-rust-direct-ps.example", move |req| {
        q5_ps_full_srv.handle(&req)
    })?);
    trust.discover(&q5_ps_tls, Q5_RUST_DIRECT_PS, "aauth-person.json")?;

    // 3. Obtain a class R3 AuthToken from `q5_ps_tls` (`Q5_RUST_DIRECT_PS`) granting `records.query` & `records.metered_query` in `r3_per_call`
    let (q5_agent, _, _, _) = make_q_agent(
        Q2_AP,
        "q2-ap-1",
        [0x61; 32],
        "caller-q5",
        Q5_RUST_DIRECT_PS,
        [0x7a; 32],
        clock,
    )?;
    let q5_pt_resp = q5_ps_tls.send(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/person"),
        &serde_json::to_vec(&json!({"resource": Q5_RUST_METERED_RES}))?,
        clock,
    )?)?;
    let q5_pt = member(&q5_pt_resp, "person_token").ok_or("missing q5_pt")?;
    let q5_reg = standard_registry()?;
    let q5_ops_set = q5_reg.parse_operation_set(
        json!({
            "vocabulary": MCP,
            "operations": [{"tool": "records.query"}, {"tool": "records.metered_query"}]
        })
        .to_string()
        .as_bytes(),
    )?;
    let q5_class_rt = q5_agent.r3_authorize(
        |req| q5_metered_res_tls.send(&req).map_err(|e| e.to_string()),
        &format!("{Q5_RUST_METERED_RES}/authorize"),
        &q5_pt,
        &q5_ops_set,
        None,
        clock,
    )?;
    let q5_class_at_resp = q5_ps_tls.send(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q5_class_rt,
            "presented_token": q5_pt,
        }))?,
        clock,
    )?)?;
    let q5_class_at = member(&q5_class_at_resp, "auth_token").ok_or("missing q5_class_at")?;
    let q5_class_holder = q5_agent.with_token(q5_class_at.clone())?;

    // 4. Invoke `POST /records/metered-query` (`{"record":"r-1"}`) -> `202 Accepted` with proposal `resource_token` offering `Q5_RELEASE_COST` (250 USD cents)
    let q5_hold_resp = q5_metered_res_tls.send(&post_at(
        &q5_class_holder,
        &format!("{Q5_RUST_METERED_RES}/records/metered-query"),
        br#"{"record":"r-1"}"#,
        clock,
    )?)?;
    let q5_hold_sess = PollSession::new(
        &format!("{Q5_RUST_METERED_RES}/records/metered-query"),
        &q5_hold_resp,
        clock,
        clock + 60,
    )?;
    let q5_pending_loc = q5_hold_sess.pending().location.clone();
    let q5_prop_rt = match &q5_hold_sess.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token requirement on q5_hold_resp".into()),
    };
    let (q5_ver_prop_rt, q5_prop_offer, q5_prop_consumed) =
        verify_budget_resource_token(&q5_prop_rt, trust, clock)?;
    let q5_proposal_offer_ok = q5_hold_resp.status().as_u16() == 202
        && q5_rel_cnt.load(Ordering::SeqCst) == 1
        && q5_prop_offer.amount() == Q5_RELEASE_COST
        && q5_prop_offer.unit() == "USD"
        && q5_prop_offer.decimals() == 2
        && q5_prop_consumed.is_none();

    // 5. Verify an unfunded per-call AuthToken is refused with `403 Forbidden` (no `AAuth-Budget`), and result stays held
    let q5_call_store = DirectoryCallStore::open(&q5_call_dir)?;
    let q5_prop_rec = q5_call_store
        .load(q5_ver_prop_rt.reference().uri())
        .map_err(|e| format!("q5 load prop rec: {e:?}"))?
        .ok_or("missing q5_prop_rec")?;
    let q5_unfunded_at = mint_per_call_auth_token(
        &q5_reg,
        &q5_ps_key,
        "q5-rust-ps-1",
        &AuthClaims {
            iss: Q5_RUST_DIRECT_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: Q5_RUST_METERED_RES.into(),
            ps: Q5_RUST_DIRECT_PS.into(),
            sub: "sub-person-q5-https://q5-rust-metered-res.example".into(),
            jti: "q5-unfunded-pc-1".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([0x7a; 32]).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        &q5_prop_rec.reference,
        &q5_prop_rec.exact_json,
    )?;
    let q5_unfunded_poll = q5_metered_res_tls.send(&get_at(
        &q5_agent.with_token(q5_unfunded_at)?,
        &q5_pending_loc,
        clock,
    )?)?;
    let q5_unfunded_refused_ok = q5_unfunded_poll.status().as_u16() == 403
        && q5_unfunded_poll.headers().get("aauth-budget").is_none();

    // 6. Exchange `q5_prop_rt` at short-capped 3-party PS (`cap = 249 < 250`) -> poll returns `403 Forbidden` with `AAuth-Budget` (`required=250`), result stays held, ledger = 0
    let q5_short_at_resp = q5_ps_short.handle(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q5_prop_rt,
            "presented_token": q5_class_at,
        }))?,
        clock,
    )?);
    let q5_short_at = member(&q5_short_at_resp, "auth_token").ok_or("missing q5_short_at")?;
    let q5_short_poll = q5_metered_res_tls.send(&get_at(
        &q5_agent.with_token(q5_short_at)?,
        &q5_pending_loc,
        clock,
    )?)?;
    let q5_short_hdr = q5_short_poll
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let q5_ledger_ref = q5_metered_res.budget_ledger().ok_or("missing q5 budget_ledger")?;
    let q5_charged_after_short = q5_ledger_ref.lock().unwrap().person_total(
        Q5_RUST_DIRECT_PS,
        "sub-person-q5-https://q5-rust-metered-res.example",
        Q5_RUST_METERED_RES,
        "USD",
    );
    let q5_short_budget_403_ok = q5_short_poll.status().as_u16() == 403
        && q5_short_hdr.contains(&format!("required={Q5_RELEASE_COST}"))
        && q5_charged_after_short == 0;

    // 7. Exchange `q5_prop_rt` at sufficiently capped 3-party PS (`cap = 500 >= 250`) -> narrows budget onto per-call AuthToken (`250`),
    //    release poll returns `200 OK` with `AAuth-Budget: ... cost=250; remaining=0 ...`, ledger = 250;
    //    replay poll returns `200 OK` with same held result and `AAuth-Budget`, ledger still = 250 (charged exact once!)
    let q5_fit_at_resp = q5_ps_tls.send(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q5_prop_rt,
            "presented_token": q5_class_at,
        }))?,
        clock,
    )?)?;
    let q5_fit_at = member(&q5_fit_at_resp, "auth_token").ok_or("missing q5_fit_at")?;
    let (_q5_ver_fit_at, q5_ver_fit_op, q5_ver_fit_budget) = verify_budget_per_call_auth_token(
        &q5_reg,
        &q5_fit_at,
        trust,
        clock,
        &q5_prop_rec.reference,
        &q5_prop_rec.exact_json,
    )?;
    let q5_ps_narrowed_ok = q5_ver_fit_budget.amount() == Q5_RELEASE_COST
        && q5_ver_fit_op.equal(&mcp("records.metered_query")?)?
        && q5_ps_full.budget_accounted() == Some(Q5_RELEASE_COST);

    let q5_release_poll = q5_metered_res_tls.send(&get_at(
        &q5_agent.with_token(q5_fit_at.clone())?,
        &q5_pending_loc,
        clock,
    )?)?;
    let q5_release_hdr = q5_release_poll
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let q5_release_body: Value = serde_json::from_slice(q5_release_poll.body())?;
    let q5_charged_after_release = q5_ledger_ref.lock().unwrap().person_total(
        Q5_RUST_DIRECT_PS,
        "sub-person-q5-https://q5-rust-metered-res.example",
        Q5_RUST_METERED_RES,
        "USD",
    );

    let q5_replay_poll = q5_metered_res_tls.send(&get_at(
        &q5_agent.with_token(q5_fit_at.clone())?,
        &q5_pending_loc,
        clock,
    )?)?;
    let q5_replay_hdr = q5_replay_poll
        .headers()
        .get("aauth-budget")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let q5_replay_body: Value = serde_json::from_slice(q5_replay_poll.body())?;
    let q5_charged_after_replay = q5_ledger_ref.lock().unwrap().person_total(
        Q5_RUST_DIRECT_PS,
        "sub-person-q5-https://q5-rust-metered-res.example",
        Q5_RUST_METERED_RES,
        "USD",
    );
    let q5_release_and_replay_ok = q5_release_poll.status().as_u16() == 200
        && q5_release_body["released"].as_str() == Some("\"r-1\"")
        && q5_release_body["metered"].as_bool() == Some(true)
        && q5_release_hdr.contains(&format!("cost={Q5_RELEASE_COST}"))
        && q5_release_hdr.contains("remaining=0")
        && q5_charged_after_release == Q5_RELEASE_COST
        && q5_replay_poll.status().as_u16() == 200
        && q5_replay_body["released"].as_str() == Some("\"r-1\"")
        && q5_replay_hdr.contains(&format!("cost={Q5_RELEASE_COST}"))
        && q5_replay_hdr.contains("remaining=0")
        && q5_charged_after_replay == Q5_RELEASE_COST
        && q5_rel_cnt.load(Ordering::SeqCst) == 1;

    // 8. Verify an unmetered release (`POST /records/query`, `{"record":"r-2"}`, `cost: None`) on the same Resource
    //    issues a plain (no-budget) proposal `resource_token` and releases without charging the ledger
    let q5_unmetered_hold_resp = q5_metered_res_tls.send(&post_at(
        &q5_class_holder,
        &format!("{Q5_RUST_METERED_RES}/records/query"),
        br#"{"record":"r-2"}"#,
        clock,
    )?)?;
    let q5_unmetered_sess = PollSession::new(
        &format!("{Q5_RUST_METERED_RES}/records/query"),
        &q5_unmetered_hold_resp,
        clock,
        clock + 60,
    )?;
    let q5_unmetered_loc = q5_unmetered_sess.pending().location.clone();
    let q5_unmetered_prop_rt = match &q5_unmetered_sess.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token on q5_unmetered_hold_resp".into()),
    };
    let q5_unmetered_no_offer =
        verify_r3_resource_token_raw(&q5_unmetered_prop_rt, trust, clock).is_ok();
    let q5_unmetered_at_resp = q5_ps_tls.send(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q5_unmetered_prop_rt,
            "presented_token": q5_class_at,
        }))?,
        clock,
    )?)?;
    let q5_unmetered_at =
        member(&q5_unmetered_at_resp, "auth_token").ok_or("missing q5_unmetered_at")?;
    let q5_unmetered_poll = q5_metered_res_tls.send(&get_at(
        &q5_agent.with_token(q5_unmetered_at)?,
        &q5_unmetered_loc,
        clock,
    )?)?;
    let q5_charged_after_unmetered = q5_ledger_ref.lock().unwrap().person_total(
        Q5_RUST_DIRECT_PS,
        "sub-person-q5-https://q5-rust-metered-res.example",
        Q5_RUST_METERED_RES,
        "USD",
    );
    let q5_unmetered_beside_ok = q5_unmetered_no_offer
        && q5_unmetered_poll.status().as_u16() == 200
        && q5_unmetered_poll.headers().get("aauth-budget").is_none()
        && q5_charged_after_unmetered == Q5_RELEASE_COST;

    // 9. Verify a Rust Federated PS (`with_federation` + `with_budgets` + `with_r3`) refuses a proposal `resource_token`
    //    carrying a budget offer with `400 invalid_resource_token` (`crates/aauth-rust-person-server/src/server/r3.rs:535`)
    let q5_fed_ps_seq = Arc::new(AtomicUsize::new(0));
    let q5_fed_ps = PersonServer::new(
        PsConfig::new(Q5_RUST_DIRECT_PS, "q5-rust-ps-1", SigningKey::from_seed([0x79; 32])),
        trust.clone(),
        q5_ps_store.clone(),
        QSharedMissionPsPolicy(q5_ps_policy.clone()),
        Box::new(move || clock) as BoxedClock,
        Box::new(move || {
            format!(
                "q5-fed-ps-jti-{}",
                q5_fed_ps_seq.fetch_add(1, Ordering::SeqCst) + 1
            )
        }) as BoxedTokenIds,
    )?
    .with_federation(DummyFederation)
    .with_budgets(IssuerPolicy::capped(
        500,
        vec![UnitDeclaration::new("USD", 2, "US dollars")?],
    ))?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(TlsFetch(q5_metered_res_tls.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(Q5ReleaseR3Policy),
        audit: Arc::new(QaAuditStore {
            commits: Arc::new(AtomicUsize::new(0)),
            last_token_jti: Arc::new(Mutex::new(None)),
        }),
    })?;
    let mut q5_fed_prop_claims = q5_ver_prop_rt.claims().clone();
    q5_fed_prop_claims.presented_jti = PersonToken::parse(&q5_pt)?.unverified_claims().jti.clone();
    q5_fed_prop_claims.jti = "q5-fed-prop-rt-1".into();
    let (q5_fed_prop_rt, _) = mint_budget_proposal_resource_token(
        &q5_reg,
        &SigningKey::from_seed([0x76; 32]),
        "q5-rust-metered-res-1",
        &q5_fed_prop_claims,
        q5_prop_rec.reference.uri(),
        &q5_prop_rec.exact_json,
        &Budget::new(Q5_RELEASE_COST, "USD", 2)?,
    )?;
    let q5_rust_fed_ps_refusal = q5_fed_ps.handle(&post_at(
        &q5_agent,
        &format!("{Q5_RUST_DIRECT_PS}/token"),
        &serde_json::to_vec(&json!({
            "resource_token": q5_fed_prop_rt,
            "presented_token": q5_pt,
        }))?,
        clock,
    )?);
    let q5_rust_fed_ps_refusal_ok = q5_rust_fed_ps_refusal.status().as_u16() == 400
        && member(&q5_rust_fed_ps_refusal, "error").as_deref() == Some("invalid_resource_token");

    // 10. Cross-language wire check against `aauth-go` main (`445af350`):
    //     (a) Go Direct PS refuses a proposal `resource_token` carrying `budget` with `400 invalid_resource_token`
    //     (b) Go Federated PS -> Go AS refuses a proposal `resource_token` carrying `budget` (`500 server_error` relayed from Go AS)
    //     (c) Go Held R3 Resource (`q5-go-held-r3-res.example`) refuses a per-call `AuthToken` carrying `budget` with `401 Unauthorized` (`Signature-Error: error=invalid_jwt`)
    let q5_go_direct_ps_refusal_ok =
        go_q_suite["q5"]["direct_ps_proposal_rt_refusal"]["ok"].as_bool() == Some(true);
    let q5_go_fed_ps_as_refusal_ok =
        go_q_suite["q5"]["fed_ps_go_as_proposal_rt_refusal"]["ok"].as_bool() == Some(true);

    // Present a budget-carrying per-call AuthToken to `q5-go-held-r3-res.example` on protected route `/records/r-go-99`
    let q5_go_prop_doc = Proposal::new(
        &mcp("records.query")?,
        &Parameters::new([("query".to_owned(), Parameter::inline(br#""r-go-99""#)?)])?,
        ProposalOptions::default(),
    )?;
    let q5_go_prop_bytes = serde_json::to_vec(&q5_go_prop_doc)?;
    let q5_go_prop_ref = Reference::new(
        &format!("{Q5_GO_HELD_R3_RES}/r3/proposals/prop-go-1"),
        &digest(&q5_go_prop_bytes),
    )?;
    let q5_go_budget_pc_at = mint_budget_per_call_auth_token(
        &q5_reg,
        &q4_rust_as_key,
        "q4-rust-as-1",
        &AuthClaims {
            iss: Q4_RUST_AS.into(),
            dwk: "aauth-access.json".into(),
            aud: Q5_GO_HELD_R3_RES.into(),
            ps: Q4_RUST_PS.into(),
            sub: "sub-person-q4-rust-https://q5-go-held-r3-res.example".into(),
            jti: "q5-go-budget-pc-at-1".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([0x77; 32]).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: Some("records.read".into()),
            account: None,
            extra: BTreeMap::new(),
        },
        &q5_go_prop_ref,
        &q5_go_prop_bytes,
        &Budget::new(Q5_RELEASE_COST, "USD", 2)?,
    )?;
    let q5_go_budget_call = send_https(
        q5_go_held_res_addr,
        "q5-go-held-r3-res.example",
        &q5_go_held_res_cert,
        &get_at(
            &q4_caller_agent.with_token(q5_go_budget_pc_at)?,
            &format!("{Q5_GO_HELD_R3_RES}/records/r-go-99"),
            clock,
        )?,
    )?;
    let q5_go_res_sig_err = q5_go_budget_call
        .headers()
        .get("signature-error")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let q5_go_res_refusal_ok =
        q5_go_budget_call.status().as_u16() == 401 && q5_go_res_sig_err.contains("invalid_jwt");

    let q5_pass = q5_config_guards_ok
        && q5_proposal_offer_ok
        && q5_unfunded_refused_ok
        && q5_short_budget_403_ok
        && q5_ps_narrowed_ok
        && q5_release_and_replay_ok
        && q5_unmetered_beside_ok
        && q5_rust_fed_ps_refusal_ok
        && q5_go_direct_ps_refusal_ok
        && q5_go_fed_ps_as_refusal_ok
        && q5_go_res_refusal_ok;
    cases.push(json!({
        "id": "QA-Q5",
        "classification": "VERIFIED_WORKING",
        "pass": q5_pass,
        "summary": format!(
            "Metered release of held R3 result (`with_release_metering`, `R3Release::cost`) & cross-language wire check verified: config guards={}, proposal offers cost as budget={}, unfunded 403={}, short budget 403+AAuth-Budget (`required=250`) & stays held={}, 3-party PS narrows budget & release charges once (`200 OK` + `AAuth-Budget`) & replay not charged again={}, unmetered release beside it={}, Rust Fed PS refuses proposal+budget with 400={}, Go Direct PS/Fed PS/Resource refuse per-call budget wire ({}/{}/{})",
            q5_config_guards_ok,
            q5_proposal_offer_ok,
            q5_unfunded_refused_ok,
            q5_short_budget_403_ok,
            q5_ps_narrowed_ok && q5_release_and_replay_ok,
            q5_unmetered_beside_ok,
            q5_rust_fed_ps_refusal_ok,
            q5_go_direct_ps_refusal_ok,
            q5_go_fed_ps_as_refusal_ok,
            q5_go_res_refusal_ok,
        ),
        "details": {
            "config_guards_ok": q5_config_guards_ok,
            "proposal_budget_offer_ok": q5_proposal_offer_ok,
            "unfunded_403_refusal_ok": q5_unfunded_refused_ok,
            "short_budget_403_header": q5_short_hdr,
            "short_budget_403_ok": q5_short_budget_403_ok,
            "ps_budget_narrowing_ok": q5_ps_narrowed_ok,
            "release_header": q5_release_hdr,
            "replay_header": q5_replay_hdr,
            "charged_after_release": q5_charged_after_release,
            "charged_after_replay": q5_charged_after_replay,
            "unmetered_beside_ok": q5_unmetered_beside_ok,
            "rust_fed_ps_proposal_budget_refusal_ok": q5_rust_fed_ps_refusal_ok,
            "go_direct_ps_proposal_budget_refusal_ok": q5_go_direct_ps_refusal_ok,
            "go_fed_ps_as_proposal_budget_refusal_ok": q5_go_fed_ps_as_refusal_ok,
            "go_held_res_per_call_budget_refusal_ok": q5_go_res_refusal_ok,
        },
    }));

    // =========================================================================
    // QA-Q6: Consumer Documentation Sufficiency Audit (Cargo.toml 0.1.0-alpha.16,
    // CONFORMANCE.md "Added on 2026-10-31", README.md, PACKAGE-README.md,
    // USE-IN-YOUR-SERVICE.md, DOC-OBS-O7-1 & DOC-OBS-P11-1..3)
    // =========================================================================
    let rust_root = crate::rust_source();
    let cargo_toml = fs::read_to_string(rust_root.join("Cargo.toml"))?;
    let readme_md = fs::read_to_string(rust_root.join("README.md"))?;
    let pkg_readme_md = fs::read_to_string(rust_root.join("PACKAGE-README.md"))?;
    let conf_md = fs::read_to_string(rust_root.join("CONFORMANCE.md"))?;
    let use_md = fs::read_to_string(rust_root.join("USE-IN-YOUR-SERVICE.md"))?;

    let go_root = Path::new(go_module_path);
    let go_conf_md = fs::read_to_string(go_root.join("CONFORMANCE.md"))?;
    let go_interp_md = fs::read_to_string(go_root.join("INTERPRETATIONS.md"))?;

    let q6_version_ok = (cargo_toml.contains("version = \"0.1.0-alpha.16\"")
        || cargo_toml.contains("version = \"0.1.0-alpha.17\""))
        && !cargo_toml.contains("0.1.0-alpha.15")
        && (readme_md.contains("v0.1.0-alpha.16") || readme_md.contains("v0.1.0-alpha.17"))
        && (readme_md.contains("version = \"0.1.0-alpha.16\"") || readme_md.contains("version = \"0.1.0-alpha.17\""))
        && (pkg_readme_md.contains("`0.1.0-alpha.16`") || pkg_readme_md.contains("`0.1.0-alpha.17`"));

    let q6_conformance_ok = [
        "Added on 2026-10-31:",
        "Four-party missions, chained or not.",
        "MissionStore::commit_mission_token",
        "403 mission_terminated",
        "with_mission_context",
        "Metered release of a held R3 result. With `with_release_metering`",
        "R3Release::cost",
        "API change: `R3Release` gains `cost`.",
        "missions carried down three- and four-party chains",
        "Federated (four-party) and upstream mission paths are supported, chained or not",
    ]
    .iter()
    .all(|needle| conf_md.contains(needle));

    let q6_use_md_ok = [
        "To meter the release of a result rather than the execution, enable budgets and\ncall `with_release_metering` after `with_r3_per_call`.",
        "R3Release::cost",
        "aauth_rust_r3::verify_budget_resource_token",
        "aauth_rust_r3::verify_budget_per_call_auth_token",
        "Missions work through federation, chained or not.",
        "MissionStore::commit_mission_token",
        "with_mission_context",
        "InvalidR3Profile",
    ]
    .iter()
    .all(|needle| use_md.contains(needle));

    // Verify DOC-OBS-O7-1 (stale "The direct constructor implements immediate, missionless PS authorization..."
    // paragraph in USE-IN-YOUR-SERVICE.md) is resolved in 0.1.0-alpha.16
    let q6_doc_obs_o7_1_resolved = !use_md
        .contains("The direct constructor implements immediate, missionless PS authorization.")
        && use_md.contains("The direct constructor issues Person and Auth tokens from this PS immediately.\nEverything else is opt-in on the same value.");

    // Verify DOC-OBS-P11-1..3 in aauth-go main (445af350) remain resolved
    let q6_doc_obs_p11_resolved = !go_conf_md.contains("and the `cached` scheme stays unsupported")
        && !(go_interp_md
            .contains("The Access Server keeps no revocation records, so it never answers")
            && go_interp_md.contains("`revoked_upstream_token`."))
        && !go_conf_md.contains("Only AP Agent tokens and PS Auth tokens are supported.");

    let q6_pass = q6_version_ok
        && q6_conformance_ok
        && q6_use_md_ok
        && q6_doc_obs_o7_1_resolved
        && q6_doc_obs_p11_resolved;

    cases.push(json!({
        "id": "QA-Q6",
        "classification": "DEFECT_RESOLVED",
        "pass": q6_pass,
        "summary": format!(
            "Consumer documentation audit passed for aauth-rust 0.1.0-alpha.16 (9961b6cc) & aauth-go main (445af350): Cargo.toml/README/PACKAGE-README version=0.1.0-alpha.16 ({}), CONFORMANCE.md 'Added on 2026-10-31' covers 4-party missions, metered R3 release & breaking API changes ({}), USE-IN-YOUR-SERVICE.md documents with_mission_context/commit_mission_token/with_release_metering/R3Release::cost ({}), DOC-OBS-O7-1 resolved in aauth-rust ({}), and DOC-OBS-P11-1..3 resolved in aauth-go main ({})",
            q6_version_ok,
            q6_conformance_ok,
            q6_use_md_ok,
            q6_doc_obs_o7_1_resolved,
            q6_doc_obs_p11_resolved,
        ),
        "details": {
            "version_0_1_0_alpha_16_ok": q6_version_ok,
            "conformance_added_2026_10_31_ok": q6_conformance_ok,
            "use_in_your_service_ok": q6_use_md_ok,
            "doc_obs_o7_1_resolved": q6_doc_obs_o7_1_resolved,
            "doc_obs_p11_1_to_3_resolved": q6_doc_obs_p11_resolved,
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
            category: "Q. Four-Party Missions & Metered R3 Release, with Cross-Language Interop".into(),
            title: format!("{id}: {summary}"),
            classification,
            passed_expectation: pass,
            summary,
            evidence: c,
        });
    }

    Ok(())
}
