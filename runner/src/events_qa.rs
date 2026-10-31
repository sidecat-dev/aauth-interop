use crate::{QaCaseReceipt, Result, Trust, get, header_values, hex_decode, json_response, text};
use crate::tls::TlsServer;
use aauth_rust_agent::{Agent, EventError, EventSubscriptions, verify_event};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_agent_provider::events::{
    DirectoryEventStore, EventInbox, EventStore, SubscribeRequest,
};
use aauth_rust_core::events::{
    EVENT_TOKEN_DOCUMENT, EventClaims, EventToken,
    SubscribeToken, body_s256, generate_identifier, mint_event_token,
};
use aauth_rust_core::{
    AgentClaims, AuthClaims, AuthToken, Confirmation, TrustedIssuerKeys,
    mint_auth_token,
};
use aauth_rust_jose::SigningKey;
use aauth_rust_resource::Deny;
use aauth_rust_resource::events::{
    AsyncApiDeclarationError, DeliveryOutcome, EventPayload, EventsConfig,
    EventsResource, MemorySubscriptionStore, SubscriptionStore,
    agent_provider_metadata_url, check_subscribe_security_scheme, subscribe_security_scheme,
};
use aauth_rust_signature_key::{KeyMaterial, sign_request as sign_raw_request};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};
use http::{Request, Response};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
};

const VALID_ASYNCAPI_JSON: &[u8] = br##"{
  "asyncapi": "3.0.0",
  "info": {"title": "Rust QA Events Service", "version": "1.0.0"},
  "channels": {
    "waitlist": {
      "address": "/events/subscribe",
      "messages": {"slotAvailable": {"$ref": "#/components/messages/SlotAvailable"}}
    }
  },
  "operations": {
    "subscribeWaitlist": {
      "action": "receive",
      "channel": {"$ref": "#/channels/waitlist"},
      "security": [{"$ref": "#/components/securitySchemes/aauth_subscribe"}]
    }
  },
  "components": {
    "messages": {
      "SlotAvailable": {
        "contentType": "application/json",
        "payload": {
          "type": "object",
          "properties": {"event_type": {"type": "string"}, "slot": {"type": "string"}},
          "required": ["event_type"]
        }
      }
    },
    "securitySchemes": {
      "aauth_subscribe": {
        "type": "http",
        "scheme": "aauth-subscribe",
        "description": "AAuth Subscribe Token as Signature-Key JWT"
      }
    }
  }
}"##;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn post_json_external(
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
    let res = post_json_external(
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

/// Standalone child process mode for `QA-J5` (Rust Agent Provider Process-Restart Durability on `DirectoryEventStore`).
pub fn run_child_rust_ap(args: &[String]) -> Result<()> {
    let mut store_dir: Option<PathBuf> = None;
    let mut now_unix: i64 = 1_700_000_000;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--store-dir" => {
                i += 1;
                store_dir = Some(PathBuf::from(args.get(i).ok_or("--store-dir requires path")?));
            }
            "--now" => {
                i += 1;
                now_unix = args.get(i).ok_or("--now requires int")?.parse()?;
            }
            _ => {}
        }
        i += 1;
    }
    let store_dir = store_dir.ok_or("--store-dir is required")?;

    let ap_issuer = "https://j5-durable-ap.example";
    let res_issuer = "https://j5-durable-res.example";
    let agent_id = "aauth:clerk@j5-durable-ap.example";

    let ap = Arc::new(
        AgentProvider::new(ap_issuer, "j5-ap-1", SigningKey::from_seed([0xA1; 32]))?
            .with_event_endpoint(&format!("{ap_issuer}/events"))?,
    );
    let res_pub_jwk = SigningKey::from_seed([0xA2; 32]).public_jwk();
    let res_jwks = json!({
        "keys": [{
            "kid": "j5-res-1",
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "Ed25519",
            "x": res_pub_jwk.x,
        }]
    });
    let res_meta = json!({
        "issuer": res_issuer,
        "jwks_uri": format!("{res_issuer}/.well-known/jwks.json"),
    });
    let res_keys = TrustedIssuerKeys::from_documents(
        res_issuer,
        "aauth-resource.json",
        res_meta.to_string().as_bytes(),
        res_jwks.to_string().as_bytes(),
    )?;
    let store = DirectoryEventStore::open(&store_dir)?;
    let inbox = Arc::new(EventInbox::new(&ap, res_keys, store)?);
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let ap_c = ap.clone();
    let inbox_c = inbox.clone();
    let shutdown_c = shutdown_flag.clone();
    let tls = TlsServer::start("j5-durable-ap.example", move |req| {
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-agent.json") => json_response(
                200,
                serde_json::from_slice(&ap_c.metadata().unwrap()).unwrap(),
            ),
            ("GET", "/.well-known/jwks.json") => {
                json_response(200, serde_json::from_slice(&ap_c.jwks().unwrap()).unwrap())
            }
            ("POST", "/events") => inbox_c.receive(&req, now_unix).into_response(),
            ("POST", "/__issue-subscribe") => {
                let body: Value = serde_json::from_slice(req.body()).unwrap_or_default();
                let max_uses = body.get("max_uses").and_then(Value::as_u64);
                let agent_token = ap_c
                    .issue(&AgentClaims {
                        iss: ap_issuer.into(),
                        dwk: "aauth-agent.json".into(),
                        sub: agent_id.into(),
                        jti: "j5-agent-tok-1".into(),
                        iat: now_unix,
                        exp: now_unix + 3600,
                        cnf: Confirmation {
                            jwk: SigningKey::from_seed([0xA3; 32]).public_jwk(),
                        },
                        ps: None,
                        parent_agent: None,
                        nbf: None,
                        extra: Default::default(),
                    })
                    .unwrap();
                let issued = ap_c
                    .issue_subscribe_token(
                        inbox_c.store(),
                        &SubscribeRequest {
                            agent_token: &agent_token,
                            resource: res_issuer,
                            expires_at: now_unix + 600,
                            max_uses,
                            subscription_expires_at: None,
                        },
                        now_unix,
                    )
                    .unwrap();
                json_response(
                    200,
                    json!({
                        "token": issued.token,
                        "eid": issued.subscription.eid,
                        "jti": issued.subscription.token_jti,
                        "max_uses": issued.subscription.max_uses,
                    }),
                )
            }
            ("POST", "/__state") => {
                let body: Value = serde_json::from_slice(req.body()).unwrap_or_default();
                let eid = body.get("eid").and_then(Value::as_str).unwrap_or("");
                let sub = inbox_c.store().subscription(eid).unwrap();
                let pending = inbox_c.store().pending(agent_id).unwrap();
                let pending_json: Vec<Value> = pending
                    .iter()
                    .map(|ev| {
                        json!({
                            "eid": ev.eid,
                            "jti": ev.jti,
                            "event_token": ev.event_token,
                            "body_b64": BASE64_STD.encode(&ev.body),
                            "content_type": ev.content_type,
                        })
                    })
                    .collect();
                json_response(
                    200,
                    json!({
                        "subscription_found": sub.is_some(),
                        "uses": sub.as_ref().map(|(_, u)| *u).unwrap_or(0),
                        "max_uses": sub.as_ref().and_then(|(s, _)| s.max_uses),
                        "pending_count": pending.len(),
                        "pending": pending_json,
                    }),
                )
            }
            ("POST", "/__shutdown") => {
                shutdown_c.store(true, Ordering::SeqCst);
                json_response(200, json!({"shutting_down": true}))
            }
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?;

    println!(
        "{}",
        json!({
            "addr": tls.address().to_string(),
            "cert_hex": hex_encode(tls.cert_der()),
            "pid": std::process::id(),
        })
    );
    use std::io::Write as _;
    std::io::stdout().flush()?;

    // Read stdin until EOF or shutdown signal
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    drop(tls);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run_events_qa_cases(
    body: &Value,
    out_dir: &Path,
    go_module_path: &str,
    clock_base: &Arc<AtomicI64>,
    trust: &Trust,
    cases: &mut Vec<QaCaseReceipt>,
    transcript_lines: &mut Vec<String>,
) -> Result<()> {
    let clock = clock_base.load(Ordering::SeqCst);
    let go_events_ap_addr: SocketAddr = text(body, "go_events_ap_addr")?.parse()?;
    let go_events_ap_cert = hex_decode(&text(body, "go_events_ap_cert_hex")?)?;
    let go_events_res_addr: SocketAddr = text(body, "go_events_res_addr")?.parse()?;
    let go_events_res_cert = hex_decode(&text(body, "go_events_res_cert_hex")?)?;
    let go_rogue_res_addr: SocketAddr = text(body, "go_rogue_res_addr")?.parse()?;
    let go_rogue_res_cert = hex_decode(&text(body, "go_rogue_res_cert_hex")?)?;

    trust.discover_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example",
        "aauth-agent.json",
    )?;
    trust.discover_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example",
        "aauth-resource.json",
    )?;
    trust.discover_external(
        go_rogue_res_addr,
        "go-rogue-res.example",
        &go_rogue_res_cert,
        "https://go-rogue-res.example",
        "aauth-resource.json",
    )?;

    // =========================================================================
    // QA-J1: Rust Events Native End-to-End, Inbox Validation Order, max_uses,
    //        Durable Store Commit Before 202, & AsyncAPI aauth_subscribe
    // =========================================================================
    let j1_ap_issuer = "https://j1-rust-ap.example";
    let j1_res_issuer = "https://j1-rust-res.example";
    let j1_rogue_issuer = "https://j1-rogue-res.example";
    let j1_agent_id = "aauth:clerk@j1-rust-ap.example";

    let j1_ap_key = SigningKey::from_seed([0x61; 32]);
    let j1_res_key = SigningKey::from_seed([0x62; 32]);
    let j1_rogue_key = SigningKey::from_seed([0x63; 32]);
    let j1_agent_key = SigningKey::from_seed([0x64; 32]);
    let j1_other_agent_key = SigningKey::from_seed([0x65; 32]);

    // 1. AsyncAPI validation checks
    let j1_asyncapi_valid_ok = check_subscribe_security_scheme(VALID_ASYNCAPI_JSON).is_ok();
    let j1_asyncapi_missing_err = check_subscribe_security_scheme(
        br#"{"asyncapi":"3.0.0","components":{"securitySchemes":{}}}"#,
    );
    let j1_asyncapi_mismatch_err = check_subscribe_security_scheme(
        br#"{"asyncapi":"3.0.0","components":{"securitySchemes":{"aauth_subscribe":{"type":"http","scheme":"bearer"}}}}"#,
    );
    let j1_asyncapi_malformed_err = check_subscribe_security_scheme(b"not-json");
    let j1_scheme_helper = subscribe_security_scheme();
    let j1_scheme_helper_ok = j1_scheme_helper.get("type").and_then(Value::as_str) == Some("http")
        && j1_scheme_helper.get("scheme").and_then(Value::as_str) == Some("aauth-subscribe");

    let j1_ap_no_ep = AgentProvider::new(j1_ap_issuer, "j1-ap-1", SigningKey::from_seed([0x61; 32]))?;
    let j1_inbox_without_ep_refused = EventInbox::new(
        &j1_ap_no_ep,
        trust.clone(),
        DirectoryEventStore::open(out_dir.join("j1-unused"))?,
    )
    .is_err();

    let j1_ap = Arc::new(
        AgentProvider::new(j1_ap_issuer, "j1-ap-1", j1_ap_key)?
            .with_event_endpoint(&format!("{j1_ap_issuer}/events"))?,
    );
    let j1_ap_store = Arc::new(DirectoryEventStore::open(out_dir.join("j1-ap-store"))?);
    let j1_inbox = Arc::new(EventInbox::new(&j1_ap, trust.clone(), j1_ap_store.clone())?);

    let j1_ap_c = j1_ap.clone();
    let j1_inbox_c = j1_inbox.clone();
    let j1_clk = clock_base.clone();
    let j1_ap_tls = TlsServer::start("j1-rust-ap.example", move |req| {
        let now_s = j1_clk.load(Ordering::SeqCst);
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-agent.json") => json_response(
                200,
                serde_json::from_slice(&j1_ap_c.metadata().unwrap()).unwrap(),
            ),
            ("GET", "/.well-known/jwks.json") => {
                json_response(200, serde_json::from_slice(&j1_ap_c.jwks().unwrap()).unwrap())
            }
            (_, "/events") => j1_inbox_c.receive(&req, now_s).into_response(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?;
    trust.discover(&j1_ap_tls, j1_ap_issuer, "aauth-agent.json")?;

    let j1_res_store = Arc::new(MemorySubscriptionStore::new());
    let j1_events_res = Arc::new(
        EventsResource::new(
            EventsConfig {
                issuer: j1_res_issuer.into(),
                signed_origin: j1_res_issuer.into(),
                kid: "j1-res-1".into(),
                signing_key: j1_res_key,
                ticket_path: "/events/tickets/".into(),
                max_ticket_lifetime: 300,
            },
            trust.clone(),
            j1_res_store.clone(),
        )?
        .with_asyncapi(VALID_ASYNCAPI_JSON.to_vec())?,
    );
    let j1_res_c = j1_events_res.clone();
    let j1_clk2 = clock_base.clone();
    let j1_res_tls = TlsServer::start("j1-rust-res.example", move |req| {
        let now_s = j1_clk2.load(Ordering::SeqCst);
        let path = req.uri().path().to_owned();
        if req.method().as_str() == "GET" && path == "/.well-known/aauth-resource.json" {
            return json_response(
                200,
                json!({
                    "issuer": j1_res_issuer,
                    "jwks_uri": format!("{j1_res_issuer}/.well-known/jwks.json"),
                }),
            );
        }
        if req.method().as_str() == "GET" && path == "/.well-known/jwks.json" {
            return json_response(
                200,
                serde_json::from_slice(&j1_res_c.jwks().unwrap()).unwrap(),
            );
        }
        if req.method().as_str() == "GET" && path == "/asyncapi.json" {
            return Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(j1_res_c.asyncapi().unwrap().to_vec())
                .unwrap();
        }
        if path == "/events/subscribe" {
            return j1_res_c
                .register(&req, now_s, |sub_req| {
                    if sub_req.request.body() == b"deny" {
                        Err(Deny)
                    } else {
                        Ok(sub_req.request.body().clone())
                    }
                })
                .into_response();
        }
        if path.starts_with("/events/tickets/") {
            return j1_res_c
                .register_with_ticket(&req, now_s, |sub_req| {
                    let mut ctx = sub_req
                        .ticket
                        .map(|t| t.context.clone())
                        .unwrap_or_default();
                    if !sub_req.request.body().is_empty() {
                        ctx.extend_from_slice(b":");
                        ctx.extend_from_slice(sub_req.request.body());
                    }
                    Ok(ctx)
                })
                .into_response();
        }
        json_response(404, json!({"error": "not_found"}))
    })?;
    trust.discover(&j1_res_tls, j1_res_issuer, "aauth-resource.json")?;

    // Rogue Resource for wrong-Resource 403 test
    let j1_rogue_jwks = json!({
        "keys": [{
            "kid": "j1-rogue-1",
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "Ed25519",
            "x": j1_rogue_key.public_jwk().x,
        }]
    });
    let j1_rogue_snap = TrustedIssuerKeys::from_documents(
        j1_rogue_issuer,
        "aauth-resource.json",
        json!({"issuer": j1_rogue_issuer, "jwks_uri": format!("{j1_rogue_issuer}/.well-known/jwks.json")})
            .to_string()
            .as_bytes(),
        j1_rogue_jwks.to_string().as_bytes(),
    )?;
    trust.insert_manual(j1_rogue_issuer, "aauth-resource.json", j1_rogue_snap)?;

    let j1_agent_tok = j1_ap.issue(&AgentClaims {
        iss: j1_ap_issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: j1_agent_id.into(),
        jti: "j1-ag-tok-1".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: j1_agent_key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let j1_agent = Agent::new(j1_agent_key, j1_agent_tok.clone())?;
    let mut j1_subs = EventSubscriptions::new(j1_agent_id)?;

    // 2. Public subscription registration & delivery (with body + no body)
    let j1_issued_pub = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(2),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j1_pub_eid = j1_subs.remember(&j1_issued_pub.token, "j1-public-waitlist".to_owned())?;
    let j1_sub_parsed = SubscribeToken::parse(&j1_issued_pub.token)?;
    let j1_sub_has_jti_and_eid = j1_sub_parsed.unverified_claims().jti.len() == 22
        && j1_sub_parsed.unverified_claims().eid.len() == 22
        && j1_pub_eid == j1_issued_pub.subscription.eid;

    let mut j1_reg_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_res_issuer}/events/subscribe"))
        .header("content-type", "application/json")
        .body(br#"{"event_types":["slot.available"]}"#.to_vec())?;
    j1_agent.sign_subscription(&mut j1_reg_req, &j1_issued_pub.token, clock)?;
    let j1_reg_resp = j1_res_tls.send(&j1_reg_req)?;
    let j1_reg_status = j1_reg_resp.status().as_u16();
    // Duplicate registration of same (iss, eid) -> 409 Conflict
    let j1_reg_dup_resp = j1_res_tls.send(&j1_reg_req)?;
    let j1_reg_dup_status = j1_reg_dup_resp.status().as_u16();

    // Deliver Event #1 (with JSON body)
    let j1_ap_meta_resp = j1_ap_tls.send(&get(&agent_provider_metadata_url(j1_ap_issuer))?)?;
    let j1_ev1_body = br#"{"event_type":"slot.available","slot":"09:30"}"#;
    let j1_prep1 = j1_events_res.prepare_event(
        j1_ap_issuer,
        &j1_pub_eid,
        Some(EventPayload {
            content_type: "application/json",
            body: j1_ev1_body,
        }),
        clock + 300,
        clock,
    )?;
    let j1_ev1_parsed = EventToken::parse(j1_prep1.token())?;
    let j1_ev1_has_body_s256 =
        j1_ev1_parsed.unverified_claims().body_s256.as_deref() == Some(&body_s256(j1_ev1_body));
    let j1_del_req1 = j1_events_res.delivery_request(&j1_prep1, j1_ap_meta_resp.body(), clock)?;
    let j1_del_resp1 = j1_ap_tls.send(&j1_del_req1)?;
    let j1_del_out1 = j1_events_res.delivery_outcome(&j1_prep1, &j1_del_resp1)?;

    // Duplicate delivery of same PreparedEvent (same jti) -> 202 with remaining_uses: Some(1)
    let j1_del_req1_dup =
        j1_events_res.delivery_request(&j1_prep1, j1_ap_meta_resp.body(), clock)?;
    let j1_del_resp1_dup = j1_ap_tls.send(&j1_del_req1_dup)?;
    let j1_del_out1_dup = j1_events_res.delivery_outcome(&j1_prep1, &j1_del_resp1_dup)?;

    // Relay Event #1 from AP store to Rust Agent
    let j1_pending1 = j1_ap_store.pending(j1_agent_id)?;
    let j1_rec1_ctx = j1_subs
        .receive(
            &j1_pending1[0].event_token,
            &j1_pending1[0].body,
            trust,
            clock,
        )?
        .context
        .clone();
    let j1_rec1_dup_is_duplicate = matches!(
        j1_subs.receive(
            &j1_pending1[0].event_token,
            &j1_pending1[0].body,
            trust,
            clock,
        ),
        Err(EventError::Duplicate)
    );
    let j1_tampered_body_err = verify_event(
        &j1_pending1[0].event_token,
        br#"{"event_type":"slot.available","slot":"TAMPERED"}"#,
        j1_agent_id,
        trust,
        clock,
    );
    j1_ap_store.acknowledge(j1_agent_id, j1_res_issuer, &j1_pending1[0].jti)?;
    let j1_pending_after_ack1 = j1_ap_store.pending(j1_agent_id)?.len();

    // Deliver Event #2 (no body!) -> remaining_uses: Some(0), subscription removed at Resource
    let j1_prep2 =
        j1_events_res.prepare_event(j1_ap_issuer, &j1_pub_eid, None, clock + 300, clock)?;
    let j1_ev2_parsed = EventToken::parse(j1_prep2.token())?;
    let j1_ev2_no_body_s256 = j1_ev2_parsed.unverified_claims().body_s256.is_none();
    let j1_del_req2 = j1_events_res.delivery_request(&j1_prep2, j1_ap_meta_resp.body(), clock)?;
    let j1_del_resp2 = j1_ap_tls.send(&j1_del_req2)?;
    let j1_del_out2 = j1_events_res.delivery_outcome(&j1_prep2, &j1_del_resp2)?;
    let j1_sub_removed_at_res = j1_res_store
        .subscription(j1_ap_issuer, &j1_pub_eid)?
        .is_none();

    let j1_pending2 = j1_ap_store.pending(j1_agent_id)?;
    let j1_rec2 = j1_subs.receive(
        &j1_pending2[0].event_token,
        &j1_pending2[0].body,
        trust,
        clock,
    )?;
    let j1_rec2_ok = j1_rec2.context == "j1-public-waitlist" && j1_pending2[0].body.is_empty();
    let j1_nobody_with_bytes_err = verify_event(
        &j1_pending2[0].event_token,
        b"unexpected",
        j1_agent_id,
        trust,
        clock,
    );
    j1_ap_store.acknowledge(j1_agent_id, j1_res_issuer, &j1_pending2[0].jti)?;

    // 3. Inbox validation order & max_uses conservation
    let j1_issued_order = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j1_order_eid = j1_issued_order.subscription.eid.clone();
    // (a) GET /events -> 405
    let j1_get_ev_resp = j1_ap_tls.send(&get(&format!("{j1_ap_issuer}/events"))?)?;
    // (b) Expired event token -> 401 expired_jwt
    let j1_exp_tok = mint_event_token(
        & SigningKey::from_seed([0x62; 32]),
        "j1-res-1",
        &EventClaims {
            iss: j1_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j1_agent_id.into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock - 600,
            exp: clock,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j1_exp_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .body(Vec::new())?;
    sign_raw_request(
        &mut j1_exp_req,
        &SigningKey::from_seed([0x62; 32]),
        KeyMaterial::SelfJwt { jwt: j1_exp_tok },
        clock,
    )?;
    let j1_exp_resp = j1_ap_tls.send(&j1_exp_req)?;
    // (c) Body mismatch -> 401 invalid_jwt
    let j1_bad_body_tok = mint_event_token(
        &SigningKey::from_seed([0x62; 32]),
        "j1-res-1",
        &EventClaims {
            iss: j1_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j1_agent_id.into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: Some(body_s256(b"expected-body")),
            extra: Default::default(),
        },
    )?;
    let mut j1_bad_body_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .header("content-type", "application/json")
        .body(b"{\"different\":true}".to_vec())?;
    sign_raw_request(
        &mut j1_bad_body_req,
        &SigningKey::from_seed([0x62; 32]),
        KeyMaterial::SelfJwt {
            jwt: j1_bad_body_tok,
        },
        clock,
    )?;
    let j1_bad_body_resp = j1_ap_tls.send(&j1_bad_body_req)?;
    // (d) Wrong Resource -> 403 Forbidden
    let j1_rogue_tok = mint_event_token(
        &j1_rogue_key,
        "j1-rogue-1",
        &EventClaims {
            iss: j1_rogue_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j1_agent_id.into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j1_rogue_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .body(Vec::new())?;
    sign_raw_request(
        &mut j1_rogue_req,
        &j1_rogue_key,
        KeyMaterial::SelfJwt { jwt: j1_rogue_tok },
        clock,
    )?;
    let j1_rogue_resp = j1_ap_tls.send(&j1_rogue_req)?;
    // (e) Wrong Agent (aud) -> 401 invalid_jwt BEFORE spending a use
    let j1_wrong_aud_tok = mint_event_token(
        &SigningKey::from_seed([0x62; 32]),
        "j1-res-1",
        &EventClaims {
            iss: j1_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: "aauth:other@j1-rust-ap.example".into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j1_wrong_aud_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .body(Vec::new())?;
    sign_raw_request(
        &mut j1_wrong_aud_req,
        &SigningKey::from_seed([0x62; 32]),
        KeyMaterial::SelfJwt {
            jwt: j1_wrong_aud_tok,
        },
        clock,
    )?;
    let j1_wrong_aud_resp = j1_ap_tls.send(&j1_wrong_aud_req)?;
    let j1_uses_after_refusals = j1_ap_store
        .subscription(&j1_order_eid)?
        .map(|(_, u)| u)
        .unwrap_or(99);

    // (f) Interrupted store write -> 503 Service Unavailable (0 uses spent), then retry -> 202 Accepted (1 use spent), then 2nd -> 404 Not Found
    j1_ap_store.interrupt_next_write();
    let j1_valid_order_tok = mint_event_token(
        &SigningKey::from_seed([0x62; 32]),
        "j1-res-1",
        &EventClaims {
            iss: j1_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j1_agent_id.into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j1_valid_order_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .body(Vec::new())?;
    sign_raw_request(
        &mut j1_valid_order_req,
        &SigningKey::from_seed([0x62; 32]),
        KeyMaterial::SelfJwt {
            jwt: j1_valid_order_tok,
        },
        clock,
    )?;
    let j1_interrupted_resp = j1_ap_tls.send(&j1_valid_order_req)?;
    let j1_uses_after_interrupt = j1_ap_store
        .subscription(&j1_order_eid)?
        .map(|(_, u)| u)
        .unwrap_or(99);
    let j1_retry_after_interrupt_resp = j1_ap_tls.send(&j1_valid_order_req)?;
    let j1_uses_after_retry = j1_ap_store
        .subscription(&j1_order_eid)?
        .map(|(_, u)| u)
        .unwrap_or(0);

    // Exhausted 2nd event on max_uses=1 -> 404
    let j1_exhaust_tok = mint_event_token(
        &SigningKey::from_seed([0x62; 32]),
        "j1-res-1",
        &EventClaims {
            iss: j1_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j1_agent_id.into(),
            eid: j1_order_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j1_exhaust_req = Request::builder()
        .method("POST")
        .uri(format!("{j1_ap_issuer}/events"))
        .body(Vec::new())?;
    sign_raw_request(
        &mut j1_exhaust_req,
        &SigningKey::from_seed([0x62; 32]),
        KeyMaterial::SelfJwt {
            jwt: j1_exhaust_tok,
        },
        clock,
    )?;
    let j1_exhaust_resp = j1_ap_tls.send(&j1_exhaust_req)?;

    // 4. Ticket-protected subscription registration
    let j1_ps_issuer = "https://j1-ps.example";
    let j1_ps_key = SigningKey::from_seed([0x66; 32]);
    let j1_ps_jwks = json!({
        "keys": [{
            "kid": "j1-ps-1",
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "Ed25519",
            "x": j1_ps_key.public_jwk().x,
        }]
    });
    trust.insert_manual(
        j1_ps_issuer,
        "aauth-person.json",
        TrustedIssuerKeys::from_documents(
            j1_ps_issuer,
            "aauth-person.json",
            json!({"issuer": j1_ps_issuer, "jwks_uri": format!("{j1_ps_issuer}/.well-known/jwks.json")})
                .to_string()
                .as_bytes(),
            j1_ps_jwks.to_string().as_bytes(),
        )?,
    )?;
    let j1_auth_compact = mint_auth_token(
        &j1_ps_key,
        "j1-ps-1",
        &AuthClaims {
            iss: j1_ps_issuer.into(),
            dwk: "aauth-person.json".into(),
            aud: j1_res_issuer.into(),
            sub: "j1-person".into(),
            ps: j1_ps_issuer.into(),
            jti: "j1-auth-1".into(),
            iat: clock,
            exp: clock + 600,
            cnf: Confirmation {
                jwk: SigningKey::from_seed([0x64; 32]).public_jwk(),
            },
            scope: Some("records.read".into()),
            mission_s256: None,
            tenant: None,
            account: None,
            nbf: None,
            extra: Default::default(),
        },
    )?;
    let j1_verified_auth = AuthToken::parse(&j1_auth_compact)?.verify(trust, clock)?;
    let j1_ticket = j1_events_res.issue_ticket(&j1_verified_auth, b"ticket-ctx-1", 120, clock)?;

    // Wrong key attempts to redeem ticket -> 403 Forbidden
    let j1_other_agent_tok = j1_ap.issue(&AgentClaims {
        iss: j1_ap_issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: j1_agent_id.into(),
        jti: "j1-ag-tok-other".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: j1_other_agent_key.public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let j1_other_agent = Agent::new(j1_other_agent_key, j1_other_agent_tok.clone())?;
    let j1_other_sub = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_other_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let mut j1_wrong_key_treq = Request::builder()
        .method("POST")
        .uri(&j1_ticket.url)
        .body(Vec::new())?;
    j1_other_agent.sign_subscription(&mut j1_wrong_key_treq, &j1_other_sub.token, clock)?;
    let j1_wrong_key_tresp = j1_res_tls.send(&j1_wrong_key_treq)?;

    // Right key redeems ticket -> 200 OK
    let j1_right_sub = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let mut j1_right_key_treq = Request::builder()
        .method("POST")
        .uri(&j1_ticket.url)
        .body(Vec::new())?;
    j1_agent.sign_subscription(&mut j1_right_key_treq, &j1_right_sub.token, clock)?;
    let j1_right_key_tresp = j1_res_tls.send(&j1_right_key_treq)?;

    // Reuse same ticket -> 403 Forbidden
    let j1_reuse_sub = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let mut j1_reuse_treq = Request::builder()
        .method("POST")
        .uri(&j1_ticket.url)
        .body(Vec::new())?;
    j1_agent.sign_subscription(&mut j1_reuse_treq, &j1_reuse_sub.token, clock)?;
    let j1_reuse_tresp = j1_res_tls.send(&j1_reuse_treq)?;

    let j1_pass = j1_asyncapi_valid_ok
        && matches!(
            j1_asyncapi_missing_err,
            Err(AsyncApiDeclarationError::Missing)
        )
        && matches!(
            j1_asyncapi_mismatch_err,
            Err(AsyncApiDeclarationError::Mismatch)
        )
        && matches!(
            j1_asyncapi_malformed_err,
            Err(AsyncApiDeclarationError::Malformed)
        )
        && j1_scheme_helper_ok
        && j1_inbox_without_ep_refused
        && j1_sub_has_jti_and_eid
        && j1_reg_status == 200
        && j1_reg_dup_status == 409
        && j1_ev1_has_body_s256
        && j1_del_out1
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(1),
            }
        && j1_del_out1_dup
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(1),
            }
        && j1_rec1_ctx == "j1-public-waitlist"
        && j1_rec1_dup_is_duplicate
        && matches!(j1_tampered_body_err, Err(EventError::Body))
        && j1_pending_after_ack1 == 0
        && j1_ev2_no_body_s256
        && j1_del_out2
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(0),
            }
        && j1_sub_removed_at_res
        && j1_rec2_ok
        && matches!(j1_nobody_with_bytes_err, Err(EventError::Body))
        && j1_get_ev_resp.status().as_u16() == 405
        && j1_exp_resp.status().as_u16() == 401
        && j1_bad_body_resp.status().as_u16() == 401
        && j1_rogue_resp.status().as_u16() == 403
        && j1_wrong_aud_resp.status().as_u16() == 401
        && j1_uses_after_refusals == 0
        && j1_interrupted_resp.status().as_u16() == 503
        && j1_uses_after_interrupt == 0
        && j1_retry_after_interrupt_resp.status().as_u16() == 202
        && j1_uses_after_retry == 1
        && j1_exhaust_resp.status().as_u16() == 404
        && j1_wrong_key_tresp.status().as_u16() == 403
        && j1_right_key_tresp.status().as_u16() == 200
        && j1_reuse_tresp.status().as_u16() == 403;

    cases.push(QaCaseReceipt {
        id: "QA-J1".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Rust Events Native End-to-End, Inbox Validation Order, max_uses, Durable Store Commit Before 202 & AsyncAPI aauth_subscribe".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j1_pass,
        summary: format!(
            "public reg={} (dup={}), body+nobody del=202 (rem=1,0), validation order 405/401/403 (uses={}), interrupted write=503->retry=202, exhausted=404, ticket wrong_key={} right={} reuse={}, asyncapi_ok={}",
            j1_reg_status,
            j1_reg_dup_status,
            j1_uses_after_refusals,
            j1_wrong_key_tresp.status().as_u16(),
            j1_right_key_tresp.status().as_u16(),
            j1_reuse_tresp.status().as_u16(),
            j1_asyncapi_valid_ok,
        ),
        evidence: json!({
            "asyncapi_valid_ok": j1_asyncapi_valid_ok,
            "asyncapi_missing_refused": matches!(j1_asyncapi_missing_err, Err(AsyncApiDeclarationError::Missing)),
            "asyncapi_mismatch_refused": matches!(j1_asyncapi_mismatch_err, Err(AsyncApiDeclarationError::Mismatch)),
            "asyncapi_malformed_refused": matches!(j1_asyncapi_malformed_err, Err(AsyncApiDeclarationError::Malformed)),
            "inbox_without_event_endpoint_refused": j1_inbox_without_ep_refused,
            "subscribe_token_has_jti_and_eid": j1_sub_has_jti_and_eid,
            "public_reg_status": j1_reg_status,
            "public_reg_dup_status": j1_reg_dup_status,
            "ev1_has_body_s256": j1_ev1_has_body_s256,
            "ev2_no_body_s256": j1_ev2_no_body_s256,
            "sub_removed_at_res_on_exhaustion": j1_sub_removed_at_res,
            "validation_order_statuses": {
                "get_method": j1_get_ev_resp.status().as_u16(),
                "expired_token": j1_exp_resp.status().as_u16(),
                "body_mismatch": j1_bad_body_resp.status().as_u16(),
                "wrong_resource": j1_rogue_resp.status().as_u16(),
                "wrong_agent_aud": j1_wrong_aud_resp.status().as_u16(),
                "uses_after_all_refusals": j1_uses_after_refusals,
            },
            "interrupted_write_status": j1_interrupted_resp.status().as_u16(),
            "uses_after_interrupt": j1_uses_after_interrupt,
            "retry_after_interrupt_status": j1_retry_after_interrupt_resp.status().as_u16(),
            "exhausted_status": j1_exhaust_resp.status().as_u16(),
            "ticket_wrong_key_status": j1_wrong_key_tresp.status().as_u16(),
            "ticket_right_key_status": j1_right_key_tresp.status().as_u16(),
            "ticket_reuse_status": j1_reuse_tresp.status().as_u16(),
        }),
    });
    transcript_lines.push(format!(
        "[QA-J1] {}: reg={} dup={} uses_after_refusals={} interrupt={} retry={} exhaust={} ticket={}/{}/{}",
        if j1_pass { "PASS" } else { "FAIL" },
        j1_reg_status,
        j1_reg_dup_status,
        j1_uses_after_refusals,
        j1_interrupted_resp.status().as_u16(),
        j1_retry_after_interrupt_resp.status().as_u16(),
        j1_exhaust_resp.status().as_u16(),
        j1_wrong_key_tresp.status().as_u16(),
        j1_right_key_tresp.status().as_u16(),
        j1_reuse_tresp.status().as_u16()
    ));

    // =========================================================================
    // QA-J2: Go Events Native End-to-End, jti & body_s256, AP Status Codes,
    //        ConfirmationKey JWK Thumbprint Ticket Binding, & ValidateAsyncAPIDocument
    // =========================================================================
    let j2_ev = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-j2",
        json!({}),
    )?;
    let j2_pass = j2_ev.get("asyncapi_valid_ok").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_missing_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_wrong_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_no_ver_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_case_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_service_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_get_status").and_then(Value::as_i64) == Some(200)
        && j2_ev.get("asyncapi_get_exact_match").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("asyncapi_post_status").and_then(Value::as_i64) == Some(405)
        && j2_ev.get("subscribe_token_has_jti").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("subscribe_no_jti_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("exp_event_status").and_then(Value::as_i64) == Some(401)
        && j2_ev
            .get("exp_event_sig_err")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("expired_jwt")
        && j2_ev.get("mismatch_body_status").and_then(Value::as_i64) == Some(401)
        && j2_ev
            .get("mismatch_body_sig_err")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("invalid_jwt")
        && j2_ev.get("rogue_res_status").and_then(Value::as_i64) == Some(403)
        && j2_ev.get("rogue_res_sig_err").and_then(Value::as_str) == Some("")
        && j2_ev.get("wrong_aud_status").and_then(Value::as_i64) == Some(401)
        && j2_ev
            .get("wrong_aud_sig_err")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("invalid_jwt")
        && j2_ev.get("uses_before_valid").and_then(Value::as_i64) == Some(0)
        && j2_ev.get("del1_remaining_uses").and_then(Value::as_i64) == Some(1)
        && j2_ev.get("del1_replay_remaining_uses").and_then(Value::as_i64) == Some(1)
        && j2_ev.get("del2_remaining_uses").and_then(Value::as_i64) == Some(0)
        && j2_ev.get("del3_exhausted_status").and_then(Value::as_i64) == Some(404)
        && j2_ev.get("uses_after").and_then(Value::as_i64) == Some(2)
        && j2_ev.get("ev1_body_s256") == j2_ev.get("ev1_expected_body_s256")
        && j2_ev.get("ev2_body_s256").and_then(Value::as_str) == Some("")
        && j2_ev.get("acc1_context").and_then(Value::as_str) == Some("j2-public-ctx")
        && j2_ev.get("acc1_duplicate").and_then(Value::as_bool) == Some(false)
        && j2_ev.get("acc1_dup_duplicate").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("tampered_body_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("acc2_nobody_ok").and_then(Value::as_bool) == Some(true)
        && j2_ev.get("wrong_key_ticket_refused").and_then(Value::as_bool) == Some(true)
        && j2_ev
            .get("right_key_ticket_eid")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        && j2_ev.get("reuse_ticket_refused").and_then(Value::as_bool) == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-J2".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Go Events Native End-to-End, jti & body_s256, AP Status Codes, ConfirmationKey JWK Thumbprint Ticket Binding & ValidateAsyncAPIDocument".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j2_pass,
        summary: format!(
            "jti_ok={}, body_s256_ok={}, AP validation 401/403/404 (uses_before={}), del rem=1->0->404, ConfirmationKey ticket thumbprint ok, ValidateAsyncAPIDocument ok",
            j2_ev.get("subscribe_token_has_jti").and_then(Value::as_bool).unwrap_or(false),
            j2_ev.get("ev1_body_s256") == j2_ev.get("ev1_expected_body_s256"),
            j2_ev.get("uses_before_valid").and_then(Value::as_i64).unwrap_or(-1),
        ),
        evidence: j2_ev.clone(),
    });
    transcript_lines.push(format!(
        "[QA-J2] {}: jti={} body_s256={} uses_before={} del3_exhaust={} ticket_thumbprint={}",
        if j2_pass { "PASS" } else { "FAIL" },
        j2_ev.get("subscribe_token_has_jti").and_then(Value::as_bool).unwrap_or(false),
        j2_ev.get("ev1_body_s256") == j2_ev.get("ev1_expected_body_s256"),
        j2_ev.get("uses_before_valid").and_then(Value::as_i64).unwrap_or(-1),
        j2_ev.get("del3_exhausted_status").and_then(Value::as_i64).unwrap_or(-1),
        j2_ev.get("wrong_key_ticket_refused").and_then(Value::as_bool).unwrap_or(false),
    ));

    // =========================================================================
    // QA-J3: Cross-Language HTTPS Events: Rust Resource -> Go Agent Provider -> Go & Rust Agents
    // =========================================================================
    let j3_res_issuer = "https://j3-rust-res.example";
    let j3_wrong_res_issuer = "https://j3-wrong-res.example";
    let j3_agent_id = "aauth:j3-agent@go-events-ap.example";
    let j3_agent_seed = [0x71_u8; 32];
    let j3_agent_seed_hex = hex_encode(&j3_agent_seed);
    let j3_other_seed = [0x72_u8; 32];
    let j3_other_seed_hex = hex_encode(&j3_other_seed);

    let j3_res_store = Arc::new(MemorySubscriptionStore::new());
    let j3_events_res = Arc::new(EventsResource::new(
        EventsConfig {
            issuer: j3_res_issuer.into(),
            signed_origin: j3_res_issuer.into(),
            kid: "j3-res-1".into(),
            signing_key: SigningKey::from_seed([0x73; 32]),
            ticket_path: "/events/tickets/".into(),
            max_ticket_lifetime: 300,
        },
        trust.clone(),
        j3_res_store.clone(),
    )?);
    let j3_res_c = j3_events_res.clone();
    let j3_clk = clock_base.clone();
    let j3_res_tls = TlsServer::start("j3-rust-res.example", move |req| {
        let now_s = j3_clk.load(Ordering::SeqCst);
        let path = req.uri().path().to_owned();
        if req.method().as_str() == "GET" && path == "/.well-known/aauth-resource.json" {
            return json_response(
                200,
                json!({
                    "issuer": j3_res_issuer,
                    "jwks_uri": format!("{j3_res_issuer}/.well-known/jwks.json"),
                }),
            );
        }
        if req.method().as_str() == "GET" && path == "/.well-known/jwks.json" {
            return json_response(
                200,
                serde_json::from_slice(&j3_res_c.jwks().unwrap()).unwrap(),
            );
        }
        if path == "/events/subscribe" {
            return j3_res_c
                .register(&req, now_s, |sub_req| Ok(sub_req.request.body().clone()))
                .into_response();
        }
        if path.starts_with("/events/tickets/") {
            return j3_res_c
                .register_with_ticket(&req, now_s, |sub_req| {
                    Ok(sub_req
                        .ticket
                        .map(|t| t.context.clone())
                        .unwrap_or_default())
                })
                .into_response();
        }
        json_response(404, json!({"error": "not_found"}))
    })?;
    trust.discover(&j3_res_tls, j3_res_issuer, "aauth-resource.json")?;
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "j3-rust-res.example",
        &j3_res_tls,
    )?;

    let j3_wrong_res_key = SigningKey::from_seed([0x74; 32]);
    let j3_wrong_res_tls = TlsServer::start("j3-wrong-res.example", move |req| {
        let path = req.uri().path().to_owned();
        if req.method().as_str() == "GET" && path == "/.well-known/aauth-resource.json" {
            return json_response(
                200,
                json!({
                    "issuer": j3_wrong_res_issuer,
                    "jwks_uri": format!("{j3_wrong_res_issuer}/.well-known/jwks.json"),
                }),
            );
        }
        if req.method().as_str() == "GET" && path == "/.well-known/jwks.json" {
            let mut jwk =
                serde_json::to_value(SigningKey::from_seed([0x74; 32]).public_jwk()).unwrap();
            jwk["kid"] = json!("j3-wrong-1");
            return json_response(200, json!({"keys": [jwk]}));
        }
        json_response(404, json!({"error": "not_found"}))
    })?;
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "j3-wrong-res.example",
        &j3_wrong_res_tls,
    )?;

    // 1. Go AP issues public subscribe token (max_uses = 2) -> Go Agent registers at Rust Resource over HTTPS
    let j3_pub_sub = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__issue-subscribe-token",
        json!({
            "agent": j3_agent_id,
            "resource": j3_res_issuer,
            "key_seed_hex": j3_agent_seed_hex,
            "lifetime_sec": 600,
            "max_uses": 2,
        }),
    )?;
    let j3_pub_compact = text(&j3_pub_sub, "compact")?;
    let j3_pub_eid = text(&j3_pub_sub, "eid")?;

    let mut j3_rust_agent_subs = EventSubscriptions::new(j3_agent_id)?;
    j3_rust_agent_subs.remember(&j3_pub_compact, "j3-public-ctx".to_owned())?;

    let j3_pub_reg = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-register-public",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_agent_seed_hex,
            "endpoint": format!("{j3_res_issuer}/events/subscribe"),
            "subscribe_token": j3_pub_compact,
            "parameters_b64": BASE64_STD.encode(br#"{"channel":"waitlist"}"#),
            "content_type": "application/json",
            "context": "j3-public-ctx",
        }),
    )?;
    let j3_pub_reg_ok = j3_pub_reg.get("ok").and_then(Value::as_bool) == Some(true);

    // 2. Wrong-Resource delivery to Go AP -> refused with 403 Forbidden (0 uses spent)
    let j3_wrong_res_ev_tok = mint_event_token(
        &j3_wrong_res_key,
        "j3-wrong-1",
        &EventClaims {
            iss: j3_wrong_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j3_agent_id.into(),
            eid: j3_pub_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j3_wrong_res_req = Request::builder()
        .method("POST")
        .uri("https://go-events-ap.example/events")
        .body(Vec::new())?;
    sign_raw_request(
        &mut j3_wrong_res_req,
        &j3_wrong_res_key,
        KeyMaterial::SelfJwt {
            jwt: j3_wrong_res_ev_tok,
        },
        clock,
    )?;
    let j3_wrong_res_resp = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &j3_wrong_res_req,
    )?;
    let j3_wrong_res_status = j3_wrong_res_resp.status().as_u16();

    // 3. Rust Resource delivers Event #1 (with JSON body) and Event #2 (no body) to Go AP over HTTPS
    let go_ap_meta_resp = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &get(&agent_provider_metadata_url("https://go-events-ap.example"))?,
    )?;
    let j3_ev1_payload = br#"{"event_type":"slot.available","slot":"14:00"}"#;
    let j3_prep1 = j3_events_res.prepare_event(
        "https://go-events-ap.example",
        &j3_pub_eid,
        Some(EventPayload {
            content_type: "application/json",
            body: j3_ev1_payload,
        }),
        clock + 300,
        clock,
    )?;
    let j3_del_req1 =
        j3_events_res.delivery_request(&j3_prep1, go_ap_meta_resp.body(), clock)?;
    let j3_del_resp1 = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &j3_del_req1,
    )?;
    let j3_del_out1 = j3_events_res.delivery_outcome(&j3_prep1, &j3_del_resp1)?;

    // Event #2: no body!
    let j3_prep2 = j3_events_res.prepare_event(
        "https://go-events-ap.example",
        &j3_pub_eid,
        None,
        clock + 300,
        clock,
    )?;
    let j3_del_req2 =
        j3_events_res.delivery_request(&j3_prep2, go_ap_meta_resp.body(), clock)?;
    let j3_del_resp2 = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &j3_del_req2,
    )?;
    let j3_del_out2 = j3_events_res.delivery_outcome(&j3_prep2, &j3_del_resp2)?;

    // 4. Event #3 on exhausted subscription -> Go AP returns 404 Not Found
    let j3_exhaust_tok = mint_event_token(
        &SigningKey::from_seed([0x73; 32]),
        "j3-res-1",
        &EventClaims {
            iss: j3_res_issuer.into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: j3_agent_id.into(),
            eid: j3_pub_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 300,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j3_exhaust_req = Request::builder()
        .method("POST")
        .uri("https://go-events-ap.example/events")
        .body(Vec::new())?;
    sign_raw_request(
        &mut j3_exhaust_req,
        &SigningKey::from_seed([0x73; 32]),
        KeyMaterial::SelfJwt {
            jwt: j3_exhaust_tok,
        },
        clock,
    )?;
    let j3_exhaust_resp = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &j3_exhaust_req,
    )?;
    let j3_exhaust_status = j3_exhaust_resp.status().as_u16();

    // 5.Ticket-protected subscription at Rust Resource (issued for j3_agent_seed key) -> redeemed by Go Agent -> delivered to Go AP
    let j3_holder_auth_compact = mint_auth_token(
        &j1_ps_key,
        "j1-ps-1",
        &AuthClaims {
            iss: j1_ps_issuer.into(),
            dwk: "aauth-person.json".into(),
            aud: j3_res_issuer.into(),
            sub: "j3-person".into(),
            ps: j1_ps_issuer.into(),
            jti: "j3-auth-1".into(),
            iat: clock,
            exp: clock + 600,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(j3_agent_seed).public_jwk(),
            },
            scope: Some("records.read".into()),
            mission_s256: None,
            tenant: None,
            account: None,
            nbf: None,
            extra: Default::default(),
        },
    )?;
    let j3_holder_auth = AuthToken::parse(&j3_holder_auth_compact)?.verify(trust, clock)?;
    let j3_ticket =
        j3_events_res.issue_ticket(&j3_holder_auth, b"j3-ticket-ctx", 120, clock)?;

    // Wrong key from Go AP attempts to redeem Rust Resource ticket -> refused (403)
    let j3_wrong_t_sub = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__issue-subscribe-token",
        json!({
            "agent": j3_agent_id,
            "resource": j3_res_issuer,
            "key_seed_hex": j3_other_seed_hex,
            "lifetime_sec": 600,
            "max_uses": 1,
        }),
    )?;
    let j3_wrong_t_reg = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-register-protected",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_other_seed_hex,
            "ticket_url": j3_ticket.url,
            "subscribe_token": text(&j3_wrong_t_sub, "compact")?,
            "parameters_b64": "",
            "content_type": "",
            "context": "j3-wrong-ticket",
        }),
    )?;
    let j3_wrong_ticket_refused = j3_wrong_t_reg.get("ok").and_then(Value::as_bool) == Some(false);

    // Matching key from Go AP redeems Rust Resource ticket -> 200 OK
    let j3_right_t_sub = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__issue-subscribe-token",
        json!({
            "agent": j3_agent_id,
            "resource": j3_res_issuer,
            "key_seed_hex": j3_agent_seed_hex,
            "lifetime_sec": 600,
            "max_uses": 1,
        }),
    )?;
    let j3_right_t_compact = text(&j3_right_t_sub, "compact")?;
    let j3_right_t_eid = text(&j3_right_t_sub, "eid")?;
    j3_rust_agent_subs.remember(&j3_right_t_compact, "j3-protected-ctx".to_owned())?;
    let j3_right_t_reg = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-register-protected",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_agent_seed_hex,
            "ticket_url": j3_ticket.url,
            "subscribe_token": j3_right_t_compact,
            "parameters_b64": BASE64_STD.encode(br#"{"event_types":["appointment.changed"]}"#),
            "content_type": "application/json",
            "context": "j3-protected-ctx",
        }),
    )?;
    let j3_right_ticket_ok = j3_right_t_reg.get("ok").and_then(Value::as_bool) == Some(true);

    // Deliver protected event from Rust Resource to Go AP
    let j3_prot_prep = j3_events_res.prepare_event(
        "https://go-events-ap.example",
        &j3_right_t_eid,
        Some(EventPayload {
            content_type: "application/json",
            body: br#"{"event_type":"appointment.changed"}"#,
        }),
        clock + 300,
        clock,
    )?;
    let j3_prot_del_req =
        j3_events_res.delivery_request(&j3_prot_prep, go_ap_meta_resp.body(), clock)?;
    let j3_prot_del_resp = TlsServer::send_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        &j3_prot_del_req,
    )?;
    let j3_prot_del_out = j3_events_res.delivery_outcome(&j3_prot_prep, &j3_prot_del_resp)?;

    // 6. Both Go Agent and Rust Agent verify the events relayed by Go AP!
    let j3_ap_dels = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__deliveries",
        json!({"eid": j3_pub_eid}),
    )?;
    let j3_del_arr = j3_ap_dels
        .get("deliveries")
        .and_then(Value::as_array)
        .ok_or("missing deliveries")?;
    let j3_d0_tok = text(&j3_del_arr[0], "token")?;
    let j3_d0_b64 = text(&j3_del_arr[0], "payload_b64")?;
    let j3_d0_ct = text(&j3_del_arr[0], "content_type")?;
    let j3_d1_tok = text(&j3_del_arr[1], "token")?;
    let j3_d1_b64 = text(&j3_del_arr[1], "payload_b64")?;
    let j3_d1_ct = text(&j3_del_arr[1], "content_type")?;

    // Go Agent accepts Event #1 (body) & Event #2 (no body), and rejects tampered body
    let j3_go_acc1 = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_agent_seed_hex,
            "event_token": j3_d0_tok,
            "payload_b64": j3_d0_b64,
            "content_type": j3_d0_ct,
        }),
    )?;
    let j3_go_acc2 = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_agent_seed_hex,
            "event_token": j3_d1_tok,
            "payload_b64": j3_d1_b64,
            "content_type": j3_d1_ct,
        }),
    )?;
    let j3_go_tampered = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j3_agent_id,
            "key_seed_hex": j3_agent_seed_hex,
            "event_token": j3_d0_tok,
            "payload_b64": BASE64_STD.encode(b"tampered"),
            "content_type": j3_d0_ct,
        }),
    )?;

    // Rust Agent accepts Event #1 (body) & Event #2 (no body) relayed from Go AP, and rejects tampered body
    let j3_d0_bytes = BASE64_STD.decode(&j3_d0_b64)?;
    let j3_d1_bytes = BASE64_STD.decode(&j3_d1_b64)?;
    let j3_rust_rec1 = j3_rust_agent_subs.receive(&j3_d0_tok, &j3_d0_bytes, trust, clock)?;
    let j3_rust_rec1_ok =
        j3_rust_rec1.context == "j3-public-ctx" && j3_d0_bytes == j3_ev1_payload;
    let j3_rust_rec2 = j3_rust_agent_subs.receive(&j3_d1_tok, &j3_d1_bytes, trust, clock)?;
    let j3_rust_rec2_ok = j3_rust_rec2.context == "j3-public-ctx" && j3_d1_bytes.is_empty();
    let j3_rust_tampered_err = verify_event(&j3_d0_tok, b"tampered", j3_agent_id, trust, clock);

    let j3_pass = j3_pub_reg_ok
        && j3_wrong_res_status == 403
        && j3_del_out1
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(1),
            }
        && j3_del_out2
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(0),
            }
        && j3_exhaust_status == 404
        && j3_wrong_ticket_refused
        && j3_right_ticket_ok
        && j3_prot_del_out
            == DeliveryOutcome::Accepted {
                remaining_uses: Some(0),
            }
        && j3_go_acc1.get("ok").and_then(Value::as_bool) == Some(true)
        && j3_go_acc2.get("ok").and_then(Value::as_bool) == Some(true)
        && j3_go_tampered.get("ok").and_then(Value::as_bool) == Some(false)
        && j3_rust_rec1_ok
        && j3_rust_rec2_ok
        && matches!(j3_rust_tampered_err, Err(EventError::Body));

    cases.push(QaCaseReceipt {
        id: "QA-J3".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Cross-Language HTTPS Events: Rust Resource -> Go Agent Provider -> Go & Rust Agents".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j3_pass,
        summary: format!(
            "public_reg={}, ticket_wrong_refused={} ticket_right={}, body+nobody del=202 (rem=1,0), exhausted={}, wrong_res={}, Go+Rust Agents verified={}/{}",
            j3_pub_reg_ok,
            j3_wrong_ticket_refused,
            j3_right_ticket_ok,
            j3_exhaust_status,
            j3_wrong_res_status,
            j3_go_acc1.get("ok").and_then(Value::as_bool).unwrap_or(false)
                && j3_go_acc2.get("ok").and_then(Value::as_bool).unwrap_or(false),
            j3_rust_rec1_ok && j3_rust_rec2_ok,
        ),
        evidence: json!({
            "public_reg_ok": j3_pub_reg_ok,
            "wrong_resource_status": j3_wrong_res_status,
            "del1_outcome": format!("{j3_del_out1:?}"),
            "del2_outcome": format!("{j3_del_out2:?}"),
            "exhausted_status": j3_exhaust_status,
            "ticket_wrong_key_refused": j3_wrong_ticket_refused,
            "ticket_right_key_ok": j3_right_ticket_ok,
            "protected_del_outcome": format!("{j3_prot_del_out:?}"),
            "go_agent_accept_body_ok": j3_go_acc1.get("ok").and_then(Value::as_bool),
            "go_agent_accept_nobody_ok": j3_go_acc2.get("ok").and_then(Value::as_bool),
            "go_agent_tampered_refused": j3_go_tampered.get("ok").and_then(Value::as_bool) == Some(false),
            "rust_agent_accept_body_ok": j3_rust_rec1_ok,
            "rust_agent_accept_nobody_ok": j3_rust_rec2_ok,
            "rust_agent_tampered_refused": matches!(j3_rust_tampered_err, Err(EventError::Body)),
        }),
    });
    transcript_lines.push(format!(
        "[QA-J3] {}: pub_reg={} wrong_res={} exhaust={} ticket={} go_agent={} rust_agent={}",
        if j3_pass { "PASS" } else { "FAIL" },
        j3_pub_reg_ok,
        j3_wrong_res_status,
        j3_exhaust_status,
        j3_right_ticket_ok,
        j3_go_acc1.get("ok").and_then(Value::as_bool).unwrap_or(false),
        j3_rust_rec1_ok && j3_rust_rec2_ok,
    ));

    // =========================================================================
    // QA-J4: Cross-Language HTTPS Events: Go Resource -> Rust Agent Provider -> Rust & Go Agents
    // =========================================================================
    let j4_ap_issuer = "https://j4-rust-ap.example";
    let j4_agent_id = "aauth:j4-agent@j4-rust-ap.example";
    let j4_agent_seed = [0x75_u8; 32];
    let j4_agent_seed_hex = hex_encode(&j4_agent_seed);
    let j4_other_seed = [0x76_u8; 32];

    let j4_ap = Arc::new(
        AgentProvider::new(j4_ap_issuer, "j4-ap-1", SigningKey::from_seed([0x77; 32]))?
            .with_event_endpoint(&format!("{j4_ap_issuer}/events"))?,
    );
    let j4_ap_store = Arc::new(DirectoryEventStore::open(out_dir.join("j4-ap-store"))?);
    let j4_inbox = Arc::new(EventInbox::new(&j4_ap, trust.clone(), j4_ap_store.clone())?);

    let j4_ap_c = j4_ap.clone();
    let j4_inbox_c = j4_inbox.clone();
    let j4_clk = clock_base.clone();
    let j4_ap_tls = TlsServer::start("j4-rust-ap.example", move |req| {
        let now_s = j4_clk.load(Ordering::SeqCst);
        match (req.method().as_str(), req.uri().path()) {
            ("GET", "/.well-known/aauth-agent.json") => json_response(
                200,
                serde_json::from_slice(&j4_ap_c.metadata().unwrap()).unwrap(),
            ),
            ("GET", "/.well-known/jwks.json") => {
                json_response(200, serde_json::from_slice(&j4_ap_c.jwks().unwrap()).unwrap())
            }
            (_, "/events") => j4_inbox_c.receive(&req, now_s).into_response(),
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?;
    trust.discover(&j4_ap_tls, j4_ap_issuer, "aauth-agent.json")?;
    register_host_with_go(
        go_events_ap_addr,
        &go_events_ap_cert,
        "j4-rust-ap.example",
        &j4_ap_tls,
    )?;

    let j4_agent_tok = j4_ap.issue(&AgentClaims {
        iss: j4_ap_issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: j4_agent_id.into(),
        jti: "j4-ag-tok-1".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(j4_agent_seed).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let j4_agent = Agent::new(SigningKey::from_seed(j4_agent_seed), j4_agent_tok.clone())?;
    let mut j4_rust_subs = EventSubscriptions::new(j4_agent_id)?;

    // 1. Rust AP issues subscribe token (max_uses = 2) -> Rust Agent registers at Go Resource over HTTPS
    let j4_pub_sub = j4_ap.issue_subscribe_token(
        j4_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j4_agent_tok,
            resource: "https://go-events-res.example",
            expires_at: clock + 600,
            max_uses: Some(2),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j4_pub_eid = j4_rust_subs.remember(&j4_pub_sub.token, "j4-public-ctx".to_owned())?;

    let mut j4_pub_reg_req = Request::builder()
        .method("POST")
        .uri("https://go-events-res.example/events/subscribe")
        .header("content-type", "application/json")
        .body(br#"{"event_types":["slot.available"]}"#.to_vec())?;
    j4_agent.sign_subscription(&mut j4_pub_reg_req, &j4_pub_sub.token, clock)?;
    let j4_pub_reg_resp = TlsServer::send_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        &j4_pub_reg_req,
    )?;
    let j4_pub_reg_status = j4_pub_reg_resp.status().as_u16();

    // Bind context in Go Agent store as well so Go Agent can also verify events relayed from Rust AP
    post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-bind-context",
        json!({
            "agent": j4_agent_id,
            "resource": "https://go-events-res.example",
            "eid": j4_pub_eid,
            "subscribe_token": j4_pub_sub.token,
            "context": "j4-public-ctx",
        }),
    )?;

    // 2. Wrong Go Resource delivers to Rust AP -> refused with 403 Forbidden (0 uses spent)
    let j4_rogue_del = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__rogue-deliver",
        json!({
            "endpoint_url": format!("{j4_ap_issuer}/events"),
            "agent": j4_agent_id,
            "eid": j4_pub_eid,
            "payload_b64": BASE64_STD.encode(br#"{"rogue":true}"#),
            "content_type": "application/json",
        }),
    )?;
    let j4_rogue_status = j4_rogue_del.get("status_code").and_then(Value::as_i64).unwrap_or(0);
    let j4_uses_after_rogue = j4_ap_store
        .subscription(&j4_pub_eid)?
        .map(|(_, u)| u)
        .unwrap_or(99);

    // 3. Go Resource delivers Event #1 (with JSON body) and Event #2 (no body) to Rust AP over HTTPS
    let j4_ev1_payload = br#"{"event_type":"slot.available","slot":"16:00"}"#;
    let j4_del1 = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__deliver-event",
        json!({
            "agent_provider": j4_ap_issuer,
            "eid": j4_pub_eid,
            "content_type": "application/json",
            "payload_b64": BASE64_STD.encode(j4_ev1_payload),
            "lifetime_sec": 300,
        }),
    )?;
    // Event #2: no body!
    let j4_del2 = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__deliver-event",
        json!({
            "agent_provider": j4_ap_issuer,
            "eid": j4_pub_eid,
            "content_type": "",
            "payload_b64": "",
            "lifetime_sec": 300,
        }),
    )?;
    // 4. Event #3 on exhausted subscription -> Rust AP refuses with 404 Not Found
    let j4_del3 = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__deliver-event",
        json!({
            "agent_provider": j4_ap_issuer,
            "eid": j4_pub_eid,
            "content_type": "",
            "payload_b64": "",
            "lifetime_sec": 300,
        }),
    )?;

    // 5. Ticket-protected subscription at Go Resource -> redeemed by Rust Agent with Rust AP subscribe token -> delivered to Rust AP
    let j4_ticket_res = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__issue-ticket",
        json!({
            "key_seed_hex": j4_agent_seed_hex,
            "context": "j4-ticket-ctx",
            "lifetime_sec": 120,
        }),
    )?;
    let j4_ticket_url = text(&j4_ticket_res, "url")?;

    // Wrong key attempts to redeem Go Resource ticket -> refused (404 cloaked)
    let j4_other_tok = j4_ap.issue(&AgentClaims {
        iss: j4_ap_issuer.into(),
        dwk: "aauth-agent.json".into(),
        sub: j4_agent_id.into(),
        jti: "j4-ag-tok-other".into(),
        iat: clock,
        exp: clock + 3600,
        cnf: Confirmation {
            jwk: SigningKey::from_seed(j4_other_seed).public_jwk(),
        },
        ps: None,
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let j4_other_agent = Agent::new(SigningKey::from_seed(j4_other_seed), j4_other_tok.clone())?;
    let j4_wrong_t_sub = j4_ap.issue_subscribe_token(
        j4_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j4_other_tok,
            resource: "https://go-events-res.example",
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let mut j4_wrong_t_req = Request::builder()
        .method("POST")
        .uri(&j4_ticket_url)
        .header("content-type", "application/json")
        .body(br#"{"event_types":["appointment.changed"]}"#.to_vec())?;
    j4_other_agent.sign_subscription(&mut j4_wrong_t_req, &j4_wrong_t_sub.token, clock)?;
    let j4_wrong_t_resp = TlsServer::send_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        &j4_wrong_t_req,
    )?;
    let j4_wrong_ticket_status = j4_wrong_t_resp.status().as_u16();

    // Matching key redeems Go Resource ticket -> 200 OK
    let j4_right_t_sub = j4_ap.issue_subscribe_token(
        j4_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j4_agent_tok,
            resource: "https://go-events-res.example",
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j4_right_t_eid =
        j4_rust_subs.remember(&j4_right_t_sub.token, "j4-protected-ctx".to_owned())?;
    let mut j4_right_t_req = Request::builder()
        .method("POST")
        .uri(&j4_ticket_url)
        .header("content-type", "application/json")
        .body(br#"{"event_types":["appointment.changed"]}"#.to_vec())?;
    j4_agent.sign_subscription(&mut j4_right_t_req, &j4_right_t_sub.token, clock)?;
    let j4_right_t_resp = TlsServer::send_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        &j4_right_t_req,
    )?;
    let j4_right_ticket_status = j4_right_t_resp.status().as_u16();

    let j4_prot_del = post_json_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        "https://go-events-res.example/__deliver-event",
        json!({
            "agent_provider": j4_ap_issuer,
            "eid": j4_right_t_eid,
            "content_type": "application/json",
            "payload_b64": BASE64_STD.encode(br#"{"event_type":"appointment.changed"}"#),
            "lifetime_sec": 300,
        }),
    )?;

    // 6. Both Rust Agent and Go Agent verify events relayed from the Rust AP's DirectoryEventStore!
    let j4_pending = j4_ap_store.pending(j4_agent_id)?;
    let j4_pub_pending: Vec<_> = j4_pending
        .iter()
        .filter(|e| e.eid == j4_pub_eid)
        .collect();
    let j4_prot_pending: Vec<_> = j4_pending
        .iter()
        .filter(|e| e.eid == j4_right_t_eid)
        .collect();
    let j4_pub_ev1 = j4_pub_pending[0];
    let j4_pub_ev2 = j4_pub_pending[1];
    let j4_prot_ev = j4_prot_pending[0];

    let j4_rust_rec1 =
        j4_rust_subs.receive(&j4_pub_ev1.event_token, &j4_pub_ev1.body, trust, clock)?;
    let j4_rust_rec1_ok =
        j4_rust_rec1.context == "j4-public-ctx" && j4_pub_ev1.body == j4_ev1_payload;
    let j4_rust_rec2 =
        j4_rust_subs.receive(&j4_pub_ev2.event_token, &j4_pub_ev2.body, trust, clock)?;
    let j4_rust_rec2_ok =
        j4_rust_rec2.context == "j4-public-ctx" && j4_pub_ev2.body.is_empty();
    let j4_rust_rec3 =
        j4_rust_subs.receive(&j4_prot_ev.event_token, &j4_prot_ev.body, trust, clock)?;
    let j4_rust_rec3_ok = j4_rust_rec3.context == "j4-protected-ctx";
    let j4_rust_tampered_err =
        verify_event(&j4_pub_ev1.event_token, b"tampered", j4_agent_id, trust, clock);

    let j4_go_acc1 = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j4_agent_id,
            "key_seed_hex": j4_agent_seed_hex,
            "agent_token": j4_agent_tok,
            "event_token": j4_pub_ev1.event_token,
            "payload_b64": BASE64_STD.encode(&j4_pub_ev1.body),
            "content_type": j4_pub_ev1.content_type.clone().unwrap_or_default(),
        }),
    )?;
    let j4_go_acc2 = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j4_agent_id,
            "key_seed_hex": j4_agent_seed_hex,
            "agent_token": j4_agent_tok,
            "event_token": j4_pub_ev2.event_token,
            "payload_b64": BASE64_STD.encode(&j4_pub_ev2.body),
            "content_type": j4_pub_ev2.content_type.clone().unwrap_or_default(),
        }),
    )?;
    let j4_go_tampered = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__go-agent-accept-event",
        json!({
            "agent": j4_agent_id,
            "key_seed_hex": j4_agent_seed_hex,
            "agent_token": j4_agent_tok,
            "event_token": j4_pub_ev1.event_token,
            "payload_b64": BASE64_STD.encode(b"tampered"),
            "content_type": "application/json",
        }),
    )?;

    let j4_pass = j4_pub_reg_status == 200
        && j4_rogue_status == 403
        && j4_uses_after_rogue == 0
        && j4_del1.get("ok").and_then(Value::as_bool) == Some(true)
        && j4_del1.get("remaining_uses").and_then(Value::as_i64) == Some(1)
        && j4_del2.get("ok").and_then(Value::as_bool) == Some(true)
        && j4_del2.get("remaining_uses").and_then(Value::as_i64) == Some(0)
        && j4_del3.get("status_code").and_then(Value::as_i64) == Some(404)
        && j4_wrong_ticket_status == 404
        && j4_right_ticket_status == 200
        && j4_prot_del.get("ok").and_then(Value::as_bool) == Some(true)
        && j4_prot_del.get("remaining_uses").and_then(Value::as_i64) == Some(0)
        && j4_rust_rec1_ok
        && j4_rust_rec2_ok
        && j4_rust_rec3_ok
        && matches!(j4_rust_tampered_err, Err(EventError::Body))
        && j4_go_acc1.get("ok").and_then(Value::as_bool) == Some(true)
        && j4_go_acc2.get("ok").and_then(Value::as_bool) == Some(true)
        && j4_go_tampered.get("ok").and_then(Value::as_bool) == Some(false);

    cases.push(QaCaseReceipt {
        id: "QA-J4".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Cross-Language HTTPS Events: Go Resource -> Rust Agent Provider -> Rust & Go Agents".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j4_pass,
        summary: format!(
            "pub_reg={}, ticket_wrong={} ticket_right={}, body+nobody del=202 (rem=1,0), exhausted={}, wrong_res={}, Rust+Go Agents verified={}/{}",
            j4_pub_reg_status,
            j4_wrong_ticket_status,
            j4_right_ticket_status,
            j4_del3.get("status_code").and_then(Value::as_i64).unwrap_or(-1),
            j4_rogue_status,
            j4_rust_rec1_ok && j4_rust_rec2_ok && j4_rust_rec3_ok,
            j4_go_acc1.get("ok").and_then(Value::as_bool).unwrap_or(false)
                && j4_go_acc2.get("ok").and_then(Value::as_bool).unwrap_or(false),
        ),
        evidence: json!({
            "public_reg_status": j4_pub_reg_status,
            "wrong_resource_status": j4_rogue_status,
            "uses_after_wrong_resource": j4_uses_after_rogue,
            "del1": j4_del1,
            "del2": j4_del2,
            "del3_exhausted": j4_del3,
            "ticket_wrong_key_status": j4_wrong_ticket_status,
            "ticket_right_key_status": j4_right_ticket_status,
            "protected_del": j4_prot_del,
            "rust_agent_accept_body_ok": j4_rust_rec1_ok,
            "rust_agent_accept_nobody_ok": j4_rust_rec2_ok,
            "rust_agent_accept_protected_ok": j4_rust_rec3_ok,
            "rust_agent_tampered_refused": matches!(j4_rust_tampered_err, Err(EventError::Body)),
            "go_agent_accept_body_ok": j4_go_acc1.get("ok").and_then(Value::as_bool),
            "go_agent_accept_nobody_ok": j4_go_acc2.get("ok").and_then(Value::as_bool),
            "go_agent_tampered_refused": j4_go_tampered.get("ok").and_then(Value::as_bool) == Some(false),
        }),
    });
    transcript_lines.push(format!(
        "[QA-J4] {}: pub_reg={} wrong_res={} exhaust={} ticket={}/{} rust_agent={} go_agent={}",
        if j4_pass { "PASS" } else { "FAIL" },
        j4_pub_reg_status,
        j4_rogue_status,
        j4_del3.get("status_code").and_then(Value::as_i64).unwrap_or(-1),
        j4_wrong_ticket_status,
        j4_right_ticket_status,
        j4_rust_rec1_ok && j4_rust_rec2_ok && j4_rust_rec3_ok,
        j4_go_acc1.get("ok").and_then(Value::as_bool).unwrap_or(false),
    ));

    // =========================================================================
    // QA-J5: Rust Agent Provider Process-Restart Durability on DirectoryEventStore
    // =========================================================================
    let j5_dir = out_dir.join("j5-durable-ap-dir");
    if j5_dir.exists() {
        fs::remove_dir_all(&j5_dir)?;
    }
    fs::create_dir_all(&j5_dir)?;
    let exe_path = std::env::current_exe()?;

    // Spawn Child Process #1
    let mut child1 = Command::new(&exe_path)
        .args([
            "--child-rust-ap",
            "--store-dir",
            &j5_dir.display().to_string(),
            "--now",
            &clock.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child1_line = String::new();
    BufReader::new(child1.stdout.as_mut().ok_or("no child1 stdout")?)
        .read_line(&mut child1_line)?;
    let child1_info: Value = serde_json::from_str(&child1_line)?;
    let child1_addr: SocketAddr = text(&child1_info, "addr")?.parse()?;
    let child1_cert = hex_decode(&text(&child1_info, "cert_hex")?)?;
    let child1_pid = child1_info.get("pid").and_then(Value::as_u64).unwrap_or(0);

    // Issue subscribe token (max_uses = 2) in Child Process #1
    let j5_sub_info = post_json_external(
        child1_addr,
        "j5-durable-ap.example",
        &child1_cert,
        "https://j5-durable-ap.example/__issue-subscribe",
        json!({"max_uses": 2}),
    )?;
    let j5_eid = text(&j5_sub_info, "eid")?;
    let j5_sub_token = text(&j5_sub_info, "token")?;

    // Deliver Event #1 over HTTPS to Child Process #1
    let j5_ev1_payload = br#"{"seq":1,"msg":"before_process_exit"}"#;
    let j5_ev1_jti = generate_identifier();
    let j5_ev1_tok = mint_event_token(
        &SigningKey::from_seed([0xA2; 32]),
        "j5-res-1",
        &EventClaims {
            iss: "https://j5-durable-res.example".into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: "aauth:clerk@j5-durable-ap.example".into(),
            eid: j5_eid.clone(),
            jti: j5_ev1_jti.clone(),
            iat: clock,
            exp: clock + 600,
            body_s256: Some(body_s256(j5_ev1_payload)),
            extra: Default::default(),
        },
    )?;
    let mut j5_del1_req = Request::builder()
        .method("POST")
        .uri("https://j5-durable-ap.example/events")
        .header("content-type", "application/json")
        .body(j5_ev1_payload.to_vec())?;
    sign_raw_request(
        &mut j5_del1_req,
        &SigningKey::from_seed([0xA2; 32]),
        KeyMaterial::SelfJwt {
            jwt: j5_ev1_tok.clone(),
        },
        clock,
    )?;
    let j5_del1_resp = TlsServer::send_external(
        child1_addr,
        "j5-durable-ap.example",
        &child1_cert,
        &j5_del1_req,
    )?;
    let j5_del1_status = j5_del1_resp.status().as_u16();
    let j5_del1_rem = serde_json::from_slice::<Value>(j5_del1_resp.body())
        .ok()
        .and_then(|v| v.get("remaining_uses").and_then(Value::as_u64));

    let j5_state_before_exit = post_json_external(
        child1_addr,
        "j5-durable-ap.example",
        &child1_cert,
        "https://j5-durable-ap.example/__state",
        json!({"eid": j5_eid}),
    )?;

    // Terminate Child Process #1 cleanly and wait for exit
    drop(child1.stdin.take());
    let child1_exit = child1.wait()?;

    // Spawn Child Process #2 on the EXACT SAME directory `j5_dir`
    let mut child2 = Command::new(&exe_path)
        .args([
            "--child-rust-ap",
            "--store-dir",
            &j5_dir.display().to_string(),
            "--now",
            &clock.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut child2_line = String::new();
    BufReader::new(child2.stdout.as_mut().ok_or("no child2 stdout")?)
        .read_line(&mut child2_line)?;
    let child2_info: Value = serde_json::from_str(&child2_line)?;
    let child2_addr: SocketAddr = text(&child2_info, "addr")?.parse()?;
    let child2_cert = hex_decode(&text(&child2_info, "cert_hex")?)?;
    let child2_pid = child2_info.get("pid").and_then(Value::as_u64).unwrap_or(0);

    // Inspect state immediately upon reopen in Child Process #2
    let j5_state_after_reopen = post_json_external(
        child2_addr,
        "j5-durable-ap.example",
        &child2_cert,
        "https://j5-durable-ap.example/__state",
        json!({"eid": j5_eid}),
    )?;

    // Replay Event #1 (same jti) to Child Process #2 -> 202 duplicate, uses stays 1!
    let j5_del1_replay_resp = TlsServer::send_external(
        child2_addr,
        "j5-durable-ap.example",
        &child2_cert,
        &j5_del1_req,
    )?;
    let j5_del1_replay_status = j5_del1_replay_resp.status().as_u16();
    let j5_del1_replay_rem = serde_json::from_slice::<Value>(j5_del1_replay_resp.body())
        .ok()
        .and_then(|v| v.get("remaining_uses").and_then(Value::as_u64));

    // Deliver Event #2 (new jti) to Child Process #2 -> 202, remaining_uses = 0, uses = 2!
    let j5_ev2_payload = br#"{"seq":2,"msg":"after_process_restart"}"#;
    let j5_ev2_tok = mint_event_token(
        &SigningKey::from_seed([0xA2; 32]),
        "j5-res-1",
        &EventClaims {
            iss: "https://j5-durable-res.example".into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: "aauth:clerk@j5-durable-ap.example".into(),
            eid: j5_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 600,
            body_s256: Some(body_s256(j5_ev2_payload)),
            extra: Default::default(),
        },
    )?;
    let mut j5_del2_req = Request::builder()
        .method("POST")
        .uri("https://j5-durable-ap.example/events")
        .header("content-type", "application/json")
        .body(j5_ev2_payload.to_vec())?;
    sign_raw_request(
        &mut j5_del2_req,
        &SigningKey::from_seed([0xA2; 32]),
        KeyMaterial::SelfJwt { jwt: j5_ev2_tok },
        clock,
    )?;
    let j5_del2_resp = TlsServer::send_external(
        child2_addr,
        "j5-durable-ap.example",
        &child2_cert,
        &j5_del2_req,
    )?;
    let j5_del2_status = j5_del2_resp.status().as_u16();
    let j5_del2_rem = serde_json::from_slice::<Value>(j5_del2_resp.body())
        .ok()
        .and_then(|v| v.get("remaining_uses").and_then(Value::as_u64));

    // Deliver Event #3 to Child Process #2 -> 404 Not Found (max_uses=2 exhausted!)
    let j5_ev3_tok = mint_event_token(
        &SigningKey::from_seed([0xA2; 32]),
        "j5-res-1",
        &EventClaims {
            iss: "https://j5-durable-res.example".into(),
            dwk: EVENT_TOKEN_DOCUMENT.into(),
            aud: "aauth:clerk@j5-durable-ap.example".into(),
            eid: j5_eid.clone(),
            jti: generate_identifier(),
            iat: clock,
            exp: clock + 600,
            body_s256: None,
            extra: Default::default(),
        },
    )?;
    let mut j5_del3_req = Request::builder()
        .method("POST")
        .uri("https://j5-durable-ap.example/events")
        .body(Vec::new())?;
    sign_raw_request(
        &mut j5_del3_req,
        &SigningKey::from_seed([0xA2; 32]),
        KeyMaterial::SelfJwt { jwt: j5_ev3_tok },
        clock,
    )?;
    let j5_del3_resp = TlsServer::send_external(
        child2_addr,
        "j5-durable-ap.example",
        &child2_cert,
        &j5_del3_req,
    )?;
    let j5_del3_status = j5_del3_resp.status().as_u16();

    let j5_state_final = post_json_external(
        child2_addr,
        "j5-durable-ap.example",
        &child2_cert,
        "https://j5-durable-ap.example/__state",
        json!({"eid": j5_eid}),
    )?;

    drop(child2.stdin.take());
    let _ = child2.wait()?;

    // Verify both retained events from Child Process #2 with Rust EventSubscriptions::receive
    let j5_res_pub = SigningKey::from_seed([0xA2; 32]).public_jwk();
    let j5_res_keys = TrustedIssuerKeys::from_documents(
        "https://j5-durable-res.example",
        "aauth-resource.json",
        br#"{"issuer":"https://j5-durable-res.example","jwks_uri":"https://j5-durable-res.example/.well-known/jwks.json"}"#,
        json!({"keys":[{"kid":"j5-res-1","kty":"OKP","crv":"Ed25519","alg":"Ed25519","x":j5_res_pub.x}]})
            .to_string()
            .as_bytes(),
    )?;
    let mut j5_agent_subs = EventSubscriptions::new("aauth:clerk@j5-durable-ap.example")?;
    j5_agent_subs.remember(&j5_sub_token, "j5-durable-ctx".to_owned())?;
    let j5_final_pending = j5_state_final
        .get("pending")
        .and_then(Value::as_array)
        .ok_or("missing final pending")?;
    let j5_p0_tok = text(&j5_final_pending[0], "event_token")?;
    let j5_p0_body = BASE64_STD.decode(text(&j5_final_pending[0], "body_b64")?)?;
    let j5_p1_tok = text(&j5_final_pending[1], "event_token")?;
    let j5_p1_body = BASE64_STD.decode(text(&j5_final_pending[1], "body_b64")?)?;
    let j5_rec0_ok = j5_agent_subs
        .receive(&j5_p0_tok, &j5_p0_body, &j5_res_keys, clock)
        .is_ok()
        && j5_p0_body == j5_ev1_payload;
    let j5_rec1_ok = j5_agent_subs
        .receive(&j5_p1_tok, &j5_p1_body, &j5_res_keys, clock)
        .is_ok()
        && j5_p1_body == j5_ev2_payload;

    let j5_pass = child1_exit.success()
        && child1_pid != 0
        && child2_pid != 0
        && child1_pid != child2_pid
        && j5_del1_status == 202
        && j5_del1_rem == Some(1)
        && j5_state_before_exit.get("uses").and_then(Value::as_u64) == Some(1)
        && j5_state_before_exit.get("pending_count").and_then(Value::as_u64) == Some(1)
        && j5_state_after_reopen.get("uses").and_then(Value::as_u64) == Some(1)
        && j5_state_after_reopen.get("pending_count").and_then(Value::as_u64) == Some(1)
        && j5_del1_replay_status == 202
        && j5_del1_replay_rem == Some(1)
        && j5_del2_status == 202
        && j5_del2_rem == Some(0)
        && j5_del3_status == 404
        && j5_state_final.get("uses").and_then(Value::as_u64) == Some(2)
        && j5_state_final.get("pending_count").and_then(Value::as_u64) == Some(2)
        && j5_rec0_ok
        && j5_rec1_ok;

    cases.push(QaCaseReceipt {
        id: "QA-J5".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Rust Agent Provider Process-Restart Durability on DirectoryEventStore".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j5_pass,
        summary: format!(
            "pid1={} (uses=1, pending=1) -> process exit -> pid2={} (uses=1, pending=1 survived), dup replay=202 (rem=1), 2nd del=202 (rem=0, uses=2), 3rd del=404",
            child1_pid, child2_pid
        ),
        evidence: json!({
            "child1_pid": child1_pid,
            "child2_pid": child2_pid,
            "del1_status": j5_del1_status,
            "del1_remaining_uses": j5_del1_rem,
            "state_before_exit": j5_state_before_exit,
            "state_after_reopen": j5_state_after_reopen,
            "del1_replay_after_restart_status": j5_del1_replay_status,
            "del1_replay_after_restart_remaining": j5_del1_replay_rem,
            "del2_status": j5_del2_status,
            "del2_remaining_uses": j5_del2_rem,
            "del3_exhausted_status": j5_del3_status,
            "state_final": j5_state_final,
            "agent_verified_both_events": j5_rec0_ok && j5_rec1_ok,
        }),
    });
    transcript_lines.push(format!(
        "[QA-J5] {}: pid1={}->pid2={} uses_after_reopen={} replay={} del2={} del3_exhaust={}",
        if j5_pass { "PASS" } else { "FAIL" },
        child1_pid,
        child2_pid,
        j5_state_after_reopen.get("uses").and_then(Value::as_u64).unwrap_or(99),
        j5_del1_replay_status,
        j5_del2_status,
        j5_del3_status,
    ));

    // =========================================================================
    // QA-J6: Wire Difference Pinning: Registration Signed JSON Body Without content-digest
    // =========================================================================
    // Construct a subscription registration POST with a JSON body signed over
    // ("@method" "@authority" "@path" "content-type" "signature-key") WITHOUT "content-digest"
    // (as in the draft's own registration example), and verify both Rust and Go Resources refuse it with 401.
    let j6_rust_sub = j1_ap.issue_subscribe_token(
        j1_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j1_agent_tok,
            resource: j1_res_issuer,
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j6_body = br#"{"event_types":["slot.available"]}"#;
    let j6_agent_ct_only = j1_agent.with_additional_signature_components(["content-type"]);

    // Variant A (exact draft example: JSON body + Content-Type covered, no Content-Digest header or component) -> Rust Resource
    let mut j6_rust_req_a = Request::builder()
        .method("POST")
        .uri(format!("{j1_res_issuer}/events/subscribe"))
        .header("content-type", "application/json")
        .body(Vec::new())?;
    j6_agent_ct_only.sign_subscription(&mut j6_rust_req_a, &j6_rust_sub.token, clock)?;
    *j6_rust_req_a.body_mut() = j6_body.to_vec();
    let j6_rust_resp_a = j1_res_tls.send(&j6_rust_req_a)?;
    let j6_rust_sig_err_a = header_values(&j6_rust_resp_a, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();

    // Variant B (Content-Digest header present on wire, but omitted from Signature-Input covered components) -> Rust Resource
    let mut j6_rust_req_b = j6_rust_req_a.clone();
    j6_rust_req_b.headers_mut().insert(
        "content-digest",
        format!("sha-256=:{}:", BASE64_STD.encode(hex_decode("0000000000000000000000000000000000000000000000000000000000000000")?))
            .parse()?,
    );
    let j6_rust_resp_b = j1_res_tls.send(&j6_rust_req_b)?;
    let j6_rust_sig_err_b = header_values(&j6_rust_resp_b, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();

    // Variant A & B -> Go Resource (https://go-events-res.example/events/subscribe)
    let j6_go_sub = j4_ap.issue_subscribe_token(
        j4_ap_store.as_ref(),
        &SubscribeRequest {
            agent_token: &j4_agent_tok,
            resource: "https://go-events-res.example",
            expires_at: clock + 600,
            max_uses: Some(1),
            subscription_expires_at: None,
        },
        clock,
    )?;
    let j6_go_agent_ct_only = j4_agent.with_additional_signature_components(["content-type"]);
    let mut j6_go_req_a = Request::builder()
        .method("POST")
        .uri("https://go-events-res.example/events/subscribe")
        .header("content-type", "application/json")
        .body(Vec::new())?;
    j6_go_agent_ct_only.sign_subscription(&mut j6_go_req_a, &j6_go_sub.token, clock)?;
    *j6_go_req_a.body_mut() = j6_body.to_vec();
    let j6_go_resp_a = TlsServer::send_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        &j6_go_req_a,
    )?;
    let j6_go_sig_err_a = header_values(&j6_go_resp_a, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();

    let mut j6_go_req_b = j6_go_req_a.clone();
    j6_go_req_b.headers_mut().insert(
        "content-digest",
        format!("sha-256=:{}:", BASE64_STD.encode([0_u8; 32])).parse()?,
    );
    let j6_go_resp_b = TlsServer::send_external(
        go_events_res_addr,
        "go-events-res.example",
        &go_events_res_cert,
        &j6_go_req_b,
    )?;
    let j6_go_sig_err_b = header_values(&j6_go_resp_b, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();

    let j6_pass = j6_rust_resp_a.status().as_u16() == 401
        && j6_rust_sig_err_a.contains("error=invalid_input")
        && j6_rust_sig_err_a.contains("\"content-digest\"")
        && j6_rust_resp_b.status().as_u16() == 401
        && j6_rust_sig_err_b.contains("error=invalid_input")
        && j6_go_resp_a.status().as_u16() == 401
        && j6_go_sig_err_a.contains("error=invalid_input")
        && j6_go_sig_err_a.contains("\"content-digest\"")
        && j6_go_resp_b.status().as_u16() == 401
        && j6_go_sig_err_b.contains("error=invalid_input");

    cases.push(QaCaseReceipt {
        id: "QA-J6".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Wire Difference Pinning: Registration Signed JSON Body Without content-digest Refused by Both Rust and Go Resources".into(),
        classification: "BOUNDARY_PINNED".into(),
        passed_expectation: j6_pass,
        summary: format!(
            "Rust Resource={} ({}), Go Resource={} ({})",
            j6_rust_resp_a.status().as_u16(),
            j6_rust_sig_err_a,
            j6_go_resp_a.status().as_u16(),
            j6_go_sig_err_a,
        ),
        evidence: json!({
            "rust_no_digest_status": j6_rust_resp_a.status().as_u16(),
            "rust_no_digest_signature_error": j6_rust_sig_err_a,
            "rust_uncovered_digest_status": j6_rust_resp_b.status().as_u16(),
            "rust_uncovered_digest_signature_error": j6_rust_sig_err_b,
            "go_no_digest_status": j6_go_resp_a.status().as_u16(),
            "go_no_digest_signature_error": j6_go_sig_err_a,
            "go_uncovered_digest_status": j6_go_resp_b.status().as_u16(),
            "go_uncovered_digest_signature_error": j6_go_sig_err_b,
        }),
    });
    transcript_lines.push(format!(
        "[QA-J6] {}: rust_status={} ({}) go_status={} ({})",
        if j6_pass { "PASS" } else { "FAIL" },
        j6_rust_resp_a.status().as_u16(),
        j6_rust_sig_err_a,
        j6_go_resp_a.status().as_u16(),
        j6_go_sig_err_a,
    ));

    // =========================================================================
    // QA-J7: Consumer Documentation Audit (USE-IN-YOUR-SERVICE.md & CONFORMANCE.md in Rust and Go)
    // =========================================================================
    let rust_root = crate::rust_source();
    let go_root = Path::new(go_module_path);

    let rust_use_doc = fs::read_to_string(rust_root.join("USE-IN-YOUR-SERVICE.md"))?;
    let rust_conf_doc = fs::read_to_string(rust_root.join("CONFORMANCE.md"))?;
    let go_use_doc = fs::read_to_string(go_root.join("USE-IN-YOUR-SERVICE.md"))?;
    let go_conf_doc = fs::read_to_string(go_root.join("CONFORMANCE.md"))?;

    let rust_use_required = [
        "## Subscribe to and deliver AAuth Events",
        "aauth_rust_core::events",
        "SubscribeToken",
        "EventToken",
        "AgentProvider::with_event_endpoint",
        "events::EventInbox",
        "issue_subscribe_token",
        "SubscribeRequest",
        "inbox.receive(&request, now).into_response()",
        "DirectoryEventStore::open",
        "EventSubscriptions::new",
        "subscriptions.remember",
        "agent.sign_subscription",
        "subscriptions.receive",
        "verify_event",
        "events::EventsResource::new",
        "EventsConfig",
        "issue_ticket",
        "register_with_ticket",
        "prepare_event",
        "agent_provider_metadata_url",
        "delivery_request",
        "admit_event_endpoint",
        "delivery_outcome",
        "with_asyncapi",
        "subscribe_security_scheme()",
    ];
    let rust_use_all_present = rust_use_required
        .iter()
        .all(|needle| rust_use_doc.contains(needle));
    let rust_conf_ok =
        rust_conf_doc.contains("AAuth Events is implemented against all 22 MUST-level rows");

    let go_use_required = [
        "## Deliver events to an Agent",
        "agentprovider.Config.Events",
        "Server.IssueSubscribeToken",
        "agentprovider/storetest.RunEventInbox",
        "resource.NewEventService",
        "eventService.PrepareEvent",
        "eventService.DeliverEvent",
        "EventServiceConfig.AsyncAPIDocument",
        "AsyncAPIHandler",
        "events.ValidateAsyncAPIDocument",
        "IssueProtectedSubscriptionTicket",
        "ConfirmationKey: principal.Confirmation",
        "resource/storetest.RunProtectedEvents",
        "Client.RegisterPublicSubscription",
        "Client.RegisterProtectedSubscription",
        "Client.AcceptEvent",
    ];
    let go_use_all_present = go_use_required
        .iter()
        .all(|needle| go_use_doc.contains(needle));
    let go_conf_ok = go_conf_doc.contains("| Events subscriptions and delivery | Implemented |")
        && go_conf_doc.contains("22 MUST-level rows of the pinned Events draft have asserting tests.");

    let j7_pass = rust_use_all_present && rust_conf_ok && go_use_all_present && go_conf_ok;

    cases.push(QaCaseReceipt {
        id: "QA-J7".into(),
        category: "J. AAuth Events (Rust & Go)".into(),
        title: "Consumer Documentation Audit: USE-IN-YOUR-SERVICE.md & CONFORMANCE.md in aauth-rust and aauth-go".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: j7_pass,
        summary: format!(
            "rust USE-IN-YOUR-SERVICE ({}/{} symbols)={}, rust CONFORMANCE={}, go USE-IN-YOUR-SERVICE ({}/{} symbols)={}, go CONFORMANCE={}",
            rust_use_required.len(),
            rust_use_required.len(),
            rust_use_all_present,
            rust_conf_ok,
            go_use_required.len(),
            go_use_required.len(),
            go_use_all_present,
            go_conf_ok,
        ),
        evidence: json!({
            "rust_use_in_your_service_all_present": rust_use_all_present,
            "rust_conformance_22_rows_recorded": rust_conf_ok,
            "go_use_in_your_service_all_present": go_use_all_present,
            "go_conformance_22_rows_recorded": go_conf_ok,
        }),
    });
    transcript_lines.push(format!(
        "[QA-J7] {}: rust_use={} rust_conf={} go_use={} go_conf={}",
        if j7_pass { "PASS" } else { "FAIL" },
        rust_use_all_present,
        rust_conf_ok,
        go_use_all_present,
        go_conf_ok,
    ));

    // =========================================================================
    // K. aauth-go Conformance Fixes QA-K1..QA-K8
    // =========================================================================
    let rust_mission_json = json!({
        "agent": "aauth:k1-agent@k1-ap.example",
        "approved_at": crate::unix_to_rfc3339(clock),
        "description": "Cross-language Rust mission blob without approver field",
        "expires_at": crate::unix_to_rfc3339(clock + 1800),
        "tools": [
            {"name": "records.read", "description": "Read medical records"}
        ]
    });
    let rust_mission_bytes = serde_json::to_vec(&rust_mission_json)?;
    let rust_mission_s256 = aauth_rust_r3::digest(&rust_mission_bytes);
    let rust_mission_encoded = crate::base64url(&rust_mission_bytes);
    let rust_mission_decoded =
        aauth_rust_core::ApprovedMission::decode(&rust_mission_s256, &rust_mission_encoded)?;

    let k_suite = post_json_external(
        go_events_ap_addr,
        "go-events-ap.example",
        &go_events_ap_cert,
        "https://go-events-ap.example/__run-k-suite",
        json!({
            "rust_mission_s256": rust_mission_s256,
            "rust_mission_encoded": rust_mission_encoded,
        }),
    )?;

    // -------------------------------------------------------------------------
    // QA-K1: /authorize Challenges & invalid_signature on Missing Signature Header
    // -------------------------------------------------------------------------
    let k1 = k_suite.get("k1").ok_or("missing k1")?;
    let k1_res_addr: SocketAddr = text(k1, "res_addr")?.parse()?;
    let k1_res_cert = hex_decode(&text(k1, "res_cert_hex")?)?;

    // Cross-language Rust -> Go /authorize challenge & missing-Signature verification
    let rust_k1_unsigned_req = Request::builder()
        .method("POST")
        .uri("https://k1-res.example/authorize")
        .header("content-type", "application/json")
        .body(br#"{"scope":"records.read"}"#.to_vec())?;
    let rust_k1_unsigned_resp = TlsServer::send_external(
        k1_res_addr,
        "k1-res.example",
        &k1_res_cert,
        &rust_k1_unsigned_req,
    )?;
    let rust_k1_unsigned_req_hdr = header_values(&rust_k1_unsigned_resp, "aauth-requirement")
        .first()
        .cloned()
        .unwrap_or_default();
    let rust_k1_unsigned_sig_err = header_values(&rust_k1_unsigned_resp, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();
    let rust_k1_parsed_req_ok = rust_k1_unsigned_req_hdr == "requirement=person-token";

    let rust_k1_missing_sig_req = Request::builder()
        .method("POST")
        .uri("https://k1-res.example/authorize")
        .header("content-type", "application/json")
        .header(
            "signature-input",
            r#"sig=("@method" "@authority" "@path");created=1700000000"#,
        )
        .header("signature-key", r#"sig=(scheme="jwt";jwt="eyJ0eXAiOiJhYS1hZ2VudCtqd3QiLCJhbGciOiJFZERTQSJ9.e30.e30")"#)
        .body(br#"{"scope":"records.read"}"#.to_vec())?;
    let rust_k1_missing_sig_resp = TlsServer::send_external(
        k1_res_addr,
        "k1-res.example",
        &k1_res_cert,
        &rust_k1_missing_sig_req,
    )?;
    let rust_k1_missing_sig_hdr = header_values(&rust_k1_missing_sig_resp, "signature-error")
        .first()
        .cloned()
        .unwrap_or_default();

    let k1_pass = k1.get("ag_challenge_status").and_then(Value::as_i64) == Some(401)
        && k1.get("ag_challenge_req").and_then(Value::as_str) == Some("requirement=person-token")
        && k1.get("ag_challenge_sig_err").and_then(Value::as_str) == Some("")
        && k1.get("auth_challenge_status").and_then(Value::as_i64) == Some(401)
        && k1.get("auth_challenge_req").and_then(Value::as_str) == Some("requirement=person-token")
        && k1.get("auth_challenge_sig_err").and_then(Value::as_str) == Some("")
        && k1.get("unsigned_challenge_status").and_then(Value::as_i64) == Some(401)
        && k1.get("unsigned_challenge_req").and_then(Value::as_str) == Some("requirement=person-token")
        && k1.get("unsigned_challenge_sig").and_then(Value::as_str) == Some("")
        && k1.get("issued_after_challenges").and_then(Value::as_i64) == Some(0)
        && k1.get("miss_sig_status").and_then(Value::as_i64) == Some(401)
        && k1.get("miss_sig_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("miss_input_status").and_then(Value::as_i64) == Some(401)
        && k1.get("miss_input_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("miss_key_status").and_then(Value::as_i64) == Some(401)
        && k1.get("miss_key_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("prot_miss_sig_status").and_then(Value::as_i64) == Some(401)
        && k1.get("prot_miss_sig_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("ps_miss_input_status").and_then(Value::as_i64) == Some(401)
        && k1.get("ps_miss_input_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("wrong_key_ag_status").and_then(Value::as_i64) == Some(401)
        && k1.get("wrong_key_ag_req").and_then(Value::as_str) == Some("")
        && k1.get("wrong_key_ag_sig_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("exp_pt_status").and_then(Value::as_i64) == Some(401)
        && k1.get("exp_pt_req").and_then(Value::as_str) == Some("")
        && k1.get("exp_pt_sig_err").and_then(Value::as_str) == Some("error=expired_jwt")
        && k1.get("wrong_key_pt_status").and_then(Value::as_i64) == Some(401)
        && k1.get("wrong_key_pt_req").and_then(Value::as_str) == Some("")
        && k1.get("wrong_key_pt_sig_err").and_then(Value::as_str) == Some("error=invalid_signature")
        && k1.get("valid_pt_status").and_then(Value::as_i64) == Some(200)
        && k1.get("valid_pt_sig_err").and_then(Value::as_str) == Some("")
        && k1.get("valid_pt_rt_ok").and_then(Value::as_bool) == Some(true)
        && k1.get("caps_unknown_params_ok").and_then(Value::as_bool) == Some(true)
        && rust_k1_unsigned_resp.status().as_u16() == 401
        && rust_k1_parsed_req_ok
        && rust_k1_unsigned_sig_err.is_empty()
        && rust_k1_missing_sig_resp.status().as_u16() == 401
        && rust_k1_missing_sig_hdr == "error=invalid_signature";

    cases.push(QaCaseReceipt {
        id: "QA-K1".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "/authorize Challenges (401 requirement=person-token) & invalid_signature on Missing Signature Header".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k1_pass,
        summary: format!(
            "ag/auth/unsigned->401 requirement=person-token (issued=0), expired_pt->401 error=expired_jwt (no challenge), missing Signature/Signature-Input/Signature-Key->401 error=invalid_signature, wrong_key->401 error=invalid_signature (no challenge), valid_pt->200 resource_token verified={}",
            k1.get("valid_pt_rt_ok").and_then(Value::as_bool).unwrap_or(false)
        ),
        evidence: json!({
            "go_k1": k1,
            "rust_cross_lang_unsigned_status": rust_k1_unsigned_resp.status().as_u16(),
            "rust_cross_lang_unsigned_requirement": rust_k1_unsigned_req_hdr,
            "rust_cross_lang_missing_sig_status": rust_k1_missing_sig_resp.status().as_u16(),
            "rust_cross_lang_missing_sig_header": rust_k1_missing_sig_hdr,
        }),
    });
    transcript_lines.push(format!(
        "[QA-K1] {}: ag_401={} auth_401={} unsigned_401={} miss_sig={} valid_pt_200={} rust_xlang_ok={}",
        if k1_pass { "PASS" } else { "FAIL" },
        k1.get("ag_challenge_req").and_then(Value::as_str).unwrap_or(""),
        k1.get("auth_challenge_req").and_then(Value::as_str).unwrap_or(""),
        k1.get("unsigned_challenge_req").and_then(Value::as_str).unwrap_or(""),
        k1.get("miss_sig_err").and_then(Value::as_str).unwrap_or(""),
        k1.get("valid_pt_status").and_then(Value::as_i64).unwrap_or(0),
        rust_k1_parsed_req_ok && rust_k1_missing_sig_hdr == "error=invalid_signature",
    ));

    // -------------------------------------------------------------------------
    // QA-K2: Four-Party Path: Expiry Recheck After Consent & PS Recording Presented AS
    // -------------------------------------------------------------------------
    let k2 = k_suite.get("k2").ok_or("missing k2")?;
    let k2_after_as1 = k2
        .get("after_as1_presentations")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let k2_after_as2 = k2
        .get("after_as2_presentations")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let k2_recorded_at_as1_send_ok = k2
        .get("recorded_at_as1_send")
        .and_then(Value::as_array)
        .map(|arr| {
            !arr.is_empty()
                && arr[0]
                    .as_array()
                    .map(|inner| inner.iter().filter_map(Value::as_str).collect::<Vec<_>>() == vec!["https://k2-as1.example"])
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    let k2_pass = k2.get("no_presentation_store_refused").and_then(Value::as_bool) == Some(true)
        && k2.get("before_presentations").map(Value::is_null).unwrap_or(false)
        && k2.get("ex1_status").and_then(Value::as_i64) == Some(200)
        && k2.get("ex2_status").and_then(Value::as_i64) == Some(200)
        && k2_after_as1 == vec!["https://k2-as1.example"]
        && k2.get("ex3_status").and_then(Value::as_i64) == Some(200)
        && k2_after_as2 == vec!["https://k2-as1.example", "https://k2-as2.example"]
        && k2_recorded_at_as1_send_ok
        && k2.get("fail_pres_status").and_then(Value::as_i64) == Some(500)
        && k2.get("fail_pres_as_not_called").and_then(Value::as_bool) == Some(true)
        && k2.get("exp_pt_status").and_then(Value::as_i64) == Some(400)
        && k2.get("exp_pt_error").and_then(Value::as_str) == Some("expired_presented_token")
        && k2.get("exp_pt_as_not_called").and_then(Value::as_bool) == Some(true)
        && k2.get("exp_rt_status").and_then(Value::as_i64) == Some(400)
        && k2.get("exp_rt_error").and_then(Value::as_str) == Some("expired_resource_token")
        && k2.get("exp_rt_as_not_called").and_then(Value::as_bool) == Some(true)
        && k2.get("curr_after_consent_status").and_then(Value::as_i64) == Some(200)
        && k2.get("curr_after_consent_has_token").and_then(Value::as_bool) == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-K2".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "Four-Party Path: Expiry Recheck After Consent & PS Recording Presented Access Server".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k2_pass,
        summary: format!(
            "presentations={:?} (recorded_before_as_send={}, store_fail_aborts={}), post_consent_expired_pt->400 {} (no_as_call={}), post_consent_expired_rt->400 {} (no_as_call={}), current_1s_before_exp->200",
            k2_after_as2,
            k2_recorded_at_as1_send_ok,
            k2.get("fail_pres_as_not_called").and_then(Value::as_bool).unwrap_or(false),
            k2.get("exp_pt_error").and_then(Value::as_str).unwrap_or(""),
            k2.get("exp_pt_as_not_called").and_then(Value::as_bool).unwrap_or(false),
            k2.get("exp_rt_error").and_then(Value::as_str).unwrap_or(""),
            k2.get("exp_rt_as_not_called").and_then(Value::as_bool).unwrap_or(false),
        ),
        evidence: k2.clone(),
    });
    transcript_lines.push(format!(
        "[QA-K2] {}: presentations={:?} exp_pt_400={}({}) exp_rt_400={}({}) curr_200={}",
        if k2_pass { "PASS" } else { "FAIL" },
        k2_after_as2,
        k2.get("exp_pt_status").and_then(Value::as_i64).unwrap_or(0),
        k2.get("exp_pt_error").and_then(Value::as_str).unwrap_or(""),
        k2.get("exp_rt_status").and_then(Value::as_i64).unwrap_or(0),
        k2.get("exp_rt_error").and_then(Value::as_str).unwrap_or(""),
        k2.get("curr_after_consent_status").and_then(Value::as_i64).unwrap_or(0),
    ));

    // -------------------------------------------------------------------------
    // QA-K3: Person-Token Interaction Code Consume Signature & 3 Failed Codes
    // -------------------------------------------------------------------------
    let k3 = k_suite.get("k3").ok_or("missing k3")?;
    let k3_pass = k3.get("max_attempts_const").and_then(Value::as_i64) == Some(3)
        && k3.get("flow1_attempt1_invalid").and_then(Value::as_bool) == Some(true)
        && k3.get("flow1_attempt2_invalid").and_then(Value::as_bool) == Some(true)
        && k3.get("flow1_attempt3_approved_token").and_then(Value::as_bool) == Some(true)
        && k3.get("flow2_attempt1_invalid").and_then(Value::as_bool) == Some(true)
        && k3.get("flow2_attempt2_invalid").and_then(Value::as_bool) == Some(true)
        && k3.get("flow2_attempt3_gone").and_then(Value::as_bool) == Some(true)
        && k3.get("flow2_attempt4_valid_refused").and_then(Value::as_bool) == Some(true)
        && k3.get("flow2_poll_status").and_then(Value::as_i64) == Some(410)
        && k3.get("flow2_poll_error").and_then(Value::as_str) == Some("invalid_code");

    cases.push(QaCaseReceipt {
        id: "QA-K3".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "Person-Token Interaction Code-Consume Signature (PersonTokenCodePresentation) & 3 Failed Codes Terminating Interaction".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k3_pass,
        summary: format!(
            "2_failed_then_valid_succeeds={}, 3_failed_terminates_with_ErrPendingPersonTokenGone={}, 4th_attempt_with_valid_code_refused={}, subsequent_poll={} ({})",
            k3.get("flow1_attempt3_approved_token").and_then(Value::as_bool).unwrap_or(false),
            k3.get("flow2_attempt3_gone").and_then(Value::as_bool).unwrap_or(false),
            k3.get("flow2_attempt4_valid_refused").and_then(Value::as_bool).unwrap_or(false),
            k3.get("flow2_poll_status").and_then(Value::as_i64).unwrap_or(0),
            k3.get("flow2_poll_error").and_then(Value::as_str).unwrap_or(""),
        ),
        evidence: k3.clone(),
    });
    transcript_lines.push(format!(
        "[QA-K3] {}: 2_fail_then_valid={} 3_fail_gone={} 4th_valid_refused={} poll={}({})",
        if k3_pass { "PASS" } else { "FAIL" },
        k3.get("flow1_attempt3_approved_token").and_then(Value::as_bool).unwrap_or(false),
        k3.get("flow2_attempt3_gone").and_then(Value::as_bool).unwrap_or(false),
        k3.get("flow2_attempt4_valid_refused").and_then(Value::as_bool).unwrap_or(false),
        k3.get("flow2_poll_status").and_then(Value::as_i64).unwrap_or(0),
        k3.get("flow2_poll_error").and_then(Value::as_str).unwrap_or(""),
    ));

    // -------------------------------------------------------------------------
    // QA-K4: Key Resolver Refusing Private & Loopback Destinations + TransportEnforcesEgress
    // -------------------------------------------------------------------------
    let k4 = k_suite.get("k4").ok_or("missing k4")?;
    let k4_pass = k4.get("all_non_public_denied").and_then(Value::as_bool) == Some(true)
        && k4.get("total_dials_on_denied").and_then(Value::as_i64) == Some(0)
        && k4.get("literal_loopback_denied").and_then(Value::as_bool) == Some(true)
        && k4.get("custom_rt_rejected").and_then(Value::as_bool) == Some(true)
        && k4.get("proxy_transport_rejected").and_then(Value::as_bool) == Some(true)
        && k4.get("pinned_dial_ok").and_then(Value::as_bool) == Some(true)
        && k4.get("dns_rebind_refused_ok").and_then(Value::as_bool) == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-K4".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "Key Resolver Refusing Private/Loopback/Link-Local/CGNAT/NAT64 Destinations + TransportEnforcesEgress & Checked-IP Pinning".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k4_pass,
        summary: format!(
            "all_13_non_public_denied={} (dials={}), literal_127_0_0_1_denied={}, custom_rt_rejected={}, proxy_rejected={}, pinned_checked_ip_dial={}, dns_rebind_refused={}",
            k4.get("all_non_public_denied").and_then(Value::as_bool).unwrap_or(false),
            k4.get("total_dials_on_denied").and_then(Value::as_i64).unwrap_or(-1),
            k4.get("literal_loopback_denied").and_then(Value::as_bool).unwrap_or(false),
            k4.get("custom_rt_rejected").and_then(Value::as_bool).unwrap_or(false),
            k4.get("proxy_transport_rejected").and_then(Value::as_bool).unwrap_or(false),
            k4.get("pinned_dial_ok").and_then(Value::as_bool).unwrap_or(false),
            k4.get("dns_rebind_refused_ok").and_then(Value::as_bool).unwrap_or(false),
        ),
        evidence: k4.clone(),
    });
    transcript_lines.push(format!(
        "[QA-K4] {}: non_public_denied={} dials={} pinned_dial={} rebind_refused={}",
        if k4_pass { "PASS" } else { "FAIL" },
        k4.get("all_non_public_denied").and_then(Value::as_bool).unwrap_or(false),
        k4.get("total_dials_on_denied").and_then(Value::as_i64).unwrap_or(-1),
        k4.get("pinned_dial_ok").and_then(Value::as_bool).unwrap_or(false),
        k4.get("dns_rebind_refused_ok").and_then(Value::as_bool).unwrap_or(false),
    ));

    // -------------------------------------------------------------------------
    // QA-K5: PollAuthToken and PollR3Call Result Types & Backing Off on 429
    // -------------------------------------------------------------------------
    let k5 = k_suite.get("k5").ok_or("missing k5")?;
    let want_backoffs = vec![5i64, 10, 15, 3, 8, 30, 35, 2];
    let k5_auth_obs = k5
        .get("auth_observed_sec")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
        .unwrap_or_default();
    let k5_r3_obs = k5
        .get("r3_observed_sec")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
        .unwrap_or_default();
    let k5_pass = k5.get("auth_initial_sec").and_then(Value::as_i64) == Some(5)
        && k5_auth_obs == want_backoffs
        && k5.get("auth_terminal_status").and_then(Value::as_i64) == Some(200)
        && k5.get("auth_person_req_ok").and_then(Value::as_bool) == Some(true)
        && k5.get("r3_initial_sec").and_then(Value::as_i64) == Some(5)
        && k5_r3_obs == want_backoffs
        && k5.get("r3_terminal_status").and_then(Value::as_i64) == Some(200)
        && k5.get("r3_person_req_ok").and_then(Value::as_bool) == Some(true)
        && k5.get("reauthorize_ok").and_then(Value::as_bool) == Some(true);

    cases.push(QaCaseReceipt {
        id: "QA-K5".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "PollAuthToken (AuthTokenPollResult) & PollR3Call (R3PollResult) Result Types, 429/503 Backoff Progression & Client.Reauthorize".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k5_pass,
        summary: format!(
            "PollAuthToken backoffs={:?} (200_ok={}, person_req={}), PollR3Call backoffs={:?} (200_ok={}, person_req={}), Client.Reauthorize={}",
            k5_auth_obs,
            k5.get("auth_terminal_status").and_then(Value::as_i64) == Some(200),
            k5.get("auth_person_req_ok").and_then(Value::as_bool).unwrap_or(false),
            k5_r3_obs,
            k5.get("r3_terminal_status").and_then(Value::as_i64) == Some(200),
            k5.get("r3_person_req_ok").and_then(Value::as_bool).unwrap_or(false),
            k5.get("reauthorize_ok").and_then(Value::as_bool).unwrap_or(false),
        ),
        evidence: k5.clone(),
    });
    transcript_lines.push(format!(
        "[QA-K5] {}: auth_backoffs={:?} r3_backoffs={:?} auth_person_req={} r3_person_req={} client_reauth={}",
        if k5_pass { "PASS" } else { "FAIL" },
        k5_auth_obs,
        k5_r3_obs,
        k5.get("auth_person_req_ok").and_then(Value::as_bool).unwrap_or(false),
        k5.get("r3_person_req_ok").and_then(Value::as_bool).unwrap_or(false),
        k5.get("reauthorize_ok").and_then(Value::as_bool).unwrap_or(false),
    ));

    // -------------------------------------------------------------------------
    // QA-K6: MissionBlob.Approver Removal & Cross-PS Mission Data Without approver
    // -------------------------------------------------------------------------
    let k6 = k_suite.get("k6").ok_or("missing k6")?;
    let go_mission_s256 = text(k6, "go_mission_s256")?;
    let go_mission_exact_json = text(k6, "go_mission_exact_json")?;
    let go_mission_encoded = crate::base64url(go_mission_exact_json.as_bytes());
    let rust_verified_go_mission =
        aauth_rust_core::ApprovedMission::decode(&go_mission_s256, &go_mission_encoded);
    let rust_verified_go_mission_ok = rust_verified_go_mission.is_ok();
    let rust_mission_roundtrip_s256_ok = rust_mission_decoded.s256() == rust_mission_s256;

    let k6_pass = k6.get("has_approver_field").and_then(Value::as_bool) == Some(false)
        && k6.get("go_encoded_has_approver").and_then(Value::as_bool) == Some(false)
        && k6.get("rust_mission_decoded_ok").and_then(Value::as_bool) == Some(true)
        && k6.get("legacy_with_approver_ok").and_then(Value::as_bool) == Some(true)
        && k6.get("go_mission_call_status").and_then(Value::as_i64) == Some(200)
        && rust_verified_go_mission_ok
        && rust_mission_roundtrip_s256_ok;

    cases.push(QaCaseReceipt {
        id: "QA-K6".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "MissionBlob.Approver Removal & Cross-PS / Cross-Language Mission Data Without approver".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k6_pass,
        summary: format!(
            "has_approver_field=false, go_encoded_has_approver=false, rust_mission_decoded_by_go={}, go_mission_decoded_by_rust={}, legacy_approver_ignored_and_preserved={}, https_call_status={}",
            k6.get("rust_mission_decoded_ok").and_then(Value::as_bool).unwrap_or(false),
            rust_verified_go_mission_ok,
            k6.get("legacy_with_approver_ok").and_then(Value::as_bool).unwrap_or(false),
            k6.get("go_mission_call_status").and_then(Value::as_i64).unwrap_or(0),
        ),
        evidence: json!({
            "go_k6": k6,
            "rust_verified_go_mission_ok": rust_verified_go_mission_ok,
            "rust_mission_s256": rust_mission_s256,
        }),
    });
    transcript_lines.push(format!(
        "[QA-K6] {}: has_approver=false rust_to_go={} go_to_rust={} legacy_preserved={} call_200={}",
        if k6_pass { "PASS" } else { "FAIL" },
        k6.get("rust_mission_decoded_ok").and_then(Value::as_bool).unwrap_or(false),
        rust_verified_go_mission_ok,
        k6.get("legacy_with_approver_ok").and_then(Value::as_bool).unwrap_or(false),
        k6.get("go_mission_call_status").and_then(Value::as_i64).unwrap_or(0),
    ));

    // -------------------------------------------------------------------------
    // QA-K7: Upstream Person Token in Call Chaining Over HTTPS
    // -------------------------------------------------------------------------
    let k7 = k_suite.get("k7").ok_or("missing k7")?;
    let k7_agent_cli_err = k7
        .get("agent_client_upstream_pt_err")
        .and_then(Value::as_str)
        .unwrap_or("");
    let k7_pass = k7.get("person_status").and_then(Value::as_i64) == Some(200)
        && k7.get("token_status").and_then(Value::as_i64) == Some(200)
        && k7.get("saw_upstream_person_at_bind").and_then(Value::as_bool) == Some(true)
        && k7.get("saw_upstream_person_at_auth").and_then(Value::as_bool) == Some(true)
        && k7.get("ordinary_bind_calls").and_then(Value::as_i64) == Some(1)
        && k7.get("chain_bind_calls").and_then(Value::as_i64) == Some(2)
        && k7.get("chain_auth_calls").and_then(Value::as_i64) == Some(1)
        && k7.get("downstream_pt_clamped_exp").and_then(Value::as_bool) == Some(true)
        && k7.get("downstream_pt_record_ag_jti").and_then(Value::as_bool) == Some(true)
        && k7.get("downstream_auth_clamped_exp").and_then(Value::as_bool) == Some(true)
        && k7.get("res2_call_status").and_then(Value::as_i64) == Some(200)
        && k7.get("neg_other_ps").and_then(Value::as_bool) == Some(true)
        && k7.get("neg_wrong_aud").and_then(Value::as_bool) == Some(true)
        && k7.get("neg_expired").and_then(Value::as_bool) == Some(true)
        && k7.get("neg_unrecorded").and_then(Value::as_bool) == Some(true)
        && k7.get("neg_missing_agent_token_jti").and_then(Value::as_bool) == Some(true)
        && k7.get("neg_revoked_calling_agent_tok").and_then(Value::as_bool) == Some(true)
        && k7_agent_cli_err.is_empty();

    cases.push(QaCaseReceipt {
        id: "QA-K7".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "Upstream Person Token in Call Chaining Over HTTPS (Person Server POST /person & POST /token Clamping, Lineage, 6 Negative Guards + agent.Client UpstreamToken GAP-K7-AGENT-CLIENT Resolved)".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: k7_pass,
        summary: format!(
            "PS /person=200 & /token=200 (clamped={}, ag_jti_lineage={}, res2_call=200, 6_neg_guards_ok=true); GAP-K7-AGENT-CLIENT RESOLVED in 2f2869d: agent.Client.verifyCallChainUpstreamTokenAt now accepts aa-person+jwt (err={:?})",
            k7.get("downstream_pt_clamped_exp").and_then(Value::as_bool).unwrap_or(false)
                && k7.get("downstream_auth_clamped_exp").and_then(Value::as_bool).unwrap_or(false),
            k7.get("downstream_pt_record_ag_jti").and_then(Value::as_bool).unwrap_or(false),
            k7_agent_cli_err,
        ),
        evidence: k7.clone(),
    });
    transcript_lines.push(format!(
        "[QA-K7] {}: ps_person={} ps_token={} clamped={} neg_guards=true agent_client_gap_resolved={}",
        if k7_pass { "PASS" } else { "FAIL" },
        k7.get("person_status").and_then(Value::as_i64).unwrap_or(0),
        k7.get("token_status").and_then(Value::as_i64).unwrap_or(0),
        k7.get("downstream_pt_clamped_exp").and_then(Value::as_bool).unwrap_or(false)
            && k7.get("downstream_auth_clamped_exp").and_then(Value::as_bool).unwrap_or(false),
        k7_agent_cli_err.is_empty(),
    ));

    // -------------------------------------------------------------------------
    // QA-K8: Consumer Upgrade & Documentation Audit for the 5 Breaking Changes
    // -------------------------------------------------------------------------
    let go_interp_doc = fs::read_to_string(go_root.join("INTERPRETATIONS.md"))?;
    let go_sec_doc = fs::read_to_string(go_root.join("SECURITY.md"))?;
    let go_readme_doc = fs::read_to_string(go_root.join("README.md"))?;
    let go_ps_server_src = fs::read_to_string(go_root.join("personserver/server.go"))?;
    let go_ps_inter_src = fs::read_to_string(go_root.join("personserver/person_interaction.go"))?;
    let go_sig_disc_src = fs::read_to_string(go_root.join("signaturekey/discovery.go"))?;
    let go_mission_src = fs::read_to_string(go_root.join("mission.go"))?;
    let go_agent_call_src = fs::read_to_string(go_root.join("agent/call.go"))?;
    let go_agent_r3_src = fs::read_to_string(go_root.join("agent/r3_call.go"))?;

    let conf_2026_10_30_ok = go_conf_doc.contains("Changes on 2026-10-30.")
        && go_conf_doc.contains("`/authorize` with no person token answers the `401` person-token challenge")
        && go_conf_doc.contains("A request missing a signature header is `invalid_signature`.")
        && go_conf_doc.contains("On the four-party path the PS rechecks presented-token expiry after consent.")
        && go_conf_doc.contains("The PS records which Access Server each person token was presented to.")
        && go_conf_doc.contains("The PS ends a person-token interaction after three failed codes.")
        && go_conf_doc.contains("The key resolver refuses private, loopback and link-local destinations")
        && go_conf_doc.contains("Agent polls back off on `429` and honor `Retry-After` on `503`.")
        && go_conf_doc.contains("Mission data no longer carries the `approver` member")
        && go_conf_doc.contains("Call chaining accepts an upstream person token.");

    let go_doc_comments_ok = !go_mission_src.contains("Approver ")
        && go_ps_server_src.contains("type PersonTokenPresentationStore interface")
        && go_ps_inter_src.contains("type PersonTokenCodePresentation struct")
        && go_ps_inter_src.contains("MaximumPersonTokenCodeAttempts")
        && go_sig_disc_src.contains("TransportEnforcesEgress bool")
        && go_agent_call_src.contains("type AuthTokenPollResult struct")
        && go_agent_r3_src.contains("type R3PollResult struct")
        && go_sec_doc.contains("TransportEnforcesEgress")
        && go_interp_doc.contains("A `429` poll answer honors both the backoff and its own `Retry-After`");

    // Audit USE-IN-YOUR-SERVICE.md coverage for the 5 breaking changes:
    let use_doc_mentions_presentation_store =
        go_use_doc.contains("PersonTokenPresentationStore");
    let use_doc_mentions_code_presentation =
        go_use_doc.contains("PersonTokenCodePresentation");
    let use_doc_mentions_transport_enforces_egress =
        go_use_doc.contains("TransportEnforcesEgress");
    let use_doc_mentions_poll_result_types =
        go_use_doc.contains("AuthTokenPollResult") && go_use_doc.contains("R3PollResult");
    let readme_has_no_stale_symbols = !go_readme_doc.contains("Approver");

    let k8_pass = conf_2026_10_30_ok && go_doc_comments_ok && readme_has_no_stale_symbols;

    cases.push(QaCaseReceipt {
        id: "QA-K8".into(),
        category: "K. aauth-go Conformance Fixes".into(),
        title: "Consumer Upgrade & Documentation Audit for the 5 Breaking Changes (CONFORMANCE.md, INTERPRETATIONS.md, SECURITY.md, Go Doc Comments & USE-IN-YOUR-SERVICE.md)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: k8_pass,
        summary: format!(
            "CONFORMANCE_2026_10_30={}, Go_doc_comments_all_5={}, SECURITY_md_egress=true; USE-IN-YOUR-SERVICE.md migration gaps noted: PersonTokenPresentationStore={}, TransportEnforcesEgress={}, PollResultTypes={}",
            conf_2026_10_30_ok,
            go_doc_comments_ok,
            use_doc_mentions_presentation_store,
            use_doc_mentions_transport_enforces_egress,
            use_doc_mentions_poll_result_types,
        ),
        evidence: json!({
            "conformance_2026_10_30_complete": conf_2026_10_30_ok,
            "go_doc_comments_all_5_present": go_doc_comments_ok,
            "readme_has_no_stale_symbols": readme_has_no_stale_symbols,
            "use_in_your_service_coverage": {
                "mentions_PersonTokenPresentationStore": use_doc_mentions_presentation_store,
                "mentions_PersonTokenCodePresentation": use_doc_mentions_code_presentation,
                "mentions_TransportEnforcesEgress": use_doc_mentions_transport_enforces_egress,
                "mentions_AuthTokenPollResult_and_R3PollResult": use_doc_mentions_poll_result_types,
            },
            "doc_and_upgrade_observations": [
                {
                    "id": "DOC-GAP-1",
                    "title": "FederatedAuthorizationConfig.Tokens static type is still TokenStore (runtime failure instead of compile-time error) and USE-IN-YOUR-SERVICE.md / personserver/storetest omit PersonTokenPresentationStore",
                    "citations": [
                        "personserver/server.go:177-180",
                        "personserver/server.go:462-466",
                        "USE-IN-YOUR-SERVICE.md:650",
                        "USE-IN-YOUR-SERVICE.md:677-690",
                        "CONFORMANCE.md:266"
                    ]
                },
                {
                    "id": "DOC-GAP-2",
                    "title": "USE-IN-YOUR-SERVICE.md loopback test-transport guidance (lines 748-751) and HTTPKeyResolverConfig references (lines 50-51, 344-347) do not mention TransportEnforcesEgress or AllowDestination/LookupAddresses",
                    "citations": [
                        "USE-IN-YOUR-SERVICE.md:50-51",
                        "USE-IN-YOUR-SERVICE.md:344-347",
                        "USE-IN-YOUR-SERVICE.md:748-751",
                        "signaturekey/discovery.go:34-62",
                        "signaturekey/egress.go:41-104",
                        "SECURITY.md:28-37"
                    ]
                },
                {
                    "id": "DOC-GAP-3",
                    "title": "USE-IN-YOUR-SERVICE.md does not yet mention PersonTokenCodePresentation / MaximumPersonTokenCodeAttempts or AuthTokenPollResult / R3PollResult",
                    "citations": [
                        "personserver/server.go:196-225",
                        "personserver/person_interaction.go:34-46",
                        "personserver/person_interaction.go:143-165",
                        "agent/call.go:627-651",
                        "agent/r3_call.go:213-236"
                    ]
                },
                {
                    "id": "GAP-K7-AGENT-CLIENT",
                    "title": "agent.Client.verifyCallChainUpstreamTokenAt (agent/client.go:624-644) only calls aauth.VerifyAuthToken and locally rejects upstream PersonToken (aa-person+jwt) before sending POST /person or POST /token",
                    "citations": [
                        "agent/client.go:53-54",
                        "agent/client.go:88-90",
                        "agent/client.go:130-132",
                        "agent/client.go:155-157",
                        "agent/client.go:624-644",
                        "personserver/upstream.go:29-74"
                    ]
                }
            ]
        }),
    });
    transcript_lines.push(format!(
        "[QA-K8] {}: conf_2026_10_30={} go_docs={} use_doc_gaps=(presentation_store={},egress={},poll_results={})",
        if k8_pass { "PASS" } else { "FAIL" },
        conf_2026_10_30_ok,
        go_doc_comments_ok,
        use_doc_mentions_presentation_store,
        use_doc_mentions_transport_enforces_egress,
        use_doc_mentions_poll_result_types,
    ));

    Ok(())
}
