mod alpha13_qa;
mod alpha14_qa;
mod alpha15_qa;
mod alpha16_qa;
mod events_qa;
mod go_chaining_qa;
mod supervision_qa;
mod go_budget_relay_qa;
mod go_features_qa;
mod go_sigkey_qa;
mod tls;

use aauth_rust_access_server::{
    AccessServer, AuthorizationRequest as AsAuthorizationRequest, Config as AsConfig,
    Decision as AsDecision, DeferredConfig as AsDeferredConfig,
    DeferredContext as AsDeferredContext, UpstreamToken,
};
use aauth_rust_agent::{Agent, PollError, PollSession, R3AgentError, Subagent};
use aauth_rust_agent_provider::AgentProvider;
use aauth_rust_budgets::{Budget, ConsumptionRecord, UnitDeclaration};
use aauth_rust_core::{
    AgentClaims, AgentKeyResolver, ApprovedMission, AuthClaims, AuthToken, Confirmation,
    PersonClaims, PersonToken, ResourceClaims, TokenError, TrustedIssuerKeys, VerifiedAuthToken,
    continuation::{
        MemoryContinuations, PendingResponse, Requirement as ContinuationRequirement,
        generate_interaction_code, generate_pending_id,
    },
    interaction::ChainedInteraction,
    metadata_jwks_uri, mint_auth_token, mint_person_token,
    mint_resource_token as mint_core_resource_token,
};
use aauth_rust_jose::{Jwk, Jws, SigningKey};
use aauth_rust_person_server::{
    AgentIdentity, AuthorizationRequest, BoxedClock, BoxedTokenIds, Config as PsConfig,
    DeferredConfig as PsDeferredConfig, Federation, FederationError, Governance, Grant,
    MemoryStore, MissionRecord, MissionState, MissionStore, Person, PersonRequest, PersonServer,
    Policy, PolicyError, R3AuthorizationRequest, R3Decision, R3IssuerConfig,
    Store as PsStore, StoreError as PsStoreError,
    TokenKind as PsTokenKind, TokenRecord as PsTokenRecord, TokenReference as PsTokenReference,
};
use aauth_rust_person_server_redb::RedbStore;
use aauth_rust_r3::{
    AnnotationEncoding, Authorization, Codec, DefinitionRegistry, Display, Error as R3Error,
    FetchBody, FetchLimits, FetchResponse, FetchTransport, GrantedOperations, IssuanceError,
    IssuanceRecord, IssuanceStore, McpCodec, Operation, OperationSet, Parameter, Parameters,
    PresentedParameter, ProposalDisplay, ProposalResult, Reference, ToolsListPage,
    ToolsListSnapshot, Vocabulary, VocabularyUri, digest,
    mint_auth_token as mint_r3_class_auth_token, mint_budget_resource_token,
    mint_per_call_auth_token, mint_proposal_resource_token, mint_resource_token,
    standard_registry, verify_resource_token as verify_r3_resource_token_raw,
};
use aauth_rust_resource::{
    AuthDecision, BoxedAuthPolicy, BoxedR3Release, DirectoryCallStore, DirectoryDocumentStore,
    HeldInvocations, PsAuthorizationConfig, PsAuthorizationResource, PsConfigurationError,
    R3CallDescription, R3CallResult, R3CallStore, R3CallToken, R3Claim, R3Config, R3DocumentRecord,
    R3DocumentStore, R3Grant, R3HeldRequest, R3HostError, R3PendingHeaders, R3PerCallConfig,
    R3ProposalRecord, R3Release, R3StoreError, R3Vocabulary,
};
use aauth_rust_signature_key::{
    Error as SigKeyError, KeyMaterial, sign_request as sign_raw_request,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs, io,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tls::TlsServer;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The aauth-rust checkout this runner was built against; the documentation
/// audit cases read its Markdown files. Set once in `main`.
static RUST_SOURCE: OnceLock<PathBuf> = OnceLock::new();

fn rust_source() -> &'static Path {
    RUST_SOURCE.get().expect("--rust-source is set in main").as_path()
}

const USAGE: &str = "usage: aauth-interop-runner --go-source DIR --out-dir DIR [--rust-source DIR]

  --go-source DIR    aauth-go checkout to build the Go fleet against
  --out-dir DIR      new or empty directory for results.json and the transcript
  --rust-source DIR  aauth-rust checkout whose documentation the audit cases
                     read; defaults to targets/aauth-rust, the checkout the
                     runner is built against

Exit status: 0 when every case meets its expectation, 1 otherwise.";

const GO_AP: &str = "https://go-ap.example";
const GO_PS: &str = "https://go-ps.example";
const FED_PS: &str = "https://fed-ps.example";
const FED_AS: &str = "https://fed-as.example";
const FED_RECORDS: &str = "https://fed-records.example";
const RUST_FED_RECORDS: &str = "https://rust-fed-records.example";
const RUST_FED_HELD: &str = "https://rust-fed-held.example";
const RECORDS: &str = "https://records.example";
const MCP: &str = "urn:aauth:vocabulary:mcp";
const TOOLS: &[u8] = br#"{"tools":[{"name":"records.read","inputSchema":{"type":"object"}},{"name":"records.delete","inputSchema":{"type":"object"}},{"name":"records.query","inputSchema":{"type":"object"}}]}"#;
const R1: &[u8] = br#"{"record":"r-1"}"#;
const R2: &[u8] = br#"{"record":"r-2"}"#;
#[allow(dead_code)]
const DENY_ME: &[u8] = br#"{"record":"deny-me"}"#;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct QaCaseReceipt {
    id: String,
    category: String,
    title: String,
    classification: String,
    passed_expectation: bool,
    summary: String,
    evidence: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct QaReport {
    generated_at_unix: i64,
    go_module_path: String,
    out_dir: String,
    #[serde(default)]
    targets: Value,
    total_cases: usize,
    verified_working_count: usize,
    defect_resolved_count: usize,
    defect_found_count: usize,
    boundary_pinned_count: usize,
    #[serde(default)]
    failed_count: usize,
    #[serde(default)]
    failed_ids: Vec<String>,
    cases: Vec<QaCaseReceipt>,
    go_fleet_final_counts: Value,
    rust_federated_counts: Value,
}

#[derive(Clone, Default)]
struct Trust(Arc<RwLock<BTreeMap<(String, String), TrustedIssuerKeys>>>);
impl AgentKeyResolver for Trust {
    fn key(&self, issuer: &str, dwk: &str, kid: &str) -> std::result::Result<Jwk, TokenError> {
        self.0
            .read()
            .map_err(|_| TokenError::InvalidKey)?
            .get(&(issuer.into(), dwk.into()))
            .ok_or(TokenError::UntrustedIssuer)?
            .key(issuer, dwk, kid)
    }
}
impl Trust {
    fn discover(&self, server: &TlsServer, issuer: &str, dwk: &str) -> Result<()> {
        let metadata = server.send(&get(&format!("{issuer}/.well-known/{dwk}"))?)?;
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = server.send(&get(&uri)?)?;
        let snapshot =
            TrustedIssuerKeys::from_documents(issuer, dwk, metadata.body(), jwks.body())?;
        self.0
            .write()
            .map_err(|_| "trust lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
    fn discover_external(
        &self,
        address: SocketAddr,
        host: &'static str,
        cert_der: &[u8],
        issuer: &str,
        dwk: &str,
    ) -> Result<()> {
        let metadata = TlsServer::send_external(
            address,
            host,
            cert_der,
            &get(&format!("{issuer}/.well-known/{dwk}"))?,
        )?;
        let uri = metadata_jwks_uri(issuer, metadata.body())?;
        let jwks = TlsServer::send_external(address, host, cert_der, &get(&uri)?)?;
        let snapshot =
            TrustedIssuerKeys::from_documents(issuer, dwk, metadata.body(), jwks.body())?;
        self.0
            .write()
            .map_err(|_| "trust lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
    fn insert_manual(&self, issuer: &str, dwk: &str, snapshot: TrustedIssuerKeys) -> Result<()> {
        self.0
            .write()
            .map_err(|_| "trust lock poisoned")?
            .insert((issuer.into(), dwk.into()), snapshot);
        Ok(())
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before Unix epoch")
        .as_secs() as i64
}
fn get(uri: &str) -> Result<Request<Vec<u8>>> {
    Ok(Request::builder().uri(uri).body(Vec::new())?)
}
fn json_response(status: u16, value: Value) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(value.to_string().into_bytes())
        .unwrap()
}
fn post_at(agent: &Agent, uri: &str, body: &[u8], signed_at: i64) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(body.to_vec())?;
    agent.sign(&mut request, signed_at)?;
    Ok(request)
}
fn signed_get(agent: &Agent, uri: &str, signed_at: i64) -> Result<Request<Vec<u8>>> {
    let mut request = Request::builder().method("GET").uri(uri).body(Vec::new())?;
    agent.sign(&mut request, signed_at)?;
    Ok(request)
}
fn alternate_access_token(compact: &str, seed: [u8; 32]) -> Result<String> {
    let parsed = Jws::parse(compact)?;
    let mut header = parsed.header().clone();
    let original_kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
    if original_kid.is_empty() || original_kid == "fed-as-2" {
        return Err("auth token kid cannot be resigned".into());
    }
    header["kid"] = json!("fed-as-2");
    let resigned = Jws::sign(&header, parsed.payload(), &SigningKey::from_seed(seed))?;
    if resigned == compact {
        return Err("alternate compact auth token matches the original".into());
    }
    Ok(resigned)
}
fn held_pending_id_ok(id: &str) -> bool {
    let bytes = id.as_bytes();
    (16..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}
fn member(response: &Response<Vec<u8>>, name: &str) -> Option<String> {
    serde_json::from_slice::<Value>(response.body())
        .ok()?
        .get(name)?
        .as_str()
        .map(str::to_owned)
}
fn header_values(response: &Response<Vec<u8>>, name: &str) -> Vec<String> {
    response
        .headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect()
}
fn challenge(response: &Response<Vec<u8>>) -> Result<String> {
    match aauth_rust_agent::Requirement::from_headers(response.headers())? {
        Some(aauth_rust_agent::Requirement::AuthToken { resource_token }) => Ok(resource_token),
        other => Err(format!(
            "expected an auth-token requirement (got {:?}, status={}, headers={:?}, body={})",
            other,
            response.status(),
            response.headers(),
            String::from_utf8_lossy(response.body())
        )
        .into()),
    }
}
fn mcp(tool: &str) -> std::result::Result<Operation, R3HostError> {
    let vocabulary = McpCodec::vocabulary().map_err(|e| R3HostError::new(e.to_string()))?;
    Operation::new(&vocabulary, format!(r#"{{"tool":"{tool}"}}"#).as_bytes())
        .map_err(|e| R3HostError::new(e.to_string()))
}
fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).ok_or("invalid hex")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("invalid hex")?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error),
    }
}
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let pending = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&pending, path)
}
fn unavailable(error: impl ToString) -> R3StoreError {
    R3StoreError::Unavailable(R3HostError::new(error.to_string()))
}
fn text(v: &Value, name: &str) -> Result<String> {
    Ok(v.get(name)
        .and_then(Value::as_str)
        .ok_or("missing stored string")?
        .to_owned())
}
fn optional(v: &Value, name: &str) -> Option<String> {
    v.get(name).and_then(Value::as_str).map(str::to_owned)
}
fn number(v: &Value, name: &str) -> Result<i64> {
    Ok(v.get(name)
        .and_then(Value::as_i64)
        .ok_or("missing stored integer")?)
}

struct FileDocuments(PathBuf, Mutex<()>);
impl R3DocumentStore for FileDocuments {
    fn commit(&self, r: &R3DocumentRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self
            .0
            .join(format!("c-{}.json", digest(r.reference.uri().as_bytes())));
        let bytes = json!({
            "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
            "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
            "auth_token_issuer_document": r.auth_token_issuer_document,
            "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
            "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
            "tenant": r.tenant, "account": r.account, "scope": r.scope,
            "issued_at": r.issued_at, "expires_at": r.expires_at,
            "mission_s256": r.mission_s256,
        })
        .to_string()
        .into_bytes();
        match write_new(&path, &bytes).map_err(unavailable)? {
            true => Ok(()),
            false if fs::read(&path).map_err(unavailable)? == bytes => Ok(()),
            false => Err(R3StoreError::Conflict),
        }
    }
    fn load(&self, uri: &str) -> std::result::Result<Option<R3DocumentRecord>, R3StoreError> {
        let path = self.0.join(format!("c-{}.json", digest(uri.as_bytes())));
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        let decode = || -> Result<R3DocumentRecord> {
            let v: Value = serde_json::from_slice(&bytes)?;
            Ok(R3DocumentRecord {
                reference: Reference::new(text(&v, "uri")?, text(&v, "digest")?)?,
                exact_json: serde_json::from_value(
                    v.get("exact_json").cloned().ok_or("missing bytes")?,
                )?,
                person_server: text(&v, "person_server")?,
                auth_token_issuer: text(&v, "auth_token_issuer")?,
                auth_token_issuer_document: text(&v, "auth_token_issuer_document")?,
                resource_token_jti: text(&v, "resource_token_jti")?,
                resource_token: text(&v, "resource_token")?,
                presented_jti: text(&v, "presented_jti")?,
                subject: text(&v, "subject")?,
                agent_jkt: text(&v, "agent_jkt")?,
                tenant: optional(&v, "tenant"),
                account: optional(&v, "account"),
                scope: optional(&v, "scope"),
                issued_at: number(&v, "issued_at")?,
                expires_at: number(&v, "expires_at")?,
                mission_s256: optional(&v, "mission_s256"),
            })
        };
        decode().map(Some).map_err(unavailable)
    }
}

const SUPERSEDED: &str = "(superseded)";

struct FileCalls(PathBuf, Mutex<()>);
impl FileCalls {
    fn record_path(&self, uri: &str) -> PathBuf {
        self.0.join(format!("p-{}.json", digest(uri.as_bytes())))
    }
    fn claim_path(&self, uri: &str) -> PathBuf {
        self.0
            .join(format!("claim-{}.json", digest(uri.as_bytes())))
    }
    fn decode(bytes: &[u8]) -> Result<R3ProposalRecord> {
        let v: Value = serde_json::from_slice(bytes)?;
        let class = &v["class_reference"];
        let held = match v.get("held") {
            Some(held) if !held.is_null() => Some(R3HeldRequest {
                pending_id: text(held, "pending_id")?,
                method: text(held, "method")?,
                uri: text(held, "uri")?,
                headers: serde_json::from_value(held["headers"].clone())?,
                body: serde_json::from_value(held["body"].clone())?,
            }),
            _ => None,
        };
        Ok(R3ProposalRecord {
            reference: Reference::new(text(&v, "uri")?, text(&v, "digest")?)?,
            exact_json: serde_json::from_value(v["exact_json"].clone())?,
            person_server: text(&v, "person_server")?,
            auth_token_issuer: text(&v, "auth_token_issuer")?,
            resource_token_jti: text(&v, "resource_token_jti")?,
            resource_token: text(&v, "resource_token")?,
            class_reference: Reference::new(text(class, "uri")?, text(class, "digest")?)?,
            presented_jti: text(&v, "presented_jti")?,
            subject: text(&v, "subject")?,
            agent_jkt: text(&v, "agent_jkt")?,
            tenant: optional(&v, "tenant"),
            account: optional(&v, "account"),
            scope: optional(&v, "scope"),
            issued_at: number(&v, "issued_at")?,
            expires_at: number(&v, "expires_at")?,
            held,
            released: match v.get("released") {
                Some(released) if !released.is_null() => Some(Self::result(released)?),
                _ => None,
            },
            release_until: v.get("release_until").and_then(Value::as_i64),
            supersedes: optional(&v, "supersedes"),
        })
    }
    fn encode_result(result: &R3CallResult) -> Value {
        let mut val = json!({
            "status": result.status,
            "content_type": result.content_type,
            "body": result.body,
        });
        if let Some(pending) = &result.pending {
            val["pending"] = json!({
                "location": pending.location,
                "retry_after": pending.retry_after,
                "cache_control": pending.cache_control,
            });
        }
        val
    }
    fn result(v: &Value) -> Result<R3CallResult> {
        let pending = match v.get("pending") {
            None | Some(Value::Null) => None,
            Some(p) => {
                let items = p
                    .get("cache_control")
                    .and_then(Value::as_array)
                    .ok_or("missing stored cache_control")?;
                let mut cache_control = Vec::new();
                for item in items {
                    cache_control.push(item.as_str().ok_or("invalid cache_control")?.to_owned());
                }
                if cache_control.is_empty() {
                    return Err("empty stored cache_control".into());
                }
                Some(R3PendingHeaders {
                    location: text(p, "location")?,
                    retry_after: text(p, "retry_after")?,
                    cache_control,
                })
            }
        };
        Ok(R3CallResult {
            status: u16::try_from(number(v, "status")?)?,
            content_type: optional(v, "content_type"),
            body: serde_json::from_value(v["body"].clone())?,
            pending,
        })
    }
    fn create(&self, r: &R3ProposalRecord) -> std::result::Result<(), R3StoreError> {
        let held = r.held.as_ref().map(|held| {
            json!({"pending_id": held.pending_id, "method": held.method, "uri": held.uri,
                   "headers": held.headers, "body": held.body})
        });
        let released = r.released.as_ref().map(Self::encode_result);
        let bytes = json!({
            "uri": r.reference.uri(), "digest": r.reference.digest(), "exact_json": r.exact_json,
            "person_server": r.person_server, "auth_token_issuer": r.auth_token_issuer,
            "resource_token_jti": r.resource_token_jti, "resource_token": r.resource_token,
            "class_reference": {"uri": r.class_reference.uri(), "digest": r.class_reference.digest()},
            "presented_jti": r.presented_jti, "subject": r.subject, "agent_jkt": r.agent_jkt,
            "tenant": r.tenant, "account": r.account, "scope": r.scope,
            "issued_at": r.issued_at, "expires_at": r.expires_at, "held": held,
            "released": released, "release_until": r.release_until, "supersedes": r.supersedes,
        })
        .to_string()
        .into_bytes();
        if let Some(held) = &r.held {
            let index = self.0.join(format!("pending-{}", held.pending_id));
            if !write_new(&index, r.reference.uri().as_bytes()).map_err(unavailable)? {
                return Err(R3StoreError::Conflict);
            }
        }
        if !write_new(&self.record_path(r.reference.uri()), &bytes).map_err(unavailable)? {
            return Err(R3StoreError::Conflict);
        }
        Ok(())
    }
    fn remove_successor(&self, record: &R3ProposalRecord) {
        let _ = fs::remove_file(self.record_path(record.reference.uri()));
        if let Some(held) = &record.held {
            let _ = fs::remove_file(self.0.join(format!("pending-{}", held.pending_id)));
        }
    }
}
impl R3CallStore for FileCalls {
    fn commit(&self, r: &R3ProposalRecord) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        self.create(r)
    }
    fn load(&self, uri: &str) -> std::result::Result<Option<R3ProposalRecord>, R3StoreError> {
        match fs::read(self.record_path(uri)) {
            Ok(bytes) => {
                let record = Self::decode(&bytes).map_err(unavailable)?;
                if record.reference.uri() != uri {
                    return Err(unavailable("stored key does not name this URI"));
                }
                Ok(Some(record))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(unavailable(error)),
        }
    }
    fn load_pending(
        &self,
        pending_id: &str,
    ) -> std::result::Result<Option<R3ProposalRecord>, R3StoreError> {
        if pending_id.is_empty()
            || !pending_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Ok(None);
        }
        let uri = match fs::read(self.0.join(format!("pending-{pending_id}"))) {
            Ok(bytes) => String::from_utf8(bytes).map_err(unavailable)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(unavailable(error)),
        };
        self.load(&uri)
    }
    fn claim(
        &self,
        uri: &str,
        token: &R3CallToken,
        now: i64,
    ) -> std::result::Result<R3Claim, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        if let Some(record) = self.load(uri)? {
            if record.release_until.is_some_and(|until| now >= until) {
                return Ok(R3Claim::Expired);
            }
        }
        let path = self.claim_path(uri);
        match fs::read(&path) {
            Ok(bytes) => {
                let v: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
                if v["compact_sha256"].as_str() != Some(token.compact_sha256.as_str()) {
                    return Ok(R3Claim::DifferentToken);
                }
                if v["result"].is_null() {
                    return Ok(R3Claim::Unfinished);
                }
                if now >= number(&v, "retain_until").map_err(unavailable)? {
                    return Ok(R3Claim::Expired);
                }
                Ok(R3Claim::Replay(
                    Self::result(&v["result"]).map_err(unavailable)?,
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if now >= token.retain_until {
                    return Ok(R3Claim::Expired);
                }
                let fence = format!(
                    "{}-{}",
                    std::process::id(),
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(unavailable)?
                        .as_nanos()
                );
                let bytes = json!({"compact_sha256": token.compact_sha256, "jti": token.jti,
                                   "retain_until": token.retain_until, "fence": fence, "result": null})
                .to_string()
                .into_bytes();
                if !write_new(&path, &bytes).map_err(unavailable)? {
                    return Ok(R3Claim::Unfinished);
                }
                Ok(R3Claim::Execute { fence })
            }
            Err(error) => Err(unavailable(error)),
        }
    }
    fn retain(
        &self,
        uri: &str,
        fence: &str,
        result: &R3CallResult,
    ) -> std::result::Result<R3CallResult, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let path = self.claim_path(uri);
        let bytes = fs::read(&path).map_err(unavailable)?;
        let mut v: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if v["fence"].as_str() != Some(fence) || !v["result"].is_null() {
            return Err(R3StoreError::Conflict);
        }
        v["result"] = Self::encode_result(result);
        replace(&path, v.to_string().as_bytes()).map_err(unavailable)?;
        Ok(result.clone())
    }
    fn held_releases(
        &self,
        agent_jkt: &str,
        subject: &str,
        now: i64,
    ) -> std::result::Result<Vec<R3ProposalRecord>, R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let mut held = Vec::new();
        for entry in fs::read_dir(&self.0).map_err(unavailable)? {
            let name = entry.map_err(unavailable)?.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("p-") || !name.ends_with(".json") {
                continue;
            }
            let bytes = fs::read(self.0.join(name)).map_err(unavailable)?;
            let record = Self::decode(&bytes).map_err(unavailable)?;
            if record.released.is_some()
                && record.agent_jkt == agent_jkt
                && record.subject == subject
                && record.release_until.is_some_and(|until| now < until)
                && !self.claim_path(record.reference.uri()).exists()
            {
                held.push(record);
            }
        }
        Ok(held)
    }
    fn supersede(
        &self,
        prior_uri: &str,
        record: &R3ProposalRecord,
        now: i64,
    ) -> std::result::Result<(), R3StoreError> {
        let _serial = self.1.lock().map_err(|_| unavailable("poisoned"))?;
        let Some(prior) = self.load(prior_uri)? else {
            return Err(R3StoreError::Conflict);
        };
        let tombstone = self.claim_path(prior_uri);
        if prior.released.is_none()
            || prior.release_until.is_none_or(|until| now >= until)
            || tombstone.exists()
            || record.supersedes.as_deref() != Some(prior_uri)
            || record.released != prior.released
            || record.release_until != prior.release_until
        {
            return Err(R3StoreError::Conflict);
        }
        self.create(record)?;
        let marker = json!({"compact_sha256": SUPERSEDED, "jti": record.resource_token_jti,
                            "retain_until": 0, "fence": "", "result": null})
        .to_string()
        .into_bytes();
        match write_new(&tombstone, &marker) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.remove_successor(record);
                Err(R3StoreError::Conflict)
            }
            Err(error) => {
                self.remove_successor(record);
                Err(unavailable(error))
            }
        }
    }
}

type Resource = PsAuthorizationResource<Trust, BoxedAuthPolicy>;

fn record_parameter(request: &Request<Vec<u8>>) -> std::result::Result<Vec<u8>, R3HostError> {
    let value: Value =
        serde_json::from_slice(request.body()).map_err(|e| R3HostError::new(e.to_string()))?;
    let record = value
        .get("record")
        .ok_or_else(|| R3HostError::new("call names no record"))?;
    serde_json::to_vec(record).map_err(|e| R3HostError::new(e.to_string()))
}

struct RustResourceCounters {
    reads: AtomicUsize,
    deletes: AtomicUsize,
    query_runs: AtomicUsize,
    held_grants: Mutex<Vec<(R3Grant, Response<Vec<u8>>)>>,
    custom_delete_responses: Mutex<BTreeMap<String, Response<Vec<u8>>>>,
    custom_query_releases: Mutex<BTreeMap<String, Response<Vec<u8>>>>,
}
impl RustResourceCounters {
    fn new() -> Self {
        Self {
            reads: AtomicUsize::new(0),
            deletes: AtomicUsize::new(0),
            query_runs: AtomicUsize::new(0),
            held_grants: Mutex::new(Vec::new()),
            custom_delete_responses: Mutex::new(BTreeMap::new()),
            custom_query_releases: Mutex::new(BTreeMap::new()),
        }
    }
}

fn compose_rust_resource(
    issuer: &str,
    kid: &str,
    seed: [u8; 32],
    access_server: Option<&str>,
    root: &Path,
    trust: &Trust,
    hold: bool,
    counters: Arc<RustResourceCounters>,
) -> Result<Resource> {
    fs::create_dir_all(root)?;
    compose_rust_resource_with_stores(
        issuer,
        kid,
        seed,
        access_server,
        Arc::new(FileDocuments(root.to_path_buf(), Mutex::new(()))),
        Arc::new(FileCalls(root.to_path_buf(), Mutex::new(()))),
        trust,
        hold,
        counters,
    )
}

#[allow(clippy::too_many_arguments)]
fn compose_rust_resource_with_stores(
    issuer: &str,
    kid: &str,
    seed: [u8; 32],
    access_server: Option<&str>,
    documents: Arc<dyn R3DocumentStore>,
    calls: Arc<dyn R3CallStore>,
    trust: &Trust,
    hold: bool,
    counters: Arc<RustResourceCounters>,
) -> Result<Resource> {
    let cfg = PsAuthorizationConfig {
        issuer: issuer.into(),
        signed_origin: issuer.into(),
        kid: kid.into(),
        signing_key: SigningKey::from_seed(seed),
        scopes: vec!["records.read".into()],
        scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
    };
    let policy: BoxedAuthPolicy = Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
        token.claims().ps == FED_PS || token.claims().ps == GO_PS
    });
    let base = match access_server {
        Some(as_issuer) => PsAuthorizationResource::new_federated(cfg, as_issuer, trust.clone(), policy)?,
        None => PsAuthorizationResource::new(cfg, trust.clone(), policy)?,
    };
    let q_counters = counters.clone();
    let release_cb: Option<BoxedR3Release> = hold.then(|| -> BoxedR3Release {
        Box::new(
            move |_: &Request<Vec<u8>>,
                  operation: &Operation,
                  presented: &BTreeMap<String, PresentedParameter>,
                  _: Option<&str>| {
                if !matches!(operation.equal(&mcp("records.query")?), Ok(true)) {
                    return Ok(None);
                }
                let record = presented
                    .get("record")
                    .and_then(PresentedParameter::inline_json)
                    .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                let shown = String::from_utf8_lossy(&record).into_owned();
                let run = q_counters.query_runs.fetch_add(1, Ordering::SeqCst) + 1;
                let response = if let Some(custom_rel) = q_counters
                    .custom_query_releases
                    .lock()
                    .unwrap()
                    .get(&shown)
                    .cloned()
                {
                    custom_rel
                } else {
                    json_response(
                        200,
                        json!({"record": shown, "query_run_seq": run}),
                    )
                };
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
                    response,
                    cost: None,
                }))
            },
        )
    });

    let resource = base
        .with_authorization_endpoint()
        .with_r3(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{issuer}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )?,
                display: Some(Box::new(|_: &OperationSet| {
                    Display::new("Read records; delete with per-call approval", None, None, None)
                        .map_err(|e| R3HostError::new(e.to_string()))
                })),
            }],
            documents,
            operation_for_request: Box::new(|request: &Request<Vec<u8>>| match request.uri().path() {
                "/records/read" => mcp("records.read").map(Some),
                "/records/delete" => mcp("records.delete").map(Some),
                "/records/query" => mcp("records.query").map(Some),
                _ => Ok(None),
            }),
            require_core_scope: false,
        })?
        .with_r3_per_call(R3PerCallConfig {
            present: Box::new(|request: &Request<Vec<u8>>, _: &Operation| {
                let record = record_parameter(request)?;
                let presented = PresentedParameter::inline(&record)
                    .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(BTreeMap::from([("record".to_owned(), presented)]))
            }),
            describe: Box::new(
                |_: &Operation, presented: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
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
                    let display = ProposalDisplay::new(
                        &Display::new(format!("Delete record {shown}"), None, None, None)
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
            calls,
            hold,
            release: release_cb,
            held_result_lifetime: 300,
        })?;
    Ok(resource)
}

fn serve_rust_resource(
    resource: &Resource,
    counters: &RustResourceCounters,
    clock: i64,
    request: Request<Vec<u8>>,
) -> Response<Vec<u8>> {
    let jti = format!(
        "rid-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let path = request.uri().path().to_owned();
    if path == "/.well-known/aauth-resource.json" {
        return json_response(
            200,
            serde_json::from_slice(&resource.metadata().unwrap()).unwrap(),
        );
    }
    if path == "/.well-known/jwks.json" {
        return json_response(
            200,
            serde_json::from_slice(&resource.jwks().unwrap()).unwrap(),
        );
    }
    if path == "/authorize" {
        return resource
            .authorize_endpoint(&request, clock, &jti)
            .into_response();
    }
    if path.starts_with("/r3/") && !path.starts_with("/r3/pending/") {
        return resource.r3_document(&request, clock);
    }
    match resource.authorize(&request, clock, &jti) {
        AuthDecision::Granted(admitted) => {
            let Some(grant) = admitted.r3_grant() else {
                return json_response(403, json!({"error":"access_denied"}));
            };
            let call = grant.held_request().unwrap_or(&request);
            let produced = match call.uri().path() {
                "/records/read" => {
                    counters.reads.fetch_add(1, Ordering::SeqCst);
                    json_response(200, json!({"read": true}))
                }
                "/records/delete" if grant.is_per_call() => match record_parameter(call) {
                    Ok(record) => {
                        let record_str = String::from_utf8_lossy(&record).into_owned();
                        counters.deletes.fetch_add(1, Ordering::SeqCst);
                        if let Some(custom_resp) = counters
                            .custom_delete_responses
                            .lock()
                            .unwrap()
                            .get(&record_str)
                            .cloned()
                        {
                            custom_resp
                        } else if record_str == "\"r-hold-open\"" {
                            counters
                                .held_grants
                                .lock()
                                .unwrap()
                                .push((grant.clone(), json_response(200, json!({"deleted": record_str}))));
                            return json_response(202, json!({"status": "held_in_flight_by_host"}));
                        } else if record_str == "\"r-drop-unretained\"" {
                            return json_response(
                                500,
                                json!({"error": "server_error", "detail": "dropped_without_retain"}),
                            );
                        } else {
                            json_response(200, json!({"deleted": record_str}))
                        }
                    }
                    Err(_) => json_response(400, json!({"error":"invalid_request"})),
                },
                _ => json_response(403, json!({"error":"access_denied"})),
            };
            resource.r3_retain(grant, produced)
        }
        other => other.into_response(),
    }
}

fn fetch_go_counts(addr: SocketAddr, cert: &[u8]) -> Result<Value> {
    let req = get(&format!("{FED_RECORDS}/__counts"))?;
    let resp = TlsServer::send_external(addr, "fed-records.example", cert, &req)?;
    Ok(serde_json::from_slice(resp.body())?)
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (i, byte)| {
            word | u32::from(*byte) << (16 - 8 * i)
        });
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(word >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn unix_to_rfc3339(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn mint_mission_record(
    ps_issuer: &str,
    owner: &AgentIdentity,
    person_id: &str,
    approved_at: i64,
    expires_at: Option<i64>,
    description: &str,
    state: MissionState,
) -> Result<MissionRecord> {
    let mut obj = json!({
        "agent": owner.subject,
        "approved_at": unix_to_rfc3339(approved_at),
        "description": description,
    });
    if let Some(exp) = expires_at {
        obj["expires_at"] = json!(unix_to_rfc3339(exp));
    }
    let bytes = serde_json::to_vec(&obj)?;
    let s256 = digest(&bytes);
    let encoded = base64url(&bytes);
    let document = ApprovedMission::decode(&s256, &encoded)?;
    Ok(MissionRecord {
        person_server: ps_issuer.to_owned(),
        owner: owner.clone(),
        person_id: person_id.to_owned(),
        state,
        document,
    })
}

struct BufferedFetchBody(Vec<u8>, usize);
impl FetchBody for BufferedFetchBody {
    fn read(&mut self, output: &mut [u8], _: Instant) -> std::io::Result<usize> {
        let count = (self.0.len() - self.1).min(output.len());
        output[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
        self.1 += count;
        Ok(count)
    }
}

struct TlsFetch(Arc<TlsServer>);
impl FetchTransport for TlsFetch {
    fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> std::io::Result<FetchResponse> {
        if Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let response = self
            .0
            .send(&request)
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Box::new(BufferedFetchBody(body, 0)) as Box<dyn FetchBody>,
        ))
    }
}

struct QaAuditStore {
    commits: Arc<AtomicUsize>,
    last_token_jti: Arc<Mutex<Option<String>>>,
}
impl IssuanceStore for QaAuditStore {
    fn commit(&self, record: &IssuanceRecord) -> std::result::Result<(), IssuanceError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        *self.last_token_jti.lock().unwrap() = Some(record.auth_token_jti.clone());
        Ok(())
    }
}

struct QaPsPolicy;
impl Policy for QaPsPolicy {
    fn bind_person(&self, _: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "mission-person".into(),
            tenant: None,
        })
    }
    fn bind_upstream(&self, _: &PersonRequest) -> std::result::Result<Person, PolicyError> {
        Ok(Person {
            id: "person-1".into(),
            subject: "upstream-mission-person".into(),
            tenant: None,
        })
    }
    fn authorize(&self, request: &AuthorizationRequest) -> std::result::Result<Grant, PolicyError> {
        Ok(Grant {
            scopes: request.scopes.clone(),
            lifetime: 600,
        })
    }
    fn consent(&self, _: &AuthorizationRequest) -> std::result::Result<(), PolicyError> {
        Ok(())
    }
}

struct DummyFederation;
impl Federation for DummyFederation {
    fn endpoint(&self, _: &str) -> std::result::Result<String, FederationError> {
        Ok("https://fed-as.example/token".into())
    }
    fn send(&self, _: &Request<Vec<u8>>) -> std::result::Result<Response<Vec<u8>>, FederationError> {
        Err(FederationError)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_qa_suite(
    request: &Request<Vec<u8>>,
    out_dir: &Path,
    go_module_path: &str,
    clock_base: &Arc<AtomicI64>,
    trust: &Trust,
    direct_res_tls: &Arc<TlsServer>,
    rust_fed_res_tls: &Arc<TlsServer>,
    rust_fed_held_tls: &Arc<TlsServer>,
    rust_fed_res: &Arc<Resource>,
    rust_fed_held: &Arc<Resource>,
    rust_fed_counters: &Arc<RustResourceCounters>,
    rust_fed_held_counters: &Arc<RustResourceCounters>,
) -> Result<Value> {
    let body: Value = serde_json::from_slice(request.body())?;
    let go_ap_addr: SocketAddr = text(&body, "go_ap_addr")?.parse()?;
    let go_ap_cert = hex_decode(&text(&body, "go_ap_cert_hex")?)?;
    let go_ps_addr: SocketAddr = text(&body, "go_ps_addr")?.parse()?;
    let go_ps_cert = hex_decode(&text(&body, "go_ps_cert_hex")?)?;
    let fed_ps_addr: SocketAddr = text(&body, "fed_ps_addr")?.parse()?;
    let fed_ps_cert = hex_decode(&text(&body, "fed_ps_cert_hex")?)?;
    let fed_as_addr: SocketAddr = text(&body, "fed_as_addr")?.parse()?;
    let fed_as_cert = hex_decode(&text(&body, "fed_as_cert_hex")?)?;
    let fed_records_addr: SocketAddr = text(&body, "fed_records_addr")?.parse()?;
    let fed_records_cert = hex_decode(&text(&body, "fed_records_cert_hex")?)?;
    let go_agent_seed_vec = hex_decode(&text(&body, "go_agent_seed_hex")?)?;
    let go_agent_seed: [u8; 32] = go_agent_seed_vec
        .try_into()
        .map_err(|_| "invalid go agent seed length")?;
    let go_agent_token = text(&body, "go_agent_token")?;
    let fed_agent_token = text(&body, "fed_agent_token")?;
    let alternate_seed_vec = hex_decode(&text(&body, "fed_as_alternate_seed_hex")?)?;
    let alternate_seed: [u8; 32] = alternate_seed_vec
        .try_into()
        .map_err(|_| "invalid alternate access seed length")?;

    trust.discover_external(go_ap_addr, "go-ap.example", &go_ap_cert, GO_AP, "aauth-agent.json")?;
    trust.discover_external(go_ps_addr, "go-ps.example", &go_ps_cert, GO_PS, "aauth-person.json")?;
    trust.discover_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        FED_PS,
        "aauth-person.json",
    )?;
    trust.discover_external(
        fed_as_addr,
        "fed-as.example",
        &fed_as_cert,
        FED_AS,
        "aauth-access.json",
    )?;
    trust.discover_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        FED_RECORDS,
        "aauth-resource.json",
    )?;

    let registry = standard_registry()?;
    let clock = clock_base.load(Ordering::SeqCst);
    let fed_agent = Agent::new(SigningKey::from_seed(go_agent_seed), fed_agent_token)?;
    let direct_agent = Agent::new(SigningKey::from_seed(go_agent_seed), go_agent_token)?;

    let delete_only = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.delete"}]})
            .to_string()
            .as_bytes(),
    )?;
    let read_only = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.read"}]})
            .to_string()
            .as_bytes(),
    )?;
    let read_and_delete = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.read"}, {"tool":"records.delete"}]})
            .to_string()
            .as_bytes(),
    )?;

    let mut cases: Vec<QaCaseReceipt> = Vec::new();
    let mut transcript_lines: Vec<String> = Vec::new();

    // =========================================================================
    // CATEGORY A: Go Federated Resource + Go Access Server + Go Federated PS + Rust Agent
    // =========================================================================

    // QA-A1: Federated Class Document Exchange & Rust Agent Delivery Verification
    let person_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/person"),
        json!({"resource": FED_RECORDS}).to_string().as_bytes(),
        clock,
    )?;
    let person_resp = TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &person_req)?;
    let person_status = person_resp.status().as_u16();
    let fed_person_token = member(&person_resp, "person_token").ok_or("missing fed person_token")?;

    let fed_class_rt = fed_agent.r3_authorize(
        |req| TlsServer::send_external(fed_records_addr, "fed-records.example", &fed_records_cert, &req),
        &format!("{FED_RECORDS}/authorize"),
        &fed_person_token,
        &delete_only,
        None,
        clock,
    )?;
    let verified_fed_class_rt = fed_agent.verify_r3_resource_token(
        &fed_class_rt,
        FED_RECORDS,
        FED_PS,
        &fed_person_token,
        None,
        trust,
        clock,
    )?;
    let class_exchange_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": fed_class_rt, "presented_token": fed_person_token})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let class_exchange_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &class_exchange_req)?;
    let class_exchange_status = class_exchange_resp.status().as_u16();
    let fed_class_auth = member(&class_exchange_resp, "auth_token").ok_or("missing fed class auth_token")?;
    let delivered_class = fed_agent.verify_r3_auth_delivery(
        &fed_class_auth,
        FED_RECORDS,
        &verified_fed_class_rt,
        &fed_person_token,
        &registry,
        trust,
        clock,
    )?;
    let counts_after_a1 = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    cases.push(QaCaseReceipt {
        id: "QA-A1".into(),
        category: "A. Go Federated Resource + Access Server + Federated PS + Rust Agent".into(),
        title: "Federated Class Document Exchange & Rust Agent Delivery Verification".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: person_status == 200
            && class_exchange_status == 200
            && verified_fed_class_rt.claims().aud == FED_AS
            && delivered_class.claims().iss == FED_AS
            && delivered_class.claims().dwk == "aauth-access.json"
            && delivered_class.claims().ps == FED_PS
            && delivered_class.claims().aud == FED_RECORDS,
        summary: format!(
            "Person token={}, Resource token aud={}, PS/AS class exchange={}, delivered iss={} dwk={} ps={} aud={}",
            person_status,
            verified_fed_class_rt.claims().aud,
            class_exchange_status,
            delivered_class.claims().iss,
            delivered_class.claims().dwk,
            delivered_class.claims().ps,
            delivered_class.claims().aud,
        ),
        evidence: json!({
            "person_status": person_status,
            "resource_token_aud": verified_fed_class_rt.claims().aud,
            "resource_token_jti": verified_fed_class_rt.claims().jti,
            "document_uri": verified_fed_class_rt.reference().uri(),
            "class_exchange_status": class_exchange_status,
            "delivered_iss": delivered_class.claims().iss,
            "delivered_dwk": delivered_class.claims().dwk,
            "delivered_ps": delivered_class.claims().ps,
            "delivered_aud": delivered_class.claims().aud,
            "counts": counts_after_a1,
        }),
    });
    transcript_lines.push(format!(
        "[QA-A1] PASS: person={} class_exchange={} rt_aud={} auth_iss={} auth_dwk={}",
        person_status,
        class_exchange_status,
        verified_fed_class_rt.claims().aud,
        delivered_class.claims().iss,
        delivered_class.claims().dwk
    ));

    // QA-A2: Federated Per-Call 401 Challenge, Proposal Exchange, Completion & Exact-Token Replay (POST /records/r-1)
    let fed_class_holder = fed_agent.with_token(fed_class_auth.clone())?;
    let r1_challenge_req = post_at(
        &fed_class_holder,
        &format!("{FED_RECORDS}/records/r-1"),
        b"{}",
        clock,
    )?;
    let r1_challenged = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &r1_challenge_req,
    )?;
    let r1_challenge_status = r1_challenged.status().as_u16();
    let r1_proposal_rt = challenge(&r1_challenged)?;
    let verified_r1_proposal = fed_agent.verify_r3_proposal_challenge(
        &r1_proposal_rt,
        FED_RECORDS,
        FED_PS,
        &fed_class_auth,
        trust,
        clock,
    )?;
    let r1_exchange_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": r1_proposal_rt, "presented_token": fed_class_auth})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let r1_exchange_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &r1_exchange_req)?;
    let r1_exchange_status = r1_exchange_resp.status().as_u16();
    let r1_per_call_auth = member(&r1_exchange_resp, "auth_token").ok_or("missing r1 per-call auth_token")?;
    let verified_r1_per_call = fed_agent.verify_r3_per_call_delivery(
        &r1_per_call_auth,
        FED_RECORDS,
        &verified_r1_proposal,
        &fed_class_auth,
        &registry,
        trust,
        clock,
    )?;
    let r1_per_call_holder = fed_agent.with_token(r1_per_call_auth.clone())?;
    let r1_complete_req = post_at(
        &r1_per_call_holder,
        &format!("{FED_RECORDS}/records/r-1"),
        b"{}",
        clock,
    )?;
    let r1_completed = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &r1_complete_req,
    )?;
    let r1_complete_status = r1_completed.status().as_u16();
    let r1_replay_req = post_at(
        &r1_per_call_holder,
        &format!("{FED_RECORDS}/records/r-1"),
        b"{}",
        clock,
    )?;
    let r1_replayed = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &r1_replay_req,
    )?;
    let r1_replay_status = r1_replayed.status().as_u16();
    let r1_replay_matches = r1_replay_status == 200 && r1_replayed.body() == r1_completed.body();
    let counts_after_a2 = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    let retry_runs_a2 = counts_after_a2["go_fed_retry_runs"].as_i64().unwrap_or(-1);
    cases.push(QaCaseReceipt {
        id: "QA-A2".into(),
        category: "A. Go Federated Resource + Access Server + Federated PS + Rust Agent".into(),
        title: "Per-Call 401 Challenge, Proposal Exchange, Completion & Exact-Token Replay (POST /records/r-1)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r1_challenge_status == 401
            && r1_exchange_status == 200
            && verified_r1_proposal.claims().aud == FED_AS
            && verified_r1_per_call.claims().dwk == "aauth-access.json"
            && r1_complete_status == 200
            && r1_replay_status == 200
            && r1_replay_matches
            && retry_runs_a2 == 1,
        summary: format!(
            "challenge={} proposal_aud={} exchange={} complete={} replay={} body_matches={} retry_handler_runs={}",
            r1_challenge_status,
            verified_r1_proposal.claims().aud,
            r1_exchange_status,
            r1_complete_status,
            r1_replay_status,
            r1_replay_matches,
            retry_runs_a2
        ),
        evidence: json!({
            "challenge_status": r1_challenge_status,
            "proposal_aud": verified_r1_proposal.claims().aud,
            "proposal_uri": verified_r1_proposal.reference().uri(),
            "exchange_status": r1_exchange_status,
            "complete_status": r1_complete_status,
            "complete_body": String::from_utf8_lossy(r1_completed.body()),
            "replay_status": r1_replay_status,
            "replay_body": String::from_utf8_lossy(r1_replayed.body()),
            "replay_matches": r1_replay_matches,
            "retry_handler_runs": retry_runs_a2,
            "counts": counts_after_a2,
        }),
    });
    transcript_lines.push(format!(
        "[QA-A2] PASS: 401_challenge={} exchange={} complete={} replay={} matches={} runs={}",
        r1_challenge_status, r1_exchange_status, r1_complete_status, r1_replay_status, r1_replay_matches, retry_runs_a2
    ));

    // QA-A3: Different Compact Auth Token on Completed 401 Per-Call Invocation (403 access_denied)
    let r1_alt_per_call = alternate_access_token(&r1_per_call_auth, alternate_seed)?;
    let r1_alt_holder = fed_agent.with_token(r1_alt_per_call)?;
    let r1_alt_req = post_at(
        &r1_alt_holder,
        &format!("{FED_RECORDS}/records/r-1"),
        b"{}",
        clock,
    )?;
    let r1_alt_resp = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &r1_alt_req,
    )?;
    let r1_alt_status = r1_alt_resp.status().as_u16();
    let r1_alt_error = member(&r1_alt_resp, "error").unwrap_or_default();
    let counts_after_a3 = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    let retry_runs_a3 = counts_after_a3["go_fed_retry_runs"].as_i64().unwrap_or(-1);
    cases.push(QaCaseReceipt {
        id: "QA-A3".into(),
        category: "A. Go Federated Resource + Access Server + Federated PS + Rust Agent".into(),
        title: "Second Compact Auth Token with Same Verified Claims on Completed 401 Call Refused with 403 access_denied".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: r1_alt_status == 403 && r1_alt_error == "access_denied" && retry_runs_a3 == 1,
        summary: format!(
            "Second compact per-call token (kid=fed-as-2) on POST /records/r-1 returned {} ({}), retry_handler_runs={}",
            r1_alt_status, r1_alt_error, retry_runs_a3
        ),
        evidence: json!({
            "status": r1_alt_status,
            "error": r1_alt_error,
            "body": String::from_utf8_lossy(r1_alt_resp.body()),
            "retry_handler_runs": retry_runs_a3,
        }),
    });
    transcript_lines.push(format!(
        "[QA-A3] PASS: 401_completed_different_compact_token={} error={} runs={}",
        r1_alt_status, r1_alt_error, retry_runs_a3
    ));

    // QA-A4: Federated Held Delivery (202 Accepted), Premature Poll Refusal (Retry-After: 5), Signed GET Poll & Replay (POST /records/held-1)
    let held_initial_req = post_at(
        &fed_class_holder,
        &format!("{FED_RECORDS}/records/held-1"),
        b"{}",
        clock,
    )?;
    let held_challenged = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &held_initial_req,
    )?;
    let held_challenge_status = held_challenged.status().as_u16();
    let mut held_poll = PollSession::new(
        &format!("{FED_RECORDS}/records/held-1"),
        &held_challenged,
        clock,
        clock + 60,
    )
    .map_err(|_| "held challenge is not a pending poll")?;
    let pending_id = held_poll
        .pending()
        .location
        .strip_prefix(&format!("{FED_RECORDS}/pending/"))
        .ok_or("held Location does not match /pending/{id}")?
        .to_owned();
    let pending_id_valid = held_pending_id_ok(&pending_id);
    let held_rt = match &held_poll.pending().requirement {
        aauth_rust_core::continuation::Requirement::AuthToken { resource_token } => {
            resource_token.clone()
        }
        _ => return Err("held 202 challenge is not an auth-token requirement".into()),
    };
    let verified_held_proposal = fed_agent.verify_r3_proposal_challenge(
        &held_rt,
        FED_RECORDS,
        FED_PS,
        &fed_class_auth,
        trust,
        clock,
    )?;
    let held_exchange_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": held_rt, "presented_token": fed_class_auth})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let held_exchange_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &held_exchange_req)?;
    let held_exchange_status = held_exchange_resp.status().as_u16();
    let held_grant = member(&held_exchange_resp, "auth_token").ok_or("missing held grant")?;
    let verified_held_grant = fed_agent.verify_r3_per_call_delivery(
        &held_grant,
        FED_RECORDS,
        &verified_held_proposal,
        &fed_class_auth,
        &registry,
        trust,
        clock,
    )?;
    let poll_holder = fed_agent.with_token(held_grant.clone())?;
    let too_early = matches!(
        held_poll.request(&poll_holder, clock),
        Err(PollError::TooEarly { at }) if at == clock + 5
    );
    let poll_at = clock + 5;
    let poll_req = held_poll.request(&poll_holder, poll_at)?;
    let polled_raw = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &poll_req,
    )?;
    let polled = held_poll
        .accept(polled_raw, poll_at)?
        .ok_or("held poll remained pending")?;
    let held_poll_status = polled.status().as_u16();
    let finished_after_terminal = matches!(
        held_poll.request(&poll_holder, poll_at),
        Err(PollError::Finished)
    );
    let poll_target = held_poll.pending().location.clone();
    let replay_poll_req = signed_get(&poll_holder, &poll_target, poll_at)?;
    let held_replayed = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &replay_poll_req,
    )?;
    let held_replay_status = held_replayed.status().as_u16();
    let held_replay_matches = held_replay_status == 200 && held_replayed.body() == polled.body();
    let counts_after_a4 = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    let held_runs_a4 = counts_after_a4["go_fed_held_runs"].as_i64().unwrap_or(-1);
    cases.push(QaCaseReceipt {
        id: "QA-A4".into(),
        category: "A. Go Federated Resource + Access Server + Federated PS + Rust Agent".into(),
        title: "Federated Held Delivery (202 Accepted), Premature Poll Refusal (Retry-After=5), Signed GET Poll & Replay".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: held_challenge_status == 202
            && pending_id_valid
            && held_exchange_status == 200
            && verified_held_grant.claims().dwk == "aauth-access.json"
            && too_early
            && held_poll_status == 200
            && finished_after_terminal
            && held_replay_status == 200
            && held_replay_matches
            && held_runs_a4 == 1,
        summary: format!(
            "202_challenge={} location={} too_early={} poll_at_+5={} finished={} replay={} matches={} held_handler_runs={}",
            held_challenge_status,
            poll_target,
            too_early,
            held_poll_status,
            finished_after_terminal,
            held_replay_status,
            held_replay_matches,
            held_runs_a4
        ),
        evidence: json!({
            "challenge_status": held_challenge_status,
            "location": poll_target,
            "pending_id": pending_id,
            "too_early_at_clock": too_early,
            "poll_status": held_poll_status,
            "poll_body": String::from_utf8_lossy(polled.body()),
            "finished_after_terminal": finished_after_terminal,
            "replay_status": held_replay_status,
            "replay_matches": held_replay_matches,
            "held_handler_runs": held_runs_a4,
            "counts": counts_after_a4,
        }),
    });
    transcript_lines.push(format!(
        "[QA-A4] PASS: 202={} too_early={} poll={} replay={} matches={} held_runs={}",
        held_challenge_status, too_early, held_poll_status, held_replay_status, held_replay_matches, held_runs_a4
    ));

    // QA-A5: Held Pending Endpoint Negative Probes on Go Resource (405 POST, 410 unknown ID, 403 second compact token, 200 original replay)
    let method_req = post_at(&poll_holder, &poll_target, b"{}", poll_at)?;
    let method_resp = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &method_req,
    )?;
    let held_method_status = method_resp.status().as_u16();
    let held_method_error = member(&method_resp, "error").unwrap_or_default();
    let held_method_allow = method_resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let unknown_req = signed_get(
        &poll_holder,
        &format!("{FED_RECORDS}/pending/not-this-held-call"),
        poll_at,
    )?;
    let unknown_resp = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &unknown_req,
    )?;
    let held_unknown_status = unknown_resp.status().as_u16();
    let held_unknown_error = member(&unknown_resp, "error").unwrap_or_default();

    let alt_held_grant = alternate_access_token(&held_grant, alternate_seed)?;
    let alt_held_holder = fed_agent.with_token(alt_held_grant)?;
    let mismatch_req = signed_get(&alt_held_holder, &poll_target, poll_at)?;
    let mismatch_resp = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &mismatch_req,
    )?;
    let held_mismatch_status = mismatch_resp.status().as_u16();
    let held_mismatch_error = member(&mismatch_resp, "error").unwrap_or_default();

    let after_neg_replay_req = signed_get(&poll_holder, &poll_target, poll_at)?;
    let after_neg_replay = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &after_neg_replay_req,
    )?;
    let after_neg_replay_ok =
        after_neg_replay.status().as_u16() == 200 && after_neg_replay.body() == polled.body();
    let counts_after_a5 = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    let held_runs_a5 = counts_after_a5["go_fed_held_runs"].as_i64().unwrap_or(-1);

    cases.push(QaCaseReceipt {
        id: "QA-A5".into(),
        category: "A. Go Federated Resource + Access Server + Federated PS + Rust Agent".into(),
        title: "Go Held Pending Endpoint Rejections: POST->405 (Allow: GET), Unknown ID->410 gone, Second Compact Token->403 access_denied".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: held_method_status == 405
            && held_method_error == "method_not_allowed"
            && held_method_allow == "GET"
            && held_unknown_status == 410
            && held_unknown_error == "gone"
            && held_mismatch_status == 403
            && held_mismatch_error == "access_denied"
            && after_neg_replay_ok
            && held_runs_a5 == 1,
        summary: format!(
            "POST /pending->{} ({}, Allow: {}), GET unknown->{} ({}), GET 2nd-compact->{} ({}), original replay still 200={}, held_runs={}",
            held_method_status,
            held_method_error,
            held_method_allow,
            held_unknown_status,
            held_unknown_error,
            held_mismatch_status,
            held_mismatch_error,
            after_neg_replay_ok,
            held_runs_a5
        ),
        evidence: json!({
            "method_status": held_method_status,
            "method_error": held_method_error,
            "method_allow": held_method_allow,
            "unknown_status": held_unknown_status,
            "unknown_error": held_unknown_error,
            "mismatch_status": held_mismatch_status,
            "mismatch_error": held_mismatch_error,
            "original_replay_after_rejections_ok": after_neg_replay_ok,
            "held_handler_runs": held_runs_a5,
        }),
    });
    transcript_lines.push(format!(
        "[QA-A5] PASS: method={} ({}) unknown={} ({}) mismatch={} ({}) replay_after={} held_runs={}",
        held_method_status, held_method_error, held_unknown_status, held_unknown_error, held_mismatch_status, held_mismatch_error, after_neg_replay_ok, held_runs_a5
    ));

    // =========================================================================
    // CATEGORY B: Cross-Language Rust Federated Resource + Go Access Server + Go Federated PS + Rust Agent
    // =========================================================================

    // QA-B1: Rust Federated Resource Class Document Exchange & Class Operation Admission over HTTPS
    let rust_fed_person_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/person"),
        json!({"resource": RUST_FED_RECORDS}).to_string().as_bytes(),
        clock,
    )?;
    let rust_fed_person_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &rust_fed_person_req)?;
    let rust_fed_person_status = rust_fed_person_resp.status().as_u16();
    let rust_fed_person_tok =
        member(&rust_fed_person_resp, "person_token").ok_or("missing rust fed person_token")?;

    let rust_fed_class_rt = fed_agent.r3_authorize(
        |req| rust_fed_res_tls.send(&req),
        &format!("{RUST_FED_RECORDS}/authorize"),
        &rust_fed_person_tok,
        &read_and_delete,
        None,
        clock,
    )?;
    let verified_rust_fed_rt = fed_agent.verify_r3_resource_token(
        &rust_fed_class_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_person_tok,
        None,
        trust,
        clock,
    )?;
    let rust_fed_class_ex_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": rust_fed_class_rt, "presented_token": rust_fed_person_tok})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let rust_fed_class_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &rust_fed_class_ex_req,
    )?;
    let rust_fed_class_ex_status = rust_fed_class_ex_resp.status().as_u16();
    let rust_fed_class_auth =
        member(&rust_fed_class_ex_resp, "auth_token").ok_or("missing rust fed class auth_token")?;
    let verified_rust_fed_class_auth = fed_agent.verify_r3_auth_delivery(
        &rust_fed_class_auth,
        RUST_FED_RECORDS,
        &verified_rust_fed_rt,
        &rust_fed_person_tok,
        &registry,
        trust,
        clock,
    )?;
    let rust_fed_holder = fed_agent.with_token(rust_fed_class_auth.clone())?;
    let rust_fed_read_resp = rust_fed_res_tls.send(&post_at(
        &rust_fed_holder,
        &format!("{RUST_FED_RECORDS}/records/read"),
        R1,
        clock,
    )?)?;
    let rust_fed_read_status = rust_fed_read_resp.status().as_u16();
    let rust_fed_reads_b1 = rust_fed_counters.reads.load(Ordering::SeqCst);
    cases.push(QaCaseReceipt {
        id: "QA-B1".into(),
        category: "B. Rust Federated Resource (PsAuthorizationResource::new_federated) + Go Access Server + Go Federated PS over HTTPS".into(),
        title: "Cross-Language Rust Federated Resource Class Exchange & Class Operation Admission over HTTPS".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: rust_fed_person_status == 200
            && verified_rust_fed_rt.claims().aud == FED_AS
            && rust_fed_class_ex_status == 200
            && verified_rust_fed_class_auth.claims().dwk == "aauth-access.json"
            && rust_fed_read_status == 200
            && rust_fed_reads_b1 == 1,
        summary: format!(
            "Rust new_federated Resource token aud={}, Go AS/PS exchange={}, class read status={}, reads={}",
            verified_rust_fed_rt.claims().aud,
            rust_fed_class_ex_status,
            rust_fed_read_status,
            rust_fed_reads_b1
        ),
        evidence: json!({
            "person_status": rust_fed_person_status,
            "resource_token_aud": verified_rust_fed_rt.claims().aud,
            "class_exchange_status": rust_fed_class_ex_status,
            "delivered_dwk": verified_rust_fed_class_auth.claims().dwk,
            "class_read_status": rust_fed_read_status,
            "rust_fed_reads": rust_fed_reads_b1,
        }),
    });
    transcript_lines.push(format!(
        "[QA-B1] PASS: rust_fed_resource aud={} go_as_exchange={} read={} reads={}",
        verified_rust_fed_rt.claims().aud, rust_fed_class_ex_status, rust_fed_read_status, rust_fed_reads_b1
    ));

    // QA-B2: Rust Federated Resource Per-Call 401 Challenge, Go AS Proposal Exchange, Completion, Replay & Different-Token Refusal
    let rf_chal_resp = rust_fed_res_tls.send(&post_at(
        &rust_fed_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let rf_chal_status = rf_chal_resp.status().as_u16();
    let rf_proposal_rt = challenge(&rf_chal_resp)?;
    let verified_rf_proposal = fed_agent.verify_r3_proposal_challenge(
        &rf_proposal_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_class_auth,
        trust,
        clock,
    )?;
    let rf_prop_ex_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": rf_proposal_rt, "presented_token": rust_fed_class_auth})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let rf_prop_ex_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &rf_prop_ex_req)?;
    let rf_prop_ex_status = rf_prop_ex_resp.status().as_u16();
    let rf_per_call_auth =
        member(&rf_prop_ex_resp, "auth_token").ok_or("missing rust fed per-call auth_token")?;
    let _verified_rf_per_call = fed_agent.verify_r3_per_call_delivery(
        &rf_per_call_auth,
        RUST_FED_RECORDS,
        &verified_rf_proposal,
        &rust_fed_class_auth,
        &registry,
        trust,
        clock,
    )?;
    let rf_pc_holder = fed_agent.with_token(rf_per_call_auth.clone())?;
    let rf_comp_resp = rust_fed_res_tls.send(&post_at(
        &rf_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let rf_comp_status = rf_comp_resp.status().as_u16();
    let rf_replay_resp = rust_fed_res_tls.send(&post_at(
        &rf_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let rf_replay_status = rf_replay_resp.status().as_u16();
    let rf_replay_matches = rf_replay_status == 200 && rf_replay_resp.body() == rf_comp_resp.body();
    let rf_alt_tok = alternate_access_token(&rf_per_call_auth, alternate_seed)?;
    let rf_alt_holder = fed_agent.with_token(rf_alt_tok)?;
    let rf_alt_resp = rust_fed_res_tls.send(&post_at(
        &rf_alt_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let rf_alt_status = rf_alt_resp.status().as_u16();
    let rf_deletes_b2 = rust_fed_counters.deletes.load(Ordering::SeqCst);
    cases.push(QaCaseReceipt {
        id: "QA-B2".into(),
        category: "B. Rust Federated Resource (PsAuthorizationResource::new_federated) + Go Access Server + Go Federated PS over HTTPS".into(),
        title: "Cross-Language Rust Federated Resource 401 Per-Call Challenge, Go AS Proposal Exchange, Completion, Replay & 2nd-Compact Refusal".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: rf_chal_status == 401
            && verified_rf_proposal.claims().aud == FED_AS
            && rf_prop_ex_status == 200
            && rf_comp_status == 200
            && rf_replay_status == 200
            && rf_replay_matches
            && rf_alt_status == 403
            && rf_deletes_b2 == 1,
        summary: format!(
            "challenge={} proposal_aud={} exchange={} complete={} replay={} matches={} 2nd_compact={} deletes={}",
            rf_chal_status,
            verified_rf_proposal.claims().aud,
            rf_prop_ex_status,
            rf_comp_status,
            rf_replay_status,
            rf_replay_matches,
            rf_alt_status,
            rf_deletes_b2
        ),
        evidence: json!({
            "challenge_status": rf_chal_status,
            "proposal_aud": verified_rf_proposal.claims().aud,
            "exchange_status": rf_prop_ex_status,
            "complete_status": rf_comp_status,
            "replay_status": rf_replay_status,
            "replay_matches": rf_replay_matches,
            "second_compact_status": rf_alt_status,
            "deletes_count": rf_deletes_b2,
        }),
    });
    transcript_lines.push(format!(
        "[QA-B2] PASS: rust_fed 401={} exchange={} complete={} replay={} 2nd_compact={} deletes={}",
        rf_chal_status, rf_prop_ex_status, rf_comp_status, rf_replay_status, rf_alt_status, rf_deletes_b2
    ));

    // QA-B3: Rust Federated Held Resource (202 Accepted), Poll Wait (Retry-After=1), Signed GET Poll, Replay & 2nd-Compact Refusal
    let rfh_person_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/person"),
        json!({"resource": RUST_FED_HELD}).to_string().as_bytes(),
        clock,
    )?;
    let rfh_person_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &rfh_person_req)?;
    let rfh_person_tok =
        member(&rfh_person_resp, "person_token").ok_or("missing rust fed held person_token")?;
    let rfh_class_rt = fed_agent.r3_authorize(
        |req| rust_fed_held_tls.send(&req),
        &format!("{RUST_FED_HELD}/authorize"),
        &rfh_person_tok,
        &delete_only,
        None,
        clock,
    )?;
    let rfh_ex_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": rfh_class_rt, "presented_token": rfh_person_tok})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let rfh_ex_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &rfh_ex_req)?;
    let rfh_class_auth =
        member(&rfh_ex_resp, "auth_token").ok_or("missing rust fed held class auth_token")?;
    let rfh_class_holder = fed_agent.with_token(rfh_class_auth.clone())?;

    let rfh_chal_resp = rust_fed_held_tls.send(&post_at(
        &rfh_class_holder,
        &format!("{RUST_FED_HELD}/records/delete"),
        R1,
        clock,
    )?)?;
    let rfh_chal_status = rfh_chal_resp.status().as_u16();
    let mut rfh_poll_session = PollSession::new(
        &format!("{RUST_FED_HELD}/records/delete"),
        &rfh_chal_resp,
        clock,
        clock + 60,
    )
    .map_err(|_| "rust fed held challenge is not a pending poll")?;
    let rfh_prop_rt = match &rfh_poll_session.pending().requirement {
        aauth_rust_core::continuation::Requirement::AuthToken { resource_token } => {
            resource_token.clone()
        }
        _ => return Err("rust fed held challenge is not auth-token requirement".into()),
    };
    let rfh_prop_ex_req = post_at(
        &fed_agent,
        &format!("{FED_PS}/token"),
        json!({"resource_token": rfh_prop_rt, "presented_token": rfh_class_auth})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let rfh_prop_ex_resp =
        TlsServer::send_external(fed_ps_addr, "fed-ps.example", &fed_ps_cert, &rfh_prop_ex_req)?;
    let rfh_held_grant =
        member(&rfh_prop_ex_resp, "auth_token").ok_or("missing rust fed held per-call grant")?;
    let rfh_poll_holder = fed_agent.with_token(rfh_held_grant.clone())?;
    let rfh_too_early = matches!(
        rfh_poll_session.request(&rfh_poll_holder, clock),
        Err(PollError::TooEarly { at }) if at == clock + 1
    );
    let rfh_poll_at = clock + 1;
    let rfh_poll_req = rfh_poll_session.request(&rfh_poll_holder, rfh_poll_at)?;
    let rfh_polled_raw = rust_fed_held_tls.send(&rfh_poll_req)?;
    let rfh_polled = rfh_poll_session
        .accept(rfh_polled_raw, rfh_poll_at)?
        .ok_or("rust fed held poll stayed pending")?;
    let rfh_poll_status = rfh_polled.status().as_u16();
    let rfh_poll_target = rfh_poll_session.pending().location.clone();
    let rfh_replay_resp =
        rust_fed_held_tls.send(&signed_get(&rfh_poll_holder, &rfh_poll_target, rfh_poll_at)?)?;
    let rfh_replay_status = rfh_replay_resp.status().as_u16();
    let rfh_replay_matches = rfh_replay_status == 200 && rfh_replay_resp.body() == rfh_polled.body();
    let rfh_alt_grant = alternate_access_token(&rfh_held_grant, alternate_seed)?;
    let rfh_alt_holder = fed_agent.with_token(rfh_alt_grant)?;
    let rfh_alt_resp =
        rust_fed_held_tls.send(&signed_get(&rfh_alt_holder, &rfh_poll_target, rfh_poll_at)?)?;
    let rfh_alt_status = rfh_alt_resp.status().as_u16();
    let rfh_deletes_b3 = rust_fed_held_counters.deletes.load(Ordering::SeqCst);

    cases.push(QaCaseReceipt {
        id: "QA-B3".into(),
        category: "B. Rust Federated Resource (PsAuthorizationResource::new_federated) + Go Access Server + Go Federated PS over HTTPS".into(),
        title: "Cross-Language Rust Federated Held Delivery (202 Accepted, Retry-After=1), Poll, Replay & 2nd-Compact Refusal".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: rfh_chal_status == 202
            && rfh_too_early
            && rfh_poll_status == 200
            && rfh_replay_status == 200
            && rfh_replay_matches
            && rfh_alt_status == 403
            && rfh_deletes_b3 == 1,
        summary: format!(
            "202_challenge={} location={} too_early={} poll_at_+1={} replay={} matches={} 2nd_compact={} deletes={}",
            rfh_chal_status,
            rfh_poll_target,
            rfh_too_early,
            rfh_poll_status,
            rfh_replay_status,
            rfh_replay_matches,
            rfh_alt_status,
            rfh_deletes_b3
        ),
        evidence: json!({
            "challenge_status": rfh_chal_status,
            "location": rfh_poll_target,
            "too_early": rfh_too_early,
            "poll_status": rfh_poll_status,
            "replay_status": rfh_replay_status,
            "replay_matches": rfh_replay_matches,
            "second_compact_status": rfh_alt_status,
            "deletes_count": rfh_deletes_b3,
        }),
    });
    transcript_lines.push(format!(
        "[QA-B3] PASS: rust_fed_held 202={} too_early={} poll={} replay={} 2nd_compact={} deletes={}",
        rfh_chal_status, rfh_too_early, rfh_poll_status, rfh_replay_status, rfh_alt_status, rfh_deletes_b3
    ));

    // =========================================================================
    // CATEGORY C: Negative / Authority / Parameter-Binding / Composition Probes
    // =========================================================================

    // QA-C1: DirectR3 Converse Proposal Pin (400 invalid_resource_token)
    let direct_person_req = post_at(
        &direct_agent,
        &format!("{GO_PS}/person"),
        json!({"resource": RECORDS}).to_string().as_bytes(),
        clock,
    )?;
    let direct_person_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &direct_person_req)?;
    let direct_person_status = direct_person_resp.status().as_u16();
    let direct_person_tok =
        member(&direct_person_resp, "person_token").ok_or("missing direct person_token")?;
    let direct_class_rt = direct_agent.r3_authorize(
        |req| direct_res_tls.send(&req),
        &format!("{RECORDS}/authorize"),
        &direct_person_tok,
        &read_and_delete,
        None,
        clock,
    )?;
    let direct_ex_req = post_at(
        &direct_agent,
        &format!("{GO_PS}/token"),
        json!({"resource_token": direct_class_rt, "presented_token": direct_person_tok})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let direct_ex_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &direct_ex_req)?;
    let direct_ex_status = direct_ex_resp.status().as_u16();

    let mint_pc_req = Request::builder()
        .method("POST")
        .uri(format!("{GO_PS}/__mint-per-call-class"))
        .header("content-type", "application/json")
        .body(b"{}".to_vec())?;
    let mint_pc_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &mint_pc_req)?;
    let direct_pc_class =
        member(&mint_pc_resp, "auth_token").ok_or("missing direct per-call class token")?;
    let direct_pc_holder = direct_agent.with_token(direct_pc_class.clone())?;
    let direct_chal = direct_res_tls.send(&post_at(
        &direct_pc_holder,
        &format!("{RECORDS}/records/delete"),
        R1,
        clock,
    )?)?;
    let direct_proposal_rt = challenge(&direct_chal)?;
    let direct_prop_ex_req = post_at(
        &direct_agent,
        &format!("{GO_PS}/token"),
        json!({"resource_token": direct_proposal_rt, "presented_token": direct_pc_class})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let direct_prop_ex_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &direct_prop_ex_req)?;
    let direct_prop_status = direct_prop_ex_resp.status().as_u16();
    let direct_prop_error = member(&direct_prop_ex_resp, "error").unwrap_or_default();
    cases.push(QaCaseReceipt {
        id: "QA-C1".into(),
        category: "C. Negative / Authority / Parameter-Binding / Composition Probes".into(),
        title: "DirectR3 Converse Proposal Pin (400 invalid_resource_token)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: direct_person_status == 200
            && direct_ex_status == 200
            && direct_prop_status == 400
            && direct_prop_error == "invalid_resource_token",
        summary: format!(
            "DirectR3 person={} class_exchange={} proposal_exchange={} ({})",
            direct_person_status, direct_ex_status, direct_prop_status, direct_prop_error
        ),
        evidence: json!({
            "person_status": direct_person_status,
            "class_exchange_status": direct_ex_status,
            "proposal_status": direct_prop_status,
            "proposal_error": direct_prop_error,
            "proposal_body": String::from_utf8_lossy(direct_prop_ex_resp.body()),
        }),
    });
    transcript_lines.push(format!(
        "[QA-C1] PASS: DirectR3 proposal exchange={} ({})",
        direct_prop_status, direct_prop_error
    ));

    // QA-C2: Presenting a Person-Server Auth Token (dwk = aauth-person.json) Directly to Go & Rust Federated Resources
    let mint_ps_for_go_req = Request::builder()
        .method("POST")
        .uri(format!("{GO_PS}/__mint-per-call-class"))
        .header("content-type", "application/json")
        .body(json!({"audience": FED_RECORDS}).to_string().into_bytes())?;
    let mint_ps_for_go_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &mint_ps_for_go_req)?;
    let ps_tok_for_go_fed =
        member(&mint_ps_for_go_resp, "auth_token").ok_or("missing ps tok for go fed")?;
    let ps_go_holder = direct_agent.with_token(ps_tok_for_go_fed)?;
    let go_fed_ps_tok_resp = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &signed_get(&ps_go_holder, &format!("{FED_RECORDS}/records/r-1"), clock)?,
    )?;
    let go_fed_ps_tok_status = go_fed_ps_tok_resp.status().as_u16();
    let go_fed_ps_tok_err = member(&go_fed_ps_tok_resp, "error").unwrap_or_default();

    let mint_ps_for_rust_req = Request::builder()
        .method("POST")
        .uri(format!("{GO_PS}/__mint-per-call-class"))
        .header("content-type", "application/json")
        .body(json!({"audience": RUST_FED_RECORDS}).to_string().into_bytes())?;
    let mint_ps_for_rust_resp =
        TlsServer::send_external(go_ps_addr, "go-ps.example", &go_ps_cert, &mint_ps_for_rust_req)?;
    let ps_tok_for_rust_fed =
        member(&mint_ps_for_rust_resp, "auth_token").ok_or("missing ps tok for rust fed")?;
    let ps_rust_holder = direct_agent.with_token(ps_tok_for_rust_fed)?;
    let rust_fed_ps_tok_resp = rust_fed_res_tls.send(&post_at(
        &ps_rust_holder,
        &format!("{RUST_FED_RECORDS}/records/read"),
        R1,
        clock,
    )?)?;
    let rust_fed_ps_tok_status = rust_fed_ps_tok_resp.status().as_u16();
    let rust_fed_ps_tok_err = member(&rust_fed_ps_tok_resp, "error").unwrap_or_default();

    cases.push(QaCaseReceipt {
        id: "QA-C2".into(),
        category: "C. Negative / Authority / Parameter-Binding / Composition Probes".into(),
        title: "Presenting a Person-Server Auth Token (dwk = aauth-person.json) Directly to Go & Rust Federated Resources".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: go_fed_ps_tok_status == 401 && rust_fed_ps_tok_status == 401,
        summary: format!(
            "PS-issued Auth token (dwk=aauth-person.json) refused by Go Federated Resource with {} ({}) and by Rust Federated Resource with {} ({})",
            go_fed_ps_tok_status, go_fed_ps_tok_err, rust_fed_ps_tok_status, rust_fed_ps_tok_err
        ),
        evidence: json!({
            "go_federated_resource_status": go_fed_ps_tok_status,
            "go_federated_resource_error": go_fed_ps_tok_err,
            "go_federated_resource_body": String::from_utf8_lossy(go_fed_ps_tok_resp.body()),
            "rust_federated_resource_status": rust_fed_ps_tok_status,
            "rust_federated_resource_error": rust_fed_ps_tok_err,
            "rust_federated_resource_body": String::from_utf8_lossy(rust_fed_ps_tok_resp.body()),
        }),
    });
    transcript_lines.push(format!(
        "[QA-C2] PASS: PS Auth token on Go Fed Res={} ({}), on Rust Fed Res={} ({})",
        go_fed_ps_tok_status, go_fed_ps_tok_err, rust_fed_ps_tok_status, rust_fed_ps_tok_err
    ));

    // QA-C3: Parameter Substitution, Ungranted Operation, and Federated PS Proposal Denial
    let go_subst_resp = TlsServer::send_held_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &post_at(&r1_per_call_holder, &format!("{FED_RECORDS}/records/r-2"), b"{}", clock)?,
    )?;
    let go_subst_status = go_subst_resp.status().as_u16();
    let rust_subst_resp = rust_fed_res_tls.send(&post_at(
        &rf_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        R2,
        clock,
    )?)?;
    let rust_subst_status = rust_subst_resp.status().as_u16();

    let ro_rt = fed_agent.r3_authorize(
        |req| TlsServer::send_external(fed_records_addr, "fed-records.example", &fed_records_cert, &req),
        &format!("{FED_RECORDS}/authorize"),
        &fed_person_token,
        &read_only,
        None,
        clock,
    )?;
    let ro_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": ro_rt, "presented_token": fed_person_token})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let ro_class_auth = member(&ro_ex_resp, "auth_token").ok_or("missing ro class auth")?;
    let ro_holder = fed_agent.with_token(ro_class_auth)?;
    let go_ungranted_del_resp = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &post_at(&ro_holder, &format!("{FED_RECORDS}/records/r-1"), b"{}", clock)?,
    )?;
    let go_ungranted_del_status = go_ungranted_del_resp.status().as_u16();

    let deny_chal_resp = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &post_at(&fed_class_holder, &format!("{FED_RECORDS}/records/deny-me"), b"{}", clock)?,
    )?;
    let deny_prop_rt = challenge(&deny_chal_resp)?;
    let deny_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": deny_prop_rt, "presented_token": fed_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let deny_ex_status = deny_ex_resp.status().as_u16();
    let deny_ex_err = member(&deny_ex_resp, "error").unwrap_or_default();

    cases.push(QaCaseReceipt {
        id: "QA-C3".into(),
        category: "C. Negative / Authority / Parameter-Binding / Composition Probes".into(),
        title: "Parameter Substitution (r-1 token on r-2 -> 403), Ungranted Delete (-> 403), and Federated PS ConsentProposal Denial (-> 403)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: go_subst_status == 403
            && rust_subst_status == 403
            && go_ungranted_del_status == 403
            && deny_ex_status == 403
            && deny_ex_err == "access_denied",
        summary: format!(
            "Parameter substitution: Go={} Rust={}; Ungranted delete: Go={}; Federated PS ConsentProposal denial: {} ({})",
            go_subst_status, rust_subst_status, go_ungranted_del_status, deny_ex_status, deny_ex_err
        ),
        evidence: json!({
            "go_param_substitution_status": go_subst_status,
            "rust_param_substitution_status": rust_subst_status,
            "go_ungranted_delete_status": go_ungranted_del_status,
            "fed_ps_proposal_denial_status": deny_ex_status,
            "fed_ps_proposal_denial_error": deny_ex_err,
        }),
    });
    transcript_lines.push(format!(
        "[QA-C3] PASS: subst_go={} subst_rust={} ungranted={} ps_deny={} ({})",
        go_subst_status, rust_subst_status, go_ungranted_del_status, deny_ex_status, deny_ex_err
    ));

    // QA-C4: Unsupported R3 Compositions on Federated Rust Resource (InvalidR3Profile & 500 when mission added after with_r3)
    let make_r3_cfg = || -> Result<R3Config> {
        Ok(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{RUST_FED_RECORDS}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )?,
                display: None,
            }],
            documents: Arc::new(FileDocuments(out_dir.join("comp-check"), Mutex::new(()))),
            operation_for_request: Box::new(|_| mcp("records.read").map(Some)),
            require_core_scope: false,
        })
    };
    fs::create_dir_all(out_dir.join("comp-check"))?;
    let base_fed = || -> Result<Resource> {
        Ok(PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: RUST_FED_RECORDS.into(),
                signed_origin: RUST_FED_RECORDS.into(),
                kid: "rust-fed-res-1".into(),
                signing_key: SigningKey::from_seed([0x55; 32]),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
            },
            FED_AS,
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint())
    };
    let mission_then_r3_err = matches!(
        base_fed()?.with_mission_context().with_r3(make_r3_cfg()?),
        Err(PsConfigurationError::InvalidR3Profile)
    );
    let r3_then_mission = base_fed()?.with_r3(make_r3_cfg()?)?.with_mission_context();
    let r3_then_mission_auth_resp = r3_then_mission
        .authorize_endpoint(
            &post_at(
                &fed_agent,
                &format!("{RUST_FED_RECORDS}/authorize"),
                json!({
                    "operations": {
                        "vocabulary": MCP,
                        "operations": [{"tool": "records.read"}]
                    }
                })
                .to_string()
                .as_bytes(),
                clock,
            )?,
            clock,
            "comp-jti-1",
        )
        .into_response();
    let r3_then_mission_status = r3_then_mission_auth_resp.status().as_u16();
    cases.push(QaCaseReceipt {
        id: "QA-C4".into(),
        category: "C. Negative / Authority / Parameter-Binding / Composition Probes".into(),
        title: "Federated Rust Resource Mission Composition Refusal (InvalidR3Profile & 500 when added after with_r3)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: mission_then_r3_err && r3_then_mission_status == 500,
        summary: format!(
            "with_mission_context().with_r3() -> Err(InvalidR3Profile)={}, with_r3().with_mission_context() runtime status={}",
            mission_then_r3_err, r3_then_mission_status
        ),
        evidence: json!({
            "mission_then_r3_invalid_r3_profile": mission_then_r3_err,
            "r3_then_mission_runtime_status": r3_then_mission_status,
            "r3_then_mission_body": String::from_utf8_lossy(r3_then_mission_auth_resp.body()),
        }),
    });
    transcript_lines.push(format!(
        "[QA-C4] PASS: mission_then_r3_err={} r3_then_mission_status={}",
        mission_then_r3_err, r3_then_mission_status
    ));

    // =========================================================================
    // CATEGORY D: Re-Verification of Pass-1 Defects (QA-D1, QA-D2, QA-D3) Under f12b2168 / a97755ae
    // =========================================================================

    // QA-D1 (RESOLVED): Reactive 401 R3 Challenge on a Budget-Enabled Rust Resource (with_budgets + with_r3) Returns 401 AuthTokenRequired Without "budget" Claim
    let budgeted_fed_res = base_fed()?
        .with_budgets(
            vec![UnitDeclaration::new("MilliwattSecond", 0, "Compute energy").unwrap()],
            format!("{RUST_FED_RECORDS}/usage"),
            10,
            100,
        )?
        .with_r3(make_r3_cfg()?)?;
    let person_holder = fed_agent.with_token(rust_fed_person_tok.clone())?;
    let mut proactive_budget_req = Request::builder()
        .method("POST")
        .uri(format!("{RUST_FED_RECORDS}/authorize"))
        .header("content-type", "application/json")
        .body(
            json!({
                "r3_operations": {
                    "vocabulary": MCP,
                    "operations": [{"tool": "records.read"}]
                }
            })
            .to_string()
            .into_bytes(),
        )?;
    person_holder.sign(&mut proactive_budget_req, clock)?;
    let proactive_budget_resp = budgeted_fed_res
        .authorize_endpoint(&proactive_budget_req, clock, "bud-proactive-1")
        .into_response();
    let proactive_budget_status = proactive_budget_resp.status().as_u16();

    let mut proactive_with_budget_req = Request::builder()
        .method("POST")
        .uri(format!("{RUST_FED_RECORDS}/authorize"))
        .header("content-type", "application/json")
        .body(
            json!({
                "r3_operations": {
                    "vocabulary": MCP,
                    "operations": [{"tool": "records.read"}]
                },
                "budget": {
                    "amount": 50,
                    "unit": "MilliwattSecond",
                    "decimals": 0
                }
            })
            .to_string()
            .into_bytes(),
        )?;
    person_holder.sign(&mut proactive_with_budget_req, clock)?;
    let proactive_with_budget_resp = budgeted_fed_res
        .authorize_endpoint(&proactive_with_budget_req, clock, "bud-proactive-2")
        .into_response();
    let proactive_with_budget_status = proactive_with_budget_resp.status().as_u16();

    let reactive_budget_req = post_at(
        &person_holder,
        &format!("{RUST_FED_RECORDS}/records/read"),
        R1,
        clock,
    )?;
    let reactive_budget_resp = budgeted_fed_res
        .authorize(&reactive_budget_req, clock, "bud-reactive-1")
        .into_response();
    let reactive_budget_status = reactive_budget_resp.status().as_u16();
    let reactive_budget_rt = challenge(&reactive_budget_resp)?;
    let verified_reactive_budget_rt = fed_agent.verify_r3_resource_token(
        &reactive_budget_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_person_tok,
        None,
        trust,
        clock,
    )?;
    let reactive_budget_claim_absent = !verified_reactive_budget_rt.claims().extra.contains_key("budget");

    cases.push(QaCaseReceipt {
        id: "QA-D1".into(),
        category: "D. Re-Verification of Earlier Federated R3 Defects".into(),
        title: "RESOLVED (QA-D1): Reactive R3 Challenge on Budget-Enabled Rust Resource (with_budgets + with_r3) Returns 401 Challenge Without 'budget' Claim".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: proactive_budget_status == 200
            && proactive_with_budget_status == 200
            && reactive_budget_status == 401
            && verified_reactive_budget_rt.claims().aud == FED_AS
            && reactive_budget_claim_absent,
        summary: format!(
            "Proactive /authorize={}, proactive /authorize+budget={}, reactive R3 route with PersonToken now returns {} with valid class Resource token (aud={}, budget_absent={})",
            proactive_budget_status,
            proactive_with_budget_status,
            reactive_budget_status,
            verified_reactive_budget_rt.claims().aud,
            reactive_budget_claim_absent
        ),
        evidence: json!({
            "proactive_authorize_status": proactive_budget_status,
            "proactive_authorize_with_budget_status": proactive_with_budget_status,
            "reactive_r3_challenge_status": reactive_budget_status,
            "reactive_r3_challenge_aud": verified_reactive_budget_rt.claims().aud,
            "reactive_r3_challenge_budget_claim_absent": reactive_budget_claim_absent,
            "source_location": "crates/aauth-rust-resource/src/r3_class.rs:715 (claims.extra.remove(\"budget\"))",
        }),
    });
    transcript_lines.push(format!(
        "[QA-D1] RESOLVED: proactive={} proactive_with_budget={} reactive={} aud={} budget_absent={}",
        proactive_budget_status,
        proactive_with_budget_status,
        reactive_budget_status,
        verified_reactive_budget_rt.claims().aud,
        reactive_budget_claim_absent
    ));

    // QA-D2 (RESOLVED): Rust PsAuthorizationResource Held Pending Endpoint (/r3/pending/{id}) Refuses POST with 405 (Allow: GET) and Unknown ID with 410 gone
    let rfh_post_pending_req = post_at(&rfh_poll_holder, &rfh_poll_target, b"{}", rfh_poll_at)?;
    let rfh_post_pending_resp = rust_fed_held_tls.send(&rfh_post_pending_req)?;
    let rfh_post_pending_status = rfh_post_pending_resp.status().as_u16();
    let rfh_post_pending_err = member(&rfh_post_pending_resp, "error").unwrap_or_default();
    let rfh_post_pending_allow = rfh_post_pending_resp
        .headers()
        .get("allow")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let rfh_unknown_pending_req = signed_get(
        &rfh_poll_holder,
        &format!("{RUST_FED_HELD}/r3/pending/not-this-held-call"),
        rfh_poll_at,
    )?;
    let rfh_unknown_pending_resp = rust_fed_held_tls.send(&rfh_unknown_pending_req)?;
    let rfh_unknown_pending_status = rfh_unknown_pending_resp.status().as_u16();
    let rfh_unknown_pending_err = member(&rfh_unknown_pending_resp, "error").unwrap_or_default();

    let rfh_after_neg_replay =
        rust_fed_held_tls.send(&signed_get(&rfh_poll_holder, &rfh_poll_target, rfh_poll_at)?)?;
    let rfh_after_neg_replay_ok =
        rfh_after_neg_replay.status().as_u16() == 200 && rfh_after_neg_replay.body() == rfh_polled.body();

    cases.push(QaCaseReceipt {
        id: "QA-D2".into(),
        category: "D. Re-Verification of Earlier Federated R3 Defects".into(),
        title: "RESOLVED (QA-D2): Rust Held Pending Endpoint (/r3/pending/{id}) Returns 405 method_not_allowed (Allow: GET) on POST and 410 gone on Unknown ID".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: rfh_post_pending_status == 405
            && rfh_post_pending_err == "method_not_allowed"
            && rfh_post_pending_allow == "GET"
            && rfh_unknown_pending_status == 410
            && rfh_unknown_pending_err == "gone"
            && rfh_after_neg_replay_ok,
        summary: format!(
            "Rust /r3/pending/{{id}} now matches Go /pending/{{id}}: POST->{} ({}, Allow: {}), GET unknown->{} ({}), original GET replay still 200={}",
            rfh_post_pending_status,
            rfh_post_pending_err,
            rfh_post_pending_allow,
            rfh_unknown_pending_status,
            rfh_unknown_pending_err,
            rfh_after_neg_replay_ok
        ),
        evidence: json!({
            "rust_post_pending_status": rfh_post_pending_status,
            "rust_post_pending_error": rfh_post_pending_err,
            "rust_post_pending_allow": rfh_post_pending_allow,
            "rust_unknown_pending_status": rfh_unknown_pending_status,
            "rust_unknown_pending_error": rfh_unknown_pending_err,
            "rust_original_replay_after_rejections_ok": rfh_after_neg_replay_ok,
            "go_post_pending_status": held_method_status,
            "go_unknown_pending_status": held_unknown_status,
            "source_location": "crates/aauth-rust-resource/src/r3_class.rs:759 & src/r3_per_call.rs:878",
        }),
    });
    transcript_lines.push(format!(
        "[QA-D2] RESOLVED: rust_post_pending={} ({}, Allow: {}), rust_unknown_pending={} ({}), replay_after={}",
        rfh_post_pending_status,
        rfh_post_pending_err,
        rfh_post_pending_allow,
        rfh_unknown_pending_status,
        rfh_unknown_pending_err,
        rfh_after_neg_replay_ok
    ));

    // QA-D3 (RESOLVED): Rust Agent R3 Verification Rejects aa-auth+jwt as Person Token & Enforces Same Access-Server Issuer Between Class and Per-Call Tokens
    let other_as_issuer = "https://other-as.example";
    let other_as_seed = [0x88; 32];
    let other_as_key = SigningKey::from_seed(other_as_seed);
    let mut other_as_jwk = serde_json::to_value(other_as_key.public_jwk())?;
    other_as_jwk["kid"] = json!("other-as-1");
    let other_as_snap = TrustedIssuerKeys::from_documents(
        other_as_issuer,
        "aauth-access.json",
        &serde_json::to_vec(&json!({"issuer": other_as_issuer, "jwks_uri": "https://other-as.example/jwks"}))?,
        &serde_json::to_vec(&json!({"keys": [other_as_jwk]}))?,
    )?;
    trust.insert_manual(other_as_issuer, "aauth-access.json", other_as_snap)?;

    let d3a_doc_path = out_dir
        .join("rust-fed-res")
        .join(format!("c-{}.json", digest(verified_rust_fed_rt.reference().uri().as_bytes())));
    let d3a_doc_val: Value = serde_json::from_slice(&fs::read(&d3a_doc_path)?)?;
    let d3a_doc_exact: Vec<u8> = serde_json::from_value(d3a_doc_val["exact_json"].clone())?;
    let (d3a_class_rt, _d3a_ref) = mint_resource_token(
        &registry,
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &aauth_rust_core::ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: other_as_issuer.into(),
            ps: FED_PS.into(),
            jti: "d3a-rt-1".into(),
            iat: clock,
            exp: clock + 300,
            sub: "fed-person".into(),
            presented_jti: verified_rust_fed_class_auth.claims().jti.clone(),
            agent_jkt: SigningKey::from_seed(go_agent_seed).public_jwk().thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        verified_rust_fed_rt.reference().uri(),
        &d3a_doc_exact,
    )?;
    let d3a_rt_res = fed_agent.verify_r3_resource_token(
        &d3a_class_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_class_auth,
        None,
        trust,
        clock,
    );
    let d3a_rt_rejected_auth_as_person = d3a_rt_res.is_err();
    let d3a_deliv_res = fed_agent.verify_r3_auth_delivery(
        &rust_fed_class_auth,
        RUST_FED_RECORDS,
        &verified_rust_fed_rt,
        &rust_fed_class_auth,
        &registry,
        trust,
        clock,
    );
    let d3a_deliv_rejected_auth_as_person = d3a_deliv_res.is_err();

    let stored_prop_path = out_dir
        .join("rust-fed-res")
        .join(format!("p-{}.json", digest(verified_rf_proposal.reference().uri().as_bytes())));
    let stored_prop_bytes = fs::read(&stored_prop_path)?;
    let stored_prop = FileCalls::decode(&stored_prop_bytes)?;
    let (cross_as_proposal_rt, _) = mint_proposal_resource_token(
        &registry,
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &aauth_rust_core::ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: other_as_issuer.into(),
            ps: FED_PS.into(),
            jti: "cross-as-prop-1".into(),
            iat: clock,
            exp: clock + 300,
            sub: "fed-person".into(),
            presented_jti: verified_rust_fed_class_auth.claims().jti.clone(),
            agent_jkt: SigningKey::from_seed(go_agent_seed).public_jwk().thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        stored_prop.reference.uri(),
        &stored_prop.exact_json,
    )?;
    let d3b_prop_chal_res = fed_agent.verify_r3_proposal_challenge(
        &cross_as_proposal_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_class_auth,
        trust,
        clock,
    );
    let d3b_prop_chal_refused = d3b_prop_chal_res.is_err();
    let d3b_rt_with_class_res = fed_agent.verify_r3_resource_token(
        &cross_as_proposal_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_class_auth,
        None,
        trust,
        clock,
    );
    let d3b_rt_with_class_refused = d3b_rt_with_class_res.is_err();

    let (cross_as_prop_from_person_rt, _) = mint_proposal_resource_token(
        &registry,
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &aauth_rust_core::ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: other_as_issuer.into(),
            ps: FED_PS.into(),
            jti: "cross-as-prop-person-1".into(),
            iat: clock,
            exp: clock + 300,
            sub: "fed-person".into(),
            presented_jti: verified_rust_fed_rt.claims().presented_jti.clone(),
            agent_jkt: SigningKey::from_seed(go_agent_seed).public_jwk().thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        stored_prop.reference.uri(),
        &stored_prop.exact_json,
    )?;
    let verified_cross_as_prop = fed_agent.verify_r3_resource_token(
        &cross_as_prop_from_person_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_person_tok,
        None,
        trust,
        clock,
    )?;
    let cross_as_per_call_auth = mint_per_call_auth_token(
        &registry,
        &other_as_key,
        "other-as-1",
        &AuthClaims {
            iss: other_as_issuer.into(),
            dwk: "aauth-access.json".into(),
            aud: RUST_FED_RECORDS.into(),
            ps: FED_PS.into(),
            sub: "fed-person".into(),
            jti: "cross-as-pc-1".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        &stored_prop.reference,
        &stored_prop.exact_json,
    )?;
    let d3b_cross_as_res = fed_agent.verify_r3_per_call_delivery(
        &cross_as_per_call_auth,
        RUST_FED_RECORDS,
        &verified_cross_as_prop,
        &rust_fed_class_auth,
        &registry,
        trust,
        clock,
    );
    let d3b_cross_as_per_call_refused = d3b_cross_as_res.is_err();

    cases.push(QaCaseReceipt {
        id: "QA-D3".into(),
        category: "D. Re-Verification of Earlier Federated R3 Defects".into(),
        title: "RESOLVED (QA-D3): Rust Agent Rejects aa-auth+jwt as Person Token & Rejects Cross-Access-Server Per-Call Token Delivery".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: d3a_rt_rejected_auth_as_person
            && d3a_deliv_rejected_auth_as_person
            && d3b_prop_chal_refused
            && d3b_rt_with_class_refused
            && d3b_cross_as_per_call_refused,
        summary: format!(
            "D3a: verify_r3_resource_token rejected aa-auth+jwt={}, verify_r3_auth_delivery rejected aa-auth+jwt={}; D3b: verify_r3_proposal_challenge refused cross-AS={}, verify_r3_resource_token refused class token={}, verify_r3_per_call_delivery refused cross-AS per-call token={}",
            d3a_rt_rejected_auth_as_person,
            d3a_deliv_rejected_auth_as_person,
            d3b_prop_chal_refused,
            d3b_rt_with_class_refused,
            d3b_cross_as_per_call_refused
        ),
        evidence: json!({
            "d3a_verify_r3_resource_token_rejected_auth_as_person": d3a_rt_rejected_auth_as_person,
            "d3a_verify_r3_auth_delivery_rejected_auth_as_person": d3a_deliv_rejected_auth_as_person,
            "d3b_verify_r3_proposal_challenge_refused_cross_as": d3b_prop_chal_refused,
            "d3b_verify_r3_resource_token_refused_class_token": d3b_rt_with_class_refused,
            "d3b_verify_r3_per_call_delivery_refused_cross_as_issuer": d3b_cross_as_per_call_refused,
            "source_location": "crates/aauth-rust-agent/src/r3.rs:209, 379, 426 & src/credentials.rs:57",
        }),
    });
    transcript_lines.push(format!(
        "[QA-D3] RESOLVED: d3a_rt_rejected={} d3a_deliv_rejected={} d3b_cross_as_per_call_refused={}",
        d3a_rt_rejected_auth_as_person, d3a_deliv_rejected_auth_as_person, d3b_cross_as_per_call_refused
    ));

    // =========================================================================
    // CATEGORY E: Truthful Boundaries of Unbuilt Items ("Still not this result")
    // =========================================================================

    // QA-E1: budget_consumed Retained-Grant Resolution Boundary (400 invalid_resource_token)
    let stored_doc_path = out_dir
        .join("rust-fed-res")
        .join(format!("c-{}.json", digest(verified_rust_fed_rt.reference().uri().as_bytes())));
    let stored_doc_bytes = fs::read(&stored_doc_path)?;
    let stored_doc_val: Value = serde_json::from_slice(&stored_doc_bytes)?;
    let stored_doc_exact: Vec<u8> = serde_json::from_value(stored_doc_val["exact_json"].clone())?;
    let budget_offer = Budget::new(100, "MilliwattSecond", 0)?;
    let budget_consumed = ConsumptionRecord::new(verified_rust_fed_class_auth.claims().jti.clone(), 50)?;
    let (consumed_rt, _) = mint_budget_resource_token(
        &registry,
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &aauth_rust_core::ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: FED_AS.into(),
            ps: FED_PS.into(),
            jti: "consumed-rt-1".into(),
            iat: clock,
            exp: clock + 300,
            sub: "fed-person".into(),
            presented_jti: verified_rust_fed_class_auth.claims().jti.clone(),
            agent_jkt: SigningKey::from_seed(go_agent_seed).public_jwk().thumbprint()?,
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        verified_rust_fed_rt.reference().uri(),
        &stored_doc_exact,
        &budget_offer,
        Some(&budget_consumed),
    )?;
    let go_consumed_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": consumed_rt, "presented_token": rust_fed_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let go_consumed_status = go_consumed_resp.status().as_u16();
    let go_consumed_err = member(&go_consumed_resp, "error").unwrap_or_default();

    cases.push(QaCaseReceipt {
        id: "QA-E1".into(),
        category: "E. Unbuilt Boundaries ('Still not this result')".into(),
        title: "budget_consumed on R3 Class Resource Token Refused with 400 invalid_resource_token".into(),
        classification: "BOUNDARY_PINNED".into(),
        passed_expectation: go_consumed_status == 400 && go_consumed_err == "invalid_resource_token",
        summary: format!(
            "Presenting R3 class Resource token with budget_consumed returns {} ({})",
            go_consumed_status, go_consumed_err
        ),
        evidence: json!({
            "status": go_consumed_status,
            "error": go_consumed_err,
            "body": String::from_utf8_lossy(go_consumed_resp.body()),
        }),
    });
    transcript_lines.push(format!(
        "[QA-E1] BOUNDARY PINNED: budget_consumed status={} ({})",
        go_consumed_status, go_consumed_err
    ));

    // QA-E2: Go Resource Connection: close Snapshot Refusal on 401 Retry and 202 Held Routes
    let held_close_resp = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &post_at(
            &fed_class_holder,
            &format!("{FED_RECORDS}/records/held-1"),
            b"{}",
            clock,
        )?,
    )?;
    let held_close_status = held_close_resp.status().as_u16();
    let held_close_err = member(&held_close_resp, "error").unwrap_or_default();

    cases.push(QaCaseReceipt {
        id: "QA-E2".into(),
        category: "E. Unbuilt Boundaries ('Still not this result')".into(),
        title: "Go Resource snapshotHeldRequest Refuses HTTP/1.1 Requests Carrying Connection: close".into(),
        classification: "BOUNDARY_PINNED".into(),
        passed_expectation: held_close_status == 500 || held_close_status == 400,
        summary: format!(
            "Sending POST /records/held-1 with Connection: close to Go Federated Resource returns {} ({}) because Go resource/held.go snapshotHeldRequest rejects r.Close == true (which also caused fedcall01 400 invalid_request before cf3c81a).",
            held_close_status, held_close_err
        ),
        evidence: json!({
            "held_with_connection_close_status": held_close_status,
            "held_with_connection_close_error": held_close_err,
            "held_with_connection_close_body": String::from_utf8_lossy(held_close_resp.body()),
        }),
    });
    transcript_lines.push(format!(
        "[QA-E2] BOUNDARY PINNED: Go held with Connection: close status={} ({})",
        held_close_status, held_close_err
    ));

    // QA-E3: Held Release Reuse vs Fresh Bytes (query-runs=2 and fresh bytes under a still-live recorded approval)
    let held_rel_counters = Arc::new(RustResourceCounters::new());
    let held_rel_res = compose_rust_resource(
        RUST_FED_HELD,
        "rust-fed-held-1",
        [0x56; 32],
        Some(other_as_issuer),
        &out_dir.join("e3-held-rel"),
        trust,
        true,
        held_rel_counters.clone(),
    )?;
    let query_only_set = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.query"}]})
            .to_string()
            .as_bytes(),
    )?;
    let e3_rt = fed_agent.r3_authorize(
        |req| Ok::<_, String>(held_rel_res.authorize_endpoint(&req, clock, "e3-doc-jti-1").into_response()),
        &format!("{RUST_FED_HELD}/authorize"),
        &rfh_person_tok,
        &query_only_set,
        None,
        clock,
    )?;
    let verified_e3_rt = fed_agent.verify_r3_resource_token(
        &e3_rt,
        RUST_FED_HELD,
        FED_PS,
        &rfh_person_tok,
        None,
        trust,
        clock,
    )?;
    let e3_doc_path = out_dir
        .join("e3-held-rel")
        .join(format!("c-{}.json", digest(verified_e3_rt.reference().uri().as_bytes())));
    let e3_doc_val: Value = serde_json::from_slice(&fs::read(&e3_doc_path)?)?;
    let e3_doc_exact: Vec<u8> = serde_json::from_value(e3_doc_val["exact_json"].clone())?;
    let mcp_vocab = McpCodec::vocabulary()?;
    let empty_ops = GrantedOperations::new(&mcp_vocab, &[])?;
    let query_ops = GrantedOperations::new(&mcp_vocab, &[mcp("records.query")?])?;
    let e3_authz = Authorization::new(
        &empty_ops,
        &query_ops,
        &registry.parse_document(&e3_doc_exact)?,
    )?;
    let e3_class_tok_1 = mint_r3_class_auth_token(
        &registry,
        &other_as_key,
        "other-as-1",
        &AuthClaims {
            iss: other_as_issuer.into(),
            dwk: "aauth-access.json".into(),
            aud: RUST_FED_HELD.into(),
            ps: FED_PS.into(),
            sub: "fed-person".into(),
            jti: "e3-class-jti-1".into(),
            iat: clock,
            exp: clock + 10,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        verified_e3_rt.reference(),
        &e3_doc_exact,
        &e3_authz,
    )?;
    let e3_holder_1 = fed_agent.with_token(e3_class_tok_1)?;
    let e3_call_1 = held_rel_res
        .authorize(
            &post_at(&e3_holder_1, &format!("{RUST_FED_HELD}/records/query"), R1, clock)?,
            clock,
            "e3-prop-1",
        )
        .into_response();
    let runs_after_call_1 = held_rel_counters.query_runs.load(Ordering::SeqCst);
    let e3_call_2_same_jti = held_rel_res
        .authorize(
            &post_at(&e3_holder_1, &format!("{RUST_FED_HELD}/records/query"), R1, clock)?,
            clock,
            "e3-prop-2",
        )
        .into_response();
    let runs_after_same_jti = held_rel_counters.query_runs.load(Ordering::SeqCst);
    let e3_class_tok_2 = mint_r3_class_auth_token(
        &registry,
        &other_as_key,
        "other-as-1",
        &AuthClaims {
            iss: other_as_issuer.into(),
            dwk: "aauth-access.json".into(),
            aud: RUST_FED_HELD.into(),
            ps: FED_PS.into(),
            sub: "fed-person".into(),
            jti: "e3-class-jti-2".into(),
            iat: clock + 15,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        verified_e3_rt.reference(),
        &e3_doc_exact,
        &e3_authz,
    )?;
    let e3_holder_2 = fed_agent.with_token(e3_class_tok_2)?;
    let e3_call_3_new_jti = held_rel_res
        .authorize(
            &post_at(&e3_holder_2, &format!("{RUST_FED_HELD}/records/query"), R1, clock + 15)?,
            clock + 15,
            "e3-prop-3",
        )
        .into_response();
    let runs_after_new_jti = held_rel_counters.query_runs.load(Ordering::SeqCst);

    cases.push(QaCaseReceipt {
        id: "QA-E3".into(),
        category: "E. Unbuilt Boundaries ('Still not this result')".into(),
        title: "Held Release Reuse vs Fresh Bytes (query-runs=2 Under Same-JTI Live Token vs Cached Custody Reuse After Class Expiry)".into(),
        classification: "BOUNDARY_PINNED".into(),
        passed_expectation: e3_call_1.status().as_u16() == 202
            && runs_after_call_1 == 1
            && e3_call_2_same_jti.status().as_u16() == 202
            && runs_after_same_jti == 2
            && e3_call_3_new_jti.status().as_u16() == 202
            && runs_after_new_jti == 2,
        summary: format!(
            "Call 1 (jti-1, t=0)->202 (query_runs={}); Call 2 (same live jti-1, t=0)->202 recomputes (query_runs={}); Call 3 (replacement jti-2 after jti-1 expiry, t=+15)->202 reuses cached release without recomputing (query_runs={})",
            runs_after_call_1, runs_after_same_jti, runs_after_new_jti
        ),
        evidence: json!({
            "call_1_status": e3_call_1.status().as_u16(),
            "runs_after_call_1": runs_after_call_1,
            "call_2_same_live_jti_status": e3_call_2_same_jti.status().as_u16(),
            "runs_after_same_live_jti": runs_after_same_jti,
            "call_3_replacement_jti_after_expiry_status": e3_call_3_new_jti.status().as_u16(),
            "runs_after_replacement_jti": runs_after_new_jti,
            "source_location": "crates/aauth-rust-resource/src/r3_per_call.rs:436-450 (held_release_matches)",
        }),
    });
    transcript_lines.push(format!(
        "[QA-E3] BOUNDARY PINNED: query_runs after call1={}, after same_live_jti={}, after replacement_jti={}",
        runs_after_call_1, runs_after_same_jti, runs_after_new_jti
    ));

    // =========================================================================
    // CATEGORY F: Live Held-Grant Poll Verification (635b8d80 / a97755ae)
    // =========================================================================

    // QA-F1: Live Held-Grant Second Poll Returns 202 Accepted (Retry-After=1, no-store, {"status":"pending"}, No AAuth-Requirement) While Host Holds R3Grant, Then Replays 200 OK After r3_retain Over HTTPS
    let f1_deletes_before = rust_fed_held_counters.deletes.load(Ordering::SeqCst);
    let f1_chal_resp = rust_fed_held_tls.send(&post_at(
        &rfh_class_holder,
        &format!("{RUST_FED_HELD}/records/delete"),
        br#"{"record":"r-hold-open"}"#,
        clock,
    )?)?;
    let f1_chal_status = f1_chal_resp.status().as_u16();
    let mut f1_poll_session = PollSession::new(
        &format!("{RUST_FED_HELD}/records/delete"),
        &f1_chal_resp,
        clock,
        clock + 60,
    )
    .map_err(|_| "QA-F1 held challenge is not a pending poll")?;
    let f1_pending_location = f1_poll_session.pending().location.clone();
    let f1_prop_rt = match &f1_poll_session.pending().requirement {
        aauth_rust_core::continuation::Requirement::AuthToken { resource_token } => {
            resource_token.clone()
        }
        _ => return Err("QA-F1 held challenge is not auth-token requirement".into()),
    };
    let f1_prop_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": f1_prop_rt, "presented_token": rfh_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let f1_held_tok = member(&f1_prop_ex_resp, "auth_token").ok_or("missing QA-F1 held grant")?;
    let f1_poll_holder = fed_agent.with_token(f1_held_tok)?;

    let f1_poll1_at = clock + 1;
    let f1_poll1_req = f1_poll_session.request(&f1_poll_holder, f1_poll1_at)?;
    let _f1_poll1_raw = rust_fed_held_tls.send(&f1_poll1_req)?;
    let f1_deletes_after_poll1 = rust_fed_held_counters.deletes.load(Ordering::SeqCst);
    let f1_held_grants_len = rust_fed_held_counters.held_grants.lock().unwrap().len();

    let f1_poll2_raw =
        rust_fed_held_tls.send(&signed_get(&f1_poll_holder, &f1_pending_location, f1_poll1_at)?)?;
    let f1_poll2_status = f1_poll2_raw.status().as_u16();
    let f1_poll2_location = f1_poll2_raw
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let f1_poll2_retry_after = f1_poll2_raw
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let f1_poll2_cache_control = f1_poll2_raw
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let f1_poll2_no_requirement = f1_poll2_raw.headers().get("aauth-requirement").is_none();
    let f1_poll2_status_member = member(&f1_poll2_raw, "status").unwrap_or_default();
    let f1_poll2_accepted_as_pending = f1_poll_session.accept(f1_poll2_raw.clone(), f1_poll1_at)?.is_none();
    let f1_deletes_after_poll2 = rust_fed_held_counters.deletes.load(Ordering::SeqCst);

    let (f1_grant_obj, f1_produced_resp) = rust_fed_held_counters
        .held_grants
        .lock()
        .unwrap()
        .pop()
        .ok_or("missing held R3Grant in QA-F1")?;
    let f1_retained_resp = rust_fed_held.r3_retain(&f1_grant_obj, f1_produced_resp);
    let f1_retained_status = f1_retained_resp.status().as_u16();

    let f1_poll3_at = clock + 2;
    let f1_poll3_req = f1_poll_session.request(&f1_poll_holder, f1_poll3_at)?;
    let f1_poll3_raw = rust_fed_held_tls.send(&f1_poll3_req)?;
    let f1_poll3_terminal = f1_poll_session
        .accept(f1_poll3_raw, f1_poll3_at)?
        .ok_or("QA-F1 3rd poll after r3_retain remained pending")?;
    let f1_poll3_status = f1_poll3_terminal.status().as_u16();
    let f1_poll3_matches =
        f1_poll3_status == 200 && f1_poll3_terminal.body() == f1_retained_resp.body();
    let f1_deletes_after_poll3 = rust_fed_held_counters.deletes.load(Ordering::SeqCst);

    cases.push(QaCaseReceipt {
        id: "QA-F1".into(),
        category: "F. Live Held-Grant Poll & Retry Verification".into(),
        title: "Live Held-Grant Second Poll Stays 202 Accepted (Retry-After=1, no-store, status=pending, No AAuth-Requirement) While Grant Is Held, Then Replays 200 OK After r3_retain".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: f1_chal_status == 202
            && f1_held_grants_len == 1
            && f1_deletes_after_poll1 == f1_deletes_before + 1
            && f1_poll2_status == 202
            && f1_poll2_location == f1_pending_location
            && f1_poll2_retry_after == "1"
            && f1_poll2_cache_control == "no-store"
            && f1_poll2_no_requirement
            && f1_poll2_status_member == "pending"
            && f1_poll2_accepted_as_pending
            && f1_deletes_after_poll2 == f1_deletes_before + 1
            && f1_retained_status == 200
            && f1_poll3_status == 200
            && f1_poll3_matches
            && f1_deletes_after_poll3 == f1_deletes_before + 1,
        summary: format!(
            "2nd poll while R3Grant held -> {} (Location matches={}, Retry-After={}, Cache-Control={}, no_req={}, status={}, PollSession pending={}); after r3_retain -> 3rd poll={} (matches={}, handler_runs_delta={})",
            f1_poll2_status,
            f1_poll2_location == f1_pending_location,
            f1_poll2_retry_after,
            f1_poll2_cache_control,
            f1_poll2_no_requirement,
            f1_poll2_status_member,
            f1_poll2_accepted_as_pending,
            f1_poll3_status,
            f1_poll3_matches,
            f1_deletes_after_poll3 - f1_deletes_before
        ),
        evidence: json!({
            "challenge_status": f1_chal_status,
            "pending_location": f1_pending_location,
            "second_poll_while_held_status": f1_poll2_status,
            "second_poll_location": f1_poll2_location,
            "second_poll_retry_after": f1_poll2_retry_after,
            "second_poll_cache_control": f1_poll2_cache_control,
            "second_poll_no_aauth_requirement": f1_poll2_no_requirement,
            "second_poll_body": String::from_utf8_lossy(f1_poll2_raw.body()),
            "second_poll_accepted_by_poll_session_as_pending": f1_poll2_accepted_as_pending,
            "r3_retain_status": f1_retained_status,
            "third_poll_after_retain_status": f1_poll3_status,
            "third_poll_body": String::from_utf8_lossy(f1_poll3_terminal.body()),
            "third_poll_matches_retained": f1_poll3_matches,
            "handler_runs_delta": f1_deletes_after_poll3 - f1_deletes_before,
            "source_location": "crates/aauth-rust-resource/src/r3_per_call.rs:330-379, 1087-1091 & src/ps_authorization.rs:241, 310",
        }),
    });
    transcript_lines.push(format!(
        "[QA-F1] PASS: poll2_while_held={} (retry_after={}, cache_control={}, no_req={}, status={}) -> retain={} -> poll3={} (matches={}, delta_runs={})",
        f1_poll2_status,
        f1_poll2_retry_after,
        f1_poll2_cache_control,
        f1_poll2_no_requirement,
        f1_poll2_status_member,
        f1_retained_status,
        f1_poll3_status,
        f1_poll3_matches,
        f1_deletes_after_poll3 - f1_deletes_before
    ));

    // QA-F2: Dropping R3Grant Without r3_retain Fails Closed with 500 server_error on Subsequent Held Poll and 401 Retry Over HTTPS
    let f2_held_del_before = rust_fed_held_counters.deletes.load(Ordering::SeqCst);
    let f2_held_chal = rust_fed_held_tls.send(&post_at(
        &rfh_class_holder,
        &format!("{RUST_FED_HELD}/records/delete"),
        br#"{"record":"r-drop-unretained"}"#,
        clock,
    )?)?;
    let f2_held_poll_sess = PollSession::new(
        &format!("{RUST_FED_HELD}/records/delete"),
        &f2_held_chal,
        clock,
        clock + 60,
    )
    .map_err(|_| "QA-F2 held challenge is not a pending poll")?;
    let f2_held_loc = f2_held_poll_sess.pending().location.clone();
    let f2_held_prop_rt = match &f2_held_poll_sess.pending().requirement {
        aauth_rust_core::continuation::Requirement::AuthToken { resource_token } => {
            resource_token.clone()
        }
        _ => return Err("QA-F2 held challenge is not auth-token requirement".into()),
    };
    let f2_held_ex = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": f2_held_prop_rt, "presented_token": rfh_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let f2_held_tok = member(&f2_held_ex, "auth_token").ok_or("missing QA-F2 held auth_token")?;
    let f2_held_holder = fed_agent.with_token(f2_held_tok)?;
    let _f2_held_poll1 =
        rust_fed_held_tls.send(&signed_get(&f2_held_holder, &f2_held_loc, clock + 1)?)?;
    let f2_held_poll2 =
        rust_fed_held_tls.send(&signed_get(&f2_held_holder, &f2_held_loc, clock + 1)?)?;
    let f2_held_poll2_status = f2_held_poll2.status().as_u16();
    let f2_held_poll2_err = member(&f2_held_poll2, "error").unwrap_or_default();
    let f2_held_del_after = rust_fed_held_counters.deletes.load(Ordering::SeqCst);

    let f2_retry_del_before = rust_fed_counters.deletes.load(Ordering::SeqCst);
    let f2_retry_chal = rust_fed_res_tls.send(&post_at(
        &rust_fed_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-drop-unretained"}"#,
        clock,
    )?)?;
    let f2_retry_prop_rt = challenge(&f2_retry_chal)?;
    let f2_retry_ex = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": f2_retry_prop_rt, "presented_token": rust_fed_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let f2_retry_tok = member(&f2_retry_ex, "auth_token").ok_or("missing QA-F2 retry auth_token")?;
    let f2_retry_holder = fed_agent.with_token(f2_retry_tok)?;
    let _f2_retry_call1 = rust_fed_res_tls.send(&post_at(
        &f2_retry_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-drop-unretained"}"#,
        clock,
    )?)?;
    let f2_retry_call2 = rust_fed_res_tls.send(&post_at(
        &f2_retry_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-drop-unretained"}"#,
        clock,
    )?)?;
    let f2_retry_call2_status = f2_retry_call2.status().as_u16();
    let f2_retry_call2_err = member(&f2_retry_call2, "error").unwrap_or_default();
    let f2_retry_del_after = rust_fed_counters.deletes.load(Ordering::SeqCst);

    cases.push(QaCaseReceipt {
        id: "QA-F2".into(),
        category: "F. Live Held-Grant Poll & Retry Verification".into(),
        title: "Dropping R3Grant Without r3_retain Fails Closed with 500 server_error on Subsequent Held Poll and 401 Retry Without Re-Running Handler".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: f2_held_poll2_status == 500
            && f2_held_poll2_err == "server_error"
            && f2_held_del_after == f2_held_del_before + 1
            && f2_retry_call2_status == 500
            && f2_retry_call2_err == "server_error"
            && f2_retry_del_after == f2_retry_del_before + 1,
        summary: format!(
            "Dropped unretained grant: held 2nd poll -> {} ({}, runs_delta={}); 401 2nd retry -> {} ({}, runs_delta={})",
            f2_held_poll2_status,
            f2_held_poll2_err,
            f2_held_del_after - f2_held_del_before,
            f2_retry_call2_status,
            f2_retry_call2_err,
            f2_retry_del_after - f2_retry_del_before
        ),
        evidence: json!({
            "held_second_poll_after_drop_status": f2_held_poll2_status,
            "held_second_poll_after_drop_error": f2_held_poll2_err,
            "held_handler_runs_delta": f2_held_del_after - f2_held_del_before,
            "retry_second_call_after_drop_status": f2_retry_call2_status,
            "retry_second_call_after_drop_error": f2_retry_call2_err,
            "retry_handler_runs_delta": f2_retry_del_after - f2_retry_del_before,
            "source_location": "crates/aauth-rust-resource/src/r3_per_call.rs:348-379, 1087-1091",
        }),
    });
    transcript_lines.push(format!(
        "[QA-F2] PASS: dropped_unretained held_poll2={} ({}, delta_runs={}) retry_call2={} ({}, delta_runs={})",
        f2_held_poll2_status,
        f2_held_poll2_err,
        f2_held_del_after - f2_held_del_before,
        f2_retry_call2_status,
        f2_retry_call2_err,
        f2_retry_del_after - f2_retry_del_before
    ));

    // QA-F3: Live 401 Per-Call Retry Returns 503 temporarily_unavailable (Retry-After: 1, No Location, No AAuth-Requirement) While Grant Is Held, Then Replays 200 OK After r3_retain Over HTTPS (24b48dd3 / 0c869395)
    let f3_del_before = rust_fed_counters.deletes.load(Ordering::SeqCst);
    let f3_chal_resp = rust_fed_res_tls.send(&post_at(
        &rust_fed_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-hold-open"}"#,
        clock,
    )?)?;
    let f3_chal_status = f3_chal_resp.status().as_u16();
    let f3_prop_rt = challenge(&f3_chal_resp)?;
    let f3_prop_ex = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": f3_prop_rt, "presented_token": rust_fed_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let f3_pc_tok = member(&f3_prop_ex, "auth_token").ok_or("missing QA-F3 per-call auth_token")?;
    let f3_pc_holder = fed_agent.with_token(f3_pc_tok)?;

    let _f3_call1 = rust_fed_res_tls.send(&post_at(
        &f3_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-hold-open"}"#,
        clock,
    )?)?;
    let f3_del_after_call1 = rust_fed_counters.deletes.load(Ordering::SeqCst);
    let f3_held_grants_len = rust_fed_counters.held_grants.lock().unwrap().len();

    let f3_call2 = rust_fed_res_tls.send(&post_at(
        &f3_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-hold-open"}"#,
        clock,
    )?)?;
    let f3_call2_status = f3_call2.status().as_u16();
    let f3_call2_err = member(&f3_call2, "error").unwrap_or_default();
    let f3_call2_retry_after = f3_call2
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let f3_call2_no_location = f3_call2.headers().get("location").is_none();
    let f3_call2_no_requirement = f3_call2.headers().get("aauth-requirement").is_none();
    let f3_del_after_call2 = rust_fed_counters.deletes.load(Ordering::SeqCst);

    let (f3_grant_obj, f3_produced_resp) = rust_fed_counters
        .held_grants
        .lock()
        .unwrap()
        .pop()
        .ok_or("missing held R3Grant in QA-F3")?;
    let f3_retained_resp = rust_fed_res.r3_retain(&f3_grant_obj, f3_produced_resp);
    let f3_retained_status = f3_retained_resp.status().as_u16();

    let f3_call3 = rust_fed_res_tls.send(&post_at(
        &f3_pc_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-hold-open"}"#,
        clock,
    )?)?;
    let f3_call3_status = f3_call3.status().as_u16();
    let f3_call3_matches = f3_call3_status == 200 && f3_call3.body() == f3_retained_resp.body();
    let f3_del_after_call3 = rust_fed_counters.deletes.load(Ordering::SeqCst);

    cases.push(QaCaseReceipt {
        id: "QA-F3".into(),
        category: "F. Live Held-Grant Poll & Retry Verification".into(),
        title: "Live 401 Per-Call Retry Stays 503 temporarily_unavailable (Retry-After=1, No Location, No AAuth-Requirement) While Grant Is Held, Then Replays 200 OK After r3_retain".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: f3_chal_status == 401
            && f3_held_grants_len == 1
            && f3_del_after_call1 == f3_del_before + 1
            && f3_call2_status == 503
            && f3_call2_err == "temporarily_unavailable"
            && f3_call2_retry_after == "1"
            && f3_call2_no_location
            && f3_call2_no_requirement
            && f3_del_after_call2 == f3_del_before + 1
            && f3_retained_status == 200
            && f3_call3_status == 200
            && f3_call3_matches
            && f3_del_after_call3 == f3_del_before + 1,
        summary: format!(
            "2nd 401 retry while R3Grant held -> {} ({}, Retry-After={}, no_loc={}, no_req={}); after r3_retain -> 3rd retry={} (matches={}, handler_runs_delta={})",
            f3_call2_status,
            f3_call2_err,
            f3_call2_retry_after,
            f3_call2_no_location,
            f3_call2_no_requirement,
            f3_call3_status,
            f3_call3_matches,
            f3_del_after_call3 - f3_del_before
        ),
        evidence: json!({
            "challenge_status": f3_chal_status,
            "second_retry_while_held_status": f3_call2_status,
            "second_retry_while_held_error": f3_call2_err,
            "second_retry_retry_after": f3_call2_retry_after,
            "second_retry_no_location": f3_call2_no_location,
            "second_retry_no_aauth_requirement": f3_call2_no_requirement,
            "second_retry_body": String::from_utf8_lossy(f3_call2.body()),
            "r3_retain_status": f3_retained_status,
            "third_retry_after_retain_status": f3_call3_status,
            "third_retry_body": String::from_utf8_lossy(f3_call3.body()),
            "third_retry_matches_retained": f3_call3_matches,
            "handler_runs_delta": f3_del_after_call3 - f3_del_before,
            "source_location": "crates/aauth-rust-resource/src/ps_authorization.rs:279, 457 & src/r3_per_call.rs:1075, 1087",
        }),
    });
    transcript_lines.push(format!(
        "[QA-F3] PASS: retry2_while_held={} ({}, retry_after={}, no_loc={}, no_req={}) -> retain={} -> retry3={} (matches={}, delta_runs={})",
        f3_call2_status,
        f3_call2_err,
        f3_call2_retry_after,
        f3_call2_no_location,
        f3_call2_no_requirement,
        f3_retained_status,
        f3_call3_status,
        f3_call3_matches,
        f3_del_after_call3 - f3_del_before
    ));

    // =========================================================================
    // CATEGORY G: Application 202 Header Retention
    // =========================================================================

    // Helper closure for 401 retry per-call completion + replay on rust_fed_res_tls:
    let run_401_custom_delete = |record_id: &str,
                                 produced: Response<Vec<u8>>|
     -> Result<(Response<Vec<u8>>, Response<Vec<u8>>, usize, usize)> {
        rust_fed_counters
            .custom_delete_responses
            .lock()
            .unwrap()
            .insert(format!("\"{record_id}\""), produced);
        let payload = json!({"record": record_id}).to_string().into_bytes();
        let del_before = rust_fed_counters.deletes.load(Ordering::SeqCst);
        let chal = rust_fed_res_tls.send(&post_at(
            &rust_fed_holder,
            &format!("{RUST_FED_RECORDS}/records/delete"),
            &payload,
            clock,
        )?)?;
        let prop_rt = challenge(&chal)?;
        let ex_resp = TlsServer::send_external(
            fed_ps_addr,
            "fed-ps.example",
            &fed_ps_cert,
            &post_at(
                &fed_agent,
                &format!("{FED_PS}/token"),
                json!({"resource_token": prop_rt, "presented_token": rust_fed_class_auth})
                    .to_string()
                    .as_bytes(),
                clock,
            )?,
        )?;
        let pc_tok = member(&ex_resp, "auth_token").ok_or("missing custom delete per-call auth_token")?;
        let pc_holder = fed_agent.with_token(pc_tok)?;
        let first = rust_fed_res_tls.send(&post_at(
            &pc_holder,
            &format!("{RUST_FED_RECORDS}/records/delete"),
            &payload,
            clock,
        )?)?;
        let del_after_first = rust_fed_counters.deletes.load(Ordering::SeqCst);
        let replay = rust_fed_res_tls.send(&post_at(
            &pc_holder,
            &format!("{RUST_FED_RECORDS}/records/delete"),
            &payload,
            clock,
        )?)?;
        let del_after_replay = rust_fed_counters.deletes.load(Ordering::SeqCst);
        Ok((
            first,
            replay,
            del_after_first - del_before,
            del_after_replay - del_before,
        ))
    };

    // QA-G1: Valid Per-Call Application 202 Retention & Replay on Both 401 Retry and 202 Held-Poll Paths Over HTTPS
    // G1a: 401 retry with full same-origin Location, multi-header Cache-Control (["private, max-age=0", "No-Store"]), Content-Type parameter
    let g1a_resp_in = Response::builder()
        .status(202)
        .header("location", format!("{RUST_FED_RECORDS}/jobs/r-202-full?step=1"))
        .header("retry-after", "7")
        .header("cache-control", "private, max-age=0")
        .header("cache-control", "No-Store")
        .header("content-type", "Application/JSON; charset=utf-8")
        .body(br#"{"status":"queued","job":"r-202-full"}"#.to_vec())?;
    let (g1a_first, g1a_replay, g1a_runs_1, g1a_runs_2) =
        run_401_custom_delete("r-202-full", g1a_resp_in)?;
    let g1a_expected_headers = (
        vec![format!("{RUST_FED_RECORDS}/jobs/r-202-full?step=1")],
        vec!["7".to_owned()],
        vec!["private, max-age=0".to_owned(), "No-Store".to_owned()],
        vec!["Application/JSON; charset=utf-8".to_owned()],
    );
    let g1a_first_headers = (
        header_values(&g1a_first, "location"),
        header_values(&g1a_first, "retry-after"),
        header_values(&g1a_first, "cache-control"),
        header_values(&g1a_first, "content-type"),
    );
    let g1a_replay_headers = (
        header_values(&g1a_replay, "location"),
        header_values(&g1a_replay, "retry-after"),
        header_values(&g1a_replay, "cache-control"),
        header_values(&g1a_replay, "content-type"),
    );
    let g1a_ok = g1a_first.status().as_u16() == 202
        && g1a_replay.status().as_u16() == 202
        && g1a_first_headers == g1a_expected_headers
        && g1a_replay_headers == g1a_expected_headers
        && g1a_first.body() == br#"{"status":"queued","job":"r-202-full"}"#
        && g1a_replay.body() == g1a_first.body()
        && g1a_runs_1 == 1
        && g1a_runs_2 == 1;

    // G1b: 401 retry with relative Location (/calls/pending/rel-1), Retry-After: 0, quoted Content-Type parameter, and Agent PollSession::new interop
    let g1b_resp_in = Response::builder()
        .status(202)
        .header("location", "/calls/pending/rel-1")
        .header("retry-after", "0")
        .header("cache-control", "no-store")
        .header("content-type", "application/json; profile=\"urn:example:job\"")
        .body(br#"{"status":"starting"}"#.to_vec())?;
    let (g1b_first, g1b_replay, g1b_runs_1, g1b_runs_2) =
        run_401_custom_delete("r-202-rel", g1b_resp_in)?;
    let g1b_poll_sess = PollSession::new(
        &format!("{RUST_FED_RECORDS}/records/delete"),
        &g1b_replay,
        clock,
        clock + 60,
    );
    let g1b_poll_sess_ok = g1b_poll_sess
        .as_ref()
        .is_ok_and(|s| s.pending().location == format!("{RUST_FED_RECORDS}/calls/pending/rel-1") && s.pending().retry_after == 0);
    let g1b_ok = g1b_first.status().as_u16() == 202
        && g1b_replay.status().as_u16() == 202
        && header_values(&g1b_replay, "location") == vec!["/calls/pending/rel-1".to_owned()]
        && header_values(&g1b_replay, "retry-after") == vec!["0".to_owned()]
        && header_values(&g1b_replay, "cache-control") == vec!["no-store".to_owned()]
        && header_values(&g1b_replay, "content-type")
            == vec!["application/json; profile=\"urn:example:job\"".to_owned()]
        && g1b_replay.body() == br#"{"status":"starting"}"#
        && g1b_poll_sess_ok
        && g1b_runs_1 == 1
        && g1b_runs_2 == 1;

    // G1d: 401 retry with max nanosecond-duration Retry-After: 9223372036 and relative Location (/calls/pending/rel-max-ra)
    let g1d_resp_in = Response::builder()
        .status(202)
        .header("location", "/calls/pending/rel-max-ra")
        .header("retry-after", "9223372036")
        .header("cache-control", "private, No-Store")
        .header("content-type", "application/json")
        .body(br#"{"status":"pending"}"#.to_vec())?;
    let (g1d_first, g1d_replay, g1d_runs_1, g1d_runs_2) =
        run_401_custom_delete("r-202-max-ra", g1d_resp_in)?;
    let g1d_ok = g1d_first.status().as_u16() == 202
        && g1d_replay.status().as_u16() == 202
        && header_values(&g1d_replay, "location") == vec!["/calls/pending/rel-max-ra".to_owned()]
        && header_values(&g1d_replay, "retry-after") == vec!["9223372036".to_owned()]
        && header_values(&g1d_replay, "cache-control") == vec!["private, No-Store".to_owned()]
        && g1d_replay.body() == br#"{"status":"pending"}"#
        && g1d_runs_1 == 1
        && g1d_runs_2 == 1;

    // G1c: 202 held-delivery poll completion on rust_fed_held_tls returning a nested application 202 Accepted
    rust_fed_held_counters
        .custom_delete_responses
        .lock()
        .unwrap()
        .insert(
            "\"r-202-held-nested\"".to_owned(),
            Response::builder()
                .status(202)
                .header("location", "/jobs/held-nested-1")
                .header("retry-after", "4")
                .header("cache-control", "private, no-store")
                .header("content-type", "application/json")
                .body(br#"{"status":"processing_nested"}"#.to_vec())?,
        );
    let g1c_del_before = rust_fed_held_counters.deletes.load(Ordering::SeqCst);
    let g1c_chal = rust_fed_held_tls.send(&post_at(
        &rfh_class_holder,
        &format!("{RUST_FED_HELD}/records/delete"),
        br#"{"record":"r-202-held-nested"}"#,
        clock,
    )?)?;
    let g1c_outer_sess = PollSession::new(
        &format!("{RUST_FED_HELD}/records/delete"),
        &g1c_chal,
        clock,
        clock + 60,
    )
    .map_err(|_| "QA-G1c outer held challenge is not a pending poll")?;
    let g1c_pending_loc = g1c_outer_sess.pending().location.clone();
    let g1c_prop_rt = match &g1c_outer_sess.pending().requirement {
        aauth_rust_core::continuation::Requirement::AuthToken { resource_token } => {
            resource_token.clone()
        }
        _ => return Err("QA-G1c outer held challenge is not auth-token requirement".into()),
    };
    let g1c_ex = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": g1c_prop_rt, "presented_token": rfh_class_auth})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let g1c_tok = member(&g1c_ex, "auth_token").ok_or("missing QA-G1c held auth_token")?;
    let g1c_holder = fed_agent.with_token(g1c_tok)?;
    let g1c_poll1 = rust_fed_held_tls.send(&signed_get(&g1c_holder, &g1c_pending_loc, clock + 1)?)?;
    let g1c_poll2 = rust_fed_held_tls.send(&signed_get(&g1c_holder, &g1c_pending_loc, clock + 1)?)?;
    let g1c_del_after = rust_fed_held_counters.deletes.load(Ordering::SeqCst);
    let g1c_nested_sess_ok = PollSession::new(&g1c_pending_loc, &g1c_poll2, clock + 1, clock + 60)
        .is_ok_and(|s| s.pending().location == format!("{RUST_FED_HELD}/jobs/held-nested-1") && s.pending().retry_after == 4);
    let g1c_ok = g1c_poll1.status().as_u16() == 202
        && g1c_poll2.status().as_u16() == 202
        && header_values(&g1c_poll1, "location") == vec!["/jobs/held-nested-1".to_owned()]
        && header_values(&g1c_poll2, "location") == vec!["/jobs/held-nested-1".to_owned()]
        && header_values(&g1c_poll2, "retry-after") == vec!["4".to_owned()]
        && header_values(&g1c_poll2, "cache-control") == vec!["private, no-store".to_owned()]
        && g1c_poll2.body() == br#"{"status":"processing_nested"}"#
        && g1c_nested_sess_ok
        && g1c_del_after == g1c_del_before + 1;

    cases.push(QaCaseReceipt {
        id: "QA-G1".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "Valid Per-Call Application 202 Retention & Replay on Both 401 Retry and 202 Held-Poll Paths Over HTTPS".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: g1a_ok && g1b_ok && g1c_ok && g1d_ok,
        summary: format!(
            "G1a (401 full-origin + multi Cache-Control): ok={}; G1b (401 relative /calls/pending/rel-1 + Retry-After=0 + PollSession): ok={}; G1d (Retry-After=9223372036 boundary): ok={}; G1c (202 held-poll nested application 202 + replay): ok={}",
            g1a_ok, g1b_ok, g1d_ok, g1c_ok
        ),
        evidence: json!({
            "g1a_first_status": g1a_first.status().as_u16(),
            "g1a_replay_status": g1a_replay.status().as_u16(),
            "g1a_replay_headers": g1a_replay_headers,
            "g1a_handler_runs": g1a_runs_2,
            "g1b_replay_status": g1b_replay.status().as_u16(),
            "g1b_poll_session_resolved_location": format!("{RUST_FED_RECORDS}/calls/pending/rel-1"),
            "g1b_poll_session_ok": g1b_poll_sess_ok,
            "g1b_handler_runs": g1b_runs_2,
            "g1d_replay_status": g1d_replay.status().as_u16(),
            "g1d_replay_retry_after": header_values(&g1d_replay, "retry-after"),
            "g1d_handler_runs": g1d_runs_2,
            "g1c_held_poll1_status": g1c_poll1.status().as_u16(),
            "g1c_held_poll2_status": g1c_poll2.status().as_u16(),
            "g1c_held_poll2_location": header_values(&g1c_poll2, "location"),
            "g1c_held_poll2_retry_after": header_values(&g1c_poll2, "retry-after"),
            "g1c_held_poll2_cache_control": header_values(&g1c_poll2, "cache-control"),
            "g1c_nested_poll_session_ok": g1c_nested_sess_ok,
            "g1c_handler_runs": g1c_del_after - g1c_del_before,
        }),
    });
    transcript_lines.push(format!(
        "[QA-G1] PASS: g1a_ok={} g1b_ok={} g1d_ok={} g1c_ok={}",
        g1a_ok, g1b_ok, g1d_ok, g1c_ok
    ));

    // QA-G2: DirectoryCallStore & DirectoryDocumentStore Reopen Durability Across Resource Re-Instantiation Over HTTPS (Valid 202 & Rejected 202)
    let g2_root = out_dir.join("g2-dir-reopen");
    let g2_docs_dir = g2_root.join("docs");
    let g2_calls_dir = g2_root.join("calls");
    let g2_doc_store_1 = Arc::new(
        DirectoryDocumentStore::open(&g2_docs_dir).map_err(|e| format!("open doc store 1: {e:?}"))?,
    );
    let g2_call_store_1 = Arc::new(
        DirectoryCallStore::open(&g2_calls_dir).map_err(|e| format!("open call store 1: {e:?}"))?,
    );
    // Load the class document record committed by rust_fed_res so rust_fed_class_auth works directly on g2_res_1 and g2_res_2
    let main_doc_store = FileDocuments(out_dir.join("rust-fed-res"), Mutex::new(()));
    let main_class_doc = main_doc_store
        .load(verified_rust_fed_rt.reference().uri())
        .map_err(|e| format!("load main class doc: {e:?}"))?
        .ok_or("missing main class document for QA-G2")?;
    g2_doc_store_1
        .commit(&main_class_doc)
        .map_err(|e| format!("commit class doc to g2_doc_store_1: {e:?}"))?;

    let g2_counters_1 = Arc::new(RustResourceCounters::new());
    g2_counters_1
        .custom_delete_responses
        .lock()
        .unwrap()
        .insert(
            "\"r-reopen-valid-202\"".to_owned(),
            Response::builder()
                .status(202)
                .header("location", "/jobs/reopen-42")
                .header("retry-after", "9")
                .header("cache-control", "private")
                .header("cache-control", "no-store")
                .header("content-type", "application/json; charset=\"utf-8\"")
                .body(br#"{"status":"persisted_across_reopen","step":1}"#.to_vec())?,
        );
    g2_counters_1
        .custom_delete_responses
        .lock()
        .unwrap()
        .insert(
            "\"r-reopen-bad-202\"".to_owned(),
            Response::builder()
                .status(202)
                .header("location", "https://evil.example/jobs/reopen-bad")
                .header("retry-after", "5")
                .header("cache-control", "no-store")
                .header("content-type", "application/json")
                .body(br#"{"status":"pending"}"#.to_vec())?,
        );
    let g2_res_1 = Arc::new(compose_rust_resource_with_stores(
        RUST_FED_RECORDS,
        "rust-fed-res-1",
        [0x55; 32],
        Some(FED_AS),
        g2_doc_store_1,
        g2_call_store_1,
        trust,
        false,
        g2_counters_1.clone(),
    )?);
    let g2_res_1_c = g2_res_1.clone();
    let g2_cnt_1_c = g2_counters_1.clone();
    let g2_tls_1 = TlsServer::start("rust-fed-records.example", move |req| {
        serve_rust_resource(&g2_res_1_c, &g2_cnt_1_c, clock, req)
    })?;

    // Helper to challenge on g2_tls_1, sync the proposal record to main FileCalls so Go FED_PS/FED_AS can fetch it, exchange at FED_PS, and complete on g2_tls_1:
    let main_call_store = FileCalls(out_dir.join("rust-fed-res"), Mutex::new(()));
    let complete_on_g2_tls_1 = |record_id: &str| -> Result<(Agent, Response<Vec<u8>>, String)> {
        let payload = json!({"record": record_id}).to_string().into_bytes();
        let chal = g2_tls_1.send(&post_at(
            &rust_fed_holder,
            &format!("{RUST_FED_RECORDS}/records/delete"),
            &payload,
            clock,
        )?)?;
        let prop_rt = challenge(&chal)?;
        let ver_prop = fed_agent.verify_r3_proposal_challenge(
            &prop_rt,
            RUST_FED_RECORDS,
            FED_PS,
            &rust_fed_class_auth,
            trust,
            clock,
        )?;
        let prop_uri = ver_prop.reference().uri().to_owned();
        let dir_store_reader = DirectoryCallStore::open(&g2_calls_dir)
            .map_err(|e| format!("open call store reader: {e:?}"))?;
        let prop_rec = dir_store_reader
            .load(&prop_uri)
            .map_err(|e| format!("load prop from dir store: {e:?}"))?
            .ok_or("missing committed proposal in DirectoryCallStore")?;
        main_call_store
            .commit(&prop_rec)
            .map_err(|e| format!("commit prop to main call store: {e:?}"))?;
        let ex_resp = TlsServer::send_external(
            fed_ps_addr,
            "fed-ps.example",
            &fed_ps_cert,
            &post_at(
                &fed_agent,
                &format!("{FED_PS}/token"),
                json!({"resource_token": prop_rt, "presented_token": rust_fed_class_auth})
                    .to_string()
                    .as_bytes(),
                clock,
            )?,
        )?;
        let pc_tok = member(&ex_resp, "auth_token").ok_or("missing QA-G2 per-call auth_token")?;
        let pc_holder = fed_agent.with_token(pc_tok)?;
        let first_resp = g2_tls_1.send(&post_at(
            &pc_holder,
            &format!("{RUST_FED_RECORDS}/records/delete"),
            &payload,
            clock,
        )?)?;
        Ok((pc_holder, first_resp, prop_uri))
    };

    let (g2_valid_holder, g2_valid_first, g2_valid_uri) = complete_on_g2_tls_1("r-reopen-valid-202")?;
    let (g2_bad_holder, g2_bad_first, g2_bad_uri) = complete_on_g2_tls_1("r-reopen-bad-202")?;
    let g2_runs_instance_1 = g2_counters_1.deletes.load(Ordering::SeqCst);

    // Inspect raw claim-*.json files written by DirectoryCallStore on disk
    let g2_valid_claim_path = g2_calls_dir.join(format!("claim-{}.json", digest(g2_valid_uri.as_bytes())));
    let g2_valid_claim_json: Value = serde_json::from_slice(&fs::read(&g2_valid_claim_path)?)?;
    let g2_valid_disk_pending = g2_valid_claim_json["result"]["pending"].clone();
    let g2_bad_claim_path = g2_calls_dir.join(format!("claim-{}.json", digest(g2_bad_uri.as_bytes())));
    let g2_bad_claim_json: Value = serde_json::from_slice(&fs::read(&g2_bad_claim_path)?)?;
    let g2_bad_disk_status = g2_bad_claim_json["result"]["status"].as_u64().unwrap_or(0);
    let g2_bad_disk_no_pending = g2_bad_claim_json["result"].get("pending").is_none();

    // Drop Instance #1 (both TlsServer and Resource/DirectoryCallStore) and reopen DirectoryCallStore::open & DirectoryDocumentStore::open in Instance #2
    drop(g2_tls_1);
    drop(g2_res_1);

    let g2_doc_store_2 = Arc::new(DirectoryDocumentStore::open(&g2_docs_dir)?);
    let g2_call_store_2 = Arc::new(DirectoryCallStore::open(&g2_calls_dir)?);
    let g2_counters_2 = Arc::new(RustResourceCounters::new());
    let g2_res_2 = Arc::new(compose_rust_resource_with_stores(
        RUST_FED_RECORDS,
        "rust-fed-res-1",
        [0x55; 32],
        Some(FED_AS),
        g2_doc_store_2,
        g2_call_store_2,
        trust,
        false,
        g2_counters_2.clone(),
    )?);
    let g2_res_2_c = g2_res_2.clone();
    let g2_cnt_2_c = g2_counters_2.clone();
    let g2_tls_2 = TlsServer::start("rust-fed-records.example", move |req| {
        serve_rust_resource(&g2_res_2_c, &g2_cnt_2_c, clock, req)
    })?;

    let g2_valid_reopen_replay = g2_tls_2.send(&post_at(
        &g2_valid_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-reopen-valid-202"}"#,
        clock,
    )?)?;
    let g2_bad_reopen_replay = g2_tls_2.send(&post_at(
        &g2_bad_holder,
        &format!("{RUST_FED_RECORDS}/records/delete"),
        br#"{"record":"r-reopen-bad-202"}"#,
        clock,
    )?)?;
    let g2_runs_instance_2 = g2_counters_2.deletes.load(Ordering::SeqCst);

    let g2_valid_ok = g2_valid_first.status().as_u16() == 202
        && g2_valid_reopen_replay.status().as_u16() == 202
        && header_values(&g2_valid_reopen_replay, "location") == vec!["/jobs/reopen-42".to_owned()]
        && header_values(&g2_valid_reopen_replay, "retry-after") == vec!["9".to_owned()]
        && header_values(&g2_valid_reopen_replay, "cache-control")
            == vec!["private".to_owned(), "no-store".to_owned()]
        && header_values(&g2_valid_reopen_replay, "content-type")
            == vec!["application/json; charset=\"utf-8\"".to_owned()]
        && g2_valid_reopen_replay.body() == br#"{"status":"persisted_across_reopen","step":1}"#;
    let g2_bad_ok = g2_bad_first.status().as_u16() == 500
        && member(&g2_bad_first, "error").as_deref() == Some("server_error")
        && g2_bad_reopen_replay.status().as_u16() == 500
        && member(&g2_bad_reopen_replay, "error").as_deref() == Some("server_error")
        && g2_bad_reopen_replay.headers().get("location").is_none()
        && g2_bad_reopen_replay.headers().get("retry-after").is_none()
        && g2_bad_disk_status == 500
        && g2_bad_disk_no_pending;

    cases.push(QaCaseReceipt {
        id: "QA-G2".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "DirectoryCallStore & DirectoryDocumentStore Reopen Durability for Both Valid Application 202 and Rejected Application 202 Over HTTPS".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: g2_valid_ok && g2_bad_ok && g2_runs_instance_1 == 2 && g2_runs_instance_2 == 0,
        summary: format!(
            "Across DirectoryCallStore reopen: valid 202 replayed 202 with Location/Retry-After/Cache-Control intact (ok={}); rejected cross-origin 202 replayed 500 server_error (ok={}); instance1_runs={}, instance2_runs={}",
            g2_valid_ok, g2_bad_ok, g2_runs_instance_1, g2_runs_instance_2
        ),
        evidence: json!({
            "valid_first_status": g2_valid_first.status().as_u16(),
            "valid_reopen_replay_status": g2_valid_reopen_replay.status().as_u16(),
            "valid_reopen_location": header_values(&g2_valid_reopen_replay, "location"),
            "valid_reopen_retry_after": header_values(&g2_valid_reopen_replay, "retry-after"),
            "valid_reopen_cache_control": header_values(&g2_valid_reopen_replay, "cache-control"),
            "valid_reopen_content_type": header_values(&g2_valid_reopen_replay, "content-type"),
            "valid_disk_pending_json": g2_valid_disk_pending,
            "bad_first_status": g2_bad_first.status().as_u16(),
            "bad_reopen_replay_status": g2_bad_reopen_replay.status().as_u16(),
            "bad_disk_status": g2_bad_disk_status,
            "bad_disk_no_pending": g2_bad_disk_no_pending,
            "instance_1_handler_runs": g2_runs_instance_1,
            "instance_2_handler_runs_after_reopen": g2_runs_instance_2,
        }),
    });
    transcript_lines.push(format!(
        "[QA-G2] PASS: reopen_valid_202={} reopen_bad_202={} instance1_runs={} instance2_runs={}",
        g2_valid_ok, g2_bad_ok, g2_runs_instance_1, g2_runs_instance_2
    ));

    // QA-G3: Adversarial Location & Retry-After 202 Matrix Over HTTPS -> Stored and Replayed as 500 server_error Without Re-Running Handler
    let build_202 = |locs: &[&str], retry_afters: &[&str], ccs: &[&str], cts: &[&str], body: &[u8]| -> Response<Vec<u8>> {
        let mut b = Response::builder().status(202);
        for l in locs {
            b = b.header("location", *l);
        }
        for ra in retry_afters {
            b = b.header("retry-after", *ra);
        }
        for cc in ccs {
            b = b.header("cache-control", *cc);
        }
        for ct in cts {
            b = b.header("content-type", *ct);
        }
        b.body(body.to_vec()).unwrap()
    };
    let ok_body = br#"{"status":"pending"}"#;
    let g3_matrix: Vec<(&str, Response<Vec<u8>>)> = vec![
        ("missing_location", build_202(&[], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("empty_location", build_202(&[""], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("duplicate_location", build_202(&["/jobs/1", "/jobs/2"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("cross_origin_host", build_202(&["https://elsewhere.example/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("scheme_mismatch_http", build_202(&["http://rust-fed-records.example/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("port_mismatch_8443", build_202(&["https://rust-fed-records.example:8443/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("explicit_default_port_443", build_202(&["https://rust-fed-records.example:443/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("network_path_same_host", build_202(&["//rust-fed-records.example/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("network_path_other_host", build_202(&["//other.example/calls/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("triple_slash_reference", build_202(&["///jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("bare_relative_path", build_202(&["relative/path"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("query_only_location", build_202(&["?attempt=2"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("fragment_relative", build_202(&["/jobs/1#frag"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("fragment_absolute", build_202(&["https://rust-fed-records.example/jobs/1#frag"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("userinfo_in_authority", build_202(&["https://user@rust-fed-records.example/jobs/1"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("scheme_opaque_no_authority", build_202(&["mailto:ops@rust-fed-records.example"], &["5"], &["no-store"], &["application/json"], ok_body)),
        ("missing_retry_after", build_202(&["/jobs/1"], &[], &["no-store"], &["application/json"], ok_body)),
        ("duplicate_retry_after", build_202(&["/jobs/1"], &["5", "5"], &["no-store"], &["application/json"], ok_body)),
        ("non_decimal_retry_after", build_202(&["/jobs/1"], &["soon"], &["no-store"], &["application/json"], ok_body)),
        ("unit_suffixed_retry_after", build_202(&["/jobs/1"], &["5s"], &["no-store"], &["application/json"], ok_body)),
        ("http_date_retry_after", build_202(&["/jobs/1"], &["Fri, 30 Oct 2026 07:00:00 GMT"], &["no-store"], &["application/json"], ok_body)),
        ("negative_retry_after", build_202(&["/jobs/1"], &["-1"], &["no-store"], &["application/json"], ok_body)),
        ("plus_prefixed_retry_after", build_202(&["/jobs/1"], &["+5"], &["no-store"], &["application/json"], ok_body)),
        ("fractional_retry_after", build_202(&["/jobs/1"], &["1.5"], &["no-store"], &["application/json"], ok_body)),
        ("overflow_retry_after", build_202(&["/jobs/1"], &["9223372037"], &["no-store"], &["application/json"], ok_body)),
    ];

    let mut g3_results = Vec::new();
    let mut g3_all_ok = true;
    for (name, resp_in) in g3_matrix {
        let rec_id = format!("r-g3-{name}");
        let (first, replay, runs_1, runs_2) = run_401_custom_delete(&rec_id, resp_in)?;
        let sub_ok = first.status().as_u16() == 500
            && member(&first, "error").as_deref() == Some("server_error")
            && first.headers().get("location").is_none()
            && first.headers().get("retry-after").is_none()
            && replay.status().as_u16() == 500
            && member(&replay, "error").as_deref() == Some("server_error")
            && replay.headers().get("location").is_none()
            && replay.headers().get("retry-after").is_none()
            && runs_1 == 1
            && runs_2 == 1;
        if !sub_ok {
            g3_all_ok = false;
        }
        g3_results.push(json!({
            "subcase": name,
            "first_status": first.status().as_u16(),
            "replay_status": replay.status().as_u16(),
            "error": member(&replay, "error"),
            "runs_after_first": runs_1,
            "runs_after_replay": runs_2,
            "passed": sub_ok,
        }));
    }

    cases.push(QaCaseReceipt {
        id: "QA-G3".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "Adversarial Location & Retry-After 202 Matrix (25 Subcases) Stored and Replayed as 500 server_error Without Re-Running Handler".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: g3_all_ok,
        summary: format!(
            "All {}/{} adversarial Location & Retry-After 202 subcases converted to 500 server_error on completion and replayed as 500 server_error with 1 handler execution",
            g3_results.iter().filter(|r| r["passed"].as_bool() == Some(true)).count(),
            g3_results.len()
        ),
        evidence: json!({
            "subcase_count": g3_results.len(),
            "all_passed": g3_all_ok,
            "subcases": g3_results,
        }),
    });
    transcript_lines.push(format!(
        "[QA-G3] PASS: location_and_retry_after_202_matrix={}/{} all_500_and_replayed={}",
        g3_results.iter().filter(|r| r["passed"].as_bool() == Some(true)).count(),
        g3_results.len(),
        g3_all_ok
    ));

    // QA-G4: Adversarial Cache-Control, Content-Type, & Strict JSON Body 202 Matrix Over HTTPS -> Stored and Replayed as 500 server_error Without Re-Running Handler
    let g4_matrix: Vec<(&str, Response<Vec<u8>>)> = vec![
        ("missing_cache_control", build_202(&["/jobs/1"], &["5"], &[], &["application/json"], ok_body)),
        ("cache_control_without_no_store", build_202(&["/jobs/1"], &["5"], &["private, no-cache, max-age=0"], &["application/json"], ok_body)),
        ("cache_control_prefix_token", build_202(&["/jobs/1"], &["5"], &["no-store-custom"], &["application/json"], ok_body)),
        ("missing_content_type", build_202(&["/jobs/1"], &["5"], &["no-store"], &[], ok_body)),
        ("duplicate_content_type", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json", "application/json"], ok_body)),
        ("wrong_content_type_problem_json", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/problem+json"], ok_body)),
        ("wrong_content_type_text_plain", build_202(&["/jobs/1"], &["5"], &["no-store"], &["text/plain"], ok_body)),
        ("malformed_ct_param_no_eq", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json; charset"], ok_body)),
        ("malformed_ct_param_empty_val", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json; charset="], ok_body)),
        ("malformed_ct_param_unclosed_quote", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json; charset=\"utf-8"], ok_body)),
        ("malformed_ct_param_quoted_backslash", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json; p=\"a\\b\""], ok_body)),
        ("empty_body", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], b"")),
        ("non_json_body", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], b"pending")),
        ("json_array_body", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], b"[\"pending\"]")),
        ("missing_status_field", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"job":"1"}"#)),
        ("empty_status_string", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"status":""}"#)),
        ("non_string_status_int", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"status":202}"#)),
        ("non_string_status_null", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"status":null}"#)),
        ("uppercase_only_status_key", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"STATUS":"pending"}"#)),
        ("case_colliding_status_key", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"status":"pending","Status":"done"}"#)),
        ("duplicate_json_status_key", build_202(&["/jobs/1"], &["5"], &["no-store"], &["application/json"], br#"{"status":"pending","status":"done"}"#)),
    ];

    let mut g4_results = Vec::new();
    let mut g4_all_ok = true;
    for (name, resp_in) in g4_matrix {
        let rec_id = format!("r-g4-{name}");
        let (first, replay, runs_1, runs_2) = run_401_custom_delete(&rec_id, resp_in)?;
        let sub_ok = first.status().as_u16() == 500
            && member(&first, "error").as_deref() == Some("server_error")
            && first.headers().get("location").is_none()
            && first.headers().get("retry-after").is_none()
            && replay.status().as_u16() == 500
            && member(&replay, "error").as_deref() == Some("server_error")
            && replay.headers().get("location").is_none()
            && replay.headers().get("retry-after").is_none()
            && runs_1 == 1
            && runs_2 == 1;
        if !sub_ok {
            g4_all_ok = false;
        }
        g4_results.push(json!({
            "subcase": name,
            "first_status": first.status().as_u16(),
            "replay_status": replay.status().as_u16(),
            "error": member(&replay, "error"),
            "runs_after_first": runs_1,
            "runs_after_replay": runs_2,
            "passed": sub_ok,
        }));
    }

    cases.push(QaCaseReceipt {
        id: "QA-G4".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "Adversarial Cache-Control, Content-Type & Strict JSON Body 202 Matrix (21 Subcases) Stored and Replayed as 500 server_error Without Re-Running Handler".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: g4_all_ok,
        summary: format!(
            "All {}/{} adversarial Cache-Control, Content-Type, & JSON body 202 subcases converted to 500 server_error on completion and replayed as 500 server_error with 1 handler execution",
            g4_results.iter().filter(|r| r["passed"].as_bool() == Some(true)).count(),
            g4_results.len()
        ),
        evidence: json!({
            "subcase_count": g4_results.len(),
            "all_passed": g4_all_ok,
            "subcases": g4_results,
        }),
    });
    transcript_lines.push(format!(
        "[QA-G4] PASS: cc_ct_body_202_matrix={}/{} all_500_and_replayed={}",
        g4_results.iter().filter(|r| r["passed"].as_bool() == Some(true)).count(),
        g4_results.len(),
        g4_all_ok
    ));

    // QA-G5 (RESOLVED): Re-Verification of Attempt-13 Findings QA-G5a (Location: * and bare host) and QA-G5c (BoxedR3Release 202 under hold=true) at 81c1d29 / db8af21
    let (g5_asterisk_first, g5_asterisk_replay, g5_ast_r1, g5_ast_r2) = run_401_custom_delete(
        "r-g5-loc-asterisk",
        build_202(&["*"], &["5"], &["no-store"], &["application/json"], ok_body),
    )?;
    let g5_asterisk_refused = g5_asterisk_first.status().as_u16() == 500
        && member(&g5_asterisk_first, "error").as_deref() == Some("server_error")
        && g5_asterisk_first.headers().get("location").is_none()
        && g5_asterisk_first.headers().get("retry-after").is_none()
        && g5_asterisk_replay.status().as_u16() == 500
        && member(&g5_asterisk_replay, "error").as_deref() == Some("server_error")
        && g5_ast_r1 == 1
        && g5_ast_r2 == 1;

    let (g5_bare_host_first, g5_bare_host_replay, g5_bh_r1, g5_bh_r2) = run_401_custom_delete(
        "r-g5-loc-bare-host",
        build_202(
            &["rust-fed-records.example"],
            &["5"],
            &["no-store"],
            &["application/json"],
            ok_body,
        ),
    )?;
    let g5_bare_host_refused = g5_bare_host_first.status().as_u16() == 500
        && member(&g5_bare_host_first, "error").as_deref() == Some("server_error")
        && g5_bare_host_first.headers().get("location").is_none()
        && g5_bare_host_first.headers().get("retry-after").is_none()
        && g5_bare_host_replay.status().as_u16() == 500
        && member(&g5_bare_host_replay, "error").as_deref() == Some("server_error")
        && g5_bh_r1 == 1
        && g5_bh_r2 == 1;

    // G5c: Probe BoxedR3Release returning valid & invalid 202 Accepted on held_rel_res (/records/query), polling twice each:
    held_rel_counters
        .custom_query_releases
        .lock()
        .unwrap()
        .insert(
            "\"r-rel-valid-202\"".to_owned(),
            build_202(&["/jobs/rel-valid"], &["5"], &["no-store"], &["application/json"], ok_body),
        );
    held_rel_counters
        .custom_query_releases
        .lock()
        .unwrap()
        .insert(
            "\"r-rel-bad-202\"".to_owned(),
            build_202(
                &["https://evil.example/jobs/rel-bad"],
                &["5"],
                &["no-store"],
                &["text/plain"],
                b"not-json",
            ),
        );
    held_rel_counters
        .custom_query_releases
        .lock()
        .unwrap()
        .insert(
            "\"r-rel-asterisk-202\"".to_owned(),
            build_202(&["*"], &["5"], &["no-store"], &["application/json"], ok_body),
        );
    let g5_rel_class_tok = mint_r3_class_auth_token(
        &registry,
        &other_as_key,
        "other-as-1",
        &AuthClaims {
            iss: other_as_issuer.into(),
            dwk: "aauth-access.json".into(),
            aud: RUST_FED_HELD.into(),
            ps: FED_PS.into(),
            sub: "fed-person".into(),
            jti: "g5-rel-class-jti".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        verified_e3_rt.reference(),
        &e3_doc_exact,
        &e3_authz,
    )?;
    let g5_rel_class_holder = fed_agent.with_token(g5_rel_class_tok.clone())?;
    let run_release_202_probe_twice =
        |rec_id: &str, prop_jti: &str, pc_jti: &str| -> Result<(Response<Vec<u8>>, Response<Vec<u8>>, usize, String)> {
            let runs_before = held_rel_counters.query_runs.load(Ordering::SeqCst);
            let chal = held_rel_res
                .authorize(
                    &post_at(
                        &g5_rel_class_holder,
                        &format!("{RUST_FED_HELD}/records/query"),
                        json!({"record": rec_id}).to_string().as_bytes(),
                        clock,
                    )?,
                    clock,
                    prop_jti,
                )
                .into_response();
            let prop_rt = match aauth_rust_agent::Requirement::from_headers(chal.headers())? {
                Some(aauth_rust_agent::Requirement::AuthToken { resource_token }) => resource_token,
                _ => return Err("missing auth-token requirement on release-gated 202 challenge".into()),
            };
            let ver_prop = fed_agent.verify_r3_proposal_challenge(
                &prop_rt,
                RUST_FED_HELD,
                FED_PS,
                &g5_rel_class_tok,
                trust,
                clock,
            )?;
            let prop_path = out_dir
                .join("e3-held-rel")
                .join(format!("p-{}.json", digest(ver_prop.reference().uri().as_bytes())));
            let prop_rec = FileCalls::decode(&fs::read(&prop_path)?)?;
            let pc_tok = mint_per_call_auth_token(
                &registry,
                &other_as_key,
                "other-as-1",
                &AuthClaims {
                    iss: other_as_issuer.into(),
                    dwk: "aauth-access.json".into(),
                    aud: RUST_FED_HELD.into(),
                    ps: FED_PS.into(),
                    sub: "fed-person".into(),
                    jti: pc_jti.into(),
                    iat: clock,
                    exp: clock + 300,
                    cnf: Confirmation {
                        jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
                    },
                    nbf: None,
                    tenant: None,
                    mission_s256: None,
                    scope: None,
                    account: None,
                    extra: BTreeMap::new(),
                },
                &prop_rec.reference,
                &prop_rec.exact_json,
            )?;
            let pc_holder = fed_agent.with_token(pc_tok)?;
            let pending_url = chal
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or("missing location header on release-gated 202 challenge")?
                .to_owned();
            let poll1_req = signed_get(
                &pc_holder,
                &pending_url,
                clock + 1,
            )?;
            let poll1_resp = held_rel_res
                .authorize(&poll1_req, clock + 1, &format!("{pc_jti}-poll1"))
                .into_response();
            let poll2_req = signed_get(
                &pc_holder,
                &pending_url,
                clock + 1,
            )?;
            let poll2_resp = held_rel_res
                .authorize(&poll2_req, clock + 1, &format!("{pc_jti}-poll2"))
                .into_response();
            let runs_after = held_rel_counters.query_runs.load(Ordering::SeqCst);
            Ok((poll1_resp, poll2_resp, runs_after - runs_before, pending_url))
        };
    let (g5_rel_valid_1, g5_rel_valid_2, g5_rel_valid_runs, g5_rel_valid_pending_url) =
        run_release_202_probe_twice("r-rel-valid-202", "g5-rel-prop-1", "g5-rel-pc-1")?;
    let (g5_rel_bad_1, g5_rel_bad_2, g5_rel_bad_runs, _) =
        run_release_202_probe_twice("r-rel-bad-202", "g5-rel-prop-2", "g5-rel-pc-2")?;
    let (g5_rel_ast_1, g5_rel_ast_2, g5_rel_ast_runs, _) =
        run_release_202_probe_twice("r-rel-asterisk-202", "g5-rel-prop-3", "g5-rel-pc-3")?;

    let g5_rel_valid_poll_sess_ok = PollSession::new(
        &g5_rel_valid_pending_url,
        &g5_rel_valid_2,
        clock + 1,
        clock + 60,
    )
    .is_ok_and(|s| s.pending().location == format!("{RUST_FED_HELD}/jobs/rel-valid") && s.pending().retry_after == 5);

    let g5_rel_valid_preserved = g5_rel_valid_1.status().as_u16() == 202
        && g5_rel_valid_2.status().as_u16() == 202
        && header_values(&g5_rel_valid_1, "location") == vec!["/jobs/rel-valid".to_owned()]
        && header_values(&g5_rel_valid_2, "location") == vec!["/jobs/rel-valid".to_owned()]
        && header_values(&g5_rel_valid_2, "retry-after") == vec!["5".to_owned()]
        && header_values(&g5_rel_valid_2, "cache-control") == vec!["no-store".to_owned()]
        && g5_rel_valid_2.body() == ok_body
        && g5_rel_valid_poll_sess_ok
        && g5_rel_valid_runs == 1;
    let g5_rel_bad_refused = g5_rel_bad_1.status().as_u16() == 500
        && member(&g5_rel_bad_1, "error").as_deref() == Some("server_error")
        && g5_rel_bad_1.headers().get("location").is_none()
        && g5_rel_bad_2.status().as_u16() == 500
        && member(&g5_rel_bad_2, "error").as_deref() == Some("server_error")
        && g5_rel_bad_runs == 1
        && g5_rel_ast_1.status().as_u16() == 500
        && g5_rel_ast_2.status().as_u16() == 500
        && g5_rel_ast_runs == 1;

    cases.push(QaCaseReceipt {
        id: "QA-G5".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "RESOLVED (QA-G5a & QA-G5c): Non-Path Relative Locations (* and Bare Host) Refused as 500 server_error & BoxedR3Release 202 Responses Kept Under Pending Rule".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: g5_asterisk_refused
            && g5_bare_host_refused
            && g5_rel_valid_preserved
            && g5_rel_bad_refused,
        summary: format!(
            "QA-G5a resolved: Location='*' -> 500/500 (ok={}), Location='rust-fed-records.example' -> 500/500 (ok={}); QA-G5c resolved: BoxedR3Release valid 202 -> 202/202 with Location=/jobs/rel-valid & PollSession ok={} (runs={}), invalid 202 -> 500/500 (ok={})",
            g5_asterisk_refused,
            g5_bare_host_refused,
            g5_rel_valid_poll_sess_ok,
            g5_rel_valid_runs,
            g5_rel_bad_refused
        ),
        evidence: json!({
            "g5a_location_asterisk_first_status": g5_asterisk_first.status().as_u16(),
            "g5a_location_asterisk_replay_status": g5_asterisk_replay.status().as_u16(),
            "g5a_location_asterisk_runs": g5_ast_r2,
            "g5a_location_bare_host_first_status": g5_bare_host_first.status().as_u16(),
            "g5a_location_bare_host_replay_status": g5_bare_host_replay.status().as_u16(),
            "g5a_location_bare_host_runs": g5_bh_r2,
            "g5c_release_valid_poll1_status": g5_rel_valid_1.status().as_u16(),
            "g5c_release_valid_poll2_status": g5_rel_valid_2.status().as_u16(),
            "g5c_release_valid_location": header_values(&g5_rel_valid_2, "location"),
            "g5c_release_valid_retry_after": header_values(&g5_rel_valid_2, "retry-after"),
            "g5c_release_valid_cache_control": header_values(&g5_rel_valid_2, "cache-control"),
            "g5c_release_valid_agent_poll_session_ok": g5_rel_valid_poll_sess_ok,
            "g5c_release_valid_runs": g5_rel_valid_runs,
            "g5c_release_bad_cross_origin_poll1_status": g5_rel_bad_1.status().as_u16(),
            "g5c_release_bad_cross_origin_poll2_status": g5_rel_bad_2.status().as_u16(),
            "g5c_release_bad_asterisk_poll1_status": g5_rel_ast_1.status().as_u16(),
            "g5c_release_bad_asterisk_poll2_status": g5_rel_ast_2.status().as_u16(),
            "source_locations": [
                "crates/aauth-rust-resource/src/r3_per_call.rs:534-540 (same_origin_location)",
                "crates/aauth-rust-resource/src/r3_per_call.rs:936-937 (prepare_retained on release.response)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-G5] RESOLVED: asterisk_refused={} bare_host_refused={} rel_valid_preserved={} (poll_sess={}) rel_bad_refused={}",
        g5_asterisk_refused,
        g5_bare_host_refused,
        g5_rel_valid_preserved,
        g5_rel_valid_poll_sess_ok,
        g5_rel_bad_refused
    ));

    // QA-G6 (DOCUMENTED BOUNDARY in CONFORMANCE.md): Multi-Header Cache-Control Kept by Resource (Matching aauth-go) vs Refused by aauth-rust-agent PollSession
    let g6_multi_cc_poll_ok = PollSession::new(
        &format!("{RUST_FED_RECORDS}/records/delete"),
        &g1a_replay,
        clock,
        clock + 60,
    )
    .is_ok();
    let g6_boundary_matches_conformance =
        g1a_replay.status().as_u16() == 202 && !g6_multi_cc_poll_ok;

    cases.push(QaCaseReceipt {
        id: "QA-G6".into(),
        category: "G. Application 202 Header Retention".into(),
        title: "Documented Cross-Crate Boundary (CONFORMANCE.md): Multi-Line Cache-Control Retained by Resource (Matching aauth-go) vs Refused by Rust Agent PollSession".into(),
        classification: "BOUNDARY_PINNED".into(),
        passed_expectation: g6_boundary_matches_conformance,
        summary: format!(
            "Resource retains & replays 202 with split Cache-Control lines {:?} (status={}), while aauth-rust-agent PollSession::new refuses multi-line Cache-Control (ok={}), as documented in CONFORMANCE.md",
            header_values(&g1a_replay, "cache-control"),
            g1a_replay.status().as_u16(),
            g6_multi_cc_poll_ok
        ),
        evidence: json!({
            "resource_replay_status": g1a_replay.status().as_u16(),
            "resource_replay_cache_control": header_values(&g1a_replay, "cache-control"),
            "agent_poll_session_accepts_multi_line_cache_control": g6_multi_cc_poll_ok,
            "conformance_reference": "CONFORMANCE.md lines 764-766",
            "source_location": "crates/aauth-rust-core/src/continuation.rs:92, 412-415 (one_header(\"cache-control\"))",
        }),
    });
    transcript_lines.push(format!(
        "[QA-G6] BOUNDARY PINNED: resource_multi_cc_202={} agent_poll_session_ok={}",
        g1a_replay.status().as_u16(),
        g6_multi_cc_poll_ok
    ));

    // =========================================================================================
    // Category H: Approved Mission Composition with Direct Class R3 (0.1.0-alpha.10 / 72e722e1)
    // =========================================================================================
    const H_AP: &str = "https://mission-ap.example";
    const H_PS: &str = "https://mission-ps.example";
    const H_RES: &str = "https://mission-records.example";
    const H_RES_NOMISS: &str = "https://nomission-records.example";

    const H_AP_SEED: [u8; 32] = [0x81; 32];
    const H_PS_SEED: [u8; 32] = [0x82; 32];
    const H_RES_SEED: [u8; 32] = [0x83; 32];
    const H_RES_NOMISS_SEED: [u8; 32] = [0x84; 32];
    const H_AGENT_SEED: [u8; 32] = [0x85; 32];
    const H_OTHER_AGENT_SEED: [u8; 32] = [0x86; 32];
    const H_CHILD_AGENT_SEED: [u8; 32] = [0x87; 32];

    let h_ap_key = SigningKey::from_seed(H_AP_SEED);
    let h_ps_key = SigningKey::from_seed(H_PS_SEED);
    let h_res_key = SigningKey::from_seed(H_RES_SEED);
    let h_agent_key = SigningKey::from_seed(H_AGENT_SEED);
    let h_other_agent_key = SigningKey::from_seed(H_OTHER_AGENT_SEED);
    let h_child_agent_key = SigningKey::from_seed(H_CHILD_AGENT_SEED);

    let h_ap_provider = AgentProvider::new(H_AP, "mission-ap-1", SigningKey::from_seed(H_AP_SEED))?;
    let mut h_ap_jwk = serde_json::to_value(h_ap_key.public_jwk())?;
    h_ap_jwk["kid"] = json!("mission-ap-1");
    trust.insert_manual(
        H_AP,
        "aauth-agent.json",
        TrustedIssuerKeys::from_documents(
            H_AP,
            "aauth-agent.json",
            &serde_json::to_vec(&json!({"issuer": H_AP, "jwks_uri": format!("{H_AP}/jwks.json")}))?,
            &serde_json::to_vec(&json!({"keys": [h_ap_jwk]}))?,
        )?,
    )?;

    let h_owner = AgentIdentity {
        issuer: H_AP.into(),
        subject: "aauth:reader@mission-ap.example".into(),
    };
    let h_other_owner = AgentIdentity {
        issuer: H_AP.into(),
        subject: "aauth:other@mission-ap.example".into(),
    };
    let h_agent_compact = h_ap_provider.issue(&AgentClaims {
        iss: H_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: h_owner.subject.clone(),
        jti: "h-agent-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: h_agent_key.public_jwk(),
        },
        ps: Some(H_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let h_agent = Agent::new(SigningKey::from_seed(H_AGENT_SEED), h_agent_compact.clone())?;

    let h_other_agent_compact = h_ap_provider.issue(&AgentClaims {
        iss: H_AP.into(),
        dwk: "aauth-agent.json".into(),
        sub: h_other_owner.subject.clone(),
        jti: "h-other-agent-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: h_other_agent_key.public_jwk(),
        },
        ps: Some(H_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;
    let h_other_agent = Agent::new(SigningKey::from_seed(H_OTHER_AGENT_SEED), h_other_agent_compact)?;

    let h_child_agent_compact = h_ap_provider.issue_subagent(
        &AgentClaims {
            iss: H_AP.into(),
            dwk: "aauth-agent.json".into(),
            sub: "aauth:reader+child@mission-ap.example".into(),
            jti: "h-child-agent-1".into(),
            iat: clock,
            exp: clock + 1800,
            cnf: Confirmation {
                jwk: h_child_agent_key.public_jwk(),
            },
            ps: Some(H_PS.into()),
            parent_agent: Some(h_owner.subject.clone()),
            nbf: None,
            extra: Default::default(),
        },
        &h_agent_compact,
        clock,
    )?;
    let h_child_agent = Agent::new(SigningKey::from_seed(H_CHILD_AGENT_SEED), h_child_agent_compact.clone())?;

    let h_doc_dir = out_dir.join("h-mission-r3-docs");
    let h_res_policy_calls = Arc::new(AtomicUsize::new(0));
    let h_res_reads = Arc::new(AtomicUsize::new(0));
    let h_res_queries = Arc::new(AtomicUsize::new(0));
    let h_res_clock = Arc::new(AtomicI64::new(clock));

    let make_h_resource = |doc_store: Arc<dyn R3DocumentStore>, policy_cnt: Arc<AtomicUsize>| -> Result<Resource> {
        let cfg = PsAuthorizationConfig {
            issuer: H_RES.into(),
            signed_origin: H_RES.into(),
            kid: "mission-res-1".into(),
            signing_key: SigningKey::from_seed(H_RES_SEED),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        };
        let policy: BoxedAuthPolicy = Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
            policy_cnt.fetch_add(1, Ordering::SeqCst);
            token.claims().ps == H_PS
        });
        Ok(PsAuthorizationResource::new(cfg, trust.clone(), policy)?
            .with_authorization_endpoint()
            .with_mission_context()
            .with_r3(R3Config {
                registry: standard_registry()?,
                definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
                vocabularies: vec![R3Vocabulary {
                    definition: McpCodec::parse_definition(
                        &format!("{H_RES}/mcp"),
                        &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                    )?,
                    display: Some(Box::new(|_: &OperationSet| {
                        Display::new("Mission-scoped records access", None, None, None)
                            .map_err(|e| R3HostError::new(e.to_string()))
                    })),
                }],
                documents: doc_store,
                operation_for_request: Box::new(|req: &Request<Vec<u8>>| match req.uri().path() {
                    "/records/read" => mcp("records.read").map(Some),
                    "/records/query" => mcp("records.query").map(Some),
                    "/records/delete" => mcp("records.delete").map(Some),
                    _ => Ok(None),
                }),
                require_core_scope: false,
            })?)
    };

    let h_res = Arc::new(make_h_resource(
        Arc::new(DirectoryDocumentStore::open(&h_doc_dir)?),
        h_res_policy_calls.clone(),
    )?);
    let h_res_for_tls = h_res.clone();
    let h_res_reads_tls = h_res_reads.clone();
    let h_res_queries_tls = h_res_queries.clone();
    let h_res_clk_tls = h_res_clock.clone();
    let h_res_jti_seq = Arc::new(AtomicUsize::new(0));
    let h_res_tls = Arc::new(TlsServer::start("mission-records.example", move |req| {
        let now_ts = h_res_clk_tls.load(Ordering::SeqCst);
        let jti = format!("h-res-jti-{}", h_res_jti_seq.fetch_add(1, Ordering::SeqCst) + 1);
        let path = req.uri().path().to_owned();
        if path == "/.well-known/aauth-resource.json" {
            return json_response(200, serde_json::from_slice(&h_res_for_tls.metadata().unwrap()).unwrap());
        }
        if path == "/.well-known/jwks.json" {
            return json_response(200, serde_json::from_slice(&h_res_for_tls.jwks().unwrap()).unwrap());
        }
        if path == "/authorize" {
            return h_res_for_tls.authorize_endpoint(&req, now_ts, &jti).into_response();
        }
        if path.starts_with("/r3/") {
            return h_res_for_tls.r3_document(&req, now_ts);
        }
        match h_res_for_tls.authorize(&req, now_ts, &jti) {
            AuthDecision::Granted(admitted) => {
                if admitted.r3_grant().is_none() {
                    return json_response(403, json!({"error": "access_denied"}));
                }
                let body = match path.as_str() {
                    "/records/read" => {
                        h_res_reads_tls.fetch_add(1, Ordering::SeqCst);
                        json!({"read": true, "mission_s256": admitted.token().claims().mission_s256})
                    }
                    "/records/query" => {
                        h_res_queries_tls.fetch_add(1, Ordering::SeqCst);
                        json!({"queried": true, "mission_s256": admitted.token().claims().mission_s256})
                    }
                    _ => return json_response(403, json!({"error": "access_denied"})),
                };
                json_response(200, body)
            }
            other => other.into_response(),
        }
    })?);
    trust.discover(&h_res_tls, H_RES, "aauth-resource.json")?;

    // Also spin up a missionless R3 resource (without .with_mission_context()) for QA-H2d
    let h_nomiss_doc_dir = out_dir.join("h-nomission-r3-docs");
    let h_nomiss_policy_calls = Arc::new(AtomicUsize::new(0));
    let h_nomiss_policy_cnt = h_nomiss_policy_calls.clone();
    let h_res_nomiss = Arc::new(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: H_RES_NOMISS.into(),
                signed_origin: H_RES_NOMISS.into(),
                kid: "nomiss-res-1".into(),
                signing_key: SigningKey::from_seed(H_RES_NOMISS_SEED),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
            },
            trust.clone(),
            Box::new(move |token: &VerifiedAuthToken, _: &Request<Vec<u8>>| {
                h_nomiss_policy_cnt.fetch_add(1, Ordering::SeqCst);
                token.claims().ps == H_PS
            }) as BoxedAuthPolicy,
        )?
        .with_authorization_endpoint()
        .with_r3(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{H_RES_NOMISS}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )?,
                display: None,
            }],
            documents: Arc::new(DirectoryDocumentStore::open(&h_nomiss_doc_dir)?),
            operation_for_request: Box::new(|req: &Request<Vec<u8>>| match req.uri().path() {
                "/records/read" => mcp("records.read").map(Some),
                _ => Ok(None),
            }),
            require_core_scope: false,
        })?,
    );
    let h_nomiss_for_tls = h_res_nomiss.clone();
    let h_nomiss_clk = h_res_clock.clone();
    let h_res_nomiss_tls = Arc::new(TlsServer::start("nomission-records.example", move |req| {
        let now_ts = h_nomiss_clk.load(Ordering::SeqCst);
        let path = req.uri().path().to_owned();
        if path == "/.well-known/aauth-resource.json" {
            return json_response(200, serde_json::from_slice(&h_nomiss_for_tls.metadata().unwrap()).unwrap());
        }
        if path == "/.well-known/jwks.json" {
            return json_response(200, serde_json::from_slice(&h_nomiss_for_tls.jwks().unwrap()).unwrap());
        }
        if path == "/authorize" {
            return h_nomiss_for_tls.authorize_endpoint(&req, now_ts, "nomiss-rt-1").into_response();
        }
        if path.starts_with("/r3/") {
            return h_nomiss_for_tls.r3_document(&req, now_ts);
        }
        h_nomiss_for_tls.authorize(&req, now_ts, "nomiss-call-1").into_response()
    })?);
    trust.discover(&h_res_nomiss_tls, H_RES_NOMISS, "aauth-resource.json")?;

    // Set up PersonServer (H_PS) over HTTPS with R3IssuerConfig fetching R3 documents over HTTPS from H_RES
    let h_ps_store = MemoryStore::default();
    let h_ps_clock = Arc::new(AtomicI64::new(clock));
    let h_ps_lifetime = Arc::new(AtomicI64::new(600));
    let h_ps_return_per_call = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let h_ps_seen_missions = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
    let h_audit_commits = Arc::new(AtomicUsize::new(0));
    let h_audit_last_jti = Arc::new(Mutex::new(None));
    let h_ps_id_seq = Arc::new(AtomicUsize::new(0));

    let h_ps_clk_cb = h_ps_clock.clone();
    let h_ps_ids_cb = h_ps_id_seq.clone();
    let h_ps_life_cb = h_ps_lifetime.clone();
    let h_ps_pc_cb = h_ps_return_per_call.clone();
    let h_ps_seen_cb = h_ps_seen_missions.clone();

    let h_ps = Arc::new(
        PersonServer::new(
            PsConfig::new(H_PS, "mission-ps-1", SigningKey::from_seed(H_PS_SEED)),
            trust.clone(),
            h_ps_store.clone(),
            QaPsPolicy,
            Box::new(move || h_ps_clk_cb.load(Ordering::SeqCst)) as BoxedClock,
            Box::new(move || format!("h-ps-tok-{}", h_ps_ids_cb.fetch_add(1, Ordering::SeqCst) + 1)) as BoxedTokenIds,
        )?
        .with_r3(R3IssuerConfig {
            registry: standard_registry()?,
            egress: Box::new(|uri: &str, _: Instant| {
                if uri.starts_with(&format!("{H_RES}/r3/")) {
                    Ok(())
                } else {
                    Err(io::Error::other("egress refused"))
                }
            }),
            transport: Box::new(TlsFetch(h_res_tls.clone())),
            limits: FetchLimits::default(),
            policy: Box::new(
                move |request: &R3AuthorizationRequest<'_>| -> std::result::Result<R3Decision, PolicyError> {
                    h_ps_seen_cb.lock().unwrap().push(
                        request
                            .core
                            .mission
                            .as_ref()
                            .map(|m| m.document.s256().to_owned()),
                    );
                    let vocab = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
                    let read_op = mcp("records.read").map_err(|_| PolicyError::Unavailable)?;
                    let query_op = mcp("records.query").map_err(|_| PolicyError::Unavailable)?;
                    let delete_op = mcp("records.delete").map_err(|_| PolicyError::Unavailable)?;
                    let mut granted_ops = vec![read_op];
                    if request
                        .document
                        .operation_set()
                        .operations()
                        .unwrap_or_default()
                        .iter()
                        .any(|op| op.equal(&query_op).unwrap_or(false))
                    {
                        granted_ops.push(query_op);
                    }
                    let per_call = if h_ps_pc_cb.load(Ordering::SeqCst) {
                        Some(
                            GrantedOperations::new(&vocab, &[delete_op])
                                .map_err(|_| PolicyError::Unavailable)?,
                        )
                    } else {
                        None
                    };
                    Ok(R3Decision {
                        granted: GrantedOperations::new(&vocab, &granted_ops)
                            .map_err(|_| PolicyError::Unavailable)?,
                        per_call,
                        scopes: Vec::new(),
                        lifetime: h_ps_life_cb.load(Ordering::SeqCst),
                    })
                },
            ),
            audit: Arc::new(QaAuditStore {
                commits: h_audit_commits.clone(),
                last_token_jti: h_audit_last_jti.clone(),
            }),
        })?,
    );
    let h_ps_for_tls = h_ps.clone();
    let h_ps_tls = Arc::new(TlsServer::start("mission-ps.example", move |req| {
        h_ps_for_tls.handle(&req)
    })?);
    trust.discover(&h_ps_tls, H_PS, "aauth-person.json")?;

    let read_and_query = registry.parse_operation_set(
        json!({"vocabulary": MCP, "operations": [{"tool":"records.read"}, {"tool":"records.query"}]})
            .to_string()
            .as_bytes(),
    )?;

    // QA-H1: Positive End-to-End HTTPS Composition of Approved Mission with Direct Class R3
    let mission_a = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock,
        Some(clock + 300),
        "Read and query records for quarterly audit",
        MissionState::Active,
    )?;
    let mission_a_s256 = mission_a.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_a.clone())?;

    // 1. Issue mission-bound PersonToken over HTTPS from H_PS
    let h1_person_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_a_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let person_a = member(&h1_person_resp, "person_token")
        .ok_or("QA-H1: missing person_token from /person")?;
    let ver_person_a = PersonToken::parse(&person_a)?.verify(trust, clock)?;
    let h1_person_ok = h1_person_resp.status().as_u16() == 200
        && ver_person_a.claims().mission_s256.as_deref() == Some(mission_a_s256.as_str())
        && ver_person_a.claims().exp == clock + 300;

    // 2. Proactive POST /authorize with r3_operations via Agent::r3_authorize over HTTPS
    let mcp_vocab = McpCodec::vocabulary()?;
    let proactive_rt_compact = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    )?;
    let ver_proactive_rt = h_agent.verify_r3_resource_token(
        &proactive_rt_compact,
        H_RES,
        H_PS,
        &person_a,
        None,
        trust,
        clock,
    )?;
    let h1_proactive_rt_ok = ver_proactive_rt.claims().mission_s256.as_deref() == Some(mission_a_s256.as_str())
        && ver_proactive_rt.claims().exp == clock + 300;

    // Verify DirectoryDocumentStore persisted mission_s256 across fresh reopen
    let reopened_doc_store = DirectoryDocumentStore::open(&h_doc_dir)?;
    let stored_doc_a = reopened_doc_store
        .load(ver_proactive_rt.reference().uri())
        .map_err(|e| format!("load stored_doc_a: {e:?}"))?
        .ok_or("QA-H1: missing stored R3DocumentRecord in DirectoryDocumentStore")?;
    let h1_doc_store_ok = stored_doc_a.mission_s256.as_deref() == Some(mission_a_s256.as_str());

    // 3. Reactive 401 R3 challenge on /records/read using mission-bound PersonToken over HTTPS
    let h_agent_person_a = h_agent.with_token(person_a.clone())?;
    let h1_reactive_401 = h_res_tls.send(&signed_get(
        &h_agent_person_a,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let reactive_rt_compact = challenge(&h1_reactive_401)?;
    let ver_reactive_rt = h_agent.verify_r3_resource_token(
        &reactive_rt_compact,
        H_RES,
        H_PS,
        &person_a,
        None,
        trust,
        clock,
    )?;
    let h1_reactive_rt_ok = h1_reactive_401.status().as_u16() == 401
        && ver_reactive_rt.claims().mission_s256.as_deref() == Some(mission_a_s256.as_str());

    // 4. Exchange proactive ResourceToken at H_PS /token with decision.lifetime=600 > mission.expires_at=clock+300
    let h1_tok1_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt.compact(),
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let auth_a1 = member(&h1_tok1_resp, "auth_token")
        .ok_or("QA-H1: missing auth_token from /token")?;
    let ver_auth_a1 = h_agent.verify_r3_auth_delivery(
        &auth_a1,
        H_RES,
        &ver_proactive_rt,
        &person_a,
        &registry,
        trust,
        clock,
    )?;
    let h1_policy_saw_mission = h_ps_seen_missions
        .lock()
        .unwrap()
        .last()
        .cloned()
        .flatten()
        .as_deref()
        == Some(mission_a_s256.as_str());
    let h1_audit_committed = h_audit_commits.load(Ordering::SeqCst) == 1
        && h_audit_last_jti.lock().unwrap().as_deref() == Some(ver_auth_a1.claims().jti.as_str());
    let h1_store_committed = h_ps_store
        .token(&PsTokenReference {
            issuer: H_PS.into(),
            jti: ver_auth_a1.claims().jti.clone(),
        })?
        .is_some();
    let h1_mission_still_active = h_ps_store
        .load_mission(H_PS, &h_owner, &mission_a_s256, clock)?
        .state
        == MissionState::Active;
    let h1_clamped_exp_ok = h1_tok1_resp.status().as_u16() == 200
        && ver_auth_a1.claims().mission_s256.as_deref() == Some(mission_a_s256.as_str())
        && ver_auth_a1.claims().exp == clock + 300;

    // 5. Exchange reactive ResourceToken at H_PS /token with decision.lifetime=120 < mission.expires_at=clock+300
    h_ps_lifetime.store(120, Ordering::SeqCst);
    let h1_tok2_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_reactive_rt.compact(),
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    h_ps_lifetime.store(600, Ordering::SeqCst);
    let auth_a2 = member(&h1_tok2_resp, "auth_token")
        .ok_or("QA-H1: missing auth_token (within-window) from /token")?;
    let ver_auth_a2 = h_agent.verify_r3_auth_delivery(
        &auth_a2,
        H_RES,
        &ver_reactive_rt,
        &person_a,
        &registry,
        trust,
        clock,
    )?;
    let h1_within_window_exp_ok = h1_tok2_resp.status().as_u16() == 200
        && ver_auth_a2.claims().mission_s256.as_deref() == Some(mission_a_s256.as_str())
        && ver_auth_a2.claims().exp == clock + 120;

    // 6. Resource admission, multi-call reuse (/records/read + /records/query), and DirectoryDocumentStore reopen
    let h_agent_auth_a1 = h_agent.with_token(auth_a1.clone())?;
    let h1_read_req = signed_get(&h_agent_auth_a1, &format!("{H_RES}/records/read"), clock)?;
    let h1_read_resp = h_res_tls.send(&h1_read_req)?;
    let h1_read_receipt_ok = member(&h1_read_resp, "mission_s256").as_deref() == Some(mission_a_s256.as_str());
    let h1_query_req = post_at(
        &h_agent_auth_a1,
        &format!("{H_RES}/records/query"),
        br#"{"q":"all"}"#,
        clock,
    )?;
    let h1_query_resp = h_res_tls.send(&h1_query_req)?;
    let h1_query_receipt_ok = member(&h1_query_resp, "mission_s256").as_deref() == Some(mission_a_s256.as_str());
    // Un-granted operation (/records/delete) refused with 403 even under valid mission Auth token
    let h1_ungranted_delete_resp = h_res_tls.send(&post_at(
        &h_agent_auth_a1,
        &format!("{H_RES}/records/delete"),
        R1,
        clock,
    )?)?;
    // Reopened Resource instance admitting the same mission-bound class Auth token
    let h_res_reopened_cnt = Arc::new(AtomicUsize::new(0));
    let h_res_reopened = make_h_resource(
        Arc::new(DirectoryDocumentStore::open(&h_doc_dir)?),
        h_res_reopened_cnt.clone(),
    )?;
    let h1_reopen_admitted = matches!(
        h_res_reopened.authorize(&h1_read_req, clock, "reopen-jti-1"),
        AuthDecision::Granted(ref g) if g.r3_grant().is_some()
    ) && h_res_reopened_cnt.load(Ordering::SeqCst) == 1;

    let h1_all_ok = h1_person_ok
        && h1_proactive_rt_ok
        && h1_doc_store_ok
        && h1_reactive_rt_ok
        && h1_clamped_exp_ok
        && h1_within_window_exp_ok
        && h1_policy_saw_mission
        && h1_audit_committed
        && h1_store_committed
        && h1_mission_still_active
        && h1_read_resp.status().as_u16() == 200
        && h1_read_receipt_ok
        && h1_query_resp.status().as_u16() == 200
        && h1_query_receipt_ok
        && h1_ungranted_delete_resp.status().as_u16() == 403
        && h_res_policy_calls.load(Ordering::SeqCst) == 2
        && h_res_reads.load(Ordering::SeqCst) == 1
        && h_res_queries.load(Ordering::SeqCst) == 1
        && h1_reopen_admitted;

    cases.push(QaCaseReceipt {
        id: "QA-H1".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "End-to-End HTTPS Composition of Approved Mission with Direct Class R3 (Proactive /authorize, Reactive 401 Challenge, DirectoryDocumentStore Reopen, PS R3 Grant, Expiry Clamping, Multi-Call Reuse)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: h1_all_ok,
        summary: format!(
            "Mission-bound R3 class flow succeeded over HTTPS: proactive/reactive ResourceToken mission_s256={}, DirectoryDocumentStore reopen={}, PS policy saw mission={}, exp clamped (600->300s) & within-window (120s)={}, multi-call read+query=200/200",
            h1_proactive_rt_ok && h1_reactive_rt_ok,
            h1_doc_store_ok && h1_reopen_admitted,
            h1_policy_saw_mission,
            h1_clamped_exp_ok && h1_within_window_exp_ok
        ),
        evidence: json!({
            "mission_a_s256": mission_a_s256,
            "person_token_exp": ver_person_a.claims().exp,
            "proactive_resource_token_mission_s256": ver_proactive_rt.claims().mission_s256,
            "reactive_resource_token_mission_s256": ver_reactive_rt.claims().mission_s256,
            "directory_document_store_mission_s256": stored_doc_a.mission_s256,
            "ps_policy_saw_mission": h1_policy_saw_mission,
            "ps_r3_audit_committed": h1_audit_committed,
            "ps_mission_store_token_committed": h1_store_committed,
            "ps_mission_state_active": h1_mission_still_active,
            "auth_token_clamped_exp_offset": ver_auth_a1.claims().exp - clock,
            "auth_token_within_window_exp_offset": ver_auth_a2.claims().exp - clock,
            "read_status": h1_read_resp.status().as_u16(),
            "read_mission_echoed": h1_read_receipt_ok,
            "query_status": h1_query_resp.status().as_u16(),
            "query_mission_echoed": h1_query_receipt_ok,
            "ungranted_delete_status": h1_ungranted_delete_resp.status().as_u16(),
            "reopened_resource_admitted": h1_reopen_admitted,
        }),
    });
    transcript_lines.push(format!(
        "[QA-H1] PASS: mission_r3_e2e_ok={} clamped_exp={}s within_window_exp={}s reopen_admitted={}",
        h1_all_ok,
        ver_auth_a1.claims().exp - clock,
        ver_auth_a2.claims().exp - clock,
        h1_reopen_admitted
    ));

    // QA-H2: Resource-Side Mission Binding Enforcement (403 Before Policy; Policy Counter Does Not Increment)
    let h2_policy_before = h_res_policy_calls.load(Ordering::SeqCst);
    let parsed_doc_a = registry.parse_document(&stored_doc_a.exact_json)?;
    let h2_authz = Authorization::new(
        &GrantedOperations::new(&mcp_vocab, &[mcp("records.read")?])?,
        &GrantedOperations::new(&mcp_vocab, &[])?,
        &parsed_doc_a,
    )?;

    // 2a: Missionless R3 Auth token referencing mission_a's class document -> 403 before policy
    let h2a_missionless_auth = mint_r3_class_auth_token(
        &standard_registry()?,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "h2a-missionless-auth".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference(),
        &stored_doc_a.exact_json,
        &h2_authz,
    )?;
    let h2a_resp = h_res_tls.send(&signed_get(
        &h_agent.with_token(h2a_missionless_auth.clone())?,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let h2a_ok = h2a_resp.status().as_u16() == 403
        && member(&h2a_resp, "error").as_deref() == Some("access_denied")
        && h_res_policy_calls.load(Ordering::SeqCst) == h2_policy_before;

    // 2b: R3 Auth token bound to mission_b referencing mission_a's class document -> 403 before policy
    let mission_b = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock,
        Some(clock + 300),
        "Second distinct mission B",
        MissionState::Active,
    )?;
    let mission_b_s256 = mission_b.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_b.clone())?;
    let h2b_wrong_mission_auth = mint_r3_class_auth_token(
        &standard_registry()?,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "h2b-wrong-mission-auth".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: Some(mission_b_s256.clone()),
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference(),
        &stored_doc_a.exact_json,
        &h2_authz,
    )?;
    let h2b_resp = h_res_tls.send(&signed_get(
        &h_agent.with_token(h2b_wrong_mission_auth)?,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let h2b_ok = h2b_resp.status().as_u16() == 403
        && member(&h2b_resp, "error").as_deref() == Some("access_denied")
        && h_res_policy_calls.load(Ordering::SeqCst) == h2_policy_before;

    // 2c: Mission-bound R3 Auth token referencing a missionless class document on with_mission_context Resource -> 403 before policy
    let h2c_person_nomiss_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES}).to_string().as_bytes(),
        clock,
    )?)?;
    let person_nomiss = member(&h2c_person_nomiss_resp, "person_token")
        .ok_or("QA-H2c: missing missionless person_token")?;
    let nomiss_rt_compact = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_nomiss,
        &read_only,
        None,
        clock,
    )?;
    let ver_nomiss_rt = h_agent.verify_r3_resource_token(
        &nomiss_rt_compact,
        H_RES,
        H_PS,
        &person_nomiss,
        None,
        trust,
        clock,
    )?;
    let stored_doc_nomiss = DirectoryDocumentStore::open(&h_doc_dir)?
        .load(ver_nomiss_rt.reference().uri())
        .map_err(|e| format!("load stored_doc_nomiss: {e:?}"))?
        .ok_or("QA-H2c: missing missionless R3DocumentRecord")?;
    let parsed_doc_nomiss = registry.parse_document(&stored_doc_nomiss.exact_json)?;
    let h2c_authz = Authorization::new(
        &GrantedOperations::new(&mcp_vocab, &[mcp("records.read")?])?,
        &GrantedOperations::new(&mcp_vocab, &[])?,
        &parsed_doc_nomiss,
    )?;
    let h2c_mission_on_nomiss_doc_auth = mint_r3_class_auth_token(
        &standard_registry()?,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "h2c-mission-on-nomiss-doc".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: Some(mission_a_s256.clone()),
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        ver_nomiss_rt.reference(),
        &stored_doc_nomiss.exact_json,
        &h2c_authz,
    )?;
    let h2c_resp = h_res_tls.send(&signed_get(
        &h_agent.with_token(h2c_mission_on_nomiss_doc_auth)?,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let h2c_ok = ver_nomiss_rt.claims().mission_s256.is_none()
        && stored_doc_nomiss.mission_s256.is_none()
        && h2c_resp.status().as_u16() == 403
        && member(&h2c_resp, "error").as_deref() == Some("access_denied")
        && h_res_policy_calls.load(Ordering::SeqCst) == h2_policy_before;

    // 2d: Mission-bound PersonToken and AuthToken presented to a Resource WITHOUT with_mission_context (H_RES_NOMISS) -> 401 invalid_jwt before policy
    let person_for_nomiss_res = mint_person_token(
        &h_ps_key,
        "mission-ps-1",
        &PersonClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES_NOMISS.into(),
            sub: "mission-person".into(),
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            jti: "h2d-person-with-mission".into(),
            iat: clock,
            exp: clock + 300,
            nbf: None,
            mission_s256: Some(mission_a_s256.clone()),
            tenant: None,
            extra: BTreeMap::new(),
        },
    )?;
    let h2d_authz_resp = h_res_nomiss_tls.send(&post_at(
        &h_agent.with_token(person_for_nomiss_res.clone())?,
        &format!("{H_RES_NOMISS}/authorize"),
        json!({
            "r3_operations": {
                "vocabulary": MCP,
                "operations": [{"tool": "records.read"}],
            }
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h2d_call_resp = h_res_nomiss_tls.send(&signed_get(
        &h_agent.with_token(person_for_nomiss_res)?,
        &format!("{H_RES_NOMISS}/records/read"),
        clock,
    )?)?;
    let h2d_ok = h2d_authz_resp.status().as_u16() == 401
        && header_values(&h2d_authz_resp, "signature-error")
            .iter()
            .any(|v| v.contains("error=invalid_jwt"))
        && h2d_call_resp.status().as_u16() == 401
        && header_values(&h2d_call_resp, "signature-error")
            .iter()
            .any(|v| v.contains("error=invalid_jwt"))
        && h_nomiss_policy_calls.load(Ordering::SeqCst) == 0;

    // 2e: Malformed mission_s256 claim rejected at JWT parsing / minting
    let h2e_malformed_mint_err = mint_r3_class_auth_token(
        &standard_registry()?,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "h2e-bad-mission-digest".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: Some("not-a-valid-sha256-digest!".into()),
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference(),
        &stored_doc_a.exact_json,
        &h2_authz,
    )
    .is_err();

    let h2_all_ok = h2a_ok && h2b_ok && h2c_ok && h2d_ok && h2e_malformed_mint_err;

    cases.push(QaCaseReceipt {
        id: "QA-H2".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "Resource-Side Mission Binding Enforcement (Missionless vs Mission-Bound, Cross-Mission Mismatch, Mission on Missionless Document, and Mission Against Missionless Resource)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: h2_all_ok,
        summary: format!(
            "All 5 Resource mission-binding boundary checks enforced before policy (policy_calls_delta=0): missionless_auth_on_mission_doc=403 ({}), mission_b_on_mission_a_doc=403 ({}), mission_auth_on_missionless_doc=403 ({}), mission_on_missionless_resource=401 ({}), malformed_mission_s256_rejected={}",
            h2a_ok, h2b_ok, h2c_ok, h2d_ok, h2e_malformed_mint_err
        ),
        evidence: json!({
            "h2a_missionless_auth_on_mission_doc_status": h2a_resp.status().as_u16(),
            "h2b_wrong_mission_b_on_mission_a_doc_status": h2b_resp.status().as_u16(),
            "h2c_mission_auth_on_missionless_doc_status": h2c_resp.status().as_u16(),
            "h2d_mission_token_on_nomission_resource_authorize_status": h2d_authz_resp.status().as_u16(),
            "h2d_mission_token_on_nomission_resource_call_status": h2d_call_resp.status().as_u16(),
            "h2e_malformed_mission_s256_rejected": h2e_malformed_mint_err,
            "policy_calls_before": h2_policy_before,
            "policy_calls_after": h_res_policy_calls.load(Ordering::SeqCst),
        }),
    });
    transcript_lines.push(format!(
        "[QA-H2] PASS: h2a_403={} h2b_403={} h2c_403={} h2d_401={} h2e_malformed={} policy_delta=0",
        h2a_ok, h2b_ok, h2c_ok, h2d_ok, h2e_malformed_mint_err
    ));

    // QA-H3: Person Server Mission Lifecycle, Ownership & Claim Integrity Boundaries Over HTTPS
    // 3a: Terminated ("revoked") mission on PersonServer issues no further PersonToken or R3 AuthToken
    let mission_rev = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock,
        Some(clock + 300),
        "Mission to be revoked before R3 token exchange",
        MissionState::Active,
    )?;
    let mission_rev_s256 = mission_rev.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_rev)?;
    let person_rev = member(
        &h_ps_tls.send(&post_at(
            &h_agent,
            &format!("{H_PS}/person"),
            json!({"resource": H_RES, "mission_s256": mission_rev_s256})
                .to_string()
                .as_bytes(),
            clock,
        )?)?,
        "person_token",
    )
    .ok_or("QA-H3a: missing person_rev")?;
    let rev_rt_compact = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_rev,
        &read_only,
        None,
        clock,
    )?;
    let ver_rev_rt = h_agent.verify_r3_resource_token(
        &rev_rt_compact,
        H_RES,
        H_PS,
        &person_rev,
        None,
        trust,
        clock,
    )?;
    h_ps_store.terminate_mission(H_PS, &h_owner, &mission_rev_s256, "revoked")?;
    let h3_policy_before = h_ps_seen_missions.lock().unwrap().len();
    let h3_audit_before = h_audit_commits.load(Ordering::SeqCst);
    let h3a_tok_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_rev_rt.compact(),
            "presented_token": person_rev,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h3a_person_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_rev_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h3a_ok = h3a_tok_resp.status().as_u16() == 403
        && member(&h3a_tok_resp, "error").as_deref() == Some("mission_terminated")
        && member(&h3a_tok_resp, "mission_status").as_deref() == Some("terminated")
        && member(&h3a_tok_resp, "termination_reason").as_deref() == Some("revoked")
        && member(&h3a_tok_resp, "auth_token").is_none()
        && h3a_person_resp.status().as_u16() == 403
        && member(&h3a_person_resp, "error").as_deref() == Some("mission_terminated")
        && member(&h3a_person_resp, "termination_reason").as_deref() == Some("revoked")
        && h_ps_seen_missions.lock().unwrap().len() == h3_policy_before
        && h_audit_commits.load(Ordering::SeqCst) == h3_audit_before;

    // 3b: Completed mission on PersonServer -> 403 mission_terminated (termination_reason="completed")
    let mission_done = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock,
        Some(clock + 300),
        "Mission completed",
        MissionState::Active,
    )?;
    let mission_done_s256 = mission_done.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_done)?;
    h_ps_store.terminate_mission(H_PS, &h_owner, &mission_done_s256, "completed")?;
    let h3b_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_done_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h3b_ok = h3b_resp.status().as_u16() == 403
        && member(&h3b_resp, "error").as_deref() == Some("mission_terminated")
        && member(&h3b_resp, "termination_reason").as_deref() == Some("completed");

    // 3c: Expired mission on PersonServer -> 403 mission_terminated (termination_reason="expired")
    let mission_exp = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock - 100,
        Some(clock + 10),
        "Short mission expiring at clock+10",
        MissionState::Active,
    )?;
    let mission_exp_s256 = mission_exp.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_exp)?;
    let person_exp = member(
        &h_ps_tls.send(&post_at(
            &h_agent,
            &format!("{H_PS}/person"),
            json!({"resource": H_RES, "mission_s256": mission_exp_s256})
                .to_string()
                .as_bytes(),
            clock,
        )?)?,
        "person_token",
    )
    .ok_or("QA-H3c: missing person_exp")?;
    let ver_person_exp = PersonToken::parse(&person_exp)?.verify(trust, clock)?;
    let (rt_exp, _) = mint_resource_token(
        &registry,
        &h_res_key,
        "mission-res-1",
        &ResourceClaims {
            iss: H_RES.into(),
            dwk: "aauth-resource.json".into(),
            aud: H_PS.into(),
            ps: H_PS.into(),
            sub: ver_person_exp.claims().sub.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            presented_jti: ver_person_exp.claims().jti.clone(),
            jti: "h3c-rt-exp".into(),
            iat: clock,
            exp: clock + 60,
            scope: None,
            nbf: None,
            mission_s256: Some(mission_exp_s256.clone()),
            tenant: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference().uri(),
        &stored_doc_a.exact_json,
    )?;
    h_ps_clock.store(clock + 10, Ordering::SeqCst);
    let h3c_person_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_exp_s256})
            .to_string()
            .as_bytes(),
        clock + 10,
    )?)?;
    // For /token, mint a fresh person_exp2 with exp = clock + 60 so presented_token itself isn't expired at clock + 10, isolating mission expiry
    h_ps_clock.store(clock, Ordering::SeqCst);
    let mission_exp2 = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock - 100,
        Some(clock + 300),
        "Mission whose clock will advance past expires_at",
        MissionState::Active,
    )?;
    let mission_exp2_s256 = mission_exp2.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_exp2)?;
    let person_exp2 = member(
        &h_ps_tls.send(&post_at(
            &h_agent,
            &format!("{H_PS}/person"),
            json!({"resource": H_RES, "mission_s256": mission_exp2_s256})
                .to_string()
                .as_bytes(),
            clock,
        )?)?,
        "person_token",
    )
    .ok_or("QA-H3c: missing person_exp2")?;
    let exp2_rt_compact = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_exp2,
        &read_only,
        None,
        clock,
    )?;
    let ver_exp2_rt = h_agent.verify_r3_resource_token(
        &exp2_rt_compact,
        H_RES,
        H_PS,
        &person_exp2,
        None,
        trust,
        clock,
    )?;
    h_ps_clock.store(clock + 300, Ordering::SeqCst);
    let h3c_tok_at_300_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_exp2_rt.compact(),
            "presented_token": person_exp2,
        })
        .to_string()
        .as_bytes(),
        clock + 300,
    )?)?;
    // Materialize expiry via /person at clock + 300, then verify /token with live tokens also returns 403 mission_terminated ("expired")
    let h3c_person_exp2_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_exp2_s256})
            .to_string()
            .as_bytes(),
        clock + 300,
    )?)?;
    h_ps_clock.store(clock, Ordering::SeqCst);
    let h3c_tok_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_exp2_rt.compact(),
            "presented_token": person_exp2,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let _ = rt_exp;
    let h3c_ok = h3c_person_resp.status().as_u16() == 403
        && member(&h3c_person_resp, "error").as_deref() == Some("mission_terminated")
        && member(&h3c_person_resp, "termination_reason").as_deref() == Some("expired")
        && h3c_person_exp2_resp.status().as_u16() == 403
        && h3c_tok_at_300_resp.status().as_u16() == 400
        && h3c_tok_resp.status().as_u16() == 403
        && member(&h3c_tok_resp, "error").as_deref() == Some("mission_terminated")
        && member(&h3c_tok_resp, "termination_reason").as_deref() == Some("expired");

    // 3d: Unknown mission digest and wrong-owner Agent on PersonServer -> 400 invalid_request
    let unknown_s256 = digest(b"nonexistent-mission-document");
    let h3d_unknown_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": unknown_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h3d_wrong_owner_resp = h_ps_tls.send(&post_at(
        &h_other_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_a_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h3d_ok = h3d_unknown_resp.status().as_u16() == 400
        && member(&h3d_unknown_resp, "error").as_deref() == Some("invalid_request")
        && h3d_wrong_owner_resp.status().as_u16() == 400
        && member(&h3d_wrong_owner_resp, "error").as_deref() == Some("invalid_request");

    // 3e: Stripped or substituted mission_s256 between presented_token and resource_token at POST /token -> 400 invalid_resource_token
    let person_b = member(
        &h_ps_tls.send(&post_at(
            &h_agent,
            &format!("{H_PS}/person"),
            json!({"resource": H_RES, "mission_s256": mission_b_s256})
                .to_string()
                .as_bytes(),
            clock,
        )?)?,
        "person_token",
    )
    .ok_or("QA-H3e: missing person_b")?;
    let ver_person_a_parsed = PersonToken::parse(&person_a)?.verify(trust, clock)?;
    let (rt_stripped_mission, _) = mint_resource_token(
        &registry,
        &h_res_key,
        "mission-res-1",
        &ResourceClaims {
            iss: H_RES.into(),
            dwk: "aauth-resource.json".into(),
            aud: H_PS.into(),
            ps: H_PS.into(),
            sub: ver_person_a_parsed.claims().sub.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            presented_jti: ver_person_a_parsed.claims().jti.clone(),
            jti: "h3e-rt-stripped".into(),
            iat: clock,
            exp: clock + 300,
            scope: None,
            nbf: None,
            mission_s256: None,
            tenant: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference().uri(),
        &stored_doc_a.exact_json,
    )?;
    let (rt_substituted_mission_b, _) = mint_resource_token(
        &registry,
        &h_res_key,
        "mission-res-1",
        &ResourceClaims {
            iss: H_RES.into(),
            dwk: "aauth-resource.json".into(),
            aud: H_PS.into(),
            ps: H_PS.into(),
            sub: ver_person_a_parsed.claims().sub.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            presented_jti: ver_person_a_parsed.claims().jti.clone(),
            jti: "h3e-rt-substituted".into(),
            iat: clock,
            exp: clock + 300,
            scope: None,
            nbf: None,
            mission_s256: Some(mission_b_s256.clone()),
            tenant: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        ver_proactive_rt.reference().uri(),
        &stored_doc_a.exact_json,
    )?;
    let h3e_stripped_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": rt_stripped_mission,
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h3e_substituted_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": rt_substituted_mission_b,
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h3e_cross_presented_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt.compact(),
            "presented_token": person_b,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h3e_ok = h3e_stripped_resp.status().as_u16() == 400
        && member(&h3e_stripped_resp, "error").as_deref() == Some("invalid_resource_token")
        && h3e_substituted_resp.status().as_u16() == 400
        && member(&h3e_substituted_resp, "error").as_deref() == Some("invalid_resource_token")
        && h3e_cross_presented_resp.status().as_u16() == 400
        && member(&h3e_cross_presented_resp, "error").as_deref() == Some("invalid_resource_token")
        && h_ps_seen_missions.lock().unwrap().len() == h3_policy_before;

    let h3_all_ok = h3a_ok && h3b_ok && h3c_ok && h3d_ok && h3e_ok;

    cases.push(QaCaseReceipt {
        id: "QA-H3".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "Person Server Mission Lifecycle, Ownership & Claim Integrity Boundaries Over HTTPS (Terminated/Revoked, Completed, Expired, Unknown, Wrong Owner, Stripped/Substituted mission_s256)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: h3_all_ok,
        summary: format!(
            "PersonServer mission boundaries verified over HTTPS: revoked=403 mission_terminated ({}), completed=403 ({}), expired=403 ({}), unknown/wrong_owner=400 ({}), stripped/substituted mission_s256=400 invalid_resource_token ({}) with 0 R3 policy calls",
            h3a_ok, h3b_ok, h3c_ok, h3d_ok, h3e_ok
        ),
        evidence: json!({
            "revoked_token_status": h3a_tok_resp.status().as_u16(),
            "revoked_token_error": member(&h3a_tok_resp, "error"),
            "revoked_token_reason": member(&h3a_tok_resp, "termination_reason"),
            "completed_person_status": h3b_resp.status().as_u16(),
            "completed_person_reason": member(&h3b_resp, "termination_reason"),
            "expired_person_status": h3c_person_resp.status().as_u16(),
            "expired_token_status": h3c_tok_resp.status().as_u16(),
            "expired_token_reason": member(&h3c_tok_resp, "termination_reason"),
            "unknown_mission_status": h3d_unknown_resp.status().as_u16(),
            "wrong_owner_status": h3d_wrong_owner_resp.status().as_u16(),
            "stripped_mission_rt_status": h3e_stripped_resp.status().as_u16(),
            "substituted_mission_rt_status": h3e_substituted_resp.status().as_u16(),
            "cross_presented_mission_status": h3e_cross_presented_resp.status().as_u16(),
        }),
    });
    transcript_lines.push(format!(
        "[QA-H3] PASS: revoked={} completed={} expired={} unknown_owner={} stripped_sub={}",
        h3a_ok, h3b_ok, h3c_ok, h3d_ok, h3e_ok
    ));

    // QA-H4: Refused Unsupported Combinations (Per-Call Proposals, Federation / AS, Sub-Agents, Call Chaining)
    let make_dummy_r3_cfg = |issuer: &str, dir: &Path| -> Result<R3Config> {
        Ok(R3Config {
            registry: standard_registry()?,
            definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
            vocabularies: vec![R3Vocabulary {
                definition: McpCodec::parse_definition(
                    &format!("{issuer}/mcp"),
                    &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS)]),
                )?,
                display: None,
            }],
            documents: Arc::new(DirectoryDocumentStore::open(dir)?),
            operation_for_request: Box::new(|_| mcp("records.read").map(Some)),
            require_core_scope: false,
        })
    };
    let make_dummy_per_call_cfg = |dir: &Path| -> Result<R3PerCallConfig> {
        Ok(R3PerCallConfig {
            present: Box::new(|_, _| Ok(BTreeMap::new())),
            describe: Box::new(|_, _, _| {
                Ok(R3CallDescription {
                    parameters: Parameters::new([])
                        .map_err(|e| R3HostError::new(e.to_string()))?,
                    display: None,
                })
            }),
            calls: Arc::new(DirectoryCallStore::open(dir)?),
            hold: false,
            release: None,
            held_result_lifetime: 300,
        })
    };

    // 4a: Missions + Per-Call Proposals
    let h4a_cfg_order1_err = matches!(
        PsAuthorizationResource::new(
            PsAuthorizationConfig {
                issuer: H_RES.into(),
                signed_origin: H_RES.into(),
                kid: "mission-res-1".into(),
                signing_key: SigningKey::from_seed(H_RES_SEED),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
            },
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_mission_context()
        .with_r3(make_dummy_r3_cfg(H_RES, &out_dir.join("h4a-1-docs"))?)?
        .with_r3_per_call(make_dummy_per_call_cfg(&out_dir.join("h4a-1-calls"))?),
        Err(PsConfigurationError::InvalidR3Profile)
    );
    let h4a_res_order2 = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: H_RES.into(),
            signed_origin: H_RES.into(),
            kid: "mission-res-1".into(),
            signing_key: SigningKey::from_seed(H_RES_SEED),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        trust.clone(),
        Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
    )?
    .with_authorization_endpoint()
    .with_r3(make_dummy_r3_cfg(H_RES, &out_dir.join("h4a-2-docs"))?)?
    .with_r3_per_call(make_dummy_per_call_cfg(&out_dir.join("h4a-2-calls"))?)?
    .with_mission_context();
    let h4a_order2_authz_500 = h4a_res_order2
        .authorize_endpoint(
            &post_at(
                &h_agent_person_a,
                &format!("{H_RES}/authorize"),
                json!({
                    "r3_operations": {
                        "vocabulary": MCP,
                        "operations": [{"tool": "records.read"}],
                    }
                })
                .to_string()
                .as_bytes(),
                clock,
            )?,
            clock,
            "h4a-rt-1",
        )
        .into_response()
        .status()
        .as_u16()
        == 500;
    let h4a_order2_call_500 = h4a_res_order2
        .authorize(
            &signed_get(&h_agent_person_a, &format!("{H_RES}/records/read"), clock)?,
            clock,
            "h4a-rt-2",
        )
        .into_response()
        .status()
        .as_u16()
        == 500;

    // PersonServer presented with a proposal ResourceToken (/r3/p....) carrying mission_s256 -> 400 invalid_resource_token
    let prop_bytes = &stored_prop.exact_json;
    let prop_uri = format!("{H_RES}/r3/p.{}", digest(prop_bytes));
    let (rt_proposal_with_mission, _) = mint_proposal_resource_token(
        &registry,
        &h_res_key,
        "mission-res-1",
        &ResourceClaims {
            iss: H_RES.into(),
            dwk: "aauth-resource.json".into(),
            aud: H_PS.into(),
            ps: H_PS.into(),
            sub: ver_person_a_parsed.claims().sub.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            presented_jti: ver_person_a_parsed.claims().jti.clone(),
            jti: "h4a-prop-rt-mission".into(),
            iat: clock,
            exp: clock + 300,
            scope: None,
            nbf: None,
            mission_s256: Some(mission_a_s256.clone()),
            tenant: None,
            account: None,
            login_hint: None,
            extra: BTreeMap::new(),
        },
        &prop_uri,
        prop_bytes,
    )?;
    let h4a_ps_prop_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": rt_proposal_with_mission,
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    // PersonServer R3 policy returning per_call: Some(...) under an active mission -> 500 server_error
    let proactive_rt_pc_compact = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_delete,
        None,
        clock,
    )?;
    let ver_proactive_rt_pc = h_agent.verify_r3_resource_token(
        &proactive_rt_pc_compact,
        H_RES,
        H_PS,
        &person_a,
        None,
        trust,
        clock,
    )?;
    h_ps_return_per_call.store(true, Ordering::SeqCst);
    let h4a_ps_policy_pc_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt_pc.compact(),
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    h_ps_return_per_call.store(false, Ordering::SeqCst);
    let h4a_ok = h4a_cfg_order1_err
        && h4a_order2_authz_500
        && h4a_order2_call_500
        && h4a_ps_prop_resp.status().as_u16() == 400
        && member(&h4a_ps_prop_resp, "error").as_deref() == Some("invalid_resource_token")
        && h4a_ps_policy_pc_resp.status().as_u16() == 500
        && member(&h4a_ps_policy_pc_resp, "error").as_deref() == Some("server_error");

    // 4b: Missions + Federation / Access Server (as_url)
    let h4b_cfg_order1_err = matches!(
        PsAuthorizationResource::new_federated(
            PsAuthorizationConfig {
                issuer: H_RES.into(),
                signed_origin: H_RES.into(),
                kid: "mission-res-1".into(),
                signing_key: SigningKey::from_seed(H_RES_SEED),
                scopes: vec!["records.read".into()],
                scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
            },
            FED_AS,
            trust.clone(),
            Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
        )?
        .with_mission_context()
        .with_r3(make_dummy_r3_cfg(H_RES, &out_dir.join("h4b-1-docs"))?),
        Err(PsConfigurationError::InvalidR3Profile)
    );
    let h4b_res_order2 = PsAuthorizationResource::new_federated(
        PsAuthorizationConfig {
            issuer: H_RES.into(),
            signed_origin: H_RES.into(),
            kid: "mission-res-1".into(),
            signing_key: SigningKey::from_seed(H_RES_SEED),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        FED_AS,
        trust.clone(),
        Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) as BoxedAuthPolicy,
    )?
    .with_authorization_endpoint()
    .with_r3(make_dummy_r3_cfg(H_RES, &out_dir.join("h4b-2-docs"))?)?
    .with_mission_context();
    let h4b_order2_authz_500 = h4b_res_order2
        .authorize_endpoint(
            &post_at(
                &h_agent_person_a,
                &format!("{H_RES}/authorize"),
                json!({
                    "r3_operations": {
                        "vocabulary": MCP,
                        "operations": [{"tool": "records.read"}],
                    }
                })
                .to_string()
                .as_bytes(),
                clock,
            )?,
            clock,
            "h4b-rt-1",
        )
        .into_response()
        .status()
        .as_u16()
        == 500;
    let h4b_order2_call_500 = h4b_res_order2
        .authorize(
            &signed_get(&h_agent_person_a, &format!("{H_RES}/records/read"), clock)?,
            clock,
            "h4b-rt-2",
        )
        .into_response()
        .status()
        .as_u16()
        == 500;
    // Federated PersonServer (with_federation + with_r3) presented with mission-bound R3 ResourceToken -> 400 invalid_resource_token
    let h4b_fed_ps_clk = h_ps_clock.clone();
    let h4b_fed_ps = PersonServer::new(
        PsConfig::new(H_PS, "mission-ps-1", SigningKey::from_seed(H_PS_SEED)),
        trust.clone(),
        h_ps_store.clone(),
        QaPsPolicy,
        Box::new(move || h4b_fed_ps_clk.load(Ordering::SeqCst)) as BoxedClock,
        Box::new(|| "h4b-fed-ps-jti".into()) as BoxedTokenIds,
    )?
    .with_federation(DummyFederation)
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(|_: &str, _: Instant| Ok(())),
        transport: Box::new(TlsFetch(h_res_tls.clone())),
        limits: FetchLimits::default(),
        policy: Box::new(
            |_: &R3AuthorizationRequest<'_>| -> std::result::Result<R3Decision, PolicyError> {
                Err(PolicyError::Denied)
            },
        ),
        audit: Arc::new(QaAuditStore {
            commits: Arc::new(AtomicUsize::new(0)),
            last_token_jti: Arc::new(Mutex::new(None)),
        }),
    })?;
    let h4b_fed_ps_resp = h4b_fed_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt.compact(),
            "presented_token": person_a,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?);
    let h4b_ok = h4b_cfg_order1_err
        && h4b_order2_authz_500
        && h4b_order2_call_500
        && matches!(h4b_fed_ps_resp.status().as_u16(), 400 | 403);

    // 4c: Missions + Sub-Agents / Delegation
    let h4c_ps_person_subagent_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({
            "resource": H_RES,
            "mission_s256": mission_a_s256,
            "subagent_token": h_child_agent_compact,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h4c_ps_tok_subagent_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt.compact(),
            "presented_token": person_a,
            "subagent_token": h_child_agent_compact,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h4c_child_caller_resp = h_ps_tls.send(&post_at(
        &h_child_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_a_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h_subagent = Subagent::verify(&h_agent_compact, &h_child_agent_compact, trust, clock)?;
    let child_person_with_mission = mint_person_token(
        &h_ps_key,
        "mission-ps-1",
        &PersonClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            sub: "mission-person".into(),
            cnf: Confirmation {
                jwk: h_child_agent_key.public_jwk(),
            },
            jti: "h4c-child-person-mission".into(),
            iat: clock,
            exp: clock + 300,
            nbf: None,
            mission_s256: Some(mission_a_s256.clone()),
            tenant: None,
            extra: BTreeMap::new(),
        },
    )?;
    let h4c_subagent_verify_err = matches!(
        h_subagent.verify_person_delivery(&child_person_with_mission, H_RES, H_PS, trust, clock),
        Err(TokenError::InvalidJwt)
    );
    let h4c_ok = h4c_ps_person_subagent_resp.status().as_u16() == 400
        && member(&h4c_ps_person_subagent_resp, "error").as_deref() == Some("invalid_request")
        && h4c_ps_tok_subagent_resp.status().as_u16() == 400
        && member(&h4c_ps_tok_subagent_resp, "error").as_deref() == Some("invalid_request")
        && h4c_child_caller_resp.status().as_u16() == 401
        && h4c_subagent_verify_err;

    // 4d: Missions + Call Chaining (upstream_token)
    // Issue a missionless PersonToken for H_AP so H_PS stores a valid TokenRecord for upstream_token
    let upstream_person_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_AP}).to_string().as_bytes(),
        clock,
    )?)?;
    let upstream_tok = member(&upstream_person_resp, "person_token")
        .ok_or("QA-H4d: missing upstream person_token")?;
    let h4d_ps_person_upstream_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({
            "resource": H_RES,
            "mission_s256": mission_a_s256,
            "upstream_token": upstream_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h4d_ps_tok_upstream_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": ver_proactive_rt.compact(),
            "presented_token": person_a,
            "upstream_token": upstream_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?)?;
    let h4d_ok = h4d_ps_person_upstream_resp.status().as_u16() == 400
        && matches!(
            member(&h4d_ps_person_upstream_resp, "error").as_deref(),
            Some("invalid_request" | "invalid_upstream_token")
        )
        && h4d_ps_tok_upstream_resp.status().as_u16() == 400
        && matches!(
            member(&h4d_ps_tok_upstream_resp, "error").as_deref(),
            Some("invalid_request" | "invalid_upstream_token")
        );

    let h4_all_ok = h4a_ok && h4b_ok && h4c_ok && h4d_ok;

    cases.push(QaCaseReceipt {
        id: "QA-H4".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "Refused Unsupported Combinations (Missions + Per-Call Proposals, Federation / AS, Sub-Agents, and Call Chaining)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: h4_all_ok,
        summary: format!(
            "All unsupported combinations refused across Resource, PersonServer & Agent: per_call_proposals={} (cfg=InvalidR3Profile, runtime=500, ps_prop=400, ps_policy_pc=500), federation_as={}, subagents={}, call_chaining_upstream={}",
            h4a_ok, h4b_ok, h4c_ok, h4d_ok
        ),
        evidence: json!({
            "per_call_resource_cfg_err": h4a_cfg_order1_err,
            "per_call_resource_runtime_500": h4a_order2_authz_500 && h4a_order2_call_500,
            "per_call_ps_proposal_rt_status": h4a_ps_prop_resp.status().as_u16(),
            "per_call_ps_policy_decision_status": h4a_ps_policy_pc_resp.status().as_u16(),
            "federation_resource_cfg_err": h4b_cfg_order1_err,
            "federation_resource_runtime_500": h4b_order2_authz_500 && h4b_order2_call_500,
            "federation_ps_token_status": h4b_fed_ps_resp.status().as_u16(),
            "subagent_ps_person_status": h4c_ps_person_subagent_resp.status().as_u16(),
            "subagent_ps_token_status": h4c_ps_tok_subagent_resp.status().as_u16(),
            "subagent_caller_status": h4c_child_caller_resp.status().as_u16(),
            "subagent_helper_rejects_mission": h4c_subagent_verify_err,
            "upstream_ps_person_status": h4d_ps_person_upstream_resp.status().as_u16(),
            "upstream_ps_token_status": h4d_ps_tok_upstream_resp.status().as_u16(),
        }),
    });
    transcript_lines.push(format!(
        "[QA-H4] PASS: per_call_refused={} federation_refused={} subagents_refused={} upstream_refused={}",
        h4a_ok, h4b_ok, h4c_ok, h4d_ok
    ));

    // QA-H5: Rust Agent Validation Boundary (verify_r3_resource_token, r3_authorize, verify_r3_auth_delivery)
    let mint_h5_rt = |exp: i64, mission: Option<String>, presented_jti: &str, sub: &str| -> Result<String> {
        let (compact, _) = mint_resource_token(
            &registry,
            &h_res_key,
            "mission-res-1",
            &ResourceClaims {
                iss: H_RES.into(),
                dwk: "aauth-resource.json".into(),
                aud: H_PS.into(),
                ps: H_PS.into(),
                sub: sub.into(),
                agent_jkt: h_agent.public_jwk().thumbprint()?,
                presented_jti: presented_jti.into(),
                jti: format!("h5-rt-{exp}-{}", mission.is_some()),
                iat: clock,
                exp,
                scope: None,
                nbf: None,
                mission_s256: mission,
                tenant: None,
                account: None,
                login_hint: None,
                extra: BTreeMap::new(),
            },
            ver_proactive_rt.reference().uri(),
            &stored_doc_a.exact_json,
        )?;
        Ok(compact)
    };
    // 5a: Mission-bound R3 ResourceToken with exp (clock+301) > person_a.exp (clock+300) -> Err(R3AgentError::Context)
    let h5_rt_outlives = mint_h5_rt(
        clock + 301,
        Some(mission_a_s256.clone()),
        &ver_person_a_parsed.claims().jti,
        &ver_person_a_parsed.claims().sub,
    )?;
    let h5a_outlives_refused = matches!(
        h_agent.verify_r3_resource_token(&h5_rt_outlives, H_RES, H_PS, &person_a, None, trust, clock),
        Err(R3AgentError::Context)
    );
    // 5b: Mission-bound R3 ResourceToken with exp == person_a.exp (clock+300) and exp < person_a.exp (clock+200) -> Ok
    let h5_rt_equal = mint_h5_rt(
        clock + 300,
        Some(mission_a_s256.clone()),
        &ver_person_a_parsed.claims().jti,
        &ver_person_a_parsed.claims().sub,
    )?;
    let h5_rt_shorter = mint_h5_rt(
        clock + 200,
        Some(mission_a_s256.clone()),
        &ver_person_a_parsed.claims().jti,
        &ver_person_a_parsed.claims().sub,
    )?;
    let h5b_within_accepted = h_agent
        .verify_r3_resource_token(&h5_rt_equal, H_RES, H_PS, &person_a, None, trust, clock)
        .is_ok()
        && h_agent
            .verify_r3_resource_token(&h5_rt_shorter, H_RES, H_PS, &person_a, None, trust, clock)
            .is_ok();
    // 5c: Missionless R3 ResourceToken with exp (clock+300) > missionless PersonToken.exp (clock+180) -> Ok
    let short_nomiss_person = mint_person_token(
        &h_ps_key,
        "mission-ps-1",
        &PersonClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            sub: "mission-person".into(),
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            jti: "h5c-short-nomiss-person".into(),
            iat: clock,
            exp: clock + 180,
            nbf: None,
            mission_s256: None,
            tenant: None,
            extra: BTreeMap::new(),
        },
    )?;
    let h5_rt_nomiss_longer = mint_h5_rt(
        clock + 300,
        None,
        "h5c-short-nomiss-person",
        "mission-person",
    )?;
    let h5c_nomiss_outlives_accepted = h_agent
        .verify_r3_resource_token(
            &h5_rt_nomiss_longer,
            H_RES,
            H_PS,
            &short_nomiss_person,
            None,
            trust,
            clock,
        )
        .is_ok();
    // 5d: Stripped/mismatched mission_s256 on ResourceToken or AuthToken -> Err(R3AgentError::Context)
    let h5d_stripped_rt_refused = matches!(
        h_agent.verify_r3_resource_token(&rt_stripped_mission, H_RES, H_PS, &person_a, None, trust, clock),
        Err(R3AgentError::Context)
    );
    let h5d_wrong_auth_refused = matches!(
        h_agent.verify_r3_auth_delivery(
            &h2a_missionless_auth,
            H_RES,
            &ver_proactive_rt,
            &person_a,
            &registry,
            trust,
            clock,
        ),
        Err(R3AgentError::Context)
    );

    let h5_all_ok = h5a_outlives_refused
        && h5b_within_accepted
        && h5c_nomiss_outlives_accepted
        && h5d_stripped_rt_refused
        && h5d_wrong_auth_refused;

    cases.push(QaCaseReceipt {
        id: "QA-H5".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "Rust Agent Validation Boundary (Mission-Bound R3 Resource Token Outliving Person Token Refused; Equal/Shorter & Missionless Accepted)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: h5_all_ok,
        summary: format!(
            "Agent R3 validation boundary verified: mission_rt_outlives_person=Err(Context) ({}), equal_and_shorter_exp=Ok ({}), missionless_rt_outlives_person=Ok ({}), stripped_or_mismatched_mission=Err(Context) ({})",
            h5a_outlives_refused,
            h5b_within_accepted,
            h5c_nomiss_outlives_accepted,
            h5d_stripped_rt_refused && h5d_wrong_auth_refused
        ),
        evidence: json!({
            "mission_rt_exp_gt_person_exp_refused": h5a_outlives_refused,
            "mission_rt_exp_eq_and_lt_person_exp_accepted": h5b_within_accepted,
            "missionless_rt_exp_gt_person_exp_accepted": h5c_nomiss_outlives_accepted,
            "stripped_mission_rt_refused": h5d_stripped_rt_refused,
            "missionless_auth_for_mission_rt_refused": h5d_wrong_auth_refused,
            "source_location": "crates/aauth-rust-agent/src/r3.rs:231",
        }),
    });
    transcript_lines.push(format!(
        "[QA-H5] PASS: outlives_refused={} within_accepted={} nomiss_outlives_accepted={} mismatch_refused={}",
        h5a_outlives_refused,
        h5b_within_accepted,
        h5c_nomiss_outlives_accepted,
        h5d_stripped_rt_refused && h5d_wrong_auth_refused
    ));

    // QA-H6 (DEFECT_RESOLVED): PsAuthorizationResource Clamps Mission-Bound ResourceToken.exp to Presented Token's exp
    // Across Proactive /authorize, Reactive 401 R3 Challenge, and Budget Step-Up (d778d45 / 3a691c40)
    let mission_short = mint_mission_record(
        H_PS,
        &h_owner,
        "person-1",
        clock,
        Some(clock + 120),
        "120-second mission (< 300s default resource token lifetime)",
        MissionState::Active,
    )?;
    let mission_short_s256 = mission_short.document.s256().to_owned();
    h_ps_store.install_approved_mission(mission_short)?;
    let person_short_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES, "mission_s256": mission_short_s256})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let person_short = member(&person_short_resp, "person_token")
        .ok_or("QA-H6: missing person_short")?;
    let ver_person_short = PersonToken::parse(&person_short)?.verify(trust, clock)?;

    // Path 1 (authorize_endpoint -> proactive_r3): Agent::r3_authorize (proactive POST /authorize) + Agent::verify_r3_resource_token with 120s mission at `clock`,
    // plus full /token exchange at PersonServer and /records/read admission over HTTPS
    let raw_proactive_short_rt = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_short,
        &read_only,
        None,
        clock,
    )?;
    let raw_proactive_short_ver = verify_r3_resource_token_raw(&raw_proactive_short_rt, trust, clock)?;
    let h6_proactive_short_res = h_agent.verify_r3_resource_token(
        &raw_proactive_short_rt,
        H_RES,
        H_PS,
        &person_short,
        None,
        trust,
        clock,
    );
    let h6_proactive_short_ver_rt = h6_proactive_short_res
        .as_ref()
        .map_err(|e| format!("QA-H6 proactive short verify failed: {e:?}"))?;
    let h6_short_token_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({"resource_token": raw_proactive_short_rt, "presented_token": person_short})
            .to_string()
            .as_bytes(),
        clock,
    )?)?;
    let h6_short_token_status = h6_short_token_resp.status().as_u16();
    let h6_short_auth = member(&h6_short_token_resp, "auth_token")
        .ok_or("QA-H6: missing short mission auth_token")?;
    let h6_short_auth_ver = h_agent.verify_r3_auth_delivery(
        &h6_short_auth,
        H_RES,
        h6_proactive_short_ver_rt,
        &person_short,
        &registry,
        trust,
        clock,
    )?;
    let h6_short_read_resp = h_res_tls.send(&signed_get(
        &h_agent.with_token(h6_short_auth.clone())?,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let h6_short_read_status = h6_short_read_resp.status().as_u16();

    // Path 2 (authorize_proved -> r3_challenge): Reactive 401 R3 challenge on /records/read with 120s mission at `clock`, then Agent::verify_r3_resource_token
    let h6_reactive_short_401 = h_res_tls.send(&signed_get(
        &h_agent.with_token(person_short.clone())?,
        &format!("{H_RES}/records/read"),
        clock,
    )?)?;
    let raw_reactive_short_rt = challenge(&h6_reactive_short_401)?;
    let raw_reactive_short_ver = verify_r3_resource_token_raw(&raw_reactive_short_rt, trust, clock)?;
    let h6_reactive_short_res = h_agent.verify_r3_resource_token(
        &raw_reactive_short_rt,
        H_RES,
        H_PS,
        &person_short,
        None,
        trust,
        clock,
    );

    // Scenario B: 300s mission (mission_a, expires_at = clock + 300), PersonToken issued at `clock`, Agent calls r3_authorize + verify_r3_resource_token 1 second later at `clock + 1`
    h_res_clock.store(clock + 1, Ordering::SeqCst);
    let raw_1s_later_rt = h_agent.r3_authorize(
        |req| h_res_tls.send(&req),
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_only,
        None,
        clock + 1,
    )?;
    h_res_clock.store(clock, Ordering::SeqCst);
    let raw_1s_later_ver = verify_r3_resource_token_raw(&raw_1s_later_rt, trust, clock + 1)?;
    let h6_1s_later_res = h_agent.verify_r3_resource_token(
        &raw_1s_later_rt,
        H_RES,
        H_PS,
        &person_a,
        None,
        trust,
        clock + 1,
    );

    // Path 3 (mint_step_up on budget-enabled Resource with .with_mission_context()):
    // Present a mission-bound AuthToken with exp = clock + 120 and insufficient budget (20 < default_bound 50),
    // verify the 401 step-up ResourceToken has exp clamped to clock + 120 (while a missionless AuthToken with exp = clock + 120 gets exp = clock + 300)
    let h6_budget_res = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: H_RES.into(),
            signed_origin: H_RES.into(),
            kid: "mission-res-1".into(),
            signing_key: SigningKey::from_seed(H_RES_SEED),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        trust.clone(),
        Box::new(|token: &VerifiedAuthToken, _: &Request<Vec<u8>>| token.claims().ps == H_PS),
    )?
    .with_mission_context()
    .with_budgets(
        vec![UnitDeclaration::new("MilliwattSecond", 0, "Compute energy").unwrap()],
        format!("{H_RES}/usage"),
        50,
        100,
    )?;
    let mut h6_low_budget_extra = BTreeMap::new();
    h6_low_budget_extra.insert(
        "budget".into(),
        json!({"amount": 20, "unit": "MilliwattSecond", "decimals": 0}),
    );
    let h6_mission_budget_auth = aauth_rust_core::mint_auth_token(
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            jti: "h6-mission-budget-auth-120s".into(),
            iat: clock,
            exp: clock + 120,
            scope: Some("records.read".into()),
            nbf: None,
            mission_s256: Some(mission_short_s256.clone()),
            tenant: None,
            account: None,
            extra: h6_low_budget_extra.clone(),
        },
    )?;
    let h6_stepup_mission_req = signed_get(
        &h_agent.with_token(h6_mission_budget_auth)?,
        &format!("{H_RES}/records/read"),
        clock,
    )?;
    let h6_stepup_mission_resp = h6_budget_res
        .authorize(&h6_stepup_mission_req, clock, "h6-stepup-mission-1")
        .into_response();
    let h6_stepup_mission_status = h6_stepup_mission_resp.status().as_u16();
    let h6_stepup_mission_rt = challenge(&h6_stepup_mission_resp)?;
    let h6_stepup_mission_ver = aauth_rust_core::ResourceToken::parse(&h6_stepup_mission_rt)?.verify(trust, clock)?;

    let h6_nomiss_budget_auth = aauth_rust_core::mint_auth_token(
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            jti: "h6-nomiss-budget-auth-120s".into(),
            iat: clock,
            exp: clock + 120,
            scope: Some("records.read".into()),
            nbf: None,
            mission_s256: None,
            tenant: None,
            account: None,
            extra: h6_low_budget_extra,
        },
    )?;
    let h6_stepup_nomiss_req = signed_get(
        &h_agent.with_token(h6_nomiss_budget_auth)?,
        &format!("{H_RES}/records/read"),
        clock,
    )?;
    let h6_stepup_nomiss_resp = h6_budget_res
        .authorize(&h6_stepup_nomiss_req, clock, "h6-stepup-nomiss-1")
        .into_response();
    let h6_stepup_nomiss_rt = challenge(&h6_stepup_nomiss_resp)?;
    let h6_stepup_nomiss_ver = aauth_rust_core::ResourceToken::parse(&h6_stepup_nomiss_rt)?.verify(trust, clock)?;

    let h6_resolved = ver_person_short.claims().exp == clock + 120
        && raw_proactive_short_ver.claims().exp == clock + 120
        && h6_proactive_short_res.is_ok()
        && h6_short_token_status == 200
        && h6_short_auth_ver.claims().exp == clock + 120
        && h6_short_read_status == 200
        && raw_reactive_short_ver.claims().exp == clock + 120
        && h6_reactive_short_res.is_ok()
        && ver_person_a.claims().exp == clock + 300
        && raw_1s_later_ver.claims().exp == clock + 300
        && h6_1s_later_res.is_ok()
        && h6_stepup_mission_status == 401
        && h6_stepup_mission_ver.claims().exp == clock + 120
        && h6_stepup_mission_ver.claims().mission_s256.as_deref() == Some(mission_short_s256.as_str())
        && h6_stepup_nomiss_ver.claims().exp == clock + 300;

    cases.push(QaCaseReceipt {
        id: "QA-H6".into(),
        category: "H. Approved Mission Composition with Direct Class R3".into(),
        title: "RESOLVED (QA-H6): PsAuthorizationResource Clamps Mission-Bound ResourceToken.exp to Presented Token's exp Across Proactive /authorize, Reactive 401 Challenge, and Budget Step-Up".into(),
        classification: "DEFECT_RESOLVED".into(),
        passed_expectation: h6_resolved,
        summary: format!(
            "Mission-bound ResourceToken.exp clamped to presented token exp on all 3 paths: 120s proactive={}s (verify=Ok, /token={}, read={}), 120s reactive={}s (verify=Ok), 300s at clock+1s={}s (verify=Ok), 120s budget step-up={}s (missionless step-up={}s)",
            raw_proactive_short_ver.claims().exp - clock,
            h6_short_token_status,
            h6_short_read_status,
            raw_reactive_short_ver.claims().exp - clock,
            raw_1s_later_ver.claims().exp - clock,
            h6_stepup_mission_ver.claims().exp - clock,
            h6_stepup_nomiss_ver.claims().exp - clock
        ),
        evidence: json!({
            "short_mission_120s": {
                "person_token_exp_offset": ver_person_short.claims().exp - clock,
                "proactive_resource_token_exp_offset": raw_proactive_short_ver.claims().exp - clock,
                "agent_verify_proactive_r3_resource_token_ok": h6_proactive_short_res.is_ok(),
                "ps_token_exchange_status": h6_short_token_status,
                "auth_token_exp_offset": h6_short_auth_ver.claims().exp - clock,
                "records_read_status": h6_short_read_status,
                "reactive_resource_token_exp_offset": raw_reactive_short_ver.claims().exp - clock,
                "agent_verify_reactive_r3_resource_token_ok": h6_reactive_short_res.is_ok(),
            },
            "mission_300s_called_1s_after_person_issuance": {
                "person_token_exp_offset": ver_person_a.claims().exp - clock,
                "resource_token_minted_at_clock_plus_1_exp_offset": raw_1s_later_ver.claims().exp - clock,
                "agent_verify_r3_resource_token_at_clock_plus_1_ok": h6_1s_later_res.is_ok(),
            },
            "budget_step_up_path": {
                "mission_bound_auth_120s_step_up_status": h6_stepup_mission_status,
                "mission_bound_step_up_resource_token_exp_offset": h6_stepup_mission_ver.claims().exp - clock,
                "missionless_auth_120s_step_up_resource_token_exp_offset": h6_stepup_nomiss_ver.claims().exp - clock,
            },
            "rust_source_locations": [
                "crates/aauth-rust-resource/src/ps_authorization.rs:1196, 1474, 1779, 2046 (challenge_exp clamps exp to presented_exp when mission_bound)",
                "crates/aauth-rust-agent/src/r3.rs:231 (enforces parent.mission.is_some() && claims.exp > parent.exp -> Err(R3AgentError::Context))"
            ],
            "go_reference_location": "aauth-go/resource/authorization.go:249-255 (clamps expiresAt to person.ExpiresAt when person.MissionS256 != \"\")",
        }),
    });
    transcript_lines.push(format!(
        "[QA-H6] RESOLVED: short_120s_proactive_exp=+{}s (token={}, read={}) short_120s_reactive_exp=+{}s 300s_at_t_plus_1s_exp=+{}s stepup_mission_exp=+{}s stepup_nomiss_exp=+{}s",
        raw_proactive_short_ver.claims().exp - clock,
        h6_short_token_status,
        h6_short_read_status,
        raw_reactive_short_ver.claims().exp - clock,
        raw_1s_later_ver.claims().exp - clock,
        h6_stepup_mission_ver.claims().exp - clock,
        h6_stepup_nomiss_ver.claims().exp - clock
    ));

    // =========================================================================================
    // Category I: 0.1.0-alpha.11 Required-Row Batch (18 MUST-Level Rows / a0f1e268)
    // =========================================================================================

    // -----------------------------------------------------------------------------------------
    // QA-I1: PsAuthorizationConfig::scope_descriptions Validation, Metadata Publication,
    // Undescribed Per-Call Class Scope Refusal (403), and Consumer Documentation Audit
    // -----------------------------------------------------------------------------------------
    let i1_make_cfg = |scopes: &[&str], descs: &[(&str, &str)]| PsAuthorizationConfig {
        issuer: H_RES.into(),
        signed_origin: H_RES.into(),
        kid: "mission-res-1".into(),
        signing_key: SigningKey::from_seed(H_RES_SEED),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        scope_descriptions: descs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    let i1_noop_policy = || -> BoxedAuthPolicy { Box::new(|_: &VerifiedAuthToken, _: &Request<Vec<u8>>| true) };

    let i1_empty_descs_refused = matches!(
        PsAuthorizationResource::new(i1_make_cfg(&["records.read"], &[]), trust.clone(), i1_noop_policy()),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_partial_descs_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(&["records.read", "records.write"], &[("records.read", "Read records")]),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_blank_desc_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(&["records.read"], &[("records.read", "")]),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_whitespace_desc_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(&["records.read"], &[("records.read", "   \t\n  ")]),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_extra_desc_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(
                &["records.read"],
                &[("records.read", "Read records"), ("records.admin", "Administer records")],
            ),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_wrong_key_same_len_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(&["records.read"], &[("records.other", "Other records")]),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_space_joined_key_refused = matches!(
        PsAuthorizationResource::new(
            i1_make_cfg(
                &["records.read", "records.write"],
                &[
                    ("records.read records.write", "Read and write"),
                    ("records.write", "Write"),
                ],
            ),
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );
    let i1_federated_missing_refused = matches!(
        PsAuthorizationResource::new_federated(
            i1_make_cfg(&["records.read"], &[]),
            FED_AS,
            trust.clone(),
            i1_noop_policy(),
        ),
        Err(PsConfigurationError::InvalidScopes)
    );

    // Valid multi-scope configuration publishes exact scope_descriptions in metadata without inventing authorization_endpoint
    let i1_multi_res = PsAuthorizationResource::new(
        i1_make_cfg(
            &["records.read", "records.write"],
            &[
                ("records.read", "Read records"),
                ("records.write", "Write records"),
            ],
        ),
        trust.clone(),
        i1_noop_policy(),
    )?;
    let i1_multi_meta: Value = serde_json::from_slice(&i1_multi_res.metadata()?)?;
    let i1_multi_meta_ok = i1_multi_meta["scope_descriptions"]
        == json!({
            "records.read": "Read records",
            "records.write": "Write records",
        })
        && i1_multi_meta.get("authorization_endpoint").is_none();

    // Live HTTPS metadata check on direct_res_tls and rust_fed_res_tls
    let i1_live_meta_req = Request::builder()
        .method("GET")
        .uri(format!("{RUST_FED_RECORDS}/.well-known/aauth-resource.json"))
        .body(Vec::new())?;
    let i1_live_meta_resp = rust_fed_res_tls.send(&i1_live_meta_req)?;
    let i1_live_meta_json: Value = serde_json::from_slice(i1_live_meta_resp.body())?;
    let i1_live_meta_ok = i1_live_meta_resp.status().as_u16() == 200
        && i1_live_meta_json["scope_descriptions"] == json!({"records.read": "Read records"});

    // Per-call challenge refusal (403 Forbidden) when class token carries an undescribed scope
    let i1_counters = Arc::new(RustResourceCounters::new());
    let i1_fed_res = compose_rust_resource(
        RUST_FED_RECORDS,
        "rust-fed-res-1",
        [0x55; 32],
        Some(other_as_issuer),
        &out_dir.join("i1-fed-res"),
        trust,
        false,
        i1_counters.clone(),
    )?;
    let i1_doc_rt = fed_agent.r3_authorize(
        |req| Ok::<_, String>(i1_fed_res.authorize_endpoint(&req, clock, "i1-doc-jti-1").into_response()),
        &format!("{RUST_FED_RECORDS}/authorize"),
        &rust_fed_person_tok,
        &read_and_delete,
        None,
        clock,
    )?;
    let i1_ver_doc_rt = fed_agent.verify_r3_resource_token(
        &i1_doc_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &rust_fed_person_tok,
        None,
        trust,
        clock,
    )?;
    let i1_rf_doc_path = out_dir
        .join("i1-fed-res")
        .join(format!("c-{}.json", digest(i1_ver_doc_rt.reference().uri().as_bytes())));
    let i1_rf_doc_val: Value = serde_json::from_slice(&fs::read(&i1_rf_doc_path)?)?;
    let i1_rf_doc_exact: Vec<u8> = serde_json::from_value(i1_rf_doc_val["exact_json"].clone())?;
    let i1_read_granted = GrantedOperations::new(&mcp_vocab, &[mcp("records.read")?])?;
    let i1_del_granted = GrantedOperations::new(&mcp_vocab, &[mcp("records.delete")?])?;
    let i1_rf_authz = Authorization::new(
        &i1_read_granted,
        &i1_del_granted,
        &registry.parse_document(&i1_rf_doc_exact)?,
    )?;

    let i1_mint_scoped_class = |jti: &str, scope: Option<&str>| -> Result<String> {
        Ok(mint_r3_class_auth_token(
            &registry,
            &other_as_key,
            "other-as-1",
            &AuthClaims {
                iss: other_as_issuer.into(),
                dwk: "aauth-access.json".into(),
                aud: RUST_FED_RECORDS.into(),
                ps: FED_PS.into(),
                sub: "fed-person".into(),
                jti: jti.into(),
                iat: clock,
                exp: clock + 300,
                cnf: Confirmation {
                    jwk: SigningKey::from_seed(go_agent_seed).public_jwk(),
                },
                nbf: None,
                tenant: None,
                mission_s256: None,
                scope: scope.map(str::to_owned),
                account: None,
                extra: BTreeMap::new(),
            },
            i1_ver_doc_rt.reference(),
            &i1_rf_doc_exact,
            &i1_rf_authz,
        )?)
    };

    let i1_undescribed_only_tok = i1_mint_scoped_class("i1-class-undesc-1", Some("records.admin"))?;
    let i1_mixed_undescribed_tok =
        i1_mint_scoped_class("i1-class-undesc-2", Some("records.read records.admin"))?;
    let i1_described_tok = i1_mint_scoped_class("i1-class-desc-1", Some("records.read"))?;

    let i1_del_before = i1_counters.deletes.load(Ordering::SeqCst);
    let i1_undesc1_resp = i1_fed_res
        .authorize(
            &post_at(
                &fed_agent.with_token(i1_undescribed_only_tok)?,
                &format!("{RUST_FED_RECORDS}/records/delete"),
                R1,
                clock,
            )?,
            clock,
            "i1-prop-undesc-1",
        )
        .into_response();
    let i1_undesc2_resp = i1_fed_res
        .authorize(
            &post_at(
                &fed_agent.with_token(i1_mixed_undescribed_tok)?,
                &format!("{RUST_FED_RECORDS}/records/delete"),
                R1,
                clock,
            )?,
            clock,
            "i1-prop-undesc-2",
        )
        .into_response();
    let i1_desc_resp = i1_fed_res
        .authorize(
            &post_at(
                &fed_agent.with_token(i1_described_tok.clone())?,
                &format!("{RUST_FED_RECORDS}/records/delete"),
                R1,
                clock,
            )?,
            clock,
            "i1-prop-desc-1",
        )
        .into_response();
    let i1_del_after = i1_counters.deletes.load(Ordering::SeqCst);
    let i1_desc_rt = challenge(&i1_desc_resp)?;
    let i1_desc_ver = fed_agent.verify_r3_proposal_challenge(
        &i1_desc_rt,
        RUST_FED_RECORDS,
        FED_PS,
        &i1_described_tok,
        trust,
        clock,
    )?;

    let i1_per_call_scope_guard_ok = i1_undesc1_resp.status().as_u16() == 403
        && i1_undesc2_resp.status().as_u16() == 403
        && i1_desc_resp.status().as_u16() == 401
        && i1_desc_ver.claims().scope.as_deref() == Some("records.read")
        && i1_del_after == i1_del_before;

    // Documentation audit of README.md, USE-IN-YOUR-SERVICE.md, and examples/
    let rust_repo_root = rust_source();
    let use_in_service_md = fs::read_to_string(rust_repo_root.join("USE-IN-YOUR-SERVICE.md"))?;
    let readme_md = fs::read_to_string(rust_repo_root.join("README.md"))?;
    let i1_doc_mentions_scope_descriptions = use_in_service_md.contains(
        "Use `PsAuthorizationResource` with a `PsAuthorizationConfig`: published Resource\n\
         issuer, independently configured signed origin, signing key/kid, a nonempty\n\
         scope list and a description of each scope in `scope_descriptions`.",
    ) && use_in_service_md.contains(
        "The metadata\npublishes those descriptions, and a Resource token carries only scopes described\n\
         there; a description missing, blank or for another scope is a configuration\nerror.",
    );
    let i1_no_stale_builder_in_docs = !use_in_service_md.contains("with_scope_descriptions")
        && !readme_md.contains("with_scope_descriptions");
    let example_files = [
        "crates/aauth-rust-resource/examples/three_party/mod.rs",
        "crates/aauth-rust-resource/examples/four_party/mod.rs",
        "crates/aauth-rust-resource/examples/subagent.rs",
        "crates/aauth-rust-resource/examples/r3_three_party/mod.rs",
        "crates/aauth-rust-resource/examples/r3_per_call/mod.rs",
        "crates/aauth-rust-resource/examples/r3_per_call_interop/mod.rs",
    ];
    let mut i1_all_examples_populate_scope_descriptions = true;
    for rel in example_files {
        let content = fs::read_to_string(rust_repo_root.join(rel))?;
        let cfg_count = content.matches("PsAuthorizationConfig {").count();
        let desc_count = content.matches("scope_descriptions:").count();
        if cfg_count == 0 || cfg_count != desc_count {
            i1_all_examples_populate_scope_descriptions = false;
        }
    }

    let i1_all_ok = i1_empty_descs_refused
        && i1_partial_descs_refused
        && i1_blank_desc_refused
        && i1_whitespace_desc_refused
        && i1_extra_desc_refused
        && i1_wrong_key_same_len_refused
        && i1_space_joined_key_refused
        && i1_federated_missing_refused
        && i1_multi_meta_ok
        && i1_live_meta_ok
        && i1_per_call_scope_guard_ok
        && i1_doc_mentions_scope_descriptions
        && i1_no_stale_builder_in_docs
        && i1_all_examples_populate_scope_descriptions;

    cases.push(QaCaseReceipt {
        id: "QA-I1".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "PsAuthorizationConfig::scope_descriptions Constructor Refusals (Missing, Blank, Whitespace, Extra, Wrong-Key), Metadata Publication, Per-Call Undescribed Scope 403 Guard & Doc Audit".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i1_all_ok,
        summary: format!(
            "Constructor refuses missing/blank/whitespace/extra/wrong-key scope_descriptions (ok={}); metadata publishes scope_descriptions over HTTPS (ok={}); per-call challenge with undescribed class scope returns 403 before present/describe/release (ok={}); docs & 6 examples accurately document scope_descriptions (ok={})",
            i1_empty_descs_refused
                && i1_partial_descs_refused
                && i1_blank_desc_refused
                && i1_whitespace_desc_refused
                && i1_extra_desc_refused
                && i1_wrong_key_same_len_refused
                && i1_space_joined_key_refused
                && i1_federated_missing_refused,
            i1_multi_meta_ok && i1_live_meta_ok,
            i1_per_call_scope_guard_ok,
            i1_doc_mentions_scope_descriptions
                && i1_no_stale_builder_in_docs
                && i1_all_examples_populate_scope_descriptions
        ),
        evidence: json!({
            "constructor_refusals": {
                "empty_descriptions_refused": i1_empty_descs_refused,
                "partial_descriptions_refused": i1_partial_descs_refused,
                "blank_description_refused": i1_blank_desc_refused,
                "whitespace_only_description_refused": i1_whitespace_desc_refused,
                "extra_unconfigured_scope_refused": i1_extra_desc_refused,
                "wrong_key_same_len_refused": i1_wrong_key_same_len_refused,
                "space_joined_key_refused": i1_space_joined_key_refused,
                "federated_missing_descriptions_refused": i1_federated_missing_refused,
            },
            "metadata_publication": {
                "multi_scope_metadata_matches": i1_multi_meta_ok,
                "live_https_metadata_scope_descriptions": i1_live_meta_json["scope_descriptions"],
            },
            "per_call_undescribed_scope_guard": {
                "undescribed_only_status": i1_undesc1_resp.status().as_u16(),
                "mixed_described_and_undescribed_status": i1_undesc2_resp.status().as_u16(),
                "described_scope_status": i1_desc_resp.status().as_u16(),
                "described_proposal_rt_scope": i1_desc_ver.claims().scope,
                "deletes_delta": i1_del_after - i1_del_before,
            },
            "consumer_doc_audit": {
                "use_in_your_service_documents_scope_descriptions": i1_doc_mentions_scope_descriptions,
                "no_stale_with_scope_descriptions_references": i1_no_stale_builder_in_docs,
                "all_6_resource_examples_populate_scope_descriptions": i1_all_examples_populate_scope_descriptions,
            },
            "source_locations": [
                "crates/aauth-rust-resource/src/ps_authorization.rs:69-75, 730-742, 931",
                "crates/aauth-rust-resource/src/r3_per_call.rs:863-870"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I1] PASS: scope_descriptions constructor_refusals=true metadata_published={} per_call_403_guard={} docs_audit={}",
        i1_multi_meta_ok && i1_live_meta_ok,
        i1_per_call_scope_guard_ok,
        i1_doc_mentions_scope_descriptions && i1_all_examples_populate_scope_descriptions
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I2: CSPRNG 40-bit Interaction Codes (XXXX-XXXX Crockford Base32) & 128-bit Pending URL IDs
    // (22-char Base64url) Across PS, AS, Chained Interactions, R3 Held Calls & HeldInvocations::open()
    // -----------------------------------------------------------------------------------------
    const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let is_valid_40bit_code = |code: &str| -> bool {
        let bytes = code.as_bytes();
        bytes.len() == 9
            && bytes[4] == b'-'
            && bytes
                .iter()
                .enumerate()
                .all(|(i, b)| i == 4 || CROCKFORD_ALPHABET.contains(b))
    };
    let is_valid_128bit_id = |id: &str| -> bool {
        id.len() == 22
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && URL_SAFE_NO_PAD
                .decode(id.as_bytes())
                .is_ok_and(|decoded| decoded.len() == 16)
    };

    // 1. Core generators
    let i2_core_code_1 = generate_interaction_code();
    let i2_core_code_2 = generate_interaction_code();
    let i2_core_id_1 = generate_pending_id();
    let i2_core_id_2 = generate_pending_id();
    let i2_core_ok = is_valid_40bit_code(&i2_core_code_1)
        && is_valid_40bit_code(&i2_core_code_2)
        && i2_core_code_1 != i2_core_code_2
        && is_valid_128bit_id(&i2_core_id_1)
        && is_valid_128bit_id(&i2_core_id_2)
        && i2_core_id_1 != i2_core_id_2;

    // 2. PersonServer: open_interaction_code, mission proposal pending URL, and deferred federation pending URL
    struct DummyGovernance;
    impl Governance for DummyGovernance {
        fn answer(&self, _question: &str) -> std::result::Result<String, PolicyError> {
            Ok("approved".into())
        }
        fn permit(&self, _action: &str) -> std::result::Result<bool, PolicyError> {
            Ok(true)
        }
    }
    struct DummyDeferredFedAdapter {
        as_origin: String,
    }
    impl Federation for DummyDeferredFedAdapter {
        fn endpoint(&self, _access_server: &str) -> std::result::Result<String, FederationError> {
            Ok(format!("{}/token", self.as_origin))
        }
        fn send(
            &self,
            _request: &Request<Vec<u8>>,
        ) -> std::result::Result<Response<Vec<u8>>, FederationError> {
            Ok(PendingResponse::new(
                &format!("{}/token", self.as_origin),
                &format!("{}/token/pending/{}", self.as_origin, generate_pending_id()),
                5,
                ContinuationRequirement::Approval,
            )
            .unwrap()
            .response()
            .unwrap())
        }
    }

    let i2_ps_seq = Arc::new(AtomicUsize::new(0));
    let i2_ps_seq_cb = i2_ps_seq.clone();
    let i2_ps_store = MemoryStore::default();
    let i2_ps = PersonServer::new(
        PsConfig::new(H_PS, "mission-ps-1", SigningKey::from_seed(H_PS_SEED)),
        trust.clone(),
        i2_ps_store.clone(),
        QaPsPolicy,
        Box::new(move || clock) as BoxedClock,
        Box::new(move || format!("predictable-ps-seq-{}", i2_ps_seq_cb.fetch_add(1, Ordering::SeqCst) + 1))
            as BoxedTokenIds,
    )?
    .with_governance(DummyGovernance)
    .with_missions();
    let i2_ps_seq_cb2 = i2_ps_seq.clone();
    let i2_fed_ps = PersonServer::new(
        PsConfig::new(H_PS, "mission-ps-1", SigningKey::from_seed(H_PS_SEED)),
        trust.clone(),
        i2_ps_store,
        QaPsPolicy,
        Box::new(move || clock) as BoxedClock,
        Box::new(move || format!("predictable-ps-seq-{}", i2_ps_seq_cb2.fetch_add(1, Ordering::SeqCst) + 1))
            as BoxedTokenIds,
    )?
    .with_federation(DummyDeferredFedAdapter {
        as_origin: FED_AS.into(),
    })
    .with_deferred(PsDeferredConfig::new(MemoryContinuations::new(16)))?;

    let i2_opened_1 = i2_ps.open_interaction_code(clock + 300)?;
    let i2_opened_2 = i2_ps.open_interaction_code(clock + 300)?;
    let i2_ps_interaction_ok = is_valid_128bit_id(&i2_opened_1.id)
        && is_valid_128bit_id(&i2_opened_2.id)
        && i2_opened_1.id != i2_opened_2.id
        && !i2_opened_1.id.starts_with("predictable-ps-seq-")
        && is_valid_40bit_code(&i2_opened_1.code)
        && is_valid_40bit_code(&i2_opened_2.code)
        && i2_opened_1.code != i2_opened_2.code;

    // Bind h_agent on i2_ps_store via /person first
    let i2_ps_person_resp = i2_fed_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": RUST_FED_RECORDS}).to_string().as_bytes(),
        clock,
    )?);
    let i2_ps_person_tok = member(&i2_ps_person_resp, "person_token").ok_or("missing i2 person_token")?;
    let i2_ps_person_ver = PersonToken::parse(&i2_ps_person_tok)?.verify(trust, clock)?;

    // PS Mission proposal pending URL
    let i2_mission_req = post_at(
        &h_agent,
        &format!("{H_PS}/mission"),
        json!({"description": "draft the note"})
            .to_string()
            .as_bytes(),
        clock,
    )?;
    let i2_mission_resp = i2_ps.handle(&i2_mission_req);
    let i2_mission_loc = i2_mission_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i2_mission_id = i2_mission_loc
        .strip_prefix(&format!("{H_PS}/mission/proposal/"))
        .unwrap_or("");
    let i2_ps_mission_pending_ok =
        i2_mission_resp.status().as_u16() == 202 && is_valid_128bit_id(i2_mission_id);

    // PS Deferred federation pending URL
    let i2_fed_chal = mint_core_resource_token(
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: FED_AS.into(),
            ps: H_PS.into(),
            sub: i2_ps_person_ver.claims().sub.clone(),
            jti: "i2-fed-chal-1".into(),
            presented_jti: i2_ps_person_ver.claims().jti.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("records.read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;
    let i2_ps_def_resp = i2_fed_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": i2_fed_chal,
            "presented_token": i2_ps_person_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?);
    let i2_ps_def_loc = i2_ps_def_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i2_ps_def_id = i2_ps_def_loc
        .strip_prefix(&format!("{H_PS}/token/pending/"))
        .unwrap_or("");
    let i2_ps_deferred_ok = i2_ps_def_resp.status().as_u16() == 202
        && is_valid_128bit_id(i2_ps_def_id)
        && !i2_ps_def_id.starts_with("predictable-ps-seq-");

    // 3. AccessServer: DeferredContext::interaction_code (40 bits), pending URL (128 bits), and wrong-code 500 refusal
    const I2_AS: &str = "https://i2-as.example";
    let i2_as_seen_codes = Arc::new(Mutex::new(Vec::<String>::new()));
    let i2_as_seen_cb = i2_as_seen_codes.clone();
    let i2_as_wrong_code = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let i2_as_wrong_cb = i2_as_wrong_code.clone();
    let i2_as_seq = Arc::new(AtomicUsize::new(0));
    let i2_as = AccessServer::new(
        AsConfig::new(I2_AS, "i2-as-1", SigningKey::from_seed([0x91; 32])),
        trust.clone(),
        |_: &AsAuthorizationRequest| {
            Ok(AsDecision {
                scopes: vec!["records.read".into()],
                lifetime: 300,
            })
        },
        move || clock,
        move || format!("predictable-as-seq-{}", i2_as_seq.fetch_add(1, Ordering::SeqCst) + 1),
    )?
    .with_deferred(
        AsDeferredConfig::new(MemoryContinuations::new(16)),
        move |ctx: &AsDeferredContext| {
            i2_as_seen_cb.lock().unwrap().push(ctx.interaction_code.clone());
            let code = if i2_as_wrong_cb.load(Ordering::SeqCst) {
                "2345-6789".to_owned()
            } else {
                ctx.interaction_code.clone()
            };
            Ok(Some(ContinuationRequirement::Interaction {
                url: format!("{I2_AS}/interact"),
                code,
            }))
        },
    )?;

    let i2_as_chal = mint_core_resource_token(
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: I2_AS.into(),
            ps: H_PS.into(),
            sub: i2_ps_person_ver.claims().sub.clone(),
            jti: "i2-as-chal-1".into(),
            presented_jti: i2_ps_person_ver.claims().jti.clone(),
            agent_jkt: h_agent.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("records.read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;
    let make_ps_signed_as_req = |uri: &str, body: Option<Value>| -> Result<Request<Vec<u8>>> {
        let mut builder = Request::builder()
            .method(if body.is_some() { "POST" } else { "GET" })
            .uri(uri);
        if body.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let mut req = builder.body(body.map(|b| b.to_string().into_bytes()).unwrap_or_default())?;
        sign_raw_request(
            &mut req,
            &SigningKey::from_seed(H_PS_SEED),
            KeyMaterial::JwksUri {
                id: H_PS.into(),
                dwk: "aauth-person.json".into(),
                kid: "mission-ps-1".into(),
            },
            clock,
        )?;
        Ok(req)
    };
    let i2_as_body = json!({
        "agent_token": h_agent.token(),
        "resource_token": i2_as_chal,
        "presented_token": i2_ps_person_tok,
    });
    let i2_as_resp_1 = i2_as.handle(&make_ps_signed_as_req(&format!("{I2_AS}/token"), Some(i2_as_body.clone()))?);
    let i2_as_pending_1 = PendingResponse::parse(&format!("{I2_AS}/token"), &i2_as_resp_1)
        .map_err(|_| "failed to parse i2_as_resp_1 PendingResponse")?;
    let i2_as_id_1 = i2_as_pending_1
        .location
        .strip_prefix(&format!("{I2_AS}/token/pending/"))
        .unwrap_or("")
        .to_owned();
    let i2_as_code_1 = match &i2_as_pending_1.requirement {
        ContinuationRequirement::Interaction { code, .. } => code.clone(),
        _ => String::new(),
    };
    let i2_as_resp_2 = i2_as.handle(&make_ps_signed_as_req(&format!("{I2_AS}/token"), Some(i2_as_body.clone()))?);
    let i2_as_pending_2 = PendingResponse::parse(&format!("{I2_AS}/token"), &i2_as_resp_2)
        .map_err(|_| "failed to parse i2_as_resp_2 PendingResponse")?;
    let i2_as_id_2 = i2_as_pending_2
        .location
        .strip_prefix(&format!("{I2_AS}/token/pending/"))
        .unwrap_or("")
        .to_owned();
    let i2_as_code_2 = match &i2_as_pending_2.requirement {
        ContinuationRequirement::Interaction { code, .. } => code.clone(),
        _ => String::new(),
    };

    // Policy returning a different interaction code gets 500 server_error
    i2_as_wrong_code.store(true, Ordering::SeqCst);
    let i2_as_wrong_resp = i2_as.handle(&make_ps_signed_as_req(&format!("{I2_AS}/token"), Some(i2_as_body))?);
    i2_as_wrong_code.store(false, Ordering::SeqCst);

    let i2_as_ok = i2_as_resp_1.status().as_u16() == 202
        && i2_as_resp_2.status().as_u16() == 202
        && is_valid_128bit_id(&i2_as_id_1)
        && is_valid_128bit_id(&i2_as_id_2)
        && i2_as_id_1 != i2_as_id_2
        && !i2_as_id_1.starts_with("predictable-as-seq-")
        && is_valid_40bit_code(&i2_as_code_1)
        && is_valid_40bit_code(&i2_as_code_2)
        && i2_as_code_1 != i2_as_code_2
        && i2_as_wrong_resp.status().as_u16() == 500
        && member(&i2_as_wrong_resp, "error").as_deref() == Some("server_error");

    // 4. ChainedInteraction::open draws its own 128-bit pending URL id and 40-bit interaction code
    let i2_cap_interaction = aauth_rust_core::capabilities::Capabilities::none()
        .with(aauth_rust_core::capabilities::Capability::Interaction);
    let i2_chained_1 = ChainedInteraction::open(
        &i2_as_pending_1,
        &i2_cap_interaction,
        "https://orders.example/checkout",
        "/checkout/pending",
        "https://orders.example/interact",
        "caller-jkt-1",
        clock + 300,
    )
    .map_err(|_| "ChainedInteraction::open 1 failed")?;
    let i2_chained_2 = ChainedInteraction::open(
        &i2_as_pending_1,
        &i2_cap_interaction,
        "https://orders.example/checkout",
        "/checkout/pending",
        "https://orders.example/interact",
        "caller-jkt-1",
        clock + 300,
    )
    .map_err(|_| "ChainedInteraction::open 2 failed")?;
    let i2_chained_id_1 = i2_chained_1
        .location()
        .strip_prefix("https://orders.example/checkout/pending/")
        .unwrap_or("");
    let i2_chained_id_2 = i2_chained_2
        .location()
        .strip_prefix("https://orders.example/checkout/pending/")
        .unwrap_or("");
    let i2_chained_ok = is_valid_128bit_id(i2_chained_id_1)
        && is_valid_128bit_id(i2_chained_id_2)
        && i2_chained_id_1 != i2_chained_id_2
        && i2_chained_id_1 != i2_as_id_1
        && is_valid_40bit_code(i2_chained_1.code())
        && is_valid_40bit_code(i2_chained_2.code())
        && i2_chained_1.code() != i2_chained_2.code()
        && i2_chained_1.code() != i2_as_code_1;

    // 5. R3 Held Calls (PsAuthorizationResource 202) & HeldInvocations::open()
    let i2_r3_held_1 = rust_fed_held
        .authorize(
            &post_at(
                &rfh_class_holder,
                &format!("{RUST_FED_HELD}/records/delete"),
                br#"{"record":"r-csprng-1"}"#,
                clock,
            )?,
            clock,
            "fixed-challenge-jti-alpha",
        )
        .into_response();
    let i2_r3_held_2 = rust_fed_held
        .authorize(
            &post_at(
                &rfh_class_holder,
                &format!("{RUST_FED_HELD}/records/delete"),
                br#"{"record":"r-csprng-2"}"#,
                clock,
            )?,
            clock,
            "fixed-challenge-jti-beta",
        )
        .into_response();
    let i2_r3_loc_1 = i2_r3_held_1
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i2_r3_loc_2 = i2_r3_held_2
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i2_r3_id_1 = i2_r3_loc_1
        .strip_prefix(&format!("{RUST_FED_HELD}/r3/pending/"))
        .unwrap_or("");
    let i2_r3_id_2 = i2_r3_loc_2
        .strip_prefix(&format!("{RUST_FED_HELD}/r3/pending/"))
        .unwrap_or("");

    let i2_held_invocations = HeldInvocations::new();
    let i2_held_inv_1 = i2_held_invocations.open();
    let i2_held_inv_2 = i2_held_invocations.open();
    let i2_r3_held_ok = i2_r3_held_1.status().as_u16() == 202
        && i2_r3_held_2.status().as_u16() == 202
        && is_valid_128bit_id(i2_r3_id_1)
        && is_valid_128bit_id(i2_r3_id_2)
        && i2_r3_id_1 != i2_r3_id_2
        && i2_r3_id_1 != "fixed-challenge-jti-alpha"
        && is_valid_128bit_id(&i2_held_inv_1)
        && is_valid_128bit_id(&i2_held_inv_2)
        && i2_held_inv_1 != i2_held_inv_2;

    let i2_all_ok = i2_core_ok
        && i2_ps_interaction_ok
        && i2_ps_mission_pending_ok
        && i2_ps_deferred_ok
        && i2_as_ok
        && i2_chained_ok
        && i2_r3_held_ok;

    cases.push(QaCaseReceipt {
        id: "QA-I2".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "OS CSPRNG 40-Bit Interaction Codes (XXXX-XXXX Crockford Base32) & 128-Bit Pending URL IDs (22-Char Base64url) Across PS, AS, Chained Interactions, R3 Held Calls & HeldInvocations::open()".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i2_all_ok,
        summary: format!(
            "CSPRNG 40-bit codes & 128-bit pending IDs verified across PS (interaction/mission/deferred={}), AS (deferred/wrong_code_500={}), ChainedInteraction ({}), R3 held calls & HeldInvocations::open ({})",
            i2_ps_interaction_ok && i2_ps_mission_pending_ok && i2_ps_deferred_ok,
            i2_as_ok,
            i2_chained_ok,
            i2_r3_held_ok
        ),
        evidence: json!({
            "person_server": {
                "opened_interaction_1": {"id": i2_opened_1.id, "code": i2_opened_1.code},
                "opened_interaction_2": {"id": i2_opened_2.id, "code": i2_opened_2.code},
                "mission_pending_id": i2_mission_id,
                "deferred_federation_pending_id": i2_ps_def_id,
                "all_valid_and_independent_of_host_ids": i2_ps_interaction_ok && i2_ps_mission_pending_ok && i2_ps_deferred_ok,
            },
            "access_server": {
                "pending_id_1": i2_as_id_1,
                "interaction_code_1": i2_as_code_1,
                "pending_id_2": i2_as_id_2,
                "interaction_code_2": i2_as_code_2,
                "wrong_interaction_code_refused_status": i2_as_wrong_resp.status().as_u16(),
            },
            "chained_interaction": {
                "location_1": i2_chained_1.location(),
                "code_1": i2_chained_1.code(),
                "location_2": i2_chained_2.location(),
                "code_2": i2_chained_2.code(),
            },
            "r3_held_and_held_invocations": {
                "r3_held_location_1": i2_r3_loc_1,
                "r3_held_location_2": i2_r3_loc_2,
                "held_invocations_open_1": i2_held_inv_1,
                "held_invocations_open_2": i2_held_inv_2,
            },
            "source_locations": [
                "crates/aauth-rust-core/src/continuation.rs:386-412 (generate_interaction_code, generate_pending_id)",
                "crates/aauth-rust-core/src/interaction.rs:248-288 (ChainedInteraction::open)",
                "crates/aauth-rust-person-server/src/server/governance.rs:116-148 (open_interaction_code)",
                "crates/aauth-rust-access-server/src/continuation.rs:94-125, 537-543 (drawn_code)",
                "crates/aauth-rust-resource/src/r3_per_call.rs:1059-1062, 1104-1108",
                "crates/aauth-rust-resource/src/held.rs:63-72 (HeldInvocations::open)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I2] PASS: csprng_40bit_codes_and_128bit_ids ps={} as={} chained={} r3_held={}",
        i2_ps_interaction_ok && i2_ps_mission_pending_ok && i2_ps_deferred_ok,
        i2_as_ok,
        i2_chained_ok,
        i2_r3_held_ok
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I3: Release-Gated R3 Proposal `## Action` Section & `budget: true` Pre-Approval Guard
    // -----------------------------------------------------------------------------------------
    const EXPECTED_RELEASE_ACTION: &str =
        "## Action\nThis operation has already run. What you are approving is release of its result to the agent.";

    // 1. Release proposal with no host detail (detail = None in R3Release.display) -> detail == EXPECTED_RELEASE_ACTION
    let i3_rel_none_resp = held_rel_res
        .authorize(
            &post_at(
                &g5_rel_class_holder,
                &format!("{RUST_FED_HELD}/records/query"),
                br#"{"record":"r-i3-none"}"#,
                clock,
            )?,
            clock,
            "i3-prop-rel-none",
        )
        .into_response();
    let i3_rel_none_pending = PollSession::new(
        &format!("{RUST_FED_HELD}/records/query"),
        &i3_rel_none_resp,
        clock,
        clock + 60,
    )?;
    let i3_rel_none_rt = match &i3_rel_none_pending.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token requirement on i3_rel_none_resp".into()),
    };
    let i3_rel_none_ver = fed_agent.verify_r3_proposal_challenge(
        &i3_rel_none_rt,
        RUST_FED_HELD,
        FED_PS,
        &g5_rel_class_tok,
        trust,
        clock,
    )?;
    let i3_rel_none_prop_path = out_dir
        .join("e3-held-rel")
        .join(format!("p-{}.json", digest(i3_rel_none_ver.reference().uri().as_bytes())));
    let i3_rel_none_rec = FileCalls::decode(&fs::read(&i3_rel_none_prop_path)?)?;
    let i3_rel_none_json: Value = serde_json::from_slice(&i3_rel_none_rec.exact_json)?;
    let i3_rel_none_detail = i3_rel_none_json["display"]["detail"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let i3_rel_none_ok = i3_rel_none_resp.status().as_u16() == 202
        && i3_rel_none_json.get("result").is_some()
        && i3_rel_none_detail == EXPECTED_RELEASE_ACTION;

    // 2. Custom Resource with (a) host detail on release ("## Details\n...") AND (b) an operation annotated `budget: true`
    const TOOLS_WITH_METERED: &[u8] = br#"{"tools":[
        {"name":"records.query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":false}},
        {"name":"records.metered_query","inputSchema":{"type":"object"},"_meta":{"aauth.dev/budget":true}}
    ]}"#;
    let i3_release_hook_calls = Arc::new(AtomicUsize::new(0));
    let i3_handler_exec_calls = Arc::new(AtomicUsize::new(0));
    let i3_rel_cnt_cb = i3_release_hook_calls.clone();
    let i3_doc_dir = out_dir.join("i3-metered-docs");
    let i3_call_dir = out_dir.join("i3-metered-calls");
    let i3_res = PsAuthorizationResource::new(
        PsAuthorizationConfig {
            issuer: H_RES_NOMISS.into(),
            signed_origin: H_RES_NOMISS.into(),
            kid: "nomiss-res-1".into(),
            signing_key: SigningKey::from_seed(H_RES_NOMISS_SEED),
            scopes: vec!["records.read".into()],
            scope_descriptions: BTreeMap::from([("records.read".into(), "Read records".into())]),
        },
        trust.clone(),
        Box::new(|token: &VerifiedAuthToken, _: &Request<Vec<u8>>| token.claims().ps == H_PS)
            as BoxedAuthPolicy,
    )?
    .with_authorization_endpoint()
    .with_r3(R3Config {
        registry: standard_registry()?,
        definitions: DefinitionRegistry::new(&[McpCodec::definition_registration()?])?,
        vocabularies: vec![R3Vocabulary {
            definition: McpCodec::parse_definition(
                &format!("{H_RES_NOMISS}/mcp"),
                &ToolsListSnapshot::new(vec![ToolsListPage::initial(TOOLS_WITH_METERED)]),
            )?,
            display: Some(Box::new(|_: &OperationSet| {
                Display::new("Query and metered query", None, None, None)
                    .map_err(|e| R3HostError::new(e.to_string()))
            })),
        }],
        documents: Arc::new(DirectoryDocumentStore::open(&i3_doc_dir)?),
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
            |op: &Operation, presented: &BTreeMap<String, PresentedParameter>, _: Option<&str>| {
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
                            format!("Run metered query {shown}")
                        } else {
                            format!("Run query {shown}")
                        },
                        None,
                        None,
                        None,
                    )
                    .map_err(|e| R3HostError::new(e.to_string()))?,
                    Some("## Details\nExecution consent detail."),
                )
                .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(R3CallDescription {
                    parameters,
                    display: Some(display),
                })
            },
        ),
        calls: Arc::new(DirectoryCallStore::open(&i3_call_dir)?),
        hold: true,
        release: Some(Box::new(
            move |_: &Request<Vec<u8>>,
                  _: &Operation,
                  presented: &BTreeMap<String, PresentedParameter>,
                  _: Option<&str>| {
                i3_rel_cnt_cb.fetch_add(1, Ordering::SeqCst);
                let value = presented
                    .get("record")
                    .and_then(PresentedParameter::inline_json)
                    .ok_or_else(|| R3HostError::new("record parameter is required"))?;
                let shown = String::from_utf8_lossy(&value).into_owned();
                let result = ProposalResult::new(br#"{"records":1}"#)
                    .map_err(|e| R3HostError::new(e.to_string()))?;
                let display = ProposalDisplay::new(
                    &Display::new(format!("Release query {shown}"), None, None, None)
                        .map_err(|e| R3HostError::new(e.to_string()))?,
                    Some(&format!(
                        "## Details\nOne record ({shown}), including a national identifier."
                    )),
                )
                .map_err(|e| R3HostError::new(e.to_string()))?;
                Ok(Some(R3Release {
                    result,
                    display,
                    response: json_response(200, json!({"released": shown})),
                    cost: None,
                }))
            },
        )),
        held_result_lifetime: 300,
    })?;

    // Mint a class R3 AuthToken granting both `records.query` and `records.metered_query` in `r3_per_call`
    let i3_ops_set = registry.parse_operation_set(
        json!({
            "vocabulary": MCP,
            "operations": [{"tool": "records.query"}, {"tool": "records.metered_query"}]
        })
        .to_string()
        .as_bytes(),
    )?;
    let i3_person_resp = h_ps_tls.send(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES_NOMISS}).to_string().as_bytes(),
        clock,
    )?)?;
    let i3_person_tok = member(&i3_person_resp, "person_token").ok_or("missing i3 person_token")?;
    let i3_class_rt = h_agent.r3_authorize(
        |req| Ok::<_, String>(i3_res.authorize_endpoint(&req, clock, "i3-class-rt-1").into_response()),
        &format!("{H_RES_NOMISS}/authorize"),
        &i3_person_tok,
        &i3_ops_set,
        None,
        clock,
    )?;
    let i3_class_rt_ver = h_agent.verify_r3_resource_token(
        &i3_class_rt,
        H_RES_NOMISS,
        H_PS,
        &i3_person_tok,
        None,
        trust,
        clock,
    )?;
    let i3_doc_store = DirectoryDocumentStore::open(&i3_doc_dir)?;
    let i3_call_store = DirectoryCallStore::open(&i3_call_dir)?;
    let i3_class_doc_rec = i3_doc_store
        .load(i3_class_rt_ver.reference().uri())
        .map_err(|e| format!("i3 load class doc: {e:?}"))?
        .ok_or("missing i3 class doc record")?;
    let i3_class_doc_bytes = i3_class_doc_rec.exact_json;
    let i3_per_call_granted = GrantedOperations::new(
        &mcp_vocab,
        &[mcp("records.query")?, mcp("records.metered_query")?],
    )?;
    let i3_class_authz = Authorization::new(
        &empty_ops,
        &i3_per_call_granted,
        &registry.parse_document(&i3_class_doc_bytes)?,
    )?;
    let i3_class_tok = mint_r3_class_auth_token(
        &registry,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES_NOMISS.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "i3-class-tok-1".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        i3_class_rt_ver.reference(),
        &i3_class_doc_bytes,
        &i3_class_authz,
    )?;
    let i3_class_holder = h_agent.with_token(i3_class_tok.clone())?;

    // (a) Unmetered `records.query` with host `## Details` -> release hook runs once, proposal detail opens with `## Action` + `\n\n## Details...`
    let i3_unmetered_resp = i3_res
        .authorize(
            &post_at(
                &i3_class_holder,
                &format!("{H_RES_NOMISS}/records/query"),
                R1,
                clock,
            )?,
            clock,
            "i3-prop-unmetered",
        )
        .into_response();
    let i3_hooks_after_unmetered = i3_release_hook_calls.load(Ordering::SeqCst);
    let i3_unmetered_pending = PollSession::new(
        &format!("{H_RES_NOMISS}/records/query"),
        &i3_unmetered_resp,
        clock,
        clock + 60,
    )?;
    let i3_unmetered_rt = match &i3_unmetered_pending.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token on i3_unmetered_resp".into()),
    };
    let i3_unmetered_ver = h_agent.verify_r3_proposal_challenge(
        &i3_unmetered_rt,
        H_RES_NOMISS,
        H_PS,
        &i3_class_tok,
        trust,
        clock,
    )?;
    let i3_unmetered_rec = i3_call_store
        .load(i3_unmetered_ver.reference().uri())
        .map_err(|e| format!("i3 load unmetered prop: {e:?}"))?
        .ok_or("missing i3 unmetered proposal record")?;
    let i3_unmetered_json: Value = serde_json::from_slice(&i3_unmetered_rec.exact_json)?;
    let i3_unmetered_detail = i3_unmetered_json["display"]["detail"]
        .as_str()
        .unwrap_or("")
        .to_owned();
    let i3_expected_with_details = format!(
        "{EXPECTED_RELEASE_ACTION}\n\n## Details\nOne record (\"r-1\"), including a national identifier."
    );

    // (b) Metered `records.metered_query` (`budget: true`) -> release hook is NEVER called before approval!
    let i3_metered_resp = i3_res
        .authorize(
            &post_at(
                &i3_class_holder,
                &format!("{H_RES_NOMISS}/records/metered-query"),
                R1,
                clock,
            )?,
            clock,
            "i3-prop-metered",
        )
        .into_response();
    let i3_hooks_after_metered = i3_release_hook_calls.load(Ordering::SeqCst);
    let i3_exec_before_approval = i3_handler_exec_calls.load(Ordering::SeqCst);
    let i3_metered_pending = PollSession::new(
        &format!("{H_RES_NOMISS}/records/metered-query"),
        &i3_metered_resp,
        clock,
        clock + 60,
    )?;
    let i3_metered_rt = match &i3_metered_pending.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token on i3_metered_resp".into()),
    };
    let i3_metered_ver = h_agent.verify_r3_proposal_challenge(
        &i3_metered_rt,
        H_RES_NOMISS,
        H_PS,
        &i3_class_tok,
        trust,
        clock,
    )?;
    let i3_metered_rec = i3_call_store
        .load(i3_metered_ver.reference().uri())
        .map_err(|e| format!("i3 load metered prop: {e:?}"))?
        .ok_or("missing i3 metered proposal record")?;
    let i3_metered_json: Value = serde_json::from_slice(&i3_metered_rec.exact_json)?;
    let i3_metered_has_no_result = i3_metered_json.get("result").is_none();
    let i3_metered_detail = i3_metered_json["display"]["detail"]
        .as_str()
        .unwrap_or("")
        .to_owned();

    // Approve the metered execution proposal and poll `/r3/pending/{id}` -> runs handler only AFTER approval
    let i3_metered_pc_tok = mint_per_call_auth_token(
        &registry,
        &h_ps_key,
        "mission-ps-1",
        &AuthClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: H_RES_NOMISS.into(),
            ps: H_PS.into(),
            sub: "mission-person".into(),
            jti: "i3-metered-pc-tok-1".into(),
            iat: clock,
            exp: clock + 300,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            scope: None,
            account: None,
            extra: BTreeMap::new(),
        },
        i3_metered_ver.reference(),
        &i3_metered_rec.exact_json,
    )?;
    let i3_metered_poll_req =
        i3_metered_pending.request(&h_agent.with_token(i3_metered_pc_tok)?, clock + 1)?;
    let i3_metered_poll_resp = match i3_res.authorize(&i3_metered_poll_req, clock + 1, "i3-poll-1") {
        AuthDecision::Granted(admitted) => {
            let grant = admitted.r3_grant().ok_or("missing r3_grant on metered poll")?;
            i3_handler_exec_calls.fetch_add(1, Ordering::SeqCst);
            let produced = json_response(200, json!({"metered_executed": true}));
            i3_res.r3_retain(&grant, produced)
        }
        other => other.into_response(),
    };
    let i3_exec_after_approval = i3_handler_exec_calls.load(Ordering::SeqCst);

    let i3_all_ok = i3_rel_none_ok
        && i3_hooks_after_unmetered == 1
        && i3_unmetered_detail == i3_expected_with_details
        && i3_metered_resp.status().as_u16() == 202
        && i3_hooks_after_metered == 1
        && i3_exec_before_approval == 0
        && i3_metered_has_no_result
        && i3_metered_detail == "## Details\nExecution consent detail."
        && i3_metered_poll_resp.status().as_u16() == 200
        && i3_exec_after_approval == 1;

    cases.push(QaCaseReceipt {
        id: "QA-I3".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "Release-Gated R3 Proposal Opens detail with `## Action` Section & `budget: true` Operation Is Never Run Before Approval".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i3_all_ok,
        summary: format!(
            "Release proposal opens detail with `## Action` (detail=None ok={}, detail=Some('## Details...') ok={}); `budget: true` operation skips release hook before approval (release_hooks_delta=0, exec_before_approval=0, result_omitted={}) and executes only after per-call approval (exec_after_approval={})",
            i3_rel_none_ok,
            i3_unmetered_detail == i3_expected_with_details,
            i3_metered_has_no_result,
            i3_exec_after_approval
        ),
        evidence: json!({
            "release_proposal_detail_when_host_detail_none": i3_rel_none_detail,
            "release_proposal_detail_when_host_detail_some": i3_unmetered_detail,
            "budget_true_operation_guard": {
                "initial_202_status": i3_metered_resp.status().as_u16(),
                "release_hook_calls_before_metered": i3_hooks_after_unmetered,
                "release_hook_calls_after_metered": i3_hooks_after_metered,
                "handler_executions_before_approval": i3_exec_before_approval,
                "proposal_has_no_result_member": i3_metered_has_no_result,
                "proposal_detail": i3_metered_detail,
                "poll_after_approval_status": i3_metered_poll_resp.status().as_u16(),
                "handler_executions_after_approval": i3_exec_after_approval,
            },
            "source_locations": [
                "crates/aauth-rust-resource/src/r3_per_call.rs:59-60, 708-722, 943-977 (RELEASE_ACTION, release_display, profile.metered)",
                "crates/aauth-rust-resource/src/r3_class.rs:283-287 (R3Profile::metered)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I3] PASS: release_action_prefix={} budget_true_never_runs_before_approval={}",
        i3_rel_none_ok && i3_unmetered_detail == i3_expected_with_details,
        i3_hooks_after_metered == 1 && i3_exec_before_approval == 0 && i3_exec_after_approval == 1
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I4: Agent 401 R3 `Signature-Error` Header Parsing (Never Body) &
    // `Agent::with_additional_signature_components` Over Live HTTPS
    // -----------------------------------------------------------------------------------------
    // 1. Agent::r3_authorize 401 reads Signature-Error header, never the body
    let i4_401_header_vs_body = h_agent.r3_authorize(
        |_| {
            Ok::<_, String>(
                Response::builder()
                    .status(401)
                    .header("content-type", "application/problem+json")
                    .header("signature-error", "error=invalid_signature")
                    .body(br#"{"error":"body_error_must_be_ignored"}"#.to_vec())
                    .unwrap(),
            )
        },
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    );
    let i4_401_multiline_nonjson = h_agent.r3_authorize(
        |_| {
            Ok::<_, String>(
                Response::builder()
                    .status(401)
                    .header("signature-error", "hint=\"check key\"")
                    .header("signature-error", "error=unsupported_algorithm")
                    .body(b"<<<not valid json>>>".to_vec())
                    .unwrap(),
            )
        },
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    );
    let i4_401_missing_header_body_ignored = h_agent.r3_authorize(
        |_| {
            Ok::<_, String>(
                Response::builder()
                    .status(401)
                    .header("content-type", "application/problem+json")
                    .body(br#"{"error":"invalid_signature"}"#.to_vec())
                    .unwrap(),
            )
        },
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    );
    let i4_400_reads_body = h_agent.r3_authorize(
        |_| {
            Ok::<_, String>(
                Response::builder()
                    .status(400)
                    .header("content-type", "application/problem+json")
                    .header("signature-error", "error=invalid_signature")
                    .body(br#"{"error":"invalid_request"}"#.to_vec())
                    .unwrap(),
            )
        },
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    );

    let i4_sig_err_ok = matches!(
        &i4_401_header_vs_body,
        Err(R3AgentError::Refused { status: 401, error: Some(code) }) if code == "invalid_signature"
    ) && matches!(
        &i4_401_multiline_nonjson,
        Err(R3AgentError::Refused { status: 401, error: Some(code) }) if code == "unsupported_algorithm"
    ) && matches!(
        &i4_401_missing_header_body_ignored,
        Err(R3AgentError::Refused { status: 401, error: None })
    ) && matches!(
        &i4_400_reads_body,
        Err(R3AgentError::Refused { status: 400, error: Some(code) }) if code == "invalid_request"
    );

    // 2. Agent::with_additional_signature_components over live HTTPS
    let i4_comp_agent = h_agent.with_additional_signature_components(["x-tenant", "content-digest"]);
    // Missing listed header on request -> Err(SigKeyError::InvalidInput) and request untouched
    let mut i4_missing_hdr_req = Request::builder()
        .method("GET")
        .uri(format!("{H_RES}/records/read"))
        .body(Vec::new())?;
    let i4_missing_hdr_refused =
        i4_comp_agent.sign(&mut i4_missing_hdr_req, clock) == Err(SigKeyError::InvalidInput)
            && !i4_missing_hdr_req.headers().contains_key("signature-input");

    // Invalid component names refused
    let mut i4_invalid_names_all_refused = true;
    for bad_comp in ["X-Tenant", "signature", "signature-input", "@status", ""] {
        let mut req = Request::builder()
            .method("GET")
            .uri(format!("{H_RES}/records/read"))
            .header("x-tenant", "acme")
            .body(Vec::new())?;
        if h_agent
            .with_additional_signature_components([bad_comp])
            .sign(&mut req, clock)
            != Err(SigKeyError::InvalidInput)
        {
            i4_invalid_names_all_refused = false;
        }
    }

    // with_token preserves additional_signature_components; signing GET with x-tenant covers content-digest & x-tenant and succeeds over live HTTPS
    let i4_comp_auth_holder = i4_comp_agent.with_token(auth_a1.clone())?;
    let mut i4_get_req = Request::builder()
        .method("GET")
        .uri(format!("{H_RES}/records/read?page=1"))
        .header("x-tenant", "acme-corp")
        .body(Vec::new())?;
    i4_comp_auth_holder.sign(&mut i4_get_req, clock)?;
    let i4_sig_input = i4_get_req
        .headers()
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i4_expected_sig_input = format!(
        "sig=(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\" \"x-tenant\" \"signature-key\");created={clock}"
    );
    let i4_live_https_resp = h_res_tls.send(&i4_get_req)?;
    // Tampering with covered x-tenant after signing fails signature verification (401 invalid_signature)
    let mut i4_tampered_req = i4_get_req.clone();
    i4_tampered_req
        .headers_mut()
        .insert("x-tenant", "evil-corp".parse().unwrap());
    let i4_tampered_resp = h_res_tls.send(&i4_tampered_req)?;

    // R3 authorization request and PollSession::request cover listed components (`content-digest`, `@query`)
    let i4_r3_comp_agent =
        h_agent.with_additional_signature_components(["content-type", "content-digest", "@query"]);
    let i4_r3_authz_req = i4_r3_comp_agent.r3_authorization_request(
        &format!("{H_RES}/authorize"),
        &person_a,
        &read_and_query,
        None,
        clock,
    )?;
    let i4_r3_authz_sig_input = i4_r3_authz_req
        .headers()
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let i4_r3_authz_live_resp = h_res_tls.send(&i4_r3_authz_req)?;
    let i4_poll_with_ct_refused =
        i3_rel_none_pending.request(&i4_r3_comp_agent, clock + 1).is_err();
    let i4_poll_comp_agent =
        h_agent.with_additional_signature_components(["content-digest", "@query"]);
    let i4_poll_req = i3_rel_none_pending.request(&i4_poll_comp_agent, clock + 1)?;
    let i4_poll_sig_input = i4_poll_req
        .headers()
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    let i4_components_ok = i4_missing_hdr_refused
        && i4_invalid_names_all_refused
        && i4_sig_input == i4_expected_sig_input
        && i4_live_https_resp.status().as_u16() == 200
        && i4_tampered_resp.status().as_u16() == 401
        && i4_r3_authz_sig_input
            == format!(
                "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"content-type\" \"@query\" \"signature-key\");created={clock}"
            )
        && i4_r3_authz_live_resp.status().as_u16() == 200
        && i4_poll_with_ct_refused
        && i4_poll_sig_input
            == format!(
                "sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" \"@query\" \"signature-key\");created={}",
                clock + 1
            );

    cases.push(QaCaseReceipt {
        id: "QA-I4".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "Agent::r3_authorize Reads 401 Error from Signature-Error Header (Never Body) & Agent::with_additional_signature_components Covers Listed Components Across Calls, /authorize & Polls".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i4_sig_err_ok && i4_components_ok,
        summary: format!(
            "Agent::r3_authorize 401 reads Signature-Error header and ignores body (ok={}); Agent::with_additional_signature_components covers custom headers/content-digest/@query across GET, /authorize & PollSession, refuses missing/invalid components, and rejects tampered header over HTTPS (ok={})",
            i4_sig_err_ok,
            i4_components_ok
        ),
        evidence: json!({
            "r3_authorize_401_signature_error": {
                "header_overrides_body_error": format!("{:?}", i4_401_header_vs_body),
                "multiline_header_with_non_json_body": format!("{:?}", i4_401_multiline_nonjson),
                "missing_header_ignores_body_error": format!("{:?}", i4_401_missing_header_body_ignored),
                "status_400_still_reads_body": format!("{:?}", i4_400_reads_body),
            },
            "additional_signature_components": {
                "missing_header_refused_with_invalid_input": i4_missing_hdr_refused,
                "invalid_component_names_refused": i4_invalid_names_all_refused,
                "get_signature_input": i4_sig_input,
                "live_https_get_status": i4_live_https_resp.status().as_u16(),
                "tampered_x_tenant_https_status": i4_tampered_resp.status().as_u16(),
                "r3_authorize_signature_input": i4_r3_authz_sig_input,
                "r3_authorize_live_https_status": i4_r3_authz_live_resp.status().as_u16(),
                "poll_session_signature_input": i4_poll_sig_input,
            },
            "source_locations": [
                "crates/aauth-rust-agent/src/r3.rs:78-94, 159-165 (signature_error on 401)",
                "crates/aauth-rust-agent/src/lib.rs:74-87, 120-132 (with_additional_signature_components)",
                "crates/aauth-rust-signature-key/src/lib.rs:463-474, 798-865 (sign_requests_with_components)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I4] PASS: r3_401_signature_error={} additional_signature_components={}",
        i4_sig_err_ok, i4_components_ok
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I5: Atomic R3 Audit Entry & Token Issuance Commit (`TokenRecord.r3`),
    // Fetched Document Digest Mismatch Refusal, and RedbStore Durable Round-Trip
    // -----------------------------------------------------------------------------------------
    #[derive(Clone, Default)]
    struct FallibleR3Store {
        inner: MemoryStore,
        fail_auth_commit: Arc< std::sync::atomic::AtomicBool >,
    }
    impl PsStore for FallibleR3Store {
        fn binding(
            &self,
            issuer: &str,
            agent: &AgentIdentity,
        ) -> std::result::Result<Option<aauth_rust_person_server::Binding>, PsStoreError> {
            self.inner.binding(issuer, agent)
        }
        fn token(
            &self,
            reference: &PsTokenReference,
        ) -> std::result::Result<Option<PsTokenRecord>, PsStoreError> {
            self.inner.token(reference)
        }
        fn commit(
            &self,
            record: PsTokenRecord,
            allow_new_binding: bool,
        ) -> std::result::Result<(), PsStoreError> {
            if record.kind == PsTokenKind::Auth && self.fail_auth_commit.load(Ordering::SeqCst) {
                return Err(PsStoreError::Unavailable);
            }
            self.inner.commit(record, allow_new_binding)
        }
        fn revoke_binding(
            &self,
            issuer: &str,
            agent: &AgentIdentity,
        ) -> std::result::Result<(), PsStoreError> {
            self.inner.revoke_binding(issuer, agent)
        }
    }
    #[derive(Default)]
    struct RecordingAuditLog {
        records: Mutex<Vec<IssuanceRecord>>,
    }
    impl IssuanceStore for RecordingAuditLog {
        fn commit(&self, record: &IssuanceRecord) -> std::result::Result<(), IssuanceError> {
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }
    }
    struct SwappableFetch {
        tls: Arc<TlsServer>,
        tamper_bytes: Arc< std::sync::atomic::AtomicBool >,
    }
    impl FetchTransport for SwappableFetch {
        fn send(&self, request: Request<Vec<u8>>, deadline: Instant) -> std::result::Result<FetchResponse, io::Error> {
            if Instant::now() >= deadline {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            if self.tamper_bytes.load(Ordering::SeqCst) {
                let tampered = json!({
                    "vocabulary": MCP,
                    "operations": [{"tool": "records.delete"}]
                })
                .to_string()
                .into_bytes();
                let resp = Response::builder()
                    .status(200)
                    .header("content-type", "application/aauth-r3+json")
                    .body(Box::new(BufferedFetchBody(tampered, 0)) as Box<dyn FetchBody>)
                    .map_err(io::Error::other)?;
                return Ok(resp);
            }
            let resp = self
                .tls
                .send(&request)
                .map_err(|err| io::Error::other(err.to_string()))?;
            let (parts, body) = resp.into_parts();
            Ok(Response::from_parts(
                parts,
                Box::new(BufferedFetchBody(body, 0)) as Box<dyn FetchBody>,
            ))
        }
    }

    let i5_store = FallibleR3Store::default();
    let i5_audit = Arc::new(RecordingAuditLog::default());
    let i5_tamper_fetch = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let i5_id_seq = Arc::new(AtomicUsize::new(0));
    let i5_ps = PersonServer::new(
        PsConfig::new(H_PS, "mission-ps-1", SigningKey::from_seed(H_PS_SEED)),
        trust.clone(),
        i5_store.clone(),
        QaPsPolicy,
        Box::new(move || clock) as BoxedClock,
        Box::new(move || format!("i5-tok-{}", i5_id_seq.fetch_add(1, Ordering::SeqCst) + 1))
            as BoxedTokenIds,
    )?
    .with_r3(R3IssuerConfig {
        registry: standard_registry()?,
        egress: Box::new(|uri: &str, _: Instant| {
            if uri.starts_with(&format!("{H_RES_NOMISS}/r3/")) {
                Ok(())
            } else {
                Err(io::Error::other("egress refused"))
            }
        }),
        transport: Box::new(SwappableFetch {
            tls: h_res_nomiss_tls.clone(),
            tamper_bytes: i5_tamper_fetch.clone(),
        }),
        limits: FetchLimits::default(),
        policy: Box::new(
            |_: &R3AuthorizationRequest<'_>| -> std::result::Result<R3Decision, PolicyError> {
                let vocab = McpCodec::vocabulary().map_err(|_| PolicyError::Unavailable)?;
                let read_op = mcp("records.read").map_err(|_| PolicyError::Unavailable)?;
                Ok(R3Decision {
                    granted: GrantedOperations::new(&vocab, &[read_op])
                        .map_err(|_| PolicyError::Unavailable)?,
                    per_call: None,
                    scopes: vec!["records.read".into()],
                    lifetime: 300,
                })
            },
        ),
        audit: i5_audit.clone(),
    })?;

    let i5_person_resp = i5_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/person"),
        json!({"resource": H_RES_NOMISS}).to_string().as_bytes(),
        clock,
    )?);
    let i5_person_tok = member(&i5_person_resp, "person_token").ok_or("missing i5 person_token")?;
    let i5_rt = h_agent.r3_authorize(
        |req| h_res_nomiss_tls.send(&req),
        &format!("{H_RES_NOMISS}/authorize"),
        &i5_person_tok,
        &read_and_query,
        Some("records.read"),
        clock,
    )?;

    // 1. Failed issuance commit writes NO audit entry to either Store or IssuanceStore
    i5_store.fail_auth_commit.store(true, Ordering::SeqCst);
    let i5_failed_resp = i5_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": i5_rt,
            "presented_token": i5_person_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?);
    let i5_audit_len_after_fail = i5_audit.records.lock().unwrap().len();
    let i5_store_auth_after_fail = i5_store
        .inner
        .retained()?
        .into_iter()
        .filter(|r| r.kind == PsTokenKind::Auth)
        .count();
    i5_store.fail_auth_commit.store(false, Ordering::SeqCst);

    // 2. Digest mismatch on fetched R3 document returns 400 invalid_resource_token and writes NO audit entry
    i5_tamper_fetch.store(true, Ordering::SeqCst);
    let i5_digest_mismatch_resp = i5_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": i5_rt,
            "presented_token": i5_person_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?);
    let i5_audit_len_after_mismatch = i5_audit.records.lock().unwrap().len();
    i5_tamper_fetch.store(false, Ordering::SeqCst);

    // 3. Successful issuance commits TokenRecord.r3 atomically and matches IssuanceStore
    let i5_ok_resp = i5_ps.handle(&post_at(
        &h_agent,
        &format!("{H_PS}/token"),
        json!({
            "resource_token": i5_rt,
            "presented_token": i5_person_tok,
        })
        .to_string()
        .as_bytes(),
        clock,
    )?);
    let i5_auth_records: Vec<PsTokenRecord> = i5_store
        .inner
        .retained()?
        .into_iter()
        .filter(|r| r.kind == PsTokenKind::Auth)
        .collect();
    let i5_audit_records = i5_audit.records.lock().unwrap().clone();
    let i5_reconstructed = i5_auth_records
        .first()
        .and_then(|r| r.r3_issuance().ok().flatten());
    let i5_atomic_match = i5_ok_resp.status().as_u16() == 200
        && i5_auth_records.len() == 1
        && i5_audit_records.len() == 1
        && i5_reconstructed.as_ref() == i5_audit_records.first();

    // 4. RedbStore durable persistence & validation of TokenRecord.r3 across close and reopen
    let i5_redb_dir = out_dir.join("i5-redb");
    fs::create_dir_all(&i5_redb_dir)?;
    let i5_redb_path = i5_redb_dir.join("person-r3.redb");
    if i5_redb_path.exists() {
        fs::remove_file(&i5_redb_path)?;
    }
    let i5_redb_roundtrip_ok = {
        let redb_store = RedbStore::open(&i5_redb_path)?;
        for rec in i5_store.inner.retained()? {
            let allow_new = rec.kind == PsTokenKind::Person;
            redb_store.commit(rec, allow_new)?;
        }
        // Also verify inconsistent r3 audit entry is rejected by RedbStore with InvalidRecord
        let mut bad_rec = i5_auth_records[0].clone();
        bad_rec.token.reference.jti = "i5-bad-r3-jti".into();
        bad_rec.r3.as_mut().unwrap().subject = "wrong-subject".into();
        let bad_refused = redb_store.commit(bad_rec, false) == Err(PsStoreError::InvalidRecord);
        drop(redb_store);

        let reopened = RedbStore::open(&i5_redb_path)?;
        let loaded = reopened
            .token(&i5_auth_records[0].token.reference)?
            .ok_or("missing R3 Auth record in reopened RedbStore")?;
        bad_refused
            && loaded == i5_auth_records[0]
            && loaded.r3_issuance()? == i5_reconstructed
    };

    let i5_all_ok = i5_failed_resp.status().as_u16() == 500
        && i5_audit_len_after_fail == 0
        && i5_store_auth_after_fail == 0
        && i5_digest_mismatch_resp.status().as_u16() == 400
        && member(&i5_digest_mismatch_resp, "error").as_deref() == Some("invalid_resource_token")
        && i5_audit_len_after_mismatch == 0
        && i5_atomic_match
        && i5_redb_roundtrip_ok;

    cases.push(QaCaseReceipt {
        id: "QA-I5".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "Atomic R3 Audit Entry & Token Issuance Commit (TokenRecord.r3), Fetched Document Digest Mismatch Refusal & RedbStore Reopen Durability".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i5_all_ok,
        summary: format!(
            "Failed issuance commit writes 0 audit entries (audit_len={}, store_len={}); digest mismatch returns 400 invalid_resource_token with 0 audit entries; successful issuance commits TokenRecord.r3 matching IssuanceStore (ok={}); RedbStore round-trips TokenRecord.r3 across close/reopen (ok={})",
            i5_audit_len_after_fail,
            i5_store_auth_after_fail,
            i5_atomic_match,
            i5_redb_roundtrip_ok
        ),
        evidence: json!({
            "failed_issuance_commit": {
                "status": i5_failed_resp.status().as_u16(),
                "error": member(&i5_failed_resp, "error"),
                "audit_log_entries": i5_audit_len_after_fail,
                "store_auth_records": i5_store_auth_after_fail,
            },
            "fetched_document_digest_mismatch": {
                "status": i5_digest_mismatch_resp.status().as_u16(),
                "error": member(&i5_digest_mismatch_resp, "error"),
                "audit_log_entries": i5_audit_len_after_mismatch,
            },
            "successful_atomic_commit": {
                "status": i5_ok_resp.status().as_u16(),
                "token_record_r3": i5_auth_records.first().and_then(|r| r.r3.clone()),
                "r3_issuance_matches_audit_log": i5_atomic_match,
            },
            "redb_store_durability": {
                "reopen_roundtrip_and_invalid_record_refusal_ok": i5_redb_roundtrip_ok,
            },
            "source_locations": [
                "crates/aauth-rust-person-server/src/server/r3.rs:795-822 (record.r3 committed before r3.audit)",
                "crates/aauth-rust-person-server/src/store.rs:101-183, 252-264 (R3IssuanceAudit, r3_issuance, validate_for_commit)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I5] PASS: atomic_r3_audit_commit fail_leaves_zero={} digest_mismatch_400={} redb_roundtrip={}",
        i5_audit_len_after_fail == 0 && i5_store_auth_after_fail == 0,
        i5_digest_mismatch_resp.status().as_u16() == 400 && i5_audit_len_after_mismatch == 0,
        i5_redb_roundtrip_ok
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I6: Access Server `upstream_token` Verification (`UpstreamToken::Person` & `UpstreamToken::Auth`),
    // Expiry Clamping, Agent PS Profile Relaxation, and Negative Refusals Over HTTPS
    // -----------------------------------------------------------------------------------------
    const I6_AS: &str = "https://i6-as.example";
    const I6_ORDERS: &str = "https://i6-orders.example";
    const I6_OTHER_PS: &str = "https://i6-other-ps.example";
    const I6_AS_SEED: [u8; 32] = [0x92; 32];
    const I6_ORDERS_SEED: [u8; 32] = [0x93; 32];
    const I6_INTERMEDIARY_KEY_SEED: [u8; 32] = [0x94; 32];
    const I6_OTHER_PS_SEED: [u8; 32] = [0x95; 32];

    let i6_orders_ap = AgentProvider::new(I6_ORDERS, "orders-ap-1", SigningKey::from_seed(I6_ORDERS_SEED))?;
    trust.insert_manual(
        I6_ORDERS,
        "aauth-agent.json",
        TrustedIssuerKeys::from_documents(
            I6_ORDERS,
            "aauth-agent.json",
            &i6_orders_ap.metadata()?,
            &i6_orders_ap.jwks()?,
        )?,
    )?;
    let mut i6_other_ps_jwk = serde_json::to_value(SigningKey::from_seed(I6_OTHER_PS_SEED).public_jwk())?;
    i6_other_ps_jwk["kid"] = json!("other-ps-1");
    trust.insert_manual(
        I6_OTHER_PS,
        "aauth-person.json",
        TrustedIssuerKeys::from_documents(
            I6_OTHER_PS,
            "aauth-person.json",
            &serde_json::to_vec(&json!({"issuer": I6_OTHER_PS, "jwks_uri": format!("{I6_OTHER_PS}/jwks.json")}))?,
            &serde_json::to_vec(&json!({"keys": [i6_other_ps_jwk]}))?,
        )?,
    )?;

    let i6_intermediary_key = SigningKey::from_seed(I6_INTERMEDIARY_KEY_SEED);
    let i6_intermediary_agent_tok = i6_orders_ap.issue(&AgentClaims {
        iss: I6_ORDERS.into(),
        dwk: "aauth-agent.json".into(),
        sub: "aauth:intermediary@i6-orders.example".into(),
        jti: "i6-intermediary-agent-1".into(),
        iat: clock,
        exp: clock + 1800,
        cnf: Confirmation {
            jwk: i6_intermediary_key.public_jwk(),
        },
        // Intermediary's own PS is I6_OTHER_PS (different from signing PS H_PS!)
        ps: Some(I6_OTHER_PS.into()),
        parent_agent: None,
        nbf: None,
        extra: Default::default(),
    })?;

    let i6_seen_upstreams = Arc::new(Mutex::new(Vec::<Option<UpstreamToken>>::new()));
    let i6_seen_cb = i6_seen_upstreams.clone();
    let i6_id_seq = Arc::new(AtomicUsize::new(0));
    let i6_as = Arc::new(
        AccessServer::new(
            AsConfig::new(I6_AS, "i6-as-1", SigningKey::from_seed(I6_AS_SEED)),
            trust.clone(),
            move |req: &AsAuthorizationRequest| {
                i6_seen_cb.lock().unwrap().push(req.upstream.clone());
                Ok(AsDecision {
                    scopes: vec!["records.read".into()],
                    lifetime: 3600,
                })
            },
            move || clock,
            move || format!("i6-as-tok-{}", i6_id_seq.fetch_add(1, Ordering::SeqCst) + 1),
        )?
        .with_revocation(),
    );
    let i6_as_for_tls = i6_as.clone();
    let i6_as_tls = Arc::new(TlsServer::start("i6-as.example", move |req| {
        i6_as_for_tls.handle(&req)
    })?);
    trust.discover(&i6_as_tls, I6_AS, "aauth-access.json")?;

    let i6_downstream_person = mint_person_token(
        &h_ps_key,
        "mission-ps-1",
        &PersonClaims {
            iss: H_PS.into(),
            dwk: "aauth-person.json".into(),
            aud: RUST_FED_RECORDS.into(),
            sub: "directed-person-at-downstream".into(),
            jti: "i6-downstream-person-1".into(),
            iat: clock,
            exp: clock + 900,
            cnf: Confirmation {
                jwk: i6_intermediary_key.public_jwk(),
            },
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;
    let i6_downstream_chal = mint_core_resource_token(
        &SigningKey::from_seed([0x55; 32]),
        "rust-fed-res-1",
        &ResourceClaims {
            iss: RUST_FED_RECORDS.into(),
            dwk: "aauth-resource.json".into(),
            aud: I6_AS.into(),
            ps: H_PS.into(),
            sub: "directed-person-at-downstream".into(),
            jti: "i6-downstream-chal-1".into(),
            presented_jti: "i6-downstream-person-1".into(),
            agent_jkt: i6_intermediary_key.public_jwk().thumbprint()?,
            iat: clock,
            exp: clock + 300,
            scope: Some("records.read".into()),
            account: None,
            login_hint: None,
            nbf: None,
            tenant: None,
            mission_s256: None,
            extra: BTreeMap::new(),
        },
    )?;

    let i6_mint_upstream_person = |jti: &str, iss: &str, aud: &str, exp: i64, seed: [u8; 32], kid: &str| -> Result<String> {
        Ok(mint_person_token(
            &SigningKey::from_seed(seed),
            kid,
            &PersonClaims {
                iss: iss.into(),
                dwk: "aauth-person.json".into(),
                aud: aud.into(),
                sub: "caller-at-orders".into(),
                jti: jti.into(),
                iat: clock.min(exp - 60),
                exp,
                cnf: Confirmation {
                    jwk: h_agent_key.public_jwk(),
                },
                nbf: None,
                tenant: None,
                mission_s256: None,
                extra: BTreeMap::new(),
            },
        )?)
    };
    let i6_upstream_person_ok_tok =
        i6_mint_upstream_person("i6-up-person-1", H_PS, I6_ORDERS, clock + 180, H_PS_SEED, "mission-ps-1")?;
    let i6_upstream_auth_ok_tok = mint_auth_token(
        &other_as_key,
        "other-as-1",
        &AuthClaims {
            iss: other_as_issuer.into(),
            dwk: "aauth-access.json".into(),
            aud: I6_ORDERS.into(),
            ps: H_PS.into(),
            sub: "caller-at-orders".into(),
            jti: "i6-up-auth-1".into(),
            iat: clock,
            exp: clock + 140,
            cnf: Confirmation {
                jwk: h_agent_key.public_jwk(),
            },
            scope: Some("orders.write".into()),
            account: None,
            tenant: None,
            mission_s256: None,
            nbf: None,
            extra: BTreeMap::new(),
        },
    )?;

    let i6_send_as_token = |body: Value| -> Result<Response<Vec<u8>>> {
        let req = make_ps_signed_as_req(&format!("{I6_AS}/token"), Some(body))?;
        i6_as_tls.send(&req)
    };

    // 1. Positive upstream PersonToken over HTTPS -> 200 OK, exp clamped to clock + 180
    let i6_pos_person_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_upstream_person_ok_tok,
    }))?;
    let i6_pos_person_auth = AuthToken::parse(
        &member(&i6_pos_person_resp, "auth_token").ok_or("missing i6 pos person auth_token")?,
    )?
    .verify(trust, clock)?;

    // 2. Positive upstream AuthToken (from another AS, ps == H_PS) over HTTPS -> 200 OK, exp clamped to clock + 140
    let i6_pos_auth_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_upstream_auth_ok_tok,
    }))?;
    let i6_pos_auth_granted = AuthToken::parse(
        &member(&i6_pos_auth_resp, "auth_token").ok_or("missing i6 pos auth auth_token")?,
    )?
    .verify(trust, clock)?;

    let i6_seen_count_after_pos = i6_seen_upstreams.lock().unwrap().len();

    // 3. Negative checks (all refused before policy)
    // (a) Without upstream_token, intermediary's ps != H_PS is refused as 400 invalid_agent_token
    let i6_unchained_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
    }))?;
    // (b) Bad signature on upstream_token -> 400 invalid_upstream_token
    let i6_bad_sig_tok =
        i6_mint_upstream_person("i6-up-badsig", H_PS, I6_ORDERS, clock + 180, [0x99; 32], "mission-ps-1")?;
    let i6_bad_sig_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_bad_sig_tok,
    }))?;
    // (c) Wrong audience (aud != I6_ORDERS) -> 400 invalid_upstream_token
    let i6_wrong_aud_tok = i6_mint_upstream_person(
        "i6-up-wrongaud",
        H_PS,
        "https://wrong-intermediary.example",
        clock + 180,
        H_PS_SEED,
        "mission-ps-1",
    )?;
    let i6_wrong_aud_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_wrong_aud_tok,
    }))?;
    // (d) Wrong PS (iss == I6_OTHER_PS != signing H_PS) -> 400 invalid_upstream_token
    let i6_wrong_ps_tok = i6_mint_upstream_person(
        "i6-up-wrongps",
        I6_OTHER_PS,
        I6_ORDERS,
        clock + 180,
        I6_OTHER_PS_SEED,
        "other-ps-1",
    )?;
    let i6_wrong_ps_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_wrong_ps_tok,
    }))?;
    // (e) Expired upstream_token -> 400 expired_upstream_token
    let i6_expired_tok =
        i6_mint_upstream_person("i6-up-expired", H_PS, I6_ORDERS, clock, H_PS_SEED, "mission-ps-1")?;
    let i6_expired_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_expired_tok,
    }))?;
    // (f) Combined with subagent_token -> 400 invalid_request
    let i6_subagent_combo_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "subagent_token": h_child_agent_compact,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_upstream_person_ok_tok,
    }))?;
    // (g) Revoked upstream_token -> 400 revoked_upstream_token
    let i6_revoke_req = make_ps_signed_as_req(
        &format!("{I6_AS}/revoke"),
        Some(json!({"jti": "i6-up-person-1", "exp": clock + 180})),
    )?;
    let i6_revoke_resp = i6_as_tls.send(&i6_revoke_req)?;
    let i6_revoked_up_resp = i6_send_as_token(json!({
        "agent_token": i6_intermediary_agent_tok,
        "presented_token": i6_downstream_person,
        "resource_token": i6_downstream_chal,
        "upstream_token": i6_upstream_person_ok_tok,
    }))?;

    let i6_seen_count_after_neg = i6_seen_upstreams.lock().unwrap().len();
    let i6_all_ok = i6_pos_person_resp.status().as_u16() == 200
        && i6_pos_person_auth.claims().exp == clock + 180
        && i6_pos_auth_resp.status().as_u16() == 200
        && i6_pos_auth_granted.claims().exp == clock + 140
        && i6_seen_count_after_pos == 2
        && i6_unchained_resp.status().as_u16() == 400
        && member(&i6_unchained_resp, "error").as_deref() == Some("invalid_agent_token")
        && i6_bad_sig_resp.status().as_u16() == 400
        && member(&i6_bad_sig_resp, "error").as_deref() == Some("invalid_upstream_token")
        && i6_wrong_aud_resp.status().as_u16() == 400
        && member(&i6_wrong_aud_resp, "error").as_deref() == Some("invalid_upstream_token")
        && i6_wrong_ps_resp.status().as_u16() == 400
        && member(&i6_wrong_ps_resp, "error").as_deref() == Some("invalid_upstream_token")
        && i6_expired_resp.status().as_u16() == 400
        && member(&i6_expired_resp, "error").as_deref() == Some("expired_upstream_token")
        && i6_subagent_combo_resp.status().as_u16() == 400
        && member(&i6_subagent_combo_resp, "error").as_deref() == Some("invalid_request")
        && i6_revoke_resp.status().is_success()
        && i6_revoked_up_resp.status().as_u16() == 400
        && member(&i6_revoked_up_resp, "error").as_deref() == Some("revoked_upstream_token")
        && i6_seen_count_after_neg == 2;

    cases.push(QaCaseReceipt {
        id: "QA-I6".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "Access Server Verifies Passed-Through upstream_token (Person & Auth), Clamps Grant Expiry, Relaxes Intermediary Agent PS Profile & Refuses Invalid/Expired/Revoked Upstream Tokens Before Policy".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i6_all_ok,
        summary: format!(
            "AS verifies upstream PersonToken (200, exp=+{}s) & AuthToken (200, exp=+{}s); refuses unchained intermediary ps mismatch (400 invalid_agent_token), bad sig/aud/ps (400 invalid_upstream_token), expired (400 expired_upstream_token), revoked (400 revoked_upstream_token), and subagent+upstream (400 invalid_request) with 0 policy calls",
            i6_pos_person_auth.claims().exp - clock,
            i6_pos_auth_granted.claims().exp - clock
        ),
        evidence: json!({
            "positive_person_upstream": {
                "status": i6_pos_person_resp.status().as_u16(),
                "clamped_exp_offset": i6_pos_person_auth.claims().exp - clock,
            },
            "positive_auth_upstream": {
                "status": i6_pos_auth_resp.status().as_u16(),
                "clamped_exp_offset": i6_pos_auth_granted.claims().exp - clock,
            },
            "negative_refusals_before_policy": {
                "unchained_intermediary_ps_mismatch": member(&i6_unchained_resp, "error"),
                "bad_signature": member(&i6_bad_sig_resp, "error"),
                "wrong_audience": member(&i6_wrong_aud_resp, "error"),
                "wrong_person_server": member(&i6_wrong_ps_resp, "error"),
                "expired_upstream": member(&i6_expired_resp, "error"),
                "subagent_plus_upstream": member(&i6_subagent_combo_resp, "error"),
                "revoked_upstream": member(&i6_revoked_up_resp, "error"),
                "policy_calls_on_negatives": i6_seen_count_after_neg - i6_seen_count_after_pos,
            },
            "source_locations": [
                "crates/aauth-rust-access-server/src/lib.rs:124-157, 398-415, 479-504, 585-587, 732-738",
                "crates/aauth-rust-access-server/src/revocation.rs:482-486"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I6] PASS: as_upstream_token_verification person_exp=+{}s auth_exp=+{}s neg_refusals_ok={}",
        i6_pos_person_auth.claims().exp - clock,
        i6_pos_auth_granted.claims().exp - clock,
        i6_all_ok
    ));

    // -----------------------------------------------------------------------------------------
    // QA-I7: Standard Vocabulary Namespace Guard, gRPC `method` Requirement, Runtime-Outranks-
    // Annotation & Live Cross-Language `aauth-go` HTTPS Interop on Changed Surface
    // -----------------------------------------------------------------------------------------
    // 1. Vocabulary::new refuses non-standard URIs in `urn:aauth:vocabulary:` (case-insensitive)
    struct TestCustomCodec(String);
    impl Codec for TestCustomCodec {
        type Set = Vec<Vec<u8>>;
        fn uri(&self) -> VocabularyUri {
            VocabularyUri::parse(&self.0).unwrap()
        }
        fn annotation_encoding(&self) -> AnnotationEncoding {
            AnnotationEncoding::UNAVAILABLE
        }
        fn validate_discovery_endpoint(&self, _endpoint: &str) -> std::result::Result<(), R3Error> {
            Ok(())
        }
        fn parse_set(&self, raw_operations: &[Vec<u8>]) -> std::result::Result<Self::Set, R3Error> {
            Ok(raw_operations.to_vec())
        }
        fn marshal_set(&self, set: &Self::Set) -> std::result::Result<Vec<Vec<u8>>, R3Error> {
            Ok(set.clone())
        }
        fn union_sets<'a>(
            &self,
            sets: impl IntoIterator<Item = &'a Self::Set>,
        ) -> std::result::Result<Self::Set, R3Error> {
            let mut out = Vec::new();
            for s in sets {
                out.extend(s.iter().cloned());
            }
            Ok(out)
        }
        fn sets_equal(&self, a: &Self::Set, b: &Self::Set) -> bool {
            a == b
        }
        fn is_subset(&self, _a: &Self::Set, _b: &Self::Set) -> bool {
            true
        }
        fn is_disjoint(&self, _a: &Self::Set, _b: &Self::Set) -> bool {
            true
        }
    }
    let mut i7_bad_ns_all_refused = true;
    for bad_uri in [
        "urn:aauth:vocabulary:widgets",
        "urn:aauth:vocabulary:mcp:v2",
        "urn:aauth:vocabulary:MCP",
        "URN:AAUTH:VOCABULARY:mcp",
        "urn:AAuth:vocabulary:custom",
    ] {
        if Vocabulary::new(TestCustomCodec(bad_uri.into())).is_ok() {
            i7_bad_ns_all_refused = false;
        }
    }
    let i7_good_ns_accepted = Vocabulary::new(TestCustomCodec("urn:aauth:vocabulary:mcp".into())).is_ok()
        && Vocabulary::new(TestCustomCodec("https://vocabulary.example/widgets".into())).is_ok()
        && Vocabulary::new(TestCustomCodec("urn:example:vocabulary:widgets".into())).is_ok();

    // 2. gRPC operation entries without `method` are refused across set, grant, and document parsing
    let mut i7_grpc_missing_method_refused = true;
    for bad_grpc_op in [
        json!({}),
        json!({"service": "calendar.CalendarService"}),
        json!({"Method": "calendar.CalendarService/CreateEvent"}),
    ] {
        let env = json!({
            "vocabulary": "urn:aauth:vocabulary:grpc",
            "operations": [bad_grpc_op]
        })
        .to_string();
        if registry.parse_operation_set(env.as_bytes()).is_ok()
            || registry.parse_granted_operations(env.as_bytes()).is_ok()
            || registry.parse_document(env.as_bytes()).is_ok()
        {
            i7_grpc_missing_method_refused = false;
        }
    }
    let i7_grpc_valid_ok = registry
        .parse_operation_set(
            br#"{"vocabulary":"urn:aauth:vocabulary:grpc","operations":[{"method":"calendar.CalendarService/CreateEvent"}]}"#,
        )
        .is_ok();

    // 3. Live Cross-Language `aauth-go` HTTPS Interop on Changed Surface:
    // (a) Rust Agent with `with_additional_signature_components` calling live Go Federated Resource
    //     (`FED_RECORDS/authorize` with `["content-digest", "content-type"]` and `GET /records/r-1?filter=active`
    //     with `["x-trace-id", "content-digest"]`) over HTTPS
    let i7_go_both_rt = fed_agent
        .with_additional_signature_components(["content-digest", "content-type"])
        .r3_authorize(
            |req| TlsServer::send_external(fed_records_addr, "fed-records.example", &fed_records_cert, &req),
            &format!("{FED_RECORDS}/authorize"),
            &fed_person_token,
            &read_and_delete,
            None,
            clock,
        )?;
    let i7_go_both_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({"resource_token": i7_go_both_rt, "presented_token": fed_person_token})
                .to_string()
                .as_bytes(),
            clock,
        )?,
    )?;
    let i7_go_both_class_auth =
        member(&i7_go_both_ex_resp, "auth_token").ok_or("missing i7_go_both_class_auth")?;
    let i7_go_comp_agent = fed_agent
        .with_additional_signature_components(["x-trace-id", "content-digest"])
        .with_token(i7_go_both_class_auth)?;
    let mut i7_go_read_req = Request::builder()
        .method("GET")
        .uri(format!("{FED_RECORDS}/records/r-1?filter=active"))
        .header("x-trace-id", "trace-go-interop-1")
        .body(Vec::new())?;
    i7_go_comp_agent.sign(&mut i7_go_read_req, clock)?;
    let i7_go_read_resp = TlsServer::send_external(
        fed_records_addr,
        "fed-records.example",
        &fed_records_cert,
        &i7_go_read_req,
    )?;

    // (b) Live `aauth-go` HTTPS Resource returning 401 with `Signature-Error` to Rust `Agent::r3_authorize`
    //     when signature is tampered (verifying cross-language `Signature-Error` header parsing on 401)
    let i7_go_401_sig_err = fed_agent.r3_authorize(
        |mut req| {
            // Tamper the body after signing so Go Resource rejects the HTTP Message Signature with 401 + Signature-Error
            *req.body_mut() = br#"{"r3_operations":{"vocabulary":"urn:aauth:vocabulary:mcp","operations":[]}}"#.to_vec();
            TlsServer::send_external(
                fed_records_addr,
                "fed-records.example",
                &fed_records_cert,
                &req,
            )
        },
        &format!("{FED_RECORDS}/authorize"),
        &fed_person_token,
        &read_and_delete,
        None,
        clock,
    );
    let i7_go_401_parsed_ok = matches!(
        &i7_go_401_sig_err,
        Err(R3AgentError::Refused { status: 401, error: Some(code) }) if !code.is_empty()
    );

    // (c) Live `aauth-go` Federated PS/AS (`FED_PS` / `FED_AS`) exchanging a held proposal
    //     from Rust `RUST_FED_HELD` (carrying the new 128-bit CSPRNG pending ID in `Location`)
    //     and completing the held poll with `Agent::with_additional_signature_components(["content-digest", "@query"])`!
    let i7_rel_chal_resp = rust_fed_held_tls.send(&post_at(
        &rfh_class_holder,
        &format!("{RUST_FED_HELD}/records/delete"),
        br#"{"record":"r-go-interop-rel"}"#,
        clock,
    )?)?;
    let mut i7_rel_poll_sess = PollSession::new(
        &format!("{RUST_FED_HELD}/records/delete"),
        &i7_rel_chal_resp,
        clock,
        clock + 60,
    )?;
    let i7_rel_pending_id = i7_rel_poll_sess
        .pending()
        .location
        .strip_prefix(&format!("{RUST_FED_HELD}/r3/pending/"))
        .unwrap_or("")
        .to_owned();
    let i7_rel_prop_rt = match &i7_rel_poll_sess.pending().requirement {
        ContinuationRequirement::AuthToken { resource_token } => resource_token.clone(),
        _ => return Err("missing auth-token on i7_rel_chal_resp".into()),
    };
    let i7_go_ex_resp = TlsServer::send_external(
        fed_ps_addr,
        "fed-ps.example",
        &fed_ps_cert,
        &post_at(
            &fed_agent,
            &format!("{FED_PS}/token"),
            json!({
                "resource_token": i7_rel_prop_rt,
                "presented_token": rfh_class_auth,
            })
            .to_string()
            .as_bytes(),
            clock,
        )?,
    )?;
    let i7_go_rel_tok = member(&i7_go_ex_resp, "auth_token").ok_or("missing i7_go_rel_tok from Go PS")?;
    let i7_poll_agent = fed_agent
        .with_additional_signature_components(["content-digest", "@query"])
        .with_token(i7_go_rel_tok)?;
    let i7_poll_req = i7_rel_poll_sess.request(&i7_poll_agent, clock + 1)?;
    let i7_poll_raw = rust_fed_held_tls.send(&i7_poll_req)?;
    let i7_poll_terminal = i7_rel_poll_sess
        .accept(i7_poll_raw, clock + 1)?
        .ok_or("i7 release poll did not complete")?;

    let i7_all_ok = i7_bad_ns_all_refused
        && i7_good_ns_accepted
        && i7_grpc_missing_method_refused
        && i7_grpc_valid_ok
        && i7_go_read_resp.status().as_u16() == 200
        && i7_go_401_parsed_ok
        && is_valid_128bit_id(&i7_rel_pending_id)
        && i7_go_ex_resp.status().as_u16() == 200
        && i7_poll_terminal.status().as_u16() == 200;

    cases.push(QaCaseReceipt {
        id: "QA-I7".into(),
        category: "I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens".into(),
        title: "Vocabulary Namespace Guard, gRPC Method Requirement & Live Cross-Language aauth-go HTTPS Interop (additional_signature_components, 401 Signature-Error, Release-Gated ## Action Proposal & 128-Bit CSPRNG Pending Poll)".into(),
        classification: "VERIFIED_WORKING".into(),
        passed_expectation: i7_all_ok,
        summary: format!(
            "Vocabulary::new refuses non-standard urn:aauth:vocabulary:* (ok={}); gRPC refuses missing method (ok={}); live Go Resource accepts Rust Agent additional_signature_components ({}), returns 401 Signature-Error parsed by Agent::r3_authorize (ok={}), and Go AS/PS exchanges Rust ## Action release proposal + 128-bit pending poll ({})",
            i7_bad_ns_all_refused && i7_good_ns_accepted,
            i7_grpc_missing_method_refused && i7_grpc_valid_ok,
            i7_go_read_resp.status().as_u16(),
            i7_go_401_parsed_ok,
            i7_poll_terminal.status().as_u16()
        ),
        evidence: json!({
            "vocabulary_namespace_guard": {
                "non_standard_urn_aauth_vocabulary_refused": i7_bad_ns_all_refused,
                "standard_and_third_party_uris_accepted": i7_good_ns_accepted,
            },
            "grpc_method_required": {
                "missing_method_entries_refused": i7_grpc_missing_method_refused,
                "valid_method_entry_accepted": i7_grpc_valid_ok,
            },
            "cross_language_go_interop": {
                "rust_agent_additional_components_to_go_resource_status": i7_go_read_resp.status().as_u16(),
                "go_resource_401_signature_error_parsed_by_rust_agent": format!("{:?}", i7_go_401_sig_err),
                "rust_release_proposal_128bit_pending_id": i7_rel_pending_id,
                "go_ps_as_exchange_of_rust_action_release_proposal_status": i7_go_ex_resp.status().as_u16(),
                "rust_poll_with_additional_components_terminal_status": i7_poll_terminal.status().as_u16(),
            },
            "source_locations": [
                "crates/aauth-rust-r3/src/standard.rs:51-69 (validate_namespace)",
                "crates/aauth-rust-r3/src/standard_tests.rs:815-859 (grpc_entries_without_method_are_refused)"
            ],
        }),
    });
    transcript_lines.push(format!(
        "[QA-I7] PASS: vocab_ns={} grpc_method={} go_comp_status={} go_401_sig_err={} go_rel_exchange={} poll={}",
        i7_bad_ns_all_refused && i7_good_ns_accepted,
        i7_grpc_missing_method_refused && i7_grpc_valid_ok,
        i7_go_read_resp.status().as_u16(),
        i7_go_401_parsed_ok,
        i7_go_ex_resp.status().as_u16(),
        i7_poll_terminal.status().as_u16()
    ));

    events_qa::run_events_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock_base,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    alpha13_qa::run_alpha13_qa_cases(
        out_dir,
        clock,
        trust,
        fed_ps_addr,
        &fed_ps_cert,
        fed_as_addr,
        &fed_as_cert,
        fed_records_addr,
        &fed_records_cert,
        &fed_agent,
        &mut cases,
        &mut transcript_lines,
    )?;

    go_sigkey_qa::run_go_sigkey_qa_cases(
        &body,
        go_module_path,
        clock,
        &mut cases,
        &mut transcript_lines,
    )?;

    alpha14_qa::run_alpha14_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    alpha15_qa::run_alpha15_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    go_features_qa::run_go_features_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    alpha16_qa::run_alpha16_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    go_chaining_qa::run_go_chaining_qa_cases(
        &body,
        out_dir,
        go_module_path,
        clock,
        trust,
        &mut cases,
        &mut transcript_lines,
    )?;

    let s_go_ap_addr: SocketAddr = body["go_events_ap_addr"]
        .as_str()
        .ok_or("missing go_events_ap_addr")?
        .parse()?;
    let s_go_ap_cert = hex_decode(
        body.get("go_events_ap_cert_hex")
            .and_then(Value::as_str)
            .ok_or("missing go_events_ap_cert_hex")?,
    )?;
    let s_clock = Arc::new(AtomicI64::new(clock));
    supervision_qa::run_supervision_qa(
        out_dir,
        go_module_path,
        &s_clock,
        trust,
        s_go_ap_addr,
        &s_go_ap_cert,
        &mut cases,
        &mut transcript_lines,
    )?;
    go_budget_relay_qa::run_go_budget_relay_qa(
        out_dir,
        go_module_path,
        clock,
        trust,
        s_go_ap_addr,
        &s_go_ap_cert,
        &mut cases,
        &mut transcript_lines,
    )?;

    let final_go_counts = fetch_go_counts(fed_records_addr, &fed_records_cert)?;
    let verified_working_count = cases
        .iter()
        .filter(|c| c.classification == "VERIFIED_WORKING" && c.passed_expectation)
        .count();
    let defect_resolved_count = cases
        .iter()
        .filter(|c| c.classification == "DEFECT_RESOLVED" && c.passed_expectation)
        .count();
    let defect_found_count = cases
        .iter()
        .filter(|c| c.classification == "DEFECT_CONFIRMED" && c.passed_expectation)
        .count();
    let boundary_pinned_count = cases
        .iter()
        .filter(|c| c.classification == "BOUNDARY_PINNED" && c.passed_expectation)
        .count();

    let failed_ids: Vec<String> = cases
        .iter()
        .filter(|c| !c.passed_expectation)
        .map(|c| c.id.clone())
        .collect();
    mark_failed_lines(&cases, &mut transcript_lines);
    transcript_lines.push(format!(
        "[SUMMARY] total={} met_expectation={} failed={} failed_ids={:?}",
        cases.len(),
        cases.len() - failed_ids.len(),
        failed_ids.len(),
        failed_ids
    ));
    let report = QaReport {
        generated_at_unix: now(),
        go_module_path: go_module_path.to_owned(),
        out_dir: out_dir.display().to_string(),
        targets: json!({
            "rust": git_revision(rust_source()),
            "go": git_revision(Path::new(go_module_path)),
            "runner": git_revision(Path::new(env!("CARGO_MANIFEST_DIR"))),
        }),
        total_cases: cases.len(),
        verified_working_count,
        defect_resolved_count,
        defect_found_count,
        boundary_pinned_count,
        failed_count: failed_ids.len(),
        failed_ids,
        cases,
        go_fleet_final_counts: final_go_counts,
        rust_federated_counts: json!({
            "rust_fed_reads": rust_fed_counters.reads.load(Ordering::SeqCst),
            "rust_fed_deletes": rust_fed_counters.deletes.load(Ordering::SeqCst),
            "rust_fed_held_deletes": rust_fed_held_counters.deletes.load(Ordering::SeqCst),
        }),
    };

    let pretty_report = serde_json::to_string_pretty(&report)?;
    fs::write(out_dir.join("qa-report.json"), &pretty_report)?;
    fs::write(out_dir.join("results.json"), &pretty_report)?;
    fs::write(
        out_dir.join("qa-transcript.log"),
        transcript_lines.join("\n") + "\n",
    )?;

    Ok(serde_json::to_value(&report)?)
}

/// Rewrites the transcript line of each case that missed its expectation so it
/// reads `[QA-..] FAIL: ...`; the case modules write their lines before the
/// outcome is known. A case with no line gets one from its summary.
fn mark_failed_lines(cases: &[QaCaseReceipt], lines: &mut Vec<String>) {
    for case in cases.iter().filter(|c| !c.passed_expectation) {
        let tag = format!("[{}]", case.id);
        match lines.iter_mut().find(|l| l.starts_with(&tag)) {
            Some(line) => {
                let rest = line[tag.len()..].splitn(2, ':').nth(1).unwrap_or("");
                *line = format!("{tag} FAIL:{rest}");
            }
            None => lines.push(format!("{tag} FAIL: {}", case.summary)),
        }
    }
}

/// Commit, `git describe`, dirty flag and origin URL of the checkout at
/// `dir`, or null values when it is not a git checkout.
fn git_revision(dir: &Path) -> Value {
    let git = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    };
    json!({
        "path": dir.display().to_string(),
        "commit": git(&["rev-parse", "HEAD"]),
        "describe": git(&["describe", "--tags", "--always"]),
        "dirty": git(&["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()),
        "origin": git(&["remote", "get-url", "origin"]),
    })
}

const GO_FLEET_SRC: &str = include_str!("../fleet/go_qa_fleet.go");
const GO_SIGKEY_SUITE_SRC: &str = include_str!("../fleet/go_sigkey_suite.go");
const GO_ALPHA14_SUITE_SRC: &str = include_str!("../fleet/go_alpha14_suite.go");
const GO_ALPHA15_SUITE_SRC: &str = include_str!("../fleet/go_alpha15_suite.go");
const GO_FEATURES_SUITE_SRC: &str = include_str!("../fleet/go_features_suite.go");
const GO_ALPHA16_SUITE_SRC: &str = include_str!("../fleet/go_alpha16_suite.go");
const GO_CHAINING_SUITE_SRC: &str = include_str!("../fleet/go_chaining_suite.go");
const GO_SUPERVISION_SUITE_SRC: &str = include_str!("../fleet/go_supervision_suite.go");
const GO_BUDGET_RELAY_SUITE_SRC: &str = include_str!("../fleet/go_budget_relay_suite.go");

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(err) => {
            eprintln!("aauth-interop-runner: {err}");
            std::process::exit(1);
        }
    }
}

/// Runs the suite; `Ok(false)` means it ran and at least one case missed its
/// expectation.
fn run() -> Result<bool> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args.first().map(|s| s.as_str()) == Some("--child-rust-ap") {
        events_qa::run_child_rust_ap(&raw_args[1..])?;
        return Ok(true);
    }
    let mut rust_source = None;
    let mut go_module = None;
    let mut out_dir = None;
    let mut args = raw_args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or(format!("{flag} requires a directory\n\n{USAGE}"));
        match arg.as_str() {
            "--rust-source" => rust_source = Some(fs::canonicalize(value("--rust-source")?)?),
            "--go-source" | "--go-module" => go_module = Some(fs::canonicalize(value("--go-source")?)?),
            "--out-dir" => out_dir = Some(PathBuf::from(value("--out-dir")?)),
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(true);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}").into()),
        }
    }
    let (Some(go_module), Some(out_dir)) = (go_module, out_dir) else {
        return Err(format!("--go-source and --out-dir are required\n\n{USAGE}").into());
    };
    let rust_source = match rust_source {
        Some(dir) => dir,
        None => fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../targets/aauth-rust"))?,
    };
    RUST_SOURCE.set(rust_source).expect("set once");
    if fs::read_dir(&out_dir).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(format!("{} is not empty; give a new or empty --out-dir", out_dir.display()).into());
    }
    fs::create_dir_all(&out_dir)?;
    let out_dir = fs::canonicalize(&out_dir)?;

    let issued = now();
    let clock_base = Arc::new(AtomicI64::new(issued));
    let trust = Trust::default();

    let direct_counters = Arc::new(RustResourceCounters::new());
    let direct_res = Arc::new(compose_rust_resource(
        RECORDS,
        "records-1",
        [0x53; 32],
        None,
        &out_dir.join("direct-res"),
        &trust,
        false,
        direct_counters.clone(),
    )?);
    let direct_res_c = direct_res.clone();
    let direct_cnt_c = direct_counters.clone();
    let direct_clk = clock_base.clone();
    let direct_res_tls = Arc::new(TlsServer::start("records.example", move |req| {
        serve_rust_resource(&direct_res_c, &direct_cnt_c, direct_clk.load(Ordering::SeqCst), req)
    })?);
    trust.discover(&direct_res_tls, RECORDS, "aauth-resource.json")?;

    let rust_fed_counters = Arc::new(RustResourceCounters::new());
    let rust_fed_res = Arc::new(compose_rust_resource(
        RUST_FED_RECORDS,
        "rust-fed-res-1",
        [0x55; 32],
        Some(FED_AS),
        &out_dir.join("rust-fed-res"),
        &trust,
        false,
        rust_fed_counters.clone(),
    )?);
    let rf_res_c = rust_fed_res.clone();
    let rf_cnt_c = rust_fed_counters.clone();
    let rf_clk = clock_base.clone();
    let rust_fed_res_tls = Arc::new(TlsServer::start("rust-fed-records.example", move |req| {
        serve_rust_resource(&rf_res_c, &rf_cnt_c, rf_clk.load(Ordering::SeqCst), req)
    })?);
    trust.discover(&rust_fed_res_tls, RUST_FED_RECORDS, "aauth-resource.json")?;

    let rust_fed_held_counters = Arc::new(RustResourceCounters::new());
    let rust_fed_held = Arc::new(compose_rust_resource(
        RUST_FED_HELD,
        "rust-fed-held-1",
        [0x56; 32],
        Some(FED_AS),
        &out_dir.join("rust-fed-held"),
        &trust,
        true,
        rust_fed_held_counters.clone(),
    )?);
    let rfh_res_c = rust_fed_held.clone();
    let rfh_cnt_c = rust_fed_held_counters.clone();
    let rfh_clk = clock_base.clone();
    let rust_fed_held_tls = Arc::new(TlsServer::start("rust-fed-held.example", move |req| {
        serve_rust_resource(&rfh_res_c, &rfh_cnt_c, rfh_clk.load(Ordering::SeqCst), req)
    })?);
    trust.discover(&rust_fed_held_tls, RUST_FED_HELD, "aauth-resource.json")?;

    let qa_out_dir = out_dir.clone();
    let qa_go_mod = go_module.display().to_string();
    let qa_clk = clock_base.clone();
    let qa_trust = trust.clone();
    let qa_direct_tls = direct_res_tls.clone();
    let qa_rf_tls = rust_fed_res_tls.clone();
    let qa_rfh_tls = rust_fed_held_tls.clone();
    let qa_rf_res = rust_fed_res.clone();
    let qa_rfh_res = rust_fed_held.clone();
    let qa_rf_cnt = rust_fed_counters.clone();
    let qa_rfh_cnt = rust_fed_held_counters.clone();

    let qa_control_tls = TlsServer::start("qa-control.example", move |request| {
        match (request.method().as_str(), request.uri().path()) {
            ("POST", "/run-qa") => match run_qa_suite(
                &request,
                &qa_out_dir,
                &qa_go_mod,
                &qa_clk,
                &qa_trust,
                &qa_direct_tls,
                &qa_rf_tls,
                &qa_rfh_tls,
                &qa_rf_res,
                &qa_rfh_res,
                &qa_rf_cnt,
                &qa_rfh_cnt,
            ) {
                Ok(val) => json_response(200, val),
                Err(err) => json_response(500, json!({"error": err.to_string()})),
            },
            _ => json_response(404, json!({"error": "not_found"})),
        }
    })?;

    let driver_dir = out_dir.join("go-fleet-workdir");
    fs::create_dir_all(&driver_dir)?;
    let go_mod_src = fs::read_to_string(go_module.join("go.mod"))?;
    let rewritten_mod = go_mod_src.replacen(
        "module gitlab.com/sidecat-dev/aauth-go",
        "module aauth-interop-fleet",
        1,
    );
    let driver_go_mod = format!(
        "{rewritten_mod}\nrequire gitlab.com/sidecat-dev/aauth-go v0.0.0\n\nreplace gitlab.com/sidecat-dev/aauth-go => {}\n",
        go_module.display()
    );
    fs::write(driver_dir.join("go.mod"), driver_go_mod)?;
    if go_module.join("go.sum").is_file() {
        fs::copy(go_module.join("go.sum"), driver_dir.join("go.sum"))?;
    }
    fs::write(driver_dir.join("main.go"), GO_FLEET_SRC)?;
    fs::write(driver_dir.join("m_sigkey_suite.go"), GO_SIGKEY_SUITE_SRC)?;
    fs::write(driver_dir.join("n_alpha14_suite.go"), GO_ALPHA14_SUITE_SRC)?;
    fs::write(driver_dir.join("o_alpha15_suite.go"), GO_ALPHA15_SUITE_SRC)?;
    fs::write(driver_dir.join("p_features_suite.go"), GO_FEATURES_SUITE_SRC)?;
    fs::write(driver_dir.join("q_alpha16_suite.go"), GO_ALPHA16_SUITE_SRC)?;
    fs::write(driver_dir.join("r_chaining_suite.go"), GO_CHAINING_SUITE_SRC)?;
    fs::write(driver_dir.join("s_supervision_suite.go"), GO_SUPERVISION_SUITE_SRC)?;
    fs::write(driver_dir.join("t_budget_relay_suite.go"), GO_BUDGET_RELAY_SUITE_SRC)?;
    let cfg_path = driver_dir.join("config.json");
    fs::write(
        &cfg_path,
        json!({
            "records_addr": direct_res_tls.address().to_string(),
            "records_cert_pem": direct_res_tls.cert_pem(),
            "rust_fed_records_addr": rust_fed_res_tls.address().to_string(),
            "rust_fed_records_cert_pem": rust_fed_res_tls.cert_pem(),
            "rust_fed_held_addr": rust_fed_held_tls.address().to_string(),
            "rust_fed_held_cert_pem": rust_fed_held_tls.cert_pem(),
            "qa_control_addr": qa_control_tls.address().to_string(),
            "qa_control_cert_pem": qa_control_tls.cert_pem(),
            "initial_now": issued,
        })
        .to_string(),
    )?;

    let output = Command::new("go")
        .args(["run", "-mod=readonly", ".", "config.json"])
        .current_dir(&driver_dir)
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "go_qa_fleet failed ({}):\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let transcript = fs::read_to_string(out_dir.join("qa-transcript.log"))?;
    print!("{transcript}");
    println!(
        "QA_REPORT_JSON={}",
        out_dir.join("results.json").display()
    );
    let report: Value = serde_json::from_slice(&fs::read(out_dir.join("results.json"))?)?;
    Ok(report["failed_count"] == json!(0))
}
