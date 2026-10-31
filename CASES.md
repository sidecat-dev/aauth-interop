# Cases

127 cases in 20 groups. A group letter marks the release batch that added its cases, so a group can span several protocol areas. Ids are never reused or renumbered.

Each case records one classification when it meets its expectation:

- **verified working:** the flow works as documented.
- **defect resolved:** a defect an earlier run found is fixed; the case checks the fix.
- **boundary pinned:** a known limit, recorded on purpose; the case checks the limit is still where it was.
- **defect confirmed:** a defect reproduced. No case is in this state today.

A case that misses its expectation is a failure, whatever its classification: the transcript line reads `FAIL` and `results.json` lists the id in `failed_ids`.

Totals: 106 verified working, 15 defect resolved, 6 boundary pinned.

Sources are in `runner/src/` (Rust side) and `runner/fleet/` (Go side). Category names changed when the runner became this project; the old names, as earlier reports show them, are listed under each group.

## A. Go Federated Resource + Access Server + Federated PS + Rust Agent

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-A1 | verified working | Federated Class Document Exchange & Rust Agent Delivery Verification |
| QA-A2 | verified working | Per-Call 401 Challenge, Proposal Exchange, Completion & Exact-Token Replay (POST /records/r-1) |
| QA-A3 | verified working | Second Compact Auth Token with Same Verified Claims on Completed 401 Call Refused with 403 access_denied |
| QA-A4 | verified working | Federated Held Delivery (202 Accepted), Premature Poll Refusal (Retry-After=5), Signed GET Poll & Replay |
| QA-A5 | verified working | Go Held Pending Endpoint Rejections: POST->405 (Allow: GET), Unknown ID->410 gone, Second Compact Token->403 access_denied |

## B. Rust Federated Resource (PsAuthorizationResource::new_federated) + Go Access Server + Go Federated PS over HTTPS

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-B1 | verified working | Cross-Language Rust Federated Resource Class Exchange & Class Operation Admission over HTTPS |
| QA-B2 | verified working | Cross-Language Rust Federated Resource 401 Per-Call Challenge, Go AS Proposal Exchange, Completion, Replay & 2nd-Compact Refusal |
| QA-B3 | verified working | Cross-Language Rust Federated Held Delivery (202 Accepted, Retry-After=1), Poll, Replay & 2nd-Compact Refusal |

## C. Negative / Authority / Parameter-Binding / Composition Probes

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-C1 | verified working | DirectR3 Converse Proposal Pin (400 invalid_resource_token) |
| QA-C2 | verified working | Presenting a Person-Server Auth Token (dwk = aauth-person.json) Directly to Go & Rust Federated Resources |
| QA-C3 | verified working | Parameter Substitution (r-1 token on r-2 -> 403), Ungranted Delete (-> 403), and Federated PS ConsentProposal Denial (-> 403) |
| QA-C4 | verified working | Federated Rust Resource Mission Composition Refusal (InvalidR3Profile & 500 when added after with_r3) |

## D. Re-Verification of Earlier Federated R3 Defects

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `D. Re-Verification of Pass-1 Defects (f12b2168 / a97755ae)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-D1 | defect resolved | RESOLVED (QA-D1): Reactive R3 Challenge on Budget-Enabled Rust Resource (with_budgets + with_r3) Returns 401 Challenge Without 'budget' Claim |
| QA-D2 | defect resolved | RESOLVED (QA-D2): Rust Held Pending Endpoint (/r3/pending/{id}) Returns 405 method_not_allowed (Allow: GET) on POST and 410 gone on Unknown ID |
| QA-D3 | defect resolved | RESOLVED (QA-D3): Rust Agent Rejects aa-auth+jwt as Person Token & Rejects Cross-Access-Server Per-Call Token Delivery |

## E. Unbuilt Boundaries ('Still not this result')

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-E1 | boundary pinned | budget_consumed on R3 Class Resource Token Refused with 400 invalid_resource_token |
| QA-E2 | boundary pinned | Go Resource snapshotHeldRequest Refuses HTTP/1.1 Requests Carrying Connection: close |
| QA-E3 | boundary pinned | Held Release Reuse vs Fresh Bytes (query-runs=2 Under Same-JTI Live Token vs Cached Custody Reuse After Class Expiry) |

## F. Live Held-Grant Poll & Retry Verification

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `F. Live Held-Grant Poll Verification (635b8d80 / a97755ae)`; `F. Live Held-Grant Poll & Retry Verification (635b8d80 / 24b48dd3)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-F1 | verified working | Live Held-Grant Second Poll Stays 202 Accepted (Retry-After=1, no-store, status=pending, No AAuth-Requirement) While Grant Is Held, Then Replays 200 OK After r3_retain |
| QA-F2 | verified working | Dropping R3Grant Without r3_retain Fails Closed with 500 server_error on Subsequent Held Poll and 401 Retry Without Re-Running Handler |
| QA-F3 | verified working | Live 401 Per-Call Retry Stays 503 temporarily_unavailable (Retry-After=1, No Location, No AAuth-Requirement) While Grant Is Held, Then Replays 200 OK After r3_retain |

## G. Application 202 Header Retention

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `G. Application 202 Header-Retention Increment (81c1d29 / db8af21)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-G1 | verified working | Valid Per-Call Application 202 Retention & Replay on Both 401 Retry and 202 Held-Poll Paths Over HTTPS |
| QA-G2 | verified working | DirectoryCallStore & DirectoryDocumentStore Reopen Durability for Both Valid Application 202 and Rejected Application 202 Over HTTPS |
| QA-G3 | verified working | Adversarial Location & Retry-After 202 Matrix (25 Subcases) Stored and Replayed as 500 server_error Without Re-Running Handler |
| QA-G4 | verified working | Adversarial Cache-Control, Content-Type & Strict JSON Body 202 Matrix (21 Subcases) Stored and Replayed as 500 server_error Without Re-Running Handler |
| QA-G5 | defect resolved | RESOLVED (QA-G5a & QA-G5c): Non-Path Relative Locations (* and Bare Host) Refused as 500 server_error & BoxedR3Release 202 Responses Kept Under Pending Rule |
| QA-G6 | boundary pinned | Documented Cross-Crate Boundary (CONFORMANCE.md): Multi-Line Cache-Control Retained by Resource (Matching aauth-go) vs Refused by Rust Agent PollSession |

## H. Approved Mission Composition with Direct Class R3

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `H. Approved Mission Composition with Direct Class R3 (0.1.0-alpha.10 / 3a691c40)`; `H. Approved Mission Composition with Direct Class R3 (0.1.0-alpha.10 / 72e722e1)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-H1 | verified working | End-to-End HTTPS Composition of Approved Mission with Direct Class R3 (Proactive /authorize, Reactive 401 Challenge, DirectoryDocumentStore Reopen, PS R3 Grant, Expiry Clamping, Multi-Call Reuse) |
| QA-H2 | verified working | Resource-Side Mission Binding Enforcement (Missionless vs Mission-Bound, Cross-Mission Mismatch, Mission on Missionless Document, and Mission Against Missionless Resource) |
| QA-H3 | verified working | Person Server Mission Lifecycle, Ownership & Claim Integrity Boundaries Over HTTPS (Terminated/Revoked, Completed, Expired, Unknown, Wrong Owner, Stripped/Substituted mission_s256) |
| QA-H4 | verified working | Refused Unsupported Combinations (Missions + Per-Call Proposals, Federation / AS, Sub-Agents, and Call Chaining) |
| QA-H5 | verified working | Rust Agent Validation Boundary (Mission-Bound R3 Resource Token Outliving Person Token Refused; Equal/Shorter & Missionless Accepted) |
| QA-H6 | defect resolved | RESOLVED (QA-H6): PsAuthorizationResource Clamps Mission-Bound ResourceToken.exp to Presented Token's exp Across Proactive /authorize, Reactive 401 Challenge, and Budget Step-Up |

## I. Required MUST-Level Behavior: Scopes, Identifiers, Release, Signatures, Audit & Upstream Tokens

Sources: `runner/src/main.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `I. 0.1.0-alpha.11 Required-Row Batch (18 MUST-Level Rows / a0f1e268)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-I1 | verified working | PsAuthorizationConfig::scope_descriptions Constructor Refusals (Missing, Blank, Whitespace, Extra, Wrong-Key), Metadata Publication, Per-Call Undescribed Scope 403 Guard & Doc Audit |
| QA-I2 | verified working | OS CSPRNG 40-Bit Interaction Codes (XXXX-XXXX Crockford Base32) & 128-Bit Pending URL IDs (22-Char Base64url) Across PS, AS, Chained Interactions, R3 Held Calls & HeldInvocations::open() |
| QA-I3 | verified working | Release-Gated R3 Proposal Opens detail with `## Action` Section & `budget: true` Operation Is Never Run Before Approval |
| QA-I4 | verified working | Agent::r3_authorize Reads 401 Error from Signature-Error Header (Never Body) & Agent::with_additional_signature_components Covers Listed Components Across Calls, /authorize & Polls |
| QA-I5 | verified working | Atomic R3 Audit Entry & Token Issuance Commit (TokenRecord.r3), Fetched Document Digest Mismatch Refusal & RedbStore Reopen Durability |
| QA-I6 | verified working | Access Server Verifies Passed-Through upstream_token (Person & Auth), Clamps Grant Expiry, Relaxes Intermediary Agent PS Profile & Refuses Invalid/Expired/Revoked Upstream Tokens Before Policy |
| QA-I7 | verified working | Vocabulary Namespace Guard, gRPC Method Requirement & Live Cross-Language aauth-go HTTPS Interop (additional_signature_components, 401 Signature-Error, Release-Gated ## Action Proposal & 128-Bit CSPRNG Pending Poll) |

## J. AAuth Events (Rust & Go)

Sources: `runner/src/events_qa.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `J. AAuth Events (0.1.0-alpha.12 Rust & Go External-Consumer QA)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-J1 | verified working | Rust Events Native End-to-End, Inbox Validation Order, max_uses, Durable Store Commit Before 202 & AsyncAPI aauth_subscribe |
| QA-J2 | verified working | Go Events Native End-to-End, jti & body_s256, AP Status Codes, ConfirmationKey JWK Thumbprint Ticket Binding & ValidateAsyncAPIDocument |
| QA-J3 | verified working | Cross-Language HTTPS Events: Rust Resource -> Go Agent Provider -> Go & Rust Agents |
| QA-J4 | verified working | Cross-Language HTTPS Events: Go Resource -> Rust Agent Provider -> Rust & Go Agents |
| QA-J5 | verified working | Rust Agent Provider Process-Restart Durability on DirectoryEventStore |
| QA-J6 | boundary pinned | Wire Difference Pinning: Registration Signed JSON Body Without content-digest Refused by Both Rust and Go Resources |
| QA-J7 | verified working | Consumer Documentation Audit: USE-IN-YOUR-SERVICE.md & CONFORMANCE.md in aauth-rust and aauth-go |

## K. aauth-go Conformance Fixes

Sources: `runner/src/events_qa.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `K. aauth-go Conformance Fixes (claude/go-fails a0a84b16)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-K1 | verified working | /authorize Challenges (401 requirement=person-token) & invalid_signature on Missing Signature Header |
| QA-K2 | verified working | Four-Party Path: Expiry Recheck After Consent & PS Recording Presented Access Server |
| QA-K3 | verified working | Person-Token Interaction Code-Consume Signature (PersonTokenCodePresentation) & 3 Failed Codes Terminating Interaction |
| QA-K4 | verified working | Key Resolver Refusing Private/Loopback/Link-Local/CGNAT/NAT64 Destinations + TransportEnforcesEgress & Checked-IP Pinning |
| QA-K5 | verified working | PollAuthToken (AuthTokenPollResult) & PollR3Call (R3PollResult) Result Types, 429/503 Backoff Progression & Client.Reauthorize |
| QA-K6 | verified working | MissionBlob.Approver Removal & Cross-PS / Cross-Language Mission Data Without approver |
| QA-K7 | defect resolved | Upstream Person Token in Call Chaining Over HTTPS (Person Server POST /person & POST /token Clamping, Lineage, 6 Negative Guards + agent.Client UpstreamToken GAP-K7-AGENT-CLIENT Resolved) |
| QA-K8 | verified working | Consumer Upgrade & Documentation Audit for the 5 Breaking Changes (CONFORMANCE.md, INTERPRETATIONS.md, SECURITY.md, Go Doc Comments & USE-IN-YOUR-SERVICE.md) |

## L. aauth-rust Conformance Fixes & Upgrade Audit

Sources: `runner/src/alpha13_qa.rs`, `runner/fleet/go_qa_fleet.go`.
Earlier reports: `L. aauth-rust 0.1.0-alpha.13 Conformance & Upgrade Audit (c142d986)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-L1 | verified working | missing Signature-Key -> 401 error=invalid_signature across PS/AS/Resource/Revoke (types="urn:ietf:params:sig-error:invalid_signature"/"urn:ietf:params:sig-error:invalid_signature"/"urn:ietf:params:sig-error:invalid_signature"/"urn:ietf:params:sig-error:invalid_signature"); Problem Details type matches urn:ietf:params:sig-error:<code> across invalid_input("urn:ietf:params:sig-error:invalid_input"), invalid_key("urn:ietf:params:sig-error:invalid_key"), unsupported_scheme("urn:ietf:params:sig-error:unsupported_scheme"), unsupported_algorithm("urn:ietf:params:sig-error:unsupported_algorithm"), expired_jwt("urn:ietf:params:sig-error:expired_jwt"), invalid_jwt("urn:ietf:params:sig-error:invalid_jwt") |
| QA-L2 | verified working | upper-case emission enforced (PendingResponse/is_emitted_ok=true, emitted='MQ38-7GS0'); HTTPS /interaction/pending redeemed via lowercase+alias-folded 'mq38-7gso' (redeem=200, decide=200); parse_interaction_query('code=abcd-i1lo')->'ABCD-1110' (true) |
| QA-L3 | verified working | read_call_outcome reads error member (true); AS pending poll 202->200->410 (error="gone", other_caller=404); PS pending poll 202->200->410 (error="gone") |
| QA-L4 | verified working | expired mission enforced across all 8 PS routes: /person(403 "expired"), /token(403 "expired"), /interaction(403 "expired"), /permission(403 "expired"), /audit(403 "expired"), POST /mission/{s256} update(403 "expired") & completion(403 "expired"), GET /mission/{s256}(status="terminated", reason="expired") |
| QA-L5 | verified working | verify_x509 CRL enforcement: empty=Err(InvalidKey), valid_ok=true, revoked_serial=Err(InvalidKey), expired_crl=Err(InvalidKey), wrong_signer=Err(InvalidKey) |
| QA-L6 | verified working | AAuth-Budget sent across all budgeted responses: 200(remaining=50, cost=50, unit="MilliwattSecond", decimals=0), 403_pol(remaining=50, unit="MilliwattSecond", decimals=0), 403_r3(remaining=50, unit="MilliwattSecond", decimals=0), 405(remaining=50, unit="MilliwattSecond", decimals=0), 410(remaining=100, unit="MilliwattSecond", decimals=0), 401_exhausted(remaining=0, unit="MilliwattSecond", decimals=0), 401_race_rev(remaining=100, unit="MilliwattSecond", decimals=0), 401_prerev(remaining=100, unit="MilliwattSecond", decimals=0); expired omits budget (empty=true) |
| QA-L7 | defect resolved | /person accepts federated AS AuthToken as upstream_token (status=200, chained_pt_len=552); rejects unrecorded(400 Some("invalid_upstream_token")), wrong_aud(400 Some("invalid_upstream_token")), expired(400 Some("expired_upstream_token")), revoked_parent_pt(400 Some("revoked_upstream_token"), FINDING-L7-1 resolved in 1687c5a), and revoked_binding(400 Some("revoked_upstream_token")) |
| QA-L8 | verified working | cross-language parity between aauth-rust 0.1.0-alpha.13 (c142d986) and aauth-go 34c5d55: missing Signature-Key -> 401 error=invalid_signature with type='urn:ietf:params:sig-error:invalid_signature' across Go PS("urn:ietf:params:sig-error:invalid_signature"), Go AS("urn:ietf:params:sig-error:invalid_signature"), Go Resource("urn:ietf:params:sig-error:invalid_signature"); 5 breaking API changes + 3 doc observations recorded |

## M. Signature-Key Schemes & Cross-Language Interop

Sources: `runner/src/go_sigkey_qa.rs`, `runner/fleet/go_sigkey_suite.go`.
Earlier reports: `M. aauth-go Signature-Key Additions & Cross-Language Interop (ae5c025a / claude/go-sigkey)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-M1 | verified working | hwk Multi-Algorithm (Ed25519, ES256, ES384, RS256, PS256), VerifyOptions.AcceptedAlgorithms Negotiation, Unknown hwk Parameters Ignored, & Bidirectional Rust <-> Go HTTPS Interop |
| QA-M2 | verified working | Direct jwks Scheme (scheme=jwks) Over Real HTTPS (HTTPKeyResolver, StaticJWKSResolver, VerifyJWKS, KeyCache), Exact Byte-for-Byte URL Identity, Same-KID Refresh Floor, & Bidirectional Rust <-> Go HTTPS Interop |
| QA-M3 | verified working | x509 Scheme Over Real HTTPS (VerifyX509 / verify_x509), Verify Refusal Guard, Chain & CRL Enforcement (Ed25519, ES256, ES384, Revoked Leaf, Expired/Missing CRL, RSA Leaf -> unsupported_algorithm), & Bidirectional Rust <-> Go Interop |
| QA-M4 | defect resolved | Bidirectional x509 RSA-Signed Chain & CRL Parity (Resolved in 0.1.0-alpha.15 / 3335414): RSA-Signed Root/Intermediate CA + RSA-Signed CRL Issuing EC (ES256) or Ed25519 Leaf Accepted by Both aauth-go VerifyX509 and aauth-rust verify_x509 |
| QA-M5 | verified working | cached Scheme & AssertionCache Lifecycle (Direct Verify Refusal, Sealed Unpredictable Identifiers, Fleet vs Standalone Resolution, cache_miss vs expired_jwt vs invalid_signature, >24h & self-jwt Guards, SelectScheme) |
| QA-M6 | verified working | Bidirectional Cross-Language cached Scheme, Signature-Key-Cache, cache_miss, & CachingCredential Recovery Over Real HTTPS |
| QA-M7 | verified working | Multiple Signatures (SignRequests / sign_requests) Covering Complete Signature-Key Dictionary, unsupported_scheme Precedence Over Malformed Scheme Parameters, & Bidirectional Rust <-> Go HTTPS Interop |
| QA-M8 | verified working | Documentation, Conformance & Public API Audit (CONFORMANCE.md, INTERPRETATIONS.md, SPEC-FEEDBACK.md, USE-IN-YOUR-SERVICE.md) + Native go test ./jose/... ./signaturekey/... Suite |

## N. Rust Metadata, Capabilities, Missions, Budgets & Interaction, with Cross-Language Interop

Sources: `runner/src/alpha14_qa.rs`, `runner/fleet/go_alpha14_suite.go`.
Earlier reports: `N. aauth-rust 0.1.0-alpha.14 New Features & Cross-Language Interop (68dbfc10 + aauth-go 671a88f2)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-N1 | defect resolved | FINDING-L7-1 resolved over HTTPS: federated AS AuthToken presented as upstream_token to POST /person returns 200 before revocation, 400 (Some("revoked_upstream_token")) after revoke_person_token(pt_jti), and 400 (Some("revoked_upstream_token")) after POST /revoke on outer AgentToken |
| QA-N2 | verified working | MetadataDisplay with_display across all 5 Rust role types + HTTPS enforcement on all 5 URI members (roundtrip=true, discovery_rejects_http=true, rust_parses_go=true, go_rejects_rust_http=true) |
| QA-N3 | verified working | AAuth-Capabilities read/write + interaction raised only when declared across Rust & Go over HTTPS (rust_to_go_no_cap=403, rust_to_go_with_int=202, go_to_rust_ok=true) |
| QA-N4 | verified working | AgentIdentityResource::with_further_schemes & Decision::OtherScheme over HTTPS across Rust & Go (jwt=200, hwk=200, cached=200, go_to_rust_ok=true, unlisted_accept_scheme=String("jwt, hwk, jwks_uri, cached")) |
| QA-N5 | verified working | Agent::missions observe/is_active/may_present/post_audit/with_missions over HTTPS: revoked=(Some("revoked")), expired=(Some("expired")), may_present_bound=false, post_audit_after_terminate=Err(MissionTerminated) |
| QA-N6 | verified working | Store::replace_binding with binding generations (MemoryStore + RedbStore contract passed, gen=1, stale PT -> 400 Some("revoked_presented_token"), stale AT upstream -> 400 Some("revoked_upstream_token"), enrolls_agent=[true, false, false]) |
| QA-N7 | verified working | Budgets usage_request & read_usage over HTTPS: Rust PS->Rust Res all_time=Some(500000) (sig_ver=true), Rust PS->Go Res all_time=Some(750000), Rust AS->Go Res all_time=Some(450000), negative_guards=true |
| QA-N8 | verified working | R3Definitions & Display::merged over HTTPS: guards=true, merge_rules=true, proactive_status=200, composed_summary=String("Read customer records; Delete customer records"), deduplicated_data_accessed=String("customer_profile; audit_log") |
| QA-N9 | verified working | 3-party resource-initiated interaction over HTTPS: authorize_with_interaction -> 202 /token/interaction/{id} -> redirect_to_resource -> /connect -> resource_interaction_callback -> decide_resource_interaction -> 200 auth_token (410 2nd poll) + all 5 callback error mappings + 3-wrong-codes 410 + egress 500 verified |
| QA-N10 | verified working | Consumer documentation audit: CONFORMANCE.md covers all 15 features (true), USE-IN-YOUR-SERVICE.md covers all new entry points (true), and prior DOC-OBS-L8-1..L8-3 + DOC-OBS-M8-1 are resolved (true) |

## O. Rust Signing Keys, Call Chaining & X.509, with Cross-Language Interop

Sources: `runner/src/alpha15_qa.rs`, `runner/fleet/go_alpha15_suite.go`.
Earlier reports: `O. aauth-rust 0.1.0-alpha.15 New Features & Cross-Language Interop (1f59a069 + aauth-go 671a88f2)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-O1 | verified working | KeyMaterial::Jwt { jwt, cache } & SigningKey::sign -> Vec<u8> (len=64) verified: missing jti/exp rejected with InvalidJwt, `;cache` emitted, and cached cid round-tripped over HTTPS on Rust (cid=4HPCptn_nHiQyz7KPQJ3h_NeedNAvMo60yQ3tZncbGquF-xR85f9f7UZ3qqKfwDZxz08ld6lkp3ARFPuPJi4TXzyYKGXagCoZLfJTVvd7rHbuCwhwTUxrEbinkVQ2Z9NbvSuagsPAe9gWSRQ1M-n6KUioaw91uel_3o_BAtXNLwLCUnIkpyaD42_P8ezXoDQte3pZP2q5antvYxBdwR3akrFT7UIbT5uCOPMtGcjyVicNxcgivN4u6JIx8eaVLBkphwtMLud2ubsI1zQJ2P_skTfP5C589RtfVV94GkQJDSDBWKfFcse8uMLCRU2A9nF8bBhAIRQJ7IoeHT-vFl6BbO7OuQVTHrTEys) and Go (cid=AapOrmA_AmU-RI9RBT1gDMifE4GLQ1f78bwJ6HSgXB_bAqaa__HUI9kwq3Q8_vym3Sbpr6HbW2gOesl_GlaWQ7jrQg0is1MOH8ykDOWhR1T8ZlF_ihabocpQ8DjbPUmSAdJntIVQAbI06dB2pNBy7DFTD4df7j98YfwJPEcfc_UnUYpS6_XGXDcO7epevHD3R4xBrkc4yWDWkx6EnI48mhf-tQJXC5nWLX_WU4Cq9AgoIQRkbwQ79WXHkCovsGGeRBBWNA-tjMG2bjywla_-pJgvoaHytGCG9ifLr8CUWhMSqXeYrpL0Umu0P-meh12BY-qeJTx6MabUFx4PLs5hD9LPecFgtXCh-8EZc7f0yMxdwapn6b8DMw_cCn0RHKoGyFcRcKfM-a4O3QPMfEGja149gtZeb4uiy0ywHhHT7w, closing API-OBS-M8-2) |
| QA-O2 | verified working | 4-party call chaining over HTTPS verified across PersonToken, PS AuthToken, and AS AuthToken upstreams (true: PersonToken(omit=400/Some("invalid_upstream_token"),sent=true,rec=true[up=true,prin=aauth:caller@o-rust-ap.example],res2=200); PS_AuthToken(omit=400/Some("invalid_upstream_token"),sent=true,rec=true[up=true,prin=aauth:caller@o-rust-ap.example],res2=200); AS_AuthToken(omit=400/Some("invalid_upstream_token"),sent=true,rec=true[up=true,prin=aauth:caller@o-rust-ap.example],res2=200)); Policy::consent_upstream default-deny 403 (true); step-up (true); deferred 202 + ChainedInteraction + ps:None polling (true); MemoryStore/RedbStore contracts (true); 3-party mission chaining & termination 403 (true) |
| QA-O3 | defect resolved | Multi-hop 4-party chain revocation + AS step-up descendant revocation (FINDING-O3-1 resolved in 1f59a06) over HTTPS verified: 3-hop PS->AS1->Interm1->PS->AS1(step-up)->Interm2->PS->AS2->Res3 cascade (true: rev=200,h2_step=200->401(as1_ledger=400/revoked_presented_token),h3=200->401,ps=[("https://o-rust-interm1.example", "o-ps-jti-7", 1793482147), ("https://o-rust-as.example", "o-ps-jti-7", 1793482147), ("https://o-rust-interm2.example", "o-ps-jti-8", 1793480947), ("https://o-rust-as.example", "o-ps-jti-8", 1793480947), ("https://o-rust-res3.example", "o-ps-jti-9", 1793480947), ("https://o-rust-as2.example", "o-ps-jti-9", 1793480947)],as1=[("https://o-rust-interm1.example", "o-as1-jti-7", 1793480947), ("https://o-rust-interm2.example", "o-as1-jti-8", 1793480947), ("https://o-rust-interm2.example", "o-as1-jti-9", 1793480947)],as2=[("https://o-rust-res3.example", "o-as2-jti-1", 1793480947)]); AgentToken revocation across AS1 & AS2 naming PersonToken JTIs (true); pending 202 revoked mid-wait -> 403 revoked then 410 Gone at PS (true) & AS (true) |
| QA-O4 | verified working | SigningKey::from_pkcs8_der multi-algorithm signing & Rust+Go HTTPS verification passed [Ed25519(len=64,go=200), ES256(len=64,go=200), ES384(len=96,go=200), RS256(len=256,go=200), PS256(len=256,go=200)] (closing API-OBS-M8-3); negative guards (HS256 -> UnsupportedAlgorithm, corrupt DER/curve mismatch/1024-bit RSA -> InvalidKey)=true |
| QA-O5 | verified working | RSA-signed X.509 chains & CRLs verified in aauth-rust & cross-language with Go (closing QA-M4): RSA-SHA256/384/512 CAs=true, 2048-bit RSA CA Rust=true & Go HTTP=200, revoked serial -> Some(InvalidKey), expired CRL -> Some(InvalidKey), tampered CRL -> Some(InvalidKey), 1024-bit RSA CA -> Some(InvalidKey) |
| QA-O6 | boundary pinned | Cross-language call chaining verified & Go 4-party/mission chaining boundaries pinned over HTTPS: working flows [4-party Rust PS->Rust AS->Go Res=true, 3-party mission Rust PS->Go Res=true, 3-party Go PS->Rust Res=true]; pinned Go boundaries [B1a unconfigured Go Fed PS upstream=400, B1b Go Direct PS AS-aud challenge=400 invalid_resource_token, B2 Go Direct PS AS-issued upstream=400, B3 Rust PS->Go AS (iss!=aud)=400 invalid_upstream_token TerminalError (true), B4 Go Direct PS mission upstream=500, all_go_boundaries=true] |
| QA-O7 | verified working | Consumer documentation audit passed: Cargo.toml version=0.1.0-alpha.15, CONFORMANCE.md ('Added later on 2026-10-30' + AS step-up revocation in 1f59a06) and USE-IN-YOUR-SERVICE.md accurately document KeyMaterial::Jwt { jwt, cache }, SigningKey::from_pkcs8_der (Ed25519/ES256/ES384/RS256/PS256), RSA X.509/CRL verification, 4-party chaining (consent_upstream, upstream_token, ChainedInteraction::open), and multi-hop revocation |

## P. Go Interaction, Links, Delayed Requests, Revocation, R3, Budgets & Events, with Cross-Language Interop

Sources: `runner/src/go_features_qa.rs`, `runner/fleet/go_features_suite.go`.
Earlier reports: `P. aauth-go claude/go-features Batch (d0369c7a) & Cross-Language Interop with aauth-rust 0.1.0-alpha.15 (1f59a069)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-P1 | verified working | 3-party resource-initiated interaction over HTTPS: Go->Go happy path=true, early consent & forged callback guards=true, 5 callback error mappings=true, 3-wrong-codes 410=true, egress refusal 500=true, withdrawal 403=true, Rust Agent->Go Res->Go PS=true, Go Agent->Rust Res->Go PS=true, Go Agent->Go Res->Rust PS=true |
| QA-P2 | verified working | Interaction chaining & callbacks over HTTPS: Go->Go happy path=true, undeclared cap 403=true, wrong code & 2nd visit refused=true, wrong poller 403=true, 5 callback error mappings=true, FailChainedInteraction (denied/revoked)=true, Rust Agent->Go ChainedInteraction Resource=true |
| QA-P3 | verified working | aauth-resource link relation over HTTPS: Go->Go & Go->Rust ResolveResourceLink (HTTP Link & HTML <link>)=true, Rust->Go links_from_header/links_from_html/metadata_matches_link=true, negative target guards=true, >8KiB Link & >1MiB HTML caps=true, issuer_missing/issuer_mismatch=true |
| QA-P4 | verified working | Delayed signed requests (VerifyOptions.MaxDelay=24h, ValidAt) & ReplayCache verified: online 60s refusal=true, delayed ValidAt==created & token validity at created=true, >MaxDelay & expired window & future created refused=true, ReplayCache first=nil / replay=invalid_signature / post-expiry=nil / full=ErrReplayCacheFull=true |
| QA-P5 | verified working | Multi-recipient revocation, Prefer: wait cascades, 429 rate_limited + Retry-After & Agent token eviction over HTTPS: Prefer: wait cascade across all recipients=true, upstream revoked at AS (revoked_upstream_token)=true, Resource multi-recipient revocation=true, 429 rate_limited + Retry-After & pending retention=true, Agent stops presenting refused token=true |
| QA-P6 | verified working | R3 ComposeDefinitions, MergeDisplays & release-gated ProposalResult over HTTPS: ComposeDefinitions/MergeDisplays=true, duplicate/conflict guards=true, composed R3 document over HTTPS=true, release-gated runs once (ProposalResult.Executed==true, 0 re-executions on release)=true, metered/budget:true never runs before approval=true |
| QA-P7 | verified working | Budgets held refusals, replays & signed usage answers over HTTPS: 4-party held refusal reserves 0=true, rechallenge at same Location=true, replay without double-metering=true, Go PostUsageChecked->Go & ->Rust signed usage=true, Rust read_usage/verify_usage_signature->Go signed usage=true |
| QA-P8 | verified working | Events inbox reader (agentprovider.EventInboxReader) over HTTPS: Go->Go exact byte preservation + tamper/misroute guards + AcknowledgeEvent + ErrEventInboxNotReadable=true, apstoretest.RunEventInboxSuite=true, Rust Resource->Go EventInbox->Go EventInboxReader->Rust verify_event=true |
| QA-P9 | verified working | FurtherSchemesConfig over HTTPS: Accept-Signature-Scheme/Alg ordering=true, Go hwk(ES256)/jwks/x509/jkt-jwt;cache/cached->FurtherSchemes.Protected=true, AAuth jwt->Protected=true, /authorize & /revoke reject non-AAuth schemes=true, Rust SigningKey (ES256 hwk + jkt-jwt;cache + cached)->Go FurtherSchemes=true |
| QA-P10 | defect resolved | Cross-language 4-party call chaining matrix & updated QA-O6 boundaries over HTTPS: All-Go 4-party (FederatedCallChainingConfig + AS upstream_token)=true, Go PS->Rust AS->Rust/Go Res=true, Rust PS->Go AS (PersonToken & AS-issued AuthToken when iss==aud)=true, remaining Go boundaries pinned [B2 Go PS AS-issued upstream=400 (true), B3-subagent iss!=aud=400 (true), B4 Go PS mission upstream=500 (true)] |
| QA-P11 | defect resolved | aauth-go (main 445af350) consumer documentation audit passed: CONFORMANCE.md 'Features added on 2026-10-30' covers all 10 features (true), USE-IN-YOUR-SERVICE.md provides accurate copy-pasteable guides for all 10 entry points (true), INTERPRETATIONS.md covers new interpretations (true), and all 3 prior non-blocking doc observations (DOC-OBS-P11-1..3) are resolved in 445af350 (true) |

## Q. Four-Party Missions & Metered R3 Release, with Cross-Language Interop

Sources: `runner/src/alpha16_qa.rs`, `runner/fleet/go_alpha16_suite.go`.
Earlier reports: `Q. aauth-rust 0.1.0-alpha.16 Four-Party Missions, Metered R3 Release & Cross-Language Interop (9961b6cc + aauth-go 445af350)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-Q1 | verified working | Breaking API migration (R3Release::cost & MissionStore::commit_mission_token) & store contracts verified: MemoryStore & RedbStore check_store_contract + check_persistence_contract=true, commit_mission_token federated receipt (person_server=Some, AS clock iat>at)=true, direct future iat refused=true, outliving mission.expires_at refused=true, R3Release::cost Some(42)/None=true |
| QA-Q2 | verified working | 4-party missions end-to-end over HTTPS verified: Resource with_mission_context challenge & AuthToken admission=true, happy path PS->AS->Resource with federated receipt retention=true, PS refuses AS AuthToken with wrong mission_s256/outliving exp (502 as_unreachable)=true, termination before AS (403)=true, while AS decides (403)=true, while PS/AS 202 waits (403 then 410 Gone)=true |
| QA-Q3 | verified working | 4-party mission call chaining & caller PersonToken chain revocation over HTTPS verified: 3-hop 4-party chain preserves mission_s256 & exp<=mission.expires_at across all hops=true, mid-chain mission termination refuses further /person & /token hops with 403 mission_terminated=true, caller PersonToken revocation cascades across PS & AS so all 3 hops transition 200 OK -> 401 Unauthorized & further chaining returns 400 revoked_upstream_token=true |
| QA-Q4 | verified working | Cross-language 4-party missions (Rust <-> Go main 445af350) over HTTPS verified: Go Fed PS -> Rust AS & Go AS (Rust & Go Resources)=true/true/true/true, Rust Fed PS -> Go AS top-level (Go & Rust Resources)=true/true, Rust Fed PS -> Go AS chained mission=true, mixed-deployment boundaries (Go PS B4/B2/both=true, Go AS defer=502/500=true, Go PS defer=500=true) |
| QA-Q5 | verified working | Metered release of held R3 result (`with_release_metering`, `R3Release::cost`) & cross-language wire check verified: config guards=true, proposal offers cost as budget=true, unfunded 403=true, short budget 403+AAuth-Budget (`required=250`) & stays held=true, 3-party PS narrows budget & release charges once (`200 OK` + `AAuth-Budget`) & replay not charged again=true, unmetered release beside it=true, Rust Fed PS refuses proposal+budget with 400=true, Go Direct PS/Fed PS/Resource refuse per-call budget wire (true/true/true) |
| QA-Q6 | defect resolved | Consumer documentation audit passed for aauth-rust 0.1.0-alpha.16 (9961b6cc) & aauth-go main (445af350): Cargo.toml/README/PACKAGE-README version=0.1.0-alpha.16 (true), CONFORMANCE.md 'Added on 2026-10-31' covers 4-party missions, metered R3 release & breaking API changes (true), USE-IN-YOUR-SERVICE.md documents with_mission_context/commit_mission_token/with_release_metering/R3Release::cost (true), DOC-OBS-O7-1 resolved in aauth-rust (true), and DOC-OBS-P11-1..3 resolved in aauth-go main (true) |

## R. Go Call Chaining, Polling & Hosted-Page Callbacks

Sources: `runner/src/go_chaining_qa.rs`, `runner/fleet/go_chaining_suite.go`.
Earlier reports: `R. Go Chaining & Polling Batch (aauth-go 8a3734dd + aauth-rust v0.1.0-alpha.16)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-R1 | verified working | Breaking API Changes Migration & Store Contracts: FederatedAuthorizationConfig.IssuedTokens Required When CallChaining!=nil, SessionCodePresentation, Removed Interim Errors, and Storetest Contracts |
| QA-R2 | verified working | All-Go 4-Party Call Chaining Over Real HTTPS: 3 Hops on Real Exchanges, Step-Up Receipt Tie, Missions Carried & 30m AS Lifetime, Chained Waits (Approved & Revoked), Root PersonToken & AgentToken Revocation Cascades |
| QA-R3 | verified working | Cross-Language 4-Party Call Chaining & Chain Revocation (aauth-go 8a3734dd <-> aauth-rust v0.1.0-alpha.16) Over Real HTTPS + Mixed-Deployment Boundary Pinning |
| QA-R4 | verified working | Shared agent.Pending[T] Polling Across All Deferred Agent Flows Over Real HTTPS (PollTooEarlyError, 429 +5s, 503 Retry-After, Prefer: wait=30, Interacting, Clarification, Cancel, ErrPendingFinished) |
| QA-R5 | verified working | Hosted-Page Callbacks Over Real HTTPS: ConsumeAuthorizationInteractionVisit, ConsumePersonTokenInteractionVisit, ConsumeSessionInteractionVisit, *CallbackURL, and RedirectToResourceInteraction |
| QA-R6 | defect resolved | Updated QA-P10 (B2, B3-subagent, B4) & QA-Q4 Boundary Re-Verification + Full 112-Case Regression |
| QA-R7 | verified working | Consumer Documentation Sufficiency Audit: CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md, and JOURNEYS.md on aauth-go 8a3734dd |

## S. Supervision (Rust, Go & Cross-Language)

Sources: `runner/src/supervision_qa.rs`, `runner/fleet/go_supervision_suite.go`.
Earlier reports: `S. Alpha.17 Rust & Go Supervision Batch (aauth-rust 10cacbf7 + aauth-go 2fb24239)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-S1 | verified working | Rust Supervision: Four Draft Use Cases Over Real HTTPS (standing + ask + always remembered, multi-SS routing, SS down -> fallback -> outbox replay in order, offline decision verification & mutation rejection) |
| QA-S2 | verified working | Rust Supervision: Answer Types, Missions, Four-Party, Recovery & Signature-Key ;req Response Signatures Over Real HTTPS |
| QA-S3 | verified working | Go Supervision: Four Draft Use Cases & Store Conformance Over Real HTTPS (testutil.NewSupervisionStore, testutil.NewSupervisorStore, standing + ask + always remembered, multi-SS routing, SS down -> fallback -> outbox replay in order, offline VerifyExchange/VerifyDecision & mutation rejection) |
| QA-S4 | verified working | Go Supervision: Answer Types, Missions, Four-Party & Recovery Over Real HTTPS (allow/narrow/deny/ask/SS-202/clarification with updated_request, missions, 4-party allow/narrow-refused/DeferredCompositionError, routing replay & 404 unknown_sub/unknown_mission recovery) |
| QA-S5 | verified working | Cross-Language Supervision Direction 1 (Go Person Server <-> Rust Supervision Server) Over Real HTTPS (all 4 use cases, all answer types, missions, 4-party, recovery, and cross-language offline decision verification in both Go and Rust) |
| QA-S6 | verified working | Cross-Language Supervision Direction 2 (Rust Person Server <-> Go Supervision Server) Over Real HTTPS (all 4 use cases, all answer types + updated_request clarification relay, missions, 4-party allow/ask+AS-202/narrow-refused, recovery, and cross-language offline verification in both Rust and Go) |
| QA-S7 | verified working | Full 120-Case Regression (QA-A1..QA-R7 + QA-S1..QA-S8) across Rust v0.1.0-alpha.17 (10cacbf7) and Go 2fb24239 |
| QA-S8 | verified working | Consumer Documentation Sufficiency Audit: CONFORMANCE.md & USE-IN-YOUR-SERVICE.md on aauth-rust 10cacbf7 and CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md & JOURNEYS.md on aauth-go 2fb24239 |

## T. Access Server Interaction Relay, Chained Budgets & Metered Release

Sources: `runner/src/go_budget_relay_qa.rs`, `runner/fleet/go_budget_relay_suite.go`.
Earlier reports: `T. Go Budget-Relay Batch (aauth-go 9b14543d + aauth-rust v0.1.0-alpha.17)`.

| Id | Classification | Title |
| --- | --- | --- |
| QA-T1 | verified working | All-Go Access Server Interaction Relayed to Top-Level and Chained Agents Over Real HTTPS (First Answer, Later Advance, Code Immutability, 403 user_unreachable + DELETE Withdrawal, Mission Capability Inheritance & 502 Malformed Code) |
| QA-T2 | verified working | All-Go Three-Hop Four-Party Chained Budget Over Real HTTPS (Independent Per-Hop Ceiling & Grant, Upstream Token Unconsumed, Over-Budget 403, UpstreamToken Without AuthToken Guard & AS Ceiling Violation 502) |
| QA-T3 | verified working | All-Go Four-Party Metered Release of Held R3 Results Over Real HTTPS (Proposal ResourceToken Offer, ParseReferencedArtifact Result Member, Declined/Unbudgeted/Short 403 Preserving Held Result, Single-Charge Release & Zero-Charge Replay) |
| QA-T4 | verified working | Cross-Language Interoperability Over Real HTTPS: Relayed AS Interaction (Go/Rust Agents & AS), Bidirectional 4-Party Budgeted Chaining, and Bidirectional Metered R3 Release (End-to-End & Architectural 3-Party/4-Party Boundaries) |
| QA-T5 | defect resolved | Re-Check of OBS-S6-1: supervision.Clarification.Validate Whole-Second Timeout Enforcement (1ns, 500ms, 1.5s, -1s Refused) & TestClarificationTimeoutIsWholeSeconds Verification |
| QA-T6 | verified working | Updated QA-R3 Boundary & Full 127-Case Regression (QA-A1..QA-S8 + QA-T1..QA-T7) across aauth-go 9b14543d and aauth-rust v0.1.0-alpha.17 (10cacbf7) |
| QA-T7 | verified working | Consumer Documentation Sufficiency Audit: CONFORMANCE.md, USE-IN-YOUR-SERVICE.md, INTERPRETATIONS.md & JOURNEYS.md on aauth-go 9b14543d |
