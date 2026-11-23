//! Deliver a role-issued revocation over an already registered fixture route.

use aauth_rust_core::CallOutcome;
use aauth_rust_core::revocation::{RevocationSender, RevocationTarget, read_call_outcome};
use aauth_rust_signature_key::{KeyMaterial, sign_request};
use http::{Request, Response};
use serde_json::json;

pub(crate) fn send_revocation(
    sender: &RevocationSender<'_>,
    target: &RevocationTarget<'_>,
    clock: i64,
    send: impl FnOnce(&Request<Vec<u8>>) -> crate::Result<Response<Vec<u8>>>,
) -> CallOutcome {
    let result = (|| -> crate::Result<CallOutcome> {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("{}/revoke", target.recipient))
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"jti": target.jti, "exp": target.exp}))?)?;
        sign_request(
            &mut request,
            sender.key,
            KeyMaterial::JwksUri {
                id: sender.issuer.to_owned(),
                dwk: sender.dwk.to_owned(),
                kid: sender.kid.to_owned(),
            },
            clock,
        )?;
        let response = send(&request)?;
        Ok(read_call_outcome(response.status().as_u16(), response.body()))
    })();
    result.unwrap_or(CallOutcome::Unavailable)
}
