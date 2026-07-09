//! Internal HTTP client for Runner endpoints:
//!
//! - `GET /v1/boxes/{boxId}/ssh-status` — capability/readiness probe.
//! - `POST /internal/ssh/sessions/{boxId}/stream` — HTTP/1.1 upgrade to the
//!   `boxlite-session-stream` frame protocol.
//!
//! Pre-upgrade failures are typed HTTP statuses with a small JSON body; they
//! map 1:1 onto [`RouteError`] variants so the SSH side can fail closed with
//! a stable reason code.

use std::fmt;
use std::time::Duration;

use boxlite_session_frame::{
    HEADER_SESSION_ID, HEADER_TOKEN_ID, HEADER_UNIX_USER, UPGRADE_PROTOCOL,
};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::header::{ACCEPT, AUTHORIZATION, CONNECTION, HOST, UPGRADE};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::http::{
    parse_http_base, percent_encode, read_body_bytes, read_json_body, send_request, HttpBase,
    HttpCallError,
};
use crate::token::{sanitize_reason_code, RouteError};

/// Transport value `ssh-status` must report for the russh-vsock path.
const EXPECTED_TRANSPORT: &str = "boxlite-runtime-vsock";

/// Response of `GET /v1/boxes/{boxId}/ssh-status`.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SshStatus {
    pub ready: bool,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub degraded: bool,
    #[serde(default)]
    pub degraded_reason: String,
}

/// Identity headers stamped on the upgrade request; all values were
/// validated by the Hosted API before reaching this point.
#[derive(Debug, Clone)]
pub(crate) struct SessionIdentity {
    pub session_id: String,
    pub token_id: String,
    pub unix_user: String,
}

/// HTTP client for one Runner (base URL comes per-call from the
/// [`crate::token::RoutingDecision`]).
#[derive(Clone)]
pub(crate) struct RunnerClient {
    bearer: String,
    timeout: Duration,
}

impl fmt::Debug for RunnerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunnerClient")
            .field("bearer", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl RunnerClient {
    pub(crate) fn new(service_token: &str, timeout: Duration) -> Self {
        Self {
            bearer: format!("Bearer {service_token}"),
            timeout,
        }
    }

    /// Probes readiness and transport capability; fails closed on anything
    /// but a ready, non-degraded, vsock-transport answer.
    pub(crate) async fn check_ssh_ready(
        &self,
        runner_base_url: &str,
        box_id: &str,
    ) -> Result<(), RouteError> {
        let base = parse_base(runner_base_url)?;
        let path = format!("/v1/boxes/{}/ssh-status", percent_encode(box_id));
        let request = Request::get(path)
            .header(HOST, &base.authority)
            .header(AUTHORIZATION, &self.bearer)
            .header(ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|e| {
                warn!(error = %e, "cannot build ssh-status request");
                RouteError::RunnerUnavailable
            })?;
        let response = send_request(&base, request, self.timeout)
            .await
            .map_err(|e| map_transport_error("ssh-status", e))?;

        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(RouteError::UnknownBox),
            StatusCode::UNAUTHORIZED => return Err(RouteError::RunnerRejectedAuth),
            status => {
                warn!(status = %status, "unexpected ssh-status response");
                return Err(RouteError::RunnerUnavailable);
            }
        }
        let status: SshStatus = read_json_body(response, self.timeout).await.map_err(|e| {
            warn!(error = %e, "unparseable ssh-status body");
            RouteError::RunnerUnavailable
        })?;

        if status.transport != EXPECTED_TRANSPORT {
            warn!(transport = %status.transport, "runner transport is not routable");
            return Err(RouteError::RunnerNotCapable);
        }
        if !status.ready || status.degraded {
            let reason = if status.degraded_reason.is_empty() {
                "NOT_READY".to_string()
            } else {
                sanitize_reason_code(&status.degraded_reason)
            };
            warn!(
                ready = status.ready,
                degraded = status.degraded,
                reason = %reason,
                "runner is not ready for SSH"
            );
            return Err(RouteError::RunnerNotReady { reason });
        }
        Ok(())
    }

    /// Opens the HTTP-upgraded session stream and returns the raw upgraded
    /// byte stream on `101 Switching Protocols`.
    pub(crate) async fn open_session_stream(
        &self,
        runner_base_url: &str,
        box_id: &str,
        identity: &SessionIdentity,
    ) -> Result<TokioIo<Upgraded>, RouteError> {
        let base = parse_base(runner_base_url)?;
        let path = format!("/internal/ssh/sessions/{}/stream", percent_encode(box_id));
        let request = Request::post(path)
            .header(HOST, &base.authority)
            .header(AUTHORIZATION, &self.bearer)
            .header(UPGRADE, UPGRADE_PROTOCOL)
            .header(CONNECTION, "Upgrade")
            .header(HEADER_SESSION_ID, &identity.session_id)
            .header(HEADER_TOKEN_ID, &identity.token_id)
            .header(HEADER_UNIX_USER, &identity.unix_user)
            .body(Empty::<Bytes>::new())
            .map_err(|e| {
                warn!(error = %e, "cannot build session stream request");
                RouteError::RunnerUnavailable
            })?;
        let response = send_request(&base, request, self.timeout)
            .await
            .map_err(|e| map_transport_error("session stream open", e))?;

        let status = response.status();
        if status != StatusCode::SWITCHING_PROTOCOLS {
            return Err(self.map_pre_upgrade_failure(status, response).await);
        }
        let upgraded = hyper::upgrade::on(response).await.map_err(|e| {
            warn!(error = %e, "upgrade completion failed after 101");
            RouteError::RunnerRejectedUpgrade
        })?;
        Ok(TokioIo::new(upgraded))
    }

    async fn map_pre_upgrade_failure(
        &self,
        status: StatusCode,
        response: Response<hyper::body::Incoming>,
    ) -> RouteError {
        let reason = read_error_reason(response, self.timeout).await;
        warn!(status = %status, reason = %reason, "runner rejected the session stream");
        match status {
            StatusCode::BAD_REQUEST => RouteError::RunnerRejectedUpgrade,
            StatusCode::UNAUTHORIZED => RouteError::RunnerRejectedAuth,
            StatusCode::FORBIDDEN => RouteError::RunnerRejectedUser,
            StatusCode::NOT_FOUND => RouteError::UnknownBox,
            StatusCode::CONFLICT => RouteError::BoxStopped,
            StatusCode::SERVICE_UNAVAILABLE => RouteError::RunnerNotReady { reason },
            _ => RouteError::RunnerUnavailable,
        }
    }
}

fn parse_base(runner_base_url: &str) -> Result<HttpBase, RouteError> {
    parse_http_base(runner_base_url).map_err(|e| {
        warn!(error = %e, "invalid runner base URL");
        RouteError::RunnerResolutionFailed
    })
}

fn map_transport_error(operation: &str, error: HttpCallError) -> RouteError {
    warn!(operation = operation, error = %error, "runner call failed");
    RouteError::RunnerUnavailable
}

/// Extracts the typed reason code from a small JSON error body, tolerating
/// the few key spellings in use (`code`, `reason`, `error`).
async fn read_error_reason(response: Response<hyper::body::Incoming>, timeout: Duration) -> String {
    let Ok(bytes) = read_body_bytes(response, timeout).await else {
        return "UNKNOWN".into();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        debug!("runner error body is not JSON");
        return "UNKNOWN".into();
    };
    for key in ["code", "reason", "error"] {
        if let Some(reason) = value.get(key).and_then(|v| v.as_str()) {
            return sanitize_reason_code(reason);
        }
    }
    "UNKNOWN".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_client_debug_never_contains_the_service_token() {
        let client = RunnerClient::new("runner-secret-value", Duration::from_secs(5));
        let formatted = format!("{client:?}");
        assert!(!formatted.contains("runner-secret-value"), "{formatted}");
        assert!(formatted.contains("<redacted>"), "{formatted}");
    }
}
