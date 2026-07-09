//! Token validation and box-to-runner routing against the Hosted API.
//!
//! Endpoints mirror the legacy Go gateway (`apps/ssh-gateway/main.go`, via
//! the generated `apps/api-client-go` client):
//!
//! - `GET /box/ssh-access/validate?token=<token>` →
//!   `{"valid": bool, "boxId": string, "unixUser"?: string, "tokenId"?: string}`
//! - `GET /runners/by-box/{boxId}` → `{"id": string, "domain"?: string, ...}`
//!
//! Both carry `Authorization: Bearer <service credential>`. Every failure
//! path rejects (fail closed); nothing here ever logs a full token.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST};
use hyper::Request;
use serde::Deserialize;
use tracing::{info, warn};

use crate::http::{parse_http_base, percent_encode, read_json_body, send_request, HttpBase};
use crate::redact::redact_token;

/// Stage-1 invariant: sessions run as root inside the guest; any other unix
/// user from the Hosted API is a contract violation and is rejected.
const STAGE1_UNIX_USER: &str = "root";

/// Where an authenticated session must be routed.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub box_id: String,
    /// `http://<runner domain>` — the domain exactly as the runners API
    /// returned it (including any port it carries).
    pub runner_base_url: String,
    pub unix_user: String,
    pub token_id: String,
}

/// Typed fail-closed reason. `reason()` labels the
/// `ssh_gateway_route_failures_total` metric; `user_message()` is the only
/// text that may reach an SSH client and never leaks paths, ports, or
/// transport internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// `BOXLITE_SSH_TARGET` is `off`.
    FeatureDisabled,
    /// Token invalid, or the validation response violated the contract
    /// (empty boxId, missing/blank unixUser or tokenId, non-root unixUser).
    TokenInvalid,
    /// Hosted API unreachable, timed out, or returned an error status.
    HostedApiUnavailable,
    /// Runner lookup succeeded but yielded no usable domain.
    RunnerResolutionFailed,
    /// Runner reports a transport other than the expected one.
    RunnerNotCapable,
    /// Runner is not ready or degraded; `reason` is a sanitized code.
    RunnerNotReady { reason: String },
    /// Runner answered 409 BOX_STOPPED on the stream open.
    BoxStopped,
    /// Runner answered 404 (box unknown to that runner).
    UnknownBox,
    /// Runner answered 401 (internal service token rejected).
    RunnerRejectedAuth,
    /// Runner answered 403 (unix user rejected).
    RunnerRejectedUser,
    /// Runner answered 400 or broke the upgrade handshake.
    RunnerRejectedUpgrade,
    /// Runner unreachable (connect failure/timeout) or unexpected status.
    RunnerUnavailable,
}

impl RouteError {
    /// Stable metric label for `ssh_gateway_route_failures_total{reason}`.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::FeatureDisabled => "feature_disabled",
            Self::TokenInvalid => "token_invalid",
            Self::HostedApiUnavailable => "hosted_api_unavailable",
            Self::RunnerResolutionFailed => "runner_resolution_failed",
            Self::RunnerNotCapable => "runner_not_capable",
            Self::RunnerNotReady { .. } => "runner_not_ready",
            Self::BoxStopped => "box_stopped",
            Self::UnknownBox => "unknown_box",
            Self::RunnerRejectedAuth => "runner_auth_rejected",
            Self::RunnerRejectedUser => "runner_user_rejected",
            Self::RunnerRejectedUpgrade => "runner_upgrade_rejected",
            Self::RunnerUnavailable => "runner_unavailable",
        }
    }

    /// Message shown to the SSH client. Must never contain paths, host
    /// names, port numbers, or transport names; reason codes are sanitized
    /// to letters, `_`, and `-` before interpolation.
    pub fn user_message(&self) -> String {
        match self {
            Self::FeatureDisabled => "SSH access is not enabled in this environment".into(),
            Self::TokenInvalid => "access denied".into(),
            Self::HostedApiUnavailable => {
                "temporary control plane error, please try again later".into()
            }
            Self::RunnerResolutionFailed => "the box location could not be resolved".into(),
            Self::RunnerNotCapable | Self::RunnerNotReady { .. } => {
                let reason = match self {
                    Self::RunnerNotReady { reason } => sanitize_reason_code(reason),
                    _ => "TRANSPORT_UNSUPPORTED".into(),
                };
                format!("the box is not ready for SSH (reason: {reason})")
            }
            Self::BoxStopped => "the box is stopped; start it before connecting".into(),
            Self::UnknownBox => "box not found".into(),
            Self::RunnerRejectedAuth | Self::RunnerRejectedUser | Self::RunnerRejectedUpgrade => {
                "internal routing error".into()
            }
            Self::RunnerUnavailable => "the box host is unreachable, please try again later".into(),
        }
    }
}

/// `Display` shows the metric reason (safe everywhere, including logs).
impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for RouteError {}

/// Longest reason code we relay verbatim; anything bigger is not a code.
const MAX_REASON_CODE_LEN: usize = 64;

/// Reduces a runner-provided reason to the expected SCREAMING_SNAKE code
/// shape (uppercase letters, `_`, `-`) so interpolated strings cannot leak
/// addresses, ports, paths, or transport names. Anything that does not look
/// like a code collapses to `UNKNOWN`.
pub(crate) fn sanitize_reason_code(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_uppercase() || *c == '_' || *c == '-')
        .collect();
    if cleaned.is_empty()
        || cleaned.len() > MAX_REASON_CODE_LEN
        || cleaned.to_ascii_lowercase().contains("vsock")
    {
        "UNKNOWN".into()
    } else {
        cleaned
    }
}

/// Hosted API failure detail. Never contains the token or request URL.
#[derive(Debug)]
pub struct HostedApiError {
    pub operation: &'static str,
    pub message: String,
}

impl fmt::Display for HostedApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.operation, self.message)
    }
}

impl std::error::Error for HostedApiError {}

/// Response of `GET /box/ssh-access/validate`.
#[derive(Debug, Clone, Deserialize)]
pub struct SshAccessValidation {
    pub valid: bool,
    #[serde(rename = "boxId", default)]
    pub box_id: String,
    #[serde(rename = "unixUser", default)]
    pub unix_user: Option<String>,
    #[serde(rename = "tokenId", default)]
    pub token_id: Option<String>,
}

/// Response of `GET /runners/by-box/{boxId}` (fields we consume).
#[derive(Debug, Clone, Deserialize)]
pub struct RunnerRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub domain: Option<String>,
}

/// Boxed future so `HostedApi` stays object-safe (`Arc<dyn HostedApi>`).
pub type ApiFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HostedApiError>> + Send + 'a>>;

/// Seam over the Hosted API so the validator is testable without sockets.
pub trait HostedApi: Send + Sync {
    fn validate_ssh_access<'a>(&'a self, token: &'a str) -> ApiFuture<'a, SshAccessValidation>;
    fn runner_by_box<'a>(&'a self, box_id: &'a str) -> ApiFuture<'a, RunnerRecord>;
}

/// Production [`HostedApi`] over plain HTTP/1.1.
pub struct HttpHostedApi {
    base: HttpBase,
    bearer: String,
    timeout: Duration,
}

impl fmt::Debug for HttpHostedApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpHostedApi")
            .field("base", &self.base)
            .field("bearer", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl HttpHostedApi {
    pub fn new(base_url: &str, api_token: &str, timeout: Duration) -> Result<Self, String> {
        Ok(Self {
            base: parse_http_base(base_url)?,
            bearer: format!("Bearer {api_token}"),
            timeout,
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        operation: &'static str,
        path_and_query: String,
    ) -> Result<T, HostedApiError> {
        let request = Request::get(path_and_query)
            .header(HOST, &self.base.authority)
            .header(AUTHORIZATION, &self.bearer)
            .header(ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|e| HostedApiError {
                operation,
                message: format!("cannot build request: {e}"),
            })?;
        let response = send_request(&self.base, request, self.timeout)
            .await
            .map_err(|e| HostedApiError {
                operation,
                message: e.to_string(),
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(HostedApiError {
                operation,
                message: format!("unexpected status {status}"),
            });
        }
        read_json_body(response, self.timeout)
            .await
            .map_err(|e| HostedApiError {
                operation,
                message: e.to_string(),
            })
    }
}

impl HostedApi for HttpHostedApi {
    fn validate_ssh_access<'a>(&'a self, token: &'a str) -> ApiFuture<'a, SshAccessValidation> {
        Box::pin(async move {
            let path = format!("/box/ssh-access/validate?token={}", percent_encode(token));
            self.get_json("validate ssh access", path).await
        })
    }

    fn runner_by_box<'a>(&'a self, box_id: &'a str) -> ApiFuture<'a, RunnerRecord> {
        Box::pin(async move {
            let path = format!("/runners/by-box/{}", percent_encode(box_id));
            self.get_json("resolve runner by box", path).await
        })
    }
}

/// Validates SSH tokens and resolves the owning Runner. Fail closed: any
/// error, missing field, or contract violation rejects the session.
pub struct TokenValidator {
    api: Arc<dyn HostedApi>,
    runner_scheme: String,
}

impl fmt::Debug for TokenValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenValidator")
            .field("runner_scheme", &self.runner_scheme)
            .finish_non_exhaustive()
    }
}

impl TokenValidator {
    pub fn new(api: Arc<dyn HostedApi>, runner_scheme: impl Into<String>) -> Self {
        Self {
            api,
            runner_scheme: runner_scheme.into(),
        }
    }

    /// Validates `token` and resolves the routing target.
    pub async fn validate(&self, token: &str) -> Result<RoutingDecision, RouteError> {
        let redacted = redact_token(token);
        if token.is_empty() {
            warn!(token = %redacted, "token rejected: empty");
            return Err(RouteError::TokenInvalid);
        }

        let validation = self.api.validate_ssh_access(token).await.map_err(|e| {
            warn!(token = %redacted, error = %e, "token validation call failed");
            RouteError::HostedApiUnavailable
        })?;
        if !validation.valid {
            warn!(token = %redacted, "token rejected: not valid");
            return Err(RouteError::TokenInvalid);
        }
        if validation.box_id.is_empty() {
            warn!(token = %redacted, "token rejected: validation carried an empty boxId");
            return Err(RouteError::TokenInvalid);
        }
        let Some(unix_user) = validation.unix_user.filter(|u| !u.is_empty()) else {
            warn!(token = %redacted, "token rejected: validation carried no unixUser");
            return Err(RouteError::TokenInvalid);
        };
        if unix_user != STAGE1_UNIX_USER {
            warn!(
                token = %redacted,
                unix_user = %unix_user,
                "token rejected: Stage 1 allows only the root unix user"
            );
            return Err(RouteError::TokenInvalid);
        }
        // tokenId is required downstream (X-BoxLite-Token-ID header and audit
        // correlation); a valid=true response without it is fail-closed too.
        let Some(token_id) = validation.token_id.filter(|t| !t.is_empty()) else {
            warn!(token = %redacted, "token rejected: validation carried no tokenId");
            return Err(RouteError::TokenInvalid);
        };

        let runner = self
            .api
            .runner_by_box(&validation.box_id)
            .await
            .map_err(|e| {
                warn!(
                    token = %redacted,
                    box_id = %validation.box_id,
                    error = %e,
                    "runner resolution call failed"
                );
                RouteError::HostedApiUnavailable
            })?;
        let Some(domain) = runner.domain.filter(|d| !d.is_empty()) else {
            warn!(
                token = %redacted,
                box_id = %validation.box_id,
                runner_id = %runner.id,
                "runner resolution rejected: runner has no domain"
            );
            return Err(RouteError::RunnerResolutionFailed);
        };

        info!(
            token = %redacted,
            token_id = %token_id,
            box_id = %validation.box_id,
            runner_id = %runner.id,
            runner_domain = %domain,
            "token validated and routed"
        );
        Ok(RoutingDecision {
            box_id: validation.box_id,
            runner_base_url: format!("{}://{}", self.runner_scheme, domain),
            unix_user,
            token_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No user-facing message may leak internals: no path separators, no
    /// digits (ports/CIDs), no transport names.
    #[test]
    fn user_messages_leak_nothing() {
        let errors = [
            RouteError::FeatureDisabled,
            RouteError::TokenInvalid,
            RouteError::HostedApiUnavailable,
            RouteError::RunnerResolutionFailed,
            RouteError::RunnerNotCapable,
            RouteError::RunnerNotReady {
                reason: "BOX_NOT_READY".into(),
            },
            RouteError::RunnerNotReady {
                // Hostile reason: must be sanitized before interpolation.
                reason: "/run/boxlite/vsock:2220 cid=42".into(),
            },
            RouteError::BoxStopped,
            RouteError::UnknownBox,
            RouteError::RunnerRejectedAuth,
            RouteError::RunnerRejectedUser,
            RouteError::RunnerRejectedUpgrade,
            RouteError::RunnerUnavailable,
        ];
        for error in errors {
            let message = error.user_message();
            assert!(!message.is_empty(), "{error:?}");
            assert!(!message.contains('/'), "path leak in {message:?}");
            assert!(!message.contains('\\'), "path leak in {message:?}");
            assert!(
                !message.chars().any(|c| c.is_ascii_digit()),
                "digit (port/CID) leak in {message:?}"
            );
            assert!(
                !message.to_lowercase().contains("vsock"),
                "transport leak in {message:?}"
            );
        }
    }

    #[test]
    fn every_route_error_has_a_stable_reason_label() {
        let labels = [
            RouteError::FeatureDisabled.reason(),
            RouteError::TokenInvalid.reason(),
            RouteError::HostedApiUnavailable.reason(),
            RouteError::RunnerResolutionFailed.reason(),
            RouteError::RunnerNotCapable.reason(),
            RouteError::RunnerNotReady { reason: "X".into() }.reason(),
            RouteError::BoxStopped.reason(),
            RouteError::UnknownBox.reason(),
            RouteError::RunnerRejectedAuth.reason(),
            RouteError::RunnerRejectedUser.reason(),
            RouteError::RunnerRejectedUpgrade.reason(),
            RouteError::RunnerUnavailable.reason(),
        ];
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be distinct");
        for label in labels {
            assert!(
                label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "label {label:?} must be snake_case"
            );
        }
    }

    #[test]
    fn http_hosted_api_debug_never_contains_the_service_token() {
        let api = HttpHostedApi::new(
            "http://api.internal:3000",
            "hosted-secret-value",
            Duration::from_secs(5),
        )
        .expect("valid base url");
        let formatted = format!("{api:?}");
        assert!(!formatted.contains("hosted-secret-value"), "{formatted}");
        assert!(formatted.contains("<redacted>"), "{formatted}");
    }

    #[test]
    fn sanitize_reason_code_strips_everything_but_code_chars() {
        assert_eq!(sanitize_reason_code("BOX_NOT_READY"), "BOX_NOT_READY");
        assert_eq!(sanitize_reason_code("cid=3 port:2220"), "UNKNOWN");
        assert_eq!(sanitize_reason_code("123/456"), "UNKNOWN");
        assert_eq!(sanitize_reason_code(""), "UNKNOWN");
        assert_eq!(sanitize_reason_code("VSOCK_DOWN"), "UNKNOWN");
        assert_eq!(sanitize_reason_code(&"A".repeat(65)), "UNKNOWN");
    }
}
