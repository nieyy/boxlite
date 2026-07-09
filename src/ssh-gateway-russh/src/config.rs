//! Startup configuration, validated before the listener binds.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};

/// Feature gate for the new russh-based SSH path (`BOXLITE_SSH_TARGET`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SshTarget {
    /// Gateway rejects every SSH authentication attempt.
    Off,
    /// Gateway routes sessions to Runners over the session-frame stream.
    RusshVsock,
}

/// Gateway configuration, parsed from CLI flags and environment variables.
///
/// Every credential-bearing flag hides its env value in `--help` output; the
/// `Debug` impl below (not derived) redacts the token fields too, so a
/// future `debug!(?config)` can never leak them.
#[derive(Clone, Parser)]
#[command(name = "boxlite-ssh-gateway", about = "BoxLite public SSH gateway")]
pub struct GatewayConfig {
    /// TCP address the public SSH listener binds.
    #[arg(long, env = "BOXLITE_SSH_LISTEN_ADDR", default_value = "0.0.0.0:2222")]
    pub listen_addr: SocketAddr,

    /// Path of the persistent ed25519 host key. Generated once if absent and
    /// then reused forever: public clients pin this key, so it must never be
    /// ephemeral.
    #[arg(long, env = "BOXLITE_SSH_HOST_KEY_PATH")]
    pub host_key_path: PathBuf,

    /// Base URL of the Hosted API (token validation + runner resolution).
    #[arg(long, env = "BOXLITE_HOSTED_API_URL")]
    pub hosted_api_url: String,

    /// Service credential sent as `Authorization: Bearer` to the Hosted API.
    #[arg(long, env = "BOXLITE_HOSTED_API_TOKEN", hide_env_values = true)]
    pub hosted_api_token: String,

    /// Internal service token sent as `Authorization: Bearer` to Runners.
    #[arg(long, env = "BOXLITE_RUNNER_SERVICE_TOKEN", hide_env_values = true)]
    pub runner_service_token: String,

    /// Feature gate: `off` rejects all sessions, `russh-vsock` enables routing.
    #[arg(long, env = "BOXLITE_SSH_TARGET", value_enum, default_value_t = SshTarget::Off)]
    pub ssh_target: SshTarget,

    /// Timeout in seconds applied to Hosted API calls, Runner HTTP calls, and
    /// per-request frame replies.
    #[arg(long, env = "BOXLITE_SSH_REQUEST_TIMEOUT_SECS", default_value_t = 10)]
    pub request_timeout_secs: u64,

    /// URL scheme used to reach Runner-internal endpoints derived from the
    /// runner domain. Stage 1 supports plain `http` only (cluster-internal).
    #[arg(long, env = "BOXLITE_RUNNER_SCHEME", default_value = "http")]
    pub runner_scheme: String,

    /// Maximum concurrent public SSH connections. Excess connections are
    /// dropped immediately after `accept()`, before any auth work runs, so
    /// an unauthenticated flood cannot exhaust file descriptors or memory.
    #[arg(long, env = "BOXLITE_SSH_MAX_CONNECTIONS", default_value_t = 4096)]
    pub max_connections: usize,
}

impl fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("listen_addr", &self.listen_addr)
            .field("host_key_path", &self.host_key_path)
            .field("hosted_api_url", &self.hosted_api_url)
            .field("hosted_api_token", &"<redacted>")
            .field("runner_service_token", &"<redacted>")
            .field("ssh_target", &self.ssh_target)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("runner_scheme", &self.runner_scheme)
            .field("max_connections", &self.max_connections)
            .finish()
    }
}

impl GatewayConfig {
    /// Fail-fast validation of everything not already enforced by clap.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.host_key_path.as_os_str().is_empty() {
            return Err(ConfigError("host key path must not be empty".into()));
        }
        if let Some(parent) = self.host_key_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.is_dir() {
                return Err(ConfigError(format!(
                    "host key directory {} does not exist",
                    parent.display()
                )));
            }
        }
        crate::http::parse_http_base(&self.hosted_api_url)
            .map_err(|e| ConfigError(format!("invalid hosted API URL: {e}")))?;
        if self.hosted_api_token.trim().is_empty() {
            return Err(ConfigError("hosted API token must not be empty".into()));
        }
        if self.runner_service_token.trim().is_empty() {
            return Err(ConfigError("runner service token must not be empty".into()));
        }
        if self.runner_scheme != "http" {
            return Err(ConfigError(format!(
                "unsupported runner scheme {:?} (Stage 1 supports only \"http\")",
                self.runner_scheme
            )));
        }
        if self.request_timeout_secs == 0 {
            return Err(ConfigError(
                "request timeout must be at least 1 second".into(),
            ));
        }
        if self.max_connections == 0 {
            return Err(ConfigError("max connections must be at least 1".into()));
        }
        Ok(())
    }

    /// Shared timeout for outbound HTTP calls and frame request replies.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

/// Startup configuration error; the process must exit rather than serve with
/// a partial config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid gateway configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Vec<String> {
        [
            "boxlite-ssh-gateway",
            "--host-key-path",
            "/tmp/host_key",
            "--hosted-api-url",
            "http://api.internal:3000",
            "--hosted-api-token",
            "hosted-secret",
            "--runner-service-token",
            "runner-secret",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn parse(args: Vec<String>) -> Result<GatewayConfig, clap::Error> {
        GatewayConfig::try_parse_from(args)
    }

    #[test]
    fn parses_with_defaults() {
        let config = parse(base_args()).expect("valid args");
        assert_eq!(config.listen_addr.port(), 2222);
        assert_eq!(config.ssh_target, SshTarget::Off);
        assert_eq!(config.request_timeout(), Duration::from_secs(10));
        assert_eq!(config.runner_scheme, "http");
    }

    #[test]
    fn missing_host_key_path_is_a_startup_error() {
        let args: Vec<String> = base_args()
            .into_iter()
            .filter(|a| a != "--host-key-path" && a != "/tmp/host_key")
            .collect();
        assert!(parse(args).is_err(), "clap must require --host-key-path");
    }

    #[test]
    fn missing_service_tokens_are_startup_errors() {
        for flag in ["--hosted-api-token", "--runner-service-token"] {
            let mut skip_next = false;
            let args: Vec<String> = base_args()
                .into_iter()
                .filter(|a| {
                    if skip_next {
                        skip_next = false;
                        return false;
                    }
                    if a == flag {
                        skip_next = true;
                        return false;
                    }
                    true
                })
                .collect();
            assert!(parse(args).is_err(), "clap must require {flag}");
        }
    }

    #[test]
    fn empty_service_tokens_fail_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.hosted_api_token = "  ".into();
        assert!(config.validate().is_err());

        let mut config = parse(base_args()).expect("valid args");
        config.runner_service_token = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn bad_ssh_target_is_a_startup_error() {
        let mut args = base_args();
        args.extend(["--ssh-target".into(), "bogus".into()]);
        assert!(parse(args).is_err(), "unknown BOXLITE_SSH_TARGET must fail");
    }

    #[test]
    fn valid_ssh_target_values_parse() {
        for (value, expected) in [
            ("off", SshTarget::Off),
            ("russh-vsock", SshTarget::RusshVsock),
        ] {
            let mut args = base_args();
            args.extend(["--ssh-target".into(), value.into()]);
            assert_eq!(parse(args).expect("valid target").ssh_target, expected);
        }
    }

    #[test]
    fn https_hosted_api_url_fails_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.hosted_api_url = "https://api.internal".into();
        let error = config.validate().expect_err("https unsupported in Stage 1");
        assert!(error.to_string().contains("hosted API URL"));
    }

    #[test]
    fn nonexistent_host_key_directory_fails_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.host_key_path = "/definitely/not/a/dir/host_key".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn non_http_runner_scheme_fails_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.runner_scheme = "https".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_timeout_fails_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.request_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn zero_max_connections_fails_validation() {
        let mut config = parse(base_args()).expect("valid args");
        config.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn max_connections_defaults_to_a_positive_cap() {
        let config = parse(base_args()).expect("valid args");
        assert_eq!(config.max_connections, 4096);
    }

    #[test]
    fn debug_output_never_contains_the_service_tokens() {
        let config = parse(base_args()).expect("valid args");
        let formatted = format!("{config:?}");
        assert!(!formatted.contains("hosted-secret"), "{formatted}");
        assert!(!formatted.contains("runner-secret"), "{formatted}");
        assert!(formatted.contains("<redacted>"), "{formatted}");
    }
}
