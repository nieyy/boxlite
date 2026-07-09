//! BoxLite public SSH gateway.
//!
//! Terminates public SSH with russh, treats the SSH username as an opaque
//! access token, validates it against the Hosted API, resolves the box's
//! Runner, opens an HTTP-upgraded `boxlite-session-stream` connection to
//! that Runner, and translates SSH channel events into BoxLite session
//! frames (and Runner frames back into SSH responses).
//!
//! The user-facing contract is frozen: `ssh -p 2222 <token>@ssh.dev.boxlite.ai`.
//!
//! Public entry points: [`GatewayConfig`] (startup configuration),
//! [`Gateway`] (listener + per-connection SSH handler), plus the
//! [`token`]/[`metrics`]/[`redact`] modules used by integration tests.

pub mod config;
mod frames;
mod http;
pub mod metrics;
pub mod redact;
mod runner;
mod server;
pub mod token;

pub use config::{ConfigError, GatewayConfig, SshTarget};
pub use server::{Gateway, GatewayError};
