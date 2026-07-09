//! The public SSH server: russh handler translating SSH channel events into
//! session frames and Runner frames back into SSH responses.
//!
//! # Security model
//!
//! The SSH username is an opaque access token. `none` authentication is
//! accepted only after the Hosted API validated the token (fail closed on
//! every error); password and publickey attempts are rejected and steered to
//! `none`. The full token never reaches a log line — every log site goes
//! through [`redact_token`].
//!
//! # Runner stream lifecycle
//!
//! One session-frame stream per SSH connection, opened lazily on the first
//! `channel_open_session` (so a connection that authenticates but never opens
//! a channel costs the Runner nothing). All channels of the connection
//! multiplex over that stream by nonzero gateway-chosen `channel_id`.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use boxlite_session_frame::{
    ErrorPayload, ExitStatusPayload, Frame, FrameType, OpenExecPayload, PtyRequestPayload,
    PtyResizePayload, ReplyPayload, MAX_PAYLOAD,
};
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Config as SshConfig, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Disconnect, MethodKind, MethodSet, Pty};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::{ConfigError, GatewayConfig, SshTarget};
use crate::frames::FrameMux;
use crate::metrics::Metrics;
use crate::redact::redact_token;
use crate::runner::{RunnerClient, SessionIdentity};
use crate::token::{HostedApi, HttpHostedApi, RouteError, RoutingDecision, TokenValidator};

/// Caps SSH channels per connection: `channel_open_session` spawns a
/// forwarder task and registers a frame-mux entry per channel, so an
/// unbounded client with one valid token could otherwise multiply tasks and
/// queues against a single Runner. `connection_limit` only caps concurrent
/// connections, not channels within one.
const MAX_CHANNELS_PER_CONNECTION: usize = 64;

/// Startup failure; the process must exit instead of serving.
#[derive(Debug)]
pub enum GatewayError {
    Config(ConfigError),
    HostKey(String),
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::HostKey(e) => write!(f, "host key error: {e}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<ConfigError> for GatewayError {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

/// The public SSH gateway: owns the russh config (persistent host key), the
/// token validator, the runner client, and the metric registry.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<GatewayInner>,
}

struct GatewayInner {
    ssh_config: Arc<SshConfig>,
    validator: TokenValidator,
    runner_client: RunnerClient,
    ssh_target: SshTarget,
    request_timeout: Duration,
    metrics: Arc<Metrics>,
    /// Caps concurrent TCP connections so an unauthenticated flood cannot
    /// exhaust file descriptors or memory before any auth check runs.
    connection_limit: Arc<Semaphore>,
}

impl fmt::Debug for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gateway").finish_non_exhaustive()
    }
}

impl Gateway {
    /// Builds the gateway with the production Hosted API HTTP client.
    pub async fn new(config: GatewayConfig) -> Result<Self, GatewayError> {
        config.validate()?;
        let api = HttpHostedApi::new(
            &config.hosted_api_url,
            &config.hosted_api_token,
            config.request_timeout(),
        )
        .map_err(|e| {
            GatewayError::Config(ConfigError::new(format!("invalid hosted API URL: {e}")))
        })?;
        Self::with_hosted_api(config, Arc::new(api)).await
    }

    /// Builds the gateway over any [`HostedApi`] implementation (the seam
    /// integration tests use).
    pub async fn with_hosted_api(
        config: GatewayConfig,
        api: Arc<dyn HostedApi>,
    ) -> Result<Self, GatewayError> {
        config.validate()?;
        let host_key = load_or_generate_host_key(&config.host_key_path).await?;

        let mut methods = MethodSet::empty();
        methods.push(MethodKind::None);
        let ssh_config = SshConfig {
            methods,
            keys: vec![host_key],
            // The initial `none` attempt IS the real token authentication;
            // no local secret comparison happens, so instant rejection leaks
            // no timing signal beyond the Hosted API round-trip itself.
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..SshConfig::default()
        };

        Ok(Self {
            inner: Arc::new(GatewayInner {
                ssh_config: Arc::new(ssh_config),
                validator: TokenValidator::new(api, config.runner_scheme.clone()),
                runner_client: RunnerClient::new(
                    &config.runner_service_token,
                    config.request_timeout(),
                ),
                ssh_target: config.ssh_target,
                request_timeout: config.request_timeout(),
                metrics: Arc::new(Metrics::default()),
                connection_limit: Arc::new(Semaphore::new(config.max_connections)),
            }),
        })
    }

    /// The shared metric registry.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Serves one SSH connection over any bidirectional stream until the
    /// client disconnects.
    pub async fn serve_stream<S>(&self, stream: S) -> Result<(), russh::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.inner.metrics.record_connection();
        let session_id = format!("{:032x}", rand::random::<u128>());
        info!(session = %session_id, "SSH connection accepted");
        let handler = GatewayConnection::new(Arc::clone(&self.inner), session_id.clone());
        let session =
            russh::server::run_stream(Arc::clone(&self.inner.ssh_config), stream, handler).await?;
        let result = session.await;
        match &result {
            Ok(()) => info!(session = %session_id, "SSH connection closed"),
            Err(e) => info!(session = %session_id, error = %e, "SSH connection closed with error"),
        }
        result
    }

    /// Accept loop; runs until the listener fails. Graceful shutdown is the
    /// caller's `select!` against a signal future (see `main.rs`).
    ///
    /// Every accepted connection holds one permit from `connection_limit`
    /// for its whole lifetime; once the cap is reached, new connections are
    /// dropped immediately after `accept()`, before any auth work runs.
    pub async fn run(&self, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let Ok(permit) = Arc::clone(&self.inner.connection_limit).try_acquire_owned() else {
                debug!(peer = %peer, "connection limit reached; dropping connection");
                self.inner.metrics.record_route_failure("connection_limit");
                continue;
            };
            let _ = stream.set_nodelay(true);
            debug!(peer = %peer, "TCP connection accepted");
            let gateway = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = gateway.serve_stream(stream).await {
                    debug!(error = %e, "connection task ended with error");
                }
            });
        }
    }
}

/// Loads the persistent host key, generating it exactly once if absent.
/// Never ephemeral: public clients pin this key across restarts.
async fn load_or_generate_host_key(path: &Path) -> Result<PrivateKey, GatewayError> {
    match tokio::fs::try_exists(path).await {
        Ok(true) => {
            let key = russh::keys::load_secret_key(path, None)
                .map_err(|e| GatewayError::HostKey(format!("load {}: {e}", path.display())))?;
            info!(
                path = %path.display(),
                fingerprint = %key.public_key().fingerprint(Default::default()),
                "loaded persistent host key"
            );
            Ok(key)
        }
        Ok(false) => {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .map_err(|e| GatewayError::HostKey(format!("generate: {e}")))?;
            let pem = key
                .to_openssh(LineEnding::LF)
                .map_err(|e| GatewayError::HostKey(format!("encode: {e}")))?;
            tokio::fs::write(path, pem.as_bytes())
                .await
                .map_err(|e| GatewayError::HostKey(format!("write {}: {e}", path.display())))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .await
                    .map_err(|e| GatewayError::HostKey(format!("chmod {}: {e}", path.display())))?;
            }
            info!(
                path = %path.display(),
                fingerprint = %key.public_key().fingerprint(Default::default()),
                "generated persistent host key"
            );
            Ok(key)
        }
        Err(e) => Err(GatewayError::HostKey(format!(
            "stat {}: {e}",
            path.display()
        ))),
    }
}

/// Whether a channel's OPEN_SHELL/OPEN_EXEC has been acknowledged by the
/// Runner; STDIN/EOF are gated on `Ready` per the protocol ordering rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenState {
    Pending,
    Ready,
    Failed,
}

struct ChannelBinding {
    frame_channel: u32,
    /// Present once shell/exec was requested (exactly one OPEN per channel).
    open_state: Option<watch::Receiver<OpenState>>,
    /// Kept alive so russh does not treat the server side as gone; all
    /// writes go through the session [`russh::server::Handle`] instead.
    _write_half: russh::ChannelWriteHalf<Msg>,
}

/// Per-connection handler.
struct GatewayConnection {
    gateway: Arc<GatewayInner>,
    session_id: String,
    routing: Option<Arc<RoutingDecision>>,
    mux: Option<Arc<FrameMux>>,
    channels: HashMap<ChannelId, ChannelBinding>,
    next_frame_channel: u32,
}

impl GatewayConnection {
    fn new(gateway: Arc<GatewayInner>, session_id: String) -> Self {
        Self {
            gateway,
            session_id,
            routing: None,
            mux: None,
            channels: HashMap::new(),
            // Channel 0 is reserved for connection-level control.
            next_frame_channel: 1,
        }
    }

    fn reject_other_method(&self, method: &str, user: &str) -> Auth {
        debug!(
            session = %self.session_id,
            token = %redact_token(user),
            method = method,
            "rejected auth method; steering client to none"
        );
        Auth::Reject {
            proceed_with_methods: Some(MethodSet::from(&[MethodKind::None][..])),
            partial_success: false,
        }
    }

    fn fail_closed(&self, error: &RouteError) {
        self.gateway.metrics.record_route_failure(error.reason());
        warn!(
            session = %self.session_id,
            reason = error.reason(),
            "fail closed"
        );
    }

    /// Opens the runner session stream once per connection (lazily, on the
    /// first channel open).
    async fn ensure_mux(&mut self) -> Result<Arc<FrameMux>, RouteError> {
        if let Some(mux) = &self.mux {
            return Ok(Arc::clone(mux));
        }
        let routing = Arc::clone(self.routing.as_ref().ok_or(RouteError::TokenInvalid)?);

        self.gateway
            .runner_client
            .check_ssh_ready(&routing.runner_base_url, &routing.box_id)
            .await?;

        let identity = SessionIdentity {
            session_id: self.session_id.clone(),
            token_id: routing.token_id.clone(),
            unix_user: routing.unix_user.clone(),
        };
        let upgraded = self
            .gateway
            .runner_client
            .open_session_stream(&routing.runner_base_url, &routing.box_id, &identity)
            .await?;
        info!(
            session = %self.session_id,
            box_id = %routing.box_id,
            "runner session stream opened"
        );
        let mux = FrameMux::spawn(upgraded);
        self.mux = Some(Arc::clone(&mux));
        Ok(mux)
    }

    /// Sends a request frame on the channel and reports the Runner's reply
    /// as SSH channel success/failure from a background task (the reply may
    /// take a while; the session loop must not wait for it).
    async fn forward_channel_request(
        &mut self,
        ssh_channel: ChannelId,
        frame_type: FrameType,
        payload: Vec<u8>,
        open_tx: Option<watch::Sender<OpenState>>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(binding) = self.channels.get(&ssh_channel) else {
            session.channel_failure(ssh_channel)?;
            return Ok(());
        };
        let frame_channel = binding.frame_channel;
        let Some(mux) = self.mux.clone() else {
            session.channel_failure(ssh_channel)?;
            return Ok(());
        };
        // Enqueued synchronously: requests hit the wire in callback order,
        // so PTY_REQUEST always precedes OPEN_SHELL on the same channel.
        let reply_rx = match mux.begin_request(frame_type, frame_channel, payload).await {
            Ok(rx) => rx,
            Err(_) => {
                session.channel_failure(ssh_channel)?;
                return Ok(());
            }
        };
        spawn_reply_reporter(
            session.handle(),
            ssh_channel,
            frame_channel,
            frame_type,
            reply_rx,
            self.gateway.request_timeout,
            open_tx,
        );
        Ok(())
    }

    /// Waits until the channel's OPEN_* reply resolved; returns the mux and
    /// frame channel only if data may flow (fail closed otherwise).
    async fn data_path(&mut self, ssh_channel: ChannelId) -> Option<(Arc<FrameMux>, u32)> {
        let binding = self.channels.get(&ssh_channel)?;
        let frame_channel = binding.frame_channel;
        let mut open_state = binding.open_state.clone()?;
        let mux = self.mux.clone()?;
        // Protocol ordering: STDIN only after the OPEN_* reply with ok=true.
        // Waiting here is safe: the reply arrives via the mux reader task,
        // which does not depend on this session loop.
        let timeout = self.gateway.request_timeout;
        let opened = tokio::time::timeout(
            timeout,
            open_state.wait_for(|state| *state != OpenState::Pending),
        )
        .await;
        match opened {
            Ok(Ok(state)) if *state == OpenState::Ready => Some((mux, frame_channel)),
            _ => None,
        }
    }
}

/// Reports one Runner reply as SSH channel success/failure and (for OPEN_*)
/// unblocks or fails the channel's data path.
fn spawn_reply_reporter(
    handle: russh::server::Handle,
    ssh_channel: ChannelId,
    frame_channel: u32,
    frame_type: FrameType,
    reply_rx: oneshot::Receiver<ReplyPayload>,
    timeout: Duration,
    open_tx: Option<watch::Sender<OpenState>>,
) {
    tokio::spawn(async move {
        let reply = tokio::time::timeout(timeout, reply_rx).await;
        let ok = match &reply {
            Ok(Ok(payload)) => {
                if let Some(ErrorPayload { code, message }) = &payload.error {
                    warn!(
                        channel = frame_channel,
                        request = ?frame_type,
                        code = %code,
                        message = %message,
                        "runner rejected channel request"
                    );
                }
                payload.ok
            }
            Ok(Err(_)) => {
                warn!(channel = frame_channel, request = ?frame_type, "runner stream closed before reply");
                false
            }
            Err(_) => {
                warn!(channel = frame_channel, request = ?frame_type, "runner reply timed out");
                false
            }
        };
        if let Some(open_tx) = open_tx {
            let _ = open_tx.send(if ok {
                OpenState::Ready
            } else {
                OpenState::Failed
            });
        }
        let _ = if ok {
            handle.channel_success(ssh_channel).await
        } else {
            handle.channel_failure(ssh_channel).await
        };
    });
}

/// Relays Runner frames of one channel into SSH channel events. Ends when
/// the Runner closes the channel or the mux tears down (sender dropped).
fn spawn_channel_forwarder(
    mut rx: mpsc::Receiver<Frame>,
    handle: russh::server::Handle,
    ssh_channel: ChannelId,
    frame_channel: u32,
) {
    tokio::spawn(async move {
        let mut closed_by_runner = false;
        while let Some(frame) = rx.recv().await {
            match frame.header.frame_type {
                FrameType::Stdout => {
                    if handle.data(ssh_channel, frame.payload).await.is_err() {
                        break;
                    }
                }
                FrameType::Stderr => {
                    if handle
                        .extended_data(ssh_channel, 1, frame.payload)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                FrameType::ExitStatus => {
                    match serde_json::from_slice::<ExitStatusPayload>(&frame.payload) {
                        Ok(status) => {
                            info!(
                                channel = frame_channel,
                                code = status.code,
                                "runner reported exit status"
                            );
                            // Negative codes cannot happen on this path (the
                            // Runner maps signal deaths to 128+signal); clamp
                            // defensively rather than bit-cast.
                            let code = u32::try_from(status.code).unwrap_or(255);
                            let _ = handle.exit_status_request(ssh_channel, code).await;
                        }
                        Err(e) => {
                            warn!(channel = frame_channel, error = %e, "unparseable exit status")
                        }
                    }
                }
                FrameType::Eof => {
                    let _ = handle.eof(ssh_channel).await;
                }
                FrameType::Close => {
                    closed_by_runner = true;
                    break;
                }
                FrameType::Error => {
                    match serde_json::from_slice::<ErrorPayload>(&frame.payload) {
                        Ok(e) => warn!(
                            channel = frame_channel,
                            code = %e.code,
                            message = %e.message,
                            "runner reported channel error"
                        ),
                        Err(_) => {
                            warn!(
                                channel = frame_channel,
                                "runner reported unparseable channel error"
                            )
                        }
                    }
                    closed_by_runner = true;
                    break;
                }
                other => {
                    debug!(channel = frame_channel, frame_type = ?other, "ignoring frame")
                }
            }
        }
        let _ = handle.close(ssh_channel).await;
        debug!(
            channel = frame_channel,
            closed_by_runner, "channel forwarder finished"
        );
    });
}

impl Handler for GatewayConnection {
    type Error = russh::Error;

    /// The username is the token; `none` auth carries the whole decision.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        let redacted = redact_token(user);
        if self.gateway.ssh_target != SshTarget::RusshVsock {
            self.fail_closed(&RouteError::FeatureDisabled);
            return Ok(Auth::reject());
        }
        match self.gateway.validator.validate(user).await {
            Ok(routing) => {
                info!(
                    session = %self.session_id,
                    token = %redacted,
                    box_id = %routing.box_id,
                    "authentication accepted"
                );
                self.routing = Some(Arc::new(routing));
                Ok(Auth::Accept)
            }
            Err(error) => {
                self.fail_closed(&error);
                // Generic rejection: no hint about why beyond "denied".
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.reject_other_method("password", user))
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.reject_other_method("publickey", user))
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.reject_other_method("publickey", user))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channels.len() >= MAX_CHANNELS_PER_CONNECTION {
            warn!(
                session = %self.session_id,
                limit = MAX_CHANNELS_PER_CONNECTION,
                "rejecting channel open: per-connection channel limit reached"
            );
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }

        let mux = match self.ensure_mux().await {
            Ok(mux) => mux,
            Err(error) => {
                self.fail_closed(&error);
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                // The disconnect description is the user-visible error; it
                // carries only the sanitized reason code.
                let _ = session
                    .handle()
                    .disconnect(
                        Disconnect::ByApplication,
                        error.user_message(),
                        String::new(),
                    )
                    .await;
                return Ok(());
            }
        };

        let frame_channel = self.next_frame_channel;
        self.next_frame_channel += 1;
        let rx = match mux.register_channel(frame_channel) {
            Ok(rx) => rx,
            Err(_) => {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            }
        };

        let ssh_channel = channel.id();
        // Keep only the write half; incoming traffic arrives through the
        // handler callbacks, and dropping the read half keeps russh from
        // buffering messages nobody consumes.
        let (_read_half, write_half) = channel.split();
        self.channels.insert(
            ssh_channel,
            ChannelBinding {
                frame_channel,
                open_state: None,
                _write_half: write_half,
            },
        );
        spawn_channel_forwarder(rx, session.handle(), ssh_channel, frame_channel);
        reply.accept().await;
        info!(
            session = %self.session_id,
            channel = frame_channel,
            "session channel opened"
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let payload = PtyRequestPayload {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
            width_px: pix_width,
            height_px: pix_height,
        };
        let bytes = serde_json::to_vec(&payload).expect("PtyRequestPayload is serializable");
        self.forward_channel_request(channel, FrameType::PtyRequest, bytes, None, session)
            .await
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(binding) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if binding.open_state.is_some() {
            // Exactly one OPEN_SHELL or OPEN_EXEC per channel.
            session.channel_failure(channel)?;
            return Ok(());
        }
        let (open_tx, open_rx) = watch::channel(OpenState::Pending);
        binding.open_state = Some(open_rx);
        info!(session = %self.session_id, channel = binding.frame_channel, "shell requested");
        self.forward_channel_request(
            channel,
            FrameType::OpenShell,
            b"{}".to_vec(),
            Some(open_tx),
            session,
        )
        .await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // OpenExecPayload.command is a JSON string; reject non-UTF-8 rather
        // than converting lossily.
        let Ok(command) = std::str::from_utf8(data) else {
            warn!(session = %self.session_id, "rejected exec request: command is not valid UTF-8");
            session.channel_failure(channel)?;
            return Ok(());
        };
        let Some(binding) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if binding.open_state.is_some() {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let (open_tx, open_rx) = watch::channel(OpenState::Pending);
        binding.open_state = Some(open_rx);
        info!(session = %self.session_id, channel = binding.frame_channel, "exec requested");
        let payload = OpenExecPayload {
            command: command.to_string(),
        };
        let bytes = serde_json::to_vec(&payload).expect("OpenExecPayload is serializable");
        self.forward_channel_request(channel, FrameType::OpenExec, bytes, Some(open_tx), session)
            .await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let payload = PtyResizePayload {
            cols: col_width,
            rows: row_height,
            width_px: pix_width,
            height_px: pix_height,
        };
        let bytes = serde_json::to_vec(&payload).expect("PtyResizePayload is serializable");
        self.forward_channel_request(channel, FrameType::PtyResize, bytes, None, session)
            .await
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some((mux, frame_channel)) = self.data_path(channel).await else {
            debug!(session = %self.session_id, "dropping stdin for a channel with no open execution");
            return Ok(());
        };
        for chunk in data.chunks(MAX_PAYLOAD) {
            if mux
                .send(Frame::data(FrameType::Stdin, frame_channel, chunk.to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some((mux, frame_channel)) = self.data_path(channel).await else {
            return Ok(());
        };
        let _ = mux
            .send(Frame::data(FrameType::Eof, frame_channel, Vec::new()))
            .await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(binding) = self.channels.remove(&channel) else {
            return Ok(());
        };
        info!(
            session = %self.session_id,
            channel = binding.frame_channel,
            "session channel closed"
        );
        if let Some(mux) = &self.mux {
            mux.deregister_channel(binding.frame_channel);
            let _ = mux
                .send(Frame::data(
                    FrameType::Close,
                    binding.frame_channel,
                    Vec::new(),
                ))
                .await;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(
            session = %self.session_id,
            subsystem = %name,
            "rejected subsystem request: subsystems (incl. sftp) are not supported"
        );
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(session = %self.session_id, "rejected direct-tcpip channel: forwarding not supported");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(session = %self.session_id, "rejected forwarded-tcpip channel: forwarding not supported");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(session = %self.session_id, "rejected direct-streamlocal channel: forwarding not supported");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(session = %self.session_id, "rejected x11 channel: X11 forwarding not supported");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(session = %self.session_id, "rejected x11-req: X11 forwarding not supported");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(session = %self.session_id, "rejected agent forwarding request");
        Ok(false)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // The frame protocol has no env frame; value deliberately not logged
        // (env vars may carry secrets).
        debug!(session = %self.session_id, name = %variable_name, "rejected env request");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(session = %self.session_id, "rejected tcpip-forward: forwarding not supported");
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_key_is_persistent_across_restarts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("host_key");
        let first = load_or_generate_host_key(&path).await.expect("generate");
        let second = load_or_generate_host_key(&path).await.expect("load");
        assert_eq!(
            first.public_key().to_openssh().unwrap(),
            second.public_key().to_openssh().unwrap(),
            "restart must reuse the same public host key"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "host key must not be world-readable");
        }
    }
}
