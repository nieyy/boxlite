//! russh-backed SSH session server.
//!
//! # Security model
//!
//! The server accepts `none` authentication for exactly one username
//! ([`SSH_UNIX_USER`], i.e. root) and rejects every other username and every
//! other auth method. This is safe ONLY because the listener is a private
//! vsock bound to a hardcoded port ([`GUEST_SSH_PORT`](boxlite_shared::constants::network::GUEST_SSH_PORT)):
//! the host side of the vsock belongs to the BoxLite runtime, which
//! authenticates its own callers before forwarding a connection. Never
//! expose this server on a routable transport.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use boxlite_shared::constants::guest_session::SSH_UNIX_USER;
use boxlite_shared::{BoxliteError, BoxliteResult, ExecutionClient};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Config, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, MethodKind, MethodSet, Pty};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::service::Routes as GrpcChannel;
use tracing::{debug, info, warn};

use super::bridge::{ChannelBridge, PtyParams};

/// SSH session server for one guest: owns the russh config with the
/// ephemeral host key and spawns one [`SshConnection`] handler per stream.
#[derive(Clone)]
pub(super) struct SshServer {
    config: Arc<Config>,
    exec_client: ExecutionClient<GrpcChannel>,
}

impl fmt::Debug for SshServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SshServer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SshServer {
    /// Build the server with a fresh in-memory ed25519 host key.
    ///
    /// The key is regenerated at every startup and never persisted: host key
    /// continuity is meaningless here because the BoxLite runtime owns both
    /// ends of the vsock and does not pin host keys.
    pub(super) fn new(exec_client: ExecutionClient<GrpcChannel>) -> BoxliteResult<Self> {
        let host_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .map_err(|e| BoxliteError::Internal(format!("generate ephemeral host key: {e}")))?;
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::None);
        let config = Config {
            methods,
            keys: vec![host_key],
            ..Config::default()
        };
        Ok(Self {
            config: Arc::new(config),
            exec_client,
        })
    }

    /// Serve one SSH connection over any bidirectional stream (vsock in
    /// production, in-memory duplex in tests) until the client disconnects.
    pub(super) async fn serve_stream<S>(&self, stream: S) -> Result<(), russh::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handler = SshConnection::new(self.exec_client.clone());
        info!("SSH session opened");
        let session = russh::server::run_stream(self.config.clone(), stream, handler).await?;
        let result = session.await;
        match &result {
            Ok(()) => info!("SSH session closed"),
            Err(e) => info!(error = %e, "SSH session closed with error"),
        }
        result
    }
}

/// Per-connection handler: authenticates, accepts session channels, and
/// routes channel requests to each channel's [`ChannelBridge`].
struct SshConnection {
    exec_client: ExecutionClient<GrpcChannel>,
    channels: HashMap<ChannelId, ChannelBridge>,
}

impl SshConnection {
    fn new(exec_client: ExecutionClient<GrpcChannel>) -> Self {
        Self {
            exec_client,
            channels: HashMap::new(),
        }
    }

    async fn start_execution(
        &mut self,
        channel: ChannelId,
        command: Option<String>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(bridge) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        match bridge.start(command).await {
            Ok(()) => session.channel_success(channel)?,
            Err(e) => {
                warn!(channel = %channel, error = %e, "failed to start delegated execution");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        // Client disconnected (or the connection errored out): no delegated
        // execution may outlive its SSH session.
        for bridge in self.channels.values_mut() {
            bridge.kill_running();
        }
    }
}

impl Handler for SshConnection {
    type Error = russh::Error;

    /// `none` auth is accepted for root only. Safe solely because the
    /// listener is a private vsock; see the module docs.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        if user == SSH_UNIX_USER {
            debug!(user = %user, "accepted none auth");
            Ok(Auth::Accept)
        } else {
            warn!(user = %user, "rejected none auth: only '{SSH_UNIX_USER}' may connect");
            Ok(Auth::reject())
        }
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        warn!(user = %user, "rejected password auth: method not allowed");
        Ok(Auth::reject())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        warn!(user = %user, "rejected publickey auth: method not allowed");
        Ok(Auth::reject())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        warn!(user = %user, "rejected publickey auth: method not allowed");
        Ok(Auth::reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let id = channel.id();
        // Keep only the write half. Incoming channel traffic is delivered
        // through the handler callbacks below; dropping the read half keeps
        // russh from buffering messages nobody consumes.
        let (_read_half, write_half) = channel.split();
        self.channels
            .insert(id, ChannelBridge::new(self.exec_client.clone(), write_half));
        reply.accept().await;
        debug!(channel = %id, "session channel opened");
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(host = %host_to_connect, port = port_to_connect, "rejected direct-tcpip channel: forwarding not supported");
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
        info!("rejected forwarded-tcpip channel: forwarding not supported");
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
        info!("rejected direct-streamlocal channel: forwarding not supported");
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
        info!("rejected x11 channel: X11 forwarding not supported");
        reply
            .reject(ChannelOpenFailure::AdministrativelyProhibited)
            .await;
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
        let Some(bridge) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        bridge.set_pty(PtyParams {
            term: term.to_string(),
            cols: col_width,
            rows: row_height,
            pix_width,
            pix_height,
        });
        session.channel_success(channel)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let accepted = self
            .channels
            .get_mut(&channel)
            .is_some_and(|bridge| bridge.set_env(variable_name, variable_value));
        if accepted {
            session.channel_success(channel)?;
        } else {
            // Value deliberately not logged: env vars may carry secrets.
            debug!(channel = %channel, name = %variable_name, "rejected env request");
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(channel = %channel, "shell requested");
        self.start_execution(channel, None, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // ExecRequest.args are protobuf strings, so the command must be
        // UTF-8; reject instead of converting lossily.
        let Ok(command) = std::str::from_utf8(data) else {
            warn!(channel = %channel, "rejected exec request: command is not valid UTF-8");
            session.channel_failure(channel)?;
            return Ok(());
        };
        info!(channel = %channel, "exec requested");
        // Command deliberately not logged: it may carry secrets (e.g. `curl
        // -u user:token`), matching env_request's redaction of values.
        debug!(channel = %channel, command_len = command.len(), "exec command");
        self.start_execution(channel, Some(command.to_string()), session)
            .await
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!(channel = %channel, subsystem = %name, "rejected subsystem request: subsystems not supported");
        session.channel_failure(channel)?;
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
        info!(channel = %channel, "rejected x11-req: X11 forwarding not supported");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        info!(channel = %channel, "rejected agent forwarding request");
        Ok(false)
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
        let Some(bridge) = self.channels.get_mut(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        match bridge
            .resize(col_width, row_height, pix_width, pix_height)
            .await
        {
            Ok(()) => session.channel_success(channel)?,
            Err(e) => {
                warn!(channel = %channel, error = %e, "window-change failed");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(bridge) = self.channels.get_mut(&channel) {
            bridge.stdin(data).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(bridge) = self.channels.get_mut(&channel) {
            bridge.stdin_eof().await;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(channel = %channel, "session channel closed");
        if let Some(mut bridge) = self.channels.remove(&channel) {
            bridge.kill_running();
        }
        Ok(())
    }
}
