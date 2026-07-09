//! Guest session capability: stable typed error taxonomy and the live SSH
//! readiness probe.
//!
//! The wire strings returned by [`BoxSessionErrorCode::as_str`] and
//! [`BoxSessionPhase::as_str`] are a **stable machine contract** consumed by
//! SDKs and control planes — never rename them; add new variants instead.
//!
//! Error `message`s are user-safe by construction: they never contain socket
//! paths, CIDs, or ports. Transport-level detail goes into `cause` (and logs).

use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use boxlite_shared::errors::{BoxliteError, BoxliteResult};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

/// The one session service the runtime currently exposes.
const SSH_SERVICE: &str = "ssh";

/// Bounded time to dial the per-box session socket.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounded time to wait for the SSH identification banner after connect.
const BANNER_TIMEOUT: Duration = Duration::from_secs(2);
/// RFC 4253 §4.2: the identification string is at most 255 bytes.
const BANNER_MAX_LEN: usize = 255;
/// Every SSH-2 server identification string starts with this prefix.
const SSH_BANNER_PREFIX: &[u8] = b"SSH-2.0-";

// ============================================================================
// ERROR TAXONOMY (stable wire contract)
// ============================================================================

/// Stable, machine-readable failure class for guest session operations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BoxSessionErrorCode {
    BoxStopped,
    RuntimeHandleMissing,
    RuntimeHandleStale,
    GuestEndpointMissing,
    GuestEndpointStale,
    GuestServiceNotReady,
    VsockConnectFailed,
    GuestServiceRejected,
    PermissionDenied,
    Timeout,
    Internal,
}

impl BoxSessionErrorCode {
    /// All variants, for wire-contract round-trip tests.
    pub const ALL: [Self; 11] = [
        Self::BoxStopped,
        Self::RuntimeHandleMissing,
        Self::RuntimeHandleStale,
        Self::GuestEndpointMissing,
        Self::GuestEndpointStale,
        Self::GuestServiceNotReady,
        Self::VsockConnectFailed,
        Self::GuestServiceRejected,
        Self::PermissionDenied,
        Self::Timeout,
        Self::Internal,
    ];

    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BoxStopped => "BOX_STOPPED",
            Self::RuntimeHandleMissing => "RUNTIME_HANDLE_MISSING",
            Self::RuntimeHandleStale => "RUNTIME_HANDLE_STALE",
            Self::GuestEndpointMissing => "GUEST_ENDPOINT_MISSING",
            Self::GuestEndpointStale => "GUEST_ENDPOINT_STALE",
            Self::GuestServiceNotReady => "GUEST_SERVICE_NOT_READY",
            Self::VsockConnectFailed => "VSOCK_CONNECT_FAILED",
            Self::GuestServiceRejected => "GUEST_SERVICE_REJECTED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Timeout => "TIMEOUT",
            Self::Internal => "INTERNAL",
        }
    }

    /// Parse a wire string produced by [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == s)
    }
}

impl fmt::Display for BoxSessionErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The phase of a session operation in which a failure occurred.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BoxSessionPhase {
    RuntimeLookup,
    EndpointResolve,
    TransportConnect,
    ReadinessProbe,
    SessionOpen,
}

impl BoxSessionPhase {
    /// All variants, for wire-contract round-trip tests.
    pub const ALL: [Self; 5] = [
        Self::RuntimeLookup,
        Self::EndpointResolve,
        Self::TransportConnect,
        Self::ReadinessProbe,
        Self::SessionOpen,
    ];

    /// Stable wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeLookup => "runtime_lookup",
            Self::EndpointResolve => "endpoint_resolve",
            Self::TransportConnect => "transport_connect",
            Self::ReadinessProbe => "readiness_probe",
            Self::SessionOpen => "session_open",
        }
    }

    /// Parse a wire string produced by [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|phase| phase.as_str() == s)
    }
}

impl fmt::Display for BoxSessionPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a caller should retry an operation that failed with `code`,
/// absent more specific knowledge (the design-table defaults).
pub fn default_retryable(code: BoxSessionErrorCode) -> bool {
    match code {
        BoxSessionErrorCode::BoxStopped => false,
        BoxSessionErrorCode::RuntimeHandleMissing => true,
        BoxSessionErrorCode::RuntimeHandleStale => true,
        BoxSessionErrorCode::GuestEndpointMissing => true,
        BoxSessionErrorCode::GuestEndpointStale => true,
        BoxSessionErrorCode::GuestServiceNotReady => true,
        BoxSessionErrorCode::VsockConnectFailed => true,
        BoxSessionErrorCode::GuestServiceRejected => false,
        BoxSessionErrorCode::PermissionDenied => false,
        BoxSessionErrorCode::Timeout => true,
        BoxSessionErrorCode::Internal => false,
    }
}

/// A typed guest session failure.
///
/// `message` is user-safe (no socket paths, CIDs, or ports); transport-level
/// detail lives in `cause`, which is surfaced via [`Error::source`] and logs
/// but never via [`fmt::Display`].
#[derive(Debug)]
pub struct BoxSessionError {
    pub code: BoxSessionErrorCode,
    pub phase: BoxSessionPhase,
    pub box_id: String,
    pub retryable: bool,
    pub message: String,
    pub cause: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl BoxSessionError {
    /// Build an error with the design-table default retryability for `code`.
    pub(crate) fn new(
        code: BoxSessionErrorCode,
        phase: BoxSessionPhase,
        box_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            phase,
            box_id: box_id.into(),
            retryable: default_retryable(code),
            message: message.into(),
            cause: None,
        }
    }

    /// Attach the underlying cause (may carry paths/ports — never displayed).
    pub(crate) fn with_cause(mut self, cause: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        self.cause = Some(cause.into());
        self
    }
}

impl fmt::Display for BoxSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (box={}, phase={}, retryable={}): {}",
            self.code, self.box_id, self.phase, self.retryable, self.message
        )
    }
}

impl Error for BoxSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}

/// Failure of [`crate::LiteBox::open_session_stream`]: either the caller
/// passed a bad argument, or the session itself could not be opened.
///
/// Kept distinct from [`BoxSessionError`] so a caller-side mistake (an
/// unsupported `service`) always surfaces as [`BoxliteError::InvalidArgument`]
/// — the same class [`crate::LiteBox::session_ready`] reports for the
/// identical bad input — instead of being folded into the session-open
/// failure taxonomy, which describes *why a valid request* couldn't open a
/// session (BOX_STOPPED, TIMEOUT, ...), not caller misuse.
#[derive(Debug)]
pub enum OpenSessionError {
    /// The request itself was invalid (e.g. an unsupported `service`).
    Argument(BoxliteError),
    /// The request was valid but the session could not be opened.
    Session(BoxSessionError),
}

impl fmt::Display for OpenSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(e) => e.fmt(f),
            Self::Session(e) => e.fmt(f),
        }
    }
}

impl Error for OpenSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Argument(e) => e.source(),
            Self::Session(e) => e.source(),
        }
    }
}

impl From<BoxliteError> for OpenSessionError {
    fn from(e: BoxliteError) -> Self {
        Self::Argument(e)
    }
}

impl From<BoxSessionError> for OpenSessionError {
    fn from(e: BoxSessionError) -> Self {
        Self::Session(e)
    }
}

/// Result of a live session readiness probe. `reason` is `None` iff `ready`.
#[derive(Debug)]
pub struct SessionReadiness {
    pub ready: bool,
    pub reason: Option<BoxSessionError>,
}

impl SessionReadiness {
    pub(crate) fn ready() -> Self {
        Self {
            ready: true,
            reason: None,
        }
    }

    pub(crate) fn not_ready(reason: BoxSessionError) -> Self {
        Self {
            ready: false,
            reason: Some(reason),
        }
    }
}

// ============================================================================
// LIVE PROBE (endpoint-level; box-state phases live in BoxImpl)
// ============================================================================

/// Reject any service other than `"ssh"` at the API boundary.
pub(crate) fn ensure_supported_service(service: &str) -> BoxliteResult<()> {
    if service == SSH_SERVICE {
        Ok(())
    } else {
        Err(BoxliteError::InvalidArgument(format!(
            "unsupported session service '{service}' (supported: \"{SSH_SERVICE}\")"
        )))
    }
}

/// Dial the resolved session endpoint (phases `endpoint_resolve` +
/// `transport_connect`/`session_open`).
///
/// `connect_phase` is stamped on transport-level failures: `TransportConnect`
/// for readiness probes, `SessionOpen` for raw stream opens. A missing socket
/// file is always an `endpoint_resolve` failure.
pub(crate) async fn connect_session_endpoint(
    box_id: &str,
    socket_path: &Path,
    connect_phase: BoxSessionPhase,
) -> Result<UnixStream, BoxSessionError> {
    connect_session_endpoint_with(box_id, socket_path, connect_phase, CONNECT_TIMEOUT).await
}

async fn connect_session_endpoint_with(
    box_id: &str,
    socket_path: &Path,
    connect_phase: BoxSessionPhase,
    connect_timeout: Duration,
) -> Result<UnixStream, BoxSessionError> {
    if !socket_path.exists() {
        return Err(BoxSessionError::new(
            BoxSessionErrorCode::GuestEndpointMissing,
            BoxSessionPhase::EndpointResolve,
            box_id,
            "session endpoint does not exist yet",
        ));
    }

    match tokio::time::timeout(connect_timeout, UnixStream::connect(socket_path)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            let (code, phase, message) = match e.kind() {
                // The socket file vanished between the check and the dial.
                std::io::ErrorKind::NotFound => (
                    BoxSessionErrorCode::GuestEndpointMissing,
                    BoxSessionPhase::EndpointResolve,
                    "session endpoint does not exist yet",
                ),
                std::io::ErrorKind::PermissionDenied => (
                    BoxSessionErrorCode::PermissionDenied,
                    connect_phase,
                    "not permitted to connect to the session endpoint",
                ),
                _ => (
                    BoxSessionErrorCode::VsockConnectFailed,
                    connect_phase,
                    "failed to connect to the session endpoint",
                ),
            };
            Err(BoxSessionError::new(code, phase, box_id, message).with_cause(e))
        }
        Err(_elapsed) => Err(BoxSessionError::new(
            BoxSessionErrorCode::Timeout,
            connect_phase,
            box_id,
            "timed out connecting to the session endpoint",
        )),
    }
}

/// Live SSH readiness probe against a resolved endpoint: connect, read the
/// server identification banner, close. Never writes a byte — russh servers
/// send their banner first — and never starts an SSH handshake.
pub(crate) async fn probe_ssh_endpoint(box_id: &str, socket_path: &Path) -> SessionReadiness {
    probe_ssh_endpoint_with(box_id, socket_path, CONNECT_TIMEOUT, BANNER_TIMEOUT).await
}

async fn probe_ssh_endpoint_with(
    box_id: &str,
    socket_path: &Path,
    connect_timeout: Duration,
    banner_timeout: Duration,
) -> SessionReadiness {
    let mut stream = match connect_session_endpoint_with(
        box_id,
        socket_path,
        BoxSessionPhase::TransportConnect,
        connect_timeout,
    )
    .await
    {
        Ok(stream) => stream,
        Err(reason) => return SessionReadiness::not_ready(reason),
    };

    let readiness = match read_banner(&mut stream, banner_timeout).await {
        BannerOutcome::Received(banner) if banner.starts_with(SSH_BANNER_PREFIX) => {
            SessionReadiness::ready()
        }
        BannerOutcome::Received(banner) if banner.is_empty() => {
            SessionReadiness::not_ready(BoxSessionError::new(
                BoxSessionErrorCode::GuestServiceNotReady,
                BoxSessionPhase::ReadinessProbe,
                box_id,
                "session service closed the connection before sending a banner",
            ))
        }
        BannerOutcome::Received(_) => SessionReadiness::not_ready(BoxSessionError::new(
            BoxSessionErrorCode::GuestServiceRejected,
            BoxSessionPhase::ReadinessProbe,
            box_id,
            "session service answered with a non-SSH banner",
        )),
        BannerOutcome::TimedOut => SessionReadiness::not_ready(BoxSessionError::new(
            BoxSessionErrorCode::Timeout,
            BoxSessionPhase::ReadinessProbe,
            box_id,
            "timed out waiting for the session service banner",
        )),
        BannerOutcome::IoError(e) => SessionReadiness::not_ready(
            BoxSessionError::new(
                BoxSessionErrorCode::GuestServiceNotReady,
                BoxSessionPhase::ReadinessProbe,
                box_id,
                "session service dropped the connection during the banner read",
            )
            .with_cause(e),
        ),
    };
    // `stream` drops here: the probe closes without writing anything.
    readiness
}

enum BannerOutcome {
    /// Bytes read up to a newline, [`BANNER_MAX_LEN`], or EOF (may be empty).
    Received(Vec<u8>),
    TimedOut,
    IoError(std::io::Error),
}

async fn read_banner(stream: &mut UnixStream, banner_timeout: Duration) -> BannerOutcome {
    let mut banner = Vec::with_capacity(BANNER_MAX_LEN);
    let read_loop = async {
        let mut chunk = [0u8; BANNER_MAX_LEN];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok::<(), std::io::Error>(()); // EOF
            }
            banner.extend_from_slice(&chunk[..n]);
            if banner.contains(&b'\n') || banner.len() >= BANNER_MAX_LEN {
                return Ok(());
            }
        }
    };
    match tokio::time::timeout(banner_timeout, read_loop).await {
        Ok(Ok(())) => BannerOutcome::Received(banner),
        Ok(Err(e)) => BannerOutcome::IoError(e),
        Err(_elapsed) => BannerOutcome::TimedOut,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    // ------------------------------------------------------------------
    // Wire contract
    // ------------------------------------------------------------------

    #[test]
    fn code_wire_strings_round_trip() {
        for code in BoxSessionErrorCode::ALL {
            assert_eq!(BoxSessionErrorCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(BoxSessionErrorCode::parse("NO_SUCH_CODE"), None);
    }

    #[test]
    fn phase_wire_strings_round_trip() {
        for phase in BoxSessionPhase::ALL {
            assert_eq!(BoxSessionPhase::parse(phase.as_str()), Some(phase));
        }
        assert_eq!(BoxSessionPhase::parse("no_such_phase"), None);
    }

    #[test]
    fn code_wire_strings_match_design_contract() {
        let expected = [
            (BoxSessionErrorCode::BoxStopped, "BOX_STOPPED"),
            (
                BoxSessionErrorCode::RuntimeHandleMissing,
                "RUNTIME_HANDLE_MISSING",
            ),
            (
                BoxSessionErrorCode::RuntimeHandleStale,
                "RUNTIME_HANDLE_STALE",
            ),
            (
                BoxSessionErrorCode::GuestEndpointMissing,
                "GUEST_ENDPOINT_MISSING",
            ),
            (
                BoxSessionErrorCode::GuestEndpointStale,
                "GUEST_ENDPOINT_STALE",
            ),
            (
                BoxSessionErrorCode::GuestServiceNotReady,
                "GUEST_SERVICE_NOT_READY",
            ),
            (
                BoxSessionErrorCode::VsockConnectFailed,
                "VSOCK_CONNECT_FAILED",
            ),
            (
                BoxSessionErrorCode::GuestServiceRejected,
                "GUEST_SERVICE_REJECTED",
            ),
            (BoxSessionErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (BoxSessionErrorCode::Timeout, "TIMEOUT"),
            (BoxSessionErrorCode::Internal, "INTERNAL"),
        ];
        for (code, wire) in expected {
            assert_eq!(code.as_str(), wire);
        }
        let phases = [
            (BoxSessionPhase::RuntimeLookup, "runtime_lookup"),
            (BoxSessionPhase::EndpointResolve, "endpoint_resolve"),
            (BoxSessionPhase::TransportConnect, "transport_connect"),
            (BoxSessionPhase::ReadinessProbe, "readiness_probe"),
            (BoxSessionPhase::SessionOpen, "session_open"),
        ];
        for (phase, wire) in phases {
            assert_eq!(phase.as_str(), wire);
        }
    }

    #[test]
    fn default_retryable_matches_design_table() {
        let expected = [
            (BoxSessionErrorCode::BoxStopped, false),
            (BoxSessionErrorCode::RuntimeHandleMissing, true),
            (BoxSessionErrorCode::RuntimeHandleStale, true),
            (BoxSessionErrorCode::GuestEndpointMissing, true),
            (BoxSessionErrorCode::GuestEndpointStale, true),
            (BoxSessionErrorCode::GuestServiceNotReady, true),
            (BoxSessionErrorCode::VsockConnectFailed, true),
            (BoxSessionErrorCode::GuestServiceRejected, false),
            (BoxSessionErrorCode::PermissionDenied, false),
            (BoxSessionErrorCode::Timeout, true),
            (BoxSessionErrorCode::Internal, false),
        ];
        for (code, retryable) in expected {
            assert_eq!(
                default_retryable(code),
                retryable,
                "default_retryable({code}) diverged from the design table"
            );
        }
    }

    #[test]
    fn display_never_leaks_the_cause() {
        let secret_path = "/tmp/secret-home/boxes/abc/sockets/ssh.sock";
        let err = BoxSessionError::new(
            BoxSessionErrorCode::VsockConnectFailed,
            BoxSessionPhase::TransportConnect,
            "boxdisplay1",
            "failed to connect to the session endpoint",
        )
        .with_cause(std::io::Error::other(format!(
            "connect {secret_path}: refused"
        )));

        let shown = err.to_string();
        assert!(shown.contains("VSOCK_CONNECT_FAILED"), "got: {shown}");
        assert!(shown.contains("transport_connect"), "got: {shown}");
        assert!(shown.contains("boxdisplay1"), "got: {shown}");
        assert!(
            !shown.contains(secret_path),
            "Display must not leak the cause (socket path): {shown}"
        );
        // The cause stays reachable for logs via Error::source.
        assert!(err.source().unwrap().to_string().contains(secret_path));
    }

    #[test]
    fn service_validation_rejects_unknown_service() {
        ensure_supported_service("ssh").expect("ssh must be supported");
        let err = ensure_supported_service("nosuch").unwrap_err();
        assert!(
            matches!(err, BoxliteError::InvalidArgument(_)),
            "got: {err:?}"
        );
    }

    /// Regression: `open_session_stream` used to wrap `ensure_supported_service`'s
    /// `InvalidArgument` into a `BoxSessionError{code: Internal}`, so the same
    /// bad `service` argument reported a different error class than
    /// `session_ready` for the identical input. `OpenSessionError`'s `From`
    /// conversion (the one `open_session_stream` relies on via `?`) must
    /// preserve `InvalidArgument` as an `Argument`-class error instead.
    #[test]
    fn open_session_error_reports_an_invalid_service_the_same_way_session_ready_does() {
        let err = ensure_supported_service("nosuch").unwrap_err();
        let wrapped: OpenSessionError = err.into();
        match wrapped {
            OpenSessionError::Argument(BoxliteError::InvalidArgument(_)) => {}
            other => panic!("expected Argument(InvalidArgument), got: {other:?}"),
        }
    }

    #[test]
    fn open_session_error_session_variant_wraps_box_session_error() {
        let session_err = BoxSessionError::new(
            BoxSessionErrorCode::BoxStopped,
            BoxSessionPhase::RuntimeLookup,
            "boxwrap1",
            "box is not running",
        );
        let wrapped: OpenSessionError = session_err.into();
        match wrapped {
            OpenSessionError::Session(e) => assert_eq!(e.code, BoxSessionErrorCode::BoxStopped),
            other => panic!("expected Session(..), got: {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Live probe against fake banner servers
    // ------------------------------------------------------------------

    fn sock_path(tmp: &tempfile::TempDir) -> std::path::PathBuf {
        tmp.path().join("ssh.sock")
    }

    #[tokio::test]
    async fn correct_banner_reports_ready_without_writing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"SSH-2.0-Russh_0.54\r\n").await.unwrap();
            // The probe must close without writing: expect a clean EOF.
            let mut buf = [0u8; 1];
            stream.read(&mut buf).await.unwrap()
        });

        let readiness = probe_ssh_endpoint("boxready1", &path).await;
        assert!(readiness.ready, "reason: {:?}", readiness.reason);
        assert!(readiness.reason.is_none());
        assert_eq!(server.await.unwrap(), 0, "probe must not write any bytes");
    }

    #[tokio::test]
    async fn garbage_banner_reports_guest_service_rejected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        });

        let readiness = probe_ssh_endpoint("boxgarbage1", &path).await;
        assert!(!readiness.ready);
        let reason = readiness.reason.unwrap();
        assert_eq!(reason.code, BoxSessionErrorCode::GuestServiceRejected);
        assert_eq!(reason.phase, BoxSessionPhase::ReadinessProbe);
        assert!(!reason.retryable);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn missing_socket_file_reports_guest_endpoint_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp); // never bound

        let readiness = probe_ssh_endpoint("boxmissing1", &path).await;
        assert!(!readiness.ready);
        let reason = readiness.reason.unwrap();
        assert_eq!(reason.code, BoxSessionErrorCode::GuestEndpointMissing);
        assert_eq!(reason.phase, BoxSessionPhase::EndpointResolve);
        assert!(reason.retryable);
    }

    #[tokio::test]
    async fn stale_socket_file_reports_vsock_connect_failed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        // Bind then drop: the socket file remains but nothing listens, so a
        // dial gets ECONNREFUSED — distinct from the missing-file case above.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());

        let readiness = probe_ssh_endpoint("boxstale1", &path).await;
        assert!(!readiness.ready);
        let reason = readiness.reason.unwrap();
        assert_eq!(reason.code, BoxSessionErrorCode::VsockConnectFailed);
        assert_eq!(reason.phase, BoxSessionPhase::TransportConnect);
        assert!(reason.retryable);
        assert!(reason.cause.is_some(), "io cause must be preserved");
    }

    #[tokio::test]
    async fn raw_open_connect_failure_is_stamped_session_open() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());

        let err = connect_session_endpoint("boxopen1", &path, BoxSessionPhase::SessionOpen)
            .await
            .unwrap_err();
        assert_eq!(err.code, BoxSessionErrorCode::VsockConnectFailed);
        assert_eq!(err.phase, BoxSessionPhase::SessionOpen);
    }

    #[tokio::test]
    async fn silent_server_reports_timeout_in_readiness_probe() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // Accept and hold the stream open without writing a byte.
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        // Short banner timeout keeps the test fast; the classification path
        // is identical to the production constants.
        let readiness = probe_ssh_endpoint_with(
            "boxsilent1",
            &path,
            CONNECT_TIMEOUT,
            Duration::from_millis(150),
        )
        .await;
        assert!(!readiness.ready);
        let reason = readiness.reason.unwrap();
        assert_eq!(reason.code, BoxSessionErrorCode::Timeout);
        assert_eq!(reason.phase, BoxSessionPhase::ReadinessProbe);
        assert!(reason.retryable);
        server.abort();
    }

    #[tokio::test]
    async fn instant_close_reports_guest_service_not_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            drop(stream); // close before sending any banner
        });

        let readiness = probe_ssh_endpoint("boxclosed1", &path).await;
        assert!(!readiness.ready);
        let reason = readiness.reason.unwrap();
        assert_eq!(reason.code, BoxSessionErrorCode::GuestServiceNotReady);
        assert_eq!(reason.phase, BoxSessionPhase::ReadinessProbe);
        assert!(reason.retryable);
        server.await.unwrap();
    }

    /// Drift guard: the readiness probe and the raw stream open must resolve
    /// and dial the SAME endpoint — a path that probes ready must open.
    #[tokio::test]
    async fn ready_probe_and_raw_open_share_endpoint_resolution() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = sock_path(&tmp);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(b"SSH-2.0-Russh_0.54\r\n").await.unwrap();
                let mut buf = [0u8; 1];
                let _ = stream.read(&mut buf).await;
            }
        });

        let readiness = probe_ssh_endpoint("boxdrift1", &path).await;
        assert!(readiness.ready, "reason: {:?}", readiness.reason);

        let mut stream = connect_session_endpoint("boxdrift1", &path, BoxSessionPhase::SessionOpen)
            .await
            .expect("raw open must succeed on the endpoint that probed ready");
        // The raw open performs no banner read; the first bytes the caller
        // reads are the server identification string.
        let mut prefix = [0u8; SSH_BANNER_PREFIX.len()];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, SSH_BANNER_PREFIX);
        drop(stream);
        server.await.unwrap();
    }
}
