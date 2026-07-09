//! Shared test harness: scripted Hosted API stub, fake Runner speaking the
//! HTTP upgrade + frame protocol, russh test client, and a tracing capture
//! writer for log-redaction assertions.

#![allow(dead_code)] // each test binary uses a subset of the harness

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boxlite_session_frame::{read_frame, write_frame, Frame};
use boxlite_ssh_gateway::token::{
    ApiFuture, HostedApi, HostedApiError, RunnerRecord, SshAccessValidation,
};
use boxlite_ssh_gateway::{Gateway, GatewayConfig, SshTarget};
use russh::client;
use russh::keys::PublicKey;
use russh::ChannelMsg;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Upper bound for every await in these tests; failures must never hang CI.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);

pub const TOKEN: &str = "boxlite-test-token-abcdefghijklmnop-0123456789";
pub const BOX_ID: &str = "box-e2e-1234";
pub const TOKEN_ID: &str = "token-id-5678";

// ---------------------------------------------------------------------------
// Scripted Hosted API (trait seam)
// ---------------------------------------------------------------------------

pub type ValidationScript = Result<SshAccessValidation, String>;

/// [`HostedApi`] stub. Validation answers pop from `queue` first, then fall
/// back to `fallback` forever.
pub struct StubHostedApi {
    queue: Mutex<VecDeque<ValidationScript>>,
    fallback: Mutex<ValidationScript>,
    runner: Mutex<Result<RunnerRecord, String>>,
    pub validate_calls: AtomicUsize,
}

impl StubHostedApi {
    pub fn with_fallback(fallback: ValidationScript, runner_domain: &str) -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            fallback: Mutex::new(fallback),
            runner: Mutex::new(Ok(RunnerRecord {
                id: "runner-1".into(),
                domain: Some(runner_domain.to_string()),
            })),
            validate_calls: AtomicUsize::new(0),
        })
    }

    /// Stub that always accepts [`TOKEN`] for [`BOX_ID`].
    pub fn valid(runner_domain: &str) -> Arc<Self> {
        Self::with_fallback(Ok(valid_validation()), runner_domain)
    }

    /// Stub that always rejects.
    pub fn invalid() -> Arc<Self> {
        Self::with_fallback(
            Ok(SshAccessValidation {
                valid: false,
                box_id: String::new(),
                unix_user: None,
                token_id: None,
            }),
            "unused.invalid",
        )
    }

    pub fn push_validation(&self, result: ValidationScript) {
        self.queue.lock().unwrap().push_back(result);
    }

    pub fn set_fallback(&self, result: ValidationScript) {
        *self.fallback.lock().unwrap() = result;
    }

    pub fn set_runner(&self, result: Result<RunnerRecord, String>) {
        *self.runner.lock().unwrap() = result;
    }

    pub fn validate_call_count(&self) -> usize {
        self.validate_calls.load(Ordering::SeqCst)
    }
}

pub fn valid_validation() -> SshAccessValidation {
    SshAccessValidation {
        valid: true,
        box_id: BOX_ID.into(),
        unix_user: Some("root".into()),
        token_id: Some(TOKEN_ID.into()),
    }
}

impl HostedApi for StubHostedApi {
    fn validate_ssh_access<'a>(&'a self, _token: &'a str) -> ApiFuture<'a, SshAccessValidation> {
        Box::pin(async move {
            self.validate_calls.fetch_add(1, Ordering::SeqCst);
            let scripted = self
                .queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.fallback.lock().unwrap().clone());
            scripted.map_err(|message| HostedApiError {
                operation: "validate ssh access",
                message,
            })
        })
    }

    fn runner_by_box<'a>(&'a self, _box_id: &'a str) -> ApiFuture<'a, RunnerRecord> {
        Box::pin(async move {
            self.runner
                .lock()
                .unwrap()
                .clone()
                .map_err(|message| HostedApiError {
                    operation: "resolve runner by box",
                    message,
                })
        })
    }
}

// ---------------------------------------------------------------------------
// Fake Runner (std threads + the sync session-frame codec, independently
// exercising the gateway's async codec against the reference implementation)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RunnerEvent {
    StatusRequest,
    Upgraded { headers: HashMap<String, String> },
    UpgradeRejected,
    Frame(Frame),
    StreamClosed,
}

enum Inject {
    Frame(Frame),
    Raw(Vec<u8>),
}

#[derive(Clone)]
pub enum UpgradeBehavior {
    Accept,
    Reject { status: u16, body: String },
}

#[derive(Clone)]
pub struct RunnerScript {
    /// Status code + JSON body served on `GET /v1/boxes/{id}/ssh-status`.
    pub status: (u16, String),
    pub upgrade: UpgradeBehavior,
    /// Reply `{"ok":true}` to every request frame automatically.
    pub auto_reply: bool,
}

impl RunnerScript {
    pub fn ready() -> Self {
        Self {
            status: (
                200,
                r#"{"ready":true,"transport":"boxlite-runtime-vsock","degraded":false,"degraded_reason":""}"#.into(),
            ),
            upgrade: UpgradeBehavior::Accept,
            auto_reply: true,
        }
    }

    pub fn rejecting_upgrade(status: u16, body: &str) -> Self {
        Self {
            upgrade: UpgradeBehavior::Reject {
                status,
                body: body.to_string(),
            },
            ..Self::ready()
        }
    }
}

pub struct FakeRunner {
    pub addr: SocketAddr,
    events: UnboundedReceiver<RunnerEvent>,
    inject_tx: std::sync::mpsc::Sender<Inject>,
    tcp_connections: Arc<AtomicUsize>,
}

impl FakeRunner {
    pub fn spawn(script: RunnerScript) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake runner");
        let addr = listener.local_addr().expect("local addr");
        let (event_tx, events) = unbounded_channel();
        let (inject_tx, inject_rx) = std::sync::mpsc::channel::<Inject>();
        let inject_slot = Arc::new(Mutex::new(Some(inject_rx)));
        let tcp_connections = Arc::new(AtomicUsize::new(0));

        let connections = Arc::clone(&tcp_connections);
        let accept_inject_tx = inject_tx.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                connections.fetch_add(1, Ordering::SeqCst);
                let script = script.clone();
                let event_tx = event_tx.clone();
                let inject_slot = Arc::clone(&inject_slot);
                let inject_tx = accept_inject_tx.clone();
                std::thread::spawn(move || {
                    handle_runner_conn(stream, script, event_tx, inject_slot, inject_tx)
                });
            }
        });

        Self {
            addr,
            events,
            inject_tx,
            tcp_connections,
        }
    }

    pub fn domain(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    pub fn tcp_connection_count(&self) -> usize {
        self.tcp_connections.load(Ordering::SeqCst)
    }

    pub fn inject(&self, frame: Frame) {
        self.inject_tx
            .send(Inject::Frame(frame))
            .expect("fake runner writer gone");
    }

    pub fn inject_raw(&self, bytes: Vec<u8>) {
        self.inject_tx
            .send(Inject::Raw(bytes))
            .expect("fake runner writer gone");
    }

    pub async fn next_event(&mut self) -> RunnerEvent {
        tokio::time::timeout(TEST_TIMEOUT, self.events.recv())
            .await
            .expect("timed out waiting for fake runner event")
            .expect("fake runner event stream ended")
    }

    /// Next frame observed on the upgraded stream, skipping HTTP-level
    /// events. Frame order is preserved.
    pub async fn next_frame(&mut self) -> Frame {
        loop {
            match self.next_event().await {
                RunnerEvent::Frame(frame) => return frame,
                RunnerEvent::StreamClosed => panic!("stream closed while waiting for a frame"),
                _ => continue,
            }
        }
    }

    /// Waits for the stream to close, returning frames seen on the way.
    pub async fn wait_stream_closed(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        loop {
            match self.next_event().await {
                RunnerEvent::Frame(frame) => frames.push(frame),
                RunnerEvent::StreamClosed => return frames,
                _ => continue,
            }
        }
    }
}

fn handle_runner_conn(
    mut stream: std::net::TcpStream,
    script: RunnerScript,
    event_tx: UnboundedSender<RunnerEvent>,
    inject_slot: Arc<Mutex<Option<std::sync::mpsc::Receiver<Inject>>>>,
    inject_tx: std::sync::mpsc::Sender<Inject>,
) {
    let Some(head) = read_http_head(&mut stream) else {
        return;
    };
    let (request_line, headers) = parse_http_head(&head);

    if request_line.starts_with("GET") && request_line.contains("/ssh-status") {
        let _ = event_tx.send(RunnerEvent::StatusRequest);
        let (code, body) = &script.status;
        write_http_response(&mut stream, *code, body);
        return;
    }

    if request_line.starts_with("POST") && request_line.contains("/internal/ssh/sessions/") {
        match &script.upgrade {
            UpgradeBehavior::Reject { status, body } => {
                let _ = event_tx.send(RunnerEvent::UpgradeRejected);
                write_http_response(&mut stream, *status, body);
            }
            UpgradeBehavior::Accept => {
                let response = "HTTP/1.1 101 Switching Protocols\r\n\
                                Upgrade: boxlite-session-stream\r\n\
                                Connection: Upgrade\r\n\r\n";
                if stream.write_all(response.as_bytes()).is_err() {
                    return;
                }
                let _ = event_tx.send(RunnerEvent::Upgraded { headers });

                let write_stream = stream.try_clone().expect("clone runner stream");
                let inject_rx = inject_slot
                    .lock()
                    .unwrap()
                    .take()
                    .expect("harness supports one upgraded stream per FakeRunner");
                std::thread::spawn(move || runner_writer_loop(write_stream, inject_rx));

                // Auto-replies go through the same single-writer queue as
                // injected frames, mirroring the real Runner's writer mutex.
                runner_reader_loop(stream, script.auto_reply, event_tx, inject_tx);
            }
        }
    }
}

fn runner_reader_loop(
    mut stream: std::net::TcpStream,
    auto_reply: bool,
    event_tx: UnboundedSender<RunnerEvent>,
    reply_tx: std::sync::mpsc::Sender<Inject>,
) {
    loop {
        match read_frame(&mut stream) {
            Ok(frame) => {
                if auto_reply && frame.header.request_id != 0 && !frame.is_reply() {
                    let reply = Frame::reply_ok(
                        frame.header.frame_type,
                        frame.header.channel_id,
                        frame.header.request_id,
                    );
                    let _ = reply_tx.send(Inject::Frame(reply));
                }
                let _ = event_tx.send(RunnerEvent::Frame(frame));
            }
            Err(_) => {
                let _ = event_tx.send(RunnerEvent::StreamClosed);
                return;
            }
        }
    }
}

fn runner_writer_loop(
    mut stream: std::net::TcpStream,
    inject_rx: std::sync::mpsc::Receiver<Inject>,
) {
    for msg in inject_rx.iter() {
        let result = match msg {
            Inject::Frame(frame) => write_frame(&mut stream, &frame),
            Inject::Raw(bytes) => stream.write_all(&bytes),
        };
        if result.is_err() {
            return;
        }
    }
}

fn read_http_head(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
        if head.len() > 64 * 1024 {
            return None;
        }
    }
    Some(head)
}

fn parse_http_head(head: &[u8]) -> (String, HashMap<String, String>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }
    (request_line, headers)
}

fn write_http_response(stream: &mut std::net::TcpStream, code: u16, body: &str) {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

// ---------------------------------------------------------------------------
// Gateway + russh client plumbing
// ---------------------------------------------------------------------------

pub fn test_config(host_key_dir: &std::path::Path) -> GatewayConfig {
    GatewayConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        host_key_path: host_key_dir.join("host_key"),
        hosted_api_url: "http://127.0.0.1:9".into(), // unused behind the trait seam
        hosted_api_token: "test-hosted-secret".into(),
        runner_service_token: "test-runner-secret".into(),
        ssh_target: SshTarget::RusshVsock,
        request_timeout_secs: 5,
        runner_scheme: "http".into(),
        max_connections: 4096,
    }
}

pub struct TestClient;

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connects a russh client to the gateway over an in-memory duplex stream.
pub async fn connect_client(gateway: &Gateway) -> client::Handle<TestClient> {
    let (client_stream, server_stream) = tokio::io::duplex(256 * 1024);
    let gateway = gateway.clone();
    tokio::spawn(async move {
        let _ = gateway.serve_stream(server_stream).await;
    });
    let config = Arc::new(client::Config::default());
    tokio::time::timeout(
        TEST_TIMEOUT,
        client::connect_stream(config, client_stream, TestClient),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed")
}

pub async fn connect_authenticated(gateway: &Gateway) -> client::Handle<TestClient> {
    let mut handle = connect_client(gateway).await;
    let auth = handle
        .authenticate_none(TOKEN)
        .await
        .expect("auth request failed");
    assert!(auth.success(), "none auth with a valid token must succeed");
    handle
}

/// Everything the client observed on a session channel until it closed.
#[derive(Default)]
pub struct ChannelCapture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    pub saw_eof: bool,
}

pub async fn drain_channel(channel: &mut russh::Channel<client::Msg>) -> ChannelCapture {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let mut capture = ChannelCapture::default();
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => capture.stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    capture.stderr.extend_from_slice(&data)
                }
                ChannelMsg::ExitStatus { exit_status } => capture.exit_status = Some(exit_status),
                ChannelMsg::Eof => capture.saw_eof = true,
                _ => {}
            }
        }
        capture
    })
    .await
    .expect("channel did not close within timeout")
}

// ---------------------------------------------------------------------------
// tracing capture for log-redaction assertions
// ---------------------------------------------------------------------------

/// `MakeWriter` collecting all log output; usable from any thread.
#[derive(Clone, Default)]
pub struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    pub fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// Installs (once per test process) a global subscriber writing into a
/// shared capture and returns that capture.
///
/// Deliberately global, not `set_default`-scoped: tests run in parallel
/// threads, and a thread-scoped subscriber intermittently misses events
/// emitted while other tests own the tracing callsite caches. Capturing the
/// whole process also strengthens redaction assertions — no event from ANY
/// concurrently running test may contain a full token.
pub fn install_global_capture() -> LogCapture {
    static CAPTURE: std::sync::OnceLock<LogCapture> = std::sync::OnceLock::new();
    CAPTURE
        .get_or_init(|| {
            let capture = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_writer(capture.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("global subscriber installed twice");
            capture
        })
        .clone()
}

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
