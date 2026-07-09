//! In-process tests for the SSH session service.
//!
//! Topology: russh client <-> [`SshServer`] over an in-memory duplex stream;
//! the server delegates to a fake Execution gRPC service wired in-process via
//! `tonic::transport::Server::into_service` — the same mechanism
//! `serve_vsock` uses in production, just with a fake service in place of the
//! real [`GuestServer`](super::super::server::GuestServer). No VM, no socket
//! required.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boxlite_shared::execution_server::{Execution, ExecutionServer};
use boxlite_shared::{
    exec_output, AttachRequest, ExecOutput, ExecRequest, ExecResponse, ExecStdin, ExecutionClient,
    KillRequest, KillResponse, ResizeTtyRequest, ResizeTtyResponse, SendInputAck, Stderr, Stdout,
    WaitRequest, WaitResponse,
};
use russh::client;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use russh::{ChannelMsg, Disconnect};
use tokio::sync::{watch, Mutex, Notify};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use super::server::SshServer;

/// Upper bound for every await in these tests; failures must never hang CI.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Fake Execution service
// ---------------------------------------------------------------------------

/// Scripted behavior for one execution, consumed in Exec order.
#[derive(Clone, Default)]
struct ExecPlan {
    /// Streamed on Attach, in order, then the stream ends (unless `hold`).
    outputs: Vec<exec_output::Event>,
    /// Returned by Wait once the execution is released.
    wait: WaitResponse,
    /// Keep Attach open and gate Wait until `release()` or Kill.
    hold: bool,
    /// Kill is recorded (kill_calls) but does NOT release the hold —
    /// simulates a guest process that a Kill RPC couldn't actually stop
    /// (wedged, timed-out signal delivery, etc.). Only meaningful with
    /// `hold: true`.
    kill_ineffective: bool,
}

struct ExecEntry {
    plan: ExecPlan,
    release_tx: watch::Sender<bool>,
}

#[derive(Default)]
struct FakeState {
    plans: Vec<ExecPlan>,
    exec_requests: Vec<ExecRequest>,
    execs: HashMap<String, ExecEntry>,
    kill_calls: Vec<KillRequest>,
    resize_calls: Vec<ResizeTtyRequest>,
    stdin_frames: HashMap<String, Vec<ExecStdin>>,
    /// Execution ids whose Attach response stream the *client* dropped
    /// (detected via the sender half's `closed()`) while still held open
    /// server-side — i.e. the SSH service gave up on Attach instead of
    /// leaving it (and the gRPC stream, and the SSH channel write half)
    /// leaked forever.
    attach_client_dropped: std::collections::HashSet<String>,
}

/// Fake Execution gRPC service recording every call for assertions.
#[derive(Clone, Default)]
struct FakeExec {
    state: Arc<Mutex<FakeState>>,
    changed: Arc<Notify>,
}

impl FakeExec {
    async fn push_plan(&self, plan: ExecPlan) {
        self.state.lock().await.plans.push(plan);
    }

    /// Let a held execution finish (Attach stream ends, Wait returns).
    async fn release(&self, execution_id: &str) {
        let state = self.state.lock().await;
        let entry = state.execs.get(execution_id).expect("unknown execution");
        // send_replace: updates the value even before Attach/Wait subscribed.
        entry.release_tx.send_replace(true);
    }

    /// Await a condition over the recorded state, woken by every mutation.
    async fn wait_for<T>(&self, condition: impl Fn(&FakeState) -> Option<T>) -> T {
        tokio::time::timeout(TEST_TIMEOUT, async {
            loop {
                let notified = self.changed.notified();
                if let Some(value) = condition(&*self.state.lock().await) {
                    return value;
                }
                notified.await;
            }
        })
        .await
        .expect("fake exec condition not met within timeout")
    }

    async fn mutate<T>(&self, f: impl FnOnce(&mut FakeState) -> T) -> T {
        let result = f(&mut *self.state.lock().await);
        self.changed.notify_waiters();
        result
    }
}

#[tonic::async_trait]
impl Execution for FakeExec {
    async fn exec(&self, request: Request<ExecRequest>) -> Result<Response<ExecResponse>, Status> {
        let request = request.into_inner();
        let execution_id = self
            .mutate(|state| {
                let index = state.exec_requests.len();
                let execution_id = format!("exec-{}", index + 1);
                let plan = state.plans.get(index).cloned().unwrap_or_default();
                let (release_tx, _) = watch::channel(false);
                state.exec_requests.push(request);
                state
                    .execs
                    .insert(execution_id.clone(), ExecEntry { plan, release_tx });
                execution_id
            })
            .await;
        Ok(Response::new(ExecResponse {
            execution_id,
            pid: 4242,
            started_at_ms: 1,
            error: None,
        }))
    }

    type AttachStream = ReceiverStream<Result<ExecOutput, Status>>;

    async fn attach(
        &self,
        request: Request<AttachRequest>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let execution_id = request.into_inner().execution_id;
        let (outputs, hold, mut release_rx) = {
            let state = self.state.lock().await;
            let entry = state
                .execs
                .get(&execution_id)
                .ok_or_else(|| Status::not_found(execution_id.clone()))?;
            (
                entry.plan.outputs.clone(),
                entry.plan.hold,
                entry.release_tx.subscribe(),
            )
        };
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let fake = self.clone();
        tokio::spawn(async move {
            for event in outputs {
                if tx
                    .send(Ok(ExecOutput { event: Some(event) }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            if hold {
                // Races the scripted release against the *client* dropping
                // its end of the response stream (tx.closed() resolves once
                // the paired Receiver — held by tonic's response machinery —
                // is dropped, which happens when the SSH service stops
                // polling the Attach stream). Only tx.closed() winning is a
                // client-drop; recorded so tests can assert on it directly
                // instead of inferring it from timing.
                // wait_for()'s future holds a non-Send watch::Ref guard
                // across its await, which would make this whole select! (and
                // the task spawning it) non-Send; changed() + a synchronous
                // borrow() check (dropped before the next await) avoids that.
                tokio::select! {
                    _ = async {
                        while !*release_rx.borrow() {
                            if release_rx.changed().await.is_err() {
                                break;
                            }
                        }
                    } => {}
                    _ = tx.closed() => {
                        fake.mutate(|state| {
                            state.attach_client_dropped.insert(execution_id.clone());
                        })
                        .await;
                    }
                }
            }
            // Dropping tx ends the Attach stream.
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn send_input(
        &self,
        request: Request<Streaming<ExecStdin>>,
    ) -> Result<Response<SendInputAck>, Status> {
        let mut stream = request.into_inner();
        while let Some(frame) = stream.message().await? {
            self.mutate(|state| {
                state
                    .stdin_frames
                    .entry(frame.execution_id.clone())
                    .or_default()
                    .push(frame);
            })
            .await;
        }
        Ok(Response::new(SendInputAck {}))
    }

    async fn wait(&self, request: Request<WaitRequest>) -> Result<Response<WaitResponse>, Status> {
        let execution_id = request.into_inner().execution_id;
        let (wait, hold, mut release_rx) = {
            let state = self.state.lock().await;
            let entry = state
                .execs
                .get(&execution_id)
                .ok_or_else(|| Status::not_found(execution_id.clone()))?;
            (
                entry.plan.wait.clone(),
                entry.plan.hold,
                entry.release_tx.subscribe(),
            )
        };
        if hold {
            release_rx
                .wait_for(|released| *released)
                .await
                .map_err(|_| Status::internal("release channel dropped"))?;
        }
        Ok(Response::new(wait))
    }

    async fn kill(&self, request: Request<KillRequest>) -> Result<Response<KillResponse>, Status> {
        let request = request.into_inner();
        self.mutate(|state| {
            if let Some(entry) = state.execs.get(&request.execution_id) {
                if !entry.plan.kill_ineffective {
                    entry.release_tx.send_replace(true);
                }
            }
            state.kill_calls.push(request);
        })
        .await;
        Ok(Response::new(KillResponse {
            success: true,
            error: None,
        }))
    }

    async fn resize_tty(
        &self,
        request: Request<ResizeTtyRequest>,
    ) -> Result<Response<ResizeTtyResponse>, Status> {
        self.mutate(|state| state.resize_calls.push(request.into_inner()))
            .await;
        Ok(Response::new(ResizeTtyResponse {
            success: true,
            error: None,
        }))
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    fake: FakeExec,
    server: SshServer,
}

/// Wires a fake Execution service straight into an `ExecutionClient` with no
/// socket, no separate task — the same `Router::into_service` mechanism
/// `serve_vsock` uses against the real `GuestServer` in production.
async fn start_harness() -> Harness {
    let fake = FakeExec::default();
    let router =
        tonic::transport::Server::builder().add_service(ExecutionServer::new(fake.clone()));
    let exec_client = ExecutionClient::new(router.into_service());
    let server = SshServer::new(exec_client).expect("ssh server");
    Harness { fake, server }
}

struct TestClient;

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connect a russh client to the server over an in-memory duplex stream.
async fn connect(harness: &Harness) -> client::Handle<TestClient> {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let server = harness.server.clone();
    tokio::spawn(async move {
        let _ = server.serve_stream(server_stream).await;
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

async fn connect_as_root(harness: &Harness) -> client::Handle<TestClient> {
    let mut handle = connect(harness).await;
    let auth = handle
        .authenticate_none("root")
        .await
        .expect("auth request failed");
    assert!(auth.success(), "none auth as root must succeed");
    handle
}

/// Everything the client observed on a session channel until it closed.
#[derive(Default)]
struct ChannelCapture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    saw_eof: bool,
}

async fn drain_channel(channel: &mut russh::Channel<client::Msg>) -> ChannelCapture {
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

fn stdout_event(data: &[u8]) -> exec_output::Event {
    exec_output::Event::Stdout(Stdout {
        data: data.to_vec(),
    })
}

fn stderr_event(data: &[u8]) -> exec_output::Event {
    exec_output::Event::Stderr(Stderr {
        data: data.to_vec(),
    })
}

fn exit_with_code(exit_code: i32) -> WaitResponse {
    WaitResponse {
        exit_code,
        ..WaitResponse::default()
    }
}

// ---------------------------------------------------------------------------
// 1. Authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn none_auth_as_root_succeeds() {
    let harness = start_harness().await;
    connect_as_root(&harness).await;
}

#[tokio::test]
async fn none_auth_as_other_user_is_rejected() {
    let harness = start_harness().await;
    let mut handle = connect(&harness).await;
    let auth = handle.authenticate_none("alice").await.expect("auth rpc");
    assert!(!auth.success(), "none auth as non-root must be rejected");
}

#[tokio::test]
async fn password_auth_as_root_is_rejected() {
    let harness = start_harness().await;
    let mut handle = connect(&harness).await;
    let auth = handle
        .authenticate_password("root", "hunter2")
        .await
        .expect("auth rpc");
    assert!(!auth.success(), "password auth must be rejected");
}

#[tokio::test]
async fn publickey_auth_as_root_is_rejected() {
    let harness = start_harness().await;
    let mut handle = connect(&harness).await;
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("keygen");
    let auth = handle
        .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .expect("auth rpc");
    assert!(!auth.success(), "publickey auth must be rejected");
}

// ---------------------------------------------------------------------------
// 2. Exec delegation, output streaming, binary safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_delegates_to_guest_and_reports_exit_status() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: vec![stdout_event(b"out-data"), stderr_event(b"err-data")],
            wait: exit_with_code(42),
            hold: false,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel
        .set_env(false, "FOO", "bar")
        .await
        .expect("env request");
    channel.exec(true, "echo hi").await.expect("exec request");

    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.stdout, b"out-data");
    assert_eq!(capture.stderr, b"err-data");
    assert_eq!(capture.exit_status, Some(42));
    assert!(capture.saw_eof, "server must send EOF after exit-status");

    let request = harness
        .fake
        .wait_for(|state| state.exec_requests.first().cloned())
        .await;
    assert_eq!(request.program, "/bin/sh");
    assert_eq!(request.args, vec!["-c".to_string(), "echo hi".to_string()]);
    assert_eq!(request.user.as_deref(), Some("root"));
    assert_eq!(request.env.get("FOO").map(String::as_str), Some("bar"));
    assert!(request.tty.is_none(), "no pty-req means no TtyConfig");
}

#[tokio::test]
async fn exec_output_is_binary_safe() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: vec![stdout_event(&all_bytes)],
            wait: exit_with_code(0),
            hold: false,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "binary").await.expect("exec request");

    let capture = drain_channel(&mut channel).await;
    assert_eq!(
        capture.stdout, all_bytes,
        "bytes 0x00-0xFF must round-trip exactly"
    );
}

// ---------------------------------------------------------------------------
// 3. Shell + PTY + window-change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn shell_with_pty_delegates_tty_and_window_change_resizes() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: Vec::new(),
            wait: exit_with_code(0),
            hold: true,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel
        .request_pty(true, "xterm-256color", 80, 24, 640, 480, &[])
        .await
        .expect("pty request");
    channel.request_shell(true).await.expect("shell request");

    let request = harness
        .fake
        .wait_for(|state| state.exec_requests.first().cloned())
        .await;
    assert_eq!(request.program, "/bin/sh");
    assert_eq!(request.args, vec!["-l".to_string()]);
    assert_eq!(request.user.as_deref(), Some("root"));
    let tty = request.tty.expect("pty-req must produce a TtyConfig");
    assert_eq!(
        (tty.cols, tty.rows, tty.x_pixels, tty.y_pixels),
        (80, 24, 640, 480)
    );
    assert_eq!(
        request.env.get("TERM").map(String::as_str),
        Some("xterm-256color")
    );

    channel
        .window_change(120, 40, 800, 600)
        .await
        .expect("window change");
    let resize = harness
        .fake
        .wait_for(|state| state.resize_calls.first().cloned())
        .await;
    assert_eq!(resize.execution_id, "exec-1");
    assert_eq!(
        (resize.cols, resize.rows, resize.x_pixels, resize.y_pixels),
        (120, 40, 800, 600)
    );

    harness.fake.release("exec-1").await;
    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 4. Stdin forwarding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stdin_is_forwarded_then_closed_on_eof() {
    // Deliberately not valid UTF-8.
    let payload: &[u8] = &[0x00, 0xff, 0xfe, b'h', b'i', 0x80, 0x00];
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: Vec::new(),
            wait: exit_with_code(0),
            hold: true,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "cat").await.expect("exec request");
    harness
        .fake
        .wait_for(|state| state.exec_requests.first().cloned())
        .await;

    channel.data(payload).await.expect("send stdin");
    channel.eof().await.expect("send eof");

    let frames = harness
        .fake
        .wait_for(|state| {
            let frames = state.stdin_frames.get("exec-1")?;
            frames.iter().any(|f| f.close).then(|| frames.clone())
        })
        .await;
    let (close_frames, data_frames): (Vec<_>, Vec<_>) = frames.iter().partition(|f| f.close);
    let received: Vec<u8> = data_frames.iter().flat_map(|f| f.data.clone()).collect();
    assert_eq!(received, payload, "stdin bytes must round-trip exactly");
    assert_eq!(close_frames.len(), 1, "EOF must close stdin exactly once");
    assert!(
        frames.last().expect("frames").close,
        "close must come after all data"
    );

    harness.fake.release("exec-1").await;
    drain_channel(&mut channel).await;
}

// ---------------------------------------------------------------------------
// 5. Exit status conventions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn signal_death_is_reported_as_exit_status_128_plus_signal() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: Vec::new(),
            wait: WaitResponse {
                signal: 9,
                ..WaitResponse::default()
            },
            hold: false,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel
        .exec(true, "sleep 1000")
        .await
        .expect("exec request");

    let capture = drain_channel(&mut channel).await;
    // Documented convention: signal deaths surface as exit-status 128+signal.
    assert_eq!(capture.exit_status, Some(137));
}

// ---------------------------------------------------------------------------
// 6. Unsupported requests are rejected without hanging the connection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_requests_fail_cleanly_and_connection_survives() {
    let harness = start_harness().await;
    harness.fake.push_plan(ExecPlan::default()).await;

    let handle = connect_as_root(&harness).await;

    // sftp subsystem: request must fail, not hang.
    let mut subsystem_channel = handle.channel_open_session().await.expect("open channel");
    subsystem_channel
        .request_subsystem(true, "sftp")
        .await
        .expect("send subsystem request");
    let failure = tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            match subsystem_channel.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) => return false,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .expect("subsystem reply timed out");
    assert!(failure, "sftp subsystem request must fail");

    // direct-tcpip channel open must be rejected.
    let open_result = tokio::time::timeout(
        TEST_TIMEOUT,
        handle.channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 3000),
    )
    .await
    .expect("direct-tcpip open timed out");
    assert!(
        open_result.is_err(),
        "direct-tcpip channel open must be rejected"
    );

    // The same connection still serves a normal exec afterwards.
    let mut exec_channel = handle.channel_open_session().await.expect("open channel");
    exec_channel.exec(true, "true").await.expect("exec request");
    let capture = drain_channel(&mut exec_channel).await;
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 7. Disconnect kills the delegated execution
// ---------------------------------------------------------------------------

#[tokio::test]
async fn client_disconnect_kills_running_execution() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: Vec::new(),
            wait: exit_with_code(0),
            hold: true,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let channel = handle.channel_open_session().await.expect("open channel");
    channel
        .exec(true, "sleep 1000")
        .await
        .expect("exec request");
    harness
        .fake
        .wait_for(|state| state.exec_requests.first().cloned())
        .await;

    handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .expect("disconnect");

    let kill = harness
        .fake
        .wait_for(|state| state.kill_calls.first().cloned())
        .await;
    assert_eq!(kill.execution_id, "exec-1");
    assert_eq!(kill.signal, 9, "default kill signal must be SIGKILL");
}

/// Regression: pump_output's Attach read used to have no way to stop once
/// the SSH channel closed if the guest process was wedged and Kill's RPC
/// didn't actually free it (kill_ineffective simulates exactly that) —
/// output.message().await then blocked forever, leaking the Attach stream
/// and channel write half. kill_running now cancels the pump independent of
/// Kill's outcome, which surfaces here as the SSH service actually dropping
/// its end of the Attach stream (attach_client_dropped) rather than leaving
/// it open forever waiting on a release that will never come.
#[tokio::test]
async fn client_disconnect_stops_output_pump_even_when_kill_is_ineffective() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: Vec::new(),
            wait: exit_with_code(0),
            hold: true,
            kill_ineffective: true,
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let channel = handle.channel_open_session().await.expect("open channel");
    channel
        .exec(true, "sleep 1000")
        .await
        .expect("exec request");
    harness
        .fake
        .wait_for(|state| state.exec_requests.first().cloned())
        .await;

    handle
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .expect("disconnect");

    // Kill is still attempted (recorded) even though it won't actually
    // release the hold in this test.
    let kill = harness
        .fake
        .wait_for(|state| state.kill_calls.first().cloned())
        .await;
    assert_eq!(kill.execution_id, "exec-1");

    // The real assertion: the SSH service must give up on Attach on its own,
    // independent of Kill's outcome. wait_for's TEST_TIMEOUT bound is what
    // makes this a real regression test — pre-fix, this never becomes true
    // and the test times out instead of passing.
    harness
        .fake
        .wait_for(|state| state.attach_client_dropped.contains("exec-1").then_some(()))
        .await;
}

// ---------------------------------------------------------------------------
// 8. Concurrent session channels on one connection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_channels_get_distinct_executions_and_routed_output() {
    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: vec![stdout_event(b"alpha-output")],
            wait: exit_with_code(1),
            hold: true,
            ..Default::default()
        })
        .await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: vec![stdout_event(b"beta-output")],
            wait: exit_with_code(2),
            hold: true,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut first = handle.channel_open_session().await.expect("open channel");
    let mut second = handle.channel_open_session().await.expect("open channel");
    first.exec(true, "first-cmd").await.expect("exec");
    second.exec(true, "second-cmd").await.expect("exec");

    let requests = harness
        .fake
        .wait_for(|state| (state.execs.len() == 2).then(|| state.exec_requests.clone()))
        .await;
    let commands: Vec<&str> = requests.iter().map(|r| r.args[1].as_str()).collect();
    assert!(commands.contains(&"first-cmd") && commands.contains(&"second-cmd"));

    harness.fake.release("exec-1").await;
    harness.fake.release("exec-2").await;

    let (first_capture, second_capture) =
        tokio::join!(drain_channel(&mut first), drain_channel(&mut second));

    // Fake assigns execution ids in exec order, which may not match channel
    // order; match captures to plans via their distinct payloads.
    let mut captures = [first_capture, second_capture];
    captures.sort_by_key(|c| c.stdout.clone());
    assert_eq!(captures[0].stdout, b"alpha-output");
    assert_eq!(captures[0].exit_status, Some(1));
    assert_eq!(captures[1].stdout, b"beta-output");
    assert_eq!(captures[1].exit_status, Some(2));
}

// ---------------------------------------------------------------------------
// 9. Log redaction of exec command content
// ---------------------------------------------------------------------------

/// `MakeWriter` collecting all log output; usable from any thread.
///
/// A plain OS mutex (not `tokio::sync::Mutex`): `tracing` invokes the
/// writer synchronously from inside the async runtime, and blocking on an
/// async mutex there risks deadlocking a current-thread test runtime.
#[derive(Clone, Default)]
struct LogCapture(Arc<std::sync::Mutex<Vec<u8>>>);

impl LogCapture {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
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

/// Installs (once per test process) a global subscriber writing into a
/// shared capture. Deliberately global and process-wide, not
/// `set_default`-scoped, so it reliably sees events from tests running
/// concurrently on other threads.
fn install_global_capture() -> LogCapture {
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

/// Regression: the exec handler used to log the raw command at `debug!`,
/// which may carry secrets (e.g. `curl -u user:token`). It must now log
/// only the command length, matching `env_request`'s redaction of values.
#[tokio::test]
async fn exec_command_content_never_reaches_the_logs() {
    let capture = install_global_capture();
    let canary = "curl -u test-canary-user:test-canary-secret-9f3c1a http://example.invalid";

    let harness = start_harness().await;
    harness
        .fake
        .push_plan(ExecPlan {
            outputs: vec![stdout_event(b"ok")],
            wait: exit_with_code(0),
            hold: false,
            ..Default::default()
        })
        .await;

    let handle = connect_as_root(&harness).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, canary).await.expect("exec request");
    let _ = drain_channel(&mut channel).await;

    let logs = capture.contents();
    assert!(
        !logs.contains(canary),
        "the raw exec command must never reach the logs: {logs}"
    );
    assert!(
        !logs.contains("test-canary-secret-9f3c1a"),
        "the secret embedded in the exec command leaked into the logs: {logs}"
    );
}
