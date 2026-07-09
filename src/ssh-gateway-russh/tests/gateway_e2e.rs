//! End-to-end gateway tests: a real russh client on one side, a fake Runner
//! speaking the HTTP upgrade handshake + frame protocol on the other.
//! No VM, no real Runner.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use boxlite_session_frame::{
    ErrorPayload, ExitStatusPayload, Frame, FrameType, OpenExecPayload, PtyRequestPayload,
    PtyResizePayload, CONTROL_CHANNEL_ID, MAX_PAYLOAD, PROTOCOL_VERSION,
};
use boxlite_ssh_gateway::{Gateway, SshTarget};
use common::{
    connect_authenticated, connect_client, drain_channel, test_config, FakeRunner, RunnerEvent,
    RunnerScript, StubHostedApi, TEST_TIMEOUT, TOKEN, TOKEN_ID,
};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, MethodKind};

struct TestBed {
    gateway: Gateway,
    runner: FakeRunner,
    api: Arc<StubHostedApi>,
    _tmp: tempfile::TempDir,
}

async fn testbed_with(script: RunnerScript) -> TestBed {
    let runner = FakeRunner::spawn(script);
    let api = StubHostedApi::valid(&runner.domain());
    let tmp = tempfile::tempdir().expect("tempdir");
    let gateway = Gateway::with_hosted_api(test_config(tmp.path()), api.clone())
        .await
        .expect("gateway");
    TestBed {
        gateway,
        runner,
        api,
        _tmp: tmp,
    }
}

async fn testbed() -> TestBed {
    testbed_with(RunnerScript::ready()).await
}

async fn wait_upgraded(runner: &mut FakeRunner) -> HashMap<String, String> {
    loop {
        match runner.next_event().await {
            RunnerEvent::Upgraded { headers } => return headers,
            RunnerEvent::Frame(frame) => panic!("frame before upgrade: {frame:?}"),
            _ => continue,
        }
    }
}

fn exit_status_frame(channel: u32, code: i32) -> Frame {
    let payload = serde_json::to_vec(&ExitStatusPayload { code }).unwrap();
    Frame::data(FrameType::ExitStatus, channel, payload)
}

fn finish_channel(runner: &FakeRunner, channel: u32, code: i32) {
    runner.inject(exit_status_frame(channel, code));
    runner.inject(Frame::data(FrameType::Eof, channel, Vec::new()));
    runner.inject(Frame::data(FrameType::Close, channel, Vec::new()));
}

fn raw_frame_header(
    version: u8,
    frame_type: u8,
    flags: u16,
    channel_id: u32,
    request_id: u32,
    payload_length: u32,
) -> Vec<u8> {
    let mut bytes = vec![version, frame_type];
    bytes.extend_from_slice(&flags.to_be_bytes());
    bytes.extend_from_slice(&channel_id.to_be_bytes());
    bytes.extend_from_slice(&request_id.to_be_bytes());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes
}

// ---------------------------------------------------------------------------
// 1+2. Exec round trip, upgrade headers, exit statuses
// ---------------------------------------------------------------------------

#[tokio::test]
async fn exec_round_trips_output_and_exit_status() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");

    let headers = wait_upgraded(&mut bed.runner).await;
    assert_eq!(
        headers.get("upgrade").map(String::as_str),
        Some("boxlite-session-stream")
    );
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer test-runner-secret")
    );
    assert_eq!(
        headers.get("x-boxlite-token-id").map(String::as_str),
        Some(TOKEN_ID)
    );
    assert_eq!(
        headers.get("x-boxlite-unix-user").map(String::as_str),
        Some("root")
    );
    let session_header = headers
        .get("x-boxlite-session-id")
        .expect("session id header");
    assert!(!session_header.is_empty());
    assert!(
        !session_header.contains(TOKEN),
        "session id must not embed the token"
    );

    channel.exec(true, "echo hi").await.expect("exec request");
    let open = bed.runner.next_frame().await;
    assert_eq!(open.header.frame_type, FrameType::OpenExec);
    assert_ne!(open.header.channel_id, CONTROL_CHANNEL_ID);
    assert_ne!(open.header.request_id, 0);
    let payload: OpenExecPayload = serde_json::from_slice(&open.payload).expect("payload");
    assert_eq!(payload.command, "echo hi");

    let frame_channel = open.header.channel_id;
    bed.runner.inject(Frame::data(
        FrameType::Stdout,
        frame_channel,
        b"hi\n".to_vec(),
    ));
    bed.runner.inject(Frame::data(
        FrameType::Stderr,
        frame_channel,
        b"warn\n".to_vec(),
    ));
    finish_channel(&bed.runner, frame_channel, 0);

    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.stdout, b"hi\n");
    assert_eq!(capture.stderr, b"warn\n");
    assert_eq!(capture.exit_status, Some(0));
    assert!(capture.saw_eof, "EOF must reach the client");
}

#[tokio::test]
async fn nonzero_exit_status_reaches_the_client() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "exit 42").await.expect("exec request");

    let open = bed.runner.next_frame().await;
    assert_eq!(open.header.frame_type, FrameType::OpenExec);
    finish_channel(&bed.runner, open.header.channel_id, 42);

    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.exit_status, Some(42));
}

// ---------------------------------------------------------------------------
// 3. PTY ordering and resize
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pty_request_precedes_open_shell_and_resize_follows() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");

    channel
        .request_pty(true, "xterm-256color", 120, 40, 800, 600, &[])
        .await
        .expect("pty request");
    channel.request_shell(true).await.expect("shell request");

    let pty = bed.runner.next_frame().await;
    assert_eq!(
        pty.header.frame_type,
        FrameType::PtyRequest,
        "PTY_REQUEST must arrive before OPEN_SHELL"
    );
    let pty_payload: PtyRequestPayload = serde_json::from_slice(&pty.payload).expect("payload");
    assert_eq!(pty_payload.term, "xterm-256color");
    assert_eq!((pty_payload.cols, pty_payload.rows), (120, 40));
    assert_eq!((pty_payload.width_px, pty_payload.height_px), (800, 600));

    let shell = bed.runner.next_frame().await;
    assert_eq!(shell.header.frame_type, FrameType::OpenShell);
    assert_eq!(shell.header.channel_id, pty.header.channel_id);
    assert_eq!(shell.payload, b"{}");

    channel
        .window_change(200, 50, 1024, 768)
        .await
        .expect("window change");
    let resize = bed.runner.next_frame().await;
    assert_eq!(resize.header.frame_type, FrameType::PtyResize);
    let resize_payload: PtyResizePayload =
        serde_json::from_slice(&resize.payload).expect("payload");
    assert_eq!((resize_payload.cols, resize_payload.rows), (200, 50));

    finish_channel(&bed.runner, shell.header.channel_id, 0);
    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 4. Stdin then EOF: channel stays open, runner can still send output
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stdin_and_eof_forwarded_channel_survives_for_output() {
    // Deliberately not valid UTF-8.
    let stdin_payload: &[u8] = &[0x00, 0xff, 0xfe, b'h', b'i', 0x80, 0x00];
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "cat").await.expect("exec request");

    let open = bed.runner.next_frame().await;
    assert_eq!(open.header.frame_type, FrameType::OpenExec);
    let frame_channel = open.header.channel_id;

    channel.data(stdin_payload).await.expect("send stdin");
    channel.eof().await.expect("send eof");

    let mut stdin_bytes = Vec::new();
    loop {
        let frame = bed.runner.next_frame().await;
        match frame.header.frame_type {
            FrameType::Stdin => {
                assert_eq!(frame.header.channel_id, frame_channel);
                stdin_bytes.extend_from_slice(&frame.payload);
            }
            FrameType::Eof => {
                assert_eq!(frame.header.channel_id, frame_channel);
                break;
            }
            other => panic!("unexpected frame while waiting for EOF: {other:?}"),
        }
    }
    assert_eq!(stdin_bytes, stdin_payload, "stdin must round-trip exactly");

    // Half-close only: the runner can still stream output afterwards.
    bed.runner.inject(Frame::data(
        FrameType::Stdout,
        frame_channel,
        b"after-eof".to_vec(),
    ));
    finish_channel(&bed.runner, frame_channel, 0);

    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.stdout, b"after-eof");
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 5. Binary safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn all_byte_values_round_trip_unchanged() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "binary").await.expect("exec request");

    let open = bed.runner.next_frame().await;
    let frame_channel = open.header.channel_id;
    bed.runner.inject(Frame::data(
        FrameType::Stdout,
        frame_channel,
        all_bytes.clone(),
    ));
    finish_channel(&bed.runner, frame_channel, 0);

    let capture = drain_channel(&mut channel).await;
    assert_eq!(
        capture.stdout, all_bytes,
        "bytes 0x00-0xFF must be unmodified"
    );
}

// ---------------------------------------------------------------------------
// 6. Large output does not deadlock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn four_mebibyte_output_streams_without_deadlock() {
    const CHUNKS: usize = 16; // 16 x 256 KiB = 4 MiB
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "bigdump").await.expect("exec request");

    let open = bed.runner.next_frame().await;
    let frame_channel = open.header.channel_id;

    let mut expected = Vec::with_capacity(CHUNKS * MAX_PAYLOAD);
    for i in 0..CHUNKS {
        let chunk = vec![i as u8; MAX_PAYLOAD];
        expected.extend_from_slice(&chunk);
        bed.runner
            .inject(Frame::data(FrameType::Stdout, frame_channel, chunk));
    }
    finish_channel(&bed.runner, frame_channel, 0);

    let capture = drain_channel(&mut channel).await;
    assert_eq!(capture.stdout.len(), CHUNKS * MAX_PAYLOAD);
    assert_eq!(capture.stdout, expected, "large output must arrive intact");
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 7. Invalid token: rejected before any Runner traffic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_token_is_rejected_and_never_reaches_the_runner() {
    let runner = FakeRunner::spawn(RunnerScript::ready());
    let api = StubHostedApi::invalid();
    let tmp = tempfile::tempdir().expect("tempdir");
    let gateway = Gateway::with_hosted_api(test_config(tmp.path()), api.clone())
        .await
        .expect("gateway");

    let mut handle = connect_client(&gateway).await;
    let auth = handle
        .authenticate_none("stolen-or-revoked-token")
        .await
        .expect("auth rpc");
    assert!(!auth.success(), "invalid token must be rejected");

    assert_eq!(api.validate_call_count(), 1, "hosted API must be consulted");
    assert_eq!(
        runner.tcp_connection_count(),
        0,
        "no Runner connection may be opened for an invalid token"
    );
    let snapshot = gateway.metrics().snapshot();
    assert_eq!(snapshot.route_failures.get("token_invalid"), Some(&1));
}

// ---------------------------------------------------------------------------
// 8. Revoked token: new sessions fail closed
// ---------------------------------------------------------------------------

/// Force-disconnect of existing sessions on revocation is explicitly OUT of
/// Stage-1 scope: only NEW sessions must fail closed once the validator says
/// `valid:false`.
#[tokio::test]
async fn revoked_token_rejects_new_sessions_only() {
    let mut bed = testbed().await;
    // First validation succeeds, every later one reports the token revoked.
    bed.api.push_validation(Ok(common::valid_validation()));
    bed.api
        .set_fallback(Ok(boxlite_ssh_gateway::token::SshAccessValidation {
            valid: false,
            box_id: String::new(),
            unix_user: None,
            token_id: None,
        }));

    let first = connect_authenticated(&bed.gateway).await;
    let mut first_channel = first.channel_open_session().await.expect("open channel");
    first_channel.exec(true, "sleep").await.expect("exec");
    let open = bed.runner.next_frame().await;
    let frame_channel = open.header.channel_id;

    // A new SSH session with the same token now fails closed.
    let mut second = connect_client(&bed.gateway).await;
    let auth = second.authenticate_none(TOKEN).await.expect("auth rpc");
    assert!(!auth.success(), "revoked token must reject new sessions");
    assert_eq!(bed.api.validate_call_count(), 2);

    // The existing session keeps working (Stage-1 documented behavior).
    finish_channel(&bed.runner, frame_channel, 7);
    let capture = drain_channel(&mut first_channel).await;
    assert_eq!(capture.exit_status, Some(7));
}

// ---------------------------------------------------------------------------
// 9. Pre-upgrade HTTP failures map to clean SSH failures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pre_upgrade_failures_map_to_typed_reasons_without_hanging() {
    let cases = [
        (409, r#"{"code":"BOX_STOPPED"}"#, "box_stopped"),
        (503, r#"{"code":"BOX_NOT_READY"}"#, "runner_not_ready"),
        (404, r#"{"code":"NOT_FOUND"}"#, "unknown_box"),
        (401, r#"{"code":"UNAUTHORIZED"}"#, "runner_auth_rejected"),
    ];
    for (status, body, expected_reason) in cases {
        let bed = testbed_with(RunnerScript::rejecting_upgrade(status, body)).await;
        let handle = connect_authenticated(&bed.gateway).await;
        let result = tokio::time::timeout(TEST_TIMEOUT, handle.channel_open_session()).await;
        let opened = result.unwrap_or_else(|_| panic!("status {status}: channel open hung"));
        assert!(
            opened.is_err(),
            "status {status}: channel open must fail closed"
        );
        let snapshot = bed.gateway.metrics().snapshot();
        assert_eq!(
            snapshot.route_failures.get(expected_reason),
            Some(&1),
            "status {status}: wrong reason label: {:?}",
            snapshot.route_failures
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Runner unavailable (connection refused)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unreachable_runner_fails_closed_with_metric() {
    // Bind a port and drop the listener so connections are refused.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let api = StubHostedApi::valid(&format!("127.0.0.1:{dead_port}"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let gateway = Gateway::with_hosted_api(test_config(tmp.path()), api)
        .await
        .expect("gateway");

    let handle = connect_authenticated(&gateway).await;
    let opened = tokio::time::timeout(TEST_TIMEOUT, handle.channel_open_session())
        .await
        .expect("channel open must not hang");
    assert!(opened.is_err(), "channel open must fail closed");

    let snapshot = gateway.metrics().snapshot();
    assert_eq!(snapshot.route_failures.get("runner_unavailable"), Some(&1));
}

// ---------------------------------------------------------------------------
// 11. Unsupported requests are rejected; the connection survives
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unsupported_requests_fail_cleanly_and_exec_still_works() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;

    // sftp subsystem: request must fail, not hang.
    let mut subsystem_channel = handle.channel_open_session().await.expect("open channel");
    subsystem_channel
        .request_subsystem(true, "sftp")
        .await
        .expect("send subsystem request");
    let failed = tokio::time::timeout(TEST_TIMEOUT, async {
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
    assert!(failed, "sftp subsystem request must fail");

    // direct-tcpip channel open must be rejected.
    let open_result = tokio::time::timeout(
        TEST_TIMEOUT,
        handle.channel_open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 3000),
    )
    .await
    .expect("direct-tcpip open timed out");
    assert!(open_result.is_err(), "direct-tcpip must be rejected");

    // The same connection still serves a normal exec afterwards.
    let mut exec_channel = handle.channel_open_session().await.expect("open channel");
    exec_channel.exec(true, "true").await.expect("exec request");
    let open = loop {
        let frame = bed.runner.next_frame().await;
        if frame.header.frame_type == FrameType::OpenExec {
            break frame;
        }
    };
    finish_channel(&bed.runner, open.header.channel_id, 0);
    let capture = drain_channel(&mut exec_channel).await;
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 12. Protocol error injection: ERROR on channel 0, deterministic close
// ---------------------------------------------------------------------------

async fn assert_protocol_error_closes_connection(bad_bytes: Vec<u8>) {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "victim").await.expect("exec request");
    let open = bed.runner.next_frame().await;
    assert_eq!(open.header.frame_type, FrameType::OpenExec);

    bed.runner.inject_raw(bad_bytes);

    let frames = bed.runner.wait_stream_closed().await;
    let error = frames
        .iter()
        .find(|f| f.header.frame_type == FrameType::Error)
        .expect("gateway must send ERROR before closing");
    assert_eq!(
        error.header.channel_id, CONTROL_CHANNEL_ID,
        "protocol errors are connection-level (channel 0)"
    );
    let payload: ErrorPayload = serde_json::from_slice(&error.payload).expect("payload");
    assert_eq!(payload.code, "protocol_error");

    // The SSH channel is torn down too, without hanging the client.
    drain_channel(&mut channel).await;
}

#[tokio::test]
async fn unknown_frame_type_triggers_error_and_close() {
    assert_protocol_error_closes_connection(raw_frame_header(PROTOCOL_VERSION, 42, 0, 1, 0, 0))
        .await;
}

#[tokio::test]
async fn unknown_protocol_version_triggers_error_and_close() {
    assert_protocol_error_closes_connection(raw_frame_header(9, 6, 0, 1, 0, 0)).await;
}

#[tokio::test]
async fn oversized_payload_length_triggers_error_and_close() {
    assert_protocol_error_closes_connection(raw_frame_header(
        PROTOCOL_VERSION,
        6,
        0,
        1,
        0,
        (MAX_PAYLOAD as u32) + 1,
    ))
    .await;
}

// ---------------------------------------------------------------------------
// Late frames for a closed channel are ignored (Runner contract)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn late_frames_on_closed_channel_are_ignored() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let channel = handle.channel_open_session().await.expect("open channel");
    channel
        .exec(true, "short-lived")
        .await
        .expect("exec request");
    let open = bed.runner.next_frame().await;
    let closed_channel = open.header.channel_id;

    // Client closes; the gateway must deregister and send CLOSE.
    channel.close().await.expect("client close");
    loop {
        let frame = bed.runner.next_frame().await;
        if frame.header.frame_type == FrameType::Close && frame.header.channel_id == closed_channel
        {
            break;
        }
    }

    // One in-flight STDOUT after CLOSE: NOT a protocol error; the gateway
    // must silently ignore it and keep the connection alive.
    bed.runner.inject(Frame::data(
        FrameType::Stdout,
        closed_channel,
        b"late".to_vec(),
    ));

    // A subsequent exec on a new channel still works over the same stream.
    let mut next_channel = handle.channel_open_session().await.expect("open channel");
    next_channel.exec(true, "still-works").await.expect("exec");
    let open = loop {
        let frame = bed.runner.next_frame().await;
        if frame.header.frame_type == FrameType::OpenExec {
            break frame;
        }
    };
    assert_ne!(open.header.channel_id, closed_channel);
    finish_channel(&bed.runner, open.header.channel_id, 0);
    let capture = drain_channel(&mut next_channel).await;
    assert_eq!(capture.exit_status, Some(0));
}

// ---------------------------------------------------------------------------
// 13. Multiplexing: two concurrent exec channels over one stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_channels_use_distinct_ids_and_route_output_correctly() {
    let mut bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;
    let mut first = handle.channel_open_session().await.expect("open channel");
    let mut second = handle.channel_open_session().await.expect("open channel");
    first.exec(true, "first-cmd").await.expect("exec");
    second.exec(true, "second-cmd").await.expect("exec");

    let mut opens = HashMap::new();
    while opens.len() < 2 {
        let frame = bed.runner.next_frame().await;
        if frame.header.frame_type == FrameType::OpenExec {
            let payload: OpenExecPayload = serde_json::from_slice(&frame.payload).unwrap();
            opens.insert(payload.command, frame.header.channel_id);
        }
    }
    let first_id = opens["first-cmd"];
    let second_id = opens["second-cmd"];
    assert_ne!(first_id, second_id, "channel ids must be distinct");
    assert_ne!(first_id, CONTROL_CHANNEL_ID);
    assert_ne!(second_id, CONTROL_CHANNEL_ID);

    bed.runner
        .inject(Frame::data(FrameType::Stdout, first_id, b"alpha".to_vec()));
    bed.runner
        .inject(Frame::data(FrameType::Stdout, second_id, b"beta".to_vec()));
    finish_channel(&bed.runner, first_id, 1);
    finish_channel(&bed.runner, second_id, 2);

    let (first_capture, second_capture) =
        tokio::join!(drain_channel(&mut first), drain_channel(&mut second));
    assert_eq!(first_capture.stdout, b"alpha");
    assert_eq!(first_capture.exit_status, Some(1));
    assert_eq!(second_capture.stdout, b"beta");
    assert_eq!(second_capture.exit_status, Some(2));
}

/// Regression: `channel_open_session` had no upper bound on channels per
/// authenticated connection, so a single valid-token client could multiply
/// forwarder tasks and mux registrations against one Runner without limit.
/// The connection itself must survive going over the cap — only the
/// over-the-limit open is rejected.
#[tokio::test]
async fn channel_open_beyond_the_per_connection_cap_is_rejected() {
    // Must match `MAX_CHANNELS_PER_CONNECTION` in src/server.rs — not part
    // of the public API, so duplicated here rather than exported solely for
    // this test.
    const MAX_CHANNELS_PER_CONNECTION: usize = 64;

    let bed = testbed().await;
    let handle = connect_authenticated(&bed.gateway).await;

    let mut channels = Vec::new();
    for _ in 0..MAX_CHANNELS_PER_CONNECTION {
        channels.push(
            tokio::time::timeout(TEST_TIMEOUT, handle.channel_open_session())
                .await
                .expect("open timed out")
                .expect("open within the cap must succeed"),
        );
    }

    let over_cap = tokio::time::timeout(TEST_TIMEOUT, handle.channel_open_session())
        .await
        .expect("open timed out");
    assert!(over_cap.is_err(), "open beyond the cap must be rejected");
}

// ---------------------------------------------------------------------------
// 14. Metrics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connections_total_counts_every_accepted_connection() {
    let bed = testbed().await;
    let _first = connect_authenticated(&bed.gateway).await;
    let _second = connect_authenticated(&bed.gateway).await;
    let snapshot = bed.gateway.metrics().snapshot();
    assert_eq!(snapshot.connections_total, 2);
    assert!(snapshot.route_failures.is_empty());
}

/// Regression: `Gateway::run`'s accept loop used to spawn one task per raw
/// TCP connection with no cap, so an unauthenticated flood could exhaust
/// file descriptors before any auth check ran. A connection beyond the
/// configured cap must be dropped immediately (no SSH banner, no auth
/// attempt), and the rejection must be visible on the metrics.
#[tokio::test]
async fn run_drops_connections_beyond_the_configured_cap() {
    use tokio::io::AsyncReadExt;

    let api = StubHostedApi::valid("runner.internal:3003");
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path());
    config.max_connections = 1;
    let gateway = Gateway::with_hosted_api(config, api)
        .await
        .expect("gateway");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let run_gateway = gateway.clone();
    tokio::spawn(async move {
        let _ = run_gateway.run(listener).await;
    });

    // Occupy the only permit: connect and hold the socket open without ever
    // completing the SSH handshake, so the accept loop's task never
    // releases the permit for the duration of this test.
    let _held = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect #1 timed out")
        .expect("connect #1");

    // Deterministic handoff: `record_connection()` only runs once the
    // spawned task starts, which only happens after the permit for
    // connection #1 was already acquired in the accept loop — so waiting
    // for the counter proves the permit is held, without a guessed sleep.
    tokio::time::timeout(TEST_TIMEOUT, async {
        while gateway.metrics().snapshot().connections_total < 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("first connection was never accepted");

    let mut second = tokio::time::timeout(TEST_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect #2 timed out")
        .expect("connect #2");
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(TEST_TIMEOUT, second.read(&mut buf))
        .await
        .expect("gateway must not hang on a connection over the cap")
        .expect("read");
    assert_eq!(
        n, 0,
        "connection beyond the cap must be closed with no SSH banner"
    );

    let snapshot = gateway.metrics().snapshot();
    assert_eq!(snapshot.connections_total, 1);
    assert_eq!(snapshot.route_failures.get("connection_limit"), Some(&1));
}

// ---------------------------------------------------------------------------
// 15. Log redaction across a whole session
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_session_never_logs_the_token() {
    let capture = common::install_global_capture();
    // Unique to this test so the capture (which sees the whole process) can
    // be attributed: the redacted prefix must appear, the full token never.
    const CANARY_TOKEN: &str = "canary42-redaction-e2e-token-abcdefghijklmnop";

    let mut bed = testbed().await;
    let mut handle = connect_client(&bed.gateway).await;
    let auth = handle
        .authenticate_none(CANARY_TOKEN)
        .await
        .expect("auth rpc");
    assert!(auth.success(), "stub accepts any token");
    let mut channel = handle.channel_open_session().await.expect("open channel");
    channel.exec(true, "echo hi").await.expect("exec request");
    let open = bed.runner.next_frame().await;
    finish_channel(&bed.runner, open.header.channel_id, 0);
    drain_channel(&mut channel).await;

    // Also exercise a failed auth (another log-heavy path).
    let mut rejected = connect_client(&bed.gateway).await;
    bed.api
        .push_validation(Ok(boxlite_ssh_gateway::token::SshAccessValidation {
            valid: false,
            box_id: String::new(),
            unix_user: None,
            token_id: None,
        }));
    let _ = rejected.authenticate_none(CANARY_TOKEN).await;

    let logs = capture.contents();
    let prefix: String = CANARY_TOKEN.chars().take(8).collect();
    assert!(
        logs.contains(&prefix),
        "this session's audit events must be captured"
    );
    assert!(
        !logs.contains(CANARY_TOKEN),
        "the full token appeared in logs: {logs}"
    );
    // The capture spans every concurrently running test: no event in the
    // whole process may carry the shared token or the service credentials.
    assert!(
        !logs.contains(TOKEN),
        "the shared test token appeared in logs"
    );
    assert!(
        !logs.contains("test-runner-secret") && !logs.contains("test-hosted-secret"),
        "service credentials appeared in logs"
    );
}

// ---------------------------------------------------------------------------
// Feature gate and auth method steering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn feature_gate_off_rejects_before_the_hosted_api_is_consulted() {
    let runner = FakeRunner::spawn(RunnerScript::ready());
    let api = StubHostedApi::valid(&runner.domain());
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut config = test_config(tmp.path());
    config.ssh_target = SshTarget::Off;
    let gateway = Gateway::with_hosted_api(config, api.clone())
        .await
        .expect("gateway");

    let mut handle = connect_client(&gateway).await;
    let auth = handle.authenticate_none(TOKEN).await.expect("auth rpc");
    assert!(!auth.success(), "gate off must reject");
    assert_eq!(
        api.validate_call_count(),
        0,
        "gate must fail before validation"
    );
    assert_eq!(
        gateway
            .metrics()
            .snapshot()
            .route_failures
            .get("feature_disabled"),
        Some(&1)
    );
}

#[tokio::test]
async fn publickey_and_password_are_steered_to_none_which_succeeds() {
    let bed = testbed().await;
    let mut handle = connect_client(&bed.gateway).await;

    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("keygen");
    let pk_auth = handle
        .authenticate_publickey(TOKEN, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .expect("auth rpc");
    match pk_auth {
        russh::client::AuthResult::Failure {
            remaining_methods, ..
        } => {
            assert!(
                remaining_methods.contains(&MethodKind::None),
                "server must steer the client to none auth"
            );
        }
        other => panic!("publickey must be rejected, got {other:?}"),
    }

    let pw_auth = handle
        .authenticate_password(TOKEN, "irrelevant")
        .await
        .expect("auth rpc");
    assert!(!pw_auth.success(), "password auth must be rejected");

    let none_auth = handle.authenticate_none(TOKEN).await.expect("auth rpc");
    assert!(none_auth.success(), "none auth must then succeed");
}
