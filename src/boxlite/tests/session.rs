//! Integration tests for guest SSH session readiness and raw stream open.
//!
//! Requires VM infrastructure (boxlite-shim/boxlite-guest binaries and a
//! hypervisor) — run with the `vm` nextest profile. `boxlite-guest` serves
//! SSH sessions in-process on vsock, bridged to the per-box `ssh.sock` by
//! libkrun.

mod common;

use std::time::{Duration, Instant};

use boxlite::runtime::options::BoxliteOptions;
use boxlite::{BoxSessionErrorCode, BoxliteRuntime};
use tokio::io::AsyncReadExt;

/// Generous bound for the guest to boot and the SSH service to start listening.
const SESSION_READY_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
async fn session_ready_then_open_stream_reads_ssh_banner() {
    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime.create(common::alpine_opts(), None).await.unwrap();
    let box_id = handle.id().clone();

    handle.start().await.expect("start box");

    // Poll the live probe until the guest SSH service is up.
    let deadline = Instant::now() + SESSION_READY_TIMEOUT;
    let mut last_reason = None;
    let ready = loop {
        let readiness = handle.session_ready("ssh").await.expect("probe ssh");
        if readiness.ready {
            break true;
        }
        last_reason = readiness.reason;
        if Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        ready,
        "session_ready(\"ssh\") never became ready within {SESSION_READY_TIMEOUT:?}; \
         last reason: {last_reason:?}"
    );

    // Raw stream open: the first bytes the caller reads must be the SSH
    // server identification banner (the runtime consumed nothing).
    let mut stream = handle
        .open_session_stream("ssh")
        .await
        .expect("open_session_stream after ready probe");
    let mut prefix = [0u8; 8];
    stream
        .read_exact(&mut prefix)
        .await
        .expect("read SSH banner prefix");
    assert_eq!(
        &prefix,
        b"SSH-2.0-",
        "expected SSH identification banner, got: {:?}",
        String::from_utf8_lossy(&prefix)
    );
    drop(stream);

    // A stopped box must report BoxStopped (via a fresh handle — stop()
    // invalidates the old one).
    handle.stop().await.expect("stop box");
    let fresh = runtime
        .get(box_id.as_str())
        .await
        .expect("get box")
        .expect("box persists after stop (auto_remove=false)");
    let readiness = fresh.session_ready("ssh").await.expect("probe stopped box");
    assert!(!readiness.ready);
    let reason = readiness.reason.expect("not-ready must carry a reason");
    assert_eq!(reason.code, BoxSessionErrorCode::BoxStopped);
    assert!(!reason.retryable);

    let open_err = fresh
        .open_session_stream("ssh")
        .await
        .expect_err("open_session_stream on a stopped box must fail");
    match open_err {
        boxlite::OpenSessionError::Session(e) => {
            assert_eq!(e.code, BoxSessionErrorCode::BoxStopped)
        }
        other => panic!("expected a session-class error, got: {other:?}"),
    }

    // Cleanup
    runtime.remove(box_id.as_str(), false).await.unwrap();
    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}

/// Regression: `open_session_stream` used to remap an unsupported `service`
/// into `BoxSessionError{code: Internal}`, so the same bad argument reported
/// a different error class than `session_ready` for the identical input.
/// Both entry points validate the service name before touching any live
/// state, so this doesn't need the box to be started.
#[tokio::test]
async fn invalid_service_reports_the_same_error_class_from_both_entry_points() {
    let home = boxlite_test_utils::home::PerTestBoxHome::new();
    let runtime = BoxliteRuntime::new(BoxliteOptions {
        home_dir: home.path.clone(),
        image_registries: common::test_registries(),
    })
    .expect("create runtime");
    let handle = runtime.create(common::alpine_opts(), None).await.unwrap();
    let box_id = handle.id().clone();

    let ready_err = handle
        .session_ready("bogus")
        .await
        .expect_err("unsupported service must be rejected before any live probe");
    assert!(
        matches!(ready_err, boxlite::BoxliteError::InvalidArgument(_)),
        "got: {ready_err:?}"
    );

    let open_err = handle
        .open_session_stream("bogus")
        .await
        .expect_err("unsupported service must be rejected before any live probe");
    match open_err {
        boxlite::OpenSessionError::Argument(e) => {
            assert!(
                matches!(e, boxlite::BoxliteError::InvalidArgument(_)),
                "got: {e:?}"
            );
        }
        other => panic!("expected an Argument-class error, got a session error: {other:?}"),
    }

    runtime.remove(box_id.as_str(), false).await.unwrap();
    let _ = runtime.shutdown(Some(common::TEST_SHUTDOWN_TIMEOUT)).await;
}
