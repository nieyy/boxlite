//! In-process SSH session service for BoxLite guests.
//!
//! Runs a russh-backed SSH server on the shared vsock port
//! ([`GUEST_SSH_PORT`]), delegating every shell/exec to this same process's
//! Execution gRPC service via an in-process `tonic` connector — no socket,
//! no separate process, no sibling daemon to supervise.
//!
//! Connection handling runs on its own dedicated tokio runtime so that a
//! panic confined to one SSH session's handling code does not force-exit the
//! whole guest agent; see `crate::panic_domain` and `main.rs`'s panic hook.

mod backoff;
mod bridge;
mod server;
#[cfg(test)]
mod tests;

use std::sync::{Arc, OnceLock};

use boxlite_shared::constants::network::GUEST_SSH_PORT;
use boxlite_shared::errors::{BoxliteError, BoxliteResult};
use boxlite_shared::ExecutionClient;
use tokio::runtime::Runtime;
use tracing::{info, warn};

use super::server::{grpc_router, GuestServer};
use server::SshServer;

/// Worker threads dedicated to SSH connection handling, isolated from the
/// main guest runtime.
const SSH_RUNTIME_WORKER_THREADS: usize = 2;

fn ssh_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(SSH_RUNTIME_WORKER_THREADS)
            .thread_name("boxlite-ssh")
            .on_thread_start(crate::panic_domain::mark_current_thread_as_ssh)
            .enable_all()
            .build()
            .expect("build dedicated SSH runtime")
    })
}

/// Start the SSH vsock listener on the dedicated SSH runtime. Fire-and-forget
/// from the caller: bind or accept failures are logged, never fatal to
/// `boxlite-guest` — SSH readiness simply stays false.
pub(super) fn spawn(server: Arc<GuestServer>) {
    ssh_runtime().spawn(async move {
        if let Err(e) = serve_vsock(server).await {
            warn!(error = %e, "SSH vsock listener exited");
        }
    });
}

async fn serve_vsock(server: Arc<GuestServer>) -> BoxliteResult<()> {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let exec_client = ExecutionClient::new(grpc_router(server).into_service());
    let ssh_server = SshServer::new(exec_client)?;

    let addr = VsockAddr::new(VMADDR_CID_ANY, GUEST_SSH_PORT);
    let listener = VsockListener::bind(addr).map_err(|e| {
        BoxliteError::Internal(format!("bind SSH vsock port {GUEST_SSH_PORT}: {e}"))
    })?;
    info!(port = GUEST_SSH_PORT, "SSH listening on vsock");

    let mut backoff = backoff::ACCEPT_ERROR_BACKOFF_MIN;
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                backoff = backoff::ACCEPT_ERROR_BACKOFF_MIN;
                // `none` auth grants root unconditionally (see server.rs's
                // security-model doc); that is only safe if every caller is
                // the hypervisor host, so a connection from any other CID
                // (e.g. a sibling guest on a shared vsock namespace) must be
                // dropped before a single SSH byte is exchanged.
                if !is_trusted_peer(peer.cid()) {
                    warn!(peer = %peer, "rejecting SSH vsock connection from non-host CID");
                    continue;
                }
                info!(peer = %peer, "SSH vsock connection accepted");
                let ssh_server = ssh_server.clone();
                tokio::spawn(async move {
                    if let Err(e) = ssh_server.serve_stream(stream).await {
                        warn!(error = %e, "SSH connection ended with error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, backoff_ms = backoff.as_millis() as u64, "SSH vsock accept failed");
                tokio::time::sleep(backoff).await;
                backoff = backoff::next_accept_error_backoff(backoff);
            }
        }
    }
}

/// Whether a vsock peer CID is the hypervisor host — the only caller `none`
/// auth's unconditional root grant is safe against. Also used by
/// `service::server`'s main gRPC vsock listener: the same untrusted-CID
/// class applies there too (arguably more so — that surface controls
/// container/exec/files, not just SSH).
pub(super) fn is_trusted_peer(cid: u32) -> bool {
    cid == tokio_vsock::VMADDR_CID_HOST
}

#[cfg(test)]
mod peer_trust_tests {
    use super::is_trusted_peer;

    #[test]
    fn host_cid_is_trusted() {
        assert!(is_trusted_peer(tokio_vsock::VMADDR_CID_HOST));
    }

    #[test]
    fn any_other_cid_is_rejected() {
        // VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR, and an arbitrary sibling
        // guest CID must all be rejected — only the host is trusted.
        assert!(!is_trusted_peer(tokio_vsock::VMADDR_CID_ANY));
        assert!(!is_trusted_peer(tokio_vsock::VMADDR_CID_HYPERVISOR));
        assert!(!is_trusted_peer(42));
    }
}
