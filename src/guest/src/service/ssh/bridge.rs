//! Bridges one SSH session channel to a delegated execution on this guest's
//! own Execution gRPC service.
//!
//! The SSH server never runs commands itself: shell/exec requests are
//! forwarded, in-process, to [`super::server::grpc_router`]'s Execution
//! service, and this module owns the per-channel plumbing (stdin,
//! stdout/stderr, resize, kill).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boxlite_shared::constants::guest_session::SSH_UNIX_USER;
use boxlite_shared::{
    exec_output, AttachRequest, BoxliteError, BoxliteResult, ExecRequest, ExecStdin,
    ExecutionClient, KillRequest, ResizeTtyRequest, TtyConfig, WaitRequest,
};
use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::service::Routes as GrpcChannel;
use tracing::{debug, info, warn};

/// Defensive caps on client-controlled `env` requests: count and per-item
/// byte sizes. Anything beyond gets a channel failure instead of growing
/// server memory.
const MAX_ENV_VARS: usize = 64;
const MAX_ENV_NAME_BYTES: usize = 256;
const MAX_ENV_VALUE_BYTES: usize = 4096;

/// Depth of the stdin queue between the SSH session loop and the SendInput
/// RPC stream. Bounded so a stalled guest applies backpressure to the client
/// instead of buffering unboundedly.
const STDIN_QUEUE_DEPTH: usize = 32;

/// Timeout for short control RPCs (Exec, ResizeTty, Kill). Attach, Wait and
/// SendInput live as long as the execution and are deliberately unbounded.
const CONTROL_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Signal sent to the delegated execution when its SSH channel goes away.
const SIGKILL: i32 = 9;

/// SSH extended data code for stderr (RFC 4254 section 5.2).
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// Exit status reported when the execution died by a signal: `128 + signal`.
///
/// SSH offers two ways to report a signal death (`exit-status` or
/// `exit-signal`); we deliberately use `exit-status 128+signal` because it
/// matches shell `$?` semantics and every client understands it, while
/// `exit-signal` support is spotty.
const SIGNAL_EXIT_BASE: u32 = 128;

/// Exit status reported when the guest could not tell us how the execution
/// ended (Wait RPC failure).
const INDETERMINATE_EXIT_STATUS: u32 = 255;

/// Terminal parameters recorded from `pty-req` and kept current by
/// `window-change`.
#[derive(Debug, Clone)]
pub(super) struct PtyParams {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub pix_width: u32,
    pub pix_height: u32,
}

/// A started delegated execution.
struct RunningExec {
    execution_id: String,
    /// Feeds the SendInput RPC stream; `None` after stdin EOF.
    stdin_tx: Option<mpsc::Sender<ExecStdin>>,
    /// Set by the output pump once Wait returned; kills after this are
    /// pointless and skipped.
    finished: Arc<AtomicBool>,
    /// Cancels the output pump's Attach read, independent of Kill's own
    /// outcome: once the SSH channel is gone there is no one left to
    /// deliver output to, so the pump must stop even if the guest process
    /// is wedged and never produces another Attach message (Kill's RPC
    /// itself is best-effort and can time out without actually killing it).
    /// `None` once sent — cancel_output_pump is idempotent.
    output_cancel: Option<oneshot::Sender<()>>,
    /// Count of stdin frames dropped by `stdin()`'s `try_send` because the
    /// queue was full. Surfaced to the client as a stderr notice once the
    /// execution ends (see `pump_output`) — the drop itself must stay
    /// non-blocking, but the client must not be left thinking every byte it
    /// sent arrived.
    dropped_stdin_frames: Arc<AtomicUsize>,
}

/// Per-channel state machine: collects `pty-req`/`env` before the execution
/// starts, then relays stdin/resize/kill to it.
pub(super) struct ChannelBridge {
    exec_client: ExecutionClient<GrpcChannel>,
    /// SSH-side write half; moved into the output pump when the exec starts.
    write_half: Option<ChannelWriteHalf<Msg>>,
    env: HashMap<String, String>,
    pty: Option<PtyParams>,
    running: Option<RunningExec>,
}

impl ChannelBridge {
    pub(super) fn new(
        exec_client: ExecutionClient<GrpcChannel>,
        write_half: ChannelWriteHalf<Msg>,
    ) -> Self {
        Self {
            exec_client,
            write_half: Some(write_half),
            env: HashMap::new(),
            pty: None,
            running: None,
        }
    }

    pub(super) fn set_pty(&mut self, pty: PtyParams) {
        self.pty = Some(pty);
    }

    /// Record an env var for the future ExecRequest. Returns `false` when the
    /// variable is rejected by the defensive caps or the execution already
    /// started.
    pub(super) fn set_env(&mut self, name: &str, value: &str) -> bool {
        if self.running.is_some() {
            return false;
        }
        if name.len() > MAX_ENV_NAME_BYTES || value.len() > MAX_ENV_VALUE_BYTES {
            return false;
        }
        if self.env.len() >= MAX_ENV_VARS && !self.env.contains_key(name) {
            return false;
        }
        self.env.insert(name.to_string(), value.to_string());
        true
    }

    /// Start the delegated execution: `/bin/sh -l` for a shell request,
    /// `/bin/sh -c <command>` for an exec request. A PTY is attached iff a
    /// `pty-req` preceded this on the channel.
    pub(super) async fn start(&mut self, command: Option<String>) -> BoxliteResult<()> {
        if self.running.is_some() {
            return Err(BoxliteError::Internal(
                "an execution is already running on this channel".to_string(),
            ));
        }

        let args = match command {
            Some(command) => vec!["-c".to_string(), command],
            None => vec!["-l".to_string()],
        };
        let mut env = self.env.clone();
        let tty = self.pty.as_ref().map(|pty| TtyConfig {
            rows: pty.rows,
            cols: pty.cols,
            x_pixels: pty.pix_width,
            y_pixels: pty.pix_height,
        });
        if let Some(pty) = &self.pty {
            if !pty.term.is_empty() {
                // Explicit `env TERM=...` from the client wins over pty-req.
                env.entry("TERM".to_string())
                    .or_insert_with(|| pty.term.clone());
            }
        }

        let request = ExecRequest {
            execution_id: None,
            program: "/bin/sh".to_string(),
            args,
            env,
            workdir: String::new(),
            timeout_ms: 0,
            tty,
            user: Some(SSH_UNIX_USER.to_string()),
        };

        let mut client = self.exec_client.clone();
        let response = tokio::time::timeout(CONTROL_RPC_TIMEOUT, client.exec(request))
            .await
            .map_err(|_| {
                BoxliteError::Internal(format!(
                    "Exec RPC to guest agent timed out after {CONTROL_RPC_TIMEOUT:?}"
                ))
            })?
            .map_err(|e| BoxliteError::Internal(format!("Exec RPC to guest agent failed: {e}")))?
            .into_inner();
        if let Some(error) = response.error {
            return Err(BoxliteError::Internal(format!(
                "guest agent refused execution: {}: {}",
                error.reason, error.detail
            )));
        }
        let execution_id = response.execution_id;

        let write_half = self.write_half.take().ok_or_else(|| {
            BoxliteError::Internal(format!(
                "channel write half already consumed for execution {execution_id}"
            ))
        })?;

        // stdin: one client-streaming SendInput RPC for the whole execution.
        let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_QUEUE_DEPTH);
        {
            let mut client = self.exec_client.clone();
            let execution_id = execution_id.clone();
            tokio::spawn(async move {
                if let Err(e) = client.send_input(ReceiverStream::new(stdin_rx)).await {
                    debug!(execution_id = %execution_id, error = %e, "SendInput stream ended with error");
                }
            });
        }

        let finished = Arc::new(AtomicBool::new(false));
        let dropped_stdin_frames = Arc::new(AtomicUsize::new(0));
        let (output_cancel_tx, output_cancel_rx) = oneshot::channel();
        tokio::spawn(pump_output(
            self.exec_client.clone(),
            execution_id.clone(),
            write_half,
            finished.clone(),
            output_cancel_rx,
            dropped_stdin_frames.clone(),
        ));

        info!(execution_id = %execution_id, pty = self.pty.is_some(), "delegated execution started");
        self.running = Some(RunningExec {
            execution_id,
            stdin_tx: Some(stdin_tx),
            finished,
            output_cancel: Some(output_cancel_tx),
            dropped_stdin_frames,
        });
        Ok(())
    }

    /// Forward channel data to the execution's stdin. This is called from
    /// the single per-connection dispatch loop (russh::server::Handler
    /// serializes every channel's callbacks through one handler instance),
    /// so it must never block: an `.await` on a full queue here would stall
    /// dispatch for every other channel multiplexed on this connection, not
    /// just the stalled one. try_send instead — on a full queue the guest
    /// process genuinely isn't draining stdin either way, so dropping keeps
    /// sibling channels responsive instead of freezing them too.
    pub(super) async fn stdin(&mut self, data: &[u8]) {
        let Some(running) = &self.running else {
            debug!(
                bytes = data.len(),
                "dropping stdin received before execution start"
            );
            return;
        };
        let Some(stdin_tx) = &running.stdin_tx else {
            debug!(execution_id = %running.execution_id, "dropping stdin received after EOF");
            return;
        };
        let frame = ExecStdin {
            execution_id: running.execution_id.clone(),
            data: data.to_vec(),
            close: false,
        };
        match stdin_tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                running.dropped_stdin_frames.fetch_add(1, Ordering::Relaxed);
                warn!(execution_id = %running.execution_id, bytes = data.len(),
                    "stdin queue full — dropping frame (guest not draining stdin)");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!(execution_id = %running.execution_id, "stdin stream already closed by guest");
            }
        }
    }

    /// Channel EOF: close the execution's stdin. Unlike stdin() above, EOF
    /// must never be silently dropped (the guest would hang forever waiting
    /// for more input), but it also must not block the shared dispatcher.
    /// Spawned as its own task: tokio::sync::mpsc guarantees a pending send
    /// resolves promptly either once the queue drains or (if the consumer
    /// already exited) with an immediate error — never leaks.
    pub(super) async fn stdin_eof(&mut self) {
        let Some(running) = &mut self.running else {
            return;
        };
        let Some(stdin_tx) = running.stdin_tx.take() else {
            return;
        };
        let frame = ExecStdin {
            execution_id: running.execution_id.clone(),
            data: Vec::new(),
            close: true,
        };
        tokio::spawn(async move {
            let _ = stdin_tx.send(frame).await;
        });
    }

    /// `window-change`: record the new geometry and resize the guest TTY.
    pub(super) async fn resize(
        &mut self,
        cols: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> BoxliteResult<()> {
        if let Some(pty) = &mut self.pty {
            pty.cols = cols;
            pty.rows = rows;
            pty.pix_width = pix_width;
            pty.pix_height = pix_height;
        }
        let Some(running) = &self.running else {
            return Ok(());
        };
        let request = ResizeTtyRequest {
            execution_id: running.execution_id.clone(),
            rows,
            cols,
            x_pixels: pix_width,
            y_pixels: pix_height,
        };
        let mut client = self.exec_client.clone();
        let response = tokio::time::timeout(CONTROL_RPC_TIMEOUT, client.resize_tty(request))
            .await
            .map_err(|_| {
                BoxliteError::Internal(format!(
                    "ResizeTty RPC for execution {} timed out after {CONTROL_RPC_TIMEOUT:?}",
                    running.execution_id
                ))
            })?
            .map_err(|e| {
                BoxliteError::Internal(format!(
                    "ResizeTty RPC for execution {} failed: {e}",
                    running.execution_id
                ))
            })?
            .into_inner();
        if !response.success {
            return Err(BoxliteError::Internal(format!(
                "guest agent rejected resize of execution {}: {}",
                running.execution_id,
                response.error.unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Fire-and-forget SIGKILL for the delegated execution, if still running,
    /// and unconditionally cancels the output pump. Used on channel close and
    /// client disconnect; killing an execution that just finished is a
    /// harmless no-op on the guest side.
    ///
    /// The pump cancellation does not wait on (or depend on the outcome of)
    /// the Kill RPC below: once the SSH channel is gone there is no one left
    /// to deliver output to, so the pump must stop regardless of whether the
    /// guest process actually dies. Without this, a Kill RPC that times out
    /// against a wedged guest process left the pump task blocked forever on
    /// its next Attach read, leaking the Attach stream and channel write
    /// half.
    pub(super) fn kill_running(&mut self) {
        let Some(running) = &mut self.running else {
            return;
        };
        if let Some(cancel) = running.output_cancel.take() {
            let _ = cancel.send(());
        }
        if running.finished.load(Ordering::SeqCst) {
            return;
        }
        let mut client = self.exec_client.clone();
        let execution_id = running.execution_id.clone();
        tokio::spawn(async move {
            info!(execution_id = %execution_id, signal = SIGKILL, "killing delegated execution");
            let request = KillRequest {
                execution_id: execution_id.clone(),
                signal: SIGKILL,
            };
            match tokio::time::timeout(CONTROL_RPC_TIMEOUT, client.kill(request)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!(execution_id = %execution_id, error = %e, "Kill RPC failed (execution may have already exited)");
                }
                Err(_) => {
                    warn!(execution_id = %execution_id, "Kill RPC timed out");
                }
            }
        });
    }
}

/// Streams Attach output to the SSH channel, then reaps the execution via
/// Wait and reports its exit status.
///
/// Backpressure: `data_bytes`/`extended_data_bytes` wait for SSH channel
/// window, and one Attach message is in flight at a time, so a slow SSH
/// client throttles the gRPC stream instead of growing a buffer. All bytes
/// are forwarded verbatim (binary-safe).
async fn pump_output(
    mut client: ExecutionClient<GrpcChannel>,
    execution_id: String,
    write_half: ChannelWriteHalf<Msg>,
    finished: Arc<AtomicBool>,
    mut cancel_rx: oneshot::Receiver<()>,
    dropped_stdin_frames: Arc<AtomicUsize>,
) {
    let attach_request = AttachRequest {
        execution_id: execution_id.clone(),
    };
    let mut cancelled = false;
    match client.attach(attach_request).await {
        Ok(response) => {
            let mut output = response.into_inner();
            loop {
                // Selecting against cancel_rx is why this loop can't hang
                // forever on a wedged guest process that never produces
                // another Attach message: kill_running() fires this the
                // moment the SSH channel closes, independent of whether its
                // own (best-effort, can-time-out) Kill RPC actually
                // succeeds.
                let next = tokio::select! {
                    msg = output.message() => msg,
                    _ = &mut cancel_rx => {
                        debug!(execution_id = %execution_id, "output pump cancelled: SSH channel gone");
                        cancelled = true;
                        break;
                    }
                };
                match next {
                    Ok(Some(chunk)) => {
                        let write_result = match chunk.event {
                            Some(exec_output::Event::Stdout(stdout)) => {
                                write_half.data_bytes(stdout.data).await
                            }
                            Some(exec_output::Event::Stderr(stderr)) => {
                                write_half
                                    .extended_data_bytes(SSH_EXTENDED_DATA_STDERR, stderr.data)
                                    .await
                            }
                            None => Ok(()),
                        };
                        if write_result.is_err() {
                            debug!(execution_id = %execution_id, "SSH channel gone; stopping output pump");
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!(execution_id = %execution_id, error = %e, "Attach stream failed");
                        break;
                    }
                }
            }
        }
        Err(e) => {
            warn!(execution_id = %execution_id, error = %e, "Attach RPC failed");
        }
    }

    if cancelled {
        // The SSH channel is already gone, so there's nothing left to
        // report an exit status to — and blocking on Wait here would just
        // reintroduce the same hang this cancellation exists to avoid: Wait
        // blocks until the guest process actually exits, which may never
        // happen for a wedged process whose Kill RPC timed out.
        return;
    }

    let wait_request = WaitRequest {
        execution_id: execution_id.clone(),
    };
    let exit_status = match client.wait(wait_request).await {
        Ok(response) => {
            let wait = response.into_inner();
            if wait.signal != 0 {
                SIGNAL_EXIT_BASE + wait.signal as u32
            } else {
                wait.exit_code as u32
            }
        }
        Err(e) => {
            warn!(execution_id = %execution_id, error = %e, "Wait RPC failed; reporting indeterminate exit");
            INDETERMINATE_EXIT_STATUS
        }
    };
    finished.store(true, Ordering::SeqCst);
    info!(execution_id = %execution_id, exit_status, "delegated execution finished");

    // Stdin drops must not block the shared per-connection dispatch loop
    // (see stdin()'s doc comment), so they happen silently at the time. The
    // client still needs to learn about them eventually — surfaced here,
    // once, rather than leaving the client believing every byte it sent was
    // delivered.
    let dropped = dropped_stdin_frames.load(Ordering::Relaxed);
    if let Some(notice) = stdin_drop_notice(dropped) {
        let _ = write_half
            .extended_data_bytes(SSH_EXTENDED_DATA_STDERR, notice.into_bytes())
            .await;
    }

    let _ = write_half.exit_status(exit_status).await;
    let _ = write_half.eof().await;
    let _ = write_half.close().await;
}

/// Stderr notice for dropped stdin frames, or `None` if nothing was dropped.
fn stdin_drop_notice(dropped: usize) -> Option<String> {
    if dropped == 0 {
        return None;
    }
    Some(format!(
        "boxlite: {dropped} stdin frame(s) were dropped because the process \
         wasn't draining stdin fast enough\r\n"
    ))
}

#[cfg(test)]
mod stdin_drop_notice_tests {
    use super::stdin_drop_notice;

    #[test]
    fn no_notice_when_nothing_dropped() {
        assert_eq!(stdin_drop_notice(0), None);
    }

    #[test]
    fn notice_mentions_the_drop_count() {
        let notice = stdin_drop_notice(3).expect("must notify on drops");
        assert!(
            notice.contains('3'),
            "notice must include the drop count: {notice}"
        );
    }
}
