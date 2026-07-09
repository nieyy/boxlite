//! Marks OS threads belonging to the dedicated SSH-connection runtime so the
//! global panic hook (see `main.rs`) can spare the rest of the process from a
//! bug confined to one SSH session's handling code, instead of force-exiting
//! the whole guest agent for it.

use std::cell::Cell;

thread_local! {
    static IS_SSH_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Installed as the SSH runtime's `on_thread_start` hook: every worker thread
/// of that runtime carries this marker for its whole lifetime, and — because
/// `tokio::spawn` always schedules onto the ambient runtime of the calling
/// task — any task nested (now or later) inside SSH connection handling
/// inherits it too, with no per-call-site bookkeeping required.
pub(crate) fn mark_current_thread_as_ssh() {
    IS_SSH_THREAD.with(|flag| flag.set(true));
}

/// Whether the panicking thread belongs to the SSH runtime.
pub(crate) fn is_current_thread_ssh() -> bool {
    IS_SSH_THREAD.with(|flag| flag.get())
}
