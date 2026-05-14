//! Pre-execution hook for process isolation.
//!
//! This module provides the pre-execution hook that runs after `fork()` but
//! before the new program starts in the child process.
//!
//! # What it does
//!
//! 1. **Close inherited FDs** - Prevents information leakage
//! 2. **Apply rlimits** - Resource limits (max files, memory, CPU time, etc.)
//! 3. **Write PID file** - Single source of truth for process tracking
//!
//! Sandbox-specific pre_exec hooks (cgroup join, Landlock restriction) are
//! added by each sandbox's `apply()` method — they run before this hook
//! since `Command::pre_exec` closures execute in registration order.
//!
//! # Safety
//!
//! The hook runs in a very restricted context:
//! - Only async-signal-safe syscalls are allowed
//! - No memory allocation (no Box, Vec, String)
//! - No mutex operations
//! - No logging (tracing, println)
//!
//! See the [`common`](crate::jailer::common) module for async-signal-safe utilities.

use crate::jailer::common;
use crate::runtime::advanced_options::ResourceLimits;
use std::os::fd::RawFd;
use std::process::Command;

/// Add pre-execution hook for process isolation (async-signal-safe).
///
/// Runs after fork() but before the new program starts in the child process.
/// Applies: FD preservation (dup2), optional FD cleanup, rlimits, PID file writing.
///
/// # Arguments
///
/// * `cmd` - The Command to add the hook to
/// * `resource_limits` - Resource limits to apply
/// * `pid_file_path` - Path to PID file (pre-computed CString for async-signal-safety)
/// * `preserved_fds` - FDs to preserve: each `(source, target)` is dup2'd **unconditionally**
///   before any cleanup. This ensures CLOEXEC source fds (e.g., watchdog pipe) are
///   available at the well-known target fd even when `close_fds=false`.
///   After dup2, all FDs above the highest target are closed (when `close_fds=true`).
///   Pass empty vec for default behavior (close all FDs >= 3 when close_fds=true).
/// * `close_fds` - Whether to close inherited file descriptors after dup2 preservation.
///   Pass `false` only in development mode where FD leakage is acceptable for easier
///   debugging. Does NOT affect the preserved_fds dup2 step.
///
/// # Safety
///
/// This function uses `unsafe` to set the hook. The hook itself
/// only uses async-signal-safe operations:
/// - `dup2()` / `close()` / `close_range()` syscalls
/// - `setrlimit()` syscall
/// - `open()` / `write()` / `close()` syscalls (for PID file)
/// - `getpid()` syscall
///
/// **Do NOT add any of the following to the hook:**
/// - Logging (tracing, println, eprintln)
/// - Memory allocation (Box, Vec, String creation)
/// - Mutex operations
/// - Most Rust standard library functions
pub fn add_pre_exec_hook(
    cmd: &mut Command,
    resource_limits: ResourceLimits,
    pid_file_path: Option<std::ffi::CString>,
    preserved_fds: Vec<(RawFd, i32)>,
    close_fds: bool,
) {
    use std::os::unix::process::CommandExt;

    // SAFETY: The hook only uses async-signal-safe syscalls.
    // See module documentation for details.
    unsafe {
        cmd.pre_exec(move || {
            // 1. FD preservation (dup2): always runs, regardless of close_fds.
            // The watchdog pipe read end is registered as a preserved fd (source → fd 3).
            // The source fd is created O_CLOEXEC so it does NOT survive exec on its own;
            // we must dup2 it to the well-known target fd before exec.
            // This must happen unconditionally — if close_fds=false we skip cleanup below
            // but we still need the watchdog fd in place so the shim can poll it.
            if !preserved_fds.is_empty() {
                for &(source, target) in &preserved_fds {
                    if source != target {
                        libc::dup2(source, target);
                    }
                }
            }

            // 2. FD cleanup: only when close_fds=true.
            // Closes all file descriptors above the highest preserved target (or above 2 if
            // there are no preserved fds). Skip in development mode where FD leakage is
            // acceptable and close_fds=false is explicitly set.
            if close_fds {
                if !preserved_fds.is_empty() {
                    let first_close = preserved_fds.iter().map(|(_, t)| *t).max().unwrap() + 1;
                    common::fd::close_fds_from(first_close)
                        .map_err(std::io::Error::from_raw_os_error)?;
                } else {
                    common::fd::close_inherited_fds_raw()
                        .map_err(std::io::Error::from_raw_os_error)?;
                }
            }

            // 3. Apply resource limits (rlimits)
            common::rlimit::apply_limits_raw(&resource_limits)
                .map_err(std::io::Error::from_raw_os_error)?;

            // 4. Write PID file
            if let Some(ref path) = pid_file_path {
                common::pid::write_pid_file_raw(path).map_err(std::io::Error::from_raw_os_error)?;
            }

            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_hook_compiles() {
        let mut cmd = Command::new("/bin/echo");
        let limits = ResourceLimits::default();

        add_pre_exec_hook(&mut cmd, limits, None, vec![], true);
    }

    #[test]
    fn test_add_hook_with_pid_file() {
        use std::ffi::CString;

        let mut cmd = Command::new("/bin/echo");
        let limits = ResourceLimits::default();
        let pid_file = CString::new("/tmp/test.pid").ok();

        add_pre_exec_hook(&mut cmd, limits, pid_file, vec![], true);
    }

    #[test]
    fn test_add_hook_with_preserved_fds() {
        let mut cmd = Command::new("/bin/echo");
        let limits = ResourceLimits::default();

        // Simulate preserving fd 5 → target fd 3
        add_pre_exec_hook(&mut cmd, limits, None, vec![(5, 3)], true);
    }

    #[test]
    fn test_add_hook_close_fds_false() {
        let mut cmd = Command::new("/bin/echo");
        let limits = ResourceLimits::default();

        // Development mode: hook registers without FD-close step
        add_pre_exec_hook(&mut cmd, limits, None, vec![], false);
    }

    /// Regression test: preserved_fds dup2 must run even when close_fds=false.
    ///
    /// Before the fix, the dup2 block was inside `if close_fds { ... }`, so with
    /// close_fds=false the watchdog pipe (created O_CLOEXEC) was never dup2'd to fd 3.
    /// The child shim would enter with no valid fd 3 and immediately receive SIGTERM
    /// from its watchdog poll.
    ///
    /// This test spawns a real subprocess with a preserved fd (pipe read end → fd 3)
    /// and close_fds=false, then verifies fd 3 is valid inside the child by running
    /// a small shell one-liner that reads from fd 3 with a timeout.
    #[test]
    fn test_preserved_fds_dup2_runs_when_close_fds_false() {
        use std::process::Stdio;

        // Create a pipe: parent writes, child reads from fd 3.
        let (read_end, write_end) = {
            let mut fds = [0i32; 2];
            let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
            assert_eq!(ret, 0, "pipe() failed");
            (fds[0], fds[1])
        };

        // Write a known byte so the child does not block forever.
        let payload: u8 = 0x42;
        unsafe { libc::write(write_end, &payload as *const u8 as *const libc::c_void, 1) };
        unsafe { libc::close(write_end) };

        // Build a child that reads one byte from fd 3 and exits with that byte as status.
        // Uses /bin/sh -c so we don't need a custom binary.
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "dd if=/dev/fd/3 bs=1 count=1 2>/dev/null | od -An -tu1 | tr -d ' \\n'; exit 0"]);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let limits = ResourceLimits::default();
        // preserved_fds: (read_end → 3), close_fds=false
        add_pre_exec_hook(&mut cmd, limits, None, vec![(read_end, 3)], false);

        let output = cmd.output().expect("failed to spawn child");
        // Close read_end in parent after spawn (child already dup2'd it).
        unsafe { libc::close(read_end) };

        // Child should have read the byte 0x42 = 66.
        // If preserved_fds dup2 was skipped, fd 3 would be invalid and dd would exit with
        // error output or empty stdout, failing the assertion.
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.trim() == "66",
            "Expected child to read 0x42 (66) from fd 3 via dup2; got {:?}. \
             This indicates preserved_fds dup2 did not run (regression of close_fds-wraps-dup2 bug).",
            stdout.trim()
        );
    }
}
