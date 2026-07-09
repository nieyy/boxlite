//! Guest session operations for the BoxLite C SDK (synchronous).
//!
//! Both entry points block on the underlying async call, mirroring
//! `boxlite_box_exec`: the Rust core bounds session probes and opens with
//! internal timeouts (a few seconds max), so a synchronous FFI surface is
//! safe and keeps callers free of the callback/drain machinery.
//!
//! Typed session failures cross the boundary as [`CBoxSessionError`] — the
//! stable wire strings from `BoxSessionErrorCode::as_str` /
//! `BoxSessionPhase::as_str`. The `cause` chain never crosses the FFI:
//! `message` is user-safe by construction (no socket paths, CIDs, or ports).

use std::os::raw::{c_char, c_int};
use std::os::unix::io::IntoRawFd;

use boxlite::{BoxSessionError, BoxSessionErrorCode, BoxliteError, OpenSessionError};

use crate::box_handle::BoxHandle;
use crate::error::{BoxliteErrorCode, FFIError, error_to_code, null_pointer_error, write_error};
use crate::util::{alloc_c_string, c_str_to_string, free_c_string};
use crate::{CBoxHandle, CBoxliteError};

/// A typed guest session failure, or the absence of one.
///
/// When `present` is false every pointer is NULL and the struct carries no
/// allocation. When `present` is true, `code`/`phase`/`message` are owned C
/// strings the caller must release with `boxlite_session_error_free`.
///
/// `code` is a stable machine string (`BOX_STOPPED`, `RUNTIME_HANDLE_MISSING`,
/// `RUNTIME_HANDLE_STALE`, `GUEST_ENDPOINT_MISSING`, `GUEST_ENDPOINT_STALE`,
/// `GUEST_SERVICE_NOT_READY`, `VSOCK_CONNECT_FAILED`, `GUEST_SERVICE_REJECTED`,
/// `PERMISSION_DENIED`, `TIMEOUT`, `INTERNAL`); `phase` is one of
/// `runtime_lookup`, `endpoint_resolve`, `transport_connect`,
/// `readiness_probe`, `session_open`.
#[repr(C)]
pub struct CBoxSessionError {
    /// Stable machine-readable failure class (NULL when absent).
    pub code: *mut c_char,
    /// Phase of the session operation that failed (NULL when absent).
    pub phase: *mut c_char,
    /// User-safe description; never contains transport details (NULL when absent).
    pub message: *mut c_char,
    /// Whether retrying the operation may succeed.
    pub retryable: bool,
    /// True when this struct describes a session error; false = no error.
    pub present: bool,
}

impl CBoxSessionError {
    /// The "no session error" value: all pointers NULL, nothing to free.
    fn absent() -> Self {
        CBoxSessionError {
            code: std::ptr::null_mut(),
            phase: std::ptr::null_mut(),
            message: std::ptr::null_mut(),
            retryable: false,
            present: false,
        }
    }

    fn from_session_error(err: &BoxSessionError) -> Self {
        CBoxSessionError {
            code: alloc_c_string(err.code.as_str()),
            phase: alloc_c_string(err.phase.as_str()),
            message: alloc_c_string(&err.message),
            retryable: err.retryable,
            present: true,
        }
    }
}

/// Write `value` into the out param if the caller provided one.
///
/// # Safety
/// `out` must be null or a valid pointer to a `CBoxSessionError`.
unsafe fn write_session_error(out: *mut CBoxSessionError, value: CBoxSessionError) {
    unsafe {
        if !out.is_null() {
            *out = value;
        }
    }
}

/// Writes `err`'s wire representation into the out param if the caller
/// provided one.
///
/// The (heap-allocating) `CBoxSessionError` is built only when `out` is
/// non-null: a NULL out param means the caller doesn't want the detail, and
/// building it anyway would allocate three owned C strings that are then
/// dropped without `boxlite_session_error_free` ever running on them.
///
/// # Safety
/// `out` must be null or a valid pointer to a `CBoxSessionError`.
unsafe fn write_session_error_detail(out: *mut CBoxSessionError, err: &BoxSessionError) {
    unsafe {
        if !out.is_null() {
            *out = CBoxSessionError::from_session_error(err);
        }
    }
}

/// Coarse top-level bucket for a typed session error. The precise class
/// crosses the FFI in `CBoxSessionError`; this mapping only picks the
/// closest existing `BoxliteErrorCode` for the function's return value:
/// `BOX_STOPPED` → `Stopped`, `INTERNAL` → `Internal`, everything else
/// (endpoint/transport/probe failures) → `Network`.
fn session_error_to_boxlite_error(err: &BoxSessionError) -> BoxliteError {
    // Display is user-safe by construction (never includes the cause).
    let message = err.to_string();
    match err.code {
        BoxSessionErrorCode::BoxStopped => BoxliteError::Stopped(message),
        BoxSessionErrorCode::Internal => BoxliteError::Internal(message),
        _ => BoxliteError::Network(message),
    }
}

/// Release the strings owned by a `CBoxSessionError` and reset it to the
/// absent state. Safe to call on NULL, on an absent value, and repeatedly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boxlite_session_error_free(error: *mut CBoxSessionError) {
    unsafe {
        if error.is_null() {
            return;
        }
        let err = &mut *error;
        free_c_string(err.code);
        free_c_string(err.phase);
        free_c_string(err.message);
        *err = CBoxSessionError::absent();
    }
}

/// Live readiness probe for a guest session service (only `"ssh"`).
///
/// Blocks for a bounded interval (internal connect/banner timeouts of a few
/// seconds). On return code `Ok`, `*out_ready` is set; when not ready,
/// `*out_reason` (if non-NULL) carries the typed cause — not ready is NOT an
/// error. Runtime-level failures (e.g. `InvalidArgument` for an unknown
/// service) go through `out_error` as usual.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boxlite_box_session_ready(
    handle: *mut CBoxHandle,
    service: *const c_char,
    out_ready: *mut bool,
    out_reason: *mut CBoxSessionError,
    out_error: *mut CBoxliteError,
) -> BoxliteErrorCode {
    box_session_ready(handle, service, out_ready, out_reason, out_error)
}

/// Open a raw byte stream to a guest session service (only `"ssh"`).
///
/// On return code `Ok`, `*out_fd` is a connected Unix-socket file descriptor:
/// - Ownership transfers to the caller (close with `close(2)`).
/// - The fd is in NON-BLOCKING mode; callers doing blocking I/O must clear
///   `O_NONBLOCK` or use readiness polling.
/// - No bytes have been consumed: the first read yields the SSH server
///   identification banner; the caller performs the SSH handshake.
///
/// An unsupported `service` is reported the same way `boxlite_box_session_ready`
/// reports it: `InvalidArgument` via `out_error`, `*out_session_err` stays
/// absent. Any other failure returns a coarse non-`Ok` code (`Stopped` for
/// `BOX_STOPPED`, `Internal` for `INTERNAL`, `Network` otherwise — see
/// `CBoxSessionError` for the precise class), fills `*out_session_err`
/// (if non-NULL) with the typed cause, and fills `out_error` as usual.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn boxlite_box_open_session_stream(
    handle: *mut CBoxHandle,
    service: *const c_char,
    out_fd: *mut c_int,
    out_session_err: *mut CBoxSessionError,
    out_error: *mut CBoxliteError,
) -> BoxliteErrorCode {
    box_open_session_stream(handle, service, out_fd, out_session_err, out_error)
}

unsafe fn box_session_ready(
    handle: *mut BoxHandle,
    service: *const c_char,
    out_ready: *mut bool,
    out_reason: *mut CBoxSessionError,
    out_error: *mut FFIError,
) -> BoxliteErrorCode {
    unsafe {
        if handle.is_null() {
            write_error(out_error, null_pointer_error("handle"));
            return BoxliteErrorCode::InvalidArgument;
        }
        if service.is_null() {
            write_error(out_error, null_pointer_error("service"));
            return BoxliteErrorCode::InvalidArgument;
        }
        if out_ready.is_null() {
            write_error(out_error, null_pointer_error("out_ready"));
            return BoxliteErrorCode::InvalidArgument;
        }
        // Give the out params a defined state before the fallible call.
        write_session_error(out_reason, CBoxSessionError::absent());
        *out_ready = false;

        let service = match c_str_to_string(service) {
            Ok(s) => s,
            Err(e) => {
                write_error(out_error, e);
                return BoxliteErrorCode::InvalidArgument;
            }
        };

        let handle_ref = &*handle;
        let lite = handle_ref.handle.clone();
        // The core bounds the probe with internal connect/banner timeouts,
        // so blocking the calling thread here is bounded (same pattern as
        // boxlite_box_exec).
        match handle_ref.tokio_rt.block_on(lite.session_ready(&service)) {
            Ok(readiness) => {
                *out_ready = readiness.ready;
                if let Some(reason) = readiness.reason {
                    write_session_error_detail(out_reason, &reason);
                }
                BoxliteErrorCode::Ok
            }
            Err(e) => {
                let code = error_to_code(&e);
                write_error(out_error, e);
                code
            }
        }
    }
}

unsafe fn box_open_session_stream(
    handle: *mut BoxHandle,
    service: *const c_char,
    out_fd: *mut c_int,
    out_session_err: *mut CBoxSessionError,
    out_error: *mut FFIError,
) -> BoxliteErrorCode {
    unsafe {
        if handle.is_null() {
            write_error(out_error, null_pointer_error("handle"));
            return BoxliteErrorCode::InvalidArgument;
        }
        if service.is_null() {
            write_error(out_error, null_pointer_error("service"));
            return BoxliteErrorCode::InvalidArgument;
        }
        if out_fd.is_null() {
            write_error(out_error, null_pointer_error("out_fd"));
            return BoxliteErrorCode::InvalidArgument;
        }
        write_session_error(out_session_err, CBoxSessionError::absent());
        *out_fd = -1;

        let service = match c_str_to_string(service) {
            Ok(s) => s,
            Err(e) => {
                write_error(out_error, e);
                return BoxliteErrorCode::InvalidArgument;
            }
        };

        let handle_ref = &*handle;
        let lite = handle_ref.handle.clone();
        // Bounded block: the core caps the connect with an internal timeout.
        match handle_ref
            .tokio_rt
            .block_on(lite.open_session_stream(&service))
        {
            Ok(stream) => match stream.into_std() {
                // The std stream inherits tokio's non-blocking mode; the raw
                // fd hands ownership to the caller (documented above).
                Ok(std_stream) => {
                    *out_fd = std_stream.into_raw_fd();
                    BoxliteErrorCode::Ok
                }
                Err(e) => {
                    write_error(
                        out_error,
                        BoxliteError::Internal(format!(
                            "failed to detach session stream for fd transfer: {e}"
                        )),
                    );
                    BoxliteErrorCode::Internal
                }
            },
            // Argument errors (e.g. an unsupported `service`) are reported
            // the same way `box_session_ready` reports them: `out_error`
            // only, `out_session_err` stays absent — never folded into the
            // session-open failure taxonomy.
            Err(OpenSessionError::Argument(e)) => {
                let code = error_to_code(&e);
                write_error(out_error, e);
                code
            }
            Err(OpenSessionError::Session(session_err)) => {
                write_session_error_detail(out_session_err, &session_err);
                let top_level = session_error_to_boxlite_error(&session_err);
                let code = error_to_code(&top_level);
                write_error(out_error, top_level);
                code
            }
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use boxlite::BoxSessionPhase;

    use super::*;

    /// Fabricate a typed session error without a live backend (all
    /// `BoxSessionError` fields are public).
    fn fabricated_session_error() -> BoxSessionError {
        BoxSessionError {
            code: BoxSessionErrorCode::BoxStopped,
            phase: BoxSessionPhase::RuntimeLookup,
            box_id: "boxtest1".to_string(),
            retryable: false,
            message: "box is not running".to_string(),
            cause: None,
        }
    }

    unsafe fn c_str(ptr: *const c_char) -> &'static str {
        unsafe { CStr::from_ptr(ptr).to_str().expect("valid utf-8") }
    }

    // ── String ownership round-trip ──────────────────────────────────

    #[test]
    fn session_error_round_trips_wire_strings_and_frees() {
        let mut c_err = CBoxSessionError::from_session_error(&fabricated_session_error());

        assert!(c_err.present);
        assert!(!c_err.retryable);
        unsafe {
            assert_eq!(c_str(c_err.code), "BOX_STOPPED");
            assert_eq!(c_str(c_err.phase), "runtime_lookup");
            assert_eq!(c_str(c_err.message), "box is not running");
        }

        unsafe { boxlite_session_error_free(&mut c_err as *mut _) };
        assert!(!c_err.present);
        assert!(c_err.code.is_null());
        assert!(c_err.phase.is_null());
        assert!(c_err.message.is_null());

        // Double free is a no-op: all pointers are already NULL.
        unsafe { boxlite_session_error_free(&mut c_err as *mut _) };
        assert!(!c_err.present);
    }

    #[test]
    fn write_session_error_detail_tolerates_null_out_param() {
        // Regression: `from_session_error` used to be called unconditionally
        // before the null check, allocating three owned C strings that a
        // NULL out param then made unreachable — leaked, since nothing
        // holds the pointers to free them. The allocation now sits behind
        // the null check, so this must not panic and must not touch `out`.
        unsafe { write_session_error_detail(ptr::null_mut(), &fabricated_session_error()) };
    }

    #[test]
    fn session_error_free_tolerates_null_and_absent() {
        unsafe { boxlite_session_error_free(ptr::null_mut()) };

        let mut absent = CBoxSessionError::absent();
        unsafe { boxlite_session_error_free(&mut absent as *mut _) };
        assert!(!absent.present);
    }

    // ── Top-level code mapping ───────────────────────────────────────

    #[test]
    fn session_error_maps_to_coarse_boxlite_codes() {
        let cases = [
            (BoxSessionErrorCode::BoxStopped, BoxliteErrorCode::Stopped),
            (BoxSessionErrorCode::Internal, BoxliteErrorCode::Internal),
            (
                BoxSessionErrorCode::GuestEndpointMissing,
                BoxliteErrorCode::Network,
            ),
            (
                BoxSessionErrorCode::VsockConnectFailed,
                BoxliteErrorCode::Network,
            ),
            (BoxSessionErrorCode::Timeout, BoxliteErrorCode::Network),
        ];
        for (session_code, expected) in cases {
            let mut err = fabricated_session_error();
            err.code = session_code;
            let mapped = session_error_to_boxlite_error(&err);
            assert_eq!(
                error_to_code(&mapped),
                expected,
                "session code {session_code:?} mapped to the wrong top-level code"
            );
        }
    }

    #[test]
    fn session_error_top_level_message_is_user_safe() {
        let secret_path = "/tmp/secret/sockets/ssh.sock";
        let mut err = fabricated_session_error();
        err.cause = Some(format!("connect {secret_path}: refused").into());

        let mapped = session_error_to_boxlite_error(&err);
        let shown = mapped.to_string();
        assert!(
            !shown.contains(secret_path),
            "top-level message leaked the cause: {shown}"
        );
    }

    // ── NULL-argument rejection ──────────────────────────────────────

    #[test]
    fn session_ready_rejects_null_handle() {
        let service = std::ffi::CString::new("ssh").unwrap();
        let mut ready = true;
        let mut reason = CBoxSessionError::absent();
        let mut error = FFIError::default();

        let code = unsafe {
            boxlite_box_session_ready(
                ptr::null_mut(),
                service.as_ptr(),
                &mut ready as *mut _,
                &mut reason as *mut _,
                &mut error as *mut _,
            )
        };

        assert_eq!(code, BoxliteErrorCode::InvalidArgument);
        assert!(!error.message.is_null());
        assert!(!reason.present, "reason must stay absent on null handle");
        unsafe { crate::boxlite_error_free(&mut error as *mut _) };
    }

    // The service/out_ready/out_fd null checks sit behind the handle null
    // check and cannot be reached without a live BoxHandle (LiteBox is not
    // constructible in this crate); they are exercised against a real
    // handle by the Go SDK integration tests.

    #[test]
    fn open_session_stream_rejects_null_handle() {
        let service = std::ffi::CString::new("ssh").unwrap();
        let mut fd: c_int = 0;
        let mut session_err = CBoxSessionError::absent();
        let mut error = FFIError::default();

        let code = unsafe {
            boxlite_box_open_session_stream(
                ptr::null_mut(),
                service.as_ptr(),
                &mut fd as *mut _,
                &mut session_err as *mut _,
                &mut error as *mut _,
            )
        };

        assert_eq!(code, BoxliteErrorCode::InvalidArgument);
        assert!(!error.message.is_null());
        assert!(!session_err.present);
        unsafe { crate::boxlite_error_free(&mut error as *mut _) };
    }
}
