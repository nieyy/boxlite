package boxlite

/*
#include "bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"unsafe"
)

// SessionError is a typed guest session failure from the BoxLite runtime.
//
// Code and Phase are stable machine strings (e.g. "BOX_STOPPED",
// "GUEST_ENDPOINT_MISSING", "TIMEOUT" / "runtime_lookup", "session_open").
// Message is user-safe by construction: it never contains socket paths,
// CIDs, or ports.
type SessionError struct {
	Code      string
	Phase     string
	Message   string
	Retryable bool
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("session error %s at %s: %s", e.Code, e.Phase, e.Message)
}

// AsSessionError reports whether err (or any error it wraps) is a
// *SessionError, returning it if so. errors.As-compatible.
func AsSessionError(err error) (*SessionError, bool) {
	var se *SessionError
	ok := errors.As(err, &se)
	return se, ok
}

// SessionReadiness is the result of a live session readiness probe.
// Reason is nil iff Ready.
type SessionReadiness struct {
	Ready  bool
	Reason *SessionError
}

// SessionReady probes whether a guest session service (only "ssh") accepts
// connections right now. Each call probes live — readiness is never cached
// — and never starts an SSH handshake.
//
// Not ready is NOT an error: inspect Reason for the typed cause. An error
// is returned only for runtime-level failures (unknown service, closed box
// handle).
//
// The FFI call is synchronous with bounded internal timeouts (a few seconds
// max), matching the SDK convention for sync C calls (see Box.StartExecution):
// ctx is checked on entry, not raced against the call.
func (b *Box) SessionReady(ctx context.Context, service string) (SessionReadiness, error) {
	if err := ctx.Err(); err != nil {
		return SessionReadiness{}, err
	}
	if b.handle == nil {
		return SessionReadiness{}, &Error{Code: ErrInvalidState, Message: "box handle is closed"}
	}

	cService := toCString(service)
	defer C.free(unsafe.Pointer(cService))

	var cReady C.bool
	var cReason C.CBoxSessionError
	var cerr C.CBoxliteError
	code := C.boxlite_box_session_ready(b.handle, cService, &cReady, &cReason, &cerr)
	if code != C.Ok {
		return SessionReadiness{}, freeError(&cerr)
	}
	return SessionReadiness{Ready: bool(cReady), Reason: takeSessionError(&cReason)}, nil
}

// SSH opens a raw byte stream to the box's SSH service and returns it as a
// net.Conn (a *net.UnixConn: deadlines and Close are supported). No bytes
// have been consumed — the first Read yields the server identification
// banner ("SSH-2.0-..."); the caller performs the SSH handshake.
//
// On a typed session failure (box stopped, endpoint missing, connect
// timeout, ...) the returned error is a *SessionError; use AsSessionError
// and its Retryable flag to decide whether to retry.
//
// The FFI call is synchronous with a bounded internal connect timeout (a
// few seconds max), matching the SDK convention for sync C calls: ctx is
// checked on entry, not raced against the call.
func (b *Box) SSH(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if b.handle == nil {
		return nil, &Error{Code: ErrInvalidState, Message: "box handle is closed"}
	}

	cService := toCString("ssh")
	defer C.free(unsafe.Pointer(cService))

	var fd C.int
	var cSessionErr C.CBoxSessionError
	var cerr C.CBoxliteError
	code := C.boxlite_box_open_session_stream(b.handle, cService, &fd, &cSessionErr, &cerr)
	if code != C.Ok {
		sessionErr := takeSessionError(&cSessionErr)
		genericErr := freeError(&cerr) // always reclaim the C message
		if sessionErr != nil {
			return nil, sessionErr
		}
		return nil, genericErr
	}
	return wrapConnFD(int(fd))
}

// takeSessionError converts a CBoxSessionError out-param into a
// *SessionError (nil when absent) and frees the C-owned strings.
func takeSessionError(cerr *C.CBoxSessionError) *SessionError {
	if cerr == nil || !bool(cerr.present) {
		return nil
	}
	se := &SessionError{
		Code:      cString(cerr.code),
		Phase:     cString(cerr.phase),
		Message:   cString(cerr.message),
		Retryable: bool(cerr.retryable),
	}
	C.boxlite_session_error_free(cerr)
	return se
}

// wrapConnFD adopts a connected, non-blocking Unix-socket fd (ownership
// transferred by the FFI) into a net.Conn.
//
// net.FileConn dup(2)s the descriptor and registers the duplicate with the
// runtime poller (which is what makes deadlines work), so the os.File — and
// with it the original fd — must be closed afterwards; otherwise every
// connection would pin two descriptors.
func wrapConnFD(fd int) (net.Conn, error) {
	file := os.NewFile(uintptr(fd), "boxlite-session")
	if file == nil {
		return nil, &Error{Code: ErrInternal, Message: fmt.Sprintf("invalid session stream fd %d", fd)}
	}
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return nil, &Error{Code: ErrInternal, Message: "wrap session stream fd: " + err.Error()}
	}
	return conn, nil
}
