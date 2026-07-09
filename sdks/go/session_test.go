package boxlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestSessionErrorFormat(t *testing.T) {
	err := &SessionError{
		Code:      "BOX_STOPPED",
		Phase:     "runtime_lookup",
		Message:   "box is not running",
		Retryable: false,
	}
	want := "session error BOX_STOPPED at runtime_lookup: box is not running"
	if got := err.Error(); got != want {
		t.Fatalf("SessionError.Error() = %q, want %q", got, want)
	}
}

func TestAsSessionError(t *testing.T) {
	inner := &SessionError{Code: "TIMEOUT", Phase: "readiness_probe", Message: "timed out", Retryable: true}
	wrapped := fmt.Errorf("ssh dial: %w", inner)

	se, ok := AsSessionError(wrapped)
	if !ok {
		t.Fatal("AsSessionError failed to unwrap a wrapped *SessionError")
	}
	if se != inner {
		t.Fatalf("AsSessionError returned %+v, want the wrapped instance", se)
	}
	if !se.Retryable {
		t.Fatal("Retryable flag lost through unwrapping")
	}

	if _, ok := AsSessionError(errors.New("plain")); ok {
		t.Fatal("AsSessionError matched a non-session error")
	}
}

func TestSessionReadyClosedHandle(t *testing.T) {
	b := &Box{} // handle == nil, as after Close()
	_, err := b.SessionReady(context.Background(), "ssh")
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrInvalidState {
		t.Fatalf("SessionReady on closed handle: got %v, want *Error{ErrInvalidState}", err)
	}
}

func TestSSHClosedHandle(t *testing.T) {
	b := &Box{}
	_, err := b.SSH(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrInvalidState {
		t.Fatalf("SSH on closed handle: got %v, want *Error{ErrInvalidState}", err)
	}
}

func TestSessionCallsHonorPreCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b := &Box{}
	if _, err := b.SessionReady(ctx, "ssh"); !errors.Is(err, context.Canceled) {
		t.Fatalf("SessionReady with canceled ctx: got %v, want context.Canceled", err)
	}
	if _, err := b.SSH(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("SSH with canceled ctx: got %v, want context.Canceled", err)
	}
}

// sessionTestSocketpair builds a connected AF_UNIX stream pair. The first
// fd is prepared exactly like the FFI hands it over (non-blocking,
// ownership transferred); the second is returned as a net.Conn peer.
func sessionTestSocketpair(t *testing.T) (int, net.Conn) {
	t.Helper()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	if err := syscall.SetNonblock(fds[0], true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}

	peerFile := os.NewFile(uintptr(fds[1]), "session-test-peer")
	peer, err := net.FileConn(peerFile)
	_ = peerFile.Close() // FileConn dup'd it
	if err != nil {
		t.Fatalf("FileConn(peer): %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	return fds[0], peer
}

func TestWrapConnFDRoundTrip(t *testing.T) {
	fd, peer := sessionTestSocketpair(t)

	conn, err := wrapConnFD(fd)
	if err != nil {
		t.Fatalf("wrapConnFD: %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*net.UnixConn); !ok {
		t.Fatalf("wrapConnFD returned %T, want *net.UnixConn", conn)
	}

	// Peer -> conn (the direction the SSH banner travels).
	banner := []byte("SSH-2.0-Test\r\n")
	if _, err := peer.Write(banner); err != nil {
		t.Fatalf("peer.Write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(banner))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("conn read: %v", err)
	}
	if string(buf) != string(banner) {
		t.Fatalf("round trip corrupted: got %q, want %q", buf, banner)
	}

	// conn -> peer.
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 4)
	if _, err := io.ReadFull(peer, reply); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(reply) != "pong" {
		t.Fatalf("reply corrupted: got %q", reply)
	}
}

func TestWrapConnFDSupportsDeadlines(t *testing.T) {
	fd, peer := sessionTestSocketpair(t)
	_ = peer // held open so the read blocks instead of seeing EOF

	conn, err := wrapConnFD(fd)
	if err != nil {
		t.Fatalf("wrapConnFD: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err = conn.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected deadline timeout, got %v", err)
	}
}

func TestWrapConnFDCloseReleasesConnection(t *testing.T) {
	fd, peer := sessionTestSocketpair(t)

	conn, err := wrapConnFD(fd)
	if err != nil {
		t.Fatalf("wrapConnFD: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The peer must observe EOF: proof that wrapConnFD did not leave a
	// second descriptor (the pre-dup original) holding the socket open.
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer.Read succeeded; expected EOF after conn.Close")
	}
}
