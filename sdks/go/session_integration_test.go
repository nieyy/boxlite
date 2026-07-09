//go:build boxlite_dev

package boxlite

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

// waitSessionReady polls Box.SessionReady until the service reports ready
// or the timeout elapses, returning the last observed readiness. Each call
// is a live bounded probe, so polling (not event-wait) is the intended
// consumption pattern.
func waitSessionReady(t *testing.T, box *Box, service string, timeout time.Duration) SessionReadiness {
	t.Helper()

	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for {
		readiness, err := box.SessionReady(ctx, service)
		if err != nil {
			t.Fatalf("SessionReady(%q): %v", service, err)
		}
		if readiness.Ready || time.Now().After(deadline) {
			return readiness
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestIntegrationSessionSSH drives the whole Phase-3 surface end to end:
// SessionReady goes Ready on a booted box, SSH returns a net.Conn whose
// first bytes are the SSH-2.0 identification banner, and a stopped box
// reports the typed BOX_STOPPED cause through both entry points.
func TestIntegrationSessionSSH(t *testing.T) {
	rt := newTestRuntime(t)
	box := createStartedBoxOrSkip(t, rt, "alpine:latest", WithAutoRemove(false))
	ctx := context.Background()

	readiness := waitSessionReady(t, box, "ssh", 60*time.Second)
	if !readiness.Ready {
		t.Fatalf("ssh session not ready after 60s; last reason: %+v", readiness.Reason)
	}
	if readiness.Reason != nil {
		t.Fatalf("Ready readiness must carry a nil Reason, got %+v", readiness.Reason)
	}

	conn, err := box.SSH(ctx)
	if err != nil {
		t.Fatalf("SSH: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	prefix := make([]byte, len("SSH-2.0-"))
	if _, err := io.ReadFull(conn, prefix); err != nil {
		t.Fatalf("reading SSH banner: %v", err)
	}
	if got := string(prefix); got != "SSH-2.0-" {
		t.Fatalf("first bytes = %q, want the %q identification prefix", got, "SSH-2.0-")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// ── Stopped box: both entry points must report BOX_STOPPED ──────
	if err := box.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	readiness, err = box.SessionReady(ctx, "ssh")
	if err != nil {
		t.Fatalf("SessionReady on stopped box: %v", err)
	}
	if readiness.Ready {
		t.Fatal("stopped box reported Ready")
	}
	if readiness.Reason == nil || readiness.Reason.Code != "BOX_STOPPED" {
		t.Fatalf("stopped box Reason = %+v, want Code BOX_STOPPED", readiness.Reason)
	}
	if readiness.Reason.Retryable {
		t.Fatal("BOX_STOPPED must not be retryable")
	}

	if _, err := box.SSH(ctx); err == nil {
		t.Fatal("SSH on stopped box succeeded")
	} else if se, ok := AsSessionError(err); !ok || se.Code != "BOX_STOPPED" {
		t.Fatalf("SSH on stopped box returned %v, want *SessionError with Code BOX_STOPPED", err)
	}
}

// TestIntegrationSessionReadyUnknownService asserts the runtime-level
// InvalidArgument path (unknown service goes through the generic error,
// not a SessionError).
func TestIntegrationSessionReadyUnknownService(t *testing.T) {
	rt := newTestRuntime(t)
	box := createStartedBoxOrSkip(t, rt, "alpine:latest", WithAutoRemove(false))

	_, err := box.SessionReady(context.Background(), "nosuch")
	var e *Error
	if !errors.As(err, &e) || e.Code != ErrInvalidArgument {
		t.Fatalf("SessionReady(nosuch) = %v, want *Error{ErrInvalidArgument}", err)
	}
}
