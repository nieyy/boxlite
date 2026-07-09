// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

package sessionbridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"golang.org/x/crypto/ssh"
)

// collectChannelFrames reads frames on one channel until CLOSE, returning
// stdout bytes, stderr bytes, and the exit code (nil if none was seen).
func collectChannelFrames(t *testing.T, gw *gatewayConn, channelID uint32) (stdout, stderr []byte, exitCode *int32) {
	t.Helper()
	sawEOF := false
	for {
		f := gw.readFrame()
		if f.ChannelID != channelID {
			t.Fatalf("frame %s on unexpected channel %d (want %d)", f.Type, f.ChannelID, channelID)
		}
		switch f.Type {
		case sessionframe.FrameStdout:
			if exitCode != nil {
				t.Fatalf("STDOUT after EXIT_STATUS violates ordering")
			}
			stdout = append(stdout, f.Payload...)
		case sessionframe.FrameStderr:
			if exitCode != nil {
				t.Fatalf("STDERR after EXIT_STATUS violates ordering")
			}
			stderr = append(stderr, f.Payload...)
		case sessionframe.FrameExitStatus:
			var p sessionframe.ExitStatusPayload
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				t.Fatalf("bad EXIT_STATUS payload %q: %v", f.Payload, err)
			}
			code := p.Code
			exitCode = &code
		case sessionframe.FrameEOF:
			if exitCode == nil {
				t.Fatal("EOF before EXIT_STATUS")
			}
			sawEOF = true
		case sessionframe.FrameClose:
			if !sawEOF {
				t.Fatal("CLOSE before EOF")
			}
			return stdout, stderr, exitCode
		default:
			t.Fatalf("unexpected %s frame on channel %d", f.Type, channelID)
		}
	}
}

func TestBridgeExecHappyPath(t *testing.T) {
	guest := newFakeGuest(t)
	guest.exec["run42"] = func(ch ssh.Channel) int {
		_, _ = ch.Write([]byte("out-bytes"))
		_, _ = ch.Stderr().Write([]byte("err-bytes"))
		return 42
	}
	gw := startBridge(t, guest.dialer())

	gw.openExec(7, 1, "run42")
	ev := guest.expectEvent(t, "exec")
	if ev.command != "run42" {
		t.Fatalf("guest saw command %q, want run42", ev.command)
	}

	stdout, stderr, exitCode := collectChannelFrames(t, gw, 7)
	if string(stdout) != "out-bytes" {
		t.Fatalf("stdout = %q, want out-bytes", stdout)
	}
	if string(stderr) != "err-bytes" {
		t.Fatalf("stderr = %q, want err-bytes", stderr)
	}
	if exitCode == nil || *exitCode != 42 {
		t.Fatalf("exit code = %v, want 42", exitCode)
	}
}

func TestBridgePtyRequestBeforeShellAndResize(t *testing.T) {
	guest := newFakeGuest(t)
	release := make(chan struct{})
	guest.shell = func(ch ssh.Channel) int {
		<-release
		return 0
	}
	gw := startBridge(t, guest.dialer())

	ptyPayload, _ := json.Marshal(sessionframe.PtyRequestPayload{
		Term: "xterm-256color", Cols: 80, Rows: 24, WidthPx: 640, HeightPx: 480,
	})
	gw.send(sessionframe.NewRequest(sessionframe.FramePtyRequest, 1, 1, ptyPayload))
	gw.expectReplyOK(sessionframe.FramePtyRequest, 1, 1)

	gw.send(sessionframe.NewRequest(sessionframe.FrameOpenShell, 1, 2, []byte("{}")))
	gw.expectReplyOK(sessionframe.FrameOpenShell, 1, 2)

	// pty-req must reach the guest BEFORE shell.
	pty := guest.expectEvent(t, "pty-req")
	if pty.term != "xterm-256color" || pty.cols != 80 || pty.rows != 24 {
		t.Fatalf("guest pty-req = %+v, want term=xterm-256color cols=80 rows=24", pty)
	}
	guest.expectEvent(t, "shell")

	resizePayload, _ := json.Marshal(sessionframe.PtyResizePayload{Cols: 120, Rows: 40})
	gw.send(sessionframe.NewRequest(sessionframe.FramePtyResize, 1, 3, resizePayload))
	gw.expectReplyOK(sessionframe.FramePtyResize, 1, 3)

	wc := guest.expectEvent(t, "window-change")
	if wc.cols != 120 || wc.rows != 40 {
		t.Fatalf("guest window-change = %+v, want cols=120 rows=40", wc)
	}

	close(release)
	if _, _, exitCode := collectChannelFrames(t, gw, 1); exitCode == nil || *exitCode != 0 {
		t.Fatalf("exit code = %v, want 0", exitCode)
	}
}

func TestBridgeStdinAndHalfClose(t *testing.T) {
	guest := newFakeGuest(t)
	guest.exec["echo-after-eof"] = func(ch ssh.Channel) int {
		// Reads until the client half-closes (stdin EOF), then echoes —
		// proving the channel can still deliver stdout after EOF.
		data, err := io.ReadAll(ch)
		if err != nil {
			return 1
		}
		_, _ = ch.Write(data)
		return 0
	}
	gw := startBridge(t, guest.dialer())

	gw.openExec(3, 1, "echo-after-eof")
	gw.send(sessionframe.NewData(sessionframe.FrameStdin, 3, []byte("hello ")))
	gw.send(sessionframe.NewData(sessionframe.FrameStdin, 3, []byte("guest")))
	gw.send(sessionframe.NewData(sessionframe.FrameEOF, 3, nil))

	stdout, _, exitCode := collectChannelFrames(t, gw, 3)
	if string(stdout) != "hello guest" {
		t.Fatalf("stdout = %q, want %q", stdout, "hello guest")
	}
	if exitCode == nil || *exitCode != 0 {
		t.Fatalf("exit code = %v, want 0", exitCode)
	}
}

func TestBridgeBinaryRoundTrip(t *testing.T) {
	full := make([]byte, 256)
	for i := range full {
		full[i] = byte(i)
	}
	guest := newFakeGuest(t)
	guest.exec["emit-binary"] = func(ch ssh.Channel) int {
		_, _ = ch.Write(full)
		return 0
	}
	gw := startBridge(t, guest.dialer())

	gw.openExec(1, 1, "emit-binary")
	stdout, _, _ := collectChannelFrames(t, gw, 1)
	if !bytes.Equal(stdout, full) {
		t.Fatalf("binary payload corrupted: got %d bytes % x...", len(stdout), stdout[:16])
	}
}

func TestBridgeLargeOutputChunksWithoutDeadlock(t *testing.T) {
	const totalSize = 4 << 20 // 4 MiB
	pattern := make([]byte, totalSize)
	for i := range pattern {
		pattern[i] = byte(i * 31)
	}
	wantSum := sha256.Sum256(pattern)

	guest := newFakeGuest(t)
	guest.exec["blast"] = func(ch ssh.Channel) int {
		if _, err := ch.Write(pattern); err != nil {
			return 1
		}
		return 0
	}
	gw := startBridge(t, guest.dialer())

	gw.openExec(9, 1, "blast")

	hash := sha256.New()
	received := 0
	for {
		f := gw.readFrame()
		if f.ChannelID != 9 {
			t.Fatalf("frame on unexpected channel %d", f.ChannelID)
		}
		if f.Type == sessionframe.FrameStdout {
			if len(f.Payload) > sessionframe.MaxPayload {
				t.Fatalf("frame payload %d exceeds MaxPayload", len(f.Payload))
			}
			hash.Write(f.Payload)
			received += len(f.Payload)
			continue
		}
		if f.Type == sessionframe.FrameExitStatus {
			var p sessionframe.ExitStatusPayload
			_ = json.Unmarshal(f.Payload, &p)
			if p.Code != 0 {
				t.Fatalf("exit code = %d, want 0 (guest write failed?)", p.Code)
			}
			break
		}
		t.Fatalf("unexpected %s frame before exit", f.Type)
	}
	if received != totalSize {
		t.Fatalf("received %d bytes, want %d", received, totalSize)
	}
	if got := hash.Sum(nil); !bytes.Equal(got, wantSum[:]) {
		t.Fatal("large output checksum mismatch")
	}
}

func TestBridgeProtocolErrorsCloseConnection(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"unknown version", rawHeader(9, 1, 0, 1, 1, 0)},
		{"unknown type", rawHeader(1, 99, 0, 1, 1, 0)},
		{"reserved flags", rawHeader(1, 1, 0x8000, 1, 1, 0)},
		{"oversized payload_length", rawHeader(1, 5, 0, 1, 0, sessionframe.MaxPayload+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			guest := newFakeGuest(t)
			gw := startBridge(t, guest.dialer())

			gw.sendRaw(tc.raw)

			f := gw.readFrame()
			if f.ChannelID != sessionframe.ControlChannelID {
				t.Fatalf("ERROR must be on channel 0, got %d", f.ChannelID)
			}
			payload := decodeErrorPayload(t, f)
			if payload.Code != codeProtocolError {
				t.Fatalf("error code = %q, want %q", payload.Code, codeProtocolError)
			}
			gw.expectClosed()
		})
	}
}

func TestBridgeMultiplexedChannels(t *testing.T) {
	guest := newFakeGuest(t)
	guest.exec["echo-loop"] = func(ch ssh.Channel) int {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				if _, werr := ch.Write(buf[:n]); werr != nil {
					return 1
				}
			}
			if err != nil {
				return 0
			}
		}
	}
	gw := startBridge(t, guest.dialer())

	gw.openExec(1, 1, "echo-loop")
	gw.openExec(2, 2, "echo-loop")

	readStdout := func(wantChannel uint32, want string) {
		t.Helper()
		f := gw.readFrame()
		if f.Type != sessionframe.FrameStdout || f.ChannelID != wantChannel || string(f.Payload) != want {
			t.Fatalf("got %s ch=%d payload=%q, want STDOUT ch=%d %q",
				f.Type, f.ChannelID, f.Payload, wantChannel, want)
		}
	}

	gw.send(sessionframe.NewData(sessionframe.FrameStdin, 1, []byte("alpha")))
	readStdout(1, "alpha")
	gw.send(sessionframe.NewData(sessionframe.FrameStdin, 2, []byte("bravo")))
	readStdout(2, "bravo")

	// Closing channel 1 must not disturb channel 2.
	gw.send(sessionframe.NewData(sessionframe.FrameClose, 1, nil))
	gw.send(sessionframe.NewData(sessionframe.FrameStdin, 2, []byte("still-alive")))
	readStdout(2, "still-alive")

	gw.send(sessionframe.NewData(sessionframe.FrameEOF, 2, nil))
	f := gw.readFrame()
	if f.ChannelID != 2 || f.Type != sessionframe.FrameExitStatus {
		t.Fatalf("expected EXIT_STATUS on channel 2, got %s ch=%d", f.Type, f.ChannelID)
	}
}

// TestBridgeStalledChannelDoesNotBlockSiblingChannel guards against
// head-of-line blocking: handleStdin runs on the single shared
// readLoop/dispatch goroutine, so if it wrote to the guest's stdin pipe
// directly, one channel whose guest never drains stdin would freeze frame
// dispatch for every other multiplexed channel on the connection —
// including channels that have nothing to do with the stuck one.
func TestBridgeStalledChannelDoesNotBlockSiblingChannel(t *testing.T) {
	guest := newFakeGuest(t)
	release := make(chan struct{})
	guest.exec["stuck"] = func(ch ssh.Channel) int {
		<-release // never reads — the guest simply never drains its stdin
		return 0
	}
	guest.exec["quick"] = func(ch ssh.Channel) int { return 0 }
	gw := startBridge(t, guest.dialer())

	// One goroutine owns every write to gw.conn (a net.Pipe has no
	// per-frame atomicity across concurrent writers, so writes and the
	// reads below must not interleave across goroutines).
	go func() {
		openStuck, _ := json.Marshal(sessionframe.OpenExecPayload{Command: "stuck"})
		gw.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, 1, 1, openStuck))

		// Flood channel 1's stdin past the inner SSH channel's default
		// 2 MiB flow-control window (64 * 32 KiB packets, x/crypto/ssh). The
		// guest never reads, so once the window is exhausted the guest-side
		// stdin.Write blocks for real — this is what the pre-fix code ran
		// directly on the dispatch goroutine.
		chunk := bytes.Repeat([]byte{'x'}, sessionframe.MaxPayload)
		for i := 0; i < 16; i++ { // 16 * 256 KiB = 4 MiB
			gw.send(sessionframe.NewData(sessionframe.FrameStdin, 1, chunk))
		}

		openQuick, _ := json.Marshal(sessionframe.OpenExecPayload{Command: "quick"})
		gw.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, 2, 2, openQuick))
	}()

	// Read-only on this goroutine, tolerating channel 1's frames interleaved
	// with channel 2's. Channel 2 must still reach CLOSE promptly — readFrame
	// has a built-in 5s deadline, so a regression here fails the test instead
	// of hanging it.
	channel2Done := false
	var channel2ExitCode *int32
	for !channel2Done {
		f := gw.readFrame()
		if f.ChannelID == 1 {
			continue // channel 1's OPEN_EXEC ok reply; nothing else until release
		}
		if f.ChannelID != 2 {
			t.Fatalf("frame on unexpected channel %d", f.ChannelID)
		}
		switch f.Type {
		case sessionframe.FrameExitStatus:
			var p sessionframe.ExitStatusPayload
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				t.Fatalf("bad EXIT_STATUS payload %q: %v", f.Payload, err)
			}
			channel2ExitCode = &p.Code
		case sessionframe.FrameClose:
			channel2Done = true
		}
	}
	if channel2ExitCode == nil || *channel2ExitCode != 0 {
		t.Fatalf("channel 2 exit code = %v, want 0", channel2ExitCode)
	}

	close(release)
	// Drain channel 1's own teardown so it doesn't race t.Cleanup's
	// gateway-close against the guest handler's exit.
	for {
		f := gw.readFrame()
		if f.ChannelID == 1 && f.Type == sessionframe.FrameClose {
			return
		}
	}
}

func TestBridgeGatewayDisconnectTearsDownGuestAndGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()

	guest := newFakeGuest(t)
	handlerDone := make(chan error, 1)
	guest.exec["block-on-stdin"] = func(ch ssh.Channel) int {
		// Blocks until the channel dies; records how it ended.
		_, err := io.ReadAll(ch)
		handlerDone <- err
		return 0
	}
	gw := startBridge(t, guest.dialer())
	gw.openExec(1, 1, "block-on-stdin")

	// Gateway drops the TCP connection mid-exec.
	_ = gw.conn.Close()

	select {
	case <-handlerDone:
		// Guest observed its channel closing — teardown propagated.
	case <-time.After(5 * time.Second):
		t.Fatal("guest handler still blocked 5s after gateway disconnect")
	}
	select {
	case <-gw.done:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge.Run did not return after gateway disconnect")
	}

	// Bounded settle-and-compare goroutine check (goleak is not a repo
	// dependency). Allow slack for runtime/test goroutines.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= baseline+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines did not settle: baseline=%d now=%d", baseline, runtime.NumGoroutine())
}

func TestBridgeGuestDialSessionErrorForwardsCode(t *testing.T) {
	dial := func(ctx context.Context) (net.Conn, error) {
		return nil, &GuestDialError{Code: "VSOCK_CONNECT_FAILED", Message: "guest endpoint unavailable"}
	}
	gw := startBridge(t, dial)

	f := gw.readFrame()
	if f.ChannelID != sessionframe.ControlChannelID {
		t.Fatalf("ERROR must be on channel 0, got %d", f.ChannelID)
	}
	payload := decodeErrorPayload(t, f)
	if payload.Code != "VSOCK_CONNECT_FAILED" {
		t.Fatalf("error code = %q, want VSOCK_CONNECT_FAILED", payload.Code)
	}
	gw.expectClosed()
}

func TestBridgeGuestDialUntypedErrorUsesStableCode(t *testing.T) {
	dial := func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("dial unix /var/run/secret.sock: no such file")
	}
	gw := startBridge(t, dial)

	payload := decodeErrorPayload(t, gw.readFrame())
	if payload.Code != codeGuestOpenFailed {
		t.Fatalf("error code = %q, want %q", payload.Code, codeGuestOpenFailed)
	}
	// The untyped error text may contain runtime addressing; it must not
	// reach the wire.
	if bytes.Contains([]byte(payload.Message), []byte(".sock")) {
		t.Fatalf("error message leaks runtime addressing: %q", payload.Message)
	}
	gw.expectClosed()
}

func TestBridgeChannelZeroMisuseIsFatal(t *testing.T) {
	guest := newFakeGuest(t)
	gw := startBridge(t, guest.dialer())

	gw.send(sessionframe.NewRequest(sessionframe.FrameOpenShell, sessionframe.ControlChannelID, 1, []byte("{}")))

	payload := decodeErrorPayload(t, gw.readFrame())
	if payload.Code != codeProtocolError {
		t.Fatalf("error code = %q, want %q", payload.Code, codeProtocolError)
	}
	gw.expectClosed()
}

func TestBridgeChannelReuseRejected(t *testing.T) {
	guest := newFakeGuest(t)
	guest.exec["quick"] = func(ch ssh.Channel) int { return 0 }
	gw := startBridge(t, guest.dialer())

	gw.openExec(4, 1, "quick")
	if _, _, exitCode := collectChannelFrames(t, gw, 4); exitCode == nil || *exitCode != 0 {
		t.Fatalf("exit code = %v, want 0", exitCode)
	}

	// Channel ids are unique per connection: reopening 4 must fail.
	payload, _ := json.Marshal(sessionframe.OpenExecPayload{Command: "quick"})
	gw.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, 4, 2, payload))
	f := gw.readFrame()
	if !f.IsReply() || f.Type != sessionframe.FrameOpenExec {
		t.Fatalf("expected OPEN_EXEC reply, got %s flags=%#x", f.Type, f.Flags)
	}
	var reply sessionframe.ReplyPayload
	if err := json.Unmarshal(f.Payload, &reply); err != nil || reply.Ok {
		t.Fatalf("expected ok=false reply, got %s", f.Payload)
	}
	if reply.Error == nil || reply.Error.Code != codeChannelReused {
		t.Fatalf("reply error = %+v, want code %q", reply.Error, codeChannelReused)
	}
}

// TestBridgeChannelReuseRejectedAfterFailedOpen guards the invariant
// pendingChannel documents ("ids are unique per connection") on the OPEN_FAILED
// path specifically: a channel id must stay burned even when openSession
// itself errored, not just after a successful open+close.
func TestBridgeChannelReuseRejectedAfterFailedOpen(t *testing.T) {
	guest := newFakeGuest(t)
	// "missing" is not registered in guest.exec, so the guest rejects the
	// exec request and openSession fails.
	gw := startBridge(t, guest.dialer())

	payload, _ := json.Marshal(sessionframe.OpenExecPayload{Command: "missing"})
	gw.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, 7, 1, payload))
	f := gw.readFrame()
	var openReply sessionframe.ReplyPayload
	if err := json.Unmarshal(f.Payload, &openReply); err != nil || openReply.Ok {
		t.Fatalf("expected ok=false OPEN_EXEC reply, got %s", f.Payload)
	}
	if openReply.Error == nil || openReply.Error.Code != codeOpenFailed {
		t.Fatalf("reply error = %+v, want code %q", openReply.Error, codeOpenFailed)
	}

	// Reopening the same id (7) must still be rejected as reused, even
	// though the first open never succeeded.
	guest.exec["quick"] = func(ch ssh.Channel) int { return 0 }
	payload, _ = json.Marshal(sessionframe.OpenExecPayload{Command: "quick"})
	gw.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, 7, 2, payload))
	f = gw.readFrame()
	var reopenReply sessionframe.ReplyPayload
	if err := json.Unmarshal(f.Payload, &reopenReply); err != nil || reopenReply.Ok {
		t.Fatalf("expected ok=false reply, got %s", f.Payload)
	}
	if reopenReply.Error == nil || reopenReply.Error.Code != codeChannelReused {
		t.Fatalf("reply error = %+v, want code %q", reopenReply.Error, codeChannelReused)
	}
}
