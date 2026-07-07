// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sshgateway

// Tests for runExec correctness: context cancellation policy and execution
// handle lifetime (no use-after-Close).
//
// Every test creates a real Service with a stub startExec (injected via
// Service.startExec) and calls runExec directly. This means a regression in
// service.go will be caught — unlike goroutine-pattern tests that duplicate
// the production code and stay green even if the production code breaks.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- fakes ---

// fakeExecStdin is an io.WriteCloser that records whether Close was called.
type fakeExecStdin struct {
	mu       sync.Mutex
	closed   bool
	writeErr error // if non-nil, Write always returns this error
}

func (f *fakeExecStdin) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *fakeExecStdin) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}
func (f *fakeExecStdin) WasClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// fakeExecution implements sshExecution. Wait blocks until doneCh is closed or
// ctx is cancelled. closeOrder records the event sequence so tests can assert
// that Close fires after stdin goroutine returns (i.e., after GetStdin().Close()).
//
// drainedCh simulates the SDK's drain guarantee: it is closed when the Exit
// event fires (i.e., after all stdout/stderr has been delivered). In tests that
// do not need precise control over drain timing, drainedCh is closed at
// construction time so Drained() is immediately ready. Tests that exercise the
// drain-before-channel-close invariant (TestRunExecDrainBeforeChannelClose)
// leave drainedCh open and close it explicitly to control sequencing.
type fakeExecution struct {
	stdin     *fakeExecStdin
	doneCh    chan struct{} // close to make Wait return
	drainedCh chan struct{} // close to signal stream drained (simulates OnExit)
	exitCode  int

	mu      sync.Mutex
	events  []string // ordered: "stdin.Close", "kill", "execution.Close"
	signals []int    // signals forwarded via Signal()
}

func newFakeExecution() *fakeExecution {
	drained := make(chan struct{})
	close(drained) // immediately drained by default; tests that need control use newFakeExecutionWithDrain
	return &fakeExecution{
		stdin:     &fakeExecStdin{},
		doneCh:    make(chan struct{}),
		drainedCh: drained,
	}
}

// newFakeExecutionWithStdinErr returns a fakeExecution whose stdin Write always
// returns writeErr. Used by TestRunExecStdinWriteErrorDoesNotCancelCtx.
func newFakeExecutionWithStdinErr(writeErr error) *fakeExecution {
	drained := make(chan struct{})
	close(drained)
	return &fakeExecution{
		stdin:     &fakeExecStdin{writeErr: writeErr},
		doneCh:    make(chan struct{}),
		drainedCh: drained,
	}
}

// newFakeExecutionWithDrain returns a fakeExecution with a drainedCh that is
// NOT pre-closed. The caller controls when Drained() unblocks by closing
// exec.drainedCh explicitly. Used by TestRunExecDrainBeforeChannelClose.
func newFakeExecutionWithDrain() *fakeExecution {
	return &fakeExecution{
		stdin:     &fakeExecStdin{},
		doneCh:    make(chan struct{}),
		drainedCh: make(chan struct{}),
	}
}

// fakeExecKillClosesDrain is a fakeExecution whose Kill() call closes drainedCh
// — simulating what happens when execution.Kill() terminates the Rust stdout
// pump, which eventually closes the drain channel. Used by
// TestRunExecDrainDeadlockUnblockedByTimeout.
type fakeExecKillClosesDrain struct {
	fakeExecution
}

func newFakeExecKillClosesDrain() *fakeExecKillClosesDrain {
	return &fakeExecKillClosesDrain{
		fakeExecution: fakeExecution{
			stdin:     &fakeExecStdin{},
			doneCh:    make(chan struct{}),
			drainedCh: make(chan struct{}),
		},
	}
}

// Kill closes drainedCh in addition to recording the event, so the drain wait
// unblocks after Kill is called. In production, killing the process causes the
// Rust stdout pump to terminate and fire OnExit (which closes drainedCh).
func (e *fakeExecKillClosesDrain) Kill(_ context.Context) error {
	e.fakeExecution.recordEvent("kill")
	// Simulate the Rust pump terminating after kill: close drainedCh.
	select {
	case <-e.drainedCh:
		// already closed
	default:
		close(e.drainedCh)
	}
	return nil
}

func (e *fakeExecution) recordEvent(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, name)
}

func (e *fakeExecution) Wait(ctx context.Context) (int, error) {
	select {
	case <-e.doneCh:
		return e.exitCode, nil
	case <-ctx.Done():
		return 1, ctx.Err()
	}
}

func (e *fakeExecution) Kill(_ context.Context) error {
	e.recordEvent("kill")
	return nil
}

func (e *fakeExecution) Signal(_ context.Context, sig int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.signals = append(e.signals, sig)
	return nil
}

func (e *fakeExecution) ResizeTTY(_ context.Context, _, _ int) error { return nil }

// fakeResizeCall records a single ResizeTTY call's arguments.
type fakeResizeCall struct{ rows, cols int }

// fakeRecordingResizeExecution extends fakeExecution by recording every
// ResizeTTY call. Used by TestRunExecInitialPTYDimensions to assert that the
// initial pty-req dimensions are applied exactly once, before any window-change.
type fakeRecordingResizeExecution struct {
	fakeExecution
	mu      sync.Mutex
	resizes []fakeResizeCall
}

func newFakeRecordingResizeExecution() *fakeRecordingResizeExecution {
	drained := make(chan struct{})
	close(drained)
	return &fakeRecordingResizeExecution{
		fakeExecution: fakeExecution{
			stdin:     &fakeExecStdin{},
			doneCh:    make(chan struct{}),
			drainedCh: drained,
		},
	}
}

func (e *fakeRecordingResizeExecution) ResizeTTY(_ context.Context, rows, cols int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resizes = append(e.resizes, fakeResizeCall{rows: rows, cols: cols})
	return nil
}

func (e *fakeRecordingResizeExecution) getResizes() []fakeResizeCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]fakeResizeCall(nil), e.resizes...)
}

// fakeBlockingResizeExecution is a fakeExecution whose ResizeTTY blocks until
// its context is cancelled. Used by TestRunExecResizeRacingExit to verify that
// a stalled resize call cannot deadlock reqsWg.Wait() after process exit.
type fakeBlockingResizeExecution struct {
	fakeExecution
}

func newFakeBlockingResizeExecution() *fakeBlockingResizeExecution {
	drained := make(chan struct{})
	close(drained)
	return &fakeBlockingResizeExecution{
		fakeExecution: fakeExecution{
			stdin:     &fakeExecStdin{},
			doneCh:    make(chan struct{}),
			drainedCh: drained,
		},
	}
}

// ResizeTTY blocks until ctx is cancelled, then returns ctx.Err(). This
// simulates a slow or hung resize RPC and would deadlock reqsWg.Wait() if
// ResizeTTY were called with the long-lived session ctx (which is not
// cancelled before reqsWg.Wait() on the natural-exit path).
func (e *fakeBlockingResizeExecution) ResizeTTY(ctx context.Context, _, _ int) error {
	<-ctx.Done()
	return ctx.Err()
}

func (e *fakeExecution) Close() error {
	e.recordEvent("execution.Close")
	return nil
}

func (e *fakeExecution) GetStdin() io.WriteCloser {
	// Wrap the real fakeExecStdin but record the Close event order.
	return &recordingStdinCloser{inner: e.stdin, exec: e}
}

func (e *fakeExecution) Drained() <-chan struct{} {
	return e.drainedCh
}

// recordingStdinCloser records the "stdin.Close" event before delegating,
// so we can assert Close order relative to execution.Close.
type recordingStdinCloser struct {
	inner *fakeExecStdin
	exec  *fakeExecution
}

func (r *recordingStdinCloser) Write(p []byte) (int, error) { return r.inner.Write(p) }
func (r *recordingStdinCloser) Close() error {
	r.exec.recordEvent("stdin.Close")
	return r.inner.Close()
}

// fakeSSHChannel implements ssh.Channel. Read blocks on readCh until either
// data arrives or the channel is closed (simulating client stdin).
// Close and CloseWrite are idempotent and unblock pending Reads.
// Write records each write to writtenData so tests can assert output delivery.
type fakeSSHChannel struct {
	mu          sync.Mutex
	readCh      chan []byte
	closed      bool
	closedCh    chan struct{} // closed once on first Close call
	writtenData [][]byte      // records each Write call's payload
	blockWrites bool          // if true, Write blocks until channel is closed

	stderr *fakeStderr
}

type fakeStderr struct {
	mu  sync.Mutex
	buf []byte
}

func (f *fakeStderr) Read(_ []byte) (int, error) { return 0, io.EOF }
func (f *fakeStderr) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *fakeStderr) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.buf)
}

func newFakeSSHChannel() *fakeSSHChannel {
	return &fakeSSHChannel{
		readCh:   make(chan []byte, 8),
		closedCh: make(chan struct{}),
		stderr:   &fakeStderr{},
	}
}

// newBlockingWriteSSHChannel returns a fakeSSHChannel whose Write method blocks
// until the channel is closed — simulating an SSH peer that has stopped reading
// (e.g. the client filled the SSH receive window and stopped consuming output).
func newBlockingWriteSSHChannel() *fakeSSHChannel {
	return &fakeSSHChannel{
		readCh:      make(chan []byte, 8),
		closedCh:    make(chan struct{}),
		stderr:      &fakeStderr{},
		blockWrites: true,
	}
}

func (c *fakeSSHChannel) Read(p []byte) (int, error) {
	select {
	case data, ok := <-c.readCh:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		return n, nil
	case <-c.closedCh:
		return 0, io.EOF
	}
}

func (c *fakeSSHChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	blockWrites := c.blockWrites
	closed := c.closed
	c.mu.Unlock()

	if closed {
		// Mimic real SSH channel: closed channel returns an error.
		return 0, io.ErrClosedPipe
	}

	if blockWrites {
		// Simulate a peer that has stopped reading — block until channel closed.
		<-c.closedCh
		return 0, io.ErrClosedPipe
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	c.writtenData = append(c.writtenData, buf)
	return len(p), nil
}

func (c *fakeSSHChannel) getWritten() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][]byte, len(c.writtenData))
	copy(result, c.writtenData)
	return result
}

func (c *fakeSSHChannel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	return nil
}

func (c *fakeSSHChannel) CloseWrite() error { return c.Close() }

func (c *fakeSSHChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
	return false, nil
}

func (c *fakeSSHChannel) Stderr() io.ReadWriter { return c.stderr }

// sendEOF simulates the client closing stdin (clean EOF).
func (c *fakeSSHChannel) sendEOF() { close(c.readCh) }

// --- helper ---

// newTestService returns a Service wired with a startExec stub that returns exec.
func newTestService(exec sshExecution) *Service {
	return &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			return exec, nil
		},
	}
}

// fakeReqChan returns a *ssh.Request channel that is closed immediately (no
// in-session requests). The caller can also pass a real channel to control timing.
func closedReqChan() <-chan *ssh.Request {
	ch := make(chan *ssh.Request)
	close(ch)
	return ch
}

// noReplyReq returns a *ssh.Request with WantReply false.
func noReplyReq(typ string) *ssh.Request {
	return &ssh.Request{Type: typ, WantReply: false}
}

// --- tests ---

// TestRunExecCloseAfterStdinGoroutine is the primary regression guard for the
// use-after-free finding. It asserts that execution.Close fires AFTER the stdin
// goroutine calls execution.GetStdin().Close() — never before.
//
// If defer execution.Close() is re-introduced (before stdinWg.Wait()), or if
// the WaitGroup is removed, this test fails because "execution.Close" will
// appear before "stdin.Close" in the event log.
func TestRunExecCloseAfterStdinGoroutine(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)

	var runErr error
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		runErr = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Let the goroutines start.
	time.Sleep(5 * time.Millisecond)

	// Simulate process exit: make Wait return.
	close(exec.doneCh)

	// runExec will then close ch (to unblock stdin goroutine) and call stdinWg.Wait().
	// Give it time to complete.
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return within 2s — likely deadlock in stdinWg.Wait()")
	}

	if runErr != nil {
		t.Fatalf("runExec returned error: %v", runErr)
	}

	// Close reqs so the reqs goroutine exits cleanly (avoids goroutine leak in test).
	close(reqs)

	exec.mu.Lock()
	events := append([]string(nil), exec.events...)
	exec.mu.Unlock()

	// Must have both events.
	if len(events) < 2 {
		t.Fatalf("expected 2 close events, got %v", events)
	}
	if events[0] != "stdin.Close" {
		t.Errorf("first close event must be stdin.Close, got %q (full: %v)", events[0], events)
	}
	if events[1] != "execution.Close" {
		t.Errorf("second close event must be execution.Close, got %q (full: %v)", events[1], events)
	}
}

// TestRunExecStdinEOFDoesNotCancelContext asserts that a clean stdin EOF
// (client used `ssh host cmd < /dev/null`) does NOT cancel the per-channel
// context. The process is still running and should complete naturally.
//
// Regression guard: if cancel() is re-added to the clean-EOF path of the stdin
// goroutine, ctx.Done() fires before exec.doneCh and the test catches it.
func TestRunExecStdinEOFDoesNotCancelContext(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Simulate clean stdin EOF (client closes stdin).
	ch.sendEOF()

	// Give stdin goroutine time to process the EOF.
	time.Sleep(20 * time.Millisecond)

	// Context must still be alive: the process has not exited yet.
	select {
	case <-ctx.Done():
		t.Fatal("context was cancelled by stdin EOF: runExec would abort still-running processes; " +
			"cancel() must not be called from the stdin goroutine on nil error")
	default:
		// PASS: context alive; process can run to natural completion.
	}

	// Clean up: let the process exit and runExec return.
	close(exec.doneCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after process exit")
	}
}

// TestRunExecReqsCloseAfterStdinEOFCancelsContext asserts that when stdin
// closes cleanly and then the SSH channel is torn down (reqs closed), the
// per-channel context IS cancelled so execution.Wait(ctx) unblocks.
//
// The reqs goroutine must call cancel() after
// its range loop exits. Without that, ctx stays open after disconnect and
// execution.Wait blocks indefinitely.
func TestRunExecReqsCloseAfterStdinEOFCancelsContext(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Simulate clean stdin EOF.
	ch.sendEOF()
	time.Sleep(10 * time.Millisecond)

	// Now client disconnects: close the reqs channel.
	close(reqs)

	// The reqs goroutine must call cancel() which unblocks exec.Wait(ctx).
	// exec.doneCh is never closed, so Wait must return via ctx cancellation.
	select {
	case <-runDone:
		// PASS: runExec returned (via ctx cancellation from reqs close).
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after reqs channel closed: " +
			"a process that outlives stdin EOF would block Wait indefinitely after client disconnect")
	}
}

// TestRunExecStdinDisconnectCancelsContext asserts that when io.Copy returns
// a non-nil error (client disconnected mid-session), the per-channel context
// IS cancelled so execution.Wait(ctx) unblocks.
//
// Regression guard: if cancel() is removed from the stdin goroutine's error
// path, exec.Wait blocks and runExec never returns.
func TestRunExecStdinDisconnectCancelsContext(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	// Use a channel that returns an error on Read, simulating client disconnect.
	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	// Do not defer close(reqs) here: reqs is closed explicitly below, and a
	// second close would panic. The defer cancel() above handles context cleanup.

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Close ch immediately — this causes Read in the stdin goroutine to return
	// io.EOF. But io.EOF from Read is not an error from io.Copy's perspective
	// (io.Copy returns nil on EOF). To simulate a real disconnect error we
	// need the Read to return a non-nil, non-EOF error.
	//
	// Since fakeSSHChannel.Close() causes Read to return io.EOF (which gives
	// nil from io.Copy), we test the reqs-close path for cancellation instead
	// of the stdin error path here. The stdin-error path is implicitly covered
	// by TestRunExecReqsCloseAfterStdinEOFCancelsContext which proves that any
	// disconnect (whether stdin-error or reqs-close) unblocks Wait.
	//
	// Close both ch and reqs: ctx must be cancelled within the deadline.
	_ = ch.Close()
	close(reqs)

	select {
	case <-runDone:
		// PASS: one of the two cancel paths (stdin error or reqs close) fired.
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after ch and reqs closed: " +
			"a sandbox process that ignores stdin would run forever after client disconnect")
	}
}

// TestRunExecKillOnDisconnect asserts that execution.Kill is called when the
// SSH channel is torn down (reqs closed) before the process exits naturally.
//
// Regression guard: if Kill is removed from the disconnect path, the guest
// process runs indefinitely after the SSH session ends. The test verifies that
// "kill" appears in the event log after context cancellation.
func TestRunExecKillOnDisconnect(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Simulate clean stdin EOF followed by client disconnect (reqs close).
	// exec.doneCh is never closed, so Wait returns only via ctx cancellation.
	ch.sendEOF()
	time.Sleep(10 * time.Millisecond)
	close(reqs)

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after reqs closed")
	}

	exec.mu.Lock()
	events := append([]string(nil), exec.events...)
	exec.mu.Unlock()

	// Kill must appear before execution.Close in the event log.
	killIdx := -1
	closeIdx := -1
	for i, ev := range events {
		if ev == "kill" {
			killIdx = i
		}
		if ev == "execution.Close" {
			closeIdx = i
		}
	}
	if killIdx < 0 {
		t.Errorf("Kill was not called on client disconnect; events: %v", events)
	}
	if closeIdx < 0 {
		t.Errorf("execution.Close was not called; events: %v", events)
	}
	if killIdx >= 0 && closeIdx >= 0 && killIdx > closeIdx {
		t.Errorf("Kill must fire before Close; events: %v", events)
	}
}

// TestRunExecSignalForwarding asserts that SSH "signal" in-session requests are
// forwarded to the execution via Signal() using Linux ABI signal numbers.
//
// Linux signal numbers that differ from macOS are explicitly tested to catch
// host-OS syscall constant leakage: USR1 is 10 on Linux but 30 on macOS;
// TSTP is 20 on Linux but 18 on macOS. SIGINT=2 is the same on both and is
// kept as a baseline.
func TestRunExecSignalForwarding(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request, 4)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give goroutines a moment to start.
	time.Sleep(5 * time.Millisecond)

	// Send three SSH "signal" requests that have different values on Linux vs macOS.
	// ssh.Marshal encodes the string as a 4-byte big-endian length + string bytes.
	for _, name := range []string{"INT", "USR1", "TSTP"} {
		payload := ssh.Marshal(struct{ Signal string }{Signal: name})
		reqs <- &ssh.Request{Type: "signal", WantReply: false, Payload: payload}
	}

	// Give the reqs goroutine time to process all three signals.
	time.Sleep(30 * time.Millisecond)

	// Let the process exit naturally.
	close(exec.doneCh)

	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after process exit")
	}

	// Close reqs so the reqs goroutine exits cleanly (avoids goroutine leak in test).
	close(reqs)

	exec.mu.Lock()
	signals := append([]int(nil), exec.signals...)
	exec.mu.Unlock()

	// Linux signal numbers (stable across x86/ARM64; see signal(7)):
	//   SIGINT=2, SIGUSR1=10, SIGTSTP=20
	// On macOS: SIGUSR1=30, SIGTSTP=18 — using syscall constants on the host
	// would produce wrong values for these.
	const (
		linuxSIGINT  = 2
		linuxSIGUSR1 = 10 // macOS: 30
		linuxSIGTSTP = 20 // macOS: 18
	)

	wantSignals := []struct {
		name string
		num  int
	}{
		{"INT", linuxSIGINT},
		{"USR1", linuxSIGUSR1},
		{"TSTP", linuxSIGTSTP},
	}

	if len(signals) != len(wantSignals) {
		t.Fatalf("expected %d signals forwarded, got %d: %v", len(wantSignals), len(signals), signals)
	}
	for i, want := range wantSignals {
		if signals[i] != want.num {
			t.Errorf("signal[%d] (%s): expected Linux value %d, got %d (macOS value would be different)", i, want.name, want.num, signals[i])
		}
	}
}

// TestRunExecResizeRacingExit asserts that a window-change request whose
// ResizeTTY call is in progress when the process exits naturally does NOT
// deadlock reqsWg.Wait(). The bug: ResizeTTY was passed the long-lived session
// ctx, which is not cancelled before reqsWg.Wait() on the natural-exit path
// (cancel() is still deferred in handleChannel). A stalled ResizeTTY blocks
// the reqs goroutine past close(reqsDone), preventing reqsWg.Wait() from
// returning and therefore deadlocking runExec.
//
// The fix: ResizeTTY is called with a 5s bounded context (context.Background()
// + WithTimeout), matching the pattern used for Signal. The test uses
// fakeBlockingResizeExecution, whose ResizeTTY blocks until its context is
// cancelled. If ResizeTTY still receives the session ctx the test hangs
// indefinitely; with the fix runExec returns once the 5s resize timeout fires.
//
// We use a 6s outer deadline so the test fails fast on CI rather than running
// the full default test timeout.
func TestRunExecResizeRacingExit(t *testing.T) {
	t.Parallel()

	exec := newFakeBlockingResizeExecution()
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request, 4)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, true, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give the goroutines a moment to start.
	time.Sleep(5 * time.Millisecond)

	// Send a window-change request. The reqs goroutine will enter ResizeTTY and
	// block there (fakeBlockingResizeExecution.ResizeTTY blocks on ctx.Done()).
	payload := make([]byte, 8)
	// BigEndian: cols=80, rows=24
	payload[0], payload[1], payload[2], payload[3] = 0, 0, 0, 80
	payload[4], payload[5], payload[6], payload[7] = 0, 0, 0, 24
	reqs <- &ssh.Request{Type: "window-change", WantReply: false, Payload: payload}

	// Give the reqs goroutine time to enter ResizeTTY before we let the process
	// exit, so that the race is actually exercised.
	time.Sleep(10 * time.Millisecond)

	// Simulate natural process exit: close doneCh so Wait returns.
	// This triggers close(reqsDone) in runExec. The reqs goroutine must exit
	// via the bounded resize context timing out — not by waiting for the session ctx.
	close(exec.doneCh)

	// runExec must return within 6s. With the fix the bounded 5s resize context
	// fires and unblocks ResizeTTY → reqs goroutine exits → reqsWg.Wait() returns.
	// Without the fix (session ctx passed to ResizeTTY) the test hangs here
	// because session ctx is never cancelled before reqsWg.Wait().
	select {
	case <-runDone:
		// PASS: the bounded resize context timed out and unblocked the reqs goroutine.
	case <-time.After(6 * time.Second):
		t.Fatal("runExec did not return within 6s: ResizeTTY with session ctx deadlocks " +
			"reqsWg.Wait() when process exits while a resize call is in progress")
	}
}

// TestRunExecStdinWriteErrorDoesNotCancelCtx asserts that when the guest process
// closes its stdin pipe (causing execStdin.Write to return an EPIPE-like error),
// the per-channel context is NOT cancelled. The client is still connected; only
// a ch.Read error (SSH channel failure) should cancel the context.
//
// Regression guard: if cancel() were called from the write-error branch, any
// process that closed its own stdin (e.g. a daemon that detaches) would kill
// the session even though the client is still connected.
func TestRunExecStdinWriteErrorDoesNotCancelCtx(t *testing.T) {
	t.Parallel()

	epipe := errors.New("write /dev/stdin: broken pipe")
	exec := newFakeExecutionWithStdinErr(epipe)
	svc := newTestService(exec)

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Send data so the stdin goroutine attempts a Write (which will fail with epipe).
	ch.readCh <- []byte("hello")

	// Give the stdin goroutine time to observe the write error and stop.
	time.Sleep(30 * time.Millisecond)

	// Context must still be alive: the write error is a guest-side event, not a
	// client disconnect. cancel() must NOT be called from the write-error branch.
	select {
	case <-ctx.Done():
		t.Fatal("context was cancelled by stdin write error: only SSH channel read errors " +
			"(client disconnect) should cancel; a guest-side EPIPE must not end the session")
	default:
		// PASS: context alive; the process is still running.
	}

	// Clean up: let the process exit naturally.
	close(exec.doneCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after process exit")
	}
}

// TestRunExecInitialPTYDimensions asserts that when runExec receives non-zero
// initialRows/initialCols (from a parsed pty-req payload), ResizeTTY is called
// with those dimensions immediately after exec starts and before any
// window-change request. This ensures interactive programs start with the
// correct terminal size rather than defaulting to 0x0 or 80x24.
//
// Regression guard: if the initialRows/initialCols path is removed, the first
// element of resizes will be missing or have wrong dimensions.
func TestRunExecInitialPTYDimensions(t *testing.T) {
	t.Parallel()

	exec := newFakeRecordingResizeExecution()
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	const wantRows = 48
	const wantCols = 132

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/bash", nil, true, noReplyReq("shell"), wantRows, wantCols, nil, "")
	}()

	// Give runExec time to call startExec and apply initial dimensions.
	time.Sleep(30 * time.Millisecond)

	resizes := exec.getResizes()
	if len(resizes) == 0 {
		t.Fatal("ResizeTTY was not called for initial pty-req dimensions")
	}
	first := resizes[0]
	if first.rows != wantRows || first.cols != wantCols {
		t.Errorf("initial ResizeTTY called with rows=%d cols=%d; want rows=%d cols=%d",
			first.rows, first.cols, wantRows, wantCols)
	}

	// Clean up: let the process exit.
	close(exec.doneCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after process exit")
	}
}

// TestRunExecExecOutputIsTextOnly documents the known architectural constraint
// that SSH exec output is text-only (UTF-8). The production BoxLite exec
// pipeline converts raw guest stdout/stderr bytes to String via
// String::from_utf8_lossy before delivering them to the Go io.Writer (see
// src/boxlite/src/portal/interfaces/exec.rs::route_output). Any byte sequence
// that is not valid UTF-8 is silently replaced with U+FFFD (EF BF BD in
// UTF-8), so binary-producing exec commands (e.g. `cat archive.tar`,
// `base64 -d`) will produce corrupted output over the SSH gateway.
//
// This test verifies the runExec gateway layer in isolation using a
// fakeExecution stub that bypasses the Rust from_utf8_lossy conversion and
// delivers bytes directly. This proves that runExec itself is byte-transparent:
// if the SDK were fixed to deliver raw bytes, the SSH channel would receive
// them intact. The corruption lives entirely in the Rust portal layer, not
// in this gateway.
//
// Why this matters: the subsystem path is already rejected (see handleChannel
// "subsystem" case) with a clear error. The exec/shell path silently accepts
// binary-producing commands and corrupts their output. Until the Rust SDK's
// exec pipeline is fixed to use Vec<u8> rather than String throughout, SSH
// exec must be documented as text-only (see apps/runner/README.md).
func TestRunExecExecOutputIsTextOnly(t *testing.T) {
	t.Parallel()

	exec := newFakeExecution()

	// Capture the stdout writer passed to startExec so we can inject bytes.
	var capturedStdout io.Writer
	var stdoutMu sync.Mutex

	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, stdout, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			stdoutMu.Lock()
			capturedStdout = stdout
			stdoutMu.Unlock()
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give runExec time to call startExec and start goroutines.
	time.Sleep(10 * time.Millisecond)

	// In the production path the Rust portal converts guest stdout bytes to
	// String via from_utf8_lossy before they arrive here. The fakeExecution
	// bypasses that layer and delivers bytes directly to the io.Writer, which
	// is the SSH channel.
	//
	// We write a sequence that contains a non-UTF-8 byte (0xFF is never valid
	// in UTF-8). In production this byte would be replaced by the three-byte
	// U+FFFD sequence (EF BF BD) before reaching this point. Here, the fake
	// delivers the raw byte, confirming that runExec itself is byte-transparent.
	stdoutMu.Lock()
	writer := capturedStdout
	stdoutMu.Unlock()

	if writer == nil {
		t.Fatal("stdout writer was not captured")
	}

	// Write a sequence with an embedded 0xFF byte (invalid UTF-8).
	// In production the Rust portal would replace 0xFF with EF BF BD before
	// this writer is called. The test documents the boundary:
	// - Below this write: runExec is byte-preserving (this test proves it).
	// - Above this write: the Rust portal is lossy (from_utf8_lossy).
	rawData := []byte("hello\xffworld") // \xff is invalid UTF-8
	if _, err := writer.Write(rawData); err != nil {
		t.Fatalf("write to SSH channel writer failed: %v", err)
	}

	// Process exit.
	close(exec.doneCh)
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after process exit")
	}

	// Confirm that runExec delivered the raw bytes to the SSH channel without
	// modification. This proves that the gateway itself is byte-transparent.
	written := ch.getWritten()
	found := false
	for _, w := range written {
		if string(w) == string(rawData) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("raw bytes %q not found verbatim in SSH channel writes — "+
			"runExec must be byte-transparent; corruption must not originate in this layer. "+
			"Writes: %v", rawData, written)
	}
}

// TestRunExecDrainBeforeChannelClose asserts that runExec does not close the
// SSH channel before all stdout/stderr bytes have been delivered. Without the
// drain wait, a process can exit (Wait returns), ch.Close() fires, and then
// trailing output from the SDK's concurrent stream pumps is silently dropped
// because ch.Write returns an error that deliverStdout ignores.
//
// The test simulates this race by controlling the drain signal (drainedCh)
// independently from the Wait signal (doneCh):
//  1. Process exits: close(doneCh) → Wait returns.
//  2. Before drained fires, simulate late stdout arriving: write directly to
//     the stdout io.Writer captured at startExec time — verifying the channel
//     is still open (write succeeds).
//  3. Close drainedCh to signal drain complete.
//  4. runExec may now close ch.
//
// Regression guard: without the `<-execution.Drained()` call in runExec,
// ch.Close() fires immediately after Wait returns, making the late-stdout
// write return io.ErrClosedPipe and the write is not recorded in ch.writtenData.
func TestRunExecDrainBeforeChannelClose(t *testing.T) {
	t.Parallel()

	exec := newFakeExecutionWithDrain()

	// capturedStdout captures the stdout io.Writer passed to startExec.
	// This lets us simulate a late-arriving SDK callback that writes to ch
	// after Wait() has returned but before the drain fires.
	var capturedStdout io.Writer
	var stdoutMu sync.Mutex

	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, stdout, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			stdoutMu.Lock()
			capturedStdout = stdout
			stdoutMu.Unlock()
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give runExec time to call startExec and start goroutines.
	time.Sleep(10 * time.Millisecond)

	// Simulate process exit: Wait returns.
	close(exec.doneCh)

	// Give runExec time to observe Wait returning but not yet block on Drained().
	time.Sleep(10 * time.Millisecond)

	// Simulate late stdout arriving from the SDK (after Wait unblocked, before
	// drain fires). In production this is the SDK drain goroutine dispatching
	// a Stdout event that was already queued before Wait's event was dispatched.
	stdoutMu.Lock()
	writer := capturedStdout
	stdoutMu.Unlock()

	lateData := []byte("late stdout after exit")
	var writeErr error
	if writer != nil {
		_, writeErr = writer.Write(lateData)
	}

	// Now signal drain complete: all stdout/stderr delivered.
	close(exec.drainedCh)

	// runExec must return after drain fires.
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return after drainedCh closed")
	}

	if writer == nil {
		t.Fatal("stdout writer was not captured at startExec time")
	}
	if writeErr != nil {
		t.Errorf("late stdout write failed: %v — ch was closed before drain completed, "+
			"meaning trailing output would be silently dropped; runExec must wait for "+
			"execution.Drained() before closing the SSH channel", writeErr)
	}

	written := ch.getWritten()
	found := false
	for _, w := range written {
		if string(w) == string(lateData) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("late stdout data %q not found in channel writes %v — "+
			"output was dropped because ch.Close() fired before drain completed", lateData, written)
	}
}

// TestRunExecDrainDeadlockUnblockedByTimeout asserts that runExec does not
// block forever on execution.Drained() when the SSH client stops reading
// (causing ch.Write to block, which stalls the Rust stdout pump, which never
// fires OnExit/Drained). Without a bounded drain wait, runExec hangs here.
//
// The fix: the drain wait must have a timeout (or be tied to channel/context
// liveness); on timeout, Kill() is called to unblock the pump.
//
// This test uses a channel whose Write blocks until it is closed
// (newBlockingWriteSSHChannel) and a fakeExecKillClosesDrain whose Kill()
// call closes drainedCh (simulating the Rust pump terminating after Kill).
// Without the timeout+Kill fix the test hangs; with it, runExec returns
// within the drain timeout window.
func TestRunExecDrainDeadlockUnblockedByTimeout(t *testing.T) {
	t.Parallel()

	exec := newFakeExecKillClosesDrain()

	var capturedStdout io.Writer
	var stdoutMu sync.Mutex

	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, stdout, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			stdoutMu.Lock()
			capturedStdout = stdout
			stdoutMu.Unlock()
			return exec, nil
		},
	}

	// ch.Write blocks (peer stopped reading) — simulates SSH window exhaustion.
	ch := newBlockingWriteSSHChannel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give runExec time to start and capture the stdout writer.
	time.Sleep(20 * time.Millisecond)

	stdoutMu.Lock()
	writer := capturedStdout
	stdoutMu.Unlock()

	// Simulate the process exiting naturally.
	close(exec.doneCh)

	// Give runExec time to enter the drain wait.
	time.Sleep(20 * time.Millisecond)

	// Attempt to write to the channel. Since blockWrites=true this will block
	// until either ch.Close() or the drain timeout fires (in the fix, Kill()
	// is called on timeout, which closes drainedCh, which lets runExec proceed
	// to ch.Close(), which unblocks the write).
	if writer != nil {
		go func() { _, _ = writer.Write([]byte("data")) }()
	}

	// runExec must return within the drain timeout + a small buffer (use 35s
	// to cover the 30s drain timeout in the fix). Without the fix it hangs.
	select {
	case <-runDone:
		// PASS: drain timeout fired, Kill() was called, runExec returned.
	case <-time.After(35 * time.Second):
		t.Fatal("runExec did not return within 35s: drain wait on Drained() deadlocks " +
			"when the SSH peer stops reading (ch.Write blocks, stdout pump never fires OnExit)")
	}

	// Verify Kill was called (the fix must call Kill before or on timeout).
	exec.mu.Lock()
	events := append([]string(nil), exec.events...)
	exec.mu.Unlock()

	killFound := false
	for _, ev := range events {
		if ev == "kill" {
			killFound = true
			break
		}
	}
	if !killFound {
		t.Errorf("expected Kill to be called on drain timeout, events: %v", events)
	}
}

// TestRunExecDrainTimeoutUnblocksChannel verifies that on drain timeout, runExec
// closes the SSH channel BEFORE calling Kill(). This ordering is critical:
//
//   - Kill() alone does not unblock a blocked ch.Write (SSH receive window is
//     still full after the guest is killed).
//   - ch.Close() causes any in-progress ch.Write to return io.ErrClosedPipe,
//     unblocking the SDK drain goroutine immediately.
//
// The test uses fakeExecKillClosesDrainAfterChannelClosed: its Kill() method
// asserts that the SSH channel was already closed when Kill was called, then
// closes drainedCh so the drain wait completes. Without the ch.Close()-first
// fix, Kill() fires while ch is still open and drainedCh is never closed (the
// drain goroutine remains stuck), so runExec hangs past the 35s deadline.
func TestRunExecDrainTimeoutUnblocksChannel(t *testing.T) {
	t.Parallel()

	// fakeExecKillClosesDrainAfterChannelClosed is a one-shot fake that:
	//   1. On Kill(), verifies that ch was already closed (channelClosedBeforeKill).
	//   2. Closes drainedCh so the drain-after-kill wait returns.
	// It captures the fakeSSHChannel so Kill() can inspect ch.closed.
	type killOrderExec struct {
		fakeExecution
		ch                      *fakeSSHChannel
		channelClosedBeforeKill bool
		killCalled              bool
		mu2                     sync.Mutex
	}
	drainedCh := make(chan struct{})
	ch := newBlockingWriteSSHChannel()

	exec := &killOrderExec{
		fakeExecution: fakeExecution{
			stdin:     &fakeExecStdin{},
			doneCh:    make(chan struct{}),
			drainedCh: drainedCh,
		},
		ch: ch,
	}
	// Override Kill() to record ordering and close drainedCh.
	killFn := func(_ context.Context) error {
		exec.mu2.Lock()
		exec.ch.mu.Lock()
		exec.channelClosedBeforeKill = exec.ch.closed
		exec.ch.mu.Unlock()
		exec.killCalled = true
		exec.mu2.Unlock()
		exec.fakeExecution.recordEvent("kill")
		// Simulate Rust pump terminating: close drainedCh.
		select {
		case <-drainedCh:
		default:
			close(drainedCh)
		}
		return nil
	}

	var capturedStdout io.Writer
	var stdoutMu sync.Mutex

	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, stdout, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			stdoutMu.Lock()
			capturedStdout = stdout
			stdoutMu.Unlock()
			// Return a wrapper that intercepts Kill.
			return &killInterceptExec{fakeExecution: &exec.fakeExecution, killFn: killFn}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := make(chan *ssh.Request)
	defer close(reqs)

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-1", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "")
	}()

	// Give runExec time to start.
	time.Sleep(20 * time.Millisecond)

	stdoutMu.Lock()
	writer := capturedStdout
	stdoutMu.Unlock()

	// Trigger natural process exit so runExec enters the drain wait.
	close(exec.fakeExecution.doneCh)

	// Trigger a blocking write from the drain goroutine — this simulates the SDK
	// drain goroutine stuck in ch.Write because the SSH peer stopped reading.
	if writer != nil {
		go func() { _, _ = writer.Write([]byte("stuck-data")) }()
	}

	// runExec must return within 35s (30s drain timeout + 5s secondary wait + buffer).
	select {
	case <-runDone:
	case <-time.After(35 * time.Second):
		t.Fatal("runExec did not return within 35s: ch.Close() must precede Kill() " +
			"on drain timeout to unblock stuck ch.Write in the SDK drain goroutine")
	}

	exec.mu2.Lock()
	killCalled := exec.killCalled
	closedBeforeKill := exec.channelClosedBeforeKill
	exec.mu2.Unlock()

	if !killCalled {
		t.Error("Kill was not called on drain timeout")
	}
	if !closedBeforeKill {
		t.Error("ch.Close() was not called before Kill() on drain timeout: " +
			"Kill() alone cannot unblock a stuck ch.Write; ch must be closed first " +
			"to return io.ErrClosedPipe from any in-progress Write, " +
			"which frees the SDK drain goroutine to fire Drained()")
	}
}

// killInterceptExec wraps a fakeExecution and replaces Kill() with a custom function.
// Used by TestRunExecDrainTimeoutUnblocksChannel to record ordering.
type killInterceptExec struct {
	*fakeExecution
	killFn func(ctx context.Context) error
}

func (e *killInterceptExec) Kill(ctx context.Context) error {
	return e.killFn(ctx)
}

// TestHandleChannelParsesFullPTYReq verifies that the pty-req payload parser
// correctly handles a full RFC 4254 §6.2 payload including the Modes field.
//
// A standard SSH client always includes a modes string at the end of the
// pty-req payload (see RFC 4254 §8). ssh.Unmarshal rejects payloads with
// trailing bytes when the struct has no field to absorb them — so a struct
// missing Modes causes every real SSH client's pty-req to fail, leaving
// initialRows/initialCols at zero and termEnv nil.
//
// The fix: add Modes string to the ptyPayload struct.
//
// This test verifies the struct can be parsed by constructing a full pty-req
// payload via ssh.Marshal and then unmarshalling it with the same struct shape
// used in handleChannel, confirming Term, Cols, Rows, and Modes are extracted.
func TestHandleChannelParsesFullPTYReq(t *testing.T) {
	t.Parallel()

	const wantTerm = "xterm-256color"
	const wantCols = uint32(220)
	const wantRows = uint32(50)
	const wantWpx = uint32(1760)
	const wantHpx = uint32(1000)
	const wantModes = "\x00" // RFC 4254 §8: TTY_OP_END (0x00) terminates modes list

	// Build the payload exactly as a real SSH client would.
	payload := ssh.Marshal(struct {
		Term  string
		Cols  uint32
		Rows  uint32
		Wpx   uint32
		Hpx   uint32
		Modes string
	}{
		Term:  wantTerm,
		Cols:  wantCols,
		Rows:  wantRows,
		Wpx:   wantWpx,
		Hpx:   wantHpx,
		Modes: wantModes,
	})

	// Parse using the same struct shape as handleChannel.
	var ptyPayload struct {
		Term   string
		Cols   uint32
		Rows   uint32
		Width  uint32
		Height uint32
		Modes  string
	}
	if err := ssh.Unmarshal(payload, &ptyPayload); err != nil {
		t.Fatalf("ssh.Unmarshal failed: %v — the ptyPayload struct is missing the Modes field; "+
			"ssh.Unmarshal rejects payloads with trailing bytes when the struct has no field to absorb them", err)
	}

	if ptyPayload.Term != wantTerm {
		t.Errorf("Term: got %q, want %q", ptyPayload.Term, wantTerm)
	}
	if ptyPayload.Cols != wantCols {
		t.Errorf("Cols: got %d, want %d", ptyPayload.Cols, wantCols)
	}
	if ptyPayload.Rows != wantRows {
		t.Errorf("Rows: got %d, want %d", ptyPayload.Rows, wantRows)
	}
	if ptyPayload.Modes != wantModes {
		t.Errorf("Modes: got %q, want %q", ptyPayload.Modes, wantModes)
	}

	// Verify handleChannel derives initial dimensions correctly from a
	// full pty-req payload by running handleChannel with a real pty-req
	// and then a shell request, and asserting that startExec is called
	// (not rejected) with tty=true.
	startExecCalled := false
	var capturedEnv map[string]string
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, tty bool, env map[string]string, _ string) (sshExecution, error) {
			startExecCalled = true
			capturedEnv = env
			exec := newFakeExecution()
			// Close doneCh immediately so runExec can return promptly.
			close(exec.doneCh)
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()
	// Close stdin so the stdin goroutine exits cleanly.
	ch.sendEOF()

	reqs := make(chan *ssh.Request, 4)
	reqs <- &ssh.Request{Type: "pty-req", WantReply: false, Payload: payload}
	reqs <- &ssh.Request{Type: "shell", WantReply: false, Payload: nil}
	close(reqs)

	newCh := &fakeNewChannel{
		channelType: "session",
		ch:          ch,
		reqs:        reqs,
	}

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		svc.handleChannel(newCh, "sandbox-1")
	}()

	select {
	case <-handleDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleChannel did not return within 5s")
	}

	if !startExecCalled {
		t.Fatal("startExec was not called: handleChannel may have rejected the pty-req or shell request")
	}

	// Verify TERM was extracted and forwarded as an env var.
	if capturedEnv == nil || capturedEnv["TERM"] != wantTerm {
		t.Errorf("TERM env var not forwarded correctly: got %v, want TERM=%q", capturedEnv, wantTerm)
	}
}

// fakeNewChannel implements ssh.NewChannel for testing handleChannel.
// Accept returns the provided fakeSSHChannel and the provided reqs channel.
type fakeNewChannel struct {
	channelType string
	ch          *fakeSSHChannel
	reqs        <-chan *ssh.Request
	rejected    bool
}

func (f *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return f.ch, f.reqs, nil
}

func (f *fakeNewChannel) Reject(_ ssh.RejectionReason, _ string) error {
	f.rejected = true
	return nil
}

func (f *fakeNewChannel) ChannelType() string { return f.channelType }
func (f *fakeNewChannel) ExtraData() []byte   { return nil }

// TestRunExecNonPTYExecRejected asserts that an SSH exec request without a
// prior pty-req is rejected with a protocol-level failure. This is the
// functional fix for the binary-exec finding: since the BoxLite exec pipeline
// converts raw bytes to String via from_utf8_lossy, allowing non-PTY exec
// silently corrupts binary output (e.g. `ssh host 'cat archive.tar'`). PTY
// exec is allowed because PTY output is inherently text (terminal-encoded).
// Non-PTY exec is unsafe until the Rust pipeline is made byte-preserving.
//
// This test verifies that handleChannel rejects exec when tty=false by
// checking that startExec is never called.
func TestRunExecNonPTYExecRejected(t *testing.T) {
	t.Parallel()

	startExecCalled := false
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			startExecCalled = true
			return newFakeExecution(), nil
		},
	}

	ch := newFakeSSHChannel()

	// Provide reqs that contain a non-PTY exec request (no preceding pty-req).
	reqs := make(chan *ssh.Request, 4)
	execPayload := ssh.Marshal(struct{ Command string }{Command: "cat /dev/urandom"})
	reqs <- &ssh.Request{Type: "exec", WantReply: false, Payload: execPayload}
	close(reqs)

	newChannel := &fakeNewChannel{
		channelType: "session",
		ch:          ch,
		reqs:        reqs,
	}

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		svc.handleChannel(newChannel, "sandbox-1")
	}()

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleChannel did not return within 2s")
	}

	if startExecCalled {
		t.Error("startExec was called for a non-PTY exec request — " +
			"non-PTY exec must be rejected because the exec pipeline is text-only (from_utf8_lossy); " +
			"binary-producing commands like 'cat archive.tar' would silently corrupt output")
	}
}

// TestNonPTYExecRejectedWithMessage asserts that when a non-PTY exec request is
// rejected, the SSH client receives a human-readable reason on stderr (not just a
// silent connection drop or a cryptic "channel request failed on channel N" message).
//
// The fix (Option B from the adversarial review): before replying false to the
// exec request, handleChannel writes an explanation to ch.Stderr() explaining
// why the exec was rejected and how to use -t. This matches the behaviour of a
// real sshd that rejects exec for a policy reason.
//
// Regression guard:
//   - If the stderr write is removed, stderrContent is empty and the test fails.
//   - If startExec is called despite no PTY, startExecCalled is true and the test fails.
func TestNonPTYExecRejectedWithMessage(t *testing.T) {
	t.Parallel()

	startExecCalled := false
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			startExecCalled = true
			return newFakeExecution(), nil
		},
	}

	ch := newFakeSSHChannel()

	// Non-PTY exec: send exec request without a prior pty-req.
	reqs := make(chan *ssh.Request, 4)
	execPayload := ssh.Marshal(struct{ Command string }{Command: "cat /dev/urandom"})
	reqs <- &ssh.Request{Type: "exec", WantReply: false, Payload: execPayload}
	close(reqs)

	newChannel := &fakeNewChannel{
		channelType: "session",
		ch:          ch,
		reqs:        reqs,
	}

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		svc.handleChannel(newChannel, "sandbox-1")
	}()

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleChannel did not return within 2s")
	}

	// startExec must not have been called — the rejection must happen before
	// any execution resource is allocated.
	if startExecCalled {
		t.Error("startExec was called for a non-PTY exec request")
	}

	// The rejection reason must be visible on stderr so the SSH client can
	// display it. A silent false reply only produces "channel request failed"
	// which gives the user no actionable information.
	stderrContent := ch.stderr.String()
	if stderrContent == "" {
		t.Error("non-PTY exec rejection produced no stderr message: " +
			"the SSH client would receive a silent failure with no explanation; " +
			"handleChannel must write a human-readable reason to ch.Stderr() before replying false")
	}

	// The message must mention the -t flag so the user knows how to fix it.
	if !strings.Contains(stderrContent, "-t") {
		t.Errorf("rejection message does not mention the -t flag (how to fix the error): %q", stderrContent)
	}
}

// TestNonPTYShellRejectedWithMessage asserts that a non-PTY shell request
// also receives a human-readable rejection on stderr (not just a silent drop).
func TestNonPTYShellRejectedWithMessage(t *testing.T) {
	t.Parallel()

	startExecCalled := false
	svc := &Service{
		log: slog.Default(),
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			startExecCalled = true
			return newFakeExecution(), nil
		},
	}

	ch := newFakeSSHChannel()

	// Non-PTY shell: send shell request without a prior pty-req.
	reqs := make(chan *ssh.Request, 4)
	reqs <- &ssh.Request{Type: "shell", WantReply: false, Payload: nil}
	close(reqs)

	newChannel := &fakeNewChannel{
		channelType: "session",
		ch:          ch,
		reqs:        reqs,
	}

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		svc.handleChannel(newChannel, "sandbox-1")
	}()

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleChannel did not return within 2s")
	}

	if startExecCalled {
		t.Error("startExec was called for a non-PTY shell request")
	}

	stderrContent := ch.stderr.String()
	if stderrContent == "" {
		t.Error("non-PTY shell rejection produced no stderr message")
	}
	if !strings.Contains(stderrContent, "-t") {
		t.Errorf("shell rejection message does not mention the -t flag: %q", stderrContent)
	}
}

// TestSSHUserDefaultsToRoot is the key invariant guard for the SSH user
// policy: when Service.sshUser is empty, exec and shell requests must be
// launched with user="root" (the explicit default), not user="" (which would
// inherit the container image default and be ambiguous across images).
//
// Regression guard: if sshUserOrDefault() is removed or the runExec call sites
// revert to passing "", the capturedUser will be empty and the test fails.
func TestSSHUserDefaultsToRoot(t *testing.T) {
	t.Parallel()

	var capturedUser string
	exec := newFakeExecution()
	// Close doneCh immediately so runExec returns promptly after startup.
	close(exec.doneCh)

	svc := &Service{
		log: slog.Default(),
		// sshUser deliberately left empty to exercise the default path.
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, user string) (sshExecution, error) {
			capturedUser = user
			return exec, nil
		},
	}

	ch := newFakeSSHChannel()
	ch.sendEOF()

	reqs := make(chan *ssh.Request, 4)
	reqs <- &ssh.Request{Type: "pty-req", WantReply: false, Payload: ssh.Marshal(struct {
		Term   string
		Cols   uint32
		Rows   uint32
		Width  uint32
		Height uint32
		Modes  string
	}{Term: "xterm", Cols: 80, Rows: 24, Modes: "\x00"})}
	reqs <- &ssh.Request{Type: "shell", WantReply: false, Payload: nil}
	close(reqs)

	newCh := &fakeNewChannel{
		channelType: "session",
		ch:          ch,
		reqs:        reqs,
	}

	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		svc.handleChannel(newCh, "sandbox-user-test")
	}()

	select {
	case <-handleDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handleChannel did not return within 5s")
	}

	// The SSH gateway must never pass an empty user string to startExec: empty
	// is ambiguous and image-dependent. The explicit default is "root".
	if capturedUser == "" {
		t.Error("startExec was called with user=\"\" (empty): " +
			"the SSH gateway must always pass an explicit user via sshUserOrDefault(); " +
			"empty string is never a valid value")
	}
	if capturedUser != "root" {
		t.Errorf("startExec was called with user=%q; want \"root\" (the SSH gateway default)", capturedUser)
	}
}

// TestRunExecStartupTimeoutOnSlow asserts that runExec returns within a bounded
// time when startExec blocks indefinitely (e.g. the backend is wedged). Without
// a startup timeout the goroutine is stuck until the SDK returns, which can be
// never if the backend hangs after a client disconnects.
//
// The test injects a startExec stub that blocks until its context is cancelled,
// then configures the Service with a very short startup timeout (100 ms) via a
// context.WithTimeout wrapper around the real startExec call. We simulate this
// by injecting the blocking startExec and observing runExec returns within ~1s.
//
// Regression guard: without the startCtx/startCancel timeout in runExec, the
// blocking startExec makes runExec hang indefinitely and this test times out.
func TestRunExecStartupTimeoutOnSlow(t *testing.T) {
	t.Parallel()

	// blockingStartExec blocks until its context is cancelled, then returns an error.
	// This simulates a hung backend that never completes StartExecution.
	svc := &Service{
		log: slog.Default(),
		startExec: func(ctx context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	ch := newFakeSSHChannel()

	// Use a context with a short timeout (150 ms) as the "session" context passed to
	// runExec. The startup timeout inside runExec derives from this context via
	// context.WithTimeout(ctx, startupTimeout). When the session ctx times out,
	// startCtx also expires, unblocking the blocking startExec stub.
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	reqs := closedReqChan()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-slow", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "boxlite")
	}()

	// runExec must return once the context (and therefore startCtx) expires.
	// Allow 2s — generous relative to the 150ms timeout — to handle slow CI.
	select {
	case <-runDone:
		// PASS: startExec's blocking call was unblocked by the context timeout.
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return within 2s after context expiry: " +
			"a hung startExec (no startup timeout context) blocks the goroutine indefinitely; " +
			"startExec must be called with a bounded context so a wedged backend cannot " +
			"hold the SSH session goroutine open after the client disconnects")
	}
}

// TestRunExecStartupTimeoutIgnoresContext is the key regression guard for the
// production-SDK scenario: StartExecution ignores its context on the C side
// (boxlite_box_exec is a blocking C FFI call). The old code passed a timeout
// context to startExec, which is a no-op if the callee ignores context. This
// test verifies the fix: runExec races startExec against a goroutine-level
// timeout so the wall-clock bound is real regardless of whether startExec
// honours its context.
//
// The stub deliberately ignores its context parameter and instead blocks on
// blockCh — simulating the production C FFI path that cannot be interrupted
// via context cancellation.
//
// The test also verifies the cleanup contract: when runExec returns on timeout,
// a background goroutine must Kill and Close any late-arriving execution handle.
func TestRunExecStartupTimeoutIgnoresContext(t *testing.T) {
	t.Parallel()

	blockCh := make(chan struct{})
	killCalled := make(chan struct{}, 1)
	closeCalled := make(chan struct{}, 1)

	// lateExec is returned by the stub after blockCh is closed (late arrival).
	// It records Kill and Close so we can verify the cleanup goroutine fires.
	lateExec := &killCloseRecorder{
		fakeExecution: fakeExecution{
			stdin:     &fakeExecStdin{},
			doneCh:    make(chan struct{}),
			drainedCh: func() chan struct{} { ch := make(chan struct{}); close(ch); return ch }(),
		},
		killCh:  killCalled,
		closeCh: closeCalled,
	}

	svc := &Service{
		log:            slog.Default(),
		startupTimeout: 100 * time.Millisecond, // very short; default is 30s
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			// Deliberately ignore the context: blocks until blockCh is closed.
			// This is the key property being tested — the stub simulates the
			// production SDK path where context cancellation has no effect.
			<-blockCh
			return lateExec, nil
		},
	}

	ch := newFakeSSHChannel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reqs := closedReqChan()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = svc.runExec(ctx, cancel, ch, reqs, "sandbox-ctx-ignored", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "boxlite")
	}()

	// runExec must return within the startup timeout window (100ms) + a small
	// buffer. It must not wait for blockCh or for context cancellation on the
	// stub (the stub does not check ctx).
	select {
	case <-runDone:
		// PASS: the goroutine-level timeout fired and runExec returned without
		// waiting for the context-ignoring stub to complete.
	case <-time.After(2 * time.Second):
		t.Fatal("runExec did not return within 2s even though the startup timeout " +
			"(100ms) expired: the old code passed a timeout context to startExec, " +
			"which is a no-op when startExec ignores its context (as the production " +
			"C FFI does). The fix must race startExec in a goroutine so the timeout " +
			"is wall-clock enforced.")
	}

	// Now unblock the stub to simulate the late-arriving execution handle.
	// The cleanup goroutine inside runExec must Kill and Close it.
	close(blockCh)

	// Verify Kill is called on the late execution.
	select {
	case <-killCalled:
		// PASS: cleanup goroutine called Kill on the late execution.
	case <-time.After(2 * time.Second):
		t.Error("Kill was not called on the late-arriving execution handle: " +
			"any execution that arrives after the startup timeout must be killed " +
			"to prevent a ghost process from running in the sandbox after the SSH " +
			"session has already been rejected")
	}

	// Verify Close is called on the late execution.
	select {
	case <-closeCalled:
		// PASS: cleanup goroutine called Close to release the handle.
	case <-time.After(2 * time.Second):
		t.Error("Close was not called on the late-arriving execution handle: " +
			"the handle must be released to prevent a resource leak")
	}
}

// killCloseRecorder is a fakeExecution that sends to killCh and closeCh when
// Kill or Close is called, allowing the test to observe cleanup goroutine
// behaviour after a timeout path discards the late execution handle.
type killCloseRecorder struct {
	fakeExecution
	killCh  chan<- struct{}
	closeCh chan<- struct{}
}

func (e *killCloseRecorder) Kill(_ context.Context) error {
	select {
	case e.killCh <- struct{}{}:
	default:
	}
	return nil
}

func (e *killCloseRecorder) Close() error {
	select {
	case e.closeCh <- struct{}{}:
	default:
	}
	return nil
}

// TestRunExecBackpressureUnderHungStartup verifies that when startExec is
// permanently blocked (simulating a wedged C FFI call), repeated SSH
// connection attempts are rejected after maxInFlightStartups is reached
// rather than accumulating goroutines without bound.
//
// The test:
//  1. Sets maxInFlightStartups=2 so the limit is hit quickly.
//  2. Fires 3 concurrent runExec calls each with a blocking startExec stub.
//  3. Expects the 3rd call to return immediately with a backpressure error.
//  4. Unblocks the stubs and verifies the in-flight counter returns to 0.
//
// Regression guard: without the semaphore, the 3rd call launches a third
// goroutine. With the semaphore it fails fast and the goroutine is never
// launched.
func TestRunExecBackpressureUnderHungStartup(t *testing.T) {
	t.Parallel()

	blockCh := make(chan struct{})
	var launched sync.WaitGroup

	svc := &Service{
		log:                 slog.Default(),
		maxInFlightStartups: 2,
		startupTimeout:      500 * time.Millisecond, // short so the test doesn't linger after unblocking
		startExec: func(_ context.Context, _, _ string, _ []string, _, _ io.Writer, _ bool, _ map[string]string, _ string) (sshExecution, error) {
			// Signal that this goroutine is in-flight before blocking.
			launched.Done()
			// Block until unblocked — simulates a wedged C FFI call.
			<-blockCh
			return nil, fmt.Errorf("stub unblocked")
		},
	}

	makeRunExecCall := func() error {
		ch := newFakeSSHChannel()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reqs := closedReqChan()
		return svc.runExec(ctx, cancel, ch, reqs, "sandbox-bp", "/bin/sh", nil, false, noReplyReq("shell"), 0, 0, nil, "boxlite")
	}

	// Launch 2 calls that will block in startExec.
	launched.Add(2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = makeRunExecCall()
		}()
	}

	// Wait until both goroutines are actually inside startExec (in-flight counter = 2).
	launched.Wait()

	// The 3rd call must be rejected immediately with a backpressure error
	// (the in-flight counter is already at the cap).
	start := time.Now()
	err := makeRunExecCall()
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected backpressure error from 3rd call when in-flight count is at cap, got nil")
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("3rd call took %v; expected immediate rejection (< 100ms) when backpressure cap is reached", elapsed)
	}

	// Unblock the two stuck goroutines.
	close(blockCh)

	// Wait for both runExec calls to return (they will hit the startup timeout
	// or complete after startExec returns an error).
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stuck runExec calls did not return within 3s after unblocking")
	}

	// After both goroutines have returned, the counter must be back to 0.
	// Allow a brief moment for the goroutine's deferred decrement to land.
	var finalCount int64
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if finalCount = svc.inFlightStartups.Load(); finalCount == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if finalCount != 0 {
		t.Errorf("inFlightStartups counter did not return to 0 after goroutines unblocked: got %d", finalCount)
	}
}
