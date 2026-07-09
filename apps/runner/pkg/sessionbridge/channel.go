// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

package sessionbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"golang.org/x/crypto/ssh"
)

// Reply error codes for failed channel requests.
const (
	codeBadPayload         = "BAD_PAYLOAD"
	codeChannelReused      = "CHANNEL_REUSED"
	codeChannelAlreadyOpen = "CHANNEL_ALREADY_OPEN"
	codeChannelNotOpen     = "CHANNEL_NOT_OPEN"
	codeOpenFailed         = "OPEN_FAILED"
	codePtyFailed          = "PTY_FAILED"
	codeResizeFailed       = "RESIZE_FAILED"
)

// exitCodeMissing is reported when the guest tears the channel down without
// an exit-status (session.Wait returns *ssh.ExitMissingError — e.g. the
// process was reaped by a dying guest SSH service) and for transport-level
// Wait failures. 255 mirrors OpenSSH's "remote failure" convention.
const exitCodeMissing = 255

// stdinQueueDepth bounds per-channel stdin buffering (spec: "Implementations
// MUST bound per-channel buffering... enforcement is implementation-level,
// not wire-level" — v1 has no window/credit frames). Matches boxlite-guest's
// STDIN_QUEUE_DEPTH on the guest side for consistency. Sized for interactive
// shell/exec input (keystrokes, small pastes); a channel whose guest process
// never drains stdin for this many frames has a stuck process either way —
// dropping keeps sibling channels on the same connection responsive instead
// of blocking the shared frame dispatcher on one wedged channel.
const stdinQueueDepth = 32

// errChannelClosed stops the SSH output copiers once the Gateway closed the
// channel; late output has nowhere to go.
var errChannelClosed = errors.New("sessionbridge: channel closed by gateway")

// bridgeChannel is one Gateway frame channel mapped onto one SSH session.
type bridgeChannel struct {
	id     uint32
	bridge *Bridge

	// ready is closed once the OPEN_* reply is on the wire. Output frame
	// writers and the exit watcher block on it so no STDOUT/STDERR/
	// EXIT_STATUS can precede the ok reply (spec ordering rule).
	ready chan struct{}

	// stdinCh decouples handleStdin (called synchronously from the single
	// shared readLoop/dispatch path) from the guest's stdin.Write, which can
	// block indefinitely if the guest process stops draining — without this,
	// one stalled channel would freeze frame dispatch for every other
	// multiplexed channel on the connection. stdinWriter is the SOLE
	// reader/writer/closer of the underlying stdin pipe: it drains stdinCh in
	// order, then (on stdinEOF) drains whatever is still buffered before
	// closing the pipe — closing must never race a queued-but-not-yet-written
	// byte, and must never happen on the dispatch goroutine directly (that
	// would let a wedged channel's Close/Write race, same class of bug as the
	// blocking-write problem this exists to fix). stdinEOF/stdinDone are
	// closed (not sent-to) so multiple teardown paths can signal safely.
	stdinCh   chan []byte
	stdinEOF  chan struct{} // closed once: gateway sent FrameEOF for this channel
	stdinDone chan struct{} // closed once: channel is tearing down regardless of EOF

	mu          sync.Mutex
	pty         *sessionframe.PtyRequestPayload // recorded before open
	session     *ssh.Session
	stdin       io.WriteCloser
	stdinClosed bool
	peerClosed  bool // gateway sent CLOSE/ERROR: suppress further frames
}

// pendingChannel returns the channel record for id, creating it if this is
// the first frame referencing the id. Returns nil when the id was already
// consumed by a finished OPEN (ids are unique per connection).
func (b *Bridge) pendingChannel(id uint32) *bridgeChannel {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.channels[id]; ok {
		return ch
	}
	if b.used[id] {
		return nil
	}
	ch := &bridgeChannel{
		id:        id,
		bridge:    b,
		ready:     make(chan struct{}),
		stdinCh:   make(chan []byte, stdinQueueDepth),
		stdinEOF:  make(chan struct{}),
		stdinDone: make(chan struct{}),
	}
	b.channels[id] = ch
	return ch
}

// handleOpen serves OPEN_SHELL and OPEN_EXEC: open an SSH session channel,
// apply any recorded PTY request first, start the shell/command, and reply.
func (b *Bridge) handleOpen(f *sessionframe.Frame) (fatal bool) {
	if !b.requireRequestID(f) {
		return true
	}
	reply := func(err error, code string) {
		if err == nil {
			_ = b.writeFrame(sessionframe.NewReplyOK(f.Type, f.ChannelID, f.RequestID))
		} else {
			_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID, code, err.Error()))
		}
	}

	var command string
	if f.Type == sessionframe.FrameOpenExec {
		var payload sessionframe.OpenExecPayload
		if err := json.Unmarshal(f.Payload, &payload); err != nil || payload.Command == "" {
			reply(fmt.Errorf("invalid OPEN_EXEC payload"), codeBadPayload)
			return false
		}
		command = payload.Command
	}

	ch := b.pendingChannel(f.ChannelID)
	if ch == nil {
		reply(fmt.Errorf("channel id already used on this connection"), codeChannelReused)
		return false
	}
	ch.mu.Lock()
	alreadyOpen := ch.session != nil
	pty := ch.pty
	ch.mu.Unlock()
	if alreadyOpen {
		reply(fmt.Errorf("channel already has an open session"), codeChannelAlreadyOpen)
		return false
	}

	session, stdin, err := ch.openSession(command, pty)
	if err != nil {
		b.removeChannel(f.ChannelID)
		reply(err, codeOpenFailed)
		return false
	}

	ch.mu.Lock()
	ch.session = session
	ch.stdin = stdin
	ch.mu.Unlock()
	b.mu.Lock()
	b.used[f.ChannelID] = true
	b.mu.Unlock()

	reply(nil, "")
	// Only now may output flow (spec: data only after the ok reply).
	close(ch.ready)

	b.wg.Add(2)
	go ch.stdinWriter()
	go ch.waitAndReport()
	return false
}

// openSession builds and starts the SSH session for this channel. Output
// writers are installed before start; they gate on ch.ready, so nothing is
// emitted until the ok reply is written.
func (ch *bridgeChannel) openSession(command string, pty *sessionframe.PtyRequestPayload) (*ssh.Session, io.WriteCloser, error) {
	session, err := ch.bridge.client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("open guest session: %w", err)
	}
	session.Stdout = &frameWriter{ch: ch, frameType: sessionframe.FrameStdout}
	session.Stderr = &frameWriter{ch: ch, frameType: sessionframe.FrameStderr}
	stdin, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("open stdin pipe: %w", err)
	}
	if pty != nil {
		if err := requestPty(session, pty.Term, pty.Rows, pty.Cols); err != nil {
			_ = session.Close()
			return nil, nil, fmt.Errorf("request pty: %w", err)
		}
	}
	if command != "" {
		err = session.Start(command)
	} else {
		err = session.Shell()
	}
	if err != nil {
		_ = session.Close()
		return nil, nil, fmt.Errorf("start session: %w", err)
	}
	return session, stdin, nil
}

// requestPty forwards a PTY request to the guest. x/crypto synthesizes the
// pixel dimensions from cols/rows, so width_px/height_px from the frame are
// intentionally dropped — the guest terminal only honors cols/rows anyway.
func requestPty(session *ssh.Session, term string, rows, cols uint32) error {
	if term == "" {
		term = "xterm"
	}
	return session.RequestPty(term, int(rows), int(cols), ssh.TerminalModes{})
}

// handlePtyRequest records terminal parameters for a channel; if the
// channel is already open the request is forwarded to the guest at once.
func (b *Bridge) handlePtyRequest(f *sessionframe.Frame) (fatal bool) {
	if !b.requireRequestID(f) {
		return true
	}
	var payload sessionframe.PtyRequestPayload
	if err := json.Unmarshal(f.Payload, &payload); err != nil {
		_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
			codeBadPayload, "invalid PTY_REQUEST payload"))
		return false
	}
	ch := b.pendingChannel(f.ChannelID)
	if ch == nil {
		_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
			codeChannelReused, "channel id already used on this connection"))
		return false
	}
	ch.mu.Lock()
	session := ch.session
	if session == nil {
		ch.pty = &payload
	}
	ch.mu.Unlock()

	if session != nil {
		if err := requestPty(session, payload.Term, payload.Rows, payload.Cols); err != nil {
			_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
				codePtyFailed, err.Error()))
			return false
		}
	}
	_ = b.writeFrame(sessionframe.NewReplyOK(f.Type, f.ChannelID, f.RequestID))
	return false
}

// handlePtyResize forwards a window change to the guest session.
func (b *Bridge) handlePtyResize(f *sessionframe.Frame) (fatal bool) {
	if !b.requireRequestID(f) {
		return true
	}
	var payload sessionframe.PtyResizePayload
	if err := json.Unmarshal(f.Payload, &payload); err != nil {
		_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
			codeBadPayload, "invalid PTY_RESIZE payload"))
		return false
	}
	ch := b.lookupChannel(f.ChannelID)
	if ch == nil || ch.liveSession() == nil {
		_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
			codeChannelNotOpen, "channel has no open session"))
		return false
	}
	if err := ch.liveSession().WindowChange(int(payload.Rows), int(payload.Cols)); err != nil {
		_ = b.writeFrame(sessionframe.NewReplyErr(f.Type, f.ChannelID, f.RequestID,
			codeResizeFailed, err.Error()))
		return false
	}
	_ = b.writeFrame(sessionframe.NewReplyOK(f.Type, f.ChannelID, f.RequestID))
	return false
}

// handleStdin enqueues Gateway bytes for stdinWriter to deliver. Frames for
// unknown channels are dropped: they legitimately race with channel exit.
// This must never block: it runs on the single shared dispatch path, so a
// blocking send here would stall every other multiplexed channel on the
// connection behind this one's guest process. If the bounded queue is full
// (guest genuinely not draining stdin), the frame is dropped — the spec
// requires per-channel buffering to be bounded, not lossless.
func (b *Bridge) handleStdin(f *sessionframe.Frame) {
	ch := b.lookupChannel(f.ChannelID)
	if ch == nil {
		return
	}
	ch.mu.Lock()
	closed := ch.stdinClosed
	ch.mu.Unlock()
	if closed {
		return
	}
	select {
	case ch.stdinCh <- f.Payload:
	default:
		b.logger.Warn("stdin queue full — dropping frame (guest not draining stdin)",
			"channel", f.ChannelID, "bytes", len(f.Payload))
	}
}

// stdinWriter is the sole writer to the guest's stdin pipe for this channel,
// draining stdinCh in order so handleStdin's shared-dispatch-path send never
// has to perform the (potentially blocking) pipe write itself. Exits once
// stdinDone is closed (by waitAndReport, on every teardown path).
func (ch *bridgeChannel) stdinWriter() {
	defer ch.bridge.wg.Done()
	for {
		select {
		case data := <-ch.stdinCh:
			ch.writeStdin(data)
		case <-ch.stdinEOF:
			// select can race stdinCh vs stdinEOF becoming ready together,
			// but by the time closeStdin ran, every prior handleStdin send
			// had already returned (single dispatch goroutine, in order) —
			// so anything still queued is already sitting in the buffer.
			// Drain it before closing so EOF never overtakes queued bytes.
			ch.drainStdin()
			_ = ch.stdin.Close()
			return
		case <-ch.stdinDone:
			return
		}
	}
}

func (ch *bridgeChannel) writeStdin(data []byte) {
	if _, err := ch.stdin.Write(data); err != nil {
		ch.bridge.logger.Debug("stdin write failed", "channel", ch.id, "error", err)
	}
}

// drainStdin flushes whatever is currently buffered in stdinCh, non-blocking.
func (ch *bridgeChannel) drainStdin() {
	for {
		select {
		case data := <-ch.stdinCh:
			ch.writeStdin(data)
		default:
			return
		}
	}
}

// handleStdinEOF half-closes the channel: stdin is closed, the session and
// its output direction stay alive.
func (b *Bridge) handleStdinEOF(f *sessionframe.Frame) {
	ch := b.lookupChannel(f.ChannelID)
	if ch == nil {
		return
	}
	ch.closeStdin()
}

// handlePeerClose serves a Gateway CLOSE (or channel-level ERROR): kill the
// guest process best-effort and tear the SSH session down. No reply is
// defined for CLOSE. Unknown ids are ignored — CLOSE races with our own
// exit-driven CLOSE by design.
func (b *Bridge) handlePeerClose(id uint32) {
	ch := b.lookupChannel(id)
	if ch == nil {
		return
	}
	b.removeChannel(id)
	ch.markPeerClosed()
	if session := ch.liveSession(); session != nil {
		_ = session.Signal(ssh.SIGKILL)
	}
	ch.closeSession()
}

func (ch *bridgeChannel) liveSession() *ssh.Session {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.session
}

func (ch *bridgeChannel) markPeerClosed() {
	ch.mu.Lock()
	ch.peerClosed = true
	ch.mu.Unlock()
}

func (ch *bridgeChannel) isPeerClosed() bool {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	return ch.peerClosed
}

// closeStdin signals EOF to stdinWriter, which owns the actual pipe close
// (see stdinWriter: must drain queued bytes first, and must not race
// stdinWriter's concurrent Write calls on the same io.WriteCloser).
func (ch *bridgeChannel) closeStdin() {
	ch.mu.Lock()
	alreadyClosed := ch.stdinClosed
	ch.stdinClosed = true
	ch.mu.Unlock()
	if !alreadyClosed {
		close(ch.stdinEOF)
	}
}

func (ch *bridgeChannel) closeSession() {
	if session := ch.liveSession(); session != nil {
		_ = session.Close()
	}
}

// waitAndReport waits for the guest command to exit and reports
// EXIT_STATUS, EOF, CLOSE in spec order. session.Wait only returns after
// the stdout/stderr copiers finish, so all output frames precede
// EXIT_STATUS. Frames are suppressed when the Gateway already closed the
// channel (or the whole connection is being torn down).
func (ch *bridgeChannel) waitAndReport() {
	defer ch.bridge.wg.Done()
	defer close(ch.stdinDone) // stop stdinWriter — every teardown path runs this

	err := ch.liveSession().Wait()
	code := exitCodeFromWait(err)

	ch.bridge.removeChannel(ch.id)
	<-ch.ready
	if ch.isPeerClosed() {
		return
	}

	payload, merr := json.Marshal(sessionframe.ExitStatusPayload{Code: code})
	if merr != nil {
		// ExitStatusPayload is a single int32; Marshal cannot fail.
		panic(fmt.Sprintf("sessionbridge: marshal exit status: %v", merr))
	}
	_ = ch.bridge.writeFrame(sessionframe.NewData(sessionframe.FrameExitStatus, ch.id, payload))
	_ = ch.bridge.writeFrame(sessionframe.NewData(sessionframe.FrameEOF, ch.id, nil))
	_ = ch.bridge.writeFrame(sessionframe.NewData(sessionframe.FrameClose, ch.id, nil))
}

// exitCodeFromWait maps session.Wait's result onto the wire exit code.
func exitCodeFromWait(err error) int32 {
	if err == nil {
		return 0
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return int32(exitErr.ExitStatus())
	}
	// *ssh.ExitMissingError or a transport failure: see exitCodeMissing.
	return exitCodeMissing
}

// frameWriter turns guest stdout/stderr bytes into STDOUT/STDERR frames,
// chunked to MaxPayload. Writes block on the shared frame writer, which is
// the per-channel flow-control bound: backpressure propagates through the
// SSH channel window instead of buffering unboundedly.
type frameWriter struct {
	ch        *bridgeChannel
	frameType sessionframe.FrameType
}

func (w *frameWriter) Write(p []byte) (int, error) {
	<-w.ch.ready // no output before the OPEN_* ok reply
	written := 0
	for len(p) > 0 {
		if w.ch.isPeerClosed() {
			return written, errChannelClosed
		}
		n := len(p)
		if n > sessionframe.MaxPayload {
			n = sessionframe.MaxPayload
		}
		// EncodeTo copies the payload into its wire buffer, so the subslice
		// can be handed over without copying here.
		if err := w.ch.bridge.writeFrame(sessionframe.NewData(w.frameType, w.ch.id, p[:n])); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
