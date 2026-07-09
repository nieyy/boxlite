// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

// Package sessionbridge bridges BoxLite session frames (see
// docs/architecture/ssh-session-frame-protocol.md and pkg/sessionframe)
// arriving on an upgraded HTTP connection to real SSH sessions inside a
// guest. The bridge is the inner SSH *client*: it dials the guest's raw
// byte stream (box.SSH), performs the SSH handshake as root with "none"
// auth, and translates frames to SSH channel operations and back.
//
// The package has no dependency on the BoxLite SDK: the guest stream is
// injected as a GuestDialer, so the frame<->SSH logic is testable against
// an in-process SSH server.
package sessionbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"golang.org/x/crypto/ssh"
)

// guestHandshakeTimeout bounds the inner SSH handshake with the guest.
// The transport is a local vsock/unix stream, so a healthy handshake is
// milliseconds; this only guards against a wedged guest SSH service.
const guestHandshakeTimeout = 10 * time.Second

// Connection-level ERROR codes emitted by the bridge (channel 0).
const (
	codeProtocolError   = "PROTOCOL_ERROR"
	codeHandshakeFailed = "SSH_HANDSHAKE_FAILED"
	codeGuestOpenFailed = "GUEST_STREAM_OPEN_FAILED"
)

// Inner SSH client identity.
const (
	guestSSHUser        = "root"
	guestSSHNetworkName = "boxlite-guest"
)

// GuestDialer opens the raw guest SSH byte stream for this box
// (production: box.SSH via the BoxLite SDK). A *GuestDialError return
// carries a stable code that is forwarded verbatim to the Gateway.
type GuestDialer func(ctx context.Context) (net.Conn, error)

// GuestDialError is a typed guest-dial failure with a stable wire code
// (the SDK's SessionError codes, e.g. "VSOCK_CONNECT_FAILED"). Message
// must be user-safe: no socket paths, CIDs, or ports.
type GuestDialError struct {
	Code    string
	Message string
}

func (e *GuestDialError) Error() string {
	return fmt.Sprintf("guest dial failed: %s: %s", e.Code, e.Message)
}

// Bridge owns one upgraded Gateway connection and the inner SSH client
// connection it maps to. Create with New, drive with Run; everything else
// is internal.
type Bridge struct {
	transport net.Conn  // hijacked Gateway connection (writes + close)
	reader    io.Reader // buffered reader from Hijack (may hold pipelined bytes)
	logger    *slog.Logger

	// writeMu serializes every frame write: one writer owns the socket, and
	// blocking writes are the flow-control bound required by the spec.
	writeMu sync.Mutex

	mu       sync.Mutex
	channels map[uint32]*bridgeChannel
	used     map[uint32]bool // channel ids that ever carried an OPEN_* (unique per connection)

	client *ssh.Client

	closeOnce sync.Once
	wg        sync.WaitGroup // per-channel exit-watcher goroutines
}

// New wires a Bridge over a hijacked connection. reader must be the
// buffered reader returned by Hijack so pipelined frames are not lost.
func New(transport net.Conn, reader io.Reader, logger *slog.Logger) *Bridge {
	return &Bridge{
		transport: transport,
		reader:    reader,
		logger:    logger,
		channels:  make(map[uint32]*bridgeChannel),
		used:      make(map[uint32]bool),
	}
}

// Run dials the guest, performs the inner SSH handshake, and serves frames
// until the Gateway connection closes, the guest connection dies, or ctx is
// cancelled. It always closes the transport before returning and never
// leaks goroutines.
func (b *Bridge) Run(ctx context.Context, dial GuestDialer) {
	defer b.closeTransport()

	guest, err := dial(ctx)
	if err != nil {
		var de *GuestDialError
		if errors.As(err, &de) {
			b.sendConnError(de.Code, de.Message)
		} else {
			// Untyped errors may embed runtime addressing; log the detail,
			// send only a stable code + fixed message on the wire.
			b.logger.Error("guest session stream open failed", "error", err)
			b.sendConnError(codeGuestOpenFailed, "failed to open guest session stream")
		}
		return
	}

	client, err := b.handshakeGuest(guest)
	if err != nil {
		b.logger.Error("guest ssh handshake failed", "error", err)
		b.sendConnError(codeHandshakeFailed, "ssh handshake with guest failed")
		return
	}
	b.client = client

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Any of the three teardown triggers converge on closing the transport,
	// which unblocks the frame read loop deterministically:
	//   - guest SSH connection death -> cancel -> closeTransport
	//   - ctx cancellation           -> closeTransport
	//   - Gateway closing the socket -> read loop returns on its own
	b.wg.Add(2)
	go func() {
		defer b.wg.Done()
		_ = client.Wait()
		cancel()
	}()
	go func() {
		defer b.wg.Done()
		<-runCtx.Done()
		b.closeTransport()
	}()

	b.readLoop()

	cancel()
	b.teardownChannels()
	_ = client.Close() // also closes the guest conn and stops client.Wait
	b.wg.Wait()
}

// handshakeGuest performs the inner SSH handshake as the client.
func (b *Bridge) handshakeGuest(guest net.Conn) (*ssh.Client, error) {
	// NewClientConn has no timeout of its own (ClientConfig.Timeout only
	// applies to ssh.Dial); bound the handshake with a conn deadline.
	_ = guest.SetDeadline(time.Now().Add(guestHandshakeTimeout))
	sshConn, chans, reqs, err := ssh.NewClientConn(guest, guestSSHNetworkName, guestClientConfig())
	if err != nil {
		_ = guest.Close()
		return nil, err
	}
	_ = guest.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// guestClientConfig is the inner SSH client identity: root with "none"
// auth. x/crypto always attempts the "none" method before anything in
// config.Auth (client_auth.go: clientAuthenticate starts its loop with
// noneAuth), so an empty Auth list sends exactly one "none" userauth
// request — which is what the guest's SSH service accepts for root.
func guestClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            guestSSHUser,
		Auth:            nil,
		HostKeyCallback: trustGuestEphemeralHostKey(),
	}
}

// trustGuestEphemeralHostKey accepts any guest host key. The guest's SSH
// service generates an ephemeral host key on every boot, so pinning is
// impossible by design. The trust anchor is NOT the host key: box.SSH() hands
// us a private per-box vsock/unix endpoint that the Box Runtime resolved and
// owns, so only that box's guest can be on the other end (real-SSH design,
// §"两段 SSH 与翻译职责"). InsecureIgnoreHostKey is therefore the semantically
// correct callback; it is wrapped in a named function so the decision is
// greppable and suppressible in one place.
func trustGuestEphemeralHostKey() ssh.HostKeyCallback {
	return ssh.InsecureIgnoreHostKey()
}

// readLoop decodes and dispatches Gateway frames until the connection
// fails, the peer misbehaves fatally, or a decode-level protocol error
// occurs (per spec: send ERROR on channel 0, close the connection).
func (b *Bridge) readLoop() {
	for {
		f, err := sessionframe.ReadFrame(b.reader)
		if err != nil {
			if isProtocolError(err) {
				b.sendConnError(codeProtocolError, err.Error())
			} else if !errors.Is(err, io.EOF) {
				b.logger.Debug("session stream read ended", "error", err)
			}
			return
		}
		if fatal := b.dispatch(f); fatal {
			return
		}
	}
}

// isProtocolError reports whether a ReadFrame failure is one of the
// spec-defined protocol errors (vs. plain connection loss).
func isProtocolError(err error) bool {
	return errors.Is(err, sessionframe.ErrUnsupportedVersion) ||
		errors.Is(err, sessionframe.ErrUnknownType) ||
		errors.Is(err, sessionframe.ErrReservedFlags) ||
		errors.Is(err, sessionframe.ErrPayloadTooLarge)
}

// dispatch routes one decoded frame. It returns true when the connection
// must be torn down (channel-0 misuse, connection-level peer ERROR, or a
// broken request per the reply rules — the Gateway is a trusted internal
// peer, so any of these means it is unrecoverably out of sync).
func (b *Bridge) dispatch(f *sessionframe.Frame) (fatal bool) {
	if f.ChannelID == sessionframe.ControlChannelID && f.Type != sessionframe.FrameError {
		b.sendConnError(codeProtocolError,
			fmt.Sprintf("%s frame on reserved channel 0", f.Type))
		return true
	}
	if f.IsReply() {
		// The runner never sends requests, so replies cannot occur.
		b.sendConnError(codeProtocolError,
			fmt.Sprintf("unexpected REPLY %s frame from gateway", f.Type))
		return true
	}

	switch f.Type {
	case sessionframe.FrameOpenShell, sessionframe.FrameOpenExec:
		return b.handleOpen(f)
	case sessionframe.FramePtyRequest:
		return b.handlePtyRequest(f)
	case sessionframe.FramePtyResize:
		return b.handlePtyResize(f)
	case sessionframe.FrameStdin:
		b.handleStdin(f)
	case sessionframe.FrameEOF:
		b.handleStdinEOF(f)
	case sessionframe.FrameClose:
		b.handlePeerClose(f.ChannelID)
	case sessionframe.FrameError:
		if f.ChannelID == sessionframe.ControlChannelID {
			b.logger.Warn("gateway sent connection-level ERROR", "payload", string(f.Payload))
			return true
		}
		b.handlePeerClose(f.ChannelID)
	default:
		// Unknown types are rejected by ReadFrame; this leaves only
		// runner->gateway types (STDOUT/STDERR/EXIT_STATUS) arriving in the
		// wrong direction. Drop them: the spec defines no error for it and
		// they carry no side effects.
		b.logger.Warn("dropping wrong-direction frame", "type", f.Type.String(), "channel", f.ChannelID)
	}
	return false
}

// requireRequestID enforces the reply rule (request frames carry a nonzero
// request_id). Returns false and tears the connection down when violated.
func (b *Bridge) requireRequestID(f *sessionframe.Frame) bool {
	if f.RequestID != 0 {
		return true
	}
	b.sendConnError(codeProtocolError,
		fmt.Sprintf("%s request without request_id", f.Type))
	return false
}

// sendConnError emits a connection-level ERROR on channel 0 (best effort)
// and closes the transport, per the spec's protocol-error rule. The write
// is deadline-bounded: the connection is being abandoned either way, so a
// wedged peer must not pin this goroutine.
func (b *Bridge) sendConnError(code, message string) {
	payload, err := json.Marshal(sessionframe.ErrorPayload{Code: code, Message: message})
	if err != nil {
		// ErrorPayload holds two strings; Marshal cannot fail.
		panic(fmt.Sprintf("sessionbridge: marshal error payload: %v", err))
	}
	b.writeMu.Lock()
	_ = b.transport.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = sessionframe.EncodeTo(b.transport,
		sessionframe.NewData(sessionframe.FrameError, sessionframe.ControlChannelID, payload))
	b.writeMu.Unlock()
	b.closeTransport()
}

// writeFrame is the single serialized writer for the Gateway socket.
func (b *Bridge) writeFrame(f *sessionframe.Frame) error {
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	return sessionframe.EncodeTo(b.transport, f)
}

func (b *Bridge) closeTransport() {
	b.closeOnce.Do(func() {
		_ = b.transport.Close()
	})
}

// lookupChannel returns the live channel for id, or nil.
func (b *Bridge) lookupChannel(id uint32) *bridgeChannel {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.channels[id]
}

// removeChannel drops id from the live set and permanently burns it
// (idempotent). Every removal path — failed open, peer close, normal exit —
// must retire the id: pendingChannel's "ids are unique per connection"
// invariant only holds if b.used stays set once a channel has ever existed,
// not just once it has successfully opened.
func (b *Bridge) removeChannel(id uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.channels, id)
	b.used[id] = true
}

// teardownChannels closes every live SSH session so their exit watchers
// unblock; called once from Run after the read loop ends.
func (b *Bridge) teardownChannels() {
	b.mu.Lock()
	channels := make([]*bridgeChannel, 0, len(b.channels))
	for _, ch := range b.channels {
		channels = append(channels, ch)
	}
	b.channels = make(map[uint32]*bridgeChannel)
	b.mu.Unlock()

	for _, ch := range channels {
		ch.markPeerClosed() // suppress EXIT/EOF/CLOSE frames during teardown
		ch.closeSession()
	}
}
