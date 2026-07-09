// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

package sessionbridge

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"golang.org/x/crypto/ssh"
)

// guestEvent records one SSH request observed by the fake guest server, in
// arrival order per session.
type guestEvent struct {
	kind    string // "pty-req", "shell", "exec", "window-change"
	term    string
	cols    uint32
	rows    uint32
	command string
}

// fakeGuest is a real x/crypto SSH *server* on a loopback TCP socket, so
// the bridge's inner SSH client half is exercised for real: none auth for
// root, session channels, pty-req/shell/exec/window-change. TCP (not
// net.Pipe) because the SSH handshake has both sides write their version
// banner first — a fully synchronous unbuffered pipe deadlocks there.
type fakeGuest struct {
	t        *testing.T
	config   *ssh.ServerConfig
	listener net.Listener
	events   chan guestEvent

	// exec handlers by command string; return value is the exit status to
	// send (a negative value skips exit-status, closing the channel bare).
	exec  map[string]func(ch ssh.Channel) int
	shell func(ch ssh.Channel) int
}

func newFakeGuest(t *testing.T) *fakeGuest {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	// NoClientAuth accepts the "none" userauth request — the same contract
	// the guest's SSH service exposes for root.
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	g := &fakeGuest{
		t:        t,
		config:   config,
		listener: listener,
		events:   make(chan guestEvent, 64),
		exec:     make(map[string]func(ch ssh.Channel) int),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go g.serveConn(conn)
		}
	}()
	return g
}

// dialer hands the bridge a fresh connection served by this fake guest.
func (g *fakeGuest) dialer() GuestDialer {
	return func(ctx context.Context) (net.Conn, error) {
		return net.Dial("tcp", g.listener.Addr().String())
	}
}

func (g *fakeGuest) serveConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, g.config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go g.serveSession(ch, requests)
	}
}

func (g *fakeGuest) serveSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p struct {
				Term       string
				Cols, Rows uint32
				WidthPx    uint32
				HeightPx   uint32
				Modes      string
			}
			_ = ssh.Unmarshal(req.Payload, &p)
			g.events <- guestEvent{kind: "pty-req", term: p.Term, cols: p.Cols, rows: p.Rows}
			_ = req.Reply(true, nil)
		case "window-change":
			var p struct{ Cols, Rows, WidthPx, HeightPx uint32 }
			_ = ssh.Unmarshal(req.Payload, &p)
			g.events <- guestEvent{kind: "window-change", cols: p.Cols, rows: p.Rows}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			g.events <- guestEvent{kind: "shell"}
			handler := g.shell
			ok := handler != nil
			_ = req.Reply(ok, nil)
			if ok {
				go g.runHandler(ch, handler)
			}
		case "exec":
			var p struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &p)
			g.events <- guestEvent{kind: "exec", command: p.Command}
			handler := g.exec[p.Command]
			ok := handler != nil
			_ = req.Reply(ok, nil)
			if ok {
				go g.runHandler(ch, handler)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (g *fakeGuest) runHandler(ch ssh.Channel, handler func(ch ssh.Channel) int) {
	code := handler(ch)
	if code >= 0 {
		status := struct{ Status uint32 }{uint32(code)}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
	}
	_ = ch.Close()
}

// expectEvent waits for the next guest event and asserts its kind.
func (g *fakeGuest) expectEvent(t *testing.T, kind string) guestEvent {
	t.Helper()
	select {
	case ev := <-g.events:
		if ev.kind != kind {
			t.Fatalf("expected guest event %q, got %+v", kind, ev)
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for guest event %q", kind)
		return guestEvent{}
	}
}

// gatewayConn is the test's (Gateway-side) end of the bridged transport.
type gatewayConn struct {
	t    *testing.T
	conn net.Conn
	br   *bufio.Reader
	done <-chan struct{} // closed when Bridge.Run returns
}

// startBridge wires a Bridge over a net.Pipe transport and runs it against
// dial. The returned gatewayConn speaks raw session frames.
func startBridge(t *testing.T, dial GuestDialer) *gatewayConn {
	t.Helper()
	gwSide, bridgeSide := net.Pipe()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	bridge := New(bridgeSide, bufio.NewReader(bridgeSide), logger)

	done := make(chan struct{})
	go func() {
		bridge.Run(context.Background(), dial)
		close(done)
	}()
	t.Cleanup(func() {
		_ = gwSide.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("bridge.Run did not return after gateway close")
		}
	})
	return &gatewayConn{t: t, conn: gwSide, br: bufio.NewReader(gwSide), done: done}
}

func (g *gatewayConn) send(f *sessionframe.Frame) {
	g.t.Helper()
	_ = g.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := sessionframe.EncodeTo(g.conn, f); err != nil {
		g.t.Fatalf("send %s frame: %v", f.Type, err)
	}
}

// sendRaw writes raw bytes (for malformed-header tests).
func (g *gatewayConn) sendRaw(raw []byte) {
	g.t.Helper()
	_ = g.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := g.conn.Write(raw); err != nil {
		g.t.Fatalf("send raw bytes: %v", err)
	}
}

func (g *gatewayConn) readFrame() *sessionframe.Frame {
	g.t.Helper()
	_ = g.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := sessionframe.ReadFrame(g.br)
	if err != nil {
		g.t.Fatalf("read frame: %v", err)
	}
	return f
}

// expectReplyOK reads the next frame and asserts it is an ok reply to the
// given request.
func (g *gatewayConn) expectReplyOK(frameType sessionframe.FrameType, channelID, requestID uint32) {
	g.t.Helper()
	f := g.readFrame()
	if f.Type != frameType || !f.IsReply() || f.ChannelID != channelID || f.RequestID != requestID {
		g.t.Fatalf("expected REPLY %s ch=%d req=%d, got %s flags=%#x ch=%d req=%d payload=%s",
			frameType, channelID, requestID, f.Type, f.Flags, f.ChannelID, f.RequestID, f.Payload)
	}
	var reply sessionframe.ReplyPayload
	if err := json.Unmarshal(f.Payload, &reply); err != nil || !reply.Ok {
		g.t.Fatalf("expected {\"ok\":true} reply, got %s (err=%v)", f.Payload, err)
	}
}

// expectClosed asserts the bridge closes the connection (EOF on read).
func (g *gatewayConn) expectClosed() {
	g.t.Helper()
	_ = g.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if f, err := sessionframe.ReadFrame(g.br); err == nil {
		g.t.Fatalf("expected connection close, got %s frame", f.Type)
	}
	select {
	case <-g.done:
	case <-time.After(5 * time.Second):
		g.t.Fatal("bridge.Run did not return after connection close")
	}
}

// openExec opens channelID with command and consumes the ok reply.
func (g *gatewayConn) openExec(channelID, requestID uint32, command string) {
	g.t.Helper()
	payload, _ := json.Marshal(sessionframe.OpenExecPayload{Command: command})
	g.send(sessionframe.NewRequest(sessionframe.FrameOpenExec, channelID, requestID, payload))
	g.expectReplyOK(sessionframe.FrameOpenExec, channelID, requestID)
}

// rawHeader builds a 16-byte frame header with arbitrary field values.
func rawHeader(version uint8, frameType uint8, flags uint16, channelID, requestID, payloadLen uint32) []byte {
	hdr := make([]byte, sessionframe.HeaderLen)
	hdr[0] = version
	hdr[1] = frameType
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint32(hdr[4:8], channelID)
	binary.BigEndian.PutUint32(hdr[8:12], requestID)
	binary.BigEndian.PutUint32(hdr[12:16], payloadLen)
	return hdr
}

// decodeErrorPayload unmarshals an ERROR frame payload.
func decodeErrorPayload(t *testing.T, f *sessionframe.Frame) sessionframe.ErrorPayload {
	t.Helper()
	if f.Type != sessionframe.FrameError {
		t.Fatalf("expected ERROR frame, got %s", f.Type)
	}
	var payload sessionframe.ErrorPayload
	if err := json.Unmarshal(f.Payload, &payload); err != nil {
		t.Fatalf("bad ERROR payload %q: %v", f.Payload, err)
	}
	return payload
}
