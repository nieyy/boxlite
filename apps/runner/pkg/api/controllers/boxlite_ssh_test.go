// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

package controllers

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdkboxlite "github.com/boxlite-ai/boxlite/sdks/go"
	"github.com/boxlite-ai/runner/pkg/api/middlewares"
	"github.com/boxlite-ai/runner/pkg/common"
	"github.com/boxlite-ai/runner/pkg/models/enums"
	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	common_errors "github.com/boxlite-ai/common-go/pkg/errors"
)

// fakeSessionBox substitutes the SDK box handle behind the resolve seam.
type fakeSessionBox struct {
	readiness sdkboxlite.SessionReadiness
	readyErr  error
	sshFn     func(ctx context.Context) (net.Conn, error)
}

func (f *fakeSessionBox) SessionReady(ctx context.Context, service string) (sdkboxlite.SessionReadiness, error) {
	return f.readiness, f.readyErr
}

func (f *fakeSessionBox) SSH(ctx context.Context) (net.Conn, error) {
	if f.sshFn == nil {
		return nil, errors.New("fakeSessionBox: SSH not wired")
	}
	return f.sshFn(ctx)
}

// withSessionBox overrides resolveSessionBox for the test duration.
func withSessionBox(t *testing.T, box sessionBox, state enums.BoxState, err error) {
	t.Helper()
	prev := resolveSessionBox
	resolveSessionBox = func(ctx context.Context, boxId string) (sessionBox, enums.BoxState, error) {
		return box, state, err
	}
	t.Cleanup(func() { resolveSessionBox = prev })
}

// newSshRouter builds the same middleware/route shape server.go registers.
// apiToken == "" disables auth (the seam-focused tests); otherwise the real
// AuthMiddleware guards both routes.
func newSshRouter(apiToken string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(common_errors.NewErrorMiddleware(common.HandlePossibleDockerError))
	group := r.Group("/")
	if apiToken != "" {
		group.Use(middlewares.AuthMiddleware(apiToken))
	}
	group.GET("/v1/boxes/:boxId/ssh-status", BoxliteSshStatus)
	group.POST("/internal/ssh/sessions/:boxId/stream", InternalSshSessionStream)
	return r
}

// upgradeHeaders returns a valid boxlite-session-stream handshake header
// set; tests mutate it to build the fail-closed matrix.
func upgradeHeaders() map[string]string {
	return map[string]string{
		"Upgrade":                    sessionframe.UpgradeProtocol,
		"Connection":                 "Upgrade",
		sessionframe.HeaderSessionID: "sess-1",
		sessionframe.HeaderTokenID:   "tok-1",
		sessionframe.HeaderUnixUser:  "root",
	}
}

// rawUpgradeRequest performs the handshake over a raw TCP connection (the
// std http.Client cannot speak custom upgrades) and returns the connection
// plus the parsed HTTP response. The caller owns the connection.
func rawUpgradeRequest(t *testing.T, srv *httptest.Server, boxId string, headers map[string]string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	var req strings.Builder
	fmt.Fprintf(&req, "POST /internal/ssh/sessions/%s/stream HTTP/1.1\r\nHost: runner\r\n", boxId)
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req.String())); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	return conn, br, resp
}

// bodyReason decodes the "reason" field of a JSON rejection body.
func bodyReason(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode rejection body: %v", err)
	}
	return body.Reason
}

func TestInternalSshStreamFailClosedMatrix(t *testing.T) {
	readyBox := &fakeSessionBox{readiness: sdkboxlite.SessionReadiness{Ready: true}}

	cases := []struct {
		name       string
		mutate     func(h map[string]string)
		box        sessionBox
		state      enums.BoxState
		resolveErr error
		wantStatus int
		wantReason string
	}{
		{
			name:       "missing upgrade header",
			mutate:     func(h map[string]string) { delete(h, "Upgrade") },
			box:        readyBox,
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusBadRequest,
			wantReason: reasonInvalidUpgrade,
		},
		{
			name:       "wrong upgrade protocol",
			mutate:     func(h map[string]string) { h["Upgrade"] = "websocket" },
			box:        readyBox,
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusBadRequest,
			wantReason: reasonInvalidUpgrade,
		},
		{
			name:       "missing session id header",
			mutate:     func(h map[string]string) { delete(h, sessionframe.HeaderSessionID) },
			box:        readyBox,
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusBadRequest,
			wantReason: reasonInvalidUpgrade,
		},
		{
			name:       "unknown box",
			mutate:     func(h map[string]string) {},
			resolveErr: fmt.Errorf("%w: box-x", errSessionBoxNotFound),
			wantStatus: http.StatusNotFound,
			wantReason: reasonBoxNotFound,
		},
		{
			name:       "stopped box",
			mutate:     func(h map[string]string) {},
			box:        readyBox,
			state:      enums.BoxStateStopped,
			wantStatus: http.StatusConflict,
			wantReason: reasonBoxStopped,
		},
		{
			name:       "non-root unix user",
			mutate:     func(h map[string]string) { h[sessionframe.HeaderUnixUser] = "ubuntu" },
			box:        readyBox,
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusForbidden,
			wantReason: reasonUnixUserForbidden,
		},
		{
			name:   "guest service not ready",
			mutate: func(h map[string]string) {},
			box: &fakeSessionBox{readiness: sdkboxlite.SessionReadiness{
				Ready:  false,
				Reason: &sdkboxlite.SessionError{Code: "GUEST_SERVICE_NOT_READY", Message: "guest SSH service not up"},
			}},
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusServiceUnavailable,
			wantReason: "GUEST_SERVICE_NOT_READY",
		},
		{
			name:   "readiness probe session error",
			mutate: func(h map[string]string) {},
			box: &fakeSessionBox{
				readyErr: &sdkboxlite.SessionError{Code: "VSOCK_CONNECT_FAILED", Message: "cannot reach guest"},
			},
			state:      enums.BoxStateStarted,
			wantStatus: http.StatusServiceUnavailable,
			wantReason: "VSOCK_CONNECT_FAILED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSessionBox(t, tc.box, tc.state, tc.resolveErr)
			srv := httptest.NewServer(newSshRouter(""))
			defer srv.Close()

			headers := upgradeHeaders()
			tc.mutate(headers)
			conn, _, resp := rawUpgradeRequest(t, srv, "box-1", headers)
			defer conn.Close()

			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if got := bodyReason(t, resp); got != tc.wantReason {
				t.Fatalf("reason = %q, want %q", got, tc.wantReason)
			}
		})
	}
}

func TestInternalSshStreamAuthRequired(t *testing.T) {
	withSessionBox(t, &fakeSessionBox{readiness: sdkboxlite.SessionReadiness{Ready: true}},
		enums.BoxStateStarted, nil)
	srv := httptest.NewServer(newSshRouter("secret-token"))
	defer srv.Close()

	// No Authorization header -> the middleware rejects with 401.
	conn, _, resp := rawUpgradeRequest(t, srv, "box-1", upgradeHeaders())
	defer conn.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status without auth = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// With the right bearer token the request passes the middleware (and is
	// then rejected by upgrade validation, proving auth ran first and ok).
	headers := upgradeHeaders()
	headers["Authorization"] = "Bearer secret-token"
	delete(headers, "Upgrade")
	conn2, _, resp2 := rawUpgradeRequest(t, srv, "box-1", headers)
	defer conn2.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("status with auth = %d, want 400 (past middleware)", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// miniGuestSSH is a minimal in-test SSH server (none auth for root, exec
// only) used to drive the full HTTP-upgrade happy path. It listens on
// loopback TCP: the SSH handshake has both sides write their version banner
// first, which deadlocks on a synchronous unbuffered net.Pipe.
type miniGuestSSH struct {
	listener net.Listener
}

func newMiniGuestSSH(t *testing.T) *miniGuestSSH {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveMiniGuestConn(conn, config)
		}
	}()
	return &miniGuestSSH{listener: listener}
}

// serveMiniGuestConn serves one SSH connection: every exec writes "out" to
// stdout, "err" to stderr, and exits 42.
func serveMiniGuestConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range requests {
				if req.Type != "exec" {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				_ = req.Reply(true, nil)
				_, _ = ch.Write([]byte("out"))
				_, _ = ch.Stderr().Write([]byte("err"))
				status := struct{ Status uint32 }{42}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
				_ = ch.Close()
			}
		}()
	}
}

func (g *miniGuestSSH) dial(ctx context.Context) (net.Conn, error) {
	return net.Dial("tcp", g.listener.Addr().String())
}

func TestInternalSshStreamHappyPath(t *testing.T) {
	guest := newMiniGuestSSH(t)
	withSessionBox(t, &fakeSessionBox{
		readiness: sdkboxlite.SessionReadiness{Ready: true},
		sshFn:     guest.dial,
	}, enums.BoxStateStarted, nil)
	srv := httptest.NewServer(newSshRouter(""))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	request := "POST /internal/ssh/sessions/box-1/stream HTTP/1.1\r\n" +
		"Host: runner\r\n" +
		"Upgrade: " + sessionframe.UpgradeProtocol + "\r\n" +
		"Connection: Upgrade\r\n" +
		sessionframe.HeaderSessionID + ": sess-1\r\n" +
		sessionframe.HeaderTokenID + ": tok-1\r\n" +
		sessionframe.HeaderUnixUser + ": root\r\n\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// The 101 handshake must be byte-exact per the protocol spec.
	wantHandshake := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: boxlite-session-stream\r\nConnection: Upgrade\r\n\r\n"
	handshake := make([]byte, len(wantHandshake))
	if _, err := io.ReadFull(conn, handshake); err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if string(handshake) != wantHandshake {
		t.Fatalf("handshake = %q, want %q", handshake, wantHandshake)
	}

	// OPEN_EXEC on channel 5 -> ok reply, output frames, exit 42, EOF, CLOSE.
	execPayload, _ := json.Marshal(sessionframe.OpenExecPayload{Command: "anything"})
	if err := sessionframe.EncodeTo(conn, sessionframe.NewRequest(sessionframe.FrameOpenExec, 5, 1, execPayload)); err != nil {
		t.Fatalf("send OPEN_EXEC: %v", err)
	}

	br := bufio.NewReader(conn)
	reply, err := sessionframe.ReadFrame(br)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply.Type != sessionframe.FrameOpenExec || !reply.IsReply() || reply.ChannelID != 5 || reply.RequestID != 1 {
		t.Fatalf("unexpected reply frame: %s flags=%#x ch=%d req=%d", reply.Type, reply.Flags, reply.ChannelID, reply.RequestID)
	}
	var replyPayload sessionframe.ReplyPayload
	if err := json.Unmarshal(reply.Payload, &replyPayload); err != nil || !replyPayload.Ok {
		t.Fatalf("expected ok reply, got %s", reply.Payload)
	}

	var stdout, stderr []byte
	var exitCode *int32
	sawEOF, sawClose := false, false
	for !sawClose {
		f, err := sessionframe.ReadFrame(br)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if f.ChannelID != 5 {
			t.Fatalf("frame %s on channel %d, want 5", f.Type, f.ChannelID)
		}
		switch f.Type {
		case sessionframe.FrameStdout:
			stdout = append(stdout, f.Payload...)
		case sessionframe.FrameStderr:
			stderr = append(stderr, f.Payload...)
		case sessionframe.FrameExitStatus:
			var p sessionframe.ExitStatusPayload
			if err := json.Unmarshal(f.Payload, &p); err != nil {
				t.Fatalf("bad exit payload: %v", err)
			}
			exitCode = &p.Code
		case sessionframe.FrameEOF:
			sawEOF = true
		case sessionframe.FrameClose:
			sawClose = true
		default:
			t.Fatalf("unexpected frame %s", f.Type)
		}
	}
	if string(stdout) != "out" || string(stderr) != "err" {
		t.Fatalf("stdout=%q stderr=%q, want out/err", stdout, stderr)
	}
	if exitCode == nil || *exitCode != 42 {
		t.Fatalf("exit code = %v, want 42", exitCode)
	}
	if !sawEOF {
		t.Fatal("no EOF frame before CLOSE")
	}
}

func TestInternalSshStreamGuestDialSessionError(t *testing.T) {
	withSessionBox(t, &fakeSessionBox{
		readiness: sdkboxlite.SessionReadiness{Ready: true},
		sshFn: func(ctx context.Context) (net.Conn, error) {
			return nil, &sdkboxlite.SessionError{Code: "VSOCK_CONNECT_FAILED", Message: "guest endpoint unavailable"}
		},
	}, enums.BoxStateStarted, nil)
	srv := httptest.NewServer(newSshRouter(""))
	defer srv.Close()

	conn, br, resp := rawUpgradeRequest(t, srv, "box-1", upgradeHeaders())
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	f, err := sessionframe.ReadFrame(br)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if f.Type != sessionframe.FrameError || f.ChannelID != sessionframe.ControlChannelID {
		t.Fatalf("expected connection-level ERROR, got %s ch=%d", f.Type, f.ChannelID)
	}
	var payload sessionframe.ErrorPayload
	if err := json.Unmarshal(f.Payload, &payload); err != nil {
		t.Fatalf("bad ERROR payload: %v", err)
	}
	if payload.Code != "VSOCK_CONNECT_FAILED" {
		t.Fatalf("error code = %q, want VSOCK_CONNECT_FAILED", payload.Code)
	}
	if _, err := sessionframe.ReadFrame(br); err == nil {
		t.Fatal("expected connection close after connection-level ERROR")
	}
}

func TestBoxliteSshStatus(t *testing.T) {
	t.Run("ready", func(t *testing.T) {
		withSessionBox(t, &fakeSessionBox{readiness: sdkboxlite.SessionReadiness{Ready: true}},
			enums.BoxStateStarted, nil)
		srv := httptest.NewServer(newSshRouter(""))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/boxes/box-1/ssh-status")
		if err != nil {
			t.Fatalf("GET ssh-status: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body SshStatusResponse
		raw, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("bad body %q: %v", raw, err)
		}
		if !body.Ready || body.Degraded || body.Transport != "boxlite-runtime-vsock" {
			t.Fatalf("body = %+v, want ready non-degraded vsock transport", body)
		}
	})

	t.Run("not ready reports code only", func(t *testing.T) {
		withSessionBox(t, &fakeSessionBox{readiness: sdkboxlite.SessionReadiness{
			Ready: false,
			Reason: &sdkboxlite.SessionError{
				Code:    "GUEST_SERVICE_NOT_READY",
				Message: "guest has not published the ssh service yet",
			},
		}}, enums.BoxStateStarted, nil)
		srv := httptest.NewServer(newSshRouter(""))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/boxes/box-1/ssh-status")
		if err != nil {
			t.Fatalf("GET ssh-status: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var body SshStatusResponse
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("bad body %q: %v", raw, err)
		}
		if body.Ready || !body.Degraded || body.DegradedReason != "GUEST_SERVICE_NOT_READY" {
			t.Fatalf("body = %+v, want degraded with stable code", body)
		}
		// The wire body must never expose runtime addressing ("port=" not
		// "port": the transport label legitimately contains "transport").
		for _, leak := range []string{"/", ".sock", "cid=", "port=", "127.0.0.1"} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("response body leaks %q: %s", leak, raw)
			}
		}
	})

	t.Run("session error from probe", func(t *testing.T) {
		withSessionBox(t, &fakeSessionBox{
			readyErr: &sdkboxlite.SessionError{Code: "BOX_STOPPED", Message: "box is stopped"},
		}, enums.BoxStateStarted, nil)
		srv := httptest.NewServer(newSshRouter(""))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/boxes/box-1/ssh-status")
		if err != nil {
			t.Fatalf("GET ssh-status: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body SshStatusResponse
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if !body.Degraded || body.DegradedReason != "BOX_STOPPED" {
			t.Fatalf("body = %+v, want degraded BOX_STOPPED", body)
		}
	})

	t.Run("non-session error is 500", func(t *testing.T) {
		withSessionBox(t, &fakeSessionBox{readyErr: errors.New("ffi exploded")},
			enums.BoxStateStarted, nil)
		srv := httptest.NewServer(newSshRouter(""))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/boxes/box-1/ssh-status")
		if err != nil {
			t.Fatalf("GET ssh-status: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", resp.StatusCode)
		}
	})

	t.Run("unknown box is 404", func(t *testing.T) {
		withSessionBox(t, nil, enums.BoxStateUnknown, fmt.Errorf("%w: box-1", errSessionBoxNotFound))
		srv := httptest.NewServer(newSshRouter(""))
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/v1/boxes/box-1/ssh-status")
		if err != nil {
			t.Fatalf("GET ssh-status: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})
}

func TestRedactTokenID(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"short", "short"},
		{"exactly8", "exactly8"},
		{"0123456789abcdef", "01234567..."},
		{"secret-token-id-with-entropy", "secret-t..."},
		{"日本語のトークン識別子です", "日本語のトークン..."},
	}
	for _, tc := range cases {
		if got := redactTokenID(tc.in); got != tc.want {
			t.Fatalf("redactTokenID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The redacted form must never reveal more than 8 characters + ellipsis.
	long := strings.Repeat("x", 256)
	if got := redactTokenID(long); len([]rune(got)) > 8+3 {
		t.Fatalf("redacted token too long: %q", got)
	}
	if strings.Contains(redactTokenID(long), strings.Repeat("x", 9)) {
		t.Fatal("redacted token reveals more than 8 characters")
	}
}
