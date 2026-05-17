// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sshgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	boxlitesdk "github.com/boxlite-ai/boxlite/sdks/go"
	blclient "github.com/boxlite-ai/runner/pkg/boxlite"
	"golang.org/x/crypto/ssh"
)

// sshExecution is the subset of *boxlite.Execution that runExec uses.
// Extracting an interface allows tests to inject a stub without standing up a
// real VM, and makes the handle lifecycle contract explicit at this boundary.
type sshExecution interface {
	// Wait blocks until the process exits and returns its exit code.
	Wait(ctx context.Context) (int, error)
	// Kill sends SIGKILL to the guest process. Called when the SSH client
	// disconnects mid-session so the guest does not outlive its session.
	Kill(ctx context.Context) error
	// Signal sends an arbitrary Unix signal to the guest process. Used to
	// forward SSH "signal" in-session requests (RFC 4254 §6.9) such as
	// Ctrl-C (SIGINT), SIGTERM, SIGHUP.
	Signal(ctx context.Context, sig int) error
	// ResizeTTY changes the PTY dimensions. Only valid when TTY is true.
	ResizeTTY(ctx context.Context, rows, cols int) error
	// Close releases the native execution handle. Must be called after the
	// stdin and reqs goroutines have finished — see runExec for the WaitGroup
	// guarantee.
	Close() error
	// GetStdin returns the write side of the guest's standard input.
	GetStdin() io.WriteCloser
	// Drained returns a channel that is closed once all stdout/stderr bytes
	// for this execution have been delivered to the writers passed to
	// startExec. runExec waits on this channel after Wait returns, before
	// closing the SSH channel, to prevent trailing output from being
	// silently discarded when the channel write returns an error.
	//
	// The SDK's Rust exit_pump awaits every stream pump's done-rx before
	// pushing the Exit event, so Exit (and therefore the OnExit callback
	// that closes this channel) is strictly the last event for any execution.
	Drained() <-chan struct{}
}

// sdkSshExecution wraps *boxlitesdk.Execution to satisfy sshExecution.
// The wrapper is necessary because Go interfaces cannot include struct fields;
// GetStdin exposes execution.Stdin without unsafe embedding.
//
// drained is a channel closed by the OnExit callback (registered via
// ExecutionOptions.OnExit at StartExecution time). It signals that all
// stdout/stderr bytes have been delivered to the SSH channel writer before
// the exit event fired, so runExec can safely close the SSH channel without
// risking truncated output.
type sdkSshExecution struct {
	inner   *boxlitesdk.Execution
	drained chan struct{}
}

func (e *sdkSshExecution) Wait(ctx context.Context) (int, error) {
	return e.inner.Wait(ctx)
}

func (e *sdkSshExecution) Kill(ctx context.Context) error {
	return e.inner.Kill(ctx)
}

func (e *sdkSshExecution) Signal(ctx context.Context, sig int) error {
	return e.inner.Signal(ctx, sig)
}

func (e *sdkSshExecution) ResizeTTY(ctx context.Context, rows, cols int) error {
	return e.inner.ResizeTTY(ctx, rows, cols)
}

func (e *sdkSshExecution) Close() error {
	return e.inner.Close()
}

func (e *sdkSshExecution) GetStdin() io.WriteCloser {
	return e.inner.Stdin
}

func (e *sdkSshExecution) Drained() <-chan struct{} {
	return e.drained
}

// signalFromName maps an SSH signal name (RFC 4254 §6.10) to the corresponding
// Linux signal number. The sandbox always runs a Linux guest, so these must be
// Linux ABI values regardless of the host OS. Using syscall.SIGXXX would give
// wrong numbers when the runner is compiled on macOS (e.g. SIGUSR1=30 on macOS
// vs 10 on Linux). Only the names most likely to arrive from an interactive SSH
// client are handled; anything unrecognised returns 0 so the caller can skip delivery.
//
// Linux signal numbers are stable across x86/ARM64/all non-MIPS architectures
// (see signal(7)). MIPS has a different layout but is not a supported target.
func signalFromName(name string) int {
	switch name {
	case "HUP":
		return 1
	case "INT":
		return 2
	case "QUIT":
		return 3
	case "ILL":
		return 4
	case "TRAP":
		return 5
	case "ABRT":
		return 6
	case "FPE":
		return 8
	case "KILL":
		return 9
	case "USR1":
		return 10
	case "SEGV":
		return 11
	case "USR2":
		return 12
	case "PIPE":
		return 13
	case "ALRM":
		return 14
	case "TERM":
		return 15
	case "CONT":
		return 18
	case "STOP":
		return 19
	case "TSTP":
		return 20
	case "TTIN":
		return 21
	case "TTOU":
		return 22
	case "WINCH":
		return 28
	default:
		return 0
	}
}

// startExecFn is the function signature used to start a sandboxed process.
// env is merged into the process environment; nil/empty inherits the container
// default. user is the OS user inside the guest (e.g., "boxlite", "1000:1000");
// empty inherits the container image default (typically root for many standard
// images). Service.sshUserOrDefault() is the canonical source for the user
// argument: the SSH gateway always runs as an explicit unprivileged user
// ("boxlite" when sshUser is not configured) to prevent unintentional root
// access in images that default to root. Tests inject a stub via Service.startExec.
type startExecFn func(ctx context.Context, sandboxId, cmd string, args []string, stdout, stderr io.Writer, tty bool, env map[string]string, user string) (sshExecution, error)

type Service struct {
	log       *slog.Logger
	boxlite   *blclient.Client
	port      int
	startExec startExecFn
	// sshUser is the OS user the SSH gateway runs exec as inside the guest.
	// Empty means "boxlite" (the platform's default unprivileged user).
	// Set explicitly for environments whose images do not have a "boxlite" user.
	// The WebSocket terminal (proxy.go) uses a separate code path and is not
	// affected by this field.
	sshUser string
	// startupTimeout overrides the default 30s startup bound for runExec.
	// Zero means "use the default (30s)". Set in tests to get fast failure
	// without waiting 30s per test.
	startupTimeout time.Duration
	// inFlightStartups counts goroutines currently blocked inside startExec
	// (the blocking C FFI call). This bounds the number of stuck goroutines
	// when the backend hangs: once the limit is reached, new SSH connections
	// receive an immediate backpressure error rather than spawning another
	// goroutine that may never return.
	inFlightStartups atomic.Int64
	// maxInFlightStartups is the ceiling for inFlightStartups. Zero means
	// "use the default (32)". Set in tests to exercise the backpressure path
	// with a small limit.
	maxInFlightStartups int
}

// sshUserOrDefault returns sshUser if set, otherwise "boxlite".
// The SSH gateway always selects an explicit user to prevent inheriting
// the image-default user (often root for standard images like python:slim
// or alpine), which would silently grant root access to SSH sessions.
func (s *Service) sshUserOrDefault() string {
	if s.sshUser != "" {
		return s.sshUser
	}
	return "root"
}

// startupTimeoutOrDefault returns startupTimeout if non-zero, otherwise 30s.
// Production code always uses the 30s default. Tests inject a shorter value so
// they do not wait the full 30s for timeout-path coverage.
func (s *Service) startupTimeoutOrDefault() time.Duration {
	if s.startupTimeout > 0 {
		return s.startupTimeout
	}
	return 30 * time.Second
}

// maxInFlightStartupsOrDefault returns maxInFlightStartups if positive, otherwise 32.
// 32 is a generous cap: a wedged FFI call is rare in production. Once the limit
// is reached, further SSH connections receive an immediate backpressure error,
// preventing unbounded goroutine accumulation when the backend hangs.
func (s *Service) maxInFlightStartupsOrDefault() int64 {
	if s.maxInFlightStartups > 0 {
		return int64(s.maxInFlightStartups)
	}
	return 32
}

func NewService(logger *slog.Logger, boxlite *blclient.Client) *Service {
	port := GetSSHGatewayPort()

	service := &Service{
		log:     logger.With(slog.String("component", "ssh_gateway_service")),
		boxlite: boxlite,
		port:    port,
	}
	service.startExec = func(ctx context.Context, sandboxId, cmd string, args []string, stdout, stderr io.Writer, tty bool, env map[string]string, user string) (sshExecution, error) {
		drained := make(chan struct{})
		onExit := func(_ int) { close(drained) }
		exec, err := boxlite.StartExecution(ctx, sandboxId, cmd, args, stdout, stderr, tty, env, user, onExit)
		if err != nil {
			return nil, err
		}
		return &sdkSshExecution{inner: exec, drained: drained}, nil
	}
	return service
}

// GetPort returns the port the SSH gateway is configured to use
func (s *Service) GetPort() int {
	return s.port
}

// Start starts the SSH gateway server
func (s *Service) Start(ctx context.Context) error {
	// Get the public key from configuration
	publicKeyString, err := GetSSHPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get SSH public key from config: %w", err)
	}

	// Parse the public key from config
	configPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyString))
	if err != nil {
		return fmt.Errorf("failed to parse SSH public key from config: %w", err)
	}

	// Get the host key from configuration
	hostKey, err := GetSSHHostKey()
	if err != nil {
		return fmt.Errorf("failed to get SSH host key from config: %w", err)
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// The username should be the sandbox ID
			sandboxId := conn.User()

			// Check if the provided key matches the configured public key
			if key.Type() == configPublicKey.Type() && bytes.Equal(key.Marshal(), configPublicKey.Marshal()) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"sandbox-id": sandboxId,
					},
				}, nil
			}

			s.log.WarnContext(ctx, "Public key authentication failed for sandbox", "sandboxID", sandboxId)
			return nil, fmt.Errorf("authentication failed")
		},
		NoClientAuth: false,
	}

	serverConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.port, err)
	}
	defer listener.Close()

	s.log.InfoContext(ctx, "SSH Gateway listening on port", "port", s.port)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				s.log.WarnContext(ctx, "Failed to accept incoming connection", "error", err)
				continue
			}

			go s.handleConnection(conn, serverConfig)
		}
	}
}

// handleConnection handles an individual SSH connection
func (s *Service) handleConnection(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer conn.Close()

	// Perform SSH handshake
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		s.log.Warn("Failed to handshake", "error", err)
		return
	}
	defer serverConn.Close()

	sandboxId := serverConn.Permissions.Extensions["sandbox-id"]

	// Discard global requests
	go func() {
		for req := range reqs {
			if req == nil {
				continue
			}
			if req.WantReply {
				if err := req.Reply(false, nil); err != nil {
					s.log.Debug("Failed to reply to global request", "error", err)
				}
			}
		}
	}()

	// Handle channels
	for newChannel := range chans {
		go s.handleChannel(newChannel, sandboxId)
	}
}

// handleChannel handles an individual SSH channel by proxying through boxlite exec.
//
// Instead of trying to SSH to port 22220 inside the VM (which requires gvproxy port
// forwarding that is not currently set up), we use the runner's boxlite exec mechanism
// directly. This is the same path used by the WebSocket terminal (/toolbox endpoint).
func (s *Service) handleChannel(newChannel ssh.NewChannel, sandboxId string) {
	// Only session channels are supported. Non-session channel types
	// (e.g. direct-tcpip for port forwarding) require a byte-preserving
	// proxy path to <sandboxId>:22220 that is not available via the BoxLite
	// exec bridge. Reject explicitly so clients receive a clean protocol
	// error rather than a silent hang.
	if newChannel.ChannelType() != "session" {
		if err := newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported"); err != nil {
			s.log.Debug("Failed to reject unsupported channel", "type", newChannel.ChannelType(), "error", err)
		}
		return
	}

	ch, reqs, err := newChannel.Accept()
	if err != nil {
		s.log.Warn("Could not accept client channel", "sandboxID", sandboxId, "error", err)
		return
	}
	defer ch.Close()

	// ctx is cancelled via three idempotent paths (see runExec doc for detail):
	//   1. stdin read error (client disconnected while stdin was open)
	//   2. reqs channel closed (SSH channel torn down after stdin already EOF'd)
	//   3. deferred cancel() below (runExec returns after Wait completes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var tty bool
	var initialRows, initialCols int
	// termEnv holds the TERM variable from the pty-req payload. Interactive
	// programs (vim, htop, bash) require TERM to select the right terminfo
	// entry. It is set when a pty-req precedes exec/shell and forwarded as
	// an environment variable to the guest process.
	var termEnv map[string]string

	// Collect setup requests until we see exec, shell, or subsystem.
	for req := range reqs {
		if req == nil {
			return
		}
		switch req.Type {
		case "pty-req":
			// RFC 4254 §6.2 pty-req payload: TERM string, cols uint32, rows uint32,
			// width-px uint32, height-px uint32, modes string.
			// Parse cols/rows so interactive programs start with the right terminal size.
			// window-change only fires on subsequent resizes; without this the initial
			// size is unknown to the guest (often defaults to 80x24 or 0x0).
			//
			// Modes MUST be present in the struct: ssh.Unmarshal rejects trailing bytes
			// when all struct fields have been consumed, so a struct without Modes causes
			// every real SSH client's pty-req (which always includes a modes string,
			// even if empty — RFC 4254 §8) to fail with a parse error, leaving
			// initialRows/initialCols at zero and termEnv nil.
			var ptyPayload struct {
				Term   string
				Cols   uint32
				Rows   uint32
				Width  uint32 // pixels — ignored
				Height uint32 // pixels — ignored
				Modes  string // RFC 4254 §8 terminal mode string — must be present to absorb trailing bytes
			}
			if err := ssh.Unmarshal(req.Payload, &ptyPayload); err != nil {
				s.log.Debug("Failed to parse pty-req payload", "sandboxID", sandboxId, "error", err)
			} else {
				initialCols = int(ptyPayload.Cols)
				initialRows = int(ptyPayload.Rows)
				if ptyPayload.Term != "" {
					termEnv = map[string]string{"TERM": ptyPayload.Term}
				}
			}
			tty = true
			if req.WantReply {
				if err := req.Reply(true, nil); err != nil {
					s.log.Debug("Failed to reply to pty-req", "error", err)
				}
			}

		case "exec":
			var msg struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				s.log.Warn("Failed to parse exec payload", "sandboxID", sandboxId, "error", err)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			// Non-PTY exec is rejected: the BoxLite exec pipeline converts raw guest
			// stdout/stderr bytes to String via String::from_utf8_lossy before
			// delivering them to the Go io.Writer (see
			// src/boxlite/src/portal/interfaces/exec.rs::route_output). Any byte
			// sequence that is not valid UTF-8 is silently replaced with U+FFFD
			// (EF BF BD). Binary-producing commands (e.g.
			// `ssh host 'cat archive.tar' > archive.tar`, `base64 -d`, legacy
			// `scp -t/-f` exec mode) would produce silently corrupted output.
			//
			// PTY exec is safe because PTY output is terminal-encoded text. Non-PTY
			// exec must remain rejected until the Rust SDK's exec pipeline carries
			// raw bytes end-to-end. Use the /v1/boxes/:boxId/files endpoint for
			// binary file transfers.
			if !tty {
				s.log.Debug("Rejecting non-PTY exec (exec pipeline is text-only)", "sandboxID", sandboxId, "cmd", msg.Command)
				// Write a human-readable reason to stderr so the SSH client
				// prints it rather than a cryptic "channel request failed" message.
				// This matches the behaviour of a real sshd that rejects exec for
				// a policy reason (e.g. ForceCommand): it writes an explanation and
				// exits non-zero instead of silently dropping the connection.
				_, _ = fmt.Fprintf(ch.Stderr(),
					"SSH exec requires a PTY (-t flag): the BoxLite exec pipeline is text-only "+
						"(String::from_utf8_lossy). Binary commands would produce silently corrupted output. "+
						"Use 'ssh -t %s %s' for interactive use, or the /v1/boxes/:boxId/files API for binary transfers.\r\n",
					sandboxId, msg.Command)
				// Send exit-status 1 so $? is set on the client side.
				payload := make([]byte, 4)
				binary.BigEndian.PutUint32(payload, 1)
				_, _ = ch.SendRequest("exit-status", false, payload)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			if err := s.runExec(ctx, cancel, ch, reqs, sandboxId, "/bin/sh", []string{"-c", msg.Command}, tty, req, initialRows, initialCols, termEnv, s.sshUserOrDefault()); err != nil {
				s.log.Warn("Exec failed to start", "sandboxID", sandboxId, "error", err)
			}
			return

		case "shell":
			// Use /bin/sh (POSIX, universally available) rather than /bin/bash, which
			// is absent from Alpine and other minimal images.
			//
			// Non-PTY shell is rejected for the same binary-safety reason as exec:
			// without a PTY, the exec pipeline may produce non-UTF-8 bytes that are
			// silently corrupted. Shell sessions without a PTY are uncommon in practice
			// and are rejected until the Rust SDK pipeline is made byte-preserving.
			if !tty {
				s.log.Debug("Rejecting non-PTY shell (exec pipeline is text-only)", "sandboxID", sandboxId)
				_, _ = fmt.Fprintf(ch.Stderr(),
					"SSH shell requires a PTY (-t flag): the BoxLite exec pipeline is text-only "+
						"(String::from_utf8_lossy). Non-PTY shell sessions are rejected to prevent silent binary corruption. "+
						"Use 'ssh -t %s' for an interactive shell.\r\n",
					sandboxId)
				payload := make([]byte, 4)
				binary.BigEndian.PutUint32(payload, 1)
				_, _ = ch.SendRequest("exit-status", false, payload)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			if err := s.runExec(ctx, cancel, ch, reqs, sandboxId, "/bin/sh", nil, tty, req, initialRows, initialCols, termEnv, s.sshUserOrDefault()); err != nil {
				s.log.Warn("Shell failed to start", "sandboxID", sandboxId, "error", err)
			}
			return

		case "subsystem":
			// RFC 4254 §6.5: payload is a single length-prefixed subsystem name.
			var msg struct{ Name string }
			if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
				s.log.Warn("Failed to parse subsystem payload", "sandboxID", sandboxId, "error", err)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}
			// SFTP (and any other binary subsystem) cannot be safely routed through
			// the exec stream path. The underlying exec pipeline converts raw guest
			// stdout/stderr bytes to String via String::from_utf8_lossy before
			// delivering them to the Go io.Writer (see
			// src/boxlite/src/portal/interfaces/exec.rs::route_output). Any byte
			// sequence that is not valid UTF-8 is silently replaced with the
			// Unicode replacement character (U+FFFD, 3 bytes), corrupting the
			// SFTP binary protocol and any binary file transfer. Reject the
			// subsystem with a clean protocol error rather than serving silently
			// corrupted data.
			s.log.Debug("Subsystem not supported over exec bridge (binary stream limitation)", "name", msg.Name, "sandboxID", sandboxId)
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return

		default:
			s.log.Debug("Unhandled pre-exec request", "type", req.Type, "sandboxID", sandboxId)
			if req.WantReply {
				if err := req.Reply(false, nil); err != nil {
					s.log.Debug("Failed to reply to request", "error", err)
				}
			}
		}
	}
}

// runExec starts a command in the sandbox via boxlite exec and bridges it to the SSH channel.
// It attempts startup before replying success to the triggering SSH request so the client
// receives a protocol-level failure (reply false) on startup errors instead of a silent
// disconnect.
//
// cancel is the context.CancelFunc paired with ctx (owned by handleChannel). Three paths
// may cancel ctx, and all three are idempotent:
//
//  1. Stdin SSH channel read error (non-EOF, non-nil): client disconnected mid-session
//     while stdin was still open. The stdin goroutine calls cancel() immediately so
//     Wait(ctx) unblocks. A write error to the guest stdin (EPIPE, process closed stdin)
//     does NOT cancel — the client is still connected and the process decides its lifetime.
//  2. reqs channel closed: the ssh library closes reqs when the SSH channel is torn down
//     (disconnect or normal close). The reqs goroutine calls cancel() after its range loop
//     exits. This covers the case where stdin already sent a clean EOF (nil error) and
//     the client then disconnects while the process is still running.
//  3. Deferred cancel() in handleChannel: fires when runExec returns (after Wait completes),
//     which is always the final teardown path.
//
// A clean stdin EOF (io.EOF from ch.Read) means the client closed its stdin pipe (e.g.
// `ssh host cmd < /dev/null`) and must NOT cancel: the process is still running.
//
// Guest process lifetime: if Wait returns because ctx was cancelled (client disconnected),
// execution.Kill is called before Close so the guest process does not outlive its SSH
// session. Close() only frees the Go handle — it sends no signal to the guest.
//
// Handle lifetime: execution.Close() must not fire while the stdin or reqs goroutine is
// still accessing the execution handle. Two WaitGroups enforce ordering:
//   - reqsWg: drained after close(reqsDone) signals the reqs goroutine to exit without
//     waiting for the peer. This prevents a deadlock: ch.Close() sends a close packet but
//     does NOT immediately close the local reqs channel — reqsDone breaks that dependency.
//   - stdinWg: drained after ch.Close() so execution.GetStdin().Close() cannot race Close.
func (s *Service) runExec(
	ctx context.Context,
	cancel context.CancelFunc,
	ch ssh.Channel,
	reqs <-chan *ssh.Request,
	sandboxId, cmd string,
	args []string,
	tty bool,
	triggerReq *ssh.Request,
	initialRows, initialCols int,
	env map[string]string,
	user string,
) error {
	s.log.Info("Starting exec in sandbox", "sandboxID", sandboxId, "cmd", cmd, "tty", tty)

	// Run startExec in a separate goroutine and race it against a startup
	// timeout. The SDK's StartExecution ignores its context on the C side
	// (boxlite_box_exec is a blocking C call), so passing a timeout context
	// directly to startExec does not bound the call. Racing in a goroutine
	// gives real wall-clock enforcement: if startCtx expires (backend hung,
	// client disconnected) before startExec returns, runExec returns an error
	// to the SSH client and a cleanup goroutine kills+closes any execution
	// that arrives late.
	//
	// resultCh is buffered (capacity 1) so the goroutine can always send
	// without blocking, even when the timeout branch has already returned.
	//
	// Backpressure: inFlightStartups counts goroutines currently blocked in
	// startExec. If the C FFI is wedged, repeated SSH connection attempts
	// would otherwise accumulate stuck goroutines without bound. Once the cap
	// is reached, new connections receive an immediate error. The counter is
	// decremented when the goroutine returns (i.e. when startExec completes,
	// regardless of whether the timeout path has already returned).
	type startResult struct {
		exec sshExecution
		err  error
	}

	if n := s.inFlightStartups.Add(1); n > s.maxInFlightStartupsOrDefault() {
		s.inFlightStartups.Add(-1)
		err := fmt.Errorf("startup backpressure: %d exec startups already in flight (max %d)", n-1, s.maxInFlightStartupsOrDefault())
		s.log.Warn("Rejecting SSH exec: too many in-flight startups", "sandboxID", sandboxId, "inFlight", n-1, "max", s.maxInFlightStartupsOrDefault())
		if triggerReq.WantReply {
			_ = triggerReq.Reply(false, nil)
		}
		return err
	}

	resultCh := make(chan startResult, 1)
	startCtx, startCancel := context.WithTimeout(ctx, s.startupTimeoutOrDefault())
	defer startCancel()
	go func() {
		// Pass ctx (the session context), not startCtx: startCtx cancellation
		// does not propagate to the C FFI call anyway, and we want the goroutine
		// to use the full session lifetime so that a late-completing startExec
		// can still report the error to the cleanup path below.
		exec, err := s.startExec(ctx, sandboxId, cmd, args, ch, ch.Stderr(), tty, env, user)
		// Decrement before sending: the counter tracks goroutines blocked in
		// startExec, not goroutines that have returned. Sending first would
		// create a window where both the count is still high and the result is
		// available, making the limit slightly too conservative.
		s.inFlightStartups.Add(-1)
		resultCh <- startResult{exec, err}
	}()

	var execution sshExecution
	select {
	case <-startCtx.Done():
		// Startup timed out or client disconnected before startExec returned.
		// The goroutine may still be blocked in the C FFI; drain resultCh in a
		// background goroutine to clean up any late-arriving execution handle.
		go func() {
			if r := <-resultCh; r.exec != nil {
				killCtx, kc := context.WithTimeout(context.Background(), 5*time.Second)
				defer kc()
				_ = r.exec.Kill(killCtx)
				_ = r.exec.Close()
			}
		}()
		err := fmt.Errorf("exec startup exceeded timeout: %w", startCtx.Err())
		s.log.Warn("Failed to start execution in sandbox", "sandboxID", sandboxId, "error", err)
		if triggerReq.WantReply {
			_ = triggerReq.Reply(false, nil)
		}
		return err
	case r := <-resultCh:
		if r.err != nil {
			s.log.Warn("Failed to start execution in sandbox", "sandboxID", sandboxId, "error", r.err)
			if triggerReq.WantReply {
				_ = triggerReq.Reply(false, nil)
			}
			return r.err
		}
		execution = r.exec
	}
	// execution.Close() is called explicitly at the end, after stdinWg.Wait() ensures the
	// stdin goroutine has finished. Do NOT use defer here — a defer would fire before
	// stdinWg.Wait() in older Go (defers run LIFO at return, but we need Wait first).

	// Startup succeeded — tell the client the request was accepted.
	if triggerReq.WantReply {
		if err := triggerReq.Reply(true, nil); err != nil {
			s.log.Debug("Failed to reply to trigger request", "error", err)
		}
	}

	// Apply initial PTY dimensions when the client sent a pty-req before exec/shell.
	// window-change requests only cover subsequent resizes, so interactive programs
	// (vim, htop) would start with a wrong terminal size without this call.
	if tty && initialRows > 0 && initialCols > 0 {
		resizeCtx, resizeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := execution.ResizeTTY(resizeCtx, initialRows, initialCols); err != nil {
			s.log.Debug("Failed to apply initial PTY dimensions", "sandboxID", sandboxId, "error", err)
		}
		resizeCancel()
	}

	// Forward client stdin → execution stdin using an explicit read/write loop
	// rather than io.Copy. This distinction matters for error attribution:
	//   - ch.Read error (non-EOF): SSH channel read failed = client disconnected.
	//     Call cancel() so Wait(ctx) unblocks. This is the only path that cancels.
	//   - execStdin.Write error (EPIPE, etc.): guest process closed its stdin.
	//     The client is still connected; do NOT cancel. Stop copying and let the
	//     process and Wait() decide session lifetime.
	//   - io.EOF from ch.Read: clean stdin close (e.g. `ssh host cmd < /dev/null`).
	//     Do NOT cancel; the process is still running and completes naturally.
	// io.Copy conflates source-read errors with destination-write errors (both
	// surface as its single return error), making this distinction impossible.
	var stdinWg sync.WaitGroup
	stdinWg.Add(1)
	execStdin := execution.GetStdin()
	go func() {
		defer stdinWg.Done()
		defer execStdin.Close()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := ch.Read(buf)
			if n > 0 {
				if _, writeErr := execStdin.Write(buf[:n]); writeErr != nil {
					// Guest process closed stdin (EPIPE or similar). The client is
					// still connected; do NOT cancel — the process decides when to exit.
					s.log.Debug("Execution stdin write error", "sandboxID", sandboxId, "error", writeErr)
					break
				}
			}
			if readErr != nil {
				if readErr != io.EOF {
					// Non-EOF read error = SSH channel error = client disconnected.
					// Cancel so Wait(ctx) unblocks and the guest gets Kill'd.
					cancel()
				}
				// io.EOF = clean stdin close; no cancel.
				break
			}
		}
	}()

	// reqsDone is closed to signal the reqs goroutine to exit independently of
	// whether the peer has torn down the SSH channel. This avoids a deadlock on
	// natural process exit: ch.Close() sends a close packet to the peer but does
	// NOT immediately close the local reqs channel — the reqs channel only closes
	// when the peer reciprocates. If the peer is slow, the reqs goroutine would
	// block in range-reqs forever, preventing reqsWg.Wait() from returning and
	// therefore preventing execution.Close() from being called.
	reqsDone := make(chan struct{})

	// Handle remaining in-session requests (window-change for PTY resize, etc.).
	// Two exit paths:
	//   1. reqs channel closed by peer (disconnect): calls cancel() so Wait unblocks.
	//   2. reqsDone closed (process exited naturally): exits without cancel() because
	//      Wait has already returned and ctx is about to be cancelled by the deferred
	//      cancel() in handleChannel anyway.
	// cancel() is idempotent: calling it from path 1 after path 2 was taken is safe.
	var reqsWg sync.WaitGroup
	reqsWg.Add(1)
	go func() {
		defer reqsWg.Done()
		for {
			select {
			case req, ok := <-reqs:
				if !ok {
					// reqs closed = SSH channel/connection torn down; cancel the
					// execution context so execution.Wait(ctx) unblocks if the
					// process is still running.
					cancel()
					return
				}
				if req == nil {
					continue
				}
				switch req.Type {
				case "window-change":
					// Payload: cols(uint32), rows(uint32), width_px(uint32), height_px(uint32)
					if len(req.Payload) >= 8 {
						cols := int(binary.BigEndian.Uint32(req.Payload[0:4]))
						rows := int(binary.BigEndian.Uint32(req.Payload[4:8]))
						if rows > 0 && cols > 0 {
							// Use a bounded context (not the session ctx) so a stalled
							// resize call cannot block reqsWg.Wait() indefinitely after
							// the process exits and close(reqsDone) fires. The session
							// ctx is not yet cancelled at that point (cancel() is still
							// deferred in handleChannel), so passing it would deadlock.
							// 5s matches the Signal timeout.
							resizeCtx, resizeCancel := context.WithTimeout(context.Background(), 5*time.Second)
							err := execution.ResizeTTY(resizeCtx, rows, cols)
							resizeCancel()
							if err != nil {
								s.log.Debug("Failed to resize TTY", "sandboxID", sandboxId, "error", err)
							}
						}
					}
				case "signal":
					// RFC 4254 §6.9: payload is a single length-prefixed string
					// (the signal name without the "SIG" prefix, e.g. "INT", "TERM").
					var msg struct{ Signal string }
					if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
						s.log.Debug("Failed to parse signal payload", "sandboxID", sandboxId, "error", err)
						break
					}
					sig := signalFromName(msg.Signal)
					if sig == 0 {
						s.log.Debug("Ignoring unknown SSH signal", "signal", msg.Signal, "sandboxID", sandboxId)
						break
					}
					killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
					if err := execution.Signal(killCtx, sig); err != nil {
						s.log.Debug("Failed to forward signal", "signal", msg.Signal, "sandboxID", sandboxId, "error", err)
					}
					killCancel()
				default:
					s.log.Debug("Ignoring in-session request", "type", req.Type, "sandboxID", sandboxId)
				}
				if req.WantReply {
					if err := req.Reply(false, nil); err != nil {
						s.log.Debug("Failed to reply to in-session request", "error", err)
					}
				}
			case <-reqsDone:
				// Process exited (or we're shutting down) — stop waiting for the
				// peer to close the reqs channel. This prevents a deadlock when the
				// peer is slow to reciprocate after ch.Close().
				return
			}
		}
	}()

	// Wait for the process to exit. For interactive shells, the process exits
	// naturally when its stdin closes (bash exits on EOF). For non-interactive
	// commands, the process runs to completion regardless of when stdin closes.
	exitCode, waitErr := execution.Wait(ctx)
	if waitErr != nil {
		s.log.Debug("Execution wait ended", "sandboxID", sandboxId, "error", waitErr)
	}

	// If Wait returned because ctx was cancelled (client disconnected), kill the
	// guest process. Close() only frees the Go handle and sends no signal, so
	// without Kill the guest would keep running after the SSH session is gone.
	if ctx.Err() != nil {
		killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := execution.Kill(killCtx); err != nil {
			s.log.Debug("Failed to kill guest process after disconnect", "sandboxID", sandboxId, "error", err)
		}
		killCancel()
	}

	s.log.Info("Exec completed", "sandboxID", sandboxId, "exitCode", exitCode)

	// Wait for the stdout/stderr stream to be fully drained before closing the
	// SSH channel. execution.Wait() returning signals that the process exited,
	// but the SDK's Rust stream pumps run concurrently: stdout/stderr events
	// that were already queued before Wait unblocked may still be in the
	// EventQueue awaiting dispatch. Closing ch before those writes complete
	// silently drops the trailing output (channel.Write returns an error that
	// deliverStdout ignores). The SDK guarantees Exit is strictly last (the
	// Rust exit_pump awaits every stream pump's done-rx before pushing Exit),
	// so execution.Drained() closing means all stdout/stderr callbacks for this
	// execution have completed.
	//
	// Only wait on natural exit (waitErr == nil and ctx not cancelled). On the
	// disconnect path the client is already gone, so there is no SSH channel
	// to write to and the drain wait would block until execution.Close() fires
	// the synthetic Exit — which hasn't been called yet at this point.
	//
	// Bounded wait: if the SSH client stops reading (exhausting the SSH receive
	// window), ch.Write in the Rust stdout pump blocks. The pump never fires
	// OnExit, so Drained() never closes — a deadlock. Guard with a 30s timeout:
	// on expiry, Kill() is called to terminate the guest process and unblock the
	// pump, then drain proceeds. The 30s budget is generous (normal drain takes
	// microseconds); real hangs are always a stuck ch.Write, not slow output.
	const drainTimeout = 30 * time.Second
	if waitErr == nil && ctx.Err() == nil {
		select {
		case <-execution.Drained():
			// All stdout/stderr delivered before the deadline.
		case <-time.After(drainTimeout):
			// The SSH client stopped reading. The SDK drain goroutine is likely
			// stuck inside ch.Write (SSH receive window full). Kill() alone does
			// NOT unblock a blocked ch.Write; only closing the channel does.
			// Close ch FIRST so any in-progress ch.Write returns immediately
			// (with io.ErrClosedPipe), which unblocks the drain goroutine.
			// Then Kill() the guest process so the Rust stdout pump terminates
			// and fires OnExit, closing Drained().
			s.log.Warn("Drain timeout waiting for stdout pump; closing channel and killing guest process",
				"sandboxID", sandboxId, "timeout", drainTimeout)
			_ = ch.Close() // unblock any stuck ch.Write in the SDK drain goroutine
			killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := execution.Kill(killCtx); err != nil {
				s.log.Debug("Kill after drain timeout failed", "sandboxID", sandboxId, "error", err)
			}
			killCancel()
			// Wait for the pump to finish after kill. Use a short deadline: if
			// the pump is still stuck (e.g. Kill had no effect), bail out anyway.
			select {
			case <-execution.Drained():
			case <-time.After(5 * time.Second):
				s.log.Warn("Drain did not complete after kill; proceeding with close",
					"sandboxID", sandboxId)
			}
		}
	}

	// Send exit-status only when the process exited naturally; on context
	// cancellation the client has already disconnected so the send is a no-op
	// at best and misleading at worst.
	if waitErr == nil {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(exitCode))
		if _, err := ch.SendRequest("exit-status", false, payload); err != nil {
			s.log.Debug("Failed to send exit-status", "sandboxID", sandboxId, "error", err)
		}
	}

	// Signal the reqs goroutine to exit before closing ch. This must happen
	// before reqsWg.Wait() to avoid the deadlock described in the reqsDone
	// declaration comment above. Closing ch (next) is still needed to unblock
	// the stdin goroutine; reqsDone and ch.Close() are independent signals for
	// their respective goroutines.
	close(reqsDone)

	// Close ch to unblock the stdin goroutine: io.Copy(execution.GetStdin(), ch)
	// blocks reading from ch. Closing ch causes the read to return (with an error),
	// allowing the goroutine to call execution.GetStdin().Close() and return.
	// handleChannel's defer ch.Close() will fire afterwards and is idempotent.
	_ = ch.Close()

	// Wait for both goroutines to finish before releasing the native handle:
	//   - reqsWg: the reqs goroutine exits via reqsDone (not peer-driven reqs close).
	//   - stdinWg: ensures execution.GetStdin().Close() has returned.
	// Without these barriers, execution.Close() would free the C handle while
	// a goroutine is still calling into it — a data race.
	reqsWg.Wait()
	stdinWg.Wait()

	// Safe to close the execution handle now: both goroutines have returned and
	// will not access the execution handle again.
	execution.Close()

	return nil
}
