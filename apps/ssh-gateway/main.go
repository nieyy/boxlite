/*
 * Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
 * SPDX-License-Identifier: AGPL-3.0
 */

package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiclient "github.com/boxlite-ai/boxlite/libs/api-client-go"
	"golang.org/x/crypto/ssh"

	log "github.com/sirupsen/logrus"
)

const (
	defaultPort = 2222
	runnerPort  = 2220
)

type SSHGateway struct {
	port           int
	apiClient      *apiclient.APIClient
	hostKey        ssh.Signer
	privateKey     ssh.Signer
	publicKey      ssh.PublicKey
	runnerAPIToken string
}

// sshAccessInfo holds the real-SSH state for a box from the runner API.
type sshAccessInfo struct {
	HostPort int    `json:"host_port"`
	UnixUser string `json:"unix_user"`
	Enabled  bool   `json:"enabled"`
	Degraded bool   `json:"degraded"`
}

// logStartupWarnings emits warnings for missing optional configuration.
func logStartupWarnings(runnerAPIToken string) {
	if runnerAPIToken == "" {
		log.Warn("RUNNER_API_TOKEN is not set: real-SSH mode is disabled; all connections use the exec bridge (boxId identity, no unix_user enforcement)")
	}
}

// getRunnerSSHAccess queries the runner's /v1/boxes/{boxId}/ssh-access endpoint.
// Returns (Enabled=false, nil) for 404 (v2 runners without real-SSH support).
// Returns (nil, err) for network errors and non-200/404 responses (fail-closed).
func (g *SSHGateway) getRunnerSSHAccess(runnerDomain string, boxId string) (*sshAccessInfo, error) {
	host := runnerDomain
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "" {
		host = "localhost"
	}
	apiPort := getEnvInt("RUNNER_API_PORT", 3003)
	url := fmt.Sprintf("http://%s:%d/v1/boxes/%s/ssh-access", host, apiPort, boxId)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("getRunnerSSHAccess: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.runnerAPIToken)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getRunnerSSHAccess: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// v2 runners don't implement this endpoint — fall back to exec bridge.
		return &sshAccessInfo{Enabled: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getRunnerSSHAccess: unexpected status %d", resp.StatusCode)
	}

	var info sshAccessInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("getRunnerSSHAccess: decode response: %w", err)
	}
	return &info, nil
}

func main() {
	port := getEnvInt("SSH_GATEWAY_PORT", defaultPort)
	apiURL := getEnv("API_URL", "http://localhost:3000")
	apiKey := getEnv("API_KEY", "")
	sshPk := getEnv("SSH_PRIVATE_KEY", "")
	sshHostKey := getEnv("SSH_HOST_KEY", "")
	runnerAPIToken := getEnv("RUNNER_API_TOKEN", "")

	if apiKey == "" {
		log.Fatal("API_KEY environment variable is required")
	}

	if sshPk == "" {
		log.Fatal("SSH_PRIVATE_KEY environment variable is required")
	}

	if sshHostKey == "" {
		log.Fatal("SSH_HOST_KEY environment variable is required")
	}

	// Decode base64 encoded private key
	decodedPk, err := base64.StdEncoding.DecodeString(sshPk)
	if err != nil {
		log.Fatalf("Failed to base64 decode SSH_PRIVATE_KEY: %v", err)
	}

	// Decode base64 encoded host key
	decodedHostKey, err := base64.StdEncoding.DecodeString(sshHostKey)
	if err != nil {
		log.Fatalf("Failed to base64 decode SSH_HOST_KEY: %v", err)
	}

	clientConfig := apiclient.NewConfiguration()
	clientConfig.Servers = apiclient.ServerConfigurations{
		{
			URL: apiURL,
		},
	}

	clientConfig.AddDefaultHeader("Authorization", "Bearer "+apiKey)

	apiClient := apiclient.NewAPIClient(clientConfig)

	apiClient.GetConfig().HTTPClient = &http.Client{
		Transport: http.DefaultTransport,
	}

	// Load the host key from environment variable
	hostKey, err := parsePrivateKey(string(decodedHostKey))
	if err != nil {
		log.Fatalf("Failed to parse host key from SSH_HOST_KEY: %v", err)
	}

	// Load the private key from environment variable
	privateKey, err := parsePrivateKey(string(decodedPk))
	if err != nil {
		log.Fatalf("Failed to parse private key from SSH_PRIVATE_KEY: %v", err)
	}

	// Generate public key from private key
	publicKey := privateKey.PublicKey()

	logStartupWarnings(runnerAPIToken)

	gateway := &SSHGateway{
		port:           port,
		apiClient:      apiClient,
		hostKey:        hostKey,
		privateKey:     privateKey,
		publicKey:      publicKey,
		runnerAPIToken: runnerAPIToken,
	}

	log.Printf("Host key loaded from SSH_HOST_KEY environment variable (base64 decoded)")
	log.Printf("Private key loaded from SSH_PRIVATE_KEY environment variable (base64 decoded)")
	log.Printf("Public key generated: %s", string(ssh.MarshalAuthorizedKey(publicKey)))

	log.Printf("Starting SSH Gateway on port %d", port)
	if err := gateway.Start(); err != nil {
		log.Fatalf("Failed to start SSH Gateway: %v", err)
	}
}

func (g *SSHGateway) Start() error {
	serverConfig := &ssh.ServerConfig{
		// Allow no client auth initially, we'll handle it in the connection handler
		NoClientAuth: true,
		// Disable password authentication completely
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("password authentication not allowed")
		},
		// Custom authentication handler
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			if err != nil {
				log.Printf("Authentication failed for user %s: %v", conn.User(), err)
			}
		},
	}

	// Add host key
	serverConfig.AddHostKey(g.hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", g.port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", g.port, err)
	}
	defer listener.Close()

	log.Printf("SSH Gateway listening on port %d", g.port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}

		go g.handleConnection(conn, serverConfig)
	}
}

func (g *SSHGateway) handleConnection(conn net.Conn, serverConfig *ssh.ServerConfig) {
	defer conn.Close()

	// Perform SSH handshake
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer serverConn.Close()

	// Extract token from username and validate it
	token := serverConn.User()
	if token == "" {
		log.Printf("No token provided in username")
		conn.Close()
		return
	}

	log.Printf("Validating SSH token")

	// Validate the token using the API
	validation, _, err := g.apiClient.BoxAPI.ValidateSshAccess(context.Background()).Token(token).Execute()
	if err != nil {
		log.Printf("Failed to validate SSH access")
		conn.Close()
		return
	}

	if !validation.Valid {
		log.Printf("Invalid token: %s", redactToken(token))
		conn.Close()
		return
	}
	// Explicit boundary check: valid=true must always carry a non-empty boxId.
	// The API contract guarantees this, but enforce it here so any schema drift
	// or future API regression fails fast rather than producing a silent empty-boxId call.
	if validation.BoxId == "" {
		log.Warnf("API returned valid=true with empty boxId for token %s — rejecting (fail-closed)", redactToken(token))
		conn.Close()
		return
	}

	runner, _, err := g.apiClient.RunnersAPI.GetRunnerByBoxId(context.Background(), validation.BoxId).Execute()
	if err != nil {
		log.Printf("Failed to get runner by box ID: %v", err)
		conn.Close()
		return
	}

	if runner.Domain == nil {
		log.Printf("Runner domain is nil for box ID: %s", validation.BoxId)
		g.sendErrorAndClose(conn, "Runner domain not found. Cannot establish SSH connection.")
		return
	}

	runnerID := runner.Id
	runnerDomain := *runner.Domain
	boxId := validation.BoxId
	// tokenIsSSHAccess=true means the token was issued with an explicit unix_user
	// (real-SSH mode). The gateway must never fall back to the exec bridge for
	// such tokens — exec bridge runs as boxId, bypassing the permission model.
	tokenIsSSHAccess := deriveTokenIsSSHAccess(validation)

	log.Printf("Token validated, SSH connection established for runner: %s", runnerID)

	// Check if the box is started before proceeding. boxId is guaranteed
	// non-empty by the boundary check above.
	log.Printf("Checking box state for box: %s", boxId)
	box, _, err := g.apiClient.BoxAPI.GetBox(context.Background(), boxId).Execute()
	if err != nil {
		log.Printf("Failed to get box state for %s: %v", boxId, err)
		g.sendErrorAndClose(conn, fmt.Sprintf("Failed to verify box state: %v", err))
		return
	}

	if box.State == nil || *box.State != apiclient.BOXSTATE_STARTED {
		state := "unknown"
		if box.State != nil {
			state = string(*box.State)
		}

		log.Printf("Box %s is not started (state: %s), closing connection", boxId, state)
		g.sendErrorAndClose(conn, fmt.Sprintf("Box is not started (state: %s). Please start the box before attempting to connect.", state))
		return
	}

	log.Printf("Box %s is started, allowing SSH connection", boxId)

	// Handle global requests
	go func() {
		for req := range reqs {
			if req == nil {
				continue
			}
			log.Printf("Global request: %s", req.Type)
			// For now, just discard requests
			if req.WantReply {
				req.Reply(false, []byte("not implemented")) // nolint:errcheck
			}
		}
	}()

	// Handle channels
	// Capture the unix_user from the validated token so handleChannel can verify
	// it matches the runner's configured user (prevents stale-token user confusion).
	tokenUnixUser := validation.GetUnixUser()

	for newChannel := range chans {
		go g.handleChannel(newChannel, runnerID, runnerDomain, token, boxId, tokenIsSSHAccess, tokenUnixUser)
	}
}

func (g *SSHGateway) handleChannel(newChannel ssh.NewChannel, runnerID string, runnerDomain string, token string, boxId string, tokenIsSSHAccess bool, tokenUnixUser string) {
	log.Printf("New channel: %s for runner: %s", newChannel.ChannelType(), runnerID)

	// Accept the channel from the client
	clientChannel, clientRequests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept client channel: %v", err)
		return
	}
	defer clientChannel.Close()

	signer := g.privateKey

	// Determine routing: real-SSH or exec-bridge.
	realSSHEnabled := false
	var realSSHPort int
	var realSSHUser string

	if tokenIsSSHAccess && tokenUnixUser == "" {
		// SSH-access token (HasUnixUser=true) with empty unix_user string — reject
		// fail-closed. The controller normalizes empty string to null before DB save,
		// so this is a defense-in-depth boundary check; it should never fire in practice.
		log.Warnf("SSH-access token for %s carries empty unix_user — rejecting (fail-closed)", boxId)
		return
	}

	if g.runnerAPIToken == "" && tokenIsSSHAccess {
		// No runner API token but this is an SSH-access token — fail-closed.
		// The exec bridge runs as boxId (not unix_user) and would bypass
		// the permission model that real-SSH was configured to enforce.
		//
		// Defense-in-depth note: when runnerAPIToken=="", the block below
		// (`if g.runnerAPIToken != ""`) is skipped entirely, so the
		// `else if tokenIsSSHAccess` fail-closed branch inside it is unreachable.
		// This guard here is the SOLE fail-closed path for the no-token case.
		// Do not remove this guard assuming the inner branch covers it.
		log.Warnf("SSH-access token for %s but RUNNER_API_TOKEN not configured — rejecting (fail-closed)", boxId)
		return
	}

	if g.runnerAPIToken != "" {
		info, lookupErr := g.getRunnerSSHAccess(runnerDomain, boxId)
		if lookupErr != nil {
			log.Warnf("getRunnerSSHAccess failed for %s: %v — rejecting channel (fail-closed)", boxId, lookupErr)
			return
		}
		if info.Degraded {
			// Real-SSH is configured but temporarily unavailable (gvproxy port
			// forward could not be established). Fail-closed: never silently fall
			// back to exec-bridge. The user requested real SSH; give them an error
			// rather than a different session type without their knowledge.
			log.Warnf("SSH for %s is degraded (gvproxy unavailable) — rejecting channel (fail-closed)", boxId)
			return
		}
		if info.Enabled {
			if !tokenIsSSHAccess {
				// Legacy exec-bridge token: the runner has real-SSH enabled but
				// this token was issued before real-SSH was configured (null unixUser).
				// Do NOT upgrade it to real-SSH — that would route the session to
				// info.UnixUser without the caller ever having requested that account.
				// Fall through to exec-bridge below.
				log.Printf("Legacy exec-bridge token used while real-SSH is enabled for %s — using exec bridge", boxId)
			} else if tokenUnixUser != info.UnixUser {
				// SSH-access token but unix_user mismatch — stale token from a failed
				// rotation. Reject fail-closed; do not fall back to exec bridge.
				log.Warnf("SSH-access token unix_user %q does not match runner unix_user %q for %s — rejecting (fail-closed)", tokenUnixUser, info.UnixUser, boxId)
				return
			} else {
				realSSHEnabled = true
				realSSHPort = info.HostPort
				// Use tokenUnixUser (from the validated token) rather than info.UnixUser
				// (from the runner state). They are equal at this point (the != check above
				// guards entry), but the token value is the proof-of-intent: the SSH
				// username must come from what the caller requested and was granted, not
				// from what the runner happens to report.
				realSSHUser = tokenUnixUser
			}
		} else if tokenIsSSHAccess {
			// SSH-access token but runner says not enabled — fail-closed.
			log.Warnf("SSH-access token for %s but runner reports SSH not enabled — rejecting (fail-closed)", boxId)
			return
		}
		// Enabled=false && !tokenIsSSHAccess: legacy exec-bridge path — fall through.
	}

	// Connect to the appropriate backend.
	var runnerConn *ssh.Client
	if realSSHEnabled {
		runnerConn, err = g.connectToRunner(realSSHUser, runnerDomain, realSSHPort, signer)
		if err != nil {
			// Real-SSH dial failed — fail-closed (never fall back to exec bridge).
			log.Warnf("Failed to connect to real-SSH for %s on port %d — rejecting (fail-closed): %v", boxId, realSSHPort, err)
			return
		}
	} else {
		runnerConn, err = g.connectToRunner(boxId, runnerDomain, runnerPort, signer)
		if err != nil {
			log.Printf("Failed to connect to runner: %v", err)
			return
		}
	}
	defer runnerConn.Close()

	// Open channel to the runner
	runnerChannel, runnerRequests, err := runnerConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		log.Printf("Failed to open channel to runner: %v", err)
		return
	}
	defer runnerChannel.Close()

	// hasPTY is set to true when the client sends a pty-req, indicating an
	// interactive terminal session. This changes the channel-close strategy: for
	// PTY sessions we fully close the client channel (channel-close) once the
	// runner is done sending, so the SSH client exits immediately without
	// requiring the user to press Enter a second time. For non-PTY sessions
	// (scp, sftp, non-interactive exec) we use CloseWrite (channel-eof only) so
	// the client has a chance to send its final protocol messages before we tear
	// down the channel.
	var hasPTY atomic.Bool

	// Forward requests from client to runner
	go func() {
		for req := range clientRequests {
			if req == nil {
				return
			}
			log.Printf("Client request: %s for runner %s", req.Type, runnerID)

			if req.Type == "pty-req" {
				hasPTY.Store(true)
			}

			ok, err := runnerChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				if err != nil {
					log.Printf("Failed to send request to runner: %v", err)
					req.Reply(false, []byte(err.Error())) // nolint:errcheck
				} else {
					req.Reply(ok, nil) // nolint:errcheck
				}
			}
		}
	}()

	// Forward requests from runner to client
	go func() {
		for req := range runnerRequests {
			if req == nil {
				return
			}
			log.Printf("Runner request: %s for runner %s", req.Type, runnerID)

			ok, err := clientChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				if err != nil {
					log.Printf("Failed to send request to client: %v", err)
					req.Reply(false, []byte(err.Error())) // nolint:errcheck
				} else {
					req.Reply(ok, nil) // nolint:errcheck
				}
			}
		}
	}()

	// Bidirectional data forwarding with proper half-close propagation.
	//
	// SSH channels are half-duplex per direction. When one side finishes
	// sending (io.Copy returns because the source hit EOF), we must call
	// CloseWrite() on the destination channel to deliver a channel-eof to
	// the peer. Without this, commands that wait for server EOF before
	// exiting — most notably scp — hang indefinitely after the transfer
	// completes even though all data was delivered successfully.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(runnerChannel, clientChannel); err != nil {
			log.Printf("Client to runner copy error: %v", err)
		}
		// Signal to the runner that the client is done sending.
		runnerChannel.CloseWrite() //nolint:errcheck
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(clientChannel, runnerChannel); err != nil {
			log.Printf("Runner to client copy error: %v", err)
		}
		// Signal to the client that the runner is done sending.
		//
		// PTY (interactive) sessions: use Close() to send a full channel-close.
		// The shell has already exited, so there is no meaningful data left to
		// receive from the client. A full close causes the SSH client to exit
		// immediately, without requiring the user to press Enter a second time
		// (which was the observable symptom when only CloseWrite/channel-eof was
		// sent and the client's local PTY stayed open waiting for keyboard input).
		//
		// Non-PTY sessions (scp, sftp, non-interactive exec): use CloseWrite()
		// to send only channel-eof. The client may still need to send final
		// protocol messages (e.g. scp's trailing status byte) before it is safe
		// to tear down the channel; a full Close() here would discard those.
		if hasPTY.Load() {
			clientChannel.Close() //nolint:errcheck
		} else {
			clientChannel.CloseWrite() //nolint:errcheck
		}
	}()

	keepAliveContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Keep box alive while connection is open
	go func() {
		// Update immediately upon starting
		_, err := g.apiClient.BoxAPI.UpdateLastActivity(keepAliveContext, boxId).Execute()
		if err != nil {
			log.Warnf("failed to update last activity for box %s (will retry)", boxId)
		}

		// Then every 45 seconds
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_, err := g.apiClient.BoxAPI.UpdateLastActivity(keepAliveContext, boxId).Execute()
				if err != nil {
					log.Errorf("failed to update last activity for box %s", boxId)
				}
			case <-keepAliveContext.Done():
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("Channel closed for runner: %s", runnerID)
}

// connectToRunner dials an SSH server (exec bridge or real sshd) and returns a client.
// user is the SSH username; port is the target TCP port (runnerPort or a real-SSH host_port).
func (g *SSHGateway) connectToRunner(user string, runnerDomain string, port int, signer ssh.Signer) (*ssh.Client, error) {
	host := runnerDomain
	if host == "" {
		host = "localhost"
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if host == "" {
		return nil, fmt.Errorf("invalid host: empty host after processing runner domain")
	}

	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to dial runner: %w", err)
	}

	return client, nil
}

// sendErrorAndClose sends an error message to the client and closes the connection
func (g *SSHGateway) sendErrorAndClose(conn net.Conn, errorMessage string) {
	log.Printf("Sending error to client: %s", errorMessage)

	// For now, just close the connection
	// The client will see "Connection closed by remote host"
	// In a more sophisticated implementation, we could send a proper SSH disconnect message
	// but this requires restructuring the connection handling
	conn.Close()
}

func parsePrivateKey(privateKeyPEM string) (ssh.Signer, error) {
	// First try to parse as OpenSSH format (newer format)
	signer, err := ssh.ParsePrivateKey([]byte(privateKeyPEM))
	if err == nil {
		return signer, nil
	}

	// If OpenSSH parsing fails, try PKCS1 format (older format)
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried OpenSSH and PKCS1 formats): %w", err)
	}

	signer, err = ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	return signer, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// deriveTokenIsSSHAccess reports whether a validated token is a real-SSH
// token (explicit unix_user) rather than a legacy exec-bridge token.
//
// Deliberately NOT validation.HasUnixUser(): the generated client wraps
// unixUser in NullableString, whose HasUnixUser()/IsSet() report whether the
// JSON *key* was present at all — true for both a real value and an explicit
// `"unixUser":null`. The API always sends the key (never omits it; see
// SshAccessValidationDto.fromValidationResult in
// apps/api/src/box/dto/ssh-access.dto.ts, which sets dto.unixUser = unixUser
// ?? null), so HasUnixUser() is always true regardless of whether there's an
// actual unix user — misclassifying every legacy exec-bridge token as
// real-SSH. GetUnixUser() correctly collapses "absent" and "explicit null" to
// "" in both cases.
func deriveTokenIsSSHAccess(validation *apiclient.SshAccessValidationDto) bool {
	return validation.GetUnixUser() != ""
}

// redactToken returns a safe representation of a bearer token for logging.
// It keeps the first 8 characters (enough for correlation) and replaces the
// remainder with "…" so live credentials never appear in plaintext in logs.
func redactToken(token string) string {
	const prefixLen = 8
	if len(token) <= prefixLen {
		return "***"
	}
	return token[:prefixLen] + "…"
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
