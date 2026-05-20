// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

//go:build integration

package sshgateway_test

// SSH integration tests for real-SSH sandbox access.
//
// These tests connect directly to the sshd running inside a VM (bypassing the
// SSH Gateway) to verify that SFTP, scp, non-PTY exec, and interactive shell
// all work end-to-end.  They require a running Runner EC2 with a sandbox that
// has SSH access enabled via POST /v1/boxes/{id}/ssh-access.
//
// Required environment variables:
//
//	BOXLITE_SSH_HOST      – Runner EC2 hostname or IP
//	BOXLITE_SSH_PORT      – Host port allocated for the sandbox (22100-22199)
//	BOXLITE_SSH_KEY_FILE  – Path to the SSH private key installed in the sandbox
//
// Optional:
//
//	BOXLITE_SSH_USER      – Unix user inside the VM (default: "boxlite")
//
// Run with:
//
//	make test:integration:go-services

import (
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --- helpers -----------------------------------------------------------------

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("env %s not set — skipping SSH integration test", key)
	}
	return v
}

func sshUser(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("BOXLITE_SSH_USER"); u != "" {
		return u
	}
	return "boxlite"
}

func sshClientConfig(t *testing.T) *ssh.ClientConfig {
	t.Helper()
	keyFile := requireEnv(t, "BOXLITE_SSH_KEY_FILE")
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read SSH key %s: %v", keyFile, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatalf("parse SSH private key: %v", err)
	}
	return &ssh.ClientConfig{
		User:            sshUser(t),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // integration test, not production
		Timeout:         15 * time.Second,
	}
}

func sshDial(t *testing.T) *ssh.Client {
	t.Helper()
	host := requireEnv(t, "BOXLITE_SSH_HOST")
	port := requireEnv(t, "BOXLITE_SSH_PORT")
	addr := net.JoinHostPort(host, port)
	client, err := ssh.Dial("tcp", addr, sshClientConfig(t))
	if err != nil {
		t.Fatalf("ssh dial %s: %v", addr, err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func md5File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("hash %s: %v", path, err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func randomBinaryFile(t *testing.T, size int) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "boxlite-ssh-test-*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	data := make([]byte, size)
	rand.Read(data) //nolint:gosec // test data, no security concern
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return f.Name()
}

// sshFlags returns the common SSH/SCP/SFTP CLI flags for the test connection.
func sshFlags(t *testing.T) []string {
	t.Helper()
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-i", requireEnv(t, "BOXLITE_SSH_KEY_FILE"),
	}
}

// --- tests -------------------------------------------------------------------

// TestNonPTYExecOutput verifies that a non-PTY exec command runs inside the
// container and its stdout is returned intact.
func TestNonPTYExecOutput(t *testing.T) {
	client := sshDial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	out, err := session.Output("echo hello-boxlite")
	if err != nil {
		t.Fatalf("exec echo: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "hello-boxlite" {
		t.Errorf("got %q, want %q", got, "hello-boxlite")
	}
}

// TestNonPTYExecExitCode verifies that the real SSH path propagates arbitrary
// exit codes.  The exec-bridge cannot do this (it always returns 0 or a
// protocol error), so a correct non-zero exit code proves the in-VM sshd path.
func TestNonPTYExecExitCode(t *testing.T) {
	client := sshDial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	err = session.Run("sh -c 'exit 42'")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ssh.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitStatus() != 42 {
		t.Errorf("exit status = %d, want 42", exitErr.ExitStatus())
	}
}

// TestSFTPBinaryRoundTrip uploads a 4 KiB random binary file via sftp and
// downloads it back, then compares MD5 checksums.  The exec-bridge corrupts
// arbitrary binary data (Rust UTF-8 lossy conversion), so a matching checksum
// proves the SFTP subsystem runs through the real sshd path.
func TestSFTPBinaryRoundTrip(t *testing.T) {
	host := requireEnv(t, "BOXLITE_SSH_HOST")
	port := requireEnv(t, "BOXLITE_SSH_PORT")
	user := sshUser(t)
	flags := sshFlags(t)

	src := randomBinaryFile(t, 4096)
	dst := filepath(t, "dst.bin")
	remote := "/tmp/boxlite-sftp-test.bin"

	target := fmt.Sprintf("%s@%s", user, host)

	// Upload.
	upload := exec.Command("sftp",
		append(append([]string{"-P", port}, flags...),
			"-b", "-", target)...)
	upload.Stdin = strings.NewReader(fmt.Sprintf("put %s %s\n", src, remote))
	if out, err := upload.CombinedOutput(); err != nil {
		t.Fatalf("sftp put: %v\n%s", err, out)
	}

	// Download.
	download := exec.Command("sftp",
		append(append([]string{"-P", port}, flags...),
			"-b", "-", target)...)
	download.Stdin = strings.NewReader(fmt.Sprintf("get %s %s\n", remote, dst))
	if out, err := download.CombinedOutput(); err != nil {
		t.Fatalf("sftp get: %v\n%s", err, out)
	}

	if want, got := md5File(t, src), md5File(t, dst); want != got {
		t.Errorf("MD5 mismatch: uploaded %s, downloaded %s", want, got)
	}
}

// TestScpBinaryRoundTrip uploads and downloads a 4 KiB random binary file via
// scp and compares MD5 checksums (same binary-stream correctness check as SFTP).
func TestScpBinaryRoundTrip(t *testing.T) {
	host := requireEnv(t, "BOXLITE_SSH_HOST")
	port := requireEnv(t, "BOXLITE_SSH_PORT")
	user := sshUser(t)
	flags := sshFlags(t)

	src := randomBinaryFile(t, 4096)
	dst := filepath(t, "dst.bin")
	remote := fmt.Sprintf("%s@%s:/tmp/boxlite-scp-test.bin", user, host)

	// Upload.
	up := exec.Command("scp",
		append(append([]string{"-P", port}, flags...),
			src, remote)...)
	if out, err := up.CombinedOutput(); err != nil {
		t.Fatalf("scp upload: %v\n%s", err, out)
	}

	// Download.
	down := exec.Command("scp",
		append(append([]string{"-P", port}, flags...),
			remote, dst)...)
	if out, err := down.CombinedOutput(); err != nil {
		t.Fatalf("scp download: %v\n%s", err, out)
	}

	if want, got := md5File(t, src), md5File(t, dst); want != got {
		t.Errorf("MD5 mismatch: uploaded %s, downloaded %s", want, got)
	}
}

// TestInteractiveShellConnects requests a PTY and starts a shell. It verifies
// that the remote side sends at least one byte (a shell prompt) within the
// timeout, which proves the full PTY path through the in-VM sshd is working.
func TestInteractiveShellConnects(t *testing.T) {
	client := sshDial(t)

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{
		ssh.ECHO: 0,
	}); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	var buf bytes.Buffer
	session.Stdout = &buf

	if err := session.Shell(); err != nil {
		t.Fatalf("start shell: %v", err)
	}

	// Give the shell up to 3 s to emit a prompt.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if buf.Len() > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if buf.Len() == 0 {
		t.Error("shell sent no output within 3 s (expected at least a prompt byte)")
	}
}

// filepath returns a path inside t.TempDir() with the given base name.
func filepath(t *testing.T, name string) string {
	t.Helper()
	return t.TempDir() + "/" + name
}
