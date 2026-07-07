// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package config

import (
	"strconv"
	"strings"
	"testing"
)

// setBaseEnv sets the minimum env vars GetConfig needs to succeed, so tests
// can focus on the SSH port validation without also exercising the
// BoxliteApiUrl/ApiToken/Domain fallback paths (the latter would otherwise
// make a real outbound network call via getOutboundIP()).
func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BOXLITE_API_URL", "http://localhost:3000")
	t.Setenv("BOXLITE_RUNNER_TOKEN", "test-token")
	t.Setenv("RUNNER_DOMAIN", "127.0.0.1")
}

// TestSSHPortConfigRejectsOutOfRangeValues proves that GetConfig fails fast
// when SSH_PORT_BASE/SSH_PORT_POOL_SIZE are invalid, rather than accepting
// them and pushing the failure downstream to the first SSH-access request.
func TestSSHPortConfigRejectsOutOfRangeValues(t *testing.T) {
	cases := []struct {
		name        string
		base        string
		poolSize    string
		wantErrPart string
	}{
		{name: "negative base", base: "-1", poolSize: "100", wantErrPart: "SSHPortBase"},
		{name: "zero base", base: "0", poolSize: "100", wantErrPart: "SSHPortBase"},
		{name: "base above 65535", base: "70000", poolSize: "1", wantErrPart: "SSHPortBase"},
		{name: "zero pool size", base: "22100", poolSize: "0", wantErrPart: "SSHPortPoolSize"},
		{name: "negative pool size", base: "22100", poolSize: "-5", wantErrPart: "SSHPortPoolSize"},
		{name: "range exceeds 65535", base: "65500", poolSize: "100", wantErrPart: "invalid SSH port range"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("SSH_PORT_BASE", tc.base)
			t.Setenv("SSH_PORT_POOL_SIZE", tc.poolSize)
			ResetForTest()

			_, err := GetConfig()
			if err == nil {
				t.Fatalf("GetConfig() succeeded with SSH_PORT_BASE=%s SSH_PORT_POOL_SIZE=%s, want error containing %q",
					tc.base, tc.poolSize, tc.wantErrPart)
			}
			if !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Fatalf("GetConfig() error = %q, want it to contain %q", err.Error(), tc.wantErrPart)
			}
		})
	}
}

// TestSSHPortConfigAcceptsValidRange proves the default and other legitimate
// SSH port configurations still load successfully.
func TestSSHPortConfigAcceptsValidRange(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		poolSize string
	}{
		{name: "documented default", base: "22100", poolSize: "100"},
		{name: "range ending exactly at 65535", base: "65436", poolSize: "100"},
		{name: "single port pool", base: "22100", poolSize: "1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("SSH_PORT_BASE", tc.base)
			t.Setenv("SSH_PORT_POOL_SIZE", tc.poolSize)
			ResetForTest()

			cfg, err := GetConfig()
			if err != nil {
				t.Fatalf("GetConfig() failed for SSH_PORT_BASE=%s SSH_PORT_POOL_SIZE=%s: %v", tc.base, tc.poolSize, err)
			}
			wantBase, err := strconv.Atoi(tc.base)
			if err != nil {
				t.Fatalf("test case base %q is not a valid integer: %v", tc.base, err)
			}
			if cfg.SSHPortBase != wantBase {
				t.Fatalf("SSHPortBase = %d, want %s", cfg.SSHPortBase, tc.base)
			}
		})
	}
}
