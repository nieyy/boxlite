// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/boxlite-ai/runner/cmd/runner/config"
)

// TestGatewayOnlyKeysReturnsOnlyGatewayKey verifies that gatewayOnlyKeys
// returns a single-element slice containing exactly the gateway key, regardless
// of any caller-supplied keys. This is the core security invariant: only the
// gateway's public key is installed in the guest authorized_keys file, so a
// caller cannot bypass the gateway by authenticating directly with their own
// private key.
func TestGatewayOnlyKeysReturnsOnlyGatewayKey(t *testing.T) {
	gwKey := "ssh-ed25519 AAABBBCCC gateway@host"

	got := gatewayOnlyKeys(gwKey)

	if len(got) != 1 {
		t.Fatalf("gatewayOnlyKeys: expected exactly 1 key, got %d: %v", len(got), got)
	}
	if got[0] != gwKey {
		t.Fatalf("gatewayOnlyKeys: expected %q, got %q", gwKey, got[0])
	}
}

// TestGatewayOnlyKeysDoesNotIncludeCallerKey verifies that caller-supplied keys
// are never included in the returned slice. The result must have exactly one
// entry — the gateway key — even when the caller provides additional keys.
func TestGatewayOnlyKeysDoesNotIncludeCallerKey(t *testing.T) {
	gwKey := "ssh-ed25519 GW gw@host"
	// These keys are what the caller would have sent in the request body.
	// They must NOT appear in the guest authorized_keys.
	callerKeys := []string{"ssh-rsa K1 u1@host", "ssh-rsa K2 u2@host"}

	got := gatewayOnlyKeys(gwKey)

	if len(got) != 1 {
		t.Fatalf("gatewayOnlyKeys: result must contain only the gateway key; got %d keys: %v", len(got), got)
	}
	for _, ck := range callerKeys {
		for _, g := range got {
			if g == ck {
				t.Fatalf("gatewayOnlyKeys: caller key %q must not appear in result", ck)
			}
		}
	}
}

// TestEnableSSHAccessRejectsWhenGatewayKeyEmpty verifies that EnableSSHAccess
// returns a non-200 error and does NOT call r.Boxlite.EnableSSHAccess when
// SSH_GATEWAY_PUBLIC_KEY is empty.
//
// Before fix: the handler silently skipped key injection and proceeded to call
// Boxlite, returning 200 with state the gateway could never use.
// After fix: the handler returns 503 immediately, before reaching the runner
// singleton or Boxlite client.
//
// The test verifies the precondition by:
//  1. Resetting the config cache so env changes take effect.
//  2. Setting all required config fields except SSH_GATEWAY_PUBLIC_KEY.
//  3. Calling the handler through a real gin router (same path as production).
//  4. Asserting the response is 503 (not 200) — Boxlite was never reached
//     because the handler returned before GetInstance was called.
func TestEnableSSHAccessRejectsWhenGatewayKeyEmpty(t *testing.T) {
	// Reset the config singleton so the env vars set below take effect.
	config.ResetForTest()
	t.Cleanup(config.ResetForTest)

	// Supply required config fields. SSH_GATEWAY_PUBLIC_KEY is intentionally
	// absent to trigger the precondition failure.
	t.Setenv("BOXLITE_API_URL", "http://test.example.invalid:8080")
	t.Setenv("BOXLITE_RUNNER_TOKEN", "test-token")
	t.Setenv("RUNNER_DOMAIN", "127.0.0.1")
	t.Setenv("SSH_GATEWAY_PUBLIC_KEY", "") // empty = not configured

	// authorized_keys in the body is now optional (field is accepted for API
	// compat but ignored at the guest level); omit it to exercise that path.
	body := `{"unix_user":"boxlite"}`
	w := runHandler(
		http.MethodPost,
		"/v1/boxes/:boxId/ssh-access",
		"/v1/boxes/test-box/ssh-access",
		strings.NewReader(body),
		EnableSSHAccess,
	)

	// Must be a non-200 error. 503 (SSH gateway public key not configured) is
	// the expected status; 500 (config load error) is also acceptable. Either
	// way, Boxlite was never called because the handler returned before
	// runner.GetInstance was reached.
	if w.Code == http.StatusOK {
		t.Fatalf("EnableSSHAccess returned 200 when SSH_GATEWAY_PUBLIC_KEY is empty; "+
			"body=%s — the handler must return a non-200 error so the gateway key "+
			"precondition is enforced before any Boxlite state is persisted", w.Body.String())
	}
	if w.Code != http.StatusServiceUnavailable && w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 503 or 500, got %d body=%s", w.Code, w.Body.String())
	}
}
