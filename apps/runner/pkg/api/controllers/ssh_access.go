// Copyright 2025 BoxLite AI
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"log/slog"
	"net/http"
	"regexp"

	"github.com/boxlite-ai/runner/cmd/runner/config"
	"github.com/boxlite-ai/runner/pkg/runner"
	"github.com/gin-gonic/gin"
)

// posixUsernameRe matches POSIX-portable usernames: starts with [a-z_],
// followed by up to 31 chars from [a-z0-9_-]. Rejects path separators,
// whitespace, and control characters that could enable path traversal or
// sshd_config injection in the guest.
var posixUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func validateUnixUser(u string) bool {
	return posixUsernameRe.MatchString(u)
}

type enableSSHRequest struct {
	// AuthorizedKeys is accepted for API compatibility and reserved for a future
	// TCP-proxy mode, but is NOT installed in the guest authorized_keys file
	// under the current SSH-level-proxy architecture. Only the gateway's own
	// public key is written to the guest. See gatewayOnlyKeys for rationale.
	AuthorizedKeys []string `json:"authorized_keys"`
	UnixUser       string   `json:"unix_user"`
}

type sshAccessResponse struct {
	HostPort int    `json:"host_port"`
	UnixUser string `json:"unix_user"`
	Enabled  bool   `json:"enabled"`
	// Degraded is true when SSH has been configured for this box (state exists)
	// but is temporarily unhealthy or disabled-pending. Callers must treat this
	// as fail-closed: the box HAS real-SSH configured, so falling back to the
	// exec bridge would bypass the unix_user permission model. Reject the channel
	// and let the client retry after the degraded state clears.
	//
	// Invariant: Degraded=true implies Enabled=false. When Degraded=true the
	// HostPort and UnixUser fields are populated with the last-known values so
	// the caller can log them for diagnosis; it MUST NOT dial HostPort.
	Degraded bool `json:"degraded"`
}

// gatewayOnlyKeys returns a slice containing only the gateway public key.
//
// Security model: the gateway acts as an SSH-level proxy (gateway → guest sshd
// using the gateway's own private key). In this model ONLY the gateway key must
// appear in the guest authorized_keys file. Installing caller-supplied public
// keys alongside the gateway key would allow the caller to bypass the gateway
// entirely — connecting directly to the host port (22100-22199) using their own
// private key — skipping token validation, expiry checking, audit logging, and
// revocation. The network-level guard (AWS security group restricts the port
// range to the gateway SG only) provides defence-in-depth, but authorised_keys
// is the definitive auth boundary and must not contain caller keys.
//
// Caller-provided authorized_keys are accepted in the request body for API
// compatibility and reserved for a future TCP-proxy mode (where the gateway
// does a raw TCP forward and sshd authenticates the caller directly), but they
// are NOT installed in the guest under the current SSH-level proxy architecture.
func gatewayOnlyKeys(gatewayKey string) []string {
	return []string{gatewayKey}
}

// EnableSSHAccess configures sshd inside the box and allocates a host port.
//
// Precondition: SSH_GATEWAY_PUBLIC_KEY must be set in config. The gateway's
// public key is required so that the gateway's private key is accepted by the
// guest sshd. Without it the gateway cannot authenticate to the guest even
// though SSH access is nominally enabled. A missing or unloadable key is a
// server configuration error, not a caller error, so this function returns
// 503 (Service Unavailable) rather than proceeding and returning a 200 that
// the gateway cannot actually use.
func EnableSSHAccess(ctx *gin.Context) {
	boxId := ctx.Param("boxId")

	var req enableSSHRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.UnixUser == "" {
		req.UnixUser = "root"
	}
	if !validateUnixUser(req.UnixUser) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "unix_user must match [a-z_][a-z0-9_-]{0,31}"})
		return
	}

	// Load config and enforce the gateway key precondition before any runner
	// or Boxlite call. A missing key means SSH access cannot work end-to-end;
	// returning early here prevents a misleading 200 response with persisted
	// state that the gateway will never be able to use.
	cfg, err := config.GetConfig()
	if err != nil {
		slog.Default().Error("EnableSSHAccess: failed to load config", "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server configuration error"})
		return
	}
	if cfg.SSHGatewayPublicKey == "" {
		slog.Default().Error("EnableSSHAccess: SSH_GATEWAY_PUBLIC_KEY not configured; cannot enable SSH access")
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "SSH gateway public key not configured on this runner"})
		return
	}
	// Only the gateway key is installed in the guest authorized_keys. See
	// gatewayOnlyKeys for the full security rationale. Caller-supplied keys
	// (req.AuthorizedKeys) are accepted in the request body for API
	// compatibility but are NOT forwarded to the guest in the current
	// SSH-level-proxy architecture.
	authorizedKeys := gatewayOnlyKeys(cfg.SSHGatewayPublicKey)

	r, err := runner.GetInstance(nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if r.SSHPortAllocator == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "SSH port allocator not configured"})
		return
	}

	hostPort, err := r.Boxlite.EnableSSHAccess(ctx.Request.Context(), boxId, authorizedKeys, req.UnixUser, r.SSHPortAllocator)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusOK, sshAccessResponse{
		HostPort: hostPort,
		UnixUser: req.UnixUser,
		Enabled:  true,
	})
}

// GetSSHAccess returns the current SSH access state for a box.
func GetSSHAccess(ctx *gin.Context) {
	boxId := ctx.Param("boxId")

	r, err := runner.GetInstance(nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// GetSSHAccess returns a value copy of the internal state snapshot, so
	// reading ForwardHealthy, DisablePending, HostPort, and UnixUser below is
	// race-free even though other goroutines may concurrently mutate the stored
	// *SSHState fields under the client's internal lock.
	state, ok := r.Boxlite.GetSSHAccess(boxId)
	if !ok {
		ctx.JSON(http.StatusOK, sshAccessResponse{Enabled: false})
		return
	}

	// Report enabled only when the SSH forward is known healthy and there is no
	// pending disable in progress. Callers (e.g. the SSH gateway) use Enabled to
	// decide whether to route to the real-sshd port or fall back to exec-bridge.
	//
	// When the state exists but is degraded (ForwardHealthy=false or
	// DisablePending=true), return Degraded=true instead of a bare Enabled=false.
	// This lets the gateway distinguish two fundamentally different situations:
	//
	//   Enabled=false, Degraded=false  → SSH was never configured on this box.
	//                                    The exec bridge is the correct fallback.
	//
	//   Enabled=false, Degraded=true   → SSH WAS configured but is temporarily
	//                                    unhealthy or being torn down. The exec
	//                                    bridge would bypass the unix_user model
	//                                    (it runs as sandboxId, not unix_user).
	//                                    The gateway must fail-closed: reject the
	//                                    channel and let the client retry.
	//
	// HostPort and UnixUser are populated for diagnostics; the gateway MUST NOT
	// dial HostPort when Degraded=true (the forward is down or being removed).
	//
	// (Finding 2, Round 52)
	if !state.ForwardHealthy || state.DisablePending {
		ctx.JSON(http.StatusOK, sshAccessResponse{
			HostPort: state.HostPort,
			UnixUser: state.UnixUser,
			Enabled:  false,
			Degraded: true,
		})
		return
	}

	ctx.JSON(http.StatusOK, sshAccessResponse{
		HostPort: state.HostPort,
		UnixUser: state.UnixUser,
		Enabled:  true,
	})
}

// DisableSSHAccess stops sshd and removes the port forward for a box.
func DisableSSHAccess(ctx *gin.Context) {
	boxId := ctx.Param("boxId")

	r, err := runner.GetInstance(nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if r.SSHPortAllocator == nil {
		ctx.JSON(http.StatusServiceUnavailable, gin.H{"error": "SSH port allocator not configured"})
		return
	}

	if err := r.Boxlite.DisableSSHAccess(ctx.Request.Context(), boxId, r.SSHPortAllocator); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx.JSON(http.StatusNoContent, nil)
}
