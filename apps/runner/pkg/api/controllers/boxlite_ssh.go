// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 BoxLite AI

package controllers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	sdkboxlite "github.com/boxlite-ai/boxlite/sdks/go"
	"github.com/boxlite-ai/runner/pkg/models/enums"
	"github.com/boxlite-ai/runner/pkg/runner"
	"github.com/boxlite-ai/runner/pkg/sessionbridge"
	"github.com/boxlite-ai/runner/pkg/sessionframe"
	"github.com/gin-gonic/gin"
)

// sshTransportName is the only transport the runner bridges; never expose
// runtime addressing (socket paths, CIDs, ports) beyond this label.
const sshTransportName = "boxlite-runtime-vsock"

// sshSessionUpgradeResponse is the exact 101 handshake for the
// boxlite-session-stream upgrade; after these bytes the connection carries
// session frames (docs/architecture/ssh-session-frame-protocol.md).
const sshSessionUpgradeResponse = "HTTP/1.1 101 Switching Protocols\r\n" +
	"Upgrade: " + sessionframe.UpgradeProtocol + "\r\n" +
	"Connection: Upgrade\r\n\r\n"

// Stable pre-upgrade rejection reasons (JSON "reason" field).
const (
	reasonInvalidUpgrade    = "INVALID_UPGRADE"
	reasonBoxNotFound       = "BOX_NOT_FOUND"
	reasonBoxStopped        = "BOX_STOPPED"
	reasonUnixUserForbidden = "UNIX_USER_FORBIDDEN"
)

// errSessionBoxNotFound marks a resolve failure as "unknown box" (-> 404).
var errSessionBoxNotFound = errors.New("box not found")

// sessionBox is the surface of a box handle needed by the SSH session
// endpoints. *sdkboxlite.Box implements it; tests substitute fakes.
type sessionBox interface {
	SessionReady(ctx context.Context, service string) (sdkboxlite.SessionReadiness, error)
	SSH(ctx context.Context) (net.Conn, error)
}

// resolveSessionBox is the production lookup; tests override.
var resolveSessionBox = func(ctx context.Context, boxId string) (sessionBox, enums.BoxState, error) {
	r, err := runner.GetInstance(nil)
	if err != nil {
		return nil, enums.BoxStateUnknown, err
	}
	bx, err := r.Boxlite.GetBox(ctx, boxId)
	if err != nil {
		return nil, enums.BoxStateUnknown, fmt.Errorf("%w: %s", errSessionBoxNotFound, boxId)
	}
	state, err := r.Boxlite.GetBoxState(ctx, boxId)
	if err != nil {
		return nil, enums.BoxStateUnknown, err
	}
	return bx, state, nil
}

// SshStatusResponse is the readiness diagnostic for a box's SSH service.
// DegradedReason is a stable code string only (e.g. "GUEST_SERVICE_NOT_READY"),
// never runtime addressing.
type SshStatusResponse struct {
	Ready          bool   `json:"ready"`
	Transport      string `json:"transport"`
	Degraded       bool   `json:"degraded"`
	DegradedReason string `json:"degraded_reason"`
}

// BoxliteSshStatus reports whether the box's guest SSH service accepts
// connections right now.
//
//	@Summary	SSH readiness diagnostics for a box
//	@Tags		boxlite
//	@Param		boxId	path		string	true	"Box ID"
//	@Success	200		{object}	SshStatusResponse
//	@Failure	404		{object}	map[string]string	"box not found"
//	@Router		/v1/boxes/{boxId}/ssh-status [get]
func BoxliteSshStatus(ctx *gin.Context) {
	boxId := ctx.Param("boxId")
	bx, _, err := resolveSessionBox(ctx.Request.Context(), boxId)
	if err != nil {
		if errors.Is(err, errSessionBoxNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("box %s not found", boxId)})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve box"})
		return
	}

	readiness, err := bx.SessionReady(ctx.Request.Context(), "ssh")
	if err != nil {
		if se, ok := sdkboxlite.AsSessionError(err); ok {
			ctx.JSON(http.StatusOK, SshStatusResponse{
				Transport:      sshTransportName,
				Degraded:       true,
				DegradedReason: se.Code,
			})
			return
		}
		// Untyped errors may embed runtime detail; log it, answer typed.
		slog.Error("ssh readiness probe failed", "box", boxId, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "ssh readiness probe failed"})
		return
	}

	resp := SshStatusResponse{Ready: readiness.Ready, Transport: sshTransportName}
	if !readiness.Ready {
		resp.Degraded = true
		resp.DegradedReason = "GUEST_SERVICE_NOT_READY"
		if readiness.Reason != nil {
			resp.DegradedReason = readiness.Reason.Code
		}
	}
	ctx.JSON(http.StatusOK, resp)
}

// InternalSshSessionStream upgrades an authenticated internal request to
// the boxlite-session-stream protocol and bridges frames to a guest SSH
// session. All validation is fail-closed BEFORE the 101 so the Gateway
// always receives a clean HTTP status.
//
//	@Summary	Bridge a Gateway SSH session to the guest (HTTP upgrade)
//	@Tags		internal
//	@Param		boxId	path	string	true	"Box ID"
//	@Success	101
//	@Failure	400	{object}	map[string]string	"invalid upgrade request"
//	@Failure	403	{object}	map[string]string	"unix user forbidden"
//	@Failure	404	{object}	map[string]string	"box not found"
//	@Failure	409	{object}	map[string]string	"box not running"
//	@Failure	503	{object}	map[string]string	"guest ssh not ready"
//	@Router		/internal/ssh/sessions/{boxId}/stream [post]
func InternalSshSessionStream(ctx *gin.Context) {
	boxId := ctx.Param("boxId")

	if msg, ok := validateSessionUpgradeRequest(ctx.Request); !ok {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": msg, "reason": reasonInvalidUpgrade})
		return
	}
	sessionID := ctx.GetHeader(sessionframe.HeaderSessionID)
	tokenID := ctx.GetHeader(sessionframe.HeaderTokenID)
	unixUser := ctx.GetHeader(sessionframe.HeaderUnixUser)

	bx, state, err := resolveSessionBox(ctx.Request.Context(), boxId)
	if err != nil {
		if errors.Is(err, errSessionBoxNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error":  fmt.Sprintf("box %s not found", boxId),
				"reason": reasonBoxNotFound,
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve box"})
		return
	}
	if state != enums.BoxStateStarted {
		ctx.JSON(http.StatusConflict, gin.H{
			"error":  fmt.Sprintf("box %s is not running", boxId),
			"reason": reasonBoxStopped,
		})
		return
	}
	if unixUser != "root" {
		ctx.JSON(http.StatusForbidden, gin.H{
			"error":  "only unix user root is bridged",
			"reason": reasonUnixUserForbidden,
		})
		return
	}

	readiness, err := bx.SessionReady(ctx.Request.Context(), "ssh")
	if err != nil {
		if se, ok := sdkboxlite.AsSessionError(err); ok {
			ctx.JSON(http.StatusServiceUnavailable, gin.H{
				"error":  "guest ssh service not ready",
				"reason": se.Code,
			})
			return
		}
		slog.Error("ssh readiness probe failed", "box", boxId, "error", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "ssh readiness probe failed"})
		return
	}
	if !readiness.Ready {
		reason := "GUEST_SERVICE_NOT_READY"
		if readiness.Reason != nil {
			reason = readiness.Reason.Code
		}
		ctx.JSON(http.StatusServiceUnavailable, gin.H{
			"error":  "guest ssh service not ready",
			"reason": reason,
		})
		return
	}

	hijacker, ok := ctx.Writer.(http.Hijacker)
	if !ok {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "connection does not support upgrade"})
		return
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "connection hijack failed"})
		return
	}
	if _, err := conn.Write([]byte(sshSessionUpgradeResponse)); err != nil {
		_ = conn.Close()
		return
	}

	logger := slog.Default().With(
		slog.String("component", "ssh_session_bridge"),
		slog.String("box", boxId),
		slog.String("session_id", sessionID),
		// Never log the raw token; the token id itself is non-sensitive but
		// is still truncated defensively.
		slog.String("token_id", redactTokenID(tokenID)),
	)
	logger.Info("ssh session stream opened")

	bridge := sessionbridge.New(conn, brw.Reader, logger)
	bridge.Run(ctx.Request.Context(), func(dialCtx context.Context) (net.Conn, error) {
		guest, err := bx.SSH(dialCtx)
		if err != nil {
			if se, ok := sdkboxlite.AsSessionError(err); ok {
				// SessionError messages are user-safe by construction
				// (no socket paths, CIDs, or ports).
				return nil, &sessionbridge.GuestDialError{Code: se.Code, Message: se.Message}
			}
			return nil, err
		}
		return guest, nil
	})
	logger.Info("ssh session stream closed")
}

// validateSessionUpgradeRequest checks the upgrade handshake headers per
// the session-frame protocol spec. Returns a client-safe message when the
// request is not a valid boxlite-session-stream upgrade.
func validateSessionUpgradeRequest(r *http.Request) (msg string, ok bool) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), sessionframe.UpgradeProtocol) {
		return fmt.Sprintf("Upgrade header must be %q", sessionframe.UpgradeProtocol), false
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return "Connection header must include Upgrade", false
	}
	for _, header := range []string{
		sessionframe.HeaderSessionID,
		sessionframe.HeaderTokenID,
		sessionframe.HeaderUnixUser,
	} {
		if r.Header.Get(header) == "" {
			return fmt.Sprintf("missing required header %s", header), false
		}
	}
	return "", true
}

// headerContainsToken reports whether a comma-separated header value
// contains token (case-insensitive), e.g. Connection: keep-alive, Upgrade.
func headerContainsToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// maxTokenIDLogChars caps how much of a token id ever reaches a log line.
const maxTokenIDLogChars = 8

// redactTokenID truncates a token id for logging: at most the first 8
// characters, never the full id. Rune-safe so a hostile id cannot smuggle
// invalid UTF-8 into log lines.
func redactTokenID(tokenID string) string {
	runes := []rune(tokenID)
	if len(runes) <= maxTokenIDLogChars {
		return tokenID
	}
	return string(runes[:maxTokenIDLogChars]) + "..."
}
