// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sessionframe

// OpenExecPayload is the JSON payload of an OPEN_EXEC request.
type OpenExecPayload struct {
	Command string `json:"command"`
}

// PtyRequestPayload is the JSON payload of a PTY_REQUEST request.
type PtyRequestPayload struct {
	Term     string `json:"term"`
	Cols     uint32 `json:"cols"`
	Rows     uint32 `json:"rows"`
	WidthPx  uint32 `json:"width_px"`
	HeightPx uint32 `json:"height_px"`
}

// PtyResizePayload is the JSON payload of a PTY_RESIZE request.
type PtyResizePayload struct {
	Cols     uint32 `json:"cols"`
	Rows     uint32 `json:"rows"`
	WidthPx  uint32 `json:"width_px"`
	HeightPx uint32 `json:"height_px"`
}

// ExitStatusPayload is the JSON payload of an EXIT_STATUS frame.
type ExitStatusPayload struct {
	Code int32 `json:"code"`
}

// ErrorPayload is the JSON payload of an ERROR frame, and the error member
// of a failed ReplyPayload. On channel 0 an ERROR frame is a
// connection-level protocol error and the connection must be closed after
// sending it.
type ErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ReplyPayload is the JSON payload of every REPLY frame. Error is present
// iff Ok is false. Field order matters on the wire: Ok must marshal first
// so a successful reply is exactly {"ok":true}.
type ReplyPayload struct {
	Ok    bool          `json:"ok"`
	Error *ErrorPayload `json:"error,omitempty"`
}
