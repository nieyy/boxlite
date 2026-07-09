// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

// Package sessionframe implements version 1 of the BoxLite session-frame
// wire protocol used between the Gateway and the Runner for real SSH
// sessions. The transport is a reliable byte stream obtained via an
// HTTP/1.1 upgrade (Upgrade: boxlite-session-stream); after
// `101 Switching Protocols` the connection carries frames both ways.
//
// A frame is a 16-byte fixed header (all integers big-endian) followed by
// exactly PayloadLen bytes of payload. A Rust implementation of the same
// spec exists on the Gateway side; the wire format here is normative and
// must not change without bumping ProtocolVersion.
package sessionframe

import (
	"encoding/json"
	"fmt"
)

// Wire-protocol constants (version 1).
const (
	// ProtocolVersion is the only version this codec accepts.
	ProtocolVersion uint8 = 1
	// HeaderLen is the fixed frame-header size in bytes.
	HeaderLen = 16
	// MaxPayload is the maximum payload_length (256 KiB).
	MaxPayload = 262144
	// ControlChannelID (0) is reserved for connection-level control;
	// only ERROR frames use it. Session channels are nonzero.
	ControlChannelID uint32 = 0
	// FlagReply marks a frame as the reply to the request with the same
	// type, channel_id, and request_id. All other flag bits are reserved
	// and must be zero.
	FlagReply uint16 = 0x0001
)

// HTTP upgrade handshake constants.
const (
	// UpgradeProtocol is the value of the Upgrade header on the
	// POST /internal/ssh/sessions/{boxId}/stream handshake.
	UpgradeProtocol = "boxlite-session-stream"

	HeaderSessionID = "X-BoxLite-Session-ID"
	HeaderTokenID   = "X-BoxLite-Token-ID"
	HeaderUnixUser  = "X-BoxLite-Unix-User"
)

// FrameType identifies the kind of frame (header byte at offset 1).
type FrameType uint8

// Frame types (version 1).
const (
	FrameOpenShell  FrameType = 1  // request; JSON payload {}
	FrameOpenExec   FrameType = 2  // request; JSON OpenExecPayload
	FramePtyRequest FrameType = 3  // request; JSON PtyRequestPayload
	FramePtyResize  FrameType = 4  // request; JSON PtyResizePayload
	FrameStdin      FrameType = 5  // raw bytes, gateway -> runner
	FrameStdout     FrameType = 6  // raw bytes, runner -> gateway
	FrameStderr     FrameType = 7  // raw bytes, runner -> gateway
	FrameExitStatus FrameType = 8  // JSON ExitStatusPayload, runner -> gateway
	FrameEOF        FrameType = 9  // empty; half-close of sender's data direction
	FrameClose      FrameType = 10 // empty; full channel teardown
	FrameError      FrameType = 11 // JSON ErrorPayload; channel 0 = connection-level
)

// String returns the spec name of the frame type, e.g. "OPEN_SHELL".
func (t FrameType) String() string {
	switch t {
	case FrameOpenShell:
		return "OPEN_SHELL"
	case FrameOpenExec:
		return "OPEN_EXEC"
	case FramePtyRequest:
		return "PTY_REQUEST"
	case FramePtyResize:
		return "PTY_RESIZE"
	case FrameStdin:
		return "STDIN"
	case FrameStdout:
		return "STDOUT"
	case FrameStderr:
		return "STDERR"
	case FrameExitStatus:
		return "EXIT_STATUS"
	case FrameEOF:
		return "EOF"
	case FrameClose:
		return "CLOSE"
	case FrameError:
		return "ERROR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// isValid reports whether t is a known version-1 frame type.
func (t FrameType) isValid() bool {
	return t >= FrameOpenShell && t <= FrameError
}

// Header is the 16-byte fixed frame header. All integers are encoded
// big-endian on the wire.
type Header struct {
	Version    uint8
	Type       FrameType
	Flags      uint16
	ChannelID  uint32
	RequestID  uint32
	PayloadLen uint32
}

// Frame is a decoded protocol frame: header plus exactly PayloadLen
// payload bytes.
type Frame struct {
	Header
	Payload []byte
}

// IsReply reports whether the REPLY flag is set.
func (f *Frame) IsReply() bool {
	return f.Flags&FlagReply != 0
}

// NewRequest builds a request frame (nonzero requestID, REPLY flag clear).
func NewRequest(t FrameType, channelID, requestID uint32, payload []byte) *Frame {
	return &Frame{
		Header: Header{
			Version:    ProtocolVersion,
			Type:       t,
			ChannelID:  channelID,
			RequestID:  requestID,
			PayloadLen: uint32(len(payload)),
		},
		Payload: payload,
	}
}

// NewReplyOK builds the successful reply to a request: same type, channel,
// and request id, REPLY flag set, payload {"ok":true}.
func NewReplyOK(t FrameType, channelID, requestID uint32) *Frame {
	return newReply(t, channelID, requestID, ReplyPayload{Ok: true})
}

// NewReplyErr builds the failed reply to a request: same type, channel,
// and request id, REPLY flag set, payload {"ok":false,"error":{...}}.
func NewReplyErr(t FrameType, channelID, requestID uint32, code, msg string) *Frame {
	return newReply(t, channelID, requestID, ReplyPayload{
		Ok:    false,
		Error: &ErrorPayload{Code: code, Message: msg},
	})
}

func newReply(t FrameType, channelID, requestID uint32, reply ReplyPayload) *Frame {
	payload, err := json.Marshal(reply)
	if err != nil {
		// ReplyPayload holds only a bool and strings; json.Marshal cannot fail.
		panic(fmt.Sprintf("sessionframe: marshal reply payload: %v", err))
	}
	return &Frame{
		Header: Header{
			Version:    ProtocolVersion,
			Type:       t,
			Flags:      FlagReply,
			ChannelID:  channelID,
			RequestID:  requestID,
			PayloadLen: uint32(len(payload)),
		},
		Payload: payload,
	}
}

// NewData builds a non-request frame (request_id 0), e.g. STDIN/STDOUT/
// STDERR bytes, EXIT_STATUS, EOF, CLOSE, or ERROR.
func NewData(t FrameType, channelID uint32, payload []byte) *Frame {
	return &Frame{
		Header: Header{
			Version:    ProtocolVersion,
			Type:       t,
			ChannelID:  channelID,
			PayloadLen: uint32(len(payload)),
		},
		Payload: payload,
	}
}
