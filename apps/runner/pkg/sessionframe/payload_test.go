// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sessionframe

import (
	"encoding/json"
	"testing"
)

// TestPayloadWireJSON pins the exact JSON each payload type puts on the
// wire, so the Go and Rust codecs cannot silently drift on key names,
// key order, or omitted fields.
func TestPayloadWireJSON(t *testing.T) {
	tests := []struct {
		name    string
		payload any
		want    string
	}{
		{
			name:    "OpenExecPayload",
			payload: OpenExecPayload{Command: "ls -la"},
			want:    `{"command":"ls -la"}`,
		},
		{
			name:    "PtyRequestPayload",
			payload: PtyRequestPayload{Term: "xterm-256color", Cols: 80, Rows: 24, WidthPx: 640, HeightPx: 480},
			want:    `{"term":"xterm-256color","cols":80,"rows":24,"width_px":640,"height_px":480}`,
		},
		{
			name:    "PtyResizePayload",
			payload: PtyResizePayload{Cols: 120, Rows: 40, WidthPx: 0, HeightPx: 0},
			want:    `{"cols":120,"rows":40,"width_px":0,"height_px":0}`,
		},
		{
			name:    "ExitStatusPayload negative code",
			payload: ExitStatusPayload{Code: -1},
			want:    `{"code":-1}`,
		},
		{
			name:    "ErrorPayload",
			payload: ErrorPayload{Code: "protocol_error", Message: "unknown frame type"},
			want:    `{"code":"protocol_error","message":"unknown frame type"}`,
		},
		{
			name:    "ReplyPayload ok omits error",
			payload: ReplyPayload{Ok: true},
			want:    `{"ok":true}`,
		},
		{
			name:    "ReplyPayload error present iff not ok",
			payload: ReplyPayload{Ok: false, Error: &ErrorPayload{Code: "denied", Message: "no such user"}},
			want:    `{"ok":false,"error":{"code":"denied","message":"no such user"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("marshal mismatch\n got %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestPayloadRoundTrips(t *testing.T) {
	t.Run("OpenExecPayload", func(t *testing.T) {
		in := OpenExecPayload{Command: `sh -c "echo \"hi\""`}
		var out OpenExecPayload
		roundTrip(t, in, &out)
		if out != in {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("PtyRequestPayload", func(t *testing.T) {
		in := PtyRequestPayload{Term: "vt100", Cols: 1, Rows: 2, WidthPx: 3, HeightPx: 4}
		var out PtyRequestPayload
		roundTrip(t, in, &out)
		if out != in {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("PtyResizePayload", func(t *testing.T) {
		in := PtyResizePayload{Cols: 200, Rows: 50, WidthPx: 1600, HeightPx: 900}
		var out PtyResizePayload
		roundTrip(t, in, &out)
		if out != in {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("ExitStatusPayload", func(t *testing.T) {
		in := ExitStatusPayload{Code: 137}
		var out ExitStatusPayload
		roundTrip(t, in, &out)
		if out != in {
			t.Fatalf("round trip: got %+v, want %+v", out, in)
		}
	})
	t.Run("ReplyPayload with error", func(t *testing.T) {
		in := ReplyPayload{Ok: false, Error: &ErrorPayload{Code: "exec_failed", Message: "command not found"}}
		var out ReplyPayload
		roundTrip(t, in, &out)
		if out.Ok != in.Ok || out.Error == nil || *out.Error != *in.Error {
			t.Fatalf("round trip: got %+v (error %+v), want %+v (error %+v)", out, out.Error, in, in.Error)
		}
	})
}

// TestNewReplyErrPayload decodes a NewReplyErr frame payload back through
// ReplyPayload to prove the constructor and the type agree on the wire form.
func TestNewReplyErrPayload(t *testing.T) {
	f := NewReplyErr(FrameOpenExec, 4, 11, "exec_failed", "command not found")
	var reply ReplyPayload
	if err := json.Unmarshal(f.Payload, &reply); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", f.Payload, err)
	}
	if reply.Ok {
		t.Fatal("reply.Ok = true, want false")
	}
	if reply.Error == nil || reply.Error.Code != "exec_failed" || reply.Error.Message != "command not found" {
		t.Fatalf("reply.Error = %+v, want code=exec_failed message=command not found", reply.Error)
	}
}

func roundTrip(t *testing.T, in any, out any) {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal(%+v): %v", in, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("json.Unmarshal(%s): %v", b, err)
	}
}
