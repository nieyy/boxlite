// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sessionframe

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

// mustHex decodes a spaced hex string like "01 01 00 00".
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex fixture %q: %v", s, err)
	}
	return b
}

// goldenVectors are the normative version-1 test vectors shared with the
// Rust implementation. Both encode and decode must match byte-for-byte.
func goldenVectors(t *testing.T) []struct {
	name  string
	frame *Frame
	wire  []byte
} {
	t.Helper()
	return []struct {
		name  string
		frame *Frame
		wire  []byte
	}{
		{
			name:  "V1 OPEN_SHELL request ch1 req1",
			frame: NewRequest(FrameOpenShell, 1, 1, []byte("{}")),
			wire:  mustHex(t, "01 01 00 00 00 00 00 01 00 00 00 01 00 00 00 02 7b 7d"),
		},
		{
			name:  "V2 STDOUT ch3 payload hi",
			frame: NewData(FrameStdout, 3, []byte("hi")),
			wire:  mustHex(t, "01 06 00 00 00 00 00 03 00 00 00 00 00 00 00 02 68 69"),
		},
		{
			name:  "V3 REPLY PTY_REQUEST ok ch2 req7",
			frame: NewReplyOK(FramePtyRequest, 2, 7),
			wire:  mustHex(t, "01 03 00 01 00 00 00 02 00 00 00 07 00 00 00 0b 7b 22 6f 6b 22 3a 74 72 75 65 7d"),
		},
	}
}

func TestGoldenVectorsEncode(t *testing.T) {
	for _, v := range goldenVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := EncodeTo(&buf, v.frame); err != nil {
				t.Fatalf("EncodeTo: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), v.wire) {
				t.Fatalf("encoded bytes mismatch\n got %x\nwant %x", buf.Bytes(), v.wire)
			}
		})
	}
}

func TestGoldenVectorsDecode(t *testing.T) {
	for _, v := range goldenVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			got, err := ReadFrame(bytes.NewReader(v.wire))
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if got.Header != v.frame.Header {
				t.Fatalf("header mismatch\n got %+v\nwant %+v", got.Header, v.frame.Header)
			}
			if !bytes.Equal(got.Payload, v.frame.Payload) {
				t.Fatalf("payload mismatch\n got %q\nwant %q", got.Payload, v.frame.Payload)
			}
		})
	}
}

func TestNewReplyOKPayloadBytes(t *testing.T) {
	f := NewReplyOK(FramePtyRequest, 2, 7)
	want := []byte(`{"ok":true}`)
	if !bytes.Equal(f.Payload, want) {
		t.Fatalf("NewReplyOK payload = %q, want %q", f.Payload, want)
	}
	if !f.IsReply() {
		t.Fatal("NewReplyOK frame: IsReply() = false, want true")
	}
}

func TestRoundTrip(t *testing.T) {
	frames := []*Frame{
		NewRequest(FrameOpenExec, 5, 9, []byte(`{"command":"ls -la"}`)),
		NewRequest(FramePtyResize, 5, 10, []byte(`{"cols":120,"rows":40,"width_px":0,"height_px":0}`)),
		NewData(FrameStdin, 5, []byte("echo hello\n")),
		NewData(FrameStderr, 5, []byte{0x00, 0xff, 0x7f}),
		NewData(FrameExitStatus, 5, []byte(`{"code":-1}`)),
		NewData(FrameEOF, 5, nil),
		NewData(FrameClose, 5, nil),
		NewData(FrameError, ControlChannelID, []byte(`{"code":"protocol_error","message":"boom"}`)),
		NewReplyErr(FrameOpenShell, 8, 3, "denied", "no such user"),
		NewData(FrameStdout, 6, bytes.Repeat([]byte{0xab}, MaxPayload)),
	}
	for _, f := range frames {
		t.Run(f.Type.String(), func(t *testing.T) {
			var buf bytes.Buffer
			if err := EncodeTo(&buf, f); err != nil {
				t.Fatalf("EncodeTo: %v", err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if got.Header != f.Header {
				t.Fatalf("header mismatch\n got %+v\nwant %+v", got.Header, f.Header)
			}
			if !bytes.Equal(got.Payload, f.Payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d bytes", len(got.Payload), len(f.Payload))
			}
		})
	}
}

func TestBackToBackFrames(t *testing.T) {
	var buf bytes.Buffer
	want := goldenVectors(t)
	for _, v := range want {
		if err := EncodeTo(&buf, v.frame); err != nil {
			t.Fatalf("EncodeTo %s: %v", v.name, err)
		}
	}
	for _, v := range want {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame %s: %v", v.name, err)
		}
		if got.Header != v.frame.Header || !bytes.Equal(got.Payload, v.frame.Payload) {
			t.Fatalf("frame %s mismatch: got %+v payload %q", v.name, got.Header, got.Payload)
		}
	}
	if _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("ReadFrame at clean stream end: err = %v, want io.EOF", err)
	}
}

// header builds a raw 16-byte header for decode-error tests.
func header(version uint8, frameType uint8, flags uint16, channelID, requestID, payloadLen uint32) []byte {
	b := make([]byte, HeaderLen)
	b[0] = version
	b[1] = frameType
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint32(b[4:8], channelID)
	binary.BigEndian.PutUint32(b[8:12], requestID)
	binary.BigEndian.PutUint32(b[12:16], payloadLen)
	return b
}

func TestReadFrameErrors(t *testing.T) {
	valid := header(1, uint8(FrameEOF), 0, 1, 0, 0)
	tests := []struct {
		name string
		wire []byte
		want error
	}{
		{"bad version 0", header(0, uint8(FrameOpenShell), 0, 1, 1, 0), ErrUnsupportedVersion},
		{"bad version 2", header(2, uint8(FrameOpenShell), 0, 1, 1, 0), ErrUnsupportedVersion},
		{"unknown type 0", header(1, 0, 0, 1, 1, 0), ErrUnknownType},
		{"unknown type 12", header(1, 12, 0, 1, 1, 0), ErrUnknownType},
		{"unknown type 255", header(1, 255, 0, 1, 1, 0), ErrUnknownType},
		{"reserved flag 0x0002", header(1, uint8(FrameOpenShell), 0x0002, 1, 1, 0), ErrReservedFlags},
		{"reserved flag 0x8001", header(1, uint8(FrameOpenShell), 0x8001, 1, 1, 0), ErrReservedFlags},
		{"payload over max", header(1, uint8(FrameStdout), 0, 1, 0, MaxPayload+1), ErrPayloadTooLarge},
		{"empty stream", nil, io.EOF},
		{"truncated header", valid[:8], io.ErrUnexpectedEOF},
		{"truncated header one byte short", valid[:HeaderLen-1], io.ErrUnexpectedEOF},
		{"payload fully missing", header(1, uint8(FrameStdout), 0, 1, 0, 4), io.ErrUnexpectedEOF},
		{"payload partially missing", append(header(1, uint8(FrameStdout), 0, 1, 0, 4), 'h', 'i'), io.ErrUnexpectedEOF},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ReadFrame(bytes.NewReader(tc.wire))
			if f != nil {
				t.Fatalf("ReadFrame returned frame %+v, want nil", f)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("ReadFrame err = %v, want errors.Is(err, %v)", err, tc.want)
			}
		})
	}
}

func TestReadFrameRejectsOversizedBeforeAllocation(t *testing.T) {
	// Header advertises 4 GiB-ish payload but the stream has no payload
	// bytes at all: validation must fail on the header alone.
	wire := header(1, uint8(FrameStdout), 0, 1, 0, 0xffffffff)
	_, err := ReadFrame(bytes.NewReader(wire))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("ReadFrame err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestEncodeToRejectsOversizedPayload(t *testing.T) {
	f := NewData(FrameStdout, 1, make([]byte, MaxPayload+1))
	err := EncodeTo(io.Discard, f)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("EncodeTo err = %v, want ErrPayloadTooLarge", err)
	}
}

func TestIsReply(t *testing.T) {
	if NewRequest(FrameOpenShell, 1, 1, []byte("{}")).IsReply() {
		t.Fatal("request frame: IsReply() = true, want false")
	}
	if !NewReplyErr(FrameOpenShell, 1, 1, "x", "y").IsReply() {
		t.Fatal("reply frame: IsReply() = false, want true")
	}
}

func TestFrameTypeString(t *testing.T) {
	tests := map[FrameType]string{
		FrameOpenShell:  "OPEN_SHELL",
		FrameOpenExec:   "OPEN_EXEC",
		FramePtyRequest: "PTY_REQUEST",
		FramePtyResize:  "PTY_RESIZE",
		FrameStdin:      "STDIN",
		FrameStdout:     "STDOUT",
		FrameStderr:     "STDERR",
		FrameExitStatus: "EXIT_STATUS",
		FrameEOF:        "EOF",
		FrameClose:      "CLOSE",
		FrameError:      "ERROR",
		FrameType(42):   "UNKNOWN(42)",
	}
	for ft, want := range tests {
		if got := ft.String(); got != want {
			t.Errorf("FrameType(%d).String() = %q, want %q", uint8(ft), got, want)
		}
	}
}
