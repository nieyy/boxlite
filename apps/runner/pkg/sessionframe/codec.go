// Copyright 2025 BoxLite AI (originally Daytona Platforms Inc.
// Modified by BoxLite AI, 2025-2026
// SPDX-License-Identifier: AGPL-3.0

package sessionframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Decode failures that are protocol errors: per spec the receiver must send
// ERROR on channel 0 (best effort) and close the connection. All are wrapped
// with %w, so match them with errors.Is. Truncation surfaces as io.EOF (clean
// end at a frame boundary) or io.ErrUnexpectedEOF (mid-frame).
var (
	ErrUnsupportedVersion = errors.New("unsupported protocol version")
	ErrUnknownType        = errors.New("unknown frame type")
	ErrReservedFlags      = errors.New("reserved flag bits set")
	ErrPayloadTooLarge    = errors.New("payload too large")
)

// EncodeTo writes f to w as one header + payload unit. The wire
// payload_length is always len(f.Payload); f.Header.PayloadLen is ignored.
// Header and payload go out in a single Write so concurrent writers on a
// net.Conn cannot interleave partial frames.
func EncodeTo(w io.Writer, f *Frame) error {
	if len(f.Payload) > MaxPayload {
		return fmt.Errorf("sessionframe: encode %s frame: %w: %d bytes (max %d)",
			f.Type, ErrPayloadTooLarge, len(f.Payload), MaxPayload)
	}
	buf := make([]byte, HeaderLen+len(f.Payload))
	buf[0] = f.Version
	buf[1] = uint8(f.Type)
	binary.BigEndian.PutUint16(buf[2:4], f.Flags)
	binary.BigEndian.PutUint32(buf[4:8], f.ChannelID)
	binary.BigEndian.PutUint32(buf[8:12], f.RequestID)
	binary.BigEndian.PutUint32(buf[12:16], uint32(len(f.Payload)))
	copy(buf[HeaderLen:], f.Payload)
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("sessionframe: write %s frame: %w", f.Type, err)
	}
	return nil
}

// ReadFrame reads and validates one frame from r. The header is validated
// before the payload is allocated, so an oversized payload_length is
// rejected without allocating.
//
// io.EOF is returned untouched when the stream ends cleanly at a frame
// boundary; a truncated header or payload yields io.ErrUnexpectedEOF.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	h := Header{
		Version:    hdr[0],
		Type:       FrameType(hdr[1]),
		Flags:      binary.BigEndian.Uint16(hdr[2:4]),
		ChannelID:  binary.BigEndian.Uint32(hdr[4:8]),
		RequestID:  binary.BigEndian.Uint32(hdr[8:12]),
		PayloadLen: binary.BigEndian.Uint32(hdr[12:16]),
	}
	if h.Version != ProtocolVersion {
		return nil, fmt.Errorf("sessionframe: %w: got %d, want %d",
			ErrUnsupportedVersion, h.Version, ProtocolVersion)
	}
	if !h.Type.isValid() {
		return nil, fmt.Errorf("sessionframe: %w: %d", ErrUnknownType, uint8(h.Type))
	}
	if h.Flags&^FlagReply != 0 {
		return nil, fmt.Errorf("sessionframe: %w: flags %#04x", ErrReservedFlags, h.Flags)
	}
	if h.PayloadLen > MaxPayload {
		return nil, fmt.Errorf("sessionframe: %s frame: %w: %d bytes (max %d)",
			h.Type, ErrPayloadTooLarge, h.PayloadLen, MaxPayload)
	}
	f := &Frame{Header: h}
	if h.PayloadLen > 0 {
		f.Payload = make([]byte, h.PayloadLen)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			if err == io.EOF {
				// The header promised PayloadLen bytes; EOF here is mid-frame.
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	return f, nil
}
