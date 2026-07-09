//! Frame header and frame types for the session-frame protocol (version 1).

use std::fmt;

use crate::payload::{ErrorPayload, ReplyPayload};
use crate::{FLAG_REPLY, HEADER_LEN, MAX_PAYLOAD, PROTOCOL_VERSION};

/// Frame type, byte 1 of the header.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// Request; JSON payload `{}` (reserved for future fields).
    OpenShell = 1,
    /// Request; JSON payload [`crate::OpenExecPayload`].
    OpenExec = 2,
    /// Request; JSON payload [`crate::PtyRequestPayload`].
    PtyRequest = 3,
    /// Request; JSON payload [`crate::PtyResizePayload`].
    PtyResize = 4,
    /// Raw bytes, gateway -> runner.
    Stdin = 5,
    /// Raw bytes, runner -> gateway.
    Stdout = 6,
    /// Raw bytes, runner -> gateway.
    Stderr = 7,
    /// JSON payload [`crate::ExitStatusPayload`], runner -> gateway.
    ExitStatus = 8,
    /// Empty payload; half-close of the sender's data direction on the channel.
    Eof = 9,
    /// Empty payload; full channel teardown.
    Close = 10,
    /// JSON payload [`crate::ErrorPayload`]. On channel 0 it is a
    /// connection-level protocol error and the connection must be closed
    /// after sending.
    Error = 11,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameDecodeError;

    fn try_from(value: u8) -> Result<Self, FrameDecodeError> {
        match value {
            1 => Ok(Self::OpenShell),
            2 => Ok(Self::OpenExec),
            3 => Ok(Self::PtyRequest),
            4 => Ok(Self::PtyResize),
            5 => Ok(Self::Stdin),
            6 => Ok(Self::Stdout),
            7 => Ok(Self::Stderr),
            8 => Ok(Self::ExitStatus),
            9 => Ok(Self::Eof),
            10 => Ok(Self::Close),
            11 => Ok(Self::Error),
            unknown => Err(FrameDecodeError::UnknownType(unknown)),
        }
    }
}

/// Typed error for header/frame decoding. Every variant is a protocol error:
/// per the spec the receiver must send `ERROR` on channel 0 (best effort) and
/// close the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameDecodeError {
    /// Header byte 0 is not [`PROTOCOL_VERSION`].
    UnsupportedVersion(u8),
    /// Header byte 1 is not a known [`FrameType`].
    UnknownType(u8),
    /// A reserved flag bit (anything other than [`FLAG_REPLY`]) is set.
    ReservedFlags(u16),
    /// `payload_length` exceeds [`MAX_PAYLOAD`].
    PayloadTooLarge(u32),
    /// The input ended before a complete header or payload was available.
    Truncated { needed: usize, got: usize },
}

impl fmt::Display for FrameDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported protocol version {version} (expected {PROTOCOL_VERSION})"
                )
            }
            Self::UnknownType(frame_type) => write!(f, "unknown frame type {frame_type}"),
            Self::ReservedFlags(flags) => {
                write!(
                    f,
                    "reserved flag bits set in {flags:#06x} (only {FLAG_REPLY:#06x} is defined)"
                )
            }
            Self::PayloadTooLarge(len) => {
                write!(f, "payload_length {len} exceeds MAX_PAYLOAD {MAX_PAYLOAD}")
            }
            Self::Truncated { needed, got } => {
                write!(f, "truncated frame: needed {needed} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for FrameDecodeError {}

/// Fixed 16-byte frame header. All integers are big-endian on the wire.
///
/// | offset | size | field            |
/// |--------|------|------------------|
/// | 0      | 1    | `version`        |
/// | 1      | 1    | `frame_type`     |
/// | 2      | 2    | `flags`          |
/// | 4      | 4    | `channel_id`     |
/// | 8      | 4    | `request_id`     |
/// | 12     | 4    | `payload_length` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: u16,
    pub channel_id: u32,
    /// 0 means "not a request"; nonzero on request frames and echoed on the
    /// matching reply.
    pub request_id: u32,
    pub payload_length: u32,
}

impl FrameHeader {
    /// Encodes the header into its 16-byte wire form.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0] = self.version;
        bytes[1] = self.frame_type as u8;
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.channel_id.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.request_id.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes
    }

    /// Decodes and validates a header from the first [`HEADER_LEN`] bytes of
    /// `bytes`.
    ///
    /// Validation order (fixed so all implementations report the same error
    /// for multi-fault headers): length, version, type, flags, payload_length.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameDecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameDecodeError::Truncated {
                needed: HEADER_LEN,
                got: bytes.len(),
            });
        }
        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(FrameDecodeError::UnsupportedVersion(version));
        }
        let frame_type = FrameType::try_from(bytes[1])?;
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        if flags & !FLAG_REPLY != 0 {
            return Err(FrameDecodeError::ReservedFlags(flags));
        }
        let channel_id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let request_id = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let payload_length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if payload_length as usize > MAX_PAYLOAD {
            return Err(FrameDecodeError::PayloadTooLarge(payload_length));
        }
        Ok(Self {
            version,
            frame_type,
            flags,
            channel_id,
            request_id,
            payload_length,
        })
    }

    /// True when the [`FLAG_REPLY`] bit is set.
    pub fn is_reply(&self) -> bool {
        self.flags & FLAG_REPLY != 0
    }
}

/// A complete frame: header plus exactly `payload_length` payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    fn new(
        frame_type: FrameType,
        flags: u16,
        channel_id: u32,
        request_id: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                frame_type,
                flags,
                channel_id,
                request_id,
                payload_length: payload.len() as u32,
            },
            payload,
        }
    }

    /// Builds a request frame (`request_id` must be nonzero per the spec).
    pub fn request(
        frame_type: FrameType,
        channel_id: u32,
        request_id: u32,
        payload: Vec<u8>,
    ) -> Self {
        Self::new(frame_type, 0, channel_id, request_id, payload)
    }

    /// Builds a successful reply to a request: same type, [`FLAG_REPLY`] set,
    /// same channel and request id, payload `{"ok":true}`.
    pub fn reply_ok(frame_type: FrameType, channel_id: u32, request_id: u32) -> Self {
        let payload = ReplyPayload {
            ok: true,
            error: None,
        };
        Self::reply(frame_type, channel_id, request_id, &payload)
    }

    /// Builds a failed reply to a request: `{"ok":false,"error":{...}}`.
    pub fn reply_err(
        frame_type: FrameType,
        channel_id: u32,
        request_id: u32,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let payload = ReplyPayload {
            ok: false,
            error: Some(ErrorPayload {
                code: code.into(),
                message: message.into(),
            }),
        };
        Self::reply(frame_type, channel_id, request_id, &payload)
    }

    fn reply(
        frame_type: FrameType,
        channel_id: u32,
        request_id: u32,
        payload: &ReplyPayload,
    ) -> Self {
        let bytes = serde_json::to_vec(payload)
            .expect("ReplyPayload serialization is infallible (plain strings and bool)");
        Self::new(frame_type, FLAG_REPLY, channel_id, request_id, bytes)
    }

    /// Builds a non-request data frame (`request_id` = 0), e.g. STDIN/STDOUT/
    /// STDERR raw bytes, EOF, CLOSE.
    pub fn data(frame_type: FrameType, channel_id: u32, payload: Vec<u8>) -> Self {
        Self::new(frame_type, 0, channel_id, 0, payload)
    }

    /// True when the [`FLAG_REPLY`] bit is set.
    pub fn is_reply(&self) -> bool {
        self.header.is_reply()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_round_trips_all_known_values() {
        for (value, expected) in [
            (1u8, FrameType::OpenShell),
            (2, FrameType::OpenExec),
            (3, FrameType::PtyRequest),
            (4, FrameType::PtyResize),
            (5, FrameType::Stdin),
            (6, FrameType::Stdout),
            (7, FrameType::Stderr),
            (8, FrameType::ExitStatus),
            (9, FrameType::Eof),
            (10, FrameType::Close),
            (11, FrameType::Error),
        ] {
            assert_eq!(FrameType::try_from(value), Ok(expected));
            assert_eq!(expected as u8, value);
        }
    }

    #[test]
    fn frame_type_rejects_unknown_values() {
        for value in [0u8, 12, 42, 255] {
            assert_eq!(
                FrameType::try_from(value),
                Err(FrameDecodeError::UnknownType(value))
            );
        }
    }

    #[test]
    fn header_encode_decode_round_trip() {
        let header = FrameHeader {
            version: PROTOCOL_VERSION,
            frame_type: FrameType::PtyResize,
            flags: FLAG_REPLY,
            channel_id: 0xDEAD_BEEF,
            request_id: 0x0102_0304,
            payload_length: MAX_PAYLOAD as u32,
        };
        assert_eq!(FrameHeader::decode(&header.encode()), Ok(header));
    }

    #[test]
    fn header_decode_rejects_unsupported_version() {
        for version in [0u8, 2, 255] {
            let mut bytes = Frame::data(FrameType::Stdin, 1, Vec::new()).header.encode();
            bytes[0] = version;
            assert_eq!(
                FrameHeader::decode(&bytes),
                Err(FrameDecodeError::UnsupportedVersion(version))
            );
        }
    }

    #[test]
    fn header_decode_rejects_unknown_type() {
        let mut bytes = Frame::data(FrameType::Stdin, 1, Vec::new()).header.encode();
        bytes[1] = 0;
        assert_eq!(
            FrameHeader::decode(&bytes),
            Err(FrameDecodeError::UnknownType(0))
        );
        bytes[1] = 12;
        assert_eq!(
            FrameHeader::decode(&bytes),
            Err(FrameDecodeError::UnknownType(12))
        );
    }

    #[test]
    fn header_decode_rejects_reserved_flags() {
        // Any bit other than 0x0001 is reserved, with or without REPLY set.
        for flags in [0x0002u16, 0x8000, 0x8001, 0xFFFF] {
            let mut bytes = Frame::data(FrameType::Stdin, 1, Vec::new()).header.encode();
            bytes[2..4].copy_from_slice(&flags.to_be_bytes());
            assert_eq!(
                FrameHeader::decode(&bytes),
                Err(FrameDecodeError::ReservedFlags(flags))
            );
        }
    }

    #[test]
    fn header_decode_rejects_oversized_payload_length() {
        let oversized = (MAX_PAYLOAD as u32) + 1;
        let mut bytes = Frame::data(FrameType::Stdin, 1, Vec::new()).header.encode();
        bytes[12..16].copy_from_slice(&oversized.to_be_bytes());
        assert_eq!(
            FrameHeader::decode(&bytes),
            Err(FrameDecodeError::PayloadTooLarge(oversized))
        );
    }

    #[test]
    fn header_decode_accepts_payload_length_at_max() {
        let mut bytes = Frame::data(FrameType::Stdin, 1, Vec::new()).header.encode();
        bytes[12..16].copy_from_slice(&(MAX_PAYLOAD as u32).to_be_bytes());
        let header = FrameHeader::decode(&bytes).expect("MAX_PAYLOAD exactly is legal");
        assert_eq!(header.payload_length as usize, MAX_PAYLOAD);
    }

    #[test]
    fn header_decode_rejects_truncated_header() {
        for len in [0usize, 1, 15] {
            let bytes = vec![PROTOCOL_VERSION; len];
            assert_eq!(
                FrameHeader::decode(&bytes),
                Err(FrameDecodeError::Truncated {
                    needed: HEADER_LEN,
                    got: len
                })
            );
        }
    }

    #[test]
    fn request_sets_fields_and_is_not_reply() {
        let frame = Frame::request(FrameType::OpenExec, 5, 9, b"{\"command\":\"ls\"}".to_vec());
        assert_eq!(frame.header.version, PROTOCOL_VERSION);
        assert_eq!(frame.header.frame_type, FrameType::OpenExec);
        assert_eq!(frame.header.flags, 0);
        assert_eq!(frame.header.channel_id, 5);
        assert_eq!(frame.header.request_id, 9);
        assert_eq!(frame.header.payload_length as usize, frame.payload.len());
        assert!(!frame.is_reply());
    }

    #[test]
    fn reply_ok_produces_exact_ok_json() {
        let frame = Frame::reply_ok(FrameType::OpenShell, 4, 8);
        assert!(frame.is_reply());
        assert_eq!(frame.header.flags, FLAG_REPLY);
        assert_eq!(frame.header.channel_id, 4);
        assert_eq!(frame.header.request_id, 8);
        assert_eq!(frame.payload, br#"{"ok":true}"#);
    }

    #[test]
    fn reply_err_carries_error_object() {
        let frame = Frame::reply_err(FrameType::PtyRequest, 2, 3, "no_pty", "pty unavailable");
        assert!(frame.is_reply());
        let payload: ReplyPayload = serde_json::from_slice(&frame.payload).unwrap();
        assert!(!payload.ok);
        let error = payload.error.expect("error present iff ok=false");
        assert_eq!(error.code, "no_pty");
        assert_eq!(error.message, "pty unavailable");
    }

    #[test]
    fn data_uses_request_id_zero() {
        let frame = Frame::data(FrameType::Stderr, 7, b"oops".to_vec());
        assert_eq!(frame.header.request_id, 0);
        assert_eq!(frame.header.flags, 0);
        assert_eq!(frame.header.payload_length, 4);
        assert!(!frame.is_reply());
    }

    #[test]
    fn decode_error_display_is_informative() {
        let message = FrameDecodeError::PayloadTooLarge(300_000).to_string();
        assert!(message.contains("300000"), "{message}");
        assert!(message.contains("262144"), "{message}");
    }
}
