//! Codec for the BoxLite session-frame protocol, version 1.
//!
//! This is the internal Gateway <-> Runner framing carried over a reliable
//! byte stream obtained via an HTTP/1.1 upgrade (`Upgrade: boxlite-session-stream`).
//! The normative wire specification lives in
//! `docs/architecture/ssh-session-frame-protocol.md`; a Go implementation is
//! maintained in parallel from the same spec, so the wire format defined here
//! must not change without a version bump.
//!
//! The crate is deliberately sync and dependency-light (serde + serde_json
//! only). Async wrappers belong to the consumers (gateway/runner), not here.

mod frame;
mod payload;
mod stream;

pub use frame::{Frame, FrameDecodeError, FrameHeader, FrameType};
pub use payload::{
    ErrorPayload, ExitStatusPayload, OpenExecPayload, PtyRequestPayload, PtyResizePayload,
    ReplyPayload,
};
pub use stream::{FrameReadError, read_frame, write_frame};

/// Wire protocol version carried in byte 0 of every frame header.
pub const PROTOCOL_VERSION: u8 = 1;

/// Fixed frame header size in bytes.
pub const HEADER_LEN: usize = 16;

/// Maximum payload size per frame: 256 KiB. `payload_length` above this is a
/// protocol error.
pub const MAX_PAYLOAD: usize = 262_144;

/// Channel 0 is reserved for connection-level control; only `ERROR` frames
/// use it. Session channels are nonzero, chosen by the Gateway, unique per
/// connection.
pub const CONTROL_CHANNEL_ID: u32 = 0;

/// Flags bit 0: set on reply frames, which echo the request's `type`,
/// `channel_id`, and `request_id`. All other flag bits are reserved and must
/// be zero.
pub const FLAG_REPLY: u16 = 0x0001;

/// Value of the `Upgrade` header in the HTTP/1.1 handshake.
pub const UPGRADE_PROTOCOL: &str = "boxlite-session-stream";

/// HTTP header carrying the session id on the upgrade request.
pub const HEADER_SESSION_ID: &str = "X-BoxLite-Session-ID";

/// HTTP header carrying the token id on the upgrade request.
pub const HEADER_TOKEN_ID: &str = "X-BoxLite-Token-ID";

/// HTTP header carrying the validated unix user on the upgrade request.
pub const HEADER_UNIX_USER: &str = "X-BoxLite-Unix-User";
