//! Golden wire vectors from docs/architecture/ssh-session-frame-protocol.md.
//!
//! These bytes are shared with the parallel Go implementation: both codecs
//! must produce and accept them byte-for-byte. Do not regenerate them from
//! the Rust encoder — they are the contract, not its output.

use std::io::Cursor;

use boxlite_session_frame::{
    FLAG_REPLY, Frame, FrameType, PROTOCOL_VERSION, read_frame, write_frame,
};

/// V1: OPEN_SHELL request, channel 1, request 1, payload `{}`.
const V1_OPEN_SHELL: &[u8] = &[
    0x01, 0x01, 0x00, 0x00, // version=1, type=1 (OPEN_SHELL), flags=0
    0x00, 0x00, 0x00, 0x01, // channel_id=1
    0x00, 0x00, 0x00, 0x01, // request_id=1
    0x00, 0x00, 0x00, 0x02, // payload_length=2
    0x7b, 0x7d, // "{}"
];

/// V2: STDOUT, channel 3, request 0, payload "hi".
const V2_STDOUT: &[u8] = &[
    0x01, 0x06, 0x00, 0x00, // version=1, type=6 (STDOUT), flags=0
    0x00, 0x00, 0x00, 0x03, // channel_id=3
    0x00, 0x00, 0x00, 0x00, // request_id=0
    0x00, 0x00, 0x00, 0x02, // payload_length=2
    0x68, 0x69, // "hi"
];

/// V3: REPLY to PTY_REQUEST ok, channel 2, request 7, payload `{"ok":true}`.
const V3_PTY_REPLY_OK: &[u8] = &[
    0x01, 0x03, 0x00, 0x01, // version=1, type=3 (PTY_REQUEST), flags=REPLY
    0x00, 0x00, 0x00, 0x02, // channel_id=2
    0x00, 0x00, 0x00, 0x07, // request_id=7
    0x00, 0x00, 0x00, 0x0b, // payload_length=11
    0x7b, 0x22, 0x6f, 0x6b, 0x22, 0x3a, 0x74, 0x72, 0x75, 0x65, 0x7d, // {"ok":true}
];

fn encode_to_vec(frame: &Frame) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, frame).expect("write_frame");
    bytes
}

#[test]
fn v1_open_shell_encodes_to_golden_bytes() {
    let frame = Frame::request(FrameType::OpenShell, 1, 1, b"{}".to_vec());
    assert_eq!(encode_to_vec(&frame), V1_OPEN_SHELL);
}

#[test]
fn v1_open_shell_decodes_from_golden_bytes() {
    let frame = read_frame(&mut Cursor::new(V1_OPEN_SHELL)).expect("decode V1");
    assert_eq!(frame.header.version, PROTOCOL_VERSION);
    assert_eq!(frame.header.frame_type, FrameType::OpenShell);
    assert_eq!(frame.header.flags, 0);
    assert_eq!(frame.header.channel_id, 1);
    assert_eq!(frame.header.request_id, 1);
    assert_eq!(frame.header.payload_length, 2);
    assert_eq!(frame.payload, b"{}");
    assert!(!frame.is_reply());
    // Byte-for-byte identity through the full round trip.
    assert_eq!(encode_to_vec(&frame), V1_OPEN_SHELL);
}

#[test]
fn v2_stdout_encodes_to_golden_bytes() {
    let frame = Frame::data(FrameType::Stdout, 3, b"hi".to_vec());
    assert_eq!(encode_to_vec(&frame), V2_STDOUT);
}

#[test]
fn v2_stdout_decodes_from_golden_bytes() {
    let frame = read_frame(&mut Cursor::new(V2_STDOUT)).expect("decode V2");
    assert_eq!(frame.header.version, PROTOCOL_VERSION);
    assert_eq!(frame.header.frame_type, FrameType::Stdout);
    assert_eq!(frame.header.flags, 0);
    assert_eq!(frame.header.channel_id, 3);
    assert_eq!(frame.header.request_id, 0);
    assert_eq!(frame.header.payload_length, 2);
    assert_eq!(frame.payload, b"hi");
    assert_eq!(encode_to_vec(&frame), V2_STDOUT);
}

#[test]
fn v3_pty_reply_ok_encodes_to_golden_bytes() {
    let frame = Frame::reply_ok(FrameType::PtyRequest, 2, 7);
    assert_eq!(encode_to_vec(&frame), V3_PTY_REPLY_OK);
}

#[test]
fn v3_pty_reply_ok_decodes_from_golden_bytes() {
    let frame = read_frame(&mut Cursor::new(V3_PTY_REPLY_OK)).expect("decode V3");
    assert_eq!(frame.header.version, PROTOCOL_VERSION);
    assert_eq!(frame.header.frame_type, FrameType::PtyRequest);
    assert_eq!(frame.header.flags, FLAG_REPLY);
    assert!(frame.is_reply());
    assert_eq!(frame.header.channel_id, 2);
    assert_eq!(frame.header.request_id, 7);
    assert_eq!(frame.header.payload_length, 11);
    assert_eq!(frame.payload, br#"{"ok":true}"#);
    assert_eq!(encode_to_vec(&frame), V3_PTY_REPLY_OK);
}

#[test]
fn golden_vectors_read_back_to_back_from_one_stream() {
    let bytes: Vec<u8> = [V1_OPEN_SHELL, V2_STDOUT, V3_PTY_REPLY_OK].concat();
    let mut cursor = Cursor::new(&bytes);
    assert_eq!(
        read_frame(&mut cursor).unwrap().header.frame_type,
        FrameType::OpenShell
    );
    assert_eq!(
        read_frame(&mut cursor).unwrap().header.frame_type,
        FrameType::Stdout
    );
    assert_eq!(
        read_frame(&mut cursor).unwrap().header.frame_type,
        FrameType::PtyRequest
    );
    assert!(read_frame(&mut cursor).is_err(), "stream exhausted");
}
