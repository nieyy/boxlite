//! Serde structs for the JSON frame payloads defined by the spec.
//!
//! `OPEN_SHELL` has no struct: its payload is the empty object `{}`, reserved
//! for future fields.

use serde::{Deserialize, Serialize};

/// `OPEN_EXEC` request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenExecPayload {
    pub command: String,
}

/// `PTY_REQUEST` request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyRequestPayload {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

/// `PTY_RESIZE` request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyResizePayload {
    pub cols: u32,
    pub rows: u32,
    pub width_px: u32,
    pub height_px: u32,
}

/// `EXIT_STATUS` payload, runner -> gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatusPayload {
    pub code: i32,
}

/// `ERROR` payload; also embedded in failed replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

/// Reply payload: `{"ok": bool, "error": {...}?}` where `error` is present
/// iff `ok` is false.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyPayload {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(value: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn open_exec_round_trip_and_wire_shape() {
        let payload = OpenExecPayload {
            command: "ls -la /".to_string(),
        };
        assert_eq!(round_trip(&payload), payload);
        // Field name is part of the wire contract shared with the Go codec.
        let parsed: OpenExecPayload = serde_json::from_str(r#"{"command":"echo hi"}"#).unwrap();
        assert_eq!(parsed.command, "echo hi");
    }

    #[test]
    fn pty_request_round_trip_and_wire_shape() {
        let payload = PtyRequestPayload {
            term: "xterm-256color".to_string(),
            cols: 120,
            rows: 40,
            width_px: 1920,
            height_px: 1080,
        };
        assert_eq!(round_trip(&payload), payload);
        let parsed: PtyRequestPayload = serde_json::from_str(
            r#"{"term":"vt100","cols":80,"rows":24,"width_px":0,"height_px":0}"#,
        )
        .unwrap();
        assert_eq!(parsed.term, "vt100");
        assert_eq!((parsed.cols, parsed.rows), (80, 24));
    }

    #[test]
    fn pty_resize_round_trip() {
        let payload = PtyResizePayload {
            cols: 80,
            rows: 24,
            width_px: 640,
            height_px: 480,
        };
        assert_eq!(round_trip(&payload), payload);
    }

    #[test]
    fn exit_status_round_trip_including_negative_code() {
        for code in [0i32, 1, 127, -1] {
            let payload = ExitStatusPayload { code };
            assert_eq!(round_trip(&payload), payload);
        }
        let parsed: ExitStatusPayload = serde_json::from_str(r#"{"code":-9}"#).unwrap();
        assert_eq!(parsed.code, -9);
    }

    #[test]
    fn error_payload_round_trip() {
        let payload = ErrorPayload {
            code: "protocol_error".to_string(),
            message: "bad frame".to_string(),
        };
        assert_eq!(round_trip(&payload), payload);
    }

    #[test]
    fn reply_ok_serializes_without_error_field() {
        let payload = ReplyPayload {
            ok: true,
            error: None,
        };
        assert_eq!(serde_json::to_string(&payload).unwrap(), r#"{"ok":true}"#);
        assert_eq!(round_trip(&payload), payload);
    }

    #[test]
    fn reply_err_serializes_with_error_object() {
        let payload = ReplyPayload {
            ok: false,
            error: Some(ErrorPayload {
                code: "denied".to_string(),
                message: "no".to_string(),
            }),
        };
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            r#"{"ok":false,"error":{"code":"denied","message":"no"}}"#
        );
        assert_eq!(round_trip(&payload), payload);
    }

    #[test]
    fn reply_without_error_field_deserializes_to_none() {
        let parsed: ReplyPayload = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert_eq!(
            parsed,
            ReplyPayload {
                ok: true,
                error: None
            }
        );
    }
}
