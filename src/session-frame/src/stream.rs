//! Blocking frame I/O over `std::io::Read`/`Write` byte streams.
//!
//! Kept sync and runtime-free on purpose; async wrappers live in the
//! gateway/runner, not in this codec crate.

use std::fmt;
use std::io::{ErrorKind, Read, Write};

use crate::frame::{Frame, FrameDecodeError, FrameHeader};
use crate::{HEADER_LEN, MAX_PAYLOAD};

/// Error returned by [`read_frame`].
///
/// A clean peer close (EOF before the first header byte of a frame) surfaces
/// as `Io` with [`ErrorKind::UnexpectedEof`]; EOF in the middle of a frame is
/// the protocol error `Decode(Truncated)`.
#[derive(Debug)]
pub enum FrameReadError {
    Io(std::io::Error),
    Decode(FrameDecodeError),
}

impl fmt::Display for FrameReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "frame read i/o error: {err}"),
            Self::Decode(err) => write!(f, "frame decode error: {err}"),
        }
    }
}

impl std::error::Error for FrameReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Decode(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for FrameReadError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<FrameDecodeError> for FrameReadError {
    fn from(err: FrameDecodeError) -> Self {
        Self::Decode(err)
    }
}

/// Reads one complete frame from `r`, validating the header.
///
/// Blocks until a full frame is available. Distinguishes stream end states:
/// - EOF before any header byte: `Io(UnexpectedEof)` — a clean connection close.
/// - EOF mid-header or mid-payload: `Decode(Truncated)` — a protocol error.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Frame, FrameReadError> {
    let mut header_bytes = [0u8; HEADER_LEN];
    let got = read_until_full(r, &mut header_bytes)?;
    if got == 0 {
        return Err(FrameReadError::Io(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "stream closed at frame boundary",
        )));
    }
    if got < HEADER_LEN {
        return Err(FrameDecodeError::Truncated {
            needed: HEADER_LEN,
            got,
        }
        .into());
    }
    let header = FrameHeader::decode(&header_bytes)?;

    let payload_len = header.payload_length as usize;
    let mut payload = vec![0u8; payload_len];
    let got = read_until_full(r, &mut payload)?;
    if got < payload_len {
        return Err(FrameDecodeError::Truncated {
            needed: HEADER_LEN + payload_len,
            got: HEADER_LEN + got,
        }
        .into());
    }
    Ok(Frame { header, payload })
}

/// Writes one frame (header then payload) to `w`. Does not flush.
///
/// Rejects with [`ErrorKind::InvalidInput`] a frame whose payload exceeds
/// [`MAX_PAYLOAD`] or whose header `payload_length` disagrees with the actual
/// payload size — both would corrupt the stream for the peer.
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> std::io::Result<()> {
    if frame.payload.len() > MAX_PAYLOAD {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes exceeds MAX_PAYLOAD {MAX_PAYLOAD}",
                frame.payload.len()
            ),
        ));
    }
    if frame.header.payload_length as usize != frame.payload.len() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "header payload_length {} does not match payload size {}",
                frame.header.payload_length,
                frame.payload.len()
            ),
        ));
    }
    w.write_all(&frame.header.encode())?;
    w.write_all(&frame.payload)?;
    Ok(())
}

/// Reads until `buf` is full or EOF; returns how many bytes were read.
/// Unlike `Read::read_exact` this lets the caller tell a clean EOF (0 bytes)
/// apart from a truncated frame (partial fill).
fn read_until_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::frame::FrameType;
    use crate::{FLAG_REPLY, PROTOCOL_VERSION};

    fn encode_to_vec(frame: &Frame) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, frame).expect("write_frame");
        bytes
    }

    #[test]
    fn round_trip_representative_frames() {
        let frames = [
            Frame::request(FrameType::OpenShell, 1, 1, b"{}".to_vec()),
            Frame::request(FrameType::OpenExec, 2, 2, br#"{"command":"true"}"#.to_vec()),
            Frame::request(
                FrameType::PtyRequest,
                3,
                4,
                br#"{"term":"xterm","cols":80,"rows":24,"width_px":0,"height_px":0}"#.to_vec(),
            ),
            Frame::reply_ok(FrameType::OpenExec, 2, 2),
            Frame::reply_err(FrameType::OpenShell, 1, 1, "denied", "nope"),
            Frame::data(FrameType::Stdin, 1, b"input\n".to_vec()),
            Frame::data(FrameType::Stdout, 1, vec![0u8, 255, 128]),
            Frame::data(FrameType::ExitStatus, 1, br#"{"code":0}"#.to_vec()),
            Frame::data(FrameType::Eof, 1, Vec::new()),
            Frame::data(FrameType::Close, 1, Vec::new()),
            Frame::data(
                FrameType::Error,
                0,
                br#"{"code":"x","message":"y"}"#.to_vec(),
            ),
        ];
        for frame in &frames {
            let bytes = encode_to_vec(frame);
            let decoded = read_frame(&mut Cursor::new(&bytes)).expect("read_frame");
            assert_eq!(&decoded, frame);
        }
    }

    #[test]
    fn round_trip_max_payload_frame() {
        let frame = Frame::data(FrameType::Stdout, 9, vec![0xAB; MAX_PAYLOAD]);
        let bytes = encode_to_vec(&frame);
        assert_eq!(bytes.len(), HEADER_LEN + MAX_PAYLOAD);
        let decoded = read_frame(&mut Cursor::new(&bytes)).expect("read_frame");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn reads_back_to_back_frames_from_one_stream() {
        let first = Frame::request(FrameType::OpenShell, 1, 1, b"{}".to_vec());
        let second = Frame::reply_ok(FrameType::OpenShell, 1, 1);
        let third = Frame::data(FrameType::Stdout, 1, b"hello".to_vec());

        let mut bytes = Vec::new();
        for frame in [&first, &second, &third] {
            write_frame(&mut bytes, frame).unwrap();
        }

        let mut cursor = Cursor::new(&bytes);
        assert_eq!(read_frame(&mut cursor).unwrap(), first);
        assert_eq!(read_frame(&mut cursor).unwrap(), second);
        assert_eq!(read_frame(&mut cursor).unwrap(), third);
        // Then a clean end-of-stream at the frame boundary.
        match read_frame(&mut cursor) {
            Err(FrameReadError::Io(err)) => assert_eq!(err.kind(), ErrorKind::UnexpectedEof),
            other => panic!("expected clean-EOF io error, got {other:?}"),
        }
    }

    #[test]
    fn clean_eof_on_empty_stream_is_io_error() {
        match read_frame(&mut Cursor::new(Vec::<u8>::new())) {
            Err(FrameReadError::Io(err)) => assert_eq!(err.kind(), ErrorKind::UnexpectedEof),
            other => panic!("expected io error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_header_is_decode_error() {
        let full = encode_to_vec(&Frame::data(FrameType::Stdout, 1, b"hi".to_vec()));
        for cut in [1usize, 8, 15] {
            match read_frame(&mut Cursor::new(&full[..cut])) {
                Err(FrameReadError::Decode(FrameDecodeError::Truncated { needed, got })) => {
                    assert_eq!(needed, HEADER_LEN);
                    assert_eq!(got, cut);
                }
                other => panic!("cut at {cut}: expected Truncated, got {other:?}"),
            }
        }
    }

    #[test]
    fn truncated_payload_is_decode_error() {
        let full = encode_to_vec(&Frame::data(FrameType::Stdout, 1, b"hello".to_vec()));
        let cut = HEADER_LEN + 2; // header complete, payload short by 3 bytes
        match read_frame(&mut Cursor::new(&full[..cut])) {
            Err(FrameReadError::Decode(FrameDecodeError::Truncated { needed, got })) => {
                assert_eq!(needed, HEADER_LEN + 5);
                assert_eq!(got, cut);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn read_frame_rejects_bad_version() {
        let mut bytes = encode_to_vec(&Frame::data(FrameType::Stdout, 1, Vec::new()));
        bytes[0] = 2;
        match read_frame(&mut Cursor::new(&bytes)) {
            Err(FrameReadError::Decode(FrameDecodeError::UnsupportedVersion(2))) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn read_frame_rejects_unknown_type() {
        let mut bytes = encode_to_vec(&Frame::data(FrameType::Stdout, 1, Vec::new()));
        bytes[1] = 42;
        match read_frame(&mut Cursor::new(&bytes)) {
            Err(FrameReadError::Decode(FrameDecodeError::UnknownType(42))) => {}
            other => panic!("expected UnknownType, got {other:?}"),
        }
    }

    #[test]
    fn read_frame_rejects_reserved_flags() {
        let mut bytes = encode_to_vec(&Frame::reply_ok(FrameType::OpenShell, 1, 1));
        bytes[2] = 0x80; // flags = 0x8001: REPLY plus a reserved bit
        match read_frame(&mut Cursor::new(&bytes)) {
            Err(FrameReadError::Decode(FrameDecodeError::ReservedFlags(0x8001))) => {}
            other => panic!("expected ReservedFlags, got {other:?}"),
        }
        assert_eq!(0x8000 | FLAG_REPLY, 0x8001);
    }

    #[test]
    fn read_frame_rejects_oversized_payload_length_without_reading_payload() {
        let oversized = (MAX_PAYLOAD as u32) + 1;
        let mut bytes = encode_to_vec(&Frame::data(FrameType::Stdout, 1, Vec::new()));
        bytes[12..16].copy_from_slice(&oversized.to_be_bytes());
        match read_frame(&mut Cursor::new(&bytes)) {
            Err(FrameReadError::Decode(FrameDecodeError::PayloadTooLarge(len))) => {
                assert_eq!(len, oversized);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn write_frame_rejects_oversized_payload() {
        let frame = Frame::data(FrameType::Stdout, 1, vec![0u8; MAX_PAYLOAD + 1]);
        let err = write_frame(&mut Vec::new(), &frame).expect_err("must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn write_frame_rejects_header_payload_length_mismatch() {
        let mut frame = Frame::data(FrameType::Stdout, 1, b"hi".to_vec());
        frame.header.payload_length = 3;
        let err = write_frame(&mut Vec::new(), &frame).expect_err("must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn write_frame_preserves_header_version_byte() {
        let frame = Frame::data(FrameType::Stdout, 1, Vec::new());
        let bytes = encode_to_vec(&frame);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
    }
}
