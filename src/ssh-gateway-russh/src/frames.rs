//! Async frame I/O and the per-connection frame multiplexer.
//!
//! `boxlite-session-frame` is deliberately sync-only; this module adds thin
//! async read/write helpers over `tokio::io` reusing `FrameHeader::{encode,
//! decode}`, plus [`FrameMux`]: one writer task owning the write half (fed by
//! a bounded mpsc) and one reader task demultiplexing inbound frames by
//! `channel_id` into bounded per-channel queues and reply frames by
//! `request_id` into oneshot waiters.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use boxlite_session_frame::{
    ErrorPayload, Frame, FrameDecodeError, FrameHeader, FrameReadError, FrameType, ReplyPayload,
    CONTROL_CHANNEL_ID, HEADER_LEN, MAX_PAYLOAD,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

/// Depth of the single writer queue. Bounded so a stalled runner connection
/// back-pressures SSH callbacks instead of buffering unboundedly.
const WRITER_QUEUE_DEPTH: usize = 64;

/// Depth of each per-channel inbound queue. Bounded so one flooding channel
/// back-pressures the connection reader instead of buffering unboundedly.
const CHANNEL_QUEUE_DEPTH: usize = 64;

/// Reads one complete frame, validating the header. Mirrors the sync
/// `boxlite_session_frame::read_frame` semantics: EOF at a frame boundary is
/// `Io(UnexpectedEof)` (clean close), EOF mid-frame is `Decode(Truncated)`.
pub(crate) async fn read_frame_async<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Frame, FrameReadError> {
    let mut header_bytes = [0u8; HEADER_LEN];
    let got = read_until_full(reader, &mut header_bytes).await?;
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
    let got = read_until_full(reader, &mut payload).await?;
    if got < payload_len {
        return Err(FrameDecodeError::Truncated {
            needed: HEADER_LEN + payload_len,
            got: HEADER_LEN + got,
        }
        .into());
    }
    Ok(Frame { header, payload })
}

/// Writes one frame (header then payload). Rejects the same invalid frames
/// the sync codec rejects, so a bug cannot corrupt the stream for the peer.
pub(crate) async fn write_frame_async<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> std::io::Result<()> {
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
    writer.write_all(&frame.header.encode()).await?;
    writer.write_all(&frame.payload).await?;
    Ok(())
}

async fn read_until_full<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(filled)
}

/// The runner session stream is gone; the caller must fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MuxClosed;

impl std::fmt::Display for MuxClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("runner session stream is closed")
    }
}

impl std::error::Error for MuxClosed {}

enum WriterMsg {
    Frame(Frame),
    /// Flush-and-close request; used by the reader on fatal errors so the
    /// TCP connection closes deterministically right after the ERROR frame.
    Shutdown,
}

#[derive(Default)]
struct Routes {
    channels: HashMap<u32, mpsc::Sender<Frame>>,
    pending_replies: HashMap<u32, oneshot::Sender<ReplyPayload>>,
}

/// Frame multiplexer over one upgraded runner stream.
///
/// Owned by the SSH connection handler; dropping the last `Arc` drops the
/// writer queue, which makes the writer task shut down the stream, which in
/// turn ends the reader task.
pub(crate) struct FrameMux {
    writer_tx: mpsc::Sender<WriterMsg>,
    routes: Arc<Mutex<Routes>>,
    closed: Arc<AtomicBool>,
    next_request_id: AtomicU32,
}

impl std::fmt::Debug for FrameMux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameMux")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl FrameMux {
    /// Spawns the writer and reader tasks over `stream`.
    pub(crate) fn spawn<S>(stream: S) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_DEPTH);
        let routes = Arc::new(Mutex::new(Routes::default()));
        let closed = Arc::new(AtomicBool::new(false));

        tokio::spawn(write_loop(write_half, writer_rx));
        // The reader holds only a weak sender: it must be able to push a
        // fatal ERROR frame, but must not keep the writer alive once the SSH
        // side dropped the mux.
        tokio::spawn(read_loop(
            read_half,
            Arc::clone(&routes),
            Arc::clone(&closed),
            writer_tx.downgrade(),
        ));

        Arc::new(Self {
            writer_tx,
            routes,
            closed,
            next_request_id: AtomicU32::new(1),
        })
    }

    /// Registers a session channel and returns its bounded inbound queue.
    ///
    /// `closed` is checked under the same `routes` lock `read_loop`'s
    /// shutdown path uses to clear `routes`, not beforehand: reading it
    /// outside the lock left a window where a channel could be inserted
    /// *after* shutdown had already cleared the map, silently admitting a
    /// receiver that would never get data or be cleaned up until the whole
    /// mux (and thus the SSH connection) dropped. The mutex's lock/unlock
    /// pair provides the happens-before edge that makes this safe even
    /// though `closed` itself uses `Relaxed` ordering.
    pub(crate) fn register_channel(
        &self,
        channel_id: u32,
    ) -> Result<mpsc::Receiver<Frame>, MuxClosed> {
        let mut routes = self.routes.lock().expect("routes mutex poisoned");
        if self.closed.load(Ordering::Relaxed) {
            return Err(MuxClosed);
        }
        let (tx, rx) = mpsc::channel(CHANNEL_QUEUE_DEPTH);
        routes.channels.insert(channel_id, tx);
        Ok(rx)
    }

    /// Forgets a channel; late frames for it are then silently ignored.
    pub(crate) fn deregister_channel(&self, channel_id: u32) {
        self.routes
            .lock()
            .expect("routes mutex poisoned")
            .channels
            .remove(&channel_id);
    }

    /// Sends a non-request frame (STDIN/EOF/CLOSE) to the runner.
    pub(crate) async fn send(&self, frame: Frame) -> Result<(), MuxClosed> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(MuxClosed);
        }
        self.writer_tx
            .send(WriterMsg::Frame(frame))
            .await
            .map_err(|_| MuxClosed)
    }

    /// Sends a request frame and returns the reply waiter. The frame is
    /// enqueued before this returns, so callers issuing requests in order
    /// (e.g. PTY_REQUEST before OPEN_SHELL) get FIFO wire order.
    pub(crate) async fn begin_request(
        &self,
        frame_type: FrameType,
        channel_id: u32,
        payload: Vec<u8>,
    ) -> Result<oneshot::Receiver<ReplyPayload>, MuxClosed> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut routes = self.routes.lock().expect("routes mutex poisoned");
            routes.pending_replies.insert(request_id, tx);
        }
        let frame = Frame::request(frame_type, channel_id, request_id, payload);
        if self.send(frame).await.is_err() {
            self.routes
                .lock()
                .expect("routes mutex poisoned")
                .pending_replies
                .remove(&request_id);
            return Err(MuxClosed);
        }
        Ok(rx)
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut writer: W, mut rx: mpsc::Receiver<WriterMsg>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            WriterMsg::Frame(frame) => {
                if let Err(e) = write_frame_async(&mut writer, &frame).await {
                    warn!(error = %e, "runner stream write failed");
                    break;
                }
            }
            WriterMsg::Shutdown => break,
        }
    }
    let _ = writer.shutdown().await;
    debug!("runner stream writer closed");
}

/// Reader outcome: whether to send an ERROR frame on channel 0 before
/// closing (our fault detection) or just close (peer already errored/EOF'd).
enum ReadEnd {
    Clean,
    Fatal(ErrorPayload),
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    routes: Arc<Mutex<Routes>>,
    closed: Arc<AtomicBool>,
    writer: mpsc::WeakSender<WriterMsg>,
) {
    let end = loop {
        match read_frame_async(&mut reader).await {
            Ok(frame) => match route_frame(frame, &routes).await {
                RouteOutcome::Continue => {}
                RouteOutcome::PeerError => break ReadEnd::Clean,
            },
            Err(FrameReadError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof => {
                debug!("runner closed the session stream");
                break ReadEnd::Clean;
            }
            Err(FrameReadError::Io(e)) => {
                warn!(error = %e, "runner stream read failed");
                break ReadEnd::Clean;
            }
            Err(FrameReadError::Decode(e)) => {
                warn!(error = %e, "protocol error on runner stream; closing connection");
                break ReadEnd::Fatal(ErrorPayload {
                    code: "protocol_error".into(),
                    message: e.to_string(),
                });
            }
        }
    };

    closed.store(true, Ordering::Relaxed);
    if let Some(writer_tx) = writer.upgrade() {
        if let ReadEnd::Fatal(payload) = end {
            // Best effort per spec: ERROR on channel 0, then close.
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            let frame = Frame::data(FrameType::Error, CONTROL_CHANNEL_ID, bytes);
            let _ = writer_tx.send(WriterMsg::Frame(frame)).await;
        }
        let _ = writer_tx.send(WriterMsg::Shutdown).await;
    }

    // Dropping the per-channel senders ends every channel forwarder, which
    // closes the SSH channels; dropping pending reply senders fails every
    // in-flight request.
    let mut routes = routes.lock().expect("routes mutex poisoned");
    routes.channels.clear();
    routes.pending_replies.clear();
    debug!("runner stream reader closed");
}

enum RouteOutcome {
    Continue,
    /// Runner sent ERROR on channel 0: connection-level error, close now.
    PeerError,
}

async fn route_frame(frame: Frame, routes: &Mutex<Routes>) -> RouteOutcome {
    let header = frame.header;

    if header.is_reply() {
        if header.request_id == 0 {
            warn!("ignoring reply frame with request_id 0");
            return RouteOutcome::Continue;
        }
        let waiter = routes
            .lock()
            .expect("routes mutex poisoned")
            .pending_replies
            .remove(&header.request_id);
        let Some(waiter) = waiter else {
            debug!(request_id = header.request_id, "reply for unknown request");
            return RouteOutcome::Continue;
        };
        let payload = serde_json::from_slice(&frame.payload).unwrap_or_else(|e| ReplyPayload {
            ok: false,
            error: Some(ErrorPayload {
                code: "bad_reply".into(),
                message: format!("unparseable reply payload: {e}"),
            }),
        });
        let _ = waiter.send(payload);
        return RouteOutcome::Continue;
    }

    match header.frame_type {
        FrameType::Error if header.channel_id == CONTROL_CHANNEL_ID => {
            match serde_json::from_slice::<ErrorPayload>(&frame.payload) {
                Ok(e) => {
                    warn!(code = %e.code, message = %e.message, "runner reported a connection-level error")
                }
                Err(_) => warn!("runner reported an unparseable connection-level error"),
            }
            RouteOutcome::PeerError
        }
        FrameType::Stdout
        | FrameType::Stderr
        | FrameType::ExitStatus
        | FrameType::Eof
        | FrameType::Close
        | FrameType::Error => {
            let sender = routes
                .lock()
                .expect("routes mutex poisoned")
                .channels
                .get(&header.channel_id)
                .cloned();
            match sender {
                Some(sender) => {
                    if sender.send(frame).await.is_err() {
                        debug!(
                            channel = header.channel_id,
                            "dropping frame for a channel whose forwarder ended"
                        );
                    }
                }
                // The Runner may have STDOUT/STDERR/EXIT_STATUS in flight
                // when we CLOSE a channel; late frames are silently ignored
                // and are NOT protocol errors.
                None => debug!(
                    channel = header.channel_id,
                    frame_type = ?header.frame_type,
                    "ignoring frame for an unknown or closed channel"
                ),
            }
            RouteOutcome::Continue
        }
        other => {
            warn!(frame_type = ?other, "ignoring unexpected gateway-bound frame type");
            RouteOutcome::Continue
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boxlite_session_frame::PROTOCOL_VERSION;

    async fn round_trip(frame: &Frame) -> Frame {
        let (mut client, mut server) = tokio::io::duplex(MAX_PAYLOAD + HEADER_LEN);
        write_frame_async(&mut client, frame).await.expect("write");
        drop(client);
        read_frame_async(&mut server).await.expect("read")
    }

    #[tokio::test]
    async fn async_codec_round_trips_representative_frames() {
        let frames = [
            Frame::request(FrameType::OpenShell, 1, 1, b"{}".to_vec()),
            Frame::request(FrameType::OpenExec, 2, 2, br#"{"command":"true"}"#.to_vec()),
            Frame::reply_ok(FrameType::OpenExec, 2, 2),
            Frame::reply_err(FrameType::OpenShell, 1, 1, "denied", "nope"),
            Frame::data(FrameType::Stdin, 1, vec![0u8, 255, 128]),
            Frame::data(FrameType::Eof, 1, Vec::new()),
        ];
        for frame in &frames {
            assert_eq!(&round_trip(frame).await, frame);
        }
    }

    #[tokio::test]
    async fn async_codec_round_trips_max_payload_frame() {
        let frame = Frame::data(FrameType::Stdout, 9, vec![0xAB; MAX_PAYLOAD]);
        assert_eq!(round_trip(&frame).await, frame);
    }

    #[tokio::test]
    async fn async_codec_reads_back_to_back_frames() {
        let first = Frame::request(FrameType::OpenShell, 1, 1, b"{}".to_vec());
        let second = Frame::reply_ok(FrameType::OpenShell, 1, 1);
        let third = Frame::data(FrameType::Stdout, 1, b"hello".to_vec());

        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        for frame in [&first, &second, &third] {
            write_frame_async(&mut client, frame).await.expect("write");
        }
        drop(client);

        assert_eq!(read_frame_async(&mut server).await.unwrap(), first);
        assert_eq!(read_frame_async(&mut server).await.unwrap(), second);
        assert_eq!(read_frame_async(&mut server).await.unwrap(), third);
        match read_frame_async(&mut server).await {
            Err(FrameReadError::Io(e)) => assert_eq!(e.kind(), ErrorKind::UnexpectedEof),
            other => panic!("expected clean EOF, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn async_codec_rejects_bad_version_and_truncation() {
        let mut bytes = Vec::new();
        boxlite_session_frame::write_frame(
            &mut bytes,
            &Frame::data(FrameType::Stdout, 1, b"hi".to_vec()),
        )
        .expect("encode");
        assert_eq!(bytes[0], PROTOCOL_VERSION);

        let mut bad_version = bytes.clone();
        bad_version[0] = 9;
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&bad_version).await.unwrap();
        drop(client);
        match read_frame_async(&mut server).await {
            Err(FrameReadError::Decode(FrameDecodeError::UnsupportedVersion(9))) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }

        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&bytes[..HEADER_LEN + 1]).await.unwrap();
        drop(client);
        match read_frame_async(&mut server).await {
            Err(FrameReadError::Decode(FrameDecodeError::Truncated { .. })) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// Regression for the `register_channel`/shutdown race: races
    /// registration against a real stream close (driving the actual
    /// `read_loop` shutdown path, not a hand-rolled simulation of it) across
    /// many iterations. A channel that gets admitted around shutdown must
    /// still resolve (its sender dropped) instead of hanging forever;
    /// before the fix this occasionally timed out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn register_channel_never_hangs_when_raced_against_shutdown() {
        for _ in 0..200 {
            let (client, server) = tokio::io::duplex(64);
            let mux = FrameMux::spawn(server);
            let closer = tokio::spawn(async move {
                drop(client);
            });
            let result = mux.register_channel(1);
            closer.await.expect("closer task panicked");
            match result {
                Err(MuxClosed) => {} // correctly rejected
                Ok(mut rx) => {
                    tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
                        .await
                        .expect("a channel admitted around shutdown must still resolve, not hang");
                }
            }
        }
    }

    #[tokio::test]
    async fn async_writer_rejects_oversized_payload() {
        let frame = Frame::data(FrameType::Stdout, 1, vec![0u8; MAX_PAYLOAD + 1]);
        let mut sink = Vec::new();
        let err = write_frame_async(&mut sink, &frame)
            .await
            .expect_err("must reject");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}
