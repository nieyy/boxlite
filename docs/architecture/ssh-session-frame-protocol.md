# SSH Session-Frame Protocol (version 1)

This document is the **normative** specification of the BoxLite session-frame protocol: the
internal framing the Gateway and the Runner speak over a single connection after an HTTP/1.1
upgrade. It multiplexes interactive SSH sessions (shells, execs, PTYs) between the two services.

Two implementations are maintained from this spec and must stay byte-compatible:

- Rust: [`boxlite-session-frame`](../../src/session-frame) (used by the Gateway/Runner Rust code)
- Go: the Runner-side codec (developed in parallel from this same document)

The [golden test vectors](#golden-test-vectors) below are the shared conformance contract; both
codecs must encode and decode them byte-for-byte.

## Transport and Upgrade Handshake

The protocol runs over a reliable byte stream obtained via an HTTP/1.1 upgrade:

```http
POST /internal/ssh/sessions/{boxId}/stream HTTP/1.1
Authorization: Bearer <internal-service-token>
X-BoxLite-Session-ID: <session-id>
X-BoxLite-Token-ID: <token-id>
X-BoxLite-Unix-User: <validated unix user, e.g. root>
Upgrade: boxlite-session-stream
Connection: Upgrade
```

The server answers `101 Switching Protocols`; from that point on the connection carries frames in
both directions. Authentication and user validation happen entirely at the HTTP layer — the frame
layer trusts the upgraded connection.

## Frame Layout

A frame is a fixed 16-byte header followed by exactly `payload_length` payload bytes. All
multi-byte integers are **big-endian** (network byte order).

| Offset | Size | Field            | Rules                                                                                                       |
|--------|------|------------------|-------------------------------------------------------------------------------------------------------------|
| 0      | 1    | `version`        | MUST be `1`                                                                                                   |
| 1      | 1    | `type`           | See [frame types](#frame-types)                                                                               |
| 2      | 2    | `flags`          | Bit `0x0001` = REPLY; all other bits are reserved and MUST be `0`                                             |
| 4      | 4    | `channel_id`     | `0` is reserved for connection-level control (only ERROR uses it); session channels are nonzero, chosen by the Gateway, unique per connection |
| 8      | 4    | `request_id`     | `0` = not a request; nonzero on request frames and echoed on the matching REPLY                               |
| 12     | 4    | `payload_length` | MUST be `<= MAX_PAYLOAD = 262144` (256 KiB)                                                                   |

## Frame Types

| Value | Name          | Direction         | Payload                                                                          |
|-------|---------------|-------------------|----------------------------------------------------------------------------------|
| 1     | `OPEN_SHELL`  | gateway → runner  | Request; JSON `{}` (reserved for future fields)                                   |
| 2     | `OPEN_EXEC`   | gateway → runner  | Request; JSON `{"command": string}`                                               |
| 3     | `PTY_REQUEST` | gateway → runner  | Request; JSON `{"term": string, "cols": u32, "rows": u32, "width_px": u32, "height_px": u32}` |
| 4     | `PTY_RESIZE`  | gateway → runner  | Request; JSON `{"cols": u32, "rows": u32, "width_px": u32, "height_px": u32}`     |
| 5     | `STDIN`       | gateway → runner  | Raw bytes                                                                         |
| 6     | `STDOUT`      | runner → gateway  | Raw bytes                                                                         |
| 7     | `STDERR`      | runner → gateway  | Raw bytes                                                                         |
| 8     | `EXIT_STATUS` | runner → gateway  | JSON `{"code": i32}`                                                              |
| 9     | `EOF`         | either            | Empty; half-close of the sender's data direction on that channel                  |
| 10    | `CLOSE`       | either            | Empty; full channel teardown                                                      |
| 11    | `ERROR`       | either            | JSON `{"code": string, "message": string}`; with `channel_id=0` it is a connection-level protocol error and the connection MUST be closed after sending |

## Replies

A reply to a request frame carries:

- the same `type` as the request,
- the REPLY flag (`0x0001`) set,
- the same `channel_id` and `request_id`,
- JSON payload `{"ok": bool, "error": {"code": string, "message": string}?}` where `error` is
  present **iff** `ok` is `false`.

A successful reply payload is exactly `{"ok":true}` (see golden vector V3).

## Ordering Rules

- `PTY_REQUEST` (if any) precedes `OPEN_SHELL` on the same channel.
- Exactly one `OPEN_SHELL` **or** `OPEN_EXEC` per channel.
- `STDIN`/`STDOUT`/`STDERR` flow only after the `OPEN_*` reply with `ok=true`.
- `EXIT_STATUS` at most once per channel.

## Protocol Errors

The following are protocol errors:

- unknown `version`,
- unknown `type`,
- reserved flag bits set,
- `payload_length > MAX_PAYLOAD`,
- short/truncated frame.

On any of them the receiver MUST send `ERROR` on channel 0 (best effort) and close the connection.

Implementation note (both codecs follow it so multi-fault headers report the same error): header
fields are validated in the order *length, version, type, flags, payload_length*.

## Flow Control

Implementations MUST bound per-channel buffering. Enforcement is implementation-level, not
wire-level — version 1 has no window/credit frames.

## Golden Test Vectors

Conformance vectors (hex, header + payload). Tests in every implementation MUST assert exact
byte-for-byte encode **and** decode of all three.

**V1 — `OPEN_SHELL` request, channel 1, request 1, payload `{}`:**

```text
01 01 00 00 00 00 00 01 00 00 00 01 00 00 00 02 7b 7d
```

**V2 — `STDOUT`, channel 3, request 0, payload `"hi"`:**

```text
01 06 00 00 00 00 00 03 00 00 00 00 00 00 00 02 68 69
```

**V3 — REPLY to `PTY_REQUEST` ok, channel 2, request 7, payload `{"ok":true}`:**

```text
01 03 00 01 00 00 00 02 00 00 00 07 00 00 00 0b 7b 22 6f 6b 22 3a 74 72 75 65 7d
```
