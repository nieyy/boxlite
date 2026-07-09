# boxlite-ssh-gateway

The public SSH gateway for hosted BoxLite. It terminates public SSH with
[russh], treats the SSH **username as an opaque access token**, validates it
against the Hosted API, resolves the box's Runner, and bridges the session to
that Runner over the internal [session-frame protocol].

The user-facing contract is **frozen**:

```bash
ssh -p 2222 <token>@ssh.dev.boxlite.ai
```

## Two-leg architecture

```text
public client ── SSH (russh, this gateway) ── Gateway ── HTTP upgrade
    "boxlite-session-stream" (session frames) ── Runner ── vsock ── boxlite-guest's SSH service
```

1. **Public leg** — real SSH. The client authenticates with the `none` method;
   the username (the token) is validated via
   `GET /box/ssh-access/validate?token=…` on the Hosted API, then the Runner
   is resolved via `GET /runners/by-box/{boxId}` (the runner's `domain` field,
   mirroring the legacy Go gateway). Password/publickey attempts are rejected
   and the client is steered to `none`.
2. **Internal leg** — one HTTP-upgraded stream per SSH connection, opened
   lazily on the first channel:
   `POST /internal/ssh/sessions/{boxId}/stream` with
   `Upgrade: boxlite-session-stream`, a bearer service token, and the
   `X-BoxLite-Session-ID` / `X-BoxLite-Token-ID` / `X-BoxLite-Unix-User`
   headers. After `101 Switching Protocols` both sides speak version-1
   session frames; all SSH channels of the connection multiplex over the one
   stream by gateway-chosen nonzero `channel_id`.

Before routing, the gateway probes `GET /v1/boxes/{boxId}/ssh-status` and
fails closed unless `ready` is true, `degraded` is false, and `transport`
is `boxlite-runtime-vsock`. Every fail-closed path has a typed reason that
labels `ssh_gateway_route_failures_total{reason}` and a user-visible message
that never leaks paths, ports, hosts, or transport names.

## Feature gate

`BOXLITE_SSH_TARGET` gates the whole path:

- `off` (default) — every SSH authentication attempt is rejected.
- `russh-vsock` — sessions are routed to Runners.

## Configuration

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--listen-addr` | `BOXLITE_SSH_LISTEN_ADDR` | `0.0.0.0:2222` | Public SSH bind address |
| `--host-key-path` | `BOXLITE_SSH_HOST_KEY_PATH` | *(required)* | Persistent ed25519 host key; generated once if absent, then reused forever (clients pin it — never delete it) |
| `--hosted-api-url` | `BOXLITE_HOSTED_API_URL` | *(required)* | Hosted API base URL (`http` only in Stage 1) |
| `--hosted-api-token` | `BOXLITE_HOSTED_API_TOKEN` | *(required)* | Bearer credential for the Hosted API |
| `--runner-service-token` | `BOXLITE_RUNNER_SERVICE_TOKEN` | *(required)* | Bearer token for Runner-internal endpoints |
| `--ssh-target` | `BOXLITE_SSH_TARGET` | `off` | Feature gate (see above) |
| `--request-timeout-secs` | `BOXLITE_SSH_REQUEST_TIMEOUT_SECS` | `10` | Timeout for Hosted API calls, Runner HTTP calls, and frame replies |
| `--runner-scheme` | `BOXLITE_RUNNER_SCHEME` | `http` | Scheme for Runner endpoints derived from the runner domain (`http` only in Stage 1) |

Configuration is validated at startup; the process exits on any error.

## Observability

- Structured `tracing` audit events for: token validation results, box/runner
  routing targets, runner stream open/close, fail-closed reasons, channel
  open/close, and exit statuses. The full token **never** appears in logs —
  only an 8-character redacted prefix. Service tokens, socket paths, and CIDs
  are never logged.
- In-process counters (logged periodically; `snapshot()` for tests):
  `ssh_gateway_connections_total`, `ssh_gateway_route_failures_total{reason}`.

## Explicitly NOT supported in Stage 1

- **sftp/scp** (any subsystem) — channel requests fail cleanly.
- **Port forwarding** — `direct-tcpip`, `forwarded-tcpip`, `tcpip-forward`,
  streamlocal, agent and X11 forwarding are all rejected.
- **Force-disconnect on token revocation** — revoking a token blocks *new*
  sessions immediately; already-established sessions are not torn down.
- **TLS on internal legs** — the Hosted API and Runner clients speak plain
  HTTP/1.1 (cluster-internal traffic).

## Testing

`cargo test -p boxlite-ssh-gateway` runs everything without a VM or a real
Runner: unit tests, token-validator tests against a stub Hosted API (trait
seam + socket level), and end-to-end tests driving the gateway with a real
russh client against an in-test fake Runner that speaks the HTTP upgrade
handshake and the frame protocol via the sync `boxlite-session-frame` codec.

[russh]: https://crates.io/crates/russh
[session-frame protocol]: ../../docs/architecture/ssh-session-frame-protocol.md
