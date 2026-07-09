"""E2E test for the real russh SSH gateway (src/ssh-gateway-russh).

Full chain, no fakes on either side: real API validates the token against
real Postgres, real Runner bridges the session-frame stream, a real VM runs
boxlite-guest's in-process SSH service. Complements the fake-Runner/fake-Hosted-API
protocol tests in src/ssh-gateway-russh/tests/gateway_e2e.rs, which exercise
the gateway in isolation.

Skipped unless boxlite-ssh-gateway is actually listening on :2222 — plain
`make test:e2e` (which doesn't run bootstrap-ssh-gateway.sh) must not fail
this file; only `make test:e2e:ssh-gateway` (after
`make test:e2e:ssh-gateway-setup`) exercises it.
"""
from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request

import boxlite
import pytest

from conftest import DEFAULT_IMAGE, drain
from e2e_auth import auth_context

# The guest's SSH vsock listener starts a few hundred ms after boxlite-guest's
# own gRPC service comes up (service::ssh::spawn is called from GuestServer::run,
# with its own accept-error backoff) — bound the same way the Rust core's own
# integration test (src/boxlite/tests/session.rs) does.
SSH_READY_TIMEOUT_S = 60


def _gateway_listening() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", 2222)) == 0


pytestmark = pytest.mark.skipif(
    not _gateway_listening(),
    reason="boxlite-ssh-gateway is not listening on :2222 — run "
    "`make test:e2e:ssh-gateway-setup` first",
)


def _mint_ssh_access_token(box_id: str) -> str:
    ctx = auth_context()
    req = urllib.request.Request(
        ctx.url_for(f"box/{box_id}/ssh-access?expiresInMinutes=5"),
        method="POST",
        headers=ctx.auth_headers(),
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise AssertionError(
            f"POST /box/{box_id}/ssh-access failed: {exc.code} {exc.read()!r}"
        ) from exc
    return body["token"]


def _ssh_run(token: str, remote_cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh", "-p", "2222",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            f"{token}@localhost",
            remote_cmd,
        ],
        capture_output=True, text=True, timeout=30,
    )


@pytest.mark.asyncio
async def test_real_ssh_gateway_shell_and_exit_code(rt, image):
    """ssh -p 2222 <token>@host through the real gateway -> real Runner ->
    real guest SSH service: stdout arrives, exit code propagates."""
    box = await rt.create(boxlite.BoxOptions(image=image, auto_remove=True))
    try:
        # Force the VM into Running state via a normal exec first — the SSH
        # session bridge fails closed (BOX_STOPPED) on a Configured box, and
        # this reuses the SDK instead of a bespoke start() call.
        ex = await box.exec("sh", ["-c", "echo booted"], None)
        out, _ = await drain(ex)
        await asyncio.wait_for(ex.wait(), timeout=60)
        assert "booted" in out, f"box did not start: {out!r}"

        token = _mint_ssh_access_token(box.id)

        # The guest's SSH service starts asynchronously after the guest's
        # control plane is already up (see module docstring) — retry the ssh
        # connection attempt, not just an internal readiness probe, since
        # that's the actual client-observable behaviour under test.
        deadline = time.monotonic() + SSH_READY_TIMEOUT_S
        result = None
        while time.monotonic() < deadline:
            result = _ssh_run(token, "echo hi && exit 42")
            if result.returncode == 42:
                break
            time.sleep(2)
        assert result is not None
        assert "hi" in result.stdout, (
            f"unexpected stdout: {result.stdout!r} stderr: {result.stderr!r}"
        )
        assert result.returncode == 42, (
            f"exit code not propagated: {result.returncode}, "
            f"stderr: {result.stderr!r}"
        )
    finally:
        await rt.remove(box.id, force=True)


@pytest.mark.asyncio
async def test_revoked_token_is_rejected(rt, image):
    """A revoked ssh-access token must fail closed on a fresh connection."""
    box = await rt.create(boxlite.BoxOptions(image=image, auto_remove=True))
    try:
        ex = await box.exec("sh", ["-c", "echo booted"], None)
        await drain(ex)
        await asyncio.wait_for(ex.wait(), timeout=60)

        token = _mint_ssh_access_token(box.id)

        ctx = auth_context()
        req = urllib.request.Request(
            ctx.url_for(f"box/{box.id}/ssh-access?token={token}"),
            method="DELETE",
            headers=ctx.auth_headers(),
        )
        urllib.request.urlopen(req, timeout=10).close()

        result = _ssh_run(token, "echo should-not-run")
        assert result.returncode != 0, (
            "revoked token was still accepted by the gateway"
        )
    finally:
        await rt.remove(box.id, force=True)
