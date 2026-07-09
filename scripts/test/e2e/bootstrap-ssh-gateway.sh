#!/usr/bin/env bash
# Extends the base e2e stack (scripts/test/e2e/bootstrap.sh) with the real
# russh SSH gateway (src/ssh-gateway-russh), so the ssh-gateway e2e suite can
# drive a real `ssh -p 2222 <token>@host` through:
#   real API (token validation) -> real Runner -> real VM (boxlite-guest's SSH service).
#
# Must run AFTER bootstrap.sh (reuses its secrets file, env file, and running
# boxlite-api/boxlite-runner services). Idempotent, like bootstrap.sh.
#
# Deliberately a separate script, not folded into bootstrap.sh: every other
# e2e-stack.yml run (unrelated to the SSH gateway) would otherwise pay the
# extra build+start cost for a component it never exercises.

set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
ENV_FILE="${ENV_FILE:-/etc/boxlite-api.env}"
SECRETS_FILE="${SECRETS_FILE:-/etc/boxlite-secrets.env}"

[[ -d "$REPO" ]] || { echo "REPO=$REPO not found"; exit 1; }
[[ -r "$SECRETS_FILE" ]] || { echo "$SECRETS_FILE missing — run bootstrap.sh first"; exit 1; }
# shellcheck disable=SC1090
source "$SECRETS_FILE"
[[ -n "${SSH_GATEWAY_API_KEY:-}" ]] || { echo "SSH_GATEWAY_API_KEY missing from $SECRETS_FILE"; exit 1; }
[[ -n "${DEFAULT_RUNNER_API_KEY:-}" ]] || { echo "DEFAULT_RUNNER_API_KEY missing from $SECRETS_FILE"; exit 1; }

echo "=== 1. build boxlite-ssh-gateway from current source ==="
cd "$REPO"
cargo build --release -p boxlite-ssh-gateway
sudo install -m 0755 target/release/boxlite-ssh-gateway /usr/local/bin/boxlite-ssh-gateway

sudo mkdir -p /var/lib/boxlite
sudo chown "$USER:$USER" /var/lib/boxlite

echo "=== 2. systemd unit ==="
sudo tee /etc/systemd/system/boxlite-ssh-gateway.service > /dev/null <<UNIT
[Unit]
Description=BoxLite SSH Gateway (russh)
After=network.target boxlite-api.service boxlite-runner.service
Wants=boxlite-api.service boxlite-runner.service

[Service]
Type=simple
User=$USER
ExecStart=/usr/local/bin/boxlite-ssh-gateway \\
    --listen-addr 0.0.0.0:2222 \\
    --host-key-path /var/lib/boxlite/ssh-gateway-host-key \\
    --hosted-api-url http://localhost:3000/api \\
    --hosted-api-token $SSH_GATEWAY_API_KEY \\
    --runner-service-token $DEFAULT_RUNNER_API_KEY \\
    --ssh-target russh-vsock
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/boxlite-ssh-gateway.log
StandardError=append:/var/log/boxlite-ssh-gateway.log

[Install]
WantedBy=multi-user.target
UNIT
sudo touch /var/log/boxlite-ssh-gateway.log && sudo chown "$USER:$USER" /var/log/boxlite-ssh-gateway.log
sudo systemctl daemon-reload

echo "=== 3. start + verify :2222 is listening ==="
sudo systemctl enable boxlite-ssh-gateway 2>/dev/null
sudo systemctl restart boxlite-ssh-gateway

gateway_ready=0
for i in $(seq 1 30); do
    if pgrep -af '/usr/local/bin/boxlite-ssh-gateway' >/dev/null \
       && ss -ltn 2>/dev/null | grep -q ':2222'; then
        gateway_ready=1; break
    fi
    sleep 2
done
if [[ $gateway_ready -ne 1 ]]; then
    echo "ERROR: boxlite-ssh-gateway did not bind :2222 within 60s" >&2
    sudo journalctl -u boxlite-ssh-gateway --no-pager -n 100 >&2
    exit 1
fi

echo ""
echo "=== ssh gateway bootstrap complete ==="
echo "gateway: $(systemctl is-active boxlite-ssh-gateway) :2222"
