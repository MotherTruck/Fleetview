#!/usr/bin/env bash
set -euo pipefail

server_url="${1:-}"
enrollment_token="${2:-}"
if [[ -z "$server_url" || -z "$enrollment_token" ]]; then
  echo "Usage: install-fleetview-agent.sh SERVER_URL ENROLLMENT_TOKEN" >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer through sudo." >&2
  exit 1
fi

if command -v pacman >/dev/null 2>&1; then
  pacman -S --needed --noconfirm go pacman-contrib arch-audit curl ca-certificates tar
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y golang-go curl ca-certificates tar debsecan
else
  echo "This installer currently supports Arch/CachyOS, Debian, and Ubuntu." >&2
  exit 1
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
curl -fsSL "${server_url%/}/install/agent-source.tar.gz" -o "$temporary_directory/agent-source.tar.gz"
tar -xzf "$temporary_directory/agent-source.tar.gz" -C "$temporary_directory"

(cd "$temporary_directory/agent" && go build -trimpath -ldflags="-s -w" -o fleetview-agent ./cmd/fleetview-agent)
install -Dm755 "$temporary_directory/agent/fleetview-agent" /usr/local/bin/fleetview-agent
install -Dm644 "$temporary_directory/agent/packaging/fleetview-agent.service" /etc/systemd/system/fleetview-agent.service
install -Dm755 "$temporary_directory/scripts/uninstall-agent.sh" /usr/local/sbin/fleetview-agent-uninstall
install -d -m700 /etc/fleetview-agent /var/lib/fleetview-agent

config_file="$(mktemp)"
trap 'rm -rf "$temporary_directory"; rm -f "$config_file"' EXIT
{
  printf 'FLEETVIEW_SERVER_URL=%s\n' "${server_url%/}"
  printf 'FLEETVIEW_ENROLLMENT_TOKEN=%s\n' "$enrollment_token"
  printf 'FLEETVIEW_STATE_PATH=/var/lib/fleetview-agent/state.json\n'
  printf 'FLEETVIEW_SCAN_INTERVAL_SECONDS=900\n'
  printf 'FLEETVIEW_METRICS_INTERVAL_SECONDS=60\n'
  printf 'FLEETVIEW_JOB_POLL_SECONDS=10\n'
  printf 'FLEETVIEW_REQUEST_TIMEOUT_SECONDS=60\n'
  printf 'FLEETVIEW_ALLOW_INSECURE_TLS=false\n'
} > "$config_file"
install -m600 "$config_file" /etc/fleetview-agent/agent.env
systemctl daemon-reload
systemctl enable --now fleetview-agent
echo "FleetView agent installed. Check it with: systemctl status fleetview-agent --no-pager"
