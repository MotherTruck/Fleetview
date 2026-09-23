#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server_url="${1:-http://127.0.0.1:8080}"
enrollment_token="${2:-}"

if [[ -z "$enrollment_token" ]]; then
  echo "Usage: $0 SERVER_URL ENROLLMENT_TOKEN" >&2
  exit 2
fi
for command_name in go systemctl curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing dependency: $command_name" >&2
    echo "Install Go, curl, and systemd before continuing." >&2
    exit 1
  fi
done
if command -v pacman >/dev/null 2>&1; then
  for command_name in checkupdates arch-audit; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "Missing dependency: $command_name" >&2; exit 1; }
  done
elif command -v apt-get >/dev/null 2>&1; then
  for command_name in dpkg-query debsecan; do
    command -v "$command_name" >/dev/null 2>&1 || { echo "Missing dependency: $command_name" >&2; exit 1; }
  done
else
  echo "Supported package manager not found (pacman or apt)." >&2
  exit 1
fi

rm -f \
  "$project_root/agent/internal/vulnerability/trivy.go" \
  "$project_root/agent/internal/vulnerability/trivy_test.go"

mkdir -p "$project_root/agent/bin"
(cd "$project_root/agent" && go build -trimpath -ldflags="-s -w" -o bin/fleetview-agent ./cmd/fleetview-agent)

sudo install -Dm755 "$project_root/agent/bin/fleetview-agent" /usr/local/bin/fleetview-agent
sudo install -Dm644 "$project_root/agent/packaging/fleetview-agent.service" /etc/systemd/system/fleetview-agent.service
sudo install -Dm755 "$project_root/scripts/uninstall-agent.sh" /usr/local/sbin/fleetview-agent-uninstall
sudo install -d -m700 /etc/fleetview-agent /var/lib/fleetview-agent
temporary_config="$(mktemp)"
trap 'rm -f "$temporary_config"' EXIT
{
  printf 'FLEETVIEW_SERVER_URL=%s\n' "$server_url"
  printf 'FLEETVIEW_ENROLLMENT_TOKEN=%s\n' "$enrollment_token"
  printf 'FLEETVIEW_STATE_PATH=/var/lib/fleetview-agent/state.json\n'
  printf 'FLEETVIEW_SCAN_INTERVAL_SECONDS=900\n'
  printf 'FLEETVIEW_METRICS_INTERVAL_SECONDS=60\n'
  printf 'FLEETVIEW_JOB_POLL_SECONDS=10\n'
  printf 'FLEETVIEW_REQUEST_TIMEOUT_SECONDS=60\n'
  printf 'FLEETVIEW_ALLOW_INSECURE_TLS=false\n'
} > "$temporary_config"
sudo install -m600 "$temporary_config" /etc/fleetview-agent/agent.env
sudo systemctl daemon-reload
sudo systemctl enable --now fleetview-agent
echo "Agent installed. Follow enrollment with: sudo journalctl -u fleetview-agent -f"
