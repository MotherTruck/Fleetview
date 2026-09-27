#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

if ! sudo test -f /etc/fleetview-agent/agent.env || ! sudo test -f /var/lib/fleetview-agent/state.json; then
  echo "The agent is not enrolled. Use scripts/install-agent.sh instead." >&2
  exit 1
fi

# Files removed from newer releases remain after an archive is extracted over
# an existing installation. Remove only these known retired scanner sources.
rm -f \
  "$project_root/agent/internal/vulnerability/trivy.go" \
  "$project_root/agent/internal/vulnerability/trivy_test.go"

mkdir -p "$project_root/agent/bin"
(cd "$project_root/agent" && go build -trimpath -ldflags="-s -w" -o bin/fleetview-agent ./cmd/fleetview-agent)

sudo install -Dm755 "$project_root/agent/bin/fleetview-agent" /usr/local/bin/fleetview-agent.new
sudo mv /usr/local/bin/fleetview-agent.new /usr/local/bin/fleetview-agent
sudo install -Dm755 "$project_root/scripts/uninstall-agent.sh" /usr/local/sbin/fleetview-agent-uninstall
sudo systemctl enable --now fleetview-agent
sudo systemctl restart fleetview-agent

echo "Agent upgraded without changing its enrollment."
echo "Check it with: sudo journalctl -u fleetview-agent -n 50 --no-pager"
