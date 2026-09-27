#!/usr/bin/env bash
# Rebuild the native agent without moving its service/configuration/state.
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v go >/dev/null || { echo "Go is required on this endpoint." >&2; exit 1; }
if sudo test -f /etc/fleetview-agent/agent.env && sudo test -f /var/lib/fleetview-agent/state.json; then
  service=fleetview-agent
else
  echo "No existing enrolled agent configuration and state found; refusing to install a new one." >&2
  exit 1
fi
sudo systemctl cat "$service" >/dev/null
binary="/usr/local/bin/$service"
sudo test -f "$binary" || { echo "Existing binary $binary not found." >&2; exit 1; }
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT
(cd "$project_root/agent" && go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$build_dir/agent" ./cmd/fleetview-agent)
backup="$HOME/${service}-binary-backup-$(date +%Y%m%d-%H%M%S)"
sudo cp -a "$binary" "$backup"
sudo install -m755 "$build_dir/agent" "$binary.new"
sudo mv "$binary.new" "$binary"
sudo systemctl restart "$service"
sudo systemctl status "$service" --no-pager -l
printf 'Updated %s; enrollment state is unchanged. Previous binary: %s\n' "$service" "$backup"
