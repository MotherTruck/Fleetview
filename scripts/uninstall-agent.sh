#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this command with sudo." >&2
  exit 1
fi

config_path="/etc/fleetview-agent/agent.env"
state_path="/var/lib/fleetview-agent/state.json"
if [[ ! -f "$config_path" || ! -f "$state_path" ]]; then
  echo "FleetView agent enrollment was not found." >&2
  exit 1
fi

server_url="$(sed -n 's/^FLEETVIEW_SERVER_URL=//p' "$config_path" | tail -n1)"
device_id="$(sed -n 's/.*"device_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state_path")"
agent_token="$(sed -n 's/.*"agent_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state_path")"
if [[ -z "$server_url" || -z "$device_id" || -z "$agent_token" ]]; then
  echo "Could not read the current agent enrollment." >&2
  exit 1
fi

code="${1:-}"
if [[ -z "$code" ]]; then
  read -r -s -p "Uninstall code (press Enter if protection is disabled): " code
  echo
fi
escaped="${code//\\/\\\\}"
escaped="${escaped//\"/\\\"}"

response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
status="$(printf '{"code":"%s"}' "$escaped" | curl -sS -o "$response_file" -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $agent_token" -H "X-Device-ID: $device_id" \
  --data-binary @- "$server_url/api/v1/agent/uninstall/verify")"
if [[ "$status" != "200" ]]; then
  echo "Uninstall authorization failed (HTTP $status)." >&2
  cat "$response_file" >&2
  exit 1
fi

systemctl disable --now fleetview-agent.service
rm -f /etc/systemd/system/fleetview-agent.service
rm -f /usr/local/bin/fleetview-agent
rm -f /etc/fleetview-agent/agent.env
rm -f /var/lib/fleetview-agent/state.json
systemctl daemon-reload
rmdir /etc/fleetview-agent /var/lib/fleetview-agent 2>/dev/null || true
rm -f /usr/local/sbin/fleetview-agent-uninstall
echo "FleetView agent removed from this device. Its historical server record was retained."
