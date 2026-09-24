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
  pacman -S --needed --noconfirm go pacman-contrib arch-audit curl ca-certificates tar openssl
elif command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y golang-go curl ca-certificates tar debsecan openssl
else
  echo "This installer currently supports Arch/CachyOS, Debian, and Ubuntu." >&2
  exit 1
fi

install -d -m700 /etc/fleetview-agent /var/lib/fleetview-agent

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

# If this server is reached over HTTPS with a private CA (the project's
# optional Caddy tls profile — see docs/TLS.md), fetch that CA once over an
# unverified connection and use it for everything after, rather than
# leaving TLS unverified for the whole install. This one bootstrap fetch
# has the same trust-on-first-use exposure the rest of this unauthenticated
# install already has (the agent source tarball itself is fetched the same
# way); a server on plain HTTP, or behind a real publicly-trusted
# certificate, needs none of this and ca_file simply stays empty.
ca_file=""
download_opts=(-fsSL)
if [[ "$server_url" == https://* ]]; then
  if curl -fsSLk "${server_url%/}/install/ca.crt" -o /etc/fleetview-agent/ca.crt.tmp 2>/dev/null \
      && [[ -s /etc/fleetview-agent/ca.crt.tmp ]] \
      && openssl x509 -in /etc/fleetview-agent/ca.crt.tmp -noout 2>/dev/null; then
    install -m644 /etc/fleetview-agent/ca.crt.tmp /etc/fleetview-agent/ca.crt
    ca_file="/etc/fleetview-agent/ca.crt"
    download_opts=(-fsSL --cacert "$ca_file")
  fi
  rm -f /etc/fleetview-agent/ca.crt.tmp
fi

curl "${download_opts[@]}" "${server_url%/}/install/agent-source.tar.gz" -o "$temporary_directory/agent-source.tar.gz"
tar -xzf "$temporary_directory/agent-source.tar.gz" -C "$temporary_directory"

(cd "$temporary_directory/agent" && go build -trimpath -ldflags="-s -w" -o fleetview-agent ./cmd/fleetview-agent)
install -Dm755 "$temporary_directory/agent/fleetview-agent" /usr/local/bin/fleetview-agent
install -Dm644 "$temporary_directory/agent/packaging/fleetview-agent.service" /etc/systemd/system/fleetview-agent.service
install -Dm755 "$temporary_directory/scripts/uninstall-agent.sh" /usr/local/sbin/fleetview-agent-uninstall

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
  if [[ -n "$ca_file" ]]; then
    printf 'FLEETVIEW_CA_FILE=%s\n' "$ca_file"
  fi
} > "$config_file"
install -m600 "$config_file" /etc/fleetview-agent/agent.env
systemctl daemon-reload
systemctl enable --now fleetview-agent
echo "FleetView agent installed. Check it with: systemctl status fleetview-agent --no-pager"
