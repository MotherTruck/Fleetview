#!/bin/sh
# Installs the FleetView agent on OPNsense (or bare FreeBSD). Unlike the
# Linux installer, this downloads the prebuilt freebsd-amd64 binary the
# management server already cross-compiles and publishes at build time
# (see server/Dockerfile's agent-build stage and server-rs/src/deployment.rs's
# published_agent_manifest) rather than compiling from source -- OPNsense
# is a locked-down firewall appliance, not somewhere you want a Go
# toolchain installed, and the same approach install-agent.ps1 already
# uses for Windows for the same reason.
#
# Run as root on the OPNsense box itself (its web GUI has no SSH-less
# "run a command" feature, so this is meant to be pasted into the console
# or an SSH session -- the one-line command the dashboard's "Add a new
# device" page generates for FreeBSD devices does exactly that).
set -e

server_url="${1:-}"
enrollment_token="${2:-}"
if [ -z "$server_url" ] || [ -z "$enrollment_token" ]; then
	echo "Usage: $0 SERVER_URL ENROLLMENT_TOKEN" >&2
	exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "Run this installer as root." >&2
	exit 1
fi
server_url="${server_url%/}"

install -d -m 700 /usr/local/etc/fleetview-agent /var/db/fleetview-agent

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

fetch -o "$temporary_directory/manifest.json" "${server_url}/install/agent-version"
expected_sha="$(sed -n 's/.*"freebsd_amd64":{"sha256":"\([0-9a-f]*\)".*/\1/p' "$temporary_directory/manifest.json")"
if [ -z "$expected_sha" ]; then
	echo "Server did not publish a FreeBSD agent build (it may be an older FleetView version); refusing to install." >&2
	exit 1
fi

fetch -o "$temporary_directory/fleetview-agent" "${server_url}/install/agent-freebsd-amd64"
actual_sha="$(sha256 -q "$temporary_directory/fleetview-agent")"
if [ "$actual_sha" != "$expected_sha" ]; then
	echo "Agent binary checksum mismatch (expected $expected_sha, got $actual_sha); refusing to install." >&2
	exit 1
fi

install -m 755 "$temporary_directory/fleetview-agent" /usr/local/bin/fleetview-agent
fetch -o /usr/local/etc/rc.d/fleetview-agent "${server_url}/install/agent-freebsd.rc"
chmod 555 /usr/local/etc/rc.d/fleetview-agent
fetch -o /usr/local/sbin/fleetview-agent-uninstall "${server_url}/install/uninstall-agent-opnsense.sh"
chmod 755 /usr/local/sbin/fleetview-agent-uninstall

config_file="$(mktemp)"
trap 'rm -rf "$temporary_directory"; rm -f "$config_file"' EXIT
{
	printf 'FLEETVIEW_SERVER_URL=%s\n' "$server_url"
	printf 'FLEETVIEW_ENROLLMENT_TOKEN=%s\n' "$enrollment_token"
	printf 'FLEETVIEW_STATE_PATH=/var/db/fleetview-agent/state.json\n'
	printf 'FLEETVIEW_SCAN_INTERVAL_SECONDS=900\n'
	printf 'FLEETVIEW_METRICS_INTERVAL_SECONDS=60\n'
	printf 'FLEETVIEW_JOB_POLL_SECONDS=10\n'
	printf 'FLEETVIEW_REQUEST_TIMEOUT_SECONDS=60\n'
	printf 'FLEETVIEW_ALLOW_INSECURE_TLS=false\n'
} > "$config_file"
install -m 600 "$config_file" /usr/local/etc/fleetview-agent/agent.env

sysrc fleetview_agent_enable=YES >/dev/null
service fleetview-agent start

echo "FleetView agent installed. Check it with: service fleetview-agent status"
