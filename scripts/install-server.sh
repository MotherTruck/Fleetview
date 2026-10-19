#!/usr/bin/env bash
# Installs (or updates) the FleetView server stack in the current
# directory: fetches docker-compose.yml (first run only), fills in fresh
# random secrets directly in it, then pulls and starts it. One command,
# no git clone, source checkout, or separate .env file needed.
#
# Safe to re-run later: an existing docker-compose.yml is always left
# untouched (your secrets and any setting you've edited live in it), so
# re-running just re-pulls and restarts against whatever's already there.
# To pick up a newer docker-compose.yml from upstream later, fetch it
# fresh yourself and reapply your edits.
set -euo pipefail
umask 077

REPO_RAW="${FLEETVIEW_INSTALLER_SOURCE:-https://raw.githubusercontent.com/mothertruck/fleetview/main}"

for cmd in docker curl openssl sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing dependency: $cmd. Install it and re-run this script." >&2
    exit 1
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "Missing dependency: the Docker Compose plugin (the 'docker compose' subcommand, not the standalone docker-compose binary). See https://docs.docker.com/compose/install/" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Cannot reach the Docker daemon. Is Docker running, and can this user run 'docker' without sudo? (sudo usermod -aG docker \"\$USER\", then log out and back in)" >&2
  exit 1
fi

if [[ -f docker-compose.yml ]]; then
  echo "==> docker-compose.yml already exists -- leaving it untouched"
else
  echo "==> Fetching docker-compose.yml"
  curl -fsSL "$REPO_RAW/docker-compose.yml" -o docker-compose.yml.new
  mv docker-compose.yml.new docker-compose.yml
fi

if grep -qE 'REPLACE_WITH_(output_of_openssl_rand_hex_32|a_different_output_of_openssl_rand_hex_32)$' docker-compose.yml; then
  echo "==> Filling in fresh random secrets"
  # Hex output only (0-9a-f), so neither value can contain a character
  # that would need escaping as a sed replacement, and neither can ever
  # collide with the REPLACE_WITH_ prefix the placeholders use.
  sed -i \
    -e "s/REPLACE_WITH_output_of_openssl_rand_hex_32/$(openssl rand -hex 32)/" \
    -e "s/REPLACE_WITH_a_different_output_of_openssl_rand_hex_32/$(openssl rand -hex 32)/" \
    docker-compose.yml
else
  echo "==> docker-compose.yml already has its secrets filled in -- leaving them untouched"
fi

admin_token="$(sed -n 's/^\s*ADMIN_TOKEN:\s*//p' docker-compose.yml | head -1)"
# DASHBOARD_ADDRESS, near the top of docker-compose.yml (e.g.
# "127.0.0.1:8080:8080") -- not a Compose variable, so .env can't override it.
bind_address="$(sed -n 's/^x-dashboard-address: &dashboard_address "\([^:]*\):.*/\1/p' docker-compose.yml | head -1)"
port="$(sed -n 's/^x-dashboard-address: &dashboard_address "[^:]*:\([^:]*\):8080"$/\1/p' docker-compose.yml | head -1)"
bind_address="${bind_address:-127.0.0.1}"
port="${port:-8080}"

echo "==> Pulling images"
docker compose pull

echo "==> Starting FleetView"
docker compose up -d

echo "==> Waiting for the server to come up"
up=false
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    up=true
    break
  fi
  sleep 1
done
if [[ "$up" != true ]]; then
  echo "Server did not come up within 30s. Check: docker compose logs --tail=100 server db" >&2
  exit 1
fi

browse_address="$bind_address"
reachability="Only reachable from this machine right now ($bind_address)."
if [[ "$bind_address" == "0.0.0.0" ]]; then
  browse_address="127.0.0.1"
  lan_address="$(hostname -I 2>/dev/null | awk '{print $1}')"
  reachability="Reachable from this machine and other devices on your network${lan_address:+ (e.g. http://$lan_address:$port)} -- this is plain HTTP, not encrypted."
fi

cat <<EOF

FleetView is running.

  Dashboard:    http://$browse_address:$port
  Admin token:  $admin_token
                (you'll be asked for this once, to create your admin login
                -- also saved as ADMIN_TOKEN in docker-compose.yml if you
                need it again)

$reachability To change who can reach it,
see "Reaching it from other devices" in README.md --
TLS is the recommended path (one extra command), kept out of this
installer since it needs you to choose the LAN address or hostname
yourself first.
EOF
