#!/usr/bin/env bash
# Installs (or updates) the FleetView server stack in the current
# directory: fetches docker-compose.yml, generates a fresh .env with
# random secrets on first run only, then pulls and starts it. One
# command, no git clone or source checkout needed.
#
# Safe to re-run later to pick up a newer docker-compose.yml: an existing
# .env is always left untouched, so your secrets, bind address, and any
# other setting you've customized survive a re-run.
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

echo "==> Fetching docker-compose.yml"
curl -fsSL "$REPO_RAW/docker-compose.yml" -o docker-compose.yml.new
mv docker-compose.yml.new docker-compose.yml

if [[ -f .env ]]; then
  echo "==> .env already exists -- leaving it untouched"
else
  echo "==> Generating .env with fresh random secrets"
  curl -fsSL "$REPO_RAW/.env.example" -o .env
  chmod 600 .env
  postgres_password="$(openssl rand -hex 32)"
  admin_token="$(openssl rand -hex 32)"
  # Hex output only (0-9a-f), so neither value can contain a character
  # that would need escaping as a sed replacement.
  sed -i \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$postgres_password/" \
    -e "s/^ADMIN_TOKEN=.*/ADMIN_TOKEN=$admin_token/" \
    .env
fi

admin_token="$(sed -n 's/^ADMIN_TOKEN=//p' .env | head -1)"
bind_address="$(sed -n 's/^FLEETVIEW_BIND_ADDRESS=//p' .env | head -1)"
bind_address="${bind_address:-127.0.0.1}"
port="$(sed -n 's/^FLEETVIEW_PORT=//p' .env | head -1)"
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

cat <<EOF

FleetView is running.

  Dashboard:    http://$bind_address:$port
  Admin token:  $admin_token
                (you'll be asked for this once, to create your admin login
                -- also saved in .env as ADMIN_TOKEN if you need it again)

Only reachable from this machine right now ($bind_address). To reach it
from other devices, see "Reaching it from other devices" in README.md --
TLS is the recommended path (one extra command), kept out of this
installer since it needs you to choose the LAN address or hostname
yourself first.
EOF
