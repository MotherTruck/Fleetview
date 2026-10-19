#!/usr/bin/env bash
# Upgrades an existing FleetView server to the latest published image.
# Since the Rust cutover (server-rs/), the server ships as a published
# image (ghcr.io/mothertruck/fleetview-server) rather than something built
# from a local source checkout, so upgrading is just pulling the newer
# image and recreating the container -- no git clone, no local build, no
# source tree to keep in sync with the running deployment at all.
set -euo pipefail
umask 077

project_dir="${1:-$(pwd)}"
cd "$project_dir"
if [[ ! -f docker-compose.yml && ! -f compose.yml && ! -f compose.yaml && ! -f docker-compose.yaml ]]; then
  echo "No Compose file found in $project_dir -- this doesn't look like an existing FleetView install. Use scripts/install-server.sh for a fresh one." >&2
  exit 1
fi

backup_dir="$HOME/fleetview-server-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -m700 "$backup_dir"
sudo docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$backup_dir/database.sql"
test -s "$backup_dir/database.sql"
echo "Database backed up to $backup_dir/database.sql"

sudo docker compose pull server
sudo docker compose up -d --no-deps server
sudo docker compose ps
sudo docker compose logs --tail=30 server

echo "Upgrade complete. Database backup: $backup_dir/database.sql"
