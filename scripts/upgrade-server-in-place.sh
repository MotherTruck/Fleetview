#!/usr/bin/env bash
# Only upgrades the management server. Keeps the existing Compose project,
# .env, database volume, and native agent service/credentials untouched.
set -euo pipefail
umask 077
project_dir="${1:-/containers/fleetview}"
release_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"
test -f .env || { echo "Existing .env not found; refusing a new installation." >&2; exit 1; }
if [[ ! -f docker-compose.yml && ! -f compose.yml && ! -f compose.yaml && ! -f docker-compose.yaml ]]; then
  echo "Existing Compose file not found." >&2; exit 1
fi
test -f "$release_root/server/app/accounts.py"
if [[ "$(pwd -P)" == "$release_root" ]]; then
  echo "Extract the release into a separate directory before running this script." >&2; exit 1
fi
backup_dir="$HOME/fleetview-server-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -m700 "$backup_dir"
sudo docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$backup_dir/database.sql"
test -s "$backup_dir/database.sql"
sudo tar --exclude=./.git --exclude=./agent/bin --exclude=./backups -czf "$backup_dir/source-and-config.tar.gz" .
sudo cp -a "$release_root/server" "$release_root/agent" "$release_root/scripts" "$release_root/docs" .
sudo docker compose build server
sudo docker compose up -d --no-deps server
sudo docker compose ps
sudo docker compose logs --tail=30 server
printf "Backup: %s\nExisting Compose configuration and native agents were preserved.\n" "$backup_dir"
