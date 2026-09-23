# Move the existing EPC/FleetView server to its permanent VM

This is a migration of the existing installation, not a fresh enrollment.
Keep /containers/epc-replacement and its actual Compose configuration.
The PostgreSQL database holds device IDs, credential hashes, inventory, jobs,
history and, after 0.13.0 setup, users. Each endpoint keeps its own agent.env
and state.json. Restore the database and change only the server URL as needed.

## 1. Prepare before downtime

Use a Debian VM with a stable LAN address and Docker Engine/Compose.
For a small home fleet, 2 vCPUs, 4 GB RAM and 40 GB disk are a starting estimate,
not a measured capacity guarantee. Monitor disk usage as telemetry grows.
An existing adequately resourced Debian VM also works.

Docker's official Debian instructions:
https://docs.docker.com/engine/install/debian/

On the VM verify:

```bash
sudo docker version
sudo docker compose version
df -h /
```

Decide on the permanent management URL before cutover. A stable hostname
behind your existing Traefik HTTPS proxy lets you move the backend later
without editing every endpoint. If current agents use the laptop IP or
127.0.0.1, they need their server URL changed; DNS alone cannot redirect a
literal IP. Certificates must be valid for the chosen hostname. Keep the
server on the trusted LAN/proxy path; PostgreSQL must not be published.

Copy FleetView-0.13.0.zip to the VM, but do NOT start a new server or enroll
devices yet. Do not substitute the ZIP's example Compose file for the
currently running installation's Compose file.

## 2. Freeze the old server and export

Wait until pending/running package or patch jobs have completed. During this
window agents may log connection errors; leave their services/configs alone.
Do not submit new jobs until cutover is complete.

In Bash on LaptopServer:

```bash
set -e
umask 077
cd /containers/epc-replacement
migration_dir="$HOME/epc-migration-$(date +%Y%m%d-%H%M%S)"
mkdir -m700 "$migration_dir"
sudo docker compose stop server
sudo docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$migration_dir/database.sql"
test -s "$migration_dir/database.sql"
sudo tar --exclude=./.git --exclude=./agent/bin --exclude=./backups -czf "$migration_dir/project.tar.gz" .
sudo chown "$(id -u):$(id -g)" "$migration_dir/project.tar.gz"
chmod 600 "$migration_dir/project.tar.gz"
printf "Transfer these two private files to the VM: %s\n" "$migration_dir"
```

Transfer database.sql and project.tar.gz over SCP/SFTP to a private directory
on the VM (the archive includes .env secrets). Substitute the actual VM user
and IP in SCP; do not paste placeholder values as real addresses.

If export/transfer fails, the original database is still intact. Resume
service with docker compose start server on LaptopServer and schedule a new
export later. Never run two active servers accepting jobs during the cutover.

## 3. Restore on the new VM

These steps assume a NEW, EMPTY /containers/epc-replacement directory and
no existing epc-replacement database on that VM. If either already exists,
stop and inspect it before restoring. Keep the old server stopped.
Do not run docker compose down -v or delete any volume.

After placing the transferred files in ~/epc-migration on the VM, ensure the
account running these commands can read both files (the old host tar was made
with sudo and then assigned to your account):

```bash
set -e
sudo mkdir -p /containers/epc-replacement
sudo tar -xzf "$HOME/epc-migration/project.tar.gz" -C /containers/epc-replacement
cd /containers/epc-replacement
sudo docker compose -p epc-replacement config --volumes
```

For your current setup the volume key should still be epc-postgres. If the
configuration binds the server to the OLD host's specific IP, edit only that
bind address in .env/Compose to match the VM or its proxy. Preserve database
name/user/password and ADMIN_TOKEN. Review any host-specific mounts or
external networks before starting.

Start ONLY PostgreSQL, restore into its empty database, and verify devices:

```bash
sudo docker compose -p epc-replacement up -d --wait db
sudo docker compose -p epc-replacement exec -T db sh -c 'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < "$HOME/epc-migration/database.sql"
sudo docker compose -p epc-replacement exec -T db sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT count(*) AS enrolled_devices FROM devices;"'
```

If restore reports an error, do not start the server or blindly re-run the
import on a partially restored database. Keep the source export and inspect.

Now extract 0.13.0 separately and overlay only application source:

```bash
set -e
release_dir=$(mktemp -d)
unzip -q "$HOME/Downloads/FleetView-0.13.0.zip" -d "$release_dir"
release_source="$release_dir/Endpoint-Central-replacement-claude-epc-replacement-continue-v8o0cx"
test -f "$release_source/server/app/accounts.py"
sudo cp -a "$release_source/server" "$release_source/agent" "$release_source/scripts" "$release_source/docs" /containers/epc-replacement/
cd /containers/epc-replacement
sudo docker compose -p epc-replacement build server
sudo docker compose -p epc-replacement up -d --no-deps server
sudo docker compose -p epc-replacement ps
sudo docker compose -p epc-replacement logs --tail=50 server
```

## 4. Verify, then point agents to the VM

Open the VM dashboard or permanent HTTPS hostname. If accounts were already
set up before export, the same username/password works; otherwise use the
existing admin token ONCE to create the first account. Confirm device IDs,
inventory and history before touching agents.

Point the existing management hostname/proxy at the VM. If endpoints used
a literal old IP, edit their EXISTING config file:

```bash
sudoedit /etc/epc-agent/agent.env
sudo systemctl restart epc-agent
sudo journalctl -u epc-agent -n 30 --no-pager -l
```

Change only EPC_SERVER_URL (or FLEETVIEW_SERVER_URL if that key is present)
to the new URL. The FLEETVIEW_ key takes precedence if both exist, so update
the effective key. Keep the state path and credential file unchanged.
For already-renamed endpoints use /etc/fleetview-agent/agent.env and the
fleetview-agent service instead. Check service Environment/EnvironmentFile
overrides if the agent continues using the old URL.
Windows endpoints use their existing service/config location; do not rerun
the enrollment installer just to change the URL.

Check that each device becomes online under its EXISTING ID. Test one read-only
inventory scan, and sign in as a viewer to confirm access boundaries.
The laptop agent may also need its URL changed if it previously used localhost.
Only install/enroll an agent on the new VM if you also want to monitor the VM
itself; the management server does not require a local endpoint agent.

## 5. Keep a recovery path

Keep the old database volume and private migration export until the VM is
verified and backed up. Do not leave the old server accepting traffic.
If reverting, stop the VM server first, then restore the old hostname/URLs
and start the laptop server. Changes received only by the VM after cutover
will not exist on the old server; export that database before discarding it.

Arrange recurring database backups AND a restore test on the VM. Monitor
available disk space. VM snapshots alone are not the database migration.

Reference for pg_dump/psql and ON_ERROR_STOP:
https://www.postgresql.org/docs/17/backup-dump.html
