# FleetView 0.15.0 — Docker container controls

The Docker Containers tab now shows Start, Stop and Restart to operators and
administrators. A confirmation queues a per-device job; the native 0.15.0 agent
sends a request to its local Docker Engine and scans again afterward. Jobs
show success or failure. Viewers can inspect inventory but cannot manage
containers. The agent requires access to `/var/run/docker.sock` on Linux or
the Docker Desktop `docker_engine` pipe on Windows. The Docker inventory
setting must be enabled and the container must appear in the device's most
recent scan. An offline agent runs queued actions when it checks in; review
pending jobs before taking a managed server offline.

## Upgrade the existing test installation

Place `FleetView-0.15.0.zip` in your Downloads folder. Run the commands in
Bash. They preserve `/containers/epc-replacement`, its Compose file and `.env`,
the `epc-postgres` volume, and the enrolled device state. The first script
backs up the database/config and rebuilds only the existing server; the
second rebuilds the native agent while retaining its existing service and
enrollment credentials. Both need the existing sudo/Docker/Go setup.

```bash
bash -c '
set -e
release_dir="$(mktemp -d)"
unzip -q "$HOME/Downloads/FleetView-0.15.0.zip" -d "$release_dir"
bash "$release_dir/Endpoint-Central-replacement-claude-epc-replacement-continue-v8o0cx/scripts/upgrade-server-in-place.sh" /containers/epc-replacement
bash /containers/epc-replacement/scripts/upgrade-agent-in-place.sh
'
```

Restart and upgrade every additional endpoint agent using the extracted ZIP
and `scripts/upgrade-agent-in-place.sh` on Linux or
`scripts/upgrade-agent-in-place.ps1` on Windows. Do not use fresh-install
scripts on enrolled devices. Confirm `sudo docker compose ps` in
`/containers/epc-replacement`, `sudo systemctl status epc-agent --no-pager -l`,
and that the device reports agent 0.15.0. Run a device scan to refresh the
Docker list before using the new controls. Stop/restart of the FleetView
server's own container can temporarily make the dashboard unavailable.

The new fresh-install Compose example exposes `FLEETVIEW_COOKIE_SECURE` to
the server for HTTPS proxy deployments; the in-place upgrade intentionally
preserves the existing Compose file. If your existing server uses HTTPS and
you need secure session cookies, add the environment mapping in the existing
Compose file separately and set `FLEETVIEW_COOKIE_SECURE=true` in `.env`.
