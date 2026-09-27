# FleetView

An agent-based cross-platform inventory and patch-management dashboard. The management server and PostgreSQL run in Docker; a native agent runs on each endpoint (systemd on Linux, a Windows service on Windows) to inspect and update the host.

Supported endpoints: Arch Linux/CachyOS (pacman), Debian/Ubuntu (APT), and Windows (winget/Windows Update). The pacman scan path uses `checkupdates`, avoiding the unsupported partial-upgrade state caused by `pacman -Sy`.

**What it does:** inventory and patch tracking, OS vulnerability scanning (with exposure scoring against listening network ports/processes), live resource monitoring with a real interactive terminal, Docker container management, scheduled/one-off software deployment, and read-only integrations with Proxmox VE and OPNsense for a fuller home-lab picture. See [`docs/`](docs/) for the deeper write-up on any one of these — [`LIVE.md`](docs/LIVE.md) (live metrics/terminal), [`NETWORKING.md`](docs/NETWORKING.md) (diagnostics, Wake-on-LAN, exposure scoring), [`INTEGRATIONS.md`](docs/INTEGRATIONS.md) (Proxmox/OPNsense), [`TLS.md`](docs/TLS.md) (encrypting agent↔server traffic), and [`API.md`](docs/API.md).

## Architecture

```text
Browser ── frontend ──► FastAPI server ── backend ──► PostgreSQL
                              ▲
                              │ outbound HTTP(S)
                              │
                       fleetview-agent.service
                              │
      /proc + /sys / Docker socket / pacman or APT
```

The agent always initiates communication. No inbound agent port or endpoint SSH credential is required. The frontend bridge publishes only the configured server port, while PostgreSQL remains on a separate internal-only backend network.

## Quick start: deploy the server from a published image

Every push to `main` builds the server image and publishes it to `ghcr.io/mothertruck/fleetview-server`. A new server host that just wants to *run* FleetView needs only Docker itself, `docker-compose.yml`, and `.env` — no git clone, no build toolchain:

```bash
mkdir fleetview && cd fleetview
curl -fsSLO https://raw.githubusercontent.com/mothertruck/fleetview/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/mothertruck/fleetview/main/.env.example
cp .env.example .env
openssl rand -hex 32   # use for POSTGRES_PASSWORD
openssl rand -hex 32   # use for ADMIN_TOKEN
# edit .env: set POSTGRES_PASSWORD, ADMIN_TOKEN, and FLEETVIEW_BIND_ADDRESS
docker compose pull
docker compose up -d
curl --fail http://127.0.0.1:8080/healthz
```

Since the GHCR package inherits this repository's visibility (private), pulling from another machine needs a one-time `docker login ghcr.io` with a [personal access token](https://github.com/settings/tokens) that has `read:packages` scope, or a fine-grained token scoped to this repo's Packages, before `docker compose pull` will succeed there.

Keep `FLEETVIEW_BIND_ADDRESS=127.0.0.1` if the dashboard only needs to be reachable from this same machine. See **Network exposure** below to publish it to other devices on your LAN.

## Building from source instead

Prefer a full checkout when developing locally or testing an unreleased change. Clone the repo, then either of these installs runs identical steps from here (`docs/DEBIAN-SERVER-SETUP.md` for Debian 12+; below for Arch/CachyOS) — only prerequisite installation differs:

```bash
sudo pacman -S --needed docker docker-compose go pacman-contrib openssl arch-audit
sudo systemctl enable --now docker
```

```bash
cp .env.example .env
openssl rand -hex 32   # POSTGRES_PASSWORD
openssl rand -hex 32   # ADMIN_TOKEN
```

Put those two generated values into `.env`. Keep `FLEETVIEW_BIND_ADDRESS=127.0.0.1` for a same-machine test. There's no enrollment secret to configure — you create a one-time enrollment token per device from the dashboard itself; `ENROLLMENT_TOKEN` in `.env` is an optional legacy shared token, left unset unless you need it.

```bash
sudo docker compose up -d --build
sudo docker compose ps
curl --fail http://127.0.0.1:8080/healthz
```

If startup fails: `sudo docker compose logs --tail=100 server db`.

## First sign-in and enrolling a device

Visit the dashboard (`http://127.0.0.1:8080` by default). The first visit asks for the `ADMIN_TOKEN` from `.env` exactly once, to create your administrator username and password; after that, sign in with those credentials like any other account (see **User accounts & roles** below).

To enroll a device: **Agent → Add a new device**, choose its platform, and click **Generate enrollment command**. It's shown once and expires after an hour by default (Arch/CachyOS, Debian, and Ubuntu each get a one-line remote installer; see **Windows** below for that platform). Run it on the target machine — that finishes the enrollment.

From there: **Dashboard** for fleet health, **Patching** for patch/vulnerability scans and deployment, **Inventory** for per-device details (a **Docker Containers** tab appears once that endpoint reports a reachable daemon), **Deploy** for the software package catalog, **Reports** for compliance summaries and CSV/PDF export, **Agent** for collection intervals and enrollment, **Integrations** for Proxmox/OPNsense, and **Admin** for accounts, theme, and fleet-wide defaults.

### User accounts & roles

Three fleet-wide roles, enforced server-side on every request:

- **Viewer** — read-only: inventory, monitoring, jobs, the package catalog, and reports.
- **Operator** — viewer, plus queuing scan/patch/package/diagnostic jobs, editing the catalog, and setting scan schedules.
- **Admin** — everything: device removal, enrollment tokens, fleet defaults, integrations, and user management.

Create accounts under **Admin → User management**; a new user gets a temporary password and must change it at next sign-in. Sessions last 12 hours; passwords are hashed with PBKDF2-SHA256 (600,000 iterations). If every admin password is lost, recover locally on the Docker host:

```bash
sudo docker compose exec server python -m app.manage_users YOUR_ADMIN_USERNAME
```

## Adding a Linux device

The server must be reachable from that endpoint — see **Network exposure** below if it isn't yet. Open **Agent → Add a new device**, confirm the management URL, and generate the enrollment command. Each token enrolls exactly one device, then stops working.

To remove the agent from a device later:

```bash
sudo fleetview-agent-uninstall
```

## Windows

Windows support has not been run against real Windows hardware — expect rough edges. There's no one-line remote installer yet: on the endpoint, get a `git clone` of this project (or the source download from the same **Add a new device** page), plus [Go](https://go.dev/dl/) and `winget` (the **App Installer** package, present by default on current Windows 10/11), then from an elevated PowerShell prompt run the command the dashboard generates:

```powershell
.\scripts\install-agent.ps1 -ServerUrl 'http://192.168.1.50:8080' -EnrollmentToken 'PASTE_THE_ONE_TIME_TOKEN'
```

To remove it: `.\scripts\uninstall-agent.ps1`. Windows vulnerability scanning isn't implemented yet (no free CVE-mapped feed for arbitrary Windows software the way arch-audit/debsecan cover their distros) — pending Windows Update security patches are reported as patch data instead.

## Operations

```bash
sudo docker compose logs -f server           # server logs
sudo journalctl -u fleetview-agent -f        # agent logs (Linux)
sudo docker compose restart server           # restart server
sudo systemctl restart fleetview-agent       # restart agent (Linux)
sudo docker compose down                     # stop server, keep PostgreSQL data
```

Upgrading the server: `./scripts/upgrade-server-in-place.sh <your compose directory>` backs up the database and current source, then rebuilds and restarts only the `server` container — your `.env`, PostgreSQL volume, and enrolled agents are untouched. Upgrading an agent in place, preserving its enrollment: `scripts/upgrade-agent-in-place.sh` (Linux) or `.ps1` (Windows) from an extracted release.

### Re-enroll a device

Re-enrollment creates a new device identity. Stop the agent and preserve its old state until you're sure:

```bash
sudo systemctl stop fleetview-agent
sudo mv /var/lib/fleetview-agent/state.json /var/lib/fleetview-agent/state.json.backup
sudo systemctl start fleetview-agent
```

The enrollment token must still be present in `/etc/fleetview-agent/agent.env`.

## Network exposure

The default `127.0.0.1:8080` binding is suitable only for the server and agent running on the same machine. Never expose port 8080 directly to the internet — see [`docs/TLS.md`](docs/TLS.md) to add HTTPS via the optional Caddy profile before opening this up beyond a trusted LAN.

### Can't reach the dashboard from another machine?

`127.0.0.1` means "this machine only." If Docker runs in a VM, on a server, or in another container host, a browser on a different machine can't use that address. Run the read-only diagnostic on the Docker machine:

```bash
./scripts/check-access.sh
```

Then: find the Docker machine's LAN address (`ip -4 addr show scope global`), set `FLEETVIEW_BIND_ADDRESS` to it in `.env` (or `0.0.0.0` on a trusted network), and apply with `sudo docker compose up -d`. Agents on other machines need `FLEETVIEW_SERVER_URL` set to that same address.

Docker inserts its own firewall rules for published ports, so host rules such as `ufw deny 8080` may not restrict them — binding to one specific interface address is more reliable than a host firewall alone.

## Current limitations

- Windows: no vulnerability scanning yet, no one-line remote installer, not yet run against real Windows hardware.
- Vulnerability scanning covers Arch (via the Arch Security Team feed) and genuine Debian (via the Debian Security Tracker) only — not CachyOS-specific/AUR packages, Ubuntu (its package versions diverge too far from Debian's for `debsecan` to be reliable), application dependencies, or container images.
- Exposure scoring is a same-host name-matching heuristic between vulnerable packages and listening processes, not active exploit verification, and doesn't yet cross-reference firewall/NAT rules to distinguish LAN-only from internet-facing.
- No database migrations, agent auto-update beyond the manual/console upgrade paths above, maintenance windows, or policy scheduling.
- Accounts have fleet-wide roles only — no per-device/per-group access control, SSO, or MFA.
- A job claimed by an agent and interrupted before completion stays `running`; automatic lease recovery isn't implemented.
- Enrollment tokens are single-use; if a device's enrollment response is lost before it saves the credential, generate a fresh token.

## Project layout

```text
agent/                 Go endpoint agent
  cmd/fleetview-agent/       executable entry point
  internal/            inventory, packages, telemetry, live channel, vulnerability, config
  packaging/           systemd unit and example environment file
server/                FastAPI service and embedded dashboard
  app/accounts.py      account/session API (login, setup, user management)
  app/manage_users.py  local admin-recovery console command
scripts/               install/upgrade/diagnostic helpers
docs/                  feature guides (see links above)
docker-compose.yml     server and PostgreSQL deployment
```

## Development checks

```bash
python3 -m py_compile server/app/*.py
node --check server/app/static/app.js
cd agent && go test ./...
```

`server/tests/ui_dom_test.cjs` is a jsdom-based smoke test of the dashboard's own JS, without a real browser — a fast sanity check, not a substitute for testing in one. It needs `jsdom` installed locally (`npm install jsdom` in a scratch directory is enough; nothing is added to this repo for it):

```bash
node server/tests/ui_dom_test.cjs
```

`make test` runs the Python unit tests. Some require the server's own dependencies (`httpx`, used by `fastapi.testclient.TestClient`) and are skipped when those aren't installed on the host; to run everything inside the server image without touching your real database:

```bash
sudo docker compose run --rm --no-deps -v "$PWD/server/tests:/app/tests:ro" server python -m unittest discover -s /app/tests -v
```

Interactive API documentation is available at `http://127.0.0.1:8080/api/docs` while the server is running.
