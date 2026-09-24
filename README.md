# FleetView

An agent-based cross-platform inventory and patch-management prototype (formerly "EPC Replacement"). The management server and PostgreSQL run in Docker; the endpoint agent runs natively under systemd (Linux) or as a Windows service so it can inspect and update the host.

This repository is the project's home going forward, starting from a snapshot of `mothertruck/endpoint-central-replacement`'s code as of this move (that repository is being retired in favor of this one).

The endpoint adapters support Arch Linux/CachyOS through pacman, Debian/Ubuntu through APT, and Windows through winget/Windows Update. The pacman scan path uses `checkupdates`, avoiding the unsupported partial-upgrade state caused by `pacman -Sy`.

## Included in version 0.18.0

- **Live metrics and an interactive terminal**: agents 0.18.0+ keep a second persistent WebSocket connection to the server alongside the existing poll-based job loop (purely additive -- a device with no live connection is still fully manageable through queued jobs exactly as before). It carries a fast metrics sample every ~2s for real-time dashboard tiles and the device Monitoring view (the existing 60s REST-reported history/trend charts are untouched), and an admin-only **Terminal** tab that spawns a real shell on the device (Bash on Linux, PowerShell on Windows via a real ConPTY pseudoconsole) streamed to [xterm.js](https://xtermjs.org/) in the browser -- unlike every other action in this dashboard, this is a live interactive session, not a queued job. Every terminal session is audit-logged, limited to one at a time per device, protected by an Origin check against cross-site WebSocket hijacking, and never auto-reconnects. See [`docs/LIVE.md`](docs/LIVE.md) for the full picture.
- **Agent tab: fleet-wide version table**: a new table lists every enrolled device's agent version, whether it's current, and a Live indicator, with an **Upgrade** button per row -- previously this required selecting one device at a time from a dropdown.

## Included in version 0.17.0

- **Encrypt agent↔server traffic**: an optional `tls` Compose profile (`docker compose --profile tls up -d`) adds a [Caddy](https://caddyserver.com/) reverse proxy in front of the server, terminating HTTPS with a certificate from Caddy's own private CA — a public CA like Let's Encrypt won't issue a certificate for the LAN IP or private hostname this dashboard is normally reached at. Point the install command at the `https://` server URL and both installer scripts (`remote-install-linux.sh`, `install-agent.ps1`) fetch and pin that CA automatically before installing anything else (`FLEETVIEW_CA_FILE`) — no manual certificate distribution needed for a normal install. `FLEETVIEW_ALLOW_INSECURE_TLS=true` remains available to skip validation entirely if that automatic fetch isn't practical. Off by default; existing plain-HTTP installs are unaffected until you opt in. See [`docs/TLS.md`](docs/TLS.md) for the full walkthrough, including why a fixed internal address is trusted for forwarded-header purposes so login-throttling by source IP keeps working correctly once traffic is proxied.

## Included in version 0.16.0

- Fixed "Copy command" on the Agent enrollment panel doing nothing on a plain-HTTP dashboard (the normal way this is reached on a LAN): `navigator.clipboard` only works in a secure context (HTTPS or localhost), so it now falls back to the older `execCommand("copy")` approach when that API isn't available. Added an **Approve all** button next to Deploy approved patches, so reviewing a long list of pending patches one at a time isn't required.
- **Run a command** (admin only): Deploy → Run a command lets an admin type an ad-hoc command and run it once on any selection of devices, using the same target-device list as the rest of the Deploy tab. There's no live/interactive shell — this queues a job the same way every other action here does: the agent picks it up at its next check-in, runs it with Bash (Linux) or PowerShell (Windows), and reports the output and exit code back to the Jobs table. Requires a native agent on 0.16.0 or later.
- **Upgrade agent from the console** (admin only): the server's own Docker image now cross-compiles and bakes in a Linux and a Windows agent binary at build time (see `server/Dockerfile`'s `agent-build` stage and `.github/workflows/docker-publish.yml`), so upgrading a device's agent no longer means running a script by hand on that machine. Open **Agent**, pick a device that's already on 0.16.0 or later, and an **Upgrade agent** button appears whenever a newer published version exists; the agent downloads the new binary, verifies its SHA-256 against what the server recorded at build time, and applies it. On Linux this happens in place with no restart or dropped connection — the process replaces its own running binary and re-executes itself, keeping the same PID, so systemd sees it as the same service instance continuing to run. On Windows, which keeps a running executable's file locked, the agent hands off to a short-lived detached helper that waits for the service to stop, swaps the file, and restarts it — functionally complete but, like the rest of this project's Windows support, not yet run against real Windows hardware. A device below 0.16.0 has no code path that understands this job type at all, so that first jump still needs `scripts/upgrade-agent-in-place.sh` (or `.ps1`) run by hand once; remote upgrades work from there onward.

## Included in version 0.15.0

- **Docker container controls**: the Docker Containers tab in a device's details now shows Start, Stop, and Restart buttons to operators and admins (viewers can still inspect, but not manage). A confirmation queues a per-device job; the native agent (0.15.0+) sends the request directly to its local Docker Engine — the Unix socket on Linux, or the Docker Desktop named pipe on Windows — and rescans afterward so the tab reflects the new state. Requires Docker inventory enabled for that device and the container to appear in its most recent scan; an offline agent runs the action the next time it checks in.
- **Patch approvals and scheduled deployment**: Patching → Review a device's needed patches and approve (or later revoke) each pending package/version individually, instead of an all-or-nothing system update. **Deploy approved patches** installs the currently-approved set on demand; an optional per-device hours interval (0 disables) automates it, with due jobs queued at the device's next check-in and a pending/running job suppressing duplicates. Arch still requires approving every pending package (pacman has no partial-upgrade support); Debian simulates `apt-get install --only-upgrade` for the approved exact versions first and refuses to deploy if the transaction would touch anything else; Windows uses winget package IDs and exact versions (Windows Update entries without a winget ID stay visible but can't be approved here). Requires native agents upgraded to 0.14.0 or later — the previous unrestricted **Install updates** action is now rejected by the server.
- **Custom installer upload** (admin only): Deploy → Upload an installer lets an admin attach one to five files (8 MiB per file, 16 MiB combined), a target OS, and a command, then deploy that saved bundle to selected devices with the exact command and file list shown in the confirmation dialog first. The agent downloads the files into a private temporary directory, verifies each one's size and SHA-256 against what the server recorded at upload time, runs the command with Bash (Linux) or PowerShell (Windows), and removes the files afterward. Bundles are immutable once saved and stored in PostgreSQL alongside other data, so back up the database regularly.

## Included in version 0.13.0

- Username/password accounts with three fleet-wide roles (**viewer**: read-only; **operator**: viewer plus scan/patch/package jobs, catalog edits, and scan schedules; **admin**: everything, including devices, fleet settings, and user management) replace the shared admin token for everyday sign-in. First launch still uses the existing `ADMIN_TOKEN` exactly once, to create the initial administrator; afterwards the token cannot bypass account permissions. See **User accounts & roles** below.
- Five complete color themes (green, blue, purple, amber, pink) — each is a coordinated dark background, panel, border, and text palette, not just a different accent color. Still a per-browser preference.
- Deploy catalog **Uninstall**: queue a confirmed removal job for selected devices, using the same per-platform identifier resolution as Deploy. Upgrade native agents to 0.12.0+ first.
- **Agent → Automatic vulnerability scan interval**: set an hours-based recurring schedule per device (0 disables); the server queues the scan itself when the agent next polls for jobs, so no scan runs early and missed intervals don't pile up. Supported on Arch/CachyOS and genuine Debian only.
- Reports **Trends** now takes a device (or the whole fleet) and a custom inclusive UTC date range, not just the whole fleet's last 30 days.
- Software deployment: a saved package catalog (name, description, version, category, and a per-platform pacman/apt/winget identifier) on the Deploy tab, so you set each package up once and deploy it to any selection of devices from then on — the right identifier is picked automatically per device's platform, and a device whose platform has none configured is skipped with a clear reason instead of failing a job
- Admin tab: a per-browser accent color picker for the dashboard theme, fleet-wide default monitoring/inventory intervals (applied to any device without its own override), and a Network panel explaining where the server's port and bind address are actually configured
- Reports: historical trend charts (fully patched %, no critical/high vulnerabilities %, online %, and fleet-wide vulnerability count over time), backed by a daily compliance snapshot recorded the first time each device reports patch or vulnerability data on a given UTC day
- **Renamed from "EPC Replacement" to FleetView.** This is a breaking rename: the agent binary, systemd service, install paths, and `EPC_*` environment variables all changed names (`FLEETVIEW_*` now). See **Upgrade an existing installation** below — the upgrade script migrates an existing agent automatically, and the agent still reads old `EPC_*` variable names as a fallback so a config file you haven't gotten around to editing keeps working.

- Reports: a compliance-style fleet summary (patched/vulnerable/online tiles plus a by-platform breakdown) and a custom report builder to filter devices, pick columns, and export the result as CSV or a printable/PDF snapshot, all from the new Reports tab
- Software deployment: install a package by name/ID on one or more devices from the new Deploy tab, across pacman, apt, and winget
- A working Windows agent (see **Windows** below) covering telemetry, inventory, patch data, and Docker inventory
- Fixed a bug where every metrics report crashed the server with a 500 (MetricSample has no `gpus` column) — resource monitoring now actually populates
- Fixed a bug where the dashboard 500'd on SQLite-backed deployments (a naive/aware datetime comparison that Postgres happened to mask)
- Remove a device from the fleet from its device details dialog, deleting its enrollment, jobs, and monitoring history (any enrollment token used to add it keeps its history but is unlinked)
- Debian vulnerability scanning through `debsecan` against the Debian Security Tracker, and a fixed APT patch scan (it now runs `apt-get update` before checking for upgradable packages, so the package cache no longer goes stale between scans)
- One-time, expiring per-device enrollment tokens generated from the dashboard (the old shared token is optional)
- Per-device random agent credentials (only a SHA-256 token digest is stored server-side)
- Heartbeats and online/offline state
- Lightweight one-minute CPU, memory, swap, root-disk, load, network, process-count, uptime, and CPU-temperature telemetry
- Seven-day resource history in PostgreSQL with configurable retention
- Current NVIDIA, AMD, and Intel GPU utilization where the platform exposes it, plus available VRAM, temperature, and power readings
- Basic Docker container inventory with automatic UI detection and no container-stat polling
- OS, CPU, memory, kernel, network, and uptime inventory
- Installed package and update inventory through pacman or APT
- Lightweight on-demand OS-package vulnerability scanning with `arch-audit` (Arch/CachyOS) or `debsecan` (Debian)
- One-command enrollment for Arch/CachyOS, Debian, and Ubuntu from the Agent page
- Searchable vulnerability findings with severity, CVE, installed version, and fixed version
- Seven primary views: live Dashboard, Patching, Inventory, Deploy, Reports, Agent, and Admin
- Fleet health summary and per-device resource monitoring charts
- Inventory device details for CPU, load, memory, root-disk usage, kernel, network, uptime, scan time, and patch time
- Searchable device details with needed-patch and installed-software tables
- Installed and available package versions shown side by side
- Versioned dashboard assets to prevent stale JavaScript after upgrades
- Manual `SCAN_DEVICE`, `SCAN_VULNERABILITIES`, and `INSTALL_UPDATES` jobs
- Patch-job confirmation, status, output, and error history
- Responsive web dashboard with role-based account sessions
- Per-device monitoring and inventory intervals, GPU/Docker toggles, and optional managed-uninstall code

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

## Deploy the server from a published image (no source checkout)

Every push to `main` builds the server image and publishes it to `ghcr.io/mothertruck/fleetview-server` (see [`.github/workflows/docker-publish.yml`](.github/workflows/docker-publish.yml)). `docker-compose.yml` names that image directly, so a new server host that just wants to *run* FleetView needs only Docker itself, `docker-compose.yml`, and `.env` — no git clone, no build toolchain:

```bash
mkdir fleetview && cd fleetview
curl -fsSLO https://raw.githubusercontent.com/mothertruck/fleetview/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/mothertruck/fleetview/main/.env.example
cp .env.example .env
# edit .env: set POSTGRES_PASSWORD, ADMIN_TOKEN, and FLEETVIEW_BIND_ADDRESS — see step 2/3 below
docker compose pull
docker compose up -d
```

Since the GHCR package inherits this repository's visibility (private), pulling from another machine needs a one-time `docker login ghcr.io` with a [personal access token](https://github.com/settings/tokens) that has `read:packages` scope, or a fine-grained token scoped to this repo's Packages, before `docker compose pull` will succeed there.

This is the same `docker-compose.yml` used below — it still has a `build:` block too, so `docker compose up -d --build` from a full checkout works exactly as before for local development. The rest of this README (configuring `.env`, opening the dashboard, enrolling devices) is identical either way; only how the `server` container's image gets onto the machine differs.

## Install on the CachyOS test machine

For a new server instance on Debian instead, see [`docs/DEBIAN-SERVER-SETUP.md`](docs/DEBIAN-SERVER-SETUP.md) — steps 2 onward below are identical regardless of host distro; only prerequisite installation differs. Either guide's steps 2 onward can be skipped entirely in favor of **Deploy the server from a published image** above, once you just want to run FleetView rather than build or develop it locally.

### 1. Install prerequisites

```bash
sudo pacman -S --needed docker docker-compose go pacman-contrib openssl arch-audit
sudo systemctl enable --now docker
```

Confirm Docker is available:

```bash
docker --version
docker compose version
checkupdates --help >/dev/null
arch-audit --version
```

### 2. Configure the server

From this project directory:

```bash
cp .env.example .env
openssl rand -hex 32
openssl rand -hex 32
```

Put the two different generated values into `.env` as `POSTGRES_PASSWORD` and `ADMIN_TOKEN`. Keep `FLEETVIEW_BIND_ADDRESS=127.0.0.1` for this same-machine test.

There is no enrollment secret to configure. You create a one-time enrollment token in the dashboard for each device you add, and each enrolled endpoint then receives its own agent credential. `ENROLLMENT_TOKEN` in `.env` is an optional legacy shared token; leave it out unless you need it.

### 3. Start the management server

```bash
sudo docker compose up -d --build
sudo docker compose ps
curl --fail http://127.0.0.1:8080/healthz
```

Expected health response:

```json
{"status":"ok"}
```

If startup fails:

```bash
sudo docker compose logs --tail=100 server db
```

### 4. Open the dashboard and create an enrollment token

Visit [http://127.0.0.1:8080](http://127.0.0.1:8080). The first visit asks for the `ADMIN_TOKEN` from `.env` exactly once, to create your administrator username and password; after that, sign in with those credentials like any other account. See **User accounts & roles** below.

To enroll this machine, open **Agent → Add a new device**, choose your Linux family, and click **Generate enrollment command**. The generated command contains a token that works for exactly one device and expires (one hour by default). It is shown only once, so copy it before leaving the page.

Open **Dashboard** for current fleet resource health. Select a device to view up to seven days of CPU, memory, disk, and network history plus current GPU data. Open **Patching** to run a patch scan, a vulnerability scan, or an approved system update. Open **Inventory** and select a device to inspect its details. The **Docker Containers** tab appears only when that endpoint reports a reachable Docker daemon. Open **Deploy** to install a package by name across one or more devices at once. Open **Reports** for a compliance summary or to build a custom fleet report. Open **Agent** to change collection intervals, toggle GPU or Docker collection, set a managed-uninstall code, or generate an enrollment command. Open **Admin** to pick an accent color, set fleet-wide default collection intervals, or see how the server's port and bind address are configured.

### Reports

Open **Reports** for a compliance-style summary of the fleet: the share of devices fully patched, the share with no critical or high vulnerabilities, how many are online right now, and how many are overdue for a scan (past twice their configured inventory interval), plus the same breakdown per platform (pacman/apt/winget). These summary cards are always fleet-wide, current-state figures. Below that, **Trends** charts those same figures (plus total vulnerability count) over time; pick **Entire fleet** or a single device from the scope selector, set a start/end UTC date (30 days by default, up to 3660 days back), and click **Apply date range**. Each device contributes at most one data point per UTC day — the first patch or vulnerability report the server receives from it that day, so later reports the same day don't shift the figure — so a day with no report for the selected scope is simply omitted, not treated as clean or offline; trends need devices to have been reporting for more than a day before there's anything to chart. Below that, the custom report builder lets you filter devices by platform, online status, and a hostname/OS search, choose which columns to include from the full device record (hostname, OS, patch and vulnerability counts, scan timestamps, and more), and click **Generate report** to preview the result. From there, **Download CSV** saves the exact filtered rows and columns as a spreadsheet, and **Print / Save as PDF** opens the browser's print dialog scoped to just the report table (choose "Save as PDF" as the destination to export a file). The compliance summary and custom report run entirely against data the dashboard already has loaded (no extra server round-trip); Trends is the one exception, fetching the selected date range of daily snapshots from the server.

### Software deployment

Open **Deploy**. The **Package catalog** panel is the normal way to deploy: save a package once — a name, optionally a description/version/category, and up to three platform identifiers (a pacman package name for Arch/CachyOS, an apt package name for Debian/Ubuntu, a winget package ID for Windows; set only the ones relevant to your fleet) — then tick devices in **Target devices** below and click **Deploy** or **Uninstall** on that package's row as many times as you like. Either button reviews a confirmation dialog naming every device and the identifier that will be used on it before queuing anything. Each device gets one `INSTALL_PACKAGE` or `UNINSTALL_PACKAGE` job with the identifier that matches its own platform, resolved automatically; a selected device whose platform has no identifier configured for that package is skipped, with the skip count called out in the confirmation message, rather than queuing a job that would just fail. Uninstall only removes the named package (no purge, autoremove, or recursive dependency removal), and needs a native agent upgraded to 0.12.0 or later. **Edit** and **Delete** manage catalog entries; deleting one doesn't touch jobs already queued from it. For a one-off install not worth saving to the catalog, **Deploy by name** below still works exactly as before: type a raw name/ID and it's used as-is for every selected device, so only select devices that share the platform the name is actually valid for. Either path queues jobs visible in both the Deploy tab's own **Recent deployments** table and the Patching tab's **Recent jobs** table. Each platform runs the package manager you'd expect — `pacman -Sy --noconfirm --needed <name>` / `pacman -R --noconfirm <name>`, `apt-get install -y <name>` / `apt-get -y remove <name>`, or `winget install`/`winget uninstall --id <name> --exact --silent`.

Under Deploy → **Upload an installer** (admin only), attach one to five files (8 MiB per file, 16 MiB combined), pick a target OS, and give a command; **Save package** stores the bundle. Tick a device of the matching platform in **Target devices** and click **Deploy** on that bundle's row — the confirmation names the files and the exact command before anything is queued. The agent verifies each file's size and SHA-256 against what the server recorded at upload time before running the command, so a bundle can't be tampered with in transit.

Patch installation is no longer a single "install everything" action. Open a device and go to its **Needed patches** tab: each pending package/version has its own **Not approved · approve** toggle — approving one does not install it yet, only marks that exact version as reviewed and ready. **Deploy approved patches** installs the currently-approved set on that device now; setting a non-zero **Automatic deployment interval (hours)** and saving the schedule instead lets the server queue the approved set itself the next time the device checks in (0 disables the schedule). Arch requires every pending package to be approved before a deployment runs, since pacman has no partial-upgrade mode; Debian re-simulates the exact approved versions with `apt-get --only-upgrade` immediately before installing and refuses to proceed if the real transaction would touch anything outside that set (a dependency bump, for example); Windows Update entries without a winget package ID are shown but can't be approved or deployed from here. Revoking an approval removes it from future deployments and cancels a matching job that's still queued, but can't stop one an agent has already claimed. This replaces the old unconfirmed **Install updates** action, which the server now rejects outright — approve, then deploy, is the only supported path — and requires a native agent on 0.14.0 or later.

A device's **Docker Containers** tab lists Start/Stop/Restart buttons next to each container once Docker inventory is enabled and the container has appeared in a scan (viewers can look but the buttons are disabled for them). Each click confirms the container name and action, then queues a job the agent runs directly against its local Docker Engine — the Unix socket on Linux, the Docker Desktop named pipe on Windows — rescanning afterward so the tab reflects the result. Requires a native agent on 0.15.0 or later.

A device shows **Online** whenever the server has heard from it (a report, heartbeat, metrics sample, or job poll) in the last two minutes, so a device you just stopped the agent on can still show online for up to two minutes before it flips to offline. Uninstalling the agent (`sudo fleetview-agent-uninstall`) only stops that endpoint from reporting; it deliberately keeps the device's server-side history. Re-enrolling a device (including reinstalling the agent) always creates a new device record, so you'll end up with a stale offline entry for the old one. Open a device's details and click **Remove device** to permanently delete a device you no longer want listed — this deletes its jobs and monitoring history and cannot be undone.

The agent reads Linux counters directly from `/proc` and `/sys` and reports one sample per minute. AMD and Intel GPU data is read from sysfs; NVIDIA data uses the already-installed `nvidia-smi`. Docker inventory uses the local Unix socket only during inventory scans and does not collect container resource metrics. The server retains seven days of host history by default.

The vulnerability scan runs `arch-audit --json` on Arch/CachyOS endpoints, which checks installed pacman packages against the Arch Security Team feed, or `debsecan --format summary --suite <codename>` on Debian endpoints, which checks installed dpkg packages against the Debian Security Tracker. Either way the scan sends normalized CVE findings to the server and does not modify the endpoint. The agent rejects scanner errors instead of reporting an inconclusive scan as clean. `debsecan` requires outbound HTTPS access from the endpoint to `security-tracker.debian.org` and only supports genuine Debian releases; it is not accurate on Ubuntu, whose package versions and security backports diverge from Debian's, so the vulnerability scan is disabled for Ubuntu endpoints until an Ubuntu-specific adapter (USN-based) is implemented.

Vulnerability scans don't have to be manual: open a device under **Agent**, set **Automatic vulnerability scan interval** in hours (0 disables it; disabled by default), and **Save scan schedule**. The server — not the agent — tracks each device's next-due time and queues the scan the next time that device polls for jobs, so nothing runs early, a device that's offline for a while doesn't accumulate a backlog of missed scans, and a scan already pending or running for a device suppresses a duplicate. Only Arch/CachyOS and genuine Debian endpoints can enable a schedule; the field stays disabled for Ubuntu and Windows. Disabling a schedule doesn't cancel a scan already queued.

Only click **Deploy approved patches** after checking that no local pacman process is running and the machine can remain powered on — on Arch this installs every currently pending, approved package at once, the same as `pacman -Syu`.

### Admin

Open **Admin** for dashboard and fleet-wide settings that don't belong to any one device. **User management** (admin only; see **User accounts & roles** below) creates and edits accounts. **Dashboard theme** picks one of five complete color themes; it's saved in this browser's `localStorage`, so it's a per-browser preference, not shared with other people who open the dashboard. **Fleet defaults** sets the monitoring and inventory intervals new (or never-customized) devices use — any device that already has its own interval set from the **Agent** page keeps that override regardless of what the fleet default is changed to. **Network** is informational only: the dashboard/API port and bind address (`FLEETVIEW_BIND_ADDRESS`/`FLEETVIEW_PORT` in `.env`) are Docker Compose settings applied before the server process starts, so the running server has no way to read or change them itself — there's nothing to save here, just the exact `.env` keys to edit and the `./scripts/check-access.sh` command to confirm what's actually published.

### User accounts & roles

The dashboard uses username/password accounts with server-side sessions instead of a shared admin token for everyday use. The very first visit to a fresh install still asks for the `ADMIN_TOKEN` from `.env`, but only once — to create the first administrator — and `X-Admin-Token` cannot authorize dashboard/API access ever again after that account exists.

Three fleet-wide roles, checked on every request server-side (the UI also hides actions a role can't use, but that's a convenience, not the actual boundary):

- **Viewer** — read-only: fleet inventory, monitoring, jobs, the package catalog, and reports.
- **Operator** — viewer, plus queuing scan/patch/package jobs, editing the package catalog, and setting scan schedules.
- **Admin** — everything: device removal/settings, enrollment tokens, fleet defaults, and user management.

Under **Admin → User management**, an admin creates a user with a temporary password (12–128 characters) and a role; that user must change their password at their next sign-in. Roles apply fleet-wide — there's no per-device or per-group access control, and no SSO/MFA. Disabling an account, changing its role, or resetting its password immediately signs out that user's existing sessions. The last enabled admin account can't be disabled or demoted, so you can't lock yourself out entirely. Every account change is written to an audit log visible at the bottom of the same page.

Sessions last 12 hours and survive an ordinary server restart. Cookies are `HttpOnly` and `SameSite=Strict`, writes require a CSRF token issued at login, and failed sign-in attempts are throttled per account and per source address. Passwords are hashed with PBKDF2-SHA256 (600,000 iterations, a random salt per password) — never stored or logged in plaintext. On plain LAN HTTP the cookie is not marked `Secure` (browsers would otherwise refuse to send it); if you terminate TLS at a reverse proxy that forwards plain HTTP to this container, set `FLEETVIEW_COOKIE_SECURE=true` in `.env` so the cookie is marked `Secure` even though the app itself sees HTTP — see the comment in `.env.example`.

If every admin password is lost, recover locally on the Docker host (this does not expose any remote bypass):

```bash
sudo docker compose exec server python -m app.manage_users YOUR_ADMIN_USERNAME
```

This prompts for a new password (hidden input), re-enables the account if it was disabled, and revokes its existing sessions.

### 5. Install and enroll the local agent

Run the command generated in step 4 as-is, or use the helper script with just the token (the value after the last space in the generated command):

```bash
chmod +x scripts/install-agent.sh
./scripts/install-agent.sh http://127.0.0.1:8080 'PASTE_THE_ONE_TIME_TOKEN'
```

Inspect the service:

```bash
systemctl status fleetview-agent --no-pager
sudo journalctl -u fleetview-agent -n 100 --no-pager
```

The initial inventory scan can take a little while because `checkupdates` downloads a temporary repository database without altering the host's active pacman database.

The one-time token is spent as soon as the agent enrolls. The per-device credential in `/var/lib/fleetview-agent/state.json` is used from then on. For tidiness you can remove the spent token from the endpoint configuration:

```bash
sudo sed -i '/^FLEETVIEW_ENROLLMENT_TOKEN=/d' /etc/fleetview-agent/agent.env
sudo systemctl restart fleetview-agent
```

## Upgrade an existing installation

### Upgrading to 0.14.0 or 0.15.0

These two releases are server *and* agent changes: patch approvals/schedules and custom installer uploads (0.14.0) need agents on 0.14.0+, and Docker container controls (0.15.0) need agents on 0.15.0+. An older agent keeps reporting ordinary inventory, but the server refuses to queue the new job types for it until it reports a new-enough version.

Run the server upgrade exactly as in **Upgrading to 0.12.0 or 0.13.0** above (`scripts/upgrade-server-in-place.sh <your compose directory>`), then upgrade each native agent in place — this replaces the binary while preserving its existing service, configuration, and enrollment, so devices don't need to re-enroll:

```bash
# on each Linux endpoint, from the extracted release directory
bash scripts/upgrade-agent-in-place.sh
```

```powershell
# on each Windows endpoint, from an elevated PowerShell prompt in the extracted release directory
.\scripts\upgrade-agent-in-place.ps1
```

Both scripts need the same Go toolchain used for the initial agent build, and build+restart the existing service rather than reinstalling it. After an agent restarts, run a Patch scan (or wait for its next scheduled one) so the server sees its new version and unlocks the new controls for that device. Full step-by-step detail, including exact paths, is in [`docs/RELEASE-0.14.0.md`](docs/RELEASE-0.14.0.md) and [`docs/RELEASE-0.15.0.md`](docs/RELEASE-0.15.0.md).

0.14.0 adds `patch_approvals`, `patch_schedules`, `custom_packages`, and `custom_package_files` tables, all created automatically on startup and empty until you use the new Patching/Deploy features; the last one stores uploaded installer file contents, so factor that into your PostgreSQL backup size and cadence.

### Upgrading to 0.12.0 or 0.13.0

The current, recommended way to upgrade an existing Docker install is `scripts/upgrade-server-in-place.sh`, which only touches the server: it backs up the database (`pg_dump`) and the current source/config directory, copies in the new `server/`, `agent/`, `scripts/`, and `docs/` folders, then rebuilds and restarts only the `server` container — your Compose project, `.env`, PostgreSQL volume, and already-enrolled native agents are untouched.

```bash
release_dir=$(mktemp -d)
unzip -q "$HOME/Downloads/FleetView-0.13.0.zip" -d "$release_dir"
bash "$release_dir"/*/scripts/upgrade-server-in-place.sh /containers/fleetview
```

Replace `/containers/fleetview` with wherever your Compose project actually lives if it differs. The script refuses to run without an existing `.env` and Compose file (so it won't create a fresh install by accident), and refuses to run from inside the extracted release directory itself. After it finishes, refresh the browser and sign in — see **User accounts & roles** above for what first sign-in looks like on 0.13.0. Existing native agents don't need reinstalling for 0.13.0 (server-only release); for 0.12.0's package-uninstall feature, upgrade agents with the usual `scripts/upgrade-agent.sh` per endpoint first. For a permanent-VM cutover instead of an in-place upgrade, see [`docs/VM-MIGRATION.md`](docs/VM-MIGRATION.md); full per-version detail also lives in [`docs/RELEASE-0.12.0.md`](docs/RELEASE-0.12.0.md) and [`docs/RELEASE-0.13.0.md`](docs/RELEASE-0.13.0.md).

Version 0.12.0 adds a `vulnerability_schedules` table (scan-interval settings per device) and 0.13.0 adds the accounts tables (`users`, `user_sessions`, `login_throttles`, `account_audit`, `auth_control`) — all created automatically on startup, all empty/inert until you use the features that populate them, and none of them touch or remove existing data.

### Upgrading from before 0.12.0

Extract the new archive over `/containers/fleetview`. The archive does not contain `.env`, and `docker compose down` does not remove the PostgreSQL volume, so the existing secrets, enrollment, and data are retained.

```bash
cd /containers/fleetview
sudo docker compose down
sudo tar -xzf "$HOME/Downloads/fleetview-mvp-0.8.0.tar.gz" -C /containers
sudo chown -R "$(id -u):$(id -g)" /containers/fleetview

cd /containers/fleetview
sudo pacman -S --needed arch-audit
sudo docker compose build --no-cache server
sudo docker compose up -d
chmod +x scripts/upgrade-agent.sh
./scripts/upgrade-agent.sh
```

### Upgrading to 0.8.0 (the FleetView rename)

This release renames the project from "EPC Replacement" to FleetView, which touches the Docker volume name, the agent binary/service, install paths, and the `EPC_*` environment variables. Two things need manual attention; everything else is automatic:

1. **Rename the Postgres volume before `docker compose up -d`**, or Compose will create a new, empty `fleetview-postgres` volume and your existing data will look like it vanished (it hasn't — it's still in the old `epc-postgres` volume, just not attached anymore):
   ```bash
   docker volume create fleetview-postgres
   docker run --rm -v epc-postgres:/from -v fleetview-postgres:/to alpine sh -c "cp -a /from/. /to/"
   ```
   Verify the copy (`docker run --rm -v fleetview-postgres:/data alpine ls /data` should show Postgres's data files) before removing the old volume with `docker volume rm epc-postgres`.
2. **Rename `EPC_BIND_ADDRESS`/`EPC_PORT` to `FLEETVIEW_BIND_ADDRESS`/`FLEETVIEW_PORT` in `.env`** at your convenience — `docker-compose.yml` still falls back to the old names if you don't get to it right away, so this isn't urgent.

Running `scripts/upgrade-agent.sh` on an endpoint that still has the old `epc-agent` install migrates it automatically: it stops and removes the old systemd service, moves `/etc/epc-agent` and `/var/lib/epc-agent` to `/etc/fleetview-agent`/`/var/lib/fleetview-agent`, and installs the agent under its new binary and service name — the endpoint's enrollment is untouched. The agent binary also still reads `EPC_`-prefixed variable names in `agent.env` as a fallback, so an endpoint isn't broken if you haven't rewritten its config file yet.

This release adds an `enrollment_tokens` table, which the server creates automatically on startup; existing tables and data are untouched, and already-enrolled agents keep working. If your `.env` still has `ENROLLMENT_TOKEN`, the old shared token keeps working. Once you are using per-device tokens you can delete that line so only one-time tokens are accepted.

Version 0.9.0 adds a `compliance_snapshots` table for Reports' Trends charts, also created automatically on startup. It starts empty and fills in as devices report, so Trends has nothing to show until devices have reported on more than one UTC day after upgrading — this is expected, not an error.

Version 0.10.0 adds a `fleet_settings` table (a single row of fleet-wide defaults for the new Admin tab), created automatically on startup with the same interval defaults (60s/900s) every device already used, so nothing changes for existing devices until you deliberately change the fleet defaults from **Admin**.

Version 0.11.0 adds a `packages` table for the Deploy tab's package catalog, created automatically on startup and empty until you save packages to it. It has no effect on **Deploy by name**, which still works exactly as it did before this table existed.

Version 0.5.1 adds `debsecan`-based vulnerability scanning for Debian endpoints and fixes the APT patch scan so it refreshes the package cache before checking for upgradable packages. Debian endpoints need `debsecan` installed before you re-run `scripts/upgrade-agent.sh` on them (`sudo apt-get install debsecan`); the script now checks for it and fails with a clear message if it's missing.

Confirm both components:

```bash
curl --fail http://127.0.0.1:8080/healthz
sudo docker compose ps
sudo journalctl -u fleetview-agent -n 50 --no-pager
```

Open `http://127.0.0.1:8080/?v=0.15.0` once after upgrading. GPU data appears after the next telemetry interval. Run a device scan once to populate the Docker Containers tab immediately.

## Add another Linux device

The server must be reachable from that endpoint. For a temporary LAN test, set `FLEETVIEW_BIND_ADDRESS=0.0.0.0` in the server `.env`, restart the Compose stack, and restrict TCP 8080 to the trusted LAN (binding to a specific LAN address is more reliable than a host firewall alone; see the note under **Network exposure**). HTTPS through Traefik is the preferred long-term setup.

Open **Agent → Add a new device**, choose the platform, confirm the management URL is one the endpoint can reach, optionally name the device, choose how long the token stays valid, and click **Generate enrollment command**. Copy the command to the endpoint. Arch/CachyOS, Debian, and Ubuntu each get a one-line remote installer; Windows gets a PowerShell command (see **Windows** below). Each token enrolls exactly one device, then stops working. The command (and so the token) can appear in shell history, which is harmless once the token is spent; revoke any unused token from **Enrollment tokens** on the same page.

The managed uninstaller is:

```bash
sudo fleetview-agent-uninstall
```

When configured, it verifies the code with the server before removing the service. This is an operator safety control, not protection against a local root user, who can always remove system files directly.

## Windows

Windows support is new and has not been run against real Windows hardware yet — expect rough edges. Unlike the Linux platforms, there's no one-line remote installer yet; on the Windows endpoint you need either a `git clone` of this project or the source bundle from the same **Add a new device** page's download link (extract it with the built-in `tar` command), plus [Go](https://go.dev/dl/) and `winget` (the **App Installer** package from the Microsoft Store; present by default on current Windows 10/11).

From an elevated PowerShell prompt in that checkout, run the command the dashboard generates:

```powershell
.\scripts\install-agent.ps1 -ServerUrl 'http://192.168.1.50:8080' -EnrollmentToken 'PASTE_THE_ONE_TIME_TOKEN'
```

This builds the agent, writes its configuration to `%ProgramData%\fleetview-agent\agent.env`, and registers + starts it as a Windows service (`fleetview-agent.exe -service install` under the hood). Follow it with:

```powershell
Get-Content "$env:ProgramData\fleetview-agent\agent.log" -Tail 50 -Wait
```

To remove it:

```powershell
.\scripts\uninstall-agent.ps1
```

What works: CPU/memory/disk/network/uptime telemetry, OS/hardware inventory, GPU monitoring via `nvidia-smi` (AMD/Intel is not implemented on Windows), Docker Desktop container inventory, and patch data from both `winget upgrade` and pending Windows Update security patches (reported, not yet installable — **Install updates** only runs `winget upgrade --all`). What doesn't: vulnerability scanning (no CVE-mapped data source exists for Windows yet, so the **Vulnerability scan** button stays disabled for these devices, the same as Ubuntu).

## Operations

Follow the server logs:

```bash
sudo docker compose logs -f server
```

Follow agent jobs:

```bash
sudo journalctl -u fleetview-agent -f
```

Restart components:

```bash
sudo docker compose restart server
sudo systemctl restart fleetview-agent
```

Stop the server without deleting its PostgreSQL data:

```bash
sudo docker compose down
```

### Re-enroll this endpoint

Re-enrollment creates a new device identity. Stop the agent and preserve the old state until you are sure you want a new record:

```bash
sudo systemctl stop fleetview-agent
sudo mv /var/lib/fleetview-agent/state.json /var/lib/fleetview-agent/state.json.backup
sudo systemctl start fleetview-agent
```

The enrollment token must still be present in `/etc/fleetview-agent/agent.env`.

## Network exposure

Version 0.6.0 defaults to `127.0.0.1:8080`, which is suitable for the server and agent running on the same machine. Never expose port 8080 directly to the internet.

Before adding remote endpoints, place the server behind Traefik with HTTPS, use a firewall allowlist where practical, and change every bootstrap/admin secret. Set `FLEETVIEW_SERVER_URL` on agents to the HTTPS URL. Keep `FLEETVIEW_ALLOW_INSECURE_TLS=false`.

### Can't reach the dashboard from another machine?

`127.0.0.1` means "this machine only". If Docker runs in a VM, on a server, or in another container host, a browser on a different machine (such as the VM's host) cannot use that address. Run the read-only diagnostic on the Docker machine:

```bash
./scripts/check-access.sh
```

Then, to make the dashboard reachable:

1. Find the Docker machine's address, for example `ip -4 addr show scope global`.
2. In `.env`, set `FLEETVIEW_BIND_ADDRESS` to that address (preferred) or to `0.0.0.0` on a trusted network.
3. Apply it with `sudo docker compose up -d`.
4. From the other machine, check `curl http://<address>:8080/healthz` and browse to `http://<address>:8080`.

Agents follow the same rule. An agent on the Docker machine can keep `FLEETVIEW_SERVER_URL=http://127.0.0.1:8080`. An agent on any other machine must use the address from step 1, for example `FLEETVIEW_SERVER_URL=http://192.168.1.50:8080`. Browse the dashboard using that same address and the **Agent → Add a new device** page will prefill it correctly.

Docker inserts its own firewall rules for published ports, so host rules such as `ufw deny 8080` may not restrict them. Binding to one specific interface address is a more reliable restriction than a host firewall alone.

## Current limitations

- Arch/CachyOS, Debian/Ubuntu, and Windows inventory and patching are supported; see **Windows** above for what's different there (early, unverified on real hardware, no CVE-mapped vulnerability scanning, no one-line remote installer yet).
- Vulnerability scanning currently covers installed official Arch packages reported by the Arch Security Team, and installed Debian packages reported by the Debian Security Tracker. CachyOS-specific repository packages, AUR packages, Ubuntu packages (see below), application dependencies, container images, and configuration scanning are not covered.
- Vulnerability scans can run on a per-device automatic schedule (Arch/CachyOS and genuine Debian only) or be requested manually at any time; there's no fleet-wide default schedule, and scheduling depends on the agent's own job-poll interval rather than a server-side cron.
- GPU readings are current-state only in this release; GPU history, container statistics, SMART data, alert delivery, and service checks are not implemented yet.
- Reports trends use daily snapshots (one per device per UTC day, retained indefinitely); the fleet or a single device and a custom UTC date range (up to 3660 days) are both supported, but there's no scheduled/emailed report delivery yet.
- Vulnerability scanning is enabled for pacman endpoints through `arch-audit` and Debian endpoints through `debsecan`. Ubuntu's package versions diverge from Debian's, so `debsecan` results would be unreliable there; the vulnerability scan stays disabled for Ubuntu until a USN-based adapter is implemented. Windows has no vulnerability scanner at all yet — there's no free CVE-mapped feed for arbitrary Windows software the way arch-audit/debsecan cover their distros; the closest available signal (pending Windows Update security patches) is reported as patch data instead, not as CVE findings.
- `debsecan` only reports whether a fix is available in the target suite, not the fixed package version, so findings from Debian endpoints leave the fixed-version field blank.
- Arch repositories do not provide a normalized security-update flag, so security counts remain zero rather than being guessed.
- Updates are all-or-nothing system upgrades; package selection and exclusions are not implemented.
- The package catalog has no bulk import/export or scheduled/recurring deployment — each Deploy or Uninstall click queues a one-time job for the devices selected at that moment.
- Accounts have fleet-wide roles only; there's no per-device or per-group access control, no SSO, and no MFA.
- Database migrations, agent auto-update, maintenance windows, retries for interrupted jobs, and policy scheduling are not implemented yet.
- A job claimed by an agent and interrupted before completion remains `running`; automatic lease recovery is a later milestone.
- Enrollment tokens are single-use. If a device enrolls but its response is lost before the agent saves its credential, that token is spent; generate a new token and re-run the installer.

These constraints are deliberate for the current MVP. The stable server protocol receives normalized inventory, update, and vulnerability records, while platform-specific agent adapters handle package discovery, patching, and advisory sources. This keeps endpoints small and allows Debian/Ubuntu and Windows support without changing the dashboard's device/job model.

## Project layout

```text
agent/                 Go endpoint agent
  cmd/fleetview-agent/       executable entry point
  internal/            inventory, pacman, API, and configuration modules
  packaging/           systemd unit and example environment file
server/                FastAPI service and embedded dashboard
  app/accounts.py      account/session API (login, setup, user management)
  app/manage_users.py  local admin-recovery console command
scripts/               local installation and upgrade helpers
docs/                  per-release upgrade notes and the VM migration guide
docker-compose.yml     server and PostgreSQL deployment
```

## Development checks

```bash
python3 -m py_compile server/app/*.py
node --check server/app/static/app.js
cd agent && go test ./...
```

`server/tests/ui_dom_test.cjs` is a jsdom-based smoke test of the dashboard's own JS (report filters, scan-schedule saving, uninstall confirm/cancel) without a real browser — useful as a fast sanity check, but not a substitute for testing in one. It needs `jsdom` installed locally (`npm install jsdom` in a scratch directory is enough; nothing is added to this repo for it), then:

```bash
node server/tests/ui_dom_test.cjs
```

`make test` runs the unit tests. The tests that exercise the enrollment endpoints, and `server/tests/test_accounts.py`/`test_fleet_features.py`, need the server dependencies (including `httpx`, used by `fastapi.testclient.TestClient`) and are skipped when those are not installed on the host. To run all of them inside the server image without touching your real database:

```bash
sudo docker compose run --rm --no-deps -v "$PWD/server/tests:/app/tests:ro" server python -m unittest discover -s /app/tests -v
```

Interactive API documentation is available at `http://127.0.0.1:8080/api/docs` while the server is running.
