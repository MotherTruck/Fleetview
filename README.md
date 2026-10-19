# FleetView

A self-hosted dashboard for inventory, patching, and remote management of your own devices. The server runs in Docker; a small agent runs on each device you want to manage.

Supported devices: Arch Linux/CachyOS, Debian/Ubuntu, Windows, and OPNsense/FreeBSD.

## 1. Run the server

On the machine that will host FleetView, with [Docker](https://docs.docker.com/engine/install/) installed:

```bash
mkdir fleetview && cd fleetview
curl -fsSL https://raw.githubusercontent.com/mothertruck/fleetview/main/scripts/install-server.sh | bash
```

That's the whole install: it fetches `docker-compose.yml`, fills in fresh
random secrets directly in it, pulls the image, starts it, and prints your
admin token and the dashboard URL when it's up. Safe to re-run later too —
an existing `docker-compose.yml` (and its secrets) is always left
untouched.

Only reachable from this machine by default. To reach it from other devices
on your network, see **Reaching it from other devices** below.

<details>
<summary>Prefer to see exactly what's happening, or the script doesn't fit
your setup? Expand for the manual steps it automates.</summary>

```bash
mkdir fleetview && cd fleetview
curl -fsSLO https://raw.githubusercontent.com/mothertruck/fleetview/main/docker-compose.yml
```

Open `docker-compose.yml` and replace `POSTGRES_PASSWORD` and `ADMIN_TOKEN`
near the top with your own values (the file tells you how):

```bash
openssl rand -hex 32   # run twice -- one value for each; the server refuses to start if either is left at its placeholder
```

Then start it:

```bash
docker compose pull
docker compose up -d
curl --fail http://127.0.0.1:8080/healthz
```

</details>

## 2. Sign in

Open `http://127.0.0.1:8080` (or whatever address you bound it to). The first visit asks for the `ADMIN_TOKEN` from `docker-compose.yml`, once, to create your admin username and password. After that, sign in normally.

## 3. Add a device

In the dashboard: **Agent → Add a new device**, pick its platform, and click **Generate enrollment command**. It's a one-time command, valid for an hour.

**Linux (Arch/CachyOS, Debian, Ubuntu):** copy the generated one-line command and run it on the device.

**OPNsense/FreeBSD:** copy the generated one-line command and run it as root from the OPNsense console or an SSH session — it downloads a prebuilt agent binary (no Go toolchain needed on the firewall itself) and starts it as an rc.d service. "Remote control" for an OPNsense device opens its own web GUI instead of a screen session.

**Windows:** install [Go](https://go.dev/dl/) and make sure `winget` is available (the **App Installer** package, present by default on current Windows 10/11), then from an elevated PowerShell prompt:

```powershell
.\scripts\install-agent.ps1 -ServerUrl 'http://YOUR_SERVER_ADDRESS:8080' -EnrollmentToken 'PASTE_THE_ONE_TIME_TOKEN'
```

That's it — the device shows up in **Inventory** once it checks in.

To remove an agent later: `sudo fleetview-agent-uninstall` (Linux/OPNsense) or `.\scripts\uninstall-agent.ps1` (Windows).

## Reaching it from other devices

`127.0.0.1` only works from the same machine. Once you open the dashboard to
the rest of your network, everything that crosses it — your admin session
cookie, every agent's credentials, the patch/command jobs you run, the
inventory data agents report — is worth protecting, because anyone else on
that network can otherwise read or tamper with it in transit.

**Recommended: enable TLS first, then point agents at the HTTPS address.**
The install scripts require a pinned CA fingerprint for an `https://`
server URL (not just trust-on-first-use) — see [`docs/TLS.md`](docs/TLS.md)
for the full walkthrough, or the short version:

1. In `docker-compose.yml`, change `FLEETVIEW_TLS_HOSTNAME:-` to
   `FLEETVIEW_TLS_HOSTNAME:-192.168.1.50` (your LAN address or hostname) and
   `FLEETVIEW_COOKIE_SECURE:-false` to `FLEETVIEW_COOKIE_SECURE:-true` — or
   set `FLEETVIEW_TLS_HOSTNAME=...` and `FLEETVIEW_COOKIE_SECURE=true` in a
   `.env` file instead, if you'd rather leave `docker-compose.yml` untouched
   for these. Either works.
2. `sudo docker compose --profile tls up -d`
3. Get the CA's fingerprint (`docs/TLS.md` step 2) — a couple of one-line commands.
4. Open `https://<FLEETVIEW_TLS_HOSTNAME>:8443` and use that same
   `https://...:8443` address, plus the fingerprint, when enrolling every agent.

**Plain HTTP instead, only if you understand the tradeoff** (e.g. a LAN you
already fully trust and control): near the top of `docker-compose.yml`,
change `DASHBOARD_ADDRESS`'s `"127.0.0.1:8080:8080"` to this machine's LAN
address (or `0.0.0.0`) instead of touching the TLS settings above, e.g.
`"0.0.0.0:8080:8080"`, then `sudo docker compose up -d` and point agents at
that address. The agent itself still refuses to enroll against a plain
`http://` URL that isn't loopback unless you also set
`FLEETVIEW_ALLOW_PLAINTEXT=true` in its config — a deliberate, explicit
opt-in, not a silent default.

Either way, never expose the server directly to the internet without HTTPS in front of it.

## Everyday operations

```bash
docker compose logs -f server           # server logs
docker compose restart server           # restart the server
docker compose down                     # stop the server (keeps your data)
docker compose pull && docker compose up -d   # update to the latest published version
```

Or `scripts/upgrade-server-in-place.sh` to do the same pull-and-recreate with a database backup taken first.

```bash
sudo journalctl -u fleetview-agent -f        # agent logs (Linux)
sudo systemctl restart fleetview-agent       # restart agent (Linux)
```

## More detail

[`docs/`](docs/) covers specific features in depth: live monitoring and the remote terminal/screen ([`LIVE.md`](docs/LIVE.md)), network diagnostics and Wake-on-LAN ([`NETWORKING.md`](docs/NETWORKING.md)), Proxmox/OPNsense integrations ([`INTEGRATIONS.md`](docs/INTEGRATIONS.md)), and HTTPS setup ([`TLS.md`](docs/TLS.md)).
