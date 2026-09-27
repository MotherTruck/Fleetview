# Setting up a new FleetView server on Debian

This is a **fresh install on a new machine**, not an upgrade — it does not
touch any existing deployment. It targets Debian 12 (bookworm) or newer.
Everything server-side runs in Docker, so the only genuinely Debian-specific
step is installing Docker itself; steps 3 onward are the same commands as
the CachyOS walkthrough in the main [README](../README.md#building-from-source-instead).

If you just want to *run* the server rather than build or develop it here,
skip straight to [**Quick start: deploy the server from a published
image**](../README.md#quick-start-deploy-the-server-from-a-published-image)
in the main README instead — it only needs Docker itself, no git/Go/source
checkout at all, and covers exactly step 1's Docker install plus steps 3-5
below in one shorter path. The rest of this guide is for building the image
locally (for example, to test an unreleased change) or if you'd rather have
the full source on this machine for any other reason.

## 1. Install prerequisites

Docker's own apt repository is used instead of Debian's bundled `docker.io`
package, because it ships the `docker compose` plugin (Compose v2) this
project's `docker-compose.yml` expects:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg git openssl
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

Confirm Docker is available:

```bash
docker --version
docker compose version
```

Optional: to run `docker`/`docker compose` without `sudo`, add your user to
the `docker` group and start a new shell session (`sudo usermod -aG docker
"$USER"`, then log out and back in — group membership doesn't apply
mid-session). The commands below use `sudo docker compose` throughout so
they work either way.

## 2. Get the source onto this machine

```bash
git clone <this repository's URL> /opt/fleetview
cd /opt/fleetview
```

Check out whichever branch or tag you consider the release to run (`main`
for the latest). If the repository is private, use the clone URL/credentials
you'd normally use for it (SSH, or an HTTPS URL with a personal access
token).

## 3. Configure the server

```bash
cp .env.example .env
openssl rand -hex 32
openssl rand -hex 32
```

Put the two different generated values into `.env` as `POSTGRES_PASSWORD`
and `ADMIN_TOKEN`.

This machine is a dedicated server reached from other machines on your
network, not a same-box test, so `FLEETVIEW_BIND_ADDRESS` almost certainly
needs to be this machine's actual LAN address rather than the
`127.0.0.1` default — otherwise nothing outside the box itself can reach
the dashboard or the API agents talk to. Find the address with `ip -4 addr
show scope global`, then set it in `.env`, for example:

```bash
FLEETVIEW_BIND_ADDRESS=192.168.1.50
FLEETVIEW_PORT=8080
```

The server speaks plain HTTP and the admin token can trigger patch jobs, so
treat that address as trusted-LAN-only for now. See **Network exposure** and
**Can't reach the dashboard from another machine?** in the main README for
the general version of this, and put the server behind a reverse proxy with
HTTPS (`FLEETVIEW_COOKIE_SECURE=true` in `.env` once you do) before this
machine is reachable from anywhere you wouldn't also trust with the admin
token.

There is no enrollment secret to configure ahead of time — you create a
one-time enrollment token per device from the dashboard after it's up.
Leave `ENROLLMENT_TOKEN` commented out unless you specifically want the
legacy shared-token workflow.

## 4. Start the management server

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

## 5. Open the dashboard and create the first administrator

From a browser that can reach `FLEETVIEW_BIND_ADDRESS:FLEETVIEW_PORT` (for
example `http://192.168.1.50:8080`), the first visit asks for the
`ADMIN_TOKEN` from `.env` exactly once, to create your administrator
username and password. After that, sign in with those credentials — the
token stops working for authentication once that account exists. See
**User accounts & roles** in the main README for the full role model.

## 6. Enroll devices

Open **Agent → Add a new device** in the dashboard, pick the endpoint's
platform, confirm the management URL is one that endpoint can actually
reach, and click **Generate enrollment command**. Arch/CachyOS, Debian, and
Ubuntu endpoints get a one-line remote installer; Windows gets a PowerShell
command. See **Windows** and **Adding a Linux device** in the main
README for the platform-specific details.

If you also want to enroll this Debian server itself as a monitored
endpoint (not required — it's fine for a machine to just run the server
container and nothing else), it needs the same Debian/Ubuntu agent
prerequisites as any other Debian endpoint: a Go toolchain to build the
small native agent, and `debsecan` for vulnerability scanning
(`sudo apt-get install -y golang-go debsecan`). Then generate a token for it
from the dashboard and run the generated one-line installer on this same
machine — enrolling the server host as a device is independent of the
server container itself and works the same as any other Debian box.

## Next steps

Everything from here on — Reports, Software deployment, patch approvals and
scheduling, the custom installer upload, Docker container controls, Admin
settings — works identically regardless of host distro; see the main
[README](../README.md) for all of it. For upgrading this install to a later
FleetView release once one ships, use `scripts/upgrade-server-in-place.sh`
exactly as documented under **Operations** in the README — that script and
the in-place agent upgrade scripts are themselves plain bash/PowerShell and
don't care which distro the server runs on either.
