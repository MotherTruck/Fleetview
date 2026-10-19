# Setting up a new FleetView server on Debian

This is a **fresh install on a new machine**, not an upgrade — it does not
touch any existing deployment. It targets Debian 12 (bookworm) or newer.
Everything server-side runs in Docker against a published image, so the
only genuinely Debian-specific step is installing Docker itself.

## 1. Install Docker

Debian's bundled `docker.io` package doesn't ship the `docker compose`
plugin (Compose v2) this project's `docker-compose.yml` expects, so this
uses Docker's own apt repository instead:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
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

Confirm it's available:

```bash
docker --version
docker compose version
```

Optional: to run `docker`/`docker compose` without `sudo`, add your user to
the `docker` group and start a new shell session (`sudo usermod -aG docker
"$USER"`, then log out and back in — group membership doesn't apply
mid-session).

## 2. Install FleetView

This machine is a dedicated server reached from other machines on your
network, not a same-box test. `docker-compose.yml` already reaches other
devices on your network out of the box (over plain HTTP); for an encrypted
option instead, use the TLS profile (see [`docs/TLS.md`](TLS.md)). Beyond
that, setup here is identical
to every other distro: see **1. Run the server** in the main
[README](../README.md), including the one-command installer
(`scripts/install-server.sh`) that fetches `docker-compose.yml`, fills in
fresh random secrets directly in it, and starts everything.

## Next steps

Everything from here on — Reports, Software deployment, patch approvals and
scheduling, the custom installer upload, Docker container controls, Admin
settings, enrolling devices — works identically regardless of host distro;
see the main [README](../README.md) for all of it. To upgrade this install
later, run `scripts/upgrade-server-in-place.sh` — it backs up the database,
pulls the latest published image, and recreates the server container, with
no source checkout needed.
