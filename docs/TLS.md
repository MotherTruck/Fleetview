# Encrypting agent↔server traffic

By default the server speaks plain HTTP, which is fine for the same machine
or a trusted LAN but means anything on the network path — patch/command
jobs, agent credentials, inventory data — travels in clear text. This adds
TLS in front of the server using [Caddy](https://caddyserver.com/), which
mints its own private certificate authority and a leaf certificate for
whatever LAN IP or hostname you configure, since a public CA like Let's
Encrypt will not issue a certificate for a private IP address or an
unresolvable internal hostname at all — the normal way this dashboard is
actually reached.

This is a fresh capability, not a migration: it's off by default (a
[Compose profile](https://docs.docker.com/compose/how-tos/profiles/)) and
existing plain-HTTP installs are unaffected until you opt in.

## 1. Enable the profile

Set the LAN IP or hostname you actually connect with — Caddy issues its
certificate for exactly this value, so it needs to match what's in your
browser's address bar and each agent's `FLEETVIEW_SERVER_URL`. Either edit
the defaults directly in `docker-compose.yml`:

```
FLEETVIEW_TLS_HOSTNAME:-192.168.1.50
FLEETVIEW_COOKIE_SECURE:-true
```

or, if you'd rather leave `docker-compose.yml` untouched, put these in a
`.env` file in the same directory instead (Compose reads it automatically):

```bash
FLEETVIEW_TLS_HOSTNAME=192.168.1.50
FLEETVIEW_COOKIE_SECURE=true
```

Then bring the stack up with the `tls` profile:

```bash
sudo docker compose --profile tls up -d
```

This starts a `caddy` container alongside the existing `db`/`server`
containers, publishing HTTPS on port 8443 (`FLEETVIEW_TLS_PORT` to change
it) and reverse-proxying to the existing plain-HTTP `server` container over
Docker's internal network — the `server` container itself is unchanged and
still also reachable on its own plain-HTTP port unless you stop publishing
that separately. Open `https://<FLEETVIEW_TLS_HOSTNAME>:8443` in a browser;
the first visit will show a certificate warning, since it's a private CA
your browser doesn't already trust (see step 3 to fix that, or just accept
the warning once for a quick test).

## 2. Get the CA's fingerprint (required for install, and for your browser)

Caddy's certificate is signed by a private CA it generates on first start,
stored in the `fleetview-caddy-data` volume — not a certificate your
system's trust store or browser already knows about, and not one the
install scripts will blindly trust either: both
`scripts/remote-install-linux.sh` and `scripts/install-agent.ps1` *require*
a pinned fingerprint for an `https://` server URL and refuse to install
without one. This is deliberate: fetching `/install/ca.crt` and trusting
whatever comes back (trust-on-first-use) is exactly what an attacker who
controls that one first connection defeats — they substitute their own CA,
the installer trusts it, and the agent is theirs from the very first
request. Pinning closes that: the fetched CA is verified against a
fingerprint you already obtained from a channel you trust, before
anything else happens.

Extract the CA once:

```bash
sudo docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./fleetview-ca.crt
```

If that path doesn't exist (Caddy's image has changed it), find the real one first:

```bash
sudo docker compose exec caddy find /data -name root.crt
```

Compute its SHA-256 fingerprint, from the machine running `docker compose`
(not the endpoint being enrolled):

```bash
openssl x509 -in fleetview-ca.crt -noout -fingerprint -sha256
# SHA256 Fingerprint=14:4D:10:AA:FA:64:29:74:FE:39:0A:6E:68:52:16:27:...
```

**For your browser**, import `fleetview-ca.crt` into your OS or browser's
trust store as a trusted root — this removes the certificate warning and
gives a clean padlock.

## 3. Point agents at the HTTPS URL, with the pinned fingerprint

On **Agent → Add a new device**, set the management server URL to
`https://<FLEETVIEW_TLS_HOSTNAME>:8443` instead of the plain-HTTP address,
then generate the install command as usual, adding the fingerprint hex from
step 2 (colons or not, case-insensitive — both installers normalize it
either way):

```bash
curl -fsSL https://<host>:8443/install/linux.sh | sudo bash -s -- \
  https://<host>:8443 <enrollment-token> 144D10AAFA642974FE390A6E68521627E815F978B589DE32535C36EA30DC6503
```

```powershell
.\scripts\install-agent.ps1 -ServerUrl https://<host>:8443 -EnrollmentToken <token> `
  -CaFingerprint 144D10AAFA642974FE390A6E68521627E815F978B589DE32535C36EA30DC6503
```

With that fingerprint, the installer fetches `/install/ca.crt` over the
first connection but verifies the result against it before trusting
anything — a substituted CA is rejected and the install aborts — and every
request after that (the agent source tarball and its checksum included) is
fully TLS-verified via `--cacert`, not just fetched over the same
unverified connection. `FLEETVIEW_CA_FILE` in the agent's config then
pins the same CA for everything the agent does afterward, every job poll
and result upload included.

**If pinning genuinely isn't practical** (e.g. a quick lab test), pass
`--insecure-tofu` (bash) or `-InsecureTofu` (PowerShell) instead of a
fingerprint to fall back to trust-on-first-use -- the installer will say so
plainly, and this is not recommended for anything handling real credentials.

**For pre-staging the file instead of fetching it at all**, copy
`fleetview-ca.crt` to the endpoint ahead of running the install command and
set `FLEETVIEW_CA_FILE` in `/etc/fleetview-agent/agent.env` (Linux) or
`%ProgramData%\fleetview-agent\agent.env` (Windows) to its path before
starting the service — no fingerprint argument needed in this case, since
you're supplying the trusted CA directly rather than fetching it.

**Skipping TLS verification entirely** is also still available: set
`FLEETVIEW_ALLOW_INSECURE_TLS=true` in the agent's config instead of
`FLEETVIEW_CA_FILE`. Traffic is still encrypted, but the agent no longer
verifies it's actually talking to your server rather than something else
on the network path — there's little reason to choose this now that CA
pinning is the normal path, but it remains available (e.g. if
`/install/ca.crt` is unreachable for some reason).

## Notes

- Live metrics and the interactive terminal (see [`docs/LIVE.md`](LIVE.md))
  run over WebSocket, which Caddy's `reverse_proxy` handles transparently
  alongside plain HTTP -- no separate configuration needed, and this
  traffic is encrypted the same way as everything else once the profile
  is enabled.
- `FLEETVIEW_TRUSTED_PROXY_IPS` isn't something you need to touch: the
  `server` container is already configured to trust forwarded headers from
  Caddy's fixed internal address (`172.28.0.10` on the `frontend` network)
  specifically, so login-throttling by source IP still works correctly
  once Caddy is proxying — without this, every request would appear to
  come from Caddy's own address instead of the real client.
- If `172.28.0.0/24` collides with another Docker network already running
  on the same host, change the `frontend` network's subnet in
  `docker-compose.yml` and update the matching IP in both the `caddy`
  service's `networks:` block and the `server` service's
  `--forwarded-allow-ips` argument to match.
- Rotating the certificate (a new `FLEETVIEW_TLS_HOSTNAME`, or just
  wanting a fresh one) means removing the `fleetview-caddy-data` volume
  and letting Caddy regenerate its CA. Existing agents keep the old
  `FLEETVIEW_CA_FILE` they were installed with, so the old CA no longer
  matches theirs — re-run the install command (or manually replace
  `ca.crt` and restart the service) on each one afterward. New installs
  after the rotation pick up the new CA automatically.
- This only covers agent↔server traffic. It doesn't change anything about
  `ADMIN_TOKEN`, database credentials, or any other secret — keep those
  handled the way the rest of the README describes.
