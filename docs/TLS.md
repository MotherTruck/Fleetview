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

In `.env`, set the LAN IP or hostname you actually connect with — Caddy
issues its certificate for exactly this value, so it needs to match what's
in your browser's address bar and each agent's `FLEETVIEW_SERVER_URL`:

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

## 2. Point agents at the HTTPS URL

On **Agent → Add a new device**, set the management server URL to
`https://<FLEETVIEW_TLS_HOSTNAME>:8443` instead of the plain-HTTP address,
then generate the install command as usual — no other change needed.

Both `scripts/remote-install-linux.sh` and `scripts/install-agent.ps1`
detect the `https://` URL automatically and fetch Caddy's private CA
themselves (from `/install/ca.crt`, which Caddy serves publicly for
exactly this purpose) before installing anything else, then pin it via
`FLEETVIEW_CA_FILE` in the agent's config. There's no manual CA
distribution step for a normal install: the certificate is trusted
correctly from the very first run.

That one CA fetch happens over an unverified connection — trust-on-first-
use. The agent source tarball fetched right after it is checked against a
SHA-256 the server publishes at image build time, which catches transport
corruption or a MITM limited to tampering with only one of those two
requests, but not one who actively controls the whole first connection
(they could substitute a matching checksum for their own tarball too) --
only a certificate the OS already trusts from the start closes that
completely. Everything the agent does afterward, every job poll and result
upload, validates against the pinned CA for real. If you want a stronger
guarantee than trust-on-first-use for that one bootstrap fetch, use Option
A below to pre-stage the CA file instead of letting the installer fetch it.

## 3. Trust the certificate (browser, or a stronger guarantee than TOFU)

Caddy's certificate is signed by a private CA it generates on first start,
stored in the `fleetview-caddy-data` volume — not a certificate your
system's trust store or browser already knows about. The install scripts
handle agents automatically (step 2); this section is for your browser, or
for pre-staging the CA on an endpoint instead of trusting the installer's
first-fetch.

Extract the CA once:

```bash
sudo docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./fleetview-ca.crt
```

If that path doesn't exist (Caddy's image has changed it), find the real one first:

```bash
sudo docker compose exec caddy find /data -name root.crt
```

**For your browser**, import `fleetview-ca.crt` into your OS or browser's
trust store as a trusted root — this removes the certificate warning and
gives a clean padlock.

**For an agent**, copy `fleetview-ca.crt` to the endpoint ahead of running
the install command and set `FLEETVIEW_CA_FILE` in
`/etc/fleetview-agent/agent.env` (Linux) or
`%ProgramData%\fleetview-agent\agent.env` (Windows) to its path before
starting the service — this is only worth doing if you don't want to trust
the installer's own one-time bootstrap fetch of `/install/ca.crt`; a
normal install doesn't need it.

**Skipping validation entirely** is also still available: set
`FLEETVIEW_ALLOW_INSECURE_TLS=true` in the agent's config instead of
`FLEETVIEW_CA_FILE`. Traffic is still encrypted, but the agent no longer
verifies it's actually talking to your server rather than something else
on the network path — there's little reason to choose this now that CA
pinning happens automatically, but it remains available (e.g. if
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
