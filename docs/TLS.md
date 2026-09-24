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
then generate the install command as usual. The agent side already
supports HTTPS server URLs; you additionally need one of the two options
in step 3 so it can validate Caddy's certificate.

## 3. Trust the certificate

Caddy's certificate is signed by a private CA it generates on first start,
stored in the `fleetview-caddy-data` volume — not a certificate your
system's trust store already knows about. Agents (and your browser, for a
clean padlock instead of a warning) need to be told to trust it, one of two
ways:

**Option A — pin the specific CA (recommended).** Extract it once:

```bash
sudo docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./fleetview-ca.crt
```

If that path doesn't exist (Caddy's image has changed it), find the real one first:

```bash
sudo docker compose exec caddy find /data -name root.crt
```

Copy `fleetview-ca.crt` to each endpoint and add this line to its
`/etc/fleetview-agent/agent.env` (Linux) or
`%ProgramData%\fleetview-agent\agent.env` (Windows), then restart the
service:

```bash
FLEETVIEW_CA_FILE=/etc/fleetview-agent/fleetview-ca.crt
```

This validates the server's certificate against that specific CA — real
authentication, not just encryption, and it stops working correctly (the
right failure mode) if a certificate ever doesn't chain to it.

**Option B — skip validation entirely.** Set
`FLEETVIEW_ALLOW_INSECURE_TLS=true` in the agent's config instead. Traffic
is still encrypted, but the agent no longer verifies it's actually talking
to your server rather than something else on the network path — only use
this if distributing the CA file per Option A isn't practical.

For your own browser, importing `fleetview-ca.crt` into your OS or
browser's trust store as a trusted root removes the certificate warning
the same way Option A does for agents.

## Notes

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
  and letting Caddy regenerate its CA — which means re-running step 3 on
  every agent afterward, since the old CA file no longer matches.
- This only covers agent↔server traffic. It doesn't change anything about
  `ADMIN_TOKEN`, database credentials, or any other secret — keep those
  handled the way the rest of the README describes.
