# Integrations: Proxmox, OPNsense and Wazuh

The **Integrations** tab (admin only) connects FleetView to other services
already running in a home lab and pulls their inventory in alongside your
managed fleet: Proxmox VE's VMs/containers, and OPNsense's DHCP leases.
This is read-only in both directions -- FleetView never changes anything
on the external service, it only reads.

## 1. Set the encryption key

Every other secret this app stores (agent tokens, account passwords) is
one-way hashed, since it only ever needs to be *compared*. Proxmox/OPNsense
credentials are different: the server has to send the actual value to the
external API on every sync, so they're encrypted instead, with a key you
provide:

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Put the output in `.env`:

```bash
FLEETVIEW_SECRET_KEY=<the generated value>
```

This is required before you can save any integration -- the server refuses
to store credentials without it, rather than silently generating a
throwaway key that would leave every saved credential undecryptable the
next time the container restarts (the server container itself has no
persistent storage of its own; only Postgres does).

Restart the stack after setting it: `docker compose up -d`.

## 2. Proxmox VE

In the Proxmox web UI: **Datacenter → Permissions → API Tokens → Add**.
`PVEAuditor` is enough permission to read inventory; you don't need a
token that can make changes. Note the **Token ID** (looks like
`root@pam!fleetview`) and the **secret** shown once at creation.

In FleetView's Integrations tab: Service = Proxmox VE, Base URL is your
Proxmox host including the port Proxmox's own UI uses
(`https://192.168.1.10:8006`), paste in the token ID and secret. Proxmox's
default installation uses a self-signed certificate, so you'll likely need
to uncheck **Verify TLS certificate** unless you've replaced it with one
your server already trusts.

## 3. OPNsense

In the OPNsense web UI: **System → Access → Users**, open your account (or
a dedicated one for this), scroll to **API keys**, and generate one. This
downloads a key/secret pair once.

In FleetView: Service = OPNsense, Base URL is your OPNsense host
(`https://192.168.1.1`), paste in the key and secret. Same self-signed
certificate note as Proxmox applies here.

**A caveat worth knowing:** OPNsense's DHCP lease API has changed shape
across versions and DHCP backends (the legacy ISC dhcpd service vs. the
newer Kea plugin, which is the default on current releases). This
integration was written against the Kea-backend endpoint, which is what
this project could verify meaningfully without a real OPNsense instance to
test against. If your leases don't show up, your OPNsense version/backend
may return a different shape than expected -- the sync error will say so
explicitly rather than silently showing nothing or wrong data. If you hit
this, the fix is a small one in `server/app/connectors/opnsense.py`'s
`fetch_dhcp_leases`; a real response body from your instance's
`/api/dhcpv4/leases/searchLease` would be enough to adjust it.

## 4. Wazuh (vulnerabilities, read-only)

Shows what Wazuh's vulnerability detector has found, per Wazuh agent, next to
your own fleet. FleetView only ever issues `_search` queries; nothing is
written to Wazuh, and Wazuh findings are shown separately from FleetView's own
scanner results (the two will not always agree).

Requires **Wazuh 4.8+** with the vulnerability detector enabled. Since 4.8 the
findings live in the Wazuh *indexer*, not the manager API, so:

- **Base URL** is the indexer: `https://<host>:9200` (not the manager's port 55000).
- Create a dedicated indexer user (Wazuh dashboard: **Indexer management →
  Security**) with a role granting only `read` on `wazuh-states-vulnerabilities-*`.
  Enter its username/password in FleetView.
- The indexer uses a self-signed certificate by default, so you'll likely need
  to uncheck **Verify TLS certificate**.

Each agent row shows Critical/High/Medium/Low counts, links to the matching
enrolled FleetView device (matched by hostname, ignoring the domain part), and
hovering a row lists its top findings by score. Up to 500 agents are synced,
with the 20 highest-scoring findings kept per agent.

**A caveat:** this was written against the documented 4.8+ index fields but
has not been run against a live Wazuh. If a sync fails, the error says why; a
real `_search` response from `wazuh-states-vulnerabilities-*` would be enough
to adjust `server-rs/src/connectors/wazuh.rs`.

## Notes

- Data refreshes automatically every two minutes, and immediately after
  you save or edit an integration. "Sync now" on a card triggers an
  immediate refresh outside that schedule.
- Editing an integration without re-entering credentials keeps the ones
  already saved -- leave those fields blank to change only the name, URL,
  or TLS setting.
- Viewers and operators can see configured integrations and their synced
  data (read-only, same as the rest of the fleet); only admins can add,
  edit, delete, or manually re-sync one.
- A sync failure (wrong credentials, unreachable host, unexpected response
  shape) is recorded and shown on that integration's card -- it never
  takes down the rest of the dashboard, and a failing integration doesn't
  block any other integration's sync.
