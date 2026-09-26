# Networking tools

Four things. The first three require agents on 0.20.0 or later (older
agents have no code path for the new job types at all -- the same "upgrade
to unlock this" situation as RUN_COMMAND/UPGRADE_AGENT in 0.16.0); exposure
scoring requires 0.21.0.

## Network diagnostics

**Deploy → Network diagnostics** runs one of four read-only tools on every
currently-selected device (the same device-selection list the rest of the
Deploy tab uses) and reports the output back, queued the same way as every
other job here -- not a live/interactive session.

- **Ping** / **Traceroute**: the device's own `ping`/`traceroute` (or
  `tracert` on Windows), run directly as a subprocess (never through a
  shell -- the target is a distinct argument, not concatenated into a
  command string).
- **DNS lookup**: resolves the target to its IP address(es) using the
  agent's own Go runtime, no external tool needed.
- **Port check**: attempts a real TCP connection to the target:port with a
  short timeout and reports open/closed plus the connection time.

Available to operators and admins (not viewers) -- it's read-only and
can't change anything on the device, so it doesn't need admin-only the way
**Run a command**'s arbitrary shell access does.

## Wake-on-LAN

Every device's inventory now includes its network interfaces' MAC
addresses. When a device is offline and has at least one known MAC, its
**Overview** tab shows a **Wake on LAN** action: pick any other
*currently online* device to relay the wake packet from, and it sends a
standard magic packet as a UDP broadcast on that device's local network.

This has to be relayed through another device on the same LAN, not sent
from the server itself: broadcast packets don't cross routers, and the
server (often in its own Docker network) usually isn't on the target's
actual physical LAN segment. In a typical single-subnet home network, any
other online device works as the relay.

## Network topology (Inventory tab)

If you've configured an OPNsense integration (see
[`docs/INTEGRATIONS.md`](INTEGRATIONS.md)), the Inventory tab gains a
**Devices seen on your network** panel: every device in OPNsense's DHCP
lease table, cross-referenced against FleetView's own managed devices by
MAC address. A lease that matches a MAC FleetView already knows about
links straight to that device's details; everything else is marked
**Unmanaged** -- the fastest way to spot something on your network that
isn't enrolled yet.

This is a client-side join over data both features already fetch (no
separate endpoint): the Integrations tab's cached OPNsense lease data, and
each device's own reported MAC addresses. It updates whenever either
refreshes.

## Exposure scoring

Every vulnerability scan (Arch/CachyOS via `archaudit`, Debian/Ubuntu via
`debsecan` -- the same two platforms vulnerability scanning already
supports) now also collects the device's listening TCP/UDP ports and the
process bound to each one, via `ss -Hlntup`. This never fails the scan
itself: if `ss` isn't installed or the agent lacks permission to see other
processes' names, the listening-ports list is just empty and every finding
is scored **Unknown**.

On the server, each vulnerability finding's package name is checked against
the listening processes' names (case-insensitive substring match, also
stripping a process's trailing "d" -- `sshd` -> `ssh`, `mysqld` -> `mysql`
-- to catch the common Unix daemon-naming convention). A match is tagged
**Listening**, with the exact matched port(s) shown, on the theory that a
vulnerable package with a process actually accepting network connections is
a materially different risk than the same CVE in a library that's only
ever loaded, never listening.

This is **not** active exploit verification -- it never attempts to
connect to, fingerprint, or exploit anything, on this device or any other.
It's a same-host name-matching heuristic shown transparently as a plain
tag with its evidence (the matched port), not a fabricated confidence
score or CVSS-style number. It can miss real matches (a vulnerable package
whose process name doesn't resemble the package name at all) and, less
often, flag a coincidental name match that isn't actually the vulnerable
code path. Treat **Listening** as "look at this one first," not as a
verdict.

Cross-referencing against OPNsense's firewall/NAT rules (to distinguish
"reachable from other devices on this LAN" from "reachable from the
internet") is a natural next step once the OPNsense integration's own
API surface for that has been verified against real hardware -- see the
caveats in [`docs/INTEGRATIONS.md`](INTEGRATIONS.md) about which
OPNsense endpoints are confirmed versus best-effort.
