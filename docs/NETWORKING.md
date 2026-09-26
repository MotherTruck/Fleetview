# Networking tools

Three things, all requiring agents on 0.20.0 or later (older agents have no
code path for the new job types at all -- the same "upgrade to unlock this"
situation as RUN_COMMAND/UPGRADE_AGENT in 0.16.0).

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
