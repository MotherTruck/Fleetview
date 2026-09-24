# Live metrics and the interactive terminal

Agents 0.18.0 and later keep a second, persistent WebSocket connection to
the server (`/api/v1/agent/live`) alongside the existing poll-based job
loop -- this is purely additive. A device with no live connection (older
agent, server briefly unreachable, a network path that blocks WebSocket
upgrades) is still fully manageable through queued jobs exactly as before;
nothing here replaces that.

The live channel carries two things:

- **Live metrics**: the agent pushes a fresh sample roughly every two
  seconds while connected. These are relayed straight to any dashboard
  currently watching that device and are never written to the database --
  the existing REST-reported samples (`FLEETVIEW_METRICS_INTERVAL_SECONDS`,
  60s by default) are what still feeds the retained history and trend
  charts, unchanged. Live metrics are purely a real-time view on top.
- **An interactive terminal**: admin-only. Opening the **Terminal** tab on
  a device (Agent tab is unaffected; this lives in the device detail
  dialog) spawns a real shell on that device -- Bash on Linux, PowerShell
  on Windows -- attached to a pseudo-terminal, and streams it to
  [xterm.js](https://xtermjs.org/) in your browser. Typed input and
  resize events go the same way, back to the agent.

## Where it shows up

- **Agent tab**: the fleet-wide agent-versions table has a **Live** column
  showing which devices currently have this connection open, independent
  of "online" (which is based on the last poll/report, up to ~2 minutes
  stale).
- **Dashboard**: monitor cards show a small pulsing dot next to
  Online/Offline when a device's live connection is open.
- **Device details → Monitoring**: the current-reading numbers at the top
  update live (every ~2s) when connected, falling back to the last
  REST-reported sample otherwise. The historical charts below are
  unaffected -- still sourced from retained history.
- **Device details → Terminal**: admin-only tab, hidden entirely for
  viewers/operators and for devices whose agent doesn't support this yet
  (below 0.18.0).

## The terminal is a real shell, not a queued command

Unlike **Deploy → Run a command** (a queued job: type it, it runs once at
the agent's next check-in, output comes back after), the terminal tab is
a live, bidirectional session -- keystrokes reach the shell as you type
them. Because of that it's held to a higher bar than the rest of this
admin-only-anyway dashboard:

- **Admin-only**, not operator. Viewers and operators never see the tab.
- **One session per device at a time.** A second attempt to open a
  terminal on a device that already has one open is refused outright
  (`4429`); there's no queueing or takeover.
- **Every session open is written to the account audit log** (who, which
  device, when), the same log the rest of the admin actions in this
  dashboard use.
- **Cross-site WebSocket hijacking is blocked by an Origin check**, not
  just the session cookie: unlike a same-origin `fetch()`, a browser will
  quite happily open a `new WebSocket(...)` cross-site with the victim's
  cookies attached, so every browser-facing live endpoint verifies the
  handshake's `Origin` header matches the `Host` it actually arrived on
  before accepting the connection (see `origin_is_trusted` in
  `server/app/live.py`).
- **The terminal never auto-reconnects.** A dropped connection (network
  blip, browser tab closed, server restart) ends the session; reopening
  the tab starts a fresh one. Auto-reconnecting an interactive shell
  without you asking for it again would be a bad surprise, and could also
  just collide with a session someone else opened in the meantime given
  the one-at-a-time limit above.

If this server is running behind the optional Caddy TLS profile (see
[`docs/TLS.md`](TLS.md)), this traffic is encrypted the same way as
everything else -- Caddy's `reverse_proxy` handles the WebSocket upgrade
transparently, no separate configuration needed.

## Agent-side notes

- The live connection reconnects on its own with capped exponential
  backoff (1s, up to 30s) if it drops -- this is independent of, and
  doesn't affect, the existing job-poll/metrics-report/scan tickers.
- On Linux the terminal is a real PTY via `github.com/creack/pty`.
- On Windows it's a real Windows ConPTY pseudoconsole, built directly on
  `golang.org/x/sys/windows` (`CreatePseudoConsole` + an attribute-list
  `CreateProcess`) rather than a separate wrapper dependency, consistent
  with the rest of this agent's Windows support. Like the rest of that
  support, this has been written against the documented Win32 sequence
  but not run against real Windows hardware.
- Terminal input/output is base64-encoded on the wire: raw shell output
  can contain arbitrary bytes that aren't valid text on their own (split
  multi-byte sequences, control codes), and the transport here is JSON.
