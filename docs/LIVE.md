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
- **Remote control**: admin-only, agents 0.23.0 and later. Opening the
  **Remote control** tab streams a live view of the device's screen (a
  JPEG frame every 250ms) and forwards your mouse/keyboard input back to
  it -- a real interactive session, not a queued job, same model as the
  terminal.

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
- **Device details → Remote control**: admin-only tab, hidden for devices
  whose agent doesn't support this yet (below 0.23.0). Unlike the other
  tabs it opens its own window (`remote-control.html`) instead of an
  inline panel -- a live screen view wants more room than fits alongside
  everything else in the device dialog. That window does its own
  availability check and shows screen.Detect()'s Reason (no desktop
  session logged in, a missing tool, etc.) if the device supports remote
  control but isn't currently available, rather than just failing to
  connect.

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

## Remote control

Same session model and security properties as the terminal above (admin-
only, one session per device at a time, every open written to the audit
log, Origin-checked, never auto-reconnects) -- see that section; this one
covers what's specific to screen/input instead of a shell.

- **Linux**: needs an active graphical session (X11 or Wayland) actually
  logged in on the device -- a headless server or a machine sitting at a
  login screen has nothing to capture. The agent detects this by scanning
  running processes for one with `DISPLAY`/`XAUTHORITY` (X11) or
  `WAYLAND_DISPLAY`/`XDG_RUNTIME_DIR` (Wayland) set, the same technique
  other Linux remote-access tools use to find a session from a system
  service with no session of its own.
- **Required tools are installed automatically, not something you set up
  by hand.** ImageMagick (`import`, X11 capture) and `xdotool` (X11
  keyboard input) are installed via the box's own package manager
  (`apt-get`/`pacman`) the moment the agent notices they're missing --
  every agent startup checks, including the restart a self-upgrade
  triggers, so upgrading the agent is the only step needed. Wayland
  capture uses `grim` the same way, but Wayland has no portal-based input
  standard the way X11 has XTEST, so a Wayland session is always
  **view-only**: you can watch, but clicks and keystrokes aren't sent.
  If a tool genuinely can't be installed (no matching package for that
  distro, no network access at that moment), the tab explains exactly
  what's missing rather than just not being there.
- **Windows**: needs a session attached to the physical console (not a
  Server Core install or a machine nobody's ever logged into locally).
  Capture is GDI (`BitBlt`) and input is `SendInput`, both direct Win32
  calls -- no external tool to install.
- **Mouse/keyboard coordinates are fraction-based (0.0-1.0), not pixels**:
  the browser only knows the size of the frame it received, so this is
  the only way input stays correctly aligned with the agent's actual
  screen resolution regardless of what either side's window size is.

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
- Remote-control frames are sent as raw binary WebSocket messages instead
  (no base64 overhead) alongside the same connection's JSON control
  messages -- the one channel that carries both framings.
- The Windows screen-capture/input path (`screen_windows.go`) was
  verified by actually executing the compiled binary under Wine against a
  real display, not just cross-compiled -- a higher bar than the ConPTY
  terminal above, which is written against the documented sequence but
  hasn't been run against real Windows.
