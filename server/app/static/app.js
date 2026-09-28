const state = {
  devices: [],
  jobs: [],
  user: null,
  csrf: "",
  users: [],
  setupRequired: false,
  page: "dashboard",
  detailDevice: null,
  detailTab: "overview",
  detailHistory: [],
  detailHistoryLoading: false,
  agentOptionsSignature: "",
  enrollmentTokens: [],
  freshToken: null,
  deploySelected: new Set(),
  reportRows: [],
  reportFields: [],
  reportHistory: [],
  fleetSettings: { default_metrics_interval_seconds: 60, default_inventory_interval_seconds: 900 },
  packages: [],
  customPackages: [],
  patchApprovals: {},
  patchSchedules: {},
  editingPackageId: null,
  publishedAgentVersion: null,
  integrations: [],
  liveDeviceIds: new Set(),
  statusSocket: null,
  metricsSocket: null,
  metricsSocketDeviceId: null,
  liveMetricsByDevice: new Map(),
  terminalSocket: null,
  terminalDeviceId: null,
  screenSocket: null,
  screenDeviceId: null,
  screenFrameUrl: null,
  screenInputEnabled: false,
  screenPointerDown: false,
  topConsumersSort: "cpu_percent",
};

const ACCENT_PRESETS = [
  { name: "Green", hex: "#5ee6b1", rgb: "94, 230, 177", bg: "#09110f", glow: "#184b3d", panel: "#111d19", surface: "#0d1815", raised: "#162720", border: "#2b443a", text: "#ecf5f1", muted: "#a1b8ae", soft: "#c9d8d2", ink: "#092118" },
  { name: "Blue", hex: "#67b7f7", rgb: "103, 183, 247", bg: "#091019", glow: "#193e61", panel: "#111d2b", surface: "#0d1724", raised: "#17283b", border: "#2b425b", text: "#eaf2fc", muted: "#a0b2ca", soft: "#c7d8ed", ink: "#0a2035" },
  { name: "Purple", hex: "#b18cf5", rgb: "177, 140, 245", bg: "#100c18", glow: "#3c285d", panel: "#1c1629", surface: "#161020", raised: "#281e3b", border: "#44345b", text: "#f2ecfc", muted: "#b6a7cd", soft: "#dbceee", ink: "#241439" },
  { name: "Amber", hex: "#f3aa63", rgb: "243, 170, 99", bg: "#15100b", glow: "#56351e", panel: "#241b13", surface: "#1a140e", raised: "#35271b", border: "#55402d", text: "#fcf1e7", muted: "#c5ae96", soft: "#e9d6c2", ink: "#2b1908" },
  { name: "Pink", hex: "#f78fc0", rgb: "247, 143, 192", bg: "#160d13", glow: "#58253f", panel: "#261722", surface: "#1c1018", raised: "#371f2d", border: "#59344b", text: "#fcecf5", muted: "#c8a7bb", soft: "#edcddd", ink: "#321025" },
];

function currentAccentHex() {
  try { return localStorage.getItem("fleetviewAccent") || ACCENT_PRESETS[0].hex; } catch { return ACCENT_PRESETS[0].hex; }
}

function applyAccent(hex) {
  const preset = ACCENT_PRESETS.find((item) => item.hex === hex) || ACCENT_PRESETS[0];
  document.documentElement.style.setProperty("--accent", preset.hex);
  document.documentElement.style.setProperty("--accent-rgb", preset.rgb);
  for (const key of ["bg", "glow", "panel", "surface", "raised", "border", "text", "muted", "soft", "ink"]) {
    document.documentElement.style.setProperty("--" + key, preset[key]);
  }
  document.documentElement.dataset.theme = preset.name.toLowerCase();
}

const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }), "X-FleetView-Request": "1",
      "X-CSRF-Token": state.csrf, ...(options.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    if (response.status === 401 && state.user) {
      endLocalSession();
      openLogin("Your session ended. Please sign in again.");
    }
    const detail = Array.isArray(body.detail) ? body.detail.map(item => `${item.loc.at(-1)}: ${item.msg}`).join("; ") : body.detail;
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

function wsBase() {
  return (location.protocol === "https:" ? "wss://" : "ws://") + location.host;
}

// A small reconnecting-WebSocket helper shared by the fleet-wide live
// status channel and the per-device metrics/terminal channels: on any
// close (including the server's own accept-then-error-frame-then-close
// rejection -- see server/app/live.py's _reject) it retries after a fixed
// delay as long as `shouldReconnect()` still says yes, so a transient
// server restart or network blip recovers on its own instead of leaving
// the dashboard silently stale.
function connectLiveSocket(path, { onMessage, onBinaryMessage, onOpen, onClose, shouldReconnect, retryMs = 3000 }) {
  const holder = { socket: null, stopped: false };
  if (typeof WebSocket === "undefined") return { close: () => {}, send: () => {} };
  const attempt = () => {
    if (holder.stopped) return;
    const socket = new WebSocket(wsBase() + path);
    holder.socket = socket;
    socket.addEventListener("open", () => onOpen && onOpen());
    socket.addEventListener("message", (event) => {
      // Remote-control frames arrive as raw binary WebSocket messages
      // alongside the usual JSON text control messages (see
      // server/app/live.py's screen-live relay) -- a Blob here, never JSON.
      if (event.data instanceof Blob) {
        onBinaryMessage && onBinaryMessage(event.data);
        return;
      }
      try { onMessage(JSON.parse(event.data)); } catch { /* ignore malformed frames */ }
    });
    socket.addEventListener("close", () => {
      if (holder.socket === socket) holder.socket = null;
      onClose && onClose();
      if (!holder.stopped && shouldReconnect()) setTimeout(attempt, retryMs);
    });
    socket.addEventListener("error", () => socket.close());
  };
  attempt();
  return {
    close: () => { holder.stopped = true; holder.socket?.close(); },
    send: (payload) => { if (holder.socket?.readyState === WebSocket.OPEN) holder.socket.send(JSON.stringify(payload)); },
  };
}

function connectLiveStatus() {
  state.statusSocket?.close();
  state.statusSocket = connectLiveSocket("/api/v1/admin/live-status", {
    shouldReconnect: () => !!state.user,
    onMessage: (message) => {
      if (message.type === "snapshot") state.liveDeviceIds = new Set(message.live_device_ids || []);
      else if (message.type === "status") {
        if (message.live) state.liveDeviceIds.add(message.device_id);
        else state.liveDeviceIds.delete(message.device_id);
      } else return;
      renderAgentVersionsTable();
      renderDashboard();
    },
  });
}

function disconnectLiveStatus() {
  state.statusSocket?.close();
  state.statusSocket = null;
  state.liveDeviceIds = new Set();
}

function connectDeviceMetrics(deviceId) {
  if (state.metricsSocketDeviceId === deviceId && state.metricsSocket) return;
  disconnectDeviceMetrics();
  state.metricsSocketDeviceId = deviceId;
  state.metricsSocket = connectLiveSocket(`/api/v1/admin/devices/${deviceId}/metrics-live`, {
    shouldReconnect: () => state.metricsSocketDeviceId === deviceId,
    onMessage: (message) => {
      if (message.type === "metrics") {
        state.liveMetricsByDevice.set(deviceId, message);
        if (state.detailDevice?.id === deviceId && state.detailTab === "monitoring") renderMonitoring(state.detailDevice);
      } else if (message.type === "status" && !message.live) {
        state.liveMetricsByDevice.delete(deviceId);
        if (state.detailDevice?.id === deviceId && state.detailTab === "monitoring") renderMonitoring(state.detailDevice);
      }
    },
  });
}

function disconnectDeviceMetrics() {
  state.metricsSocket?.close();
  state.metricsSocket = null;
  state.metricsSocketDeviceId = null;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// A real interactive shell on the device, streamed over WebSocket -- not a
// queued job like everything else this dashboard does. Unlike the metrics
// and status sockets, a dead terminal connection is never auto-reconnected:
// re-opening a shell without the admin asking for it again would be
// surprising, and the server only allows one session per device at a time
// anyway (see server/app/live.py's claim_terminal), so a stale reconnect
// attempt could just collide with a session opened from elsewhere.
function connectTerminal(deviceId) {
  if (state.terminalDeviceId === deviceId && state.terminalSocket) {
    state.xtermFit?.fit();
    return;
  }
  disconnectTerminal();
  state.terminalDeviceId = deviceId;
  const container = $("#terminalContainer");
  container.replaceChildren();
  const term = new Terminal({
    convertEol: true, fontSize: 13, fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    theme: { background: "#0b0f0d" }, scrollback: 5000,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(container);
  fit.fit();
  state.xterm = term;
  state.xtermFit = fit;
  $("#terminalStatus").textContent = "Connecting…";

  const socket = connectLiveSocket(`/api/v1/admin/devices/${deviceId}/terminal-live`, {
    shouldReconnect: () => false,
    onOpen: () => {
      $("#terminalStatus").textContent = "Connected · starting shell…";
      sendTerminalResize();
    },
    onClose: () => { $("#terminalStatus").textContent = "Disconnected"; },
    onMessage: (message) => {
      if (message.type === "terminal_output") {
        $("#terminalStatus").textContent = "Live";
        term.write(base64ToBytes(message.data));
      } else if (message.type === "terminal_closed") {
        $("#terminalStatus").textContent = `Session ended: ${message.reason || "closed"}`;
        term.write(`\r\n\x1b[90m[session ended: ${message.reason || "closed"}]\x1b[0m\r\n`);
        state.terminalSocket?.close();
      } else if (message.type === "error") {
        $("#terminalStatus").textContent = `Error: ${message.reason || "rejected"}`;
        term.write(`\r\n\x1b[91m[${message.reason || "connection rejected"}]\x1b[0m\r\n`);
      }
    },
  });
  state.terminalSocket = socket;
  term.onData((data) => socket.send({ type: "input", data: bytesToBase64(new TextEncoder().encode(data)) }));

  const handleResize = () => { fit.fit(); sendTerminalResize(); };
  window.addEventListener("resize", handleResize);
  state.terminalResizeHandler = handleResize;
}

function sendTerminalResize() {
  if (!state.xterm || !state.terminalSocket) return;
  state.terminalSocket.send({ type: "resize", cols: state.xterm.cols, rows: state.xterm.rows });
}

function disconnectTerminal() {
  if (state.terminalResizeHandler) window.removeEventListener("resize", state.terminalResizeHandler);
  state.terminalResizeHandler = null;
  state.terminalSocket?.close();
  state.terminalSocket = null;
  state.terminalDeviceId = null;
  state.xterm?.dispose();
  state.xterm = null;
  state.xtermFit = null;
}

// A live view of the device's screen, streamed over its own per-session
// WebSocket the same way the terminal's is (see server/app/live.py's
// screen-live relay): binary JPEG frames in, JSON mouse/keyboard events
// out. Like the terminal, a dead connection is never auto-reconnected --
// the server only allows one remote-control session per device at a time
// (see claim_screen), so a stale reconnect could just collide with a
// session opened elsewhere. viewOnly (from the device's reported
// remote_control capability -- e.g. a Wayland session with no
// portal-based input support) disables sending input without refusing the
// view itself.
function connectScreen(deviceId, viewOnly) {
  if (state.screenDeviceId === deviceId && state.screenSocket) return;
  disconnectScreen();
  state.screenDeviceId = deviceId;
  state.screenInputEnabled = !viewOnly;
  $("#screenContainer").dataset.input = String(!viewOnly);
  $("#screenViewOnlyNote").hidden = !viewOnly;
  $("#screenStatus").textContent = "Connecting…";

  const socket = connectLiveSocket(`/api/v1/admin/devices/${deviceId}/screen-live`, {
    shouldReconnect: () => false,
    onOpen: () => { $("#screenStatus").textContent = "Connected · waiting for first frame…"; },
    onClose: () => { $("#screenStatus").textContent = "Disconnected"; },
    onMessage: (message) => {
      if (message.type === "screen_info") {
        $("#screenStatus").textContent = "Live";
      } else if (message.type === "screen_closed") {
        $("#screenStatus").textContent = `Session ended: ${message.reason || "closed"}`;
        state.screenSocket?.close();
      } else if (message.type === "error") {
        $("#screenStatus").textContent = `Error: ${message.reason || "rejected"}`;
      }
    },
    onBinaryMessage: (blob) => {
      const url = URL.createObjectURL(blob);
      const previous = state.screenFrameUrl;
      $("#screenFrame").src = url;
      state.screenFrameUrl = url;
      if (previous) URL.revokeObjectURL(previous);
    },
  });
  state.screenSocket = socket;
}

function disconnectScreen() {
  if (state.screenFrameUrl) URL.revokeObjectURL(state.screenFrameUrl);
  state.screenFrameUrl = null;
  state.screenSocket?.close();
  state.screenSocket = null;
  state.screenDeviceId = null;
  state.screenInputEnabled = false;
  state.screenPointerDown = false;
  $("#screenFrame").removeAttribute("src");
  $("#screenContainer").dataset.input = "false";
}

// Fraction-based (0-1) coordinates, not raw pixels: the browser only knows
// this frame's own displayed size, so this is the only way to stay in
// sync with the agent's actual screen resolution (see agent/internal/live/
// screen.go and the screen package's pixel() conversion).
function screenPointerFraction(event) {
  const rect = $("#screenFrame").getBoundingClientRect();
  if (!rect.width || !rect.height) return null;
  return {
    x: Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width)),
    y: Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height)),
  };
}

const SCREEN_BUTTON_NAMES = ["left", "middle", "right"];

function escapeHtml(value = "") {
  const node = document.createElement("div");
  node.textContent = String(value);
  return node.innerHTML;
}

function applyPermissions() {
  const role = state.user?.role || "";
  document.body.dataset.role = role;
  document.body.classList.toggle("signed-out", !state.user || state.user.must_change_password);
  $("[data-page='agent']").hidden = role !== "admin";
  $("[data-page='integrations']").hidden = role !== "admin";
  $("[data-page='deploy']").hidden = role === "viewer" || !role;
  document.querySelectorAll("[data-admin-only]").forEach(node => node.hidden = role !== "admin");
  $("#removeDeviceButton").hidden = role !== "admin";
  $("#passwordButton").hidden = !state.user;
  $("#authButton").textContent = state.user ? "Sign out" : "Sign in";
  $("#accountBadge").textContent = state.user ? `${state.user.username} · ${role}` : "";
}

function endLocalSession() {
  state.authGeneration = (state.authGeneration || 0) + 1;
  state.user = null; state.csrf = ""; state.users = [];
  state.devices = []; state.jobs = []; state.enrollmentTokens = [];
  state.reportHistory = []; state.packages = []; state.reportRows = [];
  state.customPackages = []; state.patchApprovals = {}; state.patchSchedules = {};
  state.detailDevice = null; state.detailHistory = []; state.freshToken = null;
  state.agentOptionsSignature = ""; state.deploySelected.clear();
  $("#userRows").replaceChildren(); $("#accountAudit").replaceChildren();
  document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
  disconnectLiveStatus();
  disconnectDeviceMetrics();
  disconnectTerminal();
  applyPermissions();
}

function openLogin(message = "") {
  $("#loginTitle").textContent = state.setupRequired ? "Create your first admin account" : "Sign in to FleetView";
  $("#loginDescription").textContent = state.setupRequired
    ? "Verify ownership once with your existing admin token, then choose your username and password. Existing devices remain enrolled."
    : "Use your FleetView username and password.";
  $("#setupTokenLabel").hidden = !state.setupRequired;
  $("#setupToken").required = state.setupRequired;
  $("#loginPassword").minLength = state.setupRequired ? 12 : 1;
  $("#loginPassword").autocomplete = state.setupRequired ? "new-password" : "current-password";
  $("#loginSubmit").textContent = state.setupRequired ? "Create admin account" : "Sign in";
  $("#loginError").textContent = message;
  if (!$("#tokenDialog").open) $("#tokenDialog").showModal();
}

async function initializeAuth() {
  try {
    sessionStorage.removeItem("fleetviewAdminToken");
    const status = await api("/api/v1/auth/status");
    state.setupRequired = status.setup_required;
    if (state.setupRequired) { openLogin(); return; }
    try { acceptSession(await api("/api/v1/auth/me")); }
    catch { openLogin(); }
  } catch (error) { openLogin(error.message); }
}

function acceptSession(session) {
  state.authGeneration = (state.authGeneration || 0) + 1;
  state.user = session.user; state.csrf = session.csrf_token;
  state.setupRequired = false;
  $("#tokenDialog").close();
  $("#loginPassword").value = ""; $("#setupToken").value = "";
  applyPermissions();
  if (state.user.must_change_password) {
    $("#passwordDescription").textContent = "Replace your temporary password before accessing the fleet.";
    $("#cancelPassword").hidden = true;
    $("#passwordDialog").showModal();
  } else {
    $("#passwordDescription").textContent = "Changing your password signs out all your sessions.";
    $("#cancelPassword").hidden = false;
    setPage("dashboard"); refresh();
    connectLiveStatus();
  }
}

async function loadUsers() {
  if (state.user?.role !== "admin") return;
  const generation = state.authGeneration;
  try {
    const [users, audit] = await Promise.all([api("/api/v1/admin/users"), api("/api/v1/admin/users/audit/recent")]);
    if (generation !== state.authGeneration || state.user?.role !== "admin") return;
    state.users = users;
    $("#userRows").innerHTML = users.map(user => `<tr data-user-row="${escapeHtml(user.id)}">
      <td>${escapeHtml(user.username)}${user.id === state.user.id ? " (you)" : ""}<br><small>${user.must_change_password ? "Password change required" : ""}</small></td>
      <td><select data-user-role aria-label="Role for ${escapeHtml(user.username)}">${["viewer","operator","admin"].map(role => `<option value="${role}" ${role === user.role ? "selected" : ""}>${role}</option>`).join("")}</select></td>
      <td><input data-user-active type="checkbox" aria-label="Enable ${escapeHtml(user.username)}" ${user.active ? "checked" : ""}></td>
      <td>${user.id === state.user.id ? "Use Change password above" : '<input data-user-password type="password" autocomplete="new-password" minlength="12" maxlength="128" placeholder="Leave blank to keep password" aria-label="New temporary password">'}</td>
      <td><button type="button" data-save-user="${escapeHtml(user.id)}">Save</button></td></tr>`).join("");
    $("#accountAudit").innerHTML = audit.map(item => `<p class="form-note">${escapeHtml(fullDate(item.created_at))} · ${escapeHtml(item.actor)} · ${escapeHtml(item.action)} · ${escapeHtml(item.target)} · ${escapeHtml(item.details)}</p>`).join("") || "<p>No changes yet.</p>";
  } catch (error) { $("#userNotice").textContent = error.message; }
}

$("#tokenDialog").addEventListener("cancel", event => event.preventDefault());
$("#passwordDialog").addEventListener("cancel", event => { if (state.user?.must_change_password) event.preventDefault(); });
$("#loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  $("#loginSubmit").disabled = true;
  try {
    const payload = {username: $("#loginUsername").value.trim(), password: $("#loginPassword").value};
    if (state.setupRequired) payload.admin_token = $("#setupToken").value;
    acceptSession(await api(state.setupRequired ? "/api/v1/auth/setup" : "/api/v1/auth/login",
      {method: "POST", body: JSON.stringify(payload)}));
  } catch (error) { $("#loginError").textContent = error.message; }
  finally { $("#loginSubmit").disabled = false; }
});
$("#passwordButton").addEventListener("click", () => {
  $("#passwordError").textContent = ""; $("#passwordForm").reset(); $("#passwordDialog").showModal();
});
$("#cancelPassword").addEventListener("click", () => $("#passwordDialog").close());
$("#passwordForm").addEventListener("submit", async event => {
  event.preventDefault();
  if ($("#newPassword").value !== $("#confirmPassword").value) {
    $("#passwordError").textContent = "New passwords do not match."; return;
  }
  const button = $("#passwordForm button[type='submit']");
  button.disabled = true;
  try {
    await api("/api/v1/auth/password", {method:"POST", body:JSON.stringify({
      current_password:$("#currentPassword").value, new_password:$("#newPassword").value})});
    $("#passwordForm").reset(); $("#passwordDialog").close();
    endLocalSession(); openLogin("Password changed. Sign in with your new password.");
  } catch (error) { $("#passwordError").textContent = error.message; }
  finally { button.disabled = false; }
});
$("#reloadUsers").addEventListener("click", loadUsers);
$("#createUserForm").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("#createUserForm button"); button.disabled = true;
  try {
    await api("/api/v1/admin/users", {method:"POST", body:JSON.stringify({
      username:$("#newUsername").value.trim(), password:$("#userPassword").value, role:$("#userRole").value})});
    $("#createUserForm").reset();
    $("#userNotice").textContent = "User created. Share the temporary password privately; they must change it at sign-in.";
    await loadUsers();
  } catch (error) { $("#userNotice").textContent = error.message; }
  finally { button.disabled = false; }
});
$("#userRows").addEventListener("click", async event => {
  const button = event.target.closest("[data-save-user]");
  if (!button) return;
  const row = button.closest("tr");
  const payload = {role:row.querySelector("[data-user-role]").value, active:row.querySelector("[data-user-active]").checked};
  const password = row.querySelector("[data-user-password]")?.value;
  if (password) payload.password = password;
  if (!confirm("Save account changes? This signs out the user's existing sessions.")) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/users/${encodeURIComponent(button.dataset.saveUser)}`, {method:"PUT",body:JSON.stringify(payload)});
    if (button.dataset.saveUser === state.user?.id) { endLocalSession(); openLogin("Account updated. Please sign in again."); return; }
    $("#userNotice").textContent = "Account updated."; await loadUsers();
  } catch (error) { $("#userNotice").textContent = error.message; }
  finally { button.disabled = false; }
});

function safeUrl(value) {
  try {
    const parsed = new URL(String(value));
    return ["http:", "https:"].includes(parsed.protocol) ? parsed.href : "#";
  } catch { return "#"; }
}

function relativeTime(value) {
  if (!value) return "Never";
  const seconds = Math.round((new Date(value) - Date.now()) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 60) return new Intl.RelativeTimeFormat().format(seconds, "second");
  if (abs < 3600) return new Intl.RelativeTimeFormat().format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return new Intl.RelativeTimeFormat().format(Math.round(seconds / 3600), "hour");
  return new Intl.RelativeTimeFormat().format(Math.round(seconds / 86400), "day");
}

function fullDate(value) {
  return value ? new Date(value).toLocaleString() : "Never";
}

function formatBytes(value) {
  if (!Number.isFinite(Number(value)) || Number(value) <= 0) return "Unknown";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const unit = Math.max(0, Math.min(Math.floor(Math.log(Number(value)) / Math.log(1024)), units.length - 1));
  return `${(Number(value) / (1024 ** unit)).toFixed(unit >= 3 ? 1 : 0)} ${units[unit]}`;
}

function formatUptime(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return "Unknown";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days}d ${hours}h` : `${hours}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function formatLoad(inventory) {
  const values = [inventory.load_1, inventory.load_5, inventory.load_15].map(Number);
  return values.every(Number.isFinite) ? values.map((value) => value.toFixed(2)).join(" / ") : "Unknown";
}

function formatUsage(used, total) {
  const usedNumber = Number(used);
  const totalNumber = Number(total);
  if (!Number.isFinite(usedNumber) || !Number.isFinite(totalNumber) || totalNumber <= 0) return "Unknown";
  return `${formatBytes(usedNumber)} of ${formatBytes(totalNumber)} (${Math.round((usedNumber / totalNumber) * 100)}%)`;
}

function usagePercent(used, total) {
  const usedNumber = Number(used);
  const totalNumber = Number(total);
  if (!Number.isFinite(usedNumber) || !Number.isFinite(totalNumber) || totalNumber <= 0) return null;
  return Math.max(0, Math.min(100, (usedNumber / totalNumber) * 100));
}

function formatPercent(value) {
  if (value === null || value === undefined || value === "") return "Unknown";
  const number = Number(value);
  return Number.isFinite(number) ? `${number.toFixed(number >= 10 ? 0 : 1)}%` : "Unknown";
}

function formatRate(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "Unknown";
  return number <= 0 ? "0 B/s" : `${formatBytes(number)}/s`;
}

function metricValue(device, key, fallback = null) {
  const value = device.metrics?.[key];
  return value === undefined || value === null ? fallback : value;
}

function usageBar(percent, tone = "green") {
  const value = Number.isFinite(Number(percent)) ? Math.max(0, Math.min(100, Number(percent))) : 0;
  return `<div class="usage-track" aria-hidden="true"><span class="${tone}" style="width:${value.toFixed(1)}%"></span></div>`;
}

function severityPill(severity) {
  const normalized = String(severity || "UNKNOWN").toUpperCase();
  return `<span class="pill severity-${normalized.toLowerCase()}">${escapeHtml(normalized)}</span>`;
}

function exposurePill(item) {
  if (item.exposure !== "listening") return '<span class="pill severity-unknown" title="No listening process name matched this package">Unknown</span>';
  const detail = (item.exposure_detail || []).join(", ");
  return `<span class="pill severity-high" title="Listening on ${escapeHtml(detail)}">Listening</span>`;
}

function flagLabel(value) {
  if (value === true) return '<span class="pill succeeded">Yes</span>';
  if (value === false) return '<span class="pill">No</span>';
  return '<span class="pill severity-unknown">Unknown</span>';
}

function setPage(page) {
  if (page === "agent" && state.user?.role !== "admin") page = "dashboard";
  if (page === "integrations" && state.user?.role !== "admin") page = "dashboard";
  if (page === "deploy" && state.user?.role === "viewer") page = "dashboard";
  state.page = page;
  document.querySelectorAll("[data-page]").forEach((button) => button.classList.toggle("active", button.dataset.page === page));
  document.querySelectorAll("[data-page-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.pagePanel === page));
  if (page === "admin" && state.user?.role === "admin") loadUsers();
}

function renderAgentSettingsOptions() {
  const select = $("#agentSettingsDevice");
  const signature = state.devices.map((device) => `${device.id}:${device.display_name || device.hostname}`).join("|");
  if (signature === state.agentOptionsSignature) return;
  state.agentOptionsSignature = signature;
  const previous = select.value;
  select.innerHTML = state.devices.length
    ? state.devices.map((device) => `<option value="${escapeHtml(device.id)}">${escapeHtml(device.display_name || device.hostname)}</option>`).join("")
    : '<option value="">No enrolled devices</option>';
  if (state.devices.some((device) => device.id === previous)) select.value = previous;
  loadAgentSettingsForm();
}

function loadAgentSettingsForm() {
  loadScanSchedule();
  const device = state.devices.find((item) => item.id === $("#agentSettingsDevice").value);
  const settings = device?.agent_settings || {};
  $("#metricsInterval").value = settings.metrics_interval_seconds || 60;
  $("#inventoryInterval").value = settings.inventory_interval_seconds || 900;
  $("#gpuMonitoringEnabled").checked = settings.gpu_monitoring_enabled !== false;
  $("#dockerInventoryEnabled").checked = settings.docker_inventory_enabled !== false;
  $("#uninstallCodeRequired").checked = settings.uninstall_code_required === true;
  $("#uninstallCode").value = "";
  renderAgentUpgradeStatus(device);
}

function renderAgentUpgradeStatus(device) {
  const section = $("#agentUpgradeSection");
  if (!section) return;
  const manifest = state.publishedAgentVersion;
  section.hidden = state.user?.role !== "admin" || !manifest;
  if (!manifest || !device) { $("#upgradeAgentButton").hidden = true; $("#upgradeAgentStatus").textContent = ""; return; }
  const supportedPlatform = device.platform === "linux" || device.platform === "windows";
  const versionParts = String(device.agent_version || "").split(".").map(Number);
  const bootstrapped = versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 16);
  const upToDate = device.agent_version === manifest.version;
  const available = supportedPlatform && bootstrapped && !upToDate;
  $("#upgradeAgentButton").hidden = !available;
  $("#upgradeAgentStatus").textContent = !supportedPlatform ? "Remote upgrade is unsupported on this device's platform."
    : !bootstrapped ? "Upgrade this device to 0.16.0 with scripts/upgrade-agent-in-place.sh (or .ps1) first; remote upgrades work from there onward."
    : upToDate ? `This device already reports the published version (${manifest.version}).`
    : `Version ${manifest.version} is published; this device reports ${device.agent_version || "an unknown version"}.`;
}

function renderAgentVersionsTable() {
  const table = $("#agentVersionsTable");
  const note = $("#agentVersionsNote");
  if (!table) return;
  const manifest = state.publishedAgentVersion;
  note.textContent = manifest ? `Server has agent ${manifest.version} published.` : "This server has no published agent binaries built in.";
  const devices = [...state.devices].sort((a, b) => (a.display_name || a.hostname).localeCompare(b.display_name || b.hostname));
  table.innerHTML = devices.length ? devices.map((device) => {
    const supportedPlatform = device.platform === "linux" || device.platform === "windows";
    const versionParts = String(device.agent_version || "").split(".").map(Number);
    const bootstrapped = versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 16);
    const upToDate = manifest && device.agent_version === manifest.version;
    const canUpgrade = manifest && supportedPlatform && bootstrapped && !upToDate;
    const statusPill = !manifest ? '<span class="pill severity-unknown">Unknown</span>'
      : upToDate ? '<span class="pill succeeded">Up to date</span>'
      : !supportedPlatform ? '<span class="pill severity-unknown">Unsupported platform</span>'
      : !bootstrapped ? '<span class="pill severity-medium">Needs manual bootstrap</span>'
      : '<span class="pill severity-high">Outdated</span>';
    return `<tr>
      <td class="package-name">${escapeHtml(device.display_name || device.hostname)}</td>
      <td>${escapeHtml(device.platform || "Unknown")}</td>
      <td><code>${escapeHtml(device.agent_version || "Unknown")}</code></td>
      <td>${statusPill}</td>
      <td>${state.liveDeviceIds.has(device.id) ? '<span class="pill succeeded live-pulse">● Live</span>' : '<span class="pill severity-unknown">Offline</span>'}</td>
      <td>${canUpgrade ? `<button type="button" class="secondary" data-upgrade-agent="${escapeHtml(device.id)}">Upgrade</button>` : "—"}</td>
    </tr>`;
  }).join("") : '<tr><td colspan="6" class="empty">No enrolled devices.</td></tr>';
}

async function upgradeAgentDevice(id, button) {
  const device = state.devices.find(item => item.id === id);
  const manifest = state.publishedAgentVersion;
  if (!id || !device || !manifest) return;
  if (!confirm(`Upgrade the agent on ${device.display_name || device.hostname} from ${device.agent_version || "an unknown version"} to ${manifest.version}?\n\nThe agent downloads and verifies the new binary, then replaces itself. On Linux this happens in place with no restart; on Windows the service restarts briefly.`)) return;
  if (button) button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${id}/upgrade-agent`, { method: "POST" });
    showNotice(`Agent upgrade to ${manifest.version} queued for ${device.display_name || device.hostname}.`);
    setPage("patching");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { if (button) button.disabled = false; }
}

function integrationSummary(item) {
  const data = item.cached_data || {};
  if (item.kind === "proxmox") {
    const guests = [
      ...(Array.isArray(data.vms) ? data.vms : []).map((guest) => ({ ...guest, type: "VM" })),
      ...(Array.isArray(data.containers) ? data.containers : []).map((guest) => ({ ...guest, type: "CT" })),
    ];
    if (!guests.length) return "";
    return `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Name</th><th>Node</th><th>Status</th></tr></thead><tbody>${
      guests.slice(0, 25).map((guest) => `<tr><td>${escapeHtml(guest.type)}</td><td>${escapeHtml(guest.name || guest.vmid)}</td><td>${escapeHtml(guest.node || "")}</td><td><span class="pill ${guest.status === "running" ? "succeeded" : "unknown"}">${escapeHtml(guest.status || "unknown")}</span></td></tr>`).join("")
    }</tbody></table></div>${guests.length > 25 ? `<p class="form-note">${guests.length - 25} more not shown.</p>` : ""}`;
  }
  if (item.kind === "opnsense") {
    const leases = Array.isArray(data.dhcp_leases) ? data.dhcp_leases : [];
    if (!leases.length) return "";
    return `<div class="table-wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>State</th></tr></thead><tbody>${
      leases.slice(0, 25).map((lease) => `<tr><td>${escapeHtml(lease.ip || "")}</td><td><code>${escapeHtml(lease.mac || "")}</code></td><td>${escapeHtml(lease.hostname || "")}</td><td>${escapeHtml(lease.state || "")}</td></tr>`).join("")
    }</tbody></table></div>${leases.length > 25 ? `<p class="form-note">${leases.length - 25} more not shown.</p>` : ""}`;
  }
  return "";
}

function renderIntegrations() {
  const container = $("#integrationCards");
  if (!container) return;
  container.innerHTML = state.integrations.length ? state.integrations.map((item) => {
    const statusPill = item.last_sync_error ? '<span class="pill failed">Sync failed</span>'
      : item.last_synced_at ? '<span class="pill succeeded">Synced</span>'
      : '<span class="pill pending">Never synced</span>';
    const kindLabel = item.kind === "proxmox" ? "Proxmox VE" : item.kind === "opnsense" ? "OPNsense" : item.kind;
    return `<article class="inventory-card">
      <div class="device-top">
        <div><h3>${escapeHtml(item.name)}</h3><div class="device-subtitle">${escapeHtml(kindLabel)} · ${escapeHtml(item.base_url)}</div></div>
        ${statusPill}
      </div>
      ${item.last_sync_error ? `<p class="form-note integration-error">${escapeHtml(item.last_sync_error)}</p>` : ""}
      ${integrationSummary(item)}
      <p class="scan-note">Last synced ${relativeTime(item.last_synced_at)}</p>
      <div class="device-actions">
        <button type="button" class="secondary" data-integration-sync="${escapeHtml(item.id)}">Sync now</button>
        <button type="button" class="secondary" data-integration-edit="${escapeHtml(item.id)}">Edit</button>
        <button type="button" class="danger" data-integration-delete="${escapeHtml(item.id)}">Delete</button>
      </div>
    </article>`;
  }).join("") : '<div class="empty">No integrations configured yet.</div>';
}

function resetIntegrationForm() {
  $("#integrationForm").reset();
  $("#integrationId").value = "";
  $("#integrationKind").value = "proxmox";
  $("#proxmoxCredentialFields").hidden = false;
  $("#opnsenseCredentialFields").hidden = true;
  $("#integrationVerifyTls").checked = true;
  $("#integrationSubmit").textContent = "Add integration";
  $("#integrationCancelEdit").hidden = true;
}

function startEditIntegration(id) {
  const item = state.integrations.find((entry) => entry.id === id);
  if (!item) return;
  $("#integrationId").value = item.id;
  $("#integrationKind").value = item.kind;
  $("#integrationName").value = item.name;
  $("#integrationBaseUrl").value = item.base_url;
  $("#integrationVerifyTls").checked = item.verify_tls;
  $("#proxmoxCredentialFields").hidden = item.kind !== "proxmox";
  $("#opnsenseCredentialFields").hidden = item.kind !== "opnsense";
  $("#proxmoxTokenId").value = "";
  $("#proxmoxTokenSecret").value = "";
  $("#opnsenseApiKey").value = "";
  $("#opnsenseApiSecret").value = "";
  $("#integrationSubmit").textContent = "Save changes";
  $("#integrationCancelEdit").hidden = false;
  setPage("integrations");
  $("#integrationName").focus();
}

$("#integrationKind").addEventListener("change", () => {
  const kind = $("#integrationKind").value;
  $("#proxmoxCredentialFields").hidden = kind !== "proxmox";
  $("#opnsenseCredentialFields").hidden = kind !== "opnsense";
});

$("#integrationCancelEdit").addEventListener("click", resetIntegrationForm);

$("#integrationForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = $("#integrationId").value;
  const kind = $("#integrationKind").value;
  const rawCredentials = kind === "proxmox"
    ? { token_id: $("#proxmoxTokenId").value.trim(), token_secret: $("#proxmoxTokenSecret").value }
    : { api_key: $("#opnsenseApiKey").value.trim(), api_secret: $("#opnsenseApiSecret").value };
  // Blank fields mean "keep the existing credentials" on an edit; never send them as literal empty-string overwrites.
  const credentials = Object.fromEntries(Object.entries(rawCredentials).filter(([, value]) => value));
  const payload = {
    kind, name: $("#integrationName").value.trim(), base_url: $("#integrationBaseUrl").value.trim(),
    verify_tls: $("#integrationVerifyTls").checked, credentials,
  };
  const button = $("#integrationSubmit");
  button.disabled = true;
  try {
    if (id) {
      await api(`/api/v1/admin/integrations/${id}`, { method: "PUT", body: JSON.stringify(payload) });
      showNotice("Integration updated.");
    } else {
      await api("/api/v1/admin/integrations", { method: "POST", body: JSON.stringify(payload) });
      showNotice("Integration added.");
    }
    resetIntegrationForm();
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});

$("#integrationCards").addEventListener("click", async (event) => {
  const syncButton = event.target.closest("[data-integration-sync]");
  const editButton = event.target.closest("[data-integration-edit]");
  const deleteButton = event.target.closest("[data-integration-delete]");
  if (syncButton) {
    syncButton.disabled = true;
    try {
      await api(`/api/v1/admin/integrations/${syncButton.dataset.integrationSync}/sync`, { method: "POST" });
      await refresh();
    } catch (error) { showNotice(error.message, true); }
    finally { syncButton.disabled = false; }
  } else if (editButton) {
    startEditIntegration(editButton.dataset.integrationEdit);
  } else if (deleteButton) {
    const item = state.integrations.find((entry) => entry.id === deleteButton.dataset.integrationDelete);
    if (!item || !confirm(`Remove the "${item.name}" integration? This only removes it from FleetView; nothing changes on ${item.name} itself.`)) return;
    deleteButton.disabled = true;
    try {
      await api(`/api/v1/admin/integrations/${deleteButton.dataset.integrationDelete}`, { method: "DELETE" });
      showNotice("Integration removed.");
      await refresh();
    } catch (error) { showNotice(error.message, true); }
    finally { deleteButton.disabled = false; }
  }
});

function shellQuote(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

function psQuote(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

// navigator.clipboard requires a secure context (HTTPS or localhost); this
// dashboard is commonly reached over plain HTTP on a LAN address, where that
// API is unavailable entirely, so a hidden-textarea + execCommand fallback
// is required for copy buttons to work there.
async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    if (!document.execCommand("copy")) throw new Error("execCommand copy failed");
  } finally {
    document.body.removeChild(textarea);
  }
}

function tokenMetaText(fresh, status) {
  if (!fresh) return "";
  if (status === "active" && new Date(fresh.expires_at) > new Date()) {
    return `One-time token${fresh.label ? ` for ${fresh.label}` : ""}. Expires ${fullDate(fresh.expires_at)}.`;
  }
  const reason = { used: "was used to enroll a device", revoked: "was revoked" }[status] || "has expired";
  return `The last token ${reason}. Generate a new one for the next device.`;
}

function renderInstallCommand() {
  const platform = $("#installPlatform").value;
  const windows = platform === "windows";
  $("#linuxInstallOutput").hidden = windows;
  $("#windowsInstallOutput").hidden = !windows;

  const fresh = state.freshToken;
  const record = fresh && state.enrollmentTokens.find((item) => item.id === fresh.id);
  const status = record ? record.status : (fresh ? "active" : null);
  const usable = status === "active" && new Date(fresh.expires_at) > new Date();
  const serverURL = $("#installServerURL").value.trim().replace(/\/$/, "");

  if (windows) {
    const meta = $("#windowsInstallTokenMeta");
    $("#windowsInstallCommandBlock").hidden = !usable;
    $("#copyWindowsInstallCommand").disabled = !usable;
    meta.hidden = !fresh;
    meta.textContent = tokenMetaText(fresh, status);
    $("#windowsInstallCommand").textContent = usable
      ? `.\\scripts\\install-agent.ps1 -ServerUrl ${psQuote(serverURL)} -EnrollmentToken ${psQuote(fresh.token)}`
      : "";
    $("#windowsInstallCommandIntro").textContent = usable
      ? "Run this command from the project root in an elevated PowerShell prompt on the new Windows device:"
      : "Generate a one-time token to get the install command for a new Windows device.";
    return;
  }

  const meta = $("#installTokenMeta");
  $("#installCommandBlock").hidden = !usable;
  $("#copyInstallCommand").disabled = !usable;
  meta.hidden = !fresh;
  meta.textContent = tokenMetaText(fresh, status);
  if (usable) {
    const installerURL = `${serverURL}/install/linux.sh`;
    $("#installCommand").textContent = `curl -fsSL ${shellQuote(installerURL)} | sudo bash -s -- ${shellQuote(serverURL)} ${shellQuote(fresh.token)}`;
    $("#installCommandIntro").textContent = "Run this command in a terminal on the new Linux device:";
  } else {
    $("#installCommand").textContent = "";
    $("#installCommandIntro").textContent = "Generate a one-time token to get the install command for a new Linux device.";
  }
}

function renderEnrollmentTokens() {
  const names = Object.fromEntries(state.devices.map((device) => [device.id, device.display_name || device.hostname]));
  const pills = { active: "pending", used: "succeeded", expired: "unknown", revoked: "failed" };
  $("#enrollmentTokens").innerHTML = state.enrollmentTokens.length ? state.enrollmentTokens.map((item) => `
    <tr>
      <td>${escapeHtml(item.label || "—")}</td>
      <td><span class="pill ${pills[item.status] || "unknown"}">${escapeHtml(item.status)}</span></td>
      <td>${relativeTime(item.created_at)}</td>
      <td>${item.status === "active" ? escapeHtml(fullDate(item.expires_at)) : "—"}</td>
      <td>${item.device_id ? escapeHtml(names[item.device_id] || item.device_id) : "—"}</td>
      <td>${item.status === "active" ? `<button class="secondary" type="button" data-revoke-token="${escapeHtml(item.id)}">Revoke</button>` : ""}</td>
    </tr>`).join("") : '<tr><td colspan="6" class="empty">No enrollment tokens yet.</td></tr>';
}

function renderDashboard() {
  const monitored = state.devices.filter((device) => device.metrics);
  const average = (values) => values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
  const cpuValues = monitored.map((device) => Number(metricValue(device, "cpu_percent"))).filter(Number.isFinite);
  const memoryValues = monitored.map((device) => usagePercent(metricValue(device, "memory_used_bytes"), metricValue(device, "memory_total_bytes"))).filter((value) => value !== null);
  const diskValues = monitored.map((device) => usagePercent(metricValue(device, "disk_used_bytes"), metricValue(device, "disk_total_bytes"))).filter((value) => value !== null);
  const warnings = state.devices.filter((device) => {
    const cpu = Number(metricValue(device, "cpu_percent", 0));
    const memory = usagePercent(metricValue(device, "memory_used_bytes"), metricValue(device, "memory_total_bytes")) || 0;
    const disk = usagePercent(metricValue(device, "disk_used_bytes"), metricValue(device, "disk_total_bytes")) || 0;
    return !device.online || cpu >= 90 || memory >= 90 || disk >= 90;
  }).length;

  $("#onlineDeviceCount").textContent = `${state.devices.filter((device) => device.online).length}/${state.devices.length}`;
  $("#averageCPU").textContent = formatPercent(average(cpuValues));
  $("#averageMemory").textContent = formatPercent(average(memoryValues));
  $("#averageDisk").textContent = formatPercent(average(diskValues));
  $("#healthWarningCount").textContent = warnings;

  $("#monitorDevices").innerHTML = state.devices.length ? state.devices.map((device) => {
    const metrics = device.metrics;
    if (!metrics) {
      return `<article class="monitor-card waiting">
        <div class="device-top"><div><h3>${escapeHtml(device.display_name || device.hostname)}</h3><div class="device-subtitle">${escapeHtml(device.os_name || device.platform)}</div></div><div class="status ${device.online ? "online" : ""}"><span class="dot"></span>${device.online ? "Online" : "Offline"}</div></div>
        <div class="telemetry-wait">Waiting for the first telemetry sample from agent ${escapeHtml(device.agent_version || "")}. Samples arrive once per minute.</div>
      </article>`;
    }
    const memory = usagePercent(metrics.memory_used_bytes, metrics.memory_total_bytes);
    const disk = usagePercent(metrics.disk_used_bytes, metrics.disk_total_bytes);
    const cpu = Number(metrics.cpu_percent);
    const temperature = metrics.temperature_celsius === null || metrics.temperature_celsius === undefined ? "Not reported" : `${Number(metrics.temperature_celsius).toFixed(0)}°C`;
    const gpus = Array.isArray(metrics.gpus) ? metrics.gpus : [];
    const gpuSummary = gpus.length ? `${gpus.length} GPU${gpus.length === 1 ? "" : "s"} · ${formatPercent(gpus[0].utilization_percent)}` : "No GPU data";
    return `<article class="monitor-card" data-action="details" data-tab="monitoring" data-device-id="${escapeHtml(device.id)}" tabindex="0">
      <div class="device-top"><div><h3>${escapeHtml(device.display_name || device.hostname)}</h3><div class="device-subtitle">${escapeHtml([device.os_name, device.os_version].filter(Boolean).join(" · "))}</div></div><div class="status ${device.online ? "online" : ""}"><span class="dot"></span>${device.online ? "Online" : "Offline"}${state.liveDeviceIds.has(device.id) ? ' <span class="live-pulse" title="Live connection open">●</span>' : ""}</div></div>
      <div class="live-resource-grid">
        <div><span><small>CPU</small><strong>${formatPercent(cpu)}</strong></span>${usageBar(cpu)}</div>
        <div><span><small>Memory</small><strong>${formatPercent(memory)}</strong></span>${usageBar(memory)}</div>
        <div><span><small>Root disk</small><strong>${formatPercent(disk)}</strong></span>${usageBar(disk, disk >= 90 ? "orange" : "green")}</div>
      </div>
      <div class="live-secondary"><span>↓ ${formatRate(metrics.network_receive_bps)}</span><span>↑ ${formatRate(metrics.network_transmit_bps)}</span><span>CPU ${escapeHtml(temperature)}</span><span>${escapeHtml(gpuSummary)}</span><span>${metrics.process_count || 0} processes</span></div>
      <p class="scan-note">Sampled ${relativeTime(metrics.recorded_at)} · Select for history</p>
    </article>`;
  }).join("") : '<div class="empty">No devices have enrolled.</div>';
}

function renderPatching() {
  const totals = state.devices.reduce((result, device) => {
    const severities = device.vulnerability_severity_counts || {};
    result.updates += device.update_count || 0;
    result.vulnerabilities += device.vulnerability_count || 0;
    result.critical += severities.CRITICAL || 0;
    result.high += severities.HIGH || 0;
    result.exposed += device.vulnerability_exposed_count || 0;
    return result;
  }, { updates: 0, vulnerabilities: 0, critical: 0, high: 0, exposed: 0 });
  $("#patchDeviceCount").textContent = state.devices.length;
  $("#updateCount").textContent = totals.updates;
  $("#vulnerabilityCount").textContent = totals.vulnerabilities;
  $("#criticalCount").textContent = totals.critical;
  $("#highCount").textContent = totals.high;
  $("#exposedCount").textContent = totals.exposed;

  $("#patchDevices").innerHTML = state.devices.length ? state.devices.map((device) => {
    const severities = device.vulnerability_severity_counts || {};
    return `
      <article class="device">
        <div class="device-top">
          <div><h3>${escapeHtml(device.display_name || device.hostname)}</h3><div class="device-subtitle">${escapeHtml([device.os_name, device.os_version].filter(Boolean).join(" · "))}</div></div>
          <div class="status ${device.online ? "online" : ""}"><span class="dot"></span>${device.online ? "Online" : "Offline"}</div>
        </div>
        <div class="posture-grid">
          <div><small>Needed patches</small><strong>${device.update_count || 0}</strong></div>
          <div><small>Vulnerabilities</small><strong>${device.vulnerability_count || 0}</strong></div>
          <div><small>Critical / High</small><strong>${severities.CRITICAL || 0} / ${severities.HIGH || 0}</strong></div>
          <div><small title="Vulnerable packages with a process actually listening on the network">Exposed</small><strong>${device.vulnerability_exposed_count || 0}</strong></div>
          <div><small>Last patched</small><strong>${relativeTime(device.last_patched_at)}</strong></div>
        </div>
        <div class="device-actions">
          <button class="secondary" data-action="details" data-tab="patches" data-device-id="${escapeHtml(device.id)}">Review</button>
          <button data-action="scan" data-device-id="${escapeHtml(device.id)}">Patch scan</button>
          <button data-action="vulnerability-scan" data-device-id="${escapeHtml(device.id)}" ${["pacman", "apt"].includes(device.package_manager) ? "" : 'disabled title="The vulnerability adapter for this platform is not available yet"'}>Vulnerability scan</button>
          <button class="danger" data-action="update" data-device-id="${escapeHtml(device.id)}" ${device.update_count === 0 ? "disabled" : ""}>Deploy approved patches</button>
        </div>
        <p class="scan-note">Patch scan: ${relativeTime(device.last_scan_at)} · Vulnerability scan: ${relativeTime(device.last_vulnerability_scan_at)}</p>
      </article>`;
  }).join("") : '<div class="empty">No devices have enrolled.</div>';
}

function renderInventory() {
  const filter = $("#inventorySearch").value.trim().toLowerCase();
  const devices = state.devices.filter((device) => `${device.hostname} ${device.os_name} ${device.os_version}`.toLowerCase().includes(filter));
  $("#inventoryDevices").innerHTML = devices.length ? devices.map((device) => {
    const inventory = device.inventory || {};
    const addresses = Array.isArray(inventory.ip_addresses) ? inventory.ip_addresses.join(", ") : "Unknown";
    return `
      <article class="inventory-card">
        <div class="device-top">
          <div><h3>${escapeHtml(device.display_name || device.hostname)}</h3><div class="device-subtitle">${escapeHtml([device.os_name, device.os_version, device.architecture].filter(Boolean).join(" · "))}</div></div>
          <div class="status ${device.online ? "online" : ""}"><span class="dot"></span>${device.online ? "Online" : "Offline"}</div>
        </div>
        <div class="inventory-grid">
          <div><small>CPU</small><strong title="${escapeHtml(inventory.cpu_model || "Unknown")}">${escapeHtml(inventory.cpu_model || "Unknown")}</strong></div>
          <div><small>Memory</small><strong>${formatBytes(inventory.memory_bytes)}</strong></div>
          <div><small>Kernel</small><strong>${escapeHtml(inventory.kernel || "Unknown")}</strong></div>
          <div><small>IP addresses</small><strong title="${escapeHtml(addresses)}">${escapeHtml(addresses)}</strong></div>
          <div><small>Last scanned</small><strong>${relativeTime(device.last_scan_at)}</strong></div>
          <div><small>Last patched</small><strong>${relativeTime(device.last_patched_at)}</strong></div>
        </div>
        <div class="device-actions"><button data-action="details" data-tab="overview" data-device-id="${escapeHtml(device.id)}">View device details</button></div>
      </article>`;
  }).join("") : '<div class="empty">No devices match this view.</div>';
  renderNetworkTopology();
}

// Cross-references OPNsense's DHCP leases (from any configured OPNsense
// integrations) against FleetView's own managed devices by MAC address, so
// this shows everything actually on the network -- not just what's
// enrolled -- and makes unmanaged devices easy to spot. Purely a client-side
// join over data already fetched for the Integrations tab; no separate
// endpoint needed.
function renderNetworkTopology() {
  const panel = $("#networkTopologyPanel");
  if (!panel) return;
  const opnsenseIntegrations = state.integrations.filter((item) => item.kind === "opnsense");
  panel.hidden = opnsenseIntegrations.length === 0;
  if (!opnsenseIntegrations.length) return;
  const managedByMac = new Map();
  for (const device of state.devices) {
    const macs = Array.isArray(device.inventory?.mac_addresses) ? device.inventory.mac_addresses : [];
    for (const mac of macs) managedByMac.set(mac.toLowerCase(), device);
  }
  const rows = [];
  for (const integration of opnsenseIntegrations) {
    const leases = Array.isArray(integration.cached_data?.dhcp_leases) ? integration.cached_data.dhcp_leases : [];
    for (const lease of leases) {
      rows.push({ ...lease, sourceName: integration.name, managedDevice: lease.mac ? managedByMac.get(lease.mac.toLowerCase()) : null });
    }
  }
  $("#networkTopologyTable").innerHTML = rows.length ? rows.map((row) => `<tr>
    <td>${escapeHtml(row.ip || "")}</td>
    <td><code>${escapeHtml(row.mac || "")}</code></td>
    <td>${escapeHtml(row.hostname || "")}</td>
    <td>${escapeHtml(row.sourceName)}</td>
    <td>${row.managedDevice
      ? `<button type="button" class="secondary" data-action="details" data-tab="overview" data-device-id="${escapeHtml(row.managedDevice.id)}">Managed: ${escapeHtml(row.managedDevice.display_name || row.managedDevice.hostname)}</button>`
      : '<span class="pill severity-unknown">Unmanaged</span>'}</td>
  </tr>`).join("") : '<tr><td colspan="5" class="empty">No DHCP leases synced yet.</td></tr>';
}

const jobTypeLabels = { SCAN_DEVICE: "Patch scan", SCAN_VULNERABILITIES: "Vulnerability scan", INSTALL_UPDATES: "Install updates", INSTALL_APPROVED_UPDATES: "Approved patches", INSTALL_CUSTOM_PACKAGE: "Custom install", INSTALL_PACKAGE: "Install package", UNINSTALL_PACKAGE: "Uninstall package", DOCKER_CONTAINER_ACTION: "Docker action", RUN_COMMAND: "Run command", UPGRADE_AGENT: "Agent upgrade", NETWORK_DIAGNOSTIC: "Network diagnostic", WAKE_ON_LAN: "Wake-on-LAN" };

function renderJobs() {
  const names = Object.fromEntries(state.devices.map((device) => [device.id, device.hostname]));
  $("#jobs").innerHTML = state.jobs.length ? state.jobs.map((job) => `
    <tr>
      <td>${escapeHtml(job.type === "DOCKER_CONTAINER_ACTION" ? `Docker ${job.options?.action || "action"} · ${job.options?.container_id || ""}` : jobTypeLabels[job.type] || job.type)}</td>
      <td>${escapeHtml(names[job.device_id] || job.device_id)}</td>
      <td><span class="pill ${job.status}">${escapeHtml(job.status)}</span></td>
      <td>${relativeTime(job.created_at)}</td>
      <td>${escapeHtml(job.error || (job.exit_code === null ? "—" : `Exit ${job.exit_code}`))}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No jobs yet.</td></tr>';
}

function renderDeployDevices() {
  const filter = $("#deployDeviceSearch").value.trim().toLowerCase();
  const devices = state.devices.filter((device) =>
    `${device.hostname} ${device.os_name} ${device.package_manager}`.toLowerCase().includes(filter));
  for (const id of [...state.deploySelected]) {
    if (!state.devices.some((device) => device.id === id)) state.deploySelected.delete(id);
  }
  $("#deployDeviceList").innerHTML = devices.length ? devices.map((device) => `
    <label class="deploy-device-row">
      <input type="checkbox" data-deploy-device="${escapeHtml(device.id)}" ${state.deploySelected.has(device.id) ? "checked" : ""}>
      <span>
        <span class="device-name">${escapeHtml(device.display_name || device.hostname)}</span>
        <span class="device-subtitle">${escapeHtml(device.package_manager || "unknown")} · ${escapeHtml(device.os_name || "Unknown")}</span>
      </span>
      <span class="status ${device.online ? "online" : ""}"><span class="dot"></span>${device.online ? "Online" : "Offline"}</span>
    </label>`).join("") : '<div class="empty">No devices have enrolled.</div>';
  updateDeploySubmitState();
}

function updateDeploySubmitState() {
  const count = state.deploySelected.size;
  $("#deploySubmit").disabled = count === 0;
  $("#deploySelectionCount").textContent = count === 0 ? "No devices selected." : `${count} device${count === 1 ? "" : "s"} selected.`;
  const runCommandSubmit = $("#runCommandSubmit");
  if (runCommandSubmit) runCommandSubmit.disabled = count === 0 || state.user?.role !== "admin";
  const netDiagSubmit = $("#netDiagSubmit");
  if (netDiagSubmit) netDiagSubmit.disabled = count === 0 || state.user?.role === "viewer";
}

function renderDeployJobs() {
  const names = Object.fromEntries(state.devices.map((device) => [device.id, device.hostname]));
  const deployments = state.jobs.filter((job) => ["INSTALL_PACKAGE", "UNINSTALL_PACKAGE", "INSTALL_CUSTOM_PACKAGE"].includes(job.type));
  $("#deployJobs").innerHTML = deployments.length ? deployments.map((job) => `
    <tr>
      <td class="package-name">${job.type === "UNINSTALL_PACKAGE" ? "Uninstall" : "Install"}: ${escapeHtml(job.options?.name || job.options?.package || "—")}</td>
      <td>${escapeHtml(names[job.device_id] || job.device_id)}</td>
      <td><span class="pill ${job.status}">${escapeHtml(job.status)}</span></td>
      <td>${relativeTime(job.created_at)}</td>
      <td>${escapeHtml(job.error || (job.exit_code === null ? "—" : `Exit ${job.exit_code}`))}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No deployments yet.</td></tr>';
}

function renderDeploy() {
  renderDeployDevices();
  renderDeployJobs();
  renderPackageCatalog();
  renderCustomPackages();
}

function renderCustomPackages() {
  $("#customPackageRows").innerHTML = state.customPackages.length ? state.customPackages.map(pkg => `
    <tr><td class="package-name">${escapeHtml(pkg.name)}</td><td>${escapeHtml(pkg.platform)}</td>
    <td>${escapeHtml(pkg.files.map(file => file.filename).join(", "))}<div class="device-subtitle"><code>${escapeHtml(pkg.command)}</code></div></td>
    <td><button type="button" data-custom-deploy="${escapeHtml(pkg.id)}">Deploy</button></td></tr>
  `).join("") : '<tr><td colspan="4" class="empty">No uploaded packages yet.</td></tr>';
}

const PACKAGE_PLATFORM_FIELDS = [
  { key: "pacman_name", label: "pacman" },
  { key: "apt_name", label: "apt" },
  { key: "winget_id", label: "winget" },
];

function packagePlatformSummary(pkg) {
  return PACKAGE_PLATFORM_FIELDS
    .map((field) => (pkg[field.key] ? `${field.label}: ${pkg[field.key]}` : null))
    .filter(Boolean)
    .join(" · ") || "—";
}

function resolvePackageIdentifier(pkg, device) {
  const field = { pacman: "pacman_name", apt: "apt_name", winget: "winget_id" }[device.package_manager];
  const value = field ? pkg[field] : "";
  return value ? value.trim() : "";
}

function renderPackageCatalog() {
  $("#packageCatalog").innerHTML = state.packages.length ? state.packages.map((pkg) => `
    <tr>
      <td><strong>${escapeHtml(pkg.name)}</strong>${pkg.category ? `<div class="device-subtitle">${escapeHtml(pkg.category)}</div>` : ""}</td>
      <td>${escapeHtml(pkg.version || "—")}</td>
      <td>${escapeHtml(packagePlatformSummary(pkg))}</td>
      <td>
        <div class="device-actions">
          <button type="button" data-deploy-package="${escapeHtml(pkg.id)}">Deploy</button>
          <button type="button" class="secondary" data-uninstall-package="${escapeHtml(pkg.id)}">Uninstall</button>
          <button type="button" class="secondary" data-edit-package="${escapeHtml(pkg.id)}">Edit</button>
          <button type="button" class="secondary" data-delete-package="${escapeHtml(pkg.id)}">Delete</button>
        </div>
      </td>
    </tr>`).join("") : '<tr><td colspan="4" class="empty">No saved packages yet.</td></tr>';
}

function resetPackageForm() {
  state.editingPackageId = null;
  $("#packageForm").reset();
  $("#packageId").value = "";
  $("#packageSubmit").textContent = "Save package";
  $("#packageCancelEdit").hidden = true;
}

function startEditPackage(pkg) {
  state.editingPackageId = pkg.id;
  $("#packageId").value = pkg.id;
  $("#packageName").value = pkg.name;
  $("#packageDescription").value = pkg.description;
  $("#packageVersion").value = pkg.version;
  $("#packageCategory").value = pkg.category;
  $("#packagePacman").value = pkg.pacman_name;
  $("#packageApt").value = pkg.apt_name;
  $("#packageWinget").value = pkg.winget_id;
  $("#packageSubmit").textContent = "Update package";
  $("#packageCancelEdit").hidden = false;
  $("#packageName").focus();
}

async function deployCatalogPackage(pkg, uninstall = false) {
  const deviceIds = [...state.deploySelected];
  if (deviceIds.length === 0) {
    showNotice("Select at least one target device first.", true);
    return;
  }
  const toQueue = [];
  const toSkip = [];
  for (const deviceId of deviceIds) {
    const device = state.devices.find((item) => item.id === deviceId);
    const identifier = device ? resolvePackageIdentifier(pkg, device) : "";
    if (identifier) toQueue.push({ deviceId, identifier });
    else toSkip.push(device);
  }
  if (toQueue.length === 0) {
    showNotice(`${pkg.name} has no package identifier configured for any selected device's platform.`, true);
    return;
  }
  if (!confirm(`${uninstall ? "Uninstall" : "Install"} "${pkg.name}" on ${toQueue.length} selected device(s)?\n\n${toQueue.map(({deviceId, identifier}) => `${state.devices.find(d => d.id === deviceId)?.hostname}: ${identifier}`).join("\n")}\n\n${toSkip.length} unsupported device(s) will be skipped.`)) return;
  const results = await Promise.allSettled(toQueue.map(({ deviceId, identifier }) =>
    api(`/api/v1/admin/devices/${deviceId}/jobs`, {
      method: "POST",
      body: JSON.stringify({ type: uninstall ? "UNINSTALL_PACKAGE" : "INSTALL_PACKAGE", options: { package: identifier, confirmed: true } }),
    })
  ));
  const failed = results.filter((result) => result.status === "rejected");
  const succeeded = results.length - failed.length;
  const parts = [`Queued ${pkg.name} for ${succeeded} device${succeeded === 1 ? "" : "s"}.`];
  if (toSkip.length) parts.push(`${toSkip.length} skipped (no ${pkg.name} identifier for their platform).`);
  if (failed.length) parts.push(`${failed.length} failed to queue: ${failed[0].reason?.message || "unknown error"}`);
  showNotice(parts.join(" "), failed.length > 0);
  await refresh();
}

function isFullyPatched(device) { return (device.update_count || 0) === 0; }

function hasNoCriticalHighVulns(device) {
  const severities = device.vulnerability_severity_counts || {};
  return (severities.CRITICAL || 0) === 0 && (severities.HIGH || 0) === 0;
}

function isScanOverdue(device) {
  const intervalSeconds = device.agent_settings?.inventory_interval_seconds || 900;
  if (!device.last_scan_at) return true;
  const ageSeconds = (Date.now() - new Date(device.last_scan_at).getTime()) / 1000;
  return ageSeconds > intervalSeconds * 2;
}

function renderReports() {
  const selected = $("#trendDevice").value;
  $("#trendDevice").innerHTML = '<option value="">Entire fleet</option>' + state.devices.map(d =>
    `<option value="${escapeHtml(d.id)}">${escapeHtml(d.display_name || d.hostname)}</option>`).join("");
  $("#trendDevice").value = selected;
  renderComplianceSummary();
  renderComplianceByPlatform();
  renderComplianceTrends();
  renderReportFilters();
}

function renderThemeSwatches() {
  const container = $("#themeSwatches");
  if (!container || container.dataset.initialized) return;
  container.dataset.initialized = "true";
  const current = currentAccentHex();
  container.innerHTML = ACCENT_PRESETS.map((preset) => `
    <button type="button" class="theme-swatch${preset.hex === current ? " active" : ""}" data-accent="${preset.hex}" style="--swatch-color:${preset.hex};--swatch-dark:${preset.bg};--swatch-glow:${preset.glow}" aria-label="${escapeHtml(preset.name)}" aria-pressed="${preset.hex === current ? "true" : "false"}"><span aria-hidden="true"></span>${escapeHtml(preset.name)}</button>
  `).join("");
}

function renderAdmin() {
  renderThemeSwatches();
  const metricsInput = $("#defaultMetricsInterval");
  const inventoryInput = $("#defaultInventoryInterval");
  if (document.activeElement !== metricsInput) metricsInput.value = state.fleetSettings.default_metrics_interval_seconds;
  if (document.activeElement !== inventoryInput) inventoryInput.value = state.fleetSettings.default_inventory_interval_seconds;
}

function renderComplianceTrends() {
  const container = $("#reportsTrends");
  const history = state.reportHistory || [];
  if (history.length < 2) {
    container.innerHTML = '<div class="empty">Not enough history yet. Trends appear once the fleet has reported on more than one day.</div>';
    return;
  }
  const latest = history[history.length - 1];
  const dateRange = `${latest.date === history[0].date ? "" : `${history[0].date} – `}${latest.date}`;
  container.innerHTML = `
    <p class="form-note">${history.length} reporting days (${escapeHtml(dateRange)}). Scope: ${escapeHtml($("#trendDevice").selectedOptions[0]?.textContent || "Entire fleet")}. Each device contributes its first report of that UTC day; missing days are not zeroes. Summary cards above remain fleet-wide.</p>
    <div class="chart-grid-wrap">
      ${lineChart("Fully patched", `${latest.fully_patched_percent}%`, history, (day) => day.fully_patched_percent, 100, "chart-green")}
      ${lineChart("No critical/high vulnerabilities", `${latest.no_critical_high_percent}%`, history, (day) => day.no_critical_high_percent, 100, "chart-blue")}
      ${lineChart("Online", `${latest.online_percent}%`, history, (day) => day.online_percent, 100, "chart-green")}
      ${lineChart("Vulnerabilities", `${latest.total_vulnerabilities}`, history, (day) => day.total_vulnerabilities, null, "chart-orange")}
    </div>
  `;
}

function renderComplianceSummary() {
  const devices = state.devices;
  const total = devices.length;
  const pct = (count) => total === 0 ? "—" : `${Math.round((count / total) * 100)}%`;
  const fullyPatched = devices.filter(isFullyPatched).length;
  const noCriticalHigh = devices.filter(hasNoCriticalHighVulns).length;
  const online = devices.filter((device) => device.online).length;
  const overdue = devices.filter(isScanOverdue).length;

  $("#reportsSummary").innerHTML = `
    <article><span>Fully patched</span><strong>${pct(fullyPatched)}</strong><small>${fullyPatched} of ${total} devices</small></article>
    <article><span>No critical/high vulnerabilities</span><strong>${pct(noCriticalHigh)}</strong><small>${noCriticalHigh} of ${total} devices</small></article>
    <article><span>Online now</span><strong>${pct(online)}</strong><small>${online} of ${total} devices</small></article>
    <article><span>Scan overdue</span><strong>${overdue}</strong><small>past 2&times; their scan interval</small></article>
  `;
}

function renderComplianceByPlatform() {
  const groups = new Map();
  for (const device of state.devices) {
    const key = device.package_manager || "Unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(device);
  }
  const rows = [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  $("#reportsByPlatform").innerHTML = rows.length ? rows.map(([platform, devices]) => {
    const total = devices.length;
    const pct = (count) => total === 0 ? "—" : `${Math.round((count / total) * 100)}%`;
    return `<tr>
      <td>${escapeHtml(platform)}</td>
      <td>${total}</td>
      <td>${pct(devices.filter(isFullyPatched).length)}</td>
      <td>${pct(devices.filter(hasNoCriticalHighVulns).length)}</td>
      <td>${pct(devices.filter((device) => device.online).length)}</td>
    </tr>`;
  }).join("") : '<tr><td colspan="5" class="empty">No devices have enrolled.</td></tr>';
}

const REPORT_FIELDS = [
  { key: "hostname", label: "Hostname", value: (d) => d.hostname || "", default: true },
  { key: "display_name", label: "Display name", value: (d) => d.display_name || "" },
  { key: "platform", label: "Platform", value: (d) => d.platform || "" },
  { key: "package_manager", label: "Package manager", value: (d) => d.package_manager || "", default: true },
  { key: "os_name", label: "OS name", value: (d) => d.os_name || "", default: true },
  { key: "os_version", label: "OS version", value: (d) => d.os_version || "" },
  { key: "architecture", label: "Architecture", value: (d) => d.architecture || "" },
  { key: "agent_version", label: "Agent version", value: (d) => d.agent_version || "" },
  { key: "online", label: "Online", value: (d) => d.online ? "Yes" : "No", default: true },
  { key: "enrolled_at", label: "Enrolled at", value: (d) => fullDate(d.enrolled_at) },
  { key: "last_seen", label: "Last seen", value: (d) => fullDate(d.last_seen), default: true },
  { key: "update_count", label: "Needed patches", value: (d) => d.update_count ?? 0, default: true },
  { key: "security_update_count", label: "Security patches", value: (d) => d.security_update_count ?? 0 },
  { key: "vulnerability_count", label: "Vulnerabilities", value: (d) => d.vulnerability_count ?? 0, default: true },
  { key: "critical_vulns", label: "Critical vulnerabilities", value: (d) => d.vulnerability_severity_counts?.CRITICAL || 0 },
  { key: "high_vulns", label: "High vulnerabilities", value: (d) => d.vulnerability_severity_counts?.HIGH || 0 },
  { key: "exposed_vulns", label: "Exposed vulnerabilities (listening)", value: (d) => d.vulnerability_exposed_count ?? 0 },
  { key: "installed_package_count", label: "Installed packages", value: (d) => d.installed_package_count ?? 0 },
  { key: "last_scan_at", label: "Last scan", value: (d) => fullDate(d.last_scan_at) },
  { key: "last_vulnerability_scan_at", label: "Last vulnerability scan", value: (d) => fullDate(d.last_vulnerability_scan_at) },
  { key: "last_patched_at", label: "Last patched", value: (d) => fullDate(d.last_patched_at) },
];

function renderReportFilters() {
  const platformSelect = $("#reportFilterPlatform");
  const platforms = [...new Set(state.devices.map((device) => device.package_manager).filter(Boolean))].sort();
  const signature = platforms.join("|");
  if (platformSelect.dataset.signature !== signature) {
    platformSelect.dataset.signature = signature;
    const current = platformSelect.value;
    platformSelect.innerHTML = '<option value="all">All platforms</option>' +
      platforms.map((platform) => `<option value="${escapeHtml(platform)}">${escapeHtml(platform)}</option>`).join("");
    if ([...platformSelect.options].some((option) => option.value === current)) platformSelect.value = current;
  }

  const fieldsContainer = $("#reportFieldOptions");
  if (!fieldsContainer.dataset.initialized) {
    fieldsContainer.dataset.initialized = "true";
    fieldsContainer.innerHTML = REPORT_FIELDS.map((field) => `
      <label class="toggle-setting">
        <input type="checkbox" data-report-field="${field.key}" ${field.default ? "checked" : ""}>
        <span>${escapeHtml(field.label)}</span>
      </label>`).join("");
  }
}

function filteredReportDevices() {
  const platform = $("#reportFilterPlatform").value;
  const status = $("#reportFilterStatus").value;
  const search = $("#reportFilterSearch").value.trim().toLowerCase();
  return state.devices.filter((device) => {
    if (platform !== "all" && device.package_manager !== platform) return false;
    if (status === "online" && !device.online) return false;
    if (status === "offline" && device.online) return false;
    if (search && !`${device.hostname} ${device.os_name || ""}`.toLowerCase().includes(search)) return false;
    return true;
  });
}

function selectedReportFields() {
  return REPORT_FIELDS.filter((field) => document.querySelector(`[data-report-field="${field.key}"]`)?.checked);
}

function generateReport() {
  const devices = filteredReportDevices();
  const fields = selectedReportFields();
  state.reportRows = devices.map((device) => fields.map((field) => field.value(device)));
  state.reportFields = fields;

  $("#reportPreviewHead").innerHTML = `<tr>${fields.map((field) => `<th>${escapeHtml(field.label)}</th>`).join("")}</tr>`;
  $("#reportPreviewBody").innerHTML = devices.length
    ? state.reportRows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(String(value))}</td>`).join("")}</tr>`).join("")
    : `<tr><td colspan="${Math.max(fields.length, 1)}" class="empty">No devices match these filters.</td></tr>`;
  $("#reportPreviewWrap").hidden = false;
  $("#reportSummaryText").textContent = `${devices.length} device${devices.length === 1 ? "" : "s"} · ${fields.length} column${fields.length === 1 ? "" : "s"} selected.`;

  const hasData = devices.length > 0 && fields.length > 0;
  $("#reportDownloadCsv").disabled = !hasData;
  $("#reportPrint").disabled = !hasData;
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function downloadReportCsv() {
  const fields = state.reportFields || [];
  const rows = state.reportRows || [];
  const lines = [fields.map((field) => csvCell(field.label)).join(",")]
    .concat(rows.map((row) => row.map(csvCell).join(",")));
  const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `fleetview-fleet-report-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function printReport() {
  $("#reportPrintHeader").textContent = `FleetView Fleet Report — Generated ${new Date().toLocaleString()}`;
  window.print();
}

async function deployPackage(deviceIds, packageName) {
  const results = await Promise.allSettled(deviceIds.map((deviceId) =>
    api(`/api/v1/admin/devices/${deviceId}/jobs`, {
      method: "POST",
      body: JSON.stringify({ type: "INSTALL_PACKAGE", options: { package: packageName } }),
    })
  ));
  const failed = results.filter((result) => result.status === "rejected");
  const succeeded = results.length - failed.length;
  if (failed.length === 0) {
    showNotice(`Queued ${packageName} for ${succeeded} device${succeeded === 1 ? "" : "s"}.`);
  } else {
    const reason = failed[0].reason?.message || "unknown error";
    showNotice(`Queued ${packageName} for ${succeeded} of ${results.length} devices. ${failed.length} failed to queue: ${reason}`, true);
  }
  await refresh();
}

function render() {
  renderDashboard();
  renderPatching();
  renderInventory();
  renderDeploy();
  renderReports();
  renderJobs();
  renderEnrollmentTokens();
  renderInstallCommand();
  if (state.user?.role === "admin") { renderAgentSettingsOptions(); renderAgentVersionsTable(); renderIntegrations(); }
  renderAdmin();
  applyPermissions();
}

function chartPoints(samples, valueFunction, width = 640, height = 130, fixedMax = null) {
  const values = samples.map((sample) => Number(valueFunction(sample))).map((value) => Number.isFinite(value) ? Math.max(0, value) : 0);
  if (!values.length) return { points: "", max: 0 };
  const maximum = fixedMax || Math.max(...values, 1);
  const points = values.map((value, index) => {
    const x = values.length === 1 ? width / 2 : (index / (values.length - 1)) * width;
    const y = height - (Math.min(value, maximum) / maximum) * (height - 8) - 4;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return { points, max: maximum };
}

function lineChart(title, currentLabel, samples, valueFunction, fixedMax = null, colorClass = "chart-green") {
  const series = chartPoints(samples, valueFunction, 640, 130, fixedMax);
  return `<article class="chart-card">
    <div class="chart-title"><div><small>${escapeHtml(title)}</small><strong>${escapeHtml(currentLabel)}</strong></div><span>${samples.length} samples</span></div>
    <svg viewBox="0 0 640 130" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(title)} history">
      <line x1="0" y1="126" x2="640" y2="126" class="chart-grid"></line>
      <line x1="0" y1="65" x2="640" y2="65" class="chart-grid"></line>
      <polyline points="${series.points}" class="chart-line ${colorClass}"></polyline>
    </svg>
  </article>`;
}

function renderMonitoring(device) {
  const container = $("#monitoringContent");
  if (state.detailHistoryLoading) {
    container.innerHTML = '<div class="empty">Loading monitoring history…</div>';
    return;
  }
  const live = state.liveMetricsByDevice.get(device.id);
  const metrics = live || device.metrics;
  if (!metrics) {
    container.innerHTML = '<div class="empty">No telemetry has arrived yet. The upgraded agent sends its first sample after one minute.</div>';
    return;
  }
  const liveBadge = live
    ? '<span class="pill succeeded live-pulse">● Live</span>'
    : state.liveDeviceIds.has(device.id)
      ? '<span class="pill pending">Connecting…</span>'
      : '<span class="pill severity-unknown">Not live (showing last reported sample)</span>';
  const samples = state.detailHistory;
  const memory = usagePercent(metrics.memory_used_bytes, metrics.memory_total_bytes);
  const disk = usagePercent(metrics.disk_used_bytes, metrics.disk_total_bytes);
  const swap = usagePercent(metrics.swap_used_bytes, metrics.swap_total_bytes);
  const temperature = metrics.temperature_celsius === null || metrics.temperature_celsius === undefined ? "Not reported" : `${Number(metrics.temperature_celsius).toFixed(1)}°C`;
  const memoryValue = (sample) => usagePercent(sample.memory_used_bytes, sample.memory_total_bytes) || 0;
  const diskValue = (sample) => usagePercent(sample.disk_used_bytes, sample.disk_total_bytes) || 0;
  const networkMax = Math.max(...samples.flatMap((sample) => [Number(sample.network_receive_bps) || 0, Number(sample.network_transmit_bps) || 0]), 1);
  const receiveSeries = chartPoints(samples, (sample) => sample.network_receive_bps, 640, 130, networkMax);
  const transmitSeries = chartPoints(samples, (sample) => sample.network_transmit_bps, 640, 130, networkMax);
  const historyStart = samples.length ? fullDate(samples[0].recorded_at) : "Waiting for samples";
  const historyEnd = samples.length ? fullDate(samples[samples.length - 1].recorded_at) : "Waiting for samples";
  const gpus = Array.isArray(metrics.gpus) ? metrics.gpus : [];
  const gpuCards = gpus.length ? `<section class="gpu-section"><div><p class="eyebrow">GPU MONITORING</p><h3>Graphics processors</h3></div><div class="gpu-grid">${gpus.map((gpu) => {
    const gpuMemory = usagePercent(gpu.memory_used_bytes, gpu.memory_total_bytes);
    const temperatureValue = gpu.temperature_celsius === null || gpu.temperature_celsius === undefined ? "Not reported" : `${Number(gpu.temperature_celsius).toFixed(1)}°C`;
    const powerValue = gpu.power_watts === null || gpu.power_watts === undefined ? "Not reported" : `${Number(gpu.power_watts).toFixed(1)} W`;
    return `<article><div class="gpu-title"><div><small>${escapeHtml(gpu.vendor)}</small><strong>${escapeHtml(gpu.name)}</strong></div><span>GPU ${escapeHtml(gpu.index)}</span></div><dl><div><dt>Utilization</dt><dd>${formatPercent(gpu.utilization_percent)}</dd></div><div><dt>VRAM</dt><dd>${gpu.memory_total_bytes ? formatUsage(gpu.memory_used_bytes, gpu.memory_total_bytes) : "Not reported"}</dd></div><div><dt>Temperature</dt><dd>${escapeHtml(temperatureValue)}</dd></div><div><dt>Power</dt><dd>${escapeHtml(powerValue)}</dd></div></dl>${usageBar(gpu.utilization_percent)}${gpuMemory === null ? "" : usageBar(gpuMemory, "blue")}</article>`;
  }).join("")}</div></section>` : '<section class="gpu-section empty-gpu"><p>No supported GPU telemetry was detected on this device.</p></section>';

  const consumers = Array.isArray(metrics.top_consumers) ? [...metrics.top_consumers] : [];
  const sortKey = state.topConsumersSort;
  consumers.sort((a, b) => (Number(b[sortKey]) || 0) - (Number(a[sortKey]) || 0));
  const consumerRows = consumers.length ? consumers.map((item) => `
    <tr>
      <td><span class="pill ${item.kind === "container" ? "succeeded" : "unknown"}">${escapeHtml(item.kind)}</span></td>
      <td class="package-name">${escapeHtml(item.name || "Unknown")}</td>
      <td>${item.kind === "process" && item.pid ? escapeHtml(item.pid) : "—"}</td>
      <td>${formatPercent(item.cpu_percent)}</td>
      <td>${formatBytes(item.memory_bytes)}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No process/container data reported yet -- requires agent 0.22.0 or later.</td></tr>';
  const topConsumersSection = `
    <section class="top-consumers-section">
      <div class="monitoring-heading">
        <div><p class="eyebrow">LIVE SNAPSHOT</p><h3>Top resource consumers</h3></div>
        <div class="consumer-sort-toggle">
          <button type="button" class="secondary ${sortKey === "cpu_percent" ? "active" : ""}" data-consumer-sort="cpu_percent">Sort by CPU</button>
          <button type="button" class="secondary ${sortKey === "memory_bytes" ? "active" : ""}" data-consumer-sort="memory_bytes">Sort by memory</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Kind</th><th>Name</th><th>PID</th><th>CPU</th><th>Memory</th></tr></thead>
          <tbody>${consumerRows}</tbody>
        </table>
      </div>
      <p class="form-note">Host processes and running Docker containers merged into one list: the top entries by CPU and by memory (deduplicated), not a single blended score.</p>
    </section>`;

  container.innerHTML = `
    <p class="live-status-line">${liveBadge}</p>
    <div class="current-metrics">
      <div><small>CPU</small><strong>${formatPercent(metrics.cpu_percent)}</strong>${usageBar(metrics.cpu_percent)}</div>
      <div><small>Memory</small><strong>${formatPercent(memory)}</strong><span>${formatUsage(metrics.memory_used_bytes, metrics.memory_total_bytes)}</span>${usageBar(memory)}</div>
      <div><small>Root disk</small><strong>${formatPercent(disk)}</strong><span>${formatUsage(metrics.disk_used_bytes, metrics.disk_total_bytes)}</span>${usageBar(disk, disk >= 90 ? "orange" : "green")}</div>
      <div><small>Swap</small><strong>${metrics.swap_total_bytes ? formatPercent(swap) : "Not configured"}</strong><span>${metrics.swap_total_bytes ? formatUsage(metrics.swap_used_bytes, metrics.swap_total_bytes) : "—"}</span>${usageBar(swap)}</div>
      <div><small>Temperature</small><strong>${escapeHtml(temperature)}</strong><span>${metrics.process_count || 0} processes</span></div>
      <div><small>Network now</small><strong>↓ ${formatRate(metrics.network_receive_bps)}</strong><span>↑ ${formatRate(metrics.network_transmit_bps)}</span></div>
    </div>
    ${gpuCards}
    ${topConsumersSection}
    <div class="chart-grid-wrap">
      ${lineChart("CPU usage", formatPercent(metrics.cpu_percent), samples, (sample) => sample.cpu_percent, 100)}
      ${lineChart("Memory usage", formatPercent(memory), samples, memoryValue, 100, "chart-blue")}
      ${lineChart("Root disk usage", formatPercent(disk), samples, diskValue, 100, "chart-orange")}
      <article class="chart-card">
        <div class="chart-title"><div><small>Network throughput</small><strong>↓ ${formatRate(metrics.network_receive_bps)} · ↑ ${formatRate(metrics.network_transmit_bps)}</strong></div><span>${samples.length} samples</span></div>
        <svg viewBox="0 0 640 130" preserveAspectRatio="none" role="img" aria-label="Network throughput history">
          <line x1="0" y1="126" x2="640" y2="126" class="chart-grid"></line><line x1="0" y1="65" x2="640" y2="65" class="chart-grid"></line>
          <polyline points="${receiveSeries.points}" class="chart-line chart-blue"></polyline><polyline points="${transmitSeries.points}" class="chart-line chart-orange"></polyline>
        </svg>
      </article>
    </div>
    <p class="history-range">History shown: ${escapeHtml(historyStart)} to ${escapeHtml(historyEnd)}. Samples are retained for seven days.</p>`;
}

function renderOverview(device) {
  const inventory = device.inventory || {};
  const addresses = Array.isArray(inventory.ip_addresses) ? inventory.ip_addresses.join(", ") : "Unknown";
  const macAddresses = Array.isArray(inventory.mac_addresses) ? inventory.mac_addresses : [];
  const canWake = macAddresses.length > 0 && !device.online && state.user?.role !== "viewer";
  const relayOptions = state.devices.filter((item) => item.id !== device.id && item.online);
  const wakeSection = canWake ? `
    <section class="wake-on-lan"><p class="eyebrow">POWER</p>
      <dl><div><dt>MAC address${macAddresses.length > 1 ? "es" : ""}</dt><dd>${escapeHtml(macAddresses.join(", "))}</dd></div></dl>
      ${relayOptions.length ? `
        <div class="device-actions">
          <label>Wake via <select id="wakeRelayDevice">${relayOptions.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.display_name || item.hostname)}</option>`).join("")}</select></label>
          <button type="button" id="wakeDeviceButton" data-device-id="${escapeHtml(device.id)}">Wake on LAN</button>
        </div>
        <p class="form-note">Sends a magic packet from the selected online device -- it must be on the same LAN as this one, since broadcast packets don't cross routers.</p>
      ` : '<p class="form-note">No other device is currently online to relay a wake packet from.</p>'}
    </section>` : "";
  $("#detailOverview").innerHTML = `
    <section><p class="eyebrow">SYSTEM</p><dl>
      <div><dt>Hostname</dt><dd>${escapeHtml(device.hostname)}</dd></div>
      <div><dt>Operating system</dt><dd>${escapeHtml([device.os_name, device.os_version].filter(Boolean).join(" "))}</dd></div>
      <div><dt>Kernel</dt><dd>${escapeHtml(inventory.kernel || "Unknown")}</dd></div>
      <div><dt>Architecture</dt><dd>${escapeHtml(device.architecture || "Unknown")}</dd></div>
      <div><dt>Uptime</dt><dd>${formatUptime(inventory.uptime_seconds)}</dd></div>
    </dl></section>
    <section><p class="eyebrow">HARDWARE</p><dl>
      <div><dt>Processor</dt><dd>${escapeHtml(inventory.cpu_model || "Unknown")}</dd></div>
      <div><dt>Logical CPUs</dt><dd>${escapeHtml(inventory.logical_cpus || "Unknown")}</dd></div>
      <div><dt>Load average (1 / 5 / 15 min)</dt><dd>${formatLoad(inventory)}</dd></div>
      <div><dt>Memory at last scan</dt><dd>${formatUsage(inventory.memory_used_bytes, inventory.memory_bytes)}</dd></div>
      <div><dt>Memory available</dt><dd>${formatBytes(inventory.memory_available_bytes)}</dd></div>
      <div><dt>Root disk at last scan</dt><dd>${formatUsage(inventory.root_disk_used_bytes, inventory.root_disk_total_bytes)}</dd></div>
      <div><dt>Root disk available</dt><dd>${formatBytes(inventory.root_disk_available_bytes)}</dd></div>
    </dl></section>
    <section><p class="eyebrow">MANAGEMENT</p><dl>
      <div><dt>IP addresses</dt><dd>${escapeHtml(addresses)}</dd></div>
      <div><dt>Package manager</dt><dd>${escapeHtml(device.package_manager || "Unknown")}</dd></div>
      <div><dt>Agent version</dt><dd>${escapeHtml(device.agent_version || "Unknown")}</dd></div>
      <div><dt>Last seen</dt><dd>${escapeHtml(fullDate(device.last_seen))}</dd></div>
      <div><dt>Last inventory scan</dt><dd>${escapeHtml(fullDate(device.last_scan_at))}</dd></div>
      <div><dt>Last vulnerability scan</dt><dd>${escapeHtml(fullDate(device.last_vulnerability_scan_at))}</dd></div>
      <div><dt>Last successful patch</dt><dd>${escapeHtml(fullDate(device.last_patched_at))}</dd></div>
    </dl></section>
    ${wakeSection}`;
}

function renderDeviceDetails() {
  const device = state.detailDevice;
  if (!device) return;
  const inventory = device.inventory || {};
  const dockerAvailable = inventory.docker_available === true;
  $("#dockerContainersTab").hidden = !dockerAvailable;
  if (!dockerAvailable && state.detailTab === "docker") state.detailTab = "overview";
  const versionParts = String(device.agent_version || "").split(".").map(Number);
  const terminalSupported = state.user?.role === "admin" && (versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 18));
  $("#terminalTab").hidden = !terminalSupported;
  if (!terminalSupported && state.detailTab === "terminal") state.detailTab = "overview";
  const remoteControl = inventory.remote_control || {};
  // Gated on the agent's version (matching the server's own
  // supports_remote_control check), not on remoteControl.available: an
  // unavailable device still opens the tab so its Reason (no desktop
  // session found, a missing tool, etc.) is visible rather than the whole
  // feature just silently not being there.
  const screenSupported = state.user?.role === "admin" && (versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 23));
  $("#screenTab").hidden = !screenSupported;
  if (!screenSupported && state.detailTab === "screen") state.detailTab = "overview";
  const severities = device.vulnerability_severity_counts || {};
  $("#detailTitle").textContent = device.display_name || device.hostname;
  $("#detailSubtitle").textContent = [device.os_name, device.os_version, device.architecture].filter(Boolean).join(" · ");
  $("#detailMetrics").innerHTML = `
    <div><small>Status</small><strong>${device.online ? "Online" : "Offline"}</strong></div>
    <div><small>Needed patches</small><strong>${device.update_count || 0}</strong></div>
    <div><small>Vulnerabilities</small><strong>${device.vulnerability_count || 0}</strong></div>
    <div><small>Critical / High</small><strong>${severities.CRITICAL || 0} / ${severities.HIGH || 0}</strong></div>
    <div><small>Installed packages</small><strong>${device.installed_package_count || 0}</strong></div>
    <div><small>Memory</small><strong>${formatBytes(inventory.memory_bytes)}</strong></div>`;

  document.querySelectorAll("[data-detail-tab]").forEach((button) => {
    const active = button.dataset.detailTab === state.detailTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });

  const overview = state.detailTab === "overview";
  const monitoring = state.detailTab === "monitoring";
  const terminal = state.detailTab === "terminal";
  const screen = state.detailTab === "screen";
  $("#detailOverview").hidden = !overview;
  $("#detailMonitoring").hidden = !monitoring;
  $("#detailTerminal").hidden = !terminal;
  $("#detailScreen").hidden = !screen;
  $("#detailSearch").hidden = overview || monitoring || terminal || screen;
  $("#detailTableSummary").hidden = overview || monitoring || terminal || screen;
  $("#detailTableWrap").hidden = overview || monitoring || terminal || screen;
  $("#patchControls").hidden = state.detailTab !== "patches";
  $("#detailFootnote").textContent = "";
  if (overview) {
    renderOverview(device);
    return;
  }
  if (monitoring) {
    renderMonitoring(device);
    return;
  }
  if (terminal) {
    connectTerminal(device.id);
    return;
  }
  if (screen) {
    if (remoteControl.available === true) {
      connectScreen(device.id, remoteControl.view_only === true);
    } else {
      disconnectScreen();
      $("#screenContainer").dataset.input = "false";
      $("#screenViewOnlyNote").hidden = true;
      $("#screenStatus").textContent = remoteControl.reason || "Not available on this device yet -- it may need to report inventory again after a recent upgrade.";
    }
    return;
  }

  const query = $("#detailSearch").value.trim().toLowerCase();
  const sources = {
    patches: device.available_updates || [],
    vulnerabilities: device.vulnerabilities || [],
    installed: device.installed_packages || [],
    docker: Array.isArray(inventory.docker_containers) ? inventory.docker_containers : [],
  };
  const source = sources[state.detailTab] || [];
  const filtered = source.filter((item) => Object.values(item).some((value) => String(value ?? "").toLowerCase().includes(query)));
  const visible = filtered.slice(0, 250);
  const nouns = {
    patches: filtered.length === 1 ? "needed patch" : "needed patches",
    vulnerabilities: filtered.length === 1 ? "vulnerability" : "vulnerabilities",
    installed: filtered.length === 1 ? "installed package" : "installed packages",
    docker: filtered.length === 1 ? "Docker container" : "Docker containers",
  };
  $("#detailTableSummary").textContent = filtered.length > visible.length
    ? `Showing the first ${visible.length} of ${filtered.length} matches. Refine the search to narrow the list.`
    : `${filtered.length} ${nouns[state.detailTab]}.`;

  if (state.detailTab === "docker") {
    $("#detailTableHead").innerHTML = "<tr><th>Container</th><th>Image</th><th>State</th><th>Status</th><th>Ports</th><th>Created</th><th>Controls</th></tr>";
    $("#detailTableBody").innerHTML = visible.length ? visible.map((item) => {
      const ports = Array.isArray(item.ports) ? item.ports.map((port) => {
        const publicPort = port.public_port ?? port.PublicPort;
        const privatePort = port.private_port ?? port.PrivatePort;
        const protocol = port.type ?? port.Type;
        const address = port.ip ?? port.IP;
        return publicPort ? `${address || "0.0.0.0"}:${publicPort} → ${privatePort}/${protocol}` : `${privatePort}/${protocol}`;
      }).join(", ") : "—";
      const agentParts = String(device.agent_version || "").split(".").map(Number);
      const agentReady = agentParts[0] > 0 || agentParts[0] === 0 && agentParts[1] >= 15;
      const canManage = state.user?.role !== "viewer" && agentReady && device.agent_settings?.docker_inventory_enabled !== false;
      const actions = ["running", "paused", "restarting"].includes(item.state) ? ["stop", "restart"] : ["start"];
      const controls = canManage ? actions.map(action => `<button type="button" class="secondary" data-docker-action="${action}" data-container-id="${escapeHtml(item.id)}">${action[0].toUpperCase() + action.slice(1)}</button>`).join(" ") : "—";
      return `<tr><td class="package-name">${escapeHtml(item.name || item.id)}</td><td><code>${escapeHtml(item.image)}</code></td><td><span class="pill ${item.state === "running" ? "succeeded" : "unknown"}">${escapeHtml(item.state)}</span></td><td>${escapeHtml(item.status)}</td><td>${escapeHtml(ports || "—")}</td><td>${escapeHtml(fullDate(item.created_at))}</td><td>${controls}</td></tr>`;
    }).join("") : '<tr><td colspan="7" class="empty">Docker is available, but no containers were returned.</td></tr>';
    $("#detailFootnote").textContent = `Docker inventory from the last device scan: ${fullDate(device.last_scan_at)}. Actions require agent 0.15.0, run when it checks in, and refresh inventory afterward.`;
  } else if (state.detailTab === "patches") {
    const approvals = state.patchApprovals[device.id] || [];
    const decisions = new Map(approvals.map(item => [`${item.key}\u0000${item.available_version}`, item]));
    $("#detailTableHead").innerHTML = "<tr><th>Package</th><th>Installed version</th><th>Available version</th><th>Security</th><th>Reboot</th><th>Decision</th></tr>";
    $("#detailTableBody").innerHTML = visible.length ? visible.map((item) => {
      const key = item.identifier || item.package;
      const decision = decisions.get(`${key}\u0000${item.available_version}`);
      return `<tr><td class="package-name">${escapeHtml(item.package)}</td><td><code>${escapeHtml(item.installed_version)}</code></td><td><code>${escapeHtml(item.available_version)}</code></td><td>${flagLabel(item.security_update)}</td><td>${flagLabel(item.reboot_required)}</td><td>${device.package_manager === "winget" && !item.identifier || decision?.supported === false ? "Unsupported Windows update" : `<button type="button" class="secondary" data-approve-patch="${escapeHtml(key)}" data-patch-version="${escapeHtml(item.available_version)}" ${state.user?.role === "viewer" ? "disabled" : ""}>${decision?.approved ? "Approved · revoke" : "Not approved · approve"}</button>`}</td></tr>`;
    }).join("") : '<tr><td colspan="6" class="empty">No needed patches match this view.</td></tr>';
    const schedule = state.patchSchedules[device.id];
    $("#patchInterval").value = schedule?.interval_hours ?? 0;
    $("#patchScheduleInfo").textContent = schedule?.next_run_at ? `Next due: ${fullDate(schedule.next_run_at)}. Only currently approved patches will be queued.` : "Schedule disabled. Approved patches remain ready for manual deployment.";
    $("#deployApprovedPatches").disabled = state.user?.role === "viewer" || !approvals.some(item => item.approved && item.supported);
    $("#approveAllPatches").disabled = state.user?.role === "viewer" || !approvals.some(item => !item.approved && item.supported);
    $("#patchScheduleForm").querySelector("button").disabled = state.user?.role === "viewer";
    $("#patchInterval").disabled = state.user?.role === "viewer";
    $("#detailFootnote").textContent = device.package_manager === "pacman"
      ? "Arch requires approval of all pending patches before a full system upgrade. Partial upgrades are blocked."
      : "New versions need fresh approval after a scan. Debian checks the transaction for unapproved dependencies. Windows Update entries without winget IDs cannot be deployed here.";
  } else if (state.detailTab === "vulnerabilities") {
    $("#detailTableHead").innerHTML = "<tr><th>Severity</th><th>ID</th><th>Package</th><th>Installed</th><th>Fixed version</th><th>Status</th><th>Exposure</th></tr>";
    $("#detailTableBody").innerHTML = visible.length ? visible.map((item) => {
      const url = safeUrl(item.primary_url);
      const id = url === "#" ? escapeHtml(item.vulnerability_id) : `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.vulnerability_id)}</a>`;
      return `<tr title="${escapeHtml(item.title || "")}"><td>${severityPill(item.severity)}</td><td>${id}</td><td class="package-name">${escapeHtml(item.package)}</td><td><code>${escapeHtml(item.installed_version)}</code></td><td><code>${escapeHtml(item.fixed_version || "Not available")}</code></td><td>${escapeHtml(item.status)}</td><td>${exposurePill(item)}</td></tr>`;
    }).join("") : '<tr><td colspan="7" class="empty">No vulnerabilities match this view. Run a vulnerability scan if one has not completed yet.</td></tr>';
    $("#detailFootnote").textContent = `Scanner: ${device.vulnerability_scanner || "Not yet scanned"} ${device.vulnerability_scanner_version || ""} · Last scan: ${fullDate(device.last_vulnerability_scan_at)} · "Listening" means a process matching the vulnerable package name is bound to a network port on this device -- a heuristic name match, not a guarantee.`;
  } else {
    $("#detailTableHead").innerHTML = "<tr><th>Package</th><th>Installed version</th><th>Architecture</th><th>Source</th></tr>";
    $("#detailTableBody").innerHTML = visible.length ? visible.map((item) => `
      <tr><td class="package-name">${escapeHtml(item.name)}</td><td><code>${escapeHtml(item.version)}</code></td><td>${escapeHtml(item.architecture || device.architecture || "Unknown")}</td><td>${escapeHtml(item.source || device.package_manager || "Unknown")}</td></tr>`).join("")
      : '<tr><td colspan="4" class="empty">No installed packages match this view.</td></tr>';
  }
}

async function openDeviceDetails(deviceId, tab = "overview") {
  const dialog = $("#deviceDialog");
  state.detailDevice = null;
  state.detailTab = tab;
  state.detailHistory = [];
  state.detailHistoryLoading = tab === "monitoring";
  $("#detailSearch").value = "";
  $("#detailTitle").textContent = "Loading device…";
  $("#detailSubtitle").textContent = "";
  $("#detailMetrics").innerHTML = "";
  $("#detailOverview").innerHTML = "";
  $("#detailTableSummary").textContent = "Loading device data…";
  $("#detailTableHead").innerHTML = "";
  $("#detailTableBody").innerHTML = "";
  if (!dialog.open) dialog.showModal();
  try {
    const [details, approvals, schedule] = await Promise.all([
      api(`/api/v1/admin/devices/${deviceId}`),
      api(`/api/v1/admin/devices/${deviceId}/patch-approvals`),
      api(`/api/v1/admin/devices/${deviceId}/patch-schedule`),
    ]);
    state.detailDevice = details;
    state.patchApprovals[deviceId] = approvals;
    state.patchSchedules[deviceId] = schedule;
    renderDeviceDetails();
    if (tab === "monitoring") { await loadMetricHistory(); connectDeviceMetrics(deviceId); }
  } catch (error) {
    $("#detailTableSummary").textContent = error.message;
  }
}

async function loadMetricHistory() {
  if (!state.detailDevice) return;
  state.detailHistoryLoading = true;
  renderDeviceDetails();
  try {
    const hours = Number($("#metricRange").value) || 24;
    state.detailHistory = await api(`/api/v1/admin/devices/${state.detailDevice.id}/metrics?hours=${hours}`);
  } catch (error) {
    showNotice(error.message, true);
    state.detailHistory = [];
  } finally {
    state.detailHistoryLoading = false;
    renderDeviceDetails();
  }
}

function showNotice(message, error = false) {
  $("#notice").textContent = message;
  $("#notice").className = `notice${error ? " error" : ""}`;
}

function trendURL() {
  const params = new URLSearchParams();
  if ($("#trendDevice").value) params.set("device_id", $("#trendDevice").value);
  if ($("#trendStart").value || $("#trendEnd").value) {
    params.set("start", $("#trendStart").value);
    params.set("end", $("#trendEnd").value);
  } else { params.set("days", "30"); }
  return "/api/v1/admin/reports/history?" + params;
}

async function loadScanSchedule() {
  const id = $("#agentSettingsDevice").value;
  $("#saveScanSchedule").disabled = true;
  if (!id) return;
  try {
    const schedule = await api(`/api/v1/admin/devices/${id}/vulnerability-schedule`);
    if ($("#agentSettingsDevice").value !== id) return;
    $("#scanInterval").value = schedule.interval_hours;
    $("#saveScanSchedule").disabled = false;
    $("#scanScheduleStatus").textContent = !schedule.supported
      ? "This platform does not support vulnerability scanning. Leave disabled."
      : schedule.next_run_at ? `Next due: ${fullDate(schedule.next_run_at)}. Runs at the next agent check-in; missed runs do not accumulate.` : "Automatic scans disabled.";
  } catch (error) { showNotice(error.message, true); }
}

$("#scanScheduleForm").addEventListener("submit", async event => {
  event.preventDefault();
  const id = $("#agentSettingsDevice").value;
  if (!id) return;
  try {
    await api(`/api/v1/admin/devices/${id}/vulnerability-schedule`, {
      method: "PUT", body: JSON.stringify({interval_hours: Number($("#scanInterval").value)})
    });
    await loadScanSchedule();
    showNotice("Scan schedule saved. Disabling does not cancel jobs already queued.");
  } catch (error) { showNotice(error.message, true); }
});
$("#upgradeAgentButton").addEventListener("click", () => upgradeAgentDevice($("#agentSettingsDevice").value, $("#upgradeAgentButton")));
$("#agentVersionsTable").addEventListener("click", (event) => {
  const button = event.target.closest("[data-upgrade-agent]");
  if (button) upgradeAgentDevice(button.dataset.upgradeAgent, button);
});
$("#trendFilters").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    state.reportHistory = await api(trendURL());
    renderComplianceTrends();
  } catch (error) { showNotice(error.message, true); }
});
$("#trendEnd").value = new Date().toISOString().slice(0, 10);
$("#trendStart").value = new Date(Date.now() - 29 * 86400000).toISOString().slice(0, 10);

async function refresh() {
  if (!state.user || state.user.must_change_password) return;
  const generation = state.authGeneration;
  $("#refreshButton").disabled = true;
  try {
    const results = await Promise.all([
      api("/api/v1/admin/devices"),
      api("/api/v1/admin/jobs"),
      state.user.role === "admin" ? api("/api/v1/admin/enrollment-tokens") : Promise.resolve([]),
      api(trendURL()),
      api("/api/v1/admin/settings"),
      api("/api/v1/admin/packages"),
      state.user.role === "admin" ? api("/api/v1/admin/custom-packages") : Promise.resolve([]),
      state.user.role === "admin" ? api("/api/v1/admin/agent-version").catch(() => null) : Promise.resolve(null),
      api("/api/v1/admin/integrations").catch(() => []),
    ]);
    if (!state.user || generation !== state.authGeneration) return;
    [state.devices, state.jobs, state.enrollmentTokens, state.reportHistory, state.fleetSettings, state.packages, state.customPackages, state.publishedAgentVersion, state.integrations] = results;
    showNotice(state.devices.length ? "Fleet data is current." : "Server is ready. Enroll the first agent to populate the fleet.");
    $("#refreshState").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    render();
  } catch (error) {
    showNotice(error.message, true);
    $("#refreshState").textContent = "Connection failed";
  } finally { $("#refreshButton").disabled = false; }
}

async function queueJob(deviceId, type, options = {}) {
  try {
    await api(`/api/v1/admin/devices/${deviceId}/jobs`, { method: "POST", body: JSON.stringify({ type, options }) });
    showNotice(`${type.replaceAll("_", " ")} queued successfully.`);
    setPage("patching");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
}

async function queueUpdate(deviceId) {
  const device = state.devices.find((item) => item.id === deviceId);
  if (!device) return;
  try {
    const patches = await api(`/api/v1/admin/devices/${deviceId}/patch-approvals`);
    state.patchApprovals[deviceId] = patches;
    const selected = patches.filter(patch => patch.approved && patch.supported);
    if (!selected.length) { showNotice("Review this device's needed patches and approve at least one first.", true); openDeviceDetails(deviceId, "patches"); return; }
    if (device.package_manager === "pacman" && selected.length !== patches.length) {
      showNotice("Arch requires approval of every pending patch before a full upgrade.", true); openDeviceDetails(deviceId, "patches"); return;
    }
    if (!confirm(`Deploy ${selected.length} approved patch${selected.length === 1 ? "" : "es"} to ${device.hostname}?\n\n${selected.map(item => `${item.package}: ${item.available_version}`).join("\n")}\n\nThe agent checks versions again before changing software.`)) return;
    await api(`/api/v1/admin/devices/${deviceId}/deploy-approved-patches`, { method: "POST" });
    showNotice(`Queued ${selected.length} approved patch${selected.length === 1 ? "" : "es"} for ${device.hostname}.`);
    await refresh();
  } catch (error) { showNotice(error.message, true); }
}

function handleDeviceAction(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const deviceId = button.dataset.deviceId;
  if (button.dataset.action === "details") openDeviceDetails(deviceId, button.dataset.tab || "overview");
  if (button.dataset.action === "scan") queueJob(deviceId, "SCAN_DEVICE");
  if (button.dataset.action === "vulnerability-scan") queueJob(deviceId, "SCAN_VULNERABILITIES");
  if (button.dataset.action === "update") queueUpdate(deviceId);
}

$("#appTabs").addEventListener("click", (event) => {
  const button = event.target.closest("[data-page]");
  if (button) setPage(button.dataset.page);
});
$("#patchDevices").addEventListener("click", handleDeviceAction);
$("#inventoryDevices").addEventListener("click", handleDeviceAction);
$("#networkTopologyTable").addEventListener("click", handleDeviceAction);
$("#detailTableBody").addEventListener("click", async event => {
  const dockerButton = event.target.closest("[data-docker-action]");
  if (dockerButton) {
    const device = state.detailDevice;
    if (!device || state.user?.role === "viewer") return;
    const container = device.inventory?.docker_containers?.find(item => item.id === dockerButton.dataset.containerId);
    const action = dockerButton.dataset.dockerAction;
    if (!container || !["start", "stop", "restart"].includes(action)) return;
    if (!confirm(`${action[0].toUpperCase() + action.slice(1)} Docker container ${container.name || container.id} on ${device.hostname}?\n\nStopping or restarting a service can interrupt users. If this is the FleetView server container, the dashboard will be unavailable until it starts again.`)) return;
    dockerButton.disabled = true;
    try {
      await api(`/api/v1/admin/devices/${device.id}/jobs`, {
        method: "POST", body: JSON.stringify({type: "DOCKER_CONTAINER_ACTION", options: {action, container_id: container.id, confirmed: true}}),
      });
      showNotice(`Docker ${action} queued for ${container.name || container.id}. Check Jobs for the result.`);
    } catch (error) { dockerButton.disabled = false; showNotice(error.message, true); }
    return;
  }
  const button = event.target.closest("[data-approve-patch]");
  const device = state.detailDevice;
  if (!button || !device) return;
  const current = (state.patchApprovals[device.id] || []).find(item => item.key === button.dataset.approvePatch && item.available_version === button.dataset.patchVersion);
  button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}/patch-approvals`, {
      method: "PUT", body: JSON.stringify({ package: button.dataset.approvePatch, available_version: button.dataset.patchVersion, approved: !current?.approved }),
    });
    state.patchApprovals[device.id] = await api(`/api/v1/admin/devices/${device.id}/patch-approvals`);
    renderDeviceDetails();
    showNotice(current?.approved ? "Patch approval revoked." : "Patch approved for this version.");
  } catch (error) { button.disabled = false; showNotice(error.message, true); }
});
$("#deployApprovedPatches").addEventListener("click", () => {
  if (state.detailDevice) queueUpdate(state.detailDevice.id);
});
$("#approveAllPatches").addEventListener("click", async () => {
  const device = state.detailDevice;
  if (!device) return;
  const pending = (state.patchApprovals[device.id] || []).filter(item => !item.approved && item.supported);
  if (!pending.length) return;
  const button = $("#approveAllPatches");
  button.disabled = true;
  try {
    const outcomes = await Promise.allSettled(pending.map(item => api(`/api/v1/admin/devices/${device.id}/patch-approvals`, {
      method: "PUT", body: JSON.stringify({ package: item.key, available_version: item.available_version, approved: true }),
    })));
    const failed = outcomes.filter(result => result.status === "rejected");
    state.patchApprovals[device.id] = await api(`/api/v1/admin/devices/${device.id}/patch-approvals`);
    renderDeviceDetails();
    showNotice(`Approved ${pending.length - failed.length} patch${pending.length - failed.length === 1 ? "" : "es"}.${failed.length ? ` ${failed.length} failed: ${failed[0].reason.message}` : ""}`, Boolean(failed.length));
  } catch (error) { showNotice(error.message, true); }
  finally { renderDeviceDetails(); }
});
$("#patchScheduleForm").addEventListener("submit", async event => {
  event.preventDefault();
  const device = state.detailDevice;
  if (!device) return;
  try {
    state.patchSchedules[device.id] = await api(`/api/v1/admin/devices/${device.id}/patch-schedule`, {
      method: "PUT", body: JSON.stringify({ interval_hours: Number($("#patchInterval").value) }),
    });
    renderDeviceDetails();
    showNotice("Patch schedule saved. Currently approved versions will deploy when due.");
  } catch (error) { showNotice(error.message, true); }
});
$("#monitorDevices").addEventListener("click", (event) => {
  const card = event.target.closest("[data-action='details']");
  if (card) openDeviceDetails(card.dataset.deviceId, "monitoring");
});
$("#monitorDevices").addEventListener("keydown", (event) => {
  const card = event.target.closest("[data-action='details']");
  if (card && ["Enter", " "].includes(event.key)) {
    event.preventDefault();
    openDeviceDetails(card.dataset.deviceId, "monitoring");
  }
});
$("#inventorySearch").addEventListener("input", renderInventory);
$("#deployDeviceSearch").addEventListener("input", renderDeployDevices);
$("#deployDeviceList").addEventListener("change", (event) => {
  const checkbox = event.target.closest("[data-deploy-device]");
  if (!checkbox) return;
  if (checkbox.checked) state.deploySelected.add(checkbox.dataset.deployDevice);
  else state.deploySelected.delete(checkbox.dataset.deployDevice);
  updateDeploySubmitState();
});
$("#deployForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const packageName = $("#deployPackageName").value.trim();
  const deviceIds = [...state.deploySelected];
  if (!packageName || deviceIds.length === 0) return;
  const names = deviceIds.map((id) => {
    const device = state.devices.find((item) => item.id === id);
    return device ? (device.display_name || device.hostname) : id;
  });
  if (!confirm(`Deploy "${packageName}" to ${deviceIds.length} device${deviceIds.length === 1 ? "" : "s"}?\n\n${names.join(", ")}\n\nMake sure this package name is valid for every selected device's platform.`)) return;
  const button = $("#deploySubmit");
  button.disabled = true;
  try {
    await deployPackage(deviceIds, packageName);
    state.deploySelected.clear();
    $("#deployPackageName").value = "";
  } finally {
    updateDeploySubmitState();
  }
});
$("#runCommandForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const command = $("#runCommandText").value.trim();
  const deviceIds = [...state.deploySelected];
  if (!command || deviceIds.length === 0) return;
  const names = deviceIds.map((id) => {
    const device = state.devices.find((item) => item.id === id);
    return device ? (device.display_name || device.hostname) : id;
  });
  if (!confirm(`Run this command on ${deviceIds.length} device${deviceIds.length === 1 ? "" : "s"}?\n\n${names.join(", ")}\n\nCommand:\n${command}\n\nThis runs once with the agent service's privileges and cannot be interrupted once an agent claims it.`)) return;
  const button = $("#runCommandSubmit");
  button.disabled = true;
  try {
    const outcomes = await Promise.allSettled(deviceIds.map(id => api(`/api/v1/admin/devices/${id}/run-command`, {
      method: "POST", body: JSON.stringify({ command, confirmed: true }),
    })));
    const failed = outcomes.filter(result => result.status === "rejected");
    showNotice(`Queued on ${deviceIds.length - failed.length} device(s).${failed.length ? ` ${failed.length} failed: ${failed[0].reason.message}` : ""}`, Boolean(failed.length));
    $("#runCommandText").value = "";
    setPage("patching");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { updateDeploySubmitState(); }
});
$("#netDiagTool").addEventListener("change", () => {
  $("#netDiagPortLabel").hidden = $("#netDiagTool").value !== "port_check";
});
$("#netDiagForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const tool = $("#netDiagTool").value;
  const target = $("#netDiagTarget").value.trim();
  const port = $("#netDiagPort").value ? Number($("#netDiagPort").value) : null;
  const deviceIds = [...state.deploySelected];
  if (!target || deviceIds.length === 0) return;
  if (tool === "port_check" && !port) { showNotice("Port check requires a port.", true); return; }
  const button = $("#netDiagSubmit");
  button.disabled = true;
  try {
    const outcomes = await Promise.allSettled(deviceIds.map(id => api(`/api/v1/admin/devices/${id}/network-diagnostic`, {
      method: "POST", body: JSON.stringify({ tool, target, port }),
    })));
    const failed = outcomes.filter(result => result.status === "rejected");
    showNotice(`Queued on ${deviceIds.length - failed.length} device(s).${failed.length ? ` ${failed.length} failed: ${failed[0].reason.message}` : ""}`, Boolean(failed.length));
    setPage("patching");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { updateDeploySubmitState(); }
});
$("#customPackageForm").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const files = [...form.elements.files.files];
  if (!files.length || files.length > 5 || files.some(file => file.size > 8 * 1024 * 1024 || !file.size) || files.reduce((sum, file) => sum + file.size, 0) > 16 * 1024 * 1024) {
    showNotice("Choose one to five nonempty files, at most 8 MiB each and 16 MiB total.", true); return;
  }
  const button = form.querySelector("button[type='submit']");
  button.disabled = true;
  try {
    await api("/api/v1/admin/custom-packages", { method: "POST", body: new FormData(form) });
    form.reset();
    showNotice("Custom package saved. Select target devices, then deploy it.");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});
$("#customPackageRows").addEventListener("click", async event => {
  const button = event.target.closest("[data-custom-deploy]");
  if (!button) return;
  const pkg = state.customPackages.find(item => item.id === button.dataset.customDeploy);
  if (!pkg) return;
  const selected = state.devices.filter(device => state.deploySelected.has(device.id));
  const targets = selected.filter(device => pkg.platform === (device.platform === "windows" ? "windows" : "linux"));
  if (!targets.length) { showNotice("Select a device with the same platform as this custom package.", true); return; }
  if (!confirm(`Run custom installer "${pkg.name}" on ${targets.length} device(s)?\n\nFiles: ${pkg.files.map(file => file.filename).join(", ")}\nCommand: ${pkg.command}\n\nThe agent runs this command with its service privileges.`)) return;
  button.disabled = true;
  try {
    const outcomes = await Promise.allSettled(targets.map(device => api(`/api/v1/admin/custom-packages/${pkg.id}/devices/${device.id}/deploy`, { method: "POST", body: JSON.stringify({ confirmed: true }) })));
    const failed = outcomes.filter(result => result.status === "rejected");
    showNotice(`Queued ${targets.length - failed.length} install(s). ${failed.length ? `${failed.length} failed: ${failed[0].reason.message}` : ""}`, Boolean(failed.length));
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});
$("#packageForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    name: $("#packageName").value.trim(),
    description: $("#packageDescription").value.trim(),
    version: $("#packageVersion").value.trim(),
    category: $("#packageCategory").value.trim(),
    pacman_name: $("#packagePacman").value.trim(),
    apt_name: $("#packageApt").value.trim(),
    winget_id: $("#packageWinget").value.trim(),
  };
  const button = $("#packageSubmit");
  button.disabled = true;
  try {
    if (state.editingPackageId) {
      await api(`/api/v1/admin/packages/${state.editingPackageId}`, { method: "PUT", body: JSON.stringify(payload) });
      showNotice(`${payload.name} updated.`);
    } else {
      await api("/api/v1/admin/packages", { method: "POST", body: JSON.stringify(payload) });
      showNotice(`${payload.name} saved to the catalog.`);
    }
    resetPackageForm();
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});
$("#packageCancelEdit").addEventListener("click", resetPackageForm);
$("#packageCatalog").addEventListener("click", async (event) => {
  const uninstallButton = event.target.closest("[data-uninstall-package]");
  if (uninstallButton) {
    const pkg = state.packages.find(item => item.id === uninstallButton.dataset.uninstallPackage);
    uninstallButton.disabled = true;
    try { if (pkg) await deployCatalogPackage(pkg, true); }
    catch (error) { showNotice(error.message, true); }
    finally { uninstallButton.disabled = false; }
    return;
  }
  const deployButton = event.target.closest("[data-deploy-package]");
  const editButton = event.target.closest("[data-edit-package]");
  const deleteButton = event.target.closest("[data-delete-package]");
  if (deployButton) {
    const pkg = state.packages.find((item) => item.id === deployButton.dataset.deployPackage);
    if (pkg) await deployCatalogPackage(pkg);
    return;
  }
  if (editButton) {
    const pkg = state.packages.find((item) => item.id === editButton.dataset.editPackage);
    if (pkg) startEditPackage(pkg);
    return;
  }
  if (deleteButton) {
    const pkg = state.packages.find((item) => item.id === deleteButton.dataset.deletePackage);
    if (!pkg || !confirm(`Delete "${pkg.name}" from the catalog? This does not affect devices it was already deployed to.`)) return;
    deleteButton.disabled = true;
    try {
      await api(`/api/v1/admin/packages/${pkg.id}`, { method: "DELETE" });
      if (state.editingPackageId === pkg.id) resetPackageForm();
      showNotice(`${pkg.name} removed from the catalog.`);
      await refresh();
    } catch (error) { showNotice(error.message, true); deleteButton.disabled = false; }
  }
});
$("#agentSettingsDevice").addEventListener("change", loadAgentSettingsForm);
$("#agentSettingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const deviceId = $("#agentSettingsDevice").value;
  if (!deviceId) return;
  const code = $("#uninstallCode").value;
  const payload = {
    metrics_interval_seconds: Number($("#metricsInterval").value),
    inventory_interval_seconds: Number($("#inventoryInterval").value),
    gpu_monitoring_enabled: $("#gpuMonitoringEnabled").checked,
    docker_inventory_enabled: $("#dockerInventoryEnabled").checked,
    uninstall_code_required: $("#uninstallCodeRequired").checked,
    uninstall_code: code || null,
  };
  try {
    const settings = await api(`/api/v1/admin/devices/${deviceId}/settings`, { method: "PUT", body: JSON.stringify(payload) });
    const device = state.devices.find((item) => item.id === deviceId);
    if (device) device.agent_settings = settings;
    $("#uninstallCode").value = "";
    showNotice("Agent settings saved. The device will pick them up within about one minute.");
  } catch (error) { showNotice(error.message, true); }
});
$("#installPlatform").addEventListener("change", renderInstallCommand);
$("#installServerURL").addEventListener("input", renderInstallCommand);
$("#generateEnrollmentToken").addEventListener("click", async () => {
  const button = $("#generateEnrollmentToken");
  button.disabled = true;
  try {
    state.freshToken = await api("/api/v1/admin/enrollment-tokens", {
      method: "POST",
      body: JSON.stringify({
        label: $("#installTokenLabel").value.trim() || null,
        ttl_minutes: Number($("#installTokenTTL").value),
      }),
    });
    state.enrollmentTokens = await api("/api/v1/admin/enrollment-tokens");
    renderEnrollmentTokens();
    showNotice("One-time enrollment token created. Copy the command now; the token is not shown again.");
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; renderInstallCommand(); }
});
$("#enrollmentTokens").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-revoke-token]");
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/enrollment-tokens/${encodeURIComponent(button.dataset.revokeToken)}`, { method: "DELETE" });
    state.enrollmentTokens = await api("/api/v1/admin/enrollment-tokens");
    renderEnrollmentTokens();
    renderInstallCommand();
    showNotice("Enrollment token revoked.");
  } catch (error) { showNotice(error.message, true); button.disabled = false; }
});
$("#copyInstallCommand").addEventListener("click", async () => {
  try {
    await copyText($("#installCommand").textContent);
    showNotice("Installation command copied.");
  } catch { showNotice("Could not access the clipboard. Select and copy the command manually.", true); }
});
$("#copyWindowsInstallCommand").addEventListener("click", async () => {
  try {
    await copyText($("#windowsInstallCommand").textContent);
    showNotice("Installation command copied.");
  } catch { showNotice("Could not access the clipboard. Select and copy the command manually.", true); }
});
$("#reportGenerate").addEventListener("click", generateReport);
$("#reportDownloadCsv").addEventListener("click", downloadReportCsv);
$("#reportPrint").addEventListener("click", printReport);
$("#refreshButton").addEventListener("click", refresh);
$("#authButton").addEventListener("click", async () => {
  if (!state.user) { await initializeAuth(); return; }
  try {
    await api("/api/v1/auth/logout", {method: "POST"});
    endLocalSession();
    openLogin("You have signed out.");
  } catch (error) { showNotice(error.message, true); }
});
$("#closeDeviceDialog").addEventListener("click", () => $("#deviceDialog").close());
$("#deviceDialog").addEventListener("close", () => { disconnectDeviceMetrics(); disconnectTerminal(); disconnectScreen(); });
$("#removeDeviceButton").addEventListener("click", async () => {
  const device = state.detailDevice;
  if (!device) return;
  const confirmed = confirm(
    `Remove ${device.hostname} from the fleet?\n\n` +
    "This permanently deletes its enrollment, inventory, job history, and monitoring history from the server. " +
    "If its agent is still installed and running, it will start failing to report until you re-enroll it.\n\n" +
    "This cannot be undone."
  );
  if (!confirmed) return;
  const button = $("#removeDeviceButton");
  button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}`, { method: "DELETE" });
    $("#deviceDialog").close();
    showNotice(`${device.hostname} was removed from the fleet.`);
    await refresh();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    button.disabled = false;
  }
});
$("#detailSearch").addEventListener("input", renderDeviceDetails);
$("#deviceDialog").addEventListener("click", async (event) => {
  const tab = event.target.closest("[data-detail-tab]");
  if (!tab) return;
  state.detailTab = tab.dataset.detailTab;
  $("#detailSearch").value = "";
  renderDeviceDetails();
  if (state.detailTab === "monitoring") {
    if (!state.detailHistory.length) await loadMetricHistory();
    if (state.detailDevice) connectDeviceMetrics(state.detailDevice.id);
  } else {
    disconnectDeviceMetrics();
  }
  if (state.detailTab !== "terminal") disconnectTerminal();
  if (state.detailTab !== "screen") disconnectScreen();
});

// Remote-control input capture: fraction-based mouse coordinates (see
// screenPointerFraction) and raw KeyboardEvent.key values, both matching
// what agent/internal/live/screen.go expects on the other end. mouseup is
// bound to the window rather than the container so a drag that ends
// outside the frame still releases the button instead of leaving it
// stuck down on the remote device.
$("#screenContainer").addEventListener("mousemove", (event) => {
  if (!state.screenInputEnabled || !state.screenSocket) return;
  const point = screenPointerFraction(event);
  if (point) state.screenSocket.send({ type: "mouse_move", x: point.x, y: point.y });
});
$("#screenContainer").addEventListener("mousedown", (event) => {
  if (!state.screenInputEnabled || !state.screenSocket) return;
  event.preventDefault();
  $("#screenContainer").focus();
  const point = screenPointerFraction(event);
  const button = SCREEN_BUTTON_NAMES[event.button];
  if (!point || !button) return;
  state.screenPointerDown = true;
  state.screenSocket.send({ type: "mouse_button", x: point.x, y: point.y, button, pressed: true });
});
window.addEventListener("mouseup", (event) => {
  if (!state.screenPointerDown || !state.screenInputEnabled || !state.screenSocket) return;
  state.screenPointerDown = false;
  const point = screenPointerFraction(event);
  const button = SCREEN_BUTTON_NAMES[event.button];
  if (point && button) state.screenSocket.send({ type: "mouse_button", x: point.x, y: point.y, button, pressed: false });
});
$("#screenContainer").addEventListener("contextmenu", (event) => {
  if (state.screenInputEnabled) event.preventDefault();
});
$("#screenContainer").addEventListener("wheel", (event) => {
  if (!state.screenInputEnabled || !state.screenSocket) return;
  event.preventDefault();
  state.screenSocket.send({ type: "mouse_scroll", dx: event.deltaX / 100, dy: event.deltaY / 100 });
}, { passive: false });
$("#screenContainer").addEventListener("keydown", (event) => {
  if (!state.screenInputEnabled || !state.screenSocket) return;
  event.preventDefault();
  event.stopPropagation();
  state.screenSocket.send({ type: "key", key: event.key, pressed: true });
});
$("#screenContainer").addEventListener("keyup", (event) => {
  if (!state.screenInputEnabled || !state.screenSocket) return;
  event.preventDefault();
  event.stopPropagation();
  state.screenSocket.send({ type: "key", key: event.key, pressed: false });
});
$("#deviceDialog").addEventListener("click", async (event) => {
  const button = event.target.closest("#wakeDeviceButton");
  if (!button) return;
  const relayId = $("#wakeRelayDevice")?.value;
  const device = state.devices.find((item) => item.id === button.dataset.deviceId);
  if (!relayId || !device) return;
  const relay = state.devices.find((item) => item.id === relayId);
  if (!confirm(`Send a Wake-on-LAN packet for ${device.display_name || device.hostname}, relayed via ${relay?.display_name || relay?.hostname || relayId}?`)) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}/wake`, { method: "POST", body: JSON.stringify({ relay_device_id: relayId }) });
    showNotice(`Wake-on-LAN packet sent for ${device.display_name || device.hostname}.`);
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});
$("#metricRange").addEventListener("change", loadMetricHistory);
$("#monitoringContent").addEventListener("click", (event) => {
  const button = event.target.closest("[data-consumer-sort]");
  if (!button) return;
  state.topConsumersSort = button.dataset.consumerSort;
  if (state.detailDevice) renderMonitoring(state.detailDevice);
});
$("#themeSwatches").addEventListener("click", (event) => {
  const button = event.target.closest("[data-accent]");
  if (!button) return;
  applyAccent(button.dataset.accent);
  try { localStorage.setItem("fleetviewAccent", button.dataset.accent); } catch {}
  document.querySelectorAll(".theme-swatch").forEach((swatch) => {
    swatch.classList.toggle("active", swatch === button);
    swatch.setAttribute("aria-pressed", swatch === button ? "true" : "false");
  });
});
$("#fleetSettingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    state.fleetSettings = await api("/api/v1/admin/settings", {
      method: "PUT",
      body: JSON.stringify({
        default_metrics_interval_seconds: Number($("#defaultMetricsInterval").value),
        default_inventory_interval_seconds: Number($("#defaultInventoryInterval").value),
      }),
    });
    showNotice("Fleet defaults saved.");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
});
applyAccent(currentAccentHex());
setPage("dashboard");
$("#installServerURL").value = window.location.origin;
renderInstallCommand();
initializeAuth();
setInterval(() => { if (state.user && !state.user.must_change_password) refresh(); }, 30000);
