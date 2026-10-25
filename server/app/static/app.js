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
  detailContainerHistory: [],
  detailHistoryLoading: false,
  agentOptionsSignature: "",
  enrollmentTokens: [],
  freshToken: null,
  deploySelected: new Set(),
  inventorySelected: new Set(),
  inventoryTagFilter: "",
  notificationChannels: [],
  alertRules: [],
  scripts: [],
  editingScriptId: null,
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
  filesSocket: null,
  filesDeviceId: null,
  filesPath: "",
  filesEditingPath: null,
  filesEditingTruncated: false,
  topConsumersSort: "cpu_percent",
  topConsumersSortDir: "desc",
  expandedGPUProcesses: new Set(),
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
function connectLiveSocket(path, { onMessage, onOpen, onClose, shouldReconnect, retryMs = 3000 }) {
  const holder = { socket: null, stopped: false };
  if (typeof WebSocket === "undefined") return { close: () => {}, send: () => {} };
  const attempt = () => {
    if (holder.stopped) return;
    const socket = new WebSocket(wsBase() + path);
    holder.socket = socket;
    socket.addEventListener("open", () => onOpen && onOpen());
    socket.addEventListener("message", (event) => {
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
    // Returns whether the payload was actually sent, so a caller that
    // needs to know (e.g. an upload) can tell "silently dropped because
    // the socket isn't open right now" apart from "sent" instead of the
    // two looking identical, which is exactly what made upload failures
    // look like nothing happened at all.
    send: (payload) => {
      if (holder.socket?.readyState !== WebSocket.OPEN) return false;
      holder.socket.send(JSON.stringify(payload));
      return true;
    },
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
  // xterm.js captures every keystroke itself (including Ctrl/Cmd+C) and
  // sends it to the remote shell as input by default -- with a selection
  // active, that means the terminal fires SIGINT instead of letting the
  // browser's native copy run, so there is no way to copy text out of it
  // at all. Standard xterm.js workaround: when Ctrl/Cmd+C is pressed and
  // something is selected, tell xterm not to handle the event (return
  // false) so it falls through to the browser's normal copy instead of
  // being sent to the shell. With nothing selected, Ctrl+C still reaches
  // the shell as SIGINT exactly as before.
  term.attachCustomKeyEventHandler((event) => {
    if (event.type === "keydown" && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "c" && term.hasSelection()) {
      return false;
    }
    return true;
  });
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

// A live, on-demand view of this device's filesystem -- not a queued job,
// same one-session-per-device model as the terminal (see live.rs's
// claim_files). Unlike the terminal, there's nothing to keep "running"
// between requests: each directory the admin clicks into is a fresh
// "list" request, and the agent has no per-session state to lose, so a
// reconnect for the same device is harmless (unlike connectTerminal, which
// deliberately refuses to reconnect a dead session).
function connectFiles(deviceId, path = "") {
  if (state.filesDeviceId !== deviceId || !state.filesSocket) {
    disconnectFiles();
    state.filesDeviceId = deviceId;
    $("#filesStatus").textContent = "Connecting…";
    const socket = connectLiveSocket(`/api/v1/admin/devices/${deviceId}/files-live`, {
      // Contrary to this function's own leading comment, this used to be
      // hardcoded to never reconnect -- so a connection dropped by any
      // idle timeout, network blip, or backgrounded tab left state.filesSocket
      // holding a permanently dead socket. Every later list/read/write
      // (including an upload) silently no-oped forever after that (see
      // connectLiveSocket's send(), which only checks readyState without
      // raising anything), with nothing in the UI beyond a now-easy-to-miss
      // "Disconnected" status. Reconnecting is genuinely harmless here, so
      // actually do what the comment already claimed.
      shouldReconnect: () => state.filesDeviceId === deviceId,
      onOpen: () => { $("#filesStatus").textContent = "Connected"; requestFilesList(state.filesPath || path); },
      onClose: () => { $("#filesStatus").textContent = "Disconnected"; },
      onMessage: (message) => {
        if (message.type === "files_list_result") {
          $("#filesStatus").textContent = "Live";
          renderFilesListing(message);
        } else if (message.type === "files_read_result") {
          if (state.filesEditingPath === message.path) {
            openFilesEditorWithContent(message);
          } else {
            handleFileDownload(message);
          }
        } else if (message.type === "files_write_result") {
          handleFilesWriteResult(message);
        } else if (message.type === "files_closed") {
          $("#filesStatus").textContent = `Session ended: ${message.reason || "closed"}`;
        } else if (message.type === "error") {
          $("#filesStatus").textContent = `Error: ${message.reason || "rejected"}`;
        }
      },
    });
    state.filesSocket = socket;
  } else {
    requestFilesList(path);
  }
}

function requestFilesList(path) {
  state.filesPath = path;
  $("#filesListing").innerHTML = '<tr><td colspan="4" class="empty">Loading…</td></tr>';
  state.filesSocket?.send({ type: "list", path });
}

function disconnectFiles() {
  state.filesSocket?.close();
  state.filesSocket = null;
  state.filesDeviceId = null;
  state.filesPath = "";
}

function filesParentPath(path, separator) {
  const trimmed = path.replace(new RegExp(`\\${separator}+$`), "");
  const idx = trimmed.lastIndexOf(separator);
  if (idx <= 0) return separator === "\\" ? trimmed.slice(0, 3) : "/";
  return trimmed.slice(0, idx) || separator;
}

function renderFilesListing(message) {
  if (message.error) {
    $("#filesListing").innerHTML = `<tr><td colspan="4" class="empty">${escapeHtml(message.error)}</td></tr>`;
    $("#filesBreadcrumb").textContent = message.path || "";
    return;
  }
  const path = message.path || "";
  const separator = path.includes("\\") && !path.includes("/") ? "\\" : "/";
  state.filesPath = path;
  const parent = path.length > 1 ? filesParentPath(path, separator) : null;
  $("#filesBreadcrumb").innerHTML = parent !== null
    ? `<button type="button" data-files-up>↑ Up</button> · ${escapeHtml(path)}`
    : escapeHtml(path);
  const entries = message.entries || [];
  const rows = entries.map((entry) => {
    const fullPath = path.endsWith(separator) ? `${path}${entry.name}` : `${path}${separator}${entry.name}`;
    if (entry.is_dir) {
      return `<tr data-files-dir="${escapeHtml(fullPath)}"><td class="package-name">📁 ${escapeHtml(entry.name)}</td><td>—</td><td>${escapeHtml(fullDate(entry.modified_at))}</td><td></td></tr>`;
    }
    return `<tr><td>${escapeHtml(entry.name)}</td><td>${formatBytes(entry.size)}</td><td>${escapeHtml(fullDate(entry.modified_at))}</td>` +
      `<td><button type="button" class="secondary" data-files-download="${escapeHtml(fullPath)}">Download</button> ` +
      `<button type="button" class="secondary" data-files-edit="${escapeHtml(fullPath)}">Edit</button></td></tr>`;
  }).join("");
  $("#filesListing").innerHTML = rows || '<tr><td colspan="4" class="empty">Empty directory.</td></tr>';
  if (message.truncated) {
    $("#filesListing").insertAdjacentHTML("beforeend", `<tr><td colspan="4" class="empty">Showing the first entries only; this directory has more.</td></tr>`);
  }
}

function handleFileDownload(message) {
  if (message.error) { showNotice(message.error, true); return; }
  const bytes = base64ToBytes(message.data || "");
  const blob = new Blob([bytes]);
  const name = message.path.split(/[\\/]/).pop() || "download";
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = name;
  document.body.appendChild(link); link.click(); link.remove();
  URL.revokeObjectURL(url);
  if (message.truncated) showNotice(`${name} was larger than the 8 MiB limit; only the first part was downloaded.`, true);
}

// Editing reuses the same files_read/files_read_result round trip as
// Download (see connectFiles's onMessage) -- state.filesEditingPath marks
// the in-flight request as "open the editor with this" rather than
// "download this", since the server can't tell the two apart itself.
function openFilesEditor(path) {
  state.filesEditingPath = path;
  state.filesSocket?.send({ type: "read", path });
}

function openFilesEditorWithContent(message) {
  state.filesEditingTruncated = Boolean(message.truncated);
  if (message.error) { showNotice(message.error, true); state.filesEditingPath = null; return; }
  $("#filesEditPath").textContent = message.path;
  $("#filesEditNote").textContent = message.truncated
    ? "This file is larger than the 8 MiB limit -- only the first part loaded, so saving is disabled to avoid truncating it."
    : "Saving overwrites the file on the device directly.";
  $("#saveFilesEdit").disabled = message.truncated;
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(base64ToBytes(message.data || "")); }
  catch { text = null; }
  if (text === null) {
    $("#filesEditContent").value = "";
    $("#filesEditNote").textContent = "This doesn't look like a text file (not valid UTF-8); editing isn't supported.";
    $("#saveFilesEdit").disabled = true;
  } else {
    $("#filesEditContent").value = text;
  }
  $("#filesEditDialog").showModal();
}

function closeFilesEditor() {
  state.filesEditingPath = null;
  $("#filesEditDialog").close();
  $("#filesEditContent").value = "";
}

function handleFilesWriteResult(message) {
  if (message.error) { showNotice(message.error, true); return; }
  showNotice(`Saved ${message.path}.`);
  if (state.filesEditingPath === message.path) closeFilesEditor();
  requestFilesList(state.filesPath);
}

function uploadFileToCurrentDirectory(file) {
  const separator = state.filesPath.includes("\\") && !state.filesPath.includes("/") ? "\\" : "/";
  const base = state.filesPath.endsWith(separator) ? state.filesPath : `${state.filesPath}${separator}`;
  const destination = `${base}${file.name}`;
  const existing = Array.from($("#filesListing").querySelectorAll("[data-files-download]"))
    .some(button => button.dataset.filesDownload === destination);
  if (existing && !confirm(`${file.name} already exists in this directory. Overwrite it?`)) return;
  const reader = new FileReader();
  reader.onload = () => {
    const bytes = new Uint8Array(reader.result);
    const sent = state.filesSocket?.send({ type: "write", path: destination, data: bytesToBase64(bytes) });
    if (!sent) showNotice("Not connected to this device's file session right now -- reopen the Files tab and try again.", true);
  };
  reader.onerror = () => showNotice("Could not read the selected file.", true);
  reader.readAsArrayBuffer(file);
}

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
  disconnectFiles();
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
  $("#tokenDialog").hidden = false;
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
  $("#tokenDialog").hidden = true;
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

function severityPill(severity, item) {
  const normalized = String(severity || "UNKNOWN").toUpperCase();
  const title = item?.severity_source === "nvd"
    ? ` title="Scored from the CVE's published NVD data${item.cvss_score != null ? ` (CVSS ${item.cvss_score})` : ""}, since the OS-native scanner reported no severity of its own"`
    : "";
  return `<span class="pill severity-${normalized.toLowerCase()}"${title}>${escapeHtml(normalized)}</span>`;
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
  // Device details is a page (data-page-panel="device-detail"), not a
  // dialog, so navigating away from it -- via the nav, the close button,
  // or removing the device -- is just a normal page switch. Its live
  // connections (metrics/terminal/files) only make sense while it's the
  // active page, so leaving it always tears them down.
  if (state.page === "device-detail" && page !== "device-detail") {
    disconnectDeviceMetrics(); disconnectTerminal(); disconnectFiles();
  }
  state.page = page;
  // Device details isn't one of the top-level nav tabs (there's no
  // data-page="device-detail" button) -- while it's open, Inventory stays
  // highlighted, since that's conceptually where you are and where
  // clicking Inventory again takes you.
  const highlightedPage = page === "device-detail" ? "inventory" : page;
  document.querySelectorAll("[data-page]").forEach((button) => button.classList.toggle("active", button.dataset.page === highlightedPage));
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
  const supportedPlatform = device.platform === "linux" || device.platform === "windows" || device.platform === "freebsd";
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
    const supportedPlatform = device.platform === "linux" || device.platform === "windows" || device.platform === "freebsd";
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
  const opnsense = platform === "opnsense";
  $("#linuxInstallOutput").hidden = windows;
  $("#windowsInstallOutput").hidden = !windows;

  const fresh = state.freshToken;
  const record = fresh && state.enrollmentTokens.find((item) => item.id === fresh.id);
  const status = record ? record.status : (fresh ? "active" : null);
  const usable = status === "active" && new Date(fresh.expires_at) > new Date();
  const serverURL = $("#installServerURL").value.trim().replace(/\/$/, "");
  const isHttps = /^https:\/\//i.test(serverURL);
  $("#installCaFingerprintField").hidden = !isHttps;
  // Only meaningful over HTTPS (it pins the CA fetched during the installer's
  // bootstrap, see docs/TLS.md) -- stray colons/whitespace from however the
  // admin copied it are harmless, both installers normalize it the same way.
  const caFingerprint = isHttps ? $("#installCaFingerprint").value.trim() : "";
  // Mirrors config.Load's own refusal (agent/internal/config/config.go):
  // without an explicit opt-in, the agent refuses to start against a
  // plain-HTTP, non-local server at all. Rather than send an admin a
  // command that installs successfully and then crash-loops, the opt-in
  // flag is included here automatically -- same spirit as PLAINTEXT
  // requiring FLEETVIEW_ALLOW_PLAINTEXT, just surfaced where the command
  // is actually generated instead of only as a runtime failure.
  const isHttpNonLoopback = /^http:\/\//i.test(serverURL)
    && !/^http:\/\/(127\.0\.0\.1|localhost|\[?::1\]?)(:|\/|$)/i.test(serverURL);

  if (windows) {
    const meta = $("#windowsInstallTokenMeta");
    $("#windowsInstallerSection").hidden = !usable;
    meta.hidden = !fresh;
    meta.textContent = tokenMetaText(fresh, status);
    if (usable) {
      // The downloadable installer is TOFU-only (see
      // /install/agent-windows-installer.exe and internal/selfinstall in
      // the agent) -- there's nowhere to type a pinned fingerprint into a
      // double-click, so caFingerprint intentionally never reaches this
      // URL even when set; an admin who wants that stronger guarantee
      // uses the PowerShell command below instead.
      const downloadURL = `${serverURL}/install/agent-windows-installer.exe`
        + `?server_url=${encodeURIComponent(serverURL)}&token=${encodeURIComponent(fresh.token)}`;
      $("#windowsInstallerDownload").href = downloadURL;

      const installerURL = `${serverURL}/install/windows.ps1`;
      // Two statements joined by `;` rather than `irm | iex`: the script
      // takes named parameters, and interpolating a token/fingerprint into
      // a string that iex re-parses is a quoting hazard this project
      // avoids elsewhere too -- `&` with real arguments isn't.
      $("#windowsInstallCommand").textContent =
        `$ps1 = "$env:TEMP\\install-fleetview-agent.ps1"; Invoke-WebRequest -Uri ${psQuote(installerURL)} -OutFile $ps1 -UseBasicParsing; `
        + `& $ps1 -ServerUrl ${psQuote(serverURL)} -EnrollmentToken ${psQuote(fresh.token)}`
        + (caFingerprint ? ` -CaFingerprint ${psQuote(caFingerprint)}` : "")
        + (isHttpNonLoopback ? ` -AllowPlaintext` : "");
    } else {
      $("#windowsInstallerDownload").href = "#";
      $("#windowsInstallCommand").textContent = "";
    }
    $("#windowsInstallCommandIntro").textContent = usable
      ? ("Download this and run it on the new Windows device:" + (isHttpNonLoopback
          ? " (plain HTTP, unencrypted -- see docs/TLS.md to enable TLS instead)"
          : ""))
      : "Generate a one-time token to get the installer for a new Windows device.";
    // The downloadable .exe has no command line to opt into plaintext on,
    // but install_agent_installer_windows (deployment.rs) bakes the same
    // automatic opt-in into the binary's trailer server-side when
    // server_url is http:// to a non-local address, so no warning is
    // needed here -- it behaves the same as the PowerShell command below.
    $("#windowsInstallerSection").title = "";
    return;
  }

  const meta = $("#installTokenMeta");
  $("#installCommandBlock").hidden = !usable;
  $("#copyInstallCommand").disabled = !usable;
  meta.hidden = !fresh;
  meta.textContent = tokenMetaText(fresh, status);
  $("#installSourceBundle").hidden = opnsense;
  if (usable) {
    if (opnsense) {
      // No local Go toolchain on a locked-down firewall appliance: this
      // downloads the prebuilt freebsd-amd64 binary the server already
      // cross-compiles (see server/Dockerfile), the same approach the
      // Windows installer uses, rather than compiling from source like
      // the Linux installer does.
      const installerURL = `${serverURL}/install/opnsense.sh`;
      $("#installCommand").textContent = `fetch -o /tmp/install-fleetview-agent-opnsense.sh ${shellQuote(installerURL)} && sh /tmp/install-fleetview-agent-opnsense.sh ${shellQuote(serverURL)} ${shellQuote(fresh.token)}`;
      $("#installCommandIntro").textContent = "Run this command from the OPNsense console or an SSH session (as root):";
      $("#installCommandNote").textContent = "Downloads the prebuilt FreeBSD agent binary, verifies its checksum, and starts it as an rc.d service. Each token enrolls exactly one device and then stops working. The token is shown only here and only once, so copy the command before leaving this page.";
    } else {
      const installerURL = `${serverURL}/install/linux.sh`;
      $("#installCommand").textContent = `curl -fsSL ${shellQuote(installerURL)} | sudo bash -s -- ${shellQuote(serverURL)} ${shellQuote(fresh.token)}`
        + (caFingerprint ? ` ${shellQuote(caFingerprint)}` : (isHttpNonLoopback ? ` --allow-plaintext` : ""));
      $("#installCommandIntro").textContent = "Run this command in a terminal on the new Linux device:";
      $("#installCommandNote").textContent = "The command installs build prerequisites, compiles the small native agent, enrolls it, and starts its systemd service. Each token enrolls exactly one device and then stops working. The token is shown only here and only once, so copy the command before leaving this page."
        + (isHttpNonLoopback ? " This server is plain HTTP, so the command includes --allow-plaintext -- traffic to it will be unencrypted. See docs/TLS.md to enable TLS instead." : "");
    }
  } else {
    $("#installCommand").textContent = "";
    $("#installCommandIntro").textContent = opnsense
      ? "Generate a one-time token to get the install command for a new OPNsense/FreeBSD device."
      : "Generate a one-time token to get the install command for a new Linux device.";
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
          <button data-action="vulnerability-scan" data-device-id="${escapeHtml(device.id)}" ${["pacman", "apt", "winget", "windows-update"].includes(device.package_manager) ? "" : 'disabled title="The vulnerability adapter for this platform is not available yet"'}>Vulnerability scan</button>
          <button class="danger" data-action="update" data-device-id="${escapeHtml(device.id)}" ${device.update_count === 0 ? "disabled" : ""}>Deploy approved patches</button>
        </div>
        <p class="scan-note">Patch scan: ${relativeTime(device.last_scan_at)} · Vulnerability scan: ${relativeTime(device.last_vulnerability_scan_at)}</p>
      </article>`;
  }).join("") : '<div class="empty">No devices have enrolled.</div>';
}

// All distinct tags currently in use across the fleet, for the filter
// dropdown and the bulk "remove tag" picker -- computed from state.devices
// rather than a separate endpoint, since the full device list (tags
// included, see device_view) is already loaded for anyone who can see
// Inventory at all.
function allKnownTags() {
  const tags = new Set();
  for (const device of state.devices) {
    for (const tag of device.tags || []) tags.add(tag);
  }
  return [...tags].sort((a, b) => a.localeCompare(b));
}

function renderInventoryTagFilter() {
  const select = $("#inventoryTagFilter");
  const tags = allKnownTags();
  const signature = tags.join("|");
  if (select.dataset.signature === signature) {
    select.value = state.inventoryTagFilter;
    return;
  }
  select.dataset.signature = signature;
  select.innerHTML = '<option value="">All tags</option>'
    + tags.map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`).join("");
  select.value = state.inventoryTagFilter;
}

function renderInventoryBulkBar(visibleDevices) {
  // Selection can hold ids that just scrolled out of the current filter --
  // only count/act on ones still visible, so "Clear selection" after
  // narrowing a filter doesn't surprise anyone by touching devices they
  // can no longer see.
  const visibleIds = new Set(visibleDevices.map((d) => d.id));
  const selectedVisible = [...state.inventorySelected].filter((id) => visibleIds.has(id));
  const bar = $("#inventoryBulkBar");
  bar.hidden = selectedVisible.length === 0;
  $("#inventoryBulkCount").textContent = `${selectedVisible.length} selected`;
}

function visibleInventoryDevices() {
  const filter = $("#inventorySearch").value.trim().toLowerCase();
  return state.devices.filter((device) => {
    const matchesSearch = `${device.hostname} ${device.os_name} ${device.os_version}`.toLowerCase().includes(filter);
    const matchesTag = !state.inventoryTagFilter || (device.tags || []).includes(state.inventoryTagFilter);
    return matchesSearch && matchesTag;
  });
}

function renderInventory() {
  renderInventoryTagFilter();
  const devices = visibleInventoryDevices();
  const canBulkAct = state.user?.role === "admin";
  $("#inventoryDevices").innerHTML = devices.length ? devices.map((device) => {
    const inventory = device.inventory || {};
    const addresses = Array.isArray(inventory.ip_addresses) ? inventory.ip_addresses.join(", ") : "Unknown";
    const tags = device.tags || [];
    const tagPills = tags.length ? `<div class="tag-pills">${tags.map((tag) => `<span class="pill tag-pill">${escapeHtml(tag)}</span>`).join("")}</div>` : "";
    return `
      <article class="inventory-card">
        <div class="device-top">
          <div class="device-top-main">
            ${canBulkAct ? `<input type="checkbox" class="inventory-select" data-device-id="${escapeHtml(device.id)}" aria-label="Select ${escapeHtml(device.display_name || device.hostname)}" ${state.inventorySelected.has(device.id) ? "checked" : ""}>` : ""}
            <div><h3>${escapeHtml(device.display_name || device.hostname)}</h3><div class="device-subtitle">${escapeHtml([device.os_name, device.os_version, device.architecture].filter(Boolean).join(" · "))}</div>${tagPills}</div>
          </div>
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
  renderInventoryBulkBar(devices);
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

const jobTypeLabels = { SCAN_DEVICE: "Patch scan", SCAN_VULNERABILITIES: "Vulnerability scan", INSTALL_UPDATES: "Install updates", INSTALL_APPROVED_UPDATES: "Approved patches", INSTALL_CUSTOM_PACKAGE: "Custom install", INSTALL_PACKAGE: "Install package", UNINSTALL_PACKAGE: "Uninstall package", DOCKER_CONTAINER_ACTION: "Docker action", DOCKER_COMPOSE_UP: "Compose deploy", DOCKER_VOLUME_REMOVE: "Remove volume", DOCKER_VOLUME_PRUNE: "Prune volumes", RUN_COMMAND: "Run command", UPGRADE_AGENT: "Agent upgrade", NETWORK_DIAGNOSTIC: "Network diagnostic", WAKE_ON_LAN: "Wake-on-LAN", MIGRATE_SERVER: "Server migration" };

// outcome_unknown is a terminal status (see server-rs's reap_stale_jobs):
// the agent claimed this job and then never reported a result within its
// lease window -- a crash, a lost completion POST, or the device never
// coming back online. It does NOT mean the job failed; it genuinely isn't
// known whether it succeeded, failed, or never ran, so it's surfaced
// distinctly rather than folded into "failed" and never auto-retried.
const jobStatusLabels = { outcome_unknown: "Outcome unknown" };
function jobStatusCell(job) {
  const label = jobStatusLabels[job.status] || job.status;
  const title = job.status === "outcome_unknown"
    ? ' title="The agent claimed this job but never reported back within the expected window. It may have succeeded, failed, or never run -- check the device directly if this matters."'
    : "";
  return `<span class="pill ${job.status}"${title}>${escapeHtml(label)}</span>`;
}

function renderJobs() {
  const names = Object.fromEntries(state.devices.map((device) => [device.id, device.hostname]));
  $("#jobs").innerHTML = state.jobs.length ? state.jobs.map((job) => `
    <tr>
      <td>${escapeHtml(job.type === "DOCKER_CONTAINER_ACTION" ? `Docker ${job.options?.action || "action"} · ${job.options?.container_id || ""}` : jobTypeLabels[job.type] || job.type)}</td>
      <td>${escapeHtml(names[job.device_id] || job.device_id)}</td>
      <td>${jobStatusCell(job)}</td>
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
  const runScriptSubmit = $("#runScriptSubmit");
  if (runScriptSubmit) runScriptSubmit.disabled = count === 0 || state.user?.role !== "admin" || !$("#runScriptSelect").value;
}

function renderDeployJobs() {
  const names = Object.fromEntries(state.devices.map((device) => [device.id, device.hostname]));
  const deployments = state.jobs.filter((job) => ["INSTALL_PACKAGE", "UNINSTALL_PACKAGE", "INSTALL_CUSTOM_PACKAGE"].includes(job.type));
  $("#deployJobs").innerHTML = deployments.length ? deployments.map((job) => `
    <tr>
      <td class="package-name">${job.type === "UNINSTALL_PACKAGE" ? "Uninstall" : "Install"}: ${escapeHtml(job.options?.name || job.options?.package || "—")}</td>
      <td>${escapeHtml(names[job.device_id] || job.device_id)}</td>
      <td>${jobStatusCell(job)}</td>
      <td>${relativeTime(job.created_at)}</td>
      <td>${escapeHtml(job.error || (job.exit_code === null ? "—" : `Exit ${job.exit_code}`))}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No deployments yet.</td></tr>';
}

function renderDeploy() {
  renderDeployDevices();
  renderDeployJobs();
  renderPackageCatalog();
  renderCustomPackages();
  if (state.user?.role === "admin") renderScripts();
}

function renderScripts() {
  $("#scriptRows").innerHTML = state.scripts.length ? state.scripts.map((script) => `
    <tr>
      <td class="package-name">${escapeHtml(script.name)}${script.description ? `<div class="device-subtitle">${escapeHtml(script.description)}</div>` : ""}</td>
      <td>${escapeHtml(script.platform)}</td>
      <td class="device-actions">
        <button type="button" class="secondary" data-script-edit="${escapeHtml(script.id)}">Edit</button>
        <button type="button" class="danger" data-script-delete="${escapeHtml(script.id)}">Delete</button>
      </td>
    </tr>`).join("") : '<tr><td colspan="3" class="empty">No saved scripts yet.</td></tr>';
  const select = $("#runScriptSelect");
  const previous = select.value;
  select.innerHTML = '<option value="">Choose a script…</option>'
    + state.scripts.map((script) => `<option value="${escapeHtml(script.id)}">${escapeHtml(script.name)}${script.platform !== "any" ? ` (${escapeHtml(script.platform)})` : ""}</option>`).join("");
  if (state.scripts.some((script) => script.id === previous)) select.value = previous;
  updateDeploySubmitState();
}

function resetScriptForm() {
  state.editingScriptId = null;
  $("#scriptForm").reset();
  $("#scriptId").value = "";
  $("#scriptSubmit").textContent = "Save script";
  $("#scriptCancelEdit").hidden = true;
}

function editScript(script) {
  state.editingScriptId = script.id;
  $("#scriptId").value = script.id;
  $("#scriptName").value = script.name;
  $("#scriptDescription").value = script.description || "";
  $("#scriptPlatform").value = script.platform;
  $("#scriptBody").value = script.body;
  $("#scriptSubmit").textContent = "Update script";
  $("#scriptCancelEdit").hidden = false;
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
  if (state.user?.role === "admin") { renderChannels(); renderAlertRules(); }
}

const ruleKindLabels = {
  device_offline: "Device offline",
  resource_threshold: "Resource usage",
  vulnerability_found: "Critical/High vulnerability",
  job_failed: "Job failed",
};

function ruleConditionText(rule) {
  if (rule.kind === "device_offline") return `Offline > ${rule.threshold_value} min`;
  if (rule.kind === "resource_threshold") return `${rule.metric} > ${rule.threshold_value}%`;
  return ruleKindLabels[rule.kind] || rule.kind;
}

function renderChannels() {
  const tbody = $("#channelRows");
  tbody.innerHTML = state.notificationChannels.length ? state.notificationChannels.map((channel) => `
    <tr>
      <td>${escapeHtml(channel.name)}</td>
      <td class="truncate" title="${escapeHtml(channel.url)}">${escapeHtml(channel.url)}</td>
      <td>${channel.format === "slack" ? "Slack-compatible" : "Generic JSON"}</td>
      <td><span class="pill ${channel.enabled ? "succeeded" : "unknown"}">${channel.enabled ? "Yes" : "No"}</span></td>
      <td class="device-actions">
        <button type="button" class="secondary" data-channel-test="${escapeHtml(channel.id)}">Test</button>
        <button type="button" class="secondary" data-channel-toggle="${escapeHtml(channel.id)}">${channel.enabled ? "Disable" : "Enable"}</button>
        <button type="button" class="danger" data-channel-delete="${escapeHtml(channel.id)}">Delete</button>
      </td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No notification channels configured yet.</td></tr>';
}

function renderAlertRules() {
  const tbody = $("#alertRuleRows");
  const scriptName = (id) => state.scripts.find((item) => item.id === id)?.name;
  tbody.innerHTML = state.alertRules.length ? state.alertRules.map((rule) => `
    <tr>
      <td>${escapeHtml(rule.name)}</td>
      <td>${escapeHtml(ruleConditionText(rule))}</td>
      <td>${rule.tag_filter ? `<span class="pill tag-pill">${escapeHtml(rule.tag_filter)}</span>` : "Whole fleet"}</td>
      <td>${rule.action_script_id ? escapeHtml(scriptName(rule.action_script_id) || "Deleted script") : "—"}</td>
      <td><span class="pill ${rule.enabled ? "succeeded" : "unknown"}">${rule.enabled ? "Yes" : "No"}</span></td>
      <td class="device-actions">
        <button type="button" class="secondary" data-rule-toggle="${escapeHtml(rule.id)}">${rule.enabled ? "Disable" : "Enable"}</button>
        <button type="button" class="danger" data-rule-delete="${escapeHtml(rule.id)}">Delete</button>
      </td>
    </tr>`).join("") : '<tr><td colspan="6" class="empty">No alert rules configured yet.</td></tr>';
  const select = $("#ruleActionScript");
  const previous = select.value;
  select.innerHTML = '<option value="">None -- notify only</option>'
    + state.scripts.map((script) => `<option value="${escapeHtml(script.id)}">${escapeHtml(script.name)}</option>`).join("");
  if (state.scripts.some((script) => script.id === previous)) select.value = previous;
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
  const timestamps = history.map((day) => day.date);
  const vulnMax = Math.max(1, ...history.map((day) => Number(day.total_vulnerabilities) || 0));
  container.innerHTML = `
    <p class="form-note">${history.length} reporting days (${escapeHtml(dateRange)}). Scope: ${escapeHtml($("#trendDevice").selectedOptions[0]?.textContent || "Entire fleet")}. Each device contributes its first report of that UTC day; missing days are not zeroes. Summary cards above remain fleet-wide.</p>
    <div class="chart-grid-wrap">
      ${renderAreaChartCard({
        title: "Fully patched", valueLabel: formatPercent(latest.fully_patched_percent), timestamps, xFormat: shortDate,
        series: [{ name: "Fully patched", values: history.map((d) => d.fully_patched_percent) }], yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "No critical/high vulnerabilities", valueLabel: formatPercent(latest.no_critical_high_percent), timestamps, xFormat: shortDate,
        series: [{ name: "Clear of critical/high", color: "#67b7f7", gradient: "chartGradBlue", values: history.map((d) => d.no_critical_high_percent) }],
        yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "Online", valueLabel: formatPercent(latest.online_percent), timestamps, xFormat: shortDate,
        series: [{ name: "Online", values: history.map((d) => d.online_percent) }], yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "Vulnerabilities", valueLabel: String(latest.total_vulnerabilities), timestamps, xFormat: shortDate,
        series: [{ name: "Vulnerabilities", color: "#f3aa63", gradient: "chartGradOrange", values: history.map((d) => d.total_vulnerabilities) }],
        yMax: vulnMax, yFormat: (v) => String(Math.round(v)),
      })}
    </div>
  `;
  attachAllChartHovers(container);
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
      body: JSON.stringify({ type: "INSTALL_PACKAGE", options: { package: packageName, confirmed: true } }),
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

// ---- Area chart engine (CPU/memory/disk/network/Docker history) ----
//
// Filled-gradient area charts with a shared hover crosshair+tooltip and,
// for multi-series (Docker) charts, stacking and a legend/filter -- see
// the dataviz skill's mark specs (2px line, ~10-55% gradient wash, legend
// for 2+ series, crosshair-driven tooltip) this was built against.
//
// Each chart gets a generated id (chart-N) used only to look its own
// series data back up in chartRegistry for the shared hover handler --
// never embedded as anything but an opaque attribute value.
let chartSeq = 0;
const chartRegistry = new Map();
let chartTooltipEl = null;

function shortTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function shortDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString([], { month: "short", day: "numeric" });
}

// formatBytes treats 0 as "no data reported" (correct for a device's own
// current-usage display, where 0 really does mean unknown). A chart axis
// has no such ambiguity -- 0 is just the origin -- so this keeps
// formatBytes' unit scaling but renders zero as "0 B" instead.
function formatBytesAxis(value) {
  return Number(value) > 0 ? formatBytes(value) : "0 B";
}

const CATEGORICAL_GRADIENTS = ["chartGradCat0", "chartGradCat1", "chartGradCat2", "chartGradCat3", "chartGradCat4", "chartGradCat5", "chartGradCat6", "chartGradCat7"];
const CATEGORICAL_HEX = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#4caf4c", "#9085e9", "#e66767"];

function renderAreaChartCard({ title, valueLabel, note, timestamps, series, yMax, yFormat = (v) => String(Math.round(v)), xFormat = shortTime, stacked = false, filterable = false }) {
  const chartId = `chart-${++chartSeq}`;
  const width = 640, height = 170, padBottom = 24, plotH = height - padBottom;
  const n = timestamps.length;
  const xAt = (i) => (n <= 1 ? width / 2 : (i / (n - 1)) * width);
  const maxValue = Math.max(yMax || 0, 1);
  const yOf = (v) => plotH - (Math.max(0, Math.min(v, maxValue)) / maxValue) * plotH;

  let cumulative = new Array(n).fill(0);
  const bands = series.map((s, seriesIndex) => {
    const safeValues = Array.from({ length: n }, (_, i) => Number(s.values[i]) || 0);
    const bottomValues = cumulative.slice();
    const topValues = stacked ? cumulative.map((c, i) => c + safeValues[i]) : safeValues;
    if (stacked) cumulative = topValues;
    const topPoints = topValues.map((v, i) => [xAt(i), yOf(v)]);
    const bottomPoints = stacked ? bottomValues.map((v, i) => [xAt(i), yOf(v)]) : topValues.map((_, i) => [xAt(i), plotH]);
    const pathTop = topPoints.map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
    const pathBottom = bottomPoints.slice().reverse().map(([x, y]) => `L${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
    const areaD = n ? `${pathTop} ${pathBottom} Z` : "";
    const lineD = pathTop;
    const gradient = s.gradient || (stacked || series.length > 1 ? CATEGORICAL_GRADIENTS[seriesIndex % CATEGORICAL_GRADIENTS.length] : "chartGradGreen");
    const color = s.color || (stacked || series.length > 1 ? CATEGORICAL_HEX[seriesIndex % CATEGORICAL_HEX.length] : "var(--accent)");
    return { name: s.name, color, gradient, areaD, lineD, values: safeValues, topPoints };
  });

  chartRegistry.set(chartId, { timestamps, series: bands, maxValue, plotH, width, yFormat, stacked });

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ y: plotH - f * plotH, label: yFormat(maxValue * f) }));
  const xTickCount = Math.min(5, n);
  const xTicks = n ? Array.from({ length: xTickCount }, (_, i) => {
    const idx = xTickCount === 1 ? 0 : Math.round((i / (xTickCount - 1)) * (n - 1));
    return { x: xAt(idx), label: xFormat(timestamps[idx]) };
  }) : [];

  const legend = series.length >= 2 ? `<div class="chart-legend">${bands.map((b, i) =>
    `<span class="chart-legend-item" data-chart-id="${chartId}" data-series="${i}"><span class="chart-swatch" style="background:${b.color}"></span>${escapeHtml(b.name)}</span>`
  ).join("")}</div>` : "";
  const filter = filterable && series.length >= 2
    ? `<input type="search" class="chart-filter" placeholder="Filter…" data-chart-id="${chartId}" aria-label="Filter ${escapeHtml(title)} series">`
    : "";

  return `<article class="chart-card ${series.length >= 2 ? "chart-card-wide" : ""}">
    <div class="chart-title">
      <div><small>${escapeHtml(title)}</small><strong>${escapeHtml(valueLabel)}</strong></div>
      ${filter || `<span>${n} sample${n === 1 ? "" : "s"}</span>`}
    </div>
    <div class="chart-plot">
      <div class="chart-axis-y">${yTicks.map((t) => `<span style="top:${((t.y / plotH) * 100).toFixed(2)}%">${escapeHtml(t.label)}</span>`).join("")}</div>
      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="${escapeHtml(title)} history" data-chart-id="${chartId}">
        ${yTicks.map((t) => `<line x1="0" y1="${t.y.toFixed(1)}" x2="${width}" y2="${t.y.toFixed(1)}" class="chart-grid"></line>`).join("")}
        ${bands.map((b) => `<path d="${b.areaD}" fill="url(#${b.gradient})" class="chart-area" data-series-name="${escapeHtml(b.name)}"></path>`).join("")}
        ${bands.map((b) => `<path d="${b.lineD}" fill="none" stroke="${b.color}" class="chart-line-path" data-series-name="${escapeHtml(b.name)}"></path>`).join("")}
        <g class="chart-crosshair" data-crosshair="${chartId}" opacity="0">
          <line x1="0" y1="0" x2="0" y2="${plotH}" class="chart-crosshair-line"></line>
        </g>
        <rect x="0" y="0" width="${width}" height="${plotH}" fill="transparent" class="chart-hit-area" data-chart-hit="${chartId}"></rect>
      </svg>
    </div>
    <div class="chart-axis-x">${xTicks.map((t) => `<span style="left:${((t.x / width) * 100).toFixed(2)}%">${escapeHtml(t.label)}</span>`).join("")}</div>
    ${legend}
    ${note ? `<p class="chart-note">${escapeHtml(note)}</p>` : ""}
  </article>`;
}

function ensureChartTooltip() {
  if (chartTooltipEl) return chartTooltipEl;
  chartTooltipEl = document.createElement("div");
  chartTooltipEl.className = "chart-tooltip";
  chartTooltipEl.hidden = true;
  document.body.appendChild(chartTooltipEl);
  return chartTooltipEl;
}

function showChartTooltip(pageX, pageY, timeLabel, rows) {
  const tooltip = ensureChartTooltip();
  tooltip.innerHTML = "";
  const time = document.createElement("div");
  time.className = "chart-tooltip-time";
  time.textContent = timeLabel;
  tooltip.appendChild(time);
  for (const row of rows) {
    const line = document.createElement("div");
    line.className = "chart-tooltip-row";
    const key = document.createElement("span");
    key.className = "chart-tooltip-key";
    key.style.background = row.color;
    const name = document.createElement("span");
    name.className = "chart-tooltip-name";
    name.textContent = row.name;
    const value = document.createElement("strong");
    value.className = "chart-tooltip-value";
    value.textContent = row.value;
    line.append(key, name, value);
    tooltip.appendChild(line);
  }
  tooltip.hidden = false;
  const offset = 14;
  let left = pageX + offset;
  let top = pageY + offset;
  const rect = tooltip.getBoundingClientRect();
  if (left + rect.width > window.innerWidth + window.scrollX) left = pageX - rect.width - offset;
  if (top + rect.height > window.innerHeight + window.scrollY) top = pageY - rect.height - offset;
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${top}px`;
}

function hideChartTooltip() {
  if (chartTooltipEl) chartTooltipEl.hidden = true;
}

function nearestIndex(timestamps, width, offsetX) {
  if (!timestamps.length) return -1;
  if (timestamps.length === 1) return 0;
  const fraction = Math.max(0, Math.min(1, offsetX / width));
  return Math.round(fraction * (timestamps.length - 1));
}

function attachChartHover(svg) {
  const chartId = svg.dataset.chartId;
  const hitArea = svg.querySelector("[data-chart-hit]");
  const crosshair = svg.querySelector("[data-crosshair]");
  if (!hitArea || !crosshair) return;
  const move = (event) => {
    const data = chartRegistry.get(chartId);
    if (!data || !data.timestamps.length) return;
    const bounds = svg.getBoundingClientRect();
    const offsetX = ((event.clientX - bounds.left) / bounds.width) * data.width;
    const index = nearestIndex(data.timestamps, data.width, offsetX);
    if (index < 0) return;
    const x = data.series[0]?.topPoints[index]?.[0] ?? offsetX;
    crosshair.setAttribute("opacity", "1");
    crosshair.querySelector("line").setAttribute("x1", x.toFixed(1));
    crosshair.querySelector("line").setAttribute("x2", x.toFixed(1));
    const rows = data.series
      .map((s) => ({ name: s.name, color: s.color, raw: s.values[index], value: data.yFormat(s.values[index]) }))
      .filter((row) => !data.stacked || row.raw > 0 || data.series.length <= 4);
    showChartTooltip(event.pageX, event.pageY, fullDate(data.timestamps[index]), rows);
  };
  hitArea.addEventListener("pointermove", move);
  hitArea.addEventListener("pointerleave", () => {
    crosshair.setAttribute("opacity", "0");
    hideChartTooltip();
  });
}

function attachAllChartHovers(container) {
  container.querySelectorAll("svg[data-chart-id]").forEach(attachChartHover);
  container.querySelectorAll(".chart-filter").forEach((input) => {
    input.addEventListener("input", () => {
      const chartId = input.dataset.chartId;
      const query = input.value.trim().toLowerCase();
      const svg = container.querySelector(`svg[data-chart-id="${chartId}"]`);
      if (!svg) return;
      const matches = (name) => !query || name.toLowerCase().includes(query);
      svg.querySelectorAll("[data-series-name]").forEach((el) => {
        el.style.opacity = matches(el.dataset.seriesName) ? "" : ".12";
      });
      const legend = svg.closest(".chart-card")?.querySelector(".chart-legend");
      legend?.querySelectorAll(".chart-legend-item").forEach((item) => {
        const name = item.textContent.trim();
        item.style.opacity = matches(name) ? "" : ".4";
      });
    });
  });
}

// renderMonitoring is split in two: the live snapshot (current-metrics,
// GPU, top consumers) re-renders on every live-metrics WS tick, but the
// historical area charts below it only actually change when
// loadMetricHistory/loadContainerMetricHistory refetch (a new time range,
// or opening the tab) -- rebuilding their SVGs every tick as part of one
// big innerHTML would tear down and reattach the hover listeners
// constantly and make the tooltip unusable while live data streams in.
function renderMonitoring(device) {
  renderMonitoringLive(device);
  renderMonitoringCharts(device);
}

function renderMonitoringLive(device) {
  const container = $("#monitoringLive");
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
  const memory = usagePercent(metrics.memory_used_bytes, metrics.memory_total_bytes);
  const disk = usagePercent(metrics.disk_used_bytes, metrics.disk_total_bytes);
  const swap = usagePercent(metrics.swap_used_bytes, metrics.swap_total_bytes);
  const temperature = metrics.temperature_celsius === null || metrics.temperature_celsius === undefined ? "Not reported" : `${Number(metrics.temperature_celsius).toFixed(1)}°C`;
  const gpus = Array.isArray(metrics.gpus) ? metrics.gpus : [];
  const gpuProcesses = Array.isArray(metrics.gpu_processes) ? metrics.gpu_processes : [];
  const gpuCards = gpus.length ? `<section class="gpu-section"><div><p class="eyebrow">GPU MONITORING</p><h3>Graphics processors</h3></div><div class="gpu-grid">${gpus.map((gpu) => {
    const gpuMemory = usagePercent(gpu.memory_used_bytes, gpu.memory_total_bytes);
    const temperatureValue = gpu.temperature_celsius === null || gpu.temperature_celsius === undefined ? "Not reported" : `${Number(gpu.temperature_celsius).toFixed(1)}°C`;
    const powerValue = gpu.power_watts === null || gpu.power_watts === undefined ? "Not reported" : `${Number(gpu.power_watts).toFixed(1)} W`;
    const gpuKey = gpu.uuid || gpu.index;
    // A process list only has a gpu_uuid to key off when the agent can tell
    // GPUs apart (NVIDIA); with exactly one GPU reported, show everything
    // under it regardless, since there's nothing else it could belong to.
    const processes = gpuProcesses.filter((p) => (gpu.uuid && p.gpu_uuid ? p.gpu_uuid === gpu.uuid : gpus.length === 1));
    const expanded = state.expandedGPUProcesses.has(gpuKey);
    const processesSection = processes.length ? `
      <button type="button" class="secondary gpu-processes-toggle" data-gpu-toggle="${escapeHtml(gpuKey)}">${expanded ? "Hide" : "Show"} processes (${processes.length})</button>
      ${expanded ? `<div class="table-wrap">
        <table>
          <thead><tr><th>PID</th><th>Process</th><th>VRAM</th></tr></thead>
          <tbody>${processes.map((p) => `<tr><td>${escapeHtml(p.pid)}</td><td class="package-name">${escapeHtml(p.name || "Unknown")}</td><td>${formatBytes(p.memory_used_bytes)}</td></tr>`).join("")}</tbody>
        </table>
      </div>` : ""}` : "";
    return `<article><div class="gpu-title"><div><small>${escapeHtml(gpu.vendor)}</small><strong>${escapeHtml(gpu.name)}</strong></div><span>GPU ${escapeHtml(gpu.index)}</span></div><dl><div><dt>Utilization</dt><dd>${formatPercent(gpu.utilization_percent)}</dd></div><div><dt>VRAM</dt><dd>${gpu.memory_total_bytes ? formatUsage(gpu.memory_used_bytes, gpu.memory_total_bytes) : "Not reported"}</dd></div><div><dt>Temperature</dt><dd>${escapeHtml(temperatureValue)}</dd></div><div><dt>Power</dt><dd>${escapeHtml(powerValue)}</dd></div></dl>${usageBar(gpu.utilization_percent)}${gpuMemory === null ? "" : usageBar(gpuMemory, "blue")}${processesSection}</article>`;
  }).join("")}</div></section>` : '<section class="gpu-section empty-gpu"><p>No supported GPU telemetry was detected on this device.</p></section>';

  const disks = Array.isArray(metrics.disks) ? metrics.disks : [];
  const disksSection = disks.length ? `
    <section class="disks-section">
      <div class="monitoring-heading"><div><p class="eyebrow">STORAGE</p><h3>All drives</h3></div></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Mount point</th><th>Device</th><th>Filesystem</th><th>Used</th><th>Size</th></tr></thead>
          <tbody>${disks.map((d) => {
            const used = usagePercent(d.used_bytes, d.total_bytes);
            return `<tr>
              <td class="package-name">${escapeHtml(d.mount_point || "—")}</td>
              <td>${escapeHtml(d.device || "—")}</td>
              <td>${escapeHtml(d.filesystem || "—")}</td>
              <td>${formatPercent(used)}<br>${usageBar(used, used >= 90 ? "orange" : "green")}</td>
              <td>${formatUsage(d.used_bytes, d.total_bytes)}</td>
            </tr>`;
          }).join("")}</tbody>
        </table>
      </div>
    </section>` : "";

  const consumers = Array.isArray(metrics.top_consumers) ? [...metrics.top_consumers] : [];
  const sortKey = state.topConsumersSort;
  const sortDir = state.topConsumersSortDir === "asc" ? 1 : -1;
  const stringKeys = new Set(["kind", "name"]);
  consumers.sort((a, b) => {
    if (stringKeys.has(sortKey)) {
      return sortDir * String(a[sortKey] || "").localeCompare(String(b[sortKey] || ""));
    }
    return sortDir * ((Number(a[sortKey]) || 0) - (Number(b[sortKey]) || 0));
  });
  const consumerRows = consumers.length ? consumers.map((item) => `
    <tr>
      <td><span class="pill ${item.kind === "container" ? "succeeded" : "unknown"}">${escapeHtml(item.kind)}</span></td>
      <td class="package-name">${escapeHtml(item.name || "Unknown")}</td>
      <td>${item.kind === "process" && item.pid ? escapeHtml(item.pid) : "—"}</td>
      <td>${formatPercent(item.cpu_percent)}</td>
      <td>${formatBytes(item.memory_bytes)}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No process/container data reported yet -- requires agent 0.22.0 or later.</td></tr>';
  const sortArrow = (key) => sortKey === key ? (state.topConsumersSortDir === "asc" ? " ▴" : " ▾") : "";
  const sortHeader = (key, label) =>
    `<th class="sortable ${sortKey === key ? "active" : ""}" data-consumer-sort="${key}">${label}${sortArrow(key)}</th>`;
  const topConsumersSection = `
    <section class="top-consumers-section">
      <div class="monitoring-heading">
        <div><p class="eyebrow">LIVE SNAPSHOT</p><h3>Top resource consumers</h3></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            ${sortHeader("kind", "Kind")}${sortHeader("name", "Name")}<th>PID</th>
            ${sortHeader("cpu_percent", "CPU")}${sortHeader("memory_bytes", "Memory")}
          </tr></thead>
          <tbody>${consumerRows}</tbody>
        </table>
      </div>
      <p class="form-note">Host processes and running Docker containers merged into one list: click a column to sort by it, click again to reverse direction (deduplicated top entries, not a single blended score).</p>
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
    ${disksSection}
    ${topConsumersSection}`;
}

// Rebuilt only when the underlying history data actually changes (a new
// time range, or the tab just opened) -- see renderMonitoring's comment.
// lastRenderedChartsSignature lets a live-tick-triggered renderMonitoring
// call skip this safely.
let lastRenderedChartsSignature = null;

function renderMonitoringCharts(device) {
  const container = $("#monitoringCharts");
  if (state.detailHistoryLoading) {
    container.innerHTML = '<div class="empty">Loading monitoring history…</div>';
    lastRenderedChartsSignature = null;
    return;
  }
  const samples = state.detailHistory;
  const containerSamples = state.detailContainerHistory || [];
  const signature = `${device.id}:${samples.length ? samples[samples.length - 1].recorded_at : ""}:${samples.length}:${containerSamples.length}`;
  if (signature === lastRenderedChartsSignature) return;
  lastRenderedChartsSignature = signature;

  const live = state.liveMetricsByDevice.get(device.id);
  const metrics = live || device.metrics;
  if (!metrics) {
    container.innerHTML = "";
    return;
  }
  const memory = usagePercent(metrics.memory_used_bytes, metrics.memory_total_bytes);
  const disk = usagePercent(metrics.disk_used_bytes, metrics.disk_total_bytes);
  const timestamps = samples.map((s) => s.recorded_at);
  const networkMax = Math.max(...samples.flatMap((s) => [Number(s.network_receive_bps) || 0, Number(s.network_transmit_bps) || 0]), 1);
  const historyStart = samples.length ? fullDate(samples[0].recorded_at) : "Waiting for samples";
  const historyEnd = samples.length ? fullDate(samples[samples.length - 1].recorded_at) : "Waiting for samples";

  const hostCharts = `
    <div class="chart-grid-wrap">
      ${renderAreaChartCard({
        title: "CPU usage", valueLabel: formatPercent(metrics.cpu_percent), timestamps,
        series: [{ name: "CPU", values: samples.map((s) => s.cpu_percent) }], yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "Memory usage", valueLabel: formatPercent(memory), timestamps,
        series: [{ name: "Memory", color: "#67b7f7", gradient: "chartGradBlue", values: samples.map((s) => usagePercent(s.memory_used_bytes, s.memory_total_bytes) || 0) }],
        yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "Root disk usage", valueLabel: formatPercent(disk), timestamps,
        series: [{ name: "Disk", color: "#f3aa63", gradient: "chartGradOrange", values: samples.map((s) => usagePercent(s.disk_used_bytes, s.disk_total_bytes) || 0) }],
        yMax: 100, yFormat: formatPercent,
      })}
      ${renderAreaChartCard({
        title: "Network throughput", valueLabel: `↓ ${formatRate(metrics.network_receive_bps)} · ↑ ${formatRate(metrics.network_transmit_bps)}`, timestamps,
        series: [
          { name: "Download", color: "#67b7f7", gradient: "chartGradBlue", values: samples.map((s) => s.network_receive_bps) },
          { name: "Upload", color: "#f3aa63", gradient: "chartGradOrange", values: samples.map((s) => s.network_transmit_bps) },
        ],
        yMax: networkMax, yFormat: formatRate,
      })}
    </div>`;

  container.innerHTML = `${hostCharts}${renderDockerHistoryCharts(containerSamples)}
    <p class="history-range">History shown: ${escapeHtml(historyStart)} to ${escapeHtml(historyEnd)}. Samples are retained for seven days.</p>`;
  attachAllChartHovers(container);
}

// Builds the two stacked-area Docker charts (CPU%, memory) from
// container_metric_samples rows: grouped by recorded_at (all containers
// in one periodic report share a timestamp) and by container_name, so
// each gets its own band. More than 8 containers fold the smallest ones
// into "Other", matching the categorical palette's 8-slot cap.
function renderDockerHistoryCharts(rows) {
  if (!rows.length) {
    return '<p class="form-note" style="margin-top:14px">No Docker container history yet -- requires agent 0.26.3+ and at least one periodic metrics report with running containers.</p>';
  }
  const timestamps = [...new Set(rows.map((r) => r.recorded_at))].sort();
  const timeIndex = new Map(timestamps.map((t, i) => [t, i]));
  const totalsByName = new Map();
  for (const row of rows) totalsByName.set(row.container_name, (totalsByName.get(row.container_name) || 0) + (Number(row.cpu_percent) || 0));
  const orderedNames = [...totalsByName.keys()].sort((a, b) => totalsByName.get(b) - totalsByName.get(a));
  const MAX_SERIES = 8;
  const visibleNames = orderedNames.slice(0, MAX_SERIES);
  const hasOther = orderedNames.length > MAX_SERIES;
  const otherNames = new Set(orderedNames.slice(MAX_SERIES));

  const seriesNames = hasOther ? [...visibleNames, "Other"] : visibleNames;
  const buildSeries = (valueKey) => {
    const byName = new Map(seriesNames.map((name) => [name, new Array(timestamps.length).fill(0)]));
    for (const row of rows) {
      const key = otherNames.has(row.container_name) ? "Other" : row.container_name;
      const values = byName.get(key);
      if (!values) continue;
      values[timeIndex.get(row.recorded_at)] += Number(row[valueKey]) || 0;
    }
    return seriesNames.map((name) => ({ name, values: byName.get(name) }));
  };
  const stackedMax = (series) => Math.max(1, ...timestamps.map((_, i) => series.reduce((sum, s) => sum + (s.values[i] || 0), 0)));

  const cpuSeries = buildSeries("cpu_percent");
  const memSeries = buildSeries("memory_bytes");
  const cpuMax = Math.max(100, stackedMax(cpuSeries));
  const memMax = stackedMax(memSeries);

  return `<div class="chart-grid-wrap">
    ${renderAreaChartCard({
      title: "Docker CPU usage", valueLabel: `${visibleNames.length}${hasOther ? "+" : ""} container${seriesNames.length === 1 ? "" : "s"}`,
      note: "Average CPU utilization of containers", timestamps, series: cpuSeries,
      yMax: cpuMax, yFormat: (v) => `${Math.round(v)}%`, stacked: true, filterable: true,
    })}
    ${renderAreaChartCard({
      title: "Docker memory usage", valueLabel: formatBytes(memMax),
      note: "Memory usage of containers", timestamps, series: memSeries,
      yMax: memMax, yFormat: formatBytesAxis, stacked: true, filterable: true,
    })}
  </div>`;
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
    <section class="tags-editor"><p class="eyebrow">GROUPS</p>
      <label>Tags (comma-separated, used for grouping and bulk actions)
        <input id="deviceTagsInput" type="text" value="${escapeHtml((device.tags || []).join(", "))}" placeholder="e.g. production, site-ny, windows-servers" ${state.user?.role === "viewer" ? "disabled" : ""}>
      </label>
      ${state.user?.role !== "viewer" ? `<div class="device-actions"><button type="button" id="saveDeviceTags" data-device-id="${escapeHtml(device.id)}">Save tags</button></div>` : ""}
    </section>
    ${wakeSection}`;
}

function renderDockerVolumes(device) {
  const inventory = device.inventory || {};
  const volumes = Array.isArray(inventory.docker_volumes) ? inventory.docker_volumes : [];
  const versionParts = String(device.agent_version || "").split(".").map(Number);
  const agentReady = versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 31);
  const canManage = state.user?.role !== "viewer" && agentReady && device.agent_settings?.docker_inventory_enabled !== false;
  const unusedCount = volumes.filter((v) => !v.in_use).length;
  $("#pruneVolumesButton").hidden = !canManage;
  $("#pruneVolumesButton").disabled = unusedCount === 0;
  $("#pruneVolumesButton").textContent = unusedCount > 0 ? `Prune unused volumes (${unusedCount})` : "Prune unused volumes";
  $("#dockerVolumeRows").innerHTML = volumes.length ? volumes.map((volume) => `
    <tr>
      <td class="package-name">${escapeHtml(volume.name)}</td>
      <td>${escapeHtml(volume.driver || "Unknown")}</td>
      <td class="truncate" title="${escapeHtml(volume.mountpoint || "")}">${escapeHtml(volume.mountpoint || "")}</td>
      <td>${escapeHtml(fullDate(volume.created_at))}</td>
      <td><span class="pill ${volume.in_use ? "succeeded" : "severity-medium"}">${volume.in_use ? "In use" : "Unused"}</span></td>
      <td>${canManage && !volume.in_use ? `<button type="button" class="danger" data-volume-remove="${escapeHtml(volume.name)}">Remove</button>` : "—"}</td>
    </tr>`).join("") : `<tr><td colspan="6" class="empty">${agentReady ? "No Docker volumes were returned." : "Upgrade this device's agent to 0.31.0+ to see volumes."}</td></tr>`;
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
  // Gated on the agent's version (matching the server's own
  // supports_remote_control check) and the device's last-reported
  // graphical-session availability: the tab opens its own window (see the
  // deviceDialog click handler below) rather than switching
  // state.detailTab. That window still does its own live availability/reason
  // check (the inventory snapshot here can be briefly stale), so a session
  // that ended moments ago still shows a clear reason there -- but the tab
  // itself shouldn't invite a click when the last scan found no session.
  // OPNsense/FreeBSD has no graphical session to capture at all -- the
  // tab opens the device's own web GUI instead (see the deviceDialog
  // click handler below), so it's offered whenever we have an IP to
  // point it at, regardless of agent version or the (always-unavailable)
  // remote_control capability.
  const isOpnsense = device.platform === "freebsd";
  const screenVersionOk = state.user?.role === "admin" && (versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 23));
  const screenSupported = isOpnsense
    ? state.user?.role === "admin" && Array.isArray(inventory.ip_addresses) && inventory.ip_addresses.length > 0
    : screenVersionOk && inventory.remote_control?.available === true;
  $("#screenTab").hidden = !screenSupported;
  $("#screenTab").textContent = isOpnsense ? "Open web GUI ↗" : "Remote control ↗";
  const filesSupported = state.user?.role === "admin" && (versionParts[0] > 0 || (versionParts[0] === 0 && versionParts[1] >= 24));
  $("#filesTab").hidden = !filesSupported;
  if (!filesSupported && state.detailTab === "files") state.detailTab = "overview";
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
  const files = state.detailTab === "files";
  $("#detailOverview").hidden = !overview;
  $("#detailMonitoring").hidden = !monitoring;
  $("#detailTerminal").hidden = !terminal;
  $("#detailFiles").hidden = !files;
  $("#detailSearch").hidden = overview || monitoring || terminal || files;
  $("#detailTableSummary").hidden = overview || monitoring || terminal || files;
  $("#detailTableWrap").hidden = overview || monitoring || terminal || files;
  $("#patchControls").hidden = state.detailTab !== "patches";
  $("#dockerComposeCreator").hidden = state.detailTab !== "docker" || state.user?.role === "viewer";
  $("#dockerVolumesPanel").hidden = state.detailTab !== "docker";
  if (state.detailTab === "docker") renderDockerVolumes(device);
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
  if (files) {
    connectFiles(device.id);
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
      return `<tr><td class="package-name">${escapeHtml(item.package)}</td><td><code>${escapeHtml(item.installed_version)}</code></td><td><code>${escapeHtml(item.available_version)}</code></td><td>${flagLabel(item.security_update)}</td><td>${flagLabel(item.reboot_required)}</td><td>${decision?.supported === false ? "Unsupported Windows update" : `<button type="button" class="secondary" data-approve-patch="${escapeHtml(key)}" data-patch-version="${escapeHtml(item.available_version)}" ${state.user?.role === "viewer" ? "disabled" : ""}>${decision?.approved ? "Approved · revoke" : "Not approved · approve"}</button>`}</td></tr>`;
    }).join("") : '<tr><td colspan="6" class="empty">No needed patches match this view.</td></tr>';
    const schedule = state.patchSchedules[device.id];
    $("#patchInterval").value = schedule?.interval_hours ?? 0;
    const scheduledDays = new Set((schedule?.window_days || "").split(",").map((d) => d.trim()).filter(Boolean));
    $("#patchWindowDays").querySelectorAll("input[type=checkbox]").forEach((box) => { box.checked = scheduledDays.has(box.value); });
    $("#patchWindowStart").value = schedule?.window_start_hour ?? "";
    $("#patchWindowEnd").value = schedule?.window_end_hour ?? "";
    const windowNote = schedule?.window_days || (schedule?.window_start_hour != null && schedule?.window_end_hour != null)
      ? ` Restricted to a maintenance window (${scheduledDays.size ? [...scheduledDays].map((d) => ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][d]).join("/") : "every day"}${schedule?.window_start_hour != null ? `, ${schedule.window_start_hour}:00-${schedule.window_end_hour}:00 UTC` : ""}).`
      : "";
    $("#patchScheduleInfo").textContent = schedule?.next_run_at ? `Next due: ${fullDate(schedule.next_run_at)}. Only currently approved patches will be queued.${windowNote}` : "Schedule disabled. Approved patches remain ready for manual deployment.";
    $("#deployApprovedPatches").disabled = state.user?.role === "viewer" || !approvals.some(item => item.approved && item.supported);
    $("#approveAllPatches").disabled = state.user?.role === "viewer" || !approvals.some(item => !item.approved && item.supported);
    $("#patchScheduleForm").querySelector("button").disabled = state.user?.role === "viewer";
    $("#patchInterval").disabled = state.user?.role === "viewer";
    $("#detailFootnote").textContent = device.package_manager === "pacman" || device.package_manager === "windows-update"
      ? "This device requires approval of every pending patch before they can be installed. Partial installs are blocked."
      : device.package_manager === "winget"
      ? "New versions need fresh approval after a scan. Windows Update entries (identified by KB number) require approval of every pending one together; winget app updates can be approved individually."
      : "New versions need fresh approval after a scan. Debian checks the transaction for unapproved dependencies.";
  } else if (state.detailTab === "vulnerabilities") {
    $("#detailTableHead").innerHTML = "<tr><th>Severity</th><th>ID</th><th>Package</th><th>Installed</th><th>Fixed version</th><th>Status</th><th>Exposure</th></tr>";
    $("#detailTableBody").innerHTML = visible.length ? visible.map((item) => {
      const url = safeUrl(item.primary_url);
      const id = url === "#" ? escapeHtml(item.vulnerability_id) : `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.vulnerability_id)}</a>`;
      return `<tr title="${escapeHtml(item.title || "")}"><td>${severityPill(item.severity, item)}</td><td>${id}</td><td class="package-name">${escapeHtml(item.package)}</td><td><code>${escapeHtml(item.installed_version)}</code></td><td><code>${escapeHtml(item.fixed_version || "Not available")}</code></td><td>${escapeHtml(item.status)}</td><td>${exposurePill(item)}</td></tr>`;
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
  // Remember whichever page you were actually on (Dashboard, Patching,
  // Inventory, the network topology view...) so the close button returns
  // you there -- but only capture it the first time, not every time you
  // click into a different device while already viewing one.
  if (state.page !== "device-detail") state.detailOriginPage = state.page;
  state.detailDevice = null;
  state.detailTab = tab;
  state.detailHistory = [];
  state.detailContainerHistory = [];
  state.detailHistoryLoading = tab === "monitoring";
  $("#detailSearch").value = "";
  $("#detailTitle").textContent = "Loading device…";
  $("#detailSubtitle").textContent = "";
  $("#detailMetrics").innerHTML = "";
  $("#detailOverview").innerHTML = "";
  $("#detailTableSummary").textContent = "Loading device data…";
  $("#detailTableHead").innerHTML = "";
  $("#detailTableBody").innerHTML = "";
  setPage("device-detail");
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
    const deviceId = state.detailDevice.id;
    const [metrics, containerMetrics] = await Promise.all([
      api(`/api/v1/admin/devices/${deviceId}/metrics?hours=${hours}`),
      api(`/api/v1/admin/devices/${deviceId}/container-metrics?hours=${hours}`),
    ]);
    state.detailHistory = metrics;
    state.detailContainerHistory = containerMetrics;
  } catch (error) {
    showNotice(error.message, true);
    state.detailHistory = [];
    state.detailContainerHistory = [];
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
      state.user.role === "admin" ? api("/api/v1/admin/notification-channels").catch(() => []) : Promise.resolve([]),
      state.user.role === "admin" ? api("/api/v1/admin/alert-rules").catch(() => []) : Promise.resolve([]),
      state.user.role === "admin" ? api("/api/v1/admin/scripts").catch(() => []) : Promise.resolve([]),
    ]);
    if (!state.user || generation !== state.authGeneration) return;
    [state.devices, state.jobs, state.enrollmentTokens, state.reportHistory, state.fleetSettings, state.packages, state.customPackages, state.publishedAgentVersion, state.integrations, state.notificationChannels, state.alertRules, state.scripts] = results;
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
    if ((device.package_manager === "pacman" || device.package_manager === "windows-update") && selected.length !== patches.length) {
      showNotice("This device requires approval of every pending patch before they can be installed.", true); openDeviceDetails(deviceId, "patches"); return;
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
function resetComposeForm() {
  $("#composeForm").reset();
  // HTMLFormElement.reset() doesn't fire a change event, so the mode
  // toggle's own listener (which shows/hides the paste vs. build fields)
  // never runs -- without this, resetting back to the default "paste"
  // radio could leave the build-mode fields visibly stuck open.
  $("#composeBuildMode").hidden = true;
  $("#composePasteMode").hidden = false;
  $("#composeForm").hidden = true;
  $("#composeToggle").textContent = "Open compose creator";
  $("#composeError").textContent = "";
}
$("#composeToggle").addEventListener("click", () => {
  const form = $("#composeForm");
  form.hidden = !form.hidden;
  $("#composeToggle").textContent = form.hidden ? "Open compose creator" : "Close compose creator";
});
$("#composeCancel").addEventListener("click", resetComposeForm);
$("#composeForm").addEventListener("change", (event) => {
  if (event.target.name === "composeMode") {
    const build = event.target.value === "build";
    $("#composeBuildMode").hidden = !build;
    $("#composePasteMode").hidden = build;
  }
});

// A plain JSON string is also a valid YAML double-quoted scalar (YAML's
// double-quoted flow style follows JSON escaping rules), so this is a
// safe way to emit arbitrary user-typed values (image names, bind-mount
// paths, env assignments) without a full YAML serializer.
function yamlQuote(value) { return JSON.stringify(value); }

function buildComposeYaml() {
  const service = $("#composeServiceName").value.trim();
  const image = $("#composeImage").value.trim();
  if (!service || !image) throw new Error("Service name and image are required.");
  const containerName = $("#composeContainerName").value.trim();
  const restart = $("#composeRestart").value;
  const splitLines = (id) => $(id).value.split("\n").map((line) => line.trim()).filter(Boolean);
  const ports = splitLines("#composePorts");
  const volumes = splitLines("#composeVolumes");
  const env = splitLines("#composeEnv");
  const lines = ["services:", `  ${service}:`, `    image: ${yamlQuote(image)}`];
  if (containerName) lines.push(`    container_name: ${yamlQuote(containerName)}`);
  lines.push(`    restart: ${restart}`);
  if (ports.length) { lines.push("    ports:"); ports.forEach((p) => lines.push(`      - ${yamlQuote(p)}`)); }
  if (volumes.length) { lines.push("    volumes:"); volumes.forEach((v) => lines.push(`      - ${yamlQuote(v)}`)); }
  if (env.length) { lines.push("    environment:"); env.forEach((e) => lines.push(`      - ${yamlQuote(e)}`)); }
  return lines.join("\n") + "\n";
}

$("#composeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const device = state.detailDevice;
  if (!device) return;
  $("#composeError").textContent = "";
  const project = $("#composeProject").value.trim();
  let compose;
  try {
    const mode = $("#composeForm").querySelector('input[name="composeMode"]:checked').value;
    compose = mode === "paste" ? $("#composeYaml").value : buildComposeYaml();
  } catch (error) { $("#composeError").textContent = error.message; return; }
  if (!compose.trim()) { $("#composeError").textContent = "A compose file is required."; return; }
  const submitButton = $("#composeForm").querySelector('button[type="submit"]');
  submitButton.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}/jobs`, {
      method: "POST", body: JSON.stringify({ type: "DOCKER_COMPOSE_UP", options: { project, compose } }),
    });
    showNotice(`Compose deploy queued for ${device.hostname}. Check Jobs for the result.`);
    resetComposeForm();
  } catch (error) { $("#composeError").textContent = error.message; }
  finally { submitButton.disabled = false; }
});
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
$("#dockerVolumeRows").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-volume-remove]");
  if (!button) return;
  const device = state.detailDevice;
  if (!device || state.user?.role === "viewer") return;
  const name = button.dataset.volumeRemove;
  if (!confirm(`Permanently delete the Docker volume "${name}" on ${device.hostname}?\n\nThis removes its data from disk and cannot be undone.`)) return;
  button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}/jobs`, {
      method: "POST", body: JSON.stringify({ type: "DOCKER_VOLUME_REMOVE", options: { name, confirmed: true } }),
    });
    showNotice(`Volume removal queued for ${name}. Check Jobs for the result.`);
  } catch (error) { button.disabled = false; showNotice(error.message, true); }
});
$("#pruneVolumesButton").addEventListener("click", async () => {
  const device = state.detailDevice;
  if (!device) return;
  const volumes = Array.isArray(device.inventory?.docker_volumes) ? device.inventory.docker_volumes : [];
  const unused = volumes.filter((v) => !v.in_use);
  if (!unused.length) return;
  if (!confirm(`Permanently delete ${unused.length} unused Docker volume${unused.length === 1 ? "" : "s"} on ${device.hostname}?\n\n${unused.map((v) => v.name).join(", ")}\n\nThis removes their data from disk and cannot be undone.`)) return;
  const button = $("#pruneVolumesButton");
  button.disabled = true;
  try {
    await api(`/api/v1/admin/devices/${device.id}/jobs`, {
      method: "POST", body: JSON.stringify({ type: "DOCKER_VOLUME_PRUNE", options: { confirmed: true } }),
    });
    showNotice(`Volume prune queued for ${device.hostname}. Check Jobs for the result.`);
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
  const checkedDays = [...$("#patchWindowDays").querySelectorAll("input:checked")].map((box) => box.value);
  const startRaw = $("#patchWindowStart").value;
  const endRaw = $("#patchWindowEnd").value;
  try {
    state.patchSchedules[device.id] = await api(`/api/v1/admin/devices/${device.id}/patch-schedule`, {
      method: "PUT",
      body: JSON.stringify({
        interval_hours: Number($("#patchInterval").value),
        window_days: checkedDays.length ? checkedDays.join(",") : null,
        window_start_hour: startRaw === "" ? null : Number(startRaw),
        window_end_hour: endRaw === "" ? null : Number(endRaw),
      }),
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
$("#inventoryTagFilter").addEventListener("change", (event) => {
  state.inventoryTagFilter = event.target.value;
  renderInventory();
});
$("#inventoryDevices").addEventListener("change", (event) => {
  const checkbox = event.target.closest(".inventory-select");
  if (!checkbox) return;
  if (checkbox.checked) state.inventorySelected.add(checkbox.dataset.deviceId);
  else state.inventorySelected.delete(checkbox.dataset.deviceId);
  renderInventoryBulkBar(visibleInventoryDevices());
});
$("#bulkClearSelection").addEventListener("click", () => {
  state.inventorySelected.clear();
  renderInventory();
});
// Shared by every bulk-action button: runs `action` for each selected
// device id, tolerating individual failures (a device that's offline or
// already has a conflicting job queued shouldn't abort the whole batch),
// then reports how many succeeded.
async function runBulkAction(label, action) {
  const ids = [...state.inventorySelected];
  if (!ids.length) return;
  if (!confirm(`${label} for ${ids.length} selected device(s)?`)) return;
  let succeeded = 0;
  const errors = [];
  for (const id of ids) {
    try {
      await action(id);
      succeeded += 1;
    } catch (error) {
      const device = state.devices.find((item) => item.id === id);
      errors.push(`${device?.display_name || device?.hostname || id}: ${error.message}`);
    }
  }
  showNotice(
    errors.length ? `${succeeded}/${ids.length} succeeded. Failures: ${errors.slice(0, 3).join("; ")}${errors.length > 3 ? "…" : ""}` : `${label} queued for ${succeeded} device(s).`,
    errors.length > 0,
  );
  await refresh();
}
$("#bulkScanNow").addEventListener("click", () =>
  runBulkAction("Scan", (id) => api(`/api/v1/admin/devices/${id}/jobs`, { method: "POST", body: JSON.stringify({ type: "SCAN_DEVICE" }) })));
$("#bulkInstallApproved").addEventListener("click", () =>
  runBulkAction("Install approved updates", (id) => api(`/api/v1/admin/devices/${id}/deploy-approved-patches`, { method: "POST" })));
$("#bulkAddTag").addEventListener("click", async () => {
  const tag = prompt("Tag to add to all selected devices:")?.trim();
  if (!tag) return;
  await runBulkAction(`Add tag "${tag}"`, async (id) => {
    const device = state.devices.find((item) => item.id === id);
    const tags = new Set(device?.tags || []);
    tags.add(tag);
    await api(`/api/v1/admin/devices/${id}/tags`, { method: "PUT", body: JSON.stringify({ tags: [...tags] }) });
  });
});
$("#bulkRemoveTag").addEventListener("click", async () => {
  const tag = prompt("Tag to remove from all selected devices:")?.trim();
  if (!tag) return;
  await runBulkAction(`Remove tag "${tag}"`, async (id) => {
    const device = state.devices.find((item) => item.id === id);
    const tags = (device?.tags || []).filter((existing) => existing.toLowerCase() !== tag.toLowerCase());
    await api(`/api/v1/admin/devices/${id}/tags`, { method: "PUT", body: JSON.stringify({ tags }) });
  });
});
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
$("#scriptForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    name: $("#scriptName").value.trim(),
    description: $("#scriptDescription").value.trim(),
    platform: $("#scriptPlatform").value,
    body: $("#scriptBody").value,
  };
  try {
    if (state.editingScriptId) {
      await api(`/api/v1/admin/scripts/${state.editingScriptId}`, { method: "PUT", body: JSON.stringify(payload) });
    } else {
      await api("/api/v1/admin/scripts", { method: "POST", body: JSON.stringify(payload) });
    }
    showNotice("Script saved.");
    resetScriptForm();
    await refresh();
  } catch (error) { showNotice(error.message, true); }
});
$("#scriptCancelEdit").addEventListener("click", resetScriptForm);
$("#scriptRows").addEventListener("click", async (event) => {
  const editButton = event.target.closest("[data-script-edit]");
  const deleteButton = event.target.closest("[data-script-delete]");
  if (editButton) {
    const script = state.scripts.find((item) => item.id === editButton.dataset.scriptEdit);
    if (script) editScript(script);
  }
  if (deleteButton) {
    if (!confirm("Delete this saved script?")) return;
    try {
      await api(`/api/v1/admin/scripts/${deleteButton.dataset.scriptDelete}`, { method: "DELETE" });
      if (state.editingScriptId === deleteButton.dataset.scriptDelete) resetScriptForm();
      await refresh();
    } catch (error) { showNotice(error.message, true); }
  }
});
$("#runScriptSelect").addEventListener("change", updateDeploySubmitState);
$("#runScriptSubmit").addEventListener("click", async () => {
  const scriptId = $("#runScriptSelect").value;
  const script = state.scripts.find((item) => item.id === scriptId);
  const deviceIds = [...state.deploySelected];
  if (!script || deviceIds.length === 0) return;
  const names = deviceIds.map((id) => {
    const device = state.devices.find((item) => item.id === id);
    return device ? (device.display_name || device.hostname) : id;
  });
  if (!confirm(`Run "${script.name}" on ${deviceIds.length} device${deviceIds.length === 1 ? "" : "s"}?\n\n${names.join(", ")}`)) return;
  const button = $("#runScriptSubmit");
  button.disabled = true;
  try {
    const outcomes = await Promise.allSettled(deviceIds.map((id) => api(`/api/v1/admin/devices/${id}/scripts/${scriptId}/run`, { method: "POST" })));
    const failed = outcomes.filter((result) => result.status === "rejected");
    showNotice(`Queued on ${deviceIds.length - failed.length} device(s).${failed.length ? ` ${failed.length} failed: ${failed[0].reason.message}` : ""}`, Boolean(failed.length));
    setPage("patching");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
  finally { updateDeploySubmitState(); }
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
$("#installCaFingerprint").addEventListener("input", renderInstallCommand);
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
$("#closeDeviceDialog").addEventListener("click", () => setPage(state.detailOriginPage || "inventory"));
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
    setPage(state.detailOriginPage || "inventory");
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
  if (tab.dataset.detailTab === "screen") {
    // Remote control (or, for OPNsense/FreeBSD, the device's own web GUI)
    // opens in its own window rather than the device detail dialog.
    // window.open must run synchronously in the click handler (no
    // preceding await) or browsers treat it as an unrequested popup and
    // block it. A stable window name per device means clicking again
    // focuses the existing window instead of opening a second one.
    if (state.detailDevice) {
      if (state.detailDevice.platform === "freebsd") {
        const addresses = state.detailDevice.inventory?.ip_addresses;
        const ip = Array.isArray(addresses) ? addresses[0] : null;
        if (ip) {
          window.open(`https://${ip}/`, `fleetview-gui-${state.detailDevice.id}`, "noopener");
        } else {
          showNotice("No IP address has been reported for this device yet.", true);
        }
      } else {
        window.open(`/static/remote-control.html?device=${encodeURIComponent(state.detailDevice.id)}`,
          `fleetview-remote-${state.detailDevice.id}`, "width=1280,height=860,noopener");
      }
    }
    return;
  }
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
  if (state.detailTab !== "files") disconnectFiles();
});

$("#detailFiles").addEventListener("click", (event) => {
  const up = event.target.closest("[data-files-up]");
  if (up) { requestFilesList(filesParentPath(state.filesPath, state.filesPath.includes("\\") && !state.filesPath.includes("/") ? "\\" : "/")); return; }
  const dir = event.target.closest("[data-files-dir]");
  if (dir) { requestFilesList(dir.dataset.filesDir); return; }
  const download = event.target.closest("[data-files-download]");
  if (download) { state.filesEditingPath = null; state.filesSocket?.send({ type: "read", path: download.dataset.filesDownload }); return; }
  const edit = event.target.closest("[data-files-edit]");
  if (edit) { openFilesEditor(edit.dataset.filesEdit); }
});

$("#filesUploadButton").addEventListener("click", () => $("#filesUploadInput").click());
$("#filesUploadInput").addEventListener("change", () => {
  const file = $("#filesUploadInput").files[0];
  if (file) uploadFileToCurrentDirectory(file);
  $("#filesUploadInput").value = "";
});

$("#filesEditForm").addEventListener("submit", (event) => {
  event.preventDefault();
  if ($("#saveFilesEdit").disabled || !state.filesEditingPath) return;
  const bytes = new TextEncoder().encode($("#filesEditContent").value);
  state.filesSocket?.send({ type: "write", path: state.filesEditingPath, data: bytesToBase64(bytes) });
});
$("#closeFilesEdit").addEventListener("click", closeFilesEditor);
$("#cancelFilesEdit").addEventListener("click", closeFilesEditor);
$("#filesEditDialog").addEventListener("close", () => { state.filesEditingPath = null; });

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
$("#deviceDialog").addEventListener("click", async (event) => {
  const button = event.target.closest("#saveDeviceTags");
  if (!button) return;
  const tags = $("#deviceTagsInput").value.split(",").map((t) => t.trim()).filter(Boolean);
  button.disabled = true;
  try {
    const result = await api(`/api/v1/admin/devices/${button.dataset.deviceId}/tags`, {
      method: "PUT",
      body: JSON.stringify({ tags }),
    });
    const device = state.devices.find((item) => item.id === button.dataset.deviceId);
    if (device) device.tags = result.tags;
    if (state.detailDevice?.id === button.dataset.deviceId) state.detailDevice.tags = result.tags;
    showNotice("Tags saved.");
    renderInventory();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    button.disabled = false;
  }
});
$("#metricRange").addEventListener("change", loadMetricHistory);
$("#monitoringLive").addEventListener("click", (event) => {
  const sortButton = event.target.closest("[data-consumer-sort]");
  if (sortButton) {
    const key = sortButton.dataset.consumerSort;
    if (state.topConsumersSort === key) {
      state.topConsumersSortDir = state.topConsumersSortDir === "asc" ? "desc" : "asc";
    } else {
      state.topConsumersSort = key;
      state.topConsumersSortDir = key === "kind" || key === "name" ? "asc" : "desc";
    }
    if (state.detailDevice) renderMonitoring(state.detailDevice);
    return;
  }
  const gpuButton = event.target.closest("[data-gpu-toggle]");
  if (gpuButton) {
    const key = gpuButton.dataset.gpuToggle;
    if (state.expandedGPUProcesses.has(key)) {
      state.expandedGPUProcesses.delete(key);
    } else {
      state.expandedGPUProcesses.add(key);
    }
    if (state.detailDevice) renderMonitoring(state.detailDevice);
  }
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
$("#channelForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/admin/notification-channels", {
      method: "POST",
      body: JSON.stringify({ name: $("#channelName").value.trim(), url: $("#channelURL").value.trim(), format: $("#channelFormat").value }),
    });
    event.target.reset();
    showNotice("Notification channel added.");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
});
$("#channelRows").addEventListener("click", async (event) => {
  const testButton = event.target.closest("[data-channel-test]");
  const toggleButton = event.target.closest("[data-channel-toggle]");
  const deleteButton = event.target.closest("[data-channel-delete]");
  if (testButton) {
    testButton.disabled = true;
    try {
      await api(`/api/v1/admin/notification-channels/${testButton.dataset.channelTest}/test`, { method: "POST" });
      showNotice("Test notification sent.");
    } catch (error) { showNotice(error.message, true); }
    finally { testButton.disabled = false; }
  }
  if (toggleButton) {
    const channel = state.notificationChannels.find((item) => item.id === toggleButton.dataset.channelToggle);
    if (!channel) return;
    try {
      await api(`/api/v1/admin/notification-channels/${channel.id}`, {
        method: "PUT",
        body: JSON.stringify({ name: channel.name, url: channel.url, format: channel.format, enabled: !channel.enabled }),
      });
      await refresh();
    } catch (error) { showNotice(error.message, true); }
  }
  if (deleteButton) {
    if (!confirm("Delete this notification channel?")) return;
    try {
      await api(`/api/v1/admin/notification-channels/${deleteButton.dataset.channelDelete}`, { method: "DELETE" });
      await refresh();
    } catch (error) { showNotice(error.message, true); }
  }
});

$("#ruleKind").addEventListener("change", () => {
  const kind = $("#ruleKind").value;
  $("#ruleMetricField").hidden = kind !== "resource_threshold";
  $("#ruleThresholdField").hidden = !["resource_threshold", "device_offline"].includes(kind);
  $("#ruleThreshold").placeholder = kind === "device_offline" ? "minutes" : "percent";
});
$("#alertRuleForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const kind = $("#ruleKind").value;
  const body = {
    name: $("#ruleName").value.trim(),
    kind,
    tag_filter: $("#ruleTagFilter").value.trim() || null,
    action_script_id: $("#ruleActionScript").value || null,
  };
  if (kind === "resource_threshold") {
    body.metric = $("#ruleMetric").value;
    body.threshold_value = Number($("#ruleThreshold").value);
  } else if (kind === "device_offline") {
    body.threshold_value = Number($("#ruleThreshold").value);
  }
  try {
    await api("/api/v1/admin/alert-rules", { method: "POST", body: JSON.stringify(body) });
    event.target.reset();
    $("#ruleMetricField").hidden = true;
    $("#ruleThresholdField").hidden = true;
    showNotice("Alert rule added.");
    await refresh();
  } catch (error) { showNotice(error.message, true); }
});
$("#alertRuleRows").addEventListener("click", async (event) => {
  const toggleButton = event.target.closest("[data-rule-toggle]");
  const deleteButton = event.target.closest("[data-rule-delete]");
  if (toggleButton) {
    const rule = state.alertRules.find((item) => item.id === toggleButton.dataset.ruleToggle);
    if (!rule) return;
    try {
      await api(`/api/v1/admin/alert-rules/${rule.id}`, {
        method: "PUT",
        body: JSON.stringify({ name: rule.name, kind: rule.kind, metric: rule.metric, threshold_value: rule.threshold_value, tag_filter: rule.tag_filter, enabled: !rule.enabled, action_script_id: rule.action_script_id }),
      });
      await refresh();
    } catch (error) { showNotice(error.message, true); }
  }
  if (deleteButton) {
    if (!confirm("Delete this alert rule?")) return;
    try {
      await api(`/api/v1/admin/alert-rules/${deleteButton.dataset.ruleDelete}`, { method: "DELETE" });
      await refresh();
    } catch (error) { showNotice(error.message, true); }
  }
});

$("#generateMigrationToken").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const result = await api("/api/v1/admin/migration/generate-token", { method: "POST" });
    $("#migrationTokenValue").textContent = result.token;
    $("#migrationTokenOutput").hidden = false;
    $("#migrationTokenMeta").hidden = false;
    $("#migrationTokenMeta").textContent = `One-time token, expires ${fullDate(result.expires_at)}. Paste it into the old server's form, along with this server's URL.`;
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    button.disabled = false;
  }
});

$("#migrationSendForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const targetURL = $("#migrationTargetURL").value.trim();
  const token = $("#migrationToken").value.trim();
  if (!confirm(`This replaces the entire database at ${targetURL} with this server's data, and re-points every enrolled agent there. This cannot be undone. Continue?`)) return;
  const status = $("#migrationSendStatus");
  status.textContent = "Migrating… this can take a while for a large fleet.";
  const button = event.target.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const result = await api("/api/v1/admin/migration/send", {
      method: "POST",
      body: JSON.stringify({ target_url: targetURL, token }),
    });
    status.textContent = `Done. ${result.devices_queued} of ${result.devices_total} device(s) queued to reconnect to ${result.target_url}. They'll switch over at their next check-in.`;
    $("#migrationToken").value = "";
  } catch (error) {
    status.textContent = "";
    showNotice(error.message, true);
  } finally {
    button.disabled = false;
  }
});

applyAccent(currentAccentHex());
setPage("dashboard");
$("#installServerURL").value = window.location.origin;
renderInstallCommand();
initializeAuth();
setInterval(() => { if (state.user && !state.user.must_change_password) refresh(); }, 30000);
