// Standalone remote-control window: opened via window.open from the main
// dashboard (see app.js's deviceDialog click handler) rather than embedded
// in the device detail dialog, so a live screen view gets a window sized
// and dedicated to it instead of competing for space with everything else
// there. Same-origin, so the session cookie set by the main dashboard
// already covers this page -- no separate sign-in.
const $ = (selector) => document.querySelector(selector);

function deviceIdFromURL() {
  return new URLSearchParams(location.search).get("device") || "";
}

async function fetchJSON(path) {
  const response = await fetch(path, { credentials: "same-origin", headers: { "X-FleetView-Request": "1" } });
  if (!response.ok) {
    const error = new Error(`Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function wsBase() {
  return (location.protocol === "https:" ? "wss://" : "ws://") + location.host;
}

function setStatus(text) {
  $("#rcStatus").textContent = text;
}

async function main() {
  const deviceId = deviceIdFromURL();
  if (!deviceId) {
    setStatus("No device specified.");
    return;
  }

  let me;
  try {
    me = await fetchJSON("/api/v1/auth/me");
  } catch {
    setStatus("Sign in on the main FleetView tab, then reopen this window.");
    return;
  }
  if (me.user.role !== "admin") {
    setStatus("Admin access required.");
    return;
  }

  let device;
  try {
    device = await fetchJSON(`/api/v1/admin/devices/${encodeURIComponent(deviceId)}`);
  } catch {
    setStatus("Could not load this device.");
    return;
  }
  document.title = `Remote control — ${device.display_name || device.hostname}`;
  $("#rcHostname").textContent = device.display_name || device.hostname;

  const remoteControl = (device.inventory || {}).remote_control || {};
  if (remoteControl.available !== true) {
    setStatus(remoteControl.reason || "Not available on this device yet -- it may need to report inventory again after a recent upgrade.");
    return;
  }

  const inputEnabled = remoteControl.view_only !== true;
  const stage = $("#rcStage");
  const frame = $("#rcFrame");
  stage.dataset.input = String(inputEnabled);
  if (!inputEnabled) {
    setStatus(`Connecting… (view only: ${remoteControl.reason || "no input-capable desktop session"})`);
  } else {
    setStatus("Connecting…");
  }

  let frameURL = null;
  const socket = new WebSocket(`${wsBase()}/api/v1/admin/devices/${encodeURIComponent(deviceId)}/screen-live`);
  socket.addEventListener("open", () => setStatus(inputEnabled ? "Connected · waiting for first frame…" : "Connected (view only) · waiting for first frame…"));
  socket.addEventListener("close", () => setStatus("Disconnected"));
  socket.addEventListener("error", () => socket.close());
  socket.addEventListener("message", (event) => {
    if (event.data instanceof Blob) {
      const url = URL.createObjectURL(event.data);
      const previous = frameURL;
      frame.src = url;
      frame.hidden = false;
      frameURL = url;
      if (previous) URL.revokeObjectURL(previous);
      return;
    }
    let message;
    try { message = JSON.parse(event.data); } catch { return; }
    if (message.type === "screen_info") {
      setStatus(inputEnabled ? "Live" : "Live (view only)");
    } else if (message.type === "screen_closed") {
      setStatus(`Session ended: ${message.reason || "closed"}`);
      socket.close();
    } else if (message.type === "error") {
      setStatus(`Error: ${message.reason || "rejected"}`);
    }
  });

  const send = (payload) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(payload));
  };

  // Fraction-based (0-1) coordinates, not raw pixels: this window only
  // knows the size of the frame it received, so this is the only way
  // input stays aligned with the agent's actual screen resolution
  // regardless of this window's own size (see agent/internal/live/
  // screen.go and the screen package's pixel() conversion).
  const pointerFraction = (event) => {
    const rect = frame.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    return {
      x: Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width)),
      y: Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height)),
    };
  };
  const buttonNames = ["left", "middle", "right"];
  let pointerDown = false;

  if (inputEnabled) {
    stage.addEventListener("mousemove", (event) => {
      const point = pointerFraction(event);
      if (point) send({ type: "mouse_move", x: point.x, y: point.y });
    });
    stage.addEventListener("mousedown", (event) => {
      event.preventDefault();
      stage.focus();
      const point = pointerFraction(event);
      const button = buttonNames[event.button];
      if (!point || !button) return;
      pointerDown = true;
      send({ type: "mouse_button", x: point.x, y: point.y, button, pressed: true });
    });
    // Bound to the window rather than the stage so a drag that ends
    // outside the frame still releases the button instead of leaving it
    // stuck down on the remote device.
    window.addEventListener("mouseup", (event) => {
      if (!pointerDown) return;
      pointerDown = false;
      const point = pointerFraction(event);
      const button = buttonNames[event.button];
      if (point && button) send({ type: "mouse_button", x: point.x, y: point.y, button, pressed: false });
    });
    stage.addEventListener("contextmenu", (event) => event.preventDefault());
    stage.addEventListener("wheel", (event) => {
      event.preventDefault();
      send({ type: "mouse_scroll", dx: event.deltaX / 100, dy: event.deltaY / 100 });
    }, { passive: false });

    // Touch has no hover/mousemove, so a single finger is mapped to a left
    // button drag: touchstart presses down where the finger landed,
    // touchmove drags, touchend releases. preventDefault throughout stops
    // the browser from scrolling/pinch-zooming the page instead of
    // controlling the remote screen.
    let touchDown = false;
    stage.addEventListener("touchstart", (event) => {
      event.preventDefault();
      stage.focus();
      const point = pointerFraction(event.touches[0]);
      if (!point) return;
      touchDown = true;
      send({ type: "mouse_move", x: point.x, y: point.y });
      send({ type: "mouse_button", x: point.x, y: point.y, button: "left", pressed: true });
    }, { passive: false });
    stage.addEventListener("touchmove", (event) => {
      event.preventDefault();
      if (!touchDown) return;
      const point = pointerFraction(event.touches[0]);
      if (point) send({ type: "mouse_move", x: point.x, y: point.y });
    }, { passive: false });
    const endTouch = (event) => {
      event.preventDefault();
      if (!touchDown) return;
      touchDown = false;
      const point = pointerFraction(event.changedTouches[0]);
      if (point) send({ type: "mouse_button", x: point.x, y: point.y, button: "left", pressed: false });
    };
    stage.addEventListener("touchend", endTouch, { passive: false });
    stage.addEventListener("touchcancel", endTouch, { passive: false });
    stage.addEventListener("keydown", (event) => {
      event.preventDefault();
      send({ type: "key", key: event.key, pressed: true });
    });
    stage.addEventListener("keyup", (event) => {
      event.preventDefault();
      send({ type: "key", key: event.key, pressed: false });
    });
    stage.focus();
  }
}

main();
