//! Mirrors server/app/live.py: an in-memory WebSocket hub for live
//! metrics, an interactive terminal, and remote control. Purely additive
//! next to the poll-based job system -- a device with no live connection
//! here is still fully manageable through queued jobs.
//!
//! Python's version stores WebSocket objects directly in plain dicts,
//! safe only because asyncio's single-threaded cooperative scheduling
//! serializes every access with no other thread able to interleave.
//! Tokio has no such guarantee, so this port uses the standard actor
//! pattern instead: each connection owns its real WebSocket split into a
//! dedicated writer task fed by an mpsc channel, and the hub stores only
//! that channel's Sender (behind a std::sync::Mutex, since every
//! operation on it is a fast, non-blocking map lookup/insert). This is
//! the same channel-per-connection shape agent/internal/live/live.go
//! already uses on the agent side, for the same reason.
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::Router;
use axum_extra::extract::CookieJar;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::auth::{authenticate_agent, SESSION_COOKIE};
use crate::models::{Device, User};
use crate::security::token_hash;
use crate::AppState;

pub const MAX_TERMINAL_MESSAGE: usize = 64 * 1024;

#[derive(Clone)]
enum OutMsg {
    Json(Value),
    Binary(Vec<u8>),
}

type Tx = mpsc::UnboundedSender<OutMsg>;
type ViewerId = u64;

#[derive(Default)]
struct HubState {
    agents: HashMap<String, (ViewerId, Tx)>,
    metric_viewers: HashMap<String, HashMap<ViewerId, Tx>>,
    status_viewers: HashMap<ViewerId, Tx>,
    terminal_viewers: HashMap<String, (ViewerId, Tx, String)>,
    screen_viewers: HashMap<String, (ViewerId, Tx, String)>,
}

pub struct LiveHub {
    state: Mutex<HubState>,
    next_id: AtomicU64,
}

impl LiveHub {
    pub fn new() -> Self {
        LiveHub { state: Mutex::new(HubState::default()), next_id: AtomicU64::new(1) }
    }

    fn next_viewer_id(&self) -> ViewerId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn send(tx: &Tx, payload: Value) {
        let _ = tx.send(OutMsg::Json(payload));
    }

    // -- agent connection lifecycle --
    fn agent_connected(&self, device_id: &str, id: ViewerId, tx: Tx) {
        self.state.lock().unwrap().agents.insert(device_id.to_string(), (id, tx));
        self.broadcast_status(device_id, true);
    }

    fn agent_disconnected(&self, device_id: &str, id: ViewerId) {
        let (terminal_closed, screen_closed) = {
            let mut state = self.state.lock().unwrap();
            if state.agents.get(device_id).map(|(vid, _)| *vid) == Some(id) {
                state.agents.remove(device_id);
            }
            let terminal = state.terminal_viewers.remove(device_id);
            let screen = state.screen_viewers.remove(device_id);
            (terminal, screen)
        };
        self.broadcast_status(device_id, false);
        if let Some((_, tx, session)) = terminal_closed {
            Self::send(&tx, json!({"type": "terminal_closed", "session": session, "reason": "agent_disconnected"}));
        }
        if let Some((_, tx, session)) = screen_closed {
            Self::send(&tx, json!({"type": "screen_closed", "session": session, "reason": "agent_disconnected"}));
        }
    }

    pub fn is_agent_live(&self, device_id: &str) -> bool {
        self.state.lock().unwrap().agents.contains_key(device_id)
    }

    pub fn live_device_ids(&self) -> Vec<String> {
        self.state.lock().unwrap().agents.keys().cloned().collect()
    }

    // -- metrics fan-out --
    fn add_metric_viewer(&self, device_id: &str, id: ViewerId, tx: Tx) {
        self.state.lock().unwrap().metric_viewers.entry(device_id.to_string()).or_default().insert(id, tx);
    }

    fn remove_metric_viewer(&self, device_id: &str, id: ViewerId) {
        let mut state = self.state.lock().unwrap();
        if let Some(viewers) = state.metric_viewers.get_mut(device_id) {
            viewers.remove(&id);
            if viewers.is_empty() {
                state.metric_viewers.remove(device_id);
            }
        }
    }

    fn add_status_viewer(&self, id: ViewerId, tx: Tx) {
        self.state.lock().unwrap().status_viewers.insert(id, tx);
    }

    fn remove_status_viewer(&self, id: ViewerId) {
        self.state.lock().unwrap().status_viewers.remove(&id);
    }

    fn broadcast_metrics(&self, device_id: &str, payload: Value) {
        let targets: Vec<Tx> = {
            let state = self.state.lock().unwrap();
            state.metric_viewers.get(device_id).map(|m| m.values().cloned().collect()).unwrap_or_default()
        };
        for tx in targets {
            Self::send(&tx, payload.clone());
        }
    }

    fn broadcast_status(&self, device_id: &str, live: bool) {
        let message = json!({"type": "status", "device_id": device_id, "live": live});
        let targets: Vec<Tx> = {
            let state = self.state.lock().unwrap();
            let mut targets: Vec<Tx> = state.metric_viewers.get(device_id).map(|m| m.values().cloned().collect()).unwrap_or_default();
            targets.extend(state.status_viewers.values().cloned());
            targets
        };
        for tx in targets {
            Self::send(&tx, message.clone());
        }
    }

    // -- terminal (single active viewer per device) --
    fn claim_terminal(&self, device_id: &str, id: ViewerId, tx: Tx) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        if state.terminal_viewers.contains_key(device_id) {
            return None;
        }
        let session_id = Uuid::new_v4().simple().to_string();
        state.terminal_viewers.insert(device_id.to_string(), (id, tx, session_id.clone()));
        Some(session_id)
    }

    fn release_terminal(&self, device_id: &str, id: ViewerId) {
        let mut state = self.state.lock().unwrap();
        if state.terminal_viewers.get(device_id).map(|(vid, _, _)| *vid) == Some(id) {
            state.terminal_viewers.remove(device_id);
        }
    }

    fn terminal_viewer_session(&self, device_id: &str) -> Option<String> {
        self.state.lock().unwrap().terminal_viewers.get(device_id).map(|(_, _, s)| s.clone())
    }

    fn send_to_terminal_viewer(&self, device_id: &str, session: &str, payload: Value) {
        let tx = self.state.lock().unwrap().terminal_viewers.get(device_id).and_then(|(_, tx, s)| {
            (s == session).then(|| tx.clone())
        });
        if let Some(tx) = tx {
            Self::send(&tx, payload);
        }
    }

    // -- remote control (single active viewer per device) --
    fn claim_screen(&self, device_id: &str, id: ViewerId, tx: Tx) -> Option<String> {
        let mut state = self.state.lock().unwrap();
        if state.screen_viewers.contains_key(device_id) {
            return None;
        }
        let session_id = Uuid::new_v4().simple().to_string();
        state.screen_viewers.insert(device_id.to_string(), (id, tx, session_id.clone()));
        Some(session_id)
    }

    fn release_screen(&self, device_id: &str, id: ViewerId) {
        let mut state = self.state.lock().unwrap();
        if state.screen_viewers.get(device_id).map(|(vid, _, _)| *vid) == Some(id) {
            state.screen_viewers.remove(device_id);
        }
    }

    fn send_to_screen_viewer(&self, device_id: &str, session: &str, payload: Value) {
        let tx = self.state.lock().unwrap().screen_viewers.get(device_id).and_then(|(_, tx, s)| {
            (s == session).then(|| tx.clone())
        });
        if let Some(tx) = tx {
            Self::send(&tx, payload);
        }
    }

    fn send_binary_to_screen_viewer(&self, device_id: &str, data: Vec<u8>) {
        let tx = self.state.lock().unwrap().screen_viewers.get(device_id).map(|(_, tx, _)| tx.clone());
        if let Some(tx) = tx {
            let _ = tx.send(OutMsg::Binary(data));
        }
    }

    fn send_to_agent(&self, device_id: &str, payload: Value) -> bool {
        let tx = self.state.lock().unwrap().agents.get(device_id).map(|(_, tx)| tx.clone());
        match tx {
            Some(tx) => tx.send(OutMsg::Json(payload)).is_ok(),
            None => false,
        }
    }
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/agent/live", get(agent_live))
        .route("/api/v1/admin/live-status", get(browser_live_status))
        .route("/api/v1/admin/devices/:id/metrics-live", get(browser_metrics_live))
        .route("/api/v1/admin/devices/:id/terminal-live", get(browser_terminal_live))
        .route("/api/v1/admin/devices/:id/screen-live", get(browser_screen_live))
}

/// A writer task owns the real WebSocket sink for a connection's whole
/// lifetime, draining `rx` and forwarding to the socket -- the only task
/// ever allowed to touch that sink, matching the Go agent's own
/// single-writer-goroutine pattern for exactly the same reason (WebSocket
/// sinks aren't safe to write from multiple tasks concurrently).
fn spawn_writer(mut sink: futures_util::stream::SplitSink<WebSocket, Message>, mut rx: mpsc::UnboundedReceiver<OutMsg>) {
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let sent = match msg {
                OutMsg::Json(value) => sink.send(Message::Text(value.to_string())).await,
                OutMsg::Binary(data) => sink.send(Message::Binary(data)).await,
            };
            if sent.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
}

async fn reject(socket: &mut WebSocket, code: u16, reason: &str) {
    // Closing before accept collapses to a generic failure at the
    // handshake level with no code/reason reaching client JS -- accepting
    // first (axum already upgraded by the time this runs) and sending one
    // JSON error frame before the close frame is the only way either the
    // Go agent's reconnect logic or the dashboard's error UI learns why.
    let _ = socket.send(Message::Text(json!({"type": "error", "code": code, "reason": reason}).to_string())).await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame { code, reason: reason.to_string().into() })))
        .await;
}

fn origin_is_trusted(headers: &HeaderMap) -> bool {
    let origin = headers.get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if origin.is_empty() || host.is_empty() {
        return false;
    }
    let origin_host = origin.split_once("://").map(|(_, rest)| rest).unwrap_or(origin);
    origin_host == host
}

async fn lookup_device(state: &AppState, id: &str) -> Option<Device> {
    sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
}

async fn authenticate_session_user(state: &AppState, cookie: &str) -> Option<User> {
    if cookie.is_empty() {
        return None;
    }
    let hashed = token_hash(cookie);
    let row = sqlx::query("SELECT user_id, expires_at FROM user_sessions WHERE token_hash = $1")
        .bind(&hashed)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()?;
    let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
    if expires_at <= chrono::Utc::now() {
        return None;
    }
    let user_id: String = row.get("user_id");
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, active, must_change_password, created_at, last_login_at FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()?;
    if !user.active {
        return None;
    }
    Some(user)
}

async fn record_audit(state: &AppState, actor: &str, action: &str, target: &str, details: &str) {
    let _ = sqlx::query("INSERT INTO account_audit (actor, action, target, details) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(details)
        .execute(&state.db)
        .await;
}

fn version_at_least(version: Option<&str>, required: (i32, i32)) -> bool {
    let Some(version) = version else { return false };
    let mut parts = version.split('.').take(2).map(|p| p.parse::<i32>());
    let (Some(Ok(major)), Some(Ok(minor))) = (parts.next(), parts.next()) else {
        return false;
    };
    (major, minor) >= required
}

fn supports_live(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 18))
}
fn supports_remote_control(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 23))
}

fn is_unit_fraction(value: Option<&Value>) -> Option<f64> {
    let value = value?;
    if value.is_boolean() {
        return None;
    }
    let n = value.as_f64()?;
    (0.0..=1.0).contains(&n).then_some(n)
}

// -- agent endpoint --

async fn agent_live(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>, headers: HeaderMap) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_agent_live(socket, state, headers))
}

async fn handle_agent_live(mut socket: WebSocket, state: Arc<AppState>, headers: HeaderMap) {
    let device_id = headers.get("x-device-id").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let device = match authenticate_agent(&state, &device_id, &authorization).await {
        Ok(device) => device,
        Err(_) => {
            reject(&mut socket, 4401, "Invalid agent credentials").await;
            return;
        }
    };

    let id = state.hub.next_viewer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let (sink, mut stream) = socket.split();
    spawn_writer(sink, rx);
    state.hub.agent_connected(&device.id, id, tx);

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Binary(frame) => {
                // A remote-control JPEG frame: relayed opaquely, never
                // parsed as JSON, to whichever browser currently holds
                // this device's screen session (dropped if none).
                state.hub.send_binary_to_screen_viewer(&device.id, frame);
            }
            Message::Text(raw) => {
                let Ok(message) = serde_json::from_str::<Value>(&raw) else { continue };
                let message_type = message.get("type").and_then(Value::as_str).unwrap_or("");
                match message_type {
                    "metrics" => {
                        if let Ok(parsed) = serde_json::from_value::<crate::devices::MetricsReportPayload>(message.clone()) {
                            let mut payload = serde_json::to_value(parsed).unwrap();
                            let obj = payload.as_object_mut().unwrap();
                            obj.insert("type".to_string(), json!("metrics"));
                            obj.insert("device_id".to_string(), json!(device.id));
                            state.hub.broadcast_metrics(&device.id, Value::Object(obj.clone()));
                        }
                    }
                    "terminal_output" | "terminal_closed" => {
                        if let Some(session) = message.get("session").and_then(Value::as_str).map(str::to_string) {
                            if state.hub.terminal_viewer_session(&device.id).as_deref() == Some(session.as_str()) {
                                state.hub.send_to_terminal_viewer(&device.id, &session, message);
                            }
                        }
                    }
                    "screen_info" | "screen_closed" => {
                        if let Some(session) = message.get("session").and_then(Value::as_str) {
                            state.hub.send_to_screen_viewer(&device.id, session, message.clone());
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.hub.agent_disconnected(&device.id, id);
}

// -- browser: fleet-wide live status --

async fn browser_live_status(ws: WebSocketUpgrade, State(state): State<Arc<AppState>>, headers: HeaderMap, jar: CookieJar) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_browser_live_status(socket, state, headers, jar))
}

async fn handle_browser_live_status(mut socket: WebSocket, state: Arc<AppState>, headers: HeaderMap, jar: CookieJar) {
    if !origin_is_trusted(&headers) {
        reject(&mut socket, 4403, "Origin not trusted").await;
        return;
    }
    let cookie = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let Some(user) = authenticate_session_user(&state, &cookie).await else {
        reject(&mut socket, 4401, "Sign in to continue").await;
        return;
    };
    if user.must_change_password {
        reject(&mut socket, 4403, "Change your password before continuing").await;
        return;
    }

    let id = state.hub.next_viewer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let (sink, mut stream) = socket.split();
    spawn_writer(sink, rx);
    state.hub.add_status_viewer(id, tx.clone());
    LiveHub::send(&tx, json!({"type": "snapshot", "live_device_ids": state.hub.live_device_ids()}));

    while let Some(Ok(message)) = stream.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    state.hub.remove_status_viewer(id);
}

// -- browser: per-device metrics --

async fn browser_metrics_live(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_browser_metrics_live(socket, state, device_id, headers, jar))
}

async fn handle_browser_metrics_live(mut socket: WebSocket, state: Arc<AppState>, device_id: String, headers: HeaderMap, jar: CookieJar) {
    if !origin_is_trusted(&headers) {
        reject(&mut socket, 4403, "Origin not trusted").await;
        return;
    }
    let cookie = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let Some(user) = authenticate_session_user(&state, &cookie).await else {
        reject(&mut socket, 4401, "Sign in to continue").await;
        return;
    };
    if user.must_change_password {
        reject(&mut socket, 4403, "Change your password before continuing").await;
        return;
    }
    if lookup_device(&state, &device_id).await.is_none() {
        reject(&mut socket, 4404, "Device not found").await;
        return;
    }

    let id = state.hub.next_viewer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let (sink, mut stream) = socket.split();
    spawn_writer(sink, rx);
    state.hub.add_metric_viewer(&device_id, id, tx.clone());
    LiveHub::send(&tx, json!({"type": "status", "device_id": device_id, "live": state.hub.is_agent_live(&device_id)}));

    while let Some(Ok(message)) = stream.next().await {
        if matches!(message, Message::Close(_)) {
            break;
        }
    }
    state.hub.remove_metric_viewer(&device_id, id);
}

// -- browser: interactive terminal --

async fn browser_terminal_live(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_browser_terminal_live(socket, state, device_id, headers, jar))
}

async fn handle_browser_terminal_live(mut socket: WebSocket, state: Arc<AppState>, device_id: String, headers: HeaderMap, jar: CookieJar) {
    if !origin_is_trusted(&headers) {
        reject(&mut socket, 4403, "Origin not trusted").await;
        return;
    }
    let cookie = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let Some(user) = authenticate_session_user(&state, &cookie).await else {
        reject(&mut socket, 4401, "Sign in to continue").await;
        return;
    };
    if user.role != "admin" || user.must_change_password {
        reject(&mut socket, 4403, "Admin access required").await;
        return;
    }
    let Some(device) = lookup_device(&state, &device_id).await else {
        reject(&mut socket, 4404, "Device not found").await;
        return;
    };
    if !supports_live(&device) {
        reject(&mut socket, 4409, "Upgrade this device's agent to 0.18.0 for a live terminal").await;
        return;
    }
    if !state.hub.is_agent_live(&device_id) {
        reject(&mut socket, 4410, "Device is not currently connected").await;
        return;
    }

    let id = state.hub.next_viewer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let Some(session_id) = state.hub.claim_terminal(&device_id, id, tx.clone()) else {
        reject(&mut socket, 4429, "A terminal session is already open for this device").await;
        return;
    };
    let (sink, mut stream) = socket.split();
    spawn_writer(sink, rx);

    record_audit(&state, &user.username, "terminal_open", &device.hostname, &session_id).await;
    let started = state.hub.send_to_agent(&device_id, json!({"type": "terminal_start", "session": session_id, "cols": 80, "rows": 24}));
    if !started {
        LiveHub::send(&tx, json!({"type": "terminal_closed", "session": session_id, "reason": "agent_unavailable"}));
        state.hub.release_terminal(&device_id, id);
        return;
    }

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Text(raw) => {
                if raw.len() > MAX_TERMINAL_MESSAGE {
                    continue;
                }
                let Ok(message) = serde_json::from_str::<Value>(&raw) else { continue };
                match message.get("type").and_then(Value::as_str).unwrap_or("") {
                    "input" => {
                        if let Some(data) = message.get("data").and_then(Value::as_str) {
                            state.hub.send_to_agent(&device_id, json!({"type": "terminal_input", "session": session_id, "data": data}));
                        }
                    }
                    "resize" => {
                        let cols = message.get("cols").and_then(Value::as_i64);
                        let rows = message.get("rows").and_then(Value::as_i64);
                        if let (Some(cols), Some(rows)) = (cols, rows) {
                            if (1..=1000).contains(&cols) && (1..=1000).contains(&rows) {
                                state.hub.send_to_agent(&device_id, json!({"type": "terminal_resize", "session": session_id, "cols": cols, "rows": rows}));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.hub.release_terminal(&device_id, id);
    state.hub.send_to_agent(&device_id, json!({"type": "terminal_stop", "session": session_id}));
}

// -- browser: remote control --

async fn browser_screen_live(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    jar: CookieJar,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_browser_screen_live(socket, state, device_id, headers, jar))
}

async fn handle_browser_screen_live(mut socket: WebSocket, state: Arc<AppState>, device_id: String, headers: HeaderMap, jar: CookieJar) {
    if !origin_is_trusted(&headers) {
        reject(&mut socket, 4403, "Origin not trusted").await;
        return;
    }
    let cookie = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let Some(user) = authenticate_session_user(&state, &cookie).await else {
        reject(&mut socket, 4401, "Sign in to continue").await;
        return;
    };
    if user.role != "admin" || user.must_change_password {
        reject(&mut socket, 4403, "Admin access required").await;
        return;
    }
    let Some(device) = lookup_device(&state, &device_id).await else {
        reject(&mut socket, 4404, "Device not found").await;
        return;
    };
    if !supports_remote_control(&device) {
        reject(&mut socket, 4409, "Upgrade this device's agent to 0.23.0 for remote control").await;
        return;
    }
    if !state.hub.is_agent_live(&device_id) {
        reject(&mut socket, 4410, "Device is not currently connected").await;
        return;
    }

    let id = state.hub.next_viewer_id();
    let (tx, rx) = mpsc::unbounded_channel();
    let Some(session_id) = state.hub.claim_screen(&device_id, id, tx.clone()) else {
        reject(&mut socket, 4429, "A remote control session is already open for this device").await;
        return;
    };
    let (sink, mut stream) = socket.split();
    spawn_writer(sink, rx);

    record_audit(&state, &user.username, "screen_open", &device.hostname, &session_id).await;
    let started = state.hub.send_to_agent(&device_id, json!({"type": "screen_start", "session": session_id}));
    if !started {
        LiveHub::send(&tx, json!({"type": "screen_closed", "session": session_id, "reason": "agent_unavailable"}));
        state.hub.release_screen(&device_id, id);
        return;
    }

    while let Some(Ok(message)) = stream.next().await {
        match message {
            Message::Text(raw) => {
                if raw.len() > MAX_TERMINAL_MESSAGE {
                    continue;
                }
                let Ok(message) = serde_json::from_str::<Value>(&raw) else { continue };
                match message.get("type").and_then(Value::as_str).unwrap_or("") {
                    "mouse_move" => {
                        let x = is_unit_fraction(message.get("x"));
                        let y = is_unit_fraction(message.get("y"));
                        if let (Some(x), Some(y)) = (x, y) {
                            state.hub.send_to_agent(&device_id, json!({"type": "mouse_move", "session": session_id, "x": x, "y": y}));
                        }
                    }
                    "mouse_button" => {
                        let x = is_unit_fraction(message.get("x"));
                        let y = is_unit_fraction(message.get("y"));
                        let button = message.get("button").and_then(Value::as_str);
                        let pressed = message.get("pressed").and_then(Value::as_bool);
                        if let (Some(x), Some(y), Some(button), Some(pressed)) = (x, y, button, pressed) {
                            state.hub.send_to_agent(
                                &device_id,
                                json!({"type": "mouse_button", "session": session_id, "x": x, "y": y, "button": button, "pressed": pressed}),
                            );
                        }
                    }
                    "mouse_scroll" => {
                        let dx = message.get("dx").filter(|v| !v.is_boolean()).and_then(Value::as_f64);
                        let dy = message.get("dy").filter(|v| !v.is_boolean()).and_then(Value::as_f64);
                        if let (Some(dx), Some(dy)) = (dx, dy) {
                            state.hub.send_to_agent(&device_id, json!({"type": "mouse_scroll", "session": session_id, "dx": dx, "dy": dy}));
                        }
                    }
                    "key" => {
                        let key = message.get("key").and_then(Value::as_str);
                        let pressed = message.get("pressed").and_then(Value::as_bool);
                        if let (Some(key), Some(pressed)) = (key, pressed) {
                            if !key.is_empty() && key.len() <= 32 {
                                state.hub.send_to_agent(&device_id, json!({"type": "key", "session": session_id, "key": key, "pressed": pressed}));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    state.hub.release_screen(&device_id, id);
    state.hub.send_to_agent(&device_id, json!({"type": "screen_stop", "session": session_id}));
}
