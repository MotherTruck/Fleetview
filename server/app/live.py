"""In-memory WebSocket hub for live metrics and an interactive terminal.

This is a purely additive layer next to the existing poll-based job system
(see main.py/deployment.py): a device that has no live connection here can
still be fully managed through queued jobs exactly as before, and the
1-minute REST-reported metrics that feed the retained history/trend charts
are untouched. Live metrics pushed over this channel are relayed to
connected browsers only -- never written to the database -- so this stays
cheap regardless of how frequently an agent pushes them.

Assumes a single Uvicorn worker process, which is what this project's
Dockerfile/docker-compose.yml run: state below is plain in-process memory
with no cross-process coordination.

WebSocket handlers here deliberately avoid FastAPI's `Depends(get_db)` for
anything beyond a single connect-time lookup: that dependency's session
stays open for as long as the endpoint function runs, and these endpoints
run for the lifetime of a persistent connection. Holding a pooled DB
session for that long (potentially many concurrent terminals/viewers)
would starve the connection pool, so every DB touch here opens and closes
its own short-lived session via SessionLocal() instead. Those lookups run
synchronously on the event loop thread rather than via asyncio.to_thread:
each is a single fast indexed PK lookup, and SQLite's in-memory (`sqlite://`)
mode -- used by this project's own test suite -- hands a *different*,
schema-less in-memory database to every new thread, so dispatching to a
worker thread pool broke these lookups under test even though it works
fine against Postgres or a file-backed SQLite database.
"""
import json
import uuid

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import ValidationError

from .auth import SESSION_COOKIE, authenticate_agent
from .database import SessionLocal
from .enrollment import as_utc
from .models import AccountAudit, Device, User, UserSession, utcnow
from .schemas import MetricsReport
from .security import token_hash

router = APIRouter()

MAX_TERMINAL_MESSAGE = 64 * 1024


def supports_live(device: Device) -> bool:
    try:
        return tuple(int(part) for part in (device.agent_version or "").split(".")[:2]) >= (0, 18)
    except ValueError:
        return False


def origin_is_trusted(websocket: WebSocket) -> bool:
    """Cross-site WebSocket connections are not blocked by the browser the
    way cross-site form/XHR requests are (that's what the app's CSRF token
    handles for normal requests) -- a malicious page's script really can
    open `new WebSocket(...)` against this origin and have the session
    cookie attached automatically. Comparing the handshake's Origin header
    against the Host header this request actually arrived on (which Caddy,
    when the optional TLS profile is in front, forwards unchanged) is the
    standard mitigation.
    """
    origin = websocket.headers.get("origin", "")
    host = websocket.headers.get("host", "")
    if not origin or not host:
        return False
    origin_host = origin.split("://", 1)[-1]
    return origin_host == host


def _lookup_device(device_id: str) -> Device | None:
    db = SessionLocal()
    try:
        return db.get(Device, device_id)
    finally:
        db.close()


def _authenticate_agent(device_id: str, authorization: str) -> Device | None:
    db = SessionLocal()
    try:
        return authenticate_agent(db, device_id, authorization)
    except HTTPException:
        return None
    finally:
        db.close()


def _authenticate_session_user(cookie: str) -> User | None:
    if not cookie:
        return None
    db = SessionLocal()
    try:
        session = db.get(UserSession, token_hash(cookie))
        user = db.get(User, session.user_id) if session else None
        if session is None or as_utc(session.expires_at) <= utcnow() or user is None or not user.active:
            return None
        return user
    finally:
        db.close()


def _record_audit(actor: str, action: str, target: str, details: str = "") -> None:
    db = SessionLocal()
    try:
        db.add(AccountAudit(actor=actor, action=action, target=target, details=details))
        db.commit()
    finally:
        db.close()


class LiveHub:
    def __init__(self) -> None:
        self.agents: dict[str, WebSocket] = {}
        self.metric_viewers: dict[str, set[WebSocket]] = {}
        self.status_viewers: set[WebSocket] = set()
        self.terminal_viewers: dict[str, tuple[WebSocket, str]] = {}

    # -- agent connection lifecycle --
    async def agent_connected(self, device_id: str, websocket: WebSocket) -> None:
        self.agents[device_id] = websocket
        await self._broadcast_status(device_id, True)

    async def agent_disconnected(self, device_id: str, websocket: WebSocket) -> None:
        if self.agents.get(device_id) is websocket:
            del self.agents[device_id]
        await self._broadcast_status(device_id, False)
        viewer = self.terminal_viewers.get(device_id)
        if viewer is not None:
            await self._safe_send(viewer[0], {"type": "terminal_closed", "session": viewer[1], "reason": "agent_disconnected"})
            self.release_terminal(device_id, viewer[0])

    def is_agent_live(self, device_id: str) -> bool:
        return device_id in self.agents

    # -- metrics fan-out (per-device viewers + fleet-wide status viewers) --
    def add_metric_viewer(self, device_id: str, websocket: WebSocket) -> None:
        self.metric_viewers.setdefault(device_id, set()).add(websocket)

    def remove_metric_viewer(self, device_id: str, websocket: WebSocket) -> None:
        viewers = self.metric_viewers.get(device_id)
        if viewers is not None:
            viewers.discard(websocket)
            if not viewers:
                del self.metric_viewers[device_id]

    def add_status_viewer(self, websocket: WebSocket) -> None:
        self.status_viewers.add(websocket)

    def remove_status_viewer(self, websocket: WebSocket) -> None:
        self.status_viewers.discard(websocket)

    async def broadcast_metrics(self, device_id: str, payload: dict) -> None:
        for viewer in list(self.metric_viewers.get(device_id, ())):
            await self._safe_send(viewer, payload, on_fail=lambda v=viewer: self.remove_metric_viewer(device_id, v))

    async def _broadcast_status(self, device_id: str, live: bool) -> None:
        message = {"type": "status", "device_id": device_id, "live": live}
        for viewer in list(self.metric_viewers.get(device_id, ())):
            await self._safe_send(viewer, message, on_fail=lambda v=viewer: self.remove_metric_viewer(device_id, v))
        for viewer in list(self.status_viewers):
            await self._safe_send(viewer, message, on_fail=lambda v=viewer: self.remove_status_viewer(v))

    def live_device_ids(self) -> list[str]:
        return list(self.agents.keys())

    # -- terminal (single active viewer per device) --
    def claim_terminal(self, device_id: str, websocket: WebSocket) -> str | None:
        if device_id in self.terminal_viewers:
            return None
        session_id = uuid.uuid4().hex
        self.terminal_viewers[device_id] = (websocket, session_id)
        return session_id

    def release_terminal(self, device_id: str, websocket: WebSocket) -> None:
        current = self.terminal_viewers.get(device_id)
        if current is not None and current[0] is websocket:
            del self.terminal_viewers[device_id]

    def terminal_viewer_for(self, device_id: str) -> tuple[WebSocket, str] | None:
        return self.terminal_viewers.get(device_id)

    async def send_to_agent(self, device_id: str, payload: dict) -> bool:
        agent = self.agents.get(device_id)
        if agent is None:
            return False
        try:
            await agent.send_json(payload)
            return True
        except Exception:
            return False

    @staticmethod
    async def _safe_send(websocket: WebSocket, payload: dict, on_fail=None) -> None:
        try:
            await websocket.send_json(payload)
        except Exception:
            if on_fail is not None:
                on_fail()


hub = LiveHub()


async def _reject(websocket: WebSocket, code: int, reason: str) -> None:
    """Closing before accept() collapses to a generic HTTP 403 at the
    handshake level with no code or reason reaching the client -- browsers
    deliberately hide those details from JS for a failed WS handshake (see
    the WHATWG spec's WebSocket constructor steps). Accepting first and
    sending one JSON error frame before closing is the only way for either
    the Go agent's reconnect logic or the dashboard's error UI to actually
    learn why, verified against a real client during this feature's testing.
    """
    await websocket.accept()
    await websocket.send_json({"type": "error", "code": code, "reason": reason})
    await websocket.close(code=code, reason=reason)


@router.websocket("/api/v1/agent/live")
async def agent_live(websocket: WebSocket) -> None:
    device_id = websocket.headers.get("x-device-id", "")
    authorization = websocket.headers.get("authorization", "")
    device = _authenticate_agent(device_id, authorization)
    if device is None:
        await _reject(websocket, 4401, "Invalid agent credentials")
        return
    await websocket.accept()
    await hub.agent_connected(device.id, websocket)
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            message_type = message.get("type")
            if message_type == "metrics":
                fields = {key: value for key, value in message.items() if key != "type"}
                try:
                    parsed = MetricsReport.model_validate(fields)
                except ValidationError:
                    continue
                await hub.broadcast_metrics(device.id, {"type": "metrics", "device_id": device.id, **parsed.model_dump(mode="json")})
            elif message_type in ("terminal_output", "terminal_closed"):
                viewer = hub.terminal_viewer_for(device.id)
                if viewer is not None and viewer[1] == message.get("session"):
                    await hub._safe_send(viewer[0], message)
    except WebSocketDisconnect:
        pass
    finally:
        await hub.agent_disconnected(device.id, websocket)


@router.websocket("/api/v1/admin/live-status")
async def browser_live_status(websocket: WebSocket) -> None:
    if not origin_is_trusted(websocket):
        await _reject(websocket, 4403, "Origin not trusted")
        return
    user = _authenticate_session_user(websocket.cookies.get(SESSION_COOKIE, ""))
    if user is None:
        await _reject(websocket, 4401, "Sign in to continue")
        return
    await websocket.accept()
    hub.add_status_viewer(websocket)
    try:
        await websocket.send_json({"type": "snapshot", "live_device_ids": hub.live_device_ids()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove_status_viewer(websocket)


@router.websocket("/api/v1/admin/devices/{device_id}/metrics-live")
async def browser_metrics_live(websocket: WebSocket, device_id: str) -> None:
    if not origin_is_trusted(websocket):
        await _reject(websocket, 4403, "Origin not trusted")
        return
    user = _authenticate_session_user(websocket.cookies.get(SESSION_COOKIE, ""))
    if user is None:
        await _reject(websocket, 4401, "Sign in to continue")
        return
    device = _lookup_device(device_id)
    if device is None:
        await _reject(websocket, 4404, "Device not found")
        return
    await websocket.accept()
    hub.add_metric_viewer(device_id, websocket)
    try:
        await websocket.send_json({"type": "status", "device_id": device_id, "live": hub.is_agent_live(device_id)})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        hub.remove_metric_viewer(device_id, websocket)


@router.websocket("/api/v1/admin/devices/{device_id}/terminal-live")
async def browser_terminal_live(websocket: WebSocket, device_id: str) -> None:
    if not origin_is_trusted(websocket):
        await _reject(websocket, 4403, "Origin not trusted")
        return
    user = _authenticate_session_user(websocket.cookies.get(SESSION_COOKIE, ""))
    if user is None:
        await _reject(websocket, 4401, "Sign in to continue")
        return
    if user.role != "admin" or user.must_change_password:
        await _reject(websocket, 4403, "Admin access required")
        return
    device = _lookup_device(device_id)
    if device is None:
        await _reject(websocket, 4404, "Device not found")
        return
    if not supports_live(device):
        await _reject(websocket, 4409, "Upgrade this device's agent to 0.18.0 for a live terminal")
        return
    if not hub.is_agent_live(device_id):
        await _reject(websocket, 4410, "Device is not currently connected")
        return
    session_id = hub.claim_terminal(device_id, websocket)
    if session_id is None:
        await _reject(websocket, 4429, "A terminal session is already open for this device")
        return
    await websocket.accept()
    _record_audit(user.username, "terminal_open", device.hostname, session_id)
    started = await hub.send_to_agent(device_id, {"type": "terminal_start", "session": session_id, "cols": 80, "rows": 24})
    if not started:
        await websocket.send_json({"type": "terminal_closed", "session": session_id, "reason": "agent_unavailable"})
        hub.release_terminal(device_id, websocket)
        await websocket.close()
        return
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw) > MAX_TERMINAL_MESSAGE:
                continue
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            message_type = message.get("type")
            if message_type == "input":
                data = message.get("data")
                if isinstance(data, str):
                    await hub.send_to_agent(device_id, {"type": "terminal_input", "session": session_id, "data": data})
            elif message_type == "resize":
                cols, rows = message.get("cols"), message.get("rows")
                if isinstance(cols, int) and isinstance(rows, int) and 1 <= cols <= 1000 and 1 <= rows <= 1000:
                    await hub.send_to_agent(device_id, {"type": "terminal_resize", "session": session_id, "cols": cols, "rows": rows})
    except WebSocketDisconnect:
        pass
    finally:
        hub.release_terminal(device_id, websocket)
        await hub.send_to_agent(device_id, {"type": "terminal_stop", "session": session_id})
