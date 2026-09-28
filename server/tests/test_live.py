"""WebSocket live-metrics/terminal relay regression tests (server/app/live.py)."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import live as live_module
from app.database import Base, get_db
from app.main import app
from app.models import Device
from app.security import token_hash

ORIGIN = "http://testserver"


class LiveWebSocketTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

        def database():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = database
        # live.py deliberately bypasses Depends(get_db) (see its module
        # docstring: a long-lived WebSocket connection can't hold a pooled
        # session for its whole lifetime), opening its own short-lived
        # sessions from the module-level SessionLocal instead. That means
        # dependency_overrides above never reaches it, so its SessionLocal
        # reference is redirected here the same way -- straight at this
        # test's isolated in-memory engine.
        self.live_session_patch = patch.object(live_module, "SessionLocal", self.Session)
        self.live_session_patch.start()
        self.env = patch.dict(os.environ, {"ADMIN_TOKEN": "legacy-secret"})
        self.env.start()
        self.client = TestClient(app)
        self.client.headers["X-FleetView-Request"] = "1"
        with self.Session() as db:
            db.add(Device(id="live-new", hostname="fresh", platform="linux", package_manager="apt",
                          agent_version="0.18.0", agent_token_hash=token_hash("live-secret")))
            db.add(Device(id="live-old", hostname="stale", platform="linux", package_manager="apt",
                          agent_version="0.16.0", agent_token_hash=token_hash("old-secret")))
            db.commit()
        setup = self.client.post("/api/v1/auth/setup", json={
            "admin_token": "legacy-secret", "username": "admin", "password": "long-password-for-tests"})
        self.assertEqual(setup.status_code, 201, setup.text)
        self.admin_csrf = setup.json()["csrf_token"]
        self.client.headers["X-CSRF-Token"] = self.admin_csrf
        created = self.client.post("/api/v1/admin/users", json={
            "username": "vwr", "password": "long-password-for-tests", "role": "viewer"})
        self.assertEqual(created.status_code, 201, created.text)
        self.admin_cookies = dict(self.client.cookies)

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.live_session_patch.stop()
        self.env.stop()
        self.engine.dispose()

    def viewer_client(self):
        viewer = TestClient(app)
        viewer.headers["X-FleetView-Request"] = "1"
        login = viewer.post("/api/v1/auth/login", json={"username": "vwr", "password": "long-password-for-tests"})
        self.assertEqual(login.status_code, 200, login.text)
        return viewer

    def test_agent_socket_rejects_bad_credentials(self):
        with self.client.websocket_connect(
            "/api/v1/agent/live", headers={"authorization": "Bearer wrong", "x-device-id": "live-new"}
        ) as ws:
            message = ws.receive_json()
            self.assertEqual(message["type"], "error")
            self.assertEqual(message["code"], 4401)

    def test_browser_socket_requires_cookie_and_trusted_origin(self):
        anonymous = TestClient(app)
        anonymous.headers["X-FleetView-Request"] = "1"
        with anonymous.websocket_connect("/api/v1/admin/live-status", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["code"], 4401)

        untrusted = TestClient(app, cookies=self.admin_cookies)
        with untrusted.websocket_connect(
            "/api/v1/admin/live-status", headers={"origin": "http://evil.example"}
        ) as ws:
            self.assertEqual(ws.receive_json()["code"], 4403)

    def test_must_change_password_blocks_status_and_metrics_sockets(self):
        # "vwr" (from setUp) has never signed in, so it still carries the
        # forced must_change_password flag every freshly-created account
        # gets -- exactly the state a temporary-password account is in
        # before its first login. It must not be able to stream fleet
        # presence or a device's live metrics until that's cleared.
        viewer = self.viewer_client()
        with viewer.websocket_connect("/api/v1/admin/live-status", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["code"], 4403)
        with viewer.websocket_connect(
            "/api/v1/admin/devices/live-new/metrics-live", headers={"origin": ORIGIN}
        ) as ws:
            self.assertEqual(ws.receive_json()["code"], 4403)
        viewer.close()

    def test_metrics_relay_and_live_status_broadcast(self):
        admin = TestClient(app, cookies=self.admin_cookies)
        with admin.websocket_connect("/api/v1/admin/live-status", headers={"origin": ORIGIN}) as status_ws:
            snapshot = status_ws.receive_json()
            self.assertEqual(snapshot, {"type": "snapshot", "live_device_ids": []})

            with self.client.websocket_connect(
                "/api/v1/agent/live", headers={"authorization": "Bearer live-secret", "x-device-id": "live-new"}
            ) as agent_ws:
                self.assertEqual(status_ws.receive_json(), {"type": "status", "device_id": "live-new", "live": True})

                with admin.websocket_connect(
                    "/api/v1/admin/devices/live-new/metrics-live", headers={"origin": ORIGIN}
                ) as metrics_ws:
                    initial = metrics_ws.receive_json()
                    self.assertEqual(initial, {"type": "status", "device_id": "live-new", "live": True})

                    sample = {
                        "type": "metrics", "recorded_at": "2026-01-01T00:00:00Z", "cpu_percent": 42.5,
                        "memory_used_bytes": 1, "memory_total_bytes": 2, "swap_used_bytes": 0, "swap_total_bytes": 0,
                        "disk_used_bytes": 0, "disk_total_bytes": 0, "load_1": 0, "load_5": 0, "load_15": 0,
                        "network_receive_bps": 0, "network_transmit_bps": 0, "network_receive_bytes": 0,
                        "network_transmit_bytes": 0, "process_count": 1, "uptime_seconds": 1,
                        "top_consumers": [
                            {"kind": "process", "pid": 123, "name": "stress", "cpu_percent": 97.5, "memory_bytes": 1048576},
                            {"kind": "container", "name": "fv-stress-test", "cpu_percent": 100.4, "memory_bytes": 1052672},
                        ],
                    }
                    agent_ws.send_json(sample)
                    relayed = metrics_ws.receive_json()
                    self.assertEqual(relayed["type"], "metrics")
                    self.assertEqual(relayed["device_id"], "live-new")
                    self.assertEqual(relayed["cpu_percent"], 42.5)
                    self.assertEqual(relayed["top_consumers"][0]["name"], "stress")
                    self.assertEqual(relayed["top_consumers"][1]["kind"], "container")

            # Agent socket now closed (the `with` block above exited).
            self.assertEqual(status_ws.receive_json(), {"type": "status", "device_id": "live-new", "live": False})

    def test_terminal_requires_admin_and_supported_agent_and_enforces_single_session(self):
        admin = TestClient(app, cookies=self.admin_cookies)
        viewer = self.viewer_client()

        with viewer.websocket_connect("/api/v1/admin/devices/live-new/terminal-live", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["code"], 4403)

        with admin.websocket_connect("/api/v1/admin/devices/live-old/terminal-live", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["code"], 4409)  # agent too old for live terminal

        with admin.websocket_connect("/api/v1/admin/devices/live-new/terminal-live", headers={"origin": ORIGIN}) as ws:
            self.assertEqual(ws.receive_json()["code"], 4410)  # agent not currently connected

        with self.client.websocket_connect(
            "/api/v1/agent/live", headers={"authorization": "Bearer live-secret", "x-device-id": "live-new"}
        ) as agent_ws:
            with admin.websocket_connect("/api/v1/admin/devices/live-new/terminal-live", headers={"origin": ORIGIN}) as term_ws:
                start = agent_ws.receive_json()
                self.assertEqual(start["type"], "terminal_start")
                session_id = start["session"]

                # A second concurrent terminal for the same device is refused.
                with admin.websocket_connect("/api/v1/admin/devices/live-new/terminal-live", headers={"origin": ORIGIN}) as second:
                    self.assertEqual(second.receive_json()["code"], 4429)

                term_ws.send_json({"type": "input", "data": "ZWNobyBoaQ=="})
                relayed_input = agent_ws.receive_json()
                self.assertEqual(relayed_input, {"type": "terminal_input", "session": session_id, "data": "ZWNobyBoaQ=="})

                term_ws.send_json({"type": "resize", "cols": 120, "rows": 40})
                relayed_resize = agent_ws.receive_json()
                self.assertEqual(relayed_resize, {"type": "terminal_resize", "session": session_id, "cols": 120, "rows": 40})

                agent_ws.send_json({"type": "terminal_output", "session": session_id, "data": "aGk="})
                self.assertEqual(term_ws.receive_json(), {"type": "terminal_output", "session": session_id, "data": "aGk="})

            # Browser closed its terminal: the agent is told to stop it.
            stop = agent_ws.receive_json()
            self.assertEqual(stop, {"type": "terminal_stop", "session": session_id})


if __name__ == "__main__":
    unittest.main()
