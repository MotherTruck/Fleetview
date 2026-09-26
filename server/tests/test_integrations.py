"""Integration-connector regression tests: encrypted-credential handling,
role gating, and the Proxmox/OPNsense connectors against real local fake
servers standing in for the actual external APIs (which aren't reachable
from this environment)."""
import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app import secrets_crypto
from app.connectors import opnsense, proxmox
from app.database import Base, get_db
from app.main import app
from app.models import Integration, User

ORIGIN_HEADERS = {"X-FleetView-Request": "1"}


class FakeProxmoxHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("PVEAPIToken=fleetview@pve!test=correct-secret"):
            self.send_response(401)
            self.end_headers()
            return
        routes = {
            "/api2/json/nodes": {"data": [{"node": "pve1", "status": "online", "maxmem": 1000, "mem": 400}]},
            "/api2/json/nodes/pve1/qemu": {"data": [{"vmid": 100, "name": "web", "status": "running", "maxmem": 512, "mem": 200}]},
            "/api2/json/nodes/pve1/lxc": {"data": [{"vmid": 200, "name": "db", "status": "stopped", "maxmem": 256, "mem": 0}]},
        }
        body = routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class FakeOPNsenseHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        import base64
        expected = "Basic " + base64.b64encode(b"testkey:testsecret").decode()
        if self.headers.get("Authorization") != expected:
            self.send_response(401)
            self.end_headers()
            return
        routes = {
            "/api/core/system/status": {"status": "ok"},
            "/api/dhcpv4/leases/searchLease": {"rows": [
                {"address": "192.168.1.50", "hwaddr": "aa:bb:cc:dd:ee:ff", "hostname": "myhost", "state": "active"},
            ], "rowCount": 1},
        }
        body = routes.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def start_fake_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def stop_fake_server(server):
    server.shutdown()
    server.server_close()


class ProxmoxConnectorTests(unittest.TestCase):
    def setUp(self):
        self.server, self.base_url = start_fake_server(FakeProxmoxHandler)

    def tearDown(self):
        stop_fake_server(self.server)

    def test_fetch_inventory_real_http_roundtrip(self):
        data = proxmox.fetch_inventory(self.base_url, {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"})
        self.assertEqual([node["node"] for node in data["nodes"]], ["pve1"])
        self.assertEqual(data["vms"], [{"vmid": 100, "name": "web", "status": "running", "maxmem": 512, "mem": 200, "node": "pve1"}])
        self.assertEqual(data["containers"][0]["name"], "db")

    def test_bad_token_raises_clear_error(self):
        with self.assertRaises(proxmox.ProxmoxError) as ctx:
            proxmox.fetch_inventory(self.base_url, {"token_id": "fleetview@pve!test", "token_secret": "wrong"})
        self.assertIn("401", str(ctx.exception))

    def test_unreachable_host_raises_clear_error(self):
        with self.assertRaises(proxmox.ProxmoxError):
            proxmox.fetch_inventory("http://127.0.0.1:1", {"token_id": "a", "token_secret": "b"}, timeout=1)


class OPNsenseConnectorTests(unittest.TestCase):
    def setUp(self):
        self.server, self.base_url = start_fake_server(FakeOPNsenseHandler)

    def tearDown(self):
        stop_fake_server(self.server)

    def test_test_connection_succeeds_with_right_credentials(self):
        opnsense.test_connection(self.base_url, {"api_key": "testkey", "api_secret": "testsecret"})

    def test_test_connection_fails_with_wrong_credentials(self):
        with self.assertRaises(opnsense.OPNsenseError):
            opnsense.test_connection(self.base_url, {"api_key": "testkey", "api_secret": "wrong"})

    def test_fetch_dhcp_leases_real_http_roundtrip(self):
        leases = opnsense.fetch_dhcp_leases(self.base_url, {"api_key": "testkey", "api_secret": "testsecret"})
        self.assertEqual(leases, [{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "myhost", "state": "active"}])


class IntegrationsEndpointTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

        def database():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = database
        self.secret_key_patch = patch.dict(os.environ, {
            "ADMIN_TOKEN": "legacy-secret",
            "FLEETVIEW_SECRET_KEY": secrets_crypto.generate_key(),
        })
        self.secret_key_patch.start()
        secrets_crypto._fernet_cache = None
        self.proxmox_server, self.proxmox_url = start_fake_server(FakeProxmoxHandler)
        self.client = TestClient(app)
        self.client.headers.update(ORIGIN_HEADERS)
        setup = self.client.post("/api/v1/auth/setup", json={
            "admin_token": "legacy-secret", "username": "admin", "password": "long-password-for-tests"})
        self.assertEqual(setup.status_code, 201, setup.text)
        self.client.headers["X-CSRF-Token"] = setup.json()["csrf_token"]
        created = self.client.post("/api/v1/admin/users", json={
            "username": "vwr", "password": "long-password-for-tests", "role": "viewer"})
        self.assertEqual(created.status_code, 201, created.text)
        with self.Session() as db:
            db.get(User, created.json()["id"]).must_change_password = False
            db.commit()

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.secret_key_patch.stop()
        secrets_crypto._fernet_cache = None
        stop_fake_server(self.proxmox_server)
        self.engine.dispose()

    def viewer_client(self):
        viewer = TestClient(app)
        viewer.headers.update(ORIGIN_HEADERS)
        login = viewer.post("/api/v1/auth/login", json={"username": "vwr", "password": "long-password-for-tests"})
        self.assertEqual(login.status_code, 200, login.text)
        return viewer

    def test_create_syncs_immediately_and_never_exposes_credentials(self):
        response = self.client.post("/api/v1/admin/integrations", json={
            "kind": "proxmox", "name": "Home Proxmox", "base_url": self.proxmox_url, "verify_tls": False,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        })
        self.assertEqual(response.status_code, 201, response.text)
        body = response.json()
        self.assertNotIn("credentials", body)
        self.assertNotIn("encrypted_credentials", body)
        self.assertNotIn("token_secret", json.dumps(body))
        self.assertIsNone(body["last_sync_error"])
        self.assertIsNotNone(body["last_synced_at"])
        self.assertEqual(body["cached_data"]["vms"][0]["name"], "web")

        # Encrypted at rest: the raw DB row's stored value must not contain the plaintext secret.
        with self.Session() as db:
            row = db.get(Integration, body["id"])
            self.assertNotIn("correct-secret", row.encrypted_credentials)

    def test_wrong_credentials_recorded_as_sync_error_not_a_500(self):
        response = self.client.post("/api/v1/admin/integrations", json={
            "kind": "proxmox", "name": "Home Proxmox", "base_url": self.proxmox_url, "verify_tls": False,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "wrong"},
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertIn("401", response.json()["last_sync_error"])

    def test_missing_secret_key_returns_409_not_a_crash(self):
        with patch.dict(os.environ, {}, clear=False):
            del os.environ["FLEETVIEW_SECRET_KEY"]
            secrets_crypto._fernet_cache = None
            response = self.client.post("/api/v1/admin/integrations", json={
                "kind": "proxmox", "name": "X", "base_url": self.proxmox_url,
                "credentials": {"token_id": "a", "token_secret": "b"},
            })
        self.assertEqual(response.status_code, 409, response.text)
        self.assertIn("FLEETVIEW_SECRET_KEY", response.json()["detail"])

    def test_viewer_can_list_but_not_write(self):
        viewer = self.viewer_client()
        self.assertEqual(viewer.get("/api/v1/admin/integrations").status_code, 200)
        create = viewer.post("/api/v1/admin/integrations", json={
            "kind": "proxmox", "name": "X", "base_url": self.proxmox_url,
            "credentials": {"token_id": "a", "token_secret": "b"},
        })
        self.assertEqual(create.status_code, 403)

    def test_update_without_new_credentials_keeps_existing_ones_working(self):
        create = self.client.post("/api/v1/admin/integrations", json={
            "kind": "proxmox", "name": "Home Proxmox", "base_url": self.proxmox_url, "verify_tls": False,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        })
        integration_id = create.json()["id"]
        update = self.client.put(f"/api/v1/admin/integrations/{integration_id}", json={
            "kind": "proxmox", "name": "Renamed Proxmox", "base_url": self.proxmox_url, "verify_tls": False,
            "credentials": {},
        })
        self.assertEqual(update.status_code, 200, update.text)
        self.assertEqual(update.json()["name"], "Renamed Proxmox")
        self.assertIsNone(update.json()["last_sync_error"])  # still synced fine with the old credentials

    def test_delete_removes_it(self):
        create = self.client.post("/api/v1/admin/integrations", json={
            "kind": "proxmox", "name": "Home Proxmox", "base_url": self.proxmox_url, "verify_tls": False,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        })
        integration_id = create.json()["id"]
        self.assertEqual(self.client.delete(f"/api/v1/admin/integrations/{integration_id}").status_code, 204)
        self.assertEqual(self.client.get("/api/v1/admin/integrations").json(), [])


if __name__ == "__main__":
    unittest.main()
