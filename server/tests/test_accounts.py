import os
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.database import Base, get_db
from app.models import Device, User, UserSession, utcnow
from app.security import token_hash

PASSWORD = "a-long-test-password-123"
NEW_PASSWORD = "a-new-long-password-456"


class AccountsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        def database():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = database
        self.env = patch.dict(os.environ, {"ADMIN_TOKEN": "existing-owner-token"})
        self.env.start()
        self.client = TestClient(app)
        self.client.headers["X-FleetView-Request"] = "1"
        with self.Session() as db:
            db.add(Device(id="endpoint", hostname="existing", os_name="Debian",
                          package_manager="apt", agent_token_hash=token_hash("endpoint-secret")))
            db.commit()

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.env.stop()
        self.engine.dispose()

    def setup_admin(self):
        result = self.client.post("/api/v1/auth/setup", json={
            "admin_token": "existing-owner-token", "username": "Owner", "password": PASSWORD})
        self.assertEqual(result.status_code, 201, result.text)
        self.client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
        return result

    def make_user(self, role):
        result = self.client.post("/api/v1/admin/users", json={
            "username": role, "password": PASSWORD, "role": role})
        self.assertEqual(result.status_code, 201, result.text)
        return result.json()

    def sign_in(self, name, password=PASSWORD):
        client = TestClient(app)
        client.headers["X-FleetView-Request"] = "1"
        result = client.post("/api/v1/auth/login", json={"username": name, "password": password})
        self.assertEqual(result.status_code, 200, result.text)
        client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
        return client

    def change_temporary(self, client):
        result = client.post("/api/v1/auth/password", json={
            "current_password": PASSWORD, "new_password": NEW_PASSWORD})
        self.assertEqual(result.status_code, 204, result.text)

    def test_bootstrap_and_legacy_token_cutoff(self):
        self.assertTrue(self.client.get("/api/v1/auth/status").json()["setup_required"])
        bad = self.client.post("/api/v1/auth/setup", json={
            "username":"owner", "password":PASSWORD, "admin_token":"wrong"})
        self.assertEqual(bad.status_code, 401)
        result = self.setup_admin()
        self.assertIn("HttpOnly", result.headers["set-cookie"])
        self.assertIn("SameSite=strict", result.headers["set-cookie"])
        self.assertFalse(self.client.get("/api/v1/auth/status").json()["setup_required"])
        self.assertEqual(self.client.get("/api/v1/auth/me").json()["user"]["username"], "owner")
        self.assertEqual(self.client.post("/api/v1/auth/setup", json={
            "username":"other", "password":PASSWORD, "admin_token":"existing-owner-token"}).status_code, 409)
        with TestClient(app) as other:
            self.assertEqual(other.get("/api/v1/admin/devices", headers={
                "X-Admin-Token":"existing-owner-token"}).status_code, 401)
            self.assertEqual(other.post("/api/v1/agent/heartbeat", headers={
                "X-Device-ID":"endpoint", "Authorization":"Bearer endpoint-secret"}).status_code, 204)

    def test_csrf_origin_cookie_and_password_secrecy(self):
        with TestClient(app) as outsider:
            payload = {"username":"owner","password":PASSWORD,"admin_token":"existing-owner-token"}
            self.assertEqual(outsider.post("/api/v1/auth/setup", json=payload).status_code, 403)
            self.assertEqual(outsider.post("/api/v1/auth/setup", json=payload, headers={
                "X-FleetView-Request":"1","Origin":"https://evil.example"}).status_code, 403)
        self.setup_admin()
        self.client.headers.pop("X-CSRF-Token")
        self.assertEqual(self.client.post("/api/v1/admin/users", json={
            "username":"test","password":PASSWORD,"role":"viewer"}).status_code, 403)
        self.assertEqual(self.client.post("/api/v1/auth/logout").status_code, 403)
        response = self.client.post("/api/v1/auth/login", json={"username":"bad space","password":"secret-rejected"})
        self.assertNotIn("secret-rejected", response.text)
        with self.Session() as db:
            user = db.scalar(select(User))
            self.assertNotEqual(user.password_hash, PASSWORD)
            session = db.scalar(select(UserSession))
            self.assertNotEqual(session.token_hash, self.client.cookies.get("fleetview_session"))

    def test_viewer_and_operator_permissions_enforced_on_api(self):
        self.setup_admin()
        for role in ("viewer", "operator"):
            self.make_user(role)
            temporary = self.sign_in(role)
            self.assertEqual(temporary.get("/api/v1/admin/devices").status_code, 403)
            self.change_temporary(temporary)
            self.assertEqual(temporary.get("/api/v1/auth/me").status_code, 401)
            client = self.sign_in(role, NEW_PASSWORD)
            for url in ("/api/v1/admin/devices", "/api/v1/admin/packages",
                        "/api/v1/admin/reports/history", "/api/v1/admin/jobs"):
                self.assertEqual(client.get(url).status_code, 200)
            for url in ("/api/v1/admin/users", "/api/v1/admin/enrollment-tokens",
                        "/api/v1/admin/users/audit/recent"):
                self.assertEqual(client.get(url).status_code, 403)
            self.assertEqual(client.delete("/api/v1/admin/devices/endpoint").status_code, 403)
            self.assertEqual(client.put("/api/v1/admin/settings", json={}).status_code, 403)
            result = client.post("/api/v1/admin/devices/endpoint/jobs", json={"type":"SCAN_DEVICE"})
            self.assertEqual(result.status_code, 201 if role == "operator" else 403)
            client.close(); temporary.close()

    def test_disable_reset_and_last_admin(self):
        owner = self.setup_admin().json()["user"]
        self.assertEqual(self.client.put("/api/v1/admin/users/" + owner["id"],
            json={"role":"viewer","active":True}).status_code, 409)
        self.assertEqual(self.client.put("/api/v1/admin/users/" + owner["id"],
            json={"role":"admin","active":False}).status_code, 409)
        user = self.make_user("viewer")
        other = self.sign_in("viewer")
        result = self.client.put("/api/v1/admin/users/" + user["id"],
                                 json={"role":"operator","active":False})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(other.get("/api/v1/auth/me").status_code, 401)
        self.assertEqual(other.post("/api/v1/auth/login",json={
            "username":"viewer","password":PASSWORD}).status_code, 401)
        self.assertEqual(self.client.put("/api/v1/admin/users/" + user["id"], json={
            "role":"viewer","active":True,"password":NEW_PASSWORD}).status_code, 200)
        reset = self.sign_in("viewer", NEW_PASSWORD)
        self.assertTrue(reset.get("/api/v1/auth/me").json()["user"]["must_change_password"])
        self.assertTrue(self.client.get("/api/v1/admin/users/audit/recent").json())
        other.close(); reset.close()

    def test_expired_session_logout_and_throttle(self):
        self.setup_admin()
        with self.Session() as db:
            session = db.scalar(select(UserSession))
            session.expires_at = utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 401)
        for _ in range(10):
            response = self.client.post("/api/v1/auth/login",json={"username":"missing","password":"bad"})
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.post("/api/v1/auth/login",json={
            "username":"missing","password":"bad"}).status_code, 429)
        client = self.sign_in("owner")
        self.assertEqual(client.post("/api/v1/auth/logout").status_code, 204)
        self.assertEqual(client.get("/api/v1/auth/me").status_code, 401)
        client.close()

    def test_secure_cookie_for_tls(self):
        with patch.dict(os.environ, {"FLEETVIEW_COOKIE_SECURE": "true"}):
            result = self.setup_admin()
            self.assertIn("Secure", result.headers["set-cookie"])

    def test_duplicate_username_and_role_validation(self):
        self.setup_admin()
        self.make_user("viewer")
        self.assertEqual(self.client.post("/api/v1/admin/users",json={
            "username":"VIEWER","password":PASSWORD,"role":"admin"}).status_code, 409)
        self.assertEqual(self.client.post("/api/v1/admin/users",json={
            "username":"someone","password":PASSWORD,"role":"superuser"}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
