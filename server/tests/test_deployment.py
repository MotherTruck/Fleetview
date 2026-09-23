"""Approval/schedule and uploaded-file access regression tests; no packages are executed."""
import hashlib
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
from app.database import Base, get_db
from app.main import app
from app.models import Device, Job, PatchSchedule, User, utcnow
from app.security import token_hash


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        def database():
            with self.Session() as db:
                yield db
        app.dependency_overrides[get_db] = database
        self.env = patch.dict(os.environ, {"ADMIN_TOKEN": "legacy-secret"})
        self.env.start()
        self.client = TestClient(app)
        self.client.headers["X-FleetView-Request"] = "1"
        with self.Session() as db:
            db.add(Device(id="dev", hostname="target", platform="linux", package_manager="apt",
                          agent_version="0.14.0", agent_token_hash=token_hash("agent-secret"),
                          available_updates=[{"package":"curl", "installed_version":"1", "available_version":"2"},
                                             {"package":"vim", "installed_version":"1", "available_version":"3"}]))
            db.add(Device(id="arch", hostname="rolling", platform="linux", package_manager="pacman",
                          agent_version="0.14.0", agent_token_hash=token_hash("arch-secret"),
                          available_updates=[{"package":"curl", "available_version":"2"},
                                             {"package":"vim", "available_version":"3"}]))
            db.commit()
        setup = self.client.post("/api/v1/auth/setup", json={
            "admin_token":"legacy-secret", "username":"admin", "password":"long-password-for-tests"})
        self.assertEqual(setup.status_code, 201, setup.text)
        self.client.headers["X-CSRF-Token"] = setup.json()["csrf_token"]

    def tearDown(self):
        self.client.close()
        app.dependency_overrides.clear()
        self.env.stop()
        self.engine.dispose()

    def approve(self, device, package, version, approved=True):
        return self.client.put(f"/api/v1/admin/devices/{device}/patch-approvals",
            json={"package":package, "available_version":version, "approved":approved})

    def test_selected_approval_exact_version_and_legacy_update_blocked(self):
        base = "/api/v1/admin/devices/dev"
        self.assertEqual(self.client.post(base + "/deploy-approved-patches").status_code, 409)
        self.assertEqual(self.approve("dev", "curl", "9").status_code, 409)
        self.assertEqual(self.approve("dev", "curl", "2").status_code, 200)
        job = self.client.post(base + "/deploy-approved-patches")
        self.assertEqual(job.status_code, 201, job.text)
        self.assertEqual(job.json()["updates"], [{"package":"curl", "version":"2"}])
        self.assertEqual(self.client.post(base + "/jobs", json={"type":"INSTALL_UPDATES", "options":{"confirmed": True}}).status_code, 400)
        self.assertEqual(self.client.post(base + "/deploy-approved-patches").status_code, 409)
        self.assertEqual(self.approve("dev", "curl", "2", approved=False).status_code, 200)
        with self.Session() as db:
            self.assertEqual(db.get(Job, job.json()["id"]).status, "failed")
        with self.Session() as db:
            device = db.get(Device, "dev")
            device.available_updates = [{"package":"curl", "available_version":"4"}]
            db.commit()
        items = self.client.get(base + "/patch-approvals").json()
        self.assertFalse(items[0]["approved"])

    def test_arch_requires_all_approvals_and_schedules_dedupe(self):
        base = "/api/v1/admin/devices/arch"
        self.approve("arch", "curl", "2")
        self.assertEqual(self.client.post(base + "/deploy-approved-patches").status_code, 409)
        self.approve("arch", "vim", "3")
        schedule = self.client.put(base + "/patch-schedule", json={"interval_hours":1})
        self.assertEqual(schedule.status_code, 200, schedule.text)
        with self.Session() as db:
            row = db.get(PatchSchedule, "arch")
            row.next_run_at = utcnow() - timedelta(hours=2)
            db.commit()
        auth = {"Authorization":"Bearer arch-secret", "X-Device-ID":"arch"}
        first = self.client.get("/api/v1/agent/jobs/next", headers=auth)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["type"], "INSTALL_APPROVED_UPDATES")
        with self.Session() as db:
            db.get(PatchSchedule, "arch").next_run_at = utcnow() - timedelta(hours=2)
            db.commit()
        self.assertEqual(self.client.get("/api/v1/agent/jobs/next", headers=auth).status_code, 204)
        with self.Session() as db:
            self.assertEqual(len(db.scalars(select(Job)).all()), 1)

    def test_admin_only_upload_agent_download_and_sha(self):
        upload = self.client.post("/api/v1/admin/custom-packages",
            data={"name":"Local installer", "platform":"linux", "command":"bash ./install.sh"},
            files=[("files", ("install.sh", b"echo ready\n", "application/octet-stream"))])
        self.assertEqual(upload.status_code, 201, upload.text)
        bundle = upload.json()
        self.assertEqual(bundle["files"][0]["sha256"], hashlib.sha256(b"echo ready\n").hexdigest())
        bad_name = self.client.post("/api/v1/admin/custom-packages", data={"name":"Bad", "platform":"linux", "command":"true"},
            files=[("files", ("../install.sh", b"hello", "application/octet-stream"))])
        self.assertEqual(bad_name.status_code, 400)
        path = f"/api/v1/admin/custom-packages/{bundle['id']}/devices/dev/deploy"
        deploy = self.client.post(path)
        self.assertEqual(deploy.status_code, 201, deploy.text)
        job_id = deploy.json()["id"]
        manifest_path = f"/api/v1/agent/jobs/{job_id}/bundle"
        auth = {"Authorization":"Bearer agent-secret", "X-Device-ID":"dev"}
        self.assertEqual(self.client.get(manifest_path, headers=auth).status_code, 404)
        self.assertEqual(self.client.get("/api/v1/agent/jobs/next", headers=auth).status_code, 200)
        self.assertEqual(self.client.get(manifest_path, headers={"X-Device-ID":"dev"}).status_code, 401)
        self.assertEqual(self.client.get(manifest_path, headers=auth).json()["command"], "bash ./install.sh")
        file_path = manifest_path + "/files/" + bundle["files"][0]["id"]
        self.assertEqual(self.client.get(file_path, headers=auth).content, b"echo ready\n")
        self.assertEqual(self.client.get(file_path, headers={"Authorization":"Bearer arch-secret", "X-Device-ID":"arch"}).status_code, 404)
        self.assertEqual(self.client.post(f"/api/v1/agent/jobs/{job_id}/result", headers=auth,
            json={"status":"succeeded", "output":"ok"}).status_code, 204)
        self.assertEqual(self.client.get(file_path, headers=auth).status_code, 404)

    def test_viewer_cannot_approve_schedule_or_upload(self):
        created = self.client.post("/api/v1/admin/users", json={"username":"viewer", "password":"long-password-for-tests", "role":"viewer"})
        self.assertEqual(created.status_code, 201)
        with self.Session() as db:
            db.get(User, created.json()["id"]).must_change_password = False
            db.commit()
        viewer = TestClient(app)
        viewer.headers["X-FleetView-Request"] = "1"
        login = viewer.post("/api/v1/auth/login", json={"username":"viewer", "password":"long-password-for-tests"})
        self.assertEqual(login.status_code, 200, login.text)
        viewer.headers["X-CSRF-Token"] = login.json()["csrf_token"]
        self.assertEqual(viewer.get("/api/v1/admin/devices/dev/patch-approvals").status_code, 200)
        self.assertEqual(viewer.put("/api/v1/admin/devices/dev/patch-approvals", json={"package":"curl", "available_version":"2", "approved":True}).status_code, 403)
        self.assertEqual(viewer.put("/api/v1/admin/devices/dev/patch-schedule", json={"interval_hours":1}).status_code, 403)
        self.assertEqual(viewer.post("/api/v1/admin/custom-packages", data={"name":"Bad", "platform":"linux", "command":"true"},
                        files=[("files", ("install.sh", b"hello", "application/octet-stream"))]).status_code, 403)
        viewer.close()
