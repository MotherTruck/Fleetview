"""Regression checks use isolated SQLite storage, never endpoint package managers."""
import os
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1]))
os.environ["DATABASE_URL"] = "sqlite://"
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.database import Base
from app.main import (compliance_history, create_job, queue_scheduled_scan,
                      set_scan_schedule, scan_supported)
from app.models import Device, Job, VulnerabilitySchedule, ComplianceSnapshot, utcnow
from app.schemas import JobCreate, VulnerabilityScheduleUpdate


class FleetFeatures(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.db = Session(self.engine, autoflush=False)
        self.device = Device(id="one", hostname="debian", os_name="Debian GNU/Linux",
                             package_manager="apt", agent_token_hash="test")
        self.db.add(self.device)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_uninstall_requires_confirmation_and_literal_name(self):
        for options in ({"package": "htop"}, {"package": "--help", "confirmed": True},
                        {"package": "foo*", "confirmed": True},
                        {"package": "foo bar", "confirmed": True},
                        {"package": ["foo"], "confirmed": True}):
            with self.assertRaises(HTTPException):
                create_job("one", JobCreate(type="UNINSTALL_PACKAGE", options=options), self.db)
        result = create_job("one", JobCreate(type="UNINSTALL_PACKAGE",
                            options={"package": "htop", "confirmed": True}), self.db)
        self.assertEqual(result["type"], "UNINSTALL_PACKAGE")
        with self.assertRaises(HTTPException) as error:
            create_job("one", JobCreate(type="UNINSTALL_PACKAGE",
                       options={"package": "htop", "confirmed": True}), self.db)
        self.assertEqual(error.exception.status_code, 409)

    def test_docker_actions_require_known_container_and_confirmation(self):
        self.device.agent_version = "0.15.0"
        container_id = "abcdef012345"
        options = {"action": "restart", "container_id": container_id, "confirmed": True}
        with self.assertRaises(HTTPException) as error:
            create_job("one", JobCreate(type="DOCKER_CONTAINER_ACTION", options=options), self.db)
        self.assertEqual(error.exception.status_code, 400)
        self.device.inventory = {"docker_available": True, "docker_containers": [{"id": container_id}]}
        self.db.commit()
        for invalid in ({**options, "confirmed": False}, {**options, "action": "exec"},
                        {**options, "container_id": "different-id"},
                        {**options, "container_id": container_id, "extra": "value"}):
            with self.assertRaises(HTTPException):
                create_job("one", JobCreate(type="DOCKER_CONTAINER_ACTION", options=invalid), self.db)
        job = create_job("one", JobCreate(type="DOCKER_CONTAINER_ACTION", options=options), self.db)
        self.assertEqual(job["options"], options)
        with self.assertRaises(HTTPException) as error:
            create_job("one", JobCreate(type="DOCKER_CONTAINER_ACTION", options=options), self.db)
        self.assertEqual(error.exception.status_code, 409)

    def test_schedule_due_restart_dedup_and_disable(self):
        queue_scheduled_scan(self.db, self.device)
        self.assertEqual(list(self.db.scalars(select(Job))), [])
        set_scan_schedule("one", VulnerabilityScheduleUpdate(interval_hours=24), self.db)
        schedule = self.db.get(VulnerabilitySchedule, "one")
        schedule.next_run_at = utcnow() - timedelta(days=10)
        self.db.commit()
        queue_scheduled_scan(self.db, self.device)
        self.db.commit()
        self.db.expire_all()
        queue_scheduled_scan(self.db, self.device)
        self.assertEqual(len(list(self.db.scalars(select(Job)))), 1)
        schedule.next_run_at = utcnow() - timedelta(hours=1)
        self.db.commit()
        queue_scheduled_scan(self.db, self.device)
        self.db.commit()
        self.assertEqual(len(list(self.db.scalars(select(Job)))), 1)
        set_scan_schedule("one", VulnerabilityScheduleUpdate(interval_hours=0), self.db)
        queue_scheduled_scan(self.db, self.device)
        self.assertEqual(len(list(self.db.scalars(select(Job)))), 1)

    def test_unsupported_scan_platform(self):
        self.device.os_name = "Ubuntu"
        self.assertFalse(scan_supported(self.device))
        with self.assertRaises(HTTPException):
            set_scan_schedule("one", VulnerabilityScheduleUpdate(interval_hours=24), self.db)
        self.device.package_manager = "winget"
        self.assertFalse(scan_supported(self.device))

    def test_report_scope_and_inclusive_dates(self):
        self.db.add(Device(id="two", hostname="other", agent_token_hash="test"))
        for device_id in ("one", "two"):
            for day in ("2026-01-01", "2026-02-01", "2026-03-01"):
                self.db.add(ComplianceSnapshot(device_id=device_id, snapshot_date=day,
                                               update_count=2, vulnerability_count=3))
        self.db.commit()
        rows = compliance_history(30, "one", date(2026, 1, 1), date(2026, 3, 1), self.db)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row["device_count"] == 1 for row in rows))
        self.assertEqual(rows[0]["total_updates_needed"], 2)
        rows = compliance_history(30, None, date(2026, 1, 1), date(2026, 3, 1), self.db)
        self.assertEqual(rows[0]["device_count"], 2)
        for start, end in ((date(2026, 3, 1), date(2026, 1, 1)), (date(2026, 1, 1), None)):
            with self.assertRaises(HTTPException):
                compliance_history(30, None, start, end, self.db)
        self.assertEqual(compliance_history(30, "one", date(2025, 1, 1), date(2025, 2, 1), self.db), [])

    def test_http_auth_validation_and_agent_poll(self):
        from app.main import app
        from app.database import get_db
        from app.security import token_hash
        self.device.agent_token_hash = token_hash("agent-test")
        self.db.commit()
        app.dependency_overrides[get_db] = lambda: self.db
        try:
            with patch.dict(os.environ, {"ADMIN_TOKEN": "admin-test"}), TestClient(app) as client:
                url = "/api/v1/admin/devices/one/vulnerability-schedule"
                headers = {"X-Admin-Token": "admin-test"}
                self.assertEqual(client.get(url).status_code, 401)
                self.assertEqual(client.put(url, headers=headers, json={"interval_hours": -1}).status_code, 422)
                self.assertEqual(client.put(url, headers=headers, json={"interval_hours": 24}).status_code, 200)
                schedule = self.db.get(VulnerabilitySchedule, "one")
                schedule.next_run_at = utcnow() - timedelta(hours=1)
                self.db.commit()
                agent_headers = {"X-Device-Id": "one", "Authorization": "Bearer agent-test"}
                result = client.get("/api/v1/agent/jobs/next", headers=agent_headers)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["type"], "SCAN_VULNERABILITIES")
                self.assertEqual(client.get("/api/v1/agent/jobs/next", headers=agent_headers).status_code, 204)
                self.assertEqual(client.get("/api/v1/admin/reports/history?start=not-a-date&end=2026-01-01",
                                           headers=headers).status_code, 422)
                self.assertEqual(client.get("/api/v1/admin/reports/history?device_id=missing",
                                           headers=headers).status_code, 404)
        finally:
            app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
