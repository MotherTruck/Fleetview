import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.enrollment import as_utc, token_status
from app.security import new_enrollment_token, token_hash

try:  # The flow tests need the server dependencies (present in the Docker image).
    import fastapi  # noqa: F401
    import sqlalchemy  # noqa: F401

    HAVE_SERVER_DEPS = True
except ImportError:
    HAVE_SERVER_DEPS = False


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class TokenStatusTests(unittest.TestCase):
    def status(self, **overrides):
        values = {"used_at": None, "revoked_at": None, "expires_at": NOW + timedelta(hours=1), "now": NOW}
        values.update(overrides)
        return token_status(**values)

    def test_active(self):
        self.assertEqual(self.status(), "active")

    def test_expired_at_and_after_the_deadline(self):
        self.assertEqual(self.status(expires_at=NOW), "expired")
        self.assertEqual(self.status(expires_at=NOW - timedelta(seconds=1)), "expired")

    def test_revoked(self):
        self.assertEqual(self.status(revoked_at=NOW), "revoked")

    def test_used_wins_over_everything(self):
        self.assertEqual(self.status(used_at=NOW, revoked_at=NOW, expires_at=NOW - timedelta(days=1)), "used")

    def test_revoked_wins_over_expired(self):
        self.assertEqual(self.status(revoked_at=NOW, expires_at=NOW - timedelta(days=1)), "revoked")

    def test_naive_datetimes_are_treated_as_utc(self):
        naive_future = (NOW + timedelta(hours=1)).replace(tzinfo=None)
        naive_past = (NOW - timedelta(hours=1)).replace(tzinfo=None)
        self.assertEqual(self.status(expires_at=naive_future), "active")
        self.assertEqual(self.status(expires_at=naive_past), "expired")
        self.assertEqual(as_utc(NOW.replace(tzinfo=None)), NOW)


class TokenGenerationTests(unittest.TestCase):
    def test_format_and_uniqueness(self):
        tokens = {new_enrollment_token() for _ in range(200)}
        self.assertEqual(len(tokens), 200)
        for token in tokens:
            self.assertTrue(token.startswith("fv_"))
            self.assertGreaterEqual(len(token), 40)  # well above the 16-char API minimum
            self.assertFalse(token.startswith("-"))
            self.assertRegex(token, r"^[A-Za-z0-9_-]+$")  # shell-safe, URL-safe

    def test_hash_is_sha256_hex_and_not_the_token(self):
        token = new_enrollment_token()
        self.assertEqual(len(token_hash(token)), 64)
        self.assertNotIn(token, token_hash(token))


@unittest.skipUnless(HAVE_SERVER_DEPS, "server dependencies (fastapi, sqlalchemy) are not installed")
class EnrollmentFlowTests(unittest.TestCase):
    """Calls the endpoint functions directly against a throwaway SQLite database."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        # Point at a scratch database *before* importing the app so a real DATABASE_URL
        # (for example the one Docker Compose injects) is never touched by the tests.
        os.environ["DATABASE_URL"] = f"sqlite:///{cls._tmp.name}/enrollment-test.db"
        os.environ["ADMIN_TOKEN"] = "test-admin-token-not-used-directly"
        os.environ.pop("ENROLLMENT_TOKEN", None)

        from fastapi import HTTPException

        from app import main
        from app.database import SessionLocal
        from app.models import ComplianceSnapshot, Device, EnrollmentToken, FleetSettings, Job, MetricSample, Package, utcnow
        from app.schemas import AgentSettingsUpdate, DeviceReport, EnrollmentTokenCreate, EnrollRequest, FleetSettingsUpdate, MetricsReport, PackageUpsert, VulnerabilityReport

        cls.HTTPException = HTTPException
        cls.main = main
        cls.SessionLocal = SessionLocal
        cls.Device = Device
        cls.EnrollmentToken = EnrollmentToken
        cls.Job = Job
        cls.MetricSample = MetricSample
        cls.ComplianceSnapshot = ComplianceSnapshot
        cls.FleetSettings = FleetSettings
        cls.Package = Package
        cls.PackageUpsert = PackageUpsert
        cls.utcnow = staticmethod(utcnow)
        cls.Create = EnrollmentTokenCreate
        cls.Enroll = EnrollRequest
        cls.MetricsReport = MetricsReport
        cls.DeviceReport = DeviceReport
        cls.VulnerabilityReport = VulnerabilityReport
        cls.FleetSettingsUpdate = FleetSettingsUpdate
        cls.AgentSettingsUpdate = AgentSettingsUpdate

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def create_token(self, **kwargs):
        with self.SessionLocal() as db:
            return self.main.create_enrollment_token(self.Create(**kwargs), db)

    def enroll(self, token, hostname="host-a"):
        with self.SessionLocal() as db:
            return self.main.enroll(self.Enroll(enrollment_token=token, hostname=hostname, agent_version="0.5.0"), db)

    def list_tokens(self):
        with self.SessionLocal() as db:
            return {item["id"]: item for item in self.main.list_enrollment_tokens(db)}

    def assert_rejected(self, token, status_code=401):
        with self.assertRaises(self.HTTPException) as caught:
            self.enroll(token, hostname="intruder")
        self.assertEqual(caught.exception.status_code, status_code)

    def test_token_enrolls_exactly_one_device(self):
        created = self.create_token(label="one-shot")
        first = self.enroll(created["token"], hostname="one-shot-host")
        self.assertTrue(first.device_id)
        self.assertTrue(first.agent_token)
        self.assert_rejected(created["token"])  # replay is refused

        with self.SessionLocal() as db:
            hostnames = [d.hostname for d in db.query(self.Device).filter_by(hostname="intruder")]
        self.assertEqual(hostnames, [], "a rejected replay must not create a device")

    def test_used_token_records_which_device_enrolled(self):
        created = self.create_token(label="tracked")
        result = self.enroll(created["token"], hostname="tracked-host")
        record = self.list_tokens()[created["id"]]
        self.assertEqual(record["status"], "used")
        self.assertEqual(record["device_id"], result.device_id)

    def test_unknown_token_is_rejected(self):
        self.assert_rejected("fv_" + "x" * 43)

    def test_expired_token_is_rejected(self):
        created = self.create_token(ttl_minutes=1)
        with self.SessionLocal() as db:
            record = db.get(self.EnrollmentToken, created["id"])
            record.expires_at = self.utcnow() - timedelta(minutes=1)
            db.commit()
        self.assert_rejected(created["token"])
        self.assertEqual(self.list_tokens()[created["id"]]["status"], "expired")

    def test_revoked_token_is_rejected(self):
        created = self.create_token()
        with self.SessionLocal() as db:
            self.assertEqual(self.main.revoke_enrollment_token(created["id"], db).status_code, 204)
        self.assert_rejected(created["token"])
        self.assertEqual(self.list_tokens()[created["id"]]["status"], "revoked")

    def test_cannot_revoke_a_used_token_or_a_missing_one(self):
        created = self.create_token()
        self.enroll(created["token"], hostname="used-then-revoke")
        with self.SessionLocal() as db:
            with self.assertRaises(self.HTTPException) as used:
                self.main.revoke_enrollment_token(created["id"], db)
            with self.assertRaises(self.HTTPException) as missing:
                self.main.revoke_enrollment_token("does-not-exist", db)
        self.assertEqual(used.exception.status_code, 409)
        self.assertEqual(missing.exception.status_code, 404)

    def test_plaintext_is_returned_once_and_never_stored_or_listed(self):
        created = self.create_token(label="secret-check")
        self.assertIn("token", created)
        self.assertTrue(created["token"].startswith("fv_"))
        self.assertNotIn("token", self.list_tokens()[created["id"]])
        with self.SessionLocal() as db:
            record = db.get(self.EnrollmentToken, created["id"])
            self.assertEqual(record.token_hash, token_hash(created["token"]))
            stored = [str(getattr(record, column.name)) for column in record.__table__.columns]
        self.assertFalse(any(created["token"] in value for value in stored))

    def test_tokens_are_independent_of_each_other(self):
        first, second = self.create_token(), self.create_token()
        self.enroll(first["token"], hostname="independent-1")
        self.assertEqual(self.list_tokens()[second["id"]]["status"], "active")
        self.enroll(second["token"], hostname="independent-2")

    def test_blank_label_is_stored_as_none(self):
        self.assertIsNone(self.create_token(label="   ")["label"])

    def test_legacy_shared_token_still_works_only_when_configured(self):
        shared = "legacy-shared-token-0123456789"
        self.assert_rejected(shared)  # not configured -> refused
        with mock.patch.dict(os.environ, {"ENROLLMENT_TOKEN": shared}):
            self.assertTrue(self.enroll(shared, hostname="legacy-1").device_id)
            self.assertTrue(self.enroll(shared, hostname="legacy-2").device_id)  # reusable, as before
        self.assert_rejected(shared)  # removing it from the environment disables it again

    def test_delete_device_removes_its_jobs_and_metrics_and_unlinks_its_token(self):
        created = self.create_token(label="tracked-for-deletion")
        device_id = self.enroll(created["token"], hostname="device-to-delete").device_id
        with self.SessionLocal() as db:
            db.add(self.Job(device_id=device_id, type="SCAN_DEVICE"))
            db.add(self.MetricSample(device_id=device_id))
            db.commit()

        with self.SessionLocal() as db:
            response = self.main.delete_device(device_id, db)
        self.assertEqual(response.status_code, 204)

        with self.SessionLocal() as db:
            with self.assertRaises(self.HTTPException) as caught:
                self.main.get_device(device_id, db)
            self.assertEqual(caught.exception.status_code, 404)
            self.assertEqual(db.query(self.Job).filter_by(device_id=device_id).count(), 0)
            self.assertEqual(db.query(self.MetricSample).filter_by(device_id=device_id).count(), 0)
            token = db.get(self.EnrollmentToken, created["id"])
        self.assertIsNotNone(token, "the enrollment token record itself must survive device deletion")
        self.assertIsNone(token.used_by_device_id)

    def test_delete_missing_device_is_404(self):
        with self.SessionLocal() as db:
            with self.assertRaises(self.HTTPException) as caught:
                self.main.delete_device("does-not-exist", db)
        self.assertEqual(caught.exception.status_code, 404)

    def test_report_metrics_with_gpus_does_not_500(self):
        # Regression test: MetricSample has no gpus column (GPU history isn't
        # implemented; only current GPU state is kept, in device.inventory),
        # so constructing it with **payload.model_dump() unfiltered raised
        # TypeError: 'gpus' is an invalid keyword argument for MetricSample.
        created = self.create_token(label="metrics-device")
        enrolled = self.enroll(created["token"], hostname="metrics-host")
        payload = self.MetricsReport(
            recorded_at=self.utcnow(),
            cpu_percent=12.5,
            memory_used_bytes=1000,
            memory_total_bytes=2000,
            swap_used_bytes=0,
            swap_total_bytes=0,
            disk_used_bytes=1000,
            disk_total_bytes=2000,
            load_1=0.1,
            load_5=0.2,
            load_15=0.3,
            network_receive_bps=0,
            network_transmit_bps=0,
            network_receive_bytes=0,
            network_transmit_bytes=0,
            process_count=42,
            uptime_seconds=3600,
            gpus=[{"index": "0", "name": "Test GPU", "vendor": "NVIDIA"}],
        )
        with self.SessionLocal() as db:
            response = self.main.report_metrics(
                payload,
                x_device_id=enrolled.device_id,
                authorization=f"Bearer {enrolled.agent_token}",
                db=db,
            )
        self.assertEqual(response.status_code, 204)

        with self.SessionLocal() as db:
            samples = db.query(self.MetricSample).filter_by(device_id=enrolled.device_id).all()
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].cpu_percent, 12.5)
        self.assertEqual(samples[0].process_count, 42)

    def test_list_and_get_device_do_not_500_on_sqlite(self):
        # Regression test: device_view() compared device.last_seen (naive,
        # as SQLite returns it) directly against utcnow() (aware), raising
        # TypeError: can't compare offset-naive and offset-aware datetimes.
        # Postgres (production) returns aware datetimes, which is why this
        # only ever showed up against the SQLite dev/test database.
        created = self.create_token(label="online-check-device")
        enrolled = self.enroll(created["token"], hostname="online-check-host")

        with self.SessionLocal() as db:
            devices = self.main.list_devices(db)
        match = next(item for item in devices if item["id"] == enrolled.device_id)
        self.assertIs(match["online"], True)

        with self.SessionLocal() as db:
            detail = self.main.get_device(enrolled.device_id, db)
        self.assertIs(detail["online"], True)

    def report(self, enrolled, update_count=0, security_update_count=0):
        payload = self.DeviceReport(
            hostname="snapshot-host",
            agent_version="0.8.0",
            scanned_at=self.utcnow(),
            available_updates=[
                {"name": f"pkg{i}", "security_update": i < security_update_count}
                for i in range(update_count)
            ],
        )
        with self.SessionLocal() as db:
            return self.main.report(
                payload, x_device_id=enrolled.device_id, authorization=f"Bearer {enrolled.agent_token}", db=db
            )

    def report_vulnerabilities(self, enrolled, findings, listening_ports=None):
        payload = self.VulnerabilityReport(
            scanned_at=self.utcnow(), vulnerabilities=findings, listening_ports=listening_ports or []
        )
        with self.SessionLocal() as db:
            return self.main.report_vulnerabilities(
                payload, x_device_id=enrolled.device_id, authorization=f"Bearer {enrolled.agent_token}", db=db
            )

    def test_report_records_one_compliance_snapshot_per_device_per_day(self):
        created = self.create_token(label="snapshot-device")
        enrolled = self.enroll(created["token"], hostname="snapshot-host")

        self.report(enrolled, update_count=5)
        self.report(enrolled, update_count=1)  # same UTC day: must not add a second row or overwrite the first

        with self.SessionLocal() as db:
            snapshots = db.query(self.ComplianceSnapshot).filter_by(device_id=enrolled.device_id).all()
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].update_count, 5, "the first report of the day sets the snapshot, later ones must not overwrite it")

    def test_vulnerability_report_records_snapshot_and_history_aggregates_it(self):
        created = self.create_token(label="vuln-snapshot-device")
        enrolled = self.enroll(created["token"], hostname="vuln-snapshot-host")

        # A freshly enrolled device already has update_count == 0, so this
        # alone is enough to write the day's snapshot (patch and vulnerability
        # reports both feed the same snapshot, whichever arrives first).
        self.report_vulnerabilities(enrolled, [
            {"vulnerability_id": "CVE-1", "package": "openssl", "severity": "CRITICAL"},
            {"vulnerability_id": "CVE-2", "package": "curl", "severity": "LOW"},
        ])

        with self.SessionLocal() as db:
            snapshot = db.query(self.ComplianceSnapshot).filter_by(device_id=enrolled.device_id).one()
        self.assertEqual(snapshot.vulnerability_count, 2)
        self.assertEqual(snapshot.critical_vulnerability_count, 1)
        self.assertEqual(snapshot.high_vulnerability_count, 0)
        self.assertEqual(snapshot.update_count, 0)

        # The suite's other tests share this same database and may have
        # written snapshots for other devices on the same UTC day, so verify
        # the aggregation math against the actual rows rather than assuming
        # this device is the only one.
        today = self.utcnow().strftime("%Y-%m-%d")
        with self.SessionLocal() as db:
            todays_snapshots = db.query(self.ComplianceSnapshot).filter_by(snapshot_date=today).all()
            history = self.main.compliance_history(days=30, db=db)
        entry = next(item for item in history if item["date"] == today)
        self.assertEqual(entry["device_count"], len(todays_snapshots))
        self.assertEqual(entry["total_vulnerabilities"], sum(s.vulnerability_count for s in todays_snapshots))
        no_crit_high = sum(1 for s in todays_snapshots if s.critical_vulnerability_count == 0 and s.high_vulnerability_count == 0)
        self.assertEqual(entry["no_critical_high_percent"], round(no_crit_high / len(todays_snapshots) * 100, 1))
        self.assertLess(entry["no_critical_high_percent"], 100.0, "this device's CRITICAL finding must lower the fleet-wide figure")

    def test_vulnerability_exposure_flags_packages_with_a_listening_process(self):
        created = self.create_token(label="exposure-device")
        enrolled = self.enroll(created["token"], hostname="exposure-host")

        self.report_vulnerabilities(
            enrolled,
            [
                {"vulnerability_id": "CVE-100", "package": "openssh-server", "severity": "HIGH"},
                {"vulnerability_id": "CVE-200", "package": "some-library", "severity": "LOW"},
            ],
            listening_ports=[
                {"port": 22, "protocol": "tcp", "process": "sshd"},
                {"port": 68, "protocol": "udp", "process": "dhclient"},
            ],
        )

        with self.SessionLocal() as db:
            device = self.main.get_device(enrolled.device_id, db)

        findings = {item["package"]: item for item in device["vulnerabilities"]}
        self.assertEqual(findings["openssh-server"]["exposure"], "listening")
        self.assertEqual(findings["openssh-server"]["exposure_detail"], ["tcp/22"])
        self.assertEqual(findings["some-library"]["exposure"], "unknown")
        self.assertEqual(findings["some-library"]["exposure_detail"], [])
        self.assertEqual(device["vulnerability_exposed_count"], 1)
        self.assertEqual(len(device["listening_ports"]), 2)

        with self.SessionLocal() as db:
            summary = next(item for item in self.main.list_devices(db) if item["id"] == enrolled.device_id)
        self.assertEqual(summary["vulnerability_exposed_count"], 1)
        self.assertNotIn("vulnerabilities", summary, "list view must stay lightweight and not include full findings")
        self.assertNotIn("listening_ports", summary)

    def test_vulnerability_exposure_defaults_to_unknown_with_no_listening_ports(self):
        created = self.create_token(label="no-ports-device")
        enrolled = self.enroll(created["token"], hostname="no-ports-host")

        self.report_vulnerabilities(enrolled, [{"vulnerability_id": "CVE-300", "package": "curl", "severity": "LOW"}])

        with self.SessionLocal() as db:
            device = self.main.get_device(enrolled.device_id, db)
        self.assertEqual(device["vulnerabilities"][0]["exposure"], "unknown")
        self.assertEqual(device["vulnerability_exposed_count"], 0)
        self.assertEqual(device["listening_ports"], [])

    def test_new_device_uses_fleet_default_intervals_until_overridden(self):
        created = self.create_token(label="fleet-defaults-device")
        enrolled = self.enroll(created["token"], hostname="fleet-defaults-host")

        with self.SessionLocal() as db:
            self.main.update_fleet_settings(
                self.FleetSettingsUpdate(default_metrics_interval_seconds=45, default_inventory_interval_seconds=1800), db
            )

        with self.SessionLocal() as db:
            detail = self.main.get_device(enrolled.device_id, db)
        self.assertEqual(detail["agent_settings"]["metrics_interval_seconds"], 45)
        self.assertEqual(detail["agent_settings"]["inventory_interval_seconds"], 1800)

        # An explicit per-device override still wins over the fleet default.
        with self.SessionLocal() as db:
            self.main.update_device_settings(
                enrolled.device_id,
                self.AgentSettingsUpdate(metrics_interval_seconds=120, inventory_interval_seconds=1800),
                db,
            )
        with self.SessionLocal() as db:
            detail = self.main.get_device(enrolled.device_id, db)
        self.assertEqual(detail["agent_settings"]["metrics_interval_seconds"], 120)

    def test_get_fleet_settings_handles_concurrent_first_call(self):
        # Regression test: two requests racing to create the singleton row
        # (e.g. the dashboard's refresh() firing several admin GETs at once
        # on a fresh database) both see no row and both try to INSERT id=1;
        # the loser used to raise an unhandled IntegrityError instead of
        # falling back to reading the winner's row.
        with self.SessionLocal() as cleanup:
            cleanup.query(self.FleetSettings).delete()
            cleanup.commit()
        with self.SessionLocal() as db1, self.SessionLocal() as db2:
            self.assertIsNone(db1.get(self.FleetSettings, 1))
            self.assertIsNone(db2.get(self.FleetSettings, 1))
            first = self.main.get_fleet_settings(db1)
            second = self.main.get_fleet_settings(db2)
        self.assertEqual(first.id, 1)
        self.assertEqual(second.id, 1)

    def test_fleet_settings_endpoint_round_trips(self):
        # The fleet_settings row is a shared singleton other tests in this
        # class also touch, so this only checks round-tripping a write --
        # not an assumed pristine starting value.
        with self.SessionLocal() as db:
            updated = self.main.update_fleet_settings(
                self.FleetSettingsUpdate(default_metrics_interval_seconds=30, default_inventory_interval_seconds=600), db
            )
        self.assertEqual(updated, {"default_metrics_interval_seconds": 30, "default_inventory_interval_seconds": 600})

        with self.SessionLocal() as db:
            fetched = self.main.get_fleet_settings_endpoint(db)
        self.assertEqual(fetched, updated)

    def test_package_requires_at_least_one_platform_identifier(self):
        with self.SessionLocal() as db:
            with self.assertRaises(self.HTTPException) as caught:
                self.main.create_package(self.PackageUpsert(name="Nothing configured"), db)
        self.assertEqual(caught.exception.status_code, 400)

    def test_package_crud_round_trips(self):
        with self.SessionLocal() as db:
            created = self.main.create_package(
                self.PackageUpsert(
                    name="Firefox", version="1.0", category="Browsers",
                    pacman_name="firefox", apt_name="firefox-esr", winget_id="Mozilla.Firefox",
                ),
                db,
            )
        self.assertEqual(created["name"], "Firefox")
        self.assertEqual(created["winget_id"], "Mozilla.Firefox")

        with self.SessionLocal() as db:
            listed = self.main.list_packages(db)
        self.assertIn(created["id"], [item["id"] for item in listed])

        with self.SessionLocal() as db:
            updated = self.main.update_package(
                created["id"],
                self.PackageUpsert(name="Firefox", version="2.0", pacman_name="firefox"),
                db,
            )
        self.assertEqual(updated["version"], "2.0")
        self.assertEqual(updated["apt_name"], "", "fields left out of the update payload must be cleared, not merged")

        with self.SessionLocal() as db:
            with self.assertRaises(self.HTTPException) as missing:
                self.main.update_package("does-not-exist", self.PackageUpsert(name="X", pacman_name="x"), db)
        self.assertEqual(missing.exception.status_code, 404)

        with self.SessionLocal() as db:
            response = self.main.delete_package(created["id"], db)
        self.assertEqual(response.status_code, 204)
        with self.SessionLocal() as db:
            self.assertIsNone(db.get(self.Package, created["id"]))
            with self.assertRaises(self.HTTPException) as missing_delete:
                self.main.delete_package(created["id"], db)
        self.assertEqual(missing_delete.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
