from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, JSON, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthControl(Base):
    """Singleton created with the first account; serializes user administration."""
    __tablename__ = "auth_control"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AccountAudit(Base):
    __tablename__ = "account_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    platform: Mapped[str] = mapped_column(String(50), default="linux")
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(50), nullable=True)
    package_manager: Mapped[str | None] = mapped_column(String(50), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    agent_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    installed_packages: Mapped[list] = mapped_column(JSON, default=list)
    available_updates: Mapped[list] = mapped_column(JSON, default=list)
    update_count: Mapped[int] = mapped_column(Integer, default=0)
    security_update_count: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    jobs: Mapped[list["Job"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    device: Mapped[Device] = relationship(back_populates="jobs")


class EnrollmentToken(Base):
    """A one-time, expiring credential that lets exactly one agent enroll.

    Only the SHA-256 digest is stored; the plaintext is shown once when it is created.
    """

    __tablename__ = "enrollment_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_device_id: Mapped[str | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MetricSample(Base):
    __tablename__ = "metric_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0)
    memory_used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    memory_total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    swap_used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    swap_total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    disk_total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    load_1: Mapped[float] = mapped_column(Float, default=0)
    load_5: Mapped[float] = mapped_column(Float, default=0)
    load_15: Mapped[float] = mapped_column(Float, default=0)
    network_receive_bps: Mapped[float] = mapped_column(Float, default=0)
    network_transmit_bps: Mapped[float] = mapped_column(Float, default=0)
    network_receive_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    network_transmit_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    process_count: Mapped[int] = mapped_column(Integer, default=0)
    temperature_celsius: Mapped[float | None] = mapped_column(Float, nullable=True)
    uptime_seconds: Mapped[int] = mapped_column(Integer, default=0)


class Package(Base):
    """A saved, reusable software package definition for the Deploy tab's catalog.

    Per-platform identifiers are optional individually (a package might only
    ever be relevant on one or two platforms) but at least one must be set,
    enforced in the API layer rather than here.
    """

    __tablename__ = "packages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    version: Mapped[str] = mapped_column(String(100), default="")
    category: Mapped[str] = mapped_column(String(100), default="")
    pacman_name: Mapped[str] = mapped_column(String(255), default="")
    apt_name: Mapped[str] = mapped_column(String(255), default="")
    winget_id: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class FleetSettings(Base):
    """A single row (id=1) of fleet-wide admin defaults.

    Only the interval defaults live here for now: they're read as the
    fallback whenever a device has no per-device override, so changing them
    here immediately affects every device that hasn't been customized.
    """

    __tablename__ = "fleet_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    default_metrics_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    default_inventory_interval_seconds: Mapped[int] = mapped_column(Integer, default=900)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class VulnerabilitySchedule(Base):
    __tablename__ = "vulnerability_schedules"

    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    interval_hours: Mapped[int] = mapped_column(Integer, default=0)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PatchApproval(Base):
    __tablename__ = "patch_approvals"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    package_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    available_version: Mapped[str] = mapped_column(String(255), primary_key=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class PatchSchedule(Base):
    __tablename__ = "patch_schedules"
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True)
    interval_hours: Mapped[int] = mapped_column(Integer, default=0)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CustomPackage(Base):
    __tablename__ = "custom_packages"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(20))  # linux or windows
    command: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CustomPackageFile(Base):
    __tablename__ = "custom_package_files"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    package_id: Mapped[str] = mapped_column(ForeignKey("custom_packages.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    content: Mapped[bytes] = mapped_column(LargeBinary)


class Integration(Base):
    """A configured connection to an external home-lab service (Proxmox,
    OPNsense, ...). Credentials live only in `encrypted_credentials`
    (see secrets_crypto.py) -- every other column here is safe to return
    from the API as-is. `cached_data` is the last successful sync's
    result, shown immediately on page load rather than live-querying the
    external API on every request (and so a temporarily-unreachable
    integration doesn't blank the whole panel).
    """

    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    kind: Mapped[str] = mapped_column(String(20))  # "proxmox" | "opnsense"
    name: Mapped[str] = mapped_column(String(255))
    base_url: Mapped[str] = mapped_column(String(500))
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    encrypted_credentials: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cached_data: Mapped[dict] = mapped_column(JSON, default=dict)


class ComplianceSnapshot(Base):
    """One row per device per UTC day, for Reports' historical trend charts.

    Written at most once per device per day (see record_compliance_snapshot
    in main.py), the first time that device reports patch or vulnerability
    data that day, so a day's figures reflect its first scan rather than
    shifting every time the agent reports again.
    """

    __tablename__ = "compliance_snapshots"
    __table_args__ = (UniqueConstraint("device_id", "snapshot_date", name="uq_compliance_snapshot_device_day"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    snapshot_date: Mapped[str] = mapped_column(String(10), index=True)  # UTC "YYYY-MM-DD"
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    update_count: Mapped[int] = mapped_column(Integer, default=0)
    security_update_count: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    high_vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    online: Mapped[bool] = mapped_column(Boolean, default=False)
