import asyncio
import contextlib
import os
from datetime import date, datetime, timedelta, timezone
import re
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import authenticate_agent, require_admin, require_operator, require_viewer
from .accounts import router as accounts_router
from .deployment import router as deployment_router, published_agent_manifest, queue_scheduled_patch
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from .database import Base, engine, get_db
from .enrollment import as_utc, token_status
from .integrations import periodic_sync_loop, router as integrations_router
from .live import router as live_router, hub as live_hub
from .models import ComplianceSnapshot, Device, EnrollmentToken, FleetSettings, Job, MetricSample, Package, utcnow
from .schemas import AgentSettingsUpdate, DeviceReport, EnrollmentTokenCreate, EnrollRequest, EnrollResponse, FleetSettingsUpdate, JobCreate, JobResult, MetricsReport, PackageUpsert, UninstallVerifyRequest, VulnerabilityReport
from .security import new_agent_token, new_enrollment_token, password_hash, secure_equal, token_hash, verify_password
from .models import VulnerabilitySchedule
from .schemas import VulnerabilityScheduleUpdate


Base.metadata.create_all(bind=engine)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(periodic_sync_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="FleetView", version="0.22.0", docs_url="/api/docs", redoc_url=None, lifespan=lifespan)
app.include_router(accounts_router)
app.include_router(deployment_router)
app.include_router(integrations_router)
app.include_router(live_router)


@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Never echo rejected password/token inputs back into responses or logs.
    return JSONResponse(status_code=422, content={"detail": [
        {"loc": error["loc"], "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]})


@app.middleware("http")
async def private_responses(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response
STATIC_DIR = Path(__file__).parent / "static"
INSTALL_DIR = Path("/opt/fleetview-install")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _process_match_candidates(process: str) -> set[str]:
    # Unix daemons conventionally add a trailing "d" to the thing they run
    # (sshd for ssh, mysqld for mysql, crond for cron) while the package
    # name usually doesn't, so stripping it catches the single most common
    # package-vs-process naming mismatch without a hardcoded name table.
    candidates = {process}
    if len(process) >= 4 and process.endswith("d"):
        candidates.add(process[:-1])
    return candidates


def annotate_exposure(vulnerabilities: list[dict], listening_ports: list[dict]) -> list[dict]:
    """Tag each finding with whether its package has a process actually
    listening on the network, versus one that's only ever loaded as a
    library dependency -- a materially different risk. This is a name
    heuristic, not a guarantee, so it's shown as a plain "listening" tag
    with the matched ports rather than a fabricated confidence score.
    """
    ports_by_candidate: dict[str, list[dict]] = {}
    for port in listening_ports:
        process = str(port.get("process", "")).strip().lower()
        if not process or process == "unknown":
            continue
        for candidate in _process_match_candidates(process):
            ports_by_candidate.setdefault(candidate, []).append(port)

    annotated = []
    for finding in vulnerabilities:
        package = str(finding.get("package", "")).strip().lower()
        matches: list[dict] = []
        if package:
            for candidate, ports in ports_by_candidate.items():
                if len(candidate) >= 3 and (candidate in package or package in candidate):
                    matches.extend(ports)
        finding = dict(finding)
        if matches:
            finding["exposure"] = "listening"
            finding["exposure_detail"] = sorted({f"{port.get('protocol', 'tcp')}/{port.get('port')}" for port in matches})
        else:
            finding["exposure"] = "unknown"
            finding["exposure_detail"] = []
        annotated.append(finding)
    return annotated


def device_view(device: Device, fleet_settings: FleetSettings, include_packages: bool = True) -> dict:
    online = as_utc(device.last_seen) >= utcnow() - timedelta(minutes=2)
    security = (device.inventory or {}).get("_security", {})
    patching = (device.inventory or {}).get("_patching", {})
    monitoring = (device.inventory or {}).get("_monitoring", {})
    agent_settings = public_agent_settings(device, fleet_settings)
    public_inventory = {
        key: value
        for key, value in (device.inventory or {}).items()
        if not key.startswith("_")
    }
    listening_ports = security.get("listening_ports", []) if isinstance(security, dict) else []
    vulnerabilities = security.get("vulnerabilities", []) if isinstance(security, dict) else []
    vulnerabilities = annotate_exposure(vulnerabilities, listening_ports)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in vulnerabilities:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        severity_counts[severity if severity in severity_counts else "UNKNOWN"] += 1
    exposed_count = sum(1 for finding in vulnerabilities if finding.get("exposure") == "listening")
    result = {
        "id": device.id,
        "hostname": device.hostname,
        "display_name": device.display_name,
        "platform": device.platform,
        "os_name": device.os_name,
        "os_version": device.os_version,
        "architecture": device.architecture,
        "package_manager": device.package_manager,
        "agent_version": device.agent_version,
        "enrolled_at": device.enrolled_at,
        "last_seen": device.last_seen,
        "last_scan_at": device.last_scan_at,
        "online": online,
        "live": live_hub.is_agent_live(device.id),
        "update_count": device.update_count,
        "security_update_count": device.security_update_count,
        "inventory": public_inventory,
        "installed_package_count": len(device.installed_packages or []),
        "vulnerability_count": len(vulnerabilities),
        "vulnerability_severity_counts": severity_counts,
        "vulnerability_exposed_count": exposed_count,
        "last_vulnerability_scan_at": security.get("scanned_at") if isinstance(security, dict) else None,
        "vulnerability_scanner": security.get("scanner") if isinstance(security, dict) else None,
        "vulnerability_scanner_version": security.get("scanner_version") if isinstance(security, dict) else None,
        "last_patched_at": patching.get("last_patched_at") if isinstance(patching, dict) else None,
        "metrics": monitoring.get("current") if isinstance(monitoring, dict) else None,
        "agent_settings": agent_settings,
    }
    if include_packages:
        result["installed_packages"] = device.installed_packages or []
        result["available_updates"] = device.available_updates or []
        result["vulnerabilities"] = vulnerabilities
        result["listening_ports"] = listening_ports
    return result


def public_agent_settings(device: Device, fleet_settings: FleetSettings) -> dict:
    stored = (device.inventory or {}).get("_agent_settings", {})
    if not isinstance(stored, dict):
        stored = {}
    return {
        "metrics_interval_seconds": stored.get("metrics_interval_seconds", fleet_settings.default_metrics_interval_seconds),
        "inventory_interval_seconds": stored.get("inventory_interval_seconds", fleet_settings.default_inventory_interval_seconds),
        "gpu_monitoring_enabled": stored.get("gpu_monitoring_enabled", True),
        "docker_inventory_enabled": stored.get("docker_inventory_enabled", True),
        "uninstall_code_required": bool(stored.get("uninstall_code_hash")),
    }


def get_fleet_settings(db: Session) -> FleetSettings:
    settings = db.get(FleetSettings, 1)
    if settings is not None:
        return settings
    # Concurrent requests can both see no row and both try to create it; the
    # loser's INSERT hits the primary key and must fall back to a plain read
    # instead of erroring, since by then the winner's row already exists.
    settings = FleetSettings(id=1)
    db.add(settings)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        settings = db.get(FleetSettings, 1)
    else:
        db.refresh(settings)
    return settings


def job_view(job: Job) -> dict:
    return {
        "id": job.id,
        "device_id": job.device_id,
        "type": job.type,
        "status": job.status,
        "options": job.options,
        "created_at": job.created_at,
        "claimed_at": job.claimed_at,
        "completed_at": job.completed_at,
        "exit_code": job.exit_code,
        "output": job.output,
        "error": job.error,
    }


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/install/linux.sh", include_in_schema=False)
def linux_installer() -> FileResponse:
    path = INSTALL_DIR / "install-linux.sh"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Linux installer is not available")
    return FileResponse(path, media_type="text/x-shellscript", filename="install-fleetview-agent.sh")


@app.get("/install/agent-source.tar.gz", include_in_schema=False)
def linux_agent_source() -> FileResponse:
    path = INSTALL_DIR / "agent-source.tar.gz"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Agent source bundle is not available")
    return FileResponse(path, media_type="application/gzip", filename="fleetview-agent-source.tar.gz")


@app.get("/install/agent-version", include_in_schema=False)
def agent_version_manifest() -> dict:
    manifest = published_agent_manifest()
    if manifest is None:
        raise HTTPException(status_code=404, detail="Published agent binaries are not available")
    return manifest


@app.get("/install/agent-linux-amd64", include_in_schema=False)
def agent_binary_linux() -> FileResponse:
    path = INSTALL_DIR / "agent-bin" / "linux-amd64" / "fleetview-agent"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Published Linux agent binary is not available")
    return FileResponse(path, media_type="application/octet-stream", filename="fleetview-agent")


@app.get("/install/agent-windows-amd64.exe", include_in_schema=False)
def agent_binary_windows() -> FileResponse:
    path = INSTALL_DIR / "agent-bin" / "windows-amd64" / "fleetview-agent.exe"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Published Windows agent binary is not available")
    return FileResponse(path, media_type="application/octet-stream", filename="fleetview-agent.exe")


@app.post("/api/v1/agent/enroll", response_model=EnrollResponse, status_code=201)
def enroll(payload: EnrollRequest, db: Session = Depends(get_db)) -> EnrollResponse:
    now = utcnow()
    # Per-device tokens are single-use. The claim is one conditional UPDATE, so two agents
    # racing with the same token cannot both succeed: the loser matches zero rows.
    claimed = db.execute(
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == token_hash(payload.enrollment_token),
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.revoked_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(used_at=now)
        .execution_options(synchronize_session=False)
    ).rowcount == 1

    if not claimed:
        # Legacy shared token from .env. Optional; leave ENROLLMENT_TOKEN unset to disable.
        shared = os.environ.get("ENROLLMENT_TOKEN", "")
        if not shared or not secure_equal(payload.enrollment_token, shared):
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or already-used enrollment token",
            )

    token = new_agent_token()
    device = Device(
        hostname=payload.hostname,
        platform=payload.platform,
        agent_version=payload.agent_version,
        agent_token_hash=token_hash(token),
    )
    db.add(device)
    db.flush()  # assigns device.id inside the same transaction as the token claim
    if claimed:
        db.execute(
            update(EnrollmentToken)
            .where(EnrollmentToken.token_hash == token_hash(payload.enrollment_token))
            .values(used_by_device_id=device.id)
            .execution_options(synchronize_session=False)
        )
    db.commit()
    db.refresh(device)
    return EnrollResponse(device_id=device.id, agent_token=token)


def enrollment_token_view(record: EnrollmentToken, now: datetime | None = None) -> dict:
    return {
        "id": record.id,
        "label": record.label,
        "status": token_status(
            used_at=record.used_at,
            revoked_at=record.revoked_at,
            expires_at=record.expires_at,
            now=now or utcnow(),
        ),
        "created_at": record.created_at,
        "expires_at": record.expires_at,
        "used_at": record.used_at,
        "device_id": record.used_by_device_id,
    }


@app.post("/api/v1/admin/enrollment-tokens", dependencies=[Depends(require_admin)], status_code=201)
def create_enrollment_token(payload: EnrollmentTokenCreate, db: Session = Depends(get_db)) -> dict:
    token = new_enrollment_token()
    now = utcnow()
    record = EnrollmentToken(
        token_hash=token_hash(token),
        label=(payload.label or "").strip() or None,
        created_at=now,
        expires_at=now + timedelta(minutes=payload.ttl_minutes),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    # The plaintext is returned exactly once; only its hash is stored.
    return {**enrollment_token_view(record, now), "token": token}


@app.get("/api/v1/admin/enrollment-tokens", dependencies=[Depends(require_admin)])
def list_enrollment_tokens(db: Session = Depends(get_db)) -> list[dict]:
    rows = db.scalars(select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()).limit(50)).all()
    now = utcnow()
    return [enrollment_token_view(row, now) for row in rows]


@app.delete("/api/v1/admin/enrollment-tokens/{token_id}", dependencies=[Depends(require_admin)], status_code=204)
def revoke_enrollment_token(token_id: str, db: Session = Depends(get_db)) -> Response:
    record = db.get(EnrollmentToken, token_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrollment token not found")
    if record.used_at is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Token was already used to enroll a device")
    if record.revoked_at is None:
        record.revoked_at = utcnow()
        db.commit()
    return Response(status_code=204)


def record_compliance_snapshot(db: Session, device: Device) -> None:
    """Insert today's compliance snapshot for this device, if it doesn't exist yet.

    Piggybacks on the patch and vulnerability report endpoints instead of
    running on a schedule, so it costs one extra SELECT (and, once a day per
    device, one INSERT) on requests the agent is already making.
    """
    today = utcnow().strftime("%Y-%m-%d")
    existing = db.execute(
        select(ComplianceSnapshot.id).where(
            ComplianceSnapshot.device_id == device.id,
            ComplianceSnapshot.snapshot_date == today,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return
    security = (device.inventory or {}).get("_security", {})
    vulnerabilities = security.get("vulnerabilities", []) if isinstance(security, dict) else []
    critical = sum(1 for item in vulnerabilities if str(item.get("severity", "")).upper() == "CRITICAL")
    high = sum(1 for item in vulnerabilities if str(item.get("severity", "")).upper() == "HIGH")
    db.add(ComplianceSnapshot(
        device_id=device.id,
        snapshot_date=today,
        update_count=device.update_count,
        security_update_count=device.security_update_count,
        vulnerability_count=len(vulnerabilities),
        critical_vulnerability_count=critical,
        high_vulnerability_count=high,
        online=as_utc(device.last_seen) >= utcnow() - timedelta(minutes=2),
    ))


@app.post("/api/v1/agent/report", status_code=204)
def report(
    payload: DeviceReport,
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Response:
    device = authenticate_agent(db, x_device_id, authorization)
    device.hostname = payload.hostname
    device.platform = payload.platform
    device.os_name = payload.os_name
    device.os_version = payload.os_version
    device.architecture = payload.architecture
    device.package_manager = payload.package_manager
    device.agent_version = payload.agent_version
    preserved_metadata = {
        key: (device.inventory or {}).get(key)
        for key in ("_security", "_patching", "_monitoring", "_agent_settings")
        if (device.inventory or {}).get(key)
    }
    inventory = dict(payload.inventory)
    inventory.update(preserved_metadata)
    device.inventory = inventory
    device.installed_packages = payload.installed_packages
    device.available_updates = payload.available_updates
    device.update_count = len(payload.available_updates)
    device.security_update_count = sum(1 for item in payload.available_updates if item.get("security_update") is True)
    device.last_seen = utcnow()
    device.last_scan_at = payload.scanned_at
    record_compliance_snapshot(db, device)
    db.commit()
    return Response(status_code=204)


@app.post("/api/v1/agent/vulnerabilities", status_code=204)
def report_vulnerabilities(
    payload: VulnerabilityReport,
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Response:
    device = authenticate_agent(db, x_device_id, authorization)
    inventory = dict(device.inventory or {})
    inventory["_security"] = {
        "scanner": payload.scanner,
        "scanner_version": payload.scanner_version,
        "scanned_at": payload.scanned_at.isoformat(),
        "vulnerabilities": [item.model_dump(mode="json") for item in payload.vulnerabilities],
        "listening_ports": [item.model_dump(mode="json") for item in payload.listening_ports],
    }
    device.inventory = inventory
    device.last_seen = utcnow()
    record_compliance_snapshot(db, device)
    db.commit()
    return Response(status_code=204)


@app.post("/api/v1/agent/metrics", status_code=204)
def report_metrics(
    payload: MetricsReport,
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Response:
    device = authenticate_agent(db, x_device_id, authorization)
    values = payload.model_dump(mode="json")
    # MetricSample has no gpus or top_consumers columns (no history table for
    # either; the current values are preserved below via
    # device.inventory["_monitoring"] instead), so passing them through as
    # constructor kwargs raises a TypeError.
    sample = MetricSample(device_id=device.id, **payload.model_dump(exclude={"gpus", "top_consumers"}))
    db.add(sample)

    inventory = dict(device.inventory or {})
    inventory["_monitoring"] = {"current": values}
    device.inventory = inventory
    device.last_seen = utcnow()

    retention_days = max(1, min(int(os.environ.get("METRICS_RETENTION_DAYS", "7")), 90))
    cutoff = utcnow() - timedelta(days=retention_days)
    db.execute(
        delete(MetricSample).where(
            MetricSample.device_id == device.id,
            MetricSample.recorded_at < cutoff,
        )
    )
    db.commit()
    return Response(status_code=204)


@app.post("/api/v1/agent/heartbeat", status_code=204)
def heartbeat(
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Response:
    device = authenticate_agent(db, x_device_id, authorization)
    device.last_seen = utcnow()
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/agent/settings")
def get_agent_settings(
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> dict:
    device = authenticate_agent(db, x_device_id, authorization)
    device.last_seen = utcnow()
    settings = public_agent_settings(device, get_fleet_settings(db))
    db.commit()
    return {
        key: value
        for key, value in settings.items()
        if key != "uninstall_code_required"
    }


@app.post("/api/v1/agent/uninstall/verify")
def verify_agent_uninstall(
    payload: UninstallVerifyRequest,
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> dict:
    device = authenticate_agent(db, x_device_id, authorization)
    stored = (device.inventory or {}).get("_agent_settings", {})
    encoded = stored.get("uninstall_code_hash", "") if isinstance(stored, dict) else ""
    if encoded and not verify_password(payload.code, encoded):
        raise HTTPException(status_code=403, detail="Invalid uninstall code")
    return {"authorized": True}


def scan_supported(device: Device) -> bool:
    return device.package_manager == "pacman" or (
        device.package_manager == "apt" and "debian" in (device.os_name or "").lower()
    )


def queue_scheduled_scan(db: Session, device: Device) -> None:
    if not scan_supported(device):
        return
    now = utcnow()
    # Atomic due-time claim prevents duplicate scheduled jobs across workers.
    schedule = db.get(VulnerabilitySchedule, device.id)
    if not schedule or not schedule.interval_hours or as_utc(schedule.next_run_at) > now:
        return
    claimed = db.execute(update(VulnerabilitySchedule).where(
        VulnerabilitySchedule.device_id == device.id,
        VulnerabilitySchedule.next_run_at == schedule.next_run_at,
        VulnerabilitySchedule.interval_hours == schedule.interval_hours,
    ).values(next_run_at=now + timedelta(hours=schedule.interval_hours)))
    if claimed.rowcount != 1:
        return
    active = db.scalar(select(Job.id).where(
        Job.device_id == device.id, Job.type == "SCAN_VULNERABILITIES",
        Job.status.in_(["pending", "running"]),
    ))
    if active is None:
        db.add(Job(device_id=device.id, type="SCAN_VULNERABILITIES", options={"scheduled": True}))
        db.flush()


@app.get("/api/v1/admin/devices/{device_id}/vulnerability-schedule", dependencies=[Depends(require_viewer)])
def get_scan_schedule(device_id: str, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    schedule = db.get(VulnerabilitySchedule, device_id)
    return {"interval_hours": schedule.interval_hours if schedule else 0,
            "next_run_at": schedule.next_run_at if schedule and schedule.interval_hours else None,
            "supported": scan_supported(device)}


@app.put("/api/v1/admin/devices/{device_id}/vulnerability-schedule", dependencies=[Depends(require_operator)])
def set_scan_schedule(device_id: str, payload: VulnerabilityScheduleUpdate, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device not found")
    if payload.interval_hours and not scan_supported(device):
        raise HTTPException(400, "Automatic vulnerability scans support Arch/CachyOS and Debian only")
    schedule = db.get(VulnerabilitySchedule, device_id)
    if schedule is None:
        schedule = VulnerabilitySchedule(device_id=device_id)
        db.add(schedule)
    schedule.interval_hours = payload.interval_hours
    schedule.next_run_at = utcnow() + timedelta(hours=payload.interval_hours)
    db.commit()
    return get_scan_schedule(device_id, db)


@app.get("/api/v1/agent/jobs/next")
def next_job(
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
):
    device = authenticate_agent(db, x_device_id, authorization)
    db.refresh(device, with_for_update=True)
    device.last_seen = utcnow()
    queue_scheduled_scan(db, device)
    queue_scheduled_patch(db, device)
    job = db.scalar(
        select(Job)
        .where(Job.device_id == device.id, Job.status == "pending")
        .order_by(Job.created_at.asc())
        .with_for_update(skip_locked=True)
    )
    if job is None:
        db.commit()
        return Response(status_code=204)
    job.status = "running"
    job.claimed_at = utcnow()
    db.commit()
    db.refresh(job)
    return job_view(job)


@app.post("/api/v1/agent/jobs/{job_id}/result", status_code=204)
def complete_job(
    job_id: str,
    payload: JobResult,
    x_device_id: str = Header(),
    authorization: str = Header(default=""),
    db: Session = Depends(get_db),
) -> Response:
    device = authenticate_agent(db, x_device_id, authorization)
    job = db.get(Job, job_id)
    if job is None or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.status != "running":
        raise HTTPException(status_code=409, detail="Job is not running")
    job.status = payload.status
    job.exit_code = payload.exit_code
    job.output = payload.output
    job.error = payload.error
    job.completed_at = utcnow()
    if job.type in ("INSTALL_UPDATES", "INSTALL_APPROVED_UPDATES") and payload.status == "succeeded":
        inventory = dict(device.inventory or {})
        patching = dict(inventory.get("_patching", {}))
        patching["last_patched_at"] = job.completed_at.isoformat()
        patching["job_id"] = job.id
        inventory["_patching"] = patching
        device.inventory = inventory
    device.last_seen = utcnow()
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/admin/devices", dependencies=[Depends(require_viewer)])
def list_devices(db: Session = Depends(get_db)) -> list[dict]:
    devices = db.scalars(select(Device).order_by(Device.hostname.asc())).all()
    fleet_settings = get_fleet_settings(db)
    return [device_view(device, fleet_settings, include_packages=False) for device in devices]


@app.get("/api/v1/admin/devices/{device_id}", dependencies=[Depends(require_viewer)])
def get_device(device_id: str, db: Session = Depends(get_db)) -> dict:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device_view(device, get_fleet_settings(db))


@app.delete("/api/v1/admin/devices/{device_id}", dependencies=[Depends(require_admin)], status_code=204)
def delete_device(device_id: str, db: Session = Depends(get_db)) -> Response:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    # Child rows are removed explicitly rather than relying on the models' ON
    # DELETE clauses: Postgres (production) enforces those, but the SQLite
    # dev/test database does not unless foreign keys are turned on per-connection.
    db.execute(delete(Job).where(Job.device_id == device_id))
    db.execute(delete(VulnerabilitySchedule).where(VulnerabilitySchedule.device_id == device_id))
    db.execute(delete(ComplianceSnapshot).where(ComplianceSnapshot.device_id == device_id))
    db.execute(delete(MetricSample).where(MetricSample.device_id == device_id))
    # Enrollment tokens used to enroll this device keep their history; only the
    # now-dangling device reference is cleared.
    db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.used_by_device_id == device_id)
        .values(used_by_device_id=None)
    )
    db.delete(device)
    db.commit()
    return Response(status_code=204)


@app.put("/api/v1/admin/devices/{device_id}/settings", dependencies=[Depends(require_admin)])
def update_device_settings(
    device_id: str,
    payload: AgentSettingsUpdate,
    db: Session = Depends(get_db),
) -> dict:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    inventory = dict(device.inventory or {})
    existing = inventory.get("_agent_settings", {})
    existing_hash = existing.get("uninstall_code_hash", "") if isinstance(existing, dict) else ""
    if payload.uninstall_code_required and not payload.uninstall_code and not existing_hash:
        raise HTTPException(status_code=400, detail="Enter an uninstall code before enabling protection")
    settings = {
        "metrics_interval_seconds": payload.metrics_interval_seconds,
        "inventory_interval_seconds": payload.inventory_interval_seconds,
        "gpu_monitoring_enabled": payload.gpu_monitoring_enabled,
        "docker_inventory_enabled": payload.docker_inventory_enabled,
    }
    if payload.uninstall_code_required:
        settings["uninstall_code_hash"] = password_hash(payload.uninstall_code) if payload.uninstall_code else existing_hash
    inventory["_agent_settings"] = settings
    device.inventory = inventory
    fleet_settings = get_fleet_settings(db)
    db.commit()
    return public_agent_settings(device, fleet_settings)


@app.get("/api/v1/admin/devices/{device_id}/metrics", dependencies=[Depends(require_viewer)])
def get_device_metrics(
    device_id: str,
    hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
) -> list[dict]:
    if db.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    cutoff = utcnow() - timedelta(hours=hours)
    samples = db.scalars(
        select(MetricSample)
        .where(MetricSample.device_id == device_id, MetricSample.recorded_at >= cutoff)
        .order_by(MetricSample.recorded_at.desc())
        .limit(10_080)
    ).all()
    samples.reverse()
    return [
        {
            "recorded_at": item.recorded_at,
            "cpu_percent": item.cpu_percent,
            "memory_used_bytes": item.memory_used_bytes,
            "memory_total_bytes": item.memory_total_bytes,
            "swap_used_bytes": item.swap_used_bytes,
            "swap_total_bytes": item.swap_total_bytes,
            "disk_used_bytes": item.disk_used_bytes,
            "disk_total_bytes": item.disk_total_bytes,
            "load_1": item.load_1,
            "load_5": item.load_5,
            "load_15": item.load_15,
            "network_receive_bps": item.network_receive_bps,
            "network_transmit_bps": item.network_transmit_bps,
            "process_count": item.process_count,
            "temperature_celsius": item.temperature_celsius,
            "uptime_seconds": item.uptime_seconds,
        }
        for item in samples
    ]


def fleet_settings_view(settings: FleetSettings) -> dict:
    return {
        "default_metrics_interval_seconds": settings.default_metrics_interval_seconds,
        "default_inventory_interval_seconds": settings.default_inventory_interval_seconds,
    }


@app.get("/api/v1/admin/settings", dependencies=[Depends(require_viewer)])
def get_fleet_settings_endpoint(db: Session = Depends(get_db)) -> dict:
    return fleet_settings_view(get_fleet_settings(db))


@app.put("/api/v1/admin/settings", dependencies=[Depends(require_admin)])
def update_fleet_settings(payload: FleetSettingsUpdate, db: Session = Depends(get_db)) -> dict:
    settings = get_fleet_settings(db)
    settings.default_metrics_interval_seconds = payload.default_metrics_interval_seconds
    settings.default_inventory_interval_seconds = payload.default_inventory_interval_seconds
    db.commit()
    db.refresh(settings)
    return fleet_settings_view(settings)


@app.get("/api/v1/admin/reports/history", dependencies=[Depends(require_viewer)])
def compliance_history(days: int = Query(default=30, ge=1, le=3660),
                       device_id: str | None = None, start: date | None = None,
                       end: date | None = None, db: Session = Depends(get_db)) -> list[dict]:
    if (start is None) != (end is None):
        raise HTTPException(400, "Provide both start and end dates")
    end_date = end or utcnow().date()
    start_date = start or end_date - timedelta(days=days - 1)
    if start_date > end_date or (end_date - start_date).days >= 3660:
        raise HTTPException(400, "Date range must be ordered and at most 3660 days")
    query = select(ComplianceSnapshot).where(
        ComplianceSnapshot.snapshot_date >= start_date.isoformat(),
        ComplianceSnapshot.snapshot_date <= end_date.isoformat())
    if device_id:
        if db.get(Device, device_id) is None:
            raise HTTPException(404, "Device not found")
        query = query.where(ComplianceSnapshot.device_id == device_id)
    snapshots = db.scalars(query.order_by(ComplianceSnapshot.snapshot_date)).all()
    by_date: dict[str, list[ComplianceSnapshot]] = {}
    for snapshot in snapshots:
        by_date.setdefault(snapshot.snapshot_date, []).append(snapshot)
    history = []
    for date in sorted(by_date):
        day = by_date[date]
        count = len(day)
        history.append({
            "date": date,
            "device_count": count,
            "fully_patched_percent": round(sum(1 for s in day if s.update_count == 0) / count * 100, 1),
            "no_critical_high_percent": round(
                sum(1 for s in day if s.critical_vulnerability_count == 0 and s.high_vulnerability_count == 0) / count * 100, 1
            ),
            "online_percent": round(sum(1 for s in day if s.online) / count * 100, 1),
            "total_updates_needed": sum(s.update_count for s in day),
            "total_vulnerabilities": sum(s.vulnerability_count for s in day),
        })
    return history


@app.get("/api/v1/admin/jobs", dependencies=[Depends(require_viewer)])
def list_jobs(device_id: str | None = None, db: Session = Depends(get_db)) -> list[dict]:
    query = select(Job).order_by(Job.created_at.desc()).limit(100)
    if device_id:
        query = query.where(Job.device_id == device_id)
    return [job_view(job) for job in db.scalars(query).all()]


@app.post("/api/v1/admin/devices/{device_id}/jobs", dependencies=[Depends(require_operator)], status_code=201)
def create_job(device_id: str, payload: JobCreate, db: Session = Depends(get_db)) -> dict:
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    if payload.type == "INSTALL_UPDATES" and payload.options.get("confirmed") is not True:
        raise HTTPException(status_code=400, detail="INSTALL_UPDATES requires options.confirmed=true")
    if payload.type == "INSTALL_UPDATES":
        raise HTTPException(400, "Use approved patch deployment after reviewing each pending patch")
    if payload.type in ("INSTALL_PACKAGE", "UNINSTALL_PACKAGE"):
        name = payload.options.get("package")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,254}", name):
            raise HTTPException(400, "A single literal package name or ID is required")
    if payload.type == "UNINSTALL_PACKAGE" and payload.options.get("confirmed") is not True:
        raise HTTPException(400, "UNINSTALL_PACKAGE requires options.confirmed=true")
    if payload.type == "DOCKER_CONTAINER_ACTION":
        try:
            agent_version = tuple(int(part) for part in (device.agent_version or "").split(".")[:2])
        except ValueError:
            agent_version = ()
        if agent_version < (0, 15):
            raise HTTPException(400, "Upgrade this device's native agent to 0.15.0 before managing Docker")
        action = payload.options.get("action")
        container_id = payload.options.get("container_id")
        inventory = device.inventory or {}
        known = inventory.get("docker_containers")
        if (payload.options.get("confirmed") is not True
                or action not in ("start", "stop", "restart")
                or not isinstance(container_id, str)
                or not re.fullmatch(r"[a-fA-F0-9]{12,64}", container_id)
                or len(payload.options) != 3):
            raise HTTPException(400, "A confirmed Docker action and container ID are required")
        if inventory.get("docker_available") is not True or not isinstance(known, list) or not any(
            isinstance(item, dict) and item.get("id") == container_id for item in known
        ):
            raise HTTPException(400, "Container is not in this device's latest Docker inventory")
    existing = db.scalar(
        select(Job).where(
            Job.device_id == device_id,
            Job.type == payload.type,
            Job.status.in_(["pending", "running"]),
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="An equivalent job is already pending or running")
    job = Job(device_id=device_id, type=payload.type, options=payload.options)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job_view(job)


def package_view(package: Package) -> dict:
    return {
        "id": package.id,
        "name": package.name,
        "description": package.description,
        "version": package.version,
        "category": package.category,
        "pacman_name": package.pacman_name,
        "apt_name": package.apt_name,
        "winget_id": package.winget_id,
        "created_at": package.created_at,
        "updated_at": package.updated_at,
    }


def require_at_least_one_platform(payload: PackageUpsert) -> None:
    if not (payload.pacman_name.strip() or payload.apt_name.strip() or payload.winget_id.strip()):
        raise HTTPException(status_code=400, detail="Set at least one platform's package name or ID")


@app.get("/api/v1/admin/packages", dependencies=[Depends(require_viewer)])
def list_packages(db: Session = Depends(get_db)) -> list[dict]:
    packages = db.scalars(select(Package).order_by(Package.name.asc())).all()
    return [package_view(package) for package in packages]


@app.post("/api/v1/admin/packages", dependencies=[Depends(require_operator)], status_code=201)
def create_package(payload: PackageUpsert, db: Session = Depends(get_db)) -> dict:
    require_at_least_one_platform(payload)
    package = Package(**payload.model_dump())
    db.add(package)
    db.commit()
    db.refresh(package)
    return package_view(package)


@app.put("/api/v1/admin/packages/{package_id}", dependencies=[Depends(require_operator)])
def update_package(package_id: str, payload: PackageUpsert, db: Session = Depends(get_db)) -> dict:
    package = db.get(Package, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    require_at_least_one_platform(payload)
    for key, value in payload.model_dump().items():
        setattr(package, key, value)
    db.commit()
    db.refresh(package)
    return package_view(package)


@app.delete("/api/v1/admin/packages/{package_id}", dependencies=[Depends(require_operator)], status_code=204)
def delete_package(package_id: str, db: Session = Depends(get_db)) -> Response:
    package = db.get(Package, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    db.delete(package)
    db.commit()
    return Response(status_code=204)
