"""Approval-gated patch jobs and immutable uploaded installer bundles."""
import hashlib
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session, load_only

from .auth import authenticate_agent, require_admin, require_operator, require_viewer
from .database import get_db
from .enrollment import as_utc
from .models import (AccountAudit, CustomPackage, CustomPackageFile, Device, Job,
                     PatchApproval, PatchSchedule, utcnow)

router = APIRouter()
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
SAFE_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ -]{0,199}")
SAFE_PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,254}")


def patch_key(item):
    name = item.get("identifier") or item.get("package")
    version = item.get("available_version")
    if not isinstance(name, str) or not SAFE_PACKAGE.fullmatch(name) or not isinstance(version, str) or not version or len(version) > 255:
        return None
    return name, version


def supports_deployment(device):
    try:
        return tuple(int(part) for part in (device.agent_version or "").split(".")[:2]) >= (0, 14)
    except ValueError:
        return False


def pending_patches(db, device):
    approvals = {(row.package_key, row.available_version): row.approved for row in
                 db.scalars(select(PatchApproval).where(PatchApproval.device_id == device.id))}
    result = []
    for item in device.available_updates or []:
        key = patch_key(item)
        if key is None:
            continue
        result.append({**item, "key": key[0], "approved": approvals.get(key, False),
                       "supported": device.package_manager != "winget" or bool(item.get("identifier"))})
    return result


def approved_snapshot(db, device):
    patches = pending_patches(db, device)
    selected = [item for item in patches if item["approved"] and item["supported"]]
    if not selected:
        raise HTTPException(409, "No supported approved patches are pending")
    if device.package_manager == "pacman" and len(selected) != len(patches):
        raise HTTPException(409, "Arch requires approval of every pending package for a full system upgrade")
    if device.package_manager not in ("apt", "pacman", "winget"):
        raise HTTPException(400, "Patch installation is unsupported on this device")
    # An agent verifies the version and, on Debian, the exact transaction
    # before performing any changes. A legacy agent cannot execute this type.
    return [{"package": item["key"], "version": item["available_version"]} for item in selected]


def active_patch_job(db, device_id):
    return db.scalar(select(Job.id).where(Job.device_id == device_id,
        Job.type.in_(["INSTALL_UPDATES", "INSTALL_APPROVED_UPDATES"]),
        Job.status.in_(["pending", "running"])))


def queue_scheduled_patch(db, device):
    if not supports_deployment(device):
        return
    schedule = db.get(PatchSchedule, device.id)
    now = utcnow()
    if not schedule or not schedule.interval_hours or as_utc(schedule.next_run_at) > now:
        return
    claimed = db.execute(update(PatchSchedule).where(
        PatchSchedule.device_id == device.id,
        PatchSchedule.interval_hours == schedule.interval_hours,
        PatchSchedule.next_run_at == schedule.next_run_at,
    ).values(next_run_at=now + timedelta(hours=schedule.interval_hours)))
    if claimed.rowcount != 1 or active_patch_job(db, device.id):
        return
    try:
        updates = approved_snapshot(db, device)
    except HTTPException:
        return  # No approved patches, or an incomplete Arch approval set.
    db.add(Job(device_id=device.id, type="INSTALL_APPROVED_UPDATES",
               options={"updates": updates, "scheduled": True}))
    db.flush()


class ApprovalInput(BaseModel):
    package: str = Field(min_length=1, max_length=255)
    available_version: str = Field(min_length=1, max_length=255)
    approved: bool


class ScheduleInput(BaseModel):
    interval_hours: int = Field(ge=0, le=8760)


@router.get("/api/v1/admin/devices/{device_id}/patch-approvals", dependencies=[Depends(require_viewer)])
def list_approvals(device_id: str, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    return pending_patches(db, device)


@router.put("/api/v1/admin/devices/{device_id}/patch-approvals", dependencies=[Depends(require_operator)])
def set_approval(device_id: str, payload: ApprovalInput, db: Session = Depends(get_db)):
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not device:
        raise HTTPException(404, "Device not found")
    key = (payload.package, payload.available_version)
    if key not in {patch_key(item) for item in device.available_updates or []}:
        raise HTTPException(409, "Patch/version no longer appears in the latest device scan")
    if device.package_manager == "winget" and not any(
        patch_key(item) == key and item.get("identifier") for item in device.available_updates or []
    ):
        raise HTTPException(400, "This Windows patch has no winget ID; installation is not supported")
    approval = db.get(PatchApproval, (device_id, *key))
    if approval is None:
        approval = PatchApproval(device_id=device_id, package_key=key[0], available_version=key[1])
        db.add(approval)
    approval.approved = payload.approved
    if not payload.approved:
        for job in db.scalars(select(Job).where(Job.device_id == device_id,
                             Job.type == "INSTALL_APPROVED_UPDATES", Job.status == "pending")):
            if {"package": key[0], "version": key[1]} in job.options.get("updates", []):
                job.status = "failed"
                job.error = "A patch approval was revoked before dispatch; review and queue again"
                job.completed_at = utcnow()
    db.commit()
    return {"package": key[0], "available_version": key[1], "approved": approval.approved}


@router.post("/api/v1/admin/devices/{device_id}/deploy-approved-patches", dependencies=[Depends(require_operator)], status_code=201)
def deploy_approved(device_id: str, db: Session = Depends(get_db)):
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not device:
        raise HTTPException(404, "Device not found")
    if not supports_deployment(device):
        raise HTTPException(409, "Upgrade this device's existing agent to 0.14.0 and run a patch scan first")
    if active_patch_job(db, device.id):
        raise HTTPException(409, "A patch job is already pending or running")
    updates = approved_snapshot(db, device)
    job = Job(device_id=device.id, type="INSTALL_APPROVED_UPDATES", options={"updates": updates})
    db.add(job)
    db.commit()
    db.refresh(job)
    return {"id": job.id, "updates": updates}


@router.get("/api/v1/admin/devices/{device_id}/patch-schedule", dependencies=[Depends(require_viewer)])
def get_patch_schedule(device_id: str, db: Session = Depends(get_db)):
    if not db.get(Device, device_id):
        raise HTTPException(404, "Device not found")
    schedule = db.get(PatchSchedule, device_id)
    return {"interval_hours": schedule.interval_hours if schedule else 0,
            "next_run_at": schedule.next_run_at if schedule and schedule.interval_hours else None}


@router.put("/api/v1/admin/devices/{device_id}/patch-schedule", dependencies=[Depends(require_operator)])
def set_patch_schedule(device_id: str, payload: ScheduleInput, db: Session = Depends(get_db)):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404, "Device not found")
    if payload.interval_hours and device.package_manager not in ("apt", "pacman", "winget"):
        raise HTTPException(400, "Patch scheduling is unsupported on this device")
    schedule = db.get(PatchSchedule, device_id)
    if schedule is None:
        schedule = PatchSchedule(device_id=device_id)
        db.add(schedule)
    schedule.interval_hours = payload.interval_hours
    schedule.next_run_at = utcnow() + timedelta(hours=payload.interval_hours)
    db.commit()
    return get_patch_schedule(device_id, db)


def bundle_view(package, db):
    files = db.scalars(select(CustomPackageFile).options(load_only(
        CustomPackageFile.id, CustomPackageFile.filename, CustomPackageFile.size, CustomPackageFile.sha256,
    )).where(CustomPackageFile.package_id == package.id)).all()
    return {"id": package.id, "name": package.name, "platform": package.platform,
            "command": package.command, "created_at": package.created_at,
            "files": [{"id": item.id, "filename": item.filename, "size": item.size, "sha256": item.sha256} for item in files]}


@router.get("/api/v1/admin/custom-packages", dependencies=[Depends(require_admin)])
def list_bundles(db: Session = Depends(get_db)):
    packages = db.scalars(select(CustomPackage).order_by(CustomPackage.created_at.desc())).all()
    return [bundle_view(package, db) for package in packages]


@router.post("/api/v1/admin/custom-packages", status_code=201)
async def upload_bundle(request: Request, name: str = Form(...), platform: str = Form(...),
                        command: str = Form(...), files: list[UploadFile] = File(...),
                        user=Depends(require_admin), db: Session = Depends(get_db)):
    if request.headers.get("content-length") and int(request.headers["content-length"]) > 20 * 1024 * 1024:
        raise HTTPException(413, "Upload exceeds 20 MiB request limit")
    if not 1 <= len(name.strip()) <= 255 or platform not in ("linux", "windows") or not 1 <= len(command.strip()) <= 4096:
        raise HTTPException(400, "Name, platform and install command are required")
    if not 1 <= len(files) <= 5:
        raise HTTPException(400, "Upload between one and five files")
    prepared, seen, total = [], set(), 0
    for uploaded in files:
        filename = uploaded.filename or ""
        if not SAFE_FILENAME.fullmatch(filename) or filename in (".", "..") or filename in seen:
            raise HTTPException(400, "Use unique plain filenames without directories")
        seen.add(filename)
        blob = await uploaded.read(MAX_FILE + 1)
        if not blob or len(blob) > MAX_FILE:
            raise HTTPException(413, "Each file must be nonempty and at most 8 MiB")
        total += len(blob)
        if total > MAX_TOTAL:
            raise HTTPException(413, "Files total at most 16 MiB")
        prepared.append((filename, blob))
    package = CustomPackage(name=name.strip(), platform=platform, command=command.strip())
    db.add(package)
    db.flush()
    for filename, blob in prepared:
        db.add(CustomPackageFile(package_id=package.id, filename=filename, content=blob,
                                 size=len(blob), sha256=hashlib.sha256(blob).hexdigest()))
    db.add(AccountAudit(actor=user.username if user else "bootstrap", action="custom_package_created", target=package.name,
                        details=f"{platform}, {len(prepared)} file(s)"))
    db.commit()
    return bundle_view(package, db)


@router.post("/api/v1/admin/custom-packages/{package_id}/devices/{device_id}/deploy", dependencies=[Depends(require_admin)], status_code=201)
def deploy_bundle(package_id: str, device_id: str, db: Session = Depends(get_db)):
    package = db.get(CustomPackage, package_id)
    device = db.scalar(select(Device).where(Device.id == device_id).with_for_update())
    if not package or not device:
        raise HTTPException(404, "Custom package or device not found")
    if not supports_deployment(device):
        raise HTTPException(409, "Upgrade this device's existing agent to 0.14.0 and run a patch scan first")
    if (device.platform == "windows") != (package.platform == "windows"):
        raise HTTPException(400, "Custom package platform does not match the target")
    if db.scalar(select(Job.id).where(Job.device_id == device_id, Job.type == "INSTALL_CUSTOM_PACKAGE",
                                   Job.status.in_(["pending", "running"]))):
        raise HTTPException(409, "A custom install is already pending or running")
    job = Job(device_id=device_id, type="INSTALL_CUSTOM_PACKAGE", options={"package_id": package.id, "name": package.name})
    db.add(job)
    db.commit()
    return {"id": job.id, "device_id": device_id, "package": package.name}


def authorized_bundle_job(db, device_id, authorization, job_id):
    device = authenticate_agent(db, device_id, authorization)
    job = db.get(Job, job_id)
    if not job or job.device_id != device.id or job.type != "INSTALL_CUSTOM_PACKAGE" or job.status != "running":
        raise HTTPException(404, "Running custom install job not found")
    package = db.get(CustomPackage, job.options.get("package_id"))
    if not package:
        raise HTTPException(404, "Custom package not found")
    return package


@router.get("/api/v1/agent/jobs/{job_id}/bundle")
def agent_bundle(job_id: str, x_device_id: str = Header(), authorization: str = Header(default=""),
                 db: Session = Depends(get_db)):
    package = authorized_bundle_job(db, x_device_id, authorization, job_id)
    return bundle_view(package, db)


@router.get("/api/v1/agent/jobs/{job_id}/bundle/files/{file_id}")
def agent_bundle_file(job_id: str, file_id: str, x_device_id: str = Header(),
                      authorization: str = Header(default=""), db: Session = Depends(get_db)):
    package = authorized_bundle_job(db, x_device_id, authorization, job_id)
    item = db.get(CustomPackageFile, file_id)
    if not item or item.package_id != package.id:
        raise HTTPException(404, "File not found")
    return Response(content=item.content, media_type="application/octet-stream")
