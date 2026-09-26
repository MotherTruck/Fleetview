"""Connections to external home-lab services (Proxmox, OPNsense), whose
inventory is pulled in and shown alongside FleetView's own fleet -- see
docs/INTEGRATIONS.md.

Credentials are encrypted at rest (secrets_crypto.py) and never returned
by any endpoint here; every response is built through integration_view(),
which only ever reads the non-secret columns.
"""
import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import require_admin, require_viewer
from .connectors import opnsense, proxmox
from .database import SessionLocal, get_db
from .models import AccountAudit, Integration, utcnow
from .secrets_crypto import CredentialDecryptionFailed, SecretKeyNotConfigured, decrypt_text, encrypt_text

router = APIRouter()
logger = logging.getLogger("fleetview.integrations")

SYNC_INTERVAL_SECONDS = 120

CONNECTORS = {
    "proxmox": proxmox,
    "opnsense": opnsense,
}


class IntegrationInput(BaseModel):
    kind: str = Field(pattern="^(proxmox|opnsense)$")
    name: str = Field(min_length=1, max_length=255)
    base_url: str = Field(min_length=1, max_length=500)
    verify_tls: bool = True
    credentials: dict[str, str] = Field(default_factory=dict)


def integration_view(integration: Integration) -> dict:
    return {
        "id": integration.id,
        "kind": integration.kind,
        "name": integration.name,
        "base_url": integration.base_url,
        "verify_tls": integration.verify_tls,
        "created_at": integration.created_at,
        "updated_at": integration.updated_at,
        "last_synced_at": integration.last_synced_at,
        "last_sync_error": integration.last_sync_error,
        "cached_data": integration.cached_data,
    }


def _validate_credentials(kind: str, credentials: dict, *, require_all: bool) -> dict:
    connector = CONNECTORS[kind]
    fields = connector.REQUIRED_CREDENTIAL_FIELDS
    cleaned = {key: str(value) for key, value in credentials.items() if key in fields and str(value).strip()}
    if require_all and set(cleaned) != set(fields):
        raise HTTPException(400, f"{kind} requires: {', '.join(fields)}")
    return cleaned


def sync_integration(db: Session, integration: Integration) -> None:
    """Fetches fresh data from the external service and updates the row in
    place. Never raises -- failures are recorded in last_sync_error so one
    unreachable integration can't break the admin listing or the periodic
    loop that calls this for every configured integration in turn."""
    connector = CONNECTORS.get(integration.kind)
    if connector is None:
        integration.last_sync_error = f"Unknown integration kind {integration.kind!r}"
        return
    try:
        credentials = json.loads(decrypt_text(integration.encrypted_credentials))
    except (CredentialDecryptionFailed, SecretKeyNotConfigured, ValueError) as error:
        integration.last_sync_error = str(error)
        return
    try:
        data = connector.fetch_inventory(integration.base_url, credentials, integration.verify_tls)
    except Exception as error:  # noqa: BLE001 -- any connector failure must not crash the sync loop
        integration.last_sync_error = str(error)
        return
    integration.cached_data = data
    integration.last_synced_at = utcnow()
    integration.last_sync_error = None


@router.get("/api/v1/admin/integrations", dependencies=[Depends(require_viewer)])
def list_integrations(db: Session = Depends(get_db)):
    integrations = db.scalars(select(Integration).order_by(Integration.created_at)).all()
    return [integration_view(item) for item in integrations]


@router.post("/api/v1/admin/integrations", dependencies=[Depends(require_admin)], status_code=201)
def create_integration(payload: IntegrationInput, user=Depends(require_admin), db: Session = Depends(get_db)):
    if payload.kind not in CONNECTORS:
        raise HTTPException(400, f"Unsupported integration kind {payload.kind!r}")
    credentials = _validate_credentials(payload.kind, payload.credentials, require_all=True)
    try:
        encrypted = encrypt_text(json.dumps(credentials))
    except SecretKeyNotConfigured as error:
        raise HTTPException(409, str(error)) from error
    integration = Integration(kind=payload.kind, name=payload.name, base_url=payload.base_url,
                              verify_tls=payload.verify_tls, encrypted_credentials=encrypted)
    db.add(integration)
    db.add(AccountAudit(actor=user.username if user else "bootstrap", action="integration_created",
                        target=payload.name, details=payload.kind))
    db.commit()
    db.refresh(integration)
    sync_integration(db, integration)
    db.commit()
    return integration_view(integration)


@router.put("/api/v1/admin/integrations/{integration_id}", dependencies=[Depends(require_admin)])
def update_integration(integration_id: str, payload: IntegrationInput, user=Depends(require_admin), db: Session = Depends(get_db)):
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    if payload.kind not in CONNECTORS:
        raise HTTPException(400, f"Unsupported integration kind {payload.kind!r}")
    credentials = _validate_credentials(payload.kind, payload.credentials, require_all=False)
    if credentials:
        try:
            integration.encrypted_credentials = encrypt_text(json.dumps(credentials))
        except SecretKeyNotConfigured as error:
            raise HTTPException(409, str(error)) from error
    elif integration.kind != payload.kind:
        raise HTTPException(400, "Changing the integration kind requires re-entering credentials")
    integration.kind = payload.kind
    integration.name = payload.name
    integration.base_url = payload.base_url
    integration.verify_tls = payload.verify_tls
    db.add(AccountAudit(actor=user.username if user else "bootstrap", action="integration_updated",
                        target=integration.name, details=integration.kind))
    db.commit()
    sync_integration(db, integration)
    db.commit()
    db.refresh(integration)
    return integration_view(integration)


@router.delete("/api/v1/admin/integrations/{integration_id}", dependencies=[Depends(require_admin)], status_code=204)
def delete_integration(integration_id: str, user=Depends(require_admin), db: Session = Depends(get_db)):
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    db.add(AccountAudit(actor=user.username if user else "bootstrap", action="integration_deleted",
                        target=integration.name, details=integration.kind))
    db.delete(integration)
    db.commit()


@router.post("/api/v1/admin/integrations/{integration_id}/sync", dependencies=[Depends(require_admin)])
def trigger_sync(integration_id: str, db: Session = Depends(get_db)):
    integration = db.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(404, "Integration not found")
    sync_integration(db, integration)
    db.commit()
    db.refresh(integration)
    return integration_view(integration)


async def periodic_sync_loop() -> None:
    """Started from main.py's lifespan; keeps every configured integration's
    cached_data fresh without requiring an admin to click refresh. Runs the
    actual (blocking) HTTP calls in a worker thread so a slow/unreachable
    integration never stalls the event loop the live-metrics/terminal
    WebSocket connections also share."""
    while True:
        try:
            await asyncio.to_thread(_sync_all_once)
        except Exception:  # noqa: BLE001 -- one bad iteration must not kill the loop
            logger.exception("integration sync loop iteration failed")
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)


def _sync_all_once() -> None:
    db = SessionLocal()
    try:
        for integration in db.scalars(select(Integration)).all():
            sync_integration(db, integration)
        db.commit()
    finally:
        db.close()
