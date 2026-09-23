"""Human accounts only. Endpoint enrollment and credentials remain independent."""
import os
import secrets
from datetime import timedelta
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, SecretStr, field_validator
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .auth import SESSION_COOKIE, current_user, require_admin
from .database import get_db
from .models import AccountAudit, AuthControl, LoginThrottle, User, UserSession, utcnow
from .security import password_hash, secure_equal, token_hash, verify_password

router = APIRouter()
Role = Literal["admin", "operator", "viewer"]
DUMMY_HASH = password_hash(secrets.token_urlsafe(32))


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    password: SecretStr = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value):
        return value.lower()


class Setup(Credentials):
    admin_token: SecretStr = Field(min_length=1, max_length=512)
    password: SecretStr = Field(min_length=12, max_length=128)


class CreateUser(Credentials):
    password: SecretStr = Field(min_length=12, max_length=128)
    role: Role = "viewer"


class EditUser(BaseModel):
    role: Role
    active: bool
    password: SecretStr | None = Field(default=None, min_length=12, max_length=128)


class ChangePassword(BaseModel):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)


def user_view(user):
    return {key: getattr(user, key) for key in (
        "id", "username", "role", "active", "must_change_password", "created_at", "last_login_at")}


def browser_write(request: Request):
    # Custom header requires a preflight for cross-origin browser requests.
    # This app does not enable CORS. Also reject cross-site form/login requests.
    origin = request.headers.get("origin")
    if request.headers.get("X-FleetView-Request") != "1":
        raise HTTPException(403, "Request verification required")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Cross-site requests are not allowed")
    if origin:
        parsed = urlsplit(origin)
        if parsed.scheme not in ("http", "https") or parsed.netloc != request.headers.get("host"):
            raise HTTPException(403, "Cross-origin requests are not allowed")


def throttle(db: Session, request: Request, username: str):
    """Persistent atomic counters, shared by all workers; no client-forwarded IP."""
    now = utcnow()
    window = int(now.timestamp()) // 900
    peer = request.client.host if request.client else "unknown"
    db.execute(delete(LoginThrottle).where(LoginThrottle.expires_at < now))
    denied = False
    for scope, limit in ((f"peer:{peer}", 60), (f"account:{username}", 10)):
        key = token_hash(f"{scope}:{window}")
        try:
            with db.begin_nested():
                db.add(LoginThrottle(key=key, attempts=0, expires_at=now + timedelta(minutes=30)))
                db.flush()
        except IntegrityError:
            pass
        count = db.scalar(update(LoginThrottle).where(LoginThrottle.key == key)
                          .values(attempts=LoginThrottle.attempts + 1)
                          .returning(LoginThrottle.attempts))
        denied = denied or count > limit
    db.commit()  # Count failures too, even when the endpoint raises.
    if denied:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.",
                            headers={"Retry-After": "900"})


def audit(db, actor, action, target, details=""):
    db.add(AccountAudit(actor=actor, action=action, target=target, details=details))


def start_session(db, request, response, user):
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    old_cookie = request.cookies.get(SESSION_COOKIE, "")
    db.execute(delete(UserSession).where(UserSession.expires_at <= now))
    if old_cookie:
        db.execute(delete(UserSession).where(UserSession.token_hash == token_hash(old_cookie)))
    db.add(UserSession(token_hash=token_hash(raw), user_id=user.id, csrf_token=csrf,
                       expires_at=now + timedelta(hours=12)))
    user.last_login_at = now
    db.commit()
    # Existing LAN HTTP installations remain usable. Set the override to true
    # when TLS is terminated upstream and the backend sees HTTP.
    secure = request.url.scheme == "https" or os.environ.get("FLEETVIEW_COOKIE_SECURE", "").lower() == "true"
    response.set_cookie(SESSION_COOKIE, raw, max_age=43200, httponly=True,
                        secure=secure, samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"user": user_view(user), "csrf_token": csrf}


@router.get("/api/v1/auth/status")
def auth_status(db: Session = Depends(get_db)):
    return {"setup_required": db.get(AuthControl, 1) is None}


@router.post("/api/v1/auth/setup", dependencies=[Depends(browser_write)], status_code=201)
def setup(payload: Setup, request: Request, response: Response, db: Session = Depends(get_db)):
    throttle(db, request, "setup")
    if db.get(AuthControl, 1) is not None:
        raise HTTPException(409, "Account setup is already complete")
    expected = os.environ.get("ADMIN_TOKEN", "")
    if not expected or not secure_equal(payload.admin_token.get_secret_value(), expected):
        raise HTTPException(401, "Setup authorization failed")
    # The singleton key makes concurrent setup attempts mutually exclusive.
    try:
        db.add(AuthControl(id=1))
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Account setup is already complete")
    user = User(username=payload.username, password_hash=password_hash(payload.password.get_secret_value()),
                role="admin", active=True, must_change_password=False)
    db.add(user)
    db.flush()
    audit(db, user.username, "setup", user.username, "First administrator created")
    return start_session(db, request, response, user)


@router.post("/api/v1/auth/login", dependencies=[Depends(browser_write)])
def login(payload: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    throttle(db, request, payload.username)
    # Serialize login against disable/reset so a reset cannot race a new session.
    user = db.scalar(select(User).where(User.username == payload.username).with_for_update())
    valid = verify_password(payload.password.get_secret_value(), user.password_hash if user else DUMMY_HASH)
    if user is None or not valid or not user.active:
        raise HTTPException(401, "Invalid username or password")
    return start_session(db, request, response, user)


@router.get("/api/v1/auth/me")
def me(request: Request, response: Response, user: User = Depends(current_user)):
    response.headers["Cache-Control"] = "no-store"
    return {"user": user_view(user), "csrf_token": request.state.user_session.csrf_token}


@router.post("/api/v1/auth/logout", status_code=204)
def logout(request: Request, response: Response, user: User = Depends(current_user), db: Session = Depends(get_db)):
    db.delete(request.state.user_session)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.post("/api/v1/auth/password", status_code=204)
def change_password(payload: ChangePassword, request: Request, response: Response,
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    throttle(db, request, f"password:{user.id}")
    db.refresh(user, with_for_update=True)
    if not verify_password(payload.current_password.get_secret_value(), user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    if payload.current_password == payload.new_password:
        raise HTTPException(400, "Choose a different password")
    user.password_hash = password_hash(payload.new_password.get_secret_value())
    user.must_change_password = False
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    audit(db, user.username, "password_changed", user.username)
    db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")


def account_admin(user=Depends(require_admin)):
    if user is None:  # Legacy token cannot create arbitrary users before setup.
        raise HTTPException(403, "Complete account setup first")
    return user


@router.get("/api/v1/admin/users")
def list_users(user=Depends(account_admin), db: Session = Depends(get_db)):
    return [user_view(row) for row in db.scalars(select(User).order_by(User.username))]


@router.post("/api/v1/admin/users", status_code=201)
def create_user(payload: CreateUser, actor=Depends(account_admin), db: Session = Depends(get_db)):
    db.scalar(select(AuthControl).where(AuthControl.id == 1).with_for_update())
    db.refresh(actor)
    if not actor.active or actor.role != "admin":
        raise HTTPException(403, "Admin access required")
    user = User(username=payload.username, password_hash=password_hash(payload.password.get_secret_value()),
                role=payload.role, active=True, must_change_password=True)
    db.add(user)
    audit(db, actor.username, "user_created", user.username, f"role={user.role}")
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already exists")
    return user_view(user)


@router.put("/api/v1/admin/users/{user_id}")
def edit_user(user_id: str, payload: EditUser, actor=Depends(account_admin), db: Session = Depends(get_db)):
    db.scalar(select(AuthControl).where(AuthControl.id == 1).with_for_update())
    # Re-read authorization after acquiring the admin lock.
    db.refresh(actor)
    if not actor.active or actor.role != "admin":
        raise HTTPException(403, "Admin access required")
    user = db.scalar(select(User).where(User.id == user_id).with_for_update())
    if user is None:
        raise HTTPException(404, "User not found")
    if user.role == "admin" and user.active and (payload.role != "admin" or not payload.active):
        count = db.scalar(select(func.count()).select_from(User).where(User.active.is_(True), User.role == "admin"))
        if count <= 1:
            raise HTTPException(409, "Keep at least one active administrator")
    if payload.password is not None and user.id == actor.id:
        raise HTTPException(400, "Use Change password to change your own password")
    user.role, user.active = payload.role, payload.active
    if payload.password is not None:
        user.password_hash = password_hash(payload.password.get_secret_value())
        user.must_change_password = True
    db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    audit(db, actor.username, "user_updated", user.username,
          f"role={user.role}; active={user.active}; password_reset={payload.password is not None}")
    db.commit()
    return user_view(user)


@router.get("/api/v1/admin/users/audit/recent")
def audit_history(user=Depends(account_admin), db: Session = Depends(get_db)):
    rows = db.scalars(select(AccountAudit).order_by(AccountAudit.id.desc()).limit(100))
    return [{key: getattr(row, key) for key in ("actor", "action", "target", "details", "created_at")} for row in rows]
