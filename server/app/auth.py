import os

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuthControl, Device, User, UserSession, utcnow
from .database import get_db
from .enrollment import as_utc
from .security import secure_equal, token_hash


SESSION_COOKIE = "fleetview_session"


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    cookie = request.cookies.get(SESSION_COOKIE, "")
    session = db.get(UserSession, token_hash(cookie)) if cookie else None
    user = db.get(User, session.user_id) if session else None
    if session is None or as_utc(session.expires_at) <= utcnow() or user is None or not user.active:
        raise HTTPException(401, "Sign in to continue")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not secure_equal(request.headers.get("X-CSRF-Token", ""), session.csrf_token):
            raise HTTPException(403, "Session verification failed; refresh and try again")
    request.state.user_session = session
    return user


def require_viewer(request: Request, db: Session = Depends(get_db)) -> User | None:
    # Legacy API access works only BEFORE the one-time account setup. It cannot
    # bypass roles after setup, even if ADMIN_TOKEN remains in the environment.
    if db.get(AuthControl, 1) is None:
        expected = os.environ.get("ADMIN_TOKEN", "")
        supplied = request.headers.get("X-Admin-Token", "")
        if expected and secure_equal(supplied, expected):
            return None
    user = current_user(request, db)
    if user.must_change_password:
        raise HTTPException(403, "Change your temporary password before continuing")
    return user


def require_operator(request: Request, db: Session = Depends(get_db)) -> User | None:
    user = require_viewer(request, db)
    if user is not None and user.role not in ("operator", "admin"):
        raise HTTPException(403, "Operator or admin access required")
    return user


def require_admin(request: Request, db: Session = Depends(get_db)) -> User | None:
    user = require_viewer(request, db)
    if user is not None and user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user


def authenticate_agent(db: Session, device_id: str, authorization: str) -> Device:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing agent token")
    device = db.get(Device, device_id)
    supplied = token_hash(authorization.removeprefix("Bearer ").strip())
    if device is None or not secure_equal(supplied, device.agent_token_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent credentials")
    return device
