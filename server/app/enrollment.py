"""Pure helpers for per-device, one-time enrollment tokens.

Kept free of FastAPI/SQLAlchemy imports so the rules can be unit-tested anywhere.
"""

from datetime import datetime, timezone

TOKEN_PREFIX = "fv_"
DEFAULT_TTL_MINUTES = 60
MAX_TTL_MINUTES = 7 * 24 * 60


def as_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime.

    PostgreSQL returns timezone-aware values, but SQLite (used by the development
    fallback and tests) returns naive ones that were stored as UTC.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def token_status(
    *,
    used_at: datetime | None,
    revoked_at: datetime | None,
    expires_at: datetime,
    now: datetime,
) -> str:
    """Classify a token as used, revoked, expired, or active (in that precedence)."""
    if used_at is not None:
        return "used"
    if revoked_at is not None:
        return "revoked"
    if as_utc(expires_at) <= as_utc(now):
        return "expired"
    return "active"
