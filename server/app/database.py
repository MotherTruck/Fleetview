import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./fleetview-dev.db")
CONNECT_ARGS = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
# An in-memory SQLite database (used only by the test suite; real
# deployments use Postgres or a file-backed SQLite path) is per-connection,
# and SQLAlchemy's default pooling hands each new thread its own empty one
# -- StaticPool keeps every caller, on any thread, sharing the single real
# connection instead. Code that opens its own short-lived sessions off the
# request-scoped `get_db` dependency (see live.py) needs this to see the
# same data a test's fixtures set up, since the ASGI test client runs the
# app in its own background thread.
ENGINE_KWARGS = {"poolclass": StaticPool} if DATABASE_URL in ("sqlite://", "sqlite:///:memory:") else {}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=CONNECT_ARGS, **ENGINE_KWARGS)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

