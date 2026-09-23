"""Local console recovery: docker compose exec server python -m app.manage_users USERNAME"""
import argparse
import getpass
from sqlalchemy import delete, select
from .database import SessionLocal
from .models import AccountAudit, AuthControl, User, UserSession
from .security import password_hash


def main():
    parser = argparse.ArgumentParser(description="Reset and enable an existing FleetView admin account locally.")
    parser.add_argument("username")
    args = parser.parse_args()
    with SessionLocal() as db:
        db.scalar(select(AuthControl).where(AuthControl.id == 1).with_for_update())
        user = db.scalar(select(User).where(User.username == args.username.lower()).with_for_update())
        if user is None or user.role != "admin":
            parser.error("An existing administrator username is required.")
        password = getpass.getpass("New password (12–128 characters): ")
        if not 12 <= len(password) <= 128:
            parser.error("Password must contain 12–128 characters.")
        if password != getpass.getpass("Confirm new password: "):
            parser.error("Passwords do not match.")
        user.password_hash = password_hash(password)
        user.active = True
        user.must_change_password = False
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
        db.add(AccountAudit(actor="local-console", action="admin_recovered", target=user.username))
        db.commit()
    print("Administrator password reset; existing sessions revoked.")


if __name__ == "__main__":
    main()
