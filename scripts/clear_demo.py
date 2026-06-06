"""Remove demo/seed data from the database, keeping the bootstrap accounts.

Deletes the demo resident (USER-role) accounts and everything tied to them,
plus all visitors, announcements, gate-log entries and allowlist rows. The
ADMIN and SECURITY accounts, roles and permissions are kept so you can still
log in and start entering real data.

Usage (inside the web container):
    python scripts/clear_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text  # noqa: E402

from app.database import engine  # noqa: E402


def run() -> None:
    with engine.begin() as conn:
        # Wipe demo content tables (all rows here are seeded demo data).
        conn.execute(text(
            'TRUNCATE gate_entries, visitors, announcements, "allowList" '
            'RESTART IDENTITY CASCADE'
        ))
        # Remove demo resident (USER-role) accounts and their resident rows.
        conn.execute(text(
            "DELETE FROM residents WHERE user_id IN ("
            "  SELECT u.id FROM users u JOIN roles r ON u.role_id = r.id"
            "  WHERE r.name = 'USER')"
        ))
        result = conn.execute(text(
            "DELETE FROM users WHERE role_id IN "
            "(SELECT id FROM roles WHERE name = 'USER')"
        ))
        print(f"Removed {result.rowcount} demo USER account(s).")
    print("Demo data cleared. ADMIN/SECURITY accounts, roles and permissions kept.")


if __name__ == "__main__":
    run()
