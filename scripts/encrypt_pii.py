"""One-time migration: encrypt existing plaintext PII rows in place.

After PII columns were switched to EncryptedStr, rows written *before* the change
are still plaintext and won't match encrypted equality lookups (e.g. login).
This script reads each PII value via raw SQL (bypassing the ORM's transparent
decrypt), encrypts any value that isn't already encrypted, and writes it back.

Idempotent: already-encrypted values (prefixed `enc:1:`) are skipped.

Usage (inside the web container):
    python scripts/encrypt_pii.py
"""
from sqlalchemy import text

from app.database import engine
from app.security.pii import pii_encrypt, _PREFIX

# (table, column) — table names that need quoting are quoted here.
TARGETS = [
    ("users", "email"),
    ("users", "phone_number"),
    ("residents", "lot_no"),
    ("visitors", "name"),
    ("visitors", "phone"),
    ("visitors", "vehicle_plate"),
    ('"allowList"', "email"),
    ('"allowList"', "phone_number"),
    ("gate_entries", "lot_no"),
]


def run() -> None:
    total = 0
    with engine.begin() as conn:
        for table, col in TARGETS:
            rows = conn.execute(
                text(f'SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL')
            ).fetchall()
            changed = 0
            for row_id, value in rows:
                if isinstance(value, str) and value.startswith(_PREFIX):
                    continue  # already encrypted
                conn.execute(
                    text(f'UPDATE {table} SET {col} = :v WHERE id = :id'),
                    {"v": pii_encrypt(value), "id": row_id},
                )
                changed += 1
            total += changed
            print(f"{table}.{col}: encrypted {changed} of {len(rows)} rows")
    print(f"Done. Encrypted {total} value(s) total.")


if __name__ == "__main__":
    run()
