"""
integrity_check.py
SHA-256 data-integrity layer.

Design (important for the viva):
  * Every reading is hashed with HMAC-SHA256 (hashlib.sha256 + a secret key).
  * The key lives in data/integrity.key and the trusted hashes + a golden copy of
    each reading live in a SEPARATE database (data/vault.db), not in battery.db.
  * An attacker who edits battery.db - even the integrity_hash column - cannot
    forge a matching hash, because the vault and the key are elsewhere.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
VAULT_PATH = os.path.join(DATA_DIR, "vault.db")
KEY_PATH = os.path.join(DATA_DIR, "integrity.key")


def _load_key() -> bytes:
    """Load the secret key, creating it on first run."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_PATH, "r") as f:
        return f.read().strip().encode()


def canonical_string(rec: dict) -> str:
    """Fixed text form of a reading so the same data always hashes the same."""
    return "|".join([
        str(int(rec["id"])),
        f"{float(rec['voltage']):.2f}",
        f"{float(rec['current']):.2f}",
        f"{float(rec['temperature']):.2f}",
        f"{float(rec['soc']):.2f}",
        str(rec["charging_status"]),
        str(rec["timestamp"]),
    ])


def compute_hash(rec: dict) -> str:
    """Keyed SHA-256 (HMAC) of a reading."""
    return hmac.new(_load_key(), canonical_string(rec).encode(), hashlib.sha256).hexdigest()


@contextmanager
def _vault():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(VAULT_PATH, timeout=10)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS integrity_vault (
            reading_id INTEGER PRIMARY KEY,
            hash TEXT NOT NULL,
            backup TEXT NOT NULL)""")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def store_in_vault(rec: dict, hash_value: str) -> None:
    """Save the trusted hash and a golden copy of the reading."""
    backup = {k: rec[k] for k in ("id", "voltage", "current", "temperature", "soc",
                                  "charging_status", "timestamp")}
    with _vault() as conn:
        conn.execute("INSERT OR REPLACE INTO integrity_vault (reading_id, hash, backup) VALUES (?, ?, ?)",
                     (int(rec["id"]), hash_value, json.dumps(backup)))


def get_backup(reading_id: int):
    """Golden copy of a reading, used to restore tampered records."""
    with _vault() as conn:
        row = conn.execute("SELECT backup FROM integrity_vault WHERE reading_id = ?",
                           (int(reading_id),)).fetchone()
    return json.loads(row[0]) if row else None


def verify_reading(rec: dict) -> dict:
    """Recompute the hash of a stored record and compare with the vault."""
    computed = compute_hash(rec)
    with _vault() as conn:
        row = conn.execute("SELECT hash FROM integrity_vault WHERE reading_id = ?",
                           (int(rec["id"]),)).fetchone()
    if row is None:
        return {"ok": False, "reason": "No protected hash found in vault",
                "computed": computed, "trusted": None}
    trusted = row[0]
    ok = hmac.compare_digest(computed, trusted)
    reason = "Record matches protected hash" if ok else "Record content does not match protected hash"
    return {"ok": ok, "reason": reason, "computed": computed, "trusted": trusted}


def verify_many(records: list) -> dict:
    """Verify many records with one vault query. Returns {reading_id: bool}."""
    if not records:
        return {}
    with _vault() as conn:
        trusted = dict(conn.execute("SELECT reading_id, hash FROM integrity_vault").fetchall())
    key = _load_key()
    result = {}
    for rec in records:
        rid = int(rec["id"])
        expected = trusted.get(rid)
        computed = hmac.new(key, canonical_string(rec).encode(), hashlib.sha256).hexdigest()
        result[rid] = expected is not None and hmac.compare_digest(computed, expected)
    return result


def clear_vault() -> None:
    with _vault() as conn:
        conn.execute("DELETE FROM integrity_vault")
