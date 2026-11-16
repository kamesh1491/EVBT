"""
database.py
SQLite storage for readings, alerts and users. All queries are parameterized.
"""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

import pandas as pd

from modules import integrity_check

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DATA_DIR, "battery.db")
TIME_FMT = "%Y-%m-%d %H:%M:%S"
EDITABLE_FIELDS = {"voltage", "current", "temperature", "soc"}


def now_str() -> str:
    return datetime.now().strftime(TIME_FMT)


@contextmanager
def get_conn():
    """Open a connection, commit on success, roll back on error, always close."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create the database file and tables if they do not exist."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS battery_readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voltage REAL NOT NULL,
            current REAL NOT NULL,
            temperature REAL NOT NULL,
            soc REAL NOT NULL,
            charging_status TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            integrity_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );
        """)


# ---------------------------------------------------------------- readings
def insert_reading(voltage, current, temperature, soc, charging_status, timestamp=None) -> dict:
    """Store a reading, hash it, and put the trusted hash in the separate vault."""
    rec = {"voltage": round(float(voltage), 2), "current": round(float(current), 2),
           "temperature": round(float(temperature), 2), "soc": round(float(soc), 2),
           "charging_status": charging_status, "timestamp": timestamp or now_str()}
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO battery_readings (voltage, current, temperature, soc, charging_status, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (rec["voltage"], rec["current"], rec["temperature"], rec["soc"],
             rec["charging_status"], rec["timestamp"]))
        rec["id"] = cur.lastrowid
        rec["integrity_hash"] = integrity_check.compute_hash(rec)
        conn.execute("UPDATE battery_readings SET integrity_hash = ? WHERE id = ?",
                     (rec["integrity_hash"], rec["id"]))
    integrity_check.store_in_vault(rec, rec["integrity_hash"])
    return rec


def get_readings(limit=None) -> pd.DataFrame:
    """Readings in chronological order (the newest `limit` rows if limit is given)."""
    with get_conn() as conn:
        if limit:
            df = pd.read_sql_query("SELECT * FROM battery_readings ORDER BY id DESC LIMIT ?",
                                   conn, params=(int(limit),)).iloc[::-1]
        else:
            df = pd.read_sql_query("SELECT * FROM battery_readings ORDER BY id ASC", conn)
    df = df.reset_index(drop=True)
    if not df.empty:
        df["time"] = pd.to_datetime(df["timestamp"])
    return df


def get_latest_reading():
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM battery_readings ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def get_reading(reading_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM battery_readings WHERE id = ?", (int(reading_id),)).fetchone()
    return dict(row) if row else None


def count_readings() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM battery_readings").fetchone()[0]


def update_reading_value(reading_id: int, field: str, value: float) -> None:
    """Directly overwrite a stored value (used ONLY by the tampering simulation)."""
    if field not in EDITABLE_FIELDS:
        raise ValueError("Field not editable")
    with get_conn() as conn:
        conn.execute(f"UPDATE battery_readings SET {field} = ? WHERE id = ?", (float(value), int(reading_id)))


def restore_reading(backup: dict) -> None:
    """Put a reading back to its golden copy from the vault."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE battery_readings SET voltage=?, current=?, temperature=?, soc=?, charging_status=?, timestamp=? "
            "WHERE id=?",
            (backup["voltage"], backup["current"], backup["temperature"], backup["soc"],
             backup["charging_status"], backup["timestamp"], backup["id"]))


def clear_readings() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM battery_readings")
    integrity_check.clear_vault()


# ------------------------------------------------------------------ alerts
def insert_alert(attack_type, description, severity, status="Detected", timestamp=None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO security_alerts (attack_type, description, severity, timestamp, status) "
            "VALUES (?, ?, ?, ?, ?)",
            (attack_type, description, severity, timestamp or now_str(), status))
        return cur.lastrowid


def get_alerts(limit=None) -> pd.DataFrame:
    """Alerts, newest first."""
    with get_conn() as conn:
        if limit:
            return pd.read_sql_query("SELECT * FROM security_alerts ORDER BY id DESC LIMIT ?",
                                     conn, params=(int(limit),))
        return pd.read_sql_query("SELECT * FROM security_alerts ORDER BY id DESC", conn)


def count_alerts() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]


def resolve_alerts(attack_type: str, new_status: str = "Resolved") -> int:
    """Mark open alerts of one type as resolved (used after restoring tampered data)."""
    with get_conn() as conn:
        cur = conn.execute("UPDATE security_alerts SET status = ? WHERE attack_type = ? AND status = 'Detected'",
                           (new_status, attack_type))
        return cur.rowcount


def clear_alerts() -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM security_alerts")


# ------------------------------------------------------------------- users
def create_user(username: str, password_hash: str, role: str) -> None:
    with get_conn() as conn:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, password_hash, role))


def get_user(username: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return dict(row) if row else None


def count_users() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
