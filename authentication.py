"""
authentication.py
Login with salted PBKDF2-HMAC-SHA256 password hashes and role-based permissions.
"""
import hashlib
import hmac
import os

from modules import database

ITERATIONS = 200_000
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"

PERMISSIONS = {
    ROLE_ADMIN: {"view", "export", "configure", "simulate_attack", "reset", "send_charge_command"},
    ROLE_VIEWER: {"view", "export"},
}

# Demo accounts created on first run (change them for any real use)
DEFAULT_USERS = [("admin", "Admin@123", ROLE_ADMIN), ("viewer", "Viewer@123", ROLE_VIEWER)]


def hash_password(password: str, salt: bytes = None) -> str:
    """Return 'pbkdf2_sha256$iterations$salt$hash' (salt is random per user)."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, hash_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def authenticate(username: str, password: str):
    """Return {'username','role'} on success, otherwise None."""
    user = database.get_user((username or "").strip())
    if user is None:
        verify_password(password or "", _DUMMY_HASH)  # same work for unknown users
        return None
    if verify_password(password or "", user["password_hash"]):
        return {"username": user["username"], "role": user["role"]}
    return None


def has_permission(role, action: str) -> bool:
    return action in PERMISSIONS.get(role, set())


def role_label(role) -> str:
    return "Administrator" if role == ROLE_ADMIN else "Viewer" if role == ROLE_VIEWER else "Unauthenticated"


def ensure_default_users() -> None:
    for username, password, role in DEFAULT_USERS:
        if database.get_user(username) is None:
            database.create_user(username, hash_password(password), role)
