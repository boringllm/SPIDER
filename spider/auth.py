"""Multi-user authentication: password hashing, login tokens, and user management.

SPAIDER is single-host but multi-operator. Exactly one bootstrap **admin** account manages
the rest; every other account is a regular **user** who only sees the pentest sessions they
created (isolation is enforced in server.py via ``sessions.owner``). This module owns the
security-sensitive bits:

  * Password hashing with the stdlib ``hashlib.scrypt`` (memory-hard) + a per-user random
    salt. No third-party dependency. Verification is constant-time (``hmac.compare_digest``).
  * Login **tokens** (random, opaque, server-side, revocable) delivered to the browser as an
    HttpOnly cookie. Stored in the ``auth_sessions`` table so logout / user-deletion revoke them.
  * User CRUD + the first-run bootstrap check (``needs_setup``).

All persistence goes through ``Database`` (db.py); this module never touches SQLite directly.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass

from .db import Database

# scrypt cost parameters (RFC 7914). N must be a power of two; these are a sensible
# interactive-login default (~16 MiB, a few ms). Raise N to harden further.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
_SALT_BYTES = 16

# How long a login token stays valid (seconds). Re-login required afterwards.
TOKEN_TTL = 7 * 24 * 3600
COOKIE_NAME = "spider_token"

ROLES = ("admin", "user")


# --------------------------------------------------------------------------- #
# Password hashing (stdlib scrypt; format: scrypt$N$r$p$salthex$hashhex)
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Hash a password with scrypt and a fresh random salt; return a self-describing string."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored ``hash_password`` string."""
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


# A fixed dummy hash so ``authenticate`` spends the same scrypt time whether or not the username
# exists — otherwise the response is measurably faster for unknown usernames, letting an attacker
# enumerate valid accounts by timing. Computed once at import (one scrypt, a few ms).
_DUMMY_HASH = hash_password("spaider-timing-equalizer-not-a-real-password")


# --------------------------------------------------------------------------- #
# User view object
# --------------------------------------------------------------------------- #
@dataclass
class User:
    id: str
    username: str
    role: str
    disabled: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @classmethod
    def from_row(cls, row: dict) -> "User":
        return cls(id=row["id"], username=row["username"], role=row["role"],
                   disabled=bool(row.get("disabled")))

    def public(self) -> dict:
        return {"id": self.id, "username": self.username, "role": self.role,
                "disabled": self.disabled}


# --------------------------------------------------------------------------- #
# Auth manager — the operations server.py calls
# --------------------------------------------------------------------------- #
class AuthError(Exception):
    """Recoverable auth failure (bad creds, name taken, last-admin guard, …)."""


class Auth:
    """Thin orchestration layer over ``Database`` for accounts and login tokens."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ---- bootstrap ----
    async def needs_setup(self) -> bool:
        """True when there are no users yet — the first-run 'create administrator' state."""
        return not await self.db.list_users()

    # ---- account management ----
    async def create_user(self, username: str, password: str, role: str = "user") -> User:
        username = (username or "").strip()
        role = (role or "user").strip()
        if not username:
            raise AuthError("username is required")
        if not role:
            raise AuthError("role is required")
        # `admin` is the built-in privileged role; any other value must be a custom role defined in
        # the config (validated by the server before calling this — auth.py stays config-agnostic).
        if len(password or "") < 8:
            raise AuthError("password must be at least 8 characters")
        if await self.db.get_user_by_username(username):
            raise AuthError("username already taken")
        uid = "u_" + uuid.uuid4().hex[:10]
        await self.db.create_user({
            "id": uid, "username": username, "pw_hash": hash_password(password), "role": role,
        })
        return User(id=uid, username=username, role=role)

    async def create_first_admin(self, username: str, password: str) -> User:
        """First-run bootstrap: create the initial admin. Refuses once any user exists."""
        if not await self.needs_setup():
            raise AuthError("setup already completed")
        return await self.create_user(username, password, role="admin")

    async def list_users(self) -> list[dict]:
        return [User.from_row(r).public() for r in await self.db.list_users()]

    async def set_password(self, uid: str, password: str) -> None:
        if len(password or "") < 8:
            raise AuthError("password must be at least 8 characters")
        if not await self.db.get_user(uid):
            raise AuthError("no such user")
        await self.db.update_user(uid, {"pw_hash": hash_password(password)})

    async def set_disabled(self, uid: str, disabled: bool) -> None:
        row = await self.db.get_user(uid)
        if not row:
            raise AuthError("no such user")
        if disabled and row["role"] == "admin" and await self.db.count_admins() <= 1:
            raise AuthError("cannot disable the last administrator")
        await self.db.update_user(uid, {"disabled": 1 if disabled else 0})

    async def set_role(self, uid: str, role: str) -> None:
        """Change a user's access role. Guards the last admin (can't demote the only one). Role
        validity (custom roles) is checked by the caller against the config."""
        role = (role or "").strip()
        if not role:
            raise AuthError("role is required")
        row = await self.db.get_user(uid)
        if not row:
            raise AuthError("no such user")
        if row["role"] == "admin" and role != "admin" and await self.db.count_admins() <= 1:
            raise AuthError("cannot remove the last administrator")
        await self.db.update_user(uid, {"role": role})

    async def delete_user(self, uid: str) -> None:
        row = await self.db.get_user(uid)
        if not row:
            raise AuthError("no such user")
        if row["role"] == "admin" and await self.db.count_admins() <= 1:
            raise AuthError("cannot delete the last administrator")
        await self.db.delete_user(uid)

    # ---- login / tokens ----
    async def authenticate(self, username: str, password: str) -> User:
        """Verify credentials; raise AuthError on any failure (same message either way to
        avoid leaking which usernames exist)."""
        row = await self.db.get_user_by_username((username or "").strip())
        # Always run one scrypt verification (against a dummy hash when the user is unknown) so the
        # timing doesn't reveal whether the username exists (account enumeration).
        ok = verify_password(password or "", row["pw_hash"] if row else _DUMMY_HASH)
        if not row or not ok:
            raise AuthError("invalid username or password")
        if row.get("disabled"):
            raise AuthError("account is disabled")
        return User.from_row(row)

    async def login(self, username: str, password: str) -> tuple[str, User]:
        """Authenticate and mint a login token. Returns (token, user)."""
        user = await self.authenticate(username, password)
        token = secrets.token_urlsafe(32)
        await self.db.create_token(token, user.id, time.time() + TOKEN_TTL)
        return token, user

    async def resolve(self, token: str | None) -> User | None:
        """Resolve a login token to its (enabled) User, or None if missing/expired/revoked."""
        if not token:
            return None
        row = await self.db.get_token(token)
        if not row:
            return None
        if row["expires_at"] < time.time():
            await self.db.delete_token(token)
            return None
        urow = await self.db.get_user(row["user_id"])
        if not urow or urow.get("disabled"):
            return None
        return User.from_row(urow)

    async def logout(self, token: str | None) -> None:
        if token:
            await self.db.delete_token(token)
