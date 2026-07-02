"""SQLite persistence for sessions, messages, findings, costs, and plans.

Uses the stdlib sqlite3 driver from a thread executor so calls don't block the
event loop. Each session row stores config + plan + cost as JSON blobs."""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from . import config


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT,
    target TEXT,
    instructions TEXT,
    status TEXT,
    config_json TEXT,
    plan_json TEXT,
    cost_json TEXT,
    owner TEXT,
    created_at REAL,
    updated_at REAL
);
-- Multi-user auth. A `user` is an operator account; exactly one bootstrap `admin`
-- manages the rest. `auth_sessions` are login tokens (named so as not to clash with
-- the pentest Session). Isolation is enforced server-side via sessions.owner.
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    pw_hash TEXT,
    role TEXT,
    disabled INTEGER DEFAULT 0,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT,
    created_at REAL,
    expires_at REAL
);
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    parent_id TEXT,
    role TEXT,
    name TEXT,
    task TEXT,
    status TEXT,
    result TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    agent_id TEXT,
    role TEXT,
    content_json TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    agent_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT,
    data_json TEXT,
    created_at REAL
);
"""


class Database:
    """Thin async wrapper over a single SQLite connection. Every call runs in a thread
    (``_run``) behind an async lock so DB I/O never blocks the event loop. Tables are
    created from ``_SCHEMA`` on construction. Add a column/table by editing ``_SCHEMA``
    and the relevant upsert below."""

    def __init__(self, path: Path | str = config.DB_FILE) -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = asyncio.Lock()
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Add columns introduced after a DB was first created. ``CREATE TABLE IF NOT
        EXISTS`` never alters an existing table, so bring older `sessions` tables up to
        date here. Pre-existing sessions get ``owner=NULL`` (visible to admins only)."""
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(sessions)")}
        if "owner" not in cols:
            self._conn.execute("ALTER TABLE sessions ADD COLUMN owner TEXT")

    async def _run(self, fn, *args):
        """Run a blocking sqlite function in a worker thread under the lock. All async
        public methods funnel their DB work through here."""
        async with self._lock:
            return await asyncio.to_thread(fn, *args)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass

    # ---- sessions ----
    def _upsert_session(self, row: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT INTO sessions (id,name,target,instructions,status,config_json,
               plan_json,cost_json,owner,created_at,updated_at)
               VALUES (:id,:name,:target,:instructions,:status,:config_json,
               :plan_json,:cost_json,:owner,:created_at,:updated_at)
               ON CONFLICT(id) DO UPDATE SET name=:name,target=:target,
               instructions=:instructions,status=:status,config_json=:config_json,
               plan_json=:plan_json,cost_json=:cost_json,owner=:owner,updated_at=:updated_at""",
            row,
        )
        self._conn.commit()

    async def save_session(
        self,
        sid: str,
        name: str,
        target: str,
        instructions: str,
        status: str,
        cfg: dict,
        plan: dict,
        cost: dict,
        owner: str | None = None,
    ) -> None:
        """Upsert the session row (config/plan/cost stored as JSON), preserving the original
        created_at. Called whenever session state changes (Session.persist). ``owner`` is the
        id of the user who created it (used for per-user isolation)."""
        now = time.time()
        existing = await self.get_session(sid)
        created = existing["created_at"] if existing else now
        await self._run(
            self._upsert_session,
            {
                "id": sid,
                "name": name,
                "target": target,
                "instructions": instructions,
                "status": status,
                "config_json": json.dumps(cfg),
                "plan_json": json.dumps(plan),
                "cost_json": json.dumps(cost),
                "owner": owner,
                "created_at": created,
                "updated_at": now,
            },
        )

    def _get_session(self, sid: str) -> dict | None:
        cur = self._conn.execute("SELECT * FROM sessions WHERE id=?", (sid,))
        r = cur.fetchone()
        return dict(r) if r else None

    async def get_session(self, sid: str) -> dict | None:
        """One session row by id (config/plan/cost still JSON-encoded), or None."""
        return await self._run(self._get_session, sid)

    def _list_sessions(self, owner: str | None) -> list[dict]:
        if owner is None:
            cur = self._conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC")
        else:
            cur = self._conn.execute(
                "SELECT * FROM sessions WHERE owner=? ORDER BY updated_at DESC", (owner,)
            )
        return [dict(r) for r in cur.fetchall()]

    async def list_sessions(self, owner: str | None = None) -> list[dict]:
        """All sessions, or only those owned by ``owner`` when given (per-user isolation;
        admins pass owner=None to see everything)."""
        return await self._run(self._list_sessions, owner)

    def _delete_session(self, sid: str) -> None:
        self._conn.execute("DELETE FROM messages WHERE session_id=?", (sid,))
        self._conn.execute("DELETE FROM findings WHERE session_id=?", (sid,))
        self._conn.execute("DELETE FROM agents WHERE session_id=?", (sid,))
        self._conn.execute("DELETE FROM sessions WHERE id=?", (sid,))
        self._conn.commit()

    async def delete_session(self, sid: str) -> None:
        """Delete a session and all its child rows (messages, findings, agents)."""
        await self._run(self._delete_session, sid)

    # ---- agents ----
    def _save_agent(self, row: dict) -> None:
        self._conn.execute(
            """INSERT INTO agents (id,session_id,parent_id,role,name,task,status,result,created_at)
               VALUES (:id,:session_id,:parent_id,:role,:name,:task,:status,:result,:created_at)
               ON CONFLICT(id) DO UPDATE SET status=:status,result=:result,task=:task""",
            row,
        )
        self._conn.commit()

    async def save_agent(self, row: dict) -> None:
        """Upsert an agent row (id/role/name/task/status/result). Lets the process tree and
        per-agent discussion be rebuilt after a restart (SessionManager.load)."""
        row.setdefault("created_at", time.time())
        await self._run(self._save_agent, row)

    def _list_agents(self, sid: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM agents WHERE session_id=? ORDER BY created_at", (sid,)
        )
        return [dict(r) for r in cur.fetchall()]

    async def list_agents(self, sid: str) -> list[dict]:
        """All agent rows for a session in creation order (rebuilds the process tree)."""
        return await self._run(self._list_agents, sid)

    # ---- messages ----
    def _add_message(self, row: dict) -> None:
        self._conn.execute(
            """INSERT INTO messages (session_id,agent_id,role,content_json,created_at)
               VALUES (:session_id,:agent_id,:role,:content_json,:created_at)""",
            row,
        )
        self._conn.commit()

    async def add_message(self, sid: str, agent_id: str, role: str, content: Any) -> None:
        """Append one item to the durable discussion feed (chat messages, tool calls/results,
        narration, skill/memory loads). ``content`` is JSON-encoded. This is what
        GET /messages replays so the conversation survives restarts."""
        await self._run(
            self._add_message,
            {
                "session_id": sid,
                "agent_id": agent_id,
                "role": role,
                "content_json": json.dumps(content),
                "created_at": time.time(),
            },
        )

    def _list_messages(self, sid: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM messages WHERE session_id=? ORDER BY id", (sid,)
        )
        out = []
        for r in cur.fetchall():
            d = dict(r)
            d["content"] = json.loads(d.pop("content_json"))
            out.append(d)
        return out

    async def list_messages(self, sid: str) -> list[dict]:
        """The full discussion feed for a session in insertion order, content JSON-decoded."""
        return await self._run(self._list_messages, sid)

    # ---- findings ----
    def _save_finding(self, row: dict) -> None:
        self._conn.execute(
            """INSERT INTO findings (id,session_id,agent_id,title,severity,status,data_json,created_at)
               VALUES (:id,:session_id,:agent_id,:title,:severity,:status,:data_json,:created_at)
               ON CONFLICT(id) DO UPDATE SET title=:title,severity=:severity,
               status=:status,data_json=:data_json""",
            row,
        )
        self._conn.commit()

    async def save_finding(self, row: dict) -> None:
        """Upsert a finding row (data stored as JSON). Mirrors the in-memory + file copies
        kept by Session.add_finding."""
        row.setdefault("created_at", time.time())
        await self._run(self._save_finding, row)

    def _list_findings(self, sid: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM findings WHERE session_id=? ORDER BY created_at", (sid,)
        )
        out = []
        for r in cur.fetchall():
            d = dict(r)
            d["data"] = json.loads(d.pop("data_json") or "{}")
            out.append(d)
        return out

    async def list_findings(self, sid: str) -> list[dict]:
        """All findings for a session in creation order, each with its `data` JSON-decoded."""
        return await self._run(self._list_findings, sid)

    # ---- users (multi-user auth) ----
    def _create_user(self, row: dict) -> None:
        self._conn.execute(
            """INSERT INTO users (id,username,pw_hash,role,disabled,created_at)
               VALUES (:id,:username,:pw_hash,:role,:disabled,:created_at)""",
            row,
        )
        self._conn.commit()

    async def create_user(self, row: dict) -> None:
        """Insert a user row. Raises sqlite3.IntegrityError if the username is taken."""
        row.setdefault("disabled", 0)
        row.setdefault("created_at", time.time())
        await self._run(self._create_user, row)

    def _get_user(self, uid: str) -> dict | None:
        r = self._conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return dict(r) if r else None

    async def get_user(self, uid: str) -> dict | None:
        """One user row by id (includes pw_hash / role / disabled), or None."""
        return await self._run(self._get_user, uid)

    def _get_user_by_username(self, username: str) -> dict | None:
        r = self._conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None

    async def get_user_by_username(self, username: str) -> dict | None:
        """One user row by (unique) username — used at login, or None."""
        return await self._run(self._get_user_by_username, username)

    def _list_users(self) -> list[dict]:
        cur = self._conn.execute("SELECT * FROM users ORDER BY created_at")
        return [dict(r) for r in cur.fetchall()]

    async def list_users(self) -> list[dict]:
        """All user rows in creation order (for Settings → Users)."""
        return await self._run(self._list_users)

    def _count_admins(self) -> int:
        r = self._conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role='admin' AND disabled=0"
        ).fetchone()
        return int(r["n"])

    async def count_admins(self) -> int:
        """Number of enabled admin accounts — guards against deleting/demoting the last admin."""
        return await self._run(self._count_admins)

    # Columns an update may touch. The SET clause is built from the caller's dict KEYS (the VALUES are
    # always bound params), so restricting the keys to this allow-list keeps that interpolation safe
    # even if a future caller were to pass an unexpected/attacker-influenced field name.
    _USER_UPDATE_COLS = {"username", "pw_hash", "role", "disabled"}

    def _update_user(self, uid: str, fields: dict) -> None:
        bad = set(fields) - self._USER_UPDATE_COLS
        if bad:
            raise ValueError(f"cannot update user column(s): {', '.join(sorted(bad))}")
        sets = ", ".join(f"{k}=:{k}" for k in fields)
        self._conn.execute(f"UPDATE users SET {sets} WHERE id=:id", {**fields, "id": uid})
        self._conn.commit()

    async def update_user(self, uid: str, fields: dict) -> None:
        """Patch selected columns (pw_hash / role / disabled) of one user."""
        await self._run(self._update_user, uid, fields)

    def _delete_user(self, uid: str) -> None:
        self._conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (uid,))
        self._conn.execute("DELETE FROM users WHERE id=?", (uid,))
        self._conn.commit()

    async def delete_user(self, uid: str) -> None:
        """Delete a user and revoke all of their login tokens. Their pentest sessions
        remain (owner unchanged) and become visible to admins only."""
        await self._run(self._delete_user, uid)

    # ---- auth_sessions (login tokens) ----
    def _create_token(self, row: dict) -> None:
        self._conn.execute(
            "INSERT INTO auth_sessions (token,user_id,created_at,expires_at) "
            "VALUES (:token,:user_id,:created_at,:expires_at)",
            row,
        )
        self._conn.commit()

    async def create_token(self, token: str, user_id: str, expires_at: float) -> None:
        """Store a login token for a user with its expiry (set in the cookie at login)."""
        await self._run(self._create_token, {
            "token": token, "user_id": user_id,
            "created_at": time.time(), "expires_at": expires_at,
        })

    def _get_token(self, token: str) -> dict | None:
        r = self._conn.execute("SELECT * FROM auth_sessions WHERE token=?", (token,)).fetchone()
        return dict(r) if r else None

    async def get_token(self, token: str) -> dict | None:
        """Look up a login token (to resolve the cookie to a user), or None."""
        return await self._run(self._get_token, token)

    def _delete_token(self, token: str) -> None:
        self._conn.execute("DELETE FROM auth_sessions WHERE token=?", (token,))
        self._conn.commit()

    async def delete_token(self, token: str) -> None:
        """Revoke a single login token (logout)."""
        await self._run(self._delete_token, token)

    def _purge_expired_tokens(self, now: float) -> None:
        self._conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
        self._conn.commit()

    async def purge_expired_tokens(self) -> None:
        """Delete all login tokens whose expiry has passed (housekeeping)."""
        await self._run(self._purge_expired_tokens, time.time())
