"""FastAPI application: REST API, live WebSocket event stream, and static UI."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from copy import deepcopy

from fastapi import (
    Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, WebSocket, WebSocketDisconnect,
)
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth as auth_mod
from . import config as cfg_mod
from .auth import Auth, AuthError, User
from .events import bus
from .session import SessionManager

STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title="SPAIDER", version="0.1.0")
manager = SessionManager()
auth = Auth(manager.db)

# /api paths that do NOT require a logged-in user (the login/bootstrap surface). Everything
# else under /api is gated by the auth middleware below. Static assets and the SPA shell are
# always served so the login screen can load.
PUBLIC_API_PATHS = {
    "/api/health", "/api/auth/status", "/api/auth/login",
    "/api/auth/setup", "/api/auth/logout",
}


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    """Authenticate every /api request from the login-token cookie and stash the resolved
    user on ``request.state.user``. Non-public /api paths require a valid user — this is the
    server-side enforcement point for multi-user access (the UI is never trusted)."""
    request.state.user = None
    path = request.url.path
    if path.startswith("/api/"):
        request.state.user = await auth.resolve(request.cookies.get(auth_mod.COOKIE_NAME))
        if path not in PUBLIC_API_PATHS and request.state.user is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
    return await call_next(request)


@app.middleware("http")
async def _no_cache_ui(request, call_next):
    """Serve the UI and static assets with no-cache so edits always show up
    (this is a local dev tool — browsers otherwise cache app.js/style.css)."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# --------------------------------------------------------------------------- #
# Auth dependencies & helpers
# --------------------------------------------------------------------------- #
def current_user(request: Request) -> User:
    """The authenticated user for this request (set by the auth middleware)."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(401, "authentication required")
    return user


def require_admin(request: Request) -> User:
    """Like current_user but rejects non-admins (403). Gates user-management and all
    global-config writes."""
    user = current_user(request)
    if not user.is_admin:
        raise HTTPException(403, "administrator privileges required")
    return user


# --------------------------------------------------------------------------- #
# Access control (custom roles + read grants). The built-in `admin` role has every
# capability; other accounts get the capabilities of their assigned role in
# cfg["user_roles"], plus read access to the sessions granted in cfg["session_grants"].
# --------------------------------------------------------------------------- #
def _role_caps(role: str, cfg: dict | None = None) -> dict:
    """Capability map for a role name. Admin = all caps; otherwise the role's entry in
    ``cfg["user_roles"]`` (falling back to the `user` profile, then nothing)."""
    if role == "admin":
        return {c: True for c in cfg_mod.PERMISSION_CAPS}
    roles = ((cfg or cfg_mod.load_config()).get("user_roles") or {})
    return roles.get(role) or roles.get("user") or {}


def _can(user: User, cap: str, session=None, cfg: dict | None = None) -> bool:
    """Whether `user` has capability `cap`. For `edit_session`, only the session OWNER (with the
    cap) or an admin qualifies — granted read-only viewers never rename."""
    if user.is_admin:
        return True
    caps = _role_caps(user.role, cfg)
    if cap == "edit_session" and session is not None and getattr(session, "owner", None) != user.id:
        return False
    # Merged pentest right (SEPARATE_PENTEST off, the default): launch_pentest and free_target_choice
    # are the same capability — holding EITHER grants both, so every pentester gets free target choice.
    if cap in ("launch_pentest", "free_target_choice") and not _separate_pentest():
        return bool(caps.get("launch_pentest") or caps.get("free_target_choice"))
    return bool(caps.get(cap))


def _can_view_session(user: User, summary_or_session, cfg: dict | None = None) -> bool:
    """Whether `user` may VIEW a session: their own, any (admin), or one granted to a `read`-capable
    account via cfg["session_grants"]. Accepts a Session object or a list summary dict."""
    owner = summary_or_session.get("owner") if isinstance(summary_or_session, dict) else getattr(summary_or_session, "owner", None)
    sid = summary_or_session.get("id") if isinstance(summary_or_session, dict) else getattr(summary_or_session, "id", None)
    if user.is_admin or owner == user.id:
        return True
    cfg = cfg or cfg_mod.load_config()
    if not _role_caps(user.role, cfg).get("read"):
        return False
    for g in (cfg.get("session_grants") or {}).get(user.id, []):
        if g.get("owner") == owner:
            allowed = g.get("sessions") or []
            if "*" in allowed or sid in allowed:
                return True
    return False


def _secure_cookies() -> bool:
    """Whether to mark the login cookie ``Secure`` (only sent over HTTPS). Off by default so the
    local-http dev workflow keeps working; set ``SPAIDER_SECURE_COOKIES=1`` for an HTTPS/prod
    deployment so the session token is never transmitted in cleartext."""
    return os.environ.get("SPAIDER_SECURE_COOKIES", "").strip().lower() in {"1", "true", "yes", "on"}


def _set_login_cookie(response: Response, token: str) -> None:
    """Attach the login-token cookie: HttpOnly so JS can't read it, SameSite=Lax, and Secure when
    ``SPAIDER_SECURE_COOKIES`` is set (enable it behind HTTPS in production)."""
    response.set_cookie(
        auth_mod.COOKIE_NAME, token, httponly=True, samesite="lax", secure=_secure_cookies(),
        max_age=auth_mod.TOKEN_TTL, path="/",
    )


# --------------------------------------------------------------------------- #
# Login rate limiting — slow down online credential brute-forcing. In-memory, per
# (client-IP + username): after _LOGIN_MAX failures within _LOGIN_WINDOW seconds the key is locked
# out until the window rolls off. A successful login clears the counter. Bounded so it can't grow
# unboundedly. Not a substitute for a WAF, but closes the "unlimited guesses" hole for a prod deploy.
# --------------------------------------------------------------------------- #
import time as _time  # noqa: E402

_LOGIN_MAX = 8
_LOGIN_WINDOW = 300.0
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}


def _login_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "?"
    return f"{ip}|{(username or '').strip().lower()}"


def _login_recent(key: str) -> list[float]:
    now = _time.time()
    hits = [t for t in _LOGIN_ATTEMPTS.get(key, []) if now - t < _LOGIN_WINDOW]
    if hits:
        _LOGIN_ATTEMPTS[key] = hits
    else:
        _LOGIN_ATTEMPTS.pop(key, None)
    return hits


def _login_throttled(key: str) -> bool:
    return len(_login_recent(key)) >= _LOGIN_MAX


def _login_record_fail(key: str) -> None:
    _LOGIN_ATTEMPTS.setdefault(key, []).append(_time.time())
    # Opportunistic bound: if the table grows large, drop keys with no recent activity.
    if len(_LOGIN_ATTEMPTS) > 4096:
        for k in list(_LOGIN_ATTEMPTS):
            _login_recent(k)


def _login_reset(key: str) -> None:
    _LOGIN_ATTEMPTS.pop(key, None)


def _sanitize_config(cfg: dict) -> dict:
    """A copy of the config with secrets stripped, for non-admin callers (they need model/
    intensity defaults to run sessions, but must never receive API keys)."""
    c = deepcopy(cfg)
    for mc in (c.get("models") or {}).values():
        if isinstance(mc, dict):
            mc["api_key"] = ""
    if isinstance(c.get("kali"), dict):
        c["kali"]["token"] = ""   # the Kali bearer token is a secret too
    for pk in ("client_proxy", "kali_proxy"):
        if isinstance(c.get(pk), dict) and c[pk].get("url"):
            c[pk]["url"] = ""     # the proxy URL embeds id:password credentials (admin-only)
    # Top-level session MCP servers may carry credentials in their env / headers / auth blocks.
    if isinstance(c.get("mcp_servers"), dict):
        for s in c["mcp_servers"].values():
            if isinstance(s, dict):
                for secret_block in ("env", "headers", "auth"):
                    if isinstance(s.get(secret_block), dict):
                        s[secret_block] = {k: "" for k in s[secret_block]}
    c["session_grants"] = {}      # who-can-read-whose-sessions is an admin-only mapping
    return c


# The full-error renderer lives in llm.py (shared with the agent loop, so a live LLM failure
# surfaces the same complete detail in chat). Kept under the original name for the call sites here.
from .llm import format_llm_error as _full_error  # noqa: E402


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class CreateSession(BaseModel):
    name: str = ""
    config: dict[str, Any] | None = None


class RenameSession(BaseModel):
    name: str


class SetOwner(BaseModel):
    # Target user id to reassign the session to. Blank = the requesting admin ("take ownership").
    owner: str = ""


class StartSession(BaseModel):
    target: str
    instructions: str = ""
    # Optional session name dictated by the target-provider script (hidden picker flow). Applied
    # server-side as part of starting the engagement, so a LIMITED operator (launch_pentest but no
    # edit_session) still gets the script's name — the name isn't user-chosen, the script picks it.
    name: str = ""


class ResumeSession(BaseModel):
    instructions: str = ""


class ApprovalDecision(BaseModel):
    approved: bool
    reason: str = ""


class AgentMessage(BaseModel):
    message: str


class AgentDefUpdate(BaseModel):
    prompt: str | None = None
    mcp: str | None = None


class McpAdd(BaseModel):
    name: str = ""
    config: str


class McpToggle(BaseModel):
    enabled: bool


class AddRole(BaseModel):
    role: str
    system: str = ""
    tools: list[str] = []


class UserAnswer(BaseModel):
    answer: str = ""


class ReportRequest(BaseModel):
    instructions: str = ""
    template: str = ""


class PresetBody(BaseModel):
    params: dict[str, Any]


class KaliTest(BaseModel):
    # Optional URL/token to test; when omitted the saved cfg["kali"] values are used. Lets the
    # operator test the values typed in Settings before saving them. ``token`` may be the
    # sentinel "\x00keep" to mean "use the saved token" (so a masked field needn't round-trip it).
    url: str = ""
    token: str = "\x00keep"


class LLMTest(BaseModel):
    # Which role's model to test, plus optional unsaved model-config overrides from the UI. A blank
    # api_key in ``params`` is ignored so the saved key is used (the UI needn't echo the secret).
    role: str = "orchestrator"
    params: dict[str, Any] | None = None


# ---- SPAIDER human-in-the-loop request models ----
class PlanDecision(BaseModel):
    decision: str = "approve"          # approve | reject | edit
    feedback: str = ""                 # operator notes (esp. for reject/edit)
    steps: list[str] | None = None     # replacement steps when decision == "edit"


class Interjection(BaseModel):
    message: str


class IntensityBody(BaseModel):
    intensity: str


class ApprovalModeBody(BaseModel):
    mode: str   # "manual" (use policy) | "auto" (bypass all tool approval for this session)


class KillProcessBody(BaseModel):
    message: str = ""   # operator's explanation, delivered to the agent that launched the process


# ---- Auth / user-management request models ----
class Credentials(BaseModel):
    username: str
    password: str


class CreateUser(BaseModel):
    username: str
    password: str
    role: str = "user"


class PasswordReset(BaseModel):
    password: str


class DisableBody(BaseModel):
    disabled: bool


class SetRole(BaseModel):
    role: str


# --------------------------------------------------------------------------- #
# Authentication (login / first-run setup / logout) and user management
# --------------------------------------------------------------------------- #
def _disclaimer_required() -> bool:
    """HIDDEN feature flag: when the ``SPAIDER_REQUIRE_DISCLAIMER`` environment variable is set to a
    truthy value (1/true/yes/on), the UI forces the operator to read and accept a risk/responsibility
    disclaimer before starting an engagement or bypassing the approval gate. Off (and invisible) by
    default; read per-request so it can be toggled without restarting. Surfaced to the client via
    ``/api/auth/status`` (which the SPA fetches on load)."""
    return os.environ.get("SPAIDER_REQUIRE_DISCLAIMER", "").strip().lower() in {"1", "true", "yes", "on"}


def _separate_pentest() -> bool:
    """HIDDEN flag (``SEPARATE_PENTEST``, default 0/off): when OFF the ``launch_pentest`` and
    ``free_target_choice`` capabilities are MERGED into a single pentest right — anyone who can run a
    pentest gets free target choice, and ``launch_pentest`` is hidden in the access-roles UI. When ON
    the two are distinct (limited vs. free), the original behaviour. Read per-request; undocumented."""
    return os.environ.get("SEPARATE_PENTEST", "").strip().lower() in {"1", "true", "yes", "on"}


def _load_targets() -> tuple[list[dict], str]:
    """Run the operator's target-provider script (``target_providers/targets.py: list_targets()``)
    and normalise the result to a list of {id,name,target,instructions,session_name}. Loaded fresh
    each call so edits apply without a restart. Returns ``(targets, error)``; never raises."""
    import importlib.util

    path = Path(__file__).resolve().parent.parent / "target_providers" / "targets.py"
    if not path.is_file():
        return [], f"target provider not found: {path}"
    try:
        spec = importlib.util.spec_from_file_location("spaider_targets", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        raw = mod.list_targets()
    except Exception as e:  # noqa: BLE001 — operator script: surface the error, don't crash
        return [], f"target provider failed: {type(e).__name__}: {e}"
    out: list[dict] = []
    for i, t in enumerate(raw or []):
        if not isinstance(t, dict):
            continue
        target = str(t.get("target") or "").strip()
        if not target:
            continue
        out.append({
            "id": str(t.get("id") or t.get("name") or target or i),
            "name": str(t.get("name") or target),
            "target": target,
            "instructions": str(t.get("instructions") or ""),
            "session_name": str(t.get("session_name") or ""),
        })
    return out, ""


@app.get("/api/targets")
async def list_targets_ep(user: User = Depends(current_user)) -> dict:
    """Targets to offer the operator at the start of every engagement (the target picker is always
    on). `free` reflects the caller's `free_target_choice` capability (free = may also enter a target
    manually / edit the session name)."""
    if not _can(user, "launch_pentest"):
        raise HTTPException(403, "you don't have permission to run pentests")
    targets, error = _load_targets()
    return {"enabled": True, "free": _can(user, "free_target_choice"), "targets": targets, "error": error}


@app.get("/api/auth/status")
async def auth_status(request: Request) -> dict:
    """Drives the UI's auth gate: whether the caller is logged in, and whether this is a
    fresh install with no users yet (-> show the 'create administrator' screen). Also carries the
    hidden ``disclaimer`` flag, the caller's access **capabilities** (so the SPA can hide controls
    it isn't allowed to use), and ``separate_pentest`` (whether the launch/free-target rights are
    distinct or merged). The target picker is always on (``target_picker`` kept for the SPA)."""
    user = getattr(request.state, "user", None)
    caps = {}
    if user is not None:
        caps = {c: _can(user, c) for c in cfg_mod.PERMISSION_CAPS}
    return {
        "authenticated": user is not None,
        "needs_setup": await auth.needs_setup(),
        "user": user.public() if user else None,
        "is_admin": bool(user and user.is_admin),
        "caps": caps,
        "disclaimer": _disclaimer_required(),
        "target_picker": True,
        "separate_pentest": _separate_pentest(),
    }


@app.post("/api/auth/setup")
async def auth_setup(body: Credentials, response: Response) -> dict:
    """First-run bootstrap: create the initial admin account (only works when no users exist)
    and immediately log them in."""
    try:
        user = await auth.create_first_admin(body.username, body.password)
        token, _ = await auth.login(body.username, body.password)
    except AuthError as e:
        raise HTTPException(400, str(e))
    _set_login_cookie(response, token)
    return {"ok": True, "user": user.public()}


@app.post("/api/auth/login")
async def auth_login(body: Credentials, request: Request, response: Response) -> dict:
    key = _login_key(request, body.username)
    if _login_throttled(key):
        raise HTTPException(429, "too many failed login attempts — wait a few minutes and try again")
    try:
        token, user = await auth.login(body.username, body.password)
    except AuthError as e:
        _login_record_fail(key)
        raise HTTPException(401, str(e))
    _login_reset(key)
    _set_login_cookie(response, token)
    return {"ok": True, "user": user.public()}


@app.post("/api/auth/logout")
async def auth_logout(request: Request, response: Response) -> dict:
    await auth.logout(request.cookies.get(auth_mod.COOKIE_NAME))
    response.delete_cookie(auth_mod.COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/users")
async def list_users(admin: User = Depends(require_admin)) -> list[dict]:
    return await auth.list_users()


def _valid_role(role: str, cfg: dict | None = None) -> bool:
    """A role name is valid if it is the built-in `admin` or a custom role defined in the config."""
    role = (role or "").strip()
    return role == "admin" or role in ((cfg or cfg_mod.load_config()).get("user_roles") or {})


@app.post("/api/users")
async def create_user_ep(body: CreateUser, admin: User = Depends(require_admin)) -> dict:
    if not _valid_role(body.role):
        raise HTTPException(400, f"unknown role '{body.role}'")
    try:
        user = await auth.create_user(body.username, body.password, body.role)
    except AuthError as e:
        raise HTTPException(400, str(e))
    return user.public()


@app.post("/api/users/{uid}/role")
async def set_role_ep(uid: str, body: SetRole, admin: User = Depends(require_admin)) -> dict:
    """Assign an access role (admin or a custom role) to a user."""
    if not _valid_role(body.role):
        raise HTTPException(400, f"unknown role '{body.role}'")
    if uid == admin.id and body.role != "admin":
        raise HTTPException(400, "you cannot remove your own administrator role")
    try:
        await auth.set_role(uid, body.role)
    except AuthError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.delete("/api/users/{uid}")
async def delete_user_ep(uid: str, admin: User = Depends(require_admin)) -> dict:
    if uid == admin.id:
        raise HTTPException(400, "you cannot delete your own account")
    try:
        await auth.delete_user(uid)
    except AuthError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/users/{uid}/password")
async def reset_password_ep(uid: str, body: PasswordReset, admin: User = Depends(require_admin)) -> dict:
    try:
        await auth.set_password(uid, body.password)
    except AuthError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/api/users/{uid}/disable")
async def disable_user_ep(uid: str, body: DisableBody, admin: User = Depends(require_admin)) -> dict:
    if uid == admin.id and body.disabled:
        raise HTTPException(400, "you cannot disable your own account")
    try:
        await auth.set_disabled(uid, body.disabled)
    except AuthError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "version": "0.1.0"}


@app.get("/api/config")
async def get_config(user: User = Depends(current_user)) -> dict:
    """Full config for admins; secret-stripped copy for regular users (they still need
    model/intensity defaults to run a session, but never the API keys)."""
    cfg = cfg_mod.load_config()
    return cfg if user.is_admin else _sanitize_config(cfg)


@app.put("/api/config")
async def put_config(cfg: dict, admin: User = Depends(require_admin)) -> dict:
    cfg_mod.save_config(cfg)
    return {"ok": True}


@app.post("/api/config/kali/test")
async def test_kali(body: KaliTest, admin: User = Depends(require_admin)) -> dict:
    """Probe the Kali offensive-tool MCP server and report whether it is reachable.

    Opens a throwaway MCP-over-HTTP client against ``body.url`` (or, when blank, the saved
    ``cfg['kali']['url']``), runs the initialize + tools/list handshake, then closes it. This
    is the Settings → Kali 'Test connection' button — it lets the operator confirm the URL and
    that the container is up before starting an engagement. Returns
    ``{ok, url, tools, count, error}``: on success the discovered tool names (e.g. nmap_scan,
    sqlmap_scan, hydra_bruteforce); on failure a human-readable reason."""
    from .tools.mcp import MCPClient

    cfg = cfg_mod.load_config()
    kali = cfg.get("kali", {}) or {}
    url = (body.url or "").strip() or kali.get("url", "")
    # "\x00keep" => use the saved token (the UI needn't echo a secret back); else use what's posted.
    token = kali.get("token", "") if body.token == "\x00keep" else (body.token or "")
    if not url:
        return {"ok": False, "url": "", "tools": [], "count": 0,
                "error": "No Kali MCP URL set — enter one (e.g. http://kali-host:8765/mcp)."}
    client = MCPClient("kali", {"transport": "http", "url": url, "token": token, "enabled": True})
    try:
        await client.connect()
        names = [t.get("name") for t in client.tools]
        return {"ok": True, "url": url, "tools": names, "count": len(names), "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "url": url, "tools": [], "count": 0,
                "error": f"{type(e).__name__}: {e}"}
    finally:
        await client.close()


@app.post("/api/config/llm/test")
async def test_llm(body: LLMTest, admin: User = Depends(require_admin)) -> dict:
    """Check that the configured LLM actually answers: build the role's model config (saved, with
    any unsaved UI overrides applied), send a one-line 'hello', and return the model's reply.

    Routes through the client proxy when one is enabled, so this also validates the proxy path.
    Returns ``{ok, role, model, reply, via_proxy, error}`` — the Settings → Models 'Test' button."""
    from .llm import make_provider

    cfg = cfg_mod.load_config()
    role = body.role or "orchestrator"
    mc = deepcopy(cfg["models"].get(role) or cfg["models"].get("orchestrator") or {})
    for k, v in (body.params or {}).items():
        if k == "api_key" and not (v and str(v).strip()):
            continue   # keep the saved key when the UI sends a blank/masked field
        mc[k] = v
    mc["_client_proxy"] = cfg.get("client_proxy")
    via_proxy = bool((cfg.get("client_proxy") or {}).get("enabled")
                     and (cfg.get("client_proxy") or {}).get("url"))
    model = mc.get("model", "")
    try:
        provider = make_provider(mc)
        resp = await provider.complete(
            "You are a connectivity check for the SPAIDER pentest tool. Reply with one short, friendly sentence.",
            [{"role": "user", "content": [{"type": "text",
              "text": "Hello! This is a connection test from SPAIDER — please reply with a brief greeting."}]}],
            [],
        )
        reply = (resp.text or "").strip()
        if not reply:
            return {"ok": False, "role": role, "model": model, "reply": "", "via_proxy": via_proxy,
                    "error": "Connected, but the model returned an empty reply."}
        return {"ok": True, "role": role, "model": model, "reply": reply[:500],
                "via_proxy": via_proxy, "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "role": role, "model": model, "reply": "", "via_proxy": via_proxy,
                "error": _full_error(e)}


@app.get("/api/tools")
async def list_tools() -> list[dict]:
    """Metadata for every internal tool (for the Settings 'Internal tools' view)."""
    from .tools import tool_catalog

    return tool_catalog()


# --------------------------------------------------------------------------- #
# Model parameter presets
# --------------------------------------------------------------------------- #
@app.get("/api/presets")
async def get_presets(admin: User = Depends(require_admin)) -> dict:
    # SECURITY: presets snapshot a full model config and can embed api_key, so they are admin-only
    # (the Settings UI that uses them is admin-only anyway).
    from . import presets

    return presets.load_presets()


@app.put("/api/presets/{name}")
async def put_preset(name: str, body: PresetBody, admin: User = Depends(require_admin)) -> dict:
    from . import presets

    try:
        return presets.upsert_preset(name, body.params)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.delete("/api/presets/{name}")
async def remove_preset(name: str, admin: User = Depends(require_admin)) -> dict:
    from . import presets

    return presets.delete_preset(name)


# --------------------------------------------------------------------------- #
# Agent skills (markdown playbooks edited directly in the skills/ folder)
# --------------------------------------------------------------------------- #
@app.get("/api/skills")
async def get_skills() -> dict:
    from . import skills

    return {"skills": skills.list_skills(), "master": skills.master()}


# --------------------------------------------------------------------------- #
# Modular agent definitions (system prompts + per-folder mcpo MCP config)
# --------------------------------------------------------------------------- #
# SECURITY: agent definitions carry per-agent MCP server configs whose `env` can hold third-party
# secrets (API keys/tokens), so the agentdef GETs are admin-only (they back the admin Settings UI).
@app.get("/api/agentdefs")
async def list_agentdefs(admin: User = Depends(require_admin)) -> list[dict]:
    from . import agentdefs, registry

    cfg = cfg_mod.load_config()
    agentdefs.ensure_scaffold(cfg)
    return [agentdefs.raw_def(cfg, role) for role in registry.role_specs(cfg)]


@app.get("/api/agentdefs/{role}")
async def get_agentdef(role: str, admin: User = Depends(require_admin)) -> dict:
    from . import agentdefs, registry

    cfg = cfg_mod.load_config()
    if role not in registry.role_specs(cfg):
        raise HTTPException(404, "unknown role")
    agentdefs.ensure_scaffold(cfg)
    return agentdefs.raw_def(cfg, role)


@app.put("/api/agentdefs/{role}")
async def put_agentdef(role: str, body: AgentDefUpdate, admin: User = Depends(require_admin)) -> dict:
    import json

    from . import agentdefs, registry

    cfg = cfg_mod.load_config()
    if role not in registry.role_specs(cfg):
        raise HTTPException(404, "unknown role")
    try:
        agentdefs.save_def(cfg, role, body.prompt, body.mcp)
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"invalid mcp.json: {e}")
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"ok": True}


# ---- per-agent MCP server management ----
@app.get("/api/agentdefs/{role}/mcp")
async def list_agent_mcp(role: str, admin: User = Depends(require_admin)) -> list[dict]:
    from . import agentdefs

    cfg = cfg_mod.load_config()
    agentdefs.ensure_scaffold(cfg)
    return agentdefs.list_mcp(cfg, role)


@app.post("/api/agentdefs/{role}/mcp")
async def add_agent_mcp(role: str, body: McpAdd, admin: User = Depends(require_admin)) -> list[dict]:
    import json as _json

    from . import agentdefs

    cfg = cfg_mod.load_config()
    try:
        agentdefs.add_mcp(cfg, role, body.name.strip(), body.config)
    except _json.JSONDecodeError as e:
        raise HTTPException(400, f"invalid JSON: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return agentdefs.list_mcp(cfg, role)


@app.delete("/api/agentdefs/{role}/mcp/{name}")
async def delete_agent_mcp(role: str, name: str, admin: User = Depends(require_admin)) -> list[dict]:
    from . import agentdefs

    cfg = cfg_mod.load_config()
    agentdefs.remove_mcp(cfg, role, name)
    return agentdefs.list_mcp(cfg, role)


@app.post("/api/agentdefs/{role}/mcp/{name}/toggle")
async def toggle_agent_mcp(role: str, name: str, body: McpToggle, admin: User = Depends(require_admin)) -> list[dict]:
    from . import agentdefs

    cfg = cfg_mod.load_config()
    agentdefs.set_mcp_enabled(cfg, role, name, body.enabled)
    return agentdefs.list_mcp(cfg, role)


@app.post("/api/agentdefs/{role}/mcp/{name}/test")
async def test_agent_mcp(role: str, name: str, admin: User = Depends(require_admin)) -> dict:
    from . import agentdefs
    from .tools.mcp import MCPClient

    cfg = cfg_mod.load_config()
    sdef = agentdefs.get_mcp_normalized(cfg, role, name)
    if not sdef:
        raise HTTPException(404, "no such server")
    client = MCPClient(name, sdef)
    try:
        await client.connect()
        return {"ok": True, "tools": [t.get("name") for t in client.tools], "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "tools": [], "error": str(e)}
    finally:
        await client.close()


# ---- custom agents (roles) ----
@app.get("/api/roles")
async def list_roles() -> dict:
    from . import registry

    cfg = cfg_mod.load_config()
    return {"roles": registry.role_specs(cfg), "available_tools": registry.all_tool_names()}


@app.post("/api/roles")
async def add_role(body: AddRole, admin: User = Depends(require_admin)) -> dict:
    from . import config as _cfg
    from . import registry

    cfg = cfg_mod.load_config()
    try:
        registry.add_custom_role(cfg, body.role, body.system, body.tools)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # Give the new role a default model config so it appears in Settings and runs.
    role = body.role.strip().lower()
    cfg.setdefault("models", {})
    if role not in cfg["models"]:
        cfg["models"][role] = _cfg._default_model_config(role)
        cfg_mod.save_config(cfg)
    return {"ok": True, "role": role}


@app.delete("/api/roles/{role}")
async def delete_role(role: str, admin: User = Depends(require_admin)) -> dict:
    from . import registry

    cfg = cfg_mod.load_config()
    try:
        registry.remove_custom_role(cfg, role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if role in cfg.get("models", {}):
        del cfg["models"][role]
        cfg_mod.save_config(cfg)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #
@app.get("/api/sessions")
async def list_sessions(user: User = Depends(current_user)) -> list[dict]:
    """Sessions the caller may see: their own, everything for an admin, plus any other user's
    sessions a `read`-capable account has been granted (cfg["session_grants"])."""
    if user.is_admin:
        return await manager.list_all(owner=None)
    everything = await manager.list_all(owner=None)
    cfg = cfg_mod.load_config()
    return [s for s in everything if _can_view_session(user, s, cfg)]


def _session_config_for(user: User, override: dict | None) -> dict:
    """The config a new session runs under. SECURITY: only an admin may supply a per-session config
    override — a caller-supplied config could otherwise re-enable host command execution
    (poc_execution="host"), point the LLM at an attacker base_url/api_key, or repoint the Kali/proxy
    endpoints, bypassing the admin-only global-config gate. Everyone else runs the saved config."""
    return override if (override and user.is_admin) else cfg_mod.load_config()


@app.post("/api/sessions")
async def create_session(body: CreateSession, user: User = Depends(current_user)) -> dict:
    cfg = _session_config_for(user, body.config)
    session = manager.create(body.name, cfg, owner=user.id)
    await session.persist()
    return session.to_dict()


async def _require(sid: str, user: User):
    """Load a session and enforce WRITE access (owner or admin). Returns 404 (not 403) for sessions
    the caller can't act on, so the API never reveals that another user's session id exists. Used by
    every mutating endpoint — granted read-only viewers cannot reach these."""
    session = await manager.load(sid)
    if not session:
        raise HTTPException(404, "session not found")
    if not user.is_admin and session.owner != user.id:
        raise HTTPException(404, "session not found")
    return session


async def _require_view(sid: str, user: User):
    """Load a session for READ access: the owner, an admin, or a `read`-capable account granted this
    session. Used by the view/live endpoints so a reader can watch but never mutate."""
    session = await manager.load(sid)
    if not session or not _can_view_session(user, session):
        raise HTTPException(404, "session not found")
    return session


@app.get("/api/sessions/{sid}")
async def get_session(sid: str, user: User = Depends(current_user)) -> dict:
    session = await _require_view(sid, user)
    return session.to_dict()


@app.delete("/api/sessions/{sid}")
async def delete_session(sid: str, user: User = Depends(current_user)) -> dict:
    await _require(sid, user)  # ownership check before destroying anything
    await manager.delete(sid)
    return {"ok": True}


@app.post("/api/sessions/{sid}/rename")
async def rename_session(sid: str, body: RenameSession, user: User = Depends(current_user)) -> dict:
    """Rename a session at any point in its lifecycle (the name is a pure label — everything is keyed
    by the session id). Requires the `edit_session` capability (admins and the owner always have it)."""
    session = await _require(sid, user)
    if not _can(user, "edit_session", session):
        raise HTTPException(403, "you don't have permission to rename this session")
    try:
        await session.rename(body.name)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return session.to_dict()


@app.post("/api/sessions/{sid}/owner")
async def take_session_ownership(sid: str, body: SetOwner, admin: User = Depends(require_admin)) -> dict:
    """Reassign a session's owner (admin-only). With no body it transfers the session to the
    requesting admin ("take ownership"); an explicit `owner` (a valid user id) reassigns it to that
    user. The session then belongs to the new owner for isolation and the session list."""
    session = await manager.load(sid)
    if not session:
        raise HTTPException(404, "session not found")
    new_owner = (body.owner or admin.id).strip()
    if new_owner != admin.id and not await manager.db.get_user(new_owner):
        raise HTTPException(404, "no such user")
    await session.set_owner(new_owner)
    return session.to_dict()


@app.post("/api/sessions/{sid}/start")
async def start_session(sid: str, body: StartSession, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    if not _can(user, "launch_pentest"):
        raise HTTPException(403, "you don't have permission to run pentests")
    if session.status == "running":
        raise HTTPException(409, "session already running")
    # Apply the provider-dictated name (if any) before starting. This is the script's choice, not the
    # operator's, so it's allowed regardless of the edit_session capability (a limited operator can't
    # rename freely, but the picker's name must still take effect).
    if body.name and body.name.strip():
        try:
            await session.rename(body.name.strip())
        except ValueError:
            pass
    await session.start(body.target, body.instructions)
    return session.to_dict()


@app.post("/api/sessions/{sid}/resume")
async def resume_session(sid: str, body: ResumeSession, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    if session.status == "running":
        raise HTTPException(409, "session already running")
    await session.resume(body.instructions)
    return session.to_dict()


@app.post("/api/sessions/{sid}/stop")
async def stop_session(sid: str, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    await session.stop()
    return session.to_dict()


@app.get("/api/sessions/{sid}/agents")
async def session_agents(sid: str, user: User = Depends(current_user)) -> list[dict]:
    session = await _require_view(sid, user)
    return session.to_dict()["agents"]


@app.get("/api/sessions/{sid}/plan")
async def session_plan(sid: str, user: User = Depends(current_user)) -> dict:
    session = await _require_view(sid, user)
    return session.plan


@app.get("/api/sessions/{sid}/findings")
async def session_findings(sid: str, user: User = Depends(current_user)) -> list[dict]:
    session = await _require_view(sid, user)
    return list(session.findings.values())


@app.get("/api/sessions/{sid}/cost")
async def session_cost(sid: str, user: User = Depends(current_user)) -> dict:
    session = await _require_view(sid, user)
    return session.cost


@app.post("/api/sessions/{sid}/report")
async def session_report(sid: str, body: ReportRequest, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    return await session.generate_report(body.instructions, body.template)


@app.post("/api/sessions/{sid}/report/template")
async def report_template(sid: str, file: UploadFile = File(...), user: User = Depends(current_user)) -> dict:
    """Extract the text/structure from an uploaded report template (PDF / Word / Markdown) so the
    operator can use it for report generation. Returns the extracted text (which the report agent
    must follow exactly)."""
    from .docs import ALLOWED_EXTS, MAX_UPLOAD_BYTES, extract_text, safe_name

    await _require(sid, user)
    name = safe_name(file.filename or "")
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(400, f"unsupported template type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTS))}")
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    text, error = extract_text(data, name)
    if error and not text:
        raise HTTPException(400, error)
    return {"name": name, "chars": len(text), "text": text, "error": error}


@app.get("/api/sessions/{sid}/dashboard")
async def session_dashboard(sid: str, user: User = Depends(current_user)) -> dict:
    """Static (no-LLM) analytics for the session dashboard: a cost/token time series plus aggregate
    breakdowns (per agent, per model, findings by severity, tool usage), computed from the persisted
    event log so it works for a live OR a reopened session. The browser renders the charts and, on
    demand, the downloadable HTML/CSV/JSON report."""
    from . import dashboard as dash

    session = await _require_view(sid, user)
    return dash.compute(session)


@app.get("/api/sessions/{sid}/report/file/{name}")
async def report_file(sid: str, name: str, user: User = Depends(current_user)) -> FileResponse:
    """Download a generated report artifact (the .md or .docx) from the session's reports/ folder."""
    from .docs import safe_name

    session = await _require(sid, user)
    safe = safe_name(name)
    path = session.workspace / "reports" / safe
    if not path.is_file():
        raise HTTPException(404, "no such report file")
    return FileResponse(str(path), filename=safe)


# --------------------------------------------------------------------------- #
# Reference documents (operator attaches md/txt/pdf/docx to inform the engagement)
# --------------------------------------------------------------------------- #
@app.get("/api/sessions/{sid}/uploads")
async def list_uploads(sid: str, user: User = Depends(current_user)) -> list[dict]:
    session = await _require(sid, user)
    return session.list_uploads()


@app.post("/api/sessions/{sid}/uploads")
async def add_upload(sid: str, file: UploadFile = File(...), user: User = Depends(current_user)) -> dict:
    """Attach a reference document. Its text is extracted server-side and fed to the
    orchestrator at start; the original + extracted text are stored in the session workspace."""
    from .docs import ALLOWED_EXTS, MAX_UPLOAD_BYTES, safe_name

    session = await _require(sid, user)
    name = safe_name(file.filename or "")
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTS:
        raise HTTPException(400, f"unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTS))}")
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"file too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    return session.add_upload(name, data)


@app.delete("/api/sessions/{sid}/uploads/{name}")
async def remove_upload(sid: str, name: str, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    if not session.remove_upload(name):
        raise HTTPException(404, "no such upload")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Human-in-the-loop: plan approval, operator interjection, tool intensity
# --------------------------------------------------------------------------- #
@app.post("/api/sessions/{sid}/plan-approvals/{rid}")
async def resolve_plan_approval(sid: str, rid: str, body: PlanDecision,
                                user: User = Depends(current_user)) -> dict:
    """Operator's verdict on a proposed plan: approve | reject (with feedback) | edit (with
    replacement steps). Unblocks the orchestrator, which proceeds / revises / adopts the edit."""
    session = await _require(sid, user)
    if body.decision not in ("approve", "reject", "edit"):
        raise HTTPException(400, "decision must be approve|reject|edit")
    ok = session.resolve_plan_approval(rid, body.decision, body.feedback, body.steps)
    if not ok:
        raise HTTPException(404, "plan approval not found or already resolved")
    return {"ok": True}


@app.post("/api/sessions/{sid}/interject")
async def interject(sid: str, body: Interjection, user: User = Depends(current_user)) -> dict:
    """Inject an operator message / new direction to the orchestrator mid-engagement."""
    session = await _require(sid, user)
    result = await session.interject(body.message)
    return {"ok": True, "result": result}


@app.post("/api/sessions/{sid}/intensity")
async def set_intensity(sid: str, body: IntensityBody, user: User = Depends(current_user)) -> dict:
    """Change the session-wide default tool intensity (passive..insane)."""
    session = await _require(sid, user)
    if not session.set_intensity(body.intensity):
        raise HTTPException(400, f"intensity must be one of {cfg_mod.INTENSITY_LEVELS}")
    return {"ok": True, "intensity": body.intensity}


@app.post("/api/sessions/{sid}/approval-mode")
async def set_approval_mode(sid: str, body: ApprovalModeBody, user: User = Depends(current_user)) -> dict:
    """Override the tool-approval mode for THIS session at runtime: 'auto' bypasses all command
    validation (and releases anything currently waiting), 'manual' restores the policy. Does not
    change global config — this is the mid-session 'disable command validation' checkbox."""
    session = await _require(sid, user)
    if not session.set_approval_mode(body.mode):
        raise HTTPException(400, "mode must be 'manual' or 'auto'")
    return {"ok": True, "approval_mode": body.mode}


@app.get("/api/sessions/{sid}/kali/processes")
async def list_kali_processes(sid: str, user: User = Depends(current_user)) -> dict:
    """Commands/tools this session is currently running inside the Kali container (the operator's
    process monitor — an enumeration scan can overload a target)."""
    session = await _require(sid, user)
    return {"processes": await session.list_kali_processes()}


@app.post("/api/sessions/{sid}/kali/processes/{proc_id}/kill")
async def kill_kali_process(sid: str, proc_id: str, body: KillProcessBody,
                            user: User = Depends(current_user)) -> dict:
    """Kill one running Kali process. The optional ``message`` is delivered to the agent that
    launched it so it can adapt (e.g. pick a lighter scan) rather than just relaunching."""
    session = await _require(sid, user)
    result = await session.kill_kali_process(proc_id, body.message)
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "could not kill process"))
    return result


@app.get("/api/sessions/{sid}/messages")
async def session_messages(sid: str, user: User = Depends(current_user)) -> list[dict]:
    await _require_view(sid, user)
    return await manager.db.list_messages(sid)


@app.get("/api/sessions/{sid}/approvals")
async def session_approvals(sid: str, user: User = Depends(current_user)) -> list[dict]:
    session = await _require(sid, user)
    return session.pending_approvals()


# --------------------------------------------------------------------------- #
# Agent control
# --------------------------------------------------------------------------- #
@app.post("/api/sessions/{sid}/agents/{aid}/stop")
async def stop_agent(sid: str, aid: str, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    ok = await session.stop_agent(aid)
    if not ok:
        raise HTTPException(404, "agent not found")
    return {"ok": True}


@app.post("/api/sessions/{sid}/agents/{aid}/message")
async def message_agent(sid: str, aid: str, body: AgentMessage, user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    result = await session.message_agent(aid, body.message)
    return {"ok": True, "result": result}


@app.post("/api/sessions/{sid}/approvals/{approval_id}")
async def resolve_approval(sid: str, approval_id: str, body: ApprovalDecision,
                           user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    ok = session.resolve_approval(approval_id, body.approved, body.reason)
    if not ok:
        raise HTTPException(404, "approval not found or already resolved")
    return {"ok": True}


@app.post("/api/sessions/{sid}/requests/{request_id}")
async def resolve_request(sid: str, request_id: str, body: UserAnswer,
                          user: User = Depends(current_user)) -> dict:
    session = await _require(sid, user)
    ok = session.resolve_request(request_id, body.answer)
    if not ok:
        raise HTTPException(404, "request not found or already resolved")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# WebSocket live event stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws/{sid}")
async def ws_events(ws: WebSocket, sid: str) -> None:
    # The HTTP auth middleware doesn't cover WebSockets, so authenticate here from the same
    # cookie and enforce session ownership before streaming any events (closes the isolation
    # hole where anyone could subscribe to another user's session id).
    user = await auth.resolve(ws.cookies.get(auth_mod.COOKIE_NAME))
    if user is None:
        await ws.close(code=4401)  # unauthenticated
        return
    session = await manager.load(sid)
    if not session or not _can_view_session(user, session):
        await ws.close(code=4404)  # not found / not yours / not granted
        return
    await ws.accept()
    q = bus.subscribe()
    try:
        # Note: historical feed is loaded by the client from persisted messages
        # (/messages), which survives restarts. The socket only streams live events.
        while True:
            ev = await q.get()
            if ev.session_id == sid:
                await ws.send_json(ev.to_dict())
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        bus.unsubscribe(q)


# --------------------------------------------------------------------------- #
# Static UI
# --------------------------------------------------------------------------- #
@app.get("/")
async def index() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
