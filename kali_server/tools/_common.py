"""Shared helpers for the Kali tool handlers: a subprocess runner, output clipping,
target-safety checks, and the INTENSITY mapping that translates Spider's single intensity
knob (passive..insane) into the concrete, very different flags each tool needs.

The intensity is the main safety/loudness control. A tool should ALWAYS derive its timing,
thread counts, request rates and aggressiveness from these helpers rather than hard-coding a
loud default, so that 'passive'/'stealth' really are quiet and 'insane' is opt-in."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import shlex
import socket
from urllib.parse import urlparse

from . import _procs

MAX_OUTPUT = 80_000          # chars returned to Spider (then Spider clips again for the model)
DEFAULT_TIMEOUT = 300        # seconds

# ---- global concurrency cap ------------------------------------------------ #
# How many tool subprocesses may run at once across the WHOLE container (all Spider sessions /
# users / agents share this one Kali box). Without a cap, several operators each launching heavy
# scans (nmap + gobuster + nuclei + hydra ...) can spawn dozens of simultaneous processes and
# overload the container or hammer the target. Excess calls QUEUE on the semaphore instead of
# piling on. Set SPIDER_KALI_MAX_PARALLEL=0 to disable the cap (unlimited). Default: 8.
try:
    _MAX_PARALLEL = int(os.environ.get("SPIDER_KALI_MAX_PARALLEL", "8") or "8")
except ValueError:
    _MAX_PARALLEL = 8
_SEM: asyncio.Semaphore | None = None


def _subprocess_env():
    """Environment for a tool subprocess. When Spider sent kali_proxy settings in the JSON-RPC
    ``_meta`` (stashed in ``_procs.CURRENT_META``), inject HTTP(S)_PROXY / ALL_PROXY and NO_PROXY so
    proxy-aware tools (curl, wget, httpx, gospider, nuclei, ...) route through the proxy, with the
    whitelist hosts bypassing it. Returns None to inherit the parent env unchanged (no proxy set).
    Raw-socket tools like nmap ignore these vars — that's inherent to how they work."""
    meta = _procs.CURRENT_META.get() or {}
    proxy = meta.get("proxy") or {}
    url = str(proxy.get("url") or "").strip()
    if not url:
        return None
    env = dict(os.environ)
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        env[k] = url
    no_proxy = ",".join(str(h).strip() for h in (proxy.get("no_proxy") or []) if str(h).strip())
    if no_proxy:
        env["NO_PROXY"] = env["no_proxy"] = no_proxy
    return env


def _limiter():
    """Return the shared concurrency limiter as an async context manager. Lazily creates the
    semaphore on first use (so it binds to the running event loop), or a no-op context when the
    cap is disabled (SPIDER_KALI_MAX_PARALLEL<=0)."""
    global _SEM
    if _MAX_PARALLEL <= 0:
        return contextlib.nullcontext()
    if _SEM is None:
        _SEM = asyncio.Semaphore(_MAX_PARALLEL)
    return _SEM

INTENSITY_LEVELS = ["passive", "stealth", "normal", "aggressive", "insane"]


def _norm_intensity(value: str | None) -> str:
    v = (value or "normal").lower().strip()
    return v if v in INTENSITY_LEVELS else "normal"


# ---- per-concept intensity maps (extend these as you add tools) ----
# nmap -T timing template
NMAP_TIMING = {"passive": "-T1", "stealth": "-T2", "normal": "-T3",
               "aggressive": "-T4", "insane": "-T5"}
# generic worker/thread counts (gobuster, ffuf, hydra, ...)
THREADS = {"passive": 4, "stealth": 8, "normal": 30, "aggressive": 64, "insane": 120}
# requests-per-second caps for rate-limitable tools (ffuf -rate, nuclei -rl)
RATE = {"passive": 5, "stealth": 20, "normal": 80, "aggressive": 300, "insane": 1000}
# hydra parallel tasks (kept conservative — credential attacks are noisy and lock accounts)
HYDRA_TASKS = {"passive": 1, "stealth": 2, "normal": 4, "aggressive": 8, "insane": 16}


def nmap_timing(intensity: str | None) -> str:
    return NMAP_TIMING[_norm_intensity(intensity)]


def threads(intensity: str | None) -> int:
    return THREADS[_norm_intensity(intensity)]


def rate(intensity: str | None) -> int:
    return RATE[_norm_intensity(intensity)]


def hydra_tasks(intensity: str | None) -> int:
    return HYDRA_TASKS[_norm_intensity(intensity)]


def clip(text: str, n: int = MAX_OUTPUT) -> str:
    if len(text) <= n:
        return text
    return text[:n] + f"\n...[truncated, {len(text) - n} more chars]"


def require_arg(args: dict, key: str) -> str:
    val = args.get(key)
    if val is None or (isinstance(val, str) and not val.strip()):
        raise ValueError(f"'{key}' is required")
    return str(val).strip()


def host_of(target: str) -> str:
    """Extract a bare hostname/IP from a target that might be a URL."""
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or t
    return t.split("/")[0].split(":")[0]


# ---- optional scope guard -------------------------------------------------- #
# If SPIDER_SCOPE is set (comma-separated hosts / CIDRs), tools refuse targets outside it.
# This is a server-side backstop; Spider also keeps agents in scope via prompts/approvals.
def _load_scope() -> list[str]:
    raw = os.environ.get("SPIDER_SCOPE", "").strip()
    return [s.strip() for s in raw.split(",") if s.strip()] if raw else []


def check_scope(target: str) -> None:
    """Raise ValueError if SPIDER_SCOPE is configured and `target` is not inside it."""
    scope = _load_scope()
    if not scope:
        return
    host = host_of(target)
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        ip = host
    for entry in scope:
        if host == entry or ip == entry:
            return
        try:
            if ip and ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                return
        except ValueError:
            continue
    raise ValueError(
        f"target '{host}' ({ip}) is outside the configured SPIDER_SCOPE ({', '.join(scope)}). "
        f"Refusing to run. Adjust SPIDER_SCOPE on the Kali server if this target is authorised."
    )


async def run(argv: list[str], timeout: int = DEFAULT_TIMEOUT, input_text: str | None = None,
              label: str | None = None) -> str:
    """Run a command (argv list — no shell) and return ``[cmd] ... [exit=N] <output>``.
    stderr is merged into stdout; the process is killed on timeout. Use this for every tool.

    The process is launched in its own session/group (``start_new_session=True``) and registered
    in ``_procs`` so the operator can see it and kill it (and so stopping a Spider session can kill
    the whole tool tree). It also holds a slot in the global concurrency limiter for its whole
    lifetime (see ``_limiter``), so the container can't be swamped by parallel scans."""
    shown = label or " ".join(shlex.quote(a) for a in argv)
    async with _limiter():   # queue here when the container is already at its parallel-tool cap
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if input_text is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
                env=_subprocess_env(),
            )
        except FileNotFoundError as e:
            return f"[error] executable not found: {e}"
        proc_id = _procs.register(proc, shown)
        try:
            out, _ = await asyncio.wait_for(
                proc.communicate(input_text.encode() if input_text is not None else None),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:  # noqa: BLE001
                pass
            return f"[cmd] {shown}\n[timeout after {timeout}s — process killed; partial work may have occurred]"
        finally:
            killed = _procs.was_killed(proc_id)
            _procs.deregister(proc_id)
    text = out.decode("utf-8", errors="replace") if out else ""
    if killed:
        return clip(f"[cmd] {shown}\n[KILLED BY OPERATOR — process terminated before completion]\n{text}")
    return clip(f"[cmd] {shown}\n[exit={proc.returncode}]\n{text}")


async def run_shell(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Run a raw command line through /bin/sh -c (the escape hatch used by the generic
    run_command tool). Prefer argv-based ``run`` for built-in tools to avoid injection.
    Registered + group-killable like ``run`` (see its docstring), and bound by the same global
    concurrency limiter."""
    async with _limiter():   # queue here when the container is already at its parallel-tool cap
        try:
            proc = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True, env=_subprocess_env(),
            )
        except FileNotFoundError as e:
            return f"[error] shell not available: {e}"
        proc_id = _procs.register(proc, command)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            return f"[cmd] {command}\n[timeout after {timeout}s — process killed]"
        finally:
            killed = _procs.was_killed(proc_id)
            _procs.deregister(proc_id)
    text = out.decode("utf-8", errors="replace") if out else ""
    if killed:
        return clip(f"[cmd] {command}\n[KILLED BY OPERATOR — process terminated before completion]\n{text}")
    return clip(f"[cmd] {command}\n[exit={proc.returncode}]\n{text}")
