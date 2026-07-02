"""Configuration: per-role model/endpoint/key, pricing, the human-in-the-loop policy,
the tool-approval policy, default tool intensity, the Kali server connection, and limits.

This module is the single schema for `config/config.json`. Add a top-level setting in
``default_config`` and it is merged into every load (so old config files gain new keys)."""
from __future__ import annotations

import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

# Root for writable data (config, db, workspaces, agents).
# - Normal run: the repository root (parent of the `spider` package).
# - Frozen PyInstaller exe: the directory containing the .exe, so config/db/
#   workspaces persist next to it instead of in the ephemeral _MEIPASS temp dir.
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
CONFIG_FILE = CONFIG_DIR / "config.json"
WORKSPACE_ROOT = BASE_DIR / "workspaces"
DB_FILE = BASE_DIR / "spider.db"

# Pricing is expressed in USD per 1,000,000 tokens.
# Cache read ~= 0.1x input, cache write (5m TTL) ~= 1.25x input.
DEFAULT_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-8": {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0, "cache_read": 0.3, "cache_write": 3.75},
    "claude-haiku-4-5": {"input": 1.0, "output": 5.0, "cache_read": 0.1, "cache_write": 1.25},
    "gpt-4o": {"input": 2.5, "output": 10.0, "cache_read": 1.25, "cache_write": 0.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6, "cache_read": 0.075, "cache_write": 0.0},
    "mock-model": {"input": 1.0, "output": 3.0, "cache_read": 0.1, "cache_write": 1.25},
}

# The set of agent roles in the system. Each gets its own model configuration.
# SPAIDER's roles map to penetration-testing disciplines rather than RE phases.
AGENT_ROLES = [
    "orchestrator",     # pentest lead: scope, plan, delegate, keep the operator informed
    "recon",            # reconnaissance / OSINT / host & service discovery
    "web_app",          # web application testing (OWASP-style)
    "network",          # network & infrastructure / service testing
    "exploitation",     # gaining access: exploit candidate vulnerabilities
    "post_exploit",     # post-exploitation: privesc, lateral movement, looting (scoped)
    "reporting",        # writes the engagement report
    "summarizer",       # helper: context compaction
    "tool_selector",    # helper: picks a tool subset when a model's budget is exceeded
]

# When an agent's prompt (context) reaches this many tokens, a summarizer agent
# compresses its transcript so the agent continues with a compact context.
DEFAULT_MAX_CONTEXT_TOKENS = 800_000

# Default skills loaded per built-in role (optional; users can change in Settings).
# Skill names map to files in the skills/ folder. Empty list = no skill.
DEFAULT_AGENT_SKILLS = {
    "orchestrator": ["pentest_orchestration"],
    "recon": ["recon_methodology"],
    "web_app": ["web_app_testing"],
    "network": ["network_testing"],
    "exploitation": ["exploitation"],
    "post_exploit": ["post_exploitation"],
    "reporting": ["pentest_reporting"],
}

# --------------------------------------------------------------------------- #
# Tool categories & intensity — the vocabulary the approval policy and the Kali
# tools share. A tool declares a `category`; the approval policy decides per
# category whether the operator must validate before it runs.
# --------------------------------------------------------------------------- #
TOOL_CATEGORIES = [
    "control",      # agent control / bookkeeping (never gated)
    "filesystem",   # read/write files in the workspace
    "shell",        # run a command on the SPAIDER host
    "recon",        # passive/active discovery, low impact (whois, dns, nmap -sn)
    "enum",         # service/content enumeration (gobuster, enum4linux, nmap -sV)
    "web",          # active web testing (nikto, sqlmap, dirb, ffuf)
    "exploit",      # active exploitation (metasploit, exploit scripts)
    "bruteforce",   # credential attacks (hydra, medusa, password spraying)
    "destructive",  # potentially damaging / high-impact actions
    "network",      # network-level attacks (mitm, arp, proxy)
]

# Tool intensity: a single knob that maps to safer/louder real flags inside the Kali
# tools (e.g. nmap -T2 vs -T4, request rate caps, thread counts, exploit aggressiveness).
INTENSITY_LEVELS = ["passive", "stealth", "normal", "aggressive", "insane"]
DEFAULT_INTENSITY = "normal"

# Where exploits / proof-of-concept code may be executed:
#   "kali_only" — PoCs/exploits run ONLY inside the Kali container (via the Kali tools);
#                 the host's command-execution tools (run_shell/run_process/terminal) are
#                 withheld from agents. The host is for orchestration, file I/O, and the report.
#   "host"      — also allow agents to execute on the SPAIDER host (legacy behaviour).
POC_EXECUTION_MODES = ["kali_only", "host"]
DEFAULT_POC_EXECUTION = "kali_only"

# Capabilities a custom user-access role can grant (see cfg["user_roles"]). The built-in `admin`
# role implicitly has all of these PLUS exclusive access to Settings.
PERMISSION_CAPS = ["read", "launch_pentest", "free_target_choice", "edit_session"]
# Host command-execution tools confined to the Kali container in "kali_only" mode.
HOST_EXEC_TOOLS = ["run_shell", "run_process", "terminal"]


def _default_model_config(role: str) -> dict[str, Any]:
    """Default per-role LLM configuration. provider: "anthropic" | "openai" | "mock"."""
    # The lead and the exploitation agent benefit from the strongest model.
    if role in ("orchestrator", "exploitation"):
        model = "claude-opus-4-8"
    elif role == "tool_selector":
        # Cheap, fast model: it only picks a subset of tool names.
        model = "claude-haiku-4-5"
    else:
        # summarizer included — needs a large context window for compaction.
        model = "claude-sonnet-4-6"
    return {
        "provider": "anthropic",
        "model": model,
        "api_key": "",
        "base_url": "",  # empty -> SDK default endpoint
        # Verify the LLM endpoint's TLS certificate. Turn OFF only for a self-signed local
        # endpoint or a TLS-intercepting (MITM) corporate proxy — it disables cert checking
        # for this model's API calls, so use with care.
        "verify_ssl": True,
        "max_tokens": 8000,
        "max_turns": 40,
        # How long to wait for an LLM response (seconds) and how many times to retry
        # transient failures, handled by the provider SDK.
        "request_timeout": 300,
        "max_retries": 2,
        # Max number of tools the model may be given. If the tools available to an
        # agent exceed this, a tool_selector agent picks the best subset first.
        # 0 = unlimited (no selection). Mandatory internal tools are always kept;
        # only optional (custom + MCP) tools are subject to selection.
        "max_tool_size": 0,
        # thinking: "off" | "adaptive" (4.6+/Opus) | "enabled" (legacy budget_tokens)
        "thinking": "off",
        "thinking_budget": 8000,        # used when thinking == "enabled"
        "thinking_display": "summarized",  # adaptive-only models: "omitted" | "summarized"
        "effort": "",                   # "" | low | medium | high | xhigh | max
        # sampling (applied only when supported & thinking is off)
        "temperature": None,
        "top_p": None,
        "top_k": None,
        # OpenAI-compatible extras
        "frequency_penalty": None,
        "presence_penalty": None,
        "seed": None,
        "reasoning_effort": "",
        "stop": [],                     # stop sequences
        # Rename/drop outgoing request parameters to track endpoint changes without
        # code edits, e.g. {"max_tokens": "max_completion_tokens"} for newer OpenAI models.
        "param_overrides": {},
    }


def _default_tool_approval() -> dict[str, Any]:
    """The customisable tool-approval policy (the heart of SPAIDER's human-in-the-loop).

    For each tool the runtime resolves a decision in this order:
      1. tool name in ``always_auto_tools``   -> run without asking
      2. tool name in ``always_manual_tools`` -> always ask the operator
      3. the tool's category in ``by_category`` -> that mode
      4. otherwise ``default``
    A decision of "manual" pauses the agent and asks the operator to approve in the UI.
    The global ``approval_mode`` master switch can bypass this entirely (auto run)."""
    return {
        "default": "manual",
        "by_category": {
            "control": "auto",
            "filesystem": "auto",
            "recon": "auto",
            "enum": "auto",
            "shell": "manual",
            "web": "manual",
            "exploit": "manual",
            "bruteforce": "manual",
            "destructive": "manual",
            "network": "manual",
        },
        "always_manual_tools": [],
        "always_auto_tools": [],
    }


def default_config() -> dict[str, Any]:
    """Build the full default configuration tree. This is the schema of config/config.json;
    add a new top-level setting here and it appears everywhere (and is merged into old files)."""
    return {
        # Master approval switch: "manual" applies the tool_approval policy below;
        # "auto" bypasses ALL gating for a fully autonomous run (use with care).
        "approval_mode": "manual",
        "max_context_tokens": DEFAULT_MAX_CONTEXT_TOKENS,
        "workspace_root": str(WORKSPACE_ROOT),
        "agents_dir": str(BASE_DIR / "agents"),
        "models": {role: _default_model_config(role) for role in AGENT_ROLES},
        "agent_skills": deepcopy(DEFAULT_AGENT_SKILLS),
        # ---- Human-in-the-loop (SPAIDER-specific) -------------------------------
        "human_in_the_loop": {
            # Plan sign-off: "off" = never ask; "once" = approve the first plan before
            # work begins; "on_change" = approve the plan AND every later revision.
            "plan_approval": "once",
            # Let the operator inject messages / new directions mid-engagement.
            "allow_interjection": True,
            # Pause the whole engagement until the operator approves the plan (vs. let
            # the orchestrator keep planning while it waits).
            "block_on_plan_approval": True,
        },
        # ---- Tool-approval policy (customisable per category / per tool) --------
        "tool_approval": _default_tool_approval(),
        # ---- Default tool intensity (agents may override per call) --------------
        "default_intensity": DEFAULT_INTENSITY,
        # ---- Where PoCs/exploits may run (see POC_EXECUTION_MODES) --------------
        # "kali_only" (default): exploits & PoC code run inside the Kali container only;
        # the host runs no exploit/PoC commands (it handles orchestration, files, reporting).
        "poc_execution": DEFAULT_POC_EXECUTION,
        # ---- Kali offensive-tool server (the kali_server/ MCP-over-HTTP project) -
        # When enabled, SPAIDER connects to it on session start and assigns its tools
        # to the listed roles. Run the server inside your Kali container.
        "kali": {
            "enabled": False,
            "url": "http://127.0.0.1:8765/mcp",
            # Bearer token sent on every request when the Kali server runs with
            # SPIDER_KALI_TOKEN set (leave blank if the server has no token).
            "token": "",
            "assign_roles": ["recon", "web_app", "network", "exploitation", "post_exploit"],
        },
        # ---- Outbound proxies (separate for the control app vs. the Kali container) -----
        # An authenticated proxy in the form http://user:pass@host:port. They are INDEPENDENT:
        # the client can route through one while Kali doesn't (or vice-versa).
        #   • client_proxy : the SPAIDER control app uses it for its OUTBOUND connections — chiefly
        #     the LLM API. Hosts in `no_proxy` connect DIRECTLY (bypass the proxy).
        #   • kali_proxy   : pushed to the Kali container; its tools' subprocesses get HTTP(S)_PROXY
        #     / NO_PROXY env so curl/httpx/gospider/nuclei/wget route through it (raw-socket tools
        #     like nmap can't use an HTTP proxy). Hosts in `no_proxy` bypass it.
        "client_proxy": {
            "enabled": False,
            "url": "",   # http://user:pass@host:port
            "no_proxy": ["localhost", "127.0.0.1", "::1", "host.docker.internal"],
        },
        "kali_proxy": {
            "enabled": False,
            "url": "",   # http://user:pass@host:port
            "no_proxy": ["localhost", "127.0.0.1", "::1"],
        },
        # ---- Offensive-tool output filtering ------------------------------------
        # When enabled, the Kali server statically filters each tool's output down to its
        # notable findings before the agent sees it (less noise / context waste). Agents can
        # still request the full output per call with raw=true, and turning this OFF returns
        # every tool's complete output unchanged. Admin-controlled (Settings → Output filtering).
        "output_filter": {"enabled": True},
        # Sub-agent spawning limits (safety against runaway recursion).
        "limits": {
            "max_children_per_agent": 5,
            "max_total_agents": 20,
            "max_spawn_depth": 3,
        },
        # ---- Custom user-access roles (RBAC) ------------------------------------
        # Named permission profiles a user account can be assigned (Settings → Access, admin-only).
        # The built-in **admin** role is implicit and has EVERY capability plus exclusive access to
        # Settings — it is not listed here and cannot be edited. Capabilities (see PERMISSION_CAPS):
        #   read          — may view other users' sessions they've been granted (read-only)
        #   launch_pentest   — may create and start engagements
        #   free_target_choice  — when the hidden target-picker is on, may freely pick/enter a target,
        #                   edit instructions, and rename the session (vs. a script-driven LIMITED run)
        #   edit_session  — may rename their own sessions
        # `user` is the default profile for a regular account (keeps the prior behaviour).
        "user_roles": {
            "user": {"read": False, "launch_pentest": True, "free_target_choice": True, "edit_session": True},
        },
        # Per-user read grants: which other users' sessions a `read`-capable account may view.
        # { grantee_user_id: [ {"owner": owner_user_id, "sessions": ["*"] | [session_id, …]} ] }
        "session_grants": {},
        "pricing": deepcopy(DEFAULT_PRICING),
    }


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` onto ``base`` (nested dicts merged, scalars/lists
    replaced). Used by load_config so a saved file keeps user values while still gaining
    any new default keys added in later versions."""
    out = deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def _config_file() -> Path:
    """The active config file path, resolved from CONFIG_DIR at CALL time (not import time) so a
    reassignment of ``config.CONFIG_DIR`` — e.g. for test isolation — actually redirects reads/writes."""
    return CONFIG_DIR / "config.json"


def load_config() -> dict[str, Any]:
    """Load configuration, merging any saved file over defaults so new keys appear."""
    cfg = default_config()
    cfile = _config_file()
    if cfile.exists():
        try:
            saved = json.loads(cfile.read_text(encoding="utf-8"))
            cfg = _deep_merge(cfg, saved)
        except (json.JSONDecodeError, OSError):
            pass
    # Environment variables provide a convenient default API key for all roles.
    env_anthropic = os.environ.get("ANTHROPIC_API_KEY", "")
    env_openai = os.environ.get("OPENAI_API_KEY", "")
    for role, mc in cfg["models"].items():
        if not mc.get("api_key"):
            if mc.get("provider") == "anthropic" and env_anthropic:
                mc["api_key"] = env_anthropic
            elif mc.get("provider") == "openai" and env_openai:
                mc["api_key"] = env_openai
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    """Write the config tree to config.json under CONFIG_DIR (creating the folder if needed)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _config_file().write_text(json.dumps(cfg, indent=2), encoding="utf-8")
