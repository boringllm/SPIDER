"""Session orchestration: owns agents, MCP clients, the plan, findings, cost
tracking, command-approval gating, persistence, and start/stop/resume."""
from __future__ import annotations

import asyncio
import json
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import config as cfg_mod
from .agents import Agent
from .db import Database
from .events import E, bus
from .llm import Usage
from .roles import ROLES
from .tools import base_tools
from .tools.base import Tool
from .tools.mcp import MCPClient, build_mcp_tools


# Internal helper agents: they get ONLY their own role tools — no inherited MCP tools,
# no MCP catalog, no skills, no shared memory. (A tool_selector in particular must never
# receive the big tool array; its candidates are described in its prompt body instead.)
_HELPER_ROLES = {"tool_selector", "summarizer"}


def _targets_host_loopback(target: str) -> bool:
    """True if the engagement target references the operator's host loopback (localhost /
    127.0.0.0/8 / ::1). Such a target is unreachable as 127.0.0.1 from inside the Kali container,
    so agents must use ``host.docker.internal`` instead — see the prompt note in create_agent."""
    t = (target or "").lower()
    if not t:
        return False
    return ("localhost" in t or "127." in t or "::1" in t or "0.0.0.0" in t)


def _empty_cost() -> dict[str, Any]:
    return {
        "total_usd": 0.0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read": 0,
        "cache_write": 0,
        "by_agent": {},
        "by_model": {},
    }


class Session:
    def __init__(self, sid: str, name: str, cfg: dict[str, Any], db: Database,
                 owner: str | None = None) -> None:
        self.id = sid
        self.name = name
        self.cfg = cfg
        self.db = db
        # Id of the user who created this session (per-user isolation; None = legacy/admin-only).
        self.owner = owner
        self.target = ""
        self.instructions = ""
        self.status = "created"

        self.workspace = Path(cfg.get("workspace_root", str(cfg_mod.WORKSPACE_ROOT))) / sid
        self.approval_mode = cfg.get("approval_mode", "manual")
        self.max_context_tokens = int(cfg.get("max_context_tokens", cfg_mod.DEFAULT_MAX_CONTEXT_TOKENS))

        self.agents: dict[str, Agent] = {}
        # Agents reconstructed from the DB for a session not running in this process
        # (so the tree/discussion show after a restart). List of plain dicts.
        self.restored_agents: list[dict] = []
        self._tasks: dict[str, asyncio.Task] = {}
        self.orchestrator: Agent | None = None
        limits = cfg.get("limits", {}) or {}
        self.max_depth = int(limits.get("max_spawn_depth", 3))
        self.max_agents = int(limits.get("max_total_agents", 15))
        self.max_children_per_agent = int(limits.get("max_children_per_agent", 5))

        self.plan: dict[str, Any] = {"steps": []}
        self.findings: dict[str, dict] = {}
        self.cost: dict[str, Any] = _empty_cost()
        # Shared memory written by agents when they finish, keyed by role. Read by future
        # agents of the same role and by sub-agents of those roles.
        self.role_memory: dict[str, list[str]] = {}
        # MASTER MEMORY: a single cross-role digest of every finishing agent's important findings,
        # persisted to memory/master.md and injected into EVERY new agent (regardless of role) so
        # the whole engagement's key results are always in view. See record_agent_memory /
        # _master_memory_block.
        self.master_memory: list[str] = []

        self._pending_approvals: dict[str, dict] = {}
        self._approval_counter = 0
        self._pending_requests: dict[str, dict] = {}
        self._request_counter = 0
        self.roles: dict[str, dict] = {}

        # ---- Human-in-the-loop state (SPAIDER) ----
        hitl = cfg.get("human_in_the_loop", {}) or {}
        self.plan_approval_mode = hitl.get("plan_approval", "once")   # off | once | on_change
        self.block_on_plan_approval = bool(hitl.get("block_on_plan_approval", True))
        self.allow_interjection = bool(hitl.get("allow_interjection", True))
        self._pending_plan_approvals: dict[str, dict] = {}
        self._plan_counter = 0
        self._plan_approved_once = False
        # Session-wide tool intensity (agents may override per call; Kali tools map it to flags).
        self.default_intensity = cfg.get("default_intensity", cfg_mod.DEFAULT_INTENSITY)
        # Where PoCs/exploits may run: "kali_only" (default) confines them to the Kali container.
        self.poc_execution = cfg.get("poc_execution", cfg_mod.DEFAULT_POC_EXECUTION)

        self._log_task: asyncio.Task | None = None
        self.mcp_clients: dict[str, MCPClient] = {}
        self._mcp_tools_by_role: dict[str, dict[str, Tool]] = {r: {} for r in ROLES}
        # Connection pool for folder-based (mcpo) MCP servers, keyed by config signature.
        self._mcp_pool: dict[str, dict] = {}
        self.agent_defs: dict[str, dict] = {}
        # Cached catalog (name + description) of every MCP tool configured in this
        # session, injected into every agent's prompt so they know what's available.
        self._mcp_catalog: str | None = None

        # Base (native + control + custom) tools to map role tool-name lists onto.
        self._base_tools: dict[str, Tool] = base_tools()

    # ------------------------------------------------------------------ setup
    async def setup(self) -> None:
        from . import agentdefs, skills
        from .registry import role_specs

        skills.ensure_scaffold()
        for sub in ("memory", "findings", "poc", "logs", "reports", "uploads", "uploads/text"):
            (self.workspace / sub).mkdir(parents=True, exist_ok=True)
        self._start_event_log()
        self.roles = role_specs(self.cfg)
        self.agent_defs = agentdefs.load_all(self.cfg)
        await self._connect_mcp()

    def _start_event_log(self) -> None:
        """Persist the full live event stream for this session to logs/events.jsonl
        (one JSON object per line) so the engagement is fully recoverable and parseable."""
        if self._log_task and not self._log_task.done():
            return
        log_path = self.workspace / "logs" / "events.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        q = bus.subscribe()

        async def _drain() -> None:
            try:
                with log_path.open("a", encoding="utf-8") as f:
                    while True:
                        ev = await q.get()
                        if ev.session_id != self.id:
                            continue
                        f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
                        f.flush()
            except asyncio.CancelledError:
                pass
            finally:
                bus.unsubscribe(q)

        self._log_task = asyncio.create_task(_drain())

    async def _connect_mcp(self) -> None:
        """Connect session-level MCP servers and assign their tools to roles. This covers the
        Kali offensive-tool server (from cfg['kali']) plus any extra cfg['mcp_servers']. Per-
        agent folder MCP servers (agents/<role>/mcp.json) are connected lazily in create_agent."""
        servers = dict(self.cfg.get("mcp_servers", {}) or {})
        # Fold the friendly cfg["kali"] block into the generic server list under the name
        # "kali" (so its tools become kali__nmap_scan etc.).
        kali = self.cfg.get("kali", {}) or {}
        if kali.get("enabled") and kali.get("url"):
            servers["kali"] = {
                "transport": "http",
                "url": kali["url"],
                "token": kali.get("token", ""),
                "enabled": True,
                "assign_roles": kali.get("assign_roles",
                                         ["recon", "web_app", "network", "exploitation", "post_exploit"]),
            }
        for name, conf in servers.items():
            if not conf.get("enabled"):
                continue
            client = MCPClient(name, conf)
            try:
                await client.connect()
            except Exception as e:  # noqa: BLE001
                bus.emit(E.LOG, self.id, {"level": "warn",
                         "message": f"MCP '{name}' unavailable: {e}"
                         + (" (is the Kali server running and reachable?)" if name == "kali" else "")})
                continue
            self.mcp_clients[name] = client
            tools = build_mcp_tools(client, name)
            for role in conf.get("assign_roles", []):
                if role in self._mcp_tools_by_role:
                    self._mcp_tools_by_role[role].update(tools)
            bus.emit(E.LOG, self.id, {"level": "info", "message": f"MCP '{name}' connected: {len(tools)} tools"})

    # ------------------------------------------------------------- agent mgmt
    def _tools_for_role(self, role: str) -> dict[str, Tool]:
        """Resolve a role's base toolset: map the role's tool-name list (from roles.py /
        custom roles) onto the actual Tool objects in ``self._base_tools``, then add any
        statically-assigned MCP tools for that role. Folder-inherited MCP tools and skill
        tools are added later in ``create_agent``.

        When ``poc_execution`` is "kali_only" (the default), the host command-execution tools
        (run_shell / run_process / terminal) are withheld so exploits and PoCs can only run in
        the Kali container; the host keeps file I/O, HTTP, and reporting tools."""
        spec = self.roles.get(role) or {"tools": ROLES.get(role, {}).get("tools", [])}
        tools: dict[str, Tool] = {}
        for tname in spec["tools"]:
            if tname in self._base_tools:
                tools[tname] = self._base_tools[tname]
        if self.poc_execution == "kali_only":
            for tname in cfg_mod.HOST_EXEC_TOOLS:
                tools.pop(tname, None)
        tools.update(self._mcp_tools_by_role.get(role, {}))
        return tools

    async def _mcp_tools_for(self, defs: dict[str, dict]) -> dict[str, Tool]:
        """Connect (or reuse) the given mcpo server defs and return their tools."""
        out: dict[str, Tool] = {}
        for name, sdef in defs.items():
            if not sdef.get("enabled", True):
                continue
            sig = json.dumps(sdef, sort_keys=True)
            entry = self._mcp_pool.get(sig)
            if entry is None:
                client = MCPClient(name, sdef)
                try:
                    await client.connect()
                    entry = {"client": client, "tools": build_mcp_tools(client, name)}
                    self.mcp_clients[f"{name}#{len(self.mcp_clients)}"] = client
                    bus.emit(E.LOG, self.id, {"level": "info",
                             "message": f"folder MCP '{name}' connected: {len(entry['tools'])} tools"})
                except Exception as e:  # noqa: BLE001
                    entry = {"client": None, "tools": {}}
                    bus.emit(E.LOG, self.id, {"level": "warn", "message": f"folder MCP '{name}' unavailable: {e}"})
                self._mcp_pool[sig] = entry
            out.update(entry["tools"])
        return out

    async def build_mcp_catalog(self) -> str:
        """A compact catalog (name + short description) of every MCP tool configured across
        all roles in this session. Built once (best-effort) and injected into agent prompts so
        any agent knows what MCP capabilities exist — even ones it doesn't hold directly."""
        if self._mcp_catalog is not None:
            return self._mcp_catalog
        # Gather all enabled MCP server defs from every role's folder config.
        defs: dict[str, dict] = {}
        for adef in self.agent_defs.values():
            for name, sdef in (adef.get("mcp") or {}).items():
                if sdef.get("enabled", True):
                    defs[name] = sdef
        catalog = ""
        if defs:
            try:
                tools = await self._mcp_tools_for(defs)
                lines = [
                    f"- {tname}: {((t.description or '').strip().splitlines() or [''])[0][:140]}"
                    for tname, t in sorted(tools.items())
                ]
                catalog = "\n".join(lines)
            except Exception as e:  # noqa: BLE001 — catalog is best-effort
                bus.emit(E.LOG, self.id, {"level": "warn", "message": f"MCP catalog unavailable: {e}"})
        self._mcp_catalog = catalog
        return self._mcp_catalog

    def _ancestor_roles(self, parent: Agent | None) -> list[str]:
        """Roles of an agent's parent chain (so a sub-agent inherits its ancestors' memory)."""
        roles: list[str] = []
        p = parent
        seen: set[str] = set()
        while p is not None and p.id not in seen:
            seen.add(p.id)
            if p.role not in roles:
                roles.append(p.role)
            p = self.agents.get(p.parent_id) if p.parent_id else None
        return roles

    def _shared_memory_for(self, role: str, parent: Agent | None) -> str:
        """Concatenated memory for this role plus its ancestor roles (helpers excluded)."""
        roles: list[str] = []
        for r in [role, *self._ancestor_roles(parent)]:
            if r not in roles and r not in _HELPER_ROLES:
                roles.append(r)
        blocks: list[str] = []
        for r in roles:
            entries = self.role_memory.get(r) or []
            if entries:
                # keep the most recent few per role to bound the prompt size
                recent = "\n\n".join(entries[-4:])
                label = "your role" if r == role else f"parent role '{r}'"
                blocks.append(f"# Memory from {label} ({r}):\n{recent}")
        return "\n\n".join(blocks)

    def _memory_notes(self) -> list[str]:
        """Note files agents wrote to the workspace `memory/` folder via write_file
        (anything that isn't an auto-generated `role_*.md`)."""
        mem_dir = self.workspace / "memory"
        if not mem_dir.exists():
            return []
        return sorted(p.name for p in mem_dir.glob("*.md") if not p.name.startswith("role_"))

    def _memory_notes_block(self, notes: list[str], per_note: int = 3000, max_total: int = 9000) -> str:
        """Inline the CONTENT of the workspace memory notes (given to the agent directly, not
        fetched). SPAIDER injects memory into the prompt so agents never need a host file tool to
        read it; each note is included up to ``per_note`` chars, bounded overall by ``max_total``.
        The full text still lives at ``memory/<name>`` for the rare case an agent wants more."""
        if not notes:
            return ""
        lines = ["Detailed notes earlier agents recorded (included here so you don't need to fetch "
                 "them; the full text is at memory/<name> if you ever need more):"]
        budget = max_total
        for n in notes:
            try:
                text = (self.workspace / "memory" / n).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if not text:
                continue
            if budget <= 0:
                lines.append(f"\n--- memory/{n} (omitted to save context; read it with read_file) ---")
                continue
            cap = min(per_note, budget)
            shown = text[:cap]
            budget -= len(shown)
            trunc = "\n…[truncated — read memory/" + n + " for the rest]" if len(text) > cap else ""
            lines.append(f"\n--- memory/{n} ---\n{shown}{trunc}")
        return "\n".join(lines)

    def _master_memory_block(self, max_total: int = 12000) -> str:
        """The MASTER MEMORY digest (memory/master.md) inlined for injection, most-recent-first and
        bounded by ``max_total`` chars. Read from disk so it survives restarts. Injected into every
        new agent so the whole engagement's important findings are always in view."""
        path = self.workspace / "memory" / "master.md"
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
        if not text:
            return ""
        # master.md is append-only with "\n\n---\n\n" between entries; keep the most recent ones
        # that fit the budget (newest carry the latest state of the engagement).
        entries = [e.strip() for e in text.split("\n\n---\n\n") if e.strip()]
        kept: list[str] = []
        used = 0
        for e in reversed(entries):
            if used + len(e) > max_total and kept:
                kept.append("…[older master-memory entries omitted — load memory/master.md to read all]")
                break
            kept.append(e)
            used += len(e)
        return "\n\n".join(reversed(kept))

    def _loadable_memory_files(self) -> list[str]:
        """All memory files an agent may pull on demand with `load_memory` (master + per-role
        memory + the notes agents wrote). The agent SELECTS which to load; master is also injected
        automatically."""
        mem_dir = self.workspace / "memory"
        if not mem_dir.exists():
            return []
        names = sorted(p.name for p in mem_dir.glob("*.md"))
        # master first, then role_*, then notes — a sensible reading order.
        names.sort(key=lambda n: (n != "master.md", not n.startswith("role_"), n))
        return names

    def read_memory_file(self, name: str) -> str:
        """Read one memory file's full text by name (used by the load_memory tool). Path-safe."""
        from . import docs

        safe = docs.safe_name(name)
        path = self.workspace / "memory" / safe
        if not path.exists():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _memory_role_files(self, role: str, parent: Agent | None) -> list[str]:
        """The role-memory files (role_<role>.md) that feed this agent: its own role plus
        ancestor roles that actually have recorded memory."""
        files: list[str] = []
        for r in [role, *self._ancestor_roles(parent)]:
            if r not in _HELPER_ROLES and self.role_memory.get(r):
                fn = f"role_{r}.md"
                if fn not in files:
                    files.append(fn)
        return files

    def record_agent_memory(self, agent: Agent) -> None:
        """Persist a finishing agent's summary as shared memory for its role AND into the
        cross-role MASTER MEMORY (with the findings it recorded). Master memory is the engagement's
        running digest of important results, injected into every future agent."""
        if agent.role in _HELPER_ROLES:
            return
        result = (agent.result or "").strip()
        if not result:
            return
        task_line = (agent.task or "").strip().splitlines()[0] if agent.task else ""
        entry = f"## {agent.name}" + (f" — task: {task_line[:160]}" if task_line else "") + f"\n{result}"
        self.role_memory.setdefault(agent.role, []).append(entry)
        try:
            path = self.workspace / "memory" / f"role_{agent.role}.md"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(entry + "\n\n---\n\n")
        except OSError:
            pass
        # ---- MASTER MEMORY: cross-role digest (result + this agent's findings) ----
        findings = [f for f in self.findings.values() if f.get("agent_id") == agent.id]
        flines = "".join(
            f"\n  - [{f['severity']}/{f['status']}] {f['title']}"
            f" @ {(f.get('data') or {}).get('location', '?')}"
            for f in findings
        )
        master_entry = (
            f"## {agent.name} ({agent.role})" + (f" — task: {task_line[:160]}" if task_line else "")
            + f"\n{result}" + (f"\nFindings recorded:{flines}" if flines else "")
        )
        self.master_memory.append(master_entry)
        try:
            mpath = self.workspace / "memory" / "master.md"
            mpath.parent.mkdir(parents=True, exist_ok=True)
            with mpath.open("a", encoding="utf-8") as f:
                f.write(master_entry + "\n\n---\n\n")
        except OSError:
            pass

    async def create_agent(self, role: str, task: str, parent: Agent | None) -> Agent:
        # Pick up the CURRENT global config before spawning, so a freshly spawned agent always runs
        # on the latest settings (model/params/proxies/max_turns) rather than the snapshot frozen
        # when the session was created.
        self.reload_config()
        if not self.agent_defs:
            from . import agentdefs
            from .registry import role_specs

            self.roles = role_specs(self.cfg)
            self.agent_defs = agentdefs.load_all(self.cfg)
        adef = self.agent_defs.get(role) or {"system": self.roles.get(role, {}).get("system_default", ""), "mcp": {}}
        count = sum(1 for a in self.agents.values() if a.role == role) + 1
        name = f"{role}#{count}" if role != "orchestrator" else "orchestrator"
        # Route this agent's LLM calls through the operator's client proxy (if enabled). Built from
        # the (just-reloaded) session config so a proxy/model change applies on the next agent.
        model_config = self.build_model_config(role)

        is_helper = role in _HELPER_ROLES
        tools = self._tools_for_role(role)
        # Inherit folder-based MCP servers from all ancestors, then add this role's own.
        # Helper agents (tool_selector / summarizer) NEVER inherit MCP tools — a tool_selector
        # must receive only `select_tools`; its candidate tools live in its prompt body.
        inherited: dict[str, dict] = {} if is_helper else dict(parent.mcp_server_defs) if parent else {}
        if not is_helper:
            inherited.update(adef.get("mcp", {}))
            if inherited:
                tools.update(await self._mcp_tools_for(inherited))

        base_system = adef.get("system") or self.roles.get(role, {}).get("system_default", "")

        # Resolve per-skill load modes for this role (always / optional / never). Optional
        # skills are loadable on demand via the load_skill tool, so attach it now (before
        # budgeting) when any exist.
        always_skills: list[str] = []
        optional_skills: list[str] = []
        mem_text = ""
        mem_notes: list[str] = []
        if not is_helper:
            from . import skills as skills_mod

            modes = skills_mod.resolve_skill_modes(self.cfg, role)
            always_skills = [s for s, m in modes.items() if m == "always"]
            optional_skills = [s for s, m in modes.items() if m == "optional"]
            if optional_skills and "load_skill" in self._base_tools:
                tools["load_skill"] = self._base_tools["load_skill"]

        # If the tools exceed this model's max_tool_size, have a tool_selector agent
        # pick the best subset BEFORE this agent runs. Mandatory internal tools are
        # always kept; only optional (custom + MCP) tools are selected from. Applies to
        # every spawned agent regardless of who spawned it (so a sub-agent of a worker
        # gets its own tool_selector when its toolset differs from its parent's).
        max_tools = int(model_config.get("max_tool_size", 0) or 0)
        if max_tools > 0 and len(tools) > max_tools and not is_helper:
            tools = await self._budget_tools(role, name, task, base_system, tools, max_tools, parent)

        system_prompt = base_system
        if not is_helper:
            # ENGAGEMENT CONTEXT: remind every worker of the in-scope target and the current
            # tool intensity (offensive tools accept an `intensity` param; default to this).
            scope_line = (self.target or "(see your task brief)")
            system_prompt += (
                f"\n\n=== ENGAGEMENT CONTEXT ===\nIn-scope target(s): {scope_line}\n"
                f"Current tool intensity: '{self.default_intensity}' — pass this as the `intensity` "
                f"argument to Kali tools unless your task says otherwise, and do not exceed it without "
                f"escalating. Stay strictly within scope."
            )
            # HOST-LOCAL TARGET REACHABILITY: Kali tools run INSIDE the container, where 127.0.0.1
            # is the container itself — a target on the operator's host loopback is unreachable that
            # way (connection refused). The container reaches the host as `host.docker.internal`.
            if _targets_host_loopback(self.target):
                system_prompt += (
                    "\n\nNETWORK NOTE (important): the target is on the OPERATOR'S HOST loopback "
                    "(localhost/127.0.0.1). Kali tools run INSIDE the container, where 127.0.0.1 is "
                    "the container itself — using it gives 'connection refused'. To reach this target "
                    "from Kali tools, substitute the host as `host.docker.internal` (keep the same "
                    "port/path), e.g. http://host.docker.internal:PORT. Use that hostname for nmap, "
                    "gobuster, sqlmap, curl, etc. The host-side `http_request` tool (which runs on the "
                    "SPAIDER host) may still use the original localhost URL."
                )
            # EXECUTION ENVIRONMENT: in the default "kali_only" mode, all exploits and PoCs must
            # run inside the Kali container — agents have no host command-execution tools.
            if self.poc_execution == "kali_only":
                system_prompt += (
                    "\n\nEXECUTION ENVIRONMENT: Run ALL commands, exploits, and proof-of-concept code "
                    "INSIDE the Kali container. The canonical, ALWAYS-available command tool is "
                    "`kali_terminal` (use it for nmap/whatweb/gobuster/sqlmap/msfvenom/curl/custom "
                    "scripts/one-liners); dedicated `kali__<tool>` functions and `kali__run_poc` are "
                    "also available when the Kali server is connected. You have NO host command-"
                    "execution tools: never try to run commands, exploits, or PoCs on the SPAIDER host, "
                    "and do not look for `run_shell`/`terminal`. The host is only for orchestration, "
                    "reading/writing files (notes, evidence), and the final report. If `kali_terminal` "
                    "says Kali is not connected, use `ask_user` to ask the operator to start it (or "
                    "`finish` and report it) — do not spawn sub-agents to work around it."
                )
            else:
                system_prompt += (
                    "\n\nEXECUTION ENVIRONMENT: Prefer running commands, exploits, and PoCs inside the "
                    "Kali container via `kali_terminal` (or `kali__run_poc` / `kali__<tool>`). Host "
                    "execution tools are available but should be reserved for local helper tasks, not "
                    "for attacking targets."
                )
            # Point agents at any operator-provided reference documents (full text on disk).
            ref_uploads = [u for u in self.list_uploads() if u.get("chars")]
            if ref_uploads and "read_file" in tools:
                listing = "; ".join(f"{u['text_path']} ({u['ext']})" for u in ref_uploads)
                system_prompt += (
                    "\n\nREFERENCE DOCUMENTS: the operator attached documents that may inform this "
                    f"engagement — read any relevant one with `read_file`: {listing}."
                )
            # If this agent can spawn, tell it which roles are available (incl. custom agents).
            if "spawn_agent" in tools:
                from .registry import spawnable_roles

                roster = ", ".join(spawnable_roles(self.cfg))
                system_prompt += f"\n\nAVAILABLE SUB-AGENT ROLES you may spawn via spawn_agent: {roster}."
            # Tell every agent which MCP tools exist in the engagement, even ones it doesn't hold,
            # so it can spawn (or ask its parent to spawn) a sub-agent in a role that has them.
            catalog = await self.build_mcp_catalog()
            if catalog:
                system_prompt += (
                    "\n\nMCP TOOLS AVAILABLE IN THIS ENGAGEMENT (you may not hold these directly; if a "
                    "task needs one, spawn — or ask your parent to spawn — a sub-agent in a role whose "
                    f"folder grants it):\n{catalog}"
                )
            # MASTER MEMORY FIRST: the cross-role digest of every finishing agent's important
            # findings, injected into EVERY agent so the whole engagement is always in view.
            master_block = self._master_memory_block()
            if master_block:
                system_prompt += (
                    "\n\n=== MASTER MEMORY — the engagement's key findings so far (every agent's "
                    "important results; read this first) ===\n\n" + master_block
                )
            # THEN role-scoped shared memory from earlier agents of this role / ancestor roles,
            # plus the detailed notes agents wrote to the memory/ folder. SKIPPED for the reporter:
            # its report is built from the deduplicated findings dossier (in the brief) plus the
            # bounded master digest above, so re-injecting the role memory AND every scratch note
            # here would just restate the same findings several times — the duplication that was
            # overflowing the reporter's context and making the final LLM call fail. The reporter
            # can still pull any specific file on demand via load_memory (listed below).
            if role != "reporting":
                mem_text = self._shared_memory_for(role, parent)
                mem_notes = self._memory_notes()
                note_block = self._memory_notes_block(mem_notes)
                if note_block:
                    mem_text = (mem_text + "\n\n" + note_block) if mem_text else note_block
                if mem_text:
                    system_prompt += (
                        "\n\n=== SHARED MEMORY for your role/lineage (carries findings and context so you "
                        "don't need to re-ask) ===\n\n" + mem_text
                    )
            # SELECTABLE MEMORY: list every memory file and let the agent pull any it wants in full
            # via `load_memory` (master memory is already injected above; this is for the rest).
            loadable_mem = self._loadable_memory_files()
            if loadable_mem and "load_memory" in self._base_tools:
                tools["load_memory"] = self._base_tools["load_memory"]
                listing = "\n".join(f"- {n}" for n in loadable_mem)
                system_prompt += (
                    "\n\n=== MEMORY FILES YOU MAY LOAD ON DEMAND ===\n"
                    "Beyond what's injected above, you can pull any of these memory files into your "
                    "context in full by calling `load_memory` with its name (e.g. another role's "
                    f"memory, or a specific note):\n{listing}"
                )
            # THEN SKILLS: statically loaded ("always") skills appended to the prompt.
            skill_text = skills_mod.skill_text_for(always_skills)
            if skill_text:
                system_prompt += f"\n\n=== LOADED SKILLS (methodology to apply) ===\n\n{skill_text}"
            # On-demand ("optional") skills: list them so the agent can load_skill if useful.
            if optional_skills:
                avail = {s["name"]: s["description"] for s in skills_mod.list_skills()}
                lines = "\n".join(f"- {n}: {avail.get(n, '')}" for n in optional_skills)
                system_prompt += (
                    "\n\n=== SKILLS YOU MAY LOAD ON DEMAND ===\n"
                    "If a task would benefit from one of these methodologies, call `load_skill` with its "
                    f"name to pull it into your context:\n{lines}"
                )

        agent = Agent(
            session=self,
            role=role,
            name=name,
            system_prompt=system_prompt,
            tools=tools,
            model_config=model_config,
            task=task,
            parent=parent,
        )
        agent.mcp_server_defs = inherited
        agent.loadable_skills = set(optional_skills)
        self.agents[agent.id] = agent
        bus.emit(
            E.AGENT_CREATED,
            self.id,
            {"role": role, "name": name, "parent": agent.parent_id, "task": task,
             "model": model_config.get("model"), "tools": list(agent.tools.keys()),
             "system_prompt": agent.system_prompt, "mcp_servers": list(inherited.keys()),
             "turns": 0, "max_turns": agent._max_turns()},
            agent_id=agent.id,
        )
        # Surface what this agent started with, in the chat: memory first, then skills.
        if mem_text:
            role_files = self._memory_role_files(role, parent)
            files = [f"memory/{f}" for f in role_files] + [f"memory/{f}" for f in mem_notes]
            self._emit_loaded(agent, E.AGENT_MEMORY_LOADED, "memory_loaded",
                              {"files": files, "role_files": role_files, "notes": mem_notes,
                               "chars": len(mem_text)})
        for sk in always_skills:
            title = next((s["title"] for s in skills_mod.list_skills() if s["name"] == sk), sk) \
                if not is_helper else sk
            self._emit_loaded(agent, E.AGENT_SKILL_LOADED, "skill_loaded",
                              {"name": sk, "title": title, "auto": True})
        asyncio.create_task(self.persist_agent(agent))
        return agent

    def _emit_loaded(self, agent: Agent, event: str, msg_role: str, payload: dict) -> None:
        """Emit + persist a 'loaded at start' chat line (memory / static skill)."""
        bus.emit(event, self.id, payload, agent_id=agent.id)
        asyncio.create_task(self.db.add_message(self.id, agent.id, msg_role, payload))

    async def _budget_tools(
        self,
        role: str,
        agent_name: str,
        task: str,
        context_system: str,
        tools: dict[str, Tool],
        max_tools: int,
        parent: Agent | None,
    ) -> dict[str, Tool]:
        """Trim `tools` to <= max_tools for `agent_name` by spawning a tool_selector
        agent that picks the best optional tools for the agent's task. Internal
        (native + control + pentest) tools are mandatory and always kept; the selector
        chooses among optional (custom + MCP/Kali) tools to fill the remaining budget."""
        from .tools.control import control_tools
        from .tools.native import native_tools
        from .tools.pentest import pentest_tools

        mandatory_names = set(native_tools()) | set(control_tools()) | set(pentest_tools())
        mandatory = {n: t for n, t in tools.items() if n in mandatory_names}
        optional = {n: t for n, t in tools.items() if n not in mandatory_names}
        budget = max_tools - len(mandatory)

        if budget <= 0:
            bus.emit(E.LOG, self.id, {"level": "warn", "message": (
                f"{agent_name}: {len(mandatory)} mandatory internal tools already meet/exceed "
                f"max_tool_size={max_tools}; dropping all {len(optional)} optional tools.")})
            return mandatory
        if len(optional) <= budget:  # nothing to trim (defensive; caller already checked)
            return tools

        catalog = "\n".join(
            f"- {n}: {(t.description or '').strip()[:240]}" for n, t in sorted(optional.items())
        )
        instr = (
            f"The agent '{agent_name}' (role: {role}) is about to start. Its model can take at "
            f"most {budget} of the optional tools below (its mandatory internal tools are already "
            f"included and not your concern).\n\n"
            f"=== TARGET AGENT TASK ===\n{task.strip()}\n\n"
            f"=== TARGET AGENT ROLE CONTEXT ===\n{context_system.strip()[:1500]}\n\n"
            f"=== CANDIDATE TOOLS ({len(optional)}; choose at most {budget}) ===\n{catalog}\n\n"
            f"Call `select_tools` with the exact names of the at-most-{budget} most useful tools "
            f"for this agent's task."
        )
        selector = await self.create_agent("tool_selector", instr, parent=parent)
        selector.selection_candidates = set(optional)
        selector.selection_budget = budget
        self.start_agent(selector)
        await self.wait_for(selector)

        selected = selector.selected_tools
        if selected is None:
            # selector never answered (e.g. it errored) -> deterministic fallback
            chosen = sorted(optional)[:budget]
            bus.emit(E.LOG, self.id, {"level": "warn", "message": (
                f"{agent_name}: tool_selector did not answer; "
                f"falling back to first {budget} optional tools.")})
        else:
            # an explicit selection (possibly empty -> the agent gets only mandatory tools)
            chosen = [n for n in selected if n in optional][:budget]

        final = dict(mandatory)
        for n in chosen:
            final[n] = optional[n]
        bus.emit(E.LOG, self.id, {"level": "info", "message": (
            f"{agent_name}: tool budget {max_tools} -> kept {len(mandatory)} internal + "
            f"{len(chosen)} of {len(optional)} optional tools (selected by {selector.name}).")})
        return final

    def start_agent(self, agent: Agent) -> "asyncio.Task[str]":
        """Launch an agent's run loop as a background asyncio task (idempotent: returns the
        existing task if already started). Await the returned task to get its result."""
        if agent.id in self._tasks:
            return self._tasks[agent.id]
        task = asyncio.create_task(agent.run())
        self._tasks[agent.id] = task
        return task

    async def summarize_for(self, agent: Agent, transcript: str) -> str:
        """Spawn a transient summarizer agent to compress `transcript` for `agent`.
        Used by the context-compaction mechanism (and available on demand)."""
        instr = (
            f"Compress the following transcript for agent '{agent.name}' (role {agent.role}) so it "
            f"can continue its task without the original context. Their task was:\n{agent.task}\n\n"
            f"--- TRANSCRIPT START ---\n{transcript}\n--- TRANSCRIPT END ---\n\n"
            f"Return ONLY the dense summary via finish."
        )
        child = await self.create_agent("summarizer", instr, parent=agent)
        self.start_agent(child)
        result = await self.wait_for(child)
        return result or "(summary unavailable)"

    async def handoff_summary_for(self, agent: Agent, transcript: str) -> str:
        """Spawn a summarizer to distil a finishing-by-exhaustion agent's work into a HANDOFF for
        its parent / the orchestrator — so an agent that hit its turn budget before calling `finish`
        does not lose its findings. The summary captures concrete findings + evidence, what was done
        and the current state, and what remains. Returns the summary text."""
        instr = (
            f"Agent '{agent.name}' (role {agent.role}) ran out of its turn budget BEFORE it could "
            f"call `finish`, so its findings would otherwise be lost. Its task was:\n{agent.task}\n\n"
            f"Read its full transcript below and produce a concise HANDOFF for its parent/the "
            f"orchestrator so nothing is lost. Cover, with specifics and evidence:\n"
            f"1. FINDINGS — what was actually discovered (hosts/services/vulns/creds/endpoints), with proof.\n"
            f"2. STATE — what was done and where it got to.\n"
            f"3. REMAINING — what is left and the recommended next steps.\n\n"
            f"--- TRANSCRIPT START ---\n{transcript}\n--- TRANSCRIPT END ---\n\n"
            f"Return ONLY the handoff summary via finish."
        )
        child = await self.create_agent("summarizer", instr, parent=agent)
        self.start_agent(child)
        result = await self.wait_for(child)
        return (result or "").strip()

    def _report_context(self) -> str:
        """A compact, factual snapshot of the session for the report writer."""
        lines = [f"Session: {self.name}", f"Target: {self.target or '(none specified)'}"]
        if self.instructions:
            lines.append(f"Engagement scope/instructions: {self.instructions}")
        steps = self.plan.get("steps", [])
        if steps:
            lines.append("\nPlan:")
            lines += [f"  {s['id'] + 1}. [{s['status']}] {s['text']}" for s in steps]
        if self.findings:
            lines.append(f"\nFindings ({len(self.findings)}):")
            for f in self.findings.values():
                d = f.get("data", {})
                lines.append(
                    f"  - {f['id']} [{f['severity']}/{f['status']}] {f['title']} "
                    f"@ {d.get('location', '?')}"
                )
        else:
            lines.append("\nFindings: none recorded.")
        agents = [a for a in self.agents.values() if a.role != "reporting"]
        if agents:
            lines.append("\nAgents that participated:")
            lines += [f"  - {a.name} ({a.role}) — {a.status}" for a in agents]
        return "\n".join(lines)

    # severity rank for sorting / dedup (higher = more severe)
    _SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}

    def _report_findings_dossier(self, per_evidence: int = 1500, max_total: int = 24000) -> str:
        """A DEDUPLICATED, full-detail dossier of this session's findings — the single authoritative
        source the report is written from. The same vulnerability reported by several agents (same
        title + location) collapses to ONE entry (the most severe / most-detailed instance wins), so
        the reporter sees each finding once instead of the same one echoed across master memory, role
        memory and notes — the duplication that was overflowing its context. Each unique finding
        carries its severity, status, location, CWE, description and evidence (evidence capped per
        finding at ``per_evidence``; the whole block bounded by ``max_total``); the full record always
        remains at ``findings/<id>.json`` for the rare case the reporter needs more."""
        if not self.findings:
            return "(no findings were recorded this session — report that the engagement found nothing of note)"
        rank = self._SEVERITY_RANK
        groups: dict[tuple, dict] = {}
        for f in self.findings.values():
            d = f.get("data") or {}
            key = (str(f.get("title", "")).strip().lower(), str(d.get("location", "")).strip().lower())
            cur = groups.get(key)
            if cur is None:
                groups[key] = f
                continue
            # keep the better duplicate: higher severity, then more evidence (more detail)
            cd = cur.get("data") or {}
            challenger = (rank.get(f.get("severity"), 0), len(str(d.get("evidence", ""))))
            incumbent = (rank.get(cur.get("severity"), 0), len(str(cd.get("evidence", ""))))
            if challenger > incumbent:
                groups[key] = f
        uniques = sorted(groups.values(), key=lambda f: -rank.get(f.get("severity"), 0))
        dupes = len(self.findings) - len(uniques)
        header = f"{len(uniques)} unique finding(s)" + (f" (deduplicated from {len(self.findings)} recorded)" if dupes else "") + ":"
        lines = [header]
        budget = max_total
        for f in uniques:
            d = f.get("data") or {}
            desc = str(d.get("description", "")).strip()
            ev = str(d.get("evidence", "")).strip()
            if len(ev) > per_evidence:
                ev = ev[:per_evidence] + f"\n…[evidence truncated — full text in findings/{f['id']}.json]"
            block = (
                f"\n### {f.get('title') or '(untitled)'}  [{f.get('severity', '?')}/{f.get('status', '?')}]\n"
                f"- id: {f['id']}\n"
                f"- location: {d.get('location') or 'N/A'}\n"
                + (f"- cwe: {d['cwe']}\n" if d.get("cwe") else "")
                + (f"- description: {desc}\n" if desc else "")
                + (f"- evidence:\n{ev}\n" if ev else "")
            )
            if budget - len(block) < 0 and len(lines) > 1:
                lines.append("\n…[further findings omitted to bound context — read findings/<id>.json for the rest]")
                break
            lines.append(block)
            budget -= len(block)
        return "\n".join(lines)

    async def generate_report(self, instructions: str = "", template: str = "") -> dict[str, Any]:
        """Spawn a reporter agent to write the full session report, then emit BOTH a Markdown
        and a Word (.docx) file. When a `template` is given (e.g. text extracted from an operator's
        PDF/Word template) the report must reproduce its structure EXACTLY. Honours extra
        `instructions`. Returns {report, path, docx_path?, docx_name?, docx_error?, agent_id}."""
        import time as _time

        from . import docs

        if not self.roles:
            from .registry import role_specs

            self.roles = role_specs(self.cfg)
        reports_dir = self.workspace / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = _time.strftime("%Y%m%d_%H%M%S")
        rel_path = f"reports/report_{stamp}.md"

        tmpl = template.strip()
        instr = (instructions or "").strip()
        if tmpl:
            tmpl_block = (
                f"=== TEMPLATE TO FOLLOW (reproduce its structure EXACTLY) ===\n{tmpl}\n\n"
                "The report MUST follow this template's EXACT structure: the same sections in the "
                "same order, with the same headings/subheadings and any tables it defines. Fill each "
                "section with THIS engagement's real content; keep every section even if short (write "
                "'None'/'N/A' where there is nothing). Do not add or remove top-level sections, and do "
                "not reorder them."
            )
        else:
            tmpl_block = "=== TEMPLATE ===\n(no template provided — use your own comprehensive pentest structure)"
        brief = (
            f"Write the full engagement report for this session and save it to `{rel_path}`.\n\n"
            f"=== SESSION CONTEXT ===\n{self._report_context()}\n\n"
            f"=== FINDINGS DOSSIER (deduplicated — the authoritative source for the report) ===\n"
            f"{self._report_findings_dossier()}\n\n"
            f"=== EXTRA INSTRUCTIONS FROM OPERATOR ===\n{instr or '(none)'}\n\n"
            f"{tmpl_block}\n\n"
            f"Write the report from the FINDINGS DOSSIER and SESSION CONTEXT above — they already "
            f"contain every unique finding with its evidence, deduplicated. Do NOT bulk-read the "
            f"memory files (master.md / role_*.md / notes) to rebuild this; that content is already "
            f"summarised here and re-reading it will overflow your context. Only if a specific "
            f"finding's evidence was truncated and you genuinely need the rest, read that one "
            f"`findings/<id>.json`. "
            f"Write valid GitHub-flavoured Markdown — use #/##/### heading levels matching the "
            f"template's hierarchy, and Markdown tables (| col | col |) wherever the template has a "
            f"table — so it converts cleanly to Word. Then `write_file` the complete Markdown report "
            f"to `{rel_path}` and `finish` with the report text (or a brief confirmation)."
        )
        reporter = await self.create_agent("reporting", brief, parent=self.orchestrator)
        self.start_agent(reporter)
        await self.wait_for(reporter)

        out_file = self.workspace / rel_path
        report = ""
        if out_file.exists():
            report = out_file.read_text(encoding="utf-8", errors="replace")
        if not report.strip():
            report = reporter.result or "(report generation produced no output)"
            out_file.write_text(report, encoding="utf-8")

        # Also render a Word (.docx) version with the same structure.
        result: dict[str, Any] = {"report": report, "path": str(out_file), "agent_id": reporter.id}
        docx_rel = f"reports/report_{stamp}.docx"
        ok, derr = docs.markdown_to_docx(report, str(self.workspace / docx_rel))
        if ok:
            result["docx_path"] = str(self.workspace / docx_rel)
            result["docx_name"] = f"report_{stamp}.docx"
        else:
            result["docx_error"] = derr
        bus.emit(E.LOG, self.id, {"level": "info",
                 "message": f"report generated -> {rel_path}" + (f" + {docx_rel}" if ok else f" (.docx skipped: {derr})")})
        return result

    # ------------------------------------------------ reference documents (operator uploads)
    @property
    def uploads_dir(self) -> Path:
        return self.workspace / "uploads"

    def _uploads_manifest_path(self) -> Path:
        return self.uploads_dir / "manifest.json"

    def list_uploads(self) -> list[dict]:
        """Reference documents attached to this session (name, type, size, extracted chars,
        any extraction error). Read from the on-disk manifest so it survives restarts."""
        path = self._uploads_manifest_path()
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def _write_uploads_manifest(self, entries: list[dict]) -> None:
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self._uploads_manifest_path().write_text(json.dumps(entries, indent=2), encoding="utf-8")

    def add_upload(self, filename: str, data: bytes) -> dict:
        """Save an operator-attached document, extract its text, and record it in the manifest.

        The original file is stored under ``uploads/`` and the extracted plain text under
        ``uploads/text/<name>.txt`` so any agent can ``read_file`` it. Returns the manifest entry
        (which includes a non-fatal ``error`` string if the file could not be parsed)."""
        import time as _time

        from . import docs

        name = docs.safe_name(filename)
        (self.uploads_dir / "text").mkdir(parents=True, exist_ok=True)
        # Avoid clobbering an existing different file with the same name.
        entries = [e for e in self.list_uploads() if e.get("name") != name]
        (self.uploads_dir / name).write_bytes(data)
        text, error = docs.extract_text(data, name)
        text_rel = f"uploads/text/{name}.txt"
        (self.workspace / text_rel).write_text(text, encoding="utf-8")
        entry = {
            "name": name,
            "size": len(data),
            "ext": Path(name).suffix.lower(),
            "chars": len(text),
            "text_path": text_rel,
            "error": error,
            "uploaded_at": _time.time(),
        }
        entries.append(entry)
        self._write_uploads_manifest(entries)
        bus.emit(E.LOG, self.id, {"level": "info",
                 "message": f"reference document attached: {name} ({len(text)} chars)"
                 + (f" — note: {error}" if error else "")})
        return entry

    def remove_upload(self, name: str) -> bool:
        """Delete an attached document (original + extracted text) and update the manifest."""
        from . import docs

        name = docs.safe_name(name)
        entries = self.list_uploads()
        kept = [e for e in entries if e.get("name") != name]
        if len(kept) == len(entries):
            return False
        for p in (self.uploads_dir / name, self.workspace / "uploads" / "text" / f"{name}.txt"):
            try:
                p.unlink()
            except OSError:
                pass
        self._write_uploads_manifest(kept)
        return True

    def _reference_docs_block(self, per_doc: int = 4000, max_total: int = 16000) -> str:
        """Build the orchestrator-brief section describing the operator's reference documents:
        each doc's extracted text inlined up to ``per_doc`` chars (full text remains readable at
        its ``uploads/text/...`` path), bounded overall by ``max_total`` to protect context."""
        entries = [e for e in self.list_uploads() if e.get("chars")]
        if not entries:
            return ""
        lines = [
            "=== REFERENCE DOCUMENTS (operator-provided) ===",
            "The operator attached these documents to inform the engagement (scope, rules of "
            "engagement, prior findings, target docs, etc.). Use them. Each is shown below "
            "(truncated); read the FULL text with `read_file` at the given path when you need more.",
        ]
        budget = max_total
        for e in entries:
            if budget <= 0:
                lines.append(f"\n- {e['name']} ({e['ext']}, {e['chars']} chars) — full text: {e['text_path']} "
                             f"(omitted here to save context; read it with read_file).")
                continue
            try:
                text = (self.workspace / e["text_path"]).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            cap = min(per_doc, budget)
            shown = text[:cap]
            truncated = len(text) > cap
            budget -= len(shown)
            lines.append(f"\n--- {e['name']} ({e['ext']}, {e['chars']} chars; full text at {e['text_path']}) ---")
            lines.append(shown + (f"\n…[truncated — read {e['text_path']} for the rest]" if truncated else ""))
        return "\n".join(lines)

    async def wait_for(self, agent: Agent) -> str:
        """Await an already-started agent's task and return its result (safe if the agent
        was never started or was cancelled)."""
        task = self._tasks.get(agent.id)
        if task is None:
            return agent.result
        try:
            return await task
        except asyncio.CancelledError:
            return agent.result or "(cancelled)"

    def get_agent(self, agent_id: str) -> Agent | None:
        return self.agents.get(agent_id)

    def can_spawn(self, parent: Agent) -> tuple[bool, str]:
        if parent.depth >= self.max_depth:
            return False, f"maximum sub-agent depth ({self.max_depth}) reached"
        if len(self.agents) >= self.max_agents:
            return False, f"maximum total agents ({self.max_agents}) reached"
        # Per-agent limit on real sub-agents (framework helpers don't count).
        children = sum(1 for a in self.agents.values()
                       if a.parent_id == parent.id and a.role not in _HELPER_ROLES)
        if children >= self.max_children_per_agent:
            return False, f"this agent already spawned its maximum sub-agents ({self.max_children_per_agent})"
        return True, ""

    # --------------------------------------------------------------- plan
    def set_plan(self, steps: list[str]) -> None:
        """Replace the plan with a fresh ordered list of steps (each pending), emit a
        plan.update event, and persist. Called by the update_plan tool."""
        self.plan = {
            "steps": [{"id": i, "text": s, "status": "pending"} for i, s in enumerate(steps)]
        }
        bus.emit(E.PLAN_UPDATE, self.id, {"plan": self.plan})
        asyncio.create_task(self.persist())

    def set_step_status(self, index: int, status: str) -> bool:
        """Set one plan step's status by id; emit a plan.step event and persist. Returns
        False if no step has that index."""
        for step in self.plan["steps"]:
            if step["id"] == index:
                step["status"] = status
                bus.emit(E.STEP_UPDATE, self.id, {"index": index, "status": status, "plan": self.plan})
                asyncio.create_task(self.persist())
                return True
        return False

    # ------------------------------------------------- plan approval (human-in-the-loop)
    def _plan_needs_approval(self) -> bool:
        """Whether the CURRENT plan submission requires operator sign-off, per the
        `human_in_the_loop.plan_approval` mode: 'off' never; 'once' only the first plan;
        'on_change' every submission (the first plan and every later revision)."""
        if self.plan_approval_mode == "off":
            return False
        if self.plan_approval_mode == "on_change":
            return True
        # "once": only until the operator has approved a plan a single time.
        return not self._plan_approved_once

    async def submit_plan(self, agent: Agent, steps: list[str]) -> str:
        """Set the plan and, when the policy requires it, pause for operator sign-off.

        This is what the `update_plan` tool calls. Depending on `plan_approval` mode the
        operator may have to APPROVE the plan before the engagement proceeds; they can also
        REJECT it with feedback (the orchestrator revises and resubmits) or EDIT it directly
        (their edited steps replace the plan and count as approved). With
        `block_on_plan_approval` False the plan is set and the orchestrator continues while the
        operator reviews asynchronously. Returns a status string the orchestrator acts on."""
        self.set_plan(steps)
        if not self._plan_needs_approval():
            return f"Plan set with {len(steps)} steps (operator approval not required)."
        if not self.block_on_plan_approval:
            self._announce_plan_approval(blocking=False)
            return (f"Plan set with {len(steps)} steps and sent to the operator for review. "
                    f"Continue, but watch for operator feedback in your inbox.")

        self._plan_counter += 1
        rid = f"plan_{self._plan_counter}"
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_plan_approvals[rid] = {
            "id": rid, "agent_id": agent.id, "plan": self.plan, "future": fut,
        }
        bus.emit(E.PLAN_APPROVAL_REQUEST, self.id,
                 {"id": rid, "plan": self.plan, "mode": self.plan_approval_mode}, agent_id=agent.id)
        self._set_status("awaiting_plan_approval")
        try:
            decision = await fut
        except asyncio.CancelledError:
            return "Plan approval was cancelled (session stopping)."
        # decision: {"decision": "approve"|"reject"|"edit", "feedback": str, "steps": [...]}
        verdict = decision.get("decision", "approve")
        feedback = (decision.get("feedback") or "").strip()
        if self.status == "awaiting_plan_approval":
            self._set_status("running")
        if verdict == "approve":
            self._plan_approved_once = True
            return "Operator APPROVED the plan. Proceed with execution."
        if verdict == "edit":
            new_steps = decision.get("steps") or steps
            self.set_plan([str(s) for s in new_steps])
            self._plan_approved_once = True
            extra = f" Operator note: {feedback}" if feedback else ""
            return ("Operator EDITED and approved the plan; the plan now reflects their edits — "
                    f"proceed with the UPDATED plan.{extra}")
        # reject
        return (f"Operator REJECTED the plan. Feedback: {feedback or '(none given)'}. "
                f"Revise the plan accordingly and call `update_plan` again.")

    def _announce_plan_approval(self, blocking: bool) -> None:
        bus.emit(E.PLAN_APPROVAL_REQUEST, self.id,
                 {"id": "", "plan": self.plan, "mode": self.plan_approval_mode, "blocking": blocking})

    def resolve_plan_approval(self, request_id: str, decision: str, feedback: str = "",
                              steps: list | None = None) -> bool:
        """Operator's verdict on a pending plan (approve | reject | edit), delivered by the
        REST endpoint. Resolves the orchestrator's waiting future so it proceeds, revises, or
        adopts the edited plan."""
        info = self._pending_plan_approvals.pop(request_id, None)
        if not info:
            return False
        fut: asyncio.Future = info["future"]
        if not fut.done():
            fut.set_result({"decision": decision, "feedback": feedback, "steps": steps})
        bus.emit(E.PLAN_APPROVAL_RESOLVED, self.id,
                 {"id": request_id, "decision": decision, "feedback": feedback})
        return True

    def pending_plan_approvals(self) -> list[dict]:
        return [{k: v for k, v in p.items() if k != "future"}
                for p in self._pending_plan_approvals.values()]

    def has_pending_plan_approval(self, agent_id: str | None = None) -> bool:
        """True if a plan (submitted by ``agent_id``, or any agent when None) is still awaiting the
        operator's decision. Lets the agent loop tell a genuine 'waiting for approval' state apart
        from a finished one, so it doesn't nudge the orchestrator toward `finish` while it waits."""
        return any(agent_id in (None, p.get("agent_id"))
                   for p in self._pending_plan_approvals.values())

    async def await_plan_decision_for(self, agent: Agent) -> str | None:
        """If ``agent`` has a plan still awaiting the operator, BLOCK until they decide and return
        the verdict message for the agent to act on — turning an idle 'standing by for approval'
        turn into a real wait instead of an 'unfinished conversation' nudge. Returns None when no
        plan of this agent's is pending (the normal case, since blocking `submit_plan` already
        awaits its own decision inline)."""
        pend = next((p for p in self._pending_plan_approvals.values()
                     if p.get("agent_id") == agent.id), None)
        if not pend:
            return None
        try:
            decision = await pend["future"]
        except asyncio.CancelledError:
            return None
        verdict = decision.get("decision", "approve")
        feedback = (decision.get("feedback") or "").strip()
        if verdict == "edit":
            return "Operator EDITED and approved the plan — proceed with the UPDATED plan."
        if verdict == "reject":
            return (f"Operator REJECTED the plan. Feedback: {feedback or '(none given)'}. "
                    f"Revise the plan and call `update_plan` again.")
        return "Operator APPROVED the plan. Proceed with execution."

    # ------------------------------------------------- operator interjection / intensity
    async def interject(self, message: str) -> str:
        """Deliver an operator message / new direction to the orchestrator mid-engagement.
        The orchestrator reads it on its next turn (re-activated if idle). This is the main
        'jump in and steer' control. Returns a short status string."""
        if not self.allow_interjection:
            return "Interjection is disabled in this session's settings."
        if not message.strip():
            return "Empty message ignored."
        bus.emit(E.OPERATOR_INTERJECTION, self.id, {"message": message})
        # Persist so it shows in the discussion feed after a restart.
        try:
            await self.db.add_message(self.id, self.orchestrator.id if self.orchestrator else "session",
                                      "operator", {"message": message})
        except Exception:  # noqa: BLE001
            pass
        if not self.orchestrator:
            return "No orchestrator is running yet; start the engagement first."
        return await self.message_agent(self.orchestrator.id, f"[OPERATOR INTERJECTION] {message}")

    def set_intensity(self, level: str) -> bool:
        """Change the session-wide default tool intensity (passive..insane). Agents pick it up
        for subsequent tool calls; emitted so the UI reflects it."""
        if level not in cfg_mod.INTENSITY_LEVELS:
            return False
        self.default_intensity = level
        bus.emit(E.INTENSITY_CHANGED, self.id, {"intensity": level})
        return True

    def set_approval_mode(self, mode: str) -> bool:
        """Override the tool-approval mode for THIS session at runtime (does not touch global
        config). ``auto`` bypasses ALL tool approval (commands run without sign-off); ``manual``
        restores the per-category policy. Switching to ``auto`` also auto-approves any approval
        currently waiting. Emitted so the UI reflects the live state. This is the mid-session
        'disable command validation' checkbox."""
        if mode not in ("manual", "auto"):
            return False
        self.approval_mode = mode
        if mode == "auto":
            # Release anything currently blocked on operator sign-off.
            for aid in list(self._pending_approvals):
                self.resolve_approval(aid, True, "approval bypass enabled for this session")
        bus.emit(E.APPROVAL_MODE_CHANGED, self.id, {"approval_mode": mode})
        return True

    # ------------------------------------------------- Kali process monitor
    def _kali_client(self):
        """The session's connected Kali MCP client, or None."""
        client = self.mcp_clients.get("kali")
        if client is None:
            client = next((c for k, c in self.mcp_clients.items()
                           if k == "kali" or k.startswith("kali#")), None)
        return client if (client is not None and getattr(client, "connected", False)) else None

    async def list_kali_processes(self) -> list[dict]:
        """Processes (commands/tools) this session is currently running inside the Kali container —
        for the operator's process monitor. Empty if Kali isn't connected."""
        client = self._kali_client()
        if client is None:
            return []
        try:
            raw = await client.call_tool("__list_processes__", {"session": self.id})
            data = json.loads(raw)
            return data if isinstance(data, list) else []
        except Exception:  # noqa: BLE001 — monitor is best-effort
            return []

    async def kill_kali_process(self, proc_id: str, message: str = "") -> dict:
        """Kill one running Kali process and notify the agent that launched it (so it can adapt,
        e.g. choose a lighter scan). ``message`` is the operator's explanation. Returns a status
        dict ``{ok, killed?, error?}``."""
        client = self._kali_client()
        if client is None:
            return {"ok": False, "error": "Kali is not connected."}
        try:
            data = json.loads(await client.call_tool("__kill_process__", {"proc_id": proc_id}))
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}
        if not data.get("ok"):
            return {"ok": False, "error": data.get("error", "could not kill process")}
        rec = data.get("killed", {}) or {}
        bus.emit(E.KALI_PROCESS_KILLED, self.id,
                 {"proc": rec, "by": "operator", "message": message})
        # Tell the responsible agent its process was killed (and why), so it doesn't just retry.
        agent_id = rec.get("agent")
        if agent_id and self.agents.get(agent_id):
            note = (f"[OPERATOR] Your running process was KILLED by the operator: "
                    f"{rec.get('tool') or 'command'} — `{(rec.get('command') or '')[:200]}`.")
            if message.strip():
                note += f"\nReason from the operator: {message.strip()}"
            note += ("\nDo NOT simply relaunch the same command. Adapt: use a lighter intensity, a "
                     "smaller wordlist/scope, or ask the operator (ask_user) how to proceed.")
            try:
                await self.message_agent(agent_id, note)
            except Exception:  # noqa: BLE001
                pass
        return {"ok": True, "killed": rec}

    async def kill_all_kali_processes(self, reason: str = "session stopped") -> int:
        """Kill EVERY Kali process this session launched (called on stop, so no tool keeps running
        in the container after the engagement ends). Returns the number killed."""
        client = self._kali_client()
        if client is None:
            return 0
        try:
            data = json.loads(await client.call_tool("__kill_session__", {"session": self.id}))
        except Exception:  # noqa: BLE001
            return 0
        n = int(data.get("count", 0) or 0)
        if n:
            bus.emit(E.LOG, self.id, {"level": "info",
                     "message": f"killed {n} running Kali process(es) ({reason})"})
        return n

    # ------------------------------------------------------------ findings
    async def add_finding(self, fid: str, agent: Agent, title: str, severity: str, status: str, data: dict) -> None:
        """Record a finding in three places — the in-memory dict, a JSON file under the
        workspace ``findings/`` folder, and the SQLite ``findings`` table — then emit a
        finding.stored event. Called by the store_finding tool."""
        record = {
            "id": fid,
            "session_id": self.id,
            "agent_id": agent.id,
            "title": title,
            "severity": severity,
            "status": status,
            "data": data,
        }
        self.findings[fid] = record
        # Persist to the workspace findings folder (file-based memory) and DB.
        (self.workspace / "findings" / f"{fid}.json").write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
        await self.db.save_finding(
            {
                "id": fid,
                "session_id": self.id,
                "agent_id": agent.id,
                "title": title,
                "severity": severity,
                "status": status,
                "data_json": json.dumps(data),
            }
        )
        bus.emit(E.FINDING, self.id, {"finding": record}, agent_id=agent.id)

    # -------------------------------------------------------------- cost
    def add_cost(self, agent: Agent, usage: Usage) -> None:
        """Convert one turn's token `usage` to USD and roll it into the running totals.

        This is the single place token usage becomes money. Pricing is per-model and per
        token-bucket (input / output / cache_read / cache_write), expressed in USD per
        1,000,000 tokens in ``cfg["pricing"]`` (defaults in config.DEFAULT_PRICING, editable
        in Settings → Pricing). The cost is accumulated three ways for the UI: on the agent
        (``agent.cost_usd``), in the session total, and broken down ``by_agent`` and
        ``by_model``. Then a cost.update event is emitted. Called once per LLM turn from
        ``Agent._loop`` in agents.py. To change the cost formula, edit ``usd`` below."""
        model = agent.model_config.get("model", "")
        # Look up this model's rates; unknown models price at zero (won't crash the run).
        price = self.cfg.get("pricing", {}).get(model, {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0})
        # tokens / 1e6 * (USD per million tokens), summed over the four token buckets.
        usd = (
            usage.input_tokens / 1e6 * price.get("input", 0)
            + usage.output_tokens / 1e6 * price.get("output", 0)
            + usage.cache_read / 1e6 * price.get("cache_read", 0)
            + usage.cache_write / 1e6 * price.get("cache_write", 0)
        )
        agent.cost_usd += usd
        c = self.cost
        c["total_usd"] += usd
        c["input_tokens"] += usage.input_tokens
        c["output_tokens"] += usage.output_tokens
        c["cache_read"] += usage.cache_read
        c["cache_write"] += usage.cache_write

        ba = c["by_agent"].setdefault(
            agent.id, {"name": agent.name, "role": agent.role, "model": model, "usd": 0.0, "input": 0, "output": 0}
        )
        ba["usd"] += usd
        ba["input"] += usage.input_tokens
        ba["output"] += usage.output_tokens

        bm = c["by_model"].setdefault(model, {"usd": 0.0, "input": 0, "output": 0})
        bm["usd"] += usd
        bm["input"] += usage.input_tokens
        bm["output"] += usage.output_tokens

        bus.emit(E.COST_UPDATE, self.id, {"cost": c}, agent_id=agent.id)

    # ----------------------------------------------------------- approvals
    def tool_needs_approval(self, tool: Tool, args: dict | None = None) -> bool:
        """Resolve the human-in-the-loop tool-approval policy for one tool call.

        Order of precedence:
          1. Global master switch ``approval_mode == "auto"`` -> never gate (autonomous run).
          2. ``tool.requires_approval`` hard floor -> always gate (e.g. run_as_admin).
          3. Tool name in policy ``always_auto_tools`` -> don't gate.
          4. Tool name in policy ``always_manual_tools`` -> gate.
          5. The tool's category in policy ``by_category`` -> that mode ("manual" => gate).
          6. Otherwise the policy ``default``.
        Edit the policy in Settings (or config["tool_approval"]) to change what needs sign-off."""
        if self.approval_mode == "auto":
            return False
        if getattr(tool, "requires_approval", False):
            return True
        policy = self.cfg.get("tool_approval", {}) or {}
        name = tool.name
        if name in (policy.get("always_auto_tools") or []):
            return False
        if name in (policy.get("always_manual_tools") or []):
            return True
        category = getattr(tool, "category", "control") or "control"
        by_cat = policy.get("by_category", {}) or {}
        mode = by_cat.get(category, policy.get("default", "manual"))
        return mode == "manual"

    async def request_approval(self, agent: Agent, tool: Tool, args: dict) -> tuple[bool, str]:
        """Block an agent's command-exec tool until the operator approves/denies it in the
        UI. Registers a pending approval + future, emits approval.request, and awaits the
        operator's decision (delivered via ``resolve_approval``). Returns (approved, reason)."""
        self._approval_counter += 1
        aid = f"ap_{self._approval_counter}"
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        category = getattr(tool, "category", "control")
        payload = {
            "id": aid,
            "agent_id": agent.id,
            "agent_name": agent.name,
            "tool": tool.name,
            "category": category,
            "input": args,
        }
        self._pending_approvals[aid] = {**payload, "future": fut}
        bus.emit(E.APPROVAL_REQUEST, self.id, payload, agent_id=agent.id)
        try:
            return await fut
        except asyncio.CancelledError:
            return False, "cancelled"

    def resolve_approval(self, approval_id: str, approved: bool, reason: str = "") -> bool:
        """Operator's answer to a pending approval: resolves the waiting future so the
        blocked tool proceeds or is denied. Called by the approvals REST endpoint."""
        info = self._pending_approvals.pop(approval_id, None)
        if not info:
            return False
        fut: asyncio.Future = info["future"]
        if not fut.done():
            fut.set_result((approved, reason))
        bus.emit(E.APPROVAL_RESOLVED, self.id, {"id": approval_id, "approved": approved, "reason": reason})
        return True

    def pending_approvals(self) -> list[dict]:
        return [
            {k: v for k, v in a.items() if k != "future"} for a in self._pending_approvals.values()
        ]

    # ----------------------------------------------------- user input requests
    async def request_input(self, agent: Agent, message: str, kind: str = "text", suggestion: str = "") -> str:
        """Ask the operator a free-text question (e.g. which file to load into the
        reverse tool) and block until they answer. Returns the answer text."""
        self._request_counter += 1
        rid = f"req_{self._request_counter}"
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending_requests[rid] = {
            "id": rid, "agent_id": agent.id, "agent_name": agent.name,
            "message": message, "kind": kind, "suggestion": suggestion, "future": fut,
        }
        bus.emit(
            E.USER_REQUEST, self.id,
            {"id": rid, "agent_id": agent.id, "agent_name": agent.name,
             "message": message, "kind": kind, "suggestion": suggestion},
            agent_id=agent.id,
        )
        try:
            return await fut
        except asyncio.CancelledError:
            return ""

    def resolve_request(self, request_id: str, answer: str) -> bool:
        info = self._pending_requests.pop(request_id, None)
        if not info:
            return False
        fut: asyncio.Future = info["future"]
        if not fut.done():
            fut.set_result(answer)
        bus.emit(E.USER_REQUEST_RESOLVED, self.id, {"id": request_id, "answer": answer})
        return True

    def pending_requests(self) -> list[dict]:
        return [{k: v for k, v in r.items() if k != "future"} for r in self._pending_requests.values()]

    # ------------------------------------------------------------- run control
    def _set_status(self, status: str) -> None:
        self.status = status
        bus.emit(E.SESSION_STATUS, self.id, {"status": status})

    async def start(self, target: str, instructions: str) -> None:
        """Begin a fresh engagement: run setup(), build the orchestrator's brief from the
        target + instructions, create and launch the orchestrator agent, and monitor it.
        This is the top of the whole agent pipeline."""
        self.target = target
        self.instructions = instructions
        await self.setup()
        self._set_status("running")
        plan_note = {
            "off": "Operator plan approval is OFF — you may proceed once you have a plan.",
            "once": "Operator must APPROVE your FIRST plan before work proceeds (update_plan will block "
                    "until they do, and may return a rejection to revise).",
            "on_change": "Operator must APPROVE your plan AND every later revision (update_plan blocks each time).",
        }.get(self.plan_approval_mode, "")
        brief = (
            f"TARGET / SCOPE: {target}\n\nRULES OF ENGAGEMENT & INSTRUCTIONS:\n{instructions}\n\n"
            f"Your workspace is '{self.workspace}'. Conduct the full AUTHORISED penetration test: plan, "
            f"get operator sign-off if required, delegate to your specialist agents (recon -> web_app/"
            f"network -> exploitation -> post_exploit), validate findings with evidence, and stay in scope.\n"
            f"Current tool intensity: '{self.default_intensity}'. {plan_note}\n"
            f"The operator may interject at any time — watch your inbox and adapt."
        )
        ref_docs = self._reference_docs_block()
        if ref_docs:
            brief += "\n\n" + ref_docs
        self.orchestrator = await self.create_agent("orchestrator", brief, parent=None)
        task = self.start_agent(self.orchestrator)
        asyncio.create_task(self._monitor(task))
        await self.persist()

    async def _monitor(self, task: "asyncio.Task[str]") -> None:
        """Await the orchestrator task in the background and set the final session status
        (completed / stopped / error), persisting the outcome."""
        try:
            await task
            if self.status == "running":
                self._set_status("completed")
        except asyncio.CancelledError:
            self._set_status("stopped")
        except Exception as e:  # noqa: BLE001
            self._set_status("error")
            bus.emit(E.ERROR, self.id, {"message": f"Session error: {e}"})
        await self.persist()

    async def resume(self, extra_instructions: str = "") -> None:
        """Resume by re-launching the orchestrator with the prior plan and findings
        as context, plus any new operator instructions."""
        self.reload_config()   # pick up config changes (e.g. raised max_turns) made since creation
        await self.setup()
        self._set_status("running")
        plan_text = "\n".join(f"  [{s['status']}] {s['text']}" for s in self.plan.get("steps", []))
        findings_text = "\n".join(
            f"  {f['id']} [{f['severity']}/{f['status']}] {f['title']}" for f in self.findings.values()
        )
        brief = (
            f"TARGET: {self.target}\n\nORIGINAL INSTRUCTIONS:\n{self.instructions}\n\n"
            f"This is a RESUMED session. Existing plan:\n{plan_text or '  (none)'}\n\n"
            f"Existing findings:\n{findings_text or '  (none)'}\n\n"
            f"Continue the engagement from where it left off. New operator instructions:\n"
            f"{extra_instructions or '(none — continue the remaining plan steps)'}"
        )
        ref_docs = self._reference_docs_block()
        if ref_docs:
            brief += "\n\n" + ref_docs
        self.orchestrator = await self.create_agent("orchestrator", brief, parent=None)
        task = self.start_agent(self.orchestrator)
        asyncio.create_task(self._monitor(task))
        await self.persist()

    async def stop(self) -> None:
        """Halt the whole session: signal every agent to stop, deny/clear all pending
        approvals and operator requests, cancel running tasks, set status, and shut down
        external resources (MCP clients + the event-log writer)."""
        for agent in self.agents.values():
            agent.stop()
        for aid, info in list(self._pending_approvals.items()):
            self.resolve_approval(aid, False, "session stopped")
        for rid in list(self._pending_requests):
            self.resolve_request(rid, "")
        for rid in list(self._pending_plan_approvals):
            self.resolve_plan_approval(rid, "reject", "session stopped")
        for task in self._tasks.values():
            if not task.done():
                task.cancel()
        # Kill any tools still running in the Kali container BEFORE we close the MCP client, so
        # nothing keeps scanning the target after the engagement is stopped.
        try:
            await self.kill_all_kali_processes(reason="session stopped")
        except Exception:  # noqa: BLE001
            pass
        self._set_status("stopped")
        await self.persist()
        await self.shutdown()

    async def shutdown(self) -> None:
        """Close external resources (MCP clients, event log). Safe to call multiple times."""
        if self._log_task and not self._log_task.done():
            self._log_task.cancel()
        for client in self.mcp_clients.values():
            await client.close()

    async def stop_agent(self, agent_id: str) -> bool:
        agent = self.agents.get(agent_id)
        if not agent:
            return False
        agent.stop()
        task = self._tasks.get(agent_id)
        if task and not task.done():
            task.cancel()
        # release any approval this agent is waiting on
        for aid, info in list(self._pending_approvals.items()):
            if info["agent_id"] == agent_id:
                self.resolve_approval(aid, False, "agent stopped")
        return True

    async def message_agent(self, agent_id: str, message: str) -> str:
        agent = self.agents.get(agent_id)
        if not agent:
            return "no such agent"
        # Re-engaging an idle/finished/stopped session: pick up any config changes (e.g. a raised
        # max_turns) made in Settings since the session was created, and — if it was stopped —
        # revive its tools/log. A live session keeps its current config untouched.
        if self.status != "running":
            self.reload_config()
            if self.status == "stopped":
                await self.revive()
            else:
                self._set_status("running")
                await self.persist()
        agent.deliver(message, sender="operator")
        if not agent.is_running:
            asyncio.create_task(self._resume_agent(agent))
            return "delivered; agent re-activated"
        return "delivered to active agent"

    def reload_config(self) -> None:
        """Refresh this session's MODEL settings (per-role model/params incl. ``max_turns``, plus
        pricing and the context budget) from the saved global config. A session otherwise freezes a
        config SNAPSHOT taken at creation, so a change made in Settings afterwards (e.g. raising
        ``max_turns``) would never apply; calling this when the session is resumed/continued lets it
        take effect. Agents read ``max_turns`` live from ``self.cfg`` (see ``Agent._max_turns``), so
        even already-created agents pick up the new budget; other params apply to agents spawned
        after the refresh. Structural session fields are left untouched.

        No-op when there is no saved config file on disk (a fresh install, or a test driving a session
        from a hand-built in-memory config): in that case the in-memory ``self.cfg`` is authoritative
        and must not be clobbered by the packaged defaults."""
        if not cfg_mod._config_file().exists():
            return
        try:
            latest = cfg_mod.load_config()
        except Exception:  # noqa: BLE001
            return
        if isinstance(latest.get("models"), dict):
            self.cfg["models"] = latest["models"]
        if "pricing" in latest:
            self.cfg["pricing"] = latest["pricing"]
        if "max_context_tokens" in latest:
            self.cfg["max_context_tokens"] = latest["max_context_tokens"]
        # Outbound proxies also affect how agents reach the LLM / Kali, so keep them current too.
        for k in ("client_proxy", "kali_proxy"):
            if k in latest:
                self.cfg[k] = latest[k]

    def build_model_config(self, role: str) -> dict[str, Any]:
        """Build a fresh model_config for `role` from the session's CURRENT config (the per-role model
        settings + the live client-proxy injection). Used both when spawning an agent and when a
        finished/stopped agent is restarted, so each always runs on the latest configuration."""
        mc = deepcopy(self.cfg["models"].get(role) or self.cfg["models"]["orchestrator"])
        mc["_client_proxy"] = self.cfg.get("client_proxy")
        return mc

    async def revive(self) -> None:
        """Bring a STOPPED session back to a working state so the operator can resume a
        conversation with its agents. ``stop()`` cancels the agents' tasks, kills Kali processes
        and (via ``shutdown``) closes the MCP tool servers + event log; this undoes the teardown:
        reconnect each MCP client IN PLACE (same objects the agents' tools are already bound to,
        so their tools work again), restart the event log, and mark the session running. The
        per-agent stop flags are cleared lazily by ``run_followup`` when each agent is re-engaged."""
        if self.status != "stopped":
            return
        self._start_event_log()
        for client in self.mcp_clients.values():
            if client and not client.connected:
                try:
                    await client.connect()
                except Exception as e:  # noqa: BLE001 — a tool server may be gone; carry on without it
                    bus.emit(E.LOG, self.id, {"level": "warn",
                             "message": f"could not reconnect MCP '{client.name}' on resume: {e}"})
        self._set_status("running")
        await self.persist()

    async def _resume_agent(self, agent: Agent) -> None:
        # run a follow-up loop for an idle agent prodded by the operator
        try:
            await agent.run_followup()
        except Exception as e:  # noqa: BLE001
            bus.emit(E.ERROR, self.id, {"message": f"agent resume failed: {e}"}, agent_id=agent.id)

    async def set_owner(self, owner: str) -> str:
        """Reassign the session's owner (admin action). Safe at any time — the workspace/db/logs are
        keyed by the session id, so this only changes who the session belongs to for access control
        and the session list. Persists the change."""
        owner = (owner or "").strip()
        if not owner:
            raise ValueError("owner must not be empty")
        self.owner = owner
        await self.persist()
        return owner

    async def rename(self, name: str) -> str:
        """Change the session's display name. Safe at ANY time (before/during/after a run): the
        workspace folder, DB rows and event log are all keyed by the session ID, never the name, so
        renaming only updates the label. Persists and broadcasts a live title update."""
        name = (name or "").strip()
        if not name:
            raise ValueError("name must not be empty")
        self.name = name
        await self.persist()
        bus.emit(E.SESSION_RENAMED, self.id, {"name": name})
        return name

    # ------------------------------------------------------------- persistence
    async def persist(self) -> None:
        await self.db.save_session(
            self.id, self.name, self.target, self.instructions, self.status, self.cfg,
            self.plan, self.cost, owner=self.owner,
        )

    async def persist_agent(self, agent: Agent) -> None:
        await self.db.save_agent(
            {
                "id": agent.id,
                "session_id": self.id,
                "parent_id": agent.parent_id,
                "role": agent.role,
                "name": agent.name,
                "task": agent.task,
                "status": agent.status,
                "result": agent.result,
            }
        )

    def _agents_for_dict(self) -> list[dict]:
        """Live agents plus any DB-restored agents not currently live (by id)."""
        out = [
            {
                "id": a.id, "name": a.name, "role": a.role, "status": a.status,
                "parent_id": a.parent_id, "result": a.result, "cost_usd": a.cost_usd,
                "model": a.model_config.get("model"), "tools": list(a.tools.keys()),
                "task": a.task, "system_prompt": a.system_prompt,
                "mcp_servers": list(a.mcp_server_defs.keys()),
                # live turn budget so a reconnecting UI shows rounds-left without waiting for the
                # next status event (a "round" = one LLM query; see Agent._set_status).
                "turns": a._turns, "max_turns": a._max_turns(),
            }
            for a in self.agents.values()
        ]
        live_ids = set(self.agents)
        by_agent = self.cost.get("by_agent", {})
        for a in self.restored_agents:
            if a["id"] in live_ids:
                continue
            ca = by_agent.get(a["id"], {})
            out.append({
                "id": a["id"], "name": a["name"], "role": a["role"], "status": a["status"],
                "parent_id": a["parent_id"], "result": a["result"] or "",
                "cost_usd": ca.get("usd", 0.0), "model": ca.get("model", ""),
                "tools": [], "task": a["task"] or "", "system_prompt": "", "mcp_servers": [],
            })
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "target": self.target,
            "instructions": self.instructions,
            "status": self.status,
            "approval_mode": self.approval_mode,
            "workspace": str(self.workspace),
            "plan": self.plan,
            "cost": self.cost,
            "findings": list(self.findings.values()),
            "agents": self._agents_for_dict(),
            "restored": bool(self.restored_agents and not self.agents),
            "pending_approvals": self.pending_approvals(),
            "pending_requests": self.pending_requests(),
            "pending_plan_approvals": self.pending_plan_approvals(),
            "plan_approval_mode": self.plan_approval_mode,
            "allow_interjection": self.allow_interjection,
            "intensity": self.default_intensity,
            "mcp": {name: c.connected for name, c in self.mcp_clients.items()},
        }


class SessionManager:
    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database()
        self.sessions: dict[str, Session] = {}

    def create(self, name: str, cfg: dict[str, Any], owner: str | None = None) -> Session:
        sid = "s_" + uuid.uuid4().hex[:8]
        session = Session(sid, name or sid, cfg, self.db, owner=owner)
        self.sessions[sid] = session
        return session

    def get(self, sid: str) -> Session | None:
        return self.sessions.get(sid)

    async def load(self, sid: str) -> Session | None:
        """Reconstruct a session (config/plan/findings/cost) from the DB if not in memory."""
        if sid in self.sessions:
            return self.sessions[sid]
        row = await self.db.get_session(sid)
        if not row:
            return None
        cfg = json.loads(row["config_json"] or "{}") or cfg_mod.load_config()
        session = Session(sid, row["name"], cfg, self.db, owner=row.get("owner"))
        session.target = row["target"] or ""
        session.instructions = row["instructions"] or ""
        session.status = row["status"] or "created"
        session.plan = json.loads(row["plan_json"] or '{"steps": []}')
        session.cost = json.loads(row["cost_json"] or "null") or _empty_cost()
        for f in await self.db.list_findings(sid):
            session.findings[f["id"]] = {
                "id": f["id"], "session_id": sid, "agent_id": f["agent_id"],
                "title": f["title"], "severity": f["severity"], "status": f["status"], "data": f["data"],
            }
        # Restore the agent roster so the tree and per-agent discussion reappear.
        session.restored_agents = await self.db.list_agents(sid)
        self.sessions[sid] = session
        return session

    async def delete(self, sid: str) -> bool:
        """Stop (if running), remove from memory + DB, and delete the workspace."""
        session = self.sessions.pop(sid, None)
        if session:
            if session.status == "running":
                await session.stop()
            await session.shutdown()
        # Resolve the workspace path even if the session wasn't in memory.
        ws = None
        if session:
            ws = session.workspace
        else:
            row = await self.db.get_session(sid)
            if row:
                cfg = json.loads(row["config_json"] or "{}")
                ws = Path(cfg.get("workspace_root", str(cfg_mod.WORKSPACE_ROOT))) / sid
        await self.db.delete_session(sid)
        if ws and ws.exists():
            import shutil

            shutil.rmtree(ws, ignore_errors=True)
        return True

    async def list_all(self, owner: str | None = None) -> list[dict]:
        """Session summaries. When ``owner`` is given, only that user's sessions are returned
        (per-user isolation); admins pass owner=None to list everything.

        Each summary carries ``owner`` (user id) and ``owner_name`` (username) so the admin's
        session list can label whose engagement each one is — the admin monitors and can stop
        any user's session from there."""
        rows = await self.db.list_sessions(owner=owner)
        # Resolve owner ids -> usernames once (cheap) so the list can show who owns each session.
        names = {u["id"]: u["username"] for u in await self.db.list_users()}
        out = []
        for r in rows:
            live = self.sessions.get(r["id"])
            oid = r.get("owner")
            out.append(
                {
                    "id": r["id"],
                    "name": r["name"],
                    "owner": oid,
                    "owner_name": names.get(oid) or ("—" if oid is None else oid),
                    "target": r["target"],
                    "status": live.status if live else r["status"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
            )
        return out
