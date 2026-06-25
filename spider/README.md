# Spider — Developer & Customization Guide (`spider/` package)

This document is the deep reference for the **Spider control app** — the FastAPI + WebSocket +
vanilla-JS + SQLite application that lives in this `spider/` package. It explains the architecture,
every module and its key functions, the data/event flow, and — most importantly — a
**customization cookbook** that tells you *exactly which file and function to edit* for each thing
you might want to change.

- New user / operator? Start with the top-level [`../README.md`](../README.md).
- Want the offensive-tool server internals? See [`../kali_server/README.md`](../kali_server/README.md).
- This file = "I want to change/extend how Spider itself works."

> ⚠️ Authorised security testing only. Spider drives real offensive tooling. Keep changes (and
> agents) within scope.

---

## Table of contents

1. [Big picture](#1-big-picture)
2. [Request & event flow](#2-request--event-flow)
3. [Module reference](#3-module-reference) — every script, what it does, key functions
   - [`server.py`](#serverpy--http-api-websocket-auth-gate) · [`session.py`](#sessionpy--orchestration-core)
     · [`agents.py`](#agentspy--the-agent-loop) · [`llm.py`](#llmpy--provider-abstraction)
     · [`roles.py`](#rolespy--agent-prompts--toolsets) · [`registry.py`](#registrypy--role-registry--custom-agents)
     · [`agentdefs.py`](#agentdefspy--per-agent-folders-prompts--mcp) · [`config.py`](#configpy--config-schema--defaults)
     · [`db.py`](#dbpy--sqlite-persistence) · [`auth.py`](#authpy--multi-user-auth)
     · [`events.py`](#eventspy--the-event-bus) · [`skills.py`](#skillspy--methodology-playbooks)
     · [`docs.py`](#docspy--document-extraction--report-rendering) · [`presets.py`](#presetspy--model-parameter-presets)
     · [`tools/`](#the-tools-layer-toolspy)
4. [The tools layer](#4-the-tools-layer)
5. [Customization cookbook](#5-customization-cookbook) — feature → file/function
6. [Data, files & persistence](#6-data-files--persistence)
7. [Config schema reference](#7-config-schema-reference)
8. [Conventions & gotchas](#8-conventions--gotchas)

---

## 1. Big picture

Spider runs a **lead orchestrator LLM agent** that plans an engagement and spawns specialised
**sub-agents** (recon, web_app, network, exploitation, post_exploit, reporting), each running a
provider-neutral, tool-using loop. Offensive tools execute in a **Kali container** reached over
MCP-over-HTTP; local/host tools (file I/O, HTTP repeater, notes) run on the operator's host. A
**human stays in the loop** (plan approval, per-category tool approval, interjection, intensity).

```
 Browser SPA (static/)                    spider/  (this package)
 ┌───────────────────────┐  REST /api/*   ┌──────────────────────────────────────────────┐
 │ index.html / app.js   │ ─────────────► │ server.py   FastAPI + auth middleware        │
 │ (login, sessions,     │ ◄───────────── │   │                                          │
 │  live feed, settings) │  WS /ws/{sid}  │   ├─ SessionManager ─ Session (session.py)   │
 └───────────────────────┘  event stream  │   │      ├─ Agent loop (agents.py)           │
                                          │   │      │     └─ llm.py provider            │
                                          │   │      ├─ tools/ (native/control/          │
                                          │   │      │     pentest/custom/mcp)           │
                                          │   │      ├─ roles.py + registry + agentdefs  │
                                          │   │      ├─ skills.py + docs.py              │
                                          │   │      └─ events.py bus ─► logs + WS       │
                                          │   ├─ auth.py (users, tokens)                 │
                                          │   └─ db.py (SQLite)   config.py (cfg schema) │
                                          └──────────────────────────────────────────────┘
                                                            │ MCP/HTTP
                                                            ▼
                                                  kali_server/ (in Kali)
```

**Two deployables:** this `spider/` control app (operator host) and `kali_server/` (inside Kali).
They speak MCP-over-HTTP; the client is [`tools/mcp.py`](tools/mcp.py).

---

## 2. Request & event flow

**Starting an engagement (happy path):**

1. `POST /api/sessions` → `server.create_session` → `SessionManager.create` makes a `Session`
   (owner = current user).
2. `POST /api/sessions/{sid}/start` → `Session.start(target, instructions)`:
   `setup()` (workspace dirs, event log, roles, agent defs, `_connect_mcp` to Kali) → builds the
   orchestrator brief (+ any reference-doc block) → `create_agent("orchestrator", …)` →
   `start_agent` launches `Agent.run()` as an asyncio task → `_monitor` watches it.
3. The orchestrator loop (`agents.Agent._loop`) calls the LLM (`llm.py`), executes tool calls
   (`_exec_tool`), and uses **control tools** (`tools/control.py`) to `update_plan`, `spawn_agent`,
   `store_finding`, `validate_agent`, `finish`, etc.
4. Everything interesting is emitted on the **event bus** (`events.py`): the WebSocket
   (`server.ws_events`) streams it to the browser **and** `Session._start_event_log` writes it to
   `workspaces/<sid>/logs/events.jsonl`.
5. Durable conversation/findings/cost/agents are persisted via `db.py`.

**Human-in-the-loop interrupts** flow back in through REST endpoints that resolve `asyncio.Future`s
the agent is awaiting: plan approval (`/plan-approvals/{rid}` → `resolve_plan_approval`), tool
approval (`/approvals/{id}` → `resolve_approval`), input requests (`/requests/{id}` →
`resolve_request`), interjection (`/interject` → `interject`), intensity (`/intensity` →
`set_intensity`).

---

## 3. Module reference

### `server.py` — HTTP API, WebSocket, auth gate
The FastAPI app, all REST endpoints, the live WebSocket, the auth middleware, and static-file
serving. **This is the entry point for every browser interaction.**

Key pieces:
- **`_auth_gate` (middleware)** — authenticates every `/api/*` request from the login-token cookie,
  stashing the user on `request.state.user`; non-public paths require a valid user (server-side
  enforcement of multi-user access — the UI is never trusted). Public allowlist = `PUBLIC_API_PATHS`.
- **`_no_cache_ui` (middleware)** — serves the SPA + static assets with no-cache so edits show up.
- **`current_user` / `require_admin`** — FastAPI dependencies. `require_admin` (403 for non-admins)
  gates all global-config writes and user management.
- **`_require(sid, user)`** — loads a session and returns 404 (not 403) if the user doesn't own it
  — per-user isolation that doesn't leak existence.
- **`_sanitize_config`** — strips API keys from the config for non-admin callers.
- **Auth/users:** `auth_status`, `auth_setup` (first-run admin), `auth_login`, `auth_logout`,
  `list_users`, `create_user_ep`, `delete_user_ep`, `reset_password_ep`, `disable_user_ep`.
- **Config & catalogs:** `get_config`, `put_config` (admin), **`test_kali`** (admin — probes the
  Kali MCP server, see cookbook), `list_tools`, presets, skills, agentdefs (+ per-agent MCP CRUD &
  `test_agent_mcp`), roles (custom agents).
- **Sessions:** create/list/get/delete/start/resume/stop, agents/plan/findings/cost/messages/
  approvals, report (`session_report`, `report_template`, `report_file`), uploads, HITL
  (`resolve_plan_approval`, `interject`, `set_intensity`, `resolve_approval`, `resolve_request`,
  `stop_agent`, `message_agent`).
- **`ws_events`** — the `/ws/{sid}` WebSocket: re-auths from the same cookie, replays event history,
  then streams live bus events for that session.
- **Request models** — Pydantic bodies (`CreateSession`, `StartSession`, `ReportRequest`,
  `KaliTest`, `PlanDecision`, …). Add a field here when an endpoint needs new input.

### `session.py` — orchestration core
`Session` owns one engagement: agents, MCP clients, the plan, findings, cost, memory, HITL state,
persistence, and start/stop/resume. `SessionManager` creates/loads/lists/deletes sessions.

Setup & agents:
- **`setup`** — makes workspace subdirs, starts the event log, loads roles + agent defs, connects
  MCP servers.
- **`_connect_mcp`** — connects session-level MCP servers; folds the friendly `cfg["kali"]` block
  into a server named `kali` and assigns its tools to the offensive roles.
- **`_tools_for_role`** — resolves a role's base toolset; **withholds host exec tools**
  (`run_shell`/`run_process`/`terminal`) when `poc_execution == "kali_only"`.
- **`create_agent`** — the big one: builds an agent's system prompt (engagement context, execution
  environment, reference docs, spawnable roles, MCP catalog, shared memory, skills), resolves tools
  (with `_budget_tools` when over a model's `max_tool_size`), constructs the `Agent`, emits
  `AGENT_CREATED`, persists it.
- **`_budget_tools`** — spawns a `tool_selector` helper to pick the best optional tools when a
  model's tool budget is exceeded (mandatory internal tools always kept).
- **Memory:** `record_agent_memory`, `_shared_memory_for`, `_memory_notes`, `_memory_role_files`
  — role-scoped shared memory injected into later agents. **Master memory:** `record_agent_memory`
  also writes a cross-role digest to `memory/master.md`; `_master_memory_block` injects it into every
  agent; `_loadable_memory_files` + `read_memory_file` back the `load_memory` tool (an agent selects
  any memory file to load in full).

HITL:
- **Plan:** `set_plan`, `set_step_status`, `submit_plan` (+ `_plan_needs_approval`,
  `resolve_plan_approval`, `pending_plan_approvals`) — the plan-approval state machine.
- **`interject`** — deliver an operator message to the orchestrator mid-run.
- **`set_intensity`** — change the session-wide tool intensity knob.
- **Tool approval:** `tool_needs_approval` (resolves the policy — read its docstring for the
  precedence order), `request_approval`, `resolve_approval`, `pending_approvals`.
- **Input requests:** `request_input`, `resolve_request`, `pending_requests`.

Reports & docs:
- **`generate_report`** — spawns the reporter agent, writes the `.md`, then renders a `.docx` via
  `docs.markdown_to_docx`; honours an exact-structure template and extra instructions.
- **`_report_context`** — the factual session snapshot fed to the reporter.
- **Uploads:** `add_upload`/`list_uploads`/`remove_upload`/`_reference_docs_block` — operator
  reference documents (extracted text injected into the orchestrator brief).

Run control & persistence: `start`, `resume`, `stop`, `shutdown`, `_monitor`, `start_agent`,
`wait_for`, `message_agent`, `persist`, `persist_agent`, `to_dict`. `SessionManager.load`
rebuilds a session (config/plan/findings/cost + restored agent roster) from the DB after a restart.

### `agents.py` — the agent loop
`Agent` is one LLM worker. `Agent._loop` is the heart of Spider's behaviour.

- **`run` / `run_followup`** — start the loop fresh, or resume an idle agent after it was prodded
  (operator message / send-back validation).
- **`_loop`** — per turn: set `waiting_llm`, call `provider.complete` (streaming token deltas via
  `on_token`), emit `AGENT_RAW` (the full unfiltered output: thinking + text + tool_use +
  stop_reason), append to messages, execute tool calls, handle `finish`, nudge if the agent ends a
  turn without finishing (`MAX_FINISH_NUDGES`), and compact context when near the budget.
- **`_exec_tool`** — runs one tool call; **this is the approval gate call site**
  (`session.tool_needs_approval` → `request_approval`). Emits `TOOL_CALL`/`TOOL_RESULT`.
- **Validation handshake:** `finish` puts a sub-agent in `waiting_validation`; `mark_validated` /
  `awaiting_validation` drive the mandatory parent-validation flow (memory is only recorded on
  accept).
- **`_maybe_compact` / `_render_transcript`** — context compaction via a `summarizer` agent.
- **`_summarize_on_exhaustion`** — on hitting `max_turns` without finishing, spawns a summarizer
  (`Session.handoff_summary_for`) to distil the transcript into a findings handoff; sets it as the
  result and (for sub-agents) routes it through validation so the parent/orchestrator + memory get it.
- **`deliver` / `_drain_inbox`** — operator/parent messages delivered into the next turn.
- **Status** is set via `_set_status` (`running`, `waiting_llm`, `waiting_subagent`,
  `waiting_validation`, `waiting_approval`, `summarizing`, `done`, `stopped`, `error`).

### `llm.py` — provider abstraction
Provider-neutral LLM layer. `make_provider(model_config)` returns one of:
- **`AnthropicProvider`**, **`OpenAIProvider`** — real APIs; build params from the model config
  (model, keys, base_url, temperature, max_tokens, thinking, etc.), translate Spider's message/tool
  format, stream tokens, and return an `LLMResponse`.
- **`MockProvider`** — drives the entire pipeline offline (plan → spawn recon → load skill → store
  finding → tool → validate sub-agent → finish). **Keep it working when you change roles/tools** —
  it's what `tests/smoke_test.py` runs.

`LLMResponse` carries `text`, `tool_calls`, `usage`, `stop_reason`, `raw_content`, and **`thinking`
kept separate** (out of `raw_content`/messages so it can't break API replay). `Usage` accumulates
the four token buckets. `model_caps` / `apply_param_overrides` / `_apply_timeout_retries` /
`_clean_header_value` handle per-model capabilities, parameter shaping, retries, and header hygiene.

### `roles.py` — agent prompts & toolsets
The **heart of agent behaviour**: the `ROLES` dict maps each built-in role to its system prompt
(assembled from prompt fragments like `ORCHESTRATOR`, `_AUTH`, `_SCOPE`, `_DEEPER`, `_DELEGATION`,
`_FINDINGS`, `_NARRATION`) and its default tool-name list (`_WORKER_TOOLS` for the offensive roles).
Edit a prompt or tool list here to change how a built-in discipline thinks/acts.

### `registry.py` — role registry & custom agents
Merges built-in `ROLES` with operator-defined **custom roles** stored in
`config/agents/custom_roles.json`. `role_specs(cfg)` is the canonical "all roles" view used
everywhere; `spawnable_roles` excludes helpers/non-spawnable; `add_custom_role` / `remove_custom_role`
back the Settings UI; `all_tool_names` lists assignable tools.

### `agentdefs.py` — per-agent folders (prompts & MCP)
Each role gets a folder under `config/agents/<role>/` with an editable `system.md` (prompt override)
and `mcp.json` (per-agent MCP servers). `load_all` / `load_def` / `raw_def` read them; `save_def`
writes the prompt + MCP; `list_mcp`/`add_mcp`/`remove_mcp`/`set_mcp_enabled`/`get_mcp_normalized`
manage a role's MCP servers (backing the Settings → Agents MCP editor and `test_agent_mcp`).
`normalize_mcp` coerces user-entered JSON into the canonical server-def shape.

### `config.py` — config schema & defaults
Defines the config shape and constants. `default_config()` is the source of truth;
`load_config()` deep-merges the saved `config/config.json` over the defaults (so new keys appear
automatically); `save_config()` persists. Notable constants: **`AGENT_ROLES`**,
**`TOOL_CATEGORIES`** (the approval vocabulary), **`INTENSITY_LEVELS`** + `DEFAULT_INTENSITY`,
**`POC_EXECUTION_MODES`** + `DEFAULT_POC_EXECUTION`, **`HOST_EXEC_TOOLS`** (withheld in kali_only),
`DEFAULT_PRICING`, `DEFAULT_AGENT_SKILLS`, `DEFAULT_MAX_CONTEXT_TOKENS`. `_default_model_config`
seeds a new role's model block; `_default_tool_approval` the approval policy.

### `db.py` — SQLite persistence
Thin async wrapper (`Database`) over one SQLite connection; every call runs in a thread under a lock
so DB I/O never blocks the loop. Tables (in `_SCHEMA`): `sessions` (with `owner`), `users`,
`auth_sessions` (login tokens), `agents`, `messages`, `findings`. `_migrate` adds columns to older
DBs. Public methods: `save_session`/`get_session`/`list_sessions`/`delete_session`,
`save_agent`/`list_agents`, `add_message`/`list_messages`, `save_finding`/`list_findings`, and the
user/token CRUD. **To add a column/table:** edit `_SCHEMA`, add a `_migrate` clause, update the
relevant upsert.

### `auth.py` — multi-user auth
No third-party deps. `hash_password`/`verify_password` use **scrypt**. The `Auth` class wraps the DB:
`needs_setup` (first run), `create_first_admin`, `create_user`, `authenticate`, `login` (returns a
token), `resolve` (cookie token → `User`), `logout`, plus user management (`set_password`,
`set_disabled`, `delete_user`, `list_users`). `User` is a view object; `User.is_admin` drives
authorization.

### `events.py` — the event bus
`E` is the catalog of event-type string constants (session/plan/agent/tool/approval/finding/cost/
log/error — including `AGENT_RAW` for the full LLM turn and the HITL events). `EventBus` is a
pub/sub of `asyncio.Queue`s: `emit` fans an `Event` out to all subscribers and keeps a per-session
history (replayed to new WebSocket clients). The module-level singleton **`bus`** is imported
everywhere; `subscribe`/`unsubscribe`/`history` round it out.

### `skills.py` — methodology playbooks
Loads Markdown discipline playbooks from the top-level `skills/` folder. `list_skills` (name/title/
description), `read_skill`, `skill_text_for` (concatenate for prompt injection), `resolve_skill_modes`
(per-role always/optional/never from `cfg["agent_skills"]`), `master` (an index), `ensure_scaffold`
(seed defaults). Edit a skill = edit its `.md` file; no code change.

### `docs.py` — document extraction & report rendering
Operator-upload and report plumbing. `extract_text(data, filename)` dispatches by extension:
md/txt (stdlib), pdf (`_extract_pdf`, via `pypdf`), docx (`_extract_docx`, via `python-docx`,
**heading-aware** so a template's structure survives). `markdown_to_docx(md_text, out_path)` renders
a Markdown report to a structured Word file (headings, lists, tables, code, inline emphasis) — the
helpers `_add_inline_runs`, `_looks_like_table_row`, `_split_row`, `_has_style` support it.
`safe_name` prevents path traversal; `ALLOWED_EXTS` / `MAX_UPLOAD_BYTES` bound input. Optional
parsers degrade to a clear error string rather than crashing.

### `presets.py` — model parameter presets
Named bundles of model parameters saved in `config/model_presets.json`. `load_presets`,
`upsert_preset` (validated against `_allowed_fields`), `delete_preset`. Backs Settings → Models →
Presets.

### The tools layer (`tools/`)
See [section 4](#4-the-tools-layer).

---

## 4. The tools layer

A **`Tool`** ([`tools/base.py`](tools/base.py)) is a dataclass: `name`, `description`,
`input_schema` (JSON schema the LLM sees), async `handler(agent, args)`, `parallel_safe`,
`requires_approval` (hard floor), and **`category`** (drives the approval policy; one of
`config.TOOL_CATEGORIES`). `tools/__init__.py` assembles `base_tools()` (native + control + pentest
+ custom) and `tool_catalog()` (metadata for the Settings view).

| Module | What it provides | Category(ies) |
|---|---|---|
| [`native.py`](tools/native.py) | Host primitives: `run_shell` (**OS-aware** — PowerShell on Windows, sh on Linux), `run_process`, `read_file`/`write_file`/`append_file`/`list_dir`/`make_dir`. | shell / filesystem |
| [`control.py`](tools/control.py) | Agent control & bookkeeping: `spawn_agent`, `wait_for_agent`, `message_agent`, `ask_parent`, **`ask_user`** (ask the human operator; blocks for an answer and raises a UI alert), **`validate_agent`**, `get_agent_status`/`list_agents`, `update_plan`/`set_step_status`, `store_finding`/`list_findings`/`read_finding`, `finish`, `load_skill`, **`load_memory`** (pull a chosen memory file in full), `notify_user`, `select_tools`, `request_file_load`. | control |
| [`pentest.py`](tools/pentest.py) | Local pentest helpers (strix-inspired): **`kali_terminal`** (canonical command tool — ALWAYS runs in the Kali container, never the host; clear error if Kali is down), `terminal` (OS-aware host shell, stripped in `kali_only`), `http_request` (web repeater), `browser_open` (no-JS page/forms/links mapper), `record_note`. | shell / web |
| [`custom.py`](tools/custom.py) | **Where you add your own host-side tools** (example: `sha256_file`). | (you pick) |
| [`mcp.py`](tools/mcp.py) | The MCP client: `MCPClient` (stdio + HTTP transports, `connect`/`call_tool`/`close`) and `build_mcp_tools` (wraps each discovered remote tool as a `Tool`, prefixed `server__name`, category from `_meta.category`). This is how Kali tools (`kali__nmap_scan`, …) reach agents. | from server meta (else `mcp`) |

Note: in the default `kali_only` mode, `HOST_EXEC_TOOLS` (`run_shell`/`run_process`/`terminal`) are
stripped from every agent in `Session._tools_for_role` — exploits run in Kali, not on the host.

---

## 5. Customization cookbook

> Feature → the file(s)/function(s) to edit. After changing roles/tools, re-run
> `python ../tests/smoke_test.py` (it exercises the Mock provider end-to-end).

| I want to… | Edit | Notes |
|---|---|---|
| **Add an agent discipline** (cloud, mobile, wireless…) | UI: Settings → Agents & skills (no code). Code path: `registry.add_custom_role` + `config/agents/custom_roles.json`; built-ins live in `roles.py` `ROLES`. | New roles become spawnable by the orchestrator (`registry.spawnable_roles`). |
| **Change how a built-in agent thinks** | `roles.py` (its prompt fragments) **or** `config/agents/<role>/system.md` (override). | Folder override wins; see `agentdefs.load_def`. |
| **Change a built-in agent's tools** | `roles.py` tool-name list for that role. | Names must exist in `registry.all_tool_names()`. |
| **Add a host-side tool** | `tools/custom.py`: write an `async def _h_x(agent, args)` and register a `Tool(...)` in `custom_tools()` with a `category`. | Appears automatically; respects approval policy. |
| **Add a Kali offensive tool** | `../kali_server/tools/*.py` (decorate an async handler, set its `_meta.category`) + install its binary in `../kali_server/Dockerfile` + import in `tools/__init__.py`. | Surfaces in Spider as `kali__<name>` via `tools/mcp.build_mcp_tools`. Full recipe (incl. a filter): [`kali_server/README.md`](../kali_server/README.md) "Add your own tool". |
| **Add/adjust a tool output filter** | `../kali_server/tools/_filters.py`: write `_f_<tool>` and register it in `FILTERS`; test in `../kali_server/tests/test_filters.py`. | Static noise reduction. Applied in `registry.call_tool`→`_maybe_filter`; the `raw` opt-out param is auto-injected by `mcp_tool_list`. |
| **Turn output filtering on/off (admin)** | UI: Settings → Kali → "filter tool output" (`cfg["output_filter"].enabled`). Plumbed to Kali via `_meta.filter` in `tools/mcp._make_handler`; honoured in `kali_server.registry._maybe_filter`. | Off = every offensive tool returns its full raw output unchanged. Agents can always pass `raw=true` per call. |
| **Add a methodology skill** | Drop a `.md` in `../skills/`; assign per-role in Settings → Agents & skills (`cfg["agent_skills"]`). | Loaded via `skills.resolve_skill_modes` / `skill_text_for`. |
| **Change which tool categories need approval** | UI: Settings → Tool approval (`cfg["tool_approval"]`). Logic: `Session.tool_needs_approval`. | Categories = `config.TOOL_CATEGORIES`. `approval_mode="auto"` bypasses all. |
| **Bypass approvals mid-session** | `Session.set_approval_mode` (endpoint `POST …/approval-mode`, event `approval.mode_changed`); UI checkbox `bypassApproval`/`toggleApprovalBypass`. | Per-session only; `auto` also releases pending approvals. Does not touch global config. |
| **Reach a host-local target from Kali** | `Session._targets_host_loopback` + the NETWORK NOTE in `create_agent`; `kali_server/docker-compose.yml` `extra_hosts`. | Inside the container 127.0.0.1 ≠ host → agents use `host.docker.internal`. |
| **See/kill running Kali processes** | Kali side: `kali_server/tools/_procs.py` (+ `_common.run`/`run_shell`, `registry._control_op`, `_meta` in `server.py`). Spider: `Session.list_kali_processes`/`kill_kali_process`/`kill_all_kali_processes`; endpoints `…/kali/processes` & `…/kill`; UI `renderProcs`/`killProc` poll. | Tagged by session/agent/tool via `_meta`; kill = `killpg`; `stop()` kills the session's procs; `init: true` reaps. |
| **Run Kali tools in parallel / not block the monitor** | `tools/mcp.MCPClient._request` locks only for stdio, not HTTP. | Lets concurrent agent tool calls + the process monitor interleave. |
| **Cap parallel Kali tools (shared container)** | `../kali_server/tools/_common.py` `_limiter` wraps `run`/`run_shell`; size via `SPIDER_KALI_MAX_PARALLEL` (compose/.env). | One container is shared by all users; excess tool calls **queue** instead of swamping it. `0` = unlimited. |
| **Tune the live raw-streaming view** | `static/app.js` `updateRawStream`/`renderRaw`/`pushRaw` + the `agent.token`/`agent.raw` cases; provider streams via `on_token(text, kind)` in `llm.py`. | Live thinking+text per token; clean formatted turn on completion. `read_log.py` `renderRaw` mirrors the static format. |
| **Force a specific tool to always need approval** | Set `requires_approval=True` on the `Tool`, or add its name to `tool_approval.always_manual_tools`. | Hard floor checked first in `tool_needs_approval`. |
| **Change the intensity→flag behaviour** | Spider side: prompt injection in `Session.create_agent` + the `intensity` arg. Real flag mapping: `../kali_server/tools/_common.py`. | Levels = `config.INTENSITY_LEVELS`. |
| **Confine / allow PoC execution** | `cfg["poc_execution"]` (UI: Settings). Enforced in `Session._tools_for_role` via `config.HOST_EXEC_TOOLS`. | `kali_only` (default) vs `host`. Commands always go through `kali_terminal` (→ Kali); host exec tools are stripped in `kali_only`. |
| **Change the command tool / Kali routing** | `tools/pentest.py` `_h_kali_terminal` (proxies to the Kali MCP `run_command`); it's in `_WORKER_TOOLS` (`roles.py`). | Always runs in Kali; never the host. Edit `KALI_DOWN_MSG` for the no-Kali guidance. |
| **Let an agent ask the operator a question** | `tools/control.py` `_h_ask_user` (→ `Session.request_input`); UI alert in `static/app.js` `alertOperator` on the `user.request` event. | Blocks for an answer; raises a toast + title flash + desktop notification. |
| **Change the "did you finish?" nudge** | `agents.Agent._loop` (the `_finish_nudges` branch). | Now offers finish / `ask_user` / keep working. |
| **Change the turn-budget handoff** | `agents.Agent._summarize_on_exhaustion` + `Session.handoff_summary_for`; the `else` of the `_loop` while. | Summarizer distils findings when `max_turns` is hit without finishing; sub-agents route to validation. |
| **Change how memory reaches agents** | `Session._memory_notes_block` (inlines note content) + `_shared_memory_for`; injected in `create_agent`. | Memory is GIVEN in the prompt, not fetched via `read_file`. |
| **Master memory (cross-role digest)** | Written in `Session.record_agent_memory` (→ `memory/master.md` + `self.master_memory`); injected by `_master_memory_block` in `create_agent`. | Each finishing agent's result + findings; injected into EVERY new agent. |
| **Let an agent load a specific memory** | `tools/control.py` `_h_load_memory` (`load_memory` tool) → `Session.read_memory_file`; candidates from `_loadable_memory_files`; attached in `create_agent`. | Agent SELECTS which memory file to pull in full; path-safe. |
| **Add/Test the Kali connection** | Settings → Kali **Test connection** → `POST /api/config/kali/test` (`server.test_kali`); connection itself in `Session._connect_mcp` from `cfg["kali"]`; client in `tools/mcp.MCPClient`. | Probe opens a throwaway `MCPClient`, runs initialize + tools/list, returns the tool names or a clear error. |
| **Test the LLM connection** | Settings → Models per-role **Test connection** → `POST /api/config/llm/test` (`server.test_llm`); UI `testLLM(role)`. | Builds the role's model config (saved + on-screen overrides), sends a one-line "hello" via `make_provider().complete`, returns the reply. Goes through the client proxy if enabled. |
| **Configure outbound proxies** | UI Settings → Outbound proxies (`cfg["client_proxy"]`, `cfg["kali_proxy"]` — each `{enabled,url,no_proxy}`). Client: `llm._proxy_http_client` builds an httpx `mounts` client (no_proxy = direct), injected into the SDK via `http_client` (added to model_config as `_client_proxy` in `Session.create_agent`). Kali: pushed in `_meta.proxy` (`tools/mcp._make_handler`) → `kali_server/tools/_common._subprocess_env` sets HTTP(S)_PROXY/NO_PROXY on tool subprocesses. | Authenticated `http://user:pass@host:port`. Client proxy = LLM calls; Kali proxy = tool traffic. `_sanitize_config` strips both URLs for non-admins (they embed credentials). |
| **Change the report / template pipeline** | `Session.generate_report` (brief + flow), `docs.markdown_to_docx` (Word rendering), `docs._extract_docx`/`_extract_pdf` (template extraction). | Outputs both `.md` and `.docx`; template reproduced exactly. |
| **Tweak the agent loop** (turns, nudges, compaction) | `agents.Agent._loop`, `_maybe_compact`, `MAX_FINISH_NUDGES`. | Validation handshake: `finish`/`mark_validated`/`validate_agent`. |
| **Add an LLM provider / change model params** | `llm.py`: subclass `BaseProvider`, wire into `make_provider`. Params/pricing: `config.py` + Settings → Models. | Keep `MockProvider` behaviour consistent with role/tool changes. |
| **Add a REST endpoint** | `server.py`: add a Pydantic model + an `@app.<verb>` handler with the right auth dep (`current_user` / `require_admin`) and, for sessions, `_require(sid, user)`. | Owner-gate session routes. |
| **Admin: monitor/stop all users' sessions** | `SessionManager.list_all` adds `owner_name` (admins call it with `owner=None`); `_require`/WS already admit admins to any session. UI: `renderSessions` owner chip + live dot, `startSessionPoll` (admin-only background refresh). | Admin watches any session's live WS stream and can `stop` it; regular users stay isolated. |
| **Add a live event type** | `events.E` (constant) → `bus.emit(...)` at the source → handle in `static/app.js` (and `../read_log.py` if you want it in logs). | Persist to feed via `db.add_message` if it should survive restarts. |
| **Add a config field** | `config.default_config()` (+ a constant if it's an enum). | `load_config` deep-merges, so old config files pick up the new default. |
| **Add a persisted column/table** | `db._SCHEMA` + a `_migrate` clause + the relevant upsert. | Migrations run on `Database.__init__`. |
| **Change auth (hashing, token TTL, cookie)** | `auth.py` (`hash_password`, `TOKEN_TTL`), cookie in `server._set_login_cookie`. | scrypt + HttpOnly cookie; enable Secure behind HTTPS. |
| **Change the UI** | `static/index.html`, `static/app.js`, `static/style.css`. | Served no-cache; the WS event handlers live in `app.js`. |

---

## 6. Data, files & persistence

- **`spider.db`** (repo root) — SQLite: sessions, users, auth tokens, agents, messages, findings.
- **`config/config.json`** — the live config (git-ignored). `config/config.example.json` +
  `.env.example` are the templates. `config/agents/<role>/` (prompts + MCP), `custom_roles.json`,
  `model_presets.json`.
- **`workspaces/<sid>/`** — per-session: `memory/` (role memory + agent notes), `findings/`,
  `poc/`, `reports/` (`.md` + `.docx`), `uploads/` (originals) + `uploads/text/` (extracted) +
  `manifest.json`, and **`logs/events.jsonl`** (the full event stream — view with `../read_log.py`).
- **`skills/`** — Markdown methodology playbooks (top-level).

---

## 7. Config schema reference

`config.default_config()` is authoritative; here are the blocks you'll touch most:

- **`models`** — per-role `{provider, model, api_key, base_url, temperature, max_tokens,
  max_tool_size, …}`. `orchestrator` is the fallback for unseen roles.
- **`approval_mode`** — global master: `manual` (use policy) or `auto` (never gate).
- **`tool_approval`** — `{default, by_category{…}, always_manual_tools[], always_auto_tools[]}`.
- **`human_in_the_loop`** — `{plan_approval: off|once|on_change, block_on_plan_approval,
  allow_interjection}`.
- **`kali`** — `{enabled, url, assign_roles[]}` (the offensive-tool MCP server).
- **`default_intensity`** — one of `INTENSITY_LEVELS`.
- **`poc_execution`** — `kali_only` (default) or `host`.
- **`agent_skills`** — per-role skill load modes.
- **`limits`** — `{max_spawn_depth, max_total_agents, max_children_per_agent}`.
- **`pricing`** — per-model USD-per-million-tokens for the four buckets (cost accounting in
  `Session.add_cost`).
- **`max_context_tokens`** — compaction threshold.

---

## 8. Conventions & gotchas

- **Cross-platform host.** The control app runs on Windows or Linux; host shell execution is
  OS-aware (`tools/native._shell_argv`, `tools/pentest.terminal`). Offensive tooling always runs in
  Kali regardless of host OS.
- **Server-side isolation is the source of truth.** The UI only hides controls; access is enforced
  by the auth middleware, `_require(sid, user)`, the WS re-auth, and admin-only config writes. Don't
  rely on the front end for security.
- **Keep the Mock provider working.** `llm.MockProvider` and `tests/smoke_test.py` are the offline
  safety net for any change to roles, tools, or the loop.
- **Thinking blocks** are captured separately (`LLMResponse.thinking`) and kept out of message
  history so they can't break Anthropic API replay (no signature). Don't fold them back in.
- **Sub-agent validation is mandatory.** A finished child waits in `waiting_validation` until its
  parent calls `validate_agent`; memory is only recorded on accept.
- **Preview tool quirk.** Per the top-level CLAUDE.md, the browser-preview tooling keys off the
  session root — verify the UI by running `python ../run.py` and loading the page.
- **Secrets are git-ignored.** Never commit `config/config.json`, `.env`, or `spider.db`.
