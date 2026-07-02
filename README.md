# 🕷 SPAIDER — Security Pentester AI Driven: Exploitation and Reconnaissance

**SPAIDER** (**S**ecurity **P**entester **AI** **D**riven: **E**xploitation and **R**econnaissance)
is a local web app that runs a **multi-agent LLM penetration test** against authorised
targets. A lead **orchestrator** agent plans the engagement and delegates to specialised
sub-agents — recon, web-app, network, exploitation, post-exploitation, reporting — each running a
tool-using loop. The offensive tools themselves run inside a **Kali container** that SPAIDER drives
over an MCP server, so the agents use real tooling (nmap, nikto, gobuster, ffuf, sqlmap, hydra,
nuclei, metasploit, …).

Crucially, SPAIDER keeps a **human in the loop**: you can require sign-off on the plan, decide
exactly which tool categories need your approval, interject at any moment to ask a question or
change direction, and dial the **intensity** of every tool from passive to insane.

> ⚠️ **Authorised use only.** SPAIDER executes real offensive tooling. Run it solely against systems
> you own or have explicit written permission to test, on an isolated engagement network.

SPAIDER shares its architecture with the ReLive framework, re-targeted from reverse-engineering to
penetration testing.

> 🛠 **Want to customize, extend, or understand the internals?** See the developer & customization
> guide in [`spider/README.md`](spider/README.md) — it documents every module, the key functions,
> and exactly which file/function to touch for each feature (add an agent, a tool, a skill, change
> approval/intensity behaviour, the report pipeline, auth, and more).

---

## Table of contents

1. [Architecture at a glance](#architecture-at-a-glance)
2. [Screenshots](#screenshot)
2. [The agents](#the-agents)
3. [Human-in-the-loop controls](#human-in-the-loop-controls)
4. [Quick start](#quick-start)
   - [1. SPAIDER control app](#1-spider-control-app-your-host--windows-or-linux)
   - [2. Kali tool server](#2-kali-tool-server-pre-configured-docker-image)
   - [3. Test the Kali connection](#3-test-the-kali-connection)
   - [4. Run an engagement](#4-run-an-engagement)
   - [5. Generate the report](#5-generate-the-report)
5. [Tools](#tools)
6. [Project layout](#project-layout)
7. [Inspecting session logs](#inspecting-session-logs)
8. [Testing](#testing)
9. [Customizing & extending SPAIDER](#customizing--extending-spider)
10. [Safety & scope](#safety--scope)

---

## Architecture at a glance

```
┌───────────────────────────────────────────────┐          ┌──────────────────────────────┐
│  SPAIDER (your host) — FastAPI + web UI       │          │  Kali container              │
│                                               │          │                              │
│  orchestrator (pentest lead)                  │   MCP/   │  kali_server (MCP-over-HTTP) │
│    ├─ recon          ┐                        │   HTTP   │    nmap_scan, nikto_scan,    │
│    ├─ web_app        │  each = tool-using     │ ───────► │    gobuster_dir, ffuf_fuzz,  │
│    ├─ network        │  LLM agent loop        │          │    sqlmap_test, wpscan,      │
│    ├─ exploitation   │                        │          │    enum4linux, hydra,        │
│    └─ post_exploit   ┘                        │          │    nuclei, metasploit, …     │
│  + reporting / summarizer / tool_selector     │          │    (typed params +           │
│                                               │ ◄─────── │     category + intensity)    │
│  local tools: kali_terminal, http_request,    │  results │                              │
│   browser_open, record_note, file I/O         │          │  subprocess ─► real Kali CLI │
│                                               │          └──────────────────────────────┘
│  Human-in-the-loop: plan approval,            │
│   tool-approval policy, interjection,         │   SQLite persistence + live WebSocket
│   intensity, process monitor                  │   event stream to the browser UI
└───────────────────────────────────────────────┘
```

- **`spider/`** — the control app: FastAPI server, WebSocket event stream, vanilla-JS UI, the
  agent runtime, session orchestration, the LLM provider abstraction (Anthropic / OpenAI / Mock),
  and the local + MCP tool layer.
- **`kali_server/`** — a standalone MCP-over-HTTP server you run **inside Kali**. It exposes the
  offensive tools as typed functions and is documented in [`kali_server/README.md`](kali_server/README.md).

---

## Screenshot
![Session view](images/spider_session.png)
![Settings view](images/spider_settings.png)


## The agents

| Agent | Discipline |
|---|---|
| **orchestrator** | Pentest lead: scopes, plans, gets sign-off, delegates, narrates, keeps exploitation gated behind validated findings. |
| **recon** | Reconnaissance & discovery: OSINT, host/service/port discovery, content & subdomain enumeration. |
| **web_app** | Web application testing (OWASP-style): auth, access control, injection, XSS, SSRF, misconfig. |
| **network** | Network/infrastructure: SMB/LDAP/SNMP/TLS enumeration, weak creds, vulnerable services. |
| **exploitation** | Exploits **validated, in-scope** findings to demonstrate impact, safely. |
| **post_exploit** | Scoped post-exploitation: privesc, looting, lateral-movement assessment. |
| **reporting** | Writes the full engagement report from the findings + evidence. |
| *summarizer / tool_selector* | Framework helpers (context compaction; tool-budget selection). |

Add your own discipline (e.g. `cloud`, `mobile`, `wireless`) from **Settings → Agents & skills** —
custom agents become spawnable by the orchestrator.

---

## Human-in-the-loop controls

Everything below is configurable in **Settings** and steerable live during a run.

- **Plan approval** — `off` / `once` (approve the first plan) / `on_change` (approve every
  revision). When required, the orchestrator pauses and you can **approve**, **reject with
  feedback** (it revises), or **edit the steps** directly and approve.
- **Tool-approval policy** — for each tool **category** (recon, enum, web, exploit, bruteforce,
  shell, …) choose **auto** (runs immediately) or **manual** (the agent waits for your approval).
  The global *Approval mode* master switch can flip to fully autonomous.
- **Bypass approvals mid-session** — the **🔓 bypass approvals** checkbox in the session header
  toggles command validation **for the current session only** (it overrides the global policy
  without changing it). Tick it to let commands run without sign-off; untick to re-enable. Turning
  it on also releases anything currently waiting for your approval.
- **Access roles** — beyond the bootstrap **admin** (who has every right and is the only one who can
  open Settings), the admin defines named **access roles** in *Settings → Access roles* and assigns
  them to users. A role grants capabilities: **read** (view other users' sessions you've been
  *granted*, read-only), **run pentest**, **edit session name**. Read grants (also in *Access roles*)
  pick exactly whose sessions — and which of them — a reader may see.
- **Rename a session** — click the **✎** next to the session title (needs the *edit session name*
  capability). Safe at any time, before/during/after a run; it's just a label.
- **Interjection** — type into the *Interject* box any time to ask a question or change direction;
  the orchestrator reads it on its next turn and adapts.
- **Shared & master memory** — when an agent finishes, its key result and findings are written to a
  cross-engagement **master memory** (`memory/master.md`). Every newly spawned agent is given the
  master memory automatically (plus the memory for its own role/lineage), so the whole picture
  carries forward without re-asking. An agent can also **select and load** any other memory file on
  demand (another role's memory, a specific note) with the `load_memory` tool.
- **Sub-agent validation** — a spawned sub-agent does not close on its own. When it finishes it enters
  *awaiting validation*; its parent reviews the result and either **accepts** it (closes it), **sends it
  back** with more instructions (it resumes), or **discards** it and spawns a fresh agent. The
  orchestrator also revises and follows a new plan as findings warrant.
- **Per-agent Chat / Raw / Terminal views** — for each agent, switch between the **Chat** (filtered,
  readable), the **Raw** view (the model's complete unfiltered output — reasoning, answer, exact tool
  calls, and stop reason — streamed live), and the **Terminal** (commands it ran). The Raw view is for
  debugging: it lets you tell a wrong/empty answer apart from a timeout or error.
- **Finer agent statuses** — each agent shows what it's actually waiting on: *awaiting LLM*, *awaiting
  sub-agent*, *awaiting validation*, or *awaiting approval*. Agents that stop without calling `finish`
  are nudged before the loop ends and offered three choices: **finish**, **ask the operator a
  question** (`ask_user`), or keep working.
- **Turn-budget handoff** — if an agent runs out of its turn budget before finishing, a **summarizer
  steps in** and distils its transcript into a handoff (findings, current state, what remains). That
  summary becomes the agent's result, so its work flows to the parent/orchestrator and into shared &
  master memory instead of being lost.
- **Agents can ask you** — any agent can call **`ask_user`** to put a specific question to you and
  block until you answer; it raises an **alert** (an on-screen toast, a flashing tab title, and a
  desktop notification if you allow them) so you don't miss it. Answer it in the request box.
- **Running-process monitor** — the **Running in Kali** panel shows every command/tool this session
  is currently running in the container (which agent launched it, and for how long — an enumeration
  scan can overload a target). **Kill** any process; you're prompted for an optional explanation that
  is delivered to the responsible agent so it adapts (e.g. picks a lighter scan) instead of just
  relaunching. Stopping the session **kills all of its Kali processes**, so nothing keeps running
  after the engagement ends.
- **Intensity** — a single knob (passive → stealth → normal → aggressive → insane) that maps to
  each tool's real flags (nmap `-T1..-T5`, thread counts, request rates, hydra parallelism).
- **PoC execution location** — `poc_execution` (default **`kali_only`**) confines all exploit and
  proof-of-concept execution to the Kali container; agents get no host command-execution tools, and
  PoCs run via `kali__run_poc` (write + run a script in Kali). The host is used only for
  orchestration, files, and the report. Set it to `host` to also allow execution on the SPAIDER host.

---

## Quick start

### 1. SPAIDER control app (your host — Windows or Linux)
```bash
cd SPAIDER
python -m venv .venv && . .venv/Scripts/activate      # Windows; use bin/activate on Linux/mac
pip install -r requirements.txt
python run.py                                         # opens http://127.0.0.1:8000
```
The host app runs on **Windows or Linux** — host shell helper commands use PowerShell on Windows
and bash/sh on Linux automatically. (The offensive tooling always runs in the Kali container.)

**First run — create the administrator.** The first time you open SPAIDER it shows a *Create
administrator* screen; pick a username and password. That admin manages all accounts and global
settings (**Settings → Users**) and can see every session. Add regular users there — each user
only sees the sessions they create. Passwords are stored hashed (scrypt); login uses an HttpOnly
cookie.

**Admin live monitoring.** An admin's session list shows **every user's** engagement, labelled with
the owner's username (👤) and a pulsing dot for the ones that are running; the list refreshes in the
background so it stays current. The admin can open any session to watch its **live** event stream
(agent activity, commands, findings) and **Stop** it if it's misbehaving or out of scope — the same
controls as the owner. Isolation is still enforced server-side: regular users only ever see and
touch their own sessions.

In **Settings → Models** put your `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY`) — or set it in the
environment and leave the field blank. You can try the whole flow with **provider = mock** and no
key. Click **Test connection** on any model to send it a quick "hello" and see the reply — a fast
way to confirm the key, base URL, model name (and the proxy, if enabled) all work before a run.

**Outbound proxies (optional).** In **Settings → Outbound proxies** you can route traffic through an
authenticated HTTP proxy `http://user:pass@host:port`. The two proxies are independent:
- **Client proxy** — the SPAIDER control app's own outbound traffic (chiefly the **LLM API**).
- **Kali proxy** — the offensive tools in the container (curl/httpx/gospider/nuclei/wget via
  `HTTP(S)_PROXY`; raw-socket tools like nmap can't use an HTTP proxy).

Each has a **no-proxy whitelist** (one host per line, e.g. `localhost`, `127.0.0.1`,
`host.docker.internal`) whose hosts connect **directly**, bypassing the proxy.

### 2. Kali tool server (pre-configured Docker image)
The offensive tools run in a **pre-configured Kali container**. A published build is on Docker Hub, so
teammates just pull and run it — only the SPAIDER client needs installing:
```bash
docker pull sungyongkim98/spider-kali:latest      # ~1.9 GB, all tools baked in
cd kali_server
cp .env.example .env            # set SPIDER_KALI_TOKEN + SPIDER_SCOPE
docker compose up -d            # runs the pulled image on :8765
```
The one container is **shared by all users**. To keep several operators' parallel scans from
swamping it (or hammering a target), the server caps how many tool processes run at once and
**queues** the rest — set **`SPIDER_KALI_MAX_PARALLEL`** in `.env` (default **8**; `0` = unlimited).
This works together with the per-session **intensity** knob and the **Running in Kali** kill panel.
To build your own (instead of pulling) or hand the image off as a file, see the build / `scripts/share.sh`
package-and-load workflow in [`kali_server/README.md`](kali_server/README.md).

Then in SPAIDER **Settings → Kali**: tick *enable*, set the URL to `http://<kali-host>:8765/mcp` (and
the same `SPIDER_KALI_TOKEN` if you set one), Save. The Kali tools now appear to the offensive agents
as `kali__nmap_scan`, `kali__sqlmap_test`, `kali__run_poc`, etc.

> **Targets on your own machine (localhost/127.0.0.1).** The offensive tools run *inside* the Kali
> container, where `127.0.0.1` is the container itself — a target on your host's loopback is reached
> as **`host.docker.internal`** instead (e.g. `http://host.docker.internal:8881`). SPAIDER detects a
> host-local target and tells the agents to do this automatically; the bundled `docker-compose.yml`
> maps `host.docker.internal` so it also works on Linux hosts.

### 3. Test the Kali connection
Before starting an engagement, confirm SPAIDER can actually reach the container: in **Settings → Kali**
click **Test connection**. SPAIDER opens a throwaway MCP client against the URL **currently typed in
the box** (no need to save first), runs the handshake, and reports the result inline:

- ✓ **connected — N tools (nmap_scan, nikto_scan, …)** — the container is up and the tools are
  discoverable; you're ready to run.
- ✗ **<reason>** — a clear failure message (connection refused, wrong URL/port, server not running,
  auth/token mismatch). Fix it and test again.

This catches the most common setup mistake — a wrong URL or a container that isn't running — before
an agent tries to use a Kali tool mid-engagement.

### 4. Run an engagement
Create a session, enter your **in-scope target(s)** and **rules of engagement**, optionally
**📎 Attach docs** (Markdown / text / PDF / Word — scope letters, rules of engagement, prior
reports, target documentation), press **Start**, approve the plan when prompted, and watch the
agents work in the live feed and process tree. Attached documents are text-extracted and fed to
the orchestrator (and saved in the session workspace under `uploads/` so any agent can read them).

When you press **Start**, SPAIDER shows a **target picker** listing the approved targets returned by
your provider script `target_providers/targets.py` (`list_targets()`). Customise that file to source
targets from wherever you like (a CSV/JSON, a CMDB, an internal API…).

### 5. Generate the report
Click **📄 Report**. Optionally upload a **template** (`.pdf` / `.docx` / `.md`) or paste one — the
report-writer agent reproduces the template's structure **exactly** (same sections, order, headings,
and tables), filled with the engagement's real content. The report is produced as **both a Markdown
and a Word (`.docx`) file**, downloadable from the result dialog and saved under the session's
`reports/` folder.

### Analytics dashboard
Switch a session to the **Dashboard** view for live, colored graphs of the engagement: cost over
time, token usage over time, the token mix, cost per agent and per model, findings by severity, and
the most-used tools. Everything is computed **statically** from the session's event log (no LLM), so
it works for a running *or* a long-finished session. Press **⬇ Export report** to download, with no
model call:
- a self-contained **HTML report** (the graphs + all the tables, print-friendly) for a quick,
  non-technical review, and
- a **CSV** (tidy cost/token time series) + **JSON** bundle so a data-science team can load the raw
  numbers straight into pandas / a notebook.

---

## Tools

Every tool declares a **category** that drives the tool-approval policy. There are two layers: the
**internal tools** built into SPAIDER (host-side), and the **Kali tools** served by `kali_server/`
(they appear to the offensive agents as `kali__<name>`).

### Internal tools (built into SPAIDER, run on the host)

| Category | Tools | What they do |
|---|---|---|
| **control** | `spawn_agent`, `wait_for_agent`, `message_agent`, `get_agent_status`, `list_agents`, `validate_agent`, `ask_parent`, `ask_user`, `notify_user`, `update_plan`, `set_step_status`, `store_finding`, `list_findings`, `read_finding`, `load_skill`, `load_memory`, `select_tools`, `request_file_load`, `finish`, `sha256_file` | Agent orchestration & bookkeeping: spawn/await/validate sub-agents, ask the operator or parent, manage the plan, record & read findings, load skills/memory, finish a task. Never gated. |
| **filesystem** | `read_file`, `write_file`, `append_file`, `list_dir`, `make_dir`, `record_note` | Read/write files in the session workspace; `record_note` appends to the shared memory scratchpad. |
| **web** | `http_request`, `browser_open` | `http_request` is a full request "repeater" for manual web testing; `browser_open` is a no-JS page/forms/links mapper. |
| **shell (Kali)** | `kali_terminal` | The canonical command tool — runs a command **inside the Kali container** (never the host); always available to offensive roles. Clear error if Kali isn't connected. |
| **shell (host)** | `run_shell`, `run_process`, `terminal` | Host shell/exec. **Withheld from agents in the default `kali_only` mode** (set `poc_execution: host` to re-enable for local helper tasks). |

### Kali tools (served by `kali_server/`, run in the container)

| Category | Tools |
|---|---|
| **recon** | `nmap_scan`, `dns_enum`, `whois_lookup`, `whatweb_scan`, `http_probe` (httpx), `web_crawl` (gospider), `waf_detect` (wafw00f) |
| **web / API** | `nikto_scan`, `gobuster_dir`, `ffuf_fuzz`, `sqlmap_test`, `wpscan_scan`, `param_discover` (arjun — hidden params) |
| **enum / network** | `enum4linux`, `smb_list_shares`, `snmp_enum`, `ssl_scan` |
| **exploit** | `searchsploit`, `nuclei_scan`, `metasploit_run`, `commix_test` (command injection), `run_poc` (write + run a PoC in Kali) |
| **bruteforce** | `hydra_bruteforce` |
| **shell / filesystem** | `run_command`, `write_file`, `read_file` (all on the Kali host) |

The **API/web set** (`http_probe`, `web_crawl`, `param_discover`, `commix_test`, `waf_detect`)
covers probing, crawling/endpoint discovery, hidden-parameter discovery, command-injection testing,
and WAF fingerprinting — the surface-mapping and attack steps a modern web/API engagement needs.

Each Kali tool has a detailed parameter schema and maps the **intensity** knob to real flags. Add
your own in minutes by decorating an async handler (see [`kali_server/README.md`](kali_server/README.md)) —
it appears to SPAIDER automatically with its category and availability.

**Output filtering (less noise for the agents).** Every offensive tool's output is statically
filtered down to its notable findings (open ports, found paths, vulns, creds, records, params…)
before an agent sees it, so context isn't wasted on banners, progress bars and logs. An agent can
ask for the complete output of any call with `raw=true`, and the admin can disable filtering
globally in **Settings → Kali → filter tool output** (which returns every tool's raw output
unchanged). See [`kali_server/README.md`](kali_server/README.md) for how each tool is filtered.

---

## Project layout
```
Spider/
  run.py                 # start the control app
  read_log.py            # render a session's events.jsonl as a chat-style web UI (or --text)
  requirements.txt
  spider/                # the control app (FastAPI + UI + agent runtime)
    server.py            #   REST + WebSocket + auth middleware (login / users / isolation)
    auth.py              #   multi-user auth: scrypt hashing, login tokens, user CRUD
    db.py                #   SQLite: sessions (owner), users, auth_sessions, …
    session.py           #   orchestration, HITL (plan approval / interjection / intensity)
    agents.py            #   the tool-using agent loop + approval gating
    roles.py             #   the pentest agent prompts + tool lists
    config.py            #   config schema (HITL, tool-approval policy, kali, intensity)
    llm.py               #   Anthropic / OpenAI / Mock providers
    tools/               #   native, control, pentest (strix-inspired), custom, MCP client
    static/              #   the web UI (index.html, app.js, style.css)
  kali_server/           # MCP-over-HTTP server to run inside Kali (its own README + Dockerfile)
  skills/                # markdown methodology playbooks per discipline
  tests/smoke_test.py    # offline end-to-end test (mock provider) — incl. auth & isolation
```

## Inspecting session logs
Every session writes its full event stream to `workspaces/<session_id>/logs/events.jsonl`
(messages, thinking, every tool call + result, narration, plan sign-offs, operator
interjections, intensity changes, findings, cost, errors). `read_log.py` renders it:
```bash
python read_log.py --list                 # list sessions that have a log
python read_log.py s_xxxxxxxx             # build a chat-style web UI and open it
python read_log.py s_xxxxxxxx --serve     # live web UI that auto-refreshes during a run
python read_log.py s_xxxxxxxx --text      # color-coded console timeline + summary
python read_log.py s_xxxxxxxx --raw       # dump the full raw LLM conversation to the console
```
The web UI groups everything by agent (process tree in the sidebar) and has a **Chat / Raw**
toggle: *Chat* is the filtered, readable feed; *Raw* shows the **whole LLM conversation** —
each turn's reasoning, answer text, the exact tool calls (full JSON), the stop reason, and tool
outputs — for debugging. It's a single self-contained HTML file (no dependencies).

## Testing
```bash
python tests/smoke_test.py     # no keys / no Kali needed (uses the Mock provider)
```

## Customizing & extending SPAIDER
Most things are configurable from the UI (**Settings**) without touching code:

- **Add an agent discipline** (e.g. `cloud`, `mobile`, `wireless`) — Settings → Agents & skills.
- **Edit an agent's prompt / give it MCP servers** — Settings → Agents & skills.
- **Tune the tool-approval policy** (which categories need sign-off) — Settings → Tool approval.
- **Set models, keys, parameters, pricing, presets** — Settings → Models.
- **Write methodology skills** — drop a Markdown file in [`skills/`](skills/).


For deeper changes — adding a host or Kali tool, changing the agent loop, the report/template
pipeline, intensity mapping, persistence, or auth — every module and the exact function to edit is
documented in the **developer & customization guide**: [`spider/README.md`](spider/README.md).
The Kali tool server has its own guide: [`kali_server/README.md`](kali_server/README.md).

---

## Safety & scope
SPAIDER is built for authorised engagements. Keep agents in scope via the rules-of-engagement
brief, the tool-approval policy, and (on the Kali side) the `SPIDER_SCOPE` allow-list. Avoid
DoS/destructive actions unless explicitly authorised — the agents are instructed to escalate
those to you rather than act.

**Accounts.** SPAIDER is multi-user: one admin manages accounts and global settings and can **monitor
every user's session live and stop any of them**; every other user is isolated to their own sessions
(enforced server-side, not just in the UI). Bind the server to `127.0.0.1` (the default) unless you
intend to expose it; if you do expose it, put it behind HTTPS so the login cookie is protected in
transit.
