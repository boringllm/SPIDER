# Spider Kali MCP server

A small **MCP-over-HTTP** server that runs **inside your Kali container** and exposes Kali's
offensive tools to Spider as callable functions. Spider's agents (recon / web_app / network /
exploitation / post_exploit) connect to it and drive real tools — with carefully described
parameters and a single **intensity** knob that maps to each tool's real flags.

```
Spider (host)  ──MCP/HTTP──►  kali_server (in Kali)  ──subprocess──►  nmap / nikto / sqlmap / hydra / …
```

## Why a server (and not just SSH)?
Each tool is wrapped as a **typed function** with a JSON schema and a detailed description, so
the LLM agents know exactly which parameters exist and what each one does (these tools have very
different blast radius). Every tool also declares an approval **category** (recon / enum / web /
exploit / bruteforce / …) that travels to Spider so the operator's tool-approval policy can gate
the dangerous ones. And the **intensity** (passive → insane) is translated per-tool into safe vs.
loud flags (nmap `-T1`..`-T5`, thread counts, request rates, hydra parallelism).

## Run it (one command)
The image is **pre-configured** — all the tools, interpreters, and wordlists are baked in — so you
just pull and run it. A published build is on Docker Hub:

```bash
docker pull sungyongkim98/spider-kali:latest      # ~1.9 GB download, no build needed
```

Then run it with the compose file (settings come from a `.env` file, never from the image):
```bash
cd kali_server
cp .env.example .env            # then edit: set SPIDER_KALI_TOKEN and SPIDER_SCOPE
docker compose up -d            # pulls the published image (or builds locally if you changed it)
```
`docker compose ps` shows it healthy; open `http://<kali-host>:8765/` for a status page listing every
tool and whether its binary is installed.

> First build downloads Kali + the toolchain (several GB, many minutes). You only do this **once** —
> see "Build once & share" below to distribute the result.

### Build once & share (others only install the Spider client)
Build the image on one machine, hand the result to teammates as a single file, and they run it
without rebuilding. The `scripts/share.sh` (Linux/macOS) / `scripts/share.ps1` (Windows) helpers wrap
the Docker commands:
```bash
# On the machine that builds it:
scripts/share.sh build          # docker build -t spider-kali:latest
scripts/share.sh package        # -> spider-kali-image.tar.gz  (docker save + gzip)

# Send spider-kali-image.tar.gz to a teammate. On their machine:
scripts/share.sh load spider-kali-image.tar.gz   # docker load (no rebuild, works offline)
cp .env.example .env             # set their token/scope
scripts/share.sh run             # docker compose up -d
```
(Windows: `scripts\share.ps1 build|package|load|run`.) Alternatively push to a registry once
(`docker tag spider-kali ghcr.io/you/spider-kali && docker push …`) and teammates `docker pull` it.

Teammates need **only Docker + this loaded image + the Spider client** — no Kali install, no apt
downloads. They point Spider → Settings → Kali at `http://<their-docker-host>:8765/mcp` and go.

### In an existing Kali box (no Docker)
```bash
pip install -r kali_server/requirements.txt
python -m kali_server.run --host 0.0.0.0 --port 8765
```

## Point Spider at it
In Spider's **Settings → Kali** (or `config/config.json`):
```json
"kali": { "enabled": true, "url": "http://<kali-host>:8765/mcp",
          "assign_roles": ["recon","web_app","network","exploitation","post_exploit"] }
```
Spider connects on session start; the Kali tools then appear to those agents as
`kali__nmap_scan`, `kali__sqlmap_test`, etc.

## Safety / configuration (environment variables)
| Variable | Effect |
|---|---|
| `SPIDER_KALI_TOKEN` | If set, every `/mcp` request must send `Authorization: Bearer <token>`. |
| `SPIDER_SCOPE` | Comma-separated hosts/CIDRs. Tools **refuse** targets outside it (server-side backstop). |
| `SPIDER_KALI_WORKDIR` | Working dir for the generic terminal/file tools (default `/root/spider`). |
| `SPIDER_KALI_MAX_PARALLEL` | Max tool subprocesses running at once across **all** sessions/users sharing this container (default `8`; `0` = unlimited). Excess tool calls **queue** instead of overloading the box. |

> Run this only on an isolated lab/engagement network. It executes real offensive tools. The
> server is a backstop — Spider also keeps agents in scope via prompts and the approval policy.

## Running-process monitor
Every command a tool launches is tracked in a registry (`tools/_procs.py`), tagged with which Spider
session/agent/tool started it (Spider sends this in the JSON-RPC `_meta`). This powers Spider's
**Running in Kali** panel: the operator can see live processes, **kill** a runaway one (e.g. an
enumeration scan overloading the target), and stopping a session kills all of that session's
processes. Commands run in their own process group (`start_new_session=True`) so a kill takes down
the whole tool tree; the compose file runs an init (`init: true`) so killed processes are reaped.
Control ops (`__list_processes__` / `__kill_process__` / `__kill_session__`) are operator-only — they
are **not** in `tools/list`, so agents never see them.

**Concurrency cap.** Because one container is shared by every operator, `run`/`run_shell` (in
`tools/_common.py`) also hold a slot in a global `asyncio.Semaphore` sized by `SPIDER_KALI_MAX_PARALLEL`
for the lifetime of each tool. When the cap is reached, further tool calls **queue** rather than
piling more load on the container/target — a backstop that complements the per-session intensity knob
and the manual kill.

## Proxying tool traffic
Spider can push a **Kali proxy** to the server (Settings → Outbound proxies) so the offensive tools
route through an authenticated HTTP proxy. It travels in the JSON-RPC `_meta` of each tool call;
`tools/_common._subprocess_env` then sets `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` (and `NO_PROXY` for
the whitelist) on the tool subprocess. Proxy-aware tools (curl, wget, httpx, gospider, nuclei, …)
honour it; raw-socket tools like nmap can't use an HTTP proxy. This is independent of the Spider
control app's own (client) proxy. No container env/restart is needed — it applies per tool call.

## Reaching a target on the operator's own host
Tools run *inside* the container, where `127.0.0.1` is the container itself. To hit a target on the
**operator's host loopback**, use `host.docker.internal` (the compose file maps it via `extra_hosts`
so it works on Linux too). Spider detects a localhost target and tells the agents this automatically.

## Tools included
| Category | Tools |
|---|---|
| recon | `nmap_scan`, `dns_enum`, `whois_lookup`, `whatweb_scan`, `http_probe` (httpx), `web_crawl` (gospider), `waf_detect` (wafw00f) |
| web / API | `nikto_scan`, `gobuster_dir`, `ffuf_fuzz`, `sqlmap_test`, `wpscan_scan`, `param_discover` (arjun) |
| enum / network | `enum4linux`, `smb_list_shares`, `snmp_enum`, `ssl_scan` |
| exploit | `searchsploit`, `nuclei_scan`, `metasploit_run`, `commix_test` (cmd injection), `run_poc` (write + run a PoC in Kali) |
| bruteforce | `hydra_bruteforce` |
| shell / filesystem | `run_command`, `write_file`, `read_file` |

The `api_web.py` module adds a web/API wave: **`http_probe`** (bulk httpx probing/fingerprint),
**`web_crawl`** (gospider crawl → endpoints/forms/JS URLs), **`param_discover`** (arjun hidden-
parameter discovery), **`commix_test`** (OS command-injection), and **`waf_detect`** (wafw00f).

## Output filtering
Raw offensive-tool output is mostly noise (banners, progress bars, per-cipher dumps, INFO/DEBUG
logs, legal notices). `tools/_filters.py` gives each tool a **purely static** filter that keeps
only the interesting discoveries (open ports, found paths, vulns, creds, DNS records, parameters…)
and drops the rest before the agent sees it — saving the agent's context.

* **Per call:** an agent can pass `raw=true` to any filterable tool to get the COMPLETE unfiltered
  output (the parameter is auto-advertised in the tool's schema).
* **Globally:** Spider sends the operator's *Settings → Kali → filter tool output* preference in the
  JSON-RPC `_meta`; when off, `_maybe_filter` returns every tool's output unchanged.
* **Safe by design:** errors/timeouts/killed runs and tiny outputs are never filtered, and a footer
  always reports how many lines were hidden — a filter can't silently mislead. Tools with already-
  concise or agent-authored output (`run_command`, `run_poc`, `write_file`, `read_file`) are left
  unfiltered. Coverage is verified by `tests/test_filters.py` (run it after editing a filter).

## Add your own tool
Adding a tool to the Kali container is four small steps. Spider discovers it automatically (with its
category and availability) on the next connect — no Spider-side code changes.

**1. Install the binary** in the image so it ships with the container. Add the package to the right
`apt-get install` line in [`Dockerfile`](Dockerfile) (or `pip install` it):
```dockerfile
        # web / api ...
        httpx-toolkit gospider arjun commix wafw00f  mynewtool \
```

**2. Write the tool handler.** Create or extend a module in `kali_server/tools/`, decorate an
`async def` handler with `@tool(...)`, and use the `_common` helpers (`require_arg`, `check_scope`,
`run`/`run_shell`, and the intensity helpers `threads`/`rate`/`nmap_timing`/`hydra_tasks`):
```python
from ..registry import tool
from ._common import check_scope, require_arg, run, threads

@tool(
    name="my_scanner",            # the agent calls it as kali__my_scanner
    category="enum",              # one of Spider's TOOL_CATEGORIES — drives the approval policy
    requires=["mynewtool"],       # Kali binaries it needs; a missing one is reported cleanly
    description="What it does and what each parameter changes (be precise about impact/loudness).",
    input_schema={"type": "object",
                  "properties": {"target": {"type": "string", "description": "..."}},
                  "required": ["target"]},
)
async def my_scanner(args: dict) -> str:
    target = require_arg(args, "target")
    check_scope(target)           # honour SPIDER_SCOPE
    # run() registers the process (kill/monitor), enforces the parallel cap, and times out.
    return await run(["mynewtool", "-t", str(threads(args.get("intensity"))), target])
```

**3. Register the module** so it loads: add it to the import line in
[`tools/__init__.py`](tools/__init__.py).

**4. (Recommended) Add a static output filter** so the agent isn't flooded with the tool's noise.
In [`tools/_filters.py`](tools/_filters.py) write `def _f_my_scanner(lines: list[str]) -> list[str]`
that returns only the interesting lines, and register it in the `FILTERS` dict under the tool's
name. The framework already strips ANSI colour and normalises `\r` progress bars before your filter
runs, and it auto-adds the `raw=true` opt-out + the footer. Add a case to
[`tests/test_filters.py`](tests/test_filters.py) (feed a real sample, assert the findings survive
and the noise is dropped) and run `python kali_server/tests/test_filters.py`. Skip this step only
for tools whose output is already concise or agent-authored — unregistered tools pass through
unchanged.

**Functions you touch:** `@tool` (registration, `registry.py`), the `_common` run/scope/intensity
helpers, `tools/__init__.py` (import), and — for filtering — `_filters.FILTERS` + your `_f_*`
function. Then rebuild & restart the container: `docker compose up -d --build`.
