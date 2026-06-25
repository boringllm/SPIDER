"""Offline smoke test for SPAIDER. No API keys or Kali needed — uses the Mock LLM provider
and FastAPI's TestClient. Run:  python tests/smoke_test.py

Covers: config schema, pentest roles, categorised tools, the tool-approval policy, the
plan-approval + interjection + intensity HITL flows, an end-to-end mock engagement, report
generation, and the Kali MCP server (registry + JSON-RPC endpoint)."""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_passed = 0
_failed = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  [PASS] {name}")
    else:
        _failed += 1
        print(f"  [FAIL] {name} {extra}")


# --------------------------------------------------------------------------- #
def test_config_and_roles() -> None:
    from spider import config
    from spider.roles import ROLES
    cfg = config.default_config()
    check("config has human_in_the_loop", "human_in_the_loop" in cfg)
    check("config has tool_approval policy", cfg["tool_approval"]["by_category"]["exploit"] == "manual")
    check("config has kali block", "kali" in cfg and "url" in cfg["kali"])
    check("config default intensity", cfg["default_intensity"] in config.INTENSITY_LEVELS)
    check("poc_execution defaults to kali_only", cfg["poc_execution"] == "kali_only")
    for r in ("orchestrator", "recon", "web_app", "network", "exploitation", "post_exploit", "reporting"):
        check(f"role '{r}' present", r in ROLES)
    check("no reverse-engineering roles leaked", "reverse_analyst" not in ROLES)


def test_tools_categorised() -> None:
    from spider.tools import base_tools, tool_catalog
    bt = base_tools()
    check("pentest tool 'terminal' present", "terminal" in bt and bt["terminal"].category == "shell")
    check("pentest tool 'http_request' is web", bt.get("http_request") and bt["http_request"].category == "web")
    check("cross-platform run_shell present", "run_shell" in bt and bt["run_shell"].category == "shell")
    check("run_shell is policy-driven (not hard floor)", not bt["run_shell"].requires_approval)
    check("legacy run_as_admin removed", "run_as_admin" not in bt)
    check("legacy run_powershell/run_cmd removed", "run_powershell" not in bt and "run_cmd" not in bt)
    cat = {t["name"]: t for t in tool_catalog()}
    check("tool_catalog exposes category", cat["terminal"]["category"] == "shell")


def test_connection_test_and_proxies() -> None:
    """LLM connection-test + proxy plumbing: config blocks exist; a 'hello' round-trips through a
    provider (the mechanism behind Settings → Test connection); the client proxy builds a
    no_proxy-aware httpx client only when enabled; the Kali server injects proxy env from _meta;
    and proxy URLs (which embed credentials) are stripped for non-admins."""
    from spider import config
    from spider.llm import _http_client, make_provider

    c = config.default_config()
    check("client_proxy block present", "client_proxy" in c and "no_proxy" in c["client_proxy"])
    check("kali_proxy block present", "kali_proxy" in c and "no_proxy" in c["kali_proxy"])
    check("verify_ssl defaults on per model", c["models"]["orchestrator"].get("verify_ssl") is True)

    # 'send hello' round-trip via the mock provider (what Test connection does, minus the HTTP layer)
    prov = make_provider({"provider": "mock", "model": "mock"})
    resp = asyncio.run(prov.complete("connectivity check",
                       [{"role": "user", "content": [{"type": "text", "text": "Hello!"}]}], []))
    check("LLM hello round-trips to a non-empty reply", isinstance(resp.text, str) and len(resp.text) > 0)

    # custom httpx client only when a proxy and/or TLS-off is needed (None otherwise)
    check("no custom http client by default", _http_client({"_client_proxy": {"enabled": False}}) is None)
    check("no custom http client when verify on", _http_client({"verify_ssl": True}) is None)
    hc = _http_client({"_client_proxy": {"enabled": True, "url": "http://u:p@proxy:8080",
                                         "no_proxy": ["localhost", "127.0.0.1"]}})
    check("http client built for proxy", hc is not None)
    if hc is not None:
        asyncio.run(hc.aclose())
    # verify_ssl: false builds a (verify-disabled) client even without a proxy
    hc2 = _http_client({"verify_ssl": False})
    check("http client built when TLS verification disabled", hc2 is not None)
    if hc2 is not None:
        asyncio.run(hc2.aclose())

    # Kali subprocess proxy env injected from _meta, none without it
    from kali_server.tools import _common
    from kali_server.tools._procs import CURRENT_META
    CURRENT_META.set({"proxy": {"url": "http://u:p@px:3128", "no_proxy": ["localhost", "10.0.0.0/8"]}})
    env = _common._subprocess_env()
    check("kali proxy env set from _meta", bool(env) and env.get("HTTPS_PROXY") == "http://u:p@px:3128")
    check("kali no_proxy env set", bool(env) and "localhost" in (env.get("NO_PROXY") or ""))
    CURRENT_META.set({})
    check("no kali proxy env without _meta proxy", _common._subprocess_env() is None)

    # proxy URLs (embed id:password) are stripped for non-admins
    from spider.server import _full_error, _sanitize_config
    c["client_proxy"]["url"] = c["kali_proxy"]["url"] = "http://u:secret@px:8080"
    san = _sanitize_config(c)
    check("client proxy url stripped for non-admin", san["client_proxy"]["url"] == "")
    check("kali proxy url stripped for non-admin", san["kali_proxy"]["url"] == "")

    # full LLM error: includes status + the provider's response body + a traceback
    class _FakeAPIError(Exception):
        status_code = 401
        body = {"error": {"message": "invalid x-api-key"}}
    try:
        raise _FakeAPIError("Unauthorized")
    except Exception as e:  # noqa: BLE001
        full = _full_error(e)
    check("full error keeps HTTP status", "401" in full)
    check("full error includes the provider's response body", "invalid x-api-key" in full)
    check("full error includes a traceback", "Traceback" in full)


def test_env_loader() -> None:
    """The dependency-free .env loader parses quotes/spaces/comments/export, doesn't override a
    real shell variable, and (with override) does. This is what lets SPAIDER_REQUIRE_DISCLAIMER (and
    API keys) live in a .env file instead of being exported."""
    import os
    import tempfile

    from spider._env import load_env

    p = Path(tempfile.mkdtemp(prefix="spider_env_")) / ".env"
    p.write_text(
        "# a comment\n"
        'SPIDER_TEST_QUOTED = "1"\n'
        "export SPIDER_TEST_EXPORT=yes\n"
        "SPIDER_TEST_PLAIN=http://u:p@h:8080/path#frag\n"   # '#' must stay (not an inline comment)
        "\n"
        "SPIDER_TEST_PREEXISTING=fromfile\n",
        encoding="utf-8",
    )
    for k in ("SPIDER_TEST_QUOTED", "SPIDER_TEST_EXPORT", "SPIDER_TEST_PLAIN", "SPIDER_TEST_PREEXISTING"):
        os.environ.pop(k, None)
    os.environ["SPIDER_TEST_PREEXISTING"] = "fromshell"  # a real var the file must NOT clobber

    n = load_env(p)
    check("loader applied the new keys", n == 3)
    check("quoted value unquoted + spaces trimmed", os.environ.get("SPIDER_TEST_QUOTED") == "1")
    check("export prefix handled", os.environ.get("SPIDER_TEST_EXPORT") == "yes")
    check("'#' inside a value is preserved", os.environ.get("SPIDER_TEST_PLAIN") == "http://u:p@h:8080/path#frag")
    check("existing shell var not overridden", os.environ.get("SPIDER_TEST_PREEXISTING") == "fromshell")

    load_env(p, override=True)
    check("override=True lets the file win", os.environ.get("SPIDER_TEST_PREEXISTING") == "fromfile")
    check("missing file -> 0", load_env(p.parent / "nope.env") == 0)

    for k in ("SPIDER_TEST_QUOTED", "SPIDER_TEST_EXPORT", "SPIDER_TEST_PLAIN", "SPIDER_TEST_PREEXISTING"):
        os.environ.pop(k, None)


def test_disclaimer_flag() -> None:
    """The hidden risk-disclaimer feature is gated by the SPAIDER_REQUIRE_DISCLAIMER env var
    (read per-request), and surfaced to the SPA via /api/auth/status."""
    import os

    from spider.server import _disclaimer_required

    os.environ.pop("SPAIDER_REQUIRE_DISCLAIMER", None)
    check("disclaimer off by default", _disclaimer_required() is False)
    for v in ("1", "true", "YES", "on"):
        os.environ["SPAIDER_REQUIRE_DISCLAIMER"] = v
        check(f"disclaimer ON for {v!r}", _disclaimer_required() is True)
    for v in ("0", "false", "", "no"):
        os.environ["SPAIDER_REQUIRE_DISCLAIMER"] = v
        check(f"disclaimer OFF for {v!r}", _disclaimer_required() is False)
    os.environ.pop("SPAIDER_REQUIRE_DISCLAIMER", None)


def test_approval_policy() -> None:
    from spider import config
    from spider.db import Database
    from spider.session import Session
    db = Database(":memory:")
    cfg = config.default_config()
    s = Session("s_t", "t", cfg, db)
    web = SimpleNamespace(name="http_request", category="web", requires_approval=False)
    recon = SimpleNamespace(name="kali__nmap_scan", category="recon", requires_approval=False)
    # The hard-floor mechanism (requires_approval=True => always gated) still exists even
    # though no built-in tool uses it now; verify it with a synthetic tool.
    hard = SimpleNamespace(name="synthetic_dangerous", category="recon", requires_approval=True)
    check("web tool gated by policy (manual)", s.tool_needs_approval(web) is True)
    check("recon tool auto by policy", s.tool_needs_approval(recon) is False)
    check("hard-floor tool always gated", s.tool_needs_approval(hard) is True)
    s.approval_mode = "auto"
    check("auto mode bypasses everything", s.tool_needs_approval(web) is False)
    db.close()


def _mock_cfg():
    from spider import config
    cfg = config.default_config()
    for mc in cfg["models"].values():
        mc["provider"] = "mock"
        mc["model"] = "mock-model"
    cfg["approval_mode"] = "auto"  # don't block on approvals during the offline run
    cfg["human_in_the_loop"]["plan_approval"] = "off"  # don't block on plan sign-off
    return cfg


async def test_end_to_end() -> None:
    from spider import config
    from spider.session import SessionManager
    tmp = Path(tempfile.mkdtemp(prefix="spider_smoke_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"  # keep the real config untouched
    mgr = SessionManager(db=__import__("spider.db", fromlist=["Database"]).Database(str(tmp / "spider.db")))
    sess = mgr.create("smoke", cfg)
    await sess.start("10.10.10.5", "Authorised lab engagement. No DoS.")
    # wait for the orchestrator pipeline to finish (bounded)
    for _ in range(100):
        if sess.status in ("completed", "stopped", "error"):
            break
        await asyncio.sleep(0.05)
    check("session reached terminal state", sess.status in ("completed", "stopped", "error"), f"(status={sess.status})")
    check("a plan was produced", len(sess.plan.get("steps", [])) > 0)
    check("at least one agent ran", len(sess.agents) >= 1)
    check("orchestrator exists", any(a.role == "orchestrator" for a in sess.agents.values()))
    check("a finding was recorded", len(sess.findings) >= 1)

    # intensity + interjection
    check("set_intensity works", sess.set_intensity("stealth") and sess.default_intensity == "stealth")
    check("reject bad intensity", sess.set_intensity("nope") is False)
    res = await sess.interject("Focus on the web app first.")
    check("interjection delivered", "deliver" in res.lower() or "operator" in res.lower() or "active" in res.lower(), f"({res})")

    # report generation (mock writes a report file) — Markdown always, .docx when python-docx is present
    rep = await sess.generate_report("Keep it short.", "# Title\n## Executive Summary\n## Findings")
    check("report generated (.md)", bool(rep.get("report")) and Path(rep["path"]).exists())
    try:
        import docx  # noqa: F401
        check("report also produced a .docx", bool(rep.get("docx_path")) and Path(rep["docx_path"]).exists())
    except ImportError:
        pass

    # parent-validation handshake: the recon sub-agent should have been validated & closed
    recon = [a for a in sess.agents.values() if a.role == "recon"]
    check("a sub-agent ran and was closed via validation", bool(recon) and all(a.status == "done" for a in recon))
    check("validated sub-agent is marked validated", all(getattr(a, "_validated", False) for a in recon))
    await sess.shutdown()


async def test_validation_and_raw_events() -> None:
    """The raw LLM output is captured (agent.raw) and a spawned sub-agent passes through
    'waiting_validation' before its parent closes it (mandatory validation handshake)."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.events import E, bus
    from spider.session import SessionManager

    tmp = Path(tempfile.mkdtemp(prefix="spider_val_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    mgr = SessionManager(db=Database(str(tmp / "v.db")))
    q = bus.subscribe()  # capture the live event stream
    sess = mgr.create("val", cfg)
    await sess.start("10.0.0.1", "Authorised lab engagement.")
    for _ in range(200):
        if sess.status in ("completed", "stopped", "error"):
            break
        await asyncio.sleep(0.05)
    raw_turns = 0
    saw_waiting_validation = saw_waiting_subagent = False
    while not q.empty():
        ev = q.get_nowait()
        if ev.type == E.AGENT_RAW:
            raw_turns += 1
        if ev.type == E.AGENT_STATUS:
            st = ev.payload.get("status")
            saw_waiting_validation = saw_waiting_validation or st == "waiting_validation"
            saw_waiting_subagent = saw_waiting_subagent or st == "waiting_subagent"
    bus.unsubscribe(q)
    check("raw LLM output captured (agent.raw)", raw_turns > 0)
    check("a sub-agent reached 'waiting_validation'", saw_waiting_validation)
    check("parent showed 'waiting_subagent'", saw_waiting_subagent)
    await sess.shutdown()


async def test_turn_budget_handoff() -> None:
    """An agent that hits its turn budget before calling finish has its work summarized by a
    summarizer (handoff) so findings aren't lost. The exhausted agent CLOSES as done (auto-
    accepted) instead of being parked forever in 'waiting_validation' — an involuntary turn-budget
    close is not a deliberate finish that needs parent sign-off."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.session import Session

    tmp = Path(tempfile.mkdtemp(prefix="spider_budget_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    cfg["models"]["recon"]["max_turns"] = 1  # force exhaustion before finish
    sess = Session("budget", "t", cfg, Database(str(tmp / "b.db")))
    await sess.setup()
    parent = await sess.create_agent("orchestrator", "lead", parent=None)
    child = await sess.create_agent("recon", "Recon the target", parent=parent)
    sess.start_agent(child)
    res = await asyncio.wait_for(sess.wait_for(child), timeout=20)
    check("exhausted agent got a handoff summary", res.startswith("[REACHED MAX TURN BUDGET"))
    summarizers = [a for a in sess.agents.values() if a.role == "summarizer"]
    check("a summarizer was spawned for the handoff", bool(summarizers))
    # The summarizer is a transient helper — nobody validates it, so it must close on its own and
    # never sit in 'waiting_validation' forever.
    check("summarizer closes done (not stuck awaiting validation)",
          all(s.status == "done" and s.awaiting_validation is False for s in summarizers))
    check("exhausted sub-agent closes done (not stuck awaiting validation)", child.status == "done")
    check("exhausted sub-agent is not awaiting validation", child.awaiting_validation is False)

    # Re-engaging an EXHAUSTED agent whose budget was NOT raised must NOT spawn a SECOND summarizer
    # for the same exhaustion (the bug where the summarizer kicked in twice for one exhausted agent).
    n_summarizers = sum(1 for a in sess.agents.values() if a.role == "summarizer")
    child.inbox.put_nowait("[Message from operator]: continue")
    await asyncio.wait_for(child.run_followup(), timeout=20)
    check("re-engaging an exhausted agent does not summarize it twice",
          sum(1 for a in sess.agents.values() if a.role == "summarizer") == n_summarizers)
    await sess.shutdown()


async def test_orchestrator_not_summarized_on_exhaustion() -> None:
    """The orchestrator (root) is NOT summarized when it hits max_turns — there is no parent to hand
    a summary to, so it just stops at the budget with its current result (no stray summarizer agent),
    including when the operator continues it."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.session import Session

    tmp = Path(tempfile.mkdtemp(prefix="spider_orch_exhaust_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    cfg["human_in_the_loop"]["plan_approval"] = "off"   # don't block the orchestrator on approval
    cfg["models"]["orchestrator"]["max_turns"] = 1      # force exhaustion immediately
    sess = Session("orch_exhaust", "t", cfg, Database(str(tmp / "o.db")))
    await sess.setup()
    orch = await sess.create_agent("orchestrator", "lead the engagement", parent=None)
    sess.start_agent(orch)
    res = await asyncio.wait_for(sess.wait_for(orch), timeout=20)
    check("orchestrator NOT summarized on exhaustion (no summarizer spawned)",
          not any(a.role == "summarizer" for a in sess.agents.values()))
    check("orchestrator result is not a handoff summary", not res.startswith("[REACHED MAX TURN BUDGET"))
    check("exhausted orchestrator closed done", orch.status == "done")

    # continuing the orchestrator must still never spawn a summarizer for it
    orch.inbox.put_nowait("[Message from operator]: please continue")
    await asyncio.wait_for(orch.run_followup(), timeout=20)
    check("orchestrator still never summarized after continue",
          not any(a.role == "summarizer" for a in sess.agents.values()))
    await sess.shutdown()


async def test_max_turns_live_and_budget_preserved() -> None:
    """The reported bug: max_turns must be read LIVE from the session config (so raising it in
    Settings applies on the next continue) and the turn budget must be PRESERVED across re-activation
    (not reset). Together: an agent that finished near an OLD low limit picks up a raised limit on
    continue and keeps working — without being handed a fresh count."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.session import Session

    tmp = Path(tempfile.mkdtemp(prefix="spider_maxturns_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    cfg["models"]["recon"]["max_turns"] = 40
    sess = Session("maxturns", "t", cfg, Database(str(tmp / "m.db")))
    await sess.setup()
    agent = await sess.create_agent("recon", "recon the target", parent=None)
    check("max_turns read live from session config", agent._max_turns() == 40)
    sess.start_agent(agent)
    await asyncio.wait_for(sess.wait_for(agent), timeout=20)
    check("agent finished cleanly below budget", agent.stopped is False and agent._turns < 40)

    # Simulate having finished NEAR the limit; the operator raises max_turns and continues.
    agent._turns = 39
    sess.cfg["models"]["recon"]["max_turns"] = 200       # what reload_config would pick up from disk
    check("raised max_turns is picked up LIVE (not frozen at creation)", agent._max_turns() == 200)
    n_summarizers = sum(1 for a in sess.agents.values() if a.role == "summarizer")
    agent.inbox.put_nowait("[Message from operator]: continue, do a bit more")
    await asyncio.wait_for(agent.run_followup(), timeout=20)
    check("turn budget PRESERVED across continue (not reset to 0)", agent._turns >= 39)
    check("with the raised live limit, continue does not spuriously summarize",
          sum(1 for a in sess.agents.values() if a.role == "summarizer") == n_summarizers)
    await sess.shutdown()


async def test_reengage_after_stop() -> None:
    """After the operator stops an agent (or the whole session), they can resume a conversation
    with it: run_followup clears the stop flag so the loop runs again instead of breaking out
    immediately, and messaging an agent in a stopped session revives the session."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.session import Session

    tmp = Path(tempfile.mkdtemp(prefix="spider_reengage_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    sess = Session("reengage", "t", cfg, Database(str(tmp / "r.db")))
    await sess.setup()
    agent = await sess.create_agent("recon", "look around", parent=None)

    # (1) single-agent stop, then re-engage: the stop flag must be cleared so the loop runs,
    # but the TURN BUDGET must be PRESERVED (stop/resume is not a way to get a fresh budget).
    agent._turns = 5
    agent.stop()
    check("agent is stopped", agent.stopped is True)
    agent.inbox.put_nowait("[Message from operator]: are you there?")
    res = await asyncio.wait_for(agent.run_followup(), timeout=20)
    check("re-engaged agent's loop actually ran (stop flag cleared)", agent.stopped is False)
    check("re-engaged agent produced a result", isinstance(res, str) and res != "Stopped by operator.")
    check("turn budget preserved across stop/resume (not reset to 0)", agent._turns > 5)

    # (2) full session stop, then message an agent -> session revives to running.
    await sess.stop()
    check("session is stopped", sess.status == "stopped")
    out = await sess.message_agent(agent.id, "resume please")
    check("messaging an agent revives a stopped session", sess.status == "running")
    check("message_agent re-activated the agent", "re-activated" in out or "delivered" in out)
    await asyncio.sleep(0.1)
    await sess.shutdown()


async def test_plan_approval_flow() -> None:
    from spider import config
    from spider.db import Database
    from spider.session import Session
    cfg = config.default_config()
    cfg["human_in_the_loop"]["plan_approval"] = "once"
    db = Database(":memory:")
    s = Session("s_plan", "p", cfg, db)
    agent = SimpleNamespace(id="a_x")
    task = asyncio.create_task(s.submit_plan(agent, ["Recon", "Enumerate", "Report"]))
    # let it register the pending approval
    for _ in range(40):
        if s.pending_plan_approvals():
            break
        await asyncio.sleep(0.02)
    pend = s.pending_plan_approvals()
    check("plan approval requested", len(pend) == 1)
    # While the operator hasn't decided, the agent's wait is a real WAIT, not an "unfinished"
    # state: has_pending_plan_approval is True and await_plan_decision_for blocks (not returns None).
    check("pending plan approval is tracked", s.has_pending_plan_approval(agent.id) is True)
    waiter = asyncio.create_task(s.await_plan_decision_for(agent))
    await asyncio.sleep(0.05)
    check("await_plan_decision_for blocks until operator decides", not waiter.done())
    if pend:
        s.resolve_plan_approval(pend[0]["id"], "approve")
    result = await asyncio.wait_for(task, timeout=2)
    check("approved plan returns proceed", "APPROVED" in result or "proceed" in result.lower(), f"({result})")
    waited = await asyncio.wait_for(waiter, timeout=2)
    check("idle-turn waiter gets the operator's verdict", waited is not None and "APPROVED" in waited)
    check("no pending approval after resolve", s.has_pending_plan_approval() is False)
    check("await returns None when nothing pending", await s.await_plan_decision_for(agent) is None)
    db.close()


def test_poc_execution_policy() -> None:
    """PoCs/exploits run in Kali only by default: host command-execution tools are withheld
    from agents in 'kali_only' mode and kept in 'host' mode. The report agent stays on the host
    with read/write tools only (no execution)."""
    from spider import config
    from spider.db import Database
    from spider.registry import role_specs
    from spider.session import Session
    db = Database(":memory:")
    host_exec = set(config.HOST_EXEC_TOOLS)

    cfg = config.default_config()  # kali_only
    s = Session("s_poc1", "t", cfg, db); s.roles = role_specs(cfg)
    exo = set(s._tools_for_role("exploitation"))
    check("kali_only: exploitation has no host exec tools", not (exo & host_exec))
    check("kali_only: exploitation keeps file/web tools", {"read_file", "write_file", "http_request"} <= exo)

    cfg2 = config.default_config(); cfg2["poc_execution"] = "host"
    s2 = Session("s_poc2", "t", cfg2, db); s2.roles = role_specs(cfg2)
    exo2 = set(s2._tools_for_role("exploitation"))
    check("host mode: exploitation keeps host exec tools", host_exec <= exo2)

    rep = set(s._tools_for_role("reporting"))
    check("reporting (host) has write_file, no exec tools", "write_file" in rep and not (rep & host_exec))
    db.close()


def test_reference_documents() -> None:
    """Operator reference-document attachments: text extraction (md/unsupported), per-session
    storage + manifest, and injection into the orchestrator brief (read via read_file)."""
    from spider import config, docs
    from spider.db import Database
    from spider.session import Session

    txt, err = docs.extract_text(b"# Scope\nOnly 10.10.10.5 is in scope. No DoS.", "scope.md")
    check("md text extracted", bool(txt) and not err)
    _, e2 = docs.extract_text(b"x", "evil.exe")
    check("unsupported type reported", "unsupported" in e2.lower())
    check("safe_name strips path traversal", docs.safe_name("../../etc/passwd") == "passwd")

    tmp = Path(tempfile.mkdtemp(prefix="spider_docs_"))
    cfg = config.default_config(); cfg["workspace_root"] = str(tmp)
    db = Database(":memory:")
    s = Session("s_docs", "t", cfg, db)
    entry = s.add_upload("scope.md", b"# Rules of Engagement\nIn scope: 10.10.10.5. Off-limits: DoS.")
    check("upload stored with extracted chars", entry["chars"] > 0 and not entry["error"])
    check("extracted text sidecar written", (s.workspace / entry["text_path"]).exists())
    check("upload appears in manifest list", any(u["name"] == "scope.md" for u in s.list_uploads()))
    block = s._reference_docs_block()
    check("reference-docs block built", "REFERENCE DOCUMENTS" in block and "Rules of Engagement" in block)
    check("block points at the readable path", "uploads/text/scope.md.txt" in block)
    check("remove_upload works", s.remove_upload("scope.md") and not s.list_uploads())
    db.close()


def test_report_docx_and_template() -> None:
    """The report renderer converts Markdown to a structured .docx, and .docx extraction is
    heading-aware (so a Word template's structure is preserved for the report agent to follow)."""
    import tempfile

    from spider import docs
    try:
        import docx  # noqa: F401
        have_docx = True
    except ImportError:
        have_docx = False

    md = "# Title\n## Executive Summary\nText with **bold**.\n\n- a bullet\n\n| Col A | Col B |\n| --- | --- |\n| 1 | 2 |\n"
    out = Path(tempfile.mkdtemp(prefix="spider_docx_")) / "r.docx"
    ok, err = docs.markdown_to_docx(md, str(out))
    if have_docx:
        check("markdown_to_docx produced a .docx", ok and out.exists(), f"({err})")
        text, e = docs.extract_text(out.read_bytes(), "r.docx")
        check("docx extraction is heading-aware", "# Title" in text and "## Executive Summary" in text)
        check("docx round-trips the table", "| Col A | Col B |" in text)
    else:
        check("markdown_to_docx degrades gracefully without python-docx", (not ok) and "python-docx" in err)


async def test_reporter_dedup_dossier() -> None:
    """The reporter is fed a DEDUPLICATED findings dossier (the same vuln reported by several
    agents collapses to one entry, keeping the most severe / most-detailed instance) and is NOT
    re-injected with the role-memory + notes blocks — the duplication that was overflowing its
    context. Distinct findings are all kept."""
    import tempfile

    from spider import config
    from spider.db import Database
    from spider.session import Session

    tmp = Path(tempfile.mkdtemp(prefix="spider_dossier_"))
    cfg = _mock_cfg()
    cfg["workspace_root"] = str(tmp / "workspaces")
    cfg["agents_dir"] = str(tmp / "agents")
    config.CONFIG_DIR = tmp / "config"
    sess = Session("dossier", "t", cfg, Database(str(tmp / "d.db")))
    await sess.setup()
    orch = await sess.create_agent("orchestrator", "lead", parent=None)
    a1 = await sess.create_agent("web_app", "scan", parent=orch)
    a2 = await sess.create_agent("network", "scan", parent=orch)
    # same vuln (title + location) reported twice — a2's is more severe + more detailed
    await sess.add_finding("f_1", a1, "SQL Injection", "medium", "candidate",
                           {"location": "/login", "evidence": "short", "description": "maybe"})
    await sess.add_finding("f_2", a2, "sql injection", "high", "confirmed",
                           {"location": "/login", "evidence": "PROOF: ' OR 1=1-- dumped users table", "description": "confirmed"})
    # a genuinely different finding
    await sess.add_finding("f_3", a1, "XSS", "low", "candidate", {"location": "/search", "evidence": "alert(1)"})

    dossier = sess._report_findings_dossier()
    check("dossier deduplicates the same finding", dossier.count("/login") == 1)
    check("dossier keeps the distinct finding", "XSS" in dossier and "/search" in dossier)
    check("dossier reports it deduplicated 3 -> 2", "2 unique finding(s)" in dossier and "from 3 recorded" in dossier)
    check("dedup kept the more severe/detailed instance", "PROOF:" in dossier and "high/confirmed" in dossier)

    # the reporter must NOT get the role-memory / notes block injected (it duplicates the dossier)
    sess.role_memory.setdefault("orchestrator", []).append("orchestrator narrative memory")
    reporter = await sess.create_agent("reporting", "write the report", parent=orch)
    check("reporter prompt has no duplicated SHARED MEMORY block",
          "SHARED MEMORY for your role/lineage" not in reporter.system_prompt)
    worker = await sess.create_agent("web_app", "more scanning", parent=orch)
    check("a normal worker still gets SHARED MEMORY",
          "SHARED MEMORY for your role/lineage" in worker.system_prompt)
    await sess.shutdown()


async def test_auth_and_isolation() -> None:
    """Password hashing, the bootstrap admin, login tokens, and per-user session isolation
    (the security core of the multi-user feature) — exercised offline against auth + DB."""
    from spider.auth import Auth, AuthError, hash_password, verify_password
    from spider.db import Database
    db = Database(":memory:")
    auth = Auth(db)

    # password hashing is salted + verifies correctly, rejects wrong passwords
    h = hash_password("hunter2longpw")
    check("password verifies", verify_password("hunter2longpw", h))
    check("wrong password rejected", not verify_password("nope", h))
    check("two hashes of same pw differ (salt)", hash_password("hunter2longpw") != h)

    # first-run bootstrap admin
    check("needs_setup before any user", await auth.needs_setup() is True)
    admin = await auth.create_first_admin("root", "supersecret")
    check("first admin is admin", admin.is_admin)
    check("needs_setup false after setup", await auth.needs_setup() is False)

    # second create_first_admin refused; short passwords refused
    try:
        await auth.create_first_admin("root2", "supersecret"); check("second bootstrap refused", False)
    except AuthError:
        check("second bootstrap refused", True)
    try:
        await auth.create_user("bob", "short"); check("short password refused", False)
    except AuthError:
        check("short password refused", True)

    # regular user + login token round-trip + revoke on logout
    alice = await auth.create_user("alice", "alicepass1")
    tok, u = await auth.login("alice", "alicepass1")
    check("login returns the user", u.id == alice.id)
    check("token resolves to user", (await auth.resolve(tok)).username == "alice")
    await auth.logout(tok)
    check("logout revokes token", await auth.resolve(tok) is None)
    try:
        await auth.login("alice", "wrongpw"); check("bad login rejected", False)
    except AuthError:
        check("bad login rejected", True)

    # last-admin guard
    try:
        await auth.delete_user(admin.id); check("last admin protected", False)
    except AuthError:
        check("last admin protected", True)

    # session isolation at the DB layer
    await db.save_session("s_alice", "A", "t", "", "created", {}, {"steps": []}, {}, owner=alice.id)
    await db.save_session("s_admin", "B", "t", "", "created", {}, {"steps": []}, {}, owner=admin.id)
    alice_ids = {r["id"] for r in await db.list_sessions(owner=alice.id)}
    all_ids = {r["id"] for r in await db.list_sessions()}
    check("user sees only own sessions", alice_ids == {"s_alice"})
    check("admin (owner=None) sees all sessions", all_ids == {"s_alice", "s_admin"})

    # admin monitoring: SessionManager.list_all surfaces every session WITH the owner's username,
    # so the admin's UI can label whose engagement each one is (and open/stop any of them).
    from spider.session import SessionManager
    mgr = SessionManager(db=db)
    summaries = {s["id"]: s for s in await mgr.list_all(owner=None)}
    check("admin list_all sees all sessions", set(summaries) == {"s_alice", "s_admin"})
    check("list_all labels owner username", summaries["s_alice"]["owner_name"] == "alice")
    user_view = {s["id"] for s in await mgr.list_all(owner=alice.id)}
    check("user list_all stays filtered", user_view == {"s_alice"})
    db.close()


def test_kali_server() -> None:
    from fastapi.testclient import TestClient
    from kali_server.registry import REGISTRY, mcp_tool_list
    from kali_server.server import app
    check("kali registry populated", len(REGISTRY) >= 15)
    tl = mcp_tool_list()
    check("kali tools carry category meta", all("category" in t["_meta"] for t in tl))
    check("nmap_scan registered", any(t["name"] == "nmap_scan" for t in tl))
    c = TestClient(app)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    check("kali initialize ok", r.status_code == 200 and r.json()["result"]["serverInfo"]["name"] == "spider-kali")
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    names = [t["name"] for t in r.json()["result"]["tools"]]
    check("kali tools/list returns tools", "sqlmap_test" in names and "hydra_bruteforce" in names)
    check("kali run_poc tool present (PoCs run in Kali)", "run_poc" in names)
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                             "params": {"name": "nmap_scan", "arguments": {"target": "127.0.0.1", "mode": "ping"}}})
    res = r.json()["result"]
    check("kali tools/call returns content", "content" in res and res["content"][0]["type"] == "text")
    r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": "does_not_exist", "arguments": {}}})
    check("kali unknown tool -> isError", r.json()["result"]["isError"] is True)

    # new API/web tools are registered
    check("new api/web tools present",
          {"http_probe", "web_crawl", "param_discover", "commix_test", "waf_detect"} <= set(names))
    # filterable tools advertise a `raw` opt-out in their schema + a filterable meta flag
    tl2 = {t["name"]: t for t in mcp_tool_list()}
    check("filterable tool exposes raw param", "raw" in tl2["nmap_scan"]["inputSchema"]["properties"])
    check("filterable tool flagged in meta", tl2["nmap_scan"]["_meta"]["filterable"] is True)
    check("agent-output tool not filtered", tl2["run_command"]["_meta"]["filterable"] is False)

    # global concurrency cap: tool subprocesses run under a shared limiter so several users can't
    # swamp the one container with parallel scans. _limiter() yields an async context manager.
    from kali_server.tools import _common
    check("kali parallel cap configured", isinstance(_common._MAX_PARALLEL, int))
    cm = _common._limiter()
    check("kali limiter is an async context manager", hasattr(cm, "__aenter__") and hasattr(cm, "__aexit__"))


def main() -> int:
    print("== SPAIDER smoke test ==")
    print("- config & roles");      test_config_and_roles()
    print("- tools categorised");   test_tools_categorised()
    print("- approval policy");     test_approval_policy()
    print("- .env loader");         test_env_loader()
    print("- disclaimer flag");     test_disclaimer_flag()
    print("- llm test + proxies");  test_connection_test_and_proxies()
    print("- poc execution policy"); test_poc_execution_policy()
    print("- reference documents"); test_reference_documents()
    print("- report docx/template"); test_report_docx_and_template()
    print("- reporter dedup dossier"); asyncio.run(test_reporter_dedup_dossier())
    print("- auth & isolation");    asyncio.run(test_auth_and_isolation())
    print("- kali server");         test_kali_server()
    print("- plan approval flow");  asyncio.run(test_plan_approval_flow())
    print("- end-to-end (mock)");   asyncio.run(test_end_to_end())
    print("- validation & raw");    asyncio.run(test_validation_and_raw_events())
    print("- turn-budget handoff");  asyncio.run(test_turn_budget_handoff())
    print("- orchestrator not summarized"); asyncio.run(test_orchestrator_not_summarized_on_exhaustion())
    print("- max_turns live + budget preserved"); asyncio.run(test_max_turns_live_and_budget_preserved())
    print("- re-engage after stop"); asyncio.run(test_reengage_after_stop())
    print(f"\n== {_passed}/{_passed + _failed} checks passed ==")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
