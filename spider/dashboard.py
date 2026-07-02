"""Static (no-LLM) analytics for a session's dashboard.

``compute(session)`` derives all the numbers the dashboard shows — a cost/token TIME SERIES plus
aggregate breakdowns — from the session's persisted event log (``workspaces/<sid>/logs/events.jsonl``)
rather than live memory, so it is correct for a running session AND for one reopened long after it
finished. It is pure computation (no agents, no model calls); the browser turns the result into
colored charts and, on demand, a self-contained HTML report + a CSV/JSON data bundle.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

# Severity buckets shown (in order, most→least severe). Anything else lands in "other".
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _read_events(session) -> list[dict]:
    """Load the session's event log (one JSON object per line). Never raises — a missing or
    partially-written log just yields the events that are readable."""
    path = Path(session.workspace) / "logs" / "events.jsonl"
    out: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except (ValueError, TypeError):
                    continue
    except OSError:
        return []
    return out


def compute(session) -> dict[str, Any]:
    """Build the dashboard payload for one session. Everything is derived from the event log, with
    the in-memory session used only as a fallback (e.g. no log yet) and for display metadata."""
    events = _read_events(session)

    # ---- cost / token TIME SERIES (one point per cost.update = one LLM turn) ------------------
    series: list[dict] = []
    final_cost: dict | None = None
    t0: float | None = None
    for ev in events:
        if ev.get("type") != "cost.update":
            continue
        c = (ev.get("payload") or {}).get("cost") or {}
        ts = float(ev.get("ts") or 0)
        if t0 is None:
            t0 = ts
        series.append({
            "t": ts,
            "elapsed_s": round(ts - t0, 3) if t0 else 0.0,
            "total_usd": float(c.get("total_usd", 0) or 0),
            "input_tokens": int(c.get("input_tokens", 0) or 0),
            "output_tokens": int(c.get("output_tokens", 0) or 0),
            "cache_read": int(c.get("cache_read", 0) or 0),
            "cache_write": int(c.get("cache_write", 0) or 0),
        })
        final_cost = c
    # Fall back to the live snapshot if the log had no cost events yet.
    cost = final_cost or (getattr(session, "cost", None) or {})

    by_agent = sorted(
        ({
            "name": v.get("name", ""), "role": v.get("role", ""), "model": v.get("model", ""),
            "usd": float(v.get("usd", 0) or 0), "input": int(v.get("input", 0) or 0),
            "output": int(v.get("output", 0) or 0),
        } for v in (cost.get("by_agent") or {}).values()),
        key=lambda r: -r["usd"],
    )
    by_model = sorted(
        ({
            "model": m or "(unknown)", "usd": float(v.get("usd", 0) or 0),
            "input": int(v.get("input", 0) or 0), "output": int(v.get("output", 0) or 0),
        } for m, v in (cost.get("by_model") or {}).items()),
        key=lambda r: -r["usd"],
    )

    # ---- findings (prefer the log; fall back to live) -----------------------------------------
    findings: dict[str, dict] = {}
    for ev in events:
        if ev.get("type") == "finding.stored":
            f = (ev.get("payload") or {}).get("finding") or {}
            if f.get("id"):
                findings[f["id"]] = f
    if not findings and getattr(session, "findings", None):
        findings = dict(session.findings)
    by_sev = {s: 0 for s in SEVERITIES}
    by_sev["other"] = 0
    by_status: dict[str, int] = {}
    for f in findings.values():
        sev = str(f.get("severity") or "").strip().lower()
        by_sev[sev if sev in by_sev else "other"] += 1
        st = str(f.get("status") or "unknown").strip().lower()
        by_status[st] = by_status.get(st, 0) + 1

    # ---- tool usage + agent spawns ------------------------------------------------------------
    tools: dict[str, int] = {}
    agents_by_role: dict[str, int] = {}
    for ev in events:
        t = ev.get("type")
        if t == "tool.call":
            name = (ev.get("payload") or {}).get("tool") or "?"
            tools[name] = tools.get(name, 0) + 1
        elif t == "agent.created":
            role = (ev.get("payload") or {}).get("role") or "?"
            agents_by_role[role] = agents_by_role.get(role, 0) + 1
    tools_list = sorted(({"tool": k, "count": v} for k, v in tools.items()), key=lambda r: -r["count"])

    # ---- duration (span of the whole event stream) --------------------------------------------
    ts_all = [float(ev.get("ts")) for ev in events if ev.get("ts")]
    duration = (max(ts_all) - min(ts_all)) if ts_all else 0.0

    agents_total = sum(agents_by_role.values()) or len(getattr(session, "agents", {}) or {})

    return {
        "session": {
            "id": getattr(session, "id", ""),
            "name": getattr(session, "name", ""),
            "target": getattr(session, "target", ""),
            "status": getattr(session, "status", ""),
        },
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "totals": {
            "total_usd": float(cost.get("total_usd", 0) or 0),
            "input_tokens": int(cost.get("input_tokens", 0) or 0),
            "output_tokens": int(cost.get("output_tokens", 0) or 0),
            "cache_read": int(cost.get("cache_read", 0) or 0),
            "cache_write": int(cost.get("cache_write", 0) or 0),
            "agents": agents_total,
            "findings": len(findings),
            "tool_calls": sum(tools.values()),
            "llm_calls": len(series),
            "duration_s": round(duration, 1),
        },
        "series": series,
        "by_agent": by_agent,
        "by_model": by_model,
        "agents_by_role": agents_by_role,
        "findings_by_severity": by_sev,
        "findings_by_status": by_status,
        "tools": tools_list,
    }
