"""In-process async event bus used to push live updates to the UI (over WebSocket)
and to coordinate between components."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any


# Event type constants (documentation / avoid typos).
class E:
    SESSION_STATUS = "session.status"
    SESSION_RENAMED = "session.renamed"   # the operator renamed the session (live title update)
    PLAN_UPDATE = "plan.update"
    STEP_UPDATE = "plan.step"
    # Human-in-the-loop plan sign-off: the orchestrator proposed a plan and is waiting for
    # the operator to approve / reject (with feedback) / edit it before work proceeds.
    PLAN_APPROVAL_REQUEST = "plan.approval_request"
    PLAN_APPROVAL_RESOLVED = "plan.approval_resolved"
    # The operator injected a message / new direction mid-engagement.
    OPERATOR_INTERJECTION = "operator.interjection"
    # The session-wide tool intensity was changed by the operator.
    INTENSITY_CHANGED = "intensity.changed"
    # The operator toggled the per-session approval mode (manual policy <-> auto/bypass) mid-run.
    APPROVAL_MODE_CHANGED = "approval.mode_changed"
    # A running Kali process (command/tool) was killed (by the operator or on session stop).
    KALI_PROCESS_KILLED = "kali.process_killed"
    AGENT_CREATED = "agent.created"
    AGENT_STATUS = "agent.status"
    AGENT_TOKEN = "agent.token"          # streamed text delta
    AGENT_MESSAGE = "agent.message"      # a full assistant/user/system message (filtered chat)
    AGENT_RAW = "agent.raw"              # the FULL raw LLM output of one turn (thinking + text +
                                         # tool_use + stop_reason) for the raw debug view
    AGENT_NARRATION = "agent.narration"  # orchestrator's plain-language progress update to the operator
    AGENT_SKILL_LOADED = "agent.skill_loaded"  # an agent loaded a skill (static at start or on demand)
    AGENT_MEMORY_LOADED = "agent.memory_loaded"  # an agent started with shared memory injected
    AGENT_THINKING = "agent.thinking"
    TOOL_CALL = "tool.call"
    TOOL_RESULT = "tool.result"
    APPROVAL_REQUEST = "approval.request"
    APPROVAL_RESOLVED = "approval.resolved"
    USER_REQUEST = "user.request"            # agent asks operator for input (e.g. load a file)
    USER_REQUEST_RESOLVED = "user.request_resolved"
    FINDING = "finding.stored"
    COST_UPDATE = "cost.update"
    COMPACTION = "context.compacted"
    LOG = "log"
    ERROR = "error"


@dataclass
class Event:
    type: str
    session_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    ts: float = field(default_factory=time.time)
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "ts": self.ts,
            "seq": self.seq,
            "payload": self.payload,
        }


class EventBus:
    """Per-process pub/sub. Subscribers receive every event; filtering by session
    happens on the consumer side (the WebSocket layer)."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._seq = 0
        self._history: list[Event] = []
        self._history_limit = 2000

    def subscribe(self) -> asyncio.Queue[Event]:
        """Register a new consumer and return its queue. Each WebSocket connection and the
        per-session log writer call this; always pair with unsubscribe() in a finally block."""
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=10000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        """Drop a consumer's queue so it stops receiving events."""
        self._subscribers.discard(q)

    def history(self, session_id: str) -> list[Event]:
        """Return the bounded in-memory event history for one session (recent events only)."""
        return [e for e in self._history if e.session_id == session_id]

    def emit(
        self,
        type: str,
        session_id: str,
        payload: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> Event:
        """Create an Event (auto-incrementing seq), store it in the bounded history, and
        fan it out to every subscriber's queue (dropping silently if a queue is full). This
        is the one function every part of the engine calls to surface something to the UI/log."""
        self._seq += 1
        ev = Event(
            type=type,
            session_id=session_id,
            payload=payload or {},
            agent_id=agent_id,
            seq=self._seq,
        )
        self._history.append(ev)
        if len(self._history) > self._history_limit:
            self._history = self._history[-self._history_limit :]
        for q in list(self._subscribers):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass
        return ev


# Global bus instance shared across the application.
bus = EventBus()
