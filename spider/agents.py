"""Agent runtime: the tool-using agentic loop, with approval gating, cost
accounting, streaming, and inter-agent messaging."""
from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

from .events import E, bus
from .llm import BaseProvider, LLMError, Usage, format_llm_error, make_provider
from .tools.base import Tool, ToolError

if TYPE_CHECKING:
    from .session import Session

# How many times to nudge an agent that ended a turn without calling `finish` before we let
# its loop end anyway (avoids burning tokens if the model refuses to call finish).
MAX_FINISH_NUDGES = 2


class Agent:
    def __init__(
        self,
        session: "Session",
        role: str,
        name: str,
        system_prompt: str,
        tools: dict[str, Tool],
        model_config: dict[str, Any],
        task: str,
        parent: "Agent | None" = None,
    ) -> None:
        self.session = session
        self.id = "a_" + uuid.uuid4().hex[:8]
        self.role = role
        self.name = name
        self.system_prompt = system_prompt
        self.tools = tools
        self.model_config = model_config
        self.task = task
        self.parent_id = parent.id if parent else None
        self.depth = (parent.depth + 1) if parent else 0
        # MCP servers (mcpo defs) inherited from this agent's folder + all ancestors'.
        self.mcp_server_defs: dict[str, dict] = {}

        self.messages: list[dict] = []
        self.status = "idle"
        self.result: str = ""
        self.usage = Usage()
        self.cost_usd = 0.0

        self._finished = False
        # Parent-validation handshake: a spawned sub-agent that calls finish is held in
        # "waiting_validation" until its parent accepts it (then _validated=True, status done).
        # The root (orchestrator) needs no validation. Helper agents (summarizer / tool_selector)
        # are transient internal workers — nobody ever calls `validate_agent` on them, so they must
        # NOT require validation or they'd sit in "waiting_validation" forever. The reporting agent
        # is the final deliverable writer (launched by generate_report, not reviewed by a parent), so
        # it auto-completes to `done` too instead of parking in "waiting_validation".
        self._validated = parent is None or role in ("summarizer", "tool_selector", "reporting")
        self._finish_nudges = 0           # times we've nudged this agent to call finish
        self._stop = asyncio.Event()
        self.inbox: "asyncio.Queue[str]" = asyncio.Queue()
        self.is_running = False
        self._turns = 0
        # Set once this agent has been summarized on hitting its turn budget, so re-engaging an
        # already-exhausted agent (which keeps its spent budget) doesn't spawn a SECOND summarizer
        # for the same exhaustion. Cleared by run_followup only if the budget was actually raised.
        self._exhausted = False
        self._provider: BaseProvider | None = None
        self.last_input_tokens = 0  # size of the last prompt actually sent
        self._compacting = False
        self._memory_recorded = False

        # Tool-selection (used only when this agent is a tool_selector).
        self.selected_tools: list[str] | None = None
        self.selection_candidates: set[str] = set()
        self.selection_budget: int = 0
        # On-demand skills this agent may load at runtime, and which it already loaded.
        self.loadable_skills: set[str] = set()
        self.loaded_skills: set[str] = set()

    # ---- public controls ----
    def finish(self, summary: str) -> None:
        """Flag the agent as done (its loop will exit) and store ``summary`` as the result.
        Called by the `finish` tool; the summary becomes this role's shared memory."""
        self._finished = True
        if summary:
            self.result = summary

    def stop(self) -> None:
        """Request cooperative cancellation; the loop checks ``stopped`` between turns."""
        self._stop.set()

    def mark_validated(self) -> None:
        """Parent accepted this sub-agent's result: close it for good (status done) and record
        its shared-role memory. Called by the `validate_agent` tool. Idempotent."""
        self._validated = True
        if self._memory_recorded:
            return
        if self.status in ("waiting_validation", "done"):
            self._set_status("done")
            self._memory_recorded = True
            try:
                self.session.record_agent_memory(self)
            except Exception:  # noqa: BLE001 — memory is best-effort
                pass
            asyncio.create_task(self.session.persist_agent(self))

    @property
    def awaiting_validation(self) -> bool:
        return self.status == "waiting_validation" and not self._validated

    def deliver(self, content: str, sender: str) -> None:
        """Drop a message into this agent's inbox; it's read in at the top of the next
        loop turn (or when the agent is re-activated via run_followup)."""
        self.inbox.put_nowait(f"[Message from {sender}]: {content}")

    @property
    def stopped(self) -> bool:
        """True once stop() has been called (the loop uses this to break out)."""
        return self._stop.is_set()

    # ---- event helpers ----
    def _set_status(self, status: str) -> None:
        """Update the agent's status and broadcast an agent.status event to the UI. The payload
        carries the live turn budget (`turns` used so far / `max_turns`) so the UI can show how
        many rounds are LEFT for this agent — a "round" is one query sent to the LLM (self._turns
        increments once per LLM call in _loop). _set_status fires several times per turn, so the
        counter updates live."""
        self.status = status
        bus.emit(E.AGENT_STATUS, self.session.id, {
            "status": status, "role": self.role, "name": self.name,
            "turns": self._turns, "max_turns": self._max_turns(),
        }, agent_id=self.id)

    def _emit_message(self, role: str, content: Any) -> None:
        """Emit a chat message event AND persist it to the DB so the discussion feed
        survives a restart (the WebSocket only streams live; history loads from the DB)."""
        bus.emit(E.AGENT_MESSAGE, self.session.id, {"role": role, "content": content}, agent_id=self.id)
        asyncio.create_task(self.session.db.add_message(self.session.id, self.id, role, content))

    def _emit_raw(self, resp) -> None:
        """Emit + persist the complete raw LLM output of one turn (reasoning, answer text, the
        tool_use blocks with full input, and the stop_reason) for the raw debug view. This is the
        unfiltered record used to tell a wrong/empty answer apart from a timeout/error."""
        payload = {
            "thinking": (resp.thinking or "")[:20000],
            "text": resp.text or "",
            "blocks": resp.raw_content or [],
            "stop_reason": resp.stop_reason,
            "tool_calls": [{"name": c["name"], "input": c.get("input", {})} for c in resp.tool_calls],
        }
        bus.emit(E.AGENT_RAW, self.session.id, payload, agent_id=self.id)
        asyncio.create_task(self.session.db.add_message(self.session.id, self.id, "assistant_raw", payload))

    # ---- lifecycle ----
    async def run(self) -> str:
        """Entry point for a freshly spawned agent: seed the transcript with the task
        message, then run the tool-using loop until completion. Returns the result string."""
        self.messages.append({"role": "user", "content": [{"type": "text", "text": self.task}]})
        self._emit_message("user", self.task)
        return await self._loop()

    def _max_turns(self) -> int:
        """The turn budget for this agent's role, read LIVE from the session's CURRENT config
        rather than the snapshot taken when the agent was created. This means raising `max_turns`
        in Settings takes effect on the next run/continue, instead of being frozen at the value
        that was configured when the session (or agent) was first created. Falls back to the
        creation snapshot, then 40."""
        role_cfg = (self.session.cfg.get("models", {}) or {}).get(self.role) or {}
        return int(role_cfg.get("max_turns") or self.model_config.get("max_turns", 40))

    async def run_followup(self) -> str:
        # Re-activate an idle / finished / exhausted / STOPPED agent (operator re-engagement, a
        # parent send-back, or an ask_parent/message reply). Clear the stop flag — otherwise a
        # previously-stopped agent's loop would break out immediately on the `if self.stopped`
        # check and the operator could never resume a conversation with it. New inbox message(s)
        # are drained at the top of the loop.
        #
        # The turn budget (self._turns) is PRESERVED across every re-activation: it is a per-session
        # limit, and re-engaging (stop/resume, send-back, or an operator "continue") is not a way to
        # win a fresh budget. The budget itself (max_turns) is read LIVE from the session config in
        # _loop, so raising it in Settings takes effect on the next run/continue.
        self._stop.clear()
        self._finished = False
        self._finish_nudges = 0
        # A restarted (finished/stopped) agent should run on the CURRENT config, not the snapshot it
        # was created with: refresh the session's config from disk, then rebuild this agent's own
        # model_config (model/params/proxy) from it and drop the cached provider so it's recreated
        # with the new settings on the next LLM call.
        self.session.reload_config()
        self.model_config = self.session.build_model_config(self.role)
        self._provider = None
        # If the budget was RAISED in Settings since this agent exhausted, there are rounds to run
        # again — allow a future genuine exhaustion to summarize. If the budget is still spent,
        # keep `_exhausted` set so the loop's else-branch won't summarize this same exhaustion a
        # second time (re-engaging never grants a fresh budget).
        if self._turns < self._max_turns():
            self._exhausted = False
        return await self._loop()

    def _drain_inbox(self) -> None:
        """Move any pending inter-agent / operator messages from the inbox into the
        transcript as user turns, so the model sees them on the next iteration."""
        incoming: list[str] = []
        while not self.inbox.empty():
            try:
                incoming.append(self.inbox.get_nowait())
            except asyncio.QueueEmpty:
                break
        for msg in incoming:
            self.messages.append({"role": "user", "content": [{"type": "text", "text": msg}]})
            self._emit_message("user", msg)

    async def _loop(self) -> str:
        """The core agentic loop. Each turn: drain inbox -> maybe compact context ->
        call the LLM (streaming tokens) -> account token usage/cost -> execute any tool
        calls and feed results back. Exits on `finish`, a turn with no tool calls, the
        max-turns budget, a stop request, or an error. On completion it records this
        agent's result as shared role memory and persists the agent row."""
        self.is_running = True
        self._set_status("running")
        if self._provider is None:
            try:
                self._provider = make_provider(self.model_config)
            except Exception as e:  # noqa: BLE001
                self._fail(f"Provider init failed: {e}")
                return self.result
        max_turns = self._max_turns()

        try:
            while self._turns < max_turns:
                if self.stopped:
                    self._set_status("stopped")
                    self.result = self.result or "Stopped by operator."
                    break
                self._turns += 1
                self._drain_inbox()
                await self._maybe_compact()

                tool_schemas = [t.schema() for t in self.tools.values()]
                async def on_token(text: str, kind: str = "text") -> None:
                    # kind: "text" (answer) or "thinking" (reasoning). The raw view shows both;
                    # the filtered chat's streaming line ignores "thinking".
                    if text:
                        bus.emit(E.AGENT_TOKEN, self.session.id, {"text": text, "kind": kind}, agent_id=self.id)

                # "awaiting LLM": the model is generating. If the run stalls here, this status
                # (vs waiting_subagent / waiting_validation) tells the operator it's the LLM call.
                self._set_status("waiting_llm")
                try:
                    resp = await self._provider.complete(
                        self.system_prompt, self.messages, tool_schemas, on_token
                    )
                except (LLMError, Exception) as e:  # noqa: BLE001
                    # Surface the COMPLETE error in chat (status + provider response body +
                    # traceback), not just the exception string, so the operator sees the full
                    # "answer back" from the provider and can debug it from the conversation.
                    self._fail("LLM call failed.", detail=format_llm_error(e))
                    break
                self._set_status("running")
                # Emit + persist the FULL raw output of this turn for the raw debug view.
                self._emit_raw(resp)

                # ---- TOKEN USAGE & COST ACCOUNTING (per LLM turn) ----
                # `resp.usage` (input/output/cache tokens) is reported by the provider in
                # llm.py (AnthropicProvider/OpenAIProvider populate the `Usage` object from
                # the API response). Here we:
                #   1. add it to this agent's running total (self.usage);
                #   2. convert tokens -> USD and roll it into the session totals
                #      (Session.add_cost in session.py, priced from cfg["pricing"]);
                #   3. remember the size of the last prompt (input + both cache buckets) so
                #      _maybe_compact() can decide when to summarise an over-budget context.
                self.usage.add(resp.usage)
                self.session.add_cost(self, resp.usage)
                self.last_input_tokens = (
                    resp.usage.input_tokens + resp.usage.cache_read + resp.usage.cache_write
                )
                if resp.raw_content:
                    self.messages.append({"role": "assistant", "content": resp.raw_content})
                if resp.text:
                    self._emit_message("assistant", resp.text)

                if not resp.tool_calls:
                    # The model ended a turn without calling any tool. If it already called
                    # `finish`, we're done. Otherwise it stopped WITHOUT the finishing word — so
                    # ask it (up to MAX_FINISH_NUDGES times) whether it's actually finished:
                    # if yes it must call `finish`; if no it should keep working. This stops
                    # agents silently ending mid-analysis.
                    if self._finished:
                        break
                    # If this agent submitted a plan that is still awaiting the operator, an idle
                    # turn means "I'm waiting for approval" — that is NOT an unfinished conversation.
                    # Block on the operator's decision and feed it back, instead of nudging to finish.
                    pending_decision = await self.session.await_plan_decision_for(self)
                    if pending_decision is not None:
                        self.messages.append({"role": "user", "content": [{"type": "text", "text": pending_decision}]})
                        self._emit_message("user", pending_decision)
                        continue
                    if self._finish_nudges < MAX_FINISH_NUDGES:
                        self._finish_nudges += 1
                        if self.parent_id is None and self.role == "orchestrator":
                            # The orchestrator drives the whole engagement, so an idle turn is almost
                            # never "finished". Plan approval is SYNCHRONOUS (`update_plan` blocks and
                            # returns the operator's decision), so it must not sit idle "waiting for
                            # approval" — steer it to act, and only finish when the engagement is done.
                            nudge = (
                                "You ended your turn without taking an action. Do NOT stop here unless "
                                "the ENTIRE engagement is genuinely complete (all plan steps done and "
                                "findings reported) — only then call `finish`.\n"
                                "- Plan approval is synchronous: `update_plan` blocks and RETURNS the "
                                "operator's decision, so never idle 'waiting for approval'. If you have "
                                "not actually submitted a plan yet, call `update_plan` now; once it is "
                                "approved, proceed.\n"
                                "- Otherwise continue the engagement: delegate the next plan step to a "
                                "specialist agent, or call `ask_user` if you need an operator decision."
                            )
                        else:
                            has_ask_user = "ask_user" in self.tools
                            ask_clause = (
                                " If you stopped because you need a decision, missing information, a "
                                "credential, or extra scope that only the human operator can give, call "
                                "`ask_user` with a specific question — it will alert the operator and "
                                "return their answer."
                                if has_ask_user else
                                " If you need a human decision or extra scope, use `ask_parent` to "
                                "escalate to the agent that spawned you."
                            )
                            nudge = (
                                "You ended your turn without calling any tool and without calling "
                                "`finish`. Decide how to proceed: (1) if your assigned task is genuinely "
                                "COMPLETE, call `finish` now with a concise summary and the evidence; "
                                "(2) if it is NOT complete, continue the work by calling the appropriate "
                                "tools — do not stop here." + ask_clause
                            )
                        self.messages.append({"role": "user", "content": [{"type": "text", "text": nudge}]})
                        self._emit_message("user", nudge)
                        continue
                    # Still no finish after nudging -> end, keeping whatever text we have.
                    if resp.text:
                        self.result = self.result or resp.text
                    break

                # Execute tool calls, collect results for the next user turn.
                tool_results = []
                for call in resp.tool_calls:
                    if self.stopped:
                        break
                    result_content, is_error = await self._exec_tool(call)
                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": call["id"],
                            "content": result_content,
                            "is_error": is_error,
                        }
                    )
                if tool_results:
                    self.messages.append({"role": "user", "content": tool_results})

                if self._finished:
                    break
            else:
                # Hit the turn budget without calling `finish`. Don't lose the work: have a
                # summarizer distil this agent's transcript into a HANDOFF (findings + state +
                # what remains) and use that as the result, so its findings still reach the parent
                # and the shared/master memory.
                if self._exhausted:
                    # Already summarized on a PRIOR pass: the budget was spent, a summarizer ran,
                    # and the agent was then re-engaged (operator "continue" / a parent send-back)
                    # WITHOUT the budget being raised — so the loop body never ran and we landed
                    # here again immediately. Re-engaging never grants a fresh budget, so don't
                    # spawn a SECOND summarizer for the same exhaustion (the bug where the
                    # summarizer kicked in twice for one exhausted agent); keep the existing result.
                    self.result = self.result or "Reached maximum turn budget (no rounds remaining)."
                elif self.role in ("orchestrator", "summarizer", "tool_selector"):
                    # NOT summarized: the orchestrator is the root coordinator (no parent to hand a
                    # summary to — summarizing it is pointless and just spawns a stray agent), and the
                    # helper agents (summarizer / tool_selector) carry no findings and would recurse.
                    # They simply stop at the budget with their current result; the operator can ask
                    # them to continue, which grants a fresh allowance (see run_followup).
                    self._exhausted = True
                    self.result = self.result or "Reached maximum turn budget."
                else:
                    self._exhausted = True
                    self.result = await self._summarize_on_exhaustion(max_turns)
                    # A turn-budget close is an INVOLUNTARY close, not a deliberate `finish`. Don't
                    # park the sub-agent in 'waiting_validation' (a parent that never validates would
                    # leave it stuck forever with its memory unrecorded): close it done + auto-
                    # accepted. The handoff summary is its result and reaches the parent the same way
                    # a finish does. The operator/parent can still re-engage it (run_followup), which
                    # grants a fresh budget so it can do more work.
                    self._finished = True
                    self._validated = True

            if self.status not in ("error", "stopped"):
                # A spawned sub-agent that finished is held for its parent to validate before it
                # closes for good (mandatory). Until accepted it sits in "waiting_validation".
                if self._finished and not self._validated:
                    self._set_status("waiting_validation")
                else:
                    self._set_status("done")
        finally:
            self.is_running = False
            # Leave shared memory for future agents of this role — but only once the work is
            # actually closed (done / stopped), NOT while still awaiting parent validation.
            if not self._memory_recorded and self.status in ("done", "stopped"):
                self._memory_recorded = True
                try:
                    self.session.record_agent_memory(self)
                except Exception:  # noqa: BLE001 — memory is best-effort
                    pass
            await self.session.persist_agent(self)
        return self.result

    def _persist_feed(self, role: str, content: Any) -> None:
        """Durably record a feed item (tool call/result, narration) so the discussion
        can be reconstructed after a restart, not just replayed from the in-memory bus."""
        asyncio.create_task(self.session.db.add_message(self.session.id, self.id, role, content))

    def _emit_tool_result(self, name: str, result: str, is_error: bool) -> None:
        """Broadcast a tool.result event (clipped) and persist it to the feed."""
        payload = {"tool": name, "result": result[:4000], "is_error": is_error}
        bus.emit(E.TOOL_RESULT, self.session.id, payload, agent_id=self.id)
        self._persist_feed("tool_result", payload)

    async def _exec_tool(self, call: dict) -> tuple[str, bool]:
        """Dispatch a single tool call: look up the tool, gate command-exec tools through
        the operator-approval flow when in manual mode, run the handler, and emit/persist
        the call + result. Returns ``(result_text, is_error)`` for the model's next turn."""
        name = call["name"]
        args = call.get("input", {}) or {}
        tool = self.tools.get(name)
        bus.emit(E.TOOL_CALL, self.session.id, {"tool": name, "input": args}, agent_id=self.id)
        self._persist_feed("tool_call", {"tool": name, "input": args})
        if tool is None:
            msg = f"Unknown tool: {name}"
            self._emit_tool_result(name, msg, True)
            return msg, True

        # Human-in-the-loop tool gating. The decision is resolved by the session against the
        # customisable tool-approval policy (per category / per tool name) plus any hard floor
        # (tool.requires_approval). When it returns True the agent pauses for operator sign-off.
        if self.session.tool_needs_approval(tool, args):
            self._set_status("waiting_approval")
            approved, reason = await self.session.request_approval(self, tool, args)
            self._set_status("running")
            if not approved:
                msg = f"Operator denied execution of {name}: {reason or 'no reason given'}"
                self._emit_tool_result(name, msg, True)
                return msg, True

        try:
            result = await tool.handler(self, args)
            is_error = False
        except ToolError as e:
            result, is_error = f"Error: {e}", True
        except Exception as e:  # noqa: BLE001
            result, is_error = f"Unexpected tool error: {e}", True

        self._emit_tool_result(name, result, is_error)
        return result, is_error

    async def _summarize_on_exhaustion(self, max_turns: int) -> str:
        """Called when this agent hits its turn budget without finishing: spawn a summarizer to
        distil its transcript into a findings handoff so the work isn't lost, and return a
        clearly-labelled result. Falls back to whatever result/text exists if summarizing fails."""
        self._set_status("summarizing")
        bus.emit(E.LOG, self.session.id, {"level": "warn", "message": (
            f"{self.name} reached its turn budget ({max_turns}) without finishing — "
            f"summarizing its findings for handoff so they aren't lost.")}, agent_id=self.id)
        summary = ""
        try:
            summary = await self.session.handoff_summary_for(self, self._render_transcript())
        except Exception:  # noqa: BLE001 — handoff summary is best-effort
            summary = ""
        header = (f"[REACHED MAX TURN BUDGET of {max_turns} turns before calling finish — the "
                  f"following is a summary of this agent's findings and state so they are not lost]")
        body = summary or (self.result or "").strip() or "(no findings were captured before the budget ran out)"
        note = header + "\n\n" + body
        self._emit_message("assistant", note)
        return note

    # --------------------------------------------------- context compaction
    async def _maybe_compact(self) -> None:
        """If the last prompt exceeded the configured context budget, have a
        summarizer agent compress this agent's transcript and continue from it."""
        if self.role == "summarizer" or self._compacting:
            return  # never compact the summarizer itself
        threshold = getattr(self.session, "max_context_tokens", 0)
        if not threshold or self.last_input_tokens < threshold:
            return
        if len(self.messages) <= 1:
            return
        self._compacting = True
        prev_status = self.status
        self._set_status("summarizing")
        try:
            transcript = self._render_transcript()
            summary = await self.session.summarize_for(self, transcript)
            self.messages = [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                f"{self.task}\n\n[COMPRESSED CONTEXT — your earlier work was "
                                f"summarized to stay within the context budget; continue from here]\n\n"
                                f"{summary}"
                            ),
                        }
                    ],
                }
            ]
            self.last_input_tokens = 0
            bus.emit(
                E.COMPACTION,
                self.session.id,
                {"role": self.role, "name": self.name, "summary_chars": len(summary)},
                agent_id=self.id,
            )
        except Exception as e:  # noqa: BLE001 — compaction is best-effort
            bus.emit(E.LOG, self.session.id, {"level": "warn", "message": f"compaction failed: {e}"}, agent_id=self.id)
        finally:
            self._compacting = False
            self._set_status(prev_status if prev_status in ("running",) else "running")

    def _render_transcript(self) -> str:
        """Flatten the conversation into text for the summarizer."""
        lines: list[str] = []
        for m in self.messages:
            role = m["role"]
            content = m["content"]
            if isinstance(content, str):
                lines.append(f"[{role}] {content}")
                continue
            for b in content:
                t = b.get("type")
                if t == "text":
                    lines.append(f"[{role}] {b.get('text', '')}")
                elif t == "tool_use":
                    lines.append(f"[{role} tool_call] {b.get('name')}({b.get('input')})")
                elif t == "tool_result":
                    flag = " ERROR" if b.get("is_error") else ""
                    lines.append(f"[{role} tool_result{flag}] {b.get('content', '')}")
        return "\n".join(lines)

    def _fail(self, message: str, detail: str | None = None) -> None:
        """Mark the agent errored, store the message as its result, and emit an error event.
        When `detail` is given (e.g. the FULL LLM error: HTTP status + the provider's response
        body + traceback), the complete text is surfaced — the error event carries the whole
        thing so it renders in the chat feed, not just a truncated toast, so the operator can
        debug an LLM failure straight from the conversation."""
        full = message if not detail else f"{message}\n\n{detail}"
        self.result = full
        self._set_status("error")
        bus.emit(E.ERROR, self.session.id, {"message": full}, agent_id=self.id)
