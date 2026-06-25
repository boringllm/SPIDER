"""LLM provider abstraction.

Supports Anthropic-compatible and OpenAI-compatible endpoints (configurable
base_url + api_key per agent), plus a Mock provider used for offline testing.

A provider-neutral message format is used internally:

    message = {"role": "user"|"assistant", "content": [block, ...]}
    block (assistant): {"type": "text", "text": str}
                       {"type": "tool_use", "id": str, "name": str, "input": dict}
    block (user):      {"type": "text", "text": str}
                       {"type": "tool_result", "tool_use_id": str,
                        "content": str, "is_error": bool}

Each provider converts to/from its own wire format.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

# Streaming callback receives output deltas as they arrive. The second arg is the delta
# KIND: "text" (the model's answer) or "thinking" (its reasoning, when thinking is enabled).
# The raw live-stream view shows both; the filtered chat shows only "text".
TokenCB = Callable[..., Awaitable[None]]


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0

    def add(self, other: "Usage") -> None:
        """Accumulate another turn's token counts into this running total (in place)."""
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read += other.cache_read
        self.cache_write += other.cache_write


@dataclass
class LLMResponse:
    text: str = ""
    tool_calls: list[dict] = field(default_factory=list)  # [{id,name,input}]
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = "end_turn"
    # assistant blocks in the neutral format, kept API-valid (text + tool_use only) so they can
    # be appended to the transcript and sent back. Thinking is captured separately because bare
    # thinking blocks can't be replayed to the API without a signature.
    raw_content: list[dict] = field(default_factory=list)
    thinking: str = ""  # the model's reasoning text this turn (when thinking is enabled)


class LLMError(Exception):
    pass


def model_caps(model: str) -> dict[str, bool]:
    """What request parameters a given Anthropic model accepts. Drives model-aware
    param building so we never send a parameter that would 400."""
    m = (model or "").lower()
    adaptive_only = any(k in m for k in ("opus-4-8", "opus-4-7", "fable-5"))
    family_46 = any(k in m for k in ("opus-4-6", "sonnet-4-6", "opus-4-5"))
    if adaptive_only:
        # adaptive thinking only; sampling params removed; effort incl. xhigh
        return {"adaptive": True, "budget": False, "sampling": False,
                "effort": True, "xhigh": True, "max": True, "display": True}
    if family_46:
        # adaptive (recommended) + legacy budget still works; sampling allowed; effort (no xhigh)
        return {"adaptive": True, "budget": True, "sampling": True,
                "effort": True, "xhigh": False, "max": True, "display": False}
    # Haiku 4.5 / Sonnet 4.5 / older: enabled+budget_tokens; no effort
    return {"adaptive": False, "budget": True, "sampling": True,
            "effort": False, "xhigh": False, "max": False, "display": False}


# Structural params that must never be renamed/dropped via overrides.
_PROTECTED_PARAMS = {
    "model", "messages", "system", "tools", "stream",
    "stream_options", "extra_body", "extra_headers", "extra_query",
}


def apply_param_overrides(params: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    """Rename or drop outgoing request parameters per the model's `param_overrides`
    map ``{internal_name: wire_name}``. This lets the user fix endpoint drift from the
    UI without code changes — e.g. mapping ``max_tokens -> max_completion_tokens`` for
    newer OpenAI models, or mapping a param to an empty string to drop it entirely.

    Renamed params are emitted via ``extra_body`` (supported by both the Anthropic and
    OpenAI SDKs and merged into the request body), so the new name reaches the endpoint
    even if the SDK has no typed keyword for it."""
    overrides = cfg.get("param_overrides") or {}
    if not overrides:
        return params
    extra = dict(params.get("extra_body") or {})
    for internal, wire in overrides.items():
        if internal in _PROTECTED_PARAMS or internal not in params:
            continue
        value = params.pop(internal)
        wire = (wire or "").strip()
        if wire:  # empty wire name => drop the parameter
            extra[wire] = value
    if extra:
        params["extra_body"] = extra
    return params


def _clean_header_value(value: str, label: str) -> str:
    """Sanitize a value that ends up in an HTTP header (api_key, base_url). Strips
    surrounding whitespace and common invisible paste artifacts, and raises a clear
    error if non-ASCII characters remain (HTTP headers must be ASCII). The usual cause
    is copying a masked secret field, which yields '•' (U+2022) mask glyphs."""
    if not value:
        return value
    cleaned = value.strip().translate({0x200b: None, 0xfeff: None, 0x00a0: None}).strip()
    if not cleaned.isascii():
        bad = sorted({hex(ord(c)) for c in cleaned if not c.isascii()})
        hint = ""
        if "•" in cleaned:
            hint = " It looks like the masked field (•••) was copied instead of the real value."
        raise LLMError(
            f"{label} contains non-ASCII characters {bad[:4]} and can't be sent in an HTTP "
            f"header.{hint} Re-enter it in Settings (use the 👁 reveal toggle to copy the real key)."
        )
    return cleaned


def _http_client(cfg: dict[str, Any]):
    """Build the ``httpx.AsyncClient`` the LLM SDK should use, when the model config needs custom
    transport — i.e. a CLIENT proxy and/or disabled TLS verification (``verify_ssl: false``).
    Returns None when neither applies, so the SDK uses its own default client.

    The proxy config travels in the model config under the reserved ``_client_proxy`` key (injected
    by ``Session.create_agent`` / the LLM-test endpoint). The proxy whitelist is implemented with
    httpx per-host ``mounts``: ``all://`` goes through the proxy, while each ``all://<host>`` is a
    direct transport — so localhost / the Kali host / etc. bypass the proxy. ``verify_ssl`` applies
    to whichever transport(s) are built."""
    cfg = cfg or {}
    proxy = cfg.get("_client_proxy") or {}
    use_proxy = bool(proxy.get("enabled") and str(proxy.get("url") or "").strip())
    verify = bool(cfg.get("verify_ssl", True))   # default: verify TLS
    if not use_proxy and verify:
        return None                              # nothing custom needed
    import httpx

    if use_proxy:
        url = _clean_header_value(str(proxy["url"]).strip(), "proxy URL")
        mounts: dict[str, Any] = {"all://": httpx.AsyncHTTPTransport(proxy=url, verify=verify)}
        for host in proxy.get("no_proxy") or []:
            h = str(host).strip()
            if h:
                mounts[f"all://{h}"] = httpx.AsyncHTTPTransport(verify=verify)  # direct, bypass proxy
        return httpx.AsyncClient(mounts=mounts)
    return httpx.AsyncClient(verify=verify)      # no proxy, just disabled TLS verification


def _apply_timeout_retries(kwargs: dict[str, Any], cfg: dict[str, Any]) -> None:
    """Pass the configured per-LLM-call timeout (seconds) and retry count to the SDK client."""
    to = cfg.get("request_timeout")
    if to:
        try:
            kwargs["timeout"] = float(to)
        except (TypeError, ValueError):
            pass
    mr = cfg.get("max_retries")
    if mr is not None:
        try:
            kwargs["max_retries"] = int(mr)
        except (TypeError, ValueError):
            pass


class BaseProvider:
    def __init__(self, model_config: dict[str, Any]) -> None:
        self.cfg = model_config
        self.model = model_config["model"]

    async def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict],
        on_token: TokenCB | None = None,
    ) -> LLMResponse:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Anthropic
# --------------------------------------------------------------------------- #
class AnthropicProvider(BaseProvider):
    def __init__(self, model_config: dict[str, Any]) -> None:
        super().__init__(model_config)
        import anthropic

        kwargs: dict[str, Any] = {}
        if model_config.get("api_key"):
            kwargs["api_key"] = _clean_header_value(model_config["api_key"], "API key")
        if model_config.get("base_url"):
            kwargs["base_url"] = _clean_header_value(model_config["base_url"], "base_url")
        _apply_timeout_retries(kwargs, model_config)
        hc = _http_client(model_config)
        if hc is not None:
            kwargs["http_client"] = hc          # client proxy and/or disabled TLS verification
        self.client = anthropic.AsyncAnthropic(**kwargs)

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        return [
            {"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
            for t in tools
        ]

    def _build_params(self, system, messages, tools) -> dict[str, Any]:
        """Assemble the Anthropic request kwargs in a model-aware way: only attach
        thinking/effort/sampling params the model actually accepts (see model_caps), then
        apply the user's param_overrides. Edit here to change how Anthropic calls are formed."""
        caps = model_caps(self.model)
        cfg = self.cfg
        max_tokens = int(cfg.get("max_tokens", 8000))
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            params["tools"] = self._tools(tools)

        mode = cfg.get("thinking", "off")
        if mode == "adaptive" and caps["adaptive"]:
            th: dict[str, Any] = {"type": "adaptive"}
            if caps["display"]:
                disp = cfg.get("thinking_display")
                if disp in ("omitted", "summarized"):
                    th["display"] = disp
            params["thinking"] = th
        elif mode == "enabled" and caps["budget"]:
            budget = int(cfg.get("thinking_budget", 8000) or 8000)
            budget = max(1024, min(budget, max_tokens - 1))
            params["thinking"] = {"type": "enabled", "budget_tokens": budget}

        eff = cfg.get("effort", "")
        if eff and caps["effort"]:
            if eff == "xhigh" and not caps["xhigh"]:
                eff = "high"
            if eff == "max" and not caps["max"]:
                eff = "high"
            params["output_config"] = {"effort": eff}

        # Sampling params only when thinking is off and the model accepts them
        # (thinking models pin sampling; adaptive-only models reject these outright).
        if caps["sampling"] and params.get("thinking") is None:
            for k in ("temperature", "top_p", "top_k"):
                v = cfg.get(k)
                if v is not None:
                    params[k] = v
        stop = cfg.get("stop")
        if stop:
            params["stop_sequences"] = stop
        return apply_param_overrides(params, cfg)

    async def complete(self, system, messages, tools, on_token=None) -> LLMResponse:
        params = self._build_params(system, messages, tools)

        async with self.client.messages.stream(**params) as stream:
            async for event in stream:
                if event.type != "content_block_delta":
                    continue
                dtype = getattr(event.delta, "type", "")
                # Stream both the answer text and (when thinking is on) the reasoning, tagged by
                # kind so the raw view can show thinking and the filtered view can ignore it.
                if dtype == "text_delta" and on_token:
                    await on_token(event.delta.text, "text")
                elif dtype == "thinking_delta" and on_token:
                    await on_token(getattr(event.delta, "thinking", "") or "", "thinking")
            final = await stream.get_final_message()

        blocks: list[dict] = []
        tool_calls: list[dict] = []
        text = ""
        thinking = ""
        for b in final.content:
            if b.type == "text":
                text += b.text
                blocks.append({"type": "text", "text": b.text})
            elif b.type == "thinking":
                # Kept OUT of `blocks` (can't replay to the API) but surfaced for the raw view.
                thinking += getattr(b, "thinking", "") or ""
            elif b.type == "redacted_thinking":
                thinking += "[redacted reasoning]"
            elif b.type == "tool_use":
                call = {"id": b.id, "name": b.name, "input": dict(b.input)}
                tool_calls.append(call)
                blocks.append({"type": "tool_use", **call})
        # TOKEN USAGE (source): read the per-call token counts off the Anthropic response
        # into our neutral Usage object. This is what later becomes cost in Session.add_cost.
        u = final.usage
        usage = Usage(
            input_tokens=getattr(u, "input_tokens", 0) or 0,
            output_tokens=getattr(u, "output_tokens", 0) or 0,
            cache_read=getattr(u, "cache_read_input_tokens", 0) or 0,
            cache_write=getattr(u, "cache_creation_input_tokens", 0) or 0,
        )
        return LLMResponse(
            text=text,
            tool_calls=tool_calls,
            usage=usage,
            stop_reason=final.stop_reason or "end_turn",
            raw_content=blocks,
            thinking=thinking,
        )


# --------------------------------------------------------------------------- #
# OpenAI-compatible
# --------------------------------------------------------------------------- #
def _delta_reasoning(delta: Any) -> str:
    """Pull the reasoning/chain-of-thought text off a streaming chat delta, for OpenAI-compatible
    reasoning models that expose it separately from `content`. Different vendors use different
    field names (`reasoning_content` — Moonshot Kimi / DeepSeek; `reasoning` — some others), and
    the SDK may surface them as typed attrs OR as pydantic extras, so we check both."""
    for attr in ("reasoning_content", "reasoning"):
        v = getattr(delta, attr, None)
        if isinstance(v, str) and v:
            return v
    extra = getattr(delta, "model_extra", None) or {}
    for key in ("reasoning_content", "reasoning"):
        v = extra.get(key)
        if isinstance(v, str) and v:
            return v
    return ""


class OpenAIProvider(BaseProvider):
    def __init__(self, model_config: dict[str, Any]) -> None:
        super().__init__(model_config)
        import openai

        kwargs: dict[str, Any] = {}
        if model_config.get("api_key"):
            kwargs["api_key"] = _clean_header_value(model_config["api_key"], "API key")
        if model_config.get("base_url"):
            kwargs["base_url"] = _clean_header_value(model_config["base_url"], "base_url")
        _apply_timeout_retries(kwargs, model_config)
        hc = _http_client(model_config)
        if hc is not None:
            kwargs["http_client"] = hc          # client proxy and/or disabled TLS verification
        self.client = openai.AsyncOpenAI(**kwargs)

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]

    @staticmethod
    def _to_openai_messages(system: str, messages: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": system}]
        for m in messages:
            role = m["role"]
            content = m["content"]
            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue
            if role == "assistant":
                text_parts = []
                tool_calls = []
                for b in content:
                    if b["type"] == "text":
                        text_parts.append(b["text"])
                    elif b["type"] == "tool_use":
                        tool_calls.append(
                            {
                                "id": b["id"],
                                "type": "function",
                                "function": {
                                    "name": b["name"],
                                    "arguments": json.dumps(b.get("input", {})),
                                },
                            }
                        )
                msg: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                out.append(msg)
            else:  # user
                text_parts = []
                for b in content:
                    if b["type"] == "text":
                        text_parts.append(b["text"])
                    elif b["type"] == "tool_result":
                        out.append(
                            {
                                "role": "tool",
                                "tool_call_id": b["tool_use_id"],
                                "content": str(b.get("content", "")),
                            }
                        )
                if text_parts:
                    out.append({"role": "user", "content": "\n".join(text_parts)})
        return out

    def _build_params(self, system, messages, tools) -> dict[str, Any]:
        """Assemble the OpenAI chat-completions request kwargs (messages converted to
        OpenAI shape, sampling/penalty/seed/reasoning_effort passed through when set), then
        apply param_overrides. Edit here to change how OpenAI-compatible calls are formed."""
        cfg = self.cfg
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": cfg.get("max_tokens", 8000),
            "messages": self._to_openai_messages(system, messages),
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            params["tools"] = self._tools(tools)
        for key in ("temperature", "top_p", "frequency_penalty", "presence_penalty", "seed"):
            v = cfg.get(key)
            if v is not None:
                params[key] = v
        if cfg.get("stop"):
            params["stop"] = cfg["stop"]
        # OpenAI reasoning models accept reasoning_effort; pass through if set.
        if cfg.get("reasoning_effort"):
            params["reasoning_effort"] = cfg["reasoning_effort"]
        return apply_param_overrides(params, cfg)

    async def complete(self, system, messages, tools, on_token=None) -> LLMResponse:
        params = self._build_params(system, messages, tools)

        text = ""
        thinking = ""
        tool_accum: dict[int, dict] = {}
        usage = Usage()
        stop_reason = "end_turn"

        stream = await self.client.chat.completions.create(**params)
        async for chunk in stream:
            # TOKEN USAGE (source): OpenAI sends usage in a final chunk (stream_options
            # include_usage). prompt_tokens -> input, completion_tokens -> output, and any
            # cached prompt tokens -> cache_read. Feeds Session.add_cost downstream.
            if getattr(chunk, "usage", None):
                usage.input_tokens = chunk.usage.prompt_tokens or 0
                usage.output_tokens = chunk.usage.completion_tokens or 0
                details = getattr(chunk.usage, "prompt_tokens_details", None)
                if details is not None:
                    usage.cache_read = getattr(details, "cached_tokens", 0) or 0
            if not chunk.choices:
                continue
            choice = chunk.choices[0]
            delta = choice.delta
            # Reasoning models on OpenAI-compatible endpoints (Kimi, DeepSeek, etc.) stream their
            # chain-of-thought in a separate `reasoning_content` (or `reasoning`) delta field, NOT
            # in `content`. Capture it and stream it tagged "thinking" so the raw view shows it
            # live; it's kept out of the replayed message blocks (like Anthropic thinking).
            rc = _delta_reasoning(delta)
            if rc:
                thinking += rc
                if on_token:
                    await on_token(rc, "thinking")
            if getattr(delta, "content", None):
                text += delta.content
                if on_token:
                    await on_token(delta.content, "text")
            for tc in getattr(delta, "tool_calls", None) or []:
                slot = tool_accum.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                if tc.id:
                    slot["id"] = tc.id
                if tc.function and tc.function.name:
                    slot["name"] = tc.function.name
                if tc.function and tc.function.arguments:
                    slot["args"] += tc.function.arguments
            if choice.finish_reason:
                stop_reason = "tool_use" if choice.finish_reason == "tool_calls" else "end_turn"

        tool_calls: list[dict] = []
        blocks: list[dict] = []
        if text:
            blocks.append({"type": "text", "text": text})
        for _, slot in sorted(tool_accum.items()):
            try:
                args = json.loads(slot["args"]) if slot["args"] else {}
            except json.JSONDecodeError:
                args = {}
            call = {"id": slot["id"] or f"call_{len(tool_calls)}", "name": slot["name"], "input": args}
            tool_calls.append(call)
            blocks.append({"type": "tool_use", **call})
        if tool_calls:
            stop_reason = "tool_use"
        return LLMResponse(
            text=text, tool_calls=tool_calls, usage=usage, stop_reason=stop_reason,
            raw_content=blocks, thinking=thinking,
        )


# --------------------------------------------------------------------------- #
# Mock — deterministic, drives a realistic flow with no network/keys.
# --------------------------------------------------------------------------- #
class MockProvider(BaseProvider):
    """Picks tool calls based on which tools are available and what has already
    been called this conversation, ending with `finish`. Lets the entire pipeline
    be exercised offline."""

    async def complete(self, system, messages, tools, on_token=None) -> LLMResponse:
        tool_names = {t["name"] for t in tools}
        called: set[str] = set()
        for m in messages:
            if m["role"] == "assistant" and isinstance(m["content"], list):
                for b in m["content"]:
                    if b.get("type") == "tool_use":
                        called.add(b["name"])

        def make(name: str, inp: dict, say: str) -> LLMResponse:
            cid = f"mock_{name}_{len(called)}"
            blocks = [{"type": "text", "text": say}, {"type": "tool_use", "id": cid, "name": name, "input": inp}]
            return LLMResponse(
                text=say,
                tool_calls=[{"id": cid, "name": name, "input": inp}],
                usage=Usage(input_tokens=300, output_tokens=120),
                stop_reason="tool_use",
                raw_content=blocks,
            )

        if on_token:
            await on_token("", "text")

        # Tool-selector agent: parse candidate names from the prompt body and pick a few.
        if "select_tools" in tool_names and "select_tools" not in called:
            import re

            text = ""
            for m in messages:
                c = m.get("content")
                if isinstance(c, str):
                    text += c + "\n"
                elif isinstance(c, list):
                    for b in c:
                        if b.get("type") == "text":
                            text += b.get("text", "") + "\n"
            names = re.findall(r"^- ([A-Za-z0-9_]+):", text, re.MULTILINE)
            picked = names[:3] if names else []
            return make("select_tools", {"tool_names": picked}, f"Selecting {len(picked)} tools.")

        def _all_text() -> str:
            t = ""
            for m in messages:
                c = m.get("content")
                if isinstance(c, str):
                    t += c + "\n"
                elif isinstance(c, list):
                    for b in c:
                        if b.get("type") == "text":
                            t += b.get("text", "") + "\n"
            return t

        # Report writer: write the report file to the path named in the brief.
        if "write_file" in tool_names and "Report Writer" in system and "write_file" not in called:
            import re

            m = re.search(r"save it to `([^`]+)`", _all_text())
            path = m.group(1) if m else "reports/report.md"
            return make("write_file",
                        {"path": path, "content": "# Engagement Report\n\n(mock-generated report)\n"},
                        "Writing the engagement report.")

        is_orchestrator = "Orchestrator" in system
        if "update_plan" in tool_names and "update_plan" not in called:
            return make(
                "update_plan",
                {"steps": [
                    "Reconnaissance & host/service discovery",
                    "Enumerate services and web content",
                    "Identify and confirm candidate vulnerabilities",
                    "Exploit validated, in-scope findings",
                    "Scoped post-exploitation & report",
                ]},
                "Drafting the penetration-test plan.",
            )
        # Orchestrator narrates progress to the operator once the plan is set.
        if (is_orchestrator and "notify_user" in tool_names
                and "notify_user" not in called and "update_plan" in called):
            return make("notify_user",
                        {"message": "Plan is ready. Next I'll delegate reconnaissance to map the "
                                    "target's attack surface, then test and confirm findings."},
                        "Keeping the operator in the loop.")
        # Only the orchestrator delegates, to avoid unbounded recursive spawning.
        if is_orchestrator and "spawn_agent" in tool_names and "spawn_agent" not in called:
            return make(
                "spawn_agent",
                {
                    "role": "recon",
                    "task": "Map the in-scope target's attack surface.",
                    "done_when": "live hosts, open ports and services are identified",
                    "context": "Authorised engagement; stay in scope; normal intensity.",
                    "wait": True,
                },
                "Spawning a reconnaissance agent.",
            )
        # Orchestrator validates any sub-agent that finished and is awaiting validation
        # (mandatory handshake) so the run can complete.
        if is_orchestrator and "validate_agent" in tool_names:
            import re

            results_text = ""
            for m in messages:
                c = m.get("content")
                if isinstance(c, list):
                    for b in c:
                        if b.get("type") == "tool_result":
                            results_text += str(b.get("content", "")) + "\n"
            already: set[str] = set()
            for m in messages:
                if m["role"] == "assistant" and isinstance(m["content"], list):
                    for b in m["content"]:
                        if b.get("type") == "tool_use" and b.get("name") == "validate_agent":
                            aid = (b.get("input") or {}).get("agent_id")
                            if aid:
                                already.add(aid)
            for aid in re.findall(r"AWAITING YOUR VALIDATION[\s\S]*?agent_id=(a_[0-9a-f]+)", results_text):
                if aid not in already:
                    return make("validate_agent", {"agent_id": aid, "accept": True},
                                f"Reviewing and validating sub-agent {aid}.")
        # A non-orchestrator worker loads its first offered on-demand skill, to exercise
        # the dynamic-skill path.
        if not is_orchestrator and "load_skill" in tool_names and "load_skill" not in called:
            import re

            m = re.search(r"SKILLS YOU MAY LOAD ON DEMAND[\s\S]*?\n- ([a-z0-9_]+):", system)
            if m:
                return make("load_skill", {"name": m.group(1)}, f"Loading the {m.group(1)} skill.")
        if "store_finding" in tool_names and "store_finding" not in called:
            return make(
                "store_finding",
                {
                    "title": "SQL injection in /search?q=",
                    "severity": "high",
                    "status": "validated",
                    "location": "http://target/search?q=",
                    "description": "Error-based SQLi in the q parameter allows DB extraction.",
                    "evidence": "q=' returned a SQL syntax error; sqlmap confirmed UNION injection.",
                },
                "Recording a validated finding.",
            )
        # Try one read/listing/MCP tool to demonstrate tool execution.
        for cand in ("list_dir", "read_file", "record_note", "http_request", "kali__nmap_scan"):
            if cand in tool_names and cand not in called:
                if cand in ("list_dir", "read_file"):
                    inp = {"path": "README.md"} if cand == "read_file" else {"path": "."}
                elif cand == "record_note":
                    inp = {"title": "mock note", "note": "mock recon observation"}
                elif cand == "http_request":
                    inp = {"url": "http://127.0.0.1/", "method": "GET"}
                else:
                    inp = {"target": "127.0.0.1", "mode": "ping"}
                return make(cand, inp, f"Using {cand}.")
        if "finish" in tool_names:
            return make("finish", {"summary": "Mock analysis complete. See findings."}, "Wrapping up.")
        # No tools -> plain completion.
        return LLMResponse(
            text="Mock completion (no tools available).",
            usage=Usage(input_tokens=200, output_tokens=50),
            stop_reason="end_turn",
            raw_content=[{"type": "text", "text": "Mock completion."}],
        )


def make_provider(model_config: dict[str, Any]) -> BaseProvider:
    """Factory: build the right provider for a model config's ``provider`` field
    (anthropic | openai | mock). Add a new backend by writing a BaseProvider subclass
    and a branch here."""
    provider = (model_config.get("provider") or "anthropic").lower()
    if provider == "anthropic":
        return AnthropicProvider(model_config)
    if provider == "openai":
        return OpenAIProvider(model_config)
    if provider == "mock":
        return MockProvider(model_config)
    raise LLMError(f"Unknown provider: {provider}")
