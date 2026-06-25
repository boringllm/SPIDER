"""Minimal Model Context Protocol (MCP) client + tool wrapping.

Supports two transports:
  * stdio  — spawn a subprocess, exchange newline-delimited JSON-RPC.
  * http   — POST JSON-RPC to a Streamable-HTTP endpoint (json or SSE response).

Used to integrate external MCP servers — chiefly the Spider Kali offensive-tool server.
Tools are discovered dynamically via `tools/list`, so no tool names are
hard-coded. Connection failures are non-fatal: the tools simply become
unavailable and a warning is logged.
"""
from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any

from .base import Tool, ToolError

if TYPE_CHECKING:
    from ..agents import Agent

PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "spider", "version": "0.1.0"}


class MCPClient:
    def __init__(self, name: str, conf: dict[str, Any]) -> None:
        self.name = name
        self.conf = conf
        self.transport = conf.get("transport", "stdio")
        self._proc: asyncio.subprocess.Process | None = None
        self._http = None
        self._http_session_id: str | None = None
        self._id = 0
        self._lock = asyncio.Lock()
        self.tools: list[dict] = []
        self.connected = False

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    # ---- lifecycle ----
    async def connect(self) -> None:
        """Open the transport, run the MCP initialize handshake, and fetch the server's
        tool list. After this, ``self.tools`` is populated and ``connected`` is True."""
        if self.transport == "stdio":
            await self._connect_stdio()
        else:
            await self._connect_http()
        await self._initialize()
        self.tools = await self._list_tools()
        self.connected = True

    async def _connect_stdio(self) -> None:
        command = self.conf.get("command", "")
        args = self.conf.get("args", []) or []
        if not command:
            raise ToolError("stdio transport requires 'command'")
        env = None
        if self.conf.get("env"):
            import os

            env = {**os.environ, **{str(k): str(v) for k, v in self.conf["env"].items()}}
        self._proc = await asyncio.create_subprocess_exec(
            command,
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.conf.get("cwd") or None,
            env=env,
        )

    async def _connect_http(self) -> None:
        import httpx

        url = self.conf.get("url", "")
        if not url:
            raise ToolError("http transport requires 'url'")
        self._http = httpx.AsyncClient(base_url="", timeout=120.0)
        self._url = url
        # Auth headers sent on every request. A bearer ``token`` (used by the Spider Kali
        # server's SPIDER_KALI_TOKEN) is the common case; arbitrary ``headers`` are also
        # supported for other MCP servers.
        self._extra_headers: dict[str, str] = {}
        token = str(self.conf.get("token") or "").strip()
        if token:
            self._extra_headers["Authorization"] = f"Bearer {token}"
        for k, v in (self.conf.get("headers") or {}).items():
            self._extra_headers[str(k)] = str(v)

    async def _initialize(self) -> None:
        await self._request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        await self._notify("notifications/initialized", {})

    async def _list_tools(self) -> list[dict]:
        result = await self._request("tools/list", {})
        return result.get("tools", []) if isinstance(result, dict) else []

    async def call_tool(self, name: str, arguments: dict, meta: dict | None = None) -> str:
        """Invoke one MCP tool and flatten its content blocks to text. Raises ToolError if
        the server marks the result as an error. This is what each wrapped Tool's handler calls.

        ``meta`` is attached as JSON-RPC ``_meta`` — the Spider Kali server uses it to attribute a
        running process to the session/agent/tool that launched it (for the process monitor)."""
        params: dict[str, Any] = {"name": name, "arguments": arguments}
        if meta:
            params["_meta"] = meta
        result = await self._request("tools/call", params)
        if not isinstance(result, dict):
            return str(result)
        is_error = result.get("isError", False)
        parts = []
        for c in result.get("content", []):
            if c.get("type") == "text":
                parts.append(c.get("text", ""))
            else:
                parts.append(json.dumps(c))
        text = "\n".join(parts) if parts else json.dumps(result)
        if is_error:
            raise ToolError(text)
        return text

    # ---- transport-level JSON-RPC ----
    async def _request(self, method: str, params: dict) -> Any:
        """Send a JSON-RPC request (id-correlated) over the active transport and return its
        ``result``.

        For STDIO the lock is required: requests share one stdin/stdout pipe, so frames must not
        interleave. For HTTP each request is an independent POST (httpx is concurrency-safe and
        responses are matched by id), so we DON'T lock — this lets multiple agents run Kali tools
        in parallel AND lets the operator's process monitor (list/kill) run while a long tool call
        is still in flight, instead of blocking behind it."""
        rid = self._next_id()
        msg = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        if self.transport == "stdio":
            async with self._lock:
                return await self._stdio_request(msg, rid)
        return await self._http_request(msg, rid)

    async def _notify(self, method: str, params: dict) -> None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params}
        if self.transport == "stdio":
            async with self._lock:
                assert self._proc and self._proc.stdin
                self._proc.stdin.write((json.dumps(msg) + "\n").encode())
                await self._proc.stdin.drain()
        else:
            await self._http_post(msg)

    async def _stdio_request(self, msg: dict, rid: int) -> Any:
        assert self._proc and self._proc.stdin and self._proc.stdout
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()
        while True:
            line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=120.0)
            if not line:
                raise ToolError(f"MCP server '{self.name}' closed the connection")
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue  # ignore non-JSON log lines
            if data.get("id") == rid:
                if "error" in data:
                    raise ToolError(f"MCP error: {data['error']}")
                return data.get("result")
            # else: a notification or other id — keep reading.

    async def _http_post(self, msg: dict):
        import httpx

        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        headers.update(getattr(self, "_extra_headers", {}))
        if self._http_session_id:
            headers["Mcp-Session-Id"] = self._http_session_id
        resp = await self._http.post(self._url, json=msg, headers=headers)  # type: ignore
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self._http_session_id = sid
        return resp

    async def _http_request(self, msg: dict, rid: int) -> Any:
        resp = await self._http_post(msg)
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            for raw in resp.text.splitlines():
                if raw.startswith("data:"):
                    try:
                        data = json.loads(raw[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    if data.get("id") == rid:
                        if "error" in data:
                            raise ToolError(f"MCP error: {data['error']}")
                        return data.get("result")
            return {}
        if not resp.content:
            return {}
        data = resp.json()
        if "error" in data:
            raise ToolError(f"MCP error: {data['error']}")
        return data.get("result")

    async def close(self) -> None:
        """Tear down the server: terminate the stdio subprocess (kill if it hangs) or close
        the HTTP client. Safe to call multiple times."""
        try:
            if self._proc:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._proc.kill()
            if self._http:
                await self._http.aclose()
        except Exception:
            pass
        self.connected = False


def _make_handler(client: MCPClient, tool_name: str):
    """Build a Tool handler that forwards a call to the given MCP client + remote tool name.
    (A closure so each wrapped tool remembers its own client and original name.) Tags the call
    with who launched it so the Kali server's process monitor can attribute the running command."""
    async def handler(agent: "Agent", args: dict[str, Any]) -> str:
        # `filter` carries the operator's global output-filtering setting to the Kali server,
        # which uses it (unless the agent passed raw=true) to decide whether to trim tool output.
        filt = bool(((agent.session.cfg.get("output_filter") or {}).get("enabled", True)))
        meta = {"session": agent.session.id, "agent": agent.id,
                "agent_name": agent.name, "tool": tool_name, "filter": filt}
        # `proxy` carries the Kali-side proxy settings so the server can route tool subprocesses
        # (curl/httpx/gospider/nuclei/wget) through it via HTTP(S)_PROXY/NO_PROXY env vars.
        kp = agent.session.cfg.get("kali_proxy") or {}
        if kp.get("enabled") and str(kp.get("url") or "").strip():
            meta["proxy"] = {"url": str(kp["url"]).strip(), "no_proxy": kp.get("no_proxy") or []}
        return await client.call_tool(tool_name, args, meta=meta)

    return handler


def build_mcp_tools(client: MCPClient, prefix: str) -> dict[str, Tool]:
    """Wrap each discovered MCP tool as a spider Tool, prefixing the name with the server
    name to avoid collisions (e.g. kali__nmap_scan).

    The approval-policy CATEGORY for each tool is taken from the server-supplied metadata
    (``_meta.category`` or ``annotations.category``) when present — the Spider Kali server
    tags every tool with one of config.TOOL_CATEGORIES (recon/enum/web/exploit/bruteforce/…).
    Tools that declare no category get "mcp", which the policy resolves via its `default`
    decision (so unknown remote tools are gated unless the operator opts them in)."""
    tools: dict[str, Tool] = {}
    for t in client.tools:
        raw_name = t.get("name", "")
        if not raw_name:
            continue
        local = f"{prefix}__{raw_name}"
        schema = t.get("inputSchema") or {"type": "object", "properties": {}}
        meta = t.get("_meta") or {}
        annotations = t.get("annotations") or {}
        category = meta.get("category") or annotations.get("category") or "mcp"
        tools[local] = Tool(
            name=local,
            description=(t.get("description") or f"{prefix} MCP tool {raw_name}")[:2000],
            input_schema=schema,
            handler=_make_handler(client, raw_name),
            requires_approval=False,
            parallel_safe=True,
            category=str(category),
        )
    return tools
