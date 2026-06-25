"use strict";

// Tools shown in the "Commands executed" panel — local shell/terminal + any Kali tool
// (kali__*) is matched dynamically in trackCommand.
const CMD_TOOLS = new Set(["run_shell", "run_process", "terminal", "kali_terminal", "http_request"]);

// Friendly labels for the finer-grained agent statuses (what the agent is actually waiting on).
const STATUS_LABELS = {
  waiting_llm: "awaiting LLM", waiting_subagent: "awaiting sub-agent",
  waiting_validation: "awaiting validation", waiting_approval: "awaiting approval",
  summarizing: "summarizing", running: "running", done: "done",
  stopped: "stopped", error: "error", idle: "idle", created: "created",
};
function statusLabel(s) { return STATUS_LABELS[s] || s || ""; }

let state = {
  sessions: [], current: null, session: null, ws: null,
  agents: {}, plan: { steps: [] }, findings: {}, cost: null, approvals: {}, requests: {},
  // Per-agent terminal: commands each agent runs, keyed by agent id (plus "__all__").
  terminals: { __all__: [] }, agentTab: "chat",
  // Per-agent RAW LLM turns (thinking/text/tool_use/stop_reason) + the in-flight live stream.
  rawFeeds: { __all__: [] }, rawStream: {},
  uploads: [],
  procs: [], procPoll: null,
  planApprovals: {}, intensity: "normal",
  config: null, agentDefs: null, roles: null, availableTools: [],
  view: "reverse", selectedAgent: "__all__",
  feeds: { __all__: [] }, streaming: {},
  subCollapsed: {}, showPanels: true,
  orchestratorId() {
    const o = Object.values(this.agents).find(a => a.role === "orchestrator");
    return o ? o.id : "__all__";
  },
};

async function api(path, method = "GET", body) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  // Token expired/revoked mid-session: drop back to the login gate (auth endpoints excepted).
  if (res.status === 401 && !path.startsWith("/api/auth/")) showAuthGate();
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}
function esc(s) { return String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }
function truncate(s, n) { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n) + "…" : s; }
function agentName(id) { return (state.agents[id] && state.agents[id].name) || id || "system"; }

// ----------------------------------------------------------- sessions
async function loadSessions() { state.sessions = await api("/api/sessions"); renderSessions(); }
function renderSessions() {
  const el = document.getElementById("sessionList");
  if (!state.sessions.length) { el.innerHTML = '<div class="empty">No sessions</div>'; return; }
  const me = state.user || {};
  const isAdmin = me.role === "admin";
  el.innerHTML = state.sessions.map(s => {
    const running = s.status === "running";
    // For an admin, label sessions that belong to OTHER users so they can monitor (and, if needed,
    // stop) any operator's engagement. The server already lets admins open/stop any session; this is
    // just the visual cue for whose it is.
    const others = isAdmin && s.owner && s.owner !== me.id;
    const ownerTag = others ? `<span class="sess-owner" title="owner">👤 ${esc(s.owner_name || s.owner)}</span>` : "";
    return `
    <div class="session-item ${s.id === state.current ? "active" : ""} ${others ? "other-owner" : ""}" onclick="selectSession('${s.id}')">
      <button class="del-btn" title="Delete session" onclick="deleteSession(event,'${s.id}')">✕</button>
      <div class="name">${running ? '<span class="live-dot" title="running"></span>' : ""}${esc(s.name)} ${ownerTag}</div>
      <div class="meta">${esc(s.status)} · ${esc(s.target || "no target")}</div>
    </div>`;
  }).join("");
}
// Admins monitor every user's session, so keep the list (status + new sessions) fresh in the
// background. Regular users only see their own sessions and don't need the extra polling.
function startSessionPoll() {
  stopSessionPoll();
  if (!state.user || state.user.role !== "admin") return;
  state.sessionPoll = setInterval(() => { loadSessions().catch(() => {}); }, 5000);
}
function stopSessionPoll() { if (state.sessionPoll) { clearInterval(state.sessionPoll); state.sessionPoll = null; } }
async function newSession() {
  const name = prompt("Session name:", "engagement-" + new Date().toISOString().slice(0, 16));
  if (name === null) return;
  const s = await api("/api/sessions", "POST", { name });
  await loadSessions(); selectSession(s.id);
}
async function deleteSession(ev, sid) {
  ev.stopPropagation();
  if (!confirm("Delete this session and its workspace? This cannot be undone.")) return;
  await api(`/api/sessions/${sid}`, "DELETE");
  if (state.current === sid) {
    state.current = null; state.session = null;
    if (state.ws) { try { state.ws.close(); } catch (e) {} }
    document.getElementById("sessionView").classList.add("hidden");
    document.getElementById("noSession").classList.remove("hidden");
  }
  await loadSessions();
}
async function selectSession(sid) {
  state.current = sid;
  state.agents = {}; state.findings = {}; state.approvals = {}; state.requests = {};
  state.terminals = { __all__: [] }; state.agentTab = "chat"; state.uploads = [];
  state.rawFeeds = { __all__: [] }; state.rawStream = {};
  state.planApprovals = {};
  state.feeds = { __all__: [] }; state.streaming = {}; state.selectedAgent = "__all__";
  state.session = await api(`/api/sessions/${sid}`);
  state.plan = state.session.plan || { steps: [] };
  state.cost = state.session.cost;
  state.intensity = state.session.intensity || "normal";
  state.approvalMode = state.session.approval_mode || "manual";
  (state.session.agents || []).forEach(a => { state.agents[a.id] = a; state.feeds[a.id] = state.feeds[a.id] || []; });
  (state.session.findings || []).forEach(f => state.findings[f.id] = f);
  (state.session.pending_approvals || []).forEach(a => state.approvals[a.id] = a);
  (state.session.pending_requests || []).forEach(r => state.requests[r.id] = r);
  (state.session.pending_plan_approvals || []).forEach(pa => state.planApprovals[pa.id] = pa);
  // Rebuild the per-agent discussion feed from persisted messages (survives restarts).
  try {
    const msgs = await api(`/api/sessions/${sid}/messages`);
    msgs.forEach(m => {
      // rebuild the commands panel from persisted command-tool calls/results
      if (m.role === "tool_call") trackCommand(m.agent_id, m.content, false);
      else if (m.role === "tool_result") trackCommand(m.agent_id, m.content, true);
      // rebuild the raw LLM view from persisted raw turns
      if (m.role === "assistant_raw") { pushRaw(m.agent_id, m.content); return; }
      const e = feedEntryFromMessage(m);
      if (!e) return;
      (state.feeds[m.agent_id] = state.feeds[m.agent_id] || []).push(e);
      state.feeds.__all__.push({ ...e, label: `${agentName(m.agent_id)} · ${e.label}` });
    });
  } catch (e) { /* no messages yet */ }
  document.getElementById("noSession").classList.add("hidden");
  document.getElementById("sessionView").classList.remove("hidden");
  document.getElementById("sessName").textContent = state.session.name;
  document.getElementById("targetInput").value = state.session.target || "";
  document.getElementById("instructionsInput").value = state.session.instructions || "";
  const orch = Object.values(state.agents).find(a => a.role === "orchestrator");
  state.selectedAgent = orch ? orch.id : "__all__";
  state.showPanels = window.innerWidth >= 1100;
  setView("reverse"); applyPanels(); renderAll(); renderSessions(); connectWS(sid); loadUploads();
  state.procs = []; startProcPoll();
}
function connectWS(sid) {
  if (state.ws) { try { state.ws.close(); } catch (e) {} }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/${sid}`);
  state.ws = ws;
  const ind = document.getElementById("wsStatus");
  ws.onopen = () => { ind.textContent = "● live"; ind.style.color = "var(--green)"; };
  ws.onclose = () => { ind.textContent = "disconnected"; ind.style.color = "var(--muted)"; };
  ws.onmessage = (e) => handleEvent(JSON.parse(e.data));
}

// ----------------------------------------------------------- events -> feeds
// Map a persisted message row to a feed entry (mirrors the live event handlers).
function feedEntryFromMessage(m) {
  const c = m.content;
  const asText = v => typeof v === "string" ? v : JSON.stringify(v);
  switch (m.role) {
    case "user": return { cls: "user", label: "input", text: asText(c) };
    case "assistant": return { cls: "assistant", label: "assistant", text: asText(c) };
    case "tool_call": return { cls: "tool", label: "tool call", text: `→ ${c.tool}(${truncate(JSON.stringify(c.input), 300)})` };
    case "tool_result": return { cls: c.is_error ? "toolres err" : "toolres", label: `${c.tool} result`, text: truncate(String(c.result), 1500) };
    case "narration": return { cls: "narration", label: "📣 update", text: (c && c.message) || asText(c) };
    case "operator": return { cls: "user", label: "🧭 operator", text: (c && c.message) || asText(c) };
    case "memory_loaded": return { cls: "memory", label: "📚 memory", text: `loaded memory files: ${(c && c.files || []).join(", ") || "(shared memory)"}` };
    case "skill_loaded": return { cls: "skill", label: "🧠 skill", text: `loaded skill: ${(c && (c.title || c.name)) || asText(c)}${c && c.auto ? " (at start)" : ""}` };
    default: return null;
  }
}
function pushFeed(aid, cls, label, text) {
  const entry = { cls, label, text };
  (state.feeds[aid] = state.feeds[aid] || []).push(entry);
  if (state.feeds[aid].length > 500) state.feeds[aid].shift();
  state.feeds.__all__.push({ ...entry, label: `${agentName(aid)} · ${label}` });
  if (state.feeds.__all__.length > 800) state.feeds.__all__.shift();
  if (state.view === "reverse" && (state.selectedAgent === aid || state.selectedAgent === "__all__")) renderAgentFeed();
}
function trackCommand(aid, p, isResult) {
  // Track local command tools and every Kali offensive tool (kali__*) in the per-agent terminal.
  // Each entry is pushed to BOTH the agent's own list and the shared "__all__" list (same object
  // reference, so resolving a result updates both views).
  if (!CMD_TOOLS.has(p.tool) && !String(p.tool || "").startsWith("kali__")) return;
  const agentList = state.terminals[aid] = state.terminals[aid] || [];
  const allList = state.terminals.__all__ = state.terminals.__all__ || [];
  if (!isResult) {
    const entry = { agent: agentName(aid), tool: p.tool, input: p.input, result: null, error: false };
    agentList.push(entry); allList.push(entry);
    if (agentList.length > 300) agentList.shift();
    if (allList.length > 600) allList.shift();
  } else {
    [agentList, allList].forEach(L => {
      for (let i = L.length - 1; i >= 0; i--) {
        if (L[i].tool === p.tool && L[i].result === null) { L[i].result = p.result; L[i].error = p.is_error; break; }
      }
    });
  }
  if (state.agentTab === "terminal" && (state.selectedAgent === aid || state.selectedAgent === "__all__")) renderTerminal();
}
function handleEvent(ev) {
  const p = ev.payload || {}; const aid = ev.agent_id;
  switch (ev.type) {
    case "session.status":
      if (state.session) state.session.status = p.status; renderStatus(); renderSessions(); break;
    case "plan.update": case "plan.step": state.plan = p.plan; renderPlan(); break;
    case "agent.created":
      state.agents[aid] = { id: aid, name: p.name, role: p.role, status: "running",
        parent_id: p.parent, model: p.model, tools: p.tools || [], mcp_servers: p.mcp_servers || [],
        task: p.task || "", system_prompt: p.system_prompt || "" };
      state.feeds[aid] = state.feeds[aid] || [];
      if (state.selectedAgent === "__all__" && p.role === "orchestrator") state.selectedAgent = aid;
      renderTree();
      pushFeed(aid, "sys", "spawned", `${p.role} (${p.name}) — ${truncate(p.task, 200)}`);
      if (state.selectedAgent === aid) renderAgentHead();
      break;
    case "agent.status":
      if (state.agents[aid]) state.agents[aid].status = p.status;
      renderTree(); if (state.selectedAgent === aid) renderAgentHead(); break;
    case "agent.token": {
      const kind = p.kind || "text";
      // Filtered chat's streaming line shows only the answer text…
      if (kind === "text") state.streaming[aid] = (state.streaming[aid] || "") + p.text;
      // …the raw view streams BOTH the reasoning and the answer live.
      const rs = state.rawStream[aid] = state.rawStream[aid] || { text: "", thinking: "" };
      if (kind === "thinking") rs.thinking += p.text; else rs.text += p.text;
      if (state.view === "reverse" && (state.selectedAgent === aid || state.selectedAgent === "__all__")) {
        if (state.agentTab === "raw") updateRawStream(); else if (state.agentTab === "chat") updateStreamLine();
      }
      break;
    }
    case "agent.raw":
      pushRaw(aid, p);
      state.rawStream[aid] = { text: "", thinking: "" };  // turn finalized; clear live buffer
      if (state.agentTab === "raw" && state.view === "reverse" &&
          (state.selectedAgent === aid || state.selectedAgent === "__all__")) renderRaw();
      break;
    case "agent.message":
      state.streaming[aid] = "";
      if (p.role === "assistant") pushFeed(aid, "assistant", "assistant", p.content);
      else if (p.role === "user") pushFeed(aid, "user", "input", p.content);
      break;
    case "agent.narration":
      pushFeed(aid, "narration", "📣 update", p.message); break;
    case "agent.memory_loaded":
      pushFeed(aid, "memory", "📚 memory", `loaded memory files: ${(p.files || []).join(", ") || "(shared memory)"}`); break;
    case "agent.skill_loaded":
      pushFeed(aid, "skill", "🧠 skill", `loaded skill: ${p.title || p.name}${p.auto ? " (at start)" : ""}`); break;
    case "tool.call":
      pushFeed(aid, "tool", "tool call", `→ ${p.tool}(${truncate(JSON.stringify(p.input), 300)})`);
      trackCommand(aid, p, false); break;
    case "tool.result":
      pushFeed(aid, p.is_error ? "toolres err" : "toolres", `${p.tool} result`, truncate(p.result, 1500));
      trackCommand(aid, p, true); break;
    case "finding.stored":
      state.findings[p.finding.id] = p.finding; renderFindings();
      pushFeed(aid, "sys", "finding", `${p.finding.title} [${p.finding.severity}/${p.finding.status}]`); break;
    case "cost.update": state.cost = p.cost; renderCost(); if (state.selectedAgent !== "__all__") renderAgentHead(); break;
    case "context.compacted":
      pushFeed(aid, "sys", "compaction", `context compacted (summary ${p.summary_chars} chars)`); break;
    case "approval.request":
      state.approvals[p.id] = p; renderApprovals();
      pushFeed(p.agent_id, "sys", "approval", `awaiting approval to run ${p.tool}`); break;
    case "approval.resolved": delete state.approvals[p.id]; renderApprovals(); break;
    case "user.request":
      state.requests[p.id] = p; renderRequests();
      pushFeed(p.agent_id, "sys", "input requested", p.message);
      alertOperator(`${p.agent_name || "An agent"} needs your input`, p.message);
      break;
    case "user.request_resolved": delete state.requests[p.id]; renderRequests(); break;
    // ---- Spider human-in-the-loop ----
    case "plan.approval_request":
      if (p.id) { state.planApprovals[p.id] = p; renderPlanApprovals(); }
      pushFeed(aid, "sys", "plan approval", "the orchestrator is awaiting your sign-off on the plan"); break;
    case "plan.approval_resolved":
      delete state.planApprovals[p.id]; renderPlanApprovals();
      pushFeed(aid, "narration", "📋 plan", `plan ${esc(p.decision)}${p.feedback ? " — " + esc(p.feedback) : ""}`); break;
    case "operator.interjection":
      pushFeed(state.orchestratorId(), "user", "🧭 operator", p.message); break;
    case "intensity.changed":
      state.intensity = p.intensity;
      const sel = document.getElementById("intensitySelect"); if (sel) sel.value = p.intensity;
      pushFeed(aid, "sys", "intensity", `tool intensity set to ${p.intensity}`); break;
    case "approval.mode_changed":
      state.approvalMode = p.approval_mode;
      const bx = document.getElementById("bypassApproval"); if (bx) bx.checked = (p.approval_mode === "auto");
      pushFeed(aid, "sys", "approvals", p.approval_mode === "auto"
        ? "command validation BYPASSED for this session (commands run without approval)"
        : "command validation re-enabled for this session"); break;
    case "kali.process_killed": {
      const pr = p.proc || {};
      pushFeed(pr.agent || aid, "sys", "process killed",
        `🛑 killed ${pr.tool || "process"} (${truncate(pr.command || "", 80)})${p.message ? " — " + p.message : ""}`);
      refreshProcs(); break;
    }
    case "error": pushFeed(aid, "err", "error", p.message); break;
    case "log": pushFeed(aid, "sys", "log", `[${p.level}] ${p.message}`); break;
  }
}

// ----------------------------------------------------------- shared render
function renderAll() { renderStatus(); renderTree(); renderAgentHead(); renderActiveAgentView(); renderPlan(); renderFindings(); renderProcs(); renderCost(); renderApprovals(); renderRequests(); renderPlanApprovals(); const isel = document.getElementById("intensitySelect"); if (isel) isel.value = state.intensity || "normal"; const bx = document.getElementById("bypassApproval"); if (bx) bx.checked = (state.approvalMode === "auto"); }
function renderStatus() {
  const s = state.session ? state.session.status : "created";
  const el = document.getElementById("sessStatus"); el.textContent = s; el.className = "badge " + s;
}
function setView(v) {
  state.view = v;
  document.getElementById("reverseView").classList.toggle("hidden", v !== "reverse");
  document.getElementById("dashboardView").classList.toggle("hidden", v !== "dashboard");
  document.getElementById("viewReverseBtn").classList.toggle("active", v === "reverse");
  document.getElementById("viewDashBtn").classList.toggle("active", v === "dashboard");
  if (v === "dashboard") renderCost(); else renderActiveAgentView();
}
function toggleSub(name) {
  const el = document.getElementById("subwin-" + name);
  el.classList.toggle("collapsed");
  state.subCollapsed[name] = el.classList.contains("collapsed");
}
function applyPanels() {
  const r = document.getElementById("reverseView");
  r.classList.toggle("panels-on", state.showPanels);
  r.classList.toggle("panels-off", !state.showPanels);
}
function togglePanels() { state.showPanels = !state.showPanels; applyPanels(); }

// ----------------------------------------------------------- process tree
function renderTree() {
  const box = document.getElementById("treeBox");
  const all = Object.values(state.agents);
  const roots = all.filter(a => !a.parent_id || !state.agents[a.parent_id]);
  let html = `<div class="tree-row ${state.selectedAgent === "__all__" ? "active" : ""}" onclick="selectAgent('__all__')">
      <span class="role">All activity</span></div>`;
  html += roots.map(nodeHtml).join("");
  box.innerHTML = html;
}
function nodeHtml(a) {
  const kids = Object.values(state.agents).filter(c => c.parent_id === a.id);
  const nm = a.name && a.name !== a.role ? `<span class="nm">${esc(a.name)}</span>` : "";
  return `<div class="tree-node">
    <div class="tree-row ${state.selectedAgent === a.id ? "active" : ""}" onclick="selectAgent('${a.id}')"
      title="${esc(a.role)}${a.name ? " · " + esc(a.name) : ""}${kids.length ? " · spawned " + kids.length : ""}">
      <span class="role">${esc(a.role)}</span>${nm}
      <span class="badge ${a.status}" style="font-size:9px">${esc(statusLabel(a.status))}</span>
      ${kids.length ? `<span class="kidcount">▸${kids.length}</span>` : ""}
    </div>
    ${kids.length ? `<div class="tree-children">${kids.map(nodeHtml).join("")}</div>` : ""}
  </div>`;
}
function selectAgent(aid) { state.selectedAgent = aid; renderTree(); renderAgentHead(); renderActiveAgentView(); }

// ---- Chat / Raw / Terminal tabs (per selected agent) ----
function applyAgentTab() {
  const tab = state.agentTab || "chat";
  const panes = { chat: "agentFeed", raw: "agentRaw", terminal: "agentTerminal" };
  for (const [t, id] of Object.entries(panes)) {
    const el = document.getElementById(id); if (el) el.classList.toggle("hidden", tab !== t);
  }
  const btns = { chat: "tabChatBtn", raw: "tabRawBtn", terminal: "tabTermBtn" };
  for (const [t, id] of Object.entries(btns)) {
    const b = document.getElementById(id); if (b) b.classList.toggle("active", tab === t);
  }
}
function renderActiveAgentView() {
  applyAgentTab();
  if (state.agentTab === "terminal") renderTerminal();
  else if (state.agentTab === "raw") renderRaw();
  else renderAgentFeed();
}
function setAgentTab(tab) { state.agentTab = tab; renderActiveAgentView(); }

// ---- Raw LLM view (full unfiltered output, live-streamed) ----
function pushRaw(aid, turn) {
  const t = { agent: agentName(aid), ...turn };
  (state.rawFeeds[aid] = state.rawFeeds[aid] || []).push(t);
  if (state.rawFeeds[aid].length > 300) state.rawFeeds[aid].shift();
  (state.rawFeeds.__all__ = state.rawFeeds.__all__ || []).push(t);
  if (state.rawFeeds.__all__.length > 600) state.rawFeeds.__all__.shift();
}
function rawTurnHtml(t, showAgent) {
  const tools = (t.tool_calls || (t.blocks || []).filter(b => b.type === "tool_use").map(b => ({ name: b.name, input: b.input }))) || [];
  return `<div class="raw-turn">
    <div class="raw-meta">${showAgent ? `<span class="raw-who">${esc(t.agent)}</span> · ` : ""}stop: <span class="raw-stop">${esc(t.stop_reason || "?")}</span></div>
    ${t.thinking ? `<details class="raw-think" open><summary>💭 thinking (${t.thinking.length} chars)</summary><pre>${esc(t.thinking)}</pre></details>` : ""}
    ${t.text ? `<div class="raw-text">${esc(t.text)}</div>` : (!tools.length ? `<div class="raw-empty-turn">(no text output)</div>` : "")}
    ${tools.map(tc => `<div class="raw-tool">🔧 <b>${esc(tc.name)}</b><pre>${esc(JSON.stringify(tc.input || {}, null, 2))}</pre></div>`).join("")}
  </div>`;
}
function renderRaw() {
  const box = document.getElementById("agentRaw"); if (!box) return;
  const turns = state.rawFeeds[state.selectedAgent] || [];
  const showAgent = state.selectedAgent === "__all__";
  let html = turns.length
    ? turns.map(t => rawTurnHtml(t, showAgent)).join("")
    : `<div class="raw-empty">No raw LLM output ${showAgent ? "across agents" : "for this agent"} yet.\nThis view shows the model's complete unfiltered output each turn — reasoning, answer text, the exact tool calls, and the stop reason — streamed live. Use it to tell a wrong/empty answer apart from a timeout or error.</div>`;
  html += `<div id="rawStreamLine" class="raw-live"></div>`;
  box.innerHTML = html;
  updateRawStream();
  box.scrollTop = box.scrollHeight;
}
// Render the in-flight LLM output (live, token-by-token). For a single selected agent we show its
// buffer; in the all-agents view we show every agent currently streaming, each labelled. Once the
// turn completes, agent.raw clears the buffer and the clean formatted turn is appended (no noise).
function updateRawStream() {
  const el = document.getElementById("rawStreamLine"); if (!el) return;
  const aid = state.selectedAgent;
  let active;  // [ [agentId, {text, thinking}], ... ]
  if (aid === "__all__") {
    active = Object.entries(state.rawStream).filter(([, rs]) => rs && (rs.text || rs.thinking));
  } else {
    const rs = state.rawStream[aid];
    active = (rs && (rs.text || rs.thinking)) ? [[aid, rs]] : [];
  }
  if (!active.length) { el.innerHTML = ""; return; }
  el.innerHTML = active.map(([id, rs]) =>
    `<div class="raw-live-turn">` +
    (aid === "__all__" ? `<div class="raw-meta"><span class="raw-who">${esc(agentName(id))}</span> · <span class="raw-stop">streaming…</span></div>` : "") +
    (rs.thinking ? `<div class="raw-think-live">💭 ${esc(rs.thinking)}</div>` : "") +
    (rs.text ? `<div class="raw-text-live">${esc(rs.text)}</div>` : "") +
    `<span class="raw-cursor">▌</span></div>`
  ).join("");
  const box = document.getElementById("agentRaw"); if (box) box.scrollTop = box.scrollHeight;
}
function renderTerminal() {
  const box = document.getElementById("agentTerminal"); if (!box) return;
  const cmds = state.terminals[state.selectedAgent] || [];
  if (!cmds.length) {
    box.innerHTML = `<div class="term-empty">No terminal activity ${state.selectedAgent === "__all__" ? "across agents" : "for this agent"} yet.\nWhen the agent runs a command (host shell, a Kali tool, or an HTTP request) it shows up here.</div>`;
    return;
  }
  const showAgent = state.selectedAgent === "__all__";
  box.innerHTML = cmds.map(c => {
    const inp = (c.input && (c.input.command || c.input.path || c.input.url)) || JSON.stringify(c.input || {});
    return `<div class="term-block">
      <div class="term-cmd">${showAgent ? `<span class="term-who">${esc(c.agent)}</span> ` : ""}<span class="term-tool">${esc(c.tool)}</span> <span class="term-prompt">❯</span> <span class="term-arg">${esc(truncate(inp, 800))}</span></div>
      ${c.result !== null
        ? `<pre class="term-out${c.error ? " err" : ""}">${esc(truncate(c.result, 6000))}</pre>`
        : `<div class="term-running">running…</div>`}
    </div>`;
  }).join("");
  box.scrollTop = box.scrollHeight;
}

function renderAgentHead() {
  const el = document.getElementById("agentHead");
  if (state.selectedAgent === "__all__") {
    el.className = "agent-head";
    el.innerHTML = `<span class="role">All activity</span> <span class="muted">combined feed of every agent</span>`;
    return;
  }
  const a = state.agents[state.selectedAgent];
  if (!a) { el.className = "agent-head empty"; el.textContent = "Start the session — agents will appear here."; return; }
  el.className = "agent-head";
  el.innerHTML = `
    <div><span class="role">${esc(a.role)}</span> <span class="muted">${esc(a.name)}</span> <span class="badge ${a.status}">${esc(statusLabel(a.status))}</span></div>
    <div class="muted" style="font-size:11px">${esc(a.model || "")} · ${(a.tools || []).length} tools${(a.mcp_servers && a.mcp_servers.length) ? " · mcp: " + esc(a.mcp_servers.join(",")) : ""} · $${(a.cost_usd || 0).toFixed(4)}</div>
    ${a.task ? `<div class="task">task: ${esc(truncate(a.task, 300))}</div>` : ""}
    <div class="controls">
      <button class="small" onclick="viewPrompt('${a.id}')">View system prompt</button>
      <button class="small danger" onclick="stopAgent('${a.id}')">Stop agent</button>
    </div>`;
}
function renderAgentFeed() {
  const box = document.getElementById("agentFeed");
  const entries = state.feeds[state.selectedAgent] || [];
  box.innerHTML = entries.map(e => `<div class="msg ${e.cls}"><span class="lbl">${esc(e.label)}</span>${esc(e.text)}</div>`).join("")
    + `<div class="streaming" id="streamLine"></div>`;
  updateStreamLine(); box.scrollTop = box.scrollHeight;
}
function updateStreamLine() {
  const el = document.getElementById("streamLine"); if (!el) return;
  const aid = state.selectedAgent === "__all__" ? null : state.selectedAgent;
  const txt = aid ? (state.streaming[aid] || "") : "";
  el.textContent = txt;
  if (txt) { const box = document.getElementById("agentFeed"); box.scrollTop = box.scrollHeight; }
}
async function sendAgentMessage() {
  const aid = state.selectedAgent;
  if (aid === "__all__") { alert("Select a specific agent in the tree to message."); return; }
  const ta = document.getElementById("agentMsg"); const msg = ta.value.trim(); if (!msg) return;
  try {
    await api(`/api/sessions/${state.current}/agents/${aid}/message`, "POST", { message: msg });
    pushFeed(aid, "user", "you", msg); ta.value = "";
  } catch (e) { alert(e.message); }
}

// ----------------------------------------------------------- sub-windows
function renderPlan() {
  const el = document.getElementById("planBox"); if (!el) return;
  const steps = (state.plan && state.plan.steps) || [];
  if (!steps.length) { el.className = "empty"; el.textContent = "No plan yet."; return; }
  el.className = "";
  el.innerHTML = steps.map(s => `<div class="step ${s.status}"><b>${s.id + 1}.</b> ${esc(s.text)} <span class="muted">[${s.status}]</span></div>`).join("");
}
function renderFindings() {
  const el = document.getElementById("findingsBox"); if (!el) return;
  const list = Object.values(state.findings);
  if (!list.length) { el.className = "empty"; el.textContent = "No findings yet."; return; }
  el.className = "";
  el.innerHTML = list.map(f => `<div class="finding">
      <div class="title sev-${esc(f.severity)}">${esc(f.title)}</div>
      <div class="sub">${esc(f.severity)} · ${esc(f.status)} · ${esc((f.data && f.data.location) || "")}</div>
      <div class="muted" style="font-size:11px">${esc(truncate((f.data && f.data.description) || "", 200))}</div></div>`).join("");
}
// ----------------------------------------------------------- dashboard cost
function renderCost() {
  const c = state.cost; const grid = document.getElementById("costGrid"); if (!grid) return;
  if (!c) { grid.innerHTML = '<span class="muted">No usage yet.</span>'; return; }
  grid.innerHTML = `
    <div class="cost-stat"><div class="v">$${(c.total_usd || 0).toFixed(4)}</div><div class="l">total cost</div></div>
    <div class="cost-stat"><div class="v">${c.input_tokens || 0}</div><div class="l">input tokens</div></div>
    <div class="cost-stat"><div class="v">${c.output_tokens || 0}</div><div class="l">output tokens</div></div>
    <div class="cost-stat"><div class="v">${c.cache_read || 0}</div><div class="l">cache read</div></div>
    <div class="cost-stat"><div class="v">${c.cache_write || 0}</div><div class="l">cache write</div></div>
    <div class="cost-stat"><div class="v">${Object.keys(c.by_agent || {}).length}</div><div class="l">agents</div></div>`;
  const at = document.getElementById("costByAgent");
  const arows = Object.entries(c.by_agent || {}).map(([id, v]) =>
    `<tr><td>${esc(v.name)}</td><td>${esc(v.role)}</td><td>${esc(v.model)}</td><td>${v.input}</td><td>${v.output}</td><td>$${v.usd.toFixed(4)}</td></tr>`).join("");
  if (at) at.innerHTML = arows ? `<tr><th>agent</th><th>role</th><th>model</th><th>input</th><th>output</th><th>cost</th></tr>${arows}` : '<tr><td class="muted">No per-agent usage yet.</td></tr>';
  const mt = document.getElementById("costByModel");
  const mrows = Object.entries(c.by_model || {}).map(([m, v]) =>
    `<tr><td>${esc(m)}</td><td>${v.input} in</td><td>${v.output} out</td><td>$${v.usd.toFixed(4)}</td></tr>`).join("");
  if (mt) mt.innerHTML = mrows ? `<tr><th>model</th><th></th><th></th><th>cost</th></tr>${mrows}` : '<tr><td class="muted">—</td></tr>';
}

// ----------------------------------------------------------- approvals
function renderApprovals() {
  const el = document.getElementById("approvalsWrap");
  const list = Object.values(state.approvals);
  if (!list.length) { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="approvals"><b>⚠ ${list.length} command(s) awaiting approval</b>` +
    list.map(a => `<div class="approval">
        <span><b>${esc(a.agent_name)}</b> → <code>${esc(a.tool)}</code> ${esc(truncate(JSON.stringify(a.input), 140))}</span>
        <span><button class="small primary" onclick="resolveApproval('${a.id}', true)">Approve</button>
        <button class="small danger" onclick="resolveApproval('${a.id}', false)">Deny</button></span>
      </div>`).join("") + "</div>";
}

// Raise the operator's attention when an agent asks a question / needs input: a flashing title,
// a dismissable on-screen toast (that scrolls to the request), and a desktop notification when the
// user has granted permission. Best-effort and dependency-free.
let _titleFlash = null;
function alertOperator(title, body) {
  body = String(body || "");
  // 1) Desktop notification (if the operator allowed it).
  try {
    if (window.Notification) {
      if (Notification.permission === "granted") {
        new Notification("🕷 Spider — " + title, { body: body.slice(0, 180) });
      } else if (Notification.permission !== "denied") {
        Notification.requestPermission().catch(() => {});
      }
    }
  } catch (_) { /* ignore */ }
  // 2) Flash the tab title until the window regains focus.
  const base = document.title.replace(/^❗ /, "");
  if (_titleFlash) clearInterval(_titleFlash);
  let on = false;
  _titleFlash = setInterval(() => { document.title = (on = !on) ? "❗ " + title : base; }, 1000);
  const stop = () => { if (_titleFlash) { clearInterval(_titleFlash); _titleFlash = null; } document.title = base; window.removeEventListener("focus", stop); };
  window.addEventListener("focus", stop);
  // 3) On-screen toast that jumps to the request panel.
  let host = document.getElementById("opToasts");
  if (!host) { host = document.createElement("div"); host.id = "opToasts"; host.className = "op-toasts"; document.body.appendChild(host); }
  const t = document.createElement("div");
  t.className = "op-toast";
  t.innerHTML = `<b>❓ ${esc(title)}</b><div>${esc(body.slice(0, 200))}</div><span class="op-toast-x">answer ▸</span>`;
  t.onclick = () => { stop(); t.remove(); const w = document.getElementById("requestsWrap"); if (w) w.scrollIntoView({ behavior: "smooth", block: "center" }); };
  host.appendChild(t);
  setTimeout(() => t.remove(), 30000);
}

// ---- Kali running-process monitor (operator can see + kill runaway scans) ----
async function refreshProcs() {
  if (!state.current) return;
  try {
    const r = await api(`/api/sessions/${state.current}/kali/processes`);
    state.procs = r.processes || [];
  } catch (e) { state.procs = []; }
  renderProcs();
}
function startProcPoll() {
  stopProcPoll();
  refreshProcs();
  state.procPoll = setInterval(refreshProcs, 3500);  // light poll while a session is open
}
function stopProcPoll() { if (state.procPoll) { clearInterval(state.procPoll); state.procPoll = null; } }
function renderProcs() {
  const box = document.getElementById("procsBox");
  const count = document.getElementById("procCount");
  if (!box) return;
  const list = state.procs || [];
  if (count) count.textContent = list.length ? `(${list.length})` : "";
  if (!list.length) { box.className = "empty"; box.textContent = "No processes running."; return; }
  box.className = "";
  box.innerHTML = list.map(p => {
    const rt = p.runtime >= 60 ? `${Math.floor(p.runtime / 60)}m${Math.round(p.runtime % 60)}s` : `${Math.round(p.runtime)}s`;
    return `<div class="proc-row${p.killed ? " killed" : ""}">
      <div class="proc-main"><span class="proc-tool">${esc(p.tool || "command")}</span>
        <span class="proc-agent">${esc(p.agent_name || "")}</span><span class="proc-rt">${rt}</span></div>
      <div class="proc-cmd" title="${esc(p.command || "")}">${esc(truncate(p.command || "", 120))}</div>
      ${p.killed ? `<div class="proc-killed">killed</div>`
        : `<button class="small danger" onclick="killProc('${p.id}')">Kill</button>`}
    </div>`;
  }).join("");
}
async function killProc(id) {
  const proc = (state.procs || []).find(p => p.id === id) || {};
  const message = prompt(
    `Kill this Kali process and tell ${proc.agent_name || "the agent"} why (optional — e.g. "this scan is overloading the target, use a lighter wordlist"):`,
    "");
  if (message === null) return;  // operator cancelled
  try { await api(`/api/sessions/${state.current}/kali/processes/${id}/kill`, "POST", { message }); refreshProcs(); }
  catch (e) { alert(e.message); }
}

function renderRequests() {
  const el = document.getElementById("requestsWrap");
  const list = Object.values(state.requests);
  if (!list.length) { el.innerHTML = ""; return; }
  el.innerHTML = list.map(r => `<div class="approvals" style="background:#102a1a;border-color:var(--green)">
      <b>${r.kind === "question" ? "❓" : "📂"} ${esc(r.agent_name)} ${r.kind === "question" ? "asks" : "needs your input"}</b>
      <div style="margin:6px 0">${esc(r.message)}</div>
      <div class="approval">
        <input id="req-${r.id}" class="grow" placeholder="${esc(r.kind === "file" ? "Path to the file to load…" : "Your answer…")}" value="${esc(r.suggestion || "")}" />
        <button class="small primary" onclick="submitRequest('${r.id}')">Submit</button>
        <button class="small" onclick="submitRequest('${r.id}', true)">Skip</button>
      </div></div>`).join("");
}
async function submitRequest(id, skip) {
  const answer = skip ? "" : (document.getElementById("req-" + id) || {}).value || "";
  try { await api(`/api/sessions/${state.current}/requests/${id}`, "POST", { answer }); }
  catch (e) { alert(e.message); }
}

// ---- Spider: plan approval, interjection, intensity ----
function renderPlanApprovals() {
  const el = document.getElementById("planApprovalWrap"); if (!el) return;
  const list = Object.values(state.planApprovals);
  if (!list.length) { el.innerHTML = ""; return; }
  el.innerHTML = list.map(pa => {
    const steps = ((pa.plan || {}).steps || []);
    const rows = steps.map((s, i) =>
      `<input class="grow" id="planstep-${pa.id}-${i}" value="${esc(s.text || s)}" style="margin:2px 0" />`).join("");
    return `<div class="approvals plan-approval">
      <b>📋 The orchestrator proposes a plan — approve to proceed</b>
      <div class="plan-steps">${rows || '<span class="muted">(no steps)</span>'}</div>
      <div class="approval" style="margin-top:6px">
        <input id="planfb-${pa.id}" class="grow" placeholder="Feedback (used when you reject, or as a note when you edit)…" />
        <button class="small primary" onclick="resolvePlan('${pa.id}','approve')">Approve</button>
        <button class="small" onclick="resolvePlan('${pa.id}','edit')" title="Approve with your edits to the steps above">Approve edits</button>
        <button class="small danger" onclick="resolvePlan('${pa.id}','reject')" title="Send back for revision with your feedback">Reject</button>
      </div></div>`;
  }).join("");
}
async function resolvePlan(id, decision) {
  const pa = state.planApprovals[id]; if (!pa) return;
  const feedback = (document.getElementById("planfb-" + id) || {}).value || "";
  let steps = null;
  if (decision === "edit") {
    steps = ((pa.plan || {}).steps || []).map((s, i) =>
      (document.getElementById(`planstep-${id}-${i}`) || {}).value || (s.text || s)).filter(t => t.trim());
  }
  try { await api(`/api/sessions/${state.current}/plan-approvals/${id}`, "POST", { decision, feedback, steps }); }
  catch (e) { alert(e.message); }
}
async function sendInterjection() {
  const inp = document.getElementById("interjectInput");
  const message = (inp.value || "").trim();
  if (!message) return;
  try { await api(`/api/sessions/${state.current}/interject`, "POST", { message }); inp.value = ""; }
  catch (e) { alert("Interject failed: " + e.message); }
}
async function changeIntensity() {
  const intensity = document.getElementById("intensitySelect").value;
  if (!state.current) return;
  try { await api(`/api/sessions/${state.current}/intensity`, "POST", { intensity }); state.intensity = intensity; }
  catch (e) { alert(e.message); }
}
async function toggleApprovalBypass() {
  const box = document.getElementById("bypassApproval");
  if (!state.current) { box.checked = false; alert("Open a session first."); return; }
  const mode = box.checked ? "auto" : "manual";
  try { await api(`/api/sessions/${state.current}/approval-mode`, "POST", { mode }); state.approvalMode = mode; }
  catch (e) { box.checked = !box.checked; alert(e.message); }
}

// ----------------------------------------------------------- controls
async function startSession() {
  const target = document.getElementById("targetInput").value.trim();
  const instructions = document.getElementById("instructionsInput").value.trim();
  if (!target) { alert("Enter a target."); return; }
  try { await api(`/api/sessions/${state.current}/start`, "POST", { target, instructions }); }
  catch (e) { alert("Start failed: " + e.message); }
}

// ---- reference documents (md / txt / pdf / docx) attached to the engagement ----
async function loadUploads() {
  if (!state.current) { state.uploads = []; renderUploads(); return; }
  try { state.uploads = await api(`/api/sessions/${state.current}/uploads`); }
  catch (e) { state.uploads = []; }
  renderUploads();
}
function renderUploads() {
  const el = document.getElementById("uploadsList"); if (!el) return;
  const list = state.uploads || [];
  if (!list.length) { el.innerHTML = '<span class="muted" style="font-size:11px">no reference docs attached</span>'; return; }
  el.innerHTML = list.map(u => {
    const meta = u.error
      ? `<span class="up-err" title="${esc(u.error)}">⚠ ${esc(truncate(u.error, 40))}</span>`
      : `<span class="muted">${(u.chars || 0).toLocaleString()} chars</span>`;
    return `<span class="up-chip${u.error ? " err" : ""}" title="${esc(u.name)} · ${(u.size / 1024).toFixed(0)} KB">
      📄 <b>${esc(u.name)}</b> ${meta}
      <button class="up-x" title="Remove" onclick="removeUpload('${esc(u.name)}')">✕</button></span>`;
  }).join("");
}
async function uploadFiles(inputEl) {
  const files = Array.from(inputEl.files || []);
  inputEl.value = "";
  if (!files.length) return;
  if (!state.current) { alert("Open a session first."); return; }
  for (const f of files) {
    const fd = new FormData(); fd.append("file", f);
    try {
      const res = await fetch(`/api/sessions/${state.current}/uploads`, { method: "POST", body: fd });
      if (res.status === 401) { showAuthGate(); return; }
      if (!res.ok) { let d = res.statusText; try { d = (await res.json()).detail || d; } catch (e) {} throw new Error(d); }
    } catch (e) { alert(`Upload of ${f.name} failed: ${e.message}`); }
  }
  await loadUploads();
}
async function removeUpload(name) {
  try { await api(`/api/sessions/${state.current}/uploads/${encodeURIComponent(name)}`, "DELETE"); await loadUploads(); }
  catch (e) { alert(e.message); }
}
async function resumeSession() {
  const instructions = prompt("Additional instructions for resume (optional):", "") || "";
  try { await api(`/api/sessions/${state.current}/resume`, "POST", { instructions }); } catch (e) { alert("Resume failed: " + e.message); }
}
async function stopSession() { try { await api(`/api/sessions/${state.current}/stop`, "POST", {}); } catch (e) { alert(e.message); } }
async function stopAgent(aid) { try { await api(`/api/sessions/${state.current}/agents/${aid}/stop`, "POST", {}); } catch (e) { alert(e.message); } }
async function resolveApproval(id, approved) {
  let reason = ""; if (!approved) reason = prompt("Reason for denial (optional):", "") || "";
  try { await api(`/api/sessions/${state.current}/approvals/${id}`, "POST", { approved, reason }); } catch (e) { alert(e.message); }
}
function viewPrompt(aid) {
  const a = state.agents[aid]; if (!a) return;
  document.getElementById("promptAgentName").textContent = `${a.role} (${a.name})`;
  document.getElementById("promptTask").textContent = a.task ? "Task: " + a.task : "";
  document.getElementById("promptBody").textContent = a.system_prompt || "(prompt not captured)";
  document.getElementById("promptModal").classList.remove("hidden");
}
function closePrompt() { document.getElementById("promptModal").classList.add("hidden"); }

// ----------------------------------------------------------- session report
function openReport() {
  if (!state.current) { alert("Select a session first."); return; }
  document.getElementById("reportStatus").textContent = "";
  document.getElementById("reportModal").classList.remove("hidden");
}
function closeReport() { document.getElementById("reportModal").classList.add("hidden"); }
function closeReportResult() { document.getElementById("reportResultModal").classList.add("hidden"); }
async function generateReport() {
  const instructions = document.getElementById("reportInstr").value;
  const template = document.getElementById("reportTemplate").value;
  const btn = document.getElementById("reportGenBtn");
  const status = document.getElementById("reportStatus");
  btn.disabled = true; status.style.color = "var(--muted)";
  status.textContent = "Generating… a report-writer agent is running (watch the agent tree).";
  try {
    const r = await api(`/api/sessions/${state.current}/report`, "POST", { instructions, template });
    state.lastReport = r.report || "";
    state.lastDocxName = r.docx_name || "";
    document.getElementById("reportBody").textContent = state.lastReport;
    document.getElementById("reportPath").textContent = r.path || "";
    // Word output: show the Download .docx button if it was produced, else note why it was skipped.
    const dbtn = document.getElementById("downloadDocxBtn");
    dbtn.style.display = r.docx_name ? "" : "none";
    if (r.docx_error) { status.style.color = "var(--yellow)"; status.textContent = "⚠ .docx skipped: " + r.docx_error; }
    closeReport();
    document.getElementById("reportResultModal").classList.remove("hidden");
  } catch (e) {
    status.style.color = "var(--red)"; status.textContent = "✗ " + e.message;
  } finally { btn.disabled = false; }
}
async function uploadReportTemplate(inputEl) {
  const f = (inputEl.files || [])[0]; inputEl.value = "";
  if (!f || !state.current) return;
  const st = document.getElementById("reportTemplateStatus");
  st.style.color = "var(--muted)"; st.textContent = `extracting ${f.name}…`;
  const fd = new FormData(); fd.append("file", f);
  try {
    const res = await fetch(`/api/sessions/${state.current}/report/template`, { method: "POST", body: fd });
    if (res.status === 401) { showAuthGate(); return; }
    if (!res.ok) { let d = res.statusText; try { d = (await res.json()).detail || d; } catch (e) {} throw new Error(d); }
    const r = await res.json();
    document.getElementById("reportTemplate").value = r.text || "";
    st.style.color = "var(--green)";
    st.textContent = `✓ ${r.name} — ${(r.chars || 0).toLocaleString()} chars extracted (review/edit below)` + (r.error ? ` · note: ${r.error}` : "");
  } catch (e) { st.style.color = "var(--red)"; st.textContent = "✗ " + e.message; }
}
function copyReport() {
  navigator.clipboard.writeText(state.lastReport || "").catch(() => {});
}
function downloadReport() {
  const blob = new Blob([state.lastReport || ""], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `spider-report-${(state.session && state.session.name) || "session"}.md`;
  a.click(); URL.revokeObjectURL(a.href);
}
function downloadDocx() {
  if (!state.lastDocxName || !state.current) return;
  // Served by the backend (binary); same-origin GET carries the auth cookie.
  const a = document.createElement("a");
  a.href = `/api/sessions/${state.current}/report/file/${encodeURIComponent(state.lastDocxName)}`;
  a.download = state.lastDocxName;
  a.click();
}

// ----------------------------------------------------------- settings overlay
function openSettings() { document.getElementById("configOverlay").classList.remove("hidden"); setSettingsTab("general"); loadConfig(); }
function closeSettings() { document.getElementById("configOverlay").classList.add("hidden"); }
function setSettingsTab(name) {
  document.querySelectorAll(".settings-tabs button").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".settings-page").forEach(p => p.classList.toggle("hidden", p.dataset.page !== name));
}
async function loadConfig() {
  state.config = await api("/api/config");
  await loadPresets();   // presets feed the per-agent model selectors
  await loadSkills();    // skills feed the per-agent skill pickers
  renderConfig();
  await loadRoles(); await loadAgentDefs(); await loadTools();
  await loadUsers();     // admin-only Users tab (Settings is admin-only anyway)
}

// ---- model parameter presets ----
async function loadPresets() { state.presets = await api("/api/presets"); renderPresets(); }
function renderPresets() {
  const el = document.getElementById("presetsConfig"); if (!el) return;
  const names = Object.keys(state.presets || {});
  if (!names.length) { el.innerHTML = '<div class="config-role muted">No presets yet. Use “Save as preset…” on any agent below.</div>'; return; }
  el.innerHTML = `<div class="config-role"><table><tr><th>preset</th><th>provider / model</th><th></th></tr>` +
    names.map(n => { const p = state.presets[n]; return `<tr>
      <td><b style="color:var(--purple)">${esc(n)}</b></td>
      <td class="muted" style="font-size:11px">${esc(p.provider || "")} / ${esc(p.model || "")}</td>
      <td><button class="small danger" onclick="deletePreset('${esc(n)}')">Delete</button></td></tr>`; }).join("") + `</table></div>`;
}
// Parse a single model-config input's raw string value into its typed value (shared by save and
// the connection test, so the test uses exactly what's typed on screen).
function parseModelValue(key, v) {
  if (key === "max_tokens" || key === "max_turns") return parseInt(v) || 0;
  if (key === "max_tool_size" || key === "request_timeout" || key === "max_retries") return Math.max(0, parseInt(v) || 0);
  if (key === "stop") return v.trim() ? v.split(",").map(s => s.trim()).filter(Boolean) : [];
  if (NUM_KEYS.includes(key)) return v.trim() === "" ? null : parseFloat(v);
  if (key === "thinking_budget") return parseInt(v) || 8000;
  if (key === "verify_ssl") return (v === "true" || v === true);
  if (key === "param_overrides") {
    const map = {}; v.split(",").map(s => s.trim()).filter(Boolean).forEach(pair => {
      const i = pair.indexOf("="); if (i > 0) map[pair.slice(0, i).trim()] = pair.slice(i + 1).trim(); });
    return map;
  }
  return v;
}
// The current on-screen model config for one role (typed values), regardless of what's saved.
function readModelInputs(role) {
  const out = {};
  document.querySelectorAll(`[data-role="${role}"][data-key]`).forEach(el => {
    out[el.dataset.key] = parseModelValue(el.dataset.key, el.value);
  });
  return out;
}
// Sync the per-agent model inputs from the DOM back into state.config.models.
function gatherModels() {
  const c = state.config;
  document.querySelectorAll("[data-role]").forEach(el => {
    const role = el.dataset.role, key = el.dataset.key; if (!key) return;
    (c.models[role] = c.models[role] || {})[key] = parseModelValue(key, el.value);
  });
}
function applyPreset(role) {
  const name = document.getElementById("presetsel-" + role).value;
  if (!name || !state.presets[name]) return;
  gatherModels(); // keep other agents' edits
  state.config.models[role] = Object.assign({}, state.config.models[role], state.presets[name]);
  renderConfig();
  document.getElementById("presetsel-" + role).value = name;
}
async function saveAsPreset(role) {
  const name = prompt(`Save ${role}'s current parameters as a preset named:`, "");
  if (!name) return;
  gatherModels();
  try { state.presets = await api(`/api/presets/${encodeURIComponent(name.trim())}`, "PUT", { params: state.config.models[role] }); renderPresets(); renderConfig(); }
  catch (e) { alert(e.message); }
}
async function deletePreset(name) {
  if (!confirm(`Delete preset '${name}'?`)) return;
  try { state.presets = await api(`/api/presets/${encodeURIComponent(name)}`, "DELETE"); renderPresets(); renderConfig(); }
  catch (e) { alert(e.message); }
}

// ---- agent skills (markdown playbooks edited in the skills/ folder) ----
async function loadSkills() { const r = await api("/api/skills"); state.skills = r.skills || []; state.skillMaster = r.master || ""; }
// Resolve each skill's load mode for a role (mirrors the backend: dict form, legacy list, default).
function skillModes(role) {
  const raw = (state.config.agent_skills || {})[role];
  const modes = {};
  (state.skills || []).forEach(s => {
    if (raw && !Array.isArray(raw) && typeof raw === "object") modes[s.name] = raw[s.name] || "optional";
    else if (Array.isArray(raw)) modes[s.name] = raw.includes(s.name) ? "always" : "optional";
    else modes[s.name] = "optional";
  });
  return modes;
}
function skillsPickerHtml(role) {
  if (!(state.skills || []).length) return '<div class="muted" style="font-size:11px">No skills found in the skills/ folder.</div>';
  const modes = skillModes(role);
  const opt = (v, cur) => `<option value="${v}" ${cur === v ? "selected" : ""}>${({ always: "always load", optional: "may load (agent decides)", never: "never load" })[v]}</option>`;
  return `<div class="skill-grid">` + state.skills.map(s => `
    <div class="skill-pick" title="${esc(s.description)}">
      <div><b>${esc(s.title || s.name)}</b><br><span class="sk-desc">${esc(s.description || s.name)}</span></div>
      <select data-skill-role="${role}" data-skill="${esc(s.name)}" onchange="setSkillMode('${role}','${esc(s.name)}',this.value)">
        ${opt("always", modes[s.name])}${opt("optional", modes[s.name])}${opt("never", modes[s.name])}
      </select>
    </div>`).join("") + `</div>`;
}
function setSkillMode(role, skill, mode) {
  const m = state.config.agent_skills = state.config.agent_skills || {};
  let cur = m[role];
  if (!cur || Array.isArray(cur)) cur = m[role] = skillModes(role);  // materialise full dict on first edit
  cur[skill] = mode;
}

// ---- internal tools catalog (read-only; add new ones in spider/tools/custom.py) ----
async function loadTools() { state.tools = await api("/api/tools"); renderTools(); }
function renderTools() {
  const groups = {};
  (state.tools || []).forEach(t => { (groups[t.source] = groups[t.source] || []).push(t); });
  const el = document.getElementById("toolsConfig");
  if (!el) return;
  el.innerHTML = Object.entries(groups).map(([source, tools]) => `
    <div class="config-role"><h4>${esc(source)} <span class="muted" style="font-weight:normal;font-size:11px">(${tools.length})</span></h4>
      <table class="tools-table"><tr><th>tool</th><th>category</th><th>description</th><th>params</th></tr>
      ${tools.map(t => `<tr>
        <td><b style="color:var(--accent)">${esc(t.name)}</b>${t.requires_approval ? ' <span class="badge">always gated</span>' : ""}</td>
        <td><code>${esc(t.category || "control")}</code></td>
        <td class="muted" style="font-size:11px">${esc(t.description)}</td>
        <td class="muted" style="font-size:11px">${Object.keys(t.parameters || {}).map(p =>
          (t.required || []).includes(p) ? `<b>${esc(p)}</b>` : esc(p)).join(", ") || "—"}</td>
      </tr>`).join("")}</table></div>`).join("");
}

const NUM_KEYS = ["temperature", "top_p", "top_k", "frequency_penalty", "presence_penalty", "seed"];

// Tool-approval policy editor (Spider). One row per category -> auto/manual.
const TOOL_CATEGORIES = ["control", "filesystem", "shell", "recon", "enum", "web",
                         "exploit", "bruteforce", "destructive", "network", "mcp"];
function renderToolApproval() {
  const c = state.config;
  const pol = c.tool_approval = c.tool_approval || { default: "manual", by_category: {}, always_manual_tools: [], always_auto_tools: [] };
  const def = document.getElementById("toolApprovalDefault"); if (def) def.value = pol.default || "manual";
  const el = document.getElementById("toolApprovalConfig"); if (!el) return;
  const byc = pol.by_category || {};
  el.innerHTML = `<div class="config-role"><table class="tools-table"><tr><th>category</th><th>when an agent uses a tool in this category…</th></tr>` +
    TOOL_CATEGORIES.map(cat => {
      const v = byc[cat] || pol.default || "manual";
      return `<tr><td><code>${cat}</code></td><td>
        <select data-cat="${cat}">
          <option value="auto"${v === "auto" ? " selected" : ""}>auto — run immediately</option>
          <option value="manual"${v === "manual" ? " selected" : ""}>manual — ask the operator first</option>
        </select></td></tr>`;
    }).join("") + `</table></div>`;
}

function renderConfig() {
  const c = state.config;
  document.getElementById("approvalMode").value = c.approval_mode || "manual";
  document.getElementById("maxContextTokens").value = c.max_context_tokens || 800000;
  const lim = c.limits || {};
  document.getElementById("limMaxChildren").value = lim.max_children_per_agent == null ? 5 : lim.max_children_per_agent;
  document.getElementById("limMaxTotal").value = lim.max_total_agents == null ? 15 : lim.max_total_agents;
  document.getElementById("limMaxDepth").value = lim.max_spawn_depth == null ? 3 : lim.max_spawn_depth;
  // Human-in-the-loop + Kali + intensity (Spider)
  const hitl = c.human_in_the_loop || {};
  document.getElementById("planApproval").value = hitl.plan_approval || "once";
  document.getElementById("blockOnPlan").checked = hitl.block_on_plan_approval !== false;
  document.getElementById("allowInterject").checked = hitl.allow_interjection !== false;
  document.getElementById("defaultIntensity").value = c.default_intensity || "normal";
  document.getElementById("pocExecution").value = c.poc_execution || "kali_only";
  const kali = c.kali || {};
  document.getElementById("kaliEnabled").checked = !!kali.enabled;
  document.getElementById("kaliUrl").value = kali.url || "";
  document.getElementById("kaliToken").value = kali.token || "";
  document.getElementById("outputFilterEnabled").checked = (c.output_filter || {}).enabled !== false;
  const cp = c.client_proxy || {}, kp = c.kali_proxy || {};
  document.getElementById("clientProxyEnabled").checked = !!cp.enabled;
  document.getElementById("clientProxyUrl").value = cp.url || "";
  document.getElementById("clientProxyNoProxy").value = (cp.no_proxy || []).join("\n");
  document.getElementById("kaliProxyEnabled").checked = !!kp.enabled;
  document.getElementById("kaliProxyUrl").value = kp.url || "";
  document.getElementById("kaliProxyNoProxy").value = (kp.no_proxy || []).join("\n");
  renderToolApproval();
  const opt = (cur, vals) => vals.map(v => `<option ${cur === v ? "selected" : ""}>${v}</option>`).join("");
  const num = (role, key, m) => `<label>${key}<input data-role="${role}" data-key="${key}" type="number" step="any" value="${m[key] == null ? "" : m[key]}"></label>`;
  const presetNames = Object.keys(state.presets || {});
  const presetOpts = `<option value="">— preset —</option>` + presetNames.map(n => `<option>${esc(n)}</option>`).join("");
  document.getElementById("modelsConfig").innerHTML = Object.entries(c.models).map(([role, m]) => `
    <div class="config-role"><h4>${esc(role)}
      <span class="toolbar" style="display:inline-flex;margin:0 0 0 10px;font-weight:normal;vertical-align:middle">
        <select id="presetsel-${role}" style="height:26px">${presetOpts}</select>
        <button class="small" onclick="applyPreset('${role}')">Apply</button>
        <button class="small" onclick="saveAsPreset('${role}')">Save as preset…</button>
        <button class="small" onclick="testLLM('${role}')" title="Send a 'hello' to this model and show the reply">Test connection</button>
      </span></h4>
      <div id="llmTest-${role}" class="llm-test"></div>
      <div class="config-grid">
      <label>provider<select data-role="${role}" data-key="provider">${opt(m.provider, ["anthropic", "openai", "mock"])}</select></label>
      <label>model<input data-role="${role}" data-key="model" value="${esc(m.model)}"></label>
      <label>api_key<span class="secret-wrap"><input data-role="${role}" data-key="api_key" type="text" class="secret"
        name="spider_key_${role}" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"
        data-lpignore="true" data-1p-ignore data-form-type="other" value="${esc(m.api_key || "")}"
        ><button type="button" class="reveal" title="show/hide — reveal before copying" onclick="toggleSecret(this)">👁</button></span></label>
      <label>base_url<input data-role="${role}" data-key="base_url" value="${esc(m.base_url || "")}"></label>
      <label title="Verify the LLM endpoint's TLS certificate. Set false ONLY for a self-signed/local endpoint or a TLS-intercepting proxy — it disables cert checking for this model.">verify_ssl<select data-role="${role}" data-key="verify_ssl">${opt(String(m.verify_ssl !== false), ["true", "false"])}</select></label>
      <label>max_tokens<input data-role="${role}" data-key="max_tokens" type="number" value="${m.max_tokens}"></label>
      <label>max_turns<input data-role="${role}" data-key="max_turns" type="number" value="${m.max_turns}"></label>
      <label title="Max tools given to this model. If exceeded, a tool_selector agent picks the best subset. 0 = unlimited."
        >max_tool_size<input data-role="${role}" data-key="max_tool_size" type="number" min="0" value="${m.max_tool_size == null ? 0 : m.max_tool_size}"></label>
      <label title="Seconds to wait for an LLM response before timing out.">request_timeout (s)<input data-role="${role}" data-key="request_timeout" type="number" min="0" value="${m.request_timeout == null ? 300 : m.request_timeout}"></label>
      <label title="How many times to retry a failed LLM call.">max_retries<input data-role="${role}" data-key="max_retries" type="number" min="0" value="${m.max_retries == null ? 2 : m.max_retries}"></label>
      <label>thinking<select data-role="${role}" data-key="thinking">${opt(m.thinking, ["off", "adaptive", "enabled"])}</select></label>
      <label>thinking_budget<input data-role="${role}" data-key="thinking_budget" type="number" value="${m.thinking_budget || 8000}"></label>
      <label>thinking_display<select data-role="${role}" data-key="thinking_display">${opt(m.thinking_display, ["summarized", "omitted"])}</select></label>
      <label>effort<select data-role="${role}" data-key="effort">${opt(m.effort || "", ["", "low", "medium", "high", "xhigh", "max"])}</select></label>
      ${num(role, "temperature", m)}${num(role, "top_p", m)}${num(role, "top_k", m)}
      ${num(role, "frequency_penalty", m)}${num(role, "presence_penalty", m)}${num(role, "seed", m)}
      <label>stop (comma)<input data-role="${role}" data-key="stop" value="${esc((m.stop || []).join(","))}"></label>
      <label class="wide" title="Rename or drop outgoing API params, e.g. max_tokens=max_completion_tokens. Empty right side drops the param."
        >param renames (old=new, comma)<input data-role="${role}" data-key="param_overrides"
        placeholder="max_tokens=max_completion_tokens"
        value="${esc(Object.entries(m.param_overrides || {}).map(([k, v]) => k + "=" + v).join(", "))}"></label>
    </div></div>`).join("");
  renderPricing();
}
function renderPricing() {
  const c = state.config;
  const rows = Object.entries(c.pricing).map(([model, p]) => `
    <tr><td>${esc(model)}</td>
    <td><input data-price="${esc(model)}" data-key="input" type="number" step="0.01" value="${p.input}" style="width:80px"></td>
    <td><input data-price="${esc(model)}" data-key="output" type="number" step="0.01" value="${p.output}" style="width:80px"></td>
    <td><input data-price="${esc(model)}" data-key="cache_read" type="number" step="0.01" value="${p.cache_read}" style="width:80px"></td>
    <td><input data-price="${esc(model)}" data-key="cache_write" type="number" step="0.01" value="${p.cache_write}" style="width:80px"></td>
    <td><button class="small danger" onclick="removePricing('${esc(model)}')">✕</button></td></tr>`).join("");
  document.getElementById("pricingConfig").innerHTML =
    `<table><tr><th>model</th><th>input</th><th>output</th><th>cache read</th><th>cache write</th><th></th></tr>${rows}</table>`;
}
// Sync edited price inputs back into state.config.pricing (so edits survive a re-render).
function gatherPricing() {
  const c = state.config;
  document.querySelectorAll("[data-price]").forEach(el => {
    const model = el.dataset.price, key = el.dataset.key;
    (c.pricing[model] = c.pricing[model] || { input: 0, output: 0, cache_read: 0, cache_write: 0 })[key] = parseFloat(el.value) || 0;
  });
}
function addPricing() {
  const name = document.getElementById("newPriceName").value.trim();
  const status = document.getElementById("addPriceStatus");
  if (!name) { status.textContent = "enter a model name"; status.style.color = "var(--red)"; return; }
  if (state.config.pricing[name]) { status.textContent = "model already exists"; status.style.color = "var(--red)"; return; }
  gatherPricing(); // keep edits to existing rows
  const f = id => parseFloat(document.getElementById(id).value) || 0;
  state.config.pricing[name] = { input: f("newPriceInput"), output: f("newPriceOutput"), cache_read: f("newPriceCacheRead"), cache_write: f("newPriceCacheWrite") };
  renderPricing();
  ["newPriceName"].forEach(id => document.getElementById(id).value = "");
  status.textContent = "✓ added — click Save to persist"; status.style.color = "var(--green)";
  setTimeout(() => status.textContent = "", 3000);
}
function removePricing(model) {
  if (!confirm(`Remove pricing for '${model}'?`)) return;
  gatherPricing();
  delete state.config.pricing[model];
  renderPricing();
}

// ---- custom agents ----
async function loadRoles() {
  const r = await api("/api/roles");
  state.roles = r.roles; state.availableTools = r.available_tools;
  renderRoles();
}
function renderRoles() {
  const el = document.getElementById("rolesConfig");
  el.innerHTML = `<div class="config-role"><table><tr><th>agent</th><th>type</th><th>tools</th><th></th></tr>` +
    Object.entries(state.roles || {}).map(([role, s]) => `<tr>
      <td><b style="color:var(--purple)">${esc(role)}</b></td>
      <td>${s.builtin ? "built-in" : "custom"}</td>
      <td class="muted" style="font-size:11px">${esc((s.tools || []).join(", "))}</td>
      <td>${s.builtin ? "" : `<button class="small danger" onclick="removeRole('${role}')">Remove</button>`}</td>
    </tr>`).join("") + `</table>
    <div class="muted" style="font-size:11px;margin-top:6px">Available tools: ${esc((state.availableTools || []).join(", "))}</div></div>`;
}
async function addRole() {
  const role = document.getElementById("newRoleName").value.trim();
  const system = document.getElementById("newRolePrompt").value.trim();
  const toolsRaw = document.getElementById("newRoleTools").value.trim();
  const tools = toolsRaw ? toolsRaw.split(",").map(s => s.trim()).filter(Boolean) : [];
  const status = document.getElementById("addRoleStatus");
  try {
    await api("/api/roles", "POST", { role, system, tools });
    document.getElementById("newRoleName").value = ""; document.getElementById("newRolePrompt").value = ""; document.getElementById("newRoleTools").value = "";
    status.textContent = "✓ added"; status.style.color = "var(--green)"; setTimeout(() => status.textContent = "", 2500);
    await loadConfig();
  } catch (e) { status.textContent = "✗ " + e.message; status.style.color = "var(--red)"; }
}
async function removeRole(role) {
  if (!confirm(`Remove custom agent '${role}'?`)) return;
  try { await api(`/api/roles/${role}`, "DELETE"); await loadConfig(); } catch (e) { alert(e.message); }
}

// ---- agent prompts + per-folder MCP manager ----
async function loadAgentDefs() { state.agentDefs = await api("/api/agentdefs"); renderAgentDefs(); }
function renderAgentDefs() {
  document.getElementById("agentDefsConfig").innerHTML = (state.agentDefs || []).map((d, i) => `
    <div class="config-role"><h4>${esc(d.role)} ${d.builtin ? "" : '<span class="badge" style="color:var(--purple)">custom</span>'}
      <span class="muted" style="font-weight:normal;font-size:11px">${esc(d.dir)}</span></h4>
      <label class="muted" style="font-size:11px">system prompt</label>
      <textarea id="adef-prompt-${i}" style="min-height:100px;font-family:ui-monospace,monospace">${esc(d.prompt)}</textarea>
      <div class="toolbar" style="margin-top:6px">
        <button class="primary small" onclick="saveAgentDef(${i})">Save prompt</button>
        <span id="adef-status-${i}" class="muted" style="font-size:11px"></span>
      </div>
      <div class="muted" style="font-size:11px;margin-top:8px;text-transform:uppercase;letter-spacing:.5px">Skills (optional · edit content in skills/ · saved with “Save”)</div>
      ${skillsPickerHtml(d.role)}
      <div class="muted" style="font-size:11px;margin-top:8px;text-transform:uppercase;letter-spacing:.5px">MCP servers (inherited by sub-agents)</div>
      <div id="servers-${d.role}">${serversHtml(d.role, d.servers || [])}</div>
      <div class="config-grid" style="margin-top:6px">
        <label>server name<input id="newsrv-name-${d.role}" placeholder="e.g. ghidra" /></label>
      </div>
      <label class="muted" style="font-size:11px;display:block;margin-top:4px">paste JSON config (single server, or a full {"mcpServers": {...}} block)</label>
      <textarea id="newsrv-cfg-${d.role}" style="min-height:60px;font-family:ui-monospace,monospace" placeholder='{"command": "python", "args": ["bridge_mcp_ghidra.py"]}'></textarea>
      <div class="toolbar" style="margin-top:6px"><button class="small primary" onclick="mcpAdd('${d.role}')">+ Add MCP server</button>
        <span id="newsrv-status-${d.role}" class="muted" style="font-size:11px"></span></div>
    </div>`).join("");
}
function serversHtml(role, servers) {
  if (!servers.length) return '<div class="muted" style="font-size:11px">No MCP servers.</div>';
  return servers.map(s => `<div class="cmd" style="display:flex;justify-content:space-between;align-items:center;gap:8px">
    <span><b style="color:var(--accent)">${esc(s.name)}</b> <span class="muted">${esc(s.transport)} ${esc(s.command || s.url)}</span> ${s.enabled ? "" : '<span class="badge stopped">disabled</span>'}</span>
    <span>
      <button class="small" onclick="mcpToggle('${role}','${esc(s.name)}',${!s.enabled})">${s.enabled ? "Disable" : "Enable"}</button>
      <button class="small" onclick="mcpTest('${role}','${esc(s.name)}')">Test</button>
      <button class="small danger" onclick="mcpRemove('${role}','${esc(s.name)}')">Remove</button>
      <span id="mcptest-${role}-${esc(s.name)}" class="muted" style="font-size:11px"></span>
    </span></div>`).join("");
}
function refreshServers(role, servers) {
  const d = (state.agentDefs || []).find(x => x.role === role);
  if (d) d.servers = servers;
  const box = document.getElementById("servers-" + role);
  if (box) box.innerHTML = serversHtml(role, servers);
}
async function mcpAdd(role) {
  const name = document.getElementById("newsrv-name-" + role).value.trim();
  const config = document.getElementById("newsrv-cfg-" + role).value.trim();
  const status = document.getElementById("newsrv-status-" + role);
  if (!config) { status.textContent = "paste a JSON config"; return; }
  try {
    const servers = await api(`/api/agentdefs/${role}/mcp`, "POST", { name, config });
    refreshServers(role, servers);
    document.getElementById("newsrv-name-" + role).value = ""; document.getElementById("newsrv-cfg-" + role).value = "";
    status.textContent = "✓ added"; status.style.color = "var(--green)"; setTimeout(() => status.textContent = "", 2000);
  } catch (e) { status.textContent = "✗ " + e.message; status.style.color = "var(--red)"; }
}
async function mcpToggle(role, name, enabled) {
  try { refreshServers(role, await api(`/api/agentdefs/${role}/mcp/${encodeURIComponent(name)}/toggle`, "POST", { enabled })); } catch (e) { alert(e.message); }
}
async function mcpRemove(role, name) {
  try { refreshServers(role, await api(`/api/agentdefs/${role}/mcp/${encodeURIComponent(name)}`, "DELETE")); } catch (e) { alert(e.message); }
}
async function mcpTest(role, name) {
  const el = document.getElementById(`mcptest-${role}-${name}`);
  if (el) { el.textContent = "testing…"; el.style.color = "var(--muted)"; }
  try {
    const r = await api(`/api/agentdefs/${role}/mcp/${encodeURIComponent(name)}/test`, "POST", {});
    if (el) {
      el.textContent = r.ok ? `✓ ${r.tools.length} tools` : "✗ " + (r.error || "failed");
      el.style.color = r.ok ? "var(--green)" : "var(--red)";
    }
  } catch (e) { if (el) { el.textContent = "✗ " + e.message; el.style.color = "var(--red)"; } }
}
// Probe the Kali offensive-tool server from Settings → Kali. Tests the URL currently typed
// in the box (no need to save first); shows the discovered tool count or the failure reason.
async function testKali() {
  const el = document.getElementById("kaliTestStatus");
  const url = document.getElementById("kaliUrl").value.trim();
  const token = document.getElementById("kaliToken").value;
  if (el) { el.textContent = "testing…"; el.style.color = "var(--muted)"; }
  try {
    const r = await api("/api/config/kali/test", "POST", { url, token });
    if (el) {
      if (r.ok) {
        el.textContent = `✓ connected — ${r.count} tools (${r.tools.slice(0, 4).join(", ")}${r.tools.length > 4 ? "…" : ""})`;
        el.style.color = "var(--green)";
      } else {
        el.textContent = "✗ " + (r.error || "failed");
        el.style.color = "var(--red)";
      }
    }
  } catch (e) { if (el) { el.textContent = "✗ " + e.message; el.style.color = "var(--red)"; } }
}
async function testLLM(role) {
  const el = document.getElementById(`llmTest-${role}`);
  if (el) el.innerHTML = '<span class="muted">testing… (sending “hello”)</span>';
  // Send the CURRENT on-screen model config (typed values), so the test reflects unsaved edits —
  // not just what's persisted. A blank api_key is ignored server-side (the saved key is used).
  const params = readModelInputs(role);
  try {
    const r = await api("/api/config/llm/test", "POST", { role, params });
    if (!el) return;
    if (r.ok) {
      el.innerHTML = `<div class="ok">✓ ${esc(r.model)} replied${r.via_proxy ? " (via proxy)" : ""}</div>`
        + `<pre>${esc(r.reply || "")}</pre>`;
    } else {
      // Show the WHOLE error (HTTP status + the provider's full response body + traceback).
      el.innerHTML = `<div class="err">✗ LLM test failed${r.model ? " (" + esc(r.model) + ")" : ""}${r.via_proxy ? " — via proxy" : ""}</div>`
        + `<pre class="err">${esc(r.error || "failed")}</pre>`;
    }
  } catch (e) {
    if (el) el.innerHTML = `<div class="err">✗ request failed</div><pre class="err">${esc(e.message || e)}</pre>`;
  }
}
async function saveAgentDef(i) {
  const d = state.agentDefs[i];
  const prompt = document.getElementById(`adef-prompt-${i}`).value;
  const status = document.getElementById(`adef-status-${i}`);
  try {
    await api(`/api/agentdefs/${d.role}`, "PUT", { prompt });
    d.prompt = prompt;
    status.textContent = "✓ saved"; status.style.color = "var(--green)"; setTimeout(() => status.textContent = "", 2500);
  } catch (e) { status.textContent = "✗ " + e.message; status.style.color = "var(--red)"; }
}
function toggleSecret(btn) {
  const inp = btn.previousElementSibling;
  if (inp) { inp.classList.toggle("secret"); btn.classList.toggle("on"); }
}
// HTTP headers (api_key, base_url) must be ASCII. Catch copy-paste artifacts like the
// mask glyph '•' (U+2022) before they get persisted and cause cryptic request errors.
function badHeaderChars(s) {
  s = String(s || "");
  for (const ch of s) if (ch.charCodeAt(0) > 127) return ch;
  return null;
}
async function saveConfig() {
  const c = state.config;
  c.approval_mode = document.getElementById("approvalMode").value;
  c.max_context_tokens = parseInt(document.getElementById("maxContextTokens").value) || 800000;
  c.limits = c.limits || {};
  c.limits.max_children_per_agent = Math.max(0, parseInt(document.getElementById("limMaxChildren").value) || 0);
  c.limits.max_total_agents = Math.max(1, parseInt(document.getElementById("limMaxTotal").value) || 15);
  c.limits.max_spawn_depth = Math.max(1, parseInt(document.getElementById("limMaxDepth").value) || 3);
  // Human-in-the-loop + intensity + Kali (Spider)
  c.human_in_the_loop = c.human_in_the_loop || {};
  c.human_in_the_loop.plan_approval = document.getElementById("planApproval").value;
  c.human_in_the_loop.block_on_plan_approval = document.getElementById("blockOnPlan").checked;
  c.human_in_the_loop.allow_interjection = document.getElementById("allowInterject").checked;
  c.default_intensity = document.getElementById("defaultIntensity").value;
  c.poc_execution = document.getElementById("pocExecution").value;
  c.kali = c.kali || {};
  c.kali.enabled = document.getElementById("kaliEnabled").checked;
  c.kali.url = document.getElementById("kaliUrl").value.trim();
  c.kali.token = document.getElementById("kaliToken").value;
  if (!c.kali.assign_roles) c.kali.assign_roles = ["recon", "web_app", "network", "exploitation", "post_exploit"];
  c.output_filter = c.output_filter || {};
  c.output_filter.enabled = document.getElementById("outputFilterEnabled").checked;
  // Outbound proxies (client + kali). no_proxy is one host per line.
  const lines = id => document.getElementById(id).value.split("\n").map(s => s.trim()).filter(Boolean);
  c.client_proxy = {
    enabled: document.getElementById("clientProxyEnabled").checked,
    url: document.getElementById("clientProxyUrl").value.trim(),
    no_proxy: lines("clientProxyNoProxy"),
  };
  c.kali_proxy = {
    enabled: document.getElementById("kaliProxyEnabled").checked,
    url: document.getElementById("kaliProxyUrl").value.trim(),
    no_proxy: lines("kaliProxyNoProxy"),
  };
  // Tool-approval policy
  const pol = c.tool_approval = c.tool_approval || { by_category: {}, always_manual_tools: [], always_auto_tools: [] };
  pol.default = document.getElementById("toolApprovalDefault").value;
  pol.by_category = pol.by_category || {};
  document.querySelectorAll("[data-cat]").forEach(s => { pol.by_category[s.dataset.cat] = s.value; });
  gatherModels();  // sync per-agent model inputs (skills already tracked in state.config.agent_skills)
  gatherPricing();
  // Reject non-ASCII in header-bound fields (a common copy-paste artifact, e.g. the '•' mask).
  for (const [role, m] of Object.entries(c.models)) {
    for (const f of ["api_key", "base_url"]) {
      const bad = badHeaderChars(m[f]);
      if (bad) {
        const cp = "U+" + bad.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0");
        alert(`${role} ${f} contains a non-ASCII character (${cp}${bad === "•" ? " — the mask glyph; you copied the hidden field" : ""}). ` +
          `Use the 👁 reveal toggle to copy the real value, then re-enter it. Not saved.`);
        return;
      }
    }
  }
  await api("/api/config", "PUT", c);
  const saved = document.getElementById("configSaved");
  saved.textContent = "✓ saved (applies to new sessions)"; setTimeout(() => saved.textContent = "", 3000);
}

// ----------------------------------------------------------- auth gate
async function initAuth() {
  let st;
  try { st = await fetch("/api/auth/status").then(r => r.json()); }
  catch (e) { st = { authenticated: false, needs_setup: false }; }
  if (st.authenticated && st.user) bootApp(st.user);
  else showAuthForms(st.needs_setup);
}
function showAuthForms(needsSetup) {
  document.getElementById("authOverlay").classList.remove("hidden");
  document.getElementById("authSetup").classList.toggle("hidden", !needsSetup);
  document.getElementById("authLogin").classList.toggle("hidden", needsSetup);
  const f = document.getElementById(needsSetup ? "setupUser" : "loginUser");
  if (f) setTimeout(() => f.focus(), 50);
}
async function showAuthGate() {
  // Called on a 401 (token expired/revoked). Re-check setup state and show the gate.
  state.user = null;
  let st; try { st = await fetch("/api/auth/status").then(r => r.json()); } catch (e) { st = { needs_setup: false }; }
  showAuthForms(st.needs_setup);
}
function bootApp(user) {
  state.user = user;
  document.getElementById("authOverlay").classList.add("hidden");
  applyUserUI(user);
  loadSessions();
  startSessionPoll();   // admins: keep the all-users session list live
}
function applyUserUI(user) {
  document.getElementById("userLabel").textContent = `${user.username} · ${user.role}`;
  // Global Settings (config + user management) is admin-only. The server enforces this; the
  // UI simply hides the entry points for regular users.
  const isAdmin = user.role === "admin";
  const sa = document.getElementById("settingsAction"); if (sa) sa.style.display = isAdmin ? "" : "none";
  const ut = document.querySelector('.settings-tabs [data-tab="users"]'); if (ut) ut.style.display = isAdmin ? "" : "none";
}
async function doLogin() {
  const username = document.getElementById("loginUser").value.trim();
  const password = document.getElementById("loginPass").value;
  const err = document.getElementById("loginErr"); err.textContent = "";
  try {
    const r = await api("/api/auth/login", "POST", { username, password });
    document.getElementById("loginPass").value = "";
    bootApp(r.user);
  } catch (e) { err.textContent = e.message || "login failed"; }
}
async function doSetup() {
  const username = document.getElementById("setupUser").value.trim();
  const password = document.getElementById("setupPass").value;
  const confirm = document.getElementById("setupPass2").value;
  const err = document.getElementById("setupErr"); err.textContent = "";
  if (password !== confirm) { err.textContent = "passwords do not match"; return; }
  try {
    const r = await api("/api/auth/setup", "POST", { username, password });
    bootApp(r.user);
  } catch (e) { err.textContent = e.message || "setup failed"; }
}
async function doLogout() {
  try { await api("/api/auth/logout", "POST", {}); } catch (e) {}
  stopSessionPoll();
  state.current = null; state.session = null; state.user = null;
  if (state.ws) { try { state.ws.close(); } catch (e) {} }
  document.getElementById("sessionView").classList.add("hidden");
  document.getElementById("noSession").classList.remove("hidden");
  closeSettings();
  showAuthForms(false);
}

// ----------------------------------------------------------- users (admin only)
async function loadUsers() {
  try { state.users = await api("/api/users"); } catch (e) { state.users = []; }
  renderUsers();
}
function renderUsers() {
  const el = document.getElementById("usersConfig"); if (!el) return;
  const me = state.user || {};
  const rows = (state.users || []).map(u => `
    <tr>
      <td><b>${esc(u.username)}</b>${u.id === me.id ? ' <span class="muted">(you)</span>' : ""}</td>
      <td><code>${esc(u.role)}</code></td>
      <td>${u.disabled ? '<span class="badge">disabled</span>' : '<span class="muted">active</span>'}</td>
      <td>
        <button class="small" onclick="resetUserPassword('${u.id}','${esc(u.username)}')">Reset password</button>
        ${u.id === me.id ? "" : `<button class="small" onclick="toggleUserDisabled('${u.id}',${u.disabled ? "false" : "true"})">${u.disabled ? "Enable" : "Disable"}</button>
        <button class="small danger" onclick="removeUser('${u.id}','${esc(u.username)}')">Delete</button>`}
      </td>
    </tr>`).join("");
  el.innerHTML = `<div class="config-role"><table class="tools-table">
    <tr><th>username</th><th>role</th><th>status</th><th>actions</th></tr>${rows}</table></div>`;
}
async function addUser() {
  const username = document.getElementById("newUserName").value.trim();
  const password = document.getElementById("newUserPass").value;
  const role = document.getElementById("newUserRole").value;
  const st = document.getElementById("addUserStatus"); st.textContent = "";
  try {
    await api("/api/users", "POST", { username, password, role });
    document.getElementById("newUserName").value = "";
    document.getElementById("newUserPass").value = "";
    st.textContent = "✓ added"; await loadUsers();
  } catch (e) { st.textContent = "✕ " + (e.message || "failed"); }
}
async function removeUser(uid, name) {
  if (!confirm(`Delete user "${name}"? Their sessions remain but become visible to admins only.`)) return;
  try { await api(`/api/users/${uid}`, "DELETE"); await loadUsers(); }
  catch (e) { alert(e.message || "delete failed"); }
}
async function resetUserPassword(uid, name) {
  const password = prompt(`New password for "${name}" (min 8 characters):`);
  if (!password) return;
  try { await api(`/api/users/${uid}/password`, "POST", { password }); alert("password updated"); }
  catch (e) { alert(e.message || "failed"); }
}
async function toggleUserDisabled(uid, disabled) {
  try { await api(`/api/users/${uid}/disable`, "POST", { disabled }); await loadUsers(); }
  catch (e) { alert(e.message || "failed"); }
}

// ----------------------------------------------------------- init
initAuth();
