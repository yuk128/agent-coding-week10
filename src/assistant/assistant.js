// 도우미 파이프라인 (수정 금지). 신뢰 경계를 따라 guard 함수들을 호출한다.
//   요청 → [킬스위치] → [한도] → [입력 검사] → 외부 문서 감싸기 → 모의 LLM → [출력 검증] → [도구 인가] → 실행 → [출력 필터] → 응답 · 로그
const { generate } = require("../../sim/mockLlm");
const { WRITE_TOOLS, createExecutor } = require("./tools");

function createAssistant({ guard, limiter, killswitch, world, buildSystemPrompt, env = {} }) {
  const exec = createExecutor(world);
  const logs = [];
  function handle(req) {
    const { user, text = "", docs = [], confirmed = [], staffApproved = [], now = 0 } = req;
    const r = { reply: "", blocked: null, executed: [], pending: [], denied: [], events: [], llmCalled: false, llmInputChars: 0, logs: [] };
    const ev = (type, code, extra = {}) => r.events.push({ ts: now, userId: user.id, type, code, ...extra });
    const done = () => {
      const rec = { ts: now, userId: user.id, input: guard.redactSecrets(guard.redactPII(text)), blocked: r.blocked, executed: r.executed.map((e) => e.name), pending: r.pending.map((e) => e.name) };
      logs.push(rec); r.logs.push(rec); return r;
    };
    if (!killswitch.isEnabled("assistant")) { r.blocked = "KILLED"; r.reply = "현재 AI 도우미를 일시 중단했습니다."; return done(); }
    const tokens = Math.ceil(text.length / 2) + docs.reduce((s, d) => s + Math.ceil(d.text.length / 2), 0);
    const lim = limiter.check(user.id, tokens, now);
    if (!lim.allow) { r.blocked = lim.code; r.reply = "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요."; ev("RATE_LIMITED", lim.code, { tokens }); return done(); }
    const ins = guard.inspectInput(text, { channel: "user", user });
    if (ins.action === "block") { r.blocked = (ins.codes || ["BLOCKED"])[0]; r.reply = "이 요청은 처리할 수 없습니다."; ev("INPUT_BLOCKED", r.blocked); return done(); }
    const accepted = [];
    for (const d of docs) {
      const di = guard.inspectInput(d.text, { channel: "document", user });
      if (di.action === "block") { ev("DOC_QUARANTINED", (di.codes || ["BLOCKED"])[0], { source: d.source }); continue; }
      accepted.push(d);
    }
    const prompt = { system: buildSystemPrompt(env), user: typeof ins.text === "string" ? ins.text : text, context: accepted.map((d) => guard.wrapUntrusted(d.text)) };
    r.llmCalled = true;
    r.llmInputChars = prompt.user.length + prompt.context.reduce((s, c) => s + c.length, 0);
    const raw = generate(prompt, world.sessionNotes(user.id));
    const v = guard.validateAction(raw, { user });
    if (!v || !v.ok) { r.blocked = (v && v.code) || "FORMAT"; r.reply = "응답을 안전하게 처리하지 못했습니다."; ev("FORMAT_REJECTED", r.blocked); return done(); }
    const out = [v.text || ""].filter(Boolean);
    const tainted = accepted.length > 0;
    (v.calls || []).forEach((call, idx) => {
      const isWrite = WRITE_TOOLS.includes(call.name);
      let d = guard.authorizeTool(call, { user, orders: world.orders, tainted, callIndex: idx }) || { decision: "deny", reason: "NO_DECISION" };
      if (isWrite && d.decision !== "deny" && !killswitch.isEnabled("assistant.write_tools")) d = { decision: "deny", reason: "KILLED" };
      const run = () => {
        const entry = { tool: call.name, args: call.args, userId: user.id, owners: [], via: d.decision, confirmed: confirmed.includes(call.name), staff: staffApproved.includes(call.name) };
        world.ledger.push(entry); // 실행기에 '도달한' 호출은 모두 기록한다 (오류가 나도 기록)
        let res;
        try { res = exec[call.name] ? exec[call.name](call.args) : { message: "알 수 없는 도구", owners: [] }; }
        catch (e) { res = { message: "도구 실행 중 오류가 발생했습니다.", owners: [] }; ev("TOOL_ERROR", call.name); }
        entry.owners = res.owners;
        r.executed.push({ name: call.name, args: call.args, owners: res.owners });
        out.push(res.message); ev("TOOL_EXECUTED", call.name);
      };
      if (d.decision === "allow") run();
      else if (d.decision === "confirm") { if (confirmed.includes(call.name)) run(); else { r.pending.push({ name: call.name, need: "user" }); out.push(`확인이 필요합니다: ${call.name}`); } }
      else if (d.decision === "approve") { if (confirmed.includes(call.name) && staffApproved.includes(call.name)) run(); else { r.pending.push({ name: call.name, need: "staff" }); out.push(`담당자 승인이 필요합니다: ${call.name}`); } }
      else { r.denied.push({ name: call.name, reason: d.reason }); ev("AUTHZ_DENY", d.reason || "DENY", { tool: call.name }); out.push("해당 작업은 수행할 수 없습니다."); }
    });
    const rawReply = out.join("\n");
    r.reply = guard.sanitizeOutput(rawReply);
    if (guard.redactSecrets(rawReply) !== rawReply) ev("SECRET_IN_OUTPUT", "SECRET");
    return done();
  }
  return { handle, logs };
}
module.exports = { createAssistant };
