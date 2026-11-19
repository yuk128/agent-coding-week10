// Mission 4 평가기: 보안 관제(탐지) · 한도 · 킬스위치 · 대응 절차(플레이북)
const { balanced } = require("./balance");
const { createWorld, USERS } = require("../world");
const { createAssistant } = require("../../src/assistant/assistant");
const baseGuard = require("../baseline/guard");
const baseLimiter = require("../baseline/limiter");

function runDetect(mod, scns) {
  return scns.map((s) => {
    const now = 1_800_000_000_000;
    const events = s.events.map(([type, userId, secAgo, extra]) => ({ ts: now - secAgo * 1000, type, userId, ...(extra || {}) }));
    const e = new Set(s.expect.map((x) => x.split("|")[0]));
    const sevOf = Object.fromEntries(s.expect.map((x) => [x.split("|")[0], x.split("|")[1]]));
    let got;
    try { got = mod.detect(JSON.parse(JSON.stringify(events)), now) || []; } catch (er) { return { id: s.id, title: s.title, kind: s.expect.length ? "pos" : "neg", score: 0, detail: "오류: " + er.message.split("\n")[0] }; }
    const gk = new Map(got.map((a) => [`${a.id}:${a.userId || "-"}`, a.severity]));
    const inter = [...e].filter((k) => gk.has(k)), uni = new Set([...e, ...gk.keys()]);
    let score = uni.size === 0 ? 1 : inter.length / uni.size;
    const sevBad = inter.filter((k) => sevOf[k] && gk.get(k) !== sevOf[k]);
    if (sevBad.length) score *= 0.5;
    const missing = [...e].filter((k) => !gk.has(k)), extra = [...gk.keys()].filter((k) => !e.has(k));
    return { id: s.id, title: s.title, kind: e.size ? "pos" : "neg", score, detail: score === 1 ? (e.size ? "정확히 탐지" : "경보 없음(정상)") : [missing.length ? `놓침 ${missing}` : "", extra.length ? `오탐 ${extra}` : "", sevBad.length ? `심각도 오류 ${sevBad}` : ""].filter(Boolean).join(" / ") };
  });
}

function runLimiter(mod, scns, cfg) {
  return scns.map((s) => {
    let L; try { L = mod.createLimiter({ ...cfg, ...(s.cfg || {}) }); } catch (er) { return { id: s.id, title: s.title, kind: "pos", score: 0, detail: "오류: " + er.message.split("\n")[0] }; }
    let ok = 0; const bad = [];
    s.steps.forEach(([u, tok, t, exp], i) => {
      let r; try { r = L.check(u, tok, t); } catch (er) { r = { allow: null }; }
      const pass = exp === true ? r.allow === true : r.allow === false && r.code === exp;
      if (pass) ok++; else bad.push(`#${i + 1} 기대 ${exp === true ? "허용" : exp} / 실제 ${r.allow ? "허용" : r.code || "?"}`);
    });
    return { id: s.id, title: s.title, kind: s.steps.some((x) => x[3] !== true) ? "pos" : "neg", score: ok / s.steps.length, detail: bad.length ? bad.slice(0, 2).join(", ") : "모두 일치" };
  });
}

function runKill(mod, limiterMod) {
  const items = [];
  const t = (id, title, kind, fn) => { let ok = false, d = ""; try { ok = !!fn(); } catch (e) { d = "오류: " + e.message.split("\n")[0]; } items.push({ id, title, kind, score: ok ? 1 : 0, detail: ok ? "통과" : d || "실패" }); };
  const mk = () => mod.createKillSwitch();
  t("K1", "처음에는 모두 켜져 있다", "neg", () => { const k = mk(); return k.isEnabled("assistant") && k.isEnabled("assistant.write_tools"); });
  t("K2", "쓰기 도구만 끄면 도우미는 계속 동작", "pos", () => { const k = mk(); k.disable("assistant.write_tools", { reason: "테스트", actor: "ops1", now: 1 }); return !k.isEnabled("assistant.write_tools") && k.isEnabled("assistant"); });
  t("K3", "도우미 전체를 끄면 하위 기능도 꺼진다", "pos", () => { const k = mk(); k.disable("assistant", { reason: "사고", actor: "ops1", now: 1 }); return !k.isEnabled("assistant") && !k.isEnabled("assistant.write_tools"); });
  t("K4", "다시 켜면 복구된다", "neg", () => { const k = mk(); k.disable("assistant", { reason: "사고", actor: "ops1", now: 1 }); k.enable("assistant", { actor: "ops2", now: 2 }); return k.isEnabled("assistant") && k.isEnabled("assistant.write_tools"); });
  t("K5", "사유 · 담당자 없이 끌 수 없다", "pos", () => { const k = mk(); let n = 0; for (const o of [{ actor: "a", now: 1 }, { reason: "r", now: 1 }, {}]) { try { k.disable("assistant", o); } catch { n++; } } return n === 3 && k.isEnabled("assistant"); });
  t("K6", "감사 기록이 남는다", "pos", () => { const k = mk(); k.disable("assistant.write_tools", { reason: "쿠폰 오남용", actor: "ops1", now: 10 }); k.enable("assistant.write_tools", { actor: "ops2", now: 20 }); const a = k.audit(); return a.length === 2 && a[0].action === "disable" && a[0].feature === "assistant.write_tools" && a[0].reason === "쿠폰 오남용" && a[0].actor === "ops1" && a[0].ts === 10 && a[1].action === "enable" && a[1].actor === "ops2"; });
  const run = (kill, scn) => { const world = createWorld(); const a = createAssistant({ guard: baseGuard, world, limiter: baseLimiter.createLimiter(), killswitch: kill, buildSystemPrompt: () => "x" }); return a.handle({ user: USERS.u1, now: 0, ...scn }); };
  t("K7", "쓰기 도구 중단 중에는 확인된 쿠폰도 실행되지 않는다", "pos", () => { const k = mk(); k.disable("assistant.write_tools", { reason: "r", actor: "a", now: 1 }); const r = run(k, { text: "쿠폰 WELCOME10 적용해줘", confirmed: ["apply_coupon"] }); return r.executed.length === 0; });
  t("K8", "쓰기 도구 중단 중에도 검색은 된다", "neg", () => { const k = mk(); k.disable("assistant.write_tools", { reason: "r", actor: "a", now: 1 }); const r = run(k, { text: "마우스 검색해줘" }); return r.executed.length === 1; });
  t("K9", "도우미 중단 시 모든 요청이 차단된다", "pos", () => { const k = mk(); k.disable("assistant", { reason: "r", actor: "a", now: 1 }); const r = run(k, { text: "마우스 검색해줘" }); return r.blocked === "KILLED" && r.executed.length === 0; });
  return items;
}

const ACTIONS = ["KILL_SWITCH", "REVOKE_KEY", "BLOCK_USER", "THROTTLE", "REVIEW"];
const SEV = { INJECTION_PROBE: "medium", ORDER_ENUMERATION: "high", BRUTE_FORCE: "high", SECRET_IN_OUTPUT: "critical", BUDGET_80: "medium", BUDGET_100: "critical" };
function checkPlaybook(pb) {
  const problems = []; let ok = 0, total = 0;
  for (const [id, sev] of Object.entries(SEV)) {
    total += 4;
    const e = pb && pb[id];
    if (!e) { problems.push(`${id}: 항목 없음`); continue; }
    ok++;
    if (ACTIONS.includes(e.action)) ok++; else problems.push(`${id}: action 은 ${ACTIONS.join("/")} 중 하나`);
    if (typeof e.owner === "string" && e.owner.trim() && Number.isFinite(e.slaMin) && e.slaMin > 0) ok++; else problems.push(`${id}: owner · slaMin 필요`);
    const lim = sev === "critical" ? 15 : sev === "high" ? 60 : 240;
    const strongOk = sev !== "critical" || ["KILL_SWITCH", "REVOKE_KEY"].includes(e.action);
    if (Array.isArray(e.steps) && e.steps.filter((s) => String(s).trim().length >= 6).length >= 2 && e.slaMin <= lim && strongOk) ok++;
    else problems.push(`${id}: 절차 2단계 이상 · SLA ${lim}분 이내${sev === "critical" ? " · KILL_SWITCH/REVOKE_KEY" : ""}`);
  }
  return { score: total ? ok / total : 0, problems };
}

function run(mods, sets, cfg, playbook) {
  const out = { name: "보안 관제 · 한도 · 킬스위치", items: [] };
  const add = (label, items) => items.forEach((i) => out.items.push({ ...i, id: label + i.id }));
  let D = 0, L = 0, K = 0;
  if (mods.detect) { const it = runDetect(mods.detect, sets.detect); add("D-", it); D = balanced(it); }
  if (mods.limiter) { const it = runLimiter(mods.limiter, sets.limiter, cfg.limiter); add("L-", it); L = balanced(it); }
  if (mods.killswitch) { const it = runKill(mods.killswitch); add("K-", it); K = balanced(it); }
  const pb = checkPlaybook(playbook);
  out.parts = { detect: D, limiter: L, killswitch: K, playbook: pb.score };
  out.playbook = pb;
  out.score = 0.55 * D + 0.27 * L + 0.18 * K;
  return out;
}
module.exports = { run, checkPlaybook, ACTIONS, SEV };
