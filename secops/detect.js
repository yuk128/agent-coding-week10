// Mission 4-A — 보안 이벤트 탐지 (docs/SEC_CONTRACT.md §4.1)
//   detect(events, now) → [{ id, severity, userId? }]
//   events = [{ ts(ms), type, userId, code?, tokens? }]
//   type: INPUT_BLOCKED | DOC_QUARANTINED | AUTHZ_DENY | LOGIN_FAIL | SECRET_IN_OUTPUT | TOKENS_USED …
//   임계값은 config/sec.json 의 detect 항목을 쓴다. 숫자를 코드에 흩어 두지 않는다.
const CFG = require("../config/sec.json");

// 창은 (now − 창길이, now] : 시작 시각은 제외, 끝(now)은 포함
function inWindow(ev, now, windowSec) {
  return ev.ts > now - windowSec * 1000 && ev.ts <= now;
}

// 조건에 맞는 이벤트를 사용자별로 세어서, count 이상인 사용자마다 경보를 낸다
function perUser(events, now, rule, matches, id, severity) {
  const counts = new Map();
  for (const ev of events) {
    if (!inWindow(ev, now, rule.windowSec) || !matches(ev)) continue;
    counts.set(ev.userId, (counts.get(ev.userId) || 0) + 1);
  }
  const out = [];
  for (const [userId, n] of counts) if (n >= rule.count) out.push({ id, severity, userId });
  return out;
}

function detect(events, now) {
  const evs = Array.isArray(events) ? events : [];
  const d = CFG.detect;
  const alerts = [];

  // 사용자별: 차단 · 격리 합계 (프롬프트 인젝션 시도)
  alerts.push(...perUser(evs, now, d.injectionProbe,
    (e) => e.type === "INPUT_BLOCKED" || e.type === "DOC_QUARANTINED", "INJECTION_PROBE", "medium"));

  // 사용자별: 남의 주문 접근 거부 (주문번호 순회)
  alerts.push(...perUser(evs, now, d.orderEnumeration,
    (e) => e.type === "AUTHZ_DENY" && e.code === "NOT_OWNER", "ORDER_ENUMERATION", "high"));

  // 대상 계정별: 로그인 실패 반복
  alerts.push(...perUser(evs, now, d.bruteForce,
    (e) => e.type === "LOGIN_FAIL", "BRUTE_FORCE", "high"));

  // 전체: 응답에 비밀 값이 나간 이벤트는 1건만 있어도 경보 (userId 없음)
  const secretCount = d.secretInOutput.count || 1;
  const secrets = evs.filter((e) => e.type === "SECRET_IN_OUTPUT" && inWindow(e, now, d.secretInOutput.windowSec));
  if (secrets.length >= secretCount) alerts.push({ id: "SECRET_IN_OUTPUT", severity: "critical" });

  // 전체: 24시간 토큰 사용량. 100% 면 BUDGET_100 만, 80% 이상 100% 미만이면 BUDGET_80
  const budget = CFG.limiter.dailyTokenBudget;
  const used = evs
    .filter((e) => e.type === "TOKENS_USED" && inWindow(e, now, d.budget.windowSec))
    .reduce((sum, e) => sum + (Number(e.tokens) || 0), 0);
  if (used >= budget) alerts.push({ id: "BUDGET_100", severity: "critical" });
  else if (used >= budget * d.budget.warnRatio) alerts.push({ id: "BUDGET_80", severity: "medium" });

  return alerts;
}
module.exports = { detect };