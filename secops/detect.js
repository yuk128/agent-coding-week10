// Mission 4-A — 보안 이벤트 탐지 (docs/SEC_CONTRACT.md §4.1)
//   detect(events, now) → [{ id, severity, userId? }]
//   events = [{ ts(ms), type, userId, code?, tokens? }]
//   type: INPUT_BLOCKED | DOC_QUARANTINED | AUTHZ_DENY | LOGIN_FAIL | SECRET_IN_OUTPUT | TOKENS_USED …
//   임계값은 config/sec.json 의 detect 항목을 쓴다. 숫자를 코드에 흩어 두지 않는다.
const CFG = require("../config/sec.json");

function detect(events, now) {
  const alerts = [];
  // TODO: INJECTION_PROBE, ORDER_ENUMERATION, BRUTE_FORCE, SECRET_IN_OUTPUT, BUDGET_80/BUDGET_100
  return alerts;
}
module.exports = { detect };
