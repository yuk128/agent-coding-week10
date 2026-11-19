// 기준선(baseline): 아무 방어도 없는 가드. 레드팀이 '실제로 뚫리는 공격'을 확인하는 대상이다.
module.exports = {
  normalizeText: (t) => t,
  inspectInput: (t) => ({ action: "allow", codes: [], text: t }),
  wrapUntrusted: (t) => t,
  validateAction: (raw) => { try { const j = JSON.parse(raw); return { ok: true, text: j.text, calls: j.tool_calls || [] }; } catch { return { ok: true, text: raw, calls: [] }; } },
  authorizeTool: () => ({ decision: "allow" }),
  redactPII: (t) => t,
  redactSecrets: (t) => t,
  sanitizeOutput: (t) => t,
};
