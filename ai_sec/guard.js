// AI 가 작성했다고 가정한 가드레일 (초안). 데모는 통과하지만 허점이 많다. — 리뷰 대상
function normalizeText(t) { return String(t).trim(); }
function inspectInput(text) {
  if (String(text).length > 3000) return { action: "block", codes: ["TOO_LONG"], text };
  if (/시스템\s*프롬프트|system prompt|ignore (all )?previous/i.test(text)) return { action: "block", codes: ["INJECTION"], text };
  return { action: "allow", codes: [], text };
}
function wrapUntrusted(text) { return `<<UNTRUSTED\n${text}\nUNTRUSTED>>`; }
const ALLOWED = ["search_product", "get_order_status", "apply_coupon", "refund_order"];
function validateAction(raw) {
  let j; try { j = JSON.parse(raw); } catch { return { ok: false, code: "FORMAT" }; }
  const calls = j.tool_calls || [];
  if (calls.length > 10 || calls.some((c) => !ALLOWED.includes(c.name))) return { ok: false, code: "TOOL_NOT_ALLOWED" };
  return { ok: true, text: j.text, calls };
}
function authorizeTool(call, ctx) {
  if (call.name === "get_order_status") return ctx.orders.ownerOf(call.args.order_id) === ctx.user.id ? { decision: "allow" } : { decision: "deny", reason: "NOT_OWNER" };
  if (call.name === "apply_coupon" || call.name === "refund_order") return { decision: "confirm" };
  return { decision: "allow" };
}
function redactPII(t) { return String(t).replace(/\b01\d-\d{4}-\d{4}\b/g, "***-****-****").replace(/[\w.+-]+@[\w-]+\.[\w.]+/g, "***@***"); }
function redactSecrets(t) { return String(t).replace(/sk-live-\w+/g, "[SECRET]").replace(/INTERNAL-KEY-\w+/g, "[SECRET]"); }
function sanitizeOutput(t) { return redactSecrets(redactPII(t)); }
module.exports = { normalizeText, inspectInput, wrapUntrusted, validateAction, authorizeTool, redactPII, redactSecrets, sanitizeOutput };
