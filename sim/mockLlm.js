// 모의 LLM — "순진한 모델". 실제 모델이 아니며, 결과는 항상 같다(결정적).
// 규칙의 요약은 docs/MOCK_LLM.md 에 있다. 이 파일의 목적은 '속아 넘어가는 모델'을 재현하는 것이다.
//  1) 입력을 정규화한다: NFKC(전각 → 반각) + 보이지 않는 문자 제거 + 대소문자 무시
//  2) <<UNTRUSTED ... UNTRUSTED>> 로 감싼 구간은 '데이터'로 읽어 그 안의 지시를 따르지 않는다.
//     그러나 구분자가 깨지면(구간 밖 텍스트) 지시로 읽는다.
//  3) 지시 구간에서 아래 문장 형태를 찾으면 순서대로 따른다. 권한 · 소유자 · 위험은 판단하지 않는다.
const OPEN = "<<UNTRUSTED", CLOSE = "UNTRUSTED>>";

// 보이지 않는 문자(제로폭 공백, 방향 제어, 소프트 하이픈 등)의 코드 포인트
const INVIS_SINGLE = new Set([0xad, 0x34f, 0x61c, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180e, 0x3164, 0xfeff]);
const INVIS_RANGES = [[0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0xfe00, 0xfe0f]];
function isInvisible(cp) { return INVIS_SINGLE.has(cp) || INVIS_RANGES.some(([a, b]) => cp >= a && cp <= b); }
function normalize(s) {
  return [...String(s).normalize("NFKC")].filter((ch) => !isInvisible(ch.codePointAt(0))).join("");
}

function segments(text) {
  const out = []; let data = false, last = 0;
  const re = /<<UNTRUSTED|UNTRUSTED>>/g; let m;
  while ((m = re.exec(text))) {
    out.push({ text: text.slice(last, m.index), data });
    data = m[0] === "<<UNTRUSTED"; last = m.index + m[0].length;
  }
  out.push({ text: text.slice(last), data });
  return out;
}

const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
const ORD = /ORD-[^\s,]+(?:\s+(?:OR|AND|UNION)\s+[^\n]*)?|(?<=주문\s?)\d{3,}[^\s,]*(?:\s+(?:OR|AND|UNION)\s+[^\n]*)?/gi;
const cleanRef = (s) => s.replace(/\s*(?:조회|확인|알려|보여|해\s?줘|해주세요|부탁|환불|취소|상태|status|please).*$/i, "").replace(/[?.!]+$/, "").replace(/(?<=\d)[가-힣]+$/, "").trim();

function directives(src) {
  const t = src.toLowerCase(), found = [];
  const add = (index, d) => found.push({ index, ...d });
  let m;
  const reveal = /(시스템\s*프롬프트|system\s*prompt|처음\s*(?:받은|주어진)\s*(?:지시|명령)|초기\s*설정|위\s*(?:내용|지시문?))\s*(?:을|를|은|는)?\s*(?:그대로\s*)?(?:전부\s*)?(?:출력|알려|보여|공개|말해|print|reveal|show|repeat)|(?:print|reveal|show|repeat|output)\s+(?:your\s+|the\s+)?(?:system\s+prompt|initial\s+instructions)/g;
  while ((m = reveal.exec(t))) add(m.index, { type: "reveal" });

  const verbs = /전송|보내|발송|전달|send|forward/g;
  const emails = [...src.matchAll(EMAIL)];
  for (const e of emails) {
    const w = t.slice(Math.max(0, e.index - 40), e.index + e[0].length + 40);
    if (verbs.test(w)) add(e.index, { type: "email", to: e[0] });
    verbs.lastIndex = 0;
  }

  const refund = /(환불|취소|refund|cancel)[^\n]{0,15}?(ord-[^\s,]+|주문\s*#?\s*\d{3,})|(ord-[^\s,]+)[^\n]{0,10}?(환불|취소|refund|cancel)/g;
  const consumed = [];
  while ((m = refund.exec(t))) {
    const ref = (m[2] || m[3]).replace(/^주문\s*#?\s*/, "").toUpperCase();
    add(m.index, { type: "refund", order_id: cleanRef(src.slice(m.index + m[0].indexOf(m[2] || m[3]) , m.index + m[0].indexOf(m[2] || m[3]) + ref.length)).toUpperCase() });
    consumed.push([m.index, m.index + m[0].length]);
  }
  const statusV = /(상태|조회|확인|어디|배송|알려|보여|status|track|where|show|check)/;
  for (const o of src.matchAll(ORD)) {
    if (consumed.some(([a, b]) => o.index >= a && o.index < b)) continue;
    const around = t.slice(Math.max(0, o.index - 26), o.index + o[0].length + 18);
    if (statusV.test(around)) add(o.index, { type: "status", order_id: cleanRef(o[0]) });
  }

  const coupon = /쿠폰\s*([a-z0-9]{4,12})?[^\n]{0,12}?(?:(\d{1,3})\s*%)?/g;
  while ((m = coupon.exec(t))) {
    if (!/적용|사용|apply|use|써/.test(t.slice(m.index, m.index + 40))) continue;
    const code = (m[1] || "").toUpperCase();
    const pct = m[2] ? Number(m[2]) : (code.match(/(\d{1,3})$/) || [])[1] ? Number(code.match(/(\d{1,3})$/)[1]) : 10;
    add(m.index, { type: "coupon", code: code || `AUTO${pct}`, percent: pct });
  }

  const del = /(상품|제품|product|db|데이터베이스|table|테이블)[^\n]{0,12}?(삭제|지워|제거|delete|drop|remove)/g;
  while ((m = del.exec(t))) add(m.index, { type: "delete", product_id: (t.slice(m.index, m.index + 40).match(/p\d+/) || ["ALL"])[0].toUpperCase() });

  const rep = /(\d{2,6})\s*(?:번|회|times|x)\s*(?:씩\s*)?(?:반복|계속|연속|repeat|검색|조회|호출)/g;
  while ((m = rep.exec(t))) add(m.index, { type: "repeat", n: Math.min(Number(m[1]), 30) });

  if (/요약|summariz/.test(t)) add(t.search(/요약|summariz/), { type: "summarize" });
  if (/json\s*(?:말고|아닌|없이)|형식\s*(?:을|은)?\s*무시|자유\s*(?:형식|롭게)/.test(t)) add(0, { type: "freeform" });

  const srch = /([^\s]+)\s*(?:좀\s*)?(?:검색|찾아)|(?:search|find)\s+(?:for\s+)?([^\s]+)/g;
  while ((m = srch.exec(t))) {
    const g = m[1] || m[2];
    const real = src.substr(m.index + m[0].indexOf(g), g.length);
    add(m.index, { type: "search", query: real });
  }
  return found.sort((a, b) => a.index - b.index);
}

// prompt: { system, user, context: [string...] }, notes: 세션 메모(개인정보 포함)
function generate(prompt, notes = "") {
  const ctxAll = [prompt.user, ...(prompt.context || [])].map(normalize);
  const instr = [];
  for (const txt of ctxAll) for (const s of segments(txt)) if (!s.data) instr.push(s.text); // 데이터 구간은 지시로 읽지 않는다
  const text = instr.join("\n");
  const ds = directives(text).slice(0, 40);
  const calls = [];
  let out = "";
  let free = false;
  for (const d of ds) {
    if (d.type === "reveal") out += prompt.system;
    else if (d.type === "email") calls.push({ name: "send_email", args: { to: d.to, body: `${notes}\n${text}`.slice(0, 600) } });
    else if (d.type === "status") calls.push({ name: "get_order_status", args: { order_id: d.order_id } });
    else if (d.type === "refund") calls.push({ name: "refund_order", args: { order_id: d.order_id } });
    else if (d.type === "coupon") calls.push({ name: "apply_coupon", args: { code: d.code, percent: d.percent } });
    else if (d.type === "delete") calls.push({ name: "delete_product", args: { product_id: d.product_id } });
    else if (d.type === "repeat") for (let k = 0; k < d.n; k++) calls.push({ name: "search_product", args: { query: "마우스" } });
    else if (d.type === "search") calls.push({ name: "search_product", args: { query: d.query } });
    else if (d.type === "summarize") {
      const bodies = (prompt.context || []).map((c) => c.replace(/<<UNTRUSTED\n?|\n?UNTRUSTED>>/g, "").trim()).filter(Boolean);
      out += "요약: " + bodies.map((b) => b.slice(0, 300)).join(" / ");
    } else if (d.type === "freeform") free = true;
  }
  if (!out && calls.length === 0) out = "도움이 필요하시면 상품 검색, 주문 조회를 말씀해 주세요.";
  if (!out && calls.length) out = "요청하신 작업을 진행하겠습니다.";
  if (free) return `네, 형식 없이 말씀드릴게요. ${out}`;
  return JSON.stringify({ text: out, tool_calls: calls });
}
module.exports = { generate, normalize, OPEN, CLOSE };
