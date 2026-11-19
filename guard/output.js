// Mission 3-B — 출력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   redactPII(text)       : 휴대전화 · 주민등록번호 · 카드번호 · 이메일을 가린다 (주문번호 · 금액 · 날짜는 그대로)
//   redactSecrets(text)   : API 키 · 접속 문자열 · 비공개 키 · 내부 주소 등을 [SECRET] 으로 바꾼다
//   sanitizeOutput(text)  : 사용자에게 보낼 최종 문자열 (HTML 이스케이프 + 위 두 가지)
//   validateAction(raw, ctx): LLM 이 낸 문자열(raw)을 검증한다.
//        통과 → { ok: true, text, calls: [{ name, args }] } / 거절 → { ok: false, code }
//   LLM 출력은 '신뢰할 수 없는 입력'이다. 허용 목록 · 형식 · 범위를 코드로 확인한다.


// Mission 3-B — 출력 단계 방어

function redactPII(text) {
  let s = String(text);

  // 주민등록번호
  s = s.replace(/\b\d{6}-[1-4]\d{6}\b/g, (v) =>
    `${v.slice(0, 6)}-${v[7]}******`
  );

  // 휴대전화: 하이픈, 공백, 점이 있는 형식과 숫자만 있는 형식
  s = s.replace(/(?<!\d)01[016789][-. ]?\d{3,4}[-. ]?\d{4}(?!\d)/g, (v) => {
    const digits = v.replace(/\D/g, "");
    return `${digits.slice(0, 3)}-****-${digits.slice(-4)}`;
  });

  // 카드번호: 13~19자리이며 Luhn 검사를 통과한 경우만 마스킹
  const luhnValid = (digits) => {
    let sum = 0;
    let doubleDigit = false;

    for (let i = digits.length - 1; i >= 0; i--) {
      let n = Number(digits[i]);
      if (doubleDigit) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      doubleDigit = !doubleDigit;
    }
    return sum % 10 === 0;
  };

  s = s.replace(/(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g, (v) => {
    const digits = v.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) {
      return v;
    }
    return `****-****-****-${digits.slice(-4)}`;
  });

  // 이메일
  s = s.replace(
    /\b([A-Z0-9._%+-]+)@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi,
    (_, local, domain) => `${local[0]}***@${domain}`
  );

  return s;
}

function redactSecrets(text) {
  let s = String(text);

  // 개인키
  s = s.replace(
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    "[SECRET]"
  );

  // AWS Access Key
  s = s.replace(/\bAKIA[A-Z0-9]{16}\b/g, "[SECRET]");

  // Live API Key
  s = s.replace(/\bsk[-_]live[-_][A-Za-z0-9]{12,}\b/g, "[SECRET]");

  // JWT
  s = s.replace(
    /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    "[SECRET]"
  );

  // 접속 문자열의 사용자명과 비밀번호
  s = s.replace(
    /\b([a-z][a-z0-9+.-]*:\/\/[^:/\s]+:)[^@\s]+(@[^/\s]+)/gi,
    "$1[SECRET]$2"
  );

  // 내부 키 및 관리자 우회 코드
  s = s.replace(/\bINTERNAL-KEY-[A-Za-z0-9_-]+\b/gi, "[INTERNAL]");
  s = s.replace(/\bADMIN-\d+\b/gi, "[INTERNAL]");

  // 내부 주소
  s = s.replace(
    /\b(?:[a-z0-9-]+\.)+[a-z0-9-]+\.internal\b/gi,
    "[INTERNAL]"
  );

  return s;
}

function sanitizeOutput(text) {
  let s = String(text);

  // HTML 특수문자 이스케이프
  s = s.replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[ch]);

  return redactSecrets(redactPII(s));
}

function validateAction(raw, ctx) {
  let parsed;

  try {
    parsed = JSON.parse(String(raw));
  } catch {
    return { ok: false, code: "FORMAT" };
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).some((k) => !["text", "tool_calls"].includes(k)) ||
    typeof parsed.text !== "string" ||
    parsed.text.length > 2000
  ) {
    return { ok: false, code: "FORMAT" };
  }

  const calls = parsed.tool_calls === undefined ? [] : parsed.tool_calls;

  if (!Array.isArray(calls)) {
    return { ok: false, code: "FORMAT" };
  }

  if (calls.length > 3) {
    return { ok: false, code: "TOO_MANY_CALLS" };
  }

  const validArgs = (name, args) => {
    if (!args || typeof args !== "object" || Array.isArray(args)) {
      return false;
    }

    const keys = Object.keys(args);

    switch (name) {
      case "search_product":
        return (
          keys.length === 1 &&
          keys[0] === "query" &&
          typeof args.query === "string" &&
          args.query.length >= 1 &&
          args.query.length <= 50 &&
          /^[\p{L}\p{N} -]+$/u.test(args.query)
        );

      case "get_order_status":
      case "refund_order":
        return (
          keys.length === 1 &&
          keys[0] === "order_id" &&
          typeof args.order_id === "string" &&
          /^ORD-\d{4}$/.test(args.order_id)
        );

      case "apply_coupon":
        return (
          keys.length === 2 &&
          keys.includes("code") &&
          keys.includes("percent") &&
          typeof args.code === "string" &&
          /^[A-Z0-9]{4,12}$/.test(args.code) &&
          Number.isInteger(args.percent) &&
          args.percent >= 1 &&
          args.percent <= 100
        );

      default:
        return null;
    }
  };

  const allowed = [
    "search_product",
    "get_order_status",
    "apply_coupon",
    "refund_order"
  ];

  const checkedCalls = [];

  for (const call of calls) {
    if (
      !call ||
      typeof call !== "object" ||
      Array.isArray(call) ||
      Object.keys(call).some((k) => !["name", "args"].includes(k)) ||
      typeof call.name !== "string"
    ) {
      return { ok: false, code: "ARG_INVALID" };
    }

    if (!allowed.includes(call.name)) {
      return { ok: false, code: "TOOL_NOT_ALLOWED" };
    }

    if (validArgs(call.name, call.args) !== true) {
      return { ok: false, code: "ARG_INVALID" };
    }

    checkedCalls.push({
      name: call.name,
      args: call.args
    });
  }

  return {
    ok: true,
    text: parsed.text,
    calls: checkedCalls
  };
}

module.exports = {
  redactPII,
  redactSecrets,
  sanitizeOutput,
  validateAction
};
