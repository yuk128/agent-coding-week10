// Mission 3-A — 입력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   normalizeText(text)      : 모델이 읽는 방식과 같게 글자를 정리한다 (전각 → 반각, 보이지 않는 문자 제거 …)
//   inspectInput(text, ctx)  : { action: "allow" | "block", codes: [...], text } 를 돌려준다. ctx.channel 은 "user" | "document"
//   wrapUntrusted(text)      : 외부 문서를 '데이터'로 가둔다. 형식은 계약서의 구분자 규칙을 따른다.
// 주의: 필터는 보조 수단이다. 정상 사용자를 막지 않도록 '확실한 패턴'만 차단한다.


// Mission 3-A — 입력 단계 방어
// 기준: docs/SEC_CONTRACT.md §3.1

function normalizeText(text) {
  return String(text)
    .normalize("NFKC")
    // 제로폭 및 보이지 않는 문자 제거
    .replace(/[\u200B-\u200F\u2060-\u206F\u00AD\uFE00-\uFE0F\uFEFF]/g, "");
}

function inspectInput(text, ctx = {}) {
  const normalized = normalizeText(text);
  const codes = [];

  // 모델에 전달되는 기준으로 길이 검사
  if (normalized.length > 2000) {
    codes.push("TOO_LONG");
  }

  // 문서 격리 구분자를 직접 입력해 경계를 위조하는 시도
  if (/<<\s*UNTRUSTED|UNTRUSTED\s*>>/i.test(normalized)) {
    codes.push("UNTRUSTED_DELIMITER");
  }

  // 시스템 프롬프트 또는 초기 지시를 공개하라는 명확한 요청
  const promptDisclosure =
    /(?:시스템\s*프롬프트|초기\s*지시|system\s*prompt|initial\s*instructions?)[\s\S]{0,50}(?:출력|알려|보여|공개|print|reveal|show)/i.test(normalized) ||
    /(?:출력|알려|보여|공개|print|reveal|show)[\s\S]{0,50}(?:시스템\s*프롬프트|초기\s*지시|system\s*prompt|initial\s*instructions?)/i.test(normalized);

  // 이전 지시·명령·규칙을 무시하거나 잊으라는 명확한 요청
  const instructionOverride =
    /(?:이전|위|앞의|기존)\s*(?:모든\s*)?(?:지시|명령|규칙)을?\s*(?:모두\s*)?(?:무시|잊어)/i.test(normalized) ||
    /ignore\s+(?:all\s+)?previous\s+instructions?/i.test(normalized);

  if (promptDisclosure || instructionOverride) {
    codes.push("PROMPT_INJECTION");
  }

  return {
    action: codes.length > 0 ? "block" : "allow",
    codes,
    text: normalized,
  };
}

function wrapUntrusted(text) {
  // 먼저 정규화해 전각 문자 등으로 된 가짜 구분자도 찾는다.
  const normalized = normalizeText(text);

  // 본문 안의 구분자가 실제 경계로 해석되지 않도록 무력화한다.
  const safeBody = normalized
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  return `<<UNTRUSTED\n${safeBody}\nUNTRUSTED>>`;
}

module.exports = { normalizeText, inspectInput, wrapUntrusted };
