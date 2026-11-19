// Mission 3-B — 출력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   redactPII(text)       : 휴대전화 · 주민등록번호 · 카드번호 · 이메일을 가린다 (주문번호 · 금액 · 날짜는 그대로)
//   redactSecrets(text)   : API 키 · 접속 문자열 · 비공개 키 · 내부 주소 등을 [SECRET] 으로 바꾼다
//   sanitizeOutput(text)  : 사용자에게 보낼 최종 문자열 (HTML 이스케이프 + 위 두 가지)
//   validateAction(raw, ctx): LLM 이 낸 문자열(raw)을 검증한다.
//        통과 → { ok: true, text, calls: [{ name, args }] } / 거절 → { ok: false, code }
//   LLM 출력은 '신뢰할 수 없는 입력'이다. 허용 목록 · 형식 · 범위를 코드로 확인한다.

function redactPII(text) {
  // TODO
  return String(text);
}

function redactSecrets(text) {
  // TODO
  return String(text);
}

function sanitizeOutput(text) {
  // TODO
  return String(text);
}

function validateAction(raw, ctx) {
  // TODO: 지금은 모든 출력을 거절한다(안전하게 실패). 허용 규칙을 구현하세요.
  return { ok: false, code: "TODO" };
}

module.exports = { redactPII, redactSecrets, sanitizeOutput, validateAction };
