// Mission 3-A — 입력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   normalizeText(text)      : 모델이 읽는 방식과 같게 글자를 정리한다 (전각 → 반각, 보이지 않는 문자 제거 …)
//   inspectInput(text, ctx)  : { action: "allow" | "block", codes: [...], text } 를 돌려준다. ctx.channel 은 "user" | "document"
//   wrapUntrusted(text)      : 외부 문서를 '데이터'로 가둔다. 형식은 계약서의 구분자 규칙을 따른다.
// 주의: 필터는 보조 수단이다. 정상 사용자를 막지 않도록 '확실한 패턴'만 차단한다.

function normalizeText(text) {
  // TODO
  return String(text);
}

function inspectInput(text, ctx = {}) {
  // TODO: 길이 상한, 확실한 공격 패턴, 구분자 위조 등
  return { action: "allow", codes: [], text: String(text) };
}

function wrapUntrusted(text) {
  // TODO
  return String(text);
}

module.exports = { normalizeText, inspectInput, wrapUntrusted };
