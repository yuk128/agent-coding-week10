// Mission 3-C — 도구 호출 인가 (docs/SEC_CONTRACT.md §3.4 의 표)
//   authorizeTool(call, ctx) → { decision: "allow" | "confirm" | "approve" | "deny", reason }
//   call = { name, args }, ctx = { user, orders: { ownerOf(orderId) }, tainted, callIndex }
//   allow: 바로 실행 / confirm: 사용자 확인 후 실행 / approve: 사용자 확인 + 담당자 승인 / deny: 거부
//   소유자 · 한도 같은 '권한 규칙'은 프롬프트가 아니라 여기서 코드로 집행한다.

function authorizeTool(call, ctx) {
  switch (call.name) {
    case "search_product": return { decision: "allow" }; // 예시: 공개 데이터, 읽기 전용
    // TODO: get_order_status, apply_coupon, refund_order …
    default: return { decision: "deny", reason: "TOOL_NOT_ALLOWED" };
  }
}

module.exports = { authorizeTool };
