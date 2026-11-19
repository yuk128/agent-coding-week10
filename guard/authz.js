// Mission 3-C — 도구 호출 인가 (docs/SEC_CONTRACT.md §3.4 의 표)
//   authorizeTool(call, ctx) → { decision: "allow" | "confirm" | "approve" | "deny", reason }
//   call = { name, args }, ctx = { user, orders: { ownerOf(orderId) }, tainted, callIndex }
//   allow: 바로 실행 / confirm: 사용자 확인 후 실행 / approve: 사용자 확인 + 담당자 승인 / deny: 거부
//   소유자 · 한도 같은 '권한 규칙'은 프롬프트가 아니라 여기서 코드로 집행한다.


// Mission 3-C — 도구 호출 인가

function authorizeTool(call, ctx) {
  if (!call || !call.name || !ctx || !ctx.user || !ctx.orders) {
    return { decision: "deny", reason: "INVALID_CONTEXT" };
  }

  const ownerOf = (orderId) => ctx.orders.ownerOf(orderId);
  const isOwner = (orderId) =>
    ownerOf(orderId) !== null &&
    ownerOf(orderId) === ctx.user.id;

  switch (call.name) {
    case "search_product":
      return { decision: "allow" };

    case "get_order_status":
      if (!isOwner(call.args.order_id)) {
        return { decision: "deny", reason: "NOT_OWNER" };
      }
      return { decision: "allow" };

    case "apply_coupon":
      if (ctx.tainted) {
        return { decision: "deny", reason: "TAINTED_CONTEXT" };
      }
      if (
        !Number.isInteger(call.args.percent) ||
        call.args.percent < 1 ||
        call.args.percent > 20
      ) {
        return { decision: "deny", reason: "LIMIT" };
      }
      return { decision: "confirm" };

    case "refund_order":
      if (ctx.tainted) {
        return { decision: "deny", reason: "TAINTED_CONTEXT" };
      }
      if (!isOwner(call.args.order_id)) {
        return { decision: "deny", reason: "NOT_OWNER" };
      }
      return { decision: "approve" };

    default:
      return { decision: "deny", reason: "TOOL_NOT_ALLOWED" };
  }
}

module.exports = { authorizeTool };
