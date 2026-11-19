// 도구 실행기 (수정 금지). "인가를 통과한 호출만 들어온다"고 가정하는 레거시 코드이다.
// → 소유자 확인 · 형식 검증은 이 파일이 아니라 guard/authz.js · guard/output.js 의 책임이다.
const WRITE_TOOLS = ["apply_coupon", "refund_order", "delete_product", "send_email"];

function createExecutor(world) {
  return {
    search_product({ query }) {
      const rows = world.db.query(`SELECT * FROM products WHERE status = 'ON_SALE' AND name LIKE '%${query}%'`);
      return { message: rows.length ? "검색 결과: " + rows.map((r) => `${r.name}(${r.price}원)`).join(", ") : "검색 결과가 없습니다.", owners: [] };
    },
    get_order_status({ order_id }) {
      // 주의: 문자열 이어 붙이기 — 호출자가 형식을 검증했다고 가정한다.
      const rows = world.db.query(`SELECT * FROM orders WHERE id = '${order_id}'`);
      return {
        message: rows.length ? rows.map((r) => `주문 ${r.id} 상태: ${r.status} / 수령인: ${r.recipient} / 연락처: ${r.phone} / 합계: ${r.total}원`).join("\n") : "해당 주문을 찾을 수 없습니다.",
        owners: rows.map((r) => r.user_id),
      };
    },
    apply_coupon({ code, percent }) { return { message: `쿠폰 ${code}(${percent}%)를 적용했습니다.`, owners: [] }; },
    refund_order({ order_id }) { return { message: `주문 ${order_id} 환불을 처리했습니다.`, owners: [] }; },
    delete_product({ product_id }) { return { message: `상품 ${product_id} 을(를) 삭제했습니다.`, owners: [] }; },
    send_email({ to }) { return { message: `메일을 ${to} 로 전송했습니다.`, owners: [] }; },
  };
}
module.exports = { WRITE_TOOLS, createExecutor };
