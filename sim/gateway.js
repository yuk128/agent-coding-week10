// 모의 결제 게이트웨이: 어떤 키로 호출됐는지 기록한다. (키가 비어 있으면 거절)
function createGateway(expectedKey) {
  const calls = [];
  return {
    calls,
    charge({ apiKey, amount, orderId }) {
      calls.push({ apiKey, amount, orderId });
      if (!apiKey) throw new Error("gateway: missing api key");
      if (!(amount > 0)) throw new Error("gateway: invalid amount");
      return { ok: true };
    },
  };
}
module.exports = { createGateway };
