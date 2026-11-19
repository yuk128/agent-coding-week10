// 균형 점수 = (문제를 잡는 비율) × (정상을 건드리지 않는 비율).
// 아무것도 안 막는 구현(잡는 비율 0)이나 전부 막는 구현(정상 통과 비율 0)은 모두 0점이 된다.
function balanced(items) {
  const pos = items.filter((i) => i.kind === "pos"), neg = items.filter((i) => i.kind === "neg");
  const mean = (a) => a.reduce((s, i) => s + i.score, 0) / a.length;
  if (!pos.length || !neg.length) return mean(items.length ? items : [{ score: 0 }]);
  return mean(pos) * mean(neg);
}
module.exports = { balanced };
