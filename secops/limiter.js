// Mission 4-B — 한도 (docs/SEC_CONTRACT.md §4.2)
//   createLimiter(cfg) → { check(userId, tokens, now) → { allow: true } | { allow: false, code } }
//   code: TOO_LARGE | RATE_LIMIT | BUDGET
//   검사 순서: ① 요청 크기 → ② 분당 횟수 → ③ 일일 예산. 거절된 요청은 횟수·예산을 소모하지 않는다.
const DAY_MS = 86400000;

function createLimiter(cfg) {
  const allowedByUser = new Map(); // 사용자별: 허용된 요청 시각 목록
  const usedByDay = new Map();     // 날짜(floor(now/86400000))별: 허용된 토큰 합계(전체 사용자 합산)

  return {
    check(userId, tokens, now) {
      const t = Number(tokens) || 0;

      // ① 한 번에 너무 큰 요청
      if (t > cfg.maxTokensPerRequest) return { allow: false, code: "TOO_LARGE" };

      // ② 최근 60초(now-60000 < 시각 <= now)에 허용된 요청 수
      const recent = (allowedByUser.get(userId) || []).filter((x) => x > now - 60000 && x <= now);
      if (recent.length >= cfg.maxRequestsPerMin) return { allow: false, code: "RATE_LIMIT" };

      // ③ 오늘 허용된 토큰 합계 + 이번 요청 > 일일 예산 (날짜가 바뀌면 새 칸에서 0부터)
      const day = Math.floor(now / DAY_MS);
      const used = usedByDay.get(day) || 0;
      if (used + t > cfg.dailyTokenBudget) return { allow: false, code: "BUDGET" };

      // 허용된 요청만 기록한다 (거절은 아무것도 소모하지 않음)
      recent.push(now);
      allowedByUser.set(userId, recent);
      usedByDay.set(day, used + t);
      return { allow: true };
    },
  };
}
module.exports = { createLimiter };