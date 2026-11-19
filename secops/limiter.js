// Mission 4-B — 한도 (docs/SEC_CONTRACT.md §4.2)
//   createLimiter(cfg) → { check(userId, tokens, now) → { allow: true } | { allow: false, code } }
//   code: TOO_LARGE | RATE_LIMIT | BUDGET
function createLimiter(cfg) {
  return {
    check(userId, tokens, now) {
      // TODO
      return { allow: true };
    },
  };
}
module.exports = { createLimiter };
