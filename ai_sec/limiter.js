function createLimiter(cfg) {
  const hits = [];
  return { check(userId, tokens, now) {
    if (tokens > cfg.maxTokensPerRequest) return { allow: false, code: "TOO_LARGE" };
    const recent = hits.filter((t) => now - t < 60000);
    if (recent.length >= cfg.maxRequestsPerMin) return { allow: false, code: "RATE_LIMIT" };
    hits.push(now); return { allow: true };
  } };
}
module.exports = { createLimiter };
