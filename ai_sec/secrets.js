function scanSecrets(files) {
  const out = [];
  const rules = [["API_KEY_LIVE", /sk-live-\w+/], ["AWS_ACCESS_KEY", /AKIA[0-9A-Z]{16}/], ["DB_URL_CREDENTIALS", /:\/\/\w+:[^@\s]+@/], ["HARDCODED_SECRET", /(secret|password|token)\w*\s*[:=]\s*["'].+["']/i]];
  for (const f of files) f.text.split("\n").forEach((l, i) => { for (const [t, re] of rules) if (re.test(l)) { out.push({ path: f.path, line: i + 1, type: t }); break; } });
  return out;
}
module.exports = { scanSecrets };
