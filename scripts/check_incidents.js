#!/usr/bin/env node
// 사고 분석 결과(docs/incident_findings.json)의 형식과 근거 ID 가 실제로 있는지 점검한다. (정답 채점이 아니다)
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const ROOT = ["indirect_injection", "hardcoded_secret_committed", "missing_ownership_check", "malicious_dependency", "unbounded_consumption", "pii_in_logs"];
const CTRL = ["no_data_separation", "no_taint_policy", "no_output_validation", "no_ownership_check", "no_secret_scanning", "no_least_privilege", "no_rate_limit", "no_dependency_review", "no_log_masking", "no_human_approval", "no_monitoring_alert", "no_kill_switch"];
const ACT = ["disable_write_tools", "quarantine_document", "revoke_and_rotate_key", "purge_git_history", "block_user", "fix_authz_in_code", "add_enumeration_alert", "pin_and_remove_package", "rotate_secrets_exposed_to_install", "enable_rate_limit_and_budget", "add_secret_scan_ci", "notify_affected_users", "mask_logs", "add_regression_test", "kill_switch_assistant"];
const file = path.resolve(root, process.argv[2] || "docs/incident_findings.json");
let list; try { list = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { console.log("읽기 실패:", e.message); process.exit(1); }
if (!Array.isArray(list) || !list.length) { console.log("분석 결과가 비어 있습니다. incidents/INC-S1~S3 를 분석해 채우세요."); process.exit(1); }
let bad = 0;
for (const f of list) {
  const dir = path.join(root, "incidents", f.incident || "?");
  const prob = [];
  if (!fs.existsSync(dir)) prob.push("존재하지 않는 사고 번들");
  else {
    const lines = new Set(fs.readFileSync(path.join(dir, "events.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l).id));
    const chg = new Set(JSON.parse(fs.readFileSync(path.join(dir, "changes.json"), "utf8")).map((c) => c.id));
    for (const e of f.evidence || []) if (!lines.has(e) && !chg.has(e)) prob.push(`근거 ID '${e}' 가 실제 로그 · 변경 기록에 없음`);
  }
  if (!ROOT.includes(f.rootCause)) prob.push(`rootCause 는 ${ROOT.join("|")} 중 하나`);
  if (!Array.isArray(f.failedControls) || !f.failedControls.length || f.failedControls.some((c) => !CTRL.includes(c))) prob.push("failedControls 값 확인");
  if (!Array.isArray(f.immediateActions) || !f.immediateActions.length || f.immediateActions.some((c) => !ACT.includes(c))) prob.push("immediateActions 값 확인");
  if (!Array.isArray(f.evidence) || f.evidence.length < 2) prob.push("evidence 는 2개 이상");
  console.log(`${prob.length ? "✘" : "✔"} ${f.incident}` + (prob.length ? " — " + prob.join("; ") : ""));
  if (prob.length) bad++;
}
console.log(bad ? `\n${bad}건 수정 필요` : "\n형식 점검 통과 (원인이 맞는지는 교수자 채점 · 팀 토론으로 확인)");
process.exit(bad ? 1 : 0);
