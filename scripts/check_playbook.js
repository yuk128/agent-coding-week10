#!/usr/bin/env node
// 대응 절차(secops/playbook.json) 완결성 점검
const fs = require("fs"), path = require("path");
const { checkPlaybook, SEV } = require("../sim/eval/secops");
const f = path.resolve(__dirname, "..", process.argv[2] || "secops/playbook.json");
let pb; try { pb = JSON.parse(fs.readFileSync(f, "utf8")); } catch (e) { console.log("읽기 실패:", e.message); process.exit(1); }
const r = checkPlaybook(pb);
console.log(`대응 절차 완결성: ${(r.score * 100).toFixed(0)}%  (경보 ${Object.keys(SEV).length}종)`);
r.problems.forEach((p) => console.log("  ✘ " + p));
process.exit(r.score >= 1 ? 0 : 1);
