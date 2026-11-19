#!/usr/bin/env node
// 도우미에게 한 문장을 보내 본다. 사용: node scripts/demo.js "ORD-1002 상태 알려줘" [--user u1] [--doc "문서 내용"] [--baseline] [--confirm 도구이름]
const path = require("path");
const root = path.resolve(__dirname, "..");
const { run } = require("../sim/runner");
const a = process.argv.slice(2);
const opt = (n) => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : null; };
const text = a.find((x, i) => !x.startsWith("--") && !["--user", "--doc", "--confirm"].includes(a[i - 1]));
if (!text) { console.log('사용: node scripts/demo.js "문장" [--user u1|u2|u3] [--doc "외부 문서 내용"] [--baseline] [--confirm apply_coupon]'); process.exit(0); }
let guard, buildSystemPrompt;
if (a.includes("--baseline")) { guard = require("../sim/baseline/guard"); buildSystemPrompt = require("../sim/baseline/systemPrompt").buildSystemPrompt; }
else { guard = { ...require(path.join(root, "guard/input")), ...require(path.join(root, "guard/output")), ...require(path.join(root, "guard/authz")) }; buildSystemPrompt = require(path.join(root, "src/assistant/systemPrompt")).buildSystemPrompt; }
const scn = { user: opt("--user") || "u1", text, kind: "attack", docs: opt("--doc") ? [{ source: "external", text: opt("--doc") }] : [], confirmed: opt("--confirm") ? [opt("--confirm")] : [] };
const r = run(scn, { guard, buildSystemPrompt });
if (r.error) { console.log("오류:", r.error); process.exit(1); }
console.log(a.includes("--baseline") ? "[기준선: 방어 없음]" : "[우리 팀 방어]");
console.log("응답     :", JSON.stringify(r.res.reply));
console.log("실행됨   :", r.res.executed.map((e) => `${e.name}(${JSON.stringify(e.args)})`).join(", ") || "없음");
console.log("승인대기 :", r.res.pending.map((e) => `${e.name}←${e.need}`).join(", ") || "없음");
console.log("거부됨   :", r.res.denied.map((e) => `${e.name}(${e.reason})`).join(", ") || "없음");
console.log("차단     :", r.res.blocked || "없음");
console.log("로그     :", JSON.stringify(r.res.logs[0].input));
console.log("피해     :", r.harms.length ? r.harms.join(", ") : "없음 ✔");
