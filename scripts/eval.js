#!/usr/bin/env node
// 사용: node scripts/eval.js [redteam|code|scanner|guard|secops|all] [--dir ai_sec] [--json]
const path = require("path");
const { runAll, print } = require("../sim/eval");
const args = process.argv.slice(2);
const di = args.indexOf("--dir");
const what = args.find((a, i) => !a.startsWith("--") && i !== di + 1) || "all";
const res = runAll(path.resolve(__dirname, ".."), { dir: di >= 0 ? args[di + 1] : null });
if (args.includes("--json")) console.log(JSON.stringify(res, null, 2));
else print(res, what);
