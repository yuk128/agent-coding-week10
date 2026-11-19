#!/usr/bin/env node
// Mission 5 — 보안 CI 게이트. 사용: node scripts/sec-ci.js [--dir ai_sec]
//   우리 팀 산출물에서는 통과(종료 코드 0), AI 가 만든 산출물(--dir ai_sec)에서는 실패(종료 코드 1)해야 한다.
//   임계값은 THRESHOLDS 에 한 곳으로 모은다. 아래 TODO 세 가지를 완성하세요.
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const di = process.argv.indexOf("--dir");
const DIR = di >= 0 ? process.argv[di + 1] : null;
const THRESHOLDS = { maxSecretFindings: null, maxRiskyDeps: null, maxRegressionHarms: null }; // TODO: 숫자를 정하고 이유를 주석으로 쓴다

const FILES = DIR
  ? { secrets: "secrets.js", deps: "deps.js", guard: "guard.js", prompt: "prompt.js", attacks: "attacks.json", manifest: "package.json", scan: [""] }
  : { secrets: "scanner/secrets.js", deps: "scanner/deps.js", guard: ["guard/input.js", "guard/output.js", "guard/authz.js"], prompt: "src/assistant/systemPrompt.js", attacks: "redteam/attacks.json", manifest: "package.json", scan: ["app", "src", "guard", "secops", "scanner", "config"] };
const rel = (f) => path.resolve(root, DIR ? path.join(DIR, f) : f);
const load = (f) => (Array.isArray(f) ? Object.assign({}, ...f.map((x) => require(rel(x)))) : require(rel(f)));
function listFiles() {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(js|json|md|env)$/.test(e.name)) out.push({ path: path.relative(root, p), text: fs.readFileSync(p, "utf8") }); } };
  for (const s of FILES.scan) walk(path.resolve(root, DIR ? DIR : s));
  return out;
}

// ---- 검사 1: 저장소의 시크릿 (우리 scanner/secrets.js 사용)
function checkSecrets() {
  // TODO: scanSecrets(listFiles()) 결과의 개수를 THRESHOLDS.maxSecretFindings 와 비교
  return { name: "시크릿 스캔", ok: false, detail: "TODO" };
}
// ---- 검사 2: 의존성 (package.json 의 dependencies 를 scanner/deps.js 로 검사)
function checkDeps() {
  // TODO: checkDependencies(pkg, lock, registry, cfg) 결과의 개수를 THRESHOLDS.maxRiskyDeps 와 비교 (registry: sim/registry.json, cfg: config/sec.json)
  return { name: "의존성 검사", ok: false, detail: "TODO" };
}
// ---- 검사 3: 공격 회귀 (redteam/attacks.json 을 우리 방어로 돌려 피해가 없는지)
function checkRegression() {
  // TODO: sim/runner.js 의 run() 으로 공격을 하나씩 실행하고 harms 가 있는 건수를 센다 (공격→시나리오 변환은 tests/regression.test.js 참고)
  return { name: "공격 회귀", ok: false, detail: "TODO" };
}

const results = [checkSecrets(), checkDeps(), checkRegression()];
console.log(`보안 CI 게이트${DIR ? ` (--dir ${DIR})` : ""}`);
for (const r of results) console.log(`  ${r.ok ? "✔" : "✘"} ${r.name} — ${r.detail}`);
const ok = results.every((r) => r.ok);
console.log(ok ? "\n결과: 통과" : "\n결과: 실패 — 병합 · 배포를 막습니다");
process.exit(ok ? 0 : 1);
