#!/usr/bin/env node
// Mission 5 — 보안 CI 게이트. 사용: node scripts/sec-ci.js [--dir ai_sec]
//   우리 팀 산출물에서는 통과(종료 코드 0), AI 가 만든 산출물(--dir ai_sec)에서는 실패(종료 코드 1)해야 한다.
//   임계값은 THRESHOLDS 에 한 곳으로 모은다. 아래 TODO 세 가지를 완성하세요.


// Mission 5 — 보안 CI 게이트
// 사용: node scripts/sec-ci.js [--dir ai_sec]

const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const di = process.argv.indexOf("--dir");
const DIR = di >= 0 ? process.argv[di + 1] : null;

// 임계값은 한 곳에서 관리한다.
const THRESHOLDS = {
  // 시크릿은 하나라도 발견되면 유출 위험이 있으므로 허용하지 않는다.
  maxSecretFindings: 0,

  // 위험 의존성은 취약점·오타·미등록·버전 미고정 등이므로 허용하지 않는다.
  maxRiskyDeps: 0,

  // 공격 회귀 테스트에서 피해가 발생한 공격은 하나도 허용하지 않는다.
  maxRegressionHarms: 0,
};

const FILES = DIR
  ? {
      secrets: "secrets.js",
      deps: "deps.js",
      guard: "guard.js",
      prompt: "prompt.js",
      attacks: "attacks.json",
      manifest: "package.json",
      scan: [""],
    }
  : {
      secrets: "scanner/secrets.js",
      deps: "scanner/deps.js",
      guard: ["guard/input.js", "guard/output.js", "guard/authz.js"],
      prompt: "src/assistant/systemPrompt.js",
      attacks: "redteam/attacks.json",
      manifest: "package.json",
      scan: ["app", "src", "guard", "secops", "scanner", "config"],
    };

const rel = (f) => path.resolve(root, DIR ? path.join(DIR, f) : f);

const load = (f) =>
  Array.isArray(f)
    ? Object.assign({}, ...f.map((x) => require(rel(x))))
    : require(rel(f));

function listFiles() {
  const out = [];

  const walk = (d) => {
    if (!fs.existsSync(d)) return;

    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);

      if (e.isDirectory()) {
        walk(p);
      } else if (/\.(js|json|md|env)$/.test(e.name)) {
        out.push({
          path: path.relative(root, p),
          text: fs.readFileSync(p, "utf8"),
        });
      }
    }
  };

  for (const s of FILES.scan) {
    walk(path.resolve(root, DIR || s));
  }

  return out;
}


// 1. 시크릿 스캔
function checkSecrets() {
  const { scanSecrets } = load(FILES.secrets);
  const findings = scanSecrets(listFiles());

  const ok = findings.length <= THRESHOLDS.maxSecretFindings;

  return {
    name: "시크릿 스캔",
    ok,
    detail: `${findings.length}건 발견 / 허용 ${THRESHOLDS.maxSecretFindings}건`,
  };
}

// 2. 의존성 검사
function checkDeps() {
  const { checkDependencies } = require(
    path.join(root, "scanner/deps.js")
  );

  const pkg = require(rel(FILES.manifest));

  const lockPath = path.join(root, "package-lock.json");
  const lock = fs.existsSync(lockPath)
    ? require(lockPath)
    : {};

  const registry = require(path.join(root, "sim/registry.json"));
  const cfg = require(path.join(root, "config/sec.json"));

  const findings = checkDependencies(pkg, lock, registry, cfg);
  const ok = findings.length <= THRESHOLDS.maxRiskyDeps;

  return {
    name: "의존성 검사",
    ok,
    detail: `${findings.length}개 위험 패키지 / 허용 ${THRESHOLDS.maxRiskyDeps}개`,
  };
}

// 3. 공격 회귀 검사
function checkRegression() {
  const { run } = require(path.join(root, "sim/runner.js"));

  const attacks = require(rel(FILES.attacks));
  const guard = load(FILES.guard);
  const { buildSystemPrompt } = load(FILES.prompt);

  let harmCount = 0;
  let errorCount = 0;

  for (const a of attacks) {
    const scn = a.channel === "document"
      ? {
          user: a.user || "u1",
          text: a.userRequest || "이 내용을 요약해줘",
          docs: [{ source: "external", text: a.payload }],
          kind: "attack",
        }
      : {
          user: a.user || "u1",
          text: a.payload,
          kind: "attack",
        };

    const result = run(scn, { guard, buildSystemPrompt });

    if (result.error) {
      errorCount++;
    } else if (result.harms.length > 0) {
      harmCount++;
    }
  }

  const totalFailures = harmCount + errorCount;
  const ok = totalFailures <= THRESHOLDS.maxRegressionHarms;

  return {
    name: "공격 회귀",
    ok,
    detail: `${attacks.length}건 중 피해 ${harmCount}건, 실행 오류 ${errorCount}건 / 허용 ${THRESHOLDS.maxRegressionHarms}건`,
  };
}


const results = [
  checkSecrets(),
  checkDeps(),
  checkRegression(),
];

console.log(`보안 CI 게이트${DIR ? ` (--dir ${DIR})` : ""}`);

for (const r of results) {
  console.log(`  ${r.ok ? "✔" : "✘"} ${r.name} — ${r.detail}`);
}

const ok = results.every((r) => r.ok);

console.log(
  ok
    ? "\n결과: 통과"
    : "\n결과: 실패 — 병합 · 배포를 막습니다"
);

process.exit(ok ? 0 : 1);
