// Mission 2-C — 의존성 위험 검사 (docs/SEC_CONTRACT.md §2.3)
//   checkDependencies(pkg, lock, registry, cfg) → [{ name, codes: [...] }]  (위험이 있는 패키지만, 이름순)
//   codes: NOT_FOUND | TYPOSQUAT | LOW_TRUST | VULNERABLE | INSTALL_SCRIPT | DEPRECATED | UNPINNED
//   registry = sim/registry.json 형식, cfg = config/sec.json

const has = (o, k) => Object.prototype.hasOwnProperty.call(o || {}, k);

// 편집 거리(글자를 몇 번 바꾸면 같아지는가) — 타이포스쿼팅 판정용
function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[a.length][b.length];
}

// "1.2.3" 형식 비교: a<b 이면 음수
function cmpVersion(a, b) {
  const pa = String(a).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d !== 0) return d;
  }
  return 0;
}

function checkDependencies(pkg, lock, registry, cfg) {
  const deps = (pkg && pkg.dependencies) || {};
  const packages = (registry && registry.packages) || {};
  const allowScripts = (cfg && cfg.allowInstallScripts) || [];
  const result = [];

  for (const name of Object.keys(deps).sort()) {
    const spec = String(deps[name]).trim();
    const codes = new Set();

    // 설치 버전: lock 우선, 없으면 pkg 값이 정확한 버전(x.y.z)일 때만
    let installed = null;
    if (has(lock, name) && lock[name] && lock[name].version) installed = lock[name].version;
    else if (/^\d+\.\d+\.\d+$/.test(spec)) installed = spec;

    const reg = has(packages, name) ? packages[name] : null;

    if (!reg) {
      codes.add("NOT_FOUND"); // 저장소에 없는 이름(슬롭스쿼팅 의심)
    } else {
      // TYPOSQUAT: 인기 패키지와 이름이 거의 같은데 다운로드는 적음
      if ((reg.weeklyDownloads || 0) < 5000) {
        for (const other of Object.keys(packages)) {
          if (other === name) continue;
          if ((packages[other].weeklyDownloads || 0) >= 1000000 && editDistance(name, other) <= 2) {
            codes.add("TYPOSQUAT");
            break;
          }
        }
      }
      // LOW_TRUST: 등록 30일 미만 + 주간 다운로드 1,000 미만
      if ((reg.ageDays || 0) < 30 && (reg.weeklyDownloads || 0) < 1000) codes.add("LOW_TRUST");
      // VULNERABLE: high/critical 권고의 below 버전보다 낮은 버전을 설치
      if (installed) {
        for (const adv of reg.advisories || []) {
          if ((adv.severity === "high" || adv.severity === "critical") && cmpVersion(installed, adv.below) < 0) {
            codes.add("VULNERABLE");
          }
        }
      }
      // INSTALL_SCRIPT: 설치 시 스크립트가 있고 허용 목록에 없음
      if (installed && reg.versions && reg.versions[installed] && !allowScripts.includes(name)) {
        const sc = reg.versions[installed].scripts || {};
        if (sc.preinstall || sc.install || sc.postinstall) codes.add("INSTALL_SCRIPT");
      }
      if (reg.deprecated === true) codes.add("DEPRECATED");
    }

    // UNPINNED: 버전이 고정되지 않음
    const loose = ["", "*", "latest", "x"].includes(spec.toLowerCase()) || /^(git|http|file:)/i.test(spec);
    const range = /^[\^~><]/.test(spec) && !(has(lock, name) && lock[name]);
    if (loose || range) codes.add("UNPINNED");

    if (codes.size) result.push({ name, codes: [...codes].sort() });
  }
  return result;
}
module.exports = { checkDependencies };