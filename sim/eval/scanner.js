// Mission 2 평가기(2): 시크릿 탐지 · 의존성 위험 · SBOM
const { balanced } = require("./balance");
const key = (f) => `${f.path}:${f.line}:${f.type}`;

function runSecrets(mod, cases) {
  const items = [];
  for (const c of cases) {
    let got = [];
    try { got = mod.scanSecrets(c.files.map((f) => ({ ...f }))) || []; } catch (e) { items.push({ id: c.id, title: c.title, kind: c.expect.length ? "pos" : "neg", score: 0, detail: "오류: " + e.message.split("\n")[0] }); continue; }
    const g = new Set(got.map(key)), e = new Set(c.expect.map(key));
    const tp = [...e].filter((x) => g.has(x)).length, fp = [...g].filter((x) => !e.has(x));
    let score;
    if (e.size === 0) score = g.size === 0 ? 1 : 0;
    else { const p = tp / Math.max(1, g.size), r = tp / e.size; score = p + r === 0 ? 0 : (2 * p * r) / (p + r); }
    items.push({ id: c.id, title: c.title, kind: e.size ? "pos" : "neg", score, detail: e.size ? `찾음 ${tp}/${e.size}` + (fp.length ? `, 오탐 ${fp.length}` : "") : g.size ? `오탐 ${g.size}건` : "오탐 없음" });
  }
  return items;
}

function runDeps(mod, cases, registry, cfg) {
  const items = [];
  for (const c of cases) {
    let got = [];
    try { got = mod.checkDependencies(JSON.parse(JSON.stringify(c.pkg)), JSON.parse(JSON.stringify(c.lock || {})), registry, cfg) || []; } catch (e) { items.push({ id: c.id, title: c.title, kind: Object.keys(c.expect).length ? "pos" : "neg", score: 0, detail: "오류: " + e.message.split("\n")[0] }); continue; }
    const gm = Object.fromEntries(got.map((x) => [x.name, new Set(x.codes || [])]));
    const names = new Set([...Object.keys(c.expect), ...Object.keys(gm)]);
    let sum = 0, n = 0; const bad = [];
    for (const nm of names) {
      const e = new Set(c.expect[nm] || []), g = gm[nm] || new Set();
      const inter = [...e].filter((x) => g.has(x)).length, uni = new Set([...e, ...g]).size;
      const s = uni === 0 ? 1 : inter / uni; sum += s; n++;
      if (s < 1) bad.push(`${nm}: 기대 [${[...e]}] / 실제 [${[...g]}]`);
    }
    items.push({ id: c.id, title: c.title, kind: Object.keys(c.expect).length ? "pos" : "neg", score: n ? sum / n : 1, detail: bad.length ? bad.slice(0, 2).join(" | ") : "일치" });
  }
  return items;
}

function runSbom(mod, cases, registry) {
  const items = [];
  for (const c of cases) {
    let b; try { b = mod.generateSbom(JSON.parse(JSON.stringify(c.pkg)), JSON.parse(JSON.stringify(c.lock)), registry); } catch (e) { items.push({ id: c.id, title: c.title, kind: "pos", score: 0, detail: "오류: " + e.message.split("\n")[0] }); continue; }
    const E = c.expect; let ok = 0; const bad = [];
    const chk = (cond, msg) => { if (cond) ok++; else bad.push(msg); };
    chk(b && b.bomFormat === "CycloneDX" && b.specVersion === "1.5", "bomFormat/specVersion");
    const comps = (b && b.components) || [];
    chk(JSON.stringify(comps.map((x) => [x.name, x.version])) === JSON.stringify(E.components.map((x) => [x.name, x.version])), "구성요소 목록(전이 의존성 포함 · 이름순)");
    chk(JSON.stringify(comps.map((x) => x.purl)) === JSON.stringify(E.components.map((x) => x.purl)), "purl 형식");
    chk(JSON.stringify(comps.map((x) => x.licenses)) === JSON.stringify(E.components.map((x) => x.licenses)), "라이선스");
    chk(JSON.stringify(comps.map((x) => x.hashes || null)) === JSON.stringify(E.components.map((x) => x.hashes || null)), "무결성 해시");
    chk(JSON.stringify((b && b.dependencies) || []) === JSON.stringify(E.dependencies), "의존 관계(dependencies)");
    items.push({ id: c.id, title: c.title, kind: "pos", score: ok / 6, detail: bad.length ? "불일치: " + bad.join(", ") : "일치" });
  }
  return items;
}

function run(mods, sets, registry, cfg) {
  const out = { name: "스캐너(시크릿 · 의존성 · SBOM)", items: [] };
  const part = (label, items, mod) => {
    if (!mod) return 0;
    items.forEach((i) => out.items.push({ ...i, id: label + i.id }));
    return balanced(items);
  };
  const S = mods.secrets ? part("S-", runSecrets(mods.secrets, sets.secrets), mods.secrets) : 0;
  const D = mods.deps ? part("D-", runDeps(mods.deps, sets.deps, registry, cfg), mods.deps) : 0;
  const M = mods.sbom ? (() => { const it = runSbom(mods.sbom, sets.sbom, registry); it.forEach((i) => out.items.push({ ...i, id: "M-" + i.id })); return it.reduce((s, i) => s + i.score, 0) / it.length; })() : 0;
  out.parts = { secrets: S, deps: D, sbom: M };
  out.score = 0.4 * S + 0.4 * D + 0.2 * M;
  return out;
}
module.exports = { run };
