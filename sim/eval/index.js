// 평가기 묶음: 공개 시나리오로 학생(또는 AI) 산출물을 평가한다.
const fs = require("fs"), path = require("path");
const pub = require("../data/public");
const codeEval = require("./code"), scannerEval = require("./scanner"), guardEval = require("./guard"), secopsEval = require("./secops"), redteamEval = require("./redteam");
const registry = require("../registry.json");

const FILES = {
  guard: ["guard/input.js", "guard/output.js", "guard/authz.js"], prompt: ["src/assistant/systemPrompt.js"],
  secrets: ["scanner/secrets.js"], deps: ["scanner/deps.js"], sbom: ["scanner/sbom.js"],
  detect: ["secops/detect.js"], limiter: ["secops/limiter.js"], killswitch: ["secops/killswitch.js"],
  app: ["app/shop_api.js"], attacks: ["redteam/attacks.json"], playbook: ["secops/playbook.json"],
};
const AI_FILES = {
  guard: ["guard.js"], prompt: ["prompt.js"], secrets: ["secrets.js"], deps: ["deps.js"], sbom: ["sbom.js"],
  detect: ["detect.js"], limiter: ["limiter.js"], killswitch: ["killswitch.js"], app: ["shop_api.js"], attacks: ["attacks.json"], playbook: ["playbook.json"],
};
const WEIGHTS = { redteam: 6, code: 9, scanner: 7, guard: 12, secops: 6 };

function loadPublicSets() { return { code: pub.code, guard: pub.guard, secrets: pub.secrets, deps: pub.deps, sbom: pub.sbom, detect: pub.detect, limiter: pub.limiter }; }

function load(root, dir, key) {
  const rels = (dir ? AI_FILES : FILES)[key].map((f) => (dir ? path.join(dir, f) : f));
  const abs = rels.map((r) => path.resolve(root, r));
  if (key === "attacks" || key === "playbook") {
    try { return { mod: JSON.parse(fs.readFileSync(abs[0], "utf8")), rels, abs }; } catch (e) { return { error: `${rels[0]} 을(를) 읽지 못했습니다: ${e.message.split("\n")[0]}`, rels, abs }; }
  }
  const merged = {};
  for (const p of abs) {
    try { delete require.cache[require.resolve(p)]; Object.assign(merged, require(p)); }
    catch (e) { return { error: `${path.relative(root, p)} 을(를) 불러오지 못했습니다: ${e.message.split("\n")[0]}`, rels, abs }; }
  }
  return { mod: merged, rels, abs };
}

function runAll(root, { dir = null, sets, only, config } = {}) {
  sets = sets || loadPublicSets();
  const cfg = config || JSON.parse(fs.readFileSync(path.join(root, "config/sec.json"), "utf8"));
  const out = {};
  const want = (k) => !only || only.includes(k);
  const L = (k) => load(root, dir, k);
  const guardMod = () => { const g = L("guard"), p = L("prompt"); if (g.error) return { error: g.error }; if (p.error) return { error: p.error }; return { mod: { guard: g.mod, buildSystemPrompt: p.mod.buildSystemPrompt } }; };

  // 가드레일
  if (want("guard") || want("redteam")) {
    const gm = guardMod();
    const empty = { name: "가드레일 파이프라인", score: 0, items: [] };
    if (gm.error) out.guard = { ...empty, error: gm.error };
    else { try { out.guard = guardEval.run(gm.mod, sets.guard); } catch (e) { out.guard = { ...empty, error: e.message.split("\n")[0] }; } }
    out._guardMod = gm.mod;
  }
  if (want("code")) {
    const a = L("app");
    if (a.error) out.code = { name: "AI 생성 코드 보안 수정", score: 0, items: [], error: a.error };
    else { try { const files = dir ? a.abs : fs.readdirSync(path.join(root, "app")).filter((f) => f.endsWith(".js")).map((f) => path.join(root, "app", f)); out.code = codeEval.run(a.mod, sets.code, files); } catch (e) { out.code = { name: "AI 생성 코드 보안 수정", score: 0, items: [], error: e.message.split("\n")[0] }; } }
  }
  if (want("scanner")) {
    const mods = {}; let err;
    for (const k of ["secrets", "deps", "sbom"]) { const l = L(k); if (l.error) err = err || l.error; else mods[k] = l.mod; }
    try { out.scanner = scannerEval.run(mods, sets, registry, cfg); } catch (e) { out.scanner = { name: "스캐너", score: 0, items: [], error: e.message.split("\n")[0] }; }
    if (err) out.scanner.error = err;
  }
  if (want("secops")) {
    const mods = {}; let err;
    for (const k of ["detect", "limiter", "killswitch"]) { const l = L(k); if (l.error) err = err || l.error; else mods[k] = l.mod; }
    const pb = L("playbook");
    try { out.secops = secopsEval.run(mods, sets, cfg, pb.error ? null : pb.mod); } catch (e) { out.secops = { name: "보안 관제", score: 0, items: [], error: e.message.split("\n")[0], parts: {}, playbook: { score: 0, problems: [] } }; }
    if (err) out.secops.error = err;
  }
  if (want("redteam")) {
    const at = L("attacks");
    const benign = out.guard ? out.guard.items.filter((i) => i.kind === "neg") : [];
    const benignScore = benign.length ? benign.reduce((s, i) => s + i.score, 0) / benign.length : 0;
    if (at.error) out.redteam = { name: "레드팀 공격 케이스", score: 0, items: [], error: at.error };
    else { try { out.redteam = redteamEval.run(at.mod, out._guardMod, benignScore); } catch (e) { out.redteam = { name: "레드팀 공격 케이스", score: 0, items: [], error: e.message.split("\n")[0] }; } }
  }
  delete out._guardMod;
  if (only && !only.includes("guard") && out.guard) { /* guard 는 redteam 용으로만 계산됨 */ out.guard.skipped = true; }
  out.points = {};
  for (const k of Object.keys(WEIGHTS)) if (out[k] && !out[k].skipped) out.points[k] = Math.round(out[k].score * WEIGHTS[k] * 100) / 100;
  out.total = Math.round(Object.values(out.points).reduce((a, b) => a + b, 0) * 100) / 100;
  return out;
}

function print(res, only) {
  const mark = (s) => (s >= 0.999 ? "✔" : s > 0 ? "△" : "✘");
  const keys = only && only !== "all" ? [only] : ["redteam", "code", "scanner", "guard", "secops"];
  for (const k of keys) {
    const r = res[k]; if (!r) continue;
    console.log(`\n[${r.name}]  ${(r.score * 100).toFixed(0)}%  → ${res.points[k]}/${WEIGHTS[k]}점`);
    if (r.error) console.log("  ! " + r.error);
    for (const i of r.items) console.log(`  ${mark(i.score)} ${i.id} ${i.title} — ${i.detail}`);
    if (k === "secops" && r.playbook) console.log(`  ${mark(r.playbook.score)} PB 대응 절차(playbook.json) ${(r.playbook.score * 100).toFixed(0)}%` + (r.playbook.problems.length ? ` — ${r.playbook.problems[0]}` : ""));
  }
  if (!only || only === "all") console.log(`\n자동 평가 합계(공개 시나리오 기준): ${res.total}/40점`);
}
module.exports = { runAll, loadPublicSets, print, WEIGHTS };
