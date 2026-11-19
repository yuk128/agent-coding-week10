#!/usr/bin/env node
// docs/THREAT_MODEL.md · docs/SEC_REQUIREMENTS.md 의 형식을 점검한다 (내용의 타당성은 사람이 본다).
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const read = (f) => { try { return fs.readFileSync(path.join(root, f), "utf8"); } catch { return ""; } };
const checks = [];
const tm = read("docs/THREAT_MODEL.md");
const rows = (md) => md.split("\n").filter((l) => /^\|/.test(l) && !/^\|\s*-/.test(l)).map((l) => l.split("|").slice(1, -1).map((c) => c.trim()));
const trows = rows(tm).filter((r) => /^T-\d+/.test(r[0]) && r.slice(1).every((c) => c && !/^(…|\.\.\.|TODO)$/.test(c)));
checks.push(["위협 8건 이상(T-1 …), 모든 칸 채움", trows.length >= 8, `현재 ${trows.length}건`]);
const ids = new Set(); trows.forEach((r) => (r.join(" ").match(/LLM\d{2}/g) || []).forEach((x) => ids.add(x)));
checks.push(["OWASP LLM 항목 4가지 이상 연결", ids.size >= 4, `현재 ${ids.size}가지: ${[...ids].join(",")}`]);
checks.push(["'자산 · 공격자 · 공격면 · 영향' 네 질문에 답함", ["자산", "공격자", "공격면", "영향"].every((k) => new RegExp(`##[^\\n]*${k}`).test(tm) && !new RegExp(`##[^\\n]*${k}[^\\n]*\\n+\\s*(TODO|…)`).test(tm)), "네 개의 ## 제목 아래에 내용 필요"]);
const rq = read("docs/SEC_REQUIREMENTS.md");
const rrows = rows(rq).filter((r) => /^NFR-SEC-(AI-)?\d+/.test(r[0]) && r.slice(1).every((c) => c && !/^(…|\.\.\.|TODO)$/.test(c)));
checks.push(["보안 요구사항 6건 이상(NFR-SEC-AI-01 …), 모든 칸 채움", rrows.length >= 6, `현재 ${rrows.length}건`]);
checks.push(["'~해야 한다' 형식", rrows.length > 0 && rrows.every((r) => /야 한다|야 하며/.test(r[1] || "")), "요구사항 문장은 '~해야 한다' 형태(예: 막아야 한다)로 쓰기"]);
checks.push(["검증 방법이 측정 가능(테스트 ID · 시나리오 ID 포함)", rrows.length > 0 && rrows.every((r) => /(테스트|test|시나리오|공격|RT-|[A-Z]{1,2}\d)/i.test(r[3] || "")), "예: 'RT-07 공격 케이스가 피해 없이 통과'"]);
const gv = read("docs/GOVERNANCE.md");
checks.push(["거버넌스 체크리스트 5항목 이상 표시", (gv.match(/- \[[xX]\]/g) || []).length >= 5, `체크된 항목 ${(gv.match(/- \[[xX]\]/g) || []).length}개`]);
let bad = 0;
for (const [n, ok, d] of checks) { console.log(`${ok ? "✔" : "✘"} ${n}${ok ? "" : " — " + d}`); if (!ok) bad++; }
process.exit(bad ? 1 : 0);
