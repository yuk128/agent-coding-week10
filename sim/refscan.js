// 평가기 전용 간이 시크릿 탐지기 (학생의 scanner 와 별개). 코드 안에 남은 비밀 값을 찾는다.
const PATS = [
  /sk-live-[A-Za-z0-9]{10,}/, /AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/'"]+:[^\s@/'"]+@[^\s/'"]+/i,
  /\b(?:secret|password|passwd|token|api_?key|private_?key)[A-Za-z_]*\s*[:=]\s*["'][^"'\s]{6,}["']/i,
];
function findSecrets(text) { const out = []; text.split("\n").forEach((l, i) => { if (PATS.some((r) => r.test(l))) out.push(i + 1); }); return out; }
module.exports = { findSecrets };
