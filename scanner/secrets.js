// Mission 2-B — 시크릿 탐지기 (docs/SEC_CONTRACT.md §2.2)
//   scanSecrets(files) : files = [{ path, text }] → [{ path, line, type }]  (줄 번호는 1부터, 한 줄에 한 건)
//   type: PRIVATE_KEY | AWS_ACCESS_KEY | API_KEY_LIVE | JWT | DB_URL_CREDENTIALS | HARDCODED_SECRET
//   오탐(자리표시자 · 환경 변수 참조 · 형식 설명)이 많으면 팀이 경보를 무시하게 된다.

// 자리표시자(비밀이 아닌 값)인가? — §2.2 의 목록
function isPlaceholder(v) {
  const s = String(v);
  return (
    /\[[A-Z0-9_]{2,}\]/.test(s) ||            // [대문자_이름]
    /<[^>]*>/.test(s) ||                      // <...>
    /x{4,}/i.test(s) ||                       // xxxx (4자 이상)
    /\*{4,}/.test(s) ||                       // ****
    /\.{3}/.test(s) ||                        // ...
    /\$\{/.test(s) ||                         // ${...}
    /changeme/i.test(s) ||
    /your-/i.test(s) ||                       // your-...
    /dummy/i.test(s) ||
    /placeholder/i.test(s) ||
    /process\.env/i.test(s) ||
    /os\.environ/i.test(s) ||
    /(^|[^a-z])env\./i.test(s) ||             // env.XXX
    /^(.)\1+$/.test(s)                        // 같은 글자 반복
  );
}

// 해시값 · 테스트 키처럼 '비밀이 아닌' 값인가?
function isNonSecretValue(v) {
  return (
    /^sk[-_]test[-_]/i.test(v) ||                       // sk_test_ 키
    /^\$2[aby]\$/.test(v) ||                            // bcrypt
    /^\$argon2/i.test(v) ||                             // argon2
    /^(sha\d+|md5)[-:]/i.test(v)                        // sha512-... 같은 무결성/해시 표기
  );
}

const HASH_NAME = /hash|digest|checksum|sha\d*|md5|commit|integrity/i; // 해시를 담는 이름

// 줄 하나를 검사해서 유형을 돌려준다(없으면 null). 순서: 먼저 맞는 유형이 이긴다.
function classify(line) {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(line)) return "PRIVATE_KEY";

  if (/(?<![A-Z0-9])AKIA[A-Z0-9]{16}/.test(line)) return "AWS_ACCESS_KEY";

  // 실제 키(live)만. sk_test_ 는 정규식에 걸리지 않는다.
  const live = /sk-live-([A-Za-z0-9]{12,})|sk_live_([A-Za-z0-9]{12,})/.exec(line);
  if (live && !isPlaceholder(live[1] || live[2])) return "API_KEY_LIVE";

  if (/eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}/.test(line)) return "JWT";

  const db = /[A-Za-z][A-Za-z0-9+.-]*:\/\/([^\s:@\/'"]+):([^\s@\/'"]+)@[^\s'"\/]+/.exec(line);
  if (db && !isPlaceholder(db[2])) return "DB_URL_CREDENTIALS";

  // 이름에 secret/password/token 등이 들어가고, 따옴표 문자열(8자 이상)을 대입
  const re = /([A-Za-z0-9_.-]*(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*(["'])((?:(?!\2).){8,})\2/gi;
  let m;
  while ((m = re.exec(line))) {
    const name = m[1], value = m[3];
    if (HASH_NAME.test(name)) continue;       // password_hash 같은 해시 저장 이름
    if (isPlaceholder(value) || isNonSecretValue(value)) continue;
    return "HARDCODED_SECRET";
  }
  return null;
}

function scanSecrets(files) {
  const found = [];
  for (const f of files || []) {
    const lines = String(f.text == null ? "" : f.text).split(/\r?\n/);
    lines.forEach((ln, i) => {
      const type = classify(ln);
      if (type) found.push({ path: f.path, line: i + 1, type });
    });
  }
  return found;
}
module.exports = { scanSecrets };