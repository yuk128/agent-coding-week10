// Mission 2-B — 시크릿 탐지기 (docs/SEC_CONTRACT.md §2.2)
//   scanSecrets(files) : files = [{ path, text }] → [{ path, line, type }]  (줄 번호는 1부터, 한 줄에 한 건)
//   type: PRIVATE_KEY | AWS_ACCESS_KEY | API_KEY_LIVE | JWT | DB_URL_CREDENTIALS | HARDCODED_SECRET
//   오탐(자리표시자 · 환경 변수 참조 · 형식 설명)이 많으면 팀이 경보를 무시하게 된다.
function scanSecrets(files) {
  // TODO
  return [];
}
module.exports = { scanSecrets };
