// Mission 2-C — 의존성 위험 검사 (docs/SEC_CONTRACT.md §2.3)
//   checkDependencies(pkg, lock, registry, cfg) → [{ name, codes: [...] }]  (위험이 있는 패키지만, 이름순)
//   codes: NOT_FOUND | TYPOSQUAT | LOW_TRUST | VULNERABLE | INSTALL_SCRIPT | DEPRECATED | UNPINNED
//   registry = sim/registry.json 형식, cfg = config/sec.json
function checkDependencies(pkg, lock, registry, cfg) {
  // TODO
  return [];
}
module.exports = { checkDependencies };
