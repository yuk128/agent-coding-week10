// Mission 2-D — SBOM 생성 (CycloneDX 축약형, docs/SEC_CONTRACT.md §2.4)
//   generateSbom(pkg, lock, registry) → { bomFormat, specVersion, version, metadata, components, dependencies }
function generateSbom(pkg, lock, registry) {
  const packages = (registry && registry.packages) || {};
  const names = Object.keys(lock || {}).sort(); // 전이 의존성까지 lock 의 모든 항목, 이름순
  const purl = (n) => `pkg:npm/${n}@${lock[n].version}`;

  const components = names.map((n) => {
    const reg = Object.prototype.hasOwnProperty.call(packages, n) ? packages[n] : null;
    const c = {
      type: "library",
      name: n,
      version: lock[n].version,
      purl: purl(n),
      licenses: [{ license: { id: (reg && reg.license) || "NOASSERTION" } }],
    };
    if (lock[n].integrity) c.hashes = [{ alg: "SHA-512", content: lock[n].integrity }]; // integrity 가 있을 때만
    return c;
  });

  // requires 가 비어 있지 않은 항목만. lock 에 없는 이름은 제외
  const dependencies = names
    .filter((n) => lock[n].requires && Object.keys(lock[n].requires).length > 0)
    .map((n) => ({
      ref: purl(n),
      dependsOn: Object.keys(lock[n].requires)
        .filter((r) => Object.prototype.hasOwnProperty.call(lock, r))
        .map(purl)
        .sort(),
    }));

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: { component: { type: "application", name: pkg && pkg.name, version: pkg && pkg.version } },
    components,
    dependencies,
  };
}
module.exports = { generateSbom };