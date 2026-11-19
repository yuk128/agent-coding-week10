function generateSbom(pkg) {
  return { bomFormat: "CycloneDX", specVersion: "1.5", version: 1, components: Object.entries(pkg.dependencies || {}).map(([name, v]) => ({ type: "library", name, version: v })), dependencies: [] };
}
module.exports = { generateSbom };
