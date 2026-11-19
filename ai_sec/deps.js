function checkDependencies(pkg, lock, registry) {
  const out = [];
  for (const [name, spec] of Object.entries(pkg.dependencies || {})) {
    const codes = [];
    if (!registry.packages[name]) codes.push("NOT_FOUND");
    if (["*", "latest"].includes(spec)) codes.push("UNPINNED");
    if (codes.length) out.push({ name, codes });
  }
  return out;
}
module.exports = { checkDependencies };
