function detect(events, now) {
  const alerts = [];
  const blocked = events.filter((e) => e.type === "INPUT_BLOCKED").length;
  if (blocked >= 3) alerts.push({ id: "INJECTION_PROBE", severity: "medium" });
  if (events.some((e) => e.type === "SECRET_IN_OUTPUT")) alerts.push({ id: "SECRET_IN_OUTPUT", severity: "critical" });
  return alerts;
}
module.exports = { detect };
