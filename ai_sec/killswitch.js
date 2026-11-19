function createKillSwitch() {
  let on = true; const log = [];
  return { isEnabled() { return on; }, disable() { on = false; }, enable() { on = true; }, audit() { return log; } };
}
module.exports = { createKillSwitch };
