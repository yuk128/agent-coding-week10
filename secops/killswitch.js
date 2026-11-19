// Mission 4-C — 킬스위치 (docs/SEC_CONTRACT.md §4.3)
//   createKillSwitch() → { isEnabled(feature), disable(feature, { reason, actor, now }), enable(feature, { actor, now }), audit() }
//   기능 이름: "assistant"(도우미 전체), "assistant.write_tools"(쓰기 도구)
function createKillSwitch() {
  return {
    isEnabled(feature) { return true; }, // TODO
    disable(feature, opts) { throw new Error("TODO"); },
    enable(feature, opts) { throw new Error("TODO"); },
    audit() { return []; },
  };
}
module.exports = { createKillSwitch };
