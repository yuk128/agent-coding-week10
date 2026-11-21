// Mission 4-C — 킬스위치 (docs/SEC_CONTRACT.md §4.3)
//   createKillSwitch() → { isEnabled(feature), disable(feature, { reason, actor, now }), enable(feature, { actor, now }), audit() }
//   기능 이름: "assistant"(도우미 전체), "assistant.write_tools"(쓰기 도구)
//   상위를 끄면 하위도 꺼진 것으로 본다. 끌 때는 사유와 담당자가 필수, 켤 때는 담당자가 필수. 모든 변경은 감사 기록에 남긴다.
function createKillSwitch() {
  const disabled = new Set(); // 꺼 둔 기능 이름
  const log = [];             // 감사 기록 [{ ts, feature, action, reason?, actor }]

  const filled = (v) => typeof v === "string" && v.trim() !== "";

  // "assistant.write_tools" → ["assistant.write_tools", "assistant"] (자기 자신과 모든 상위)
  function selfAndParents(feature) {
    const parts = String(feature).split(".");
    const chain = [];
    for (let i = parts.length; i >= 1; i--) chain.push(parts.slice(0, i).join("."));
    return chain;
  }

  return {
    // 자기 자신이나 상위 중 하나라도 꺼져 있으면 꺼진 것
    isEnabled(feature) {
      return !selfAndParents(feature).some((f) => disabled.has(f));
    },

    disable(feature, { reason, actor, now } = {}) {
      if (!filled(reason)) throw new Error("reason required"); // 사유 없이 끌 수 없다
      if (!filled(actor)) throw new Error("actor required");   // 담당자 없이 끌 수 없다
      disabled.add(feature);
      log.push({ ts: now === undefined ? Date.now() : now, feature, action: "disable", reason, actor });
    },

    enable(feature, { actor, now } = {}) {
      if (!filled(actor)) throw new Error("actor required");   // 담당자 없이 켤 수 없다
      disabled.delete(feature);
      log.push({ ts: now === undefined ? Date.now() : now, feature, action: "enable", actor });
    },

    audit() {
      return log.map((e) => ({ ...e })); // 복사본을 돌려줘서 밖에서 기록을 고치지 못하게 한다
    },
  };
}
module.exports = { createKillSwitch };