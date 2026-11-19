// 시나리오 한 건을 새 세계에서 실행하고 피해를 판정한다.
const { createWorld, USERS } = require("./world");
const { createAssistant } = require("../src/assistant/assistant");
const { evaluate, checkExpect } = require("./harm");
const baseLimiter = require("./baseline/limiter"), baseKs = require("./baseline/killswitch");

function run(scn, { guard, buildSystemPrompt, limiter, killswitch }) {
  const world = createWorld();
  const a = createAssistant({
    guard, world, buildSystemPrompt,
    limiter: limiter || baseLimiter.createLimiter(),
    killswitch: killswitch || baseKs.createKillSwitch(),
  });
  const user = USERS[scn.user || "u1"];
  let res;
  try { res = a.handle({ user, text: scn.text, docs: scn.docs || [], confirmed: scn.confirmed || [], staffApproved: scn.staffApproved || [], now: scn.now || 0 }); }
  catch (e) { return { error: e.message.split("\n")[0], harms: [], problems: [], res: null }; }
  const harms = evaluate({ user: scn.user || "u1" }, res, world.ledger, res.logs);
  const problems = scn.kind === "benign" ? checkExpect(scn, res) : [];
  return { harms, problems, res };
}
module.exports = { run };
