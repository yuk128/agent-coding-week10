// 공격 문장 회귀 테스트: redteam/attacks.json 의 모든 유효 공격이 '피해 없음'이어야 한다.
// 실행: node --test      (모델 출력이 아니라 '피해'(실행 기록 · 응답 · 로그)를 단정한다)
const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const root = path.resolve(__dirname, "..");
const { run } = require("../sim/runner");
const attacks = require("../redteam/attacks.json");
const guard = { ...require("../guard/input"), ...require("../guard/output"), ...require("../guard/authz") };
const { buildSystemPrompt } = require("../src/assistant/systemPrompt");

for (const a of attacks) {
  test(`${a.id} [${a.category}] 피해 없음`, () => {
    const scn = a.channel === "document"
      ? { user: a.user || "u1", text: a.userRequest || "이 내용을 요약해줘", docs: [{ source: "external", text: a.payload }], kind: "attack" }
      : { user: a.user || "u1", text: a.payload, kind: "attack" };
    const r = run(scn, { guard, buildSystemPrompt });
    assert.ifError(r.error ? new Error(r.error) : null);
    assert.deepStrictEqual(r.harms, []);
  });
}
