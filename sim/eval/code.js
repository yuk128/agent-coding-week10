// Mission 2 평가기: app/shop_api.js 의 취약점 7종을 공격 입력으로 검사하고, 정상 기능이 유지되는지도 본다.
const fs = require("fs"), path = require("path");
const { createDb } = require("../minidb");
const { createGateway } = require("../gateway");
const { findSecrets } = require("../refscan");
const { balanced } = require("./balance");

const ENV = { PAYMENT_API_KEY: "pk_test_RUNTIME_7c1d93e0", TOKEN_SECRET: "ts_RUNTIME_a52e8f1b09c47d36" };
const PRODUCTS = [
  { id: "P1", name: "무선 마우스", price: 15000, stock: 10, status: "ON_SALE" },
  { id: "P2", name: "기계식 키보드", price: 59000, stock: 3, status: "ON_SALE" },
  { id: "P3", name: "USB-C 케이블", price: 9000, stock: 0, status: "ON_SALE" },
  { id: "P4", name: "구형 헤드셋", price: 30000, stock: 5, status: "STOPPED" },
  { id: "P5", name: "모니터 받침대", price: 25000, stock: 1, status: "ON_SALE" },
];
const PW = "Passw0rd!x";
const ADDR = "서울시 가상구 예시로 1";
const B64 = (s) => Buffer.from(s).toString("base64");

function makeApp(mod, env = ENV) {
  const db = createDb({ users: [], products: PRODUCTS, orders: [] });
  const gateway = createGateway();
  const clock = { t: 1_800_000_000_000, now() { return this.t; } };
  const api = mod.createApi({ db, env, clock, gateway });
  const call = (method, p, { body, token, query } = {}) => {
    let r;
    try { r = api.handle({ method, path: p, body, query, headers: token ? { authorization: `Bearer ${token}` } : {} }); }
    catch (e) { r = { status: 599, body: { error: "THROWN", message: e.message } }; }
    return r || { status: 599, body: {} };
  };
  const users = {};
  for (const [k, n, ph] of [["u1", "김하늘", "010-2345-6789"], ["u2", "이도윤", "010-9876-5432"], ["u3", "박서연", "010-5555-0303"]]) {
    const email = `${n === "김하늘" ? "haneul" : n === "이도윤" ? "doyun" : "seoyeon"}@mall.example`;
    const reg = call("POST", "/register", { body: { email, password: PW, name: n, phone: ph } });
    const lg = call("POST", "/login", { body: { email, password: PW } });
    users[k] = { email, id: reg.body && reg.body.id, token: lg.body && lg.body.token };
  }
  const mk = (u, items) => call("POST", "/orders", { token: users[u].token, body: { items, address: ADDR } });
  const o1 = mk("u1", [{ productId: "P1", quantity: 2, price: 15000 }]);
  const o2 = mk("u2", [{ productId: "P2", quantity: 1, price: 59000 }]);
  const o3 = mk("u3", [{ productId: "P5", quantity: 1, price: 25000 }]);
  return { db, gateway, clock, api, call, users, orders: { u1: o1.body && o1.body.id, u2: o2.body && o2.body.id, u3: o3.body && o3.body.id }, mod, env };
}

const LEAK = /\bat\s+[\w.<>$ ]+\s*\(|node_modules|\/home\/|\.js:\d+|postgres|stack|SqlError|TypeError|ReferenceError|RangeError|SyntaxError|SELECT\s|FROM\s|passw0rd|sk-live/i;
const noLeak = (r) => r.status >= 400 && !LEAK.test(JSON.stringify(r.body)) && typeof (r.body && r.body.error) === "string" && r.body.error.length <= 60;
const safe = (fn) => { try { return !!fn(); } catch { return false; } };

// 공격 시험: true = 방어됨
function attackTests(P, appFiles, mod) {
  const T = [];
  const add = (v, id, fn) => T.push({ v, id, fn });
  P.loginInjection.forEach((email, i) => add("V1", `login-${i}`, () => { const a = makeApp(mod); const r = a.call("POST", "/login", { body: { email, password: "wrong-password" } }); return r.status !== 200 && !(r.body && r.body.token); }));
  P.searchInjection.forEach((q, i) => add("V1", `search-${i}`, () => { const a = makeApp(mod); const r = a.call("GET", "/products", { query: { q } }); const items = (r.body && r.body.items) || []; return !items.some((x) => x.id === "P4"); }));
  add("V2", "idor-order-1", () => { const a = makeApp(mod); const r = a.call("GET", `/orders/${a.orders.u2}`, { token: a.users.u1.token }); return r.status === 404 || r.status === 403; });
  add("V2", "idor-order-2", () => { const a = makeApp(mod); const r = a.call("GET", `/orders/${a.orders.u1}`, { token: a.users.u3.token }); return (r.status === 404 || r.status === 403) && !JSON.stringify(r.body).includes(a.orders.u1 + "\",\"status"); });
  add("V2", "idor-pay", () => { const a = makeApp(mod); const r = a.call("POST", "/payments", { token: a.users.u1.token, body: { orderId: a.orders.u2 } }); return (r.status === 404 || r.status === 403) && a.gateway.calls.length === 0; });
  add("V2", "no-auth", () => { const a = makeApp(mod); const r = a.call("GET", `/orders/${a.orders.u1}`); return r.status === 401; });
  add("V3", "no-literal-secrets", () => { let n = 0; for (const f of appFiles) n += findSecrets(fs.readFileSync(f, "utf8")).length; return n === 0; });
  add("V3", "fail-closed-token", () => { try { makeApp(mod, { PAYMENT_API_KEY: ENV.PAYMENT_API_KEY }); return false; } catch { return true; } });
  add("V3", "fail-closed-payment", () => { try { makeApp(mod, { TOKEN_SECRET: ENV.TOKEN_SECRET }); return false; } catch { return true; } });
  add("V3", "uses-env-key", () => { const a = makeApp(mod); a.call("POST", "/payments", { token: a.users.u1.token, body: { orderId: a.orders.u1 } }); const c = a.gateway.calls[a.gateway.calls.length - 1]; return !!c && c.apiKey === ENV.PAYMENT_API_KEY; });
  add("V4", "not-plain-or-fast-hash", () => { const a = makeApp(mod); const u = a.db.tables.users[0]; const h = String(u.pwhash || ""); return h.length > 0 && h !== PW && !h.includes(PW) && !/^[a-f0-9]{32}$/i.test(h) && !/^[a-f0-9]{40}$/i.test(h) && !/^[a-f0-9]{64}$/i.test(h); });
  add("V4", "salted", () => { const a = makeApp(mod); const us = a.db.tables.users; return us[0].pwhash !== us[1].pwhash && us[1].pwhash !== us[2].pwhash; });
  add("V4", "no-password-stored", () => { const a = makeApp(mod); return !JSON.stringify(a.db.tables.users).includes(PW); });
  P.errorTriggers.forEach((t, i) => add("V5", `error-${i}`, () => { const a = makeApp(mod); const r = a.call(t.method, t.path.replace("{u1}", a.orders.u1), { token: a.users.u1.token, body: t.body }); return noLeak(r); }));
  P.priceTamper.forEach((t, i) => add("V6", `tamper-${i}`, () => { const a = makeApp(mod); const r = a.call("POST", "/orders", { token: a.users.u1.token, body: t.body }); if (t.expectTotal != null) return (r.status === 201 && r.body.total === t.expectTotal) || r.status === 400; return r.status === 400; }));
  P.forgedTokens.forEach((f, i) => add("V7", `forged-${i}`, () => { const a = makeApp(mod); const tok = f(a); const r = a.call("GET", `/orders/${a.orders.u2}`, { token: tok }); return r.status === 401; }));
  add("V7", "expired", () => { const a = makeApp(mod); a.clock.t += 25 * 3600 * 1000; const r = a.call("GET", `/orders/${a.orders.u1}`, { token: a.users.u1.token }); return r.status === 401; });
  return T;
}

// 정상 시험: true = 기능 유지
function functionalTests(mod) {
  const T = [];
  const add = (id, fn) => T.push({ id, fn });
  add("login", () => { const a = makeApp(mod); return !!a.users.u1.token && a.users.u1.id; });
  add("login-wrong-pw", () => { const a = makeApp(mod); const r = a.call("POST", "/login", { body: { email: a.users.u1.email, password: "nope" } }); return r.status === 401; });
  add("search", () => { const a = makeApp(mod); const r = a.call("GET", "/products", { query: { q: "마우스" } }); return r.status === 200 && r.body.items.length === 1 && r.body.items[0].id === "P1"; });
  add("search-all-onsale", () => { const a = makeApp(mod); const r = a.call("GET", "/products", { query: {} }); return r.status === 200 && r.body.items.length === 4 && !r.body.items.some((x) => x.id === "P4"); });
  add("search-apostrophe", () => { const a = makeApp(mod); const r = a.call("GET", "/products", { query: { q: "it's" } }); return r.status === 200 && r.body.items.length === 0; });
  add("own-order", () => { const a = makeApp(mod); const r = a.call("GET", `/orders/${a.orders.u1}`, { token: a.users.u1.token }); return r.status === 200 && r.body.id === a.orders.u1 && r.body.total === 30000; });
  add("create-order", () => { const a = makeApp(mod); const r = a.call("POST", "/orders", { token: a.users.u2.token, body: { items: [{ productId: "P1", quantity: 2, price: 15000 }, { productId: "P5", quantity: 1, price: 25000 }], address: ADDR } }); return r.status === 201 && r.body.total === 55000 && /^ORD-\d{4}$/.test(r.body.id); });
  add("pay-own", () => { const a = makeApp(mod); const r = a.call("POST", "/payments", { token: a.users.u1.token, body: { orderId: a.orders.u1 } }); return r.status === 200 && r.body.paid === true && a.gateway.calls.length === 1; });
  add("token-valid-later", () => { const a = makeApp(mod); a.clock.t += 600000; const r = a.call("GET", `/orders/${a.orders.u3}`, { token: a.users.u3.token }); return r.status === 200; });
  add("unknown-order-404", () => { const a = makeApp(mod); const r = a.call("GET", "/orders/ORD-9999", { token: a.users.u1.token }); return r.status === 404; });
  return T;
}

function run(mod, P, appFiles) {
  const attacks = attackTests(P, appFiles, mod), funcs = functionalTests(mod);
  const items = [];
  const names = { V1: "SQL 인젝션", V2: "접근 통제(IDOR)", V3: "시크릿 하드코딩", V4: "비밀번호 해시", V5: "오류 정보 노출", V6: "클라이언트 값 신뢰", V7: "위조 가능한 토큰" };
  for (const v of Object.keys(names)) {
    const ts = attacks.filter((t) => t.v === v);
    const ok = ts.filter((t) => safe(t.fn)).length;
    items.push({ id: v, title: names[v], kind: "pos", score: ts.length ? ok / ts.length : 0, detail: `공격 ${ts.length}건 중 ${ok}건 방어` });
  }
  const fok = funcs.filter((t) => safe(t.fn));
  const bad = funcs.filter((t) => !safe(t.fn)).map((t) => t.id);
  items.push({ id: "F", title: "정상 기능 유지", kind: "neg", score: fok.length / funcs.length, detail: `정상 시험 ${funcs.length}건 중 ${fok.length}건 통과` + (bad.length ? ` (실패: ${bad.join(", ")})` : "") });
  const score = balanced(items);
  return { name: "AI 생성 코드 보안 수정", score, items };
}
module.exports = { run, makeApp, ENV, B64 };
