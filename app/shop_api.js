// MiniMall API 초안 — AI 코딩 도구가 만들어 준 코드라고 가정한다. (수업용)
// 데모는 잘 돌아가고 테스트도 통과한다. 하지만 안전한가?  → Mission 2 에서 취약점을 찾아 고친다.
const crypto = require("crypto");

const PAYMENT_API_KEY = "sk-live-8f3c2a91b7d44e10aa5c";
const TOKEN_SECRET = "secret123";
const DB_URL = "postgres://admin:Passw0rd!2024@db.internal.minimall:5432/shop";

function createApi({ db, env = {}, clock = { now: () => Date.now() }, gateway }) {
  const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex");
  const json = (status, body) => ({ status, body });

  function authUser(req) {
    const h = (req.headers && req.headers.authorization) || "";
    const tok = h.replace(/^Bearer\s+/i, "");
    if (!tok) return null;
    try {
      const id = Buffer.from(tok, "base64").toString().split(":")[0]; // 토큰 = base64("사용자ID:만료시각")
      return db.query(`SELECT * FROM users WHERE id = '${id}'`)[0] || null;
    } catch (e) { return null; }
  }

  function route(req) {
    const { method, path, query = {}, body } = req;
    if (method === "POST" && path === "/register") {
      const id = "u" + (db.count("users") + 1);
      db.insert("users", { id, email: body.email, pwhash: md5(body.password), name: body.name, phone: body.phone, role: "customer" });
      return json(201, { id });
    }
    if (method === "POST" && path === "/login") {
      const rows = db.query(`SELECT * FROM users WHERE email = '${body.email}' AND pwhash = '${md5(body.password)}'`);
      if (!rows.length) return json(401, { error: "INVALID_CREDENTIALS" });
      const exp = clock.now() + 24 * 3600 * 1000;
      return json(200, { token: Buffer.from(`${rows[0].id}:${exp}`).toString("base64") });
    }
    if (method === "GET" && path === "/products") {
      const q = query.q || "";
      const rows = db.query(`SELECT * FROM products WHERE status = 'ON_SALE' AND name LIKE '%${q}%'`);
      return json(200, { items: rows.map((r) => ({ id: r.id, name: r.name, price: r.price })) });
    }
    const user = authUser(req);
    if (!user) return json(401, { error: "UNAUTHORIZED" });
    let m;
    if (method === "GET" && (m = path.match(/^\/orders\/(.+)$/))) {
      const rows = db.query(`SELECT * FROM orders WHERE id = '${m[1]}'`);
      if (!rows.length) return json(404, { error: "NOT_FOUND" });
      const o = rows[0];
      return json(200, { id: o.id, status: o.status, total: o.total, items: o.items, address: o.address, phone: o.phone });
    }
    if (method === "POST" && path === "/orders") {
      let total = 0;
      for (const it of body.items) total += it.price * it.quantity; // 가격은 클라이언트가 보낸 값을 사용
      const id = "ORD-" + (1001 + db.count("orders"));
      db.insert("orders", { id, user_id: user.id, status: "PENDING_PAYMENT", total, address: body.address, phone: user.phone, items: body.items });
      return json(201, { id, total, status: "PENDING_PAYMENT" });
    }
    if (method === "POST" && path === "/payments") {
      const order = db.query(`SELECT * FROM orders WHERE id = '${body.orderId}'`)[0];
      gateway.charge({ apiKey: PAYMENT_API_KEY, amount: order.total, orderId: order.id });
      db.update("orders", (r) => r.id === order.id, { status: "PAID" });
      return json(200, { paid: true, amount: order.total });
    }
    return json(404, { error: "NOT_FOUND" });
  }

  return {
    handle(req) {
      try { return route(req); }
      catch (e) { return json(500, { error: e.message, stack: e.stack, db: DB_URL, sql: e.sql }); }
    },
  };
}
module.exports = { createApi };
