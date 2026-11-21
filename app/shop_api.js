// MiniMall API 초안 — AI 코딩 도구가 만들어 준 코드라고 가정한다. (수업용)
// 데모는 잘 돌아가고 테스트도 통과한다. 하지만 안전한가?  → Mission 2 에서 취약점을 찾아 고친다.// MiniMall API — Mission 2 수정본 (docs/SEC_CONTRACT.md §2.1)
// V1 바인딩(?)  V2 소유자 확인  V3 env 에서만 키 수령(없으면 예외)  V4 scrypt+솔트
// V5 오류는 짧은 코드만  V6 가격·수량·상품·주소를 서버가 검증  V7 HMAC 서명 + 만료 토큰
const crypto = require("crypto");

const TOKEN_TTL_MS = 24 * 3600 * 1000; // 토큰 유효시간 24시간

// ---------- V4: 비밀번호 해시 (솔트 + scrypt) ----------
// 저장 형식 "솔트:해시". 같은 비밀번호라도 솔트가 달라 저장값이 매번 다르다.
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(pw), salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
  if (typeof pw !== "string" || typeof stored !== "string" || !stored.includes(":")) return false;
  const [salt, hash] = stored.split(":");
  const expected = Buffer.from(hash, "hex");
  const actual = crypto.scryptSync(pw, salt, 64);
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

// ---------- V7: 서명된 토큰 (내용.서명) ----------
function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}
// 서명이 맞고 만료 전이면 payload, 아니면 null
function verifyToken(token, secret, nowMs) {
  const parts = String(token).split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null; // 위조·변조
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!payload || typeof payload.sub !== "string" || typeof payload.exp !== "number") return null;
    if (payload.exp <= nowMs) return null; // 만료
    return payload;
  } catch (e) { return null; }
}

function createApi({ db, env = {}, clock = { now: () => Date.now() }, gateway }) {
  // ---------- V3: 비밀은 env 에서만. 없으면 시작하지 않는다(fail closed) ----------
  const PAYMENT_API_KEY = env.PAYMENT_API_KEY;
  const TOKEN_SECRET = env.TOKEN_SECRET;
  if (!PAYMENT_API_KEY || !TOKEN_SECRET) throw new Error("MISSING_ENV");

  const json = (status, body) => ({ status, body });
  const isStr = (v) => typeof v === "string" && v.trim() !== "";

  function authUser(req) {
    const h = (req.headers && req.headers.authorization) || "";
    const tok = h.replace(/^Bearer\s+/i, "");
    if (!tok) return null;
    const payload = verifyToken(tok, TOKEN_SECRET, clock.now());
    if (!payload) return null;
    // V1: 값은 항상 ? 로 바인딩
    return db.query("SELECT * FROM users WHERE id = ?", [payload.sub])[0] || null;
  }

  function route(req) {
    const { method, path, query = {} } = req;
    const body = req.body && typeof req.body === "object" ? req.body : {};

    if (method === "POST" && path === "/register") {
      if (!isStr(body.email) || !isStr(body.password)) return json(400, { error: "INVALID_INPUT" });
      if (db.query("SELECT * FROM users WHERE email = ?", [body.email]).length) return json(409, { error: "EMAIL_EXISTS" });
      const id = "u" + (db.count("users") + 1);
      db.insert("users", { id, email: body.email, pwhash: hashPassword(body.password), name: body.name, phone: body.phone, role: "customer" });
      return json(201, { id });
    }

    if (method === "POST" && path === "/login") {
      // 이메일로만 조회하고, 비밀번호는 코드에서 해시 비교한다
      const rows = isStr(body.email) ? db.query("SELECT * FROM users WHERE email = ?", [body.email]) : [];
      if (!rows.length || !verifyPassword(body.password, rows[0].pwhash)) return json(401, { error: "INVALID_CREDENTIALS" });
      const exp = clock.now() + TOKEN_TTL_MS;
      return json(200, { token: signToken({ sub: rows[0].id, exp }, TOKEN_SECRET) });
    }

    if (method === "GET" && path === "/products") {
      const q = typeof query.q === "string" ? query.q : "";
      const rows = db.query("SELECT * FROM products WHERE status = 'ON_SALE' AND name LIKE ?", [`%${q}%`]);
      return json(200, { items: rows.map((r) => ({ id: r.id, name: r.name, price: r.price })) });
    }

    const user = authUser(req);
    if (!user) return json(401, { error: "UNAUTHORIZED" });
    let m;

    if (method === "GET" && (m = path.match(/^\/orders\/(.+)$/))) {
      const o = db.query("SELECT * FROM orders WHERE id = ?", [m[1]])[0];
      // V2: 없는 주문과 남의 주문은 같은 응답
      if (!o || o.user_id !== user.id) return json(404, { error: "NOT_FOUND" });
      return json(200, { id: o.id, status: o.status, total: o.total, items: o.items, address: o.address });
    }

    if (method === "POST" && path === "/orders") {
      // V6: 클라이언트 값을 믿지 않고 서버가 검증·계산
      if (!Array.isArray(body.items) || body.items.length < 1 || !isStr(body.address)) return json(400, { error: "INVALID_INPUT" });
      let total = 0;
      const items = [];
      for (const it of body.items) {
        if (!it || !Number.isInteger(it.quantity) || it.quantity < 1 || it.quantity > 99) return json(400, { error: "INVALID_QUANTITY" });
        if (it.productId === undefined || it.productId === null) return json(400, { error: "INVALID_PRODUCT" });
        const p = db.query("SELECT * FROM products WHERE id = ?", [it.productId])[0];
        if (!p || p.status !== "ON_SALE") return json(400, { error: "INVALID_PRODUCT" });
        total += p.price * it.quantity; // 가격은 서버(DB) 기준
        items.push({ productId: p.id, quantity: it.quantity, price: p.price });
      }
      const id = "ORD-" + (1001 + db.count("orders"));
      db.insert("orders", { id, user_id: user.id, status: "PENDING_PAYMENT", total, address: body.address, phone: user.phone, items });
      return json(201, { id, total, status: "PENDING_PAYMENT" });
    }

    if (method === "POST" && path === "/payments") {
      const order = isStr(body.orderId) ? db.query("SELECT * FROM orders WHERE id = ?", [body.orderId])[0] : null;
      if (!order || order.user_id !== user.id) return json(404, { error: "NOT_FOUND" }); // V2
      gateway.charge({ apiKey: PAYMENT_API_KEY, amount: order.total, orderId: order.id }); // V3: env 키 사용
      db.update("orders", (r) => r.id === order.id, { status: "PAID" });
      return json(200, { paid: true, amount: order.total });
    }

    return json(404, { error: "NOT_FOUND" });
  }

  return {
    handle(req) {
      try { return route(req); }
      catch (e) {
        // V5: 자세한 내용은 서버 로그에만, 응답에는 짧은 코드만
        console.error("[shop_api] internal error:", e && e.stack);
        return json(500, { error: "INTERNAL_ERROR" });
      }
    },
  };
}
module.exports = { createApi };