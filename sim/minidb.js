// 아주 작은 인메모리 SQL 엔진 (수업용). 실제 DB 가 아니다.
// 지원: SELECT <열|*> FROM <표> [WHERE 조건] / 조건: <값> = | LIKE <값>, AND, OR, ?(바인딩), '문자열', 숫자, -- 주석
// 문자열을 이어 붙인 쿼리(인젝션)가 실제로 의미를 바꾸도록 만든 것이다. 파라미터 바인딩(?)으로 넘긴 값은 항상 '값'으로만 쓰인다.
class SqlError extends Error {
  constructor(msg, sql) { super(msg); this.name = "SqlError"; this.sql = sql; }
}

function tokenize(src, sql) {
  const t = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === "-" && src[i + 1] === "-") break; // 주석: 나머지 무시
    if (c === "#") break;
    if (c === "'") {
      let j = i + 1, s = "";
      for (;;) {
        if (j >= src.length) throw new SqlError(`unterminated string near "${src.slice(i, i + 12)}"`, sql);
        if (src[j] === "'" && src[j + 1] === "'") { s += "'"; j += 2; continue; }
        if (src[j] === "'") break;
        s += src[j++];
      }
      t.push({ k: "str", v: s }); i = j + 1; continue;
    }
    if (c === "?") { t.push({ k: "ph" }); i++; continue; }
    if (c === "=") { t.push({ k: "op", v: "=" }); i++; continue; }
    if (c === ",") { t.push({ k: "comma" }); i++; continue; }
    if (c === "*") { t.push({ k: "star" }); i++; continue; }
    let m = /^-?\d+(\.\d+)?/.exec(src.slice(i));
    if (m) { t.push({ k: "num", v: Number(m[0]) }); i += m[0].length; continue; }
    m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i));
    if (m) {
      const w = m[0], u = w.toUpperCase();
      if (["SELECT", "FROM", "WHERE", "AND", "OR", "LIKE"].includes(u)) t.push({ k: "kw", v: u });
      else t.push({ k: "id", v: w });
      i += w.length; continue;
    }
    throw new SqlError(`syntax error near "${src.slice(i, i + 12)}"`, sql);
  }
  return t;
}

function createDb(initial = {}) {
  const tables = {};
  for (const [n, rows] of Object.entries(initial)) tables[n] = rows.map((r) => ({ ...r }));
  const log = [];

  function query(sql, params = []) {
    log.push(sql);
    const t = tokenize(sql, sql);
    let p = 0, ph = 0;
    const peek = () => t[p], next = () => t[p++];
    const expect = (k, v) => {
      const x = next();
      if (!x || x.k !== k || (v && x.v !== v)) throw new SqlError(`syntax error near "${x ? (x.v ?? x.k) : "end"}"`, sql);
      return x;
    };
    expect("kw", "SELECT");
    const cols = [];
    if (peek() && peek().k === "star") { next(); cols.push("*"); }
    else { do { cols.push(expect("id").v); } while (peek() && peek().k === "comma" && next()); }
    expect("kw", "FROM");
    const table = expect("id").v;
    if (!tables[table]) throw new SqlError(`no such table: ${table}`, sql);
    let where = null;
    if (peek() && peek().k === "kw" && peek().v === "WHERE") {
      next();
      const operand = () => {
        const x = next();
        if (!x) throw new SqlError("syntax error near end", sql);
        if (x.k === "ph") { if (ph >= params.length) throw new SqlError("missing bind parameter", sql); return { lit: params[ph++] }; }
        if (x.k === "str" || x.k === "num") return { lit: x.v };
        if (x.k === "id") return { col: x.v };
        throw new SqlError(`syntax error near "${x.v ?? x.k}"`, sql);
      };
      const term = () => {
        const a = operand();
        const o = next();
        if (!o || !((o.k === "op" && o.v === "=") || (o.k === "kw" && o.v === "LIKE"))) throw new SqlError(`syntax error near "${o ? (o.v ?? o.k) : "end"}"`, sql);
        const b = operand();
        return { a, b, op: o.v };
      };
      const groups = [[term()]];
      while (peek() && peek().k === "kw" && (peek().v === "AND" || peek().v === "OR")) {
        const w = next().v;
        const tm = term();
        if (w === "AND") groups[groups.length - 1].push(tm); else groups.push([tm]);
      }
      where = groups;
    }
    if (p < t.length) throw new SqlError(`syntax error near "${t[p].v ?? t[p].k}"`, sql);
    const val = (o, row) => {
      if ("lit" in o) return o.lit;
      if (!(o.col in row)) throw new SqlError(`no such column: ${o.col}`, sql);
      return row[o.col];
    };
    const test = (tm, row) => {
      const x = val(tm.a, row), y = val(tm.b, row);
      if (tm.op === "=") return String(x) === String(y);
      const re = new RegExp("^" + String(y).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/%/g, ".*") + "$", "i");
      return re.test(String(x));
    };
    let rows = tables[table].filter((r) => !where || where.some((g) => g.every((tm) => test(tm, r))));
    if (!(cols.length === 1 && cols[0] === "*")) rows = rows.map((r) => Object.fromEntries(cols.map((c) => [c, r[c]])));
    return rows.map((r) => ({ ...r }));
  }
  function insert(table, row) { (tables[table] ||= []).push({ ...row }); return row; }
  function update(table, pred, patch) { let n = 0; for (const r of tables[table] || []) if (pred(r)) { Object.assign(r, patch); n++; } return n; }
  function count(table) { return (tables[table] || []).length; }
  return { query, insert, update, count, tables, log, SqlError };
}
module.exports = { createDb, SqlError };
