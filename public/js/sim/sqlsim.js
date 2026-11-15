// A small SQL engine over in-memory JSON tables (MySQL-flavoured). It exists so that training web apps can build
// queries the way vulnerable code does — by string concatenation — and still behave according to real SQL rules.
// It only ever touches the tables handed to it: no files, no network, nothing outside the simulation.
//
// Supported: SELECT [DISTINCT] exprs FROM table [WHERE ..] [ORDER BY col|n [ASC|DESC]] [LIMIT n] with UNION [ALL],
// comments (-- , #, /* */), AND/OR/NOT, = != <> < > <= >=, LIKE, IN, IS [NOT] NULL, a few scalar functions,
// and the virtual tables information_schema.tables / information_schema.columns.

export class SqlError extends Error {
  constructor(message, code = 1064) { super(message); this.code = code; }
}

const KEYWORDS = new Set(['select', 'from', 'where', 'order', 'by', 'limit', 'union', 'all', 'distinct', 'and', 'or', 'not', 'like', 'in', 'is', 'null', 'as', 'asc', 'desc', 'true', 'false']);

function syntaxError(sql, pos) {
  const near = sql.slice(pos).replace(/\s+$/, '');
  return new SqlError(`You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '${near}' at line 1`);
}

// ---------------- tokenizer ----------------
export function tokenize(sql) {
  const out = [];
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '#') break; // rest of line is a comment
    if (c === '-' && sql[i + 1] === '-' && (i + 2 >= sql.length || /\s/.test(sql[i + 2]))) break;
    if (c === '/' && sql[i + 1] === '*') {
      const end = sql.indexOf('*/', i + 2);
      if (end < 0) throw syntaxError(sql, i);
      i = end + 2; continue;
    }
    if (c === "'" || c === '"') {
      let j = i + 1; let s = '';
      for (;;) {
        if (j >= sql.length) throw syntaxError(sql, i);
        if (sql[j] === '\\' && j + 1 < sql.length) { s += sql[j + 1]; j += 2; continue; }
        if (sql[j] === c) { if (sql[j + 1] === c) { s += c; j += 2; continue; } break; }
        s += sql[j++];
      }
      out.push({ t: 'str', v: s, pos: i }); i = j + 1; continue;
    }
    const num = /^\d+(\.\d+)?/.exec(sql.slice(i));
    if (num) { out.push({ t: 'num', v: Number(num[0]), pos: i }); i += num[0].length; continue; }
    const id = /^[A-Za-z_][A-Za-z0-9_$]*/.exec(sql.slice(i));
    if (id) {
      const lower = id[0].toLowerCase();
      out.push(KEYWORDS.has(lower) ? { t: 'kw', v: lower, pos: i } : { t: 'id', v: id[0], pos: i });
      i += id[0].length; continue;
    }
    if (c === '`') {
      const end = sql.indexOf('`', i + 1);
      if (end < 0) throw syntaxError(sql, i);
      out.push({ t: 'id', v: sql.slice(i + 1, end), pos: i }); i = end + 1; continue;
    }
    const two = sql.slice(i, i + 2);
    if (['<=', '>=', '<>', '!='].includes(two)) { out.push({ t: 'op', v: two, pos: i }); i += 2; continue; }
    if ('=<>(),*.;+-'.includes(c)) { out.push({ t: 'op', v: c, pos: i }); i++; continue; }
    throw syntaxError(sql, i);
  }
  return out;
}

// ---------------- parser ----------------
class Parser {
  constructor(sql) { this.sql = sql; this.toks = tokenize(sql); this.p = 0; }
  peek(o = 0) { return this.toks[this.p + o]; }
  err(tok = this.peek()) { return syntaxError(this.sql, tok ? tok.pos : this.sql.length); }
  isKw(v) { const t = this.peek(); return t && t.t === 'kw' && t.v === v; }
  isOp(v) { const t = this.peek(); return t && t.t === 'op' && t.v === v; }
  eatKw(v) { if (this.isKw(v)) { this.p++; return true; } return false; }
  eatOp(v) { if (this.isOp(v)) { this.p++; return true; } return false; }
  needKw(v) { if (!this.eatKw(v)) throw this.err(); }
  needOp(v) { if (!this.eatOp(v)) throw this.err(); }

  parse() {
    const q = this.parseUnion();
    this.eatOp(';');
    if (this.peek()) throw this.err();
    return q;
  }

  parseUnion() {
    const parts = [this.parseSelect()];
    const alls = [];
    while (this.eatKw('union')) { alls.push(this.eatKw('all')); parts.push(this.parseSelect()); }
    let orderBy = null; let limit = null;
    // ORDER BY / LIMIT after the last SELECT apply to the whole union
    if (parts.length > 1) { const last = parts[parts.length - 1]; orderBy = last.orderBy; limit = last.limit; last.orderBy = null; last.limit = null; }
    return { parts, alls, orderBy, limit };
  }

  parseSelect() {
    this.needKw('select');
    const distinct = this.eatKw('distinct');
    const cols = [];
    do {
      if (this.isOp('*')) { this.p++; cols.push({ star: true }); continue; }
      const expr = this.parseExpr();
      let alias = null;
      if (this.eatKw('as')) { const t = this.peek(); if (!t || (t.t !== 'id' && t.t !== 'str')) throw this.err(); alias = t.v; this.p++; }
      cols.push({ expr, alias });
    } while (this.eatOp(','));
    let from = null; let where = null; let orderBy = null; let limit = null;
    if (this.eatKw('from')) {
      const t = this.peek();
      if (!t || t.t !== 'id') throw this.err();
      this.p++;
      from = t.v;
      if (this.eatOp('.')) { const t2 = this.peek(); if (!t2 || t2.t !== 'id') throw this.err(); this.p++; from = `${from}.${t2.v}`; }
    }
    if (this.eatKw('where')) where = this.parseExpr();
    if (this.eatKw('order')) {
      this.needKw('by');
      const t = this.peek();
      if (!t || (t.t !== 'id' && t.t !== 'num')) throw this.err();
      this.p++;
      let key = t.v;
      if (t.t === 'id' && this.isOp('.')) { this.p++; const t2 = this.peek(); if (!t2 || t2.t !== 'id') throw this.err(); this.p++; key = t2.v; }
      const desc = this.eatKw('desc'); if (!desc) this.eatKw('asc');
      orderBy = { key, desc, num: t.t === 'num' };
    }
    if (this.eatKw('limit')) {
      const t = this.peek();
      if (!t || t.t !== 'num') throw this.err();
      this.p++; limit = t.v;
    }
    return { distinct, cols, from, where, orderBy, limit };
  }

  // precedence: OR < AND < NOT < comparison < additive < primary
  parseExpr() { return this.parseOr(); }
  parseOr() { let l = this.parseAnd(); while (this.eatKw('or')) l = { op: 'or', l, r: this.parseAnd() }; return l; }
  parseAnd() { let l = this.parseNot(); while (this.eatKw('and')) l = { op: 'and', l, r: this.parseNot() }; return l; }
  parseNot() { if (this.eatKw('not')) return { op: 'not', e: this.parseNot() }; return this.parseCmp(); }
  parseCmp() {
    const l = this.parseAdd();
    const t = this.peek();
    if (t && t.t === 'op' && ['=', '!=', '<>', '<', '>', '<=', '>='].includes(t.v)) { this.p++; return { op: t.v, l, r: this.parseAdd() }; }
    if (this.isKw('like')) { this.p++; return { op: 'like', l, r: this.parseAdd() }; }
    if (this.isKw('not') && this.peek(1)?.t === 'kw' && this.peek(1).v === 'like') { this.p += 2; return { op: 'not', e: { op: 'like', l, r: this.parseAdd() } }; }
    if (this.isKw('in')) {
      this.p++; this.needOp('(');
      const list = [];
      do list.push(this.parseExpr()); while (this.eatOp(','));
      this.needOp(')');
      return { op: 'in', l, list };
    }
    if (this.isKw('is')) {
      this.p++;
      const neg = this.eatKw('not');
      this.needKw('null');
      return neg ? { op: 'not', e: { op: 'isnull', e: l } } : { op: 'isnull', e: l };
    }
    return l;
  }
  parseAdd() {
    let l = this.parsePrimary();
    while (this.isOp('+') || this.isOp('-')) { const op = this.peek().v; this.p++; l = { op, l, r: this.parsePrimary() }; }
    return l;
  }
  parsePrimary() {
    const t = this.peek();
    if (!t) throw this.err();
    if (t.t === 'num' || t.t === 'str') { this.p++; return { lit: t.v }; }
    if (t.t === 'kw' && t.v === 'null') { this.p++; return { lit: null }; }
    if (t.t === 'kw' && (t.v === 'true' || t.v === 'false')) { this.p++; return { lit: t.v === 'true' ? 1 : 0 }; }
    if (t.t === 'op' && t.v === '(') { this.p++; const e = this.parseExpr(); this.needOp(')'); return e; }
    if (t.t === 'op' && t.v === '-') { this.p++; return { op: '-', l: { lit: 0 }, r: this.parsePrimary() }; }
    if (t.t === 'id') {
      this.p++;
      if (this.isOp('(')) {
        this.p++;
        const args = [];
        if (!this.isOp(')')) do args.push(this.parseExpr()); while (this.eatOp(','));
        this.needOp(')');
        return { fn: t.v.toLowerCase(), args };
      }
      if (this.isOp('.')) { this.p++; const t2 = this.peek(); if (!t2 || t2.t !== 'id') throw this.err(); this.p++; return { col: t2.v, table: t.v }; }
      return { col: t.v };
    }
    throw this.err(t);
  }
}

// ---------------- evaluation ----------------
const truthy = (v) => v !== null && v !== undefined && v !== 0 && v !== '' && v !== false;
const num = (v) => (typeof v === 'number' ? v : Number.parseFloat(v) || 0);

function likeToRegExp(p) {
  return new RegExp(`^${String(p).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/%/g, '.*').replace(/_/g, '.')}$`, 'is');
}

function compare(a, b) {
  if (a === null || b === null) return null;
  if (typeof a === 'number' || typeof b === 'number') return num(a) - num(b);
  const x = String(a).toLowerCase(); const y = String(b).toLowerCase();
  return x < y ? -1 : x > y ? 1 : 0;
}

export class Database {
  /** @param spec { name, version, user, tables: { users: { columns: [...], rows: [{...}] } } } */
  constructor(spec) {
    this.name = spec.name || 'app';
    this.version = spec.version || '5.7.33-0ubuntu0.18.04.1';
    this.user = spec.user || 'webapp@localhost';
    this.tables = JSON.parse(JSON.stringify(spec.tables || {}));
  }

  /** Quote a value so it can be safely embedded in SQL (what a prepared statement does). */
  static quote(v) {
    if (v === null || v === undefined) return 'NULL';
    if (typeof v === 'number') return String(v);
    return `'${String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
  }
  /** Replace each ? with a safely quoted parameter. Values can never change the structure of the query. */
  static bind(sql, params) {
    let i = 0;
    return sql.replace(/\?/g, () => Database.quote(params[i++]));
  }

  table(name, ctxName = 'field list') {
    const clean = name.toLowerCase().replace(/^`|`$/g, '');
    if (clean === 'information_schema.tables') return { columns: ['table_schema', 'table_name'], rows: Object.keys(this.tables).map((t) => ({ table_schema: this.name, table_name: t })) };
    if (clean === 'information_schema.columns') {
      return { columns: ['table_schema', 'table_name', 'column_name'], rows: Object.entries(this.tables).flatMap(([t, d]) => d.columns.map((c) => ({ table_schema: this.name, table_name: t, column_name: c }))) };
    }
    const key = Object.keys(this.tables).find((t) => t.toLowerCase() === clean.replace(`${this.name.toLowerCase()}.`, ''));
    if (!key) throw new SqlError(`Table '${this.name}.${clean}' doesn't exist`, 1146);
    return this.tables[key];
  }

  /** Run a query. Returns { columns: [...], rows: [[...]] }. Throws SqlError. */
  query(sql) {
    const ast = new Parser(sql).parse();
    const results = ast.parts.map((s) => this.runSelect(s));
    const width = results[0].columns.length;
    for (const r of results) if (r.columns.length !== width) throw new SqlError('The used SELECT statements have a different number of columns', 1222);
    let rows = results.flatMap((r) => r.rows);
    if (ast.parts.length > 1) {
      // UNION (without ALL) removes duplicate rows
      const seen = new Set(); const dedup = [];
      rows.forEach((r, i) => {
        const partIdx = results.findIndex((_, k) => results.slice(0, k + 1).reduce((s, x) => s + x.rows.length, 0) > i);
        const all = partIdx > 0 && ast.alls[partIdx - 1];
        const key = JSON.stringify(r);
        if (all || !seen.has(key)) { seen.add(key); dedup.push(r); }
      });
      rows = dedup;
    }
    const columns = results[0].columns;
    if (ast.orderBy) rows = this.order(rows, columns, ast.orderBy);
    if (ast.limit !== null) rows = rows.slice(0, ast.limit);
    return { columns, rows };
  }

  order(rows, columns, ob) {
    let idx;
    if (ob.num) {
      idx = ob.key - 1;
      if (idx < 0 || idx >= columns.length) throw new SqlError(`Unknown column '${ob.key}' in 'order clause'`, 1054);
    } else {
      idx = columns.findIndex((c) => c.toLowerCase() === String(ob.key).toLowerCase());
      if (idx < 0) throw new SqlError(`Unknown column '${ob.key}' in 'order clause'`, 1054);
    }
    return [...rows].sort((a, b) => (compare(a[idx], b[idx]) ?? 0) * (ob.desc ? -1 : 1));
  }

  runSelect(s) {
    const t = s.from ? this.table(s.from) : { columns: [], rows: [{}] };
    const colsOut = []; const names = [];
    for (const c of s.cols) {
      if (c.star) { t.columns.forEach((n) => { colsOut.push({ expr: { col: n } }); names.push(n); }); continue; }
      colsOut.push(c);
      names.push(c.alias ?? (c.expr.col ?? this.exprLabel(c.expr)));
    }
    for (const c of colsOut) this.checkColumns(c.expr, t, 'field list');
    if (s.where) this.checkColumns(s.where, t, 'where clause');
    let rows = t.rows.filter((r) => !s.where || truthy(this.ev(s.where, r)));
    if (s.orderBy) {
      // ORDER BY before projection so it can use any table column or a select position
      if (s.orderBy.num) {
        if (s.orderBy.key < 1 || s.orderBy.key > colsOut.length) throw new SqlError(`Unknown column '${s.orderBy.key}' in 'order clause'`, 1054);
        const e = colsOut[s.orderBy.key - 1].expr;
        rows = [...rows].sort((a, b) => (compare(this.ev(e, a), this.ev(e, b)) ?? 0) * (s.orderBy.desc ? -1 : 1));
      } else {
        const known = names.some((n) => n.toLowerCase() === String(s.orderBy.key).toLowerCase()) || t.columns.some((n) => n.toLowerCase() === String(s.orderBy.key).toLowerCase());
        if (!known) throw new SqlError(`Unknown column '${s.orderBy.key}' in 'order clause'`, 1054);
        const e = { col: t.columns.find((n) => n.toLowerCase() === String(s.orderBy.key).toLowerCase()) ?? s.orderBy.key };
        rows = [...rows].sort((a, b) => (compare(this.ev(e, a), this.ev(e, b)) ?? 0) * (s.orderBy.desc ? -1 : 1));
      }
    }
    let out = rows.map((r) => colsOut.map((c) => this.ev(c.expr, r)));
    if (s.distinct) { const seen = new Set(); out = out.filter((r) => { const k = JSON.stringify(r); if (seen.has(k)) return false; seen.add(k); return true; }); }
    if (s.limit !== null) out = out.slice(0, s.limit);
    return { columns: names, rows: out };
  }

  exprLabel(e) { return e.lit !== undefined ? String(e.lit) : e.fn ? `${e.fn}()` : 'expr'; }

  checkColumns(e, t, where) {
    if (!e || typeof e !== 'object') return;
    if (e.col !== undefined && !t.columns.some((c) => c.toLowerCase() === e.col.toLowerCase())) {
      throw new SqlError(`Unknown column '${e.col}' in '${where}'`, 1054);
    }
    for (const k of ['l', 'r', 'e']) if (e[k]) this.checkColumns(e[k], t, where);
    for (const k of ['args', 'list']) (e[k] || []).forEach((x) => this.checkColumns(x, t, where));
  }

  ev(e, row) {
    if (e.lit !== undefined) return e.lit;
    if (e.col !== undefined) { const k = Object.keys(row).find((c) => c.toLowerCase() === e.col.toLowerCase()); return k === undefined ? null : row[k]; }
    if (e.fn) return this.fn(e.fn, e.args.map((a) => this.ev(a, row)));
    switch (e.op) {
      case 'and': return truthy(this.ev(e.l, row)) && truthy(this.ev(e.r, row)) ? 1 : 0;
      case 'or': return truthy(this.ev(e.l, row)) || truthy(this.ev(e.r, row)) ? 1 : 0;
      case 'not': return truthy(this.ev(e.e, row)) ? 0 : 1;
      case '+': return num(this.ev(e.l, row)) + num(this.ev(e.r, row));
      case '-': return num(this.ev(e.l, row)) - num(this.ev(e.r, row));
      case 'like': { const a = this.ev(e.l, row); return a === null ? 0 : likeToRegExp(this.ev(e.r, row)).test(String(a)) ? 1 : 0; }
      case 'in': { const a = this.ev(e.l, row); return e.list.some((x) => compare(a, this.ev(x, row)) === 0) ? 1 : 0; }
      case 'isnull': return this.ev(e.e, row) === null ? 1 : 0;
      default: {
        const c = compare(this.ev(e.l, row), this.ev(e.r, row));
        if (c === null) return 0;
        return ({ '=': c === 0, '!=': c !== 0, '<>': c !== 0, '<': c < 0, '>': c > 0, '<=': c <= 0, '>=': c >= 0 })[e.op] ? 1 : 0;
      }
    }
  }

  fn(name, args) {
    switch (name) {
      case 'version': return this.version;
      case 'database': case 'schema': return this.name;
      case 'user': case 'current_user': case 'system_user': return this.user;
      case 'concat': return args.some((a) => a === null) ? null : args.map(String).join('');
      case 'concat_ws': return args.slice(1).map(String).join(String(args[0]));
      case 'length': return String(args[0] ?? '').length;
      case 'lower': return String(args[0] ?? '').toLowerCase();
      case 'upper': return String(args[0] ?? '').toUpperCase();
      case 'substring': case 'substr': return String(args[0] ?? '').substr(num(args[1]) - 1, args[2] === undefined ? undefined : num(args[2]));
      case 'ascii': return String(args[0] ?? '').charCodeAt(0) || 0;
      case 'count': return args.length;
      default: throw new SqlError(`FUNCTION ${this.name}.${name} does not exist`, 1305);
    }
  }
}
