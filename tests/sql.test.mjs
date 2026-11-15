import test from 'node:test';
import assert from 'node:assert/strict';
import { Database, SqlError, tokenize } from '../public/js/sim/sqlsim.js';

const db = () => new Database({
  name: 'shopzone',
  tables: {
    users: {
      columns: ['id', 'username', 'password', 'role'],
      rows: [
        { id: 1, username: 'admin', password: 'x1', role: 'admin' },
        { id: 2, username: 'alice', password: 'x2', role: 'customer' },
        { id: 3, username: 'bob', password: 'x3', role: 'customer' },
      ],
    },
    products: {
      columns: ['id', 'name', 'price'],
      rows: [{ id: 1, name: 'Hammer', price: 12.5 }, { id: 2, name: 'Drill', price: 80 }, { id: 3, name: 'Saw', price: 20 }],
    },
  },
});

const names = (r) => r.rows.map((x) => x[0]);

test('basic SELECT, WHERE, ORDER BY, LIMIT, aliases, star', () => {
  const d = db();
  assert.deepEqual(d.query('SELECT * FROM users').columns, ['id', 'username', 'password', 'role']);
  assert.deepEqual(names(d.query("SELECT username FROM users WHERE role = 'customer'")), ['alice', 'bob']);
  assert.deepEqual(names(d.query('SELECT name FROM products WHERE price > 15 ORDER BY price DESC')), ['Drill', 'Saw']);
  assert.deepEqual(names(d.query('SELECT name FROM products ORDER BY price LIMIT 2')), ['Hammer', 'Saw']);
  assert.deepEqual(d.query('SELECT name AS n FROM products LIMIT 1').columns, ['n']);
  assert.deepEqual(names(d.query("select USERNAME from USERS where ID = 2")), ['alice'], 'keywords and identifiers are case-insensitive');
  assert.deepEqual(names(d.query('SELECT name FROM products WHERE id IN (1, 3)')), ['Hammer', 'Saw']);
  assert.deepEqual(names(d.query("SELECT username FROM users WHERE username LIKE 'a%'")), ['admin', 'alice']);
  assert.deepEqual(names(d.query("SELECT username FROM users WHERE NOT role = 'customer'")), ['admin']);
  assert.deepEqual(names(d.query("SELECT 1+2")), [3]);
});

test('precedence: AND binds tighter than OR; parentheses override', () => {
  const d = db();
  assert.equal(d.query("SELECT username FROM users WHERE role = 'admin' OR role = 'customer' AND id = 2").rows.length, 2);
  assert.equal(d.query("SELECT username FROM users WHERE (role = 'admin' OR role = 'customer') AND id = 2").rows.length, 1);
});

test('comments end or interrupt a statement the way MySQL does', () => {
  const d = db();
  assert.deepEqual(names(d.query("SELECT username FROM users WHERE id = 1 -- AND id = 2")), ['admin']);
  assert.deepEqual(names(d.query("SELECT username FROM users WHERE id = 1 # ignored")), ['admin']);
  assert.deepEqual(names(d.query("SELECT username FROM users /* a comment */ WHERE id = 3")), ['bob']);
  // "--" without a following space is NOT a comment: this is arithmetic, 1 - (-1) = 2
  assert.deepEqual(names(d.query('SELECT username FROM users WHERE id = 1--1')), ['alice']);
  assert.equal(tokenize("SELECT 1 -- x").length, 2);
});

test('string concatenation vs bound parameters: the same input means different things', () => {
  const d = db();
  const input = "nobody' OR '1'='1";
  // vulnerable pattern: the input becomes part of the query text
  const unsafe = d.query(`SELECT username FROM users WHERE username = '${input}'`);
  assert.equal(unsafe.rows.length, 3, 'the quote closed the string and the OR clause matched every row');
  // safe pattern: the input is always just a value
  const safe = d.query(Database.bind('SELECT username FROM users WHERE username = ?', [input]));
  assert.equal(safe.rows.length, 0);
  assert.equal(Database.quote("it's"), "'it\\'s'");
  assert.equal(Database.quote(5), '5');
  assert.equal(Database.quote(null), 'NULL');
  assert.equal(Database.bind('SELECT ? , ?', ['a', 2]), "SELECT 'a' , 2");
});

test('comment-terminated login query ignores the password check (why concatenation is dangerous)', () => {
  const d = db();
  const login = (u, p) => d.query(`SELECT * FROM users WHERE username = '${u}' AND password = '${p}'`).rows.length;
  assert.equal(login('admin', 'x1'), 1);
  assert.equal(login('admin', 'wrong'), 0);
  assert.equal(login("admin'-- ", 'wrong'), 1, 'everything after the comment marker is discarded');
  assert.equal(login("admin' #", 'wrong'), 1);
});

test('UNION: needs matching column counts, combines results, de-duplicates unless ALL', () => {
  const d = db();
  const r = d.query("SELECT name, price FROM products WHERE id = 1 UNION SELECT username, id FROM users WHERE id = 1");
  assert.deepEqual(r.rows, [['Hammer', 12.5], ['admin', 1]]);
  assert.deepEqual(r.columns, ['name', 'price'], 'column names come from the first SELECT');
  assert.throws(() => d.query('SELECT name FROM products UNION SELECT username, id FROM users'), (e) => e.code === 1222 && /different number of columns/.test(e.message));
  assert.equal(d.query('SELECT 1 UNION SELECT 1').rows.length, 1);
  assert.equal(d.query('SELECT 1 UNION ALL SELECT 1').rows.length, 2);
  assert.deepEqual(names(d.query('SELECT 5 UNION SELECT 3 ORDER BY 1')), [3, 5], 'ORDER BY after a union applies to the whole result');
});

test('ORDER BY n reveals the number of columns (error past the last one)', () => {
  const d = db();
  assert.doesNotThrow(() => d.query('SELECT id, name, price FROM products ORDER BY 3'));
  assert.throws(() => d.query('SELECT id, name, price FROM products ORDER BY 4'), (e) => e.code === 1054 && e.message === "Unknown column '4' in 'order clause'");
});

test('information_schema and server functions', () => {
  const d = db();
  assert.deepEqual(names(d.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'shopzone'")).sort(), ['products', 'users']);
  assert.deepEqual(names(d.query("SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")), ['id', 'username', 'password', 'role']);
  assert.equal(d.query('SELECT version()').rows[0][0], '5.7.33-0ubuntu0.18.04.1');
  assert.equal(d.query('SELECT database()').rows[0][0], 'shopzone');
  assert.equal(d.query("SELECT concat(username, ':', role) FROM users WHERE id = 2").rows[0][0], 'alice:customer');
  assert.equal(d.query("SELECT length('abcd')").rows[0][0], 4);
  assert.equal(d.query("SELECT substring('hello', 2, 3)").rows[0][0], 'ell');
  assert.equal(d.query("SELECT ascii('A')").rows[0][0], 65);
});

test('error messages look like MySQL and carry the offending text', () => {
  const d = db();
  assert.throws(() => d.query("SELECT * FROM users WHERE username = 'oops"), (e) => e instanceof SqlError && e.code === 1064 && /near ''oops' at line 1/.test(e.message));
  assert.throws(() => d.query('SELECT FROM users'), (e) => /You have an error in your SQL syntax.*near 'FROM users' at line 1/.test(e.message));
  assert.throws(() => d.query('SELECT * FROM nope'), (e) => e.code === 1146 && e.message === "Table 'shopzone.nope' doesn't exist");
  assert.throws(() => d.query('SELECT secret FROM users'), (e) => e.code === 1054 && e.message === "Unknown column 'secret' in 'field list'");
  assert.throws(() => d.query('SELECT * FROM users WHERE nope = 1'), (e) => e.message === "Unknown column 'nope' in 'where clause'");
  assert.throws(() => d.query('SELECT bogus(1)'), (e) => e.code === 1305);
  assert.throws(() => d.query('SELECT * FROM users WHERE id = 1 junk'), SqlError);
  assert.throws(() => d.query('SELECT * FROM users; DROP TABLE users'), SqlError, 'only one statement is ever executed');
});

test('NULL semantics and comparisons', () => {
  const d = new Database({ tables: { t: { columns: ['a'], rows: [{ a: null }, { a: 1 }] } } });
  assert.equal(d.query('SELECT a FROM t WHERE a = NULL').rows.length, 0);
  assert.equal(d.query('SELECT a FROM t WHERE a IS NULL').rows.length, 1);
  assert.equal(d.query('SELECT a FROM t WHERE a IS NOT NULL').rows.length, 1);
  assert.equal(d.query("SELECT a FROM t WHERE a = '1'").rows.length, 1, 'strings that look like numbers compare numerically');
});

test('the engine only sees the tables it was given and never mutates them', () => {
  const spec = { tables: { t: { columns: ['a'], rows: [{ a: 1 }] } } };
  const d = new Database(spec);
  d.query('SELECT * FROM t');
  assert.deepEqual(spec.tables.t.rows, [{ a: 1 }]);
  d.tables.t.rows.push({ a: 2 });
  assert.equal(spec.tables.t.rows.length, 1, 'the database holds a private copy');
  assert.throws(() => d.query('DELETE FROM t'), SqlError, 'only SELECT exists');
});
