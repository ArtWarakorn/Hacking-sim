// ShopZone — a small, deliberately vulnerable e-commerce site for chapter 4 (OWASP Top 10).
// Every "exploit" here is modelled as realistic but inert data handling:
//   - SQL injection really runs through sqlsim.Database (so parser/engine rules apply, not string matching)
//   - XSS is "confirmed" by checking whether a marker survives unescaped in the HTML this function builds —
//     nothing is ever rendered as live DOM or executed, by the Browser UI or anywhere else
//   - command injection runs against a 6-line fake shell (buildFakeShell) over a tiny fixed virtual FS,
//     never anything resembling a real shell
import { Database } from '../sim/sqlsim.js';
import { build, escapeHtml, parseForm } from '../sim/httpsim.js';

const PAGE = (title, body) => `<!DOCTYPE html>\n<html lang="en">\n<head><title>${title} - ShopZone</title></head>\n<body>\n<header><a href="/">ShopZone</a> | <a href="/search">Search</a> | <a href="/account">My Account</a> | <a href="/login">Login</a></header>\n<main>\n${body}\n</main>\n</body>\n</html>\n`;
const randToken = () => Array.from({ length: 24 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');

function init(app) {
  const db = new Database({ name: 'shopzone', version: '5.7.33-0ubuntu0.18.04.1', user: 'shopzone@localhost', tables: app.data.tables });
  const maxOrderId = Math.max(0, ...app.data.tables.orders.rows.map((r) => r.id));
  return {
    db, sessions: new Map(), comments: app.data.comments.map((c) => ({ ...c })), nextCommentId: app.data.comments.length + 1,
    nextOrderId: maxOrderId + 1, fs: app.data.fs || {},
  };
}

function sessionOf(req, state) {
  const token = req.cookies?.session;
  if (token && state.sessions.has(token)) return state.sessions.get(token);
  // A04 Cryptographic Failures: "remember me" is just base64(username) with no signature or server-side
  // record of who it was issued to - decode it (or forge your own) and you are logged in as that user
  // with no password check at all.
  const remember = req.cookies?.remember;
  if (!remember) return null;
  let username;
  try { username = atob(remember); } catch { return null; }
  // (this lookup itself is written safely on purpose - the vulnerability being taught here is the
  // unsigned, forgeable cookie, not a second SQL injection)
  const row = state.db.query(Database.bind('SELECT id, username, role FROM users WHERE username = ?', [username])).rows[0];
  return row ? { userId: row[0], username: row[1], role: row[2] } : null;
}

function productCard(p) {
  return `<div class="product"><a href="/product?id=${p.id}">${escapeHtml(p.name)}</a> - $${p.price.toFixed(2)}</div>`;
}

function commentBlock(c) {
  // The vulnerable version of this app interpolates the stored body directly into HTML with no escaping.
  // A non-vulnerable app would call escapeHtml(c.body) here (compare in the debrief/fixed version).
  return `<div class="comment"><strong>${escapeHtml(c.author)}</strong>: ${c.body}</div>`;
}

function sqlErrorPage(app, req, e) {
  return build(app, 500, { body: `<!DOCTYPE html>\n<html><body>\n<b>Fatal error</b>: Uncaught mysqli_sql_exception: ${escapeHtml(e.message)} in /var/www/html/db.php:42\n</body></html>\n` }, req);
}

// ---------------- a tiny fake shell for the command-injection mission ----------------
const SHELL_META = /[;&|`$]|\$\(/;
function buildFakeShell(fs) {
  const files = fs;
  return (line) => {
    const parts = line.trim().split(/\s+/);
    const cmd = parts[0];
    if (cmd === 'id') return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)';
    if (cmd === 'whoami') return 'www-data';
    if (cmd === 'pwd') return '/var/www/html';
    if (cmd === 'ls') { const dir = parts[1] || '.'; const names = Object.keys(files).filter((f) => f.startsWith(`${dir === '.' ? '' : dir}/`.replace('//', '/')) || dir === '.').map((f) => f.split('/').pop()); return [...new Set(names.length ? names : Object.keys(files).map((f) => f.split('/').pop()))].join('\n'); }
    if (cmd === 'cat') { const f = parts[1]; return files[f] !== undefined ? files[f] : `cat: ${f}: No such file or directory`; }
    return `sh: 1: ${cmd}: not found`;
  };
}

/**
 * The vulnerable code runs `ping -c 1 <host>` in a real shell, so `host` becomes everything after the
 * first `;`/`&&`/`||` too. The part before that separator is the (real) ping target, already rendered
 * separately by the caller — only the segments after it are the attacker's injected commands.
 */
function runInjectedCommand(host, fs) {
  if (!SHELL_META.test(host)) return null;
  const segments = host.split(/;|&&|\|\|/).map((s) => s.trim()).filter(Boolean).slice(1);
  if (!segments.length) return null;
  return segments.map(buildFakeShell(fs)).join('\n');
}

function routes(app, req, state) {
  const { method, path, query, cookies } = req;
  const session = sessionOf(req, state);

  if (path === '/' && method === 'GET') {
    const rows = state.db.query('SELECT id, name, price FROM products ORDER BY id').rows;
    const list = rows.map((r) => productCard({ id: r[0], name: r[1], price: r[2] })).join('\n');
    return build(app, 200, { body: PAGE('Home', `<h1>Welcome to ShopZone</h1>\n${list}`) }, req);
  }

  if (path === '/robots.txt' && method === 'GET') return build(app, 200, { type: 'text/plain', body: 'User-agent: *\nDisallow: /admin/\n' }, req);

  if (path === '/search' && method === 'GET') {
    const q = query.q;
    if (q === undefined) return build(app, 200, { body: PAGE('Search', '<h1>Search products</h1><form><input name="q"><button>Go</button></form>') }, req);
    // Vulnerable: the raw query string is concatenated into SQL instead of being bound as a parameter.
    const sql = `SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`;
    let rows; let errHtml = '';
    try { rows = state.db.query(sql).rows; } catch (e) { rows = []; errHtml = `<p class="sql-error">Database error: ${escapeHtml(e.message)}</p>`; }
    const resultCols = rows.length ? rows[0].length : 3;
    const list = rows.map((r) => (resultCols === 3 ? productCard({ id: r[0], name: r[1], price: Number(r[2]) || 0 }) : `<div class="product">${r.map((v) => escapeHtml(String(v))).join(' | ')}</div>`)).join('\n');
    // Vulnerable: the search term is echoed back into the page without escaping (reflected XSS).
    return build(app, 200, { body: PAGE('Search', `<h1>Search results for: ${q}</h1>\n<form><input name="q" value="${q}"><button>Go</button></form>\n${errHtml}${list}`) }, req);
  }

  if (path === '/product' && method === 'GET') {
    const id = Number(query.id);
    const rows = state.db.query(`SELECT id, name, price, description FROM products WHERE id = ${Number.isFinite(id) ? id : -1}`).rows;
    if (!rows.length) return build(app, 404, { body: PAGE('Not found', '<h1>Product not found</h1>') }, req);
    const [, name, price, desc] = rows[0];
    const comments = state.comments.filter((c) => c.productId === id).map(commentBlock).join('\n') || '<p><em>No comments yet.</em></p>';
    const body = `<h1>${escapeHtml(name)}</h1><p>$${Number(price).toFixed(2)}</p><p>${escapeHtml(desc)}</p>\n<h2>Reviews</h2>${comments}\n<form method="POST" action="/comments"><input type="hidden" name="product_id" value="${id}">\n<input name="author" placeholder="Your name" value="${escapeHtml(session?.username || '')}"><br>\n<textarea name="body" placeholder="Write a review"></textarea><button>Post</button></form>`;
    return build(app, 200, { body: PAGE(name, body) }, req);
  }

  if (path === '/comments' && method === 'POST') {
    const f = parseForm(req.body);
    const productId = Number(f.product_id);
    state.comments.push({ id: state.nextCommentId++, productId, author: (f.author || 'anonymous').slice(0, 40), body: f.body || '', postedAt: new Date().toISOString() });
    return build(app, 302, { headers: { Location: `/product?id=${productId}` }, body: '' }, req);
  }

  if (path === '/login' && method === 'GET') {
    return build(app, 200, { body: PAGE('Login', '<h1>Login</h1><form method="POST" action="/login"><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button>Login</button></form>') }, req);
  }
  if (path === '/login' && method === 'POST') {
    const f = parseForm(req.body);
    const u = f.username ?? ''; const p = f.password ?? '';
    // Vulnerable: credentials are concatenated into the query instead of being bound as parameters,
    // so a value like `' OR '1'='1` changes the structure of the WHERE clause (auth bypass).
    const sql = `SELECT id, username, role FROM users WHERE username = '${u}' AND password = '${p}'`;
    let rows;
    try { rows = state.db.query(sql).rows; } catch (e) { return sqlErrorPage(app, req, e); }
    if (!rows.length) return build(app, 200, { body: PAGE('Login', '<h1>Login</h1><p class="error">Invalid username or password.</p><form method="POST" action="/login"><input name="username"><input name="password" type="password"><button>Login</button></form>') }, req);
    const [id, username, role] = rows[0];
    // Vulnerable: a session cookie the visitor already had is reused as-is instead of always issuing a
    // fresh one on login (Session Fixation, OWASP A07) - whoever set that cookie value beforehand is now
    // logged in too, the moment this victim finishes logging in with it still attached.
    const token = req.cookies?.session || randToken();
    state.sessions.set(token, { userId: id, username, role });
    const setCookie = [`session=${token}; HttpOnly; Path=/`];
    if (f.remember === '1') setCookie.push(`remember=${btoa(username)}; Path=/; Max-Age=2592000`);
    return build(app, 302, { headers: { Location: '/account', 'Set-Cookie': setCookie }, body: '' }, req);
  }

  if (path === '/logout') return build(app, 302, { headers: { Location: '/', 'Set-Cookie': 'session=; Max-Age=0; Path=/' }, body: '' }, req);

  if (path === '/account' && method === 'GET') {
    if (!session) return build(app, 302, { headers: { Location: '/login' }, body: '' }, req);
    const orders = state.db.query(`SELECT id, total FROM orders WHERE user_id = ${session.userId}`).rows;
    const list = orders.map(([oid, total]) => `<li><a href="/account/order?id=${oid}">Order #${oid}</a> — $${Number(total).toFixed(2)}</li>`).join('\n') || '<li>No orders yet.</li>';
    return build(app, 200, { body: PAGE('My Account', `<h1>Welcome, ${escapeHtml(session.username)}</h1><h2>Your orders</h2><ul>${list}</ul>`) }, req);
  }

  if (path === '/account/order' && method === 'GET') {
    if (!session) return build(app, 302, { headers: { Location: '/login' }, body: '' }, req);
    const id = Number(query.id);
    // Vulnerable: the order is looked up by id alone — there is no check that it belongs to the logged-in
    // user (an Insecure Direct Object Reference / broken access control, OWASP A01).
    const rows = state.db.query(`SELECT id, user_id, total, shipping_address FROM orders WHERE id = ${Number.isFinite(id) ? id : -1}`).rows;
    if (!rows.length) return build(app, 404, { body: PAGE('Not found', '<h1>Order not found</h1>') }, req);
    const [oid, ownerId, total, address] = rows[0];
    const ownerRow = state.db.query(`SELECT username FROM users WHERE id = ${ownerId}`).rows[0];
    const body = `<h1>Order #${oid}</h1><p>Customer: ${escapeHtml(ownerRow?.[0] ?? `user#${ownerId}`)}</p><p>Total: $${Number(total).toFixed(2)}</p><p>Ship to: ${escapeHtml(address)}</p>`;
    return build(app, 200, { body: PAGE(`Order #${oid}`, body) }, req);
  }

  if (path === '/package.json' && method === 'GET') {
    // Vulnerable: a build artifact that should never ship to the web root is exposed as-is, revealing
    // exact dependency versions an attacker can cross-reference against known CVEs (Software Supply
    // Chain Failures, OWASP A03) without ever touching the application itself.
    return build(app, 200, { type: 'application/json', body: `${JSON.stringify({
      name: 'shopzone', version: '1.4.0', private: true,
      dependencies: { express: '4.16.2', lodash: '4.17.4', jsonwebtoken: '8.3.0' },
    }, null, 2)}\n` }, req);
  }

  if (path === '/forgot-password' && method === 'GET') {
    const username = query.username;
    if (username === undefined) {
      return build(app, 200, { body: PAGE('Forgot password', '<h1>Forgot your password?</h1><form><input name="username" placeholder="username"><button>Check</button></form>') }, req);
    }
    // Vulnerable: the response text itself reveals whether the account exists at all, before any
    // password is checked (Username Enumeration, OWASP A07).
    const exists = state.db.query(Database.bind('SELECT id FROM users WHERE username = ?', [username])).rows.length > 0;
    const msg = exists ? 'มีบัญชีนี้อยู่ในระบบ — เราได้ส่งลิงก์ตั้งรหัสผ่านใหม่ไปที่อีเมลที่ลงทะเบียนไว้แล้ว' : `ไม่พบบัญชีผู้ใช้ชื่อ "${escapeHtml(username)}" ในระบบ`;
    return build(app, 200, { body: PAGE('Forgot password', `<h1>Forgot your password?</h1><form><input name="username" value="${escapeHtml(username)}"><button>Check</button></form><p>${msg}</p>`) }, req);
  }

  if (path === '/buy' && method === 'GET') {
    if (!session) return build(app, 302, { headers: { Location: '/login' }, body: '' }, req);
    const productId = Number(query.product_id);
    const productRow = state.db.query(`SELECT id, name, price FROM products WHERE id = ${Number.isFinite(productId) ? productId : -1}`).rows[0];
    if (!productRow) return build(app, 404, { body: PAGE('Not found', '<h1>Product not found</h1>') }, req);
    const [, name, realPrice] = productRow;
    if (query.confirm === undefined) {
      return build(app, 200, { body: PAGE('Buy now', `<h1>Buy: ${escapeHtml(name)}</h1><p>Price: $${Number(realPrice).toFixed(2)} each</p><form><input type="hidden" name="product_id" value="${productId}"><label>Quantity <input name="qty" value="1"></label><input type="hidden" name="confirm" value="1"><button>Buy now</button></form>`) }, req);
    }
    const qty = Number(query.qty);
    // Vulnerable: the unit price is taken from the request when supplied (a leftover test-mode override)
    // instead of always being looked up server-side, and quantity is never checked for being a sane,
    // positive number either - either gap alone lets the client decide what the order actually costs
    // (Insecure Design, OWASP A06).
    const unitPrice = query.price !== undefined ? Number(query.price) : Number(realPrice);
    const finalQty = Number.isFinite(qty) ? qty : 1;
    const total = unitPrice * finalQty;
    const orderId = state.nextOrderId++;
    state.db.tables.orders.rows.push({ id: orderId, user_id: session.userId, total, shipping_address: '(quick buy)' });
    return build(app, 200, { body: PAGE('Order placed', `<h1>Order #${orderId} placed</h1><p>${finalQty} × ${escapeHtml(name)} = $${total.toFixed(2)}</p><a href="/account">View my orders</a>`) }, req);
  }

  if (path === '/cart' && method === 'GET') {
    let cart = null;
    try { cart = JSON.parse(atob(cookies?.cart || '')); } catch { /* no/garbled cart cookie */ }
    const setCookie = [];
    if (!cart) {
      const row = state.db.query('SELECT id, name, price FROM products WHERE id = 2').rows[0]; // a Mechanical Keyboard, added for you
      cart = { items: [{ id: row[0], name: row[1], qty: 1 }], total: Number(row[2]) };
      setCookie.push(`cart=${btoa(JSON.stringify(cart))}; Path=/`);
    }
    const summary = cart.items.map((i) => `${i.qty} × ${escapeHtml(i.name)}`).join(', ');
    const body = PAGE('Cart', `<h1>Your cart</h1><p>${summary}</p><p>Total: $${Number(cart.total).toFixed(2)}</p><a href="/cart/checkout">Checkout</a>`);
    return setCookie.length ? build(app, 200, { headers: { 'Set-Cookie': setCookie }, body }, req) : build(app, 200, { body }, req);
  }

  if (path === '/cart/checkout' && method === 'GET') {
    if (!session) return build(app, 302, { headers: { Location: '/login' }, body: '' }, req);
    let cart = null;
    try { cart = JSON.parse(atob(cookies?.cart || '')); } catch { /* no/garbled cart cookie */ }
    if (!cart) return build(app, 302, { headers: { Location: '/cart' }, body: '' }, req);
    // Vulnerable: `total` comes from this client-held, unsigned cart object and is trusted as-is instead
    // of being recalculated from the real catalogue prices server-side (Software/Data Integrity Failure -
    // "insecure deserialization" of the cart - OWASP A08).
    const orderId = state.nextOrderId++;
    const total = Number(cart.total) || 0;
    state.db.tables.orders.rows.push({ id: orderId, user_id: session.userId, total, shipping_address: '(cart checkout)' });
    return build(app, 302, { headers: { Location: '/account' }, body: '' }, req);
  }

  if (path === '/admin/diagnostics' && method === 'GET') {
    // Vulnerable: authorization is decided by a plain, client-editable cookie instead of the server-side
    // session (Broken Access Control, OWASP A01) — a visitor can just set `role=admin` themselves.
    if (cookies?.role !== 'admin') return build(app, 403, { body: PAGE('Forbidden', '<h1>403 Forbidden</h1><p>Admins only.</p>') }, req);
    const host = query.host;
    if (host === undefined) {
      return build(app, 200, { body: PAGE('Diagnostics', '<h1>Network diagnostics</h1><form><input name="host" placeholder="host to ping"><button>Ping</button></form>') }, req);
    }
    // Vulnerable: the host parameter is handed straight to a shell command (simulated) with no validation
    // or escaping (OS command injection, OWASP A05).
    const injected = runInjectedCommand(host, state.fs);
    const pingOutput = `PING ${host.split(/[;&|`]/)[0].trim() || host} (0.0.0.0) 56(84) bytes of data.\n--- ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss`;
    const out = injected !== null ? `${pingOutput}\n${injected}` : pingOutput;
    return build(app, 200, { body: PAGE('Diagnostics', `<h1>Network diagnostics</h1><form><input name="host" value="${escapeHtml(host)}"><button>Ping</button></form><pre>${escapeHtml(out)}</pre>`) }, req);
  }

  return build(app, 404, { body: PAGE('Not found', `<h1>404 Not Found</h1><p>${escapeHtml(path)}</p>`) }, req);
}

export const shopzone = {
  init,
  handle(app, req, state) { return routes(app, req, state); },
};
