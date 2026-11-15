import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell } from './helpers.mjs';
import { md5, sha1, sha256, ntlm } from '../public/js/sim/hashlib.js';

async function withDump(sh, path, lines) {
  await sh.run(`echo -e '${lines.join('\\n')}' > ${path}`);
}

test('hashid: identifies by length, flags the MD5/NTLM ambiguity, rejects garbage', async () => {
  const sh = makeShell();
  const md5r = await sh.run(`hashid ${md5('password')}`);
  assert.match(md5r.out, /\[\+\] MD5/);
  assert.match(md5r.out, /\[\+\] NTLM/);
  assert.match(md5r.out, /context decides/);
  assert.match((await sh.run(`hashid ${sha1('password')}`)).out, /\[\+\] SHA-1/);
  assert.doesNotMatch((await sh.run(`hashid ${sha1('password')}`)).out, /\[\+\] MD5/);
  assert.match((await sh.run(`hashid ${sha256('password')}`)).out, /\[\+\] SHA-256/);
  assert.match((await sh.run('hashid notahash')).out, /Unknown hash type/);
  assert.equal((await sh.run('hashid')).code, 1);
});

test('hashid -f reads a file of hashes', async () => {
  const sh = makeShell();
  await sh.run(`echo '${md5('a')}' > /tmp/h.txt`);
  await sh.run(`echo '${sha1('a')}' >> /tmp/h.txt`);
  const out = (await sh.run('hashid -f /tmp/h.txt')).out;
  assert.match(out, /\[\+\] MD5/);
  assert.match(out, /\[\+\] SHA-1/);
});

test('john: cracks raw-md5 with --format, reports uncracked separately, respects the wordlist', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/dump.txt', [`alice:${md5('letmein')}`, `bob:${md5('not-in-wordlist-xyz')}`]);
  const r = await sh.run('john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/dump.txt');
  assert.equal(r.code, 0);
  assert.match(r.out, /letmein\s+\(alice\)/);
  assert.doesNotMatch(r.out, /\(bob\)/, 'bob\'s password is not in the wordlist, so it is never reported as cracked');
  assert.match(r.out, /Loaded 2 password hashes/);
  assert.match(r.out, /1g 0:00:00:00 DONE/);
});

test('john: without --format, guesses from hash length (sha1/sha256 are unambiguous)', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/s1.txt', [`x:${sha1('qwerty')}`]);
  assert.match((await sh.run('john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/s1.txt')).out, /qwerty\s+\(x\)/);
  await withDump(sh, '/tmp/s256.txt', [`y:${sha256('admin')}`]);
  assert.match((await sh.run('john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/s256.txt')).out, /admin\s+\(y\)/);
});

test('john: a 32-hex hash with no --format is ambiguous (MD5 vs NTLM) and is not silently guessed', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/amb.txt', [`u:${md5('letmein')}`]);
  const r = await sh.run('john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/amb.txt');
  assert.match(r.out, /Warning: detected hash type "MD5", but the string is also recognized as "NTLM"/);
  assert.doesNotMatch(r.out, /letmein/, 'refuses to guess between two different algorithms that would give different results');
});

test('john: --format=nt cracks NTLM hashes specifically', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/nt.txt', [`hr_admin:${ntlm('Winter2024!')}`]);
  const r = await sh.run('john --format=nt --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/nt.txt');
  assert.match(r.out, /Winter2024!\s+\(hr_admin\)/);
});

test('john: missing arguments and missing files fail clearly', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('john')).code, 1);
  assert.match((await sh.run('john /tmp/nope.txt')).err, /no wordlist given/);
  assert.match((await sh.run('john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/nope.txt')).err, /No such file or directory/);
  await withDump(sh, '/tmp/ok.txt', [`a:${md5('x')}`]);
  assert.match((await sh.run('john --wordlist=/tmp/missing-list.txt /tmp/ok.txt')).err, /No such file or directory/);
});

test('hashcat: -m selects the algorithm explicitly, output is hash:password', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/sha1dump.txt', [sha1('qwerty')]);
  const r = await sh.run('hashcat -m 100 -a 0 /tmp/sha1dump.txt /usr/share/wordlists/rockyou-mini.txt');
  assert.equal(r.code, 0);
  assert.equal(r.out.split('\n')[2], `${sha1('qwerty')}:qwerty`);
  assert.match(r.out, /Status\.\.\.\.\.\.\.\.\.\.\.: Cracked/);
  assert.match(r.out, /Recovered\.\.\.\.\.\.\.\.: 1\/1 \(100\.00%\)/);
});

test('hashcat: -m 1000 (NTLM) vs -m 0 (MD5) on the same 32-hex value give different results', async () => {
  const sh = makeShell();
  const pw = 'Summer2024!';
  await withDump(sh, '/tmp/md5only.txt', [md5(pw)]);
  await withDump(sh, '/tmp/ntlmonly.txt', [ntlm(pw)]);
  assert.match((await sh.run('hashcat -m 0 -a 0 /tmp/md5only.txt /usr/share/wordlists/rockyou-mini.txt')).out, new RegExp(`${md5(pw)}:${pw}`));
  assert.match((await sh.run('hashcat -m 1000 -a 0 /tmp/ntlmonly.txt /usr/share/wordlists/rockyou-mini.txt')).out, new RegExp(`${ntlm(pw)}:${pw}`));
  // cross-checking with the wrong mode never cracks anything, even though both are 32 hex chars
  assert.doesNotMatch((await sh.run('hashcat -m 0 -a 0 /tmp/ntlmonly.txt /usr/share/wordlists/rockyou-mini.txt')).out, new RegExp(pw));
});

test('hashcat: invalid mode number is rejected, exhausted run reports 0 recovered', async () => {
  const sh = makeShell();
  await withDump(sh, '/tmp/x.txt', [md5('x')]);
  assert.match((await sh.run('hashcat -m 9999 -a 0 /tmp/x.txt /usr/share/wordlists/rockyou-mini.txt')).err, /invalid hash-mode/);
  await withDump(sh, '/tmp/unknown.txt', [md5('totally-not-in-the-wordlist-at-all')]);
  const r = await sh.run('hashcat -m 0 -a 0 /tmp/unknown.txt /usr/share/wordlists/rockyou-mini.txt');
  assert.match(r.out, /Status\.\.\.\.\.\.\.\.\.\.\.: Exhausted/);
  assert.match(r.out, /Recovered\.\.\.\.\.\.\.\.: 0\/1/);
});

test('zip2john + ssh2john: produce a john-crackable line; a plain unprotected file is rejected', async () => {
  const sh = makeShell();
  const sha = sha256('letmein');
  await sh.run(`echo '##CRACKHASH:${sha}##' > /tmp/fake.zip`);
  const z = await sh.run('zip2john /tmp/fake.zip');
  assert.equal(z.code, 0);
  assert.match(z.out, /fake\.zip:\$zip2\$/);
  const r = await sh.run('zip2john /tmp/fake.zip > /tmp/fake.hash && john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/fake.hash');
  assert.match(r.out, /letmein/);

  const sha2 = sha256('qwerty');
  await sh.run(`echo '##CRACKHASH:${sha2}##' > /tmp/fake_id_rsa`);
  await sh.run('ssh2john /tmp/fake_id_rsa > /tmp/key.hash');
  assert.match((await sh.run('john --wordlist=/usr/share/wordlists/rockyou-mini.txt /tmp/key.hash')).out, /qwerty/);

  await sh.run("echo 'just a plain text file, not encrypted' > /tmp/plain.zip");
  assert.match((await sh.run('zip2john /tmp/plain.zip')).err, /not a recognised zip archive/);
});

test('zip2john/ssh2john: missing file and missing argument errors', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('zip2john')).code, 1);
  assert.match((await sh.run('zip2john /tmp/does-not-exist.zip')).err, /No such file or directory/);
  assert.equal((await sh.run('ssh2john')).code, 1);
});

test('hydra: cracks a real weak FTP password, reports failure with wrong lists, validates arguments', async () => {
  const sh = makeShell();
  await sh.run("echo -e 'ftpuser\nadmin' > /tmp/users.txt");
  const ok = await sh.run('hydra -L /tmp/users.txt -P /usr/share/wordlists/rockyou-mini.txt 10.10.20.6 ftp');
  assert.equal(ok.code, 0);
  assert.match(ok.out, /\[21\]\[ftp\] host: 10\.10\.20\.6 {3}login: ftpuser {3}password: Summer2024!/);
  assert.match(ok.out, /1 valid password found/);

  await sh.run("echo -e 'nosuchuser' > /tmp/wrongusers.txt");
  const bad = await sh.run('hydra -L /tmp/wrongusers.txt -P /usr/share/wordlists/rockyou-mini.txt 10.10.20.6 ftp');
  assert.equal(bad.code, 1);
  assert.match(bad.out, /0 valid passwords found/);

  assert.match((await sh.run('hydra 10.10.20.6 ftp')).err, /username list is required/);
  assert.match((await sh.run('hydra -L /tmp/users.txt 10.10.20.6 ftp')).err, /password list is required/);
  assert.match((await sh.run('hydra -L /tmp/users.txt -P /usr/share/wordlists/rockyou-mini.txt 10.10.20.6 smtp')).err, /not supported in this simulator/);
  assert.match((await sh.run('hydra -L /tmp/users.txt -P /usr/share/wordlists/rockyou-mini.txt 10.10.20.7 ftp')).err, /could not connect/, 'db01 does not run ftp');
});

test('hydra emits a game event other missions/objectives can key off', async () => {
  const sh = makeShell();
  const seen = [];
  sh.bus.on('game', (e) => seen.push(e));
  await sh.run("echo -e 'ftpuser' > /tmp/u.txt");
  await sh.run('hydra -L /tmp/u.txt -P /usr/share/wordlists/rockyou-mini.txt 10.10.20.6 ftp');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].name, 'hydra.run');
  assert.equal(seen[0].found, 1);
  assert.equal(seen[0].host, '10.10.20.6');
});

test('every new command has Thai documentation registered', async () => {
  const sh = makeShell();
  for (const n of ['hashid', 'john', 'hashcat', 'zip2john', 'ssh2john', 'hydra']) {
    assert.match((await sh.run(`man ${n}`)).out, /^NAME\n/, `missing docs for ${n}`);
  }
});
