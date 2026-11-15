import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell, readJSON, loadWorldFromDisk, docs } from './helpers.mjs';
import { expandTarget, inScope, TOP_PORTS } from '../public/js/sim/network.js';
import { MissionEngine } from '../public/js/mission/engine.js';
import { buildMissionShell } from '../public/js/mission/runtime.js';
import { EventBus } from '../public/js/core/eventbus.js';
import { submitLine } from '../public/js/terminal/executor.js';
import { computeScore } from '../public/js/mission/scoring.js';
import { createDefaultProgress, applyMissionResult } from '../public/js/mission/progress.js';

const curriculum = readJSON('content/curriculum.json');
const ranks = readJSON('content/ranks.json');
const achievements = readJSON('content/achievements.json');

// ---------------- target expansion ----------------
test('expandTarget: IP, range, CIDR, hostname and limits', () => {
  const world = loadWorldFromDisk();
  assert.deepEqual(expandTarget('10.10.20.5', world).ips, ['10.10.20.5']);
  assert.deepEqual(expandTarget('10.10.20.5-7', world).ips, ['10.10.20.5', '10.10.20.6', '10.10.20.7']);
  assert.equal(expandTarget('10.10.20.0/24', world).ips.length, 256);
  assert.deepEqual(expandTarget('10.10.20.4/30', world).ips, ['10.10.20.4', '10.10.20.5', '10.10.20.6', '10.10.20.7']);
  assert.deepEqual(expandTarget('web01.acme.test', world), { ips: ['10.10.20.5'], name: 'web01.acme.test' });
  assert.match(expandTarget('10.0.0.0/8', world).error, /too large/);
  assert.match(expandTarget('10.10.20.9-3', world).error, /Failed to resolve/);
  assert.match(expandTarget('nosuch.example', world).error, /Failed to resolve "nosuch.example"/);
  assert.equal(inScope('10.10.20.5', ['10.10.20.0/29']), true);
  assert.equal(inScope('10.10.20.9', ['10.10.20.0/29']), false);
  assert.ok(TOP_PORTS.includes(80) && !TOP_PORTS.includes(9999), 'a service on 9999 is outside the default scan');
});

test('World: stealth hosts do not answer ping but still serve ports', () => {
  const w = loadWorldFromDisk();
  assert.equal(w.pingable('10.10.20.5'), true);
  assert.equal(w.pingable('10.10.20.7'), false);
  assert.equal(w.isUp('10.10.20.7'), true);
  assert.equal(w.portState('10.10.20.7', 3306), 'open');
  assert.equal(w.portState('10.10.20.7', 22), 'filtered', 'stealth: closed ports just go quiet');
  assert.equal(w.portState('10.10.20.5', 21), 'closed', 'normal host: RST');
  assert.equal(w.portState('10.99.0.1', 80), 'filtered', 'unknown address: nobody answers');
});

// ---------------- nmap ----------------
test('nmap default scan: top ports, tidy table, "Not shown" count', async () => {
  const sh = makeShell();
  const r = await sh.run('nmap 10.10.20.5');
  assert.equal(r.code, 0);
  assert.match(r.out, /^Starting Nmap 7\.94 \( https:\/\/nmap\.org \) at \d{4}-\d\d-\d\d \d\d:\d\d UTC\n/);
  assert.match(r.out, /Nmap scan report for web01\.acme\.test \(10\.10\.20\.5\)\nHost is up \(0\.\d{4}s latency\)\./);
  assert.match(r.out, /Not shown: 998 closed tcp ports \(reset\)\nPORT   STATE SERVICE\n22\/tcp open  ssh\n80\/tcp open  http\n/);
  assert.doesNotMatch(r.out, /VERSION/, 'no version column without -sV');
  assert.match(r.out, /Nmap done: 1 IP address \(1 host up\) scanned in [\d.]+ seconds/);
});

test('nmap finds the high port only with -p-', async () => {
  const sh = makeShell();
  assert.doesNotMatch((await sh.run('nmap 10.10.20.6')).out, /9999/);
  const full = (await sh.run('nmap -p- 10.10.20.6')).out;
  assert.match(full, /Not shown: 65530 closed tcp ports/);
  assert.match(full, /9999\/tcp open  http/);
  const one = (await sh.run('nmap -p 9999 10.10.20.6')).out;
  assert.match(one, /^[\s\S]*9999\/tcp open  http\n/);
  assert.doesNotMatch(one, /Not shown/, 'the only scanned port is listed');
  assert.match((await sh.run('nmap -p21,22 10.10.20.6')).out, /21\/tcp open  ftp\n22\/tcp open  ssh\n/);
  assert.match((await sh.run('nmap -p1-100 10.10.20.6')).out, /Not shown: 98 closed tcp ports/);
});

test('nmap -sV adds versions; -sC adds script output; -O adds OS; -A adds traceroute', async () => {
  const sh = makeShell();
  const v = (await sh.run('nmap -sV 10.10.20.5')).out;
  assert.match(v, /PORT   STATE SERVICE VERSION\n22\/tcp open  ssh     OpenSSH 8\.2p1 Ubuntu 4ubuntu0\.5 \(Ubuntu Linux; protocol 2\.0\)\n80\/tcp open  http    Apache httpd 2\.4\.41 \(\(Ubuntu\)\)\n/);
  assert.match(v, /Service Info: OS: Linux; CPE: cpe:\/o:linux:linux_kernel\n/);
  assert.match(v, /Service detection performed\. Please report/);

  const c = (await sh.run('nmap -sC 10.10.20.5')).out;
  assert.match(c, /\| http-title: ACME Logistics\n/);
  assert.match(c, /\|_?\s*\/admin\/ \/backup-old\//);

  const ftp = (await sh.run('nmap -sC -p21 10.10.20.6')).out;
  assert.match(ftp, /\| ftp-anon:\n\|   Anonymous FTP login allowed \(FTP code 230\)\n\|   -rw-r--r--    1 0        0 +\d+ Oct 12 09:00 notes\.txt\n\|_  drwxr-xr-x/);

  const o = (await sh.run('nmap -O 10.10.20.6')).out;
  assert.match(o, /Running: Linux 4\.X\nOS CPE: cpe:\/o:linux:linux_kernel:4\nOS details: Linux 4\.15 - 4\.19\nNetwork Distance: 3 hops/);
  assert.match(o, /^[\s\S]*OS and Service detection performed/m);

  const a = (await sh.run('nmap -A -p80 10.10.20.5')).out;
  assert.match(a, /TRACEROUTE \(using port 80\/tcp\)\nHOP RTT      ADDRESS\n1   [\d.]+ ms +gw\.lab\.test \(10\.10\.14\.1\)\n2 /);
  assert.match(a, /3   [\d.]+ ms +web01\.acme\.test \(10\.10\.20\.5\)/);

  assert.match((await sh.run('nmap -sVC -p80 10.10.20.5')).out, /Apache httpd[\s\S]*\| http-title/, 'combined -sVC works');
});

test('nmap host discovery: -sn lists only hosts that answer; stealth host needs -Pn', async () => {
  const sh = makeShell();
  const sweep = (await sh.run('nmap -sn 10.10.20.5-7')).out;
  assert.match(sweep, /Nmap scan report for web01\.acme\.test \(10\.10\.20\.5\)/);
  assert.match(sweep, /Nmap scan report for ftp01\.acme\.test \(10\.10\.20\.6\)/);
  assert.doesNotMatch(sweep, /db01|10\.10\.20\.7\)/, 'the stealth host does not answer pings');
  assert.match(sweep, /Nmap done: 3 IP addresses \(2 hosts up\)/);
  assert.doesNotMatch(sweep, /PORT/, '-sn does not scan ports');

  const single = (await sh.run('nmap 10.10.20.7')).out;
  assert.match(single, /Note: Host seems down\. If it is really up, but blocking our ping probes, try -Pn/);
  assert.match(single, /\(0 hosts up\)/);

  const pn = (await sh.run('nmap -Pn 10.10.20.7')).out;
  assert.match(pn, /Not shown: 999 filtered tcp ports \(no-response\)\nPORT     STATE SERVICE\n3306\/tcp open  mysql/);

  const whole = (await sh.run('nmap -sn 10.10.20.0/24')).out;
  assert.match(whole, /256 IP addresses \(5 hosts up\)/);
  assert.match(whole, /isp-gw\.acme\.test \(10\.10\.20\.1\)/, 'sweeping the /24 also hits the ISP router');
  assert.match(whole, /shop\.acme\.test \(10\.10\.20\.9\)/, 'and the ShopZone host introduced in chapter 4');
  assert.match(whole, /legacy01 \(10\.10\.20\.15\)/, 'and the forgotten legacy01 host introduced in chapter 6');
});

test('nmap edge cases: closed host, bad input, options, output file', async () => {
  const sh = makeShell();
  assert.match((await sh.run('nmap 10.10.20.1')).out, /All 1000 scanned ports on isp-gw\.acme\.test \(10\.10\.20\.1\) are closed/);
  assert.match((await sh.run('nmap -Pn 10.10.20.7')).out, /Host is up/);
  assert.match((await sh.run('nmap -Pn 10.10.20.99')).out, /Host is up\.\nAll 1000 scanned ports on 10\.10\.20\.99 are in ignored states/, 'nothing lives there but -Pn pretends');
  assert.match((await sh.run('nmap 10.10.20.99')).out, /Host seems down/);
  const bad = await sh.run('nmap nosuch.example');
  assert.match(bad.err, /Failed to resolve "nosuch\.example"\./);
  assert.match(bad.out, /0 IP addresses \(0 hosts up\)/);
  assert.match((await sh.run('nmap')).err, /Usage: nmap/);
  assert.equal((await sh.run('nmap -p 99999 10.10.20.5')).code, 1);
  assert.match((await sh.run('nmap -p 99999 10.10.20.5')).err, /port specifications are illegal/);
  assert.match((await sh.run('nmap --bogus 10.10.20.5')).err, /Unrecognized option: --bogus/);
  assert.match((await sh.run('nmap 10.0.0.0/8')).err, /too large/);
  assert.doesNotMatch((await sh.run('nmap -n 10.10.20.5')).out, /web01/, '-n skips reverse DNS');
  assert.match((await sh.run('nmap --open -sV 10.10.20.6')).out, /vsftpd/);
  assert.match((await sh.run('nmap -sT 10.10.20.5')).out, /conn-refused/);

  await sh.run('nmap -sV -oN scan.txt 10.10.20.5');
  assert.match((await sh.run('cat scan.txt')).out, /Apache httpd 2\.4\.41/);
  assert.match((await sh.run('grep -c open scan.txt')).out, /^2\n/);
  const denied = await sh.run('nmap -oN /etc/scan.txt 10.10.20.5');
  assert.match(denied.err, /Failed to open normal output file \/etc\/scan\.txt for writing: Permission denied/);
});

// ---------------- scope enforcement ----------------
function startMission(id) {
  const mission = readJSON(`content/missions/${id}.json`);
  const { stack, registry } = buildMissionShell(mission, readJSON(`content/machines/${mission.machine}.json`), docs, loadWorldFromDisk(mission.network || 'lab'));
  const bus = new EventBus();
  const engine = new MissionEngine(mission, { bus }).attach();
  const run = (line) => submitLine(line, stack, registry, { bus });
  return { mission, engine, run, stack };
}

test('scope: scanning the whole /24 touches the out-of-scope router exactly once', async () => {
  const { engine, run } = startMission('c03-m03');
  const seen = [];
  engine.events.on('violation', (v) => seen.push(v));
  await run('nmap -sn 10.10.20.0/24');
  assert.deepEqual(engine.violations.map((v) => v.ip), ['10.10.20.1', '10.10.20.9', '10.10.20.15']);
  assert.deepEqual(seen, [{ ip: '10.10.20.1', kind: 'scan', count: 1 }, { ip: '10.10.20.9', kind: 'scan', count: 2 }, { ip: '10.10.20.15', kind: 'scan', count: 3 }]);
  await run('nmap -sn 10.10.20.0/24');
  await run('ping -c 1 10.10.20.1');
  assert.equal(engine.violations.length, 3, 'the same host is only counted once');
});

test('scope: in-scope targets and the right range are clean', async () => {
  const { engine, run } = startMission('c03-m03');
  await run('nmap -sn 10.10.20.5-7');
  await run('nmap -Pn 10.10.20.7');
  await run('ping -c 1 10.10.20.5');
  await run('curl -s http://10.10.20.5/');
  assert.equal(engine.violations.length, 0);
});

test('scope: every kind of contact counts (ping, connect, http, ftp, smb, traceroute target)', async () => {
  for (const [line, ip] of [
    ['ping -c 1 10.10.20.1', '10.10.20.1'],
    ['nc -zv 10.10.20.1 22', '10.10.20.1'],
    ['curl -s http://10.10.20.1/', '10.10.20.1'],
    ['traceroute 10.10.20.1', '10.10.20.1'],
    ['gobuster dir -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt -q', null],
  ]) {
    const { engine, run } = startMission('c03-m04'); // in scope: .5 and .6 only
    await run(line);
    if (ip === null) { assert.equal(engine.violations.length, 0, `${line} targets an in-scope host`); continue; }
    assert.deepEqual(engine.violations.map((v) => v.ip), [ip], line);
  }
  const m5 = startMission('c03-m05');
  await m5.run('ftp 10.10.20.5'); // port 21 is closed there, but the attempt still touched the host
  assert.deepEqual(m5.engine.violations.map((v) => v.ip), ['10.10.20.5']);
  const m6 = startMission('c03-m06');
  await m6.run('smbclient -L //10.10.20.5 -N');
  assert.deepEqual(m6.engine.violations.map((v) => v.ip), ['10.10.20.5']);
});

test('scope: passive lookups, your own machine, and traceroute hops never count', async () => {
  const { engine, run } = startMission('c03-m04');
  await run('dig acme.test');
  await run('dig axfr acme-dev.test @10.10.20.50');
  await run('host db01.acme.test');
  await run('ping -c 1 10.10.14.2'); // own address
  await run('ping -c 1 127.0.0.1');
  await run('traceroute 10.10.20.5'); // passes through 10.10.20.1 on the way
  await run('whois acme.test');
  await run('subfinder -d acme.test');
  assert.equal(engine.violations.length, 0);
});

test('scope: missions without scope.ips are never policed', async () => {
  const { engine, run } = startMission('c02-m01');
  await run('ping -c 1 10.10.20.1');
  await run('nmap -sn 10.10.20.0/24');
  assert.equal(engine.violations.length, 0);
});

test('scope: chapter 2 network missions are policed too', async () => {
  const { engine, run } = startMission('c02-m02');
  await run('ping -c 1 10.10.20.1');
  assert.equal(engine.violations.length, 1);
});

test('scope penalties: 20% per host, capped, and the clean-run bonus is lost', () => {
  assert.deepEqual(computeScore({ xp: 300, violations: 0 }), { base: 300, bonus: 30, penalty: 0, total: 330 });
  assert.deepEqual(computeScore({ xp: 300, violations: 1 }), { base: 240, bonus: 0, penalty: 60, total: 240 });
  assert.equal(computeScore({ xp: 300, violations: 2 }).total, 180);
  assert.equal(computeScore({ xp: 300, violations: 9 }).total, 120, 'never below 40%');
  assert.equal(computeScore({ xp: 300, violations: 1, hintCost: 100, hintsUsed: 2 }).total, 140, 'hints and violations add up');
  assert.equal(computeScore({ xp: 300, violations: 4, hintCost: 500, hintsUsed: 3 }).total, 120);
});

test('scope: a violating run records the facts and withholds the clean-scope achievements', () => {
  const p = createDefaultProgress();
  const ctx = { ranks, achievements, curriculum };
  const m3 = readJSON('content/missions/c03-m03.json');
  const r = applyMissionResult(p, m3, { violations: 1, seconds: 5 }, ctx);
  assert.equal(r.score.penalty, 60);
  assert.equal(r.xpGained, 240, '300 XP minus one violation (20%), and no clean-run bonus');
  assert.deepEqual(p.completedMissions['c03-m03'], { score: 240, hintsUsed: 0, violations: 1, scoped: true, seconds: 5, completedAt: p.completedMissions['c03-m03'].completedAt });
  // "Stay In Scope" needs three CLEAN scoped missions; the dirty run does not count towards it
  for (const id of ['c03-m04', 'c03-m05']) applyMissionResult(p, readJSON(`content/missions/${id}.json`), { seconds: 1 }, ctx);
  assert.equal(p.achievements.includes('stay_in_scope'), false, 'only two clean scoped missions so far');
  const third = applyMissionResult(p, readJSON('content/missions/c03-m06.json'), { seconds: 1 }, ctx);
  assert.ok(third.newAchievements.some((a) => a.id === 'stay_in_scope'), 'the 3rd clean scoped mission unlocks it');
});

// ---------------- interactive tools ----------------
test('interactive: ftp takes over the prompt, hides the password, and returns to bash', async () => {
  const sh = makeShell();
  const seen = [];
  sh.bus.on('game', (e) => seen.push(`${e.name}:${e.user ?? e.file}:${e.ok ?? ''}`));
  const connect = await sh.run('ftp 10.10.20.6');
  assert.match(connect.out, /^Connected to 10\.10\.20\.6\.\n220 \(vsFTPd 3\.0\.3\)\n$/);
  assert.equal(sh.stack.interactive.prompt, 'Name (10.10.20.6:kali): ');
  assert.equal(sh.stack.interactive.secret, undefined);

  assert.equal((await sh.run('anonymous')).out, '331 Please specify the password.\n');
  assert.equal(sh.stack.interactive.prompt, 'Password: ');
  assert.equal(sh.stack.interactive.secret, true, 'the terminal must not echo this line');

  assert.match((await sh.run('me@home')).out, /^230 Login successful\./);
  assert.equal(sh.stack.interactive.prompt, 'ftp> ');

  // while in ftp, shell commands are NOT run
  assert.equal((await sh.run('whoami')).out, '?Invalid command.\n');
  assert.match((await sh.run('ls')).out, /150 Here comes the directory listing\.\n-rw-r--r--    1 0        0 +159 Oct 12 09:00 notes\.txt\ndrwxr-xr-x    2 0        0 +4096 Oct 12 09:02 pub\n226 Directory send OK\.\n/);
  assert.match((await sh.run('ls -la pub')).out, /readme\.txt/);
  assert.equal((await sh.run('pwd')).out, 'Remote directory: /\n');
  assert.equal((await sh.run('cd pub')).out, '250 Directory successfully changed.\n');
  assert.equal((await sh.run('pwd')).out, 'Remote directory: /pub\n');
  assert.equal((await sh.run('cd /nope')).out, '550 Failed to change directory.\n');
  assert.equal((await sh.run('cd ..')).out, '250 Directory successfully changed.\n');
  assert.match((await sh.run('get nosuch.txt')).out, /550 Failed to open file\./);
  assert.match((await sh.run('get notes.txt')).out, /150 Opening BINARY mode data connection for notes\.txt \(159 bytes\)\.\n226 Transfer complete\./);
  assert.equal((await sh.run('bye')).out, '221 Goodbye.\n');
  assert.equal(sh.stack.interactive, null, 'back at bash');
  assert.equal((await sh.run('whoami')).out, 'kali\n');

  // the downloaded file now exists locally, owned by the player
  const node = sh.stack.current.vfs.get('/home/kali/notes.txt');
  assert.equal(node.owner, 'kali');
  assert.match(node.content, /FLAG\{anonymous_ftp_is_an_open_door\}/);
  assert.deepEqual(seen, ['ftp.login:anonymous:true', 'ftp.get:notes.txt:']);
});

test('interactive: ftp login failure, closed port, and downloading to a protected folder', async () => {
  const sh = makeShell();
  await sh.run('ftp 10.10.20.6'); await sh.run('bob'); // a real user, but anonymous-only server
  const bad = await sh.run('hunter2');
  assert.equal(bad.out, '530 Login incorrect.\nLogin failed.\n');
  assert.equal(sh.stack.interactive.prompt, 'ftp> ');
  assert.equal((await sh.run('ls')).out, '530 Please login with USER and PASS.\n');
  assert.equal((await sh.run('bye')).out, '221 Goodbye.\n');

  const refused = await sh.run('ftp 10.10.20.5');
  assert.equal(refused.code, 1);
  assert.equal(refused.err, "ftp: Can't connect to `10.10.20.5:21': Connection refused\n");
  assert.equal(sh.stack.interactive, null);
  assert.match((await sh.run('ftp 10.10.20.7')).err, /Connection timed out/);
  assert.match((await sh.run('ftp nosuch.example')).err, /Name or service not known/);

  await sh.run('cd /etc'); await sh.run('ftp 10.10.20.6'); await sh.run('anonymous'); await sh.run('x');
  assert.match((await sh.run('get notes.txt')).out, /local: notes\.txt: Permission denied/);
  await sh.run('bye');
});

test('interactive: an exception inside a tool cannot trap the player', async () => {
  const sh = makeShell();
  sh.stack.interactive = { name: 'boom', prompt: 'boom> ', async onLine() { throw new Error('kaboom'); } };
  await assert.rejects(sh.run('anything'), /kaboom/);
  assert.equal(sh.stack.interactive, null, 'the prompt is released even though the handler threw');
  assert.equal((await sh.run('whoami')).out, 'kali\n');
});

test('interactive: smbclient null session, denied share, credentials, navigation and download', async () => {
  const sh = makeShell();
  const seen = [];
  sh.bus.on('game', (e) => seen.push(`${e.name}:${e.share ?? ''}:${e.file ?? ''}:${e.ok ?? ''}`));

  assert.match((await sh.run('smbclient -L //10.10.20.6 -N')).out, /\tprint\$          Disk      Printer Drivers\n\tpublic          Disk      Public share\n\thr              Disk      HR documents\n\tIPC\$            IPC       IPC Service \(ftp01 Samba\)\nSMB1 disabled/);
  assert.equal(sh.stack.interactive, null, '-L does not open a session');

  const denied = await sh.run('smbclient //10.10.20.6/hr -N');
  assert.equal(denied.err, 'tree connect failed: NT_STATUS_ACCESS_DENIED\n');
  assert.equal(denied.code, 1);
  assert.equal((await sh.run('smbclient //10.10.20.6/nope -N')).err, 'tree connect failed: NT_STATUS_BAD_NETWORK_NAME\n');
  assert.equal((await sh.run('smbclient -L //10.10.20.5 -N')).err, 'do_connect: Connection to 10.10.20.5 failed (Error NT_STATUS_CONNECTION_REFUSED)\n');
  assert.equal((await sh.run('smbclient -L //10.10.20.7 -N')).err, 'do_connect: Connection to 10.10.20.7 failed (Error NT_STATUS_IO_TIMEOUT)\n');
  assert.equal((await sh.run('smbclient -U hr_admin%wrong //10.10.20.6/hr')).err, 'session setup failed: NT_STATUS_LOGON_FAILURE\n');

  await sh.run('smbclient //10.10.20.6/public -N');
  assert.equal(sh.stack.interactive.prompt, 'smb: \\> ');
  assert.match((await sh.run('ls')).out, /welcome\.txt +N +33 .*\n.*it-notes\.txt +N +111 .*\n.*docs +D +0 /);
  assert.equal((await sh.run('cd docs')).out, '');
  assert.equal(sh.stack.interactive.prompt, 'smb: \\docs\\> ');
  assert.equal((await sh.run('pwd')).out, 'Current directory is \\\\10.10.20.6\\public\\docs\\\n');
  assert.match((await sh.run('cd nope')).out, /NT_STATUS_OBJECT_NAME_NOT_FOUND/);
  await sh.run('cd ..');
  assert.equal(sh.stack.interactive.prompt, 'smb: \\> ');
  assert.match((await sh.run('get it-notes.txt')).out, /^getting file \\it-notes\.txt of size 111 as it-notes\.txt/);
  assert.match((await sh.run('get nosuch')).out, /NT_STATUS_OBJECT_NAME_NOT_FOUND/);
  assert.equal((await sh.run('frobnicate')).out, 'frobnicate: command not found\n');
  assert.equal((await sh.run('exit')).done ?? true, true);
  assert.equal(sh.stack.interactive, null);
  assert.match((await sh.run('cat it-notes.txt')).out, /FLAG\{smb_null_session_lists_everything\}/);

  // real credentials open the HR share
  await sh.run('smbclient -U hr_admin%Winter2024! //10.10.20.6/hr');
  assert.match((await sh.run('ls')).out, /salaries\.csv/);
  await sh.run('quit');
  assert.deepEqual(seen.filter((s) => s.startsWith('smb.connect')), [
    'smb.connect:hr::false', 'smb.connect:nope::false', 'smb.connect:public::true', 'smb.connect:hr::true',
  ]);
  assert.ok(seen.includes('smb.get:public:it-notes.txt:'));
});

test('interactive: smbclient asks for a password when -N is not given (hidden input)', async () => {
  const sh = makeShell();
  const r = await sh.run('smbclient //10.10.20.6/public');
  assert.equal(r.code, 0);
  assert.equal(sh.stack.interactive.prompt, 'Password for [ACMEGROUP\\kali]:');
  assert.equal(sh.stack.interactive.secret, true);
  const after = await sh.run('');
  assert.match(after.out, /Try "help"/);
  assert.equal(sh.stack.interactive.prompt, 'smb: \\> ');
  await sh.run('exit');
});

test('interactive: lines typed into ftp re-check state objectives, secrets are never published', async () => {
  const { engine, run, mission } = startMission('c03-m05');
  const lines = [];
  // the event bus the tools use is the same one the engine listens to
  engine.bus.on('interactive', (e) => lines.push(e.line));
  await run('ftp 10.10.20.6'); await run('anonymous'); await run('my-secret-password');
  assert.equal(engine.done.has('o1'), true, 'event objective ftp.login ticks');
  assert.ok(!lines.includes('my-secret-password'), 'the password line is blanked before it reaches listeners');
  await run('get notes.txt'); await run('bye');
  assert.equal(engine.done.has('o2'), true);
  assert.equal(engine.done.has('o3'), false);
  await run('cat notes.txt');
  assert.equal(engine.done.has('o3'), true);
  assert.equal((await engine.submit('FLAG{anonymous_ftp_is_an_open_door}')).ok, true);
  assert.equal(engine.complete, true);
  assert.equal(mission.objectives.filter((o) => o.type === 'event').length, 2);
});

test('event objectives only match the right event and fields', async () => {
  const { engine, run } = startMission('c03-m05');
  await run('ftp 10.10.20.6'); await run('bob'); await run('pw'); await run('bye'); // failed login
  assert.equal(engine.done.has('o1'), false, 'wrong user / not ok');
  await run('ftp 10.10.20.6'); await run('anonymous'); await run('x'); await run('get pub/readme.txt'); await run('bye');
  assert.equal(engine.done.has('o1'), true);
  assert.equal(engine.done.has('o2'), false, 'readme.txt is not notes.txt');
});

// ---------------- web recon tools ----------------
test('gobuster: finds forgotten paths, honours -x, status filtering, and errors', async () => {
  const sh = makeShell();
  const out = (await sh.run('gobuster dir -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt')).out;
  assert.match(out, /^={63}\nGobuster v3\.6\n/);
  assert.match(out, /\[\+\] Url:\s+http:\/\/10\.10\.20\.5\n/);
  assert.match(out, /\/admin +\(Status: 301\) \[Size: \d+\] \[--> http:\/\/10\.10\.20\.5\/admin\/\]/);
  assert.match(out, /\/dev-notes +\(Status: 301\)/);
  assert.match(out, /\/robots\.txt +\(Status: 200\) \[Size: 55\]/);
  assert.match(out, /\/server-status +\(Status: 403\)/);
  assert.doesNotMatch(out, /\/staging|\/phpmyadmin/, 'only paths that exist are reported');
  assert.match(out, /Finished\n={63}\n$/);

  const quiet = (await sh.run('gobuster dir -q -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt -x php')).out;
  assert.match(quiet, /^\/about/);
  assert.match(quiet, /\/config\.php +\(Status: 200\) \[Size: 0\]/);
  assert.match(quiet, /\/index\.php +\(Status: 200\)/);
  assert.doesNotMatch(quiet, /Gobuster v3/, '-q drops the banner');
  assert.doesNotMatch((await sh.run('gobuster dir -q -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt -b 404,403,301')).out, /Status: 403|Status: 301/);

  assert.match((await sh.run('gobuster dir -u http://10.10.20.5')).err, /required flag\(s\) "wordlist" not set/);
  assert.match((await sh.run('gobuster dir -w x.txt')).err, /"url" not set/);
  assert.match((await sh.run('gobuster dir -u http://10.10.20.5 -w /nope.txt')).err, /wordlist file "\/nope\.txt" does not exist/);
  const refused = await sh.run('gobuster dir -u http://10.10.20.5:8080 -w /usr/share/wordlists/dirb/common.txt');
  assert.equal(refused.code, 1);
  assert.match(refused.err, /connection refused/);
  assert.match((await sh.run('gobuster dns -d acme.test')).err, /not supported/);
});

test('gobuster reads wordlists through the VFS (custom lists, permissions)', async () => {
  const sh = makeShell();
  await sh.run("echo 'uploads' > /tmp/mine.txt");
  assert.equal((await sh.run('gobuster dir -q -u http://10.10.20.5 -w /tmp/mine.txt')).out, '/uploads              (Status: 301) [Size: 232] [--> http://10.10.20.5/uploads/]\n');
  const root = makeShell('root');
  assert.match((await root.run('gobuster dir -q -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt')).out, /dev-notes/);
});

test('nikto and whatweb', async () => {
  const sh = makeShell();
  const n = (await sh.run('nikto -h 10.10.20.5')).out;
  assert.match(n, /\+ Target IP: +10\.10\.20\.5\n\+ Target Hostname: +10\.10\.20\.5\n\+ Target Port: +80\n/);
  assert.match(n, /\+ Server: Apache\/2\.4\.41 \(Ubuntu\)\n/);
  assert.match(n, /Retrieved x-powered-by header: PHP\/7\.4\.3/);
  assert.match(n, /X-Frame-Options header is not present/);
  assert.match(n, /\/robots\.txt: contains 2 entries/);
  assert.match(n, /Apache\/2\.4\.41 appears to be outdated/);
  assert.match(n, /\/backup-old\/: Directory indexing found\./);
  assert.match(n, /1 host\(s\) tested\n$/);
  assert.match((await sh.run('nikto -h http://10.10.20.5')).out, /Target Port: +80/);
  assert.match((await sh.run('nikto -h 10.10.20.5 -p 8080')).out, /Cannot resolve or connect to 10\.10\.20\.5:8080/);
  assert.match((await sh.run('nikto')).err, /No host specified/);

  assert.equal((await sh.run('whatweb 10.10.20.5')).out,
    'http://10.10.20.5 [200 OK] Apache[2.4.41], Bootstrap[3.3.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.20.5], JQuery[1.12.4], PHP[7.4.3], Title[ACME Logistics], X-Powered-By[PHP/7.4.3]\n');
  assert.match((await sh.run('whatweb http://10.10.20.5/admin/')).out, /\[403 Forbidden\]/);
  assert.match((await sh.run('whatweb 10.10.20.6:9999')).out, /\[200 OK\] .*HTTPServer\[SimpleHTTP\/0\.6 Python\/3\.8\.10\].*Title\[Directory listing for \/\]/);
  assert.match((await sh.run('whatweb 10.10.20.5:81')).err, /ERROR Opening: http:\/\/10\.10\.20\.5:81 - Connection refused/);
});

test('gobuster/whatweb emit http events so http objectives can see them', async () => {
  const sh = makeShell();
  const seen = new Set();
  sh.bus.on('http', (e) => seen.add(`${e.method} ${e.path} ${e.status}`));
  await sh.run('whatweb 10.10.20.5');
  await sh.run('gobuster dir -q -u http://10.10.20.5 -w /usr/share/wordlists/dirb/common.txt');
  assert.ok(seen.has('GET / 200'));
  assert.ok(seen.has('GET /dev-notes 301'));
  assert.ok(!seen.has('GET /dev-notes/ 200'), 'gobuster never visited the trailing-slash page, so it does not count as reading it');
});

// ---------------- passive recon ----------------
test('whois and subfinder', async () => {
  const sh = makeShell();
  const w = (await sh.run('whois acme.test')).out;
  assert.match(w, /^Domain Name: ACME\.TEST\n/);
  assert.match(w, /Admin Email: somchai\.j@acme\.test/);
  assert.match(w, /Registrant Country: TH/);
  assert.match((await sh.run('whois www.acme.test')).out, /Domain Name: ACME\.TEST/, 'subdomains map to the parent registration');
  assert.match((await sh.run('whois 10.10.20.5')).out, /NetRange: +10\.10\.20\.0 - 10\.10\.20\.255/);
  assert.match((await sh.run('whois nothing.example')).out, /No match for "NOTHING\.EXAMPLE"/);
  assert.equal((await sh.run('whois')).code, 64);

  assert.equal((await sh.run('subfinder -d acme.test -silent')).out, 'db01.acme.test\nftp01.acme.test\nmail.acme.test\nns1.acme.test\nshop.acme.test\nstaging.acme.test\nvpn.acme.test\nweb01.acme.test\nwww.acme.test\n');
  const loud = await sh.run('subfinder -d acme.test');
  assert.match(loud.err, /\[INF\] Enumerating subdomains for acme\.test\n\[INF\] Found 9 subdomains/);
  assert.match(loud.out, /^db01\.acme\.test\n/);
  assert.equal((await sh.run('subfinder -d nothing.example -silent')).out, '');
  assert.match((await sh.run('subfinder')).err, /no input list provided/);
  // CT logs know names DNS does not (that is the point)
  assert.match((await sh.run('dig staging.acme.test')).out, /status: NXDOMAIN/);
});

test('dig axfr: acme.test refuses, acme-dev.test hands over the whole zone', async () => {
  const sh = makeShell();
  assert.match((await sh.run('dig axfr acme.test @ns1.acme.test')).out, /; Transfer failed\./);
  const zone = (await sh.run('dig axfr acme-dev.test @10.10.20.6')).out;
  assert.match(zone, /jenkins\.acme-dev\.test\.\t\t300\tIN\tA\t10\.10\.20\.52/);
  assert.match(zone, /acme-dev\.test\.\t\t300\tIN\tTXT\t"FLAG\{zone_transfers_leak_the_map\}"/);
  assert.equal(zone.match(/\tSOA\t/g).length, 2);
  assert.match(zone, /XFR size: 9 records/);
});

// ---------------- SMB enumeration ----------------
test('enum4linux and crackmapexec', async () => {
  const sh = makeShell();
  const e = (await sh.run('enum4linux -a 10.10.20.6')).out;
  assert.match(e, /\[\+\] Got domain\/workgroup name: ACMEGROUP/);
  assert.match(e, /\/\/10\.10\.20\.6\/public\tMapping: OK Listing: OK Writing: N\/A/);
  assert.match(e, /\/\/10\.10\.20\.6\/hr\tMapping: DENIED Listing: N\/A Writing: N\/A/);
  assert.match(e, /\/\/10\.10\.20\.6\/IPC\$\tMapping: OK Listing: DENIED/);
  assert.match(e, /user:\[ftpuser\]\nuser:\[hr_admin\]/);
  assert.match(e, /S-1-22-1-1001 Unix User\\hr_admin \(Local User\)/);
  const usersOnly = (await sh.run('enum4linux -U 10.10.20.6')).out;
  assert.doesNotMatch(usersOnly, /Share Enumeration/);
  assert.match((await sh.run('enum4linux -S 10.10.20.6')).out, /Share Enumeration/);
  assert.match((await sh.run('enum4linux 10.10.20.5')).out, /Can't find workgroup\/domain/);
  assert.equal((await sh.run('enum4linux')).code, 1);

  const sweep = (await sh.run('crackmapexec smb 10.10.20.5-7')).out;
  assert.equal(sweep.trim().split('\n').length, 1, 'only the host running SMB answers');
  assert.match(sweep, /SMB +10\.10\.20\.6 +445 +FTP01 +\[\*\] Unix \(name:FTP01\) \(domain:ACMEGROUP\) \(signing:False\) \(SMBv1:False\)/);
  assert.match((await sh.run("crackmapexec smb 10.10.20.6 -u hr_admin -p 'Winter2024!'")).out, /\[\+\] ACMEGROUP\\hr_admin:Winter2024!/);
  assert.match((await sh.run('crackmapexec smb 10.10.20.6 -u hr_admin -p wrong')).out, /\[-\] ACMEGROUP\\hr_admin:wrong STATUS_LOGON_FAILURE/);
  const shares = (await sh.run("crackmapexec smb 10.10.20.6 -u hr_admin -p 'Winter2024!' --shares")).out;
  assert.match(shares, /hr +READ +HR documents/);
  assert.match(shares, /public +READ/);
  assert.match((await sh.run('crackmapexec ssh 10.10.20.6')).err, /only the smb protocol/);
});

// ---------------- sanity on the content/tooling relationship ----------------
test('every command in the registry has Thai docs, including the new recon tools', async () => {
  const sh = makeShell();
  const missing = sh.registry.names().filter((n) => !docs.some((d) => d.name === n));
  assert.deepEqual(missing, []);
  for (const n of ['nmap', 'gobuster', 'ftp', 'smbclient', 'enum4linux', 'whois']) assert.match((await sh.run(`man ${n}`)).out, /^NAME\n/);
});
