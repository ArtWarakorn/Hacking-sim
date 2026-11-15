import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell, docs } from './helpers.mjs';

test('basic navigation and prompt', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('pwd')).out, '/home/kali\n');
  assert.equal(sh.stack.current.prompt(), 'kali@kali:~$ ');
  assert.equal((await sh.run('cd Documents && pwd')).out, '/home/kali/Documents\n');
  assert.equal(sh.stack.current.prompt(), 'kali@kali:~/Documents$ ');
  assert.equal((await sh.run('cd /nope')).err, 'bash: cd: /nope: No such file or directory\n');
  await sh.run('cd -');
  assert.equal(sh.stack.current.cwd, '/home/kali');
  await sh.run('cd /var/log');
  assert.equal((await sh.run('cd ~')).code, 0);
  assert.equal(sh.stack.current.cwd, '/home/kali');
});

test('ls variants', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('ls')).out, 'Desktop  Documents\n');
  assert.match((await sh.run('ls -a')).out, /\.bash_history/);
  const long = (await sh.run('ls -l /etc/hosts')).out;
  assert.match(long, /^-rw-r--r-- 1 root root +\d+ Nov 15 10:00 \/etc\/hosts\n$/);
  assert.match((await sh.run('ls -la /home/kali')).out, /drwxr-xr-x 2 kali kali +4096 .* Documents/);
  assert.equal((await sh.run('ls /nope')).err, "ls: cannot access '/nope': No such file or directory\n");
  assert.equal((await sh.run('ls /root')).err, "ls: cannot open directory '/root': Permission denied\n");
  assert.equal((await sh.run('ls Documents | cat')).out, 'readme.txt\ntodo.txt\n');
});

test('permissions: kali cannot read root files, root can', async () => {
  const sh = makeShell();
  const r = await sh.run('cat /root/secret.txt');
  assert.equal(r.err, 'cat: /root/secret.txt: Permission denied\n');
  assert.equal(r.code, 1);
  const rootSh = makeShell('root');
  assert.equal((await rootSh.run('cat /root/secret.txt')).out, 'FLAG{only_root_can_read_this}\n');
  assert.equal(rootSh.stack.current.prompt(), 'root@kali:~# ');
});

test('pipes, redirects and chaining', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('echo hi | cat')).out, 'hi\n');
  await sh.run('echo one > /tmp/x');
  await sh.run('echo two >> /tmp/x');
  assert.equal((await sh.run('cat /tmp/x')).out, 'one\ntwo\n');
  assert.equal((await sh.run('cat /tmp/x | wc -l')).out, '2\n');
  assert.equal((await sh.run('false || echo recovered')).out, 'recovered\n');
  assert.equal((await sh.run('false && echo nope')).out, '');
  assert.equal((await sh.run('echo a; echo b')).out, 'a\nb\n');
  assert.equal((await sh.run('cat /nope 2>/dev/null; echo done')).text, 'done\n');
  const merged = await sh.run('cat /nope 2>&1 | grep -c nope');
  assert.equal(merged.out, '1\n');
  const denied = await sh.run('echo x > /etc/hosts');
  assert.equal(denied.err, 'bash: /etc/hosts: Permission denied\n');
  assert.equal(denied.code, 1);
});

test('variables, globbing and tilde', async () => {
  const sh = makeShell();
  await sh.run('export TARGET=10.10.20.5');
  assert.equal((await sh.run('echo $TARGET')).out, '10.10.20.5\n');
  assert.equal((await sh.run('cat Documents/*.txt | wc -l')).out, '6\n');
  assert.equal((await sh.run('ls ~/Documents')).out, 'readme.txt  todo.txt\n');
  assert.equal((await sh.run('false; echo $?')).out, '1\n');
  assert.equal((await sh.run('export X=1; echo $X')).out, '1\n'); // set and used on the same line
  assert.equal((await sh.run('echo "[$NOPE]" a$NOPE.b')).out, '[] a.b\n');
  assert.equal((await sh.run('echo $NOPE end')).out, 'end\n');
  assert.equal((await sh.run("echo '*.txt'")).out, '*.txt\n');
});

test('grep', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('grep -c Failed /var/log/auth.log')).out, '2\n');
  assert.match((await sh.run('grep -n Accepted /var/log/auth.log')).out, /^3:Nov 15 09:02:40/);
  assert.equal((await sh.run('grep -rn FLAG /home/kali')).out, '/home/kali/.hidden_note:1:FLAG{hidden_files_are_not_secret}\n');
  assert.equal((await sh.run('cd /home/kali && grep -r FLAG')).out, '.hidden_note:FLAG{hidden_files_are_not_secret}\n');
  assert.equal((await sh.run('grep -i FAILED /var/log/auth.log | wc -l')).out, '2\n');
  assert.equal((await sh.run('grep -v Failed /var/log/auth.log | wc -l')).out, '2\n');
  assert.equal((await sh.run('grep zzz /etc/hosts')).code, 1);
  assert.equal((await sh.run('grep -E "kali|localhost" /etc/hosts | wc -l')).out, '2\n');
});

test('find, including -perm and permission noise', async () => {
  const sh = makeShell();
  const txt = await sh.run("find / -name '*.txt'");
  assert.match(txt.out, /\/home\/kali\/Documents\/readme\.txt/);
  assert.match(txt.err, /find: ‘\/root’: Permission denied/);
  assert.equal((await sh.run("find / -name '*.txt' 2>/dev/null")).err, '');
  assert.equal((await sh.run('find /opt -type f -perm -755')).out, '/opt/tools/scan.sh\n');
  assert.equal((await sh.run('find /home/kali -maxdepth 1 -type d')).out, '/home/kali\n/home/kali/Desktop\n/home/kali/Documents\n');
  assert.equal((await sh.run('find /etc -bogus')).code, 1);
});

test('text filters and base64', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('echo hello | base64')).out, 'aGVsbG8K\n');
  assert.equal((await sh.run('echo aGVsbG8K | base64 -d')).out, 'hello\n');
  assert.equal((await sh.run('cut -d: -f1 /etc/passwd')).out, 'root\nkali\n');
  assert.equal((await sh.run('head -n 1 /var/log/auth.log | wc -l')).out, '1\n');
  assert.equal((await sh.run('tail -1 /etc/hosts')).out, '127.0.1.1\tkali\n');
  assert.equal((await sh.run('cut -d" " -f6 /var/log/auth.log | sort | uniq -c | sort -rn | head -n 1')).out.trim().split(/\s+/)[0], '2');
});

test('file management', async () => {
  const sh = makeShell();
  await sh.run('mkdir -p /tmp/w/n && touch /tmp/w/n/f');
  assert.equal((await sh.run('ls /tmp/w/n')).out, 'f\n');
  assert.equal((await sh.run('rm /tmp/w')).err, "rm: cannot remove '/tmp/w': Is a directory\n");
  await sh.run('rm -rf /tmp/w');
  assert.equal((await sh.run('ls /tmp')).out, '');
  await sh.run('chmod 600 /home/kali/Documents/todo.txt');
  assert.match((await sh.run('ls -l Documents/todo.txt')).out, /^-rw-------/);
  await sh.run('chmod u+x,go+r Documents/todo.txt');
  assert.match((await sh.run('ls -l Documents/todo.txt')).out, /^-rwxr--r--/);
});

test('system info commands', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('whoami')).out, 'kali\n');
  assert.equal((await sh.run('id')).out, 'uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo)\n');
  assert.equal((await sh.run('id root')).out, 'uid=0(root) gid=0(root) groups=0(root)\n');
  assert.match((await sh.run('uname -a')).out, /^Linux kali 6\.1\.0-kali9-amd64 #1 SMP .* x86_64 GNU\/Linux\n$/);
  assert.equal((await sh.run('hostname')).out, 'kali\n');
  assert.match((await sh.run('env')).out, /USER=kali/);
});

test('unknown commands, typos and syntax errors', async () => {
  const sh = makeShell();
  const r = await sh.run('lss');
  assert.equal(r.code, 127);
  assert.match(r.err, /bash: lss: command not found\nคำสั่งที่ใกล้เคียง: ls/);
  assert.equal((await sh.run('./nothing')).err, 'bash: ./nothing: No such file or directory\n');
  assert.equal((await sh.run('/bin/ls /opt')).out, 'tools\n');
  assert.match((await sh.run("echo 'oops")).err, /unexpected EOF/);
  assert.equal((await sh.run('| ls')).code, 2);
});

test('help, man and --help come from commands.json', async () => {
  const sh = makeShell();
  assert.match((await sh.run('help')).out, /ระบบไฟล์/);
  assert.match((await sh.run('man ls')).out, /^NAME\n {4}ls — /);
  assert.match((await sh.run('grep --help')).out, /SYNOPSIS/);
  assert.equal((await sh.run('man nothing')).code, 16);
  // every registered command is documented
  const undocumented = sh.registry.names().filter((n) => !docs.some((d) => d.name === n));
  assert.deepEqual(undocumented, []);
});

test('clear flag and history', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('clear')).clear, true);
  await sh.run('ls');
  assert.match((await sh.run('history')).out, /ls\n/);
});

test('events are emitted for the mission engine', async () => {
  const sh = makeShell();
  const seen = [];
  sh.bus.on('command', (e) => seen.push(e.line));
  sh.bus.on('file_read', (e) => seen.push(`read:${e.path}`));
  await sh.run('cat /etc/hosts');
  assert.deepEqual(seen, ['read:/etc/hosts', 'cat /etc/hosts']);
});
