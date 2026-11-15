import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell } from './helpers.mjs';
import { ipToInt, intToIp, cidrContains, networkAddress, broadcastAddress, maskString, isIPv4 } from '../public/js/sim/network.js';

test('IPv4 helpers', () => {
  assert.equal(ipToInt('10.10.14.2'), 10 * 2 ** 24 + 10 * 2 ** 16 + 14 * 256 + 2);
  assert.equal(intToIp(ipToInt('192.168.1.130')), '192.168.1.130');
  assert.equal(intToIp(ipToInt('255.255.255.255')), '255.255.255.255');
  assert.equal(maskString(24), '255.255.255.0');
  assert.equal(maskString(25), '255.255.255.128');
  assert.equal(networkAddress('192.168.1.130', 25), '192.168.1.128');
  assert.equal(broadcastAddress('10.10.14.2', 24), '10.10.14.255');
  assert.equal(cidrContains('10.10.20.0/24', '10.10.20.77'), true);
  assert.equal(cidrContains('10.10.20.0/24', '10.10.21.1'), false);
  assert.equal(isIPv4('10.10.256.1'), false);
  assert.equal(isIPv4('web01'), false);
});

test('ip, ip route and ifconfig', async () => {
  const sh = makeShell();
  const a = (await sh.run('ip a')).out;
  assert.match(a, /inet 127\.0\.0\.1\/8 scope host lo/);
  assert.match(a, /inet 10\.10\.14\.2\/24 brd 10\.10\.14\.255 scope global noprefixroute eth0/);
  assert.match((await sh.run('ip route')).out, /^default via 10\.10\.14\.1 dev eth0/);
  assert.match((await sh.run('ip r')).out, /10\.10\.14\.0\/24 dev eth0 proto kernel scope link src 10\.10\.14\.2/);
  assert.match((await sh.run('ifconfig')).out, /inet 10\.10\.14\.2  netmask 255\.255\.255\.0  broadcast 10\.10\.14\.255/);
  assert.equal((await sh.run('ip bogus')).code, 1);
  // the web server has its own addressing
  const web = makeShell('www-data', { machine: 'acme-web01' });
  assert.match((await web.run('ip route')).out, /default via 10\.10\.20\.1/);
});

test('ping: replies, TTL reflects hops, down host, DNS names, errors', async () => {
  const sh = makeShell();
  const up = await sh.run('ping -c 3 10.10.20.5');
  assert.equal(up.code, 0);
  assert.match(up.out, /^PING 10\.10\.20\.5 \(10\.10\.20\.5\) 56\(84\) bytes of data\./);
  assert.equal(up.out.match(/icmp_seq=\d ttl=62 time=/g).length, 3, 'two routers away -> ttl 62');
  assert.match(up.out, /3 packets transmitted, 3 received, 0% packet loss/);
  assert.match(up.out, /rtt min\/avg\/max\/mdev = /);

  const down = await sh.run('ping -c 2 10.10.20.7');
  assert.equal(down.code, 1);
  assert.match(down.out, /Destination Host Unreachable/);
  assert.match(down.out, /2 packets transmitted, 0 received, \+2 errors, 100% packet loss/);

  const byName = await sh.run('ping -c 1 web01.acme.test');
  assert.match(byName.out, /PING web01\.acme\.test \(10\.10\.20\.5\)/);
  assert.match(byName.out, /64 bytes from web01\.acme\.test \(10\.10\.20\.5\): icmp_seq=1 ttl=62/);

  assert.match((await sh.run('ping -c 1 127.0.0.1')).out, /ttl=64/);
  assert.match((await sh.run('ping -c 1 10.10.14.2')).out, /1 received/, 'own address answers');
  assert.equal((await sh.run('ping -c 1 nosuch.example')).err, 'ping: nosuch.example: Name or service not known\n');
  assert.equal((await sh.run('ping -c 0 10.10.20.5')).code, 2);
  assert.equal((await sh.run('ping')).code, 2);
  assert.equal((await sh.run('ping -c 1 10.99.99.99')).code, 1, 'unknown address = unreachable');
});

test('ping is deterministic (same RTT for the same host and sequence)', async () => {
  const a = (await makeShell().run('ping -c 2 10.10.20.6')).out.match(/time=[\d.]+/g);
  const b = (await makeShell().run('ping -c 2 10.10.20.6')).out.match(/time=[\d.]+/g);
  assert.deepEqual(a, b);
});

test('traceroute shows every hop and the destination', async () => {
  const sh = makeShell();
  const r = (await sh.run('traceroute 10.10.20.5')).out.trim().split('\n');
  assert.match(r[0], /^traceroute to 10\.10\.20\.5/);
  assert.equal(r.length - 1, 3);
  assert.match(r[1], /^ 1  gw\.lab\.test \(10\.10\.14\.1\)/);
  assert.match(r[2], /^ 2  isp-gw\.acme\.test \(10\.10\.20\.1\)/);
  assert.match(r[3], /^ 3  web01\.acme\.test \(10\.10\.20\.5\)/);
  const down = (await sh.run('traceroute 10.10.20.7')).out;
  assert.match(down, / 3  \* \* \*/, 'a dead host shows timeouts after the last router');
  assert.equal((await sh.run('traceroute nosuch.example')).code, 2);
});

test('dig: answers, +short, NXDOMAIN, CNAME, and zone transfer refused', async () => {
  const sh = makeShell();
  const txt = (await sh.run('dig acme.test TXT')).out;
  assert.match(txt, /status: NOERROR/);
  assert.match(txt, /ANSWER: 2,/);
  assert.match(txt, /acme\.test\.\t\t300\tIN\tTXT\t"FLAG\{dns_txt_records_leak_info\}"/);
  assert.match(txt, /;; SERVER: 10\.10\.14\.1#53/);

  assert.equal((await sh.run('dig acme.test MX +short')).out, '10 mail.acme.test.\n');
  assert.equal((await sh.run('dig +short web01.acme.test')).out, '10.10.20.5\n');
  assert.equal((await sh.run('dig www.acme.test +short')).out, 'acme.test.\n10.10.20.5\n', 'CNAME then its A record');
  assert.equal((await sh.run('dig ns acme.test +short')).out, 'ns1.acme.test.\n');

  const nx = (await sh.run('dig nothere.acme.test')).out;
  assert.match(nx, /status: NXDOMAIN/);
  assert.match(nx, /ANSWER: 0,/);
  const noData = (await sh.run('dig acme.test AAAA')).out;
  assert.match(noData, /status: NOERROR/, 'name exists, no AAAA record');
  assert.match((await sh.run('dig @10.10.20.6 acme.test')).out, /;; SERVER: 10\.10\.20\.6#53/);
  assert.match((await sh.run('dig axfr acme.test @10.10.20.6')).out, /; Transfer failed\./);
});

test('zone transfer works only when the zone allows it', async () => {
  const sh = makeShell();
  sh.stack.current.world.zones['acme.test'].axfr = true; // as a chapter-3 mission would configure
  const out = (await sh.run('dig axfr acme.test @10.10.20.6')).out;
  assert.match(out, /db01\.acme\.test\.\t\t300\tIN\tA\t10\.10\.20\.7/);
  assert.match(out, /XFR size: 14 records/);
  assert.equal(out.match(/\tSOA\t/g).length, 2, 'SOA appears first and last');
});

test('nslookup and host', async () => {
  const sh = makeShell();
  assert.match((await sh.run('nslookup web01.acme.test')).out, /Server:\t\t10\.10\.14\.1[\s\S]*Name:\tweb01\.acme\.test\nAddress: 10\.10\.20\.5/);
  assert.match((await sh.run('nslookup -type=MX acme.test')).out, /acme\.test\tmail exchanger = 10 mail\.acme\.test\./);
  assert.match((await sh.run('nslookup nope.acme.test')).out, /can't find nope\.acme\.test: NXDOMAIN/);
  assert.match((await sh.run('nslookup 10.10.20.6')).out, /6\.20\.10\.10\.in-addr\.arpa\tname = ftp01\.acme\.test\./);
  assert.equal((await sh.run('host web01.acme.test')).out, 'web01.acme.test has address 10.10.20.5\n');
  assert.match((await sh.run('host acme.test')).out, /acme\.test mail is handled by 10 mail\.acme\.test\./);
  assert.match((await sh.run('host -t TXT acme.test')).out, /descriptive text "v=spf1/);
  assert.equal((await sh.run('host nope.acme.test')).code, 1);
  assert.equal((await sh.run('host 10.10.20.5')).out, '5.20.10.10.in-addr.arpa domain name pointer web01.acme.test.\n');
});

test('curl: body, -i, -I, -v, 404, redirects and errors', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl http://10.10.20.5/')).out, /<h1>ACME Logistics<\/h1>/);
  assert.match((await sh.run('curl 10.10.20.5/about')).out, /Founded 1998/, 'scheme is optional');

  const i = (await sh.run('curl -i http://10.10.20.5/')).out;
  assert.match(i, /^HTTP\/1\.1 200 OK\nDate: /);
  assert.match(i, /\nServer: Apache\/2\.4\.41 \(Ubuntu\)\n/);
  assert.match(i, /\nX-Powered-By: PHP\/7\.4\.3\n/);
  assert.match(i, /\nContent-Length: \d+\nContent-Type: text\/html; charset=UTF-8\n\n<!DOCTYPE html>/);

  const head = (await sh.run('curl -I http://10.10.20.5/')).out;
  assert.match(head, /^HTTP\/1\.1 200 OK/);
  assert.doesNotMatch(head, /<html/, 'HEAD returns no body');
  assert.match(head, /Content-Length: [1-9]/, 'but still reports the length');

  const nf = await sh.run('curl -i http://10.10.20.5/nothing');
  assert.match(nf.out, /^HTTP\/1\.1 404 Not Found/);
  assert.equal(nf.code, 0, 'an HTTP error status is still a successful transfer for curl');
  assert.match((await sh.run('curl -i http://10.10.20.5/admin/')).out, /^HTTP\/1\.1 403 Forbidden/);

  const v = await sh.run('curl -v http://10.10.20.5/robots.txt');
  assert.match(v.err, /^\* Trying 10\.10\.20\.5:80\.\.\.\n\* Connected to 10\.10\.20\.5 \(10\.10\.20\.5\) port 80 \(#0\)\n> GET \/robots\.txt HTTP\/1\.1\n> Host: 10\.10\.20\.5\n> User-Agent: curl\/7\.88\.1/);
  assert.match(v.err, /< HTTP\/1\.1 200 OK/);
  assert.equal(v.out, 'User-agent: *\nDisallow: /admin/\nDisallow: /backup-old/\n');

  const redirect = await sh.run('curl -i http://10.10.20.5/backup-old');
  assert.match(redirect.out, /^HTTP\/1\.1 301 Moved Permanently[\s\S]*Location: http:\/\/10\.10\.20\.5\/backup-old\//);
  assert.match((await sh.run('curl -L http://10.10.20.5/backup-old')).out, /robots_txt_is_a_map_not_a_lock/, '-L follows the redirect');
});

test('curl: POST, headers, cookies and custom method', async () => {
  const sh = makeShell();
  assert.match((await sh.run('curl -d "user=a&pass=b" http://10.10.20.5/login')).out, /Invalid username or password/);
  const ok = (await sh.run('curl -i -d "user=admin&pass=admin" http://10.10.20.5/login')).out;
  assert.match(ok, /^HTTP\/1\.1 302 Found/);
  assert.match(ok, /Location: \/admin\//);
  assert.match(ok, /Set-Cookie: session=demo; HttpOnly/);
  assert.match((await sh.run('curl http://10.10.20.5/login')).out, /<form method="POST"/);
  assert.equal((await sh.run('curl -i -X PUT http://10.10.20.5/login')).out.split('\n')[0], 'HTTP/1.1 405 Method Not Allowed');
  const verbose = await sh.run('curl -v -H "X-Test: 1" -A pentest -b "a=b" http://10.10.20.5/');
  assert.match(verbose.err, /> User-Agent: pentest/);
  assert.match(verbose.err, /> x-test: 1/);
  assert.match(verbose.err, /> cookie: a=b/);
});

test('curl: errors, exit codes and -o', async () => {
  const sh = makeShell();
  const dns = await sh.run('curl http://nosuch.example/');
  assert.equal(dns.code, 6);
  assert.equal(dns.err, 'curl: (6) Could not resolve host: nosuch.example\n');
  const refused = await sh.run('curl http://10.10.20.5:8080/');
  assert.equal(refused.code, 7);
  assert.match(refused.err, /curl: \(7\) Failed to connect to 10\.10\.20\.5 port 8080 after \d+ ms: Connection refused/);
  const down = await sh.run('curl http://10.10.20.7/');
  assert.equal(down.code, 28);
  assert.equal((await sh.run('curl -s http://10.10.20.7/')).err, '', '-s hides the error text');
  assert.equal((await sh.run('curl -s http://10.10.20.7/')).code, 28, 'but keeps the exit code');
  assert.equal((await sh.run('curl http://10.10.20.6:22/')).code, 1, 'non-HTTP service');
  assert.equal((await sh.run('curl')).code, 2);
  assert.equal((await sh.run('curl --bogus http://10.10.20.5/')).code, 2);

  await sh.run('curl -s -o /tmp/robots.txt http://10.10.20.5/robots.txt');
  assert.equal((await sh.run('cat /tmp/robots.txt | wc -l')).out, '3\n');
  assert.equal((await sh.run('curl -o /root/x http://10.10.20.5/')).code, 23);
  assert.equal((await sh.run('curl http://10.10.20.5/robots.txt | grep -c Disallow')).out, '2\n');
});

test('nc: banner grabbing, port checks, ranges and raw HTTP', async () => {
  const sh = makeShell();
  const ssh = await sh.run('nc -v 10.10.20.5 22');
  assert.equal(ssh.out, 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n');
  assert.equal(ssh.err, 'Connection to 10.10.20.5 22 port [tcp/ssh] succeeded!\n');
  assert.equal((await sh.run('nc 10.10.20.5 22')).err, '', 'quiet without -v');
  assert.equal((await sh.run('nc -v 10.10.20.6 21')).out, '220 (vsFTPd 3.0.3)\n');

  const closed = await sh.run('nc -zv 10.10.20.5 21');
  assert.equal(closed.code, 1);
  assert.equal(closed.err, 'nc: connect to 10.10.20.5 port 21 (tcp) failed: Connection refused\n');
  assert.equal((await sh.run('nc -z 10.10.20.5 21')).err, '', 'silent failure without -v');

  const open = await sh.run('nc -zv 10.10.20.5 80');
  assert.equal(open.code, 0);
  assert.equal(open.out, '', '-z does not read the banner');
  assert.match(open.err, /port \[tcp\/http\] succeeded!/);

  const range = await sh.run('nc -zv 10.10.20.6 20-23');
  assert.match(range.err, /port \[tcp\/ftp\] succeeded!/);
  assert.match(range.err, /port \[tcp\/ssh\] succeeded!/);
  assert.equal(range.err.match(/Connection refused/g).length, 2, 'ports 20 and 23 are closed');

  const down = await sh.run('nc -zv 10.10.20.7 22');
  assert.equal(down.code, 1);
  assert.match(down.err, /timed out: Operation now in progress/, 'a dead host times out, it does not refuse');

  const raw = await sh.run("echo -e 'GET /robots.txt HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n' | nc 10.10.20.5 80");
  assert.match(raw.out, /^HTTP\/1\.1 200 OK\n[\s\S]*\n\nUser-agent: \*/);
  assert.match((await sh.run("echo 'nonsense' | nc 10.10.20.5 80")).out, /^HTTP\/1\.1 400 Bad Request/);
  assert.match((await sh.run('nc -l 4444')).err, /listening mode is not available yet/);
  assert.equal((await sh.run('nc 10.10.20.5 99999')).code, 1);
  assert.equal((await sh.run('nc nosuch.example 80')).code, 1);
});

test('network commands emit events for the mission engine', async () => {
  const sh = makeShell();
  const seen = [];
  sh.bus.on('http', (e) => seen.push(`http ${e.method} ${e.path} ${e.status}`));
  sh.bus.on('net', (e) => seen.push(`net ${e.kind} ${e.ip}`));
  await sh.run('curl -s http://10.10.20.5/robots.txt');
  await sh.run('ping -c 1 10.10.20.6');
  assert.deepEqual(seen, ['net http 10.10.20.5', 'http GET /robots.txt 200', 'net ping 10.10.20.6']);
});

test('no network: commands fail like a machine with no route', async () => {
  const sh = makeShell(undefined, { network: null });
  assert.match((await sh.run('ping -c 1 10.10.20.5')).err, /Network is unreachable/);
  assert.equal((await sh.run('curl http://10.10.20.5/')).code, 6);
  assert.match((await sh.run('nc -v 10.10.20.5 22')).err, /Network is unreachable/);
});

test('ps: own shell, full listing and -ef', async () => {
  const sh = makeShell('www-data', { machine: 'acme-web01' });
  const own = (await sh.run('ps')).out;
  assert.match(own, /^ {4}PID TTY +TIME CMD\n/);
  assert.match(own, /bash\n/);
  const aux = (await sh.run('ps aux')).out;
  assert.match(aux, /^USER +PID %CPU %MEM +VSZ +RSS TTY +STAT START +TIME COMMAND\n/);
  assert.match(aux, /mysql +903 .* \/usr\/sbin\/mysqld\n/);
  assert.match(aux, /www-data +815 .* \/usr\/sbin\/apache2 -k start\n/);
  assert.match(aux, /www-data +\d+ .* ps\n/, 'you can see yourself');
  assert.equal((await sh.run('ps aux | grep mysql | wc -l')).out, '1\n');
  assert.match((await sh.run('ps -ef')).out, /^UID +PID +PPID +C STIME TTY +TIME CMD\n/);
  assert.equal((await sh.run('ps --bogus')).code, 1);
});

test('ss / netstat: root sees every process, others only their own', async () => {
  const web = makeShell('www-data', { machine: 'acme-web01' });
  const ss = (await web.run('ss -tulnp')).out;
  assert.match(ss, /127\.0\.0\.1:3306/);
  assert.match(ss, /0\.0\.0\.0:22 /);
  assert.doesNotMatch(ss, /mysqld/, 'www-data cannot see mysql\'s process');
  assert.doesNotMatch(ss, /users:/, 'nor root-owned sshd/apache2 (only its own would show)');
  assert.equal((await web.run('ss -tln')).out.includes('udp'), false, '-t excludes UDP');
  assert.match((await web.run('ss -ulnp')).out, /127\.0\.0\.53:53/);
  assert.equal((await web.run('ss')).out.trim().split('\n').length, 1, 'without -l there are no established connections');

  const ns = await web.run('netstat -tulnp');
  assert.match(ns.out, /^Active Internet connections \(only servers\)/);
  assert.match(ns.out, /tcp +0 +0 127\.0\.0\.1:3306 +0\.0\.0\.0:\* +LISTEN +-\n/);
  assert.match(ns.err, /Not all processes could be identified/);

  const root = makeShell('root', { machine: 'acme-web01' });
  assert.match((await root.run('ss -tulnp')).out, /127\.0\.0\.1:3306 .*users:\(\("mysqld",pid=903,fd=3\)\)/);
  assert.match((await root.run('netstat -tulnp')).out, /LISTEN +712\/sshd/);
  assert.equal((await root.run('netstat -tulnp')).err, '');
});

test('xxd and tr', async () => {
  const sh = makeShell();
  assert.equal((await sh.run('echo hello | xxd -p')).out, '68656c6c6f0a\n');
  assert.equal((await sh.run('echo 68656c6c6f0a | xxd -r -p')).out, 'hello\n');
  const dump = (await sh.run('echo hello | xxd')).out;
  assert.equal(dump, '00000000: 6865 6c6c 6f0a                           hello.\n');
  assert.equal((await sh.run('echo hello | xxd | xxd -r')).out, 'hello\n', 'a classic dump round-trips');
  assert.equal((await sh.run('echo zz | xxd -r -p')).code, 1);

  assert.equal((await sh.run("echo URYYB | tr 'A-Za-z' 'N-ZA-Mn-za-m'")).out, 'HELLO\n');
  assert.equal((await sh.run("echo hello | tr a-z A-Z")).out, 'HELLO\n');
  assert.equal((await sh.run("echo 'a-b-c' | tr -d '-'")).out, 'abc\n');
  assert.equal((await sh.run("echo abc | tr '[:lower:]' '[:upper:]'")).out, 'ABC\n');
  assert.equal((await sh.run('tr a')).code, 1);
});

test('echo -e handles \\r so raw HTTP can be typed', async () => {
  const sh = makeShell();
  assert.equal((await sh.run("echo -e 'a\\r\\nb'")).out, 'a\r\nb\n');
});
