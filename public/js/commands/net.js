// Network commands (all simulated against session.world): ip, ifconfig, ping, traceroute, dig, nslookup, host, nc
import { parseArgs, usageErr } from './util.js';
import { PORT_NAMES, isIPv4, maskString, broadcastAddress, networkAddress } from '../sim/network.js';
import { httpRequest } from '../sim/httpsim.js';

const ok = (out = '') => ({ out, err: '', code: 0 });
const fail = (err, code = 1) => ({ out: '', err, code });
const hash = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; };
const f3 = (n) => n.toFixed(3);
const noNet = (cmd) => fail(`${cmd}: connect: Network is unreachable\n`, 2);

export function interfacesOf(machine) {
  if (machine.interfaces) return machine.interfaces;
  const gw = machine.ip.replace(/\.\d+$/, '.1');
  return [{ name: 'eth0', ip: machine.ip, prefix: 24, mac: '08:00:27:3e:5a:11', gateway: gw }];
}

const emitNet = (ctx, kind, ip, extra = {}) => ctx.bus?.emit('net', { kind, ip, session: ctx.session, ...extra });

// ---------- ip / ifconfig ----------
const ip = {
  name: 'ip',
  async run(ctx, args) {
    const sub = args.find((a) => !a.startsWith('-'));
    const ifs = interfacesOf(ctx.session.machine);
    if (!sub) return fail("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\nwhere  OBJECT := { address | route | link }\n", 255);
    if (['a', 'addr', 'address'].includes(sub)) {
      let out = '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n'
        + '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n'
        + '    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n';
      ifs.forEach((i, n) => {
        out += `${n + 2}: ${i.name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n`
          + `    link/ether ${i.mac} brd ff:ff:ff:ff:ff:ff\n`
          + `    inet ${i.ip}/${i.prefix} brd ${broadcastAddress(i.ip, i.prefix)} scope global noprefixroute ${i.name}\n`
          + '       valid_lft forever preferred_lft forever\n';
      });
      return ok(out);
    }
    if (['r', 'route'].includes(sub)) {
      const i = ifs[0];
      return ok(`default via ${i.gateway} dev ${i.name} \n${networkAddress(i.ip, i.prefix)}/${i.prefix} dev ${i.name} proto kernel scope link src ${i.ip} \n`);
    }
    if (['l', 'link'].includes(sub)) {
      return ok(`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n${ifs.map((i, n) => `${n + 2}: ${i.name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n    link/ether ${i.mac} brd ff:ff:ff:ff:ff:ff\n`).join('')}`);
    }
    return fail(`Object "${sub}" is unknown, try "ip help".\n`, 1);
  },
};

const ifconfig = {
  name: 'ifconfig',
  async run(ctx) {
    let out = '';
    for (const i of interfacesOf(ctx.session.machine)) {
      out += `${i.name}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n`
        + `        inet ${i.ip}  netmask ${maskString(i.prefix)}  broadcast ${broadcastAddress(i.ip, i.prefix)}\n`
        + `        ether ${i.mac}  txqueuelen 1000  (Ethernet)\n\n`;
    }
    out += 'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n        loop  txqueuelen 1000  (Local Loopback)\n\n';
    return ok(out);
  },
};

// ---------- ping / traceroute ----------
const ping = {
  name: 'ping',
  async run(ctx, args) {
    const { values, rest, errors } = parseArgs(args, { flags: 'nq', values: 'cWwi' });
    if (errors.length) return usageErr('ping', errors);
    if (!rest.length) return fail('ping: usage error: Destination address required\n', 2);
    const count = values.c === undefined ? 4 : Number.parseInt(values.c, 10);
    if (!(count >= 1)) return fail(`ping: invalid argument: '${values.c}'\n`, 2);
    const world = ctx.session.world;
    if (!world) return noNet('ping');
    const name = rest[0];
    const r = world.resolve(name);
    if (!r) return fail(`ping: ${name}: Name or service not known\n`, 2);
    const self = ctx.session.machine.ip;
    const local = r.ip.startsWith('127.') || r.ip === self;
    const up = local || world.pingable(r.ip);
    const n = Math.min(count, 20);
    emitNet(ctx, 'ping', r.ip);

    const label = r.name && !isIPv4(name) ? `${r.name} (${r.ip})` : r.ip;
    let out = `PING ${name} (${r.ip}) 56(84) bytes of data.\n`;
    if (!up) {
      for (let s = 1; s <= n; s++) out += `From ${self} icmp_seq=${s} Destination Host Unreachable\n`;
      out += `\n--- ${name} ping statistics ---\n${n} packets transmitted, 0 received, +${n} errors, 100% packet loss, time ${(n - 1) * 1000 + 56}ms\n`;
      return { out, err: '', code: 1 };
    }
    const hops = local ? 0 : (world.host(r.ip)?.hops?.length ?? 0);
    const ttl = (world.host(r.ip)?.ttl ?? 64) - hops;
    const times = [];
    for (let s = 1; s <= n; s++) {
      const t = local ? 0.02 + (hash(`${r.ip}/${s}`) % 40) / 1000 : world.rtt(r.ip, s);
      times.push(t);
      out += `64 bytes from ${label}: icmp_seq=${s} ttl=${local ? 64 : ttl} time=${f3(t)} ms\n`;
    }
    const min = Math.min(...times); const max = Math.max(...times); const avg = times.reduce((a, b) => a + b, 0) / n;
    const mdev = Math.sqrt(times.reduce((a, t) => a + (t - avg) ** 2, 0) / n);
    out += `\n--- ${name} ping statistics ---\n${n} packets transmitted, ${n} received, 0% packet loss, time ${(n - 1) * 1001 + 3}ms\n`
      + `rtt min/avg/max/mdev = ${f3(min)}/${f3(avg)}/${f3(max)}/${f3(mdev)} ms\n`;
    return ok(out);
  },
};

const traceroute = {
  name: 'traceroute',
  async run(ctx, args) {
    const { rest, errors } = parseArgs(args, { flags: 'nI' });
    if (errors.length) return usageErr('traceroute', errors);
    if (!rest.length) return fail('Usage: traceroute [options] host\n', 2);
    const world = ctx.session.world;
    if (!world) return noNet('traceroute');
    const r = world.resolve(rest[0]);
    if (!r) return fail(`${rest[0]}: Name or service not known\nCannot handle "host" cmdline arg \`${rest[0]}' on position 1 (argc 1)\n`, 2);
    emitNet(ctx, 'traceroute', r.ip);
    const host = world.host(r.ip);
    const hops = host?.hops ?? [];
    const rows = (ipAddr, idx) => {
      if (ipAddr === '*') return ` ${idx}  * * *\n`;
      const nm = world.hostnameOf(ipAddr);
      const t = [1, 2, 3].map((k) => `${f3(world.rtt(ipAddr, k) + idx * 0.3)} ms`).join('  ');
      return ` ${idx}  ${nm || ipAddr} (${ipAddr})  ${t}\n`;
    };
    let out = `traceroute to ${rest[0]} (${r.ip}), 30 hops max, 60 byte packets\n`;
    hops.forEach((h, i) => { out += rows(h, i + 1); });
    if (world.pingable(r.ip)) out += rows(r.ip, hops.length + 1);
    else for (let k = 1; k <= 3; k++) out += ` ${hops.length + k}  * * *\n`;
    return ok(out);
  },
};

// ---------- DNS ----------
const TYPES = new Set(['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'PTR', 'ANY', 'AXFR']);
const dot = (s) => (s.endsWith('.') ? s : `${s}.`);

function formatValue(type, value) {
  if (type === 'TXT') return `"${value}"`;
  if (['NS', 'CNAME', 'PTR'].includes(type)) return dot(value);
  if (type === 'MX') { const [p, h] = value.split(' '); return `${p} ${dot(h)}`; }
  return value;
}
const whenStamp = () => new Date().toUTCString().replace(/^(\w+), (\d+) (\w+) (\d+) ([\d:]+) GMT$/, '$1 $3 $2 $5 UTC $4');
const row = (r) => `${dot(r.name)}\t\t${r.ttl}\tIN\t${r.type}\t${formatValue(r.type, r.value)}\n`;

const dig = {
  name: 'dig',
  async run(ctx, args) {
    const world = ctx.session.world;
    if (!world) return fail('dig: couldn\'t get address for \'127.0.0.53\': network unreachable\n', 9);
    let name = null; let type = 'A'; let server = null; let short = false;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith('@')) server = a.slice(1);
      else if (a === '+short') short = true;
      else if (a === '-t' && args[i + 1]) type = args[++i].toUpperCase();
      else if (a.startsWith('+') || a.startsWith('-')) continue;
      else if (TYPES.has(a.toUpperCase())) type = a.toUpperCase();
      else name = a;
    }
    if (!name) return ok('; <<>> DiG 9.18.12-1-Debian <<>>\n;; global options: +cmd\n;; no query name given\n');
    const srv = server || world.resolver;
    const cmdline = args.filter((a) => a !== '+short').join(' ');
    emitNet(ctx, 'dns', srv, { name, type });

    if (type === 'AXFR') {
      const z = world.zoneFor(name);
      let out = `\n; <<>> DiG 9.18.12-1-Debian <<>> ${cmdline}\n;; global options: +cmd\n`;
      if (!z || z.label !== '@' || !z.zone.axfr) {
        return ok(`${out}; Transfer failed.\n`);
      }
      const soa = z.zone.records.find((r) => r.type === 'SOA');
      const fq = (l) => (l === '@' ? z.domain : `${l}.${z.domain}`);
      const all = z.zone.records.map((r) => ({ name: fq(r.name), ttl: r.ttl ?? z.zone.ttl ?? 300, type: r.type, value: r.value }));
      const soaRow = all.find((r) => r.type === 'SOA');
      out += [soaRow, ...all.filter((r) => r.type !== 'SOA' || r !== soaRow), soaRow].filter(Boolean).map(row).join('');
      return ok(`${out};; Query time: ${5 + (hash(name) % 20)} msec\n;; SERVER: ${srv}#53(${srv}) (TCP)\n;; WHEN: ${whenStamp()}\n;; XFR size: ${all.length + 1} records (messages 1, bytes ${all.length * 60})\n`);
    }

    const answers = world.records(name, type);
    if (short) return ok(answers.map((r) => (r.type === 'TXT' ? `"${r.value}"` : formatValue(r.type, r.value))).join('\n') + (answers.length ? '\n' : ''));
    const exists = world.nameExists(name) || Boolean(world.resolve(name));
    const status = exists ? 'NOERROR' : 'NXDOMAIN';
    const id = 1000 + (hash(name + type) % 60000);
    let out = `\n; <<>> DiG 9.18.12-1-Debian <<>> ${cmdline}\n;; global options: +cmd\n;; Got answer:\n`
      + `;; ->>HEADER<<- opcode: QUERY, status: ${status}, id: ${id}\n`
      + `;; flags: qr rd ra; QUERY: 1, ANSWER: ${answers.length}, AUTHORITY: 0, ADDITIONAL: 1\n\n`
      + ';; OPT PSEUDOSECTION:\n; EDNS: version: 0, flags:; udp: 65494\n'
      + `;; QUESTION SECTION:\n;${dot(name)}\t\t\tIN\t${type}\n\n`;
    if (answers.length) out += `;; ANSWER SECTION:\n${answers.map(row).join('')}\n`;
    const size = 40 + answers.reduce((s, r) => s + r.value.length + 12, 0);
    out += `;; Query time: ${5 + (hash(name) % 25)} msec\n;; SERVER: ${srv}#53(${srv}) (UDP)\n;; WHEN: ${whenStamp()}\n;; MSG SIZE  rcvd: ${size}\n\n`;
    return ok(out);
  },
};

const nslookup = {
  name: 'nslookup',
  async run(ctx, args) {
    const world = ctx.session.world;
    if (!world) return fail(';; connection timed out; no servers could be reached\n', 1);
    let type = 'A'; const rest = [];
    for (const a of args) {
      const m = /^-(?:type|q|querytype)=(\w+)$/i.exec(a);
      if (m) type = m[1].toUpperCase(); else if (!a.startsWith('-')) rest.push(a);
    }
    if (!rest.length) return fail('> (interactive mode is not supported here)\n', 1);
    const [name, srvArg] = rest;
    const srv = srvArg || world.resolver;
    emitNet(ctx, 'dns', srv, { name, type });
    const head = `Server:\t\t${srv}\nAddress:\t${srv}#53\n\n`;
    if (isIPv4(name)) {
      const hn = world.hostnameOf(name);
      const arpa = `${name.split('.').reverse().join('.')}.in-addr.arpa`;
      return ok(hn ? `${head}${arpa}\tname = ${hn}.\n\n` : `${head}** server can't find ${arpa}: NXDOMAIN\n\n`);
    }
    const ans = world.records(name, type);
    if (!ans.length) return ok(`${head}${world.nameExists(name) ? '' : `** server can't find ${name}: NXDOMAIN\n`}\n`);
    let out = `${head}Non-authoritative answer:\n`;
    for (const r of ans) {
      if (r.type === 'A') out += `Name:\t${r.name}\nAddress: ${r.value}\n`;
      else if (r.type === 'TXT') out += `${r.name}\ttext = "${r.value}"\n`;
      else if (r.type === 'MX') out += `${r.name}\tmail exchanger = ${formatValue('MX', r.value)}\n`;
      else if (r.type === 'NS') out += `${r.name}\tnameserver = ${dot(r.value)}\n`;
      else if (r.type === 'CNAME') out += `${r.name}\tcanonical name = ${dot(r.value)}\n`;
      else out += `${r.name}\t${r.type} ${r.value}\n`;
    }
    return ok(`${out}\n`);
  },
};

const host = {
  name: 'host',
  async run(ctx, args) {
    const world = ctx.session.world;
    if (!world) return fail(';; connection timed out; no servers could be reached\n', 1);
    let type = null; const rest = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-t' && args[i + 1]) type = args[++i].toUpperCase();
      else if (!args[i].startsWith('-')) rest.push(args[i]);
    }
    if (!rest.length) return fail('Usage: host [-aCdilrTvVw] [-c class] [-N ndots] [-t type] [-W time]\n', 1);
    const name = rest[0];
    emitNet(ctx, 'dns', world.resolver, { name, type: type || 'A' });
    if (isIPv4(name)) {
      const hn = world.hostnameOf(name);
      const arpa = `${name.split('.').reverse().join('.')}.in-addr.arpa`;
      return hn ? ok(`${arpa} domain name pointer ${hn}.\n`) : fail(`Host ${arpa} not found: 3(NXDOMAIN)\n`, 1);
    }
    const types = type ? [type] : ['A', 'MX'];
    let out = '';
    for (const t of types) {
      for (const r of world.records(name, t)) {
        if (r.type === 'A') out += `${r.name} has address ${r.value}\n`;
        else if (r.type === 'MX') out += `${r.name} mail is handled by ${formatValue('MX', r.value)}\n`;
        else if (r.type === 'TXT') out += `${r.name} descriptive text "${r.value}"\n`;
        else if (r.type === 'NS') out += `${r.name} name server ${dot(r.value)}\n`;
        else if (r.type === 'CNAME') out += `${r.name} is an alias for ${dot(r.value)}\n`;
        else out += `${r.name} ${r.type} ${r.value}\n`;
      }
    }
    return out ? ok(out) : fail(`Host ${name} not found: 3(NXDOMAIN)\n`, 1);
  },
};

// ---------- nc ----------
function parsePorts(spec) {
  const m = /^(\d+)(?:-(\d+))?$/.exec(spec || '');
  if (!m) return null;
  const a = Number(m[1]); const b = Number(m[2] ?? m[1]);
  if (a < 1 || b > 65535 || a > b || b - a > 1024) return null;
  return Array.from({ length: b - a + 1 }, (_, i) => a + i);
}

function rawHttp(world, input, host, port, selfIp) {
  const lines = input.split(/\r?\n/);
  const m = /^(\w+)\s+(\S+)\s+HTTP\/1\.[01]$/.exec(lines[0] || '');
  if (!m) return 'HTTP/1.1 400 Bad Request\nConnection: close\n\n';
  const headers = {};
  for (const l of lines.slice(1)) { const i = l.indexOf(':'); if (i > 0) headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); }
  const [path, query = ''] = m[2].split('?');
  const res = httpRequest(world, { scheme: 'http', host, port, method: m[1], path, query, headers, body: '', hostHeader: headers.host || host }, selfIp);
  if (!res.ok) return '';
  const r = res.response;
  return `HTTP/1.1 ${r.status} ${r.reason}\n${r.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${r.body}`;
}

const nc = {
  name: 'nc',
  async run(ctx, args, input) {
    const { flags, values, rest, errors } = parseArgs(args, { flags: 'zvnulk', values: 'wpsq' });
    if (errors.length) return usageErr('nc', errors);
    if (flags.has('l')) return fail('nc: listening mode is not available yet — it unlocks with reverse shells in chapter 6\n', 1);
    const [target, portSpec] = rest;
    if (!target || !portSpec) return fail('usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port] [-q seconds]\n\t  [-s sourceaddr] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]\n\t  [-X proxy_protocol] [-x proxy_address[:port]] [destination] [port]\n', 1);
    const world = ctx.session.world;
    if (!world) return noNet('nc');
    const ports = parsePorts(portSpec);
    if (!ports) return fail(`nc: port number invalid: ${portSpec}\n`, 1);
    const r = world.resolve(target);
    if (!r) return fail(`nc: getaddrinfo for host "${target}" port ${portSpec}: Name or service not known\n`, 1);
    const self = ctx.session.machine.ip;
    const ipAddr = r.ip === '127.0.0.1' ? self : r.ip;
    const verbose = flags.has('v');
    let out = ''; let err = ''; let connected = false;

    for (const p of ports) {
      const pname = PORT_NAMES[p] || 'unknown';
      const state = ipAddr === self && !world.host(ipAddr) ? 'closed' : world.portState(ipAddr, p);
      const svc = state === 'open' ? world.service(ipAddr, p) : null;
      emitNet(ctx, 'connect', ipAddr, { port: p });
      if (state === 'filtered') {
        if (verbose) err += `nc: connect to ${target} port ${p} (tcp) timed out: Operation now in progress\n`;
        continue;
      }
      if (state === 'closed') {
        if (verbose) err += `nc: connect to ${target} port ${p} (tcp) failed: Connection refused\n`;
        continue;
      }
      connected = true;
      if (verbose) err += `Connection to ${target} ${p} port [tcp/${pname}] succeeded!\n`;
      if (flags.has('z')) continue;
      if (svc.http && input) out += rawHttp(world, input, target, p, self);
      else if (svc.banner) out += `${svc.banner}\n`;
    }
    return { out, err, code: connected ? 0 : 1 };
  },
};

export const netCommands = [ip, ifconfig, ping, traceroute, dig, nslookup, host, nc];
