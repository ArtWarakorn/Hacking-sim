// Recon tools: whois, subfinder, nmap, gobuster, nikto, whatweb — all answered from the simulated World.
import { FsError, normalize } from '../sim/vfs.js';
import { expandTarget, isIPv4, PORT_NAMES, TOP_PORTS } from '../sim/network.js';
import { httpRequest, parseUrl } from '../sim/httpsim.js';

const ok = (out = '') => ({ out, err: '', code: 0 });
const fail = (err, code = 1) => ({ out: '', err, code });
const noNet = (cmd) => fail(`${cmd}: network is unreachable\n`, 1);
const emitNet = (ctx, kind, ip, extra = {}) => ctx.bus?.emit('net', { kind, ip, session: ctx.session, ...extra });
const stamp = () => new Date().toISOString().replace('T', ' ').slice(0, 16);

// ---------- whois ----------
const whois = {
  name: 'whois',
  async run(ctx, args) {
    const target = args.find((a) => !a.startsWith('-'));
    if (!target) return fail("Usage: whois [OPTION]... OBJECT...\nTry 'whois --help' for more information.\n", 64);
    const world = ctx.session.world;
    if (!world) return noNet('whois');
    const text = world.whois(target);
    if (text) return ok(`${text}\n`);
    if (isIPv4(target) && target.startsWith('10.10.20.')) return ok('NetRange:       10.10.20.0 - 10.10.20.255\nCIDR:           10.10.20.0/24\nOrgName:        ACME Logistics Co., Ltd.\nCountry:        TH\n');
    return ok(`No match for "${target.toUpperCase()}".\n\n>>> Last update of whois database: ${new Date().toISOString().slice(0, 19)}Z <<<\n`);
  },
};

// ---------- subfinder ----------
const BANNER = `
               __    _____           __
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \\/ /_/ / __ \\/ __  / _ \\/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /
/____/\\__,_/_.___/_/ /_/_/ /_/\\__,_/\\___/_/
                                           v2.6.3

\t\tprojectdiscovery.io

`;

const subfinder = {
  name: 'subfinder',
  async run(ctx, args) {
    let domain = null; let silent = false;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-d' || args[i] === '-domain') domain = args[++i];
      else if (args[i] === '-silent') silent = true;
    }
    if (!domain) return { out: '', err: '[FTL] Program exiting: no input list provided\n', code: 1 };
    const world = ctx.session.world;
    if (!world) return noNet('subfinder');
    emitNet(ctx, 'dns', world.resolver, { name: domain, type: 'subdomains' });
    const z = world.zoneFor(domain);
    const names = new Set(world.ctNames(domain));
    if (z) for (const r of z.zone.records) if (r.name !== '@' && ['A', 'CNAME'].includes(r.type)) names.add(`${r.name}.${z.domain}`);
    const list = [...names].sort();
    if (silent) return ok(list.length ? `${list.join('\n')}\n` : '');
    return {
      out: `${list.join('\n')}${list.length ? '\n' : ''}`,
      err: `${BANNER}[INF] Current subfinder version v2.6.3 (latest)\n[INF] Loading provider config from /home/${ctx.user.name}/.config/subfinder/provider-config.yaml\n[INF] Enumerating subdomains for ${domain}\n[INF] Found ${list.length} subdomains for ${domain} in 8 seconds 482 milliseconds\n`,
      code: 0,
    };
  },
};

// ---------- nmap ----------
function parsePortSpec(spec) {
  if (spec === '-') return { all: true };
  const set = new Set();
  for (const part of spec.split(',')) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) return null;
    const a = Number(m[1]); const b = Number(m[2] ?? m[1]);
    if (a < 1 || b > 65535 || a > b) return null;
    for (let p = a; p <= b; p++) set.add(p);
  }
  return { set };
}

function parseNmapArgs(args) {
  const o = { sn: false, sT: false, sV: false, sC: false, O: false, A: false, Pn: false, n: false, open: false, scan: null, targets: [], outFile: null, errors: [] };
  const top = new Set(TOP_PORTS);
  o.scan = { has: (p) => top.has(p), total: 1000 };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let m;
    if (a === '-sn') o.sn = true;
    else if (/^-s[STVCUn]+$/.test(a) && a !== '-sn') {
      for (const c of a.slice(2)) { if (c === 'T') o.sT = true; else if (c === 'V') o.sV = true; else if (c === 'C') o.sC = true; else if (c === 'n') o.sn = true; }
    } else if (a === '-O') o.O = true;
    else if (a === '-A') { o.A = true; o.sV = true; o.sC = true; o.O = true; }
    else if (a === '-Pn') o.Pn = true;
    else if (a === '-n') o.n = true;
    else if (a === '--open') o.open = true;
    else if (a === '-F') o.scan = { has: (p) => TOP_PORTS.slice(0, 100).includes(p), total: 100 };
    else if (/^-T\d$/.test(a) || /^-v+$/.test(a) || a === '-d' || a === '--reason') { /* timing/verbosity: no effect here */ }
    else if (/^--script(=.*)?$/.test(a)) { o.sC = true; if (a === '--script') i++; }
    else if (a === '-p' || /^-p.+/.test(a)) {
      const spec = a === '-p' ? args[++i] : a.slice(2);
      const parsed = spec === undefined ? null : parsePortSpec(spec);
      if (!parsed) { o.errors.push('Your port specifications are illegal.  Example of proper form: "-100,200-1024,T:3000-4000,U:60000-"'); continue; }
      o.scan = parsed.all ? { has: () => true, total: 65535 } : { has: (p) => parsed.set.has(p), total: parsed.set.size };
    } else if ((m = /^--top-ports(?:=(\d+))?$/.exec(a))) {
      const n = Number(m[1] ?? args[++i]);
      if (!(n >= 1)) { o.errors.push('--top-ports needs a number'); continue; }
      const topN = new Set(TOP_PORTS.slice(0, n));
      o.scan = { has: (p) => topN.has(p), total: n };
    } else if (a === '-oN') o.outFile = args[++i];
    else if (a.startsWith('-')) o.errors.push(`Unrecognized option: ${a}`);
    else o.targets.push(a);
  }
  return o;
}

const rttSec = (world, ip) => (world.rtt(ip, 1) / 1000).toFixed(4);

function scriptBlock(scripts) {
  const lines = [];
  for (const [name, val] of Object.entries(scripts || {})) {
    const parts = String(val).split('\n');
    if (parts.length === 1) lines.push(`${name}: ${parts[0]}`);
    else { lines.push(`${name}:`); for (const p of parts) lines.push(`  ${p}`); }
  }
  return lines.map((t, i) => (i === lines.length - 1 ? `|_${t}` : `| ${t}`));
}

function scanHost(world, ip, label, host, o) {
  const lines = [`Nmap scan report for ${label}`, `Host is up (${rttSec(world, ip)}s latency).`];
  if (o.sn) return `${lines.join('\n')}\n`;

  const listed = Object.entries(host?.services || {})
    .map(([p, s]) => ({ port: Number(p), svc: s, state: s.state === 'filtered' ? 'filtered' : 'open' }))
    .filter((x) => o.scan.has(x.port))
    .sort((a, b) => a.port - b.port);
  const shown = o.open ? listed.filter((x) => x.state === 'open') : listed;
  const ignored = o.scan.total - listed.length;
  const hidden = !host || host.stealth || host.firewall === 'drop' ? 'filtered' : 'closed';

  if (!shown.length) {
    if (hidden === 'closed') lines.push(`All ${o.scan.total} scanned ports on ${label} are closed`);
    else lines.push(`All ${o.scan.total} scanned ports on ${label} are in ignored states.`, `Not shown: ${ignored} filtered tcp ports (no-response)`);
  } else {
    if (ignored > 0) lines.push(hidden === 'closed' ? `Not shown: ${ignored} closed tcp ports (${o.sT ? 'conn-refused' : 'reset'})` : `Not shown: ${ignored} filtered tcp ports (no-response)`);
    const rows = shown.map((x) => {
      const svcName = x.svc.name || PORT_NAMES[x.port] || 'unknown';
      let version = '';
      if (o.sV && x.svc.product) version = `${x.svc.product}${x.svc.version ? ` ${x.svc.version}` : ''}${x.svc.extrainfo ? ` (${x.svc.extrainfo})` : ''}`;
      return { port: `${x.port}/tcp`, state: x.state, svc: svcName, version, scripts: o.sC && x.state === 'open' ? scriptBlock(x.svc.scripts) : [] };
    });
    const w1 = Math.max(4, ...rows.map((r) => r.port.length));
    const w2 = Math.max(5, ...rows.map((r) => r.state.length));
    const w3 = Math.max(7, ...rows.map((r) => r.svc.length));
    lines.push(`${'PORT'.padEnd(w1)} ${'STATE'.padEnd(w2)} ${'SERVICE'.padEnd(w3)}${o.sV ? ' VERSION' : ''}`.trimEnd());
    for (const r of rows) {
      lines.push(`${r.port.padEnd(w1)} ${r.state.padEnd(w2)} ${r.svc.padEnd(w3)}${o.sV ? ` ${r.version}` : ''}`.trimEnd());
      lines.push(...r.scripts);
    }
    if (o.sV && host?.serviceInfo) lines.push(`Service Info: ${host.serviceInfo}`);
  }
  if (o.O) {
    if (host?.os && hidden === 'closed') {
      lines.push(`Device type: ${host.os.type}`, `Running: ${host.os.running}`, `OS CPE: ${host.os.cpe}`, `OS details: ${host.os.details}`, `Network Distance: ${(host.hops?.length ?? 0) + 1} hops`);
    } else lines.push('No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).');
  }
  if (o.A && host?.hops) {
    const hopIps = [...host.hops, ip];
    lines.push('', 'TRACEROUTE (using port 80/tcp)', 'HOP RTT      ADDRESS');
    hopIps.forEach((h, i) => lines.push(`${String(i + 1).padEnd(3)} ${`${(world.rtt(h, 1) + i * 0.3).toFixed(2)} ms`.padEnd(8)} ${world.hostnameOf(h) ? `${world.hostnameOf(h)} (${h})` : h}`));
  }
  return `${lines.join('\n')}\n`;
}

const nmap = {
  name: 'nmap',
  async run(ctx, args) {
    const o = parseNmapArgs(args);
    if (o.errors.length) return fail(`${o.errors[0]}\nQUITTING!\n`, 1);
    if (!o.targets.length) return fail('Nmap 7.94 ( https://nmap.org )\nUsage: nmap [Scan Type(s)] [Options] {target specification}\nTARGET SPECIFICATION:\n  Can pass hostnames, IP addresses, networks, etc.\n  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254\nWARNING: No targets were specified, so 0 hosts scanned.\n', 1);
    const world = ctx.session.world;
    if (!world) return noNet('nmap');

    const self = ctx.session.machine.ip;
    const ips = []; let err = '';
    for (const t of o.targets) {
      const r = expandTarget(t, world);
      if (r.error) { err += `${r.error}\n`; continue; }
      for (const ip of r.ips) if (!ips.some((x) => x.ip === ip)) ips.push({ ip, name: r.name });
    }
    let out = `Starting Nmap 7.94 ( https://nmap.org ) at ${stamp()} UTC\n`;
    if (!ips.length) {
      return { out: `${out}WARNING: No targets were specified, so 0 hosts scanned.\nNmap done: 0 IP addresses (0 hosts up) scanned in 0.05 seconds\n`, err, code: 1 };
    }

    let up = 0;
    for (const { ip, name } of ips) {
      const host = world.host(ip);
      if (host) emitNet(ctx, 'scan', ip); // only hosts that really exist can be "touched" (and thus be out of scope)
      const exists = Boolean(host) && host.up !== false;
      const discovered = o.Pn ? true : exists && !host.stealth;
      if (!discovered) continue;
      up++;
      const ownName = o.n ? null : name || world.hostnameOf(ip);
      const label = ownName ? `${ownName} (${ip})` : ip;
      if (!exists) {
        // -Pn on an address nothing answers on: everything is filtered
        out += `Nmap scan report for ${label}\nHost is up.\nAll ${o.scan.total} scanned ports on ${label} are in ignored states.\nNot shown: ${o.scan.total} filtered tcp ports (no-response)\n\n`;
        continue;
      }
      out += `${scanHost(world, ip, label, host, o)}\n`;
    }
    if (up === 0 && ips.length === 1) out += 'Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn\n';
    const secs = (1.1 + up * 1.4 + (o.sV ? 5.2 : 0) + (o.O ? 3.1 : 0) + (o.scan.total > 5000 ? 8.7 : 0) + (ips.length > 16 ? 2.4 : 0)).toFixed(2);
    out += `${o.sV || o.O ? `${o.O ? 'OS and ' : ''}Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n` : ''}Nmap done: ${ips.length} IP address${ips.length === 1 ? '' : 'es'} (${up} host${up === 1 ? '' : 's'} up) scanned in ${secs} seconds\n`;

    if (o.outFile) {
      try { ctx.vfs.writeFile(normalize(o.outFile, ctx.session.cwd), out, ctx.user); }
      catch (e) { if (!(e instanceof FsError)) throw e; err += `Failed to open normal output file ${o.outFile} for writing: ${e.msg}\n`; }
    }
    return { out, err, code: 0 };
  },
};

// ---------- gobuster ----------
const gobuster = {
  name: 'gobuster',
  async run(ctx, args) {
    const mode = args[0];
    if (!mode || mode.startsWith('-')) return fail('Usage:\n  gobuster [command]\n\nAvailable Commands:\n  dir         Uses directory/file enumeration mode\n  dns         Uses DNS subdomain enumeration mode\n  vhost       Uses VHOST enumeration mode\n', 1);
    if (mode !== 'dir') return fail(`[!] gobuster ${mode} is not supported in this simulator (use: gobuster dir)\n`, 1);
    const o = { u: null, w: null, x: [], t: '10', q: false, b: '404' };
    for (let i = 1; i < args.length; i++) {
      const a = args[i];
      if (a === '-u' || a === '--url') o.u = args[++i];
      else if (a === '-w' || a === '--wordlist') o.w = args[++i];
      else if (a === '-x' || a === '--extensions') o.x = (args[++i] || '').split(',').filter(Boolean).map((e) => e.replace(/^\./, ''));
      else if (a === '-t' || a === '--threads') o.t = args[++i];
      else if (a === '-b' || a === '--status-codes-blacklist') o.b = args[++i];
      else if (a === '-q' || a === '--quiet') o.q = true;
    }
    if (!o.u) return fail('Error: required flag(s) "url" not set\n', 1);
    if (!o.w) return fail('Error: required flag(s) "wordlist" not set\n', 1);
    const world = ctx.session.world;
    if (!world) return noNet('gobuster');
    const u = parseUrl(o.u);
    if (!u) return fail(`[!] error on parsing arguments: invalid url ${o.u}\n`, 1);
    let words;
    try { words = ctx.vfs.readFile(normalize(o.w, ctx.session.cwd), ctx.user).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')); }
    catch (e) {
      if (!(e instanceof FsError)) throw e;
      return fail(`[!] error on parsing arguments: wordlist file "${o.w}" does not exist: stat ${o.w}: ${e.msg.toLowerCase()}\n`, 1);
    }
    const blacklist = new Set(o.b.split(',').map(Number));
    const self = ctx.session.machine.ip;
    const base = `${u.scheme}://${u.hostHeader}`;
    const probe = httpRequest(world, { ...u, method: 'GET', path: '/', headers: { host: u.hostHeader }, body: '' }, self);
    emitNet(ctx, 'http', probe.ip ?? null, { port: u.port });
    if (!probe.ok) return { out: '', err: `[ERROR] error on running gobuster: unable to connect to ${base}/: Get "${base}/": ${probe.message.includes('refused') ? `dial tcp ${u.host}:${u.port}: connect: connection refused` : 'context deadline exceeded (Client.Timeout exceeded while awaiting headers)'}\n`, code: 1 };

    const candidates = words.flatMap((w) => [w, ...o.x.map((e) => `${w}.${e}`)]);
    let out = '';
    if (!o.q) {
      out += '===============================================================\nGobuster v3.6\nby OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n===============================================================\n'
        + `[+] Url:                     ${base}\n[+] Method:                  GET\n[+] Threads:                 ${o.t}\n[+] Wordlist:                ${o.w}\n`
        + `[+] Negative Status codes:   ${o.b}\n[+] User Agent:              gobuster/3.6\n${o.x.length ? `[+] Extensions:              ${o.x.join(',')}\n` : ''}[+] Timeout:                 10s\n`
        + '===============================================================\nStarting gobuster in directory enumeration mode\n===============================================================\n';
    }
    for (const w of candidates) {
      const path = `/${w}`;
      const res = httpRequest(world, { ...u, method: 'GET', path, query: '', headers: { host: u.hostHeader }, body: '' }, self);
      if (!res.ok) continue;
      const r = res.response;
      ctx.bus?.emit('http', { session: ctx.session, host: u.host, ip: res.ip, port: u.port, method: 'GET', path, query: '', status: r.status });
      if (blacklist.has(r.status)) continue;
      const loc = r.headers.find(([k]) => k.toLowerCase() === 'location')?.[1];
      const size = Number(r.headers.find(([k]) => k === 'Content-Length')?.[1] ?? 0);
      out += `${path.padEnd(21)} (Status: ${r.status}) [Size: ${size}]${loc ? ` [--> ${loc}]` : ''}\n`;
    }
    if (!o.q) out += '===============================================================\nFinished\n===============================================================\n';
    return ok(out);
  },
};

// ---------- nikto ----------
const nikto = {
  name: 'nikto',
  async run(ctx, args) {
    let target = null; let port = null;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '-h' || args[i] === '-host') target = args[++i];
      else if (args[i] === '-p' || args[i] === '-port') port = Number(args[++i]);
    }
    if (!target) return fail('- ERROR: No host specified\n', 1);
    const world = ctx.session.world;
    if (!world) return noNet('nikto');
    const u = parseUrl(/^https?:\/\//.test(target) ? target : `http://${target}`);
    if (!u) return fail('- ERROR: Invalid target\n', 1);
    if (port) u.port = port;
    const self = ctx.session.machine.ip;
    const res = httpRequest(world, { ...u, method: 'GET', path: '/', query: '', headers: { host: u.hostHeader }, body: '' }, self);
    emitNet(ctx, 'http', res.ip ?? null, { port: u.port });
    if (!res.ok) return { out: `- Nikto v2.5.0\n---------------------------------------------------------------------------\n+ ERROR: Cannot resolve or connect to ${u.host}:${u.port}\n`, err: '', code: 1 };
    const hdr = (n) => res.response.headers.find(([k]) => k.toLowerCase() === n)?.[1];
    const svc = world.service(res.ip, u.port);
    const app = world.webapps[svc?.http] || {};
    const findings = [`Server: ${hdr('server')}`];
    if (hdr('x-powered-by')) findings.push(`/: Retrieved x-powered-by header: ${hdr('x-powered-by')}.`);
    if (!hdr('x-frame-options')) findings.push('/: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options');
    if (!hdr('x-content-type-options')) findings.push('/: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/');
    findings.push("No CGI Directories found (use '-C all' to force check all possible dirs)");
    const robots = app.routes?.['/robots.txt']?.body;
    if (robots) {
      const n = (robots.match(/^Disallow:/gim) || []).length;
      if (n) findings.push(`/robots.txt: contains ${n} entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt`);
    }
    const ver = /Apache\/([\d.]+)/.exec(hdr('server') || '');
    if (ver && ver[1] < '2.4.54') findings.push(`Apache/${ver[1]} appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.`);
    findings.push(...(app.nikto || []));
    ctx.bus?.emit('game', { name: 'nikto.scan', host: u.host, findings: findings.length });
    return ok(`- Nikto v2.5.0\n---------------------------------------------------------------------------\n+ Target IP:          ${res.ip}\n+ Target Hostname:    ${u.host}\n+ Target Port:        ${u.port}\n+ Start Time:         ${stamp()}:00 (GMT0)\n---------------------------------------------------------------------------\n${findings.map((f) => `+ ${f}`).join('\n')}\n+ 8102 requests: 0 error(s) and ${findings.length - 1} item(s) reported on remote host\n+ End Time:           ${stamp()}:41 (GMT0) (41 seconds)\n---------------------------------------------------------------------------\n+ 1 host(s) tested\n`);
  },
};

// ---------- whatweb ----------
const whatweb = {
  name: 'whatweb',
  async run(ctx, args) {
    const targets = args.filter((a) => !a.startsWith('-'));
    if (!targets.length) return fail('WhatWeb - Next generation web scanner version 0.5.5.\nUsage: whatweb [options] <URLs>\n', 1);
    const world = ctx.session.world;
    if (!world) return noNet('whatweb');
    let out = ''; let err = '';
    for (const t of targets) {
      const u = parseUrl(/^https?:\/\//.test(t) ? t : `http://${t}`);
      const res = u && httpRequest(world, { ...u, method: 'GET', query: u.query, headers: { host: u.hostHeader }, body: '' }, ctx.session.machine.ip);
      emitNet(ctx, 'http', res?.ip ?? null, { port: u?.port });
      if (!res?.ok) { err += `ERROR Opening: ${/^https?:\/\//.test(t) ? t : `http://${t}`} - ${res?.message?.includes('refused') ? 'Connection refused' : 'execution expired'}\n`; continue; }
      const r = res.response;
      ctx.bus?.emit('http', { session: ctx.session, host: u.host, ip: res.ip, port: u.port, method: 'GET', path: u.path, query: u.query, status: r.status });
      const hdr = (n) => r.headers.find(([k]) => k.toLowerCase() === n)?.[1];
      const server = hdr('server');
      const plugins = new Map();
      const apache = /Apache\/([\d.]+)/.exec(server || '');
      if (apache) plugins.set('Apache', `Apache[${apache[1]}]`);
      plugins.set('Country', 'Country[RESERVED][ZZ]');
      if (server) plugins.set('HTTPServer', /\(Ubuntu\)/.test(server) ? `HTTPServer[Ubuntu Linux][${server}]` : `HTTPServer[${server}]`);
      plugins.set('IP', `IP[${res.ip}]`);
      const php = /PHP\/([\d.]+)/.exec(hdr('x-powered-by') || '');
      if (php) plugins.set('PHP', `PHP[${php[1]}]`);
      const title = /<title>(.*?)<\/title>/is.exec(r.body)?.[1];
      if (title) plugins.set('Title', `Title[${title}]`);
      if (hdr('x-powered-by')) plugins.set('X-Powered-By', `X-Powered-By[${hdr('x-powered-by')}]`);
      const loc = hdr('location');
      if (loc) plugins.set('RedirectLocation', `RedirectLocation[${loc}]`);
      for (const extra of world.webapps[world.service(res.ip, u.port)?.http]?.tech || []) plugins.set(extra, extra);
      const list = [...plugins.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, v]) => v);
      out += `${u.scheme}://${u.hostHeader}${u.path === '/' ? '' : u.path} [${r.status} ${r.reason}] ${list.join(', ')}\n`;
    }
    return { out, err, code: err && !out ? 1 : 0 };
  },
};

export const reconCommands = [whois, subfinder, nmap, gobuster, nikto, whatweb];
