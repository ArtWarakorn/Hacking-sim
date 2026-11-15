// Network simulator: IPv4 helpers + a "World" of fictional hosts, services and DNS zones.
// Nothing here touches the real network — every packet is answered from JSON.

export const isIPv4 = (s) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255);
export const ipToInt = (ip) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
export const intToIp = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');
const maskInt = (prefix) => (prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0);
export const maskString = (prefix) => intToIp(maskInt(prefix));
export const networkAddress = (ip, prefix) => intToIp((ipToInt(ip) & maskInt(prefix)) >>> 0);
export const broadcastAddress = (ip, prefix) => intToIp(((ipToInt(ip) & maskInt(prefix)) | (~maskInt(prefix) >>> 0)) >>> 0);
export function cidrContains(cidr, ip) {
  const [base, p] = cidr.split('/');
  return networkAddress(base, Number(p)) === networkAddress(ip, Number(p));
}

/** Is `ip` covered by a scope list of IPs and/or CIDRs? */
export const inScope = (ip, list) => list.some((e) => (e.includes('/') ? cidrContains(e, ip) : e === ip));

/**
 * Expand an nmap-style target: IP, hostname, CIDR (/22 or smaller), or last-octet range (10.10.20.5-7).
 * -> { ips: [...] } or { error }
 */
export function expandTarget(spec, world) {
  let m;
  if ((m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(spec))) {
    const prefix = Number(m[2]);
    if (!isIPv4(m[1]) || prefix > 32) return { error: `Failed to resolve "${spec}".` };
    if (prefix < 22) return { error: `target ${spec} is too large for this simulator (maximum /22 = 1024 addresses)` };
    const start = ipToInt(networkAddress(m[1], prefix));
    const count = 2 ** (32 - prefix);
    return { ips: Array.from({ length: count }, (_, i) => intToIp(start + i)) };
  }
  if ((m = /^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/.exec(spec))) {
    const [a, b] = [Number(m[2]), Number(m[3])];
    if (a > b || b > 255) return { error: `Failed to resolve "${spec}".` };
    return { ips: Array.from({ length: b - a + 1 }, (_, i) => `${m[1]}${a + i}`) };
  }
  if (isIPv4(spec)) return { ips: [spec] };
  const r = world.resolve(spec);
  return r ? { ips: [r.ip], name: r.name } : { error: `Failed to resolve "${spec}".` };
}

/** Roughly nmap's most common ports. A default scan only looks at these ("top 1000"); `-p-` looks at everything. */
export const TOP_PORTS = [
  80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025, 587, 8888,
  199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001,
  515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
  513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 9100, 5550, 3128, 5432, 3000, 8090, 6379, 27017,
  161, 69, 119, 37, 49, 70, 42, 3260, 1521, 4443, 7070, 9090, 2222, 5985, 5986,
];

export const PORT_NAMES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3', 139: 'netbios-ssn',
  143: 'imap', 443: 'https', 445: 'microsoft-ds', 3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql', 8080: 'http-alt',
};

/** Ids of every webapp referenced by a network definition (so loaders know what to fetch). */
export const webappIds = (def) => [...new Set(Object.values(def.hosts || {}).flatMap((h) => Object.values(h.services || {}).map((s) => s.http).filter(Boolean)))];

const hash = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; };

export class World {
  constructor(def = {}, webapps = {}) {
    this.def = def;
    // Deep-cloned: content loaders cache the parsed network JSON, so without this every mission built from
    // the same cached def would share (and corrupt) the same live host objects - this matters once anything
    // mutates host state at runtime, e.g. a backdoor that "opens" a port after being triggered.
    this.hosts = new Map(Object.entries(JSON.parse(JSON.stringify(def.hosts || {}))));
    this.zones = def.dns || {};
    this.webapps = webapps;
    this.resolver = def.resolver || '10.10.14.1';
    this._appState = new Map();
    // port -> { ip: attacker's real IP (who must be the one receiving the connection), stack: the
    // SessionStack `nc -l` was run from. A listener is consumed (removed) by the first connection it
    // accepts, exactly like real `nc -l` without `-k`.
    this.listeners = new Map();
    // ip -> runtime (see sim/session.js createRuntime), for hosts a player might land a real interactive
    // shell on during a mission (an exploited backdoor, a reverse shell, a pivot). Populated at mission
    // setup time from `mission.reachableMachines`; most hosts in the world never need one.
    this.machines = new Map();
  }

  setMachine(ip, runtime) { this.machines.set(ip, runtime); }
  machineFor(ip) { return this.machines.get(ip) || null; }

  listen(port, ip, stack) {
    if (this.listeners.has(port)) return false;
    this.listeners.set(port, { ip, stack });
    return true;
  }

  unlisten(port) { this.listeners.delete(port); }

  /** A reverse shell calling back to attackerIp:port. Pushes `session` onto the waiting stack if one matches. */
  acceptReverseShell(port, attackerIp, session) {
    const l = this.listeners.get(port);
    if (!l || l.ip !== attackerIp) return false;
    this.listeners.delete(port);
    l.stack.push(session);
    return true;
  }

  /**
   * Private mutable store for one dynamic webapp (sessions, a Database instance, stored comments, ...).
   * Created on first use via `init()` and kept for the lifetime of this World (one per mission/sandbox run).
   */
  appState(appId, init = () => ({})) {
    if (!this._appState.has(appId)) this._appState.set(appId, init());
    return this._appState.get(appId);
  }

  host(ip) { return this.hosts.get(ip) || null; }
  isUp(ip) { const h = this.host(ip); return Boolean(h && h.up !== false); }
  /** Answers ICMP/discovery probes. A `stealth` host is alive but silently drops everything it doesn't serve. */
  pingable(ip) { const h = this.host(ip); return Boolean(h && h.up !== false && !h.stealth); }
  /** 'open' | 'closed' (RST) | 'filtered' (no reply). Unknown or dead hosts never answer. */
  portState(ip, port) {
    const h = this.host(ip);
    if (!h || h.up === false) return 'filtered';
    const svc = h.services?.[String(port)];
    if (svc) return svc.state === 'filtered' ? 'filtered' : 'open';
    return h.stealth || h.firewall === 'drop' ? 'filtered' : 'closed';
  }
  whois(name) {
    const lc = name.toLowerCase();
    let best = null;
    for (const [d, text] of Object.entries(this.def.whois || {})) if ((lc === d || lc.endsWith(`.${d}`)) && (!best || d.length > best.d.length)) best = { d, text };
    return best?.text ?? null;
  }
  /** Names from public sources (certificate transparency etc.) — may include names that are not in DNS. */
  ctNames(domain) { return this.def.ct_logs?.[domain] || []; }
  service(ip, port) { return this.host(ip)?.services?.[String(port)] || null; }
  hostnameOf(ip) { return this.host(ip)?.hostname || null; }

  /** Find the zone that owns an FQDN -> { domain, zone, label } */
  zoneFor(fqdn) {
    const name = fqdn.toLowerCase().replace(/\.$/, '');
    let best = null;
    for (const [domain, zone] of Object.entries(this.zones)) {
      if ((name === domain || name.endsWith(`.${domain}`)) && (!best || domain.length > best.domain.length)) {
        best = { domain, zone, label: name === domain ? '@' : name.slice(0, -domain.length - 1) };
      }
    }
    return best;
  }

  /** DNS records for a name: [{ name, ttl, type, value }]. Follows one CNAME for A queries. */
  records(fqdn, type) {
    const z = this.zoneFor(fqdn);
    if (!z) return [];
    const fq = (label) => (label === '@' ? z.domain : `${label}.${z.domain}`);
    const rows = z.zone.records.filter((r) => r.name === z.label).map((r) => ({ name: fq(r.name), ttl: r.ttl ?? z.zone.ttl ?? 300, type: r.type, value: r.value }));
    if (type === 'ANY') return rows;
    const direct = rows.filter((r) => r.type === type);
    if (!direct.length && type === 'A') {
      const cname = rows.find((r) => r.type === 'CNAME');
      if (cname) return [cname, ...this.records(cname.value, 'A')];
    }
    return direct;
  }

  nameExists(fqdn) { const z = this.zoneFor(fqdn); return Boolean(z && z.zone.records.some((r) => r.name === z.label)); }

  /** Resolve a hostname or IP to { ip, name }. null when unknown. */
  resolve(target) {
    if (isIPv4(target)) return { ip: target, name: null };
    if (target === 'localhost') return { ip: '127.0.0.1', name: 'localhost' };
    const a = this.records(target, 'A').find((r) => r.type === 'A');
    if (a) return { ip: a.value, name: target.toLowerCase().replace(/\.$/, '') };
    for (const [ip, h] of this.hosts) if (h.hostname === target.toLowerCase()) return { ip, name: h.hostname };
    return null;
  }

  rtt(ip, seq) {
    const hops = this.host(ip)?.hops?.length ?? 0;
    return 0.25 + hops * 0.45 + (hash(`${ip}/${seq}`) % 700) / 1000;
  }
}
