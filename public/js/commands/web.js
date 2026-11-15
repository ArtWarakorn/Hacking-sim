// curl against the simulated HTTP world.
import { parseUrl, httpRequest } from '../sim/httpsim.js';
import { FsError, normalize } from '../sim/vfs.js';

const SHORT_WITH_VALUE = new Set(['X', 'd', 'H', 'A', 'b', 'o', 'u', 'e', 'U']); // U = --data-urlencode (no real short form)
const LONG = {
  include: 'i', head: 'I', silent: 's', verbose: 'v', location: 'L', insecure: 'k', 'show-error': 'S', get: 'G',
  request: 'X', data: 'd', 'data-raw': 'd', 'data-urlencode': 'U', header: 'H', 'user-agent': 'A', cookie: 'b', output: 'o',
};

function parseCurlArgs(args) {
  const o = { flags: new Set(), headers: [], data: [], urls: [], method: null, agent: 'curl/7.88.1', cookie: null, output: null, errors: [] };
  const take = (key, val) => {
    if (key === 'X') o.method = val.toUpperCase();
    else if (key === 'd') o.data.push(val);
    else if (key === 'U') { const eq = val.indexOf('='); o.data.push(eq < 0 ? encodeURIComponent(val) : `${val.slice(0, eq)}=${encodeURIComponent(val.slice(eq + 1))}`); }
    else if (key === 'H') o.headers.push(val);
    else if (key === 'A') o.agent = val;
    else if (key === 'b') o.cookie = val;
    else if (key === 'o') o.output = val;
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--') && a.length > 2) {
      const [nameRaw, inline] = a.slice(2).split(/=(.*)/s);
      const key = LONG[nameRaw];
      if (!key) { o.errors.push(`option --${nameRaw}: is unknown`); continue; }
      if (SHORT_WITH_VALUE.has(key)) {
        const val = inline ?? args[++i];
        if (val === undefined) { o.errors.push(`option --${nameRaw}: requires parameter`); continue; }
        take(key, val);
      } else o.flags.add(key);
    } else if (a.length > 1 && a[0] === '-') {
      for (let j = 1; j < a.length; j++) {
        const c = a[j];
        if (SHORT_WITH_VALUE.has(c)) {
          const tail = a.slice(j + 1);
          const val = tail || args[++i];
          if (val === undefined) { o.errors.push(`option -${c}: requires parameter`); break; }
          take(c, val);
          break;
        } else o.flags.add(c);
      }
    } else o.urls.push(a);
  }
  return o;
}

const curl = {
  name: 'curl',
  async run(ctx, args) {
    const o = parseCurlArgs(args);
    if (o.errors.length) return { out: '', err: `curl: ${o.errors[0]}\ncurl: try 'curl --help' for more information\n`, code: 2 };
    if (!o.urls.length) return { out: '', err: "curl: no URL specified\ncurl: try 'curl --help' or 'curl --manual' for more information\n", code: 2 };
    const world = ctx.session.world;
    if (!world) return { out: '', err: 'curl: (6) Could not resolve host: network unreachable\n', code: 6 };

    const verbose = o.flags.has('v');
    const showHeaders = o.flags.has('i') || o.flags.has('I');
    const silent = o.flags.has('s') && !o.flags.has('S');
    const headers = { 'user-agent': o.agent, accept: '*/*' };
    for (const h of o.headers) { const i = h.indexOf(':'); if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim(); }
    if (o.cookie) headers.cookie = o.cookie;
    const getMode = o.flags.has('G'); // -G / --get: send -d data as a query string instead of a POST body
    let body = '';
    if (o.data.length && !getMode) {
      body = o.data.join('&');
      if (!headers['content-type']) headers['content-type'] = 'application/x-www-form-urlencoded';
    }
    let method = o.method || (o.flags.has('I') ? 'HEAD' : (!getMode && o.data.length) ? 'POST' : 'GET');

    let out = ''; let err = ''; let code = 0;
    const self = ctx.session.machine.ip;

    for (const rawUrl of o.urls) {
      let url = rawUrl;
      if (getMode && o.data.length) url += (url.includes('?') ? '&' : '?') + o.data.join('&');
      let redirects = 0;
      for (;;) {
        const u = parseUrl(url);
        if (!u) { err += `curl: (3) URL using bad/illegal format or missing URL\n`; code = 3; break; }
        const req = { ...u, method, headers: { host: u.hostHeader, ...headers }, body };
        const res = httpRequest(world, req, self);
        ctx.bus?.emit('net', { kind: 'http', ip: res.ip ?? null, port: u.port, session: ctx.session });

        if (verbose) {
          err += `* Trying ${res.ip ?? u.host}:${u.port}...\n`;
          if (res.ok) err += `* Connected to ${u.host} (${res.ip}) port ${u.port} (#0)\n`;
          err += `> ${method} ${u.path}${u.query ? `?${u.query}` : ''} HTTP/1.1\n> Host: ${u.hostHeader}\n> User-Agent: ${o.agent}\n> Accept: */*\n`;
          for (const [k, v] of Object.entries(headers)) if (!['user-agent', 'accept'].includes(k)) err += `> ${k}: ${v}\n`;
          err += '>\n';
        }
        if (!res.ok) {
          if (!silent) err += `curl: (${res.code}) ${res.message}\n`;
          code = res.code;
          break;
        }
        const r = res.response;
        ctx.bus?.emit('http', {
          session: ctx.session, host: u.host, ip: res.ip, port: u.port, method, path: u.path, query: u.query, status: r.status,
          full: true, source: 'curl', reqHeaders: req.headers, reqBody: body, resHeaders: r.headers, resBody: r.body,
        });
        const head = `HTTP/1.1 ${r.status} ${r.reason}\n${r.headers.map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n`;
        if (verbose) err += `< HTTP/1.1 ${r.status} ${r.reason}\n${r.headers.map(([k, v]) => `< ${k}: ${v}`).join('\n')}\n<\n`;
        if (showHeaders) out += head;

        const location = r.headers.find(([k]) => k.toLowerCase() === 'location')?.[1];
        if (o.flags.has('L') && location && [301, 302, 303, 307, 308].includes(r.status) && redirects < 10) {
          redirects++;
          url = new URL(location, `${u.scheme}://${u.hostHeader}${u.path}`).href;
          if ([301, 302, 303].includes(r.status)) { method = 'GET'; body = ''; delete headers['content-type']; }
          continue;
        }
        if (o.output) {
          try { ctx.vfs.writeFile(normalize(o.output, ctx.session.cwd), r.body, ctx.user); }
          catch (e) {
            if (!(e instanceof FsError)) throw e;
            err += `curl: (23) Failure writing output to destination (${e.msg})\n`; code = 23;
          }
        } else out += r.body;
        break;
      }
    }
    return { out, err, code };
  },
};

export const webCommands = [curl];
