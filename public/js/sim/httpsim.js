// HTTP simulator: turns a request into a response using a webapp definition (content/webapps/*.json).
// curl, nc (raw HTTP), the browser and the proxy all go through httpRequest().
//
// Two kinds of webapp:
//  - static (default): `routes` is a map of path -> fixed response (what chapters 2-3 used).
//  - dynamic (`"engine": "<name>"`): logic lives in public/js/webapps/<name>.js and is looked up via the
//    registry in public/js/webapps/index.js. Handlers run real code (DB queries, cookies, sessions) but never
//    execute anything the player submits as script — payloads are only ever compared as text. See webapps/index.js.
import { getEngine } from '../webapps/index.js';

export const REASONS = {
  200: 'OK', 201: 'Created', 204: 'No Content', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
  500: 'Internal Server Error', 503: 'Service Unavailable',
};

export function parseUrl(raw) {
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`); } catch { return null; }
  if (!['http:', 'https:'].includes(u.protocol)) return null;
  return {
    scheme: u.protocol.slice(0, -1), host: u.hostname, port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
    path: u.pathname || '/', query: u.search.slice(1), hostHeader: u.host,
  };
}

const byteLength = (s) => new TextEncoder().encode(s).length;

/** Parse a Cookie header into {name: value}. Dynamic apps use this to find their session. */
export function parseCookies(header) {
  const out = {};
  for (const part of (header || '').split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/** Parse `a=1&b=2` (a query string or an application/x-www-form-urlencoded body) into {a:'1', b:'2'}. */
export function parseForm(text) {
  const out = {};
  for (const part of (text || '').split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const key = decodeURIComponent((i < 0 ? part : part.slice(0, i)).replace(/\+/g, ' '));
    out[key] = i < 0 ? '' : decodeURIComponent(part.slice(i + 1).replace(/\+/g, ' '));
  }
  return out;
}

/** Escape text for safe placement inside HTML (what a non-vulnerable app would call on every output). */
export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function ruleMatches(when = {}, req) {
  if (when.method && ![].concat(when.method).includes(req.method)) return false;
  if (when.body && !new RegExp(when.body).test(req.body || '')) return false;
  if (when.query && !new RegExp(when.query).test(req.query || '')) return false;
  if (when.cookie && !new RegExp(when.cookie).test(req.headers.cookie || '')) return false;
  for (const [name, re] of Object.entries(when.header || {})) {
    if (!new RegExp(re).test(req.headers[name.toLowerCase()] || '')) return false;
  }
  return true;
}

/**
 * Build a response object. Exported so webapp handlers (dynamic apps) can use the same shape.
 * A header value may be an array (e.g. `'Set-Cookie': ['a=1', 'b=2']`) to emit it as two separate
 * header lines, matching how a real server sends multiple cookies in one response.
 */
export function build(app, status, { headers = {}, body = '', type = 'text/html; charset=UTF-8' } = {}, req) {
  const list = [['Date', new Date().toUTCString()], ['Server', app.server || 'nginx']];
  if (app.poweredBy) list.push(['X-Powered-By', app.poweredBy]);
  for (const [k, v] of Object.entries(headers)) {
    if (Array.isArray(v)) v.forEach((vv) => list.push([k, vv]));
    else list.push([k, v]);
  }
  const sendBody = req.method === 'HEAD' ? '' : body;
  list.push(['Content-Length', String(byteLength(body))], ['Content-Type', type]);
  return { status, reason: REASONS[status] || '', headers: list, body: sendBody };
}

const notFoundBody = (path) => `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head><title>404 Not Found</title></head><body>\n<h1>Not Found</h1>\n<p>The requested URL ${path} was not found on this server.</p>\n</body></html>\n`;

function respondStatic(app, req) {
  let route = app.routes?.[req.path];
  if (!route && !req.path.endsWith('/') && app.routes?.[`${req.path}/`]) {
    return build(app, 301, {
      headers: { Location: `http://${req.hostHeader}${req.path}/` },
      body: `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head><title>301 Moved Permanently</title></head><body>\n<h1>Moved Permanently</h1>\n<p>The document has moved <a href="http://${req.hostHeader}${req.path}/">here</a>.</p>\n</body></html>\n`,
    }, req);
  }
  if (!route) {
    const nf = app.notFound || {};
    return build(app, 404, { body: nf.body ?? notFoundBody(req.path), type: nf.type }, req);
  }
  if (route.methods && !route.methods.includes(req.method) && !(req.method === 'HEAD' && route.methods.includes('GET'))) {
    return build(app, 405, { headers: { Allow: route.methods.join(', ') }, body: '<h1>Method Not Allowed</h1>\n' }, req);
  }
  const r = route.responses ? route.responses.find((x) => ruleMatches(x.when, req)) || route.responses[route.responses.length - 1] : route;
  return build(app, r.status ?? 200, r, req);
}

/** `state` is the World's private, per-app mutable store (sessions, DB, stored comments, ...). Created lazily. */
function respondDynamic(app, req, world) {
  const engine = getEngine(app.engine);
  if (!engine) return build(app, 500, { body: '<h1>Internal Server Error</h1>\n' }, req);
  const state = world.appState(app.id, () => engine.init(app, world));
  req = { ...req, cookies: parseCookies(req.headers.cookie), query: Object.freeze(parseForm(req.query)) };
  try {
    const res = engine.handle(app, req, state, world);
    return res instanceof Promise ? res : res; // handlers are synchronous; kept simple on purpose
  } catch (e) {
    return build(app, 500, { body: `<h1>Internal Server Error</h1>\n<!-- ${e.message.replace(/[<>]/g, '')} -->\n` }, req);
  }
}

function respond(app, req, world) {
  return app.engine ? respondDynamic(app, req, world) : respondStatic(app, req);
}

/**
 * @param world  World instance
 * @param req    { scheme, host, port, method, path, query, headers (lower-case keys), body, hostHeader }
 * @param selfIp IP of the machine the request originates from ("localhost" maps to it)
 * @returns { ok:true, ip, response } | { ok:false, code, message }  (code = curl exit code)
 */
export function httpRequest(world, req, selfIp) {
  const resolved = world.resolve(req.host);
  if (!resolved) return { ok: false, code: 6, message: `Could not resolve host: ${req.host}` };
  const ip = resolved.ip === '127.0.0.1' ? selfIp : resolved.ip;
  const refused = { ok: false, code: 7, message: `Failed to connect to ${req.host} port ${req.port} after 1 ms: Connection refused`, ip };
  if (ip === selfIp && !world.host(ip)) return refused; // our own machine has no services in the lab world
  const state = world.portState(ip, req.port);
  if (state === 'filtered') return { ok: false, code: 28, message: `Failed to connect to ${req.host} port ${req.port} after 5001 ms: Connection timed out`, ip };
  if (state === 'closed') return refused;
  const svc = world.service(ip, req.port);
  if (!svc.http) return { ok: false, code: 1, message: 'Received HTTP/0.9 when not allowed', ip };
  const app = world.webapps[svc.http];
  if (!app) return { ok: false, code: 52, message: 'Empty reply from server', ip };
  return { ok: true, ip, response: respond(app, req, world) };
}
