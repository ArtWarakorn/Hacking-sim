'use strict';
// HackSim server — Node built-ins only (no npm install needed).
const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 3001;
const HOST = '127.0.0.1';
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONTENT_DIR = path.join(ROOT, 'content');
const DATA_DIR = process.env.HACKSIM_DATA_DIR || path.join(ROOT, 'data');
const PROGRESS_FILE = path.join(DATA_DIR, 'progress.json');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const DEFAULT_PROGRESS = () => ({
  profile: null,
  xp: 0,
  rank: 'Script Kiddie',
  completedMissions: {},
  lessonsDone: [],
  achievements: [],
  notesByMission: {},
  settings: { scanlines: true },
});

function send(res, status, body, type = 'application/json; charset=utf-8') {
  const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function loadProgress() {
  try {
    return JSON.parse(fs.readFileSync(PROGRESS_FILE, 'utf8'));
  } catch {
    return DEFAULT_PROGRESS();
  }
}

function saveProgress(obj) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = PROGRESS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
  fs.renameSync(tmp, PROGRESS_FILE); // atomic replace
}

async function handleApi(req, res, pathname) {
  try {
    if (pathname === '/api/progress' && req.method === 'GET') {
      return send(res, 200, loadProgress());
    }
    if (pathname === '/api/progress' && req.method === 'POST') {
      const data = JSON.parse(await readBody(req));
      if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new Error('invalid progress');
      saveProgress(data);
      return send(res, 200, { ok: true });
    }
    if (pathname === '/api/progress/reset' && req.method === 'POST') {
      saveProgress(DEFAULT_PROGRESS());
      return send(res, 200, { ok: true });
    }
    if (pathname === '/api/progress/export' && req.method === 'GET') {
      res.setHeader('Content-Disposition', 'attachment; filename="hacksim-progress.json"');
      return send(res, 200, loadProgress());
    }
    if (pathname === '/api/progress/import' && req.method === 'POST') {
      const data = JSON.parse(await readBody(req));
      if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new Error('invalid progress');
      saveProgress({ ...DEFAULT_PROGRESS(), ...data });
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'not found' });
  } catch (err) {
    return send(res, 400, { error: String(err.message || err) });
  }
}

function serveStatic(res, baseDir, relPath) {
  const filePath = path.normalize(path.join(baseDir, relPath));
  if (filePath !== baseDir && !filePath.startsWith(baseDir + path.sep)) {
    return send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
  }
  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    const type = MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    fs.readFile(filePath, (e, buf) => (e ? send(res, 500, 'Error', 'text/plain; charset=utf-8') : send(res, 200, buf, type)));
  });
}

const server = http.createServer((req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  } catch {
    return send(res, 400, 'Bad request', 'text/plain; charset=utf-8');
  }
  if (pathname.startsWith('/api/')) return handleApi(req, res, pathname);
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed', 'text/plain; charset=utf-8');
  if (pathname.startsWith('/content/')) return serveStatic(res, CONTENT_DIR, pathname.slice('/content/'.length));
  if (pathname === '/') pathname = '/index.html';
  return serveStatic(res, PUBLIC_DIR, pathname.slice(1));
});

server.listen(PORT, HOST, () => {
  console.log(`HackSim running at http://localhost:${PORT}`);
});
