// Usage: node tools/validate.mjs   (also run by `npm test`)
// Checks every JSON file under content/ for structure and cross-references.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { objectiveHash } from '../public/js/core/hash.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const content = path.join(root, 'content');
const OBJECTIVE_TYPES = new Set(['command', 'file_read', 'shell', 'privilege', 'answer', 'flag', 'http', 'fs', 'event', 'report']);
const EVENT_NAMES = new Set(['ftp.login', 'ftp.get', 'smb.connect', 'smb.get', 'enum4linux.run', 'nikto.scan']);
const DNS_TYPES = new Set(['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'PTR']);
const DIFFICULTIES = new Set(['tutorial', 'easy', 'medium', 'hard', 'insane']);

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else if (name.endsWith('.json')) yield p;
  }
}

export async function validate() {
  const errors = [];
  const err = (file, msg) => errors.push(`${path.relative(root, file)}: ${msg}`);
  const json = new Map();

  for (const f of walk(content)) {
    try { json.set(f, JSON.parse(readFileSync(f, 'utf8'))); } catch (e) { err(f, `invalid JSON — ${e.message}`); }
  }
  const load = (rel) => json.get(path.join(content, rel));
  const exists = (rel) => existsSync(path.join(content, rel));

  const curriculum = load('curriculum.json');
  const ranks = load('ranks.json');
  const achievements = load('achievements.json');
  const docs = load('commands.json');
  const cFile = path.join(content, 'curriculum.json');
  if (!curriculum?.chapters) { err(cFile, 'missing "chapters"'); return errors; }

  // ranks
  if (!Array.isArray(ranks) || ranks[0]?.xp !== 0) err(path.join(content, 'ranks.json'), 'must be an array starting at xp 0');
  else if (ranks.some((r, i) => i && r.xp <= ranks[i - 1].xp)) err(path.join(content, 'ranks.json'), 'xp must be strictly increasing');

  // commands
  const names = new Set();
  for (const d of docs || []) {
    if (names.has(d.name)) err(path.join(content, 'commands.json'), `duplicate command ${d.name}`);
    names.add(d.name);
    for (const k of ['category', 'summary', 'synopsis', 'description']) if (!d[k]) err(path.join(content, 'commands.json'), `${d.name}: missing ${k}`);
  }

  // curriculum
  const chapterIds = new Set();
  const missionIds = new Set();
  for (const ch of curriculum.chapters) {
    if (chapterIds.has(ch.id)) err(cFile, `duplicate chapter ${ch.id}`);
    chapterIds.add(ch.id);
    if (!DIFFICULTIES.has(ch.difficulty)) err(cFile, `${ch.id}: bad difficulty ${ch.difficulty}`);
    for (const r of ch.unlock?.requiresChapters || []) {
      if (!curriculum.chapters.some((c) => c.id === r)) err(cFile, `${ch.id}: requiresChapters unknown ${r}`);
    }
    if (ch.unlock?.minRank && !ranks?.some((r) => r.name === ch.unlock.minRank)) err(cFile, `${ch.id}: unknown minRank ${ch.unlock.minRank}`);
    for (const id of ch.missions) {
      if (missionIds.has(id)) err(cFile, `mission ${id} listed twice`);
      missionIds.add(id);
    }
  }

  // achievements
  for (const a of achievements || []) {
    if (a.condition?.type === 'chapter_complete' && !chapterIds.has(a.condition.chapter)) err(path.join(content, 'achievements.json'), `${a.id}: unknown chapter`);
  }

  // missions
  const walkthroughsFile = path.join(root, 'tests', 'walkthroughs.json');
  const walkthroughs = existsSync(walkthroughsFile) ? JSON.parse(readFileSync(walkthroughsFile, 'utf8')) : {};
  for (const ch of curriculum.chapters) {
    for (const id of ch.missions) {
      const file = path.join(content, 'missions', `${id}.json`);
      const m = json.get(file);
      if (!m) { err(file, 'mission file missing or invalid'); continue; }
      if (m.id !== id) err(file, `id "${m.id}" does not match filename`);
      if (m.chapter !== ch.id) err(file, `chapter "${m.chapter}" but listed under ${ch.id}`);
      for (const k of ['title', 'difficulty', 'xp', 'briefing', 'machine', 'objectives', 'debrief']) if (m[k] === undefined) err(file, `missing "${k}"`);
      if (!DIFFICULTIES.has(m.difficulty)) err(file, `bad difficulty ${m.difficulty}`);
      if (!(m.xp > 0)) err(file, 'xp must be > 0');
      if (!exists(`machines/${m.machine}.json`)) err(file, `machine "${m.machine}" not found`);
      else if (m.startUser && !load(`machines/${m.machine}.json`).users.some((u) => u.name === m.startUser)) err(file, `startUser "${m.startUser}" is not a user of ${m.machine}`);
      if (m.network && !exists(`network/${m.network}.json`)) err(file, `network "${m.network}" not found`);
      if ((m.objectives || []).some((o) => ['http'].includes(o.type) || (o.type === 'command' && /^\^?\(?(curl|ping|nc|dig)/.test(o.match || ''))) && !exists(`network/${m.network || 'lab'}.json`)) err(file, 'uses network commands but the network file is missing');
      if (m.lesson && !exists(`lessons/${m.lesson}.json`)) err(file, `lesson "${m.lesson}" not found`);
      const ids = new Set();
      const wt = walkthroughs[id];
      if (!wt) err(file, 'no walkthrough in tests/walkthroughs.json (every mission must be provably solvable)');
      for (const e of m.scope?.ips || []) if (!/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(e)) err(file, `scope.ips entry "${e}" is not an IP or CIDR`);
      for (const o of m.objectives || []) {
        if (ids.has(o.id)) err(file, `duplicate objective id ${o.id}`);
        ids.add(o.id);
        if (!OBJECTIVE_TYPES.has(o.type)) err(file, `${o.id}: unknown type ${o.type}`);
        if (o.type === 'command') {
          try { new RegExp(o.match); } catch { err(file, `${o.id}: invalid regex`); }
        }
        if (o.type === 'file_read' && !o.path && !o.match) err(file, `${o.id}: file_read needs "path" or "match"`);
        if (o.type === 'event') {
          if (!EVENT_NAMES.has(o.name)) err(file, `${o.id}: unknown event "${o.name}" (known: ${[...EVENT_NAMES].join(', ')})`);
          for (const re of Object.values(o.where || {})) { try { new RegExp(re); } catch { err(file, `${o.id}: invalid regex in where`); } }
        }
        if (o.type === 'fs' && !o.path) err(file, `${o.id}: fs objective needs "path"`);
        if (o.type === 'fs' && o.mode === undefined && o.owner === undefined && o.contains === undefined && o.exists === undefined) err(file, `${o.id}: fs objective needs mode, owner, contains or exists`);
        if (o.type === 'http') { try { new RegExp(o.path ?? '.*'); } catch { err(file, `${o.id}: invalid path regex`); } }
        if (o.type === 'flag' && !o.flagHash) err(file, `${o.id}: flag objective needs flagHash`);
        if (o.type === 'answer' && !o.answerHash) err(file, `${o.id}: answer objective needs answerHash`);
        if ((o.type === 'flag' || o.type === 'answer') && wt) {
          const solution = wt.submit?.[o.id];
          if (solution === undefined) err(file, `${o.id}: walkthrough has no submit value`);
          else if ((await objectiveHash(m.id, o.id, o.type, solution)) !== (o.flagHash ?? o.answerHash)) err(file, `${o.id}: walkthrough value does not match the stored hash`);
        }
      }
      (m.hints || []).forEach((h, i) => { if (!(h.cost >= 0) || !h.text) err(file, `hint ${i + 1}: needs cost and text`); });
    }
  }
  for (const f of json.keys()) {
    if (f.includes(`${path.sep}missions${path.sep}`) && !missionIds.has(path.basename(f, '.json'))) err(f, 'mission file not listed in curriculum.json');
  }

  // machines
  for (const [f, m] of json) {
    if (!f.includes(`${path.sep}machines${path.sep}`)) continue;
    const names = m.users?.map((u) => u.name) || [];
    if (new Set(names).size !== names.length) err(f, 'duplicate user names');
    if (!names.includes(m.startUser)) err(f, `startUser "${m.startUser}" is not in users`);
    const pids = new Set();
    for (const p of m.processes || []) { if (pids.has(p.pid)) err(f, `duplicate pid ${p.pid}`); pids.add(p.pid); if (!names.includes(p.user)) err(f, `process ${p.pid}: unknown user ${p.user}`); }
    for (const s of m.listening || []) if (!pids.has(s.pid)) err(f, `listening port ${s.port}: no process with pid ${s.pid}`);
  }

  // networks and webapps
  for (const [f, n] of json) {
    if (f.includes(`${path.sep}network${path.sep}`)) {
      for (const [ip, h] of Object.entries(n.hosts || {})) {
        for (const hop of h.hops || []) if (hop !== '*' && !n.hosts[hop]) err(f, `${ip}: hop ${hop} is not a host`);
        for (const [port, svc] of Object.entries(h.services || {})) {
          if (svc.http && !exists(`webapps/${svc.http}.json`)) err(f, `${ip}:${port}: webapp "${svc.http}" not found`);
          if (!svc.http && !svc.banner && !svc.name) err(f, `${ip}:${port}: service needs a "name" (plus "http" or "banner" if it talks)`);
        }
      }
      for (const [domain, zone] of Object.entries(n.dns || {})) {
        for (const r of zone.records || []) if (!DNS_TYPES.has(r.type)) err(f, `${domain}: unknown record type ${r.type}`);
        if (!zone.records?.some((r) => r.type === 'SOA')) err(f, `${domain}: zone needs an SOA record`);
      }
    }
    if (f.includes(`${path.sep}webapps${path.sep}`)) {
      if (n.engine) {
        if (!['shopzone'].includes(n.engine)) err(f, `unknown engine "${n.engine}"`);
        if (n.id !== path.basename(f, '.json')) err(f, `id "${n.id}" does not match filename`);
      } else if (!n.routes || !Object.keys(n.routes).every((r) => r.startsWith('/'))) {
        err(f, 'routes must be a map of paths starting with "/"');
      }
      for (const [r, def] of Object.entries(n.routes || {})) {
        for (const x of def.responses || []) { try { if (x.when?.body) new RegExp(x.when.body); } catch { err(f, `${r}: invalid regex in when.body`); } }
      }
    }
  }

  // lessons
  for (const [f, l] of json) {
    if (!f.includes(`${path.sep}lessons${path.sep}`)) continue;
    if (!l.sections?.length) err(f, 'lesson needs sections');
    (l.quiz || []).forEach((q, i) => {
      if (!Array.isArray(q.choices) || q.choices.length < 2) err(f, `quiz ${i + 1}: needs 2+ choices`);
      else if (!Number.isInteger(q.answer) || q.answer < 0 || q.answer >= q.choices.length) err(f, `quiz ${i + 1}: answer index out of range`);
    });
  }
  return errors;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const errors = await validate();
  if (errors.length) { console.error(`✖ ${errors.length} problem(s):\n${errors.map((e) => `  - ${e}`).join('\n')}`); process.exit(1); }
  console.log('✔ content is valid');
}
