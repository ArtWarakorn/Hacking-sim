// Mission engine: watches terminal events, ticks objectives, checks flags/answers, tracks hints.
import { EventBus } from '../core/eventbus.js';
import { objectiveHash } from '../core/hash.js';
import { inScope } from '../sim/network.js';

const SUBMIT_TYPES = new Set(['flag', 'answer']);
// Actions that touch a host. DNS lookups are passive and traceroute hops are not "targets", so neither counts.
const SCOPED_KINDS = new Set(['ping', 'traceroute', 'connect', 'http', 'scan', 'ftp', 'smb']);

export class MissionEngine {
  /**
   * @param mission  parsed mission JSON
   * @param opts.bus the EventBus the terminal/commands emit to ('command', 'file_read')
   */
  constructor(mission, { bus, hash = objectiveHash, now = () => Date.now() } = {}) {
    this.mission = mission;
    this.bus = bus;
    this.hash = hash;
    this.now = now;
    this.events = new EventBus(); // emits 'objective' {objective}, 'complete', 'hint'
    this.done = new Set();
    this.violations = []; // { ip, kind } — one per distinct out-of-scope host touched
    this.hintsRevealed = 0;
    this.attempts = 0;
    this.startedAt = now();
    this.finishedAt = null;
    this.unsubscribe = [];
  }

  attach() {
    this.unsubscribe.push(
      this.bus.on('command', (e) => this.onCommand(e)),
      this.bus.on('file_read', (e) => this.onFileRead(e)),
      this.bus.on('http', (e) => this.onHttp(e)),
      this.bus.on('game', (e) => this.onGame(e)),
      this.bus.on('net', (e) => this.onNet(e)),
      this.bus.on('interactive', (e) => this.checkState(e.session)),
    );
    return this;
  }

  detach() {
    this.unsubscribe.forEach((off) => off());
    this.unsubscribe = [];
  }

  get complete() { return this.mission.objectives.every((o) => this.done.has(o.id)); }
  get seconds() { return ((this.finishedAt ?? this.now()) - this.startedAt) / 1000; }
  get objectives() { return this.mission.objectives.map((o) => ({ ...o, done: this.done.has(o.id) })); }

  // ----- events -----
  onCommand({ line, session, status }) {
    for (const o of this.mission.objectives) {
      if (this.done.has(o.id)) continue;
      if (o.type === 'command' && status === (o.status ?? 0) && new RegExp(o.match, 'i').test(line.trim())) this.tick(o);
    }
    this.checkState(session);
  }

  /** State-based objectives are re-checked after every command and every line typed into ftp/smbclient/etc. */
  checkState(session) {
    for (const o of this.mission.objectives) {
      if (this.done.has(o.id)) continue;
      if (o.type === 'shell' && sessionMatches(session, o)) this.tick(o);
      else if (o.type === 'privilege' && session.user.uid === 0 && (!o.host || session.host === o.host)) this.tick(o);
      else if (o.type === 'fs' && fsMatches(session, o)) this.tick(o);
    }
  }

  /** Tools announce notable things ({ name: 'ftp.login', user, ok, ... }); `event` objectives match on name + fields. */
  onGame(e) {
    for (const o of this.mission.objectives) {
      if (o.type !== 'event' || this.done.has(o.id) || o.name !== e.name) continue;
      if (Object.entries(o.where || {}).every(([k, re]) => new RegExp(re, 'i').test(String(e[k])))) this.tick(o);
    }
  }

  /** Scope enforcement: touching a host outside `scope.ips` is recorded (once per host) and costs XP. */
  onNet({ kind, ip, session }) {
    const ips = this.mission.scope?.ips;
    if (!ips || !ip || !SCOPED_KINDS.has(kind)) return;
    if (ip.startsWith('127.') || ip === session.machine.ip) return;
    if (inScope(ip, ips) || this.violations.some((v) => v.ip === ip)) return;
    this.violations.push({ ip, kind });
    this.events.emit('violation', { ip, kind, count: this.violations.length });
  }

  /** Emitted by curl (and later the browser/proxy) for every HTTP request that reached a server. */
  onHttp({ host, method, path, status }) {
    for (const o of this.mission.objectives) {
      if (o.type !== 'http' || this.done.has(o.id)) continue;
      if (o.host && o.host !== host) continue;
      if (o.method && o.method !== method) continue;
      if (o.status !== undefined && o.status !== status) continue;
      if (new RegExp(o.path ?? '.*').test(path)) this.tick(o);
    }
  }

  onFileRead({ path }) {
    for (const o of this.mission.objectives) {
      if (o.type !== 'file_read' || this.done.has(o.id)) continue;
      if (o.path === path || (o.match && new RegExp(o.match).test(path))) this.tick(o);
    }
  }

  tick(objective) {
    if (this.done.has(objective.id)) return;
    this.done.add(objective.id);
    this.events.emit('objective', { objective: { ...objective, done: true } });
    if (this.complete && this.finishedAt === null) {
      this.finishedAt = this.now();
      this.events.emit('complete', { engine: this });
    }
  }

  // ----- flags and answers -----
  /** Try `value` against every pending flag/answer objective. Resolves { ok, objective?, message }. */
  async submit(value) {
    const text = String(value ?? '').trim();
    if (!text) return { ok: false, message: 'กรอกคำตอบหรือ flag ก่อน' };
    this.attempts++;
    for (const o of this.mission.objectives) {
      if (!SUBMIT_TYPES.has(o.type) || this.done.has(o.id)) continue;
      const expected = o.flagHash ?? o.answerHash;
      if (expected && (await this.hash(this.mission.id, o.id, o.type, text)) === expected) {
        this.tick(o);
        return { ok: true, objective: o, message: o.type === 'flag' ? 'Flag ถูกต้อง!' : 'คำตอบถูกต้อง!' };
      }
    }
    const pending = this.mission.objectives.some((o) => SUBMIT_TYPES.has(o.type) && !this.done.has(o.id));
    return { ok: false, message: pending ? 'ยังไม่ถูกต้อง ลองตรวจอีกครั้ง' : 'ไม่มีข้อที่ต้องส่งคำตอบแล้ว' };
  }

  // ----- hints -----
  get hints() { return this.mission.hints || []; }
  get hintsUsed() { return this.hintsRevealed; }
  get hintCost() { return this.hints.slice(0, this.hintsRevealed).reduce((s, h) => s + h.cost, 0); }
  get nextHintCost() { return this.hints[this.hintsRevealed]?.cost ?? null; }
  get revealedHints() { return this.hints.slice(0, this.hintsRevealed); }

  requestHint() {
    const hint = this.hints[this.hintsRevealed];
    if (!hint) return null;
    this.hintsRevealed++;
    this.events.emit('hint', { hint, index: this.hintsRevealed });
    return hint;
  }
}

/** `fs` objective: the file system reached a state, e.g. { path, mode: "600" } or { path, contains: "x" } or { path, exists: false }. */
function fsMatches(session, o) {
  const node = session.vfs.get(o.path);
  if (o.exists === false) return !node;
  if (!node) return false;
  if (o.mode !== undefined && (node.mode & 0o7777) !== parseInt(o.mode, 8)) return false;
  if (o.owner !== undefined && node.owner !== o.owner) return false;
  if (o.contains !== undefined && !(node.content ?? '').includes(o.contains)) return false;
  return true;
}

function sessionMatches(session, o) {
  return (!o.user || session.user.name === o.user) && (!o.host || session.host === o.host);
}
