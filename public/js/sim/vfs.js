// In-memory virtual file system with Unix-style ownership and permission bits.
// Pure JS — no DOM, so it runs in the browser and under `node --test`.

const MSG = {
  ENOENT: 'No such file or directory',
  EACCES: 'Permission denied',
  ENOTDIR: 'Not a directory',
  EISDIR: 'Is a directory',
  EEXIST: 'File exists',
  EPERM: 'Operation not permitted',
};

export class FsError extends Error {
  constructor(code, path) {
    super(`${path}: ${MSG[code]}`);
    this.code = code;
    this.path = path;
    this.msg = MSG[code];
  }
}

export function normalize(p, cwd = '/') {
  if (!p.startsWith('/')) p = `${cwd}/${p}`;
  const out = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
}
export const dirname = (p) => (p === '/' ? '/' : p.slice(0, p.lastIndexOf('/')) || '/');
export const basename = (p) => (p === '/' ? '/' : p.slice(p.lastIndexOf('/') + 1));
export const join = (a, b) => (a === '/' ? `/${b}` : `${a.replace(/\/$/, '')}/${b}`);

export function globToRegExp(pattern) {
  const src = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${src}$`);
}

export function canAccess(node, user, bit) {
  if (user.uid === 0) return true;
  let bits;
  if (node.owner === user.name) bits = (node.mode >> 6) & 7;
  else if ((user.groups || []).some((g) => g.name === node.group)) bits = (node.mode >> 3) & 7;
  else bits = node.mode & 7;
  return (bits & bit) !== 0;
}

export function modeString(node) {
  const m = node.mode;
  let s = node.type === 'dir' ? 'd' : '-';
  for (const shift of [6, 3, 0]) {
    const b = (m >> shift) & 7;
    s += (b & 4 ? 'r' : '-') + (b & 2 ? 'w' : '-') + (b & 1 ? 'x' : '-');
  }
  if (m & 0o4000) s = s.slice(0, 3) + (s[3] === 'x' ? 's' : 'S') + s.slice(4);
  if (m & 0o2000) s = s.slice(0, 6) + (s[6] === 'x' ? 's' : 'S') + s.slice(7);
  if (m & 0o1000) s = s.slice(0, 9) + (s[9] === 'x' ? 't' : 'T');
  return s;
}

export const sizeOf = (node) => (node.type === 'dir' ? 4096 : new TextEncoder().encode(node.content).length);

export class VFS {
  constructor(entries = {}) {
    this.nodes = new Map();
    this.kids = new Map();
    this._put('/', { type: 'dir', mode: 0o755, owner: 'root', group: 'root', mtime: 'Nov 15 10:00' });
    for (const [p, spec] of Object.entries(entries)) this.add(p, spec);
  }

  _put(path, node) {
    this.nodes.set(path, node);
    if (path !== '/') {
      const d = dirname(path);
      if (!this.kids.has(d)) this.kids.set(d, new Set());
      this.kids.get(d).add(basename(path));
    }
    if (node.type === 'dir' && !this.kids.has(path)) this.kids.set(path, new Set());
  }

  /** Add/replace a node from a JSON spec (used when loading machines). Parents are created root-owned. */
  add(path, spec) {
    path = normalize(path);
    const type = spec.type || 'file';
    this.mkdirp(dirname(path));
    this._put(path, {
      type,
      content: type === 'file' ? String(spec.content ?? '') : undefined,
      mode: typeof spec.mode === 'number' ? spec.mode : parseInt(spec.mode ?? (type === 'dir' ? '755' : '644'), 8),
      owner: spec.owner || 'root',
      group: spec.group || spec.owner || 'root',
      mtime: spec.mtime || 'Nov 15 10:00',
    });
  }

  mkdirp(path, owner = 'root', group = 'root') {
    let cur = '';
    for (const seg of normalize(path).split('/').filter(Boolean)) {
      cur += `/${seg}`;
      const n = this.nodes.get(cur);
      if (!n) this._put(cur, { type: 'dir', mode: 0o755, owner, group, mtime: 'Nov 15 10:00' });
      else if (n.type !== 'dir') throw new FsError('ENOTDIR', cur);
    }
  }

  get(path) { return this.nodes.get(normalize(path)); }
  exists(path) { return this.nodes.has(normalize(path)); }

  /** Look up a node. With `user`, enforces execute permission on every ancestor directory. */
  resolve(path, user) {
    const p = normalize(path);
    if (user) {
      let cur = '';
      for (const seg of p.split('/').filter(Boolean)) {
        const dir = this.nodes.get(cur || '/');
        if (dir.type !== 'dir') throw new FsError('ENOTDIR', p);
        if (!canAccess(dir, user, 1)) throw new FsError('EACCES', p);
        cur += `/${seg}`;
        if (!this.nodes.has(cur)) throw new FsError('ENOENT', p);
      }
    }
    const n = this.nodes.get(p);
    if (!n) throw new FsError('ENOENT', p);
    return n;
  }

  /** Child names (unsorted-safe: returns sorted) with no permission checks. */
  names(path) { return [...(this.kids.get(normalize(path)) || [])].sort(); }

  readdir(path, user) {
    const n = this.resolve(path, user);
    if (n.type !== 'dir') throw new FsError('ENOTDIR', normalize(path));
    if (!canAccess(n, user, 4)) throw new FsError('EACCES', normalize(path));
    return this.names(path);
  }

  readFile(path, user) {
    const n = this.resolve(path, user);
    if (n.type === 'dir') throw new FsError('EISDIR', normalize(path));
    if (!canAccess(n, user, 4)) throw new FsError('EACCES', normalize(path));
    return n.content;
  }

  writeFile(path, content, user, { append = false } = {}) {
    const p = normalize(path);
    const parent = this.resolve(dirname(p), user);
    if (parent.type !== 'dir') throw new FsError('ENOTDIR', p);
    if (!canAccess(parent, user, 1)) throw new FsError('EACCES', p);
    const n = this.nodes.get(p);
    if (n) {
      if (n.type === 'dir') throw new FsError('EISDIR', p);
      if (!canAccess(n, user, 2)) throw new FsError('EACCES', p);
      n.content = append ? n.content + content : content;
      return;
    }
    if (!canAccess(parent, user, 2)) throw new FsError('EACCES', p);
    this._put(p, {
      type: 'file', content, mode: 0o644, owner: user.name,
      group: user.groups?.[0]?.name || user.name, mtime: 'Nov 15 10:00',
    });
  }

  mkdir(path, user, { parents = false } = {}) {
    const p = normalize(path);
    if (this.nodes.has(p)) {
      if (parents && this.nodes.get(p).type === 'dir') return;
      throw new FsError('EEXIST', p);
    }
    const parentPath = dirname(p);
    if (!parents || this.nodes.has(parentPath)) {
      const parent = this.resolve(parentPath, user);
      if (parent.type !== 'dir') throw new FsError('ENOTDIR', p);
      if (!canAccess(parent, user, 2) || !canAccess(parent, user, 1)) throw new FsError('EACCES', p);
    } else {
      this.mkdir(parentPath, user, { parents: true });
    }
    this._put(p, {
      type: 'dir', mode: 0o755, owner: user.name,
      group: user.groups?.[0]?.name || user.name, mtime: 'Nov 15 10:00',
    });
  }

  remove(path, user, { recursive = false } = {}) {
    const p = normalize(path);
    const n = this.resolve(p, user);
    if (p === '/') throw new FsError('EPERM', p);
    const parent = this.nodes.get(dirname(p));
    if (!canAccess(parent, user, 2)) throw new FsError('EACCES', p);
    if (n.type === 'dir' && !recursive) throw new FsError('EISDIR', p);
    const drop = (q) => {
      for (const name of this.kids.get(q) || []) drop(join(q, name));
      this.kids.delete(q);
      this.nodes.delete(q);
    };
    drop(p);
    this.kids.get(dirname(p))?.delete(basename(p));
  }

  chmod(path, mode, user) {
    const n = this.resolve(path, user);
    if (user.uid !== 0 && n.owner !== user.name) throw new FsError('EPERM', normalize(path));
    n.mode = mode;
  }

  /** Depth-first list of every descendant path (absolute), sorted. */
  *walk(path) {
    const p = normalize(path);
    for (const name of this.names(p)) {
      const child = join(p, name);
      yield child;
      if (this.nodes.get(child).type === 'dir') yield* this.walk(child);
    }
  }

  /** Expand `*` / `?` in the last path segment. Returns [] when nothing matches. */
  expandGlob(pattern, cwd) {
    const slash = pattern.lastIndexOf('/');
    const dirPart = slash >= 0 ? pattern.slice(0, slash + 1) : '';
    const basePat = pattern.slice(slash + 1);
    if (/[*?]/.test(dirPart)) return [];
    const dirAbs = normalize(dirPart || '.', cwd);
    if (this.nodes.get(dirAbs)?.type !== 'dir') return [];
    const re = globToRegExp(basePat);
    return this.names(dirAbs)
      .filter((n) => re.test(n) && (basePat.startsWith('.') || !n.startsWith('.')))
      .map((n) => dirPart + n);
  }
}
