// File-system and text-processing commands. Each command: { name, run(ctx, args, input) -> {out, err, code} }
import {
  FsError, canAccess, modeString, sizeOf, join, dirname, basename, globToRegExp, normalize,
} from '../sim/vfs.js';
import { parseArgs, usageErr, splitLines, fsFail } from './util.js';

const ok = (out = '') => ({ out, err: '', code: 0 });
const fail = (err, code = 1) => ({ out: '', err, code });

// ---------- ls ----------
const humanSize = (n) => {
  if (n < 1024) return String(n);
  const units = ['K', 'M', 'G'];
  let v = n / 1024; let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)}${units[i]}`;
};

function colorName(name, node, color) {
  if (!color) return name;
  if (node.type === 'dir') return `\x1b[1;34m${name}\x1b[0m`;
  if (node.mode & 0o4000) return `\x1b[1;31m${name}\x1b[0m`;
  if (node.mode & 0o111) return `\x1b[1;32m${name}\x1b[0m`;
  return name;
}

function formatEntries(entries, { long, color, piped, human, withTotal }) {
  if (!entries.length) return '';
  if (!long) return entries.map((e) => colorName(e.name, e.node, color)).join(piped ? '\n' : '  ') + '\n';
  const rows = entries.map((e) => ({
    mode: modeString(e.node),
    links: e.node.type === 'dir' ? '2' : '1',
    owner: e.node.owner, group: e.node.group,
    size: human ? humanSize(sizeOf(e.node)) : String(sizeOf(e.node)),
    mtime: e.node.mtime,
    name: colorName(e.name, e.node, color),
  }));
  const w = (k) => Math.max(...rows.map((r) => r[k].length));
  const wl = w('links'), wo = w('owner'), wg = w('group'), ws = w('size');
  let out = '';
  if (withTotal) {
    const blocks = entries.reduce((s, e) => s + Math.ceil(sizeOf(e.node) / 4096) * 4, 0);
    out += `total ${blocks}\n`;
  }
  for (const r of rows) {
    out += `${r.mode} ${r.links.padStart(wl)} ${r.owner.padEnd(wo)} ${r.group.padEnd(wg)} ${r.size.padStart(ws)} ${r.mtime} ${r.name}\n`;
  }
  return out;
}

const sortKey = (name) => name.replace(/^\./, '').toLowerCase();

const ls = {
  name: 'ls',
  async run(ctx, args) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'laAh1' });
    if (errors.length) return usageErr('ls', errors);
    const fmt = { long: flags.has('l'), color: !ctx.piped, piped: ctx.piped || flags.has('1'), human: flags.has('h') };
    const showAll = flags.has('a');
    const showAlmost = flags.has('A');
    const targets = rest.length ? rest : ['.'];
    let err = ''; let code = 0;
    const files = []; const dirs = [];
    for (const t of targets) {
      try {
        const abs = ctx.abs(t);
        const node = ctx.vfs.resolve(abs, ctx.user);
        (node.type === 'dir' ? dirs : files).push({ arg: t, abs, node });
      } catch (e) {
        err += fsFail('ls', t, e).replace(/^ls: (.*?): /, `ls: cannot access '$1': `); code = 2;
      }
    }
    const sections = [];
    if (files.length) {
      files.sort((a, b) => sortKey(a.arg).localeCompare(sortKey(b.arg)));
      sections.push(formatEntries(files.map((f) => ({ name: f.arg, node: f.node })), fmt));
    }
    for (const d of dirs) {
      try {
        const names = ctx.vfs.readdir(d.abs, ctx.user)
          .filter((n) => showAll || showAlmost || !n.startsWith('.'))
          .sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
        const entries = names.map((n) => ({ name: n, node: ctx.vfs.get(join(d.abs, n)) }));
        if (showAll) entries.unshift({ name: '.', node: d.node }, { name: '..', node: ctx.vfs.get(dirname(d.abs)) });
        const header = targets.length > 1 ? `${d.arg}:\n` : '';
        sections.push(header + formatEntries(entries, { ...fmt, withTotal: true }));
      } catch (e) {
        err += fsFail('ls', d.arg, e).replace(/^ls: (.*?): /, `ls: cannot open directory '$1': `); code = 2;
      }
    }
    return { out: sections.join('\n'), err, code };
  },
};

// ---------- navigation ----------
const pwd = { name: 'pwd', async run(ctx) { return ok(`${ctx.session.cwd}\n`); } };

const cd = {
  name: 'cd',
  async run(ctx, args) {
    const s = ctx.session;
    let target = args[0] ?? s.env.HOME;
    if (target === '-') target = s.env.OLDPWD || s.cwd;
    const abs = ctx.abs(target);
    try {
      const node = ctx.vfs.resolve(abs, ctx.user);
      if (node.type !== 'dir') return fail(`bash: cd: ${target}: Not a directory\n`);
      if (!canAccess(node, ctx.user, 1)) return fail(`bash: cd: ${target}: Permission denied\n`);
    } catch (e) {
      if (!(e instanceof FsError)) throw e;
      return fail(`bash: cd: ${target}: ${e.msg}\n`);
    }
    s.env.OLDPWD = s.cwd;
    s.cwd = abs;
    s.env.PWD = abs;
    return ok(args[0] === '-' ? `${abs}\n` : '');
  },
};

// ---------- reading ----------
const cat = {
  name: 'cat',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'n' });
    if (errors.length) return usageErr('cat', errors);
    const sources = rest.length ? rest : ['-'];
    let out = ''; let err = ''; let code = 0;
    for (const f of sources) {
      try {
        out += f === '-' ? (input ?? '') : ctx.vfs.readFile(ctx.abs(f), ctx.user);
        if (f !== '-') ctx.bus?.emit('file_read', { path: ctx.abs(f), session: ctx.session });
      } catch (e) { err += fsFail('cat', f, e); code = 1; }
    }
    if (flags.has('n')) out = splitLines(out).map((l, i) => `${String(i + 1).padStart(6)}\t${l}`).join('\n') + (out ? '\n' : '');
    return { out, err, code };
  },
};

function headTail(which) {
  return {
    name: which,
    async run(ctx, args, input) {
      const { values, rest, errors } = parseArgs(args, { values: 'n', numeric: true });
      if (errors.length) return usageErr(which, errors);
      const n = values.n === undefined ? 10 : Number.parseInt(values.n, 10);
      if (Number.isNaN(n)) return fail(`${which}: invalid number of lines: '${values.n}'\n`);
      const pick = (text) => {
        const lines = splitLines(text);
        const sel = which === 'head' ? lines.slice(0, n) : lines.slice(Math.max(0, lines.length - n));
        return sel.length ? sel.join('\n') + '\n' : '';
      };
      if (!rest.length) return ok(pick(input ?? ''));
      let out = ''; let err = ''; let code = 0;
      rest.forEach((f, idx) => {
        try {
          const body = pick(ctx.vfs.readFile(ctx.abs(f), ctx.user));
          out += rest.length > 1 ? `${idx ? '\n' : ''}==> ${f} <==\n${body}` : body;
        } catch (e) { err += fsFail(which, f, e); code = 1; }
      });
      return { out, err, code };
    },
  };
}

const wc = {
  name: 'wc',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'lwc' });
    if (errors.length) return usageErr('wc', errors);
    const count = (t) => ({ l: (t.match(/\n/g) || []).length, w: (t.trim() ? t.trim().split(/\s+/).length : 0), c: new TextEncoder().encode(t).length });
    const keys = ['l', 'w', 'c'].filter((k) => flags.has(k));
    const show = keys.length ? keys : ['l', 'w', 'c'];
    const rows = []; let err = ''; let code = 0;
    if (!rest.length) rows.push({ name: '', ...count(input ?? '') });
    for (const f of rest) {
      try { rows.push({ name: f, ...count(ctx.vfs.readFile(ctx.abs(f), ctx.user)) }); } catch (e) { err += fsFail('wc', f, e); code = 1; }
    }
    if (rest.length > 1) rows.push({ name: 'total', l: rows.reduce((s, r) => s + r.l, 0), w: rows.reduce((s, r) => s + r.w, 0), c: rows.reduce((s, r) => s + r.c, 0) });
    const width = show.length === 1 && rows.length === 1 ? 0 : Math.max(1, ...rows.flatMap((r) => show.map((k) => String(r[k]).length)));
    const out = rows.map((r) => show.map((k) => String(r[k]).padStart(width)).join(' ') + (r.name ? ` ${r.name}` : '')).join('\n');
    return { out: out ? `${out}\n` : '', err, code };
  },
};

// ---------- searching ----------
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const grep = {
  name: 'grep',
  async run(ctx, args, input) {
    const { flags, values, rest, errors } = parseArgs(args, { flags: 'ivncrlFEHhR', values: 'e' });
    if (errors.length) return usageErr('grep', errors);
    const files = [...rest];
    const pattern = values.e !== undefined ? values.e : files.shift();
    if (pattern === undefined) return fail("Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", 2);
    let re;
    try {
      const src = flags.has('F') ? escapeRe(pattern) : (flags.has('E') ? pattern : pattern.replace(/\\\|/g, '|'));
      re = new RegExp(src, flags.has('i') ? 'i' : '');
    } catch {
      return fail(`grep: Invalid regular expression: ${pattern}\n`, 2);
    }
    const recursive = flags.has('r') || flags.has('R');
    const sources = []; // { label, read: () => text }
    let err = ''; let code = 1;
    const targets = files.length ? files : (recursive ? ['.'] : null);
    if (!targets) sources.push({ label: '(standard input)', text: input ?? '' });
    else {
      for (const f of targets) {
        const abs = ctx.abs(f);
        let node;
        try { node = ctx.vfs.resolve(abs, ctx.user); } catch (e) { err += fsFail('grep', f, e); code = 2; continue; }
        if (node.type === 'dir') {
          if (!recursive) { err += `grep: ${f}: Is a directory\n`; continue; }
          for (const p of ctx.vfs.walk(abs)) {
            if (ctx.vfs.get(p).type !== 'file') continue;
            let label = f === '.' && !files.length ? p.slice(abs.length + 1) : join(f, p.slice(abs.length + 1));
            if (f !== '.' && f.endsWith('/')) label = f + p.slice(abs.length + 1);
            sources.push({ label, abs: p });
          }
        } else sources.push({ label: f, abs });
      }
    }
    const withName = !flags.has('h') && (flags.has('H') || sources.length > 1 || (recursive && targets));
    let out = '';
    for (const src of sources) {
      let text = src.text;
      if (text === undefined) {
        try { text = ctx.vfs.readFile(src.abs, ctx.user); } catch (e) { err += fsFail('grep', src.label, e); code = 2; continue; }
      }
      let matches = 0;
      let body = '';
      splitLines(text).forEach((line, i) => {
        if (re.test(line) === flags.has('v')) return;
        matches++;
        if (flags.has('c') || flags.has('l')) return;
        body += `${withName ? `${src.label}:` : ''}${flags.has('n') ? `${i + 1}:` : ''}${line}\n`;
      });
      if (matches) code = code === 2 ? 2 : 0;
      if (flags.has('c')) out += `${withName ? `${src.label}:` : ''}${matches}\n`;
      else if (flags.has('l')) { if (matches) out += `${src.label}\n`; }
      else out += body;
    }
    return { out, err, code };
  },
};

const find = {
  name: 'find',
  async run(ctx, args) {
    const paths = [];
    let i = 0;
    while (i < args.length && !args[i].startsWith('-') && args[i] !== '!' && args[i] !== '(') paths.push(args[i++]);
    if (!paths.length) paths.push('.');
    const tests = []; let maxdepth = Infinity;
    for (; i < args.length; i++) {
      const a = args[i];
      const val = () => {
        if (args[i + 1] === undefined) throw new Error(`missing argument to \`${a}'`);
        return args[++i];
      };
      try {
        if (a === '-name') { const re = globToRegExp(val()); tests.push((n, d) => re.test(basename(d))); }
        else if (a === '-iname') { const re = new RegExp(globToRegExp(val()).source, 'i'); tests.push((n, d) => re.test(basename(d))); }
        else if (a === '-type') { const t = val(); tests.push((n) => (t === 'd' ? n.type === 'dir' : t === 'f' ? n.type === 'file' : false)); }
        else if (a === '-user') { const u = val(); tests.push((n) => n.owner === u); }
        else if (a === '-maxdepth') maxdepth = Number.parseInt(val(), 10);
        else if (a === '-perm') {
          const spec = val();
          const mode = Number.parseInt(spec.replace(/^[-/]/, ''), 8);
          if (spec[0] === '-') tests.push((n) => (n.mode & mode) === mode);
          else if (spec[0] === '/') tests.push((n) => (n.mode & mode) !== 0);
          else tests.push((n) => (n.mode & 0o7777) === mode);
        } else if (a === '-print') { /* default action */ }
        else return fail(`find: unknown predicate \`${a}'\n`);
      } catch (e) { return fail(`find: ${e.message}\n`); }
    }
    let out = ''; let err = ''; let code = 0;
    const visit = (display, abs, depth) => {
      const node = ctx.vfs.get(abs);
      if (tests.every((t) => t(node, display))) out += `${display}\n`;
      if (node.type === 'dir' && depth < maxdepth) {
        let names;
        try { names = ctx.vfs.readdir(abs, ctx.user); } catch { err += `find: ‘${display}’: Permission denied\n`; code = 1; return; }
        for (const n of names) visit(display === '/' ? `/${n}` : `${display.replace(/\/$/, '')}/${n}`, join(abs, n), depth + 1);
      }
    };
    for (const p of paths) {
      try { ctx.vfs.resolve(ctx.abs(p), ctx.user); } catch { err += `find: ‘${p}’: No such file or directory\n`; code = 1; continue; }
      visit(p, ctx.abs(p), 0);
    }
    return { out, err, code };
  },
};

// ---------- creating / changing ----------
const touch = {
  name: 'touch',
  async run(ctx, args) {
    if (!args.length) return fail("touch: missing file operand\nTry 'touch --help' for more information.\n");
    let err = '';
    for (const f of args) {
      try { if (!ctx.vfs.exists(ctx.abs(f))) ctx.vfs.writeFile(ctx.abs(f), '', ctx.user); else ctx.vfs.resolve(ctx.abs(f), ctx.user); }
      catch (e) { err += fsFail('touch', f, e).replace(/^touch: (.*?): /, "touch: cannot touch '$1': "); }
    }
    return { out: '', err, code: err ? 1 : 0 };
  },
};

const mkdir = {
  name: 'mkdir',
  async run(ctx, args) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'p' });
    if (errors.length) return usageErr('mkdir', errors);
    if (!rest.length) return fail("mkdir: missing operand\nTry 'mkdir --help' for more information.\n");
    let err = '';
    for (const d of rest) {
      try { ctx.vfs.mkdir(ctx.abs(d), ctx.user, { parents: flags.has('p') }); }
      catch (e) { err += fsFail('mkdir', d, e).replace(/^mkdir: (.*?): /, "mkdir: cannot create directory '$1': "); }
    }
    return { out: '', err, code: err ? 1 : 0 };
  },
};

const rm = {
  name: 'rm',
  async run(ctx, args) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'rRf' });
    if (errors.length) return usageErr('rm', errors);
    if (!rest.length) return flags.has('f') ? ok() : fail("rm: missing operand\nTry 'rm --help' for more information.\n");
    let err = '';
    for (const f of rest) {
      const abs = ctx.abs(f);
      if (abs === '/') { err += "rm: it is dangerous to operate recursively on '/'\n"; continue; }
      try { ctx.vfs.remove(abs, ctx.user, { recursive: flags.has('r') || flags.has('R') }); }
      catch (e) {
        if (e instanceof FsError && e.code === 'ENOENT' && flags.has('f')) continue;
        err += fsFail('rm', f, e).replace(/^rm: (.*?): /, "rm: cannot remove '$1': ");
      }
    }
    return { out: '', err, code: err ? 1 : 0 };
  },
};

function applySymbolic(spec, node) {
  let mode = node.mode & 0o7777;
  for (const clause of spec.split(',')) {
    const m = /^([ugoa]*)([-+=])([rwxst]*)$/.exec(clause);
    if (!m) return null;
    const who = m[1] || 'a';
    let bits = 0;
    const perm = (r, w, x) => (m[3].includes('r') ? r : 0) | (m[3].includes('w') ? w : 0) | (m[3].includes('x') ? x : 0);
    let mask = 0;
    if (who.includes('u') || who.includes('a')) { bits |= perm(0o400, 0o200, 0o100); mask |= 0o700; if (m[3].includes('s')) bits |= 0o4000; }
    if (who.includes('g') || who.includes('a')) { bits |= perm(0o040, 0o020, 0o010); mask |= 0o070; if (m[3].includes('s')) bits |= 0o2000; }
    if (who.includes('o') || who.includes('a')) { bits |= perm(0o004, 0o002, 0o001); mask |= 0o007; if (m[3].includes('t')) bits |= 0o1000; }
    if (m[2] === '+') mode |= bits;
    else if (m[2] === '-') mode &= ~bits;
    else mode = (mode & ~(mask | 0o7000)) | bits;
  }
  return mode;
}

const chmod = {
  name: 'chmod',
  async run(ctx, args) {
    if (args.length < 2) return fail("chmod: missing operand\nTry 'chmod --help' for more information.\n");
    const [spec, ...files] = args;
    let err = '';
    for (const f of files) {
      try {
        const node = ctx.vfs.resolve(ctx.abs(f), ctx.user);
        const mode = /^[0-7]{1,4}$/.test(spec) ? Number.parseInt(spec, 8) : applySymbolic(spec, node);
        if (mode === null) return fail(`chmod: invalid mode: ‘${spec}’\n`);
        ctx.vfs.chmod(ctx.abs(f), mode, ctx.user);
      } catch (e) { err += fsFail('chmod', f, e).replace(/^chmod: (.*?): /, "chmod: changing permissions of '$1': "); }
    }
    return { out: '', err, code: err ? 1 : 0 };
  },
};

// ---------- text filters ----------
const sort = {
  name: 'sort',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'rnu' });
    if (errors.length) return usageErr('sort', errors);
    let text = input ?? ''; let err = '';
    if (rest.length) {
      text = '';
      for (const f of rest) { try { text += ctx.vfs.readFile(ctx.abs(f), ctx.user); } catch (e) { err += fsFail('sort', f, e); } }
    }
    let lines = splitLines(text);
    lines.sort(flags.has('n') ? (a, b) => (parseFloat(a) || 0) - (parseFloat(b) || 0) : (a, b) => (a < b ? -1 : a > b ? 1 : 0));
    if (flags.has('r')) lines.reverse();
    if (flags.has('u')) lines = lines.filter((l, i) => i === 0 || l !== lines[i - 1]);
    return { out: lines.length ? `${lines.join('\n')}\n` : '', err, code: err ? 2 : 0 };
  },
};

const uniq = {
  name: 'uniq',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'cd' });
    if (errors.length) return usageErr('uniq', errors);
    let text = input ?? '';
    if (rest.length) { try { text = ctx.vfs.readFile(ctx.abs(rest[0]), ctx.user); } catch (e) { return fail(fsFail('uniq', rest[0], e)); } }
    const groups = [];
    for (const l of splitLines(text)) {
      if (groups.length && groups[groups.length - 1].line === l) groups[groups.length - 1].n++;
      else groups.push({ line: l, n: 1 });
    }
    const out = groups.filter((g) => !flags.has('d') || g.n > 1)
      .map((g) => (flags.has('c') ? `${String(g.n).padStart(7)} ${g.line}` : g.line)).join('\n');
    return ok(out ? `${out}\n` : '');
  },
};

const cut = {
  name: 'cut',
  async run(ctx, args, input) {
    const { values, rest, errors } = parseArgs(args, { values: 'df' });
    if (errors.length) return usageErr('cut', errors);
    if (!values.f) return fail("cut: you must specify a list of bytes, characters, or fields\n");
    const delim = values.d ?? '\t';
    const wanted = new Set();
    for (const part of values.f.split(',')) {
      const m = /^(\d+)(?:-(\d+))?$/.exec(part);
      if (!m) return fail(`cut: invalid field range\n`);
      for (let k = Number(m[1]); k <= Number(m[2] ?? m[1]); k++) wanted.add(k);
    }
    let text = input ?? '';
    if (rest.length) { try { text = ctx.vfs.readFile(ctx.abs(rest[0]), ctx.user); } catch (e) { return fail(fsFail('cut', rest[0], e)); } }
    const out = splitLines(text).map((l) => (l.includes(delim) ? l.split(delim).filter((_, i) => wanted.has(i + 1)).join(delim) : l)).join('\n');
    return ok(out ? `${out}\n` : '');
  },
};

const base64 = {
  name: 'base64',
  async run(ctx, args, input) {
    const { flags, values, long, rest, errors } = parseArgs(args, { flags: 'd', values: 'w' });
    if (errors.length) return usageErr('base64', errors);
    let text = input ?? '';
    if (rest.length) { try { text = ctx.vfs.readFile(ctx.abs(rest[0]), ctx.user); } catch (e) { return fail(fsFail('base64', rest[0], e)); } }
    if (flags.has('d') || long.has('decode')) {
      try {
        const bin = atob(text.replace(/\s+/g, ''));
        return ok(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
      } catch { return fail('base64: invalid input\n'); }
    }
    const bytes = new TextEncoder().encode(text);
    let bin = '';
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    const enc = btoa(bin);
    const wrap = values.w === undefined ? 76 : Number.parseInt(values.w, 10);
    if (!wrap) return ok(`${enc}\n`);
    return ok(`${enc.match(new RegExp(`.{1,${wrap}}`, 'g'))?.join('\n') ?? ''}\n`);
  },
};

// ---------- xxd ----------
const hex2 = (n) => n.toString(16).padStart(2, '0');

const xxd = {
  name: 'xxd',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'pr' });
    if (errors.length) return usageErr('xxd', errors);
    let text = input ?? '';
    if (rest.length) { try { text = ctx.vfs.readFile(ctx.abs(rest[0]), ctx.user); } catch (e) { return fail(fsFail('xxd', rest[0], e)); } }
    if (flags.has('r')) {
      // reverse: plain hex (-p) or a classic dump ("00000000: 4865 6c6c ...  Hell")
      const hex = flags.has('p')
        ? text.replace(/\s+/g, '')
        : splitLines(text).map((l) => (l.split(':')[1] || '').split('  ')[0].replace(/\s+/g, '')).join('');
      if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) return fail('xxd: invalid input.\n');
      const bytes = Uint8Array.from(hex.match(/../g) || [], (h) => parseInt(h, 16));
      return ok(new TextDecoder().decode(bytes));
    }
    const bytes = new TextEncoder().encode(text);
    if (flags.has('p')) {
      const hex = [...bytes].map(hex2).join('');
      return ok(hex ? `${hex.match(/.{1,60}/g).join('\n')}\n` : '');
    }
    let out = '';
    for (let off = 0; off < bytes.length; off += 16) {
      const chunk = bytes.slice(off, off + 16);
      let hexPart = '';
      for (let i = 0; i < 16; i += 2) hexPart += `${chunk[i] === undefined ? '  ' : hex2(chunk[i])}${chunk[i + 1] === undefined ? '  ' : hex2(chunk[i + 1])} `;
      const ascii = [...chunk].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('');
      out += `${off.toString(16).padStart(8, '0')}: ${hexPart} ${ascii}\n`;
    }
    return ok(out);
  },
};

// ---------- tr ----------
function expandSet(spec) {
  const classes = { '[:lower:]': 'abcdefghijklmnopqrstuvwxyz', '[:upper:]': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '[:digit:]': '0123456789', '[:space:]': ' \t\n', '[:alpha:]': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' };
  let s = spec.replace(/\\n/g, '\n').replace(/\\t/g, '\t');
  for (const [k, v] of Object.entries(classes)) s = s.split(k).join(v);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    if (s[i + 1] === '-' && i + 2 < s.length) {
      for (let c = s.charCodeAt(i); c <= s.charCodeAt(i + 2); c++) out.push(String.fromCharCode(c));
      i += 2;
    } else out.push(s[i]);
  }
  return out;
}

const tr = {
  name: 'tr',
  async run(ctx, args, input) {
    const { flags, rest, errors } = parseArgs(args, { flags: 'ds' });
    if (errors.length) return usageErr('tr', errors);
    const del = flags.has('d');
    if (rest.length < (del ? 1 : 2)) return fail(`tr: missing operand\nTry 'tr --help' for more information.\n`, 1);
    const set1 = expandSet(rest[0]);
    const text = input ?? '';
    if (del) return ok([...text].filter((c) => !set1.includes(c)).join(''));
    const set2 = expandSet(rest[1]);
    if (!set2.length) return fail('tr: when not truncating set1, string2 must be non-empty\n', 1);
    const map = new Map(set1.map((c, i) => [c, set2[Math.min(i, set2.length - 1)]]));
    return ok([...text].map((c) => map.get(c) ?? c).join(''));
  },
};

export const fsCommands = [ls, pwd, cd, cat, headTail('head'), headTail('tail'), wc, grep, find, touch, mkdir, rm, chmod, sort, uniq, cut, base64, xxd, tr];
// re-exported for tests
export { normalize };
