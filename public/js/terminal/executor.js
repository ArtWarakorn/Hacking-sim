// Runs one command line against a SessionStack: parsing, expansion, pipes, redirects, && || ;
import { tokenize, parse, expandVars } from './parser.js';
import { FsError, normalize } from '../sim/vfs.js';
import { bus as defaultBus } from '../core/eventbus.js';

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function expandWord(token, session) {
  let v = expandVars(token.value, session.env, session.lastStatus);
  if (!token.quoted) {
    if (v === '' && token.hasVar) return []; // unquoted $EMPTY disappears, like bash
    if (v === '~') v = session.env.HOME;
    else if (v.startsWith('~/')) v = session.env.HOME + v.slice(1);
    if (/[*?]/.test(v)) {
      const hits = session.vfs.expandGlob(v, session.cwd);
      if (hits.length) return hits;
    }
  }
  return [v];
}

async function runCommand(argv, ctx, registry, input) {
  const name = argv[0];
  if (name.includes('/')) {
    const abs = normalize(name, ctx.session.cwd);
    const base = abs.split('/').pop();
    if (/^\/(usr\/)?(local\/)?s?bin\//.test(abs) && registry.has(base)) return runCommand([base, ...argv.slice(1)], ctx, registry, input);
    const node = ctx.vfs.get(abs);
    if (!node) return { out: '', err: `bash: ${name}: No such file or directory\n`, code: 127 };
    if (node.type === 'dir') return { out: '', err: `bash: ${name}: Is a directory\n`, code: 126 };
    return { out: '', err: `bash: ${name}: Permission denied\n`, code: 126 };
  }
  const cmd = registry.get(name);
  if (!cmd) {
    const near = registry.names().filter((n) => levenshtein(n, name) <= 1 || (name.length > 2 && n.startsWith(name)));
    const hint = near.length ? `\nคำสั่งที่ใกล้เคียง: ${near.slice(0, 3).join(', ')}` : '';
    return { out: '', err: `bash: ${name}: command not found${hint}\n`, code: 127 };
  }
  if (argv.includes('--help') && registry.doc(name)) return { out: registry.helpText(name), err: '', code: 0 };
  const res = await cmd.run(ctx, argv.slice(1), input);
  return { out: res.out ?? '', err: res.err ?? '', code: res.code ?? 0, clear: res.clear, exit: res.exit, interactive: res.interactive };
}

async function runPipeline(cmds, session, registry, opts) {
  let input = null;
  let out = '';
  let err = '';
  let code = 0;
  let clear = false;
  let exited = false;
  let interactive = null;

  for (let i = 0; i < cmds.length; i++) {
    const cmd = cmds[i];
    const last = i === cmds.length - 1;
    const argv = cmd.argv.flatMap((t) => expandWord(t, session));
    const redirTarget = (r) => expandWord(r.target, session)[0];

    // Redirect plan
    let outDest = { type: 'out' };
    let errDest = { type: 'err' };
    let stdin = input;
    let early = null;
    for (const r of cmd.redirects) {
      if (r.op === '>' || r.op === '>>') outDest = { type: 'file', path: redirTarget(r), append: r.op === '>>', written: false };
      else if (r.op === '2>' || r.op === '2>>') errDest = { type: 'file', path: redirTarget(r), append: r.op === '2>>', written: false };
      else if (r.op === '2>&1') errDest = outDest;
      else if (r.op === '<') {
        try { stdin = session.vfs.readFile(normalize(redirTarget(r), session.cwd), session.user); }
        catch (e) {
          if (!(e instanceof FsError)) throw e;
          early = `bash: ${redirTarget(r)}: ${e.msg}\n`;
        }
      }
    }
    if (early) { err += early; code = 1; input = ''; continue; }

    const ctx = {
      session, vfs: session.vfs, user: session.user, registry,
      stack: opts.stack, history: opts.history, bus: opts.bus,
      piped: !last || outDest.type === 'file',
      abs: (p) => normalize(p, session.cwd),
    };
    const res = await runCommand(argv, ctx, registry, stdin);
    code = res.code;
    if (res.clear) clear = true;
    if (res.exit) exited = true;
    if (last) interactive = res.interactive || null; // only a command at the end of a pipeline can take over the prompt

    let nextInput = '';
    const deliver = (text, dest) => {
      if (!text) return;
      if (dest.type === 'out') nextInput += text;
      else if (dest.type === 'err') err += text;
      else if (dest.path === '/dev/null') { /* discard */ }
      else {
        try {
          session.vfs.writeFile(normalize(dest.path, session.cwd), text, session.user, { append: dest.append || dest.written });
          dest.written = true;
        } catch (e) {
          if (!(e instanceof FsError)) throw e;
          err += `bash: ${dest.path}: ${e.msg}\n`; code = 1;
        }
      }
    };
    // `> file` should create/truncate the file even with no output
    if (outDest.type === 'file' && !res.out && outDest.path !== '/dev/null') {
      try { session.vfs.writeFile(normalize(outDest.path, session.cwd), '', session.user, { append: outDest.append }); outDest.written = true; }
      catch (e) { if (!(e instanceof FsError)) throw e; err += `bash: ${outDest.path}: ${e.msg}\n`; code = 1; }
    }
    deliver(res.out, outDest);
    deliver(res.err, errDest);
    input = nextInput;
    if (last) out = nextInput;
  }
  return { out, err, code, clear, exited, interactive };
}

/**
 * Execute a full command line. Returns { out, err, output, code, clear, exit }.
 * `output` is err-then-out for convenience when printing.
 */
export async function execute(line, stack, registry, { history = null, bus = defaultBus } = {}) {
  const session = stack.current;
  let list;
  try {
    list = parse(tokenize(line));
  } catch (e) {
    session.lastStatus = 2;
    const err = `bash: ${e.message}\n`;
    return { out: '', err, output: err, code: 2, clear: false, exit: false };
  }

  let out = ''; let err = ''; let status = 0; let clear = false; let exit = false;
  let prevOp = null;
  let interactive = null;
  for (const item of list) {
    if ((prevOp === '&&' && status !== 0) || (prevOp === '||' && status === 0)) { prevOp = item.next; continue; }
    const active = stack.current; // `exit` may have popped a session mid-line
    const res = await runPipeline(item.pipeline, active, registry, { stack, history, bus });
    out += res.out; err += res.err; status = res.code;
    if (res.clear) { clear = true; out = ''; err = ''; }
    if (res.exited) exit = true;
    interactive = res.interactive;
    active.lastStatus = status;
    prevOp = item.next;
  }
  session.lastStatus = status;
  if (interactive) stack.interactive = interactive;
  bus.emit('command', { line, session, status, out, err });
  return { out, err, output: err + out, code: status, clear, exit };
}

/**
 * Interactive tools (ftp, smbclient, later ssh/msfconsole/mysql) take over the prompt: a command returns
 * `interactive: { name, prompt, secret?, onLine(line) }`. While `stack.interactive` is set, typed lines go to
 * onLine, which returns { out, err, code } plus optionally `interactive` (next state) or `done: true` (back to bash).
 */
export async function submitLine(line, stack, registry, opts = {}) {
  const it = stack.interactive;
  if (!it) return execute(line, stack, registry, opts);
  const bus = opts.bus || defaultBus;
  stack.interactive = null; // cleared first so a throwing handler can never trap the player
  const res = (await it.onLine(line)) || {};
  if (res.interactive) stack.interactive = res.interactive;
  else if (!res.done) stack.interactive = it;
  bus.emit('interactive', { line: it.secret ? '' : line, session: stack.current, context: it.name });
  const out = res.out ?? ''; const err = res.err ?? '';
  return { out, err, output: err + out, code: res.code ?? 0, clear: false, exit: false };
}
