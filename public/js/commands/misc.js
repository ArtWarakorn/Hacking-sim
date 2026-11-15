// System/info commands: whoami, id, hostname, uname, env, export, echo, date, history, clear, exit, help, man, true, false
import { parseArgs, usageErr } from './util.js';

const ok = (out = '') => ({ out, err: '', code: 0 });

const whoami = { name: 'whoami', async run(ctx) { return ok(`${ctx.user.name}\n`); } };

const id = {
  name: 'id',
  async run(ctx, args) {
    let user = ctx.user;
    if (args[0]) {
      user = ctx.session.machine.users.find((u) => u.name === args[0]);
      if (!user) return { out: '', err: `id: ‘${args[0]}’: no such user\n`, code: 1 };
    }
    const gid = user.gid ?? user.uid;
    const groups = user.groups?.length ? user.groups : [{ name: user.name, gid }];
    const primary = groups.find((g) => g.gid === gid) || groups[0];
    return ok(`uid=${user.uid}(${user.name}) gid=${primary.gid}(${primary.name}) groups=${groups.map((g) => `${g.gid}(${g.name})`).join(',')}\n`);
  },
};

const hostname = { name: 'hostname', async run(ctx) { return ok(`${ctx.session.host}\n`); } };

const uname = {
  name: 'uname',
  async run(ctx, args) {
    const { flags, errors } = parseArgs(args, { flags: 'asrvmn' });
    if (errors.length) return usageErr('uname', errors);
    const k = ctx.session.machine.kernel || { release: '6.1.0-kali9-amd64', version: '#1 SMP PREEMPT_DYNAMIC', arch: 'x86_64' };
    const all = flags.has('a');
    const parts = [];
    if (all || flags.has('s') || !flags.size) parts.push('Linux');
    if (all || flags.has('n')) parts.push(ctx.session.host);
    if (all || flags.has('r')) parts.push(k.release);
    if (all || flags.has('v')) parts.push(k.version);
    if (all || flags.has('m')) parts.push(k.arch);
    if (all) parts.push('GNU/Linux');
    return ok(`${parts.join(' ')}\n`);
  },
};

const env = {
  name: 'env',
  async run(ctx) { return ok(Object.entries(ctx.session.env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n'); },
};

const exportCmd = {
  name: 'export',
  async run(ctx, args) {
    if (!args.length) return env.run(ctx);
    for (const a of args) {
      const m = /^([A-Za-z_]\w*)=(.*)$/s.exec(a);
      if (m) ctx.session.env[m[1]] = m[2];
    }
    return ok();
  },
};

const echo = {
  name: 'echo',
  async run(ctx, args) {
    let newline = true; let escapes = false;
    while (args[0] && /^-[neE]+$/.test(args[0])) {
      if (args[0].includes('n')) newline = false;
      if (args[0].includes('e')) escapes = true;
      if (args[0].includes('E')) escapes = false;
      args = args.slice(1);
    }
    let text = args.join(' ');
    if (escapes) text = text.replace(/\\(n|t|r|\\)/g, (_, c) => ({ n: '\n', t: '\t', r: '\r', '\\': '\\' }[c]));
    return ok(text + (newline ? '\n' : ''));
  },
};

const date = {
  name: 'date',
  async run() { return ok(`${new Date().toUTCString().replace(/^(\w+), (\d+) (\w+) (\d+) ([\d:]+) GMT$/, '$1 $3 $2 $5 UTC $4')}\n`); },
};

const history = {
  name: 'history',
  async run(ctx) {
    const items = ctx.history?.items || [];
    return ok(items.map((l, i) => `${String(i + 1).padStart(5)}  ${l}`).join('\n') + (items.length ? '\n' : ''));
  },
};

const clear = { name: 'clear', async run() { return { out: '', err: '', code: 0, clear: true }; } };

const exit = {
  name: 'exit',
  async run(ctx) {
    if (ctx.stack && ctx.stack.depth > 1) { ctx.stack.pop(); return { out: 'logout\n', err: '', code: 0, exit: true }; }
    return { out: 'ไม่สามารถปิด terminal หลักได้ (กดปุ่ม "กลับ Dashboard" เพื่อออก)\n', err: '', code: 0 };
  },
};

const trueCmd = { name: 'true', async run() { return ok(); } };
const falseCmd = { name: 'false', async run() { return { out: '', err: '', code: 1 }; } };

const help = {
  name: 'help',
  async run(ctx) {
    const groups = new Map();
    for (const c of ctx.registry.list()) {
      const doc = ctx.registry.doc(c.name);
      const cat = doc?.category || 'อื่น ๆ';
      if (!groups.has(cat)) groups.set(cat, []);
      groups.get(cat).push({ name: c.name, desc: doc?.summary || '' });
    }
    let out = 'คำสั่งที่ใช้ได้ (พิมพ์ `man <คำสั่ง>` เพื่อดูรายละเอียด, กด Tab เพื่อเติมคำสั่ง)\n';
    for (const [cat, items] of groups) {
      out += `\n\x1b[1;32m${cat}\x1b[0m\n`;
      for (const it of items) out += `  ${it.name.padEnd(10)} ${it.desc}\n`;
    }
    return ok(out);
  },
};

const man = {
  name: 'man',
  async run(ctx, args) {
    if (!args[0]) return { out: '', err: 'What manual page do you want?\nFor example, try `man ls`.\n', code: 1 };
    const text = ctx.registry.helpText(args[0]);
    if (!text) return { out: '', err: `No manual entry for ${args[0]}\n`, code: 16 };
    return ok(text);
  },
};

export const miscCommands = [whoami, id, hostname, uname, env, exportCmd, echo, date, history, clear, exit, trueCmd, falseCmd, help, man];
