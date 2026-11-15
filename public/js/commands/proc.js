// Process and socket listing: ps, ss, netstat. Data comes from machine.processes / machine.listening.
import { parseArgs, usageErr } from './util.js';

const ok = (out = '') => ({ out, err: '', code: 0 });

const DEFAULT_PROCESSES = [
  { user: 'root', pid: 1, ppid: 0, cpu: 0.0, mem: 0.1, vsz: 168940, rss: 11620, tty: '?', stat: 'Ss', start: '09:00', time: '0:02', cmd: '/sbin/init' },
];

const processesOf = (machine) => machine.processes || DEFAULT_PROCESSES;

/** Rows for the player's own shell + the ps command, so `ps aux` shows "you" like the real thing. */
function ownRows(session, stackDepth) {
  const base = 4100 + stackDepth * 10;
  return [
    { user: session.user.name, pid: base, ppid: 1, cpu: 0.0, mem: 0.1, vsz: 8196, rss: 5120, tty: 'pts/0', stat: 'Ss', start: '14:20', time: '0:00', cmd: '-bash' },
    { user: session.user.name, pid: base + 1, ppid: base, cpu: 0.0, mem: 0.0, vsz: 10064, rss: 3328, tty: 'pts/0', stat: 'R+', start: '14:21', time: '0:00', cmd: 'ps' },
  ];
}

const ps = {
  name: 'ps',
  async run(ctx, args) {
    const all = args.join(' ');
    const session = ctx.session;
    const own = ownRows(session, ctx.stack?.depth ?? 1);
    if (!args.length) {
      return ok(`    PID TTY          TIME CMD\n${own.map((p) => `${String(p.pid).padStart(7)} pts/0    00:00:00 ${p.cmd.replace(/^-/, '')}`).join('\n')}\n`);
    }
    const list = [...processesOf(session.machine), ...own];
    if (/(^|\s)-?[a-z]*ef\b|(^|\s)-ef/.test(all)) {
      let out = 'UID          PID    PPID  C STIME TTY          TIME CMD\n';
      for (const p of list) out += `${p.user.slice(0, 8).padEnd(8)} ${String(p.pid).padStart(7)} ${String(p.ppid ?? 1).padStart(7)}  0 ${p.start} ${p.tty.padEnd(8)} 00:${(p.time || '0:00').padStart(5, '0')} ${p.cmd}\n`;
      return ok(out);
    }
    if (/(^|\s)-?[a-z]*(aux|ax|e)\b/.test(all)) {
      let out = 'USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n';
      for (const p of list) {
        out += `${p.user.slice(0, 8).padEnd(8)} ${String(p.pid).padStart(7)} ${p.cpu.toFixed(1).padStart(4)} ${p.mem.toFixed(1).padStart(4)} ${String(p.vsz).padStart(6)} ${String(p.rss).padStart(5)} ${p.tty.padEnd(8)} ${p.stat.padEnd(4)} ${p.start.padEnd(5)} ${(p.time || '0:00').padStart(6)} ${p.cmd}\n`;
      }
      return ok(out);
    }
    return { out: '', err: `error: unsupported option (BSD syntax)\nUsage:\n ps [options]\n\n Try 'ps --help <simple|list|output|threads|misc|all>'\n  or 'ps --help <s|l|o|t|m|a>'\n for additional help text.\n`, code: 1 };
  },
};

/** Which listening sockets match the t/u filters? */
function sockets(machine, { tcp, udp }) {
  const all = machine.listening || [];
  const wantAll = !tcp && !udp;
  return all.filter((s) => wantAll || (tcp && s.proto === 'tcp') || (udp && s.proto === 'udp'));
}

/** Process info is only visible for your own processes unless you are root — just like the real thing. */
function visibleProc(machine, session, sock) {
  const proc = processesOf(machine).find((p) => p.pid === sock.pid);
  if (!proc) return null;
  if (session.user.uid !== 0 && proc.user !== session.user.name) return null;
  return proc;
}

const progName = (p) => p.cmd.split(' ')[0].split('/').pop();

const ss = {
  name: 'ss',
  async run(ctx, args) {
    const { flags, errors } = parseArgs(args, { flags: 'tulnpa4' });
    if (errors.length) return usageErr('ss', errors);
    const listening = flags.has('l') || flags.has('a');
    const rows = listening ? sockets(ctx.session.machine, { tcp: flags.has('t'), udp: flags.has('u') }) : [];
    const showProc = flags.has('p');
    let out = `Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port${showProc ? '  Process' : ''}\n`;
    for (const s of rows) {
      const proc = showProc ? visibleProc(ctx.session.machine, ctx.session, s) : null;
      const procCol = proc ? `  users:(("${progName(proc)}",pid=${proc.pid},fd=${s.fd ?? 3}))` : '';
      out += `${s.proto.padEnd(6)} ${(s.proto === 'tcp' ? 'LISTEN' : 'UNCONN').padEnd(7)} 0       ${String(s.proto === 'tcp' ? 128 : 0).padEnd(8)} ${`${s.addr}:${s.port}`.padStart(15)}   ${(s.addr.includes(':') ? '[::]:*' : '0.0.0.0:*').padStart(12)}${procCol}\n`;
    }
    return ok(out);
  },
};

const netstat = {
  name: 'netstat',
  async run(ctx, args) {
    const { flags, errors } = parseArgs(args, { flags: 'tulnpa' });
    if (errors.length) return usageErr('netstat', errors);
    const rows = sockets(ctx.session.machine, { tcp: flags.has('t'), udp: flags.has('u') });
    const showProc = flags.has('p');
    let out = 'Active Internet connections (only servers)\n'
      + `Proto Recv-Q Send-Q Local Address           Foreign Address         State       ${showProc ? 'PID/Program name' : ''}\n`;
    for (const s of rows) {
      const proc = showProc ? visibleProc(ctx.session.machine, ctx.session, s) : null;
      const pcol = showProc ? (proc ? `${proc.pid}/${progName(proc)}` : '-') : '';
      out += `${s.proto.padEnd(5)} ${'0'.padStart(6)} ${'0'.padStart(6)} ${`${s.addr}:${s.port}`.padEnd(23)} ${(s.proto === 'tcp' ? '0.0.0.0:*' : '0.0.0.0:*').padEnd(23)} ${(s.proto === 'tcp' ? 'LISTEN' : '').padEnd(11)} ${pcol}\n`;
    }
    const err = showProc && ctx.session.user.uid !== 0
      ? '(Not all processes could be identified, non-owned process info\n will not be shown, you would have to be root to see it all.)\n'
      : '';
    return { out, err, code: 0 };
  },
};

export const procCommands = [ps, ss, netstat];
