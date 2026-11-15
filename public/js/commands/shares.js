// File-sharing services: ftp and smbclient (interactive), enum4linux and crackmapexec (one-shot).
import { FsError, normalize } from '../sim/vfs.js';
import { expandTarget } from '../sim/network.js';

const ok = (out = '') => ({ out, err: '', code: 0 });
const fail = (err, code = 1) => ({ out: '', err, code });
const emitNet = (ctx, kind, ip, extra = {}) => ctx.bus?.emit('net', { kind, ip, session: ctx.session, ...extra });
const game = (ctx, name, data) => ctx.bus?.emit('game', { name, session: ctx.session, ...data });
const sizeOfFile = (s) => new TextEncoder().encode(s).length;

/** Resolve a /-separated path inside a nested { name: content | {dir} } tree. */
function lookup(tree, parts) {
  let node = tree;
  for (const p of parts) {
    if (node === null || typeof node !== 'object' || !(p in node)) return undefined;
    node = node[p];
  }
  return node;
}
/** Apply a possibly-relative path to a cwd (array of names). Returns the new parts array. */
function applyPath(cwd, path, sep = '/') {
  const parts = path.startsWith(sep) ? [] : [...cwd];
  for (const seg of path.split(sep).filter(Boolean)) {
    if (seg === '.') continue;
    if (seg === '..') parts.pop(); else parts.push(seg);
  }
  return parts;
}
const isDir = (n) => n !== null && typeof n === 'object';

// ======================= ftp =======================
function ftpListing(node) {
  return Object.entries(node).map(([name, v]) => {
    const dir = isDir(v);
    return `${dir ? 'drwxr-xr-x' : '-rw-r--r--'}    ${dir ? 2 : 1} 0        0 ${String(dir ? 4096 : sizeOfFile(v)).padStart(15)} Oct 12 09:0${dir ? 2 : 0} ${name}`;
  }).join('\n');
}

const FTP_HELP = 'Commands may be abbreviated.  Commands are:\n\nascii   bye     binary  cd      dir     exit    get     help    ls      passive pwd     quit\n';

function ftpShell(ctx, ip, data, authed) {
  let cwd = [];
  const here = () => lookup(data.tree, cwd);
  return {
    name: 'ftp',
    prompt: 'ftp> ',
    async onLine(line) {
      const [cmd, ...rest] = line.trim().split(/\s+/);
      const args = rest.filter((a) => !a.startsWith('-')); // ls -la etc: flags are accepted and ignored
      if (!cmd) return { out: '' };
      if (['bye', 'quit', 'exit'].includes(cmd)) return { out: '221 Goodbye.\n', done: true };
      if (['help', '?'].includes(cmd)) return { out: FTP_HELP };
      if (['ascii', 'binary'].includes(cmd)) return { out: `200 Switching to ${cmd === 'ascii' ? 'ASCII' : 'Binary'} mode.\n` };
      if (['passive', 'prompt', 'status'].includes(cmd)) return { out: cmd === 'passive' ? 'Passive mode: off; fallback to active mode: off.\n' : '' };
      if (!authed) return { out: '530 Please login with USER and PASS.\n' };
      switch (cmd) {
        case 'pwd': return { out: `Remote directory: /${cwd.join('/')}\n` };
        case 'ls': case 'dir': {
          const node = args[0] ? lookup(data.tree, applyPath(cwd, args[0])) : here();
          if (node === undefined) return { out: '550 Failed to open file.\n' };
          const body = isDir(node) ? ftpListing(node) : `-rw-r--r--    1 0        0 ${String(sizeOfFile(node)).padStart(15)} Oct 12 09:00 ${args[0]}`;
          return { out: `229 Entering Extended Passive Mode (|||10234|)\n150 Here comes the directory listing.\n${body}${body ? '\n' : ''}226 Directory send OK.\n` };
        }
        case 'cd': {
          if (!args[0]) return { out: '?Invalid command.\n' };
          const parts = applyPath(cwd, args[0]);
          if (!isDir(lookup(data.tree, parts))) return { out: '550 Failed to change directory.\n' };
          cwd = parts;
          return { out: '250 Directory successfully changed.\n' };
        }
        case 'get': {
          if (!args[0]) return { out: '(remote-file) usage: get remote-file [local-file]\n' };
          const remote = applyPath(cwd, args[0]);
          const local = args[1] || remote[remote.length - 1];
          const node = lookup(data.tree, remote);
          const header = `local: ${local} remote: ${args[0]}\n`;
          if (node === undefined || isDir(node)) return { out: `${header}229 Entering Extended Passive Mode (|||10261|)\n550 Failed to open file.\n` };
          try { ctx.vfs.writeFile(normalize(local, ctx.session.cwd), node, ctx.user); }
          catch (e) {
            if (!(e instanceof FsError)) throw e;
            return { out: `local: ${local}: ${e.msg}\n` };
          }
          game(ctx, 'ftp.get', { host: ip, file: remote[remote.length - 1] });
          const n = sizeOfFile(node);
          return { out: `${header}229 Entering Extended Passive Mode (|||10261|)\n150 Opening BINARY mode data connection for ${args[0]} (${n} bytes).\n226 Transfer complete.\n${n} bytes received in 00:00 (${(n / 1.8).toFixed(2)} KiB/s)\n` };
        }
        default: return { out: '?Invalid command.\n' };
      }
    },
  };
}

const ftp = {
  name: 'ftp',
  async run(ctx, args) {
    const target = args.find((a) => !a.startsWith('-'));
    if (!target) return fail('ftp: usage: ftp [-pinegvd] [host [port]]\n', 1);
    const world = ctx.session.world;
    if (!world) return fail(`ftp: ${target}: Temporary failure in name resolution\n`, 1);
    const r = world.resolve(target);
    if (!r) return fail(`ftp: ${target}: Name or service not known\n`, 1);
    emitNet(ctx, 'ftp', r.ip);
    const state = world.portState(r.ip, 21);
    if (state !== 'open') return fail(`ftp: Can't connect to \`${r.ip}:21': ${state === 'closed' ? 'Connection refused' : 'Connection timed out'}\n`, 1);
    const svc = world.service(r.ip, 21);
    const data = world.host(r.ip)?.ftp || { anonymous: false, tree: {} };
    const user = ctx.user.name;

    const passwordStep = (name) => ({
      name: 'ftp', prompt: 'Password: ', secret: true,
      async onLine(pw) {
        const good = (['anonymous', 'ftp'].includes(name) && data.anonymous) || data.accounts?.[name] === pw;
        game(ctx, 'ftp.login', { host: r.ip, user: name, ok: good });
        if (!good) return { out: '530 Login incorrect.\nLogin failed.\n', interactive: ftpShell(ctx, r.ip, data, false) };
        return { out: '230 Login successful.\nRemote system type is UNIX.\nUsing binary mode to transfer files.\n', interactive: ftpShell(ctx, r.ip, data, true) };
      },
    });
    const nameStep = {
      name: 'ftp', prompt: `Name (${target}:${user}): `,
      async onLine(line) {
        const name = line.trim() || user;
        // CVE-2011-2523: vsftpd 2.3.4 contains a backdoor triggered by a ":)" smiley in the USER command -
        // it silently opens a root shell on port 6200 instead of continuing the login, and the FTP
        // connection itself just hangs from here (real write-ups describe exactly this).
        if (data.backdoor && name.includes(':)')) {
          const host = world.host(r.ip);
          if (host) host.services['6200'] = { name: 'shell', banner: 'root@legacy01:/# ' };
          game(ctx, 'ftp.backdoor', { host: r.ip, trigger: name });
          return { out: '', err: '', code: 0, done: true };
        }
        return { out: '331 Please specify the password.\n', interactive: passwordStep(name) };
      },
    };
    return { out: `Connected to ${target}.\n${svc.banner || '220 FTP server ready.'}\n`, err: '', code: 0, interactive: nameStep };
  },
};

// ======================= smbclient =======================
const SMB_DATE = 'Tue Nov 10 10:00:00 2026';
const tabs = (s) => `\t${s}`;

function smbList(smb) {
  const rows = Object.entries(smb.shares).map(([n, s]) => tabs(`${n.padEnd(15)} ${s.type.padEnd(9)} ${s.comment}`));
  return `\n${tabs('Sharename       Type      Comment')}\n${tabs('---------       ----      -------')}\n${rows.join('\n')}\nSMB1 disabled -- no workgroup available\n`;
}

function validUser(smb, user, pass) {
  if (!user || ['guest', 'anonymous'].includes(user)) return true; // null / guest session
  return Object.values(smb.shares).some((s) => s.credentials?.[user] === pass);
}

function smbShell(ctx, ip, shareName, share) {
  let cwd = [];
  const prompt = () => `smb: \\${cwd.join('\\')}${cwd.length ? '\\' : ''}> `;
  const state = {
    name: 'smbclient',
    get prompt() { return prompt(); },
    async onLine(line) {
      const [cmd, ...rest] = line.trim().split(/\s+/);
      const arg = rest.join(' ');
      if (!cmd) return { out: '' };
      if (['exit', 'quit', 'q'].includes(cmd)) return { out: '', done: true };
      if (['help', '?'].includes(cmd)) return { out: 'ls  dir  cd  pwd  get  lcd  help  exit  quit\n' };
      if (['ls', 'dir'].includes(cmd)) {
        const node = arg ? lookup(share.tree || {}, applyPath(cwd, arg, '\\')) : lookup(share.tree || {}, cwd);
        if (!isDir(node)) return { out: `NT_STATUS_NO_SUCH_FILE listing \\${arg}\n` };
        const row = (n, attr, size) => `  ${n.padEnd(35)}${attr.padStart(2)} ${String(size).padStart(8)}  ${SMB_DATE}`;
        const lines = [row('.', 'D', 0), row('..', 'D', 0), ...Object.entries(node).map(([n, v]) => (isDir(v) ? row(n, 'D', 0) : row(n, 'N', sizeOfFile(v))))];
        return { out: `${lines.join('\n')}\n\n\t\t7158264 blocks of size 1024. 3254512 blocks available\n` };
      }
      if (cmd === 'pwd') return { out: `Current directory is \\\\${ip}\\${shareName}\\${cwd.join('\\')}${cwd.length ? '\\' : ''}\n` };
      if (cmd === 'cd') {
        const parts = applyPath(cwd, arg || '\\', '\\');
        if (!isDir(lookup(share.tree || {}, parts))) return { out: `cd \\${arg}: NT_STATUS_OBJECT_NAME_NOT_FOUND\n` };
        cwd = parts;
        return { out: '' };
      }
      if (cmd === 'lcd') return { out: `the local directory is now ${ctx.session.cwd}\n` };
      if (cmd === 'get') {
        if (!arg) return { out: 'get <filename> [localname]\n' };
        const [remoteArg, localArg] = rest;
        const remote = applyPath(cwd, remoteArg, '\\');
        const node = lookup(share.tree || {}, remote);
        if (node === undefined || isDir(node)) return { out: `NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \\${remote.join('\\')}\n` };
        const local = localArg || remote[remote.length - 1];
        try { ctx.vfs.writeFile(normalize(local, ctx.session.cwd), node, ctx.user); }
        catch (e) {
          if (!(e instanceof FsError)) throw e;
          return { out: `NT_STATUS_ACCESS_DENIED opening local file ${local}\n` };
        }
        game(ctx, 'smb.get', { host: ip, share: shareName, file: remote[remote.length - 1] });
        const n = sizeOfFile(node);
        return { out: `getting file \\${remote.join('\\')} of size ${n} as ${local} (${(n / 1.2 / 1024).toFixed(1)} KiloBytes/sec) (average ${(n / 1.2 / 1024).toFixed(1)} KiloBytes/sec)\n` };
      }
      return { out: `${cmd}: command not found\n` };
    },
  };
  return state;
}

const smbclient = {
  name: 'smbclient',
  async run(ctx, args) {
    let list = false; let noPass = false; let user = null; let pass = null; let spec = null;
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a === '-L' || a === '--list') { list = true; if (args[i + 1] && !args[i + 1].startsWith('-')) spec = args[++i]; }
      else if (a.startsWith('-L') && a.length > 2) { list = true; spec = a.slice(2); }
      else if (a === '-N' || a === '--no-pass') noPass = true;
      else if (a === '-U' || a === '--user') { const [u, ...p] = (args[++i] || '').split('%'); user = u; if (p.length) pass = p.join('%'); }
      else if (/^-U./.test(a)) { const [u, ...p] = a.slice(2).split('%'); user = u; if (p.length) pass = p.join('%'); }
      else if (a === '-W' || a === '-m' || a === '-I') i++;
      else if (!a.startsWith('-')) spec = spec ?? a;
    }
    if (!spec) return fail('Usage: smbclient [-?EgBVNkPeC] [-?|--help] [--usage] [-R|--name-resolve=NAME-RESOLVE-ORDER] [-M|--message=HOST]\n        [-I|--ip-address=IP] [-L|--list=HOST] [-T|--tar=<c|x>IXFqgbNan] service <password>\n', 1);
    const m = /^(?:\/\/|\\\\)([^/\\]+)(?:[/\\](.+))?$/.exec(spec);
    const hostSpec = m ? m[1] : spec;
    const shareName = m?.[2];
    const world = ctx.session.world;
    if (!world) return fail('Connection failed (Error NT_STATUS_NETWORK_UNREACHABLE)\n', 1);
    const r = world.resolve(hostSpec);
    if (!r) return fail(`do_connect: Connection to ${hostSpec} failed (Error NT_STATUS_UNSUCCESSFUL)\n`, 1);
    emitNet(ctx, 'smb', r.ip);
    const port = [445, 139].find((p) => world.portState(r.ip, p) === 'open');
    const smb = world.host(r.ip)?.smb;
    if (!port || !smb) {
      const st = world.portState(r.ip, 445);
      return fail(`do_connect: Connection to ${hostSpec} failed (Error ${st === 'filtered' ? 'NT_STATUS_IO_TIMEOUT' : 'NT_STATUS_CONNECTION_REFUSED'})\n`, 1);
    }

    const proceed = (password) => {
      if (!validUser(smb, user, password)) return fail('session setup failed: NT_STATUS_LOGON_FAILURE\n', 1);
      if (list || !shareName) return ok(smbList(smb));
      const share = smb.shares[shareName];
      if (!share || share.type === 'IPC') {
        const bad = !share;
        game(ctx, 'smb.connect', { host: r.ip, share: shareName, user: user || '', ok: false });
        return fail(bad ? 'tree connect failed: NT_STATUS_BAD_NETWORK_NAME\n' : 'tree connect failed: NT_STATUS_ACCESS_DENIED\n', 1);
      }
      const allowed = share.anonymous || (user && share.credentials?.[user] === password);
      game(ctx, 'smb.connect', { host: r.ip, share: shareName, user: user || '', ok: Boolean(allowed) });
      if (!allowed) return fail('tree connect failed: NT_STATUS_ACCESS_DENIED\n', 1);
      return { out: 'Try "help" to get a list of possible commands.\n', err: '', code: 0, interactive: smbShell(ctx, r.ip, shareName, share) };
    };

    if (noPass || pass !== null) return proceed(pass ?? '');
    return {
      out: '', err: '', code: 0,
      interactive: {
        name: 'smbclient', prompt: `Password for [${smb.workgroup}\\${ctx.user.name}]:`, secret: true,
        async onLine(pw) { const res = proceed(pw); return { ...res, done: !res.interactive }; },
      },
    };
  },
};

// ======================= enum4linux =======================
const enum4linux = {
  name: 'enum4linux',
  async run(ctx, args) {
    const flags = new Set(args.filter((a) => a.startsWith('-')).flatMap((a) => (a.length > 1 ? [...a.slice(1)] : [])));
    const target = args.find((a) => !a.startsWith('-'));
    if (!target) return fail('enum4linux v0.9.1 (http://labs.portcullis.co.uk/application/enum4linux/)\nUsage: ./enum4linux.pl [options] ip\n', 1);
    const world = ctx.session.world;
    if (!world) return fail('enum4linux: network is unreachable\n', 1);
    const r = world.resolve(target);
    if (!r) return fail(`Unable to resolve ${target}\n`, 1);
    emitNet(ctx, 'smb', r.ip);
    const smb = world.host(r.ip)?.smb;
    const bar = (t) => `\n ${'='.repeat(9)}( ${t} )${'='.repeat(9)}\n\n`;
    let out = `Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on ${new Date().toUTCString()}\n${bar(`Target Information`)}Target ........... ${r.ip}\nRID Range ........ 500-550,1000-1050\nUsername ......... ''\nPassword ......... ''\nKnown Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none\n`;
    if (!smb) {
      return ok(`${out}${bar(`Enumerating Workgroup/Domain on ${r.ip}`)}[E] Can't find workgroup/domain\n\n\nenum4linux complete on ${new Date().toUTCString()}\n`);
    }
    game(ctx, 'enum4linux.run', { host: r.ip });
    const all = flags.has('a') || (!flags.has('U') && !flags.has('S'));
    out += `${bar(`Enumerating Workgroup/Domain on ${r.ip}`)}[+] Got domain/workgroup name: ${smb.workgroup}\n`;
    if (all || flags.has('S')) {
      out += `${bar(`Share Enumeration on ${r.ip}`)}${smbList(smb).replace(/^\n/, '')}\n[+] Attempting to map shares on ${r.ip}\n`;
      for (const [n, s] of Object.entries(smb.shares)) {
        const status = s.type === 'IPC' ? 'Mapping: OK Listing: DENIED Writing: N/A' : s.anonymous ? 'Mapping: OK Listing: OK Writing: N/A' : 'Mapping: DENIED Listing: N/A Writing: N/A';
        out += `//${r.ip}/${n}\t${status}\n`;
      }
    }
    if (all || flags.has('U')) {
      out += `${bar(`Users on ${r.ip}`)}`;
      smb.users.forEach((u, i) => { out += `index: 0x${(i + 1).toString(16)} RID: 0x${u.rid.toString(16)} acb: 0x00000010 Account: ${u.name}\tName: \tDesc: \n`; });
      out += `\nuser:[${smb.users.map((u) => u.name).join(']\nuser:[')}]\n`;
      out += `${bar(`Getting local user list via RID cycling on ${r.ip}`)}${smb.users.map((u) => `S-1-22-1-${u.rid} Unix User\\${u.name} (Local User)`).join('\n')}\n`;
    }
    return ok(`${out}\nenum4linux complete on ${new Date().toUTCString()}\n`);
  },
};

// ======================= crackmapexec =======================
const crackmapexec = {
  name: 'crackmapexec',
  async run(ctx, args) {
    const [proto, ...rest] = args;
    if (proto !== 'smb') return fail('usage: crackmapexec [-h] {smb} ... (only the smb protocol is available here)\n', 1);
    let user = null; let pass = null; let shares = false;
    const targets = [];
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === '-u') user = rest[++i];
      else if (rest[i] === '-p') pass = rest[++i];
      else if (rest[i] === '--shares') shares = true;
      else if (!rest[i].startsWith('-')) targets.push(rest[i]);
    }
    if (!targets.length) return fail('usage: crackmapexec smb [-h] [-u USERNAME] [-p PASSWORD] [--shares] target [target ...]\n', 1);
    const world = ctx.session.world;
    if (!world) return fail('crackmapexec: network is unreachable\n', 1);
    let out = '';
    for (const t of targets) {
      const ex = expandTarget(t, world);
      if (ex.error) { out += `[-] ${ex.error}\n`; continue; }
      for (const ip of ex.ips) {
        const smb = world.host(ip)?.smb;
        if (!smb || world.portState(ip, 445) !== 'open') continue;
        emitNet(ctx, 'smb', ip);
        const line = (msg) => `SMB         ${ip.padEnd(15)} 445    ${smb.netbios.padEnd(16)} ${msg}\n`;
        out += line(`[*] Unix (name:${smb.netbios}) (domain:${smb.workgroup}) (signing:False) (SMBv1:False)`);
        if (user === null) continue;
        const good = validUser(smb, user, pass ?? '');
        out += line(good ? `[+] ${smb.workgroup}\\${user}:${pass ?? ''}` : `[-] ${smb.workgroup}\\${user}:${pass ?? ''} STATUS_LOGON_FAILURE`);
        if (good && shares) {
          out += line('[*] Enumerated shares') + line('Share           Permissions     Remark') + line('-----           -----------     ------');
          for (const [n, s] of Object.entries(smb.shares)) {
            const perm = s.anonymous || (user && s.credentials?.[user] === pass) ? 'READ' : '';
            out += line(`${n.padEnd(15)} ${perm.padEnd(15)} ${s.comment}`);
          }
        }
      }
    }
    return ok(out);
  },
};

export const shareCommands = [ftp, smbclient, enum4linux, crackmapexec];
