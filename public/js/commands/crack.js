// Password-cracking tools: hashid, john, hashcat, zip2john, ssh2john, hydra.
// Everything here is comparison against hash functions in sim/hashlib.js over the tiny wordlists shipped
// with the game - there is no real cracking engine, no GPU, nothing that touches a real file or network.
import { FsError, normalize } from '../sim/vfs.js';
import { ALGORITHMS, md5, sha1, sha256, ntlm } from '../sim/hashlib.js';
import { parseArgs, usageErr, splitLines, fsFail } from './util.js';
import { expandTarget } from '../sim/network.js';

const ok = (out = '') => ({ out, err: '', code: 0 });
const fail = (err, code = 1) => ({ out: '', err, code });

// ---------------- shared: identify + crack a single hash string ----------------
// A "wrapped" hash (from zip2john/ssh2john) carries a plain SHA-256 of the real secret inside a
// recognisable envelope, so the same crack loop below handles database dumps and archive/key
// passphrases uniformly - only the *display* format differs, matching the real tools' conventions.
const WRAPPERS = [
  { re: /\$zip2\$\*.*?([0-9a-f]{64}).*?\$\/zip2\$/i, kind: 'ZIP' },
  { re: /\$sshng\$.*?([0-9a-f]{64})/i, kind: 'SSH-KEY' },
];

function identify(hash) {
  for (const w of WRAPPERS) { const m = w.re.exec(hash); if (m) return { kind: w.kind, algo: 'sha256', digest: m[1].toLowerCase() }; }
  const h = hash.trim().toLowerCase();
  if (/^[0-9a-f]{32}$/.test(h)) return { kind: 'MD5/NTLM', algo: null, digest: h }; // ambiguous without more context
  if (/^[0-9a-f]{40}$/.test(h)) return { kind: 'SHA1', algo: 'sha1', digest: h };
  if (/^[0-9a-f]{64}$/.test(h)) return { kind: 'SHA256', algo: 'sha256', digest: h };
  return null;
}

const FORMAT_ALGO = { 'raw-md5': 'md5', md5: 'md5', 'raw-sha1': 'sha1', sha1: 'sha1', 'raw-sha256': 'sha256', sha256: 'sha256', nt: 'ntlm', ntlm: 'ntlm' };
const HASHCAT_MODE = { 0: 'md5', 100: 'sha1', 1400: 'sha256', 1000: 'ntlm' };

/** Try every wordlist candidate against one digest. Returns the matching word, or null. */
function crackOne(digest, algo, words) {
  const fn = ALGORITHMS[algo];
  for (const w of words) if (fn(w) === digest) return w;
  return null;
}

function readWordlist(ctx, path) {
  const text = ctx.vfs.readFile(ctx.abs(path), ctx.user);
  return splitLines(text).filter(Boolean);
}

// ---------------- hashid ----------------
const hashid = {
  name: 'hashid',
  async run(ctx, args) {
    const { flags, values, rest, errors } = parseArgs(args, { flags: 'j', values: 'f' });
    if (errors.length) return usageErr('hashid', errors);
    let targets = rest;
    if (values.f) {
      try { targets = splitLines(ctx.vfs.readFile(ctx.abs(values.f), ctx.user)).filter(Boolean); }
      catch (e) { return fail(fsFail('hashid', values.f, e)); }
    }
    if (!targets.length) return fail('hashid: no hashes given (pass one as an argument or use -f <file>)\n', 1);
    let out = '';
    for (const h of targets) {
      out += `Analyzing '${h}'\n`;
      const info = identify(h);
      if (!info) { out += '[+] Unknown hash type\n\n'; continue; }
      if (info.kind === 'MD5/NTLM') {
        out += '[+] MD5\n[+] NTLM\n[+] MD4\n[+] Domain Cached Credentials\n';
        out += '[i] 32 hex characters matches several algorithms - context decides which one it really is (a web app\'s user table is usually MD5; a Windows SAM/NTDS dump is NTLM)\n\n';
      } else if (info.kind === 'SHA1') {
        out += '[+] SHA-1\n[+] RIPEMD-160\n\n';
      } else if (info.kind === 'SHA256') {
        out += '[+] SHA-256\n[+] GOST R 34.11-2012\n\n';
      } else if (info.kind === 'ZIP') {
        out += '[+] PKZIP (legacy) [zip2john format]\n\n';
      } else if (info.kind === 'SSH-KEY') {
        out += '[+] SSH Private Key [ssh2john format]\n\n';
      }
    }
    return ok(out);
  },
};

// ---------------- hash-file cracking shared by john/hashcat ----------------
function parseHashFile(text) {
  // Accepts "user:hash" (unshadowed-style) or a bare hash per line.
  return splitLines(text).filter(Boolean).map((line) => {
    const i = line.indexOf(':');
    const hasUser = i > 0 && !/^\$/.test(line) && !line.slice(0, i).includes('$');
    return hasUser ? { user: line.slice(0, i), hash: line.slice(i + 1) } : { user: null, hash: line };
  });
}

function loadHashFile(ctx, cmd, path) {
  try { return { rows: parseHashFile(ctx.vfs.readFile(ctx.abs(path), ctx.user)) }; }
  catch (e) { return { error: fsFail(cmd, path, e) }; }
}

const john = {
  name: 'john',
  async run(ctx, args) {
    const { values, rest, errors } = parseArgs(args, {});
    const forceFormat = args.find((a) => a.startsWith('--format='))?.slice('--format='.length).toLowerCase();
    const wordlistArg = args.find((a) => a.startsWith('--wordlist='))?.slice('--wordlist='.length);
    const hashFile = args.filter((a) => !a.startsWith('--')).pop();
    if (errors.length) return usageErr('john', errors);
    if (!hashFile) return fail('john: no password hashes loaded\n', 1);
    if (!wordlistArg) return fail("john: no wordlist given - use --wordlist=<path>\n", 1);
    const { rows, error } = loadHashFile(ctx, 'john', hashFile);
    if (error) return fail(error);
    let words;
    try { words = readWordlist(ctx, wordlistArg); } catch (e) { return fail(fsFail('john', wordlistArg, e)); }

    const results = [];
    let label = null;
    for (const row of rows) {
      const info = identify(row.hash);
      if (!info) continue;
      const algo = forceFormat ? FORMAT_ALGO[forceFormat] : info.algo;
      if (!algo) { results.push({ row, info, cracked: null, ambiguous: true }); continue; }
      label = label || (algo === 'ntlm' ? 'NT' : `Raw-${algo.toUpperCase()}`);
      const word = crackOne(info.digest, algo, words);
      results.push({ row, info, cracked: word });
    }
    const cracked = results.filter((r) => r.cracked);
    let out = 'Using default input encoding: UTF-8\n';
    if (results.some((r) => r.ambiguous)) out += "Warning: detected hash type \"MD5\", but the string is also recognized as \"NTLM\"\nUse the \"--format=NT\" option to force loading these as that type instead\n";
    out += `Loaded ${results.length} password hash${results.length === 1 ? '' : 'es'}${label ? ` (${label} [simulated])` : ''}\n`;
    out += "Press 'q' or Ctrl-C to abort, almost any other key for status\n";
    for (const r of cracked) out += `${r.cracked.padEnd(16)} (${r.row.user || r.info.kind})\n`;
    out += `${cracked.length}g 0:00:00:00 DONE (2026-11-15 10:00) ${cracked.length ? '100.0g/s' : '0g/s'} 1024p/s 1024c/s 1024C/s\n`;
    out += 'Use the "--show" option to display all of the cracked passwords reliably\n';
    out += `Session completed.\n`;
    return ok(out);
  },
};

const hashcat = {
  name: 'hashcat',
  async run(ctx, args) {
    const { values, rest, errors } = parseArgs(args, { values: 'ma' });
    if (errors.length) return usageErr('hashcat', errors);
    const positional = rest;
    if (!positional.length) return fail('hashcat: No hashes loaded.\n', 1);
    const [hashFile, wordlistArg] = positional;
    if (!wordlistArg) return fail('hashcat: no wordlist given\n', 1);
    const { rows, error } = loadHashFile(ctx, 'hashcat', hashFile);
    if (error) return fail(error);
    let words;
    try { words = readWordlist(ctx, wordlistArg); } catch (e) { return fail(fsFail('hashcat', wordlistArg, e)); }

    const modeAlgo = values.m !== undefined ? HASHCAT_MODE[Number(values.m)] : undefined;
    if (values.m !== undefined && !modeAlgo) return fail(`hashcat: invalid hash-mode specified: ${values.m}\n`, 1);

    let out = 'hashcat (v6.2.6) starting\n\n';
    const cracked = [];
    for (const row of rows) {
      const info = identify(row.hash);
      if (!info) continue;
      const algo = modeAlgo || info.algo;
      if (!algo) { out += `${row.hash}: Token length exception - try specifying -m to disambiguate (e.g. -m 0 for MD5, -m 1000 for NTLM)\n`; continue; }
      const word = crackOne(info.digest, algo, words);
      if (word) { cracked.push({ row, word }); out += `${row.hash}:${word}\n`; }
    }
    out += `\nSession..........: hashcat\nStatus...........: ${cracked.length ? 'Cracked' : 'Exhausted'}\nHash.Mode........: ${values.m ?? '(auto)'}\n`
      + `Recovered........: ${cracked.length}/${rows.length} (${rows.length ? ((cracked.length / rows.length) * 100).toFixed(2) : '0.00'}%)\n`;
    return ok(out);
  },
};

// ---------------- zip2john / ssh2john ----------------
function extractCrackable(ctx, cmd, path, wrapperKind, envelope) {
  const abs = ctx.abs(path);
  let node;
  try { node = ctx.vfs.resolve(abs, ctx.user); } catch (e) { return { error: fsFail(cmd, path, e) }; }
  if (node.type === 'dir') return { error: `${cmd}: ${path}: Is a directory\n` };
  const sha = /##CRACKHASH:([0-9a-f]{64})##/.exec(node.content || '');
  if (!sha) return { error: `${cmd}: ${path}: not a recognised ${wrapperKind === 'ZIP' ? 'zip archive' : 'SSH private key'} (no password protection detected)\n` };
  const name = path.split('/').pop();
  return { line: envelope(name, sha[1]) };
}

const zip2john = {
  name: 'zip2john',
  async run(ctx, args) {
    if (!args.length) return fail('zip2john: usage: zip2john [zip files] ...\n', 1);
    let out = ''; let err = '';
    for (const f of args) {
      const r = extractCrackable(ctx, 'zip2john', f, 'ZIP', (name, hex) => `${name}:$zip2$*0*3*0*${hex.slice(0, 20)}*2c*8*${hex}*${hex.slice(0, 20)}*$/zip2$::${name}`);
      if (r.error) { err += r.error; continue; }
      out += `${r.line}\n`;
      err += `ver 2.0 efh 5455 efh 7875 ${f}/PK.SFX.MANIFEST.txt PKZIP Encr: TS_chk, cmplen=20, decmplen=10, crc=00000000 ts=0000 cs=0000 type=8\n`;
    }
    return { out, err, code: 0 };
  },
};

const ssh2john = {
  name: 'ssh2john',
  async run(ctx, args) {
    if (!args.length) return fail('ssh2john: usage: ssh2john [keyfiles] ...\n', 1);
    let out = '';
    for (const f of args) {
      const r = extractCrackable(ctx, 'ssh2john', f, 'SSH-KEY', (name, hex) => `${name}:$sshng$1$16$0000000000000000000000000000000$${hex.length}$${hex}`);
      if (r.error) return fail(r.error);
      out += `${r.line}\n`;
    }
    return ok(out);
  },
};

// ---------------- hydra ----------------
const SERVICE_PORT = { ftp: 21, ssh: 22 };

function ftpAccounts(world, ip) {
  const data = world.host(ip)?.ftp;
  return data?.accounts ? { ...data.accounts } : {};
}

const hydra = {
  name: 'hydra',
  async run(ctx, args) {
    const { values, flags, rest, errors } = parseArgs(args, { flags: 'VIf', values: 'lLpPs' });
    if (errors.length) return usageErr('hydra', errors);
    const [targetSpec, service] = rest;
    if (!targetSpec || !service) return fail('Hydra: error: Missing target/service\nSyntax: hydra [options] server service\n', 255);
    if (!(service in SERVICE_PORT)) return fail(`Hydra: error: service ${service} is not supported in this simulator (supported: ftp, ssh)\n`, 255);
    if (!values.L) return fail('hydra: a username list is required: -L <userlist>\n', 255);
    if (!values.P) return fail('hydra: a password list is required: -P <passlist>\n', 255);

    const world = ctx.session.world;
    if (!world) return fail('hydra: network is unreachable\n', 1);
    const target = expandTarget(targetSpec, world);
    if (target.error) return fail(`Hydra: error: ${target.error}\n`, 255);
    const ip = target.ips[0];
    const port = SERVICE_PORT[service];
    const state = world.portState(ip, port);
    if (state !== 'open') return fail(`[ERROR] could not connect to target ${ip}:${port}\n`, 1);

    let users; let passwords;
    try { users = readWordlist(ctx, values.L); } catch (e) { return fail(fsFail('hydra', values.L, e)); }
    try { passwords = readWordlist(ctx, values.P); } catch (e) { return fail(fsFail('hydra', values.P, e)); }
    if (users.length * passwords.length > 20000) return fail('hydra: userlist x passlist is too large for this simulator (keep it under 20000 combinations)\n', 1);

    const accounts = service === 'ftp' ? ftpAccounts(world, ip) : {};
    const found = [];
    for (const u of users) for (const p of passwords) if (accounts[u] === p) found.push({ u, p });

    let out = `Hydra v9.5 (c) 2023 by van Hauser/THC - for legal purposes only\n\n`
      + `Hydra starting at 2026-11-15 10:00:00\n[DATA] max 1 task per 1 server, overall 1 task, ${users.length * passwords.length} login tries (l:${users.length}/p:${passwords.length}), ~${Math.ceil((users.length * passwords.length) / 1)} tries per task\n`
      + `[DATA] attacking ${service}://${ip}:${port}/\n`;
    for (const { u, p } of found) out += `[${port}][${service}] host: ${ip}   login: ${u}   password: ${p}\n`;
    out += `1 of 1 target ${found.length ? 'successfully completed' : 'completed, 0 valid passwords found'}, ${found.length} valid password${found.length === 1 ? '' : 's'} found\n`
      + `Hydra finished at 2026-11-15 10:00:0${found.length ? '1' : '5'}\n`;
    ctx.bus?.emit('net', { kind: 'connect', ip, session: ctx.session, port });
    ctx.bus?.emit('game', { name: 'hydra.run', session: ctx.session, host: ip, service, found: found.length });
    return { out, err: '', code: found.length ? 0 : 1 };
  },
};

export const crackCommands = [hashid, john, hashcat, zip2john, ssh2john, hydra];
