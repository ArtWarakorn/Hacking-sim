import { FsError } from '../sim/vfs.js';

/**
 * Small getopt. spec.flags: boolean short flags ('lah'); spec.values: short flags taking a value ('n');
 * spec.numeric: accept -5 as n=5. Long options land in `long`.
 */
export function parseArgs(args, { flags = '', values = '', numeric = false } = {}) {
  const out = { flags: new Set(), values: {}, long: new Set(), rest: [], errors: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--') { out.rest.push(...args.slice(i + 1)); break; }
    if (a.startsWith('--') && a.length > 2) { out.long.add(a.slice(2)); continue; }
    if (a.length > 1 && a[0] === '-' && a[1] !== '-') {
      if (numeric && /^-\d+$/.test(a)) { out.values.n = a.slice(1); continue; }
      for (let j = 1; j < a.length; j++) {
        const c = a[j];
        if (flags.includes(c)) out.flags.add(c);
        else if (values.includes(c)) {
          const tail = a.slice(j + 1);
          if (tail) out.values[c] = tail;
          else {
            out.values[c] = args[++i];
            if (out.values[c] === undefined) out.errors.push(`option requires an argument -- '${c}'`);
          }
          break;
        } else out.errors.push(`invalid option -- '${c}'`);
      }
      continue;
    }
    out.rest.push(a);
  }
  return out;
}

export const usageErr = (cmd, errors) => ({
  out: '', err: `${cmd}: ${errors[0]}\nTry '${cmd} --help' for more information.\n`, code: 2,
});

export const splitLines = (text) => {
  const lines = text.split('\n');
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines;
};

/** Format a filesystem failure the way coreutils does: "cmd: arg: Message". Rethrows non-fs errors. */
export function fsFail(cmd, arg, e) {
  if (!(e instanceof FsError)) throw e;
  return `${cmd}: ${arg}: ${e.msg}\n`;
}
