import { normalize, join, canAccess } from '../sim/vfs.js';

/**
 * Tab completion for the last word of `line`.
 * Returns { line, options } — `line` is the (possibly extended) input; `options` lists
 * candidates when the completion is ambiguous.
 */
export function complete(line, session, commandNames) {
  const m = /([^\s|;&]*)$/.exec(line);
  const word = m[1];
  const start = line.length - word.length;
  const before = line.slice(0, start);
  const isCommand = /^\s*$/.test(before) || /[|;&]\s*$/.test(before);

  let candidates = [];
  let suffixFor = () => ' ';
  let prefix = '';

  if (isCommand && !word.includes('/')) {
    candidates = commandNames.filter((n) => n.startsWith(word));
  } else {
    const slash = word.lastIndexOf('/');
    const dirPart = slash >= 0 ? word.slice(0, slash + 1) : '';
    const base = word.slice(slash + 1);
    const dirAbs = normalize(dirPart || '.', session.cwd);
    const node = session.vfs.get(dirAbs);
    if (node?.type === 'dir' && canAccess(node, session.user, 4)) {
      candidates = session.vfs.names(dirAbs).filter((n) => n.startsWith(base) && (base.startsWith('.') || !n.startsWith('.')));
      suffixFor = (name) => (session.vfs.get(join(dirAbs, name)).type === 'dir' ? '/' : ' ');
    }
    prefix = dirPart;
  }

  if (!candidates.length) return { line, options: [] };
  if (candidates.length === 1) {
    return { line: before + prefix + candidates[0] + suffixFor(candidates[0]), options: [] };
  }
  let common = candidates[0];
  for (const c of candidates) while (!c.startsWith(common)) common = common.slice(0, -1);
  const nextLine = before + prefix + common;
  return { line: nextLine, options: nextLine === line ? candidates : [] };
}
