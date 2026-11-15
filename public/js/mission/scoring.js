// XP, hints and ranks. Pure functions — no DOM, no storage.

/**
 * Hints and scope violations cost XP (together at most 60% of the mission). Each distinct out-of-scope host
 * you touched costs 20%. The +10% "clean run" bonus needs zero hints AND zero violations.
 */
export function computeScore({ xp, hintCost = 0, hintsUsed = 0, violations = 0 }) {
  const floor = Math.ceil(xp * 0.4);
  const penalty = Math.round(xp * Math.min(0.6, 0.2 * violations));
  const base = Math.max(floor, xp - hintCost - penalty);
  const bonus = hintsUsed === 0 && violations === 0 ? Math.round(xp * 0.1) : 0;
  return { base, bonus, penalty, total: base + bonus };
}

/** ranks: [{name, xp}] ascending by xp. */
export function rankIndexFor(xp, ranks) {
  let idx = 0;
  ranks.forEach((r, i) => { if (xp >= r.xp) idx = i; });
  return idx;
}
export const rankFor = (xp, ranks) => ranks[rankIndexFor(xp, ranks)];

/** Progress toward the next rank: { current, next|null, into, needed, pct }. */
export function rankProgress(xp, ranks) {
  const i = rankIndexFor(xp, ranks);
  const current = ranks[i];
  const next = ranks[i + 1] || null;
  if (!next) return { current, next: null, into: xp - current.xp, needed: 0, pct: 100 };
  const span = next.xp - current.xp;
  const into = xp - current.xp;
  return { current, next, into, needed: next.xp - xp, pct: Math.min(100, Math.round((into / span) * 100)) };
}

export function formatDuration(seconds) {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}
