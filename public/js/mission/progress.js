// Player progress rules: defaults, unlocking, applying mission results, achievements. Pure functions.
import { computeScore, rankFor, rankIndexFor } from './scoring.js';

export const createDefaultProgress = () => ({
  profile: null, // { name, createdAt }
  xp: 0,
  rank: 'Script Kiddie',
  completedMissions: {}, // id -> { score, hintsUsed, seconds, completedAt }
  lessonsDone: [],
  achievements: [], // ids
  notesByMission: {},
  settings: { scanlines: true },
});

export function normalizeProgress(p) {
  const d = createDefaultProgress();
  const src = p && typeof p === 'object' ? p : {};
  return { ...d, ...src, settings: { ...d.settings, ...(src.settings || {}) } };
}

const isDone = (progress, id) => Boolean(progress.completedMissions[id]);

export function chapterById(curriculum, id) {
  return curriculum.chapters.find((c) => c.id === id);
}

export function chapterComplete(progress, chapter) {
  return chapter.missions.length > 0 && chapter.missions.every((id) => isDone(progress, id));
}

/** -> { planned, unlocked, reason, done, total } */
export function chapterState(progress, chapter, curriculum, ranks) {
  const done = chapter.missions.filter((id) => isDone(progress, id)).length;
  const total = chapter.missions.length;
  if (total === 0) return { planned: true, unlocked: false, reason: 'เร็วๆ นี้', done, total };
  for (const reqId of chapter.unlock?.requiresChapters || []) {
    const req = chapterById(curriculum, reqId);
    if (!req || !chapterComplete(progress, req)) {
      return { planned: false, unlocked: false, reason: `ต้องจบบท "${req?.title ?? reqId}" ก่อน`, done, total };
    }
  }
  const minRank = chapter.unlock?.minRank;
  if (minRank) {
    const needIdx = ranks.findIndex((r) => r.name === minRank);
    if (rankIndexFor(progress.xp, ranks) < needIdx) {
      return { planned: false, unlocked: false, reason: `ต้องมียศ ${minRank} ขึ้นไป`, done, total };
    }
  }
  return { planned: false, unlocked: true, reason: '', done, total };
}

/** -> { state: 'locked'|'lesson'|'available'|'done', reason } */
export function missionState(progress, mission, curriculum, ranks) {
  if (isDone(progress, mission.id)) return { state: 'done', reason: '' };
  const chapter = chapterById(curriculum, mission.chapter);
  const cs = chapterState(progress, chapter, curriculum, ranks);
  if (!cs.unlocked) return { state: 'locked', reason: cs.reason };
  const idx = chapter.missions.indexOf(mission.id);
  if (idx > 0 && !isDone(progress, chapter.missions[idx - 1])) {
    return { state: 'locked', reason: 'ต้องจบภารกิจก่อนหน้าก่อน' };
  }
  if (mission.lesson && !progress.lessonsDone.includes(mission.lesson)) {
    return { state: 'lesson', reason: 'ต้องผ่านบทเรียนก่อน' };
  }
  return { state: 'available', reason: '' };
}

export function nextMission(progress, curriculum, ranks, missions) {
  for (const ch of curriculum.chapters) {
    for (const id of ch.missions) {
      const m = missions.get(id);
      if (m && ['available', 'lesson'].includes(missionState(progress, m, curriculum, ranks).state)) return m;
    }
  }
  return null;
}

function conditionMet(cond, progress, curriculum) {
  const results = Object.values(progress.completedMissions);
  switch (cond.type) {
    case 'missions_completed': return results.length >= cond.count;
    case 'no_hints': return results.filter((r) => r.hintsUsed === 0).length >= cond.count;
    case 'lessons_done': return progress.lessonsDone.length >= cond.count;
    case 'clean_scope': return results.filter((r) => r.scoped && r.violations === 0).length >= cond.count;
    case 'xp': return progress.xp >= cond.amount;
    case 'chapter_complete': {
      const ch = chapterById(curriculum, cond.chapter);
      return Boolean(ch) && chapterComplete(progress, ch);
    }
    default: return false;
  }
}

/** Unlocks any newly satisfied achievements (mutates progress). Returns the new definitions. */
export function evaluateAchievements(progress, defs, curriculum) {
  const fresh = defs.filter((d) => !progress.achievements.includes(d.id) && conditionMet(d.condition, progress, curriculum));
  for (const d of fresh) progress.achievements.push(d.id);
  return fresh;
}

/**
 * Record a finished mission (mutates progress).
 * XP is only awarded the first time; replays keep the best score.
 */
export function applyMissionResult(progress, mission, { hintCost = 0, hintsUsed = 0, seconds = 0, violations = 0 }, { ranks, achievements, curriculum }) {
  const rankBefore = progress.rank;
  const score = computeScore({ xp: mission.xp, hintCost, hintsUsed, violations });
  const scoped = Boolean(mission.scope?.ips);
  const prev = progress.completedMissions[mission.id];
  const first = !prev;
  let xpGained = 0;
  if (first) {
    xpGained = score.total;
    progress.xp += xpGained;
    progress.completedMissions[mission.id] = { score: score.total, hintsUsed, violations, scoped, seconds: Math.round(seconds), completedAt: new Date().toISOString() };
  } else if (score.total > prev.score) {
    progress.completedMissions[mission.id] = { ...prev, score: score.total, hintsUsed, violations, scoped, seconds: Math.round(seconds) };
  }
  progress.rank = rankFor(progress.xp, ranks).name;
  const newAchievements = evaluateAchievements(progress, achievements, curriculum);
  return { first, score, xpGained, rankBefore, rankAfter: progress.rank, rankUp: rankBefore !== progress.rank, newAchievements };
}
