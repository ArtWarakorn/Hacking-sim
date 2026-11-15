import test from 'node:test';
import assert from 'node:assert/strict';
import { readJSON, loadWorldFromDisk } from './helpers.mjs';
import { EventBus } from '../public/js/core/eventbus.js';
import { stripAnsi } from '../public/js/terminal/ansi.js';
import { submitLine } from '../public/js/terminal/executor.js';
import { buildMissionShell } from '../public/js/mission/runtime.js';
import { MissionEngine } from '../public/js/mission/engine.js';
import { computeScore, rankFor, rankProgress, formatDuration } from '../public/js/mission/scoring.js';
import {
  createDefaultProgress, normalizeProgress, chapterState, missionState, applyMissionResult, nextMission,
} from '../public/js/mission/progress.js';
import { validate } from '../tools/validate.mjs';

const curriculum = readJSON('content/curriculum.json');
const ranks = readJSON('content/ranks.json');
const achievements = readJSON('content/achievements.json');
const docs = readJSON('content/commands.json');
const walkthroughs = readJSON('tests/walkthroughs.json');
const missions = new Map(curriculum.chapters.flatMap((c) => c.missions).map((id) => [id, readJSON(`content/missions/${id}.json`)]));

/** Start a mission exactly as the UI does and return helpers for typing commands. */
function startMission(id) {
  const mission = missions.get(id);
  const { stack, registry } = buildMissionShell(mission, readJSON(`content/machines/${mission.machine}.json`), docs, loadWorldFromDisk(mission.network || 'lab'));
  const bus = new EventBus();
  const engine = new MissionEngine(mission, { bus }).attach();
  const history = { items: [] };
  const run = async (line) => {
    const r = await submitLine(line, stack, registry, { history, bus });
    return { ...r, text: stripAnsi(r.output) };
  };
  return { mission, engine, run, stack };
}

test('content validates (JSON, cross-references, hashes vs walkthroughs)', async () => {
  assert.deepEqual(await validate(), []);
});

for (const [id, wt] of Object.entries(walkthroughs)) {
  test(`walkthrough completes mission ${id}`, async () => {
    const { engine, run } = startMission(id);
    let completed = 0;
    engine.events.on('complete', () => completed++);
    for (const step of wt.steps) {
      const { cmd, code = 0 } = typeof step === 'string' ? { cmd: step } : step;
      const r = await run(cmd);
      assert.equal(r.code, code, `step "${cmd}" exited ${r.code}, expected ${code}: ${r.text}`);
    }
    for (const value of Object.values(wt.submit)) assert.equal((await engine.submit(value)).ok, true);
    assert.equal(engine.complete, true);
    assert.equal(completed, 1, 'complete event fires exactly once');
  });
}

test('every mission in the curriculum has a walkthrough', () => {
  assert.deepEqual([...missions.keys()].filter((id) => !walkthroughs[id]), []);
});

test('objectives only tick on the right trigger', async () => {
  const { engine, run } = startMission('c01-m01');
  await run('ls');
  await run('ls -l');
  assert.equal(engine.done.has('o1'), false, 'plain ls / ls -l must not count as ls -a');
  await run('ls /nope'); // fails -> status 2 -> must not count either
  await run('ls -a');
  assert.equal(engine.done.has('o1'), true);
  await run('cat /etc/hosts');
  assert.equal(engine.done.has('o2'), false);
  await run('cat ~/.hidden_note');
  assert.equal(engine.done.has('o2'), true);
  assert.equal(engine.complete, false, 'flag not submitted yet');
});

test('flag check: case-sensitive for flags, trimmed, wrong answers rejected', async () => {
  const { engine } = startMission('c01-m01');
  assert.equal((await engine.submit('')).ok, false);
  assert.equal((await engine.submit('FLAG{nope}')).ok, false);
  assert.equal((await engine.submit('flag{hidden_files_are_not_secret}')).ok, false);
  assert.equal(engine.attempts, 2, 'an empty submit is not counted as an attempt');
  const ok = await engine.submit('  FLAG{hidden_files_are_not_secret}  ');
  assert.equal(ok.ok, true);
  assert.equal(ok.objective.id, 'o3');
  assert.equal((await engine.submit('FLAG{hidden_files_are_not_secret}')).ok, false, 'already solved');
});

test('answers also ignore a trailing dot (DNS style), flags do not', async () => {
  const { engine } = startMission('c02-m03');
  assert.equal((await engine.submit('Mail.ACME.test.')).ok, true);
  assert.equal((await engine.submit('FLAG{dns_txt_records_leak_info}.')).ok, false);
  assert.equal((await engine.submit('FLAG{dns_txt_records_leak_info}')).ok, true);
});

test('answers ignore case and whitespace; a flag does not satisfy an answer objective', async () => {
  const { engine } = startMission('c00-m02');
  assert.equal((await engine.submit(' NO ')).ok, true);
  assert.equal(engine.done.has('o3'), true);
  assert.equal((await engine.submit('10.10.20.5')).ok, false);
  assert.equal((await engine.submit('10.10.20.1')).ok, true);
});

test('hints are revealed in order and cost XP', () => {
  const { engine } = startMission('c01-m01');
  assert.equal(engine.hintsUsed, 0);
  assert.equal(engine.nextHintCost, 10);
  engine.requestHint();
  engine.requestHint();
  assert.equal(engine.hintsUsed, 2);
  assert.equal(engine.hintCost, 35);
  assert.equal(engine.nextHintCost, null);
  assert.equal(engine.requestHint(), null);
});

test('detach stops listening', async () => {
  const { engine, run } = startMission('c01-m01');
  engine.detach();
  await run('ls -a');
  assert.equal(engine.done.size, 0);
});

test('mission environments are isolated from each other and from the base machine', async () => {
  const a = startMission('c00-m01');
  const b = startMission('c00-m02');
  assert.match((await a.run('ls Documents')).text, /welcome\.txt/);
  assert.doesNotMatch((await b.run('ls Documents')).text, /welcome\.txt/);
  await a.run('echo x > /tmp/mine');
  assert.equal((await b.run('ls /tmp')).text, '');
});

// ----- scoring -----
test('score: hint penalty is capped, no-hint bonus applies', () => {
  assert.deepEqual(computeScore({ xp: 100, hintCost: 0, hintsUsed: 0 }), { base: 100, bonus: 10, penalty: 0, total: 110 });
  assert.deepEqual(computeScore({ xp: 100, hintCost: 30, hintsUsed: 2 }), { base: 70, bonus: 0, penalty: 0, total: 70 });
  assert.equal(computeScore({ xp: 100, hintCost: 500, hintsUsed: 3 }).total, 40);
});

test('ranks and progress bar', () => {
  assert.equal(rankFor(0, ranks).name, 'Script Kiddie');
  assert.equal(rankFor(299, ranks).name, 'Script Kiddie');
  assert.equal(rankFor(300, ranks).name, 'Intern');
  const p = rankProgress(150, ranks);
  assert.equal(p.next.name, 'Intern');
  assert.equal(p.needed, 150);
  assert.equal(p.pct, 50);
  assert.equal(rankProgress(99999, ranks).next, null);
  assert.equal(formatDuration(125), '02:05');
});

// ----- progress / unlocking -----
test('unlocking: lesson gate, sequential missions, chapter gate', () => {
  const p = createDefaultProgress();
  const state = (id) => missionState(p, missions.get(id), curriculum, ranks).state;
  assert.equal(state('c00-m01'), 'lesson');
  assert.equal(state('c00-m02'), 'locked');
  assert.equal(state('c01-m01'), 'locked');
  p.lessonsDone.push('c00-l01');
  assert.equal(state('c00-m01'), 'available');
  assert.equal(state('c00-m02'), 'locked', 'needs m01 first');
  p.completedMissions['c00-m01'] = { score: 100 };
  assert.equal(state('c00-m01'), 'done');
  assert.equal(state('c00-m02'), 'available');
  assert.equal(state('c00-m04'), 'locked', 'sequential: m03 comes first');
  for (const id of ['c00-m02', 'c00-m03']) p.completedMissions[id] = { score: 100 };
  assert.equal(state('c00-m04'), 'lesson', 'c00-m04 needs its own lesson c00-l02');
  p.lessonsDone.push('c00-l02');
  assert.equal(state('c00-m04'), 'available');
  assert.equal(chapterState(p, curriculum.chapters[0], curriculum, ranks).unlocked, true);
  assert.equal(state('c01-m01'), 'locked', 'chapter 1 needs ALL of chapter 0');
  p.completedMissions['c00-m04'] = { score: 100 };
  assert.equal(state('c01-m01'), 'lesson');
});

test('planned chapters (no missions yet) show as coming soon and stay locked', () => {
  const c04 = curriculum.chapters.find((c) => c.id === 'c04');
  const s = chapterState(createDefaultProgress(), c04, curriculum, ranks);
  assert.equal(s.planned, true);
  assert.equal(s.unlocked, false);
});

test('applyMissionResult: XP only once, rank up, achievements, replay keeps best', () => {
  const p = createDefaultProgress();
  const ctx = { ranks, achievements, curriculum };
  const m1 = missions.get('c00-m01');
  const r1 = applyMissionResult(p, m1, { hintCost: 0, hintsUsed: 0, seconds: 42.6 }, ctx);
  assert.equal(r1.first, true);
  assert.equal(r1.xpGained, 110);
  assert.equal(p.xp, 110);
  assert.deepEqual(r1.newAchievements.map((a) => a.id).sort(), ['clean_run', 'first_blood']);
  assert.equal(p.completedMissions['c00-m01'].seconds, 43);

  const r2 = applyMissionResult(p, m1, { hintCost: 20, hintsUsed: 2, seconds: 10 }, ctx);
  assert.equal(r2.first, false);
  assert.equal(r2.xpGained, 0);
  assert.equal(p.xp, 110);
  assert.equal(p.completedMissions['c00-m01'].score, 110, 'worse replay does not overwrite');

  const r3 = applyMissionResult(p, missions.get('c00-m02'), { hintCost: 0, hintsUsed: 0, seconds: 5 }, ctx);
  assert.equal(r3.xpGained, 165);
  assert.equal(p.xp, 275);
  for (const id of ['c00-m03', 'c00-m04']) p.completedMissions[id] = { score: 1, hintsUsed: 1 };
  const r4 = applyMissionResult(p, missions.get('c01-m01'), { hintCost: 0, hintsUsed: 0, seconds: 5 }, ctx);
  assert.equal(r4.rankUp, true);
  assert.equal(p.rank, 'Intern');
  assert.ok(r4.newAchievements.some((a) => a.id === 'rank_intern'));
  assert.ok(r4.newAchievements.some((a) => a.id === 'chapter_0'), 'chapter 0 complete');
});

test('nextMission suggests the first playable mission', () => {
  const p = createDefaultProgress();
  assert.equal(nextMission(p, curriculum, ranks, missions).id, 'c00-m01');
  p.lessonsDone.push('c00-l01');
  p.completedMissions['c00-m01'] = { score: 1 };
  assert.equal(nextMission(p, curriculum, ranks, missions).id, 'c00-m02');
});

test('normalizeProgress fills in missing fields from older saves', () => {
  const p = normalizeProgress({ xp: 50, settings: { scanlines: false } });
  assert.equal(p.xp, 50);
  assert.deepEqual(p.lessonsDone, []);
  assert.equal(p.settings.scanlines, false);
  assert.deepEqual(normalizeProgress(null), createDefaultProgress());
});
