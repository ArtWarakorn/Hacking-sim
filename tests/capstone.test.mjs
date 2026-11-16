import test from 'node:test';
import assert from 'node:assert/strict';
import { readJSON, loadWorldFromDisk, docs } from './helpers.mjs';
import { EventBus } from '../public/js/core/eventbus.js';
import { submitLine } from '../public/js/terminal/executor.js';
import { buildMissionShell } from '../public/js/mission/runtime.js';
import { MissionEngine } from '../public/js/mission/engine.js';

function start(id) {
  const mission = readJSON(`content/missions/${id}.json`);
  const reach = Object.fromEntries((mission.reachableMachines || []).map((r) => [r.machine, readJSON(`content/machines/${r.machine}.json`)]));
  const { stack, registry } = buildMissionShell(mission, readJSON(`content/machines/${mission.machine}.json`), docs, loadWorldFromDisk(mission.network), reach);
  const bus = new EventBus();
  const engine = new MissionEngine(mission, { bus }).attach();
  const run = (line) => submitLine(line, stack, registry, { history: { items: [] }, bus });
  return { engine, run };
}

test('capstone: the full walkthrough stays inside scope (no violations)', async () => {
  const { engine, run } = start('c11-m01');
  for (const step of readJSON('tests/walkthroughs.json')['c11-m01'].steps) await run(step);
  assert.deepEqual(engine.violations, []);
  for (const id of ['o1', 'o3', 'o4']) assert.ok(engine.done.has(id), `${id} should be done`);
});

test('capstone: scanning the whole /24 touches the out-of-scope gateway', async () => {
  const { engine, run } = start('c11-m01');
  await run('nmap -sn 10.10.20.0/24');
  assert.ok(engine.violations.some((v) => v.ip === '10.10.20.1'));
});

test('capstone: web01/ftp01 are rabbit holes - scanning them gives no shell objective', async () => {
  const { engine, run } = start('c11-m01');
  await run('nmap -sV -sC 10.10.20.5');
  await run('nmap -sV -sC 10.10.20.6');
  assert.ok(!engine.done.has('o3') && !engine.done.has('o4'));
});
