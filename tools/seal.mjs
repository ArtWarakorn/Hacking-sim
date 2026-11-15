// Usage: node tools/seal.mjs
// Fills in every flagHash/answerHash in content/missions/*.json from tests/walkthroughs.json.
// Authoring flow: write the objective with "answerHash": "SEAL", put the solution in walkthroughs.json, run this.
// The file text is edited in place (only the hash strings change), so hand formatting is preserved.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { objectiveHash } from '../public/js/core/hash.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const curriculum = JSON.parse(readFileSync(path.join(root, 'content/curriculum.json'), 'utf8'));
const walkthroughs = JSON.parse(readFileSync(path.join(root, 'tests/walkthroughs.json'), 'utf8'));

let changed = 0;
for (const id of curriculum.chapters.flatMap((c) => c.missions)) {
  const file = path.join(root, 'content/missions', `${id}.json`);
  if (!existsSync(file)) continue;
  const text = readFileSync(file, 'utf8');
  const mission = JSON.parse(text);
  const sealed = mission.objectives.filter((o) => o.type === 'flag' || o.type === 'answer');
  const queue = [];
  for (const o of sealed) {
    const value = walkthroughs[id]?.submit?.[o.id];
    if (value === undefined) { console.error(`✖ ${id}/${o.id}: no solution in tests/walkthroughs.json`); process.exitCode = 1; queue.push(null); continue; }
    queue.push(await objectiveHash(id, o.id, o.type, value));
  }
  let i = 0;
  const next = text.replace(/("(?:flagHash|answerHash)":\s*")[^"]*(")/g, (m, a, b) => (queue[i] ? `${a}${queue[i++]}${b}` : (i++, m)));
  if (next !== text) { writeFileSync(file, next); changed++; console.log(`sealed ${id}`); }
}
console.log(changed ? `✔ updated ${changed} mission file(s)` : '✔ everything already sealed');
