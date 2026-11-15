// Usage: node tools/hash.mjs <missionId> <objectiveId> <flag|answer> "<value>"
// Prints the hash to paste into the objective's "flagHash" / "answerHash" field.
import { objectiveHash } from '../public/js/core/hash.js';

const [missionId, objectiveId, type, ...rest] = process.argv.slice(2);
const value = rest.join(' ');
if (!missionId || !objectiveId || !['flag', 'answer'].includes(type) || !value) {
  console.error('Usage: node tools/hash.mjs <missionId> <objectiveId> <flag|answer> "<value>"');
  process.exit(1);
}
console.log(await objectiveHash(missionId, objectiveId, type, value));
