import test from 'node:test';
import assert from 'node:assert/strict';
import { makeShell } from './helpers.mjs';
import { parseVector, baseScore, severity, roundUp } from '../public/js/sim/cvss.js';

const score = (v) => baseScore(parseVector(v).metrics).score;

test('cvss: matches published FIRST/NVD base scores', () => {
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 6.5);
  assert.equal(score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('cvss: severity bands and roundUp', () => {
  assert.deepEqual([0, 0.1, 3.9, 4, 6.9, 7, 8.9, 9, 10].map(severity), ['None', 'Low', 'Low', 'Medium', 'Medium', 'High', 'High', 'Critical', 'Critical']);
  assert.equal(roundUp(4.02), 4.1);
  assert.equal(roundUp(4), 4);
});

test('cvss: rejects malformed vectors', () => {
  assert.ok(parseVector('AV:N').error);
  assert.ok(parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H').error);
  assert.ok(parseVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').error);
});

test('cvss command: prints score, and errors on bad input', async () => {
  const sh = makeShell();
  const ok = await sh.run('cvss CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  assert.match(ok.out, /Base Score:\s+9\.8/);
  assert.match(ok.out, /Severity:\s+Critical/);
  assert.match((await sh.run('cvss')).out, /Attack Vector/);
  const bad = await sh.run('cvss nonsense');
  assert.equal(bad.code, 1);
});
