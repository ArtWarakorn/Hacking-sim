// Reporting tools: cvss (CVSS v3.1 base score calculator).
import { parseVector, baseScore, severity } from '../sim/cvss.js';

const LEGEND = `CVSS v3.1 base metrics (vector: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_)
  AV  Attack Vector        N=Network A=Adjacent L=Local P=Physical
  AC  Attack Complexity    L=Low H=High
  PR  Privileges Required  N=None L=Low H=High
  UI  User Interaction     N=None R=Required
  S   Scope                U=Unchanged C=Changed
  C/I/A  Confidentiality / Integrity / Availability impact   H=High L=Low N=None
`;

const cvss = {
  name: 'cvss',
  async run(ctx, args) {
    const vector = args.find((a) => !a.startsWith('-'));
    if (!vector) return { out: LEGEND, err: '', code: 0 };
    const p = parseVector(vector);
    if (p.error) return { out: '', err: `cvss: ${p.error}\n`, code: 1 };
    const r = baseScore(p.metrics);
    ctx.bus?.emit('game', { name: 'cvss.calc', session: ctx.session, vector, score: r.score, severity: severity(r.score) });
    return {
      out: `Vector:            ${vector}\nExploitability:    ${r.exploitability.toFixed(1)}\nImpact:            ${r.impact.toFixed(1)}\nBase Score:        ${r.score.toFixed(1)}\nSeverity:          ${severity(r.score)}\n`,
      err: '', code: 0,
    };
  },
};

export const reportCommands = [cvss];
