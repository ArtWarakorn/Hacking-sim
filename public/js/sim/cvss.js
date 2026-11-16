// CVSS v3.1 base score calculator (FIRST.org specification, section 7).
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
};

/** Round up to one decimal, avoiding floating point artefacts (spec Appendix A). */
export function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function parseVector(vector) {
  const parts = String(vector).trim().split('/');
  if (parts[0] !== 'CVSS:3.1') return { error: 'vector ต้องขึ้นต้นด้วย CVSS:3.1' };
  const m = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(':');
    m[k] = v;
  }
  const ok = W.AV[m.AV] !== undefined && W.AC[m.AC] !== undefined && W.UI[m.UI] !== undefined
    && ['U', 'C'].includes(m.S) && W.PR[m.S]?.[m.PR] !== undefined
    && W.CIA[m.C] !== undefined && W.CIA[m.I] !== undefined && W.CIA[m.A] !== undefined;
  return ok ? { metrics: m } : { error: 'vector ไม่ถูกต้อง (ต้องมี AV AC PR UI S C I A ครบ)' };
}

export function severity(score) {
  if (score === 0) return 'None';
  if (score < 4) return 'Low';
  if (score < 7) return 'Medium';
  if (score < 9) return 'High';
  return 'Critical';
}

export function baseScore(m) {
  const iss = 1 - (1 - W.CIA[m.C]) * (1 - W.CIA[m.I]) * (1 - W.CIA[m.A]);
  const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * W.PR[m.S][m.PR] * W.UI[m.UI];
  if (impact <= 0) return { score: 0, impact, exploitability };
  const raw = m.S === 'U' ? Math.min(impact + exploitability, 10) : Math.min(1.08 * (impact + exploitability), 10);
  return { score: roundUp(raw), impact, exploitability };
}
