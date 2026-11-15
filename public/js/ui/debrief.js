// Debrief: result summary + what the technique means in the real world and how to defend.
import { h, richText } from './dom.js';
import { formatDuration } from '../mission/scoring.js';
import { nextMission } from '../mission/progress.js';

export function mountDebrief(container, { store, content, go, results }, missionId) {
  const mission = content.missions.get(missionId);
  const saved = store.progress.completedMissions[missionId];
  if (!mission || !saved) { go('/'); return () => {}; }
  const res = results.get(missionId); // only present right after finishing in this page session
  const next = nextMission(store.progress, content.curriculum, content.ranks, content.missions);

  const stat = (label, value) => h('div', { class: 'stat' }, h('span', { class: 'muted small' }, label), h('strong', null, value));
  const summary = res
    ? [
      stat('XP ที่ได้', res.first ? `+${res.xpGained}` : '0 (เล่นซ้ำ)'),
      stat('คะแนนฐาน', res.score.base),
      stat('โบนัสไม่ใช้ hint', res.score.bonus),
      stat('Hint ที่ใช้', `${res.hintsUsed} (−${res.hintCost} XP)`),
      mission.scope?.ips && stat('ละเมิด scope', res.violations ? `${res.violations} (−${res.score.penalty} XP)` : '0 — สะอาด'),
      stat('ส่งคำตอบ', `${res.attempts} ครั้ง`),
      stat('เวลา', formatDuration(res.seconds)),
    ]
    : [stat('คะแนนที่ดีที่สุด', saved.score), stat('Hint ที่ใช้', saved.hintsUsed), saved.scoped && stat('ละเมิด scope', saved.violations ?? 0), stat('เวลา', formatDuration(saved.seconds))];

  container.replaceChildren(h('article', { class: 'debrief' },
    h('h1', null, `Debrief: ${mission.title}`),
    res?.rankUp && h('p', { class: 'badge ok big' }, `เลื่อนยศเป็น ${res.rankAfter}!`),
    h('div', { class: 'card stats-grid' }, summary),
    res?.violationIps?.length > 0 && h('div', { class: 'card violation-card' }, h('h2', null, 'บทเรียนเรื่อง scope'),
      h('p', null, `คุณแตะเครื่องนอก scope: ${res.violationIps.join(', ')}`),
      h('p', { class: 'muted' }, 'ในงานจริงสิ่งนี้อาจผิดสัญญาและกฎหมาย: ระบุเป้าหมายให้ตรง (เช่น nmap 10.10.20.5-7 แทน /24) และตรวจรายการ scope ก่อนสแกนทุกครั้ง')),
    res?.newAchievements.length > 0 && h('div', { class: 'card' }, h('h2', null, 'Achievement ใหม่'),
      h('ul', null, res.newAchievements.map((a) => h('li', null, h('strong', null, a.title), ` — ${a.description}`)))),
    h('section', { class: 'card' },
      h('h2', null, 'ในโลกจริง และวิธีป้องกัน'),
      mission.debrief.map((p) => h('p', null, richText(p)))),
    mission.references?.length > 0 && h('section', { class: 'card' }, h('h2', null, 'อ้างอิง'),
      h('ul', null, mission.references.map((r) => h('li', null, r)))),
    h('div', { class: 'row' },
      next && h('button', { class: 'btn primary', type: 'button', onClick: () => go(next.lesson && !store.progress.lessonsDone.includes(next.lesson) ? `/lesson/${next.lesson}` : `/mission/${next.id}`) }, `ภารกิจถัดไป: ${next.title}`),
      h('button', { class: 'btn', type: 'button', onClick: () => go(`/mission/${mission.id}`) }, 'เล่นซ้ำ'),
      h('button', { class: 'btn', type: 'button', onClick: () => go('/') }, 'กลับ Dashboard'))));
  return () => {};
}
