// Dashboard: rank/XP, next-mission shortcut, chapter map with lock states, achievements, data tools.
import { h, difficultyBadge } from './dom.js';
import { toast } from './toast.js';
import { rankProgress } from '../mission/scoring.js';
import { chapterState, missionState, nextMission, normalizeProgress } from '../mission/progress.js';

const STATE_LABEL = { done: 'เสร็จแล้ว', available: 'เล่นได้', lesson: 'ต้องเรียนก่อน', locked: 'ล็อก' };

export function mountDashboard(container, { store, content, go }) {
  const { curriculum, ranks, achievements, missions } = content;

  const openMission = (m, st) => {
    if (st.state === 'locked') return toast(st.reason, 'warn');
    if (st.state === 'lesson') return go(`/lesson/${m.lesson}`);
    return go(`/mission/${m.id}`);
  };

  const render = () => {
    const p = store.progress;
    const rp = rankProgress(p.xp, ranks);
    const total = missions.size;
    const done = Object.keys(p.completedMissions).length;
    const next = nextMission(p, curriculum, ranks, missions);

    const stats = h('section', { class: 'card stats' },
      h('div', { class: 'stats-head' },
        h('div', null,
          h('div', { class: 'handle' }, p.profile?.name ?? 'player'),
          h('div', { class: 'rank' }, rp.current.name)),
        h('div', { class: 'xp' }, `${p.xp} XP`)),
      h('div', { class: 'bar', role: 'progressbar', 'aria-valuenow': rp.pct, 'aria-valuemin': 0, 'aria-valuemax': 100 },
        h('div', { class: 'bar-fill', style: { width: `${rp.pct}%` } })),
      h('div', { class: 'muted small' }, rp.next ? `อีก ${rp.needed} XP ถึงยศ ${rp.next.name}` : 'ยศสูงสุดแล้ว'),
      h('div', { class: 'stat-row' },
        h('span', null, `ภารกิจ ${done}/${total}`),
        h('span', null, `บทเรียน ${p.lessonsDone.length}`),
        h('span', null, `Achievement ${p.achievements.length}/${achievements.length}`)),
      next && h('button', { class: 'btn primary', onClick: () => openMission(next, missionState(p, next, curriculum, ranks)) },
        `${p.lessonsDone.length || done ? 'ทำต่อ' : 'เริ่มเลย'}: ${next.title}`));

    const chapters = curriculum.chapters.map((ch, i) => {
      const cs = chapterState(p, ch, curriculum, ranks);
      return h('section', { class: `card chapter ${cs.unlocked ? '' : 'is-locked'}` },
        h('div', { class: 'chapter-head' },
          h('span', { class: 'chapter-no' }, `บท ${i}`),
          difficultyBadge(ch.difficulty),
          cs.planned && h('span', { class: 'badge soon' }, 'เร็วๆ นี้')),
        h('h3', null, ch.title),
        h('p', { class: 'muted small' }, ch.description),
        !cs.planned && !cs.unlocked && h('p', { class: 'lock-reason small' }, `ล็อก — ${cs.reason}`),
        !cs.planned && h('ul', { class: 'missions' }, ch.missions.map((id) => {
          const m = missions.get(id);
          const st = missionState(p, m, curriculum, ranks);
          return h('li', null, h('button', {
            class: `mission-row st-${st.state}`, type: 'button', onClick: () => openMission(m, st),
            'aria-label': `${m.title} (${STATE_LABEL[st.state]})`,
          },
          h('span', { class: `chip st-${st.state}` }, STATE_LABEL[st.state]),
          h('span', { class: 'mission-title' }, m.title),
          h('span', { class: 'muted small' }, `${p.completedMissions[id]?.score ?? m.xp} XP`)));
        })),
        !cs.planned && h('div', { class: 'muted small' }, `ความคืบหน้า ${cs.done}/${cs.total}`));
    });

    const earned = new Set(p.achievements);
    const badges = h('section', { class: 'card' },
      h('h2', null, 'Achievements'),
      h('div', { class: 'ach-grid' }, achievements.map((a) => h('div', { class: `ach ${earned.has(a.id) ? 'earned' : ''}`, title: a.description },
        h('strong', null, a.title), h('span', { class: 'muted small' }, a.description)))));

    const fileInput = h('input', {
      type: 'file', accept: 'application/json', hidden: true,
      onChange: async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        try {
          store.replace(normalizeProgress(JSON.parse(await file.text())));
          toast('นำเข้าข้อมูลสำเร็จ', 'ok');
          render();
        } catch { toast('ไฟล์ไม่ถูกต้อง', 'error'); }
      },
    });
    const tools = h('section', { class: 'card tools' },
      h('h2', null, 'ข้อมูลผู้เล่น'),
      h('p', { class: 'muted small' }, store.mode === 'server' ? 'บันทึกที่ data/progress.json' : 'โหมดออฟไลน์: บันทึกในเบราว์เซอร์ (localStorage)'),
      h('div', { class: 'row' },
        h('button', { class: 'btn', type: 'button', onClick: () => {
          const url = URL.createObjectURL(new Blob([JSON.stringify(store.progress, null, 2)], { type: 'application/json' }));
          const a = h('a', { href: url, download: 'hacksim-progress.json' });
          a.click();
          URL.revokeObjectURL(url);
        } }, 'ส่งออก'),
        h('button', { class: 'btn', type: 'button', onClick: () => fileInput.click() }, 'นำเข้า'),
        h('button', { class: 'btn', type: 'button', onClick: () => go('/sandbox') }, 'Sandbox terminal'),
        h('button', { class: 'btn danger', type: 'button', onClick: () => {
          if (!confirm('รีเซ็ตความคืบหน้าทั้งหมด? ย้อนกลับไม่ได้')) return;
          store.reset();
          go('/profile');
        } }, 'รีเซ็ตทั้งหมด')),
      fileInput);

    container.replaceChildren(h('div', { class: 'dash' }, stats, h('div', { class: 'chapters' }, chapters), badges, tools));
  };

  render();
  return () => {};
}
