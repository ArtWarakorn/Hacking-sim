// Lesson page: readable sections + a quiz that must be fully correct to unlock the missions.
import { h, richText } from './dom.js';
import { toast } from './toast.js';
import { loadLesson } from '../core/loader.js';

function renderSection(s) {
  return h('section', { class: 'lesson-section' },
    h('h2', null, s.title),
    (s.body || []).map((t) => h('p', null, richText(t))),
    s.list && h('ul', null, s.list.map((li) => h('li', null, richText(li)))),
    s.code && h('pre', { class: 'code' }, s.code.join('\n')),
    s.tip && h('p', { class: 'tip' }, h('strong', null, 'เคล็ดลับ: '), richText(s.tip)));
}

export async function mountLesson(container, { store, content, go }, lessonId) {
  const lesson = await loadLesson(lessonId);
  const targets = [...content.missions.values()].filter((m) => m.lesson === lessonId);
  const nextTarget = targets.find((m) => !store.progress.completedMissions[m.id]) || targets[0];

  const quizForm = h('form', { class: 'card quiz', noValidate: true });
  const result = h('div', { class: 'quiz-result', role: 'status' });
  const picks = lesson.quiz.map(() => null);

  lesson.quiz.forEach((q, qi) => {
    quizForm.append(h('fieldset', { class: 'question', 'data-q': qi },
      h('legend', null, `${qi + 1}. ${q.q}`),
      q.choices.map((c, ci) => h('label', { class: 'choice' },
        h('input', { type: 'radio', name: `q${qi}`, value: ci, onChange: () => { picks[qi] = ci; } }),
        h('span', null, c))),
      h('p', { class: 'explain small', hidden: true }, q.explain)));
  });

  quizForm.append(h('button', {
    class: 'btn primary', type: 'submit',
  }, 'ตรวจคำตอบ'), result);

  quizForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (picks.some((p) => p === null)) { result.textContent = 'ตอบให้ครบทุกข้อก่อน'; result.className = 'quiz-result bad'; return; }
    let correct = 0;
    quizForm.querySelectorAll('fieldset').forEach((fs, qi) => {
      const ok = picks[qi] === lesson.quiz[qi].answer;
      if (ok) correct++;
      fs.classList.toggle('right', ok);
      fs.classList.toggle('wrong', !ok);
      fs.querySelector('.explain').hidden = false;
    });
    if (correct === lesson.quiz.length) {
      const first = !store.progress.lessonsDone.includes(lessonId);
      store.update((p) => { if (first) p.lessonsDone.push(lessonId); });
      result.className = 'quiz-result good';
      result.replaceChildren(
        h('p', null, `ถูกทุกข้อ (${correct}/${lesson.quiz.length}) — ปลดล็อกภารกิจแล้ว`),
        h('button', { class: 'btn primary', type: 'button', onClick: () => go(nextTarget ? `/mission/${nextTarget.id}` : '/') },
          nextTarget ? `ไปทำภารกิจ: ${nextTarget.title}` : 'กลับ Dashboard'));
      if (first) toast('ผ่านบทเรียนแล้ว', 'ok');
    } else {
      result.className = 'quiz-result bad';
      result.textContent = `ถูก ${correct}/${lesson.quiz.length} — อ่านคำอธิบายใต้แต่ละข้อ แล้วแก้คำตอบที่ผิดจากนั้นกดตรวจอีกครั้ง`;
    }
  });

  const done = store.progress.lessonsDone.includes(lessonId);
  container.replaceChildren(h('article', { class: 'lesson' },
    h('button', { class: 'btn link', type: 'button', onClick: () => go('/') }, '← กลับ Dashboard'),
    h('h1', null, lesson.title),
    done && h('p', { class: 'badge ok' }, 'ผ่านแล้ว'),
    lesson.sections.map(renderSection),
    h('h2', null, 'แบบทดสอบ'),
    quizForm));
  return () => {};
}
