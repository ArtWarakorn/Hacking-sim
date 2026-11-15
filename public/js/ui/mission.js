// Mission screen: briefing/objectives/hints (left), terminal (center), notes (right).
import { h, richText, difficultyBadge } from './dom.js';
import { toast } from './toast.js';
import { loadMachine, loadWorld } from '../core/loader.js';
import { EventBus } from '../core/eventbus.js';
import { Terminal } from '../terminal/terminal.js';
import { mountBrowser } from './browser.js';
import { mountProxy } from './proxy.js';
import { buildMissionShell } from '../mission/runtime.js';
import { MissionEngine } from '../mission/engine.js';
import { applyMissionResult, missionState } from '../mission/progress.js';
import { formatDuration, computeScore } from '../mission/scoring.js';

export async function mountMission(container, ctx, missionId) {
  const { store, content, go, results } = ctx;
  const mission = content.missions.get(missionId);
  if (!mission) { go('/'); return () => {}; }

  const gate = missionState(store.progress, mission, content.curriculum, content.ranks);
  if (gate.state === 'locked') { toast(gate.reason, 'warn'); go('/'); return () => {}; }
  if (gate.state === 'lesson') { go(`/lesson/${mission.lesson}`); return () => {}; }

  const [machine, world] = await Promise.all([loadMachine(mission.machine), loadWorld(mission.network || 'lab')]);
  const bus = new EventBus();
  const { stack, registry } = buildMissionShell(mission, machine, content.commandDocs, world);
  const engine = new MissionEngine(mission, { bus }).attach();

  // ---------- left panel ----------
  const objectivesEl = h('ul', { class: 'objectives' });
  const renderObjectives = () => objectivesEl.replaceChildren(...engine.objectives.map((o) =>
    h('li', { class: o.done ? 'done' : '' }, h('span', { class: 'check-mark', 'aria-hidden': true }, o.done ? '✔' : '○'), h('span', null, richText(o.text)))));

  const hintsEl = h('ol', { class: 'hints' });
  const hintBtn = h('button', { class: 'btn', type: 'button', onClick: () => {
    if (!engine.requestHint()) return;
    renderHints();
  } });
  const renderHints = () => {
    hintsEl.replaceChildren(...engine.revealedHints.map((x) => h('li', null, richText(x.text), h('span', { class: 'muted small' }, ` (−${x.cost} XP)`))));
    const cost = engine.nextHintCost;
    hintBtn.hidden = cost === null;
    hintBtn.textContent = cost === null ? '' : `ขอ Hint (−${cost} XP)`;
  };

  const needsSubmit = mission.objectives.some((o) => o.type === 'flag' || o.type === 'answer');
  const feedback = h('p', { class: 'feedback', role: 'status' });
  const answerInput = h('input', { type: 'text', placeholder: 'FLAG{...} หรือคำตอบ', autocomplete: 'off', 'aria-label': 'คำตอบหรือ flag' });
  const submitForm = needsSubmit && h('form', {
    class: 'submit-form',
    onSubmit: async (e) => {
      e.preventDefault();
      const r = await engine.submit(answerInput.value);
      feedback.textContent = r.message;
      feedback.className = `feedback ${r.ok ? 'good' : 'bad'}`;
      if (r.ok) answerInput.value = '';
    },
  }, answerInput, h('button', { class: 'btn primary', type: 'submit' }, 'ส่ง'), feedback);

  const timerEl = h('span', { class: 'timer', 'aria-label': 'เวลา' }, '00:00');
  const timer = setInterval(() => { timerEl.textContent = formatDuration(engine.seconds); }, 1000);

  const violationEl = h('p', { class: 'violation', role: 'alert', hidden: true });
  const doneBanner = h('div', { class: 'card success', hidden: true });

  const left = h('aside', { class: 'panel left' },
    h('div', { class: 'row wrap' }, difficultyBadge(mission.difficulty), h('span', { class: 'badge' }, `${mission.xp} XP`), h('span', { class: 'badge' }, `~${mission.estMinutes} นาที`)),
    h('p', { class: 'briefing' }, richText(mission.briefing)),
    h('h3', null, 'Scope'),
    h('ul', { class: 'scope' },
      mission.scope.inScope.map((s) => h('li', { class: 'in' }, h('span', { class: 'tag' }, 'IN'), s)),
      mission.scope.outOfScope.map((s) => h('li', { class: 'out' }, h('span', { class: 'tag' }, 'OUT'), s))),
    mission.scope.ips && h('p', { class: 'muted small' }, 'ภารกิจนี้ตรวจ scope: การแตะเครื่องนอก scope จะถูกหัก XP'),
    violationEl,
    h('h3', null, 'เป้าหมาย'),
    objectivesEl,
    submitForm,
    h('h3', null, 'Hint'),
    hintsEl, hintBtn,
    doneBanner);

  // ---------- center: terminal / browser / proxy ----------
  // Browser and Proxy act on behalf of the attacker's own machine (kali), never whichever host the
  // terminal has pivoted into via ssh/su — exactly like a real browser/Burp running on your attack box.
  const selfSession = stack.sessions[0];
  const httpHistory = []; // full curl/browser/repeater requests, newest first (used by the Proxy tab)
  const offHttpLog = bus.on('http', (e) => {
    if (!e.full) return;
    httpHistory.unshift({ ...e, time: e.time ?? Date.now() });
    if (httpHistory.length > 200) httpHistory.length = 200;
  });

  const termRoot = h('div', { class: 'term-root' });
  const browserRoot = h('div', { class: 'tool-panel', hidden: true });
  const proxyRoot = h('div', { class: 'tool-panel', hidden: true });
  let proxyHandle = null;
  const tools = { terminal: termRoot, browser: browserRoot, proxy: proxyRoot };
  const toolTabs = {};
  const showTool = (name) => {
    for (const n of Object.keys(tools)) { tools[n].hidden = n !== name; toolTabs[n].classList.toggle('active', n === name); }
    if (name === 'terminal') term.focus();
    if (name === 'browser' && !browserRoot.dataset.mounted) { mountBrowser(browserRoot, { world, selfIp: selfSession.machine.ip, bus, session: selfSession }); browserRoot.dataset.mounted = '1'; }
    if (name === 'proxy' && !proxyHandle) proxyHandle = mountProxy(proxyRoot, { world, selfIp: selfSession.machine.ip, bus, session: selfSession, httpHistory });
  };
  for (const [name, label] of [['terminal', 'Terminal'], ['browser', 'Browser'], ['proxy', 'Proxy']]) {
    toolTabs[name] = h('button', { class: `tab-btn${name === 'terminal' ? ' active' : ''}`, type: 'button', onClick: () => showTool(name) }, label);
  }
  const center = h('section', { class: 'center-col' },
    h('div', { class: 'tab-bar' }, Object.values(toolTabs)),
    termRoot, browserRoot, proxyRoot);

  // ---------- right: notes ----------
  let saveTimer = null;
  const notes = h('textarea', {
    class: 'notes', placeholder: 'จดโน้ตระหว่างทำภารกิจ (บันทึกอัตโนมัติ)', 'aria-label': 'โน้ต',
    value: store.progress.notesByMission[mission.id] || '',
    onInput: () => {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => store.update((p) => { p.notesByMission[mission.id] = notes.value; }), 600);
    },
  });
  const right = h('aside', { class: 'panel right' }, h('h3', null, 'Notes'), notes);

  container.replaceChildren(h('div', { class: 'mission' },
    h('header', { class: 'mission-head' },
      h('button', { class: 'btn link', type: 'button', onClick: () => go('/') }, '← Dashboard'),
      h('h1', null, mission.title),
      timerEl),
    h('div', { class: 'mission-grid' }, left, center, right)));

  const term = new Terminal(termRoot, {
    stack, registry, bus,
    banner: `ภารกิจ: ${mission.title}\nพิมพ์ \x1b[1;32mhelp\x1b[0m เพื่อดูคำสั่ง · \x1b[1;32mman <คำสั่ง>\x1b[0m เพื่ออ่านคู่มือ · Tab เติมอัตโนมัติ\n\n`,
  });

  // ---------- events ----------
  engine.events.on('objective', () => renderObjectives());
  engine.events.on('violation', ({ ip, count }) => {
    const penalty = Math.round(mission.xp * Math.min(0.6, 0.2 * count));
    violationEl.hidden = false;
    violationEl.textContent = `ละเมิด scope ${count} ครั้ง (−${penalty} XP): ${engine.violations.map((v) => v.ip).join(', ')}`;
    // The event fires while the command is still running; print after its output has been shown.
    setTimeout(() => term.print(`\n\x1b[1;31m[SCOPE VIOLATION]\x1b[0m ${ip} อยู่นอก scope ของงานนี้ — บันทึกการละเมิด (−20% XP) ในงานจริงอาจผิดสัญญาหรือกฎหมาย\n\n`), 0);
    toast(`นอก scope: ${ip} (−20% XP)`, 'error', 6000);
  });
  engine.events.on('complete', () => {
    clearInterval(timer);
    const stats = { hintCost: engine.hintCost, hintsUsed: engine.hintsUsed, seconds: engine.seconds, violations: engine.violations.length };
    const res = store.update((p) => applyMissionResult(p, mission, stats, content));
    results.set(mission.id, { ...res, ...stats, attempts: engine.attempts, violationIps: engine.violations.map((v) => v.ip) });
    renderObjectives();
    doneBanner.hidden = false;
    doneBanner.replaceChildren(
      h('h3', null, 'ภารกิจสำเร็จ!'),
      h('p', null, res.first ? `ได้รับ ${res.xpGained} XP` : 'เล่นซ้ำ (ไม่ได้ XP เพิ่ม)'),
      h('button', { class: 'btn primary', type: 'button', onClick: () => go(`/debrief/${mission.id}`) }, 'ดู Debrief'));
    toast(res.first ? `ภารกิจสำเร็จ +${res.xpGained} XP` : 'ภารกิจสำเร็จ', 'ok');
    if (res.rankUp) toast(`เลื่อนยศเป็น ${res.rankAfter}!`, 'ok', 5500);
    res.newAchievements.forEach((a) => toast(`Achievement: ${a.title}`, 'ok', 5500));
    doneBanner.scrollIntoView?.({ block: 'nearest' });
  });

  renderObjectives();
  renderHints();
  term.focus();

  return () => {
    clearInterval(timer);
    clearTimeout(saveTimer);
    engine.detach();
    offHttpLog();
    proxyHandle?.destroy();
    // flush notes typed within the debounce window
    if (notes.value !== (store.progress.notesByMission[mission.id] || '')) store.update((p) => { p.notesByMission[mission.id] = notes.value; });
  };
}
