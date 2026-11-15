// Entry point: loads progress + content, then runs a tiny hash router (#/, #/lesson/ID, #/mission/ID, ...).
import { loadProgress } from './core/storage.js';
import { loadContent } from './core/loader.js';
import { Store } from './core/state.js';
import { rankFor } from './mission/scoring.js';
import { mountProfile } from './ui/profile.js';
import { mountDashboard } from './ui/dashboard.js';
import { mountLesson } from './ui/lesson.js';
import { mountMission } from './ui/mission.js';
import { mountDebrief } from './ui/debrief.js';
import { mountSandbox } from './ui/sandbox.js';

const statusEl = document.getElementById('status');
const view = document.getElementById('view');

const go = (path) => {
  const target = `#${path}`;
  if (location.hash === target) render(); else location.hash = target;
};

let store; let content; let cleanup = () => {}; let renderId = 0;
const results = new Map(); // missionId -> result of this page session (shown on the debrief)

// Each mount renders into its own detached element. The router swaps it into the page only if no newer
// navigation started meanwhile, so a superseded (stale) mount can never put a dead screen on display.
const routes = [
  [/^\/$/, (c, root) => mountDashboard(root, c)],
  [/^\/profile$/, (c, root) => mountProfile(root, c)],
  [/^\/lesson\/([\w-]+)$/, (c, root, id) => mountLesson(root, c, id)],
  [/^\/mission\/([\w-]+)$/, (c, root, id) => mountMission(root, c, id)],
  [/^\/debrief\/([\w-]+)$/, (c, root, id) => mountDebrief(root, c, id)],
  [/^\/sandbox$/, (c, root) => mountSandbox(root, c)],
];

function updateStatus() {
  const p = store.progress;
  statusEl.textContent = p.profile ? `${p.profile.name} · ${rankFor(p.xp, content.ranks).name} · ${p.xp} XP` : '';
}

let lastHash = null;

async function render() {
  const id = ++renderId;
  cleanup(); // tear the previous screen down first (detaches its engine and timers)...
  cleanup = () => {};
  view.inert = true; // ...and make whatever is still on display unusable until the new screen is ready
  lastHash = location.hash;
  const path = location.hash.slice(1) || '/';
  const ctx = { store, content, go, results };
  let target = path;
  if (!store.progress.profile) target = '/profile';
  else if (target === '/profile') target = '/';
  for (const [re, mount] of routes) {
    const m = re.exec(target);
    if (!m) continue;
    const root = document.createElement('div');
    try {
      const fn = await mount(ctx, root, ...m.slice(1));
      if (id !== renderId) { fn?.(); return; } // a newer navigation won the race: discard this screen
      cleanup = fn || (() => {});
      view.replaceChildren(root);
      view.inert = false;
      root.querySelector('.term-input, #handle')?.focus();
    } catch (e) {
      console.error(e);
      if (id === renderId) { view.textContent = `เกิดข้อผิดพลาด: ${e.message}`; view.inert = false; }
      return;
    }
    window.scrollTo(0, 0);
    return;
  }
  view.inert = false;
  go('/');
}

/** The browser can deliver a hashchange for a hash we are already showing (e.g. around reloads): ignore those. */
const onHashChange = () => { if (location.hash !== lastHash) render(); };

async function boot() {
  try {
    const [loaded, c] = await Promise.all([loadProgress(), loadContent()]);
    store = new Store(loaded.progress, loaded.mode);
    content = c;
  } catch (e) {
    view.textContent = `โหลดเกมไม่สำเร็จ: ${e.message}`;
    return;
  }
  store.subscribe(updateStatus);
  updateStatus();
  addEventListener('hashchange', onHashChange);
  render();
}

boot();
