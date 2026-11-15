// Persists player progress: the Node server (data/progress.json) when reachable, localStorage otherwise.
import { normalizeProgress } from '../mission/progress.js';

const LS_KEY = 'hacksim.progress.v1';
const JSON_HEADERS = { 'Content-Type': 'application/json' };
let queue = Promise.resolve(); // serialize writes so an older save can never land after a newer one

export async function loadProgress() {
  try {
    const res = await fetch('/api/progress');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { progress: normalizeProgress(await res.json()), mode: 'server' };
  } catch {
    let data = null;
    try { data = JSON.parse(localStorage.getItem(LS_KEY)); } catch { /* blocked or corrupt */ }
    return { progress: normalizeProgress(data), mode: 'local' };
  }
}

export function saveProgress(progress, mode) {
  const body = JSON.stringify(progress);
  queue = queue.then(async () => {
    if (mode === 'server') {
      try {
        const res = await fetch('/api/progress', { method: 'POST', headers: JSON_HEADERS, body });
        if (res.ok) return;
      } catch { /* fall through to localStorage */ }
    }
    try { localStorage.setItem(LS_KEY, body); } catch { /* storage unavailable: progress lives for this tab only */ }
  });
  return queue;
}
