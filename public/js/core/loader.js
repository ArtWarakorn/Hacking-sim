// Fetches game content (JSON) from /content/*. Cached per page load.
import { World, webappIds } from '../sim/network.js';

const cache = new Map();

export async function loadJSON(path) {
  if (cache.has(path)) return cache.get(path);
  const res = await fetch(path);
  if (!res.ok) throw new Error(`โหลด ${path} ไม่สำเร็จ (${res.status})`);
  const data = await res.json();
  cache.set(path, data);
  return data;
}

export const loadMachine = (id) => loadJSON(`/content/machines/${id}.json`);

/** A simulated network plus every webapp it serves. A fresh World per mission (state is never shared). */
export async function loadWorld(name = 'lab') {
  const def = await loadJSON(`/content/network/${name}.json`);
  const ids = webappIds(def);
  const apps = await Promise.all(ids.map((id) => loadJSON(`/content/webapps/${id}.json`)));
  return new World(def, Object.fromEntries(ids.map((id, i) => [id, apps[i]])));
}
export const loadCommandDocs = () => loadJSON('/content/commands.json');
export const loadLesson = (id) => loadJSON(`/content/lessons/${id}.json`);

/** Everything the dashboard needs: curriculum, ranks, achievements, command docs and every mission file. */
export async function loadContent() {
  const [curriculum, ranks, achievements, commandDocs] = await Promise.all([
    loadJSON('/content/curriculum.json'),
    loadJSON('/content/ranks.json'),
    loadJSON('/content/achievements.json'),
    loadCommandDocs(),
  ]);
  const ids = curriculum.chapters.flatMap((c) => c.missions);
  const list = await Promise.all(ids.map((id) => loadJSON(`/content/missions/${id}.json`)));
  return { curriculum, ranks, achievements, commandDocs, missions: new Map(list.map((m) => [m.id, m])) };
}
