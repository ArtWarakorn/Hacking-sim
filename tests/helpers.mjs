import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { createRuntime, createSession, SessionStack } from '../public/js/sim/session.js';
import { createRegistry } from '../public/js/commands/index.js';
import { submitLine } from '../public/js/terminal/executor.js';
import { stripAnsi } from '../public/js/terminal/ansi.js';
import { EventBus } from '../public/js/core/eventbus.js';
import { World, webappIds } from '../public/js/sim/network.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const readJSON = (rel) => JSON.parse(readFileSync(path.join(root, rel), 'utf8'));

export const docs = readJSON('content/commands.json');

/** Same as loadWorld() in the browser, but reading from disk. A fresh World each call. */
export function loadWorldFromDisk(name = 'lab') {
  const def = readJSON(`content/network/${name}.json`);
  return new World(def, Object.fromEntries(webappIds(def).map((id) => [id, readJSON(`content/webapps/${id}.json`)])));
}

/** Fresh sandbox: returns run(line) -> { out, err, code, text } with ANSI stripped. */
export function makeShell(userName, { machine = 'training-box', network = 'lab' } = {}) {
  const def = readJSON(`content/machines/${machine}.json`);
  const stack = new SessionStack(createSession(createRuntime(def, network ? loadWorldFromDisk(network) : null), userName));
  const registry = createRegistry(docs);
  const bus = new EventBus();
  const history = { items: [] };
  const run = async (line) => {
    history.items.push(line);
    const r = await submitLine(line, stack, registry, { history, bus });
    return { ...r, out: stripAnsi(r.out), err: stripAnsi(r.err), text: stripAnsi(r.output) };
  };
  return { run, stack, registry, bus };
}
