import { fsCommands } from './fs.js';
import { miscCommands } from './misc.js';
import { netCommands } from './net.js';
import { webCommands } from './web.js';
import { procCommands } from './proc.js';
import { reconCommands } from './recon.js';
import { shareCommands } from './shares.js';

/** Command registry. `docs` is the array from content/commands.json (used by help, man, --help). */
export function createRegistry(docs = []) {
  const commands = new Map();
  for (const c of [...fsCommands, ...miscCommands, ...netCommands, ...webCommands, ...procCommands, ...reconCommands, ...shareCommands]) commands.set(c.name, c);
  const docMap = new Map(docs.map((d) => [d.name, d]));

  const registry = {
    get: (name) => commands.get(name),
    has: (name) => commands.has(name),
    names: () => [...commands.keys()].sort(),
    list: () => [...commands.values()],
    doc: (name) => docMap.get(name),
    /** Register extra commands (later phases add nmap, curl, ssh, ...). */
    register(cmd) { commands.set(cmd.name, cmd); return registry; },
    helpText(name) {
      const d = docMap.get(name);
      if (!d) return commands.has(name) ? `NAME\n    ${name}\n` : null;
      let t = `NAME\n    ${d.name} — ${d.summary}\n\nSYNOPSIS\n    ${d.synopsis}\n\nคำอธิบาย\n    ${d.description}\n`;
      if (d.examples?.length) t += `\nตัวอย่าง\n${d.examples.map((e) => `    $ ${e}`).join('\n')}\n`;
      return t;
    },
  };
  return registry;
}
