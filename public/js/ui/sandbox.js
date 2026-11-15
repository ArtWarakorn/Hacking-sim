// Free-play terminal on the training box (no objectives, no XP).
import { h } from './dom.js';
import { loadMachine, loadWorld } from '../core/loader.js';
import { createRuntime, createSession, SessionStack } from '../sim/session.js';
import { createRegistry } from '../commands/index.js';
import { Terminal } from '../terminal/terminal.js';
import { EventBus } from '../core/eventbus.js';

export async function mountSandbox(container, { content, go }) {
  const [machine, world] = await Promise.all([loadMachine('training-box'), loadWorld('lab')]);
  const stack = new SessionStack(createSession(createRuntime(machine, world)));
  const termRoot = h('div', { class: 'term-root' });
  container.replaceChildren(h('div', { class: 'sandbox' },
    h('div', { class: 'row' }, h('button', { class: 'btn link', type: 'button', onClick: () => go('/') }, '← Dashboard'), h('h1', null, 'Sandbox')),
    h('p', { class: 'muted small' }, 'ฝึกพิมพ์คำสั่งอิสระ — ไม่มี XP ไม่มีเป้าหมาย รีเฟรชหน้าเพื่อรีเซ็ตเครื่อง'),
    termRoot));
  const term = new Terminal(termRoot, {
    stack, registry: createRegistry(content.commandDocs), bus: new EventBus(),
    banner: 'HackSim sandbox — พิมพ์ \x1b[1;32mhelp\x1b[0m เพื่อดูคำสั่ง\n',
  });
  term.focus();
  return () => {};
}
