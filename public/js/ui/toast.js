import { h } from './dom.js';

let host = null;

export function toast(message, kind = 'info', ms = 3800) {
  if (!host) {
    host = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
    document.body.append(host);
  }
  const el = h('div', { class: `toast toast-${kind}` }, message);
  host.append(el);
  while (host.children.length > 4) host.firstElementChild.remove(); // never let a burst of toasts cover the screen
  setTimeout(() => el.classList.add('toast-out'), ms);
  setTimeout(() => el.remove(), ms + 400);
}
