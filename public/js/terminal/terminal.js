// DOM terminal: prompt + input line, history (↑/↓), Tab completion, Ctrl+L / Ctrl+C.
import { submitLine } from './executor.js';
import { complete } from './completer.js';
import { History } from './history.js';
import { ansiToFragment } from './ansi.js';

export class Terminal {
  constructor(root, { stack, registry, banner = '', bus }) {
    this.stack = stack;
    this.registry = registry;
    this.bus = bus; // per-mission event bus (falls back to the global one in executor.js)
    this.history = new History();
    this.busy = false;

    root.innerHTML = '';
    this.el = document.createElement('div');
    this.el.className = 'term';
    this.out = document.createElement('div');
    this.out.className = 'term-out';
    const line = document.createElement('div');
    line.className = 'term-line';
    this.promptEl = document.createElement('span');
    this.promptEl.className = 'term-prompt';
    this.input = document.createElement('input');
    this.input.className = 'term-input';
    this.input.type = 'text';
    this.input.autocomplete = 'off';
    this.input.spellcheck = false;
    this.input.setAttribute('autocapitalize', 'off');
    this.input.setAttribute('aria-label', 'terminal input');
    line.append(this.promptEl, this.input);
    this.el.append(this.out, line);
    root.append(this.el);

    this.el.addEventListener('click', () => { if (!getSelection()?.toString()) this.input.focus(); });
    this.input.addEventListener('keydown', (e) => this.onKey(e));
    if (banner) this.print(banner);
    this.refreshPrompt();
  }

  get session() { return this.stack.current; }

  /** Interactive tools (ftp>, smb: \>) replace the bash prompt; secret prompts hide what is typed. */
  get interactive() { return this.stack.interactive || null; }

  refreshPrompt() {
    this.promptEl.textContent = this.interactive?.prompt ?? this.session.prompt();
    this.input.type = this.interactive?.secret ? 'password' : 'text';
  }
  focus() { this.input.focus(); }

  print(text) {
    if (!text) return;
    this.out.append(ansiToFragment(text));
    this.scroll();
  }
  scroll() { this.el.scrollTop = this.el.scrollHeight; }
  clear() { this.out.innerHTML = ''; }

  echoLine(value) {
    const row = document.createElement('div');
    const p = document.createElement('span');
    p.className = 'term-prompt';
    p.textContent = this.promptEl.textContent;
    row.append(p, document.createTextNode(value));
    this.out.append(row);
  }

  /** Run a line as if the player typed it (also used by tests/tutorial hooks). */
  async run(line) {
    this.busy = true;
    this.input.disabled = true;
    try {
      const res = await submitLine(line, this.stack, this.registry, { history: this.history, ...(this.bus ? { bus: this.bus } : {}) });
      if (res.clear) this.clear();
      this.print(res.output);
    } catch (e) {
      console.error(e);
      this.print(`bash: internal error: ${e.message}\n`);
    } finally {
      this.busy = false;
      this.input.disabled = false;
      this.refreshPrompt();
      this.input.focus();
      this.scroll();
    }
  }

  async onKey(e) {
    if (this.busy) { e.preventDefault(); return; }
    if (e.key === 'Enter') {
      e.preventDefault();
      const line = this.input.value;
      const secret = Boolean(this.interactive?.secret);
      this.echoLine(secret ? '' : line); // never echo a password
      this.input.value = '';
      if (!secret) this.history.push(line);
      if (line.trim() || this.interactive) await this.run(line);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      this.input.value = this.history.prev(this.input.value);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      this.input.value = this.history.next();
    } else if (e.key === 'Tab') {
      e.preventDefault();
      if (this.interactive) return;
      const { line, options } = complete(this.input.value, this.session, this.registry.names());
      this.input.value = line;
      if (options.length) {
        this.echoLine(this.input.value);
        this.print(`${options.join('  ')}\n`);
      }
    } else if (e.ctrlKey && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      this.clear();
    } else if (e.ctrlKey && e.key.toLowerCase() === 'c') {
      e.preventDefault();
      this.echoLine(this.interactive?.secret ? '^C' : `${this.input.value}^C`);
      this.input.value = '';
      if (this.interactive) { this.stack.interactive = null; this.refreshPrompt(); } // Ctrl+C leaves ftp/smbclient
    }
  }
}
