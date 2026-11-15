// Minimal ANSI SGR -> DOM spans (bold + 16 colors). Text goes in via textContent, so it is XSS-safe.
export function ansiToFragment(text) {
  const frag = document.createDocumentFragment();
  const re = /\x1b\[([0-9;]*)m/g;
  let classes = [];
  let last = 0;
  let m;
  const emit = (s) => {
    if (!s) return;
    const span = document.createElement('span');
    span.textContent = s;
    if (classes.length) span.className = classes.join(' ');
    frag.appendChild(span);
  };
  while ((m = re.exec(text))) {
    emit(text.slice(last, m.index));
    last = re.lastIndex;
    for (const code of (m[1] || '0').split(';').map(Number)) {
      if (code === 0) classes = [];
      else if (code === 1) classes.push('a-bold');
      else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) {
        classes = classes.filter((c) => !c.startsWith('a-fg'));
        classes.push(`a-fg${code}`);
      }
    }
  }
  emit(text.slice(last));
  return frag;
}

export const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
