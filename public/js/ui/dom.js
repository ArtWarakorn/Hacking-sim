// Tiny DOM helpers. All content goes through textContent / text nodes — never innerHTML.

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k in el && !k.includes('-')) {
      try { el[k] = v; } catch { el.setAttribute(k, v); }
    } else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

/** Inline formatting for lesson/briefing text: `code`, **bold**, *italic*. */
export function richText(text) {
  const frag = document.createDocumentFragment();
  for (const part of String(text).split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/)) {
    if (!part) continue;
    if (part.startsWith('`')) frag.append(h('code', null, part.slice(1, -1)));
    else if (part.startsWith('**')) frag.append(h('strong', null, part.slice(2, -2)));
    else if (part.startsWith('*') && part.length > 2) frag.append(h('em', null, part.slice(1, -1)));
    else frag.append(document.createTextNode(part));
  }
  return frag;
}

export const DIFFICULTY_LABEL = { tutorial: 'Tutorial', easy: 'Easy', medium: 'Medium', hard: 'Hard', insane: 'Insane' };

export const difficultyBadge = (d) => h('span', { class: `badge diff-${d}` }, DIFFICULTY_LABEL[d] || d);
