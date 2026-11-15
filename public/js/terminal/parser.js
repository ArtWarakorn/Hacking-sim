// Shell-ish tokenizer + parser: quotes, $VAR, | || && ; > >> 2> 2>> 2>&1 <
// Never evaluates anything — it only produces a structure for executor.js.

// Variable references are NOT resolved while tokenizing (so `export X=1; echo $X` and `false; echo $?`
// work on one line). They are kept as NAME placeholders and resolved by expandVars() at run time.
const VAR_OPEN = '';
const VAR_CLOSE = '';
const VAR_RE = new RegExp(`${VAR_OPEN}([^${VAR_CLOSE}]*)${VAR_CLOSE}`, 'g');

export function expandVars(value, env = {}, lastStatus = 0) {
  return value.replace(VAR_RE, (_, name) => (name === '?' ? String(lastStatus) : (env[name] ?? '')));
}

export function tokenize(line) {
  const tokens = [];
  let buf = '';
  let has = false;
  let quoted = false;
  let hasVar = false;
  let i = 0;

  const pushWord = () => {
    if (has) tokens.push({ type: 'word', value: buf, quoted, hasVar });
    buf = ''; has = false; quoted = false; hasVar = false;
  };
  const expandVar = () => {
    // line[i] === '$'
    const rest = line.slice(i + 1);
    let m;
    if (rest[0] === '?') { i += 2; hasVar = true; has = true; return `${VAR_OPEN}?${VAR_CLOSE}`; }
    if ((m = /^\{([A-Za-z_]\w*)\}/.exec(rest))) { i += m[0].length + 1; hasVar = true; has = true; return `${VAR_OPEN}${m[1]}${VAR_CLOSE}`; }
    if ((m = /^[A-Za-z_]\w*/.exec(rest))) { i += m[0].length + 1; hasVar = true; has = true; return `${VAR_OPEN}${m[0]}${VAR_CLOSE}`; }
    i += 1;
    return '$';
  };

  while (i < line.length) {
    const c = line[i];
    if (c === "'") {
      const j = line.indexOf("'", i + 1);
      if (j < 0) throw new Error('unexpected EOF while looking for matching `\'\'');
      buf += line.slice(i + 1, j); has = true; quoted = true; i = j + 1;
    } else if (c === '"') {
      i++;
      while (i < line.length && line[i] !== '"') {
        if (line[i] === '\\' && '"\\$`'.includes(line[i + 1] ?? '')) { buf += line[i + 1]; i += 2; }
        else if (line[i] === '$') buf += expandVar();
        else buf += line[i++];
      }
      if (i >= line.length) throw new Error('unexpected EOF while looking for matching `"\'');
      i++; has = true; quoted = true;
    } else if (c === '\\') {
      if (i + 1 < line.length) { buf += line[i + 1]; has = true; quoted = true; i += 2; } else i++;
    } else if (c === '$') {
      buf += expandVar();
      has = true;
    } else if (/\s/.test(c)) {
      pushWord(); i++;
    } else if (c === '#' && !has) {
      break; // comment
    } else if (c === '|') {
      pushWord();
      if (line[i + 1] === '|') { tokens.push({ type: 'op', value: '||' }); i += 2; }
      else { tokens.push({ type: 'op', value: '|' }); i++; }
    } else if (c === '&') {
      pushWord();
      if (line[i + 1] === '&') { tokens.push({ type: 'op', value: '&&' }); i += 2; }
      else throw new Error("syntax error near unexpected token `&' (background jobs are not supported)");
    } else if (c === ';') {
      pushWord(); tokens.push({ type: 'op', value: ';' }); i++;
    } else if (c === '<') {
      pushWord(); tokens.push({ type: 'op', value: '<' }); i++;
    } else if (c === '>') {
      let op = '>';
      if (has && !quoted && buf === '2') { buf = ''; has = false; op = '2>'; } else pushWord();
      i++;
      if (line[i] === '>') { op += '>'; i++; }
      else if (op === '2>' && line[i] === '&' && line[i + 1] === '1') { op = '2>&1'; i += 2; }
      tokens.push({ type: 'op', value: op });
    } else {
      buf += c; has = true; i++;
    }
  }
  pushWord();
  return tokens;
}

const REDIRECTS = new Set(['>', '>>', '2>', '2>>', '<']);

/** tokens -> [{ pipeline: [{argv:[token], redirects:[{op,target}]}], next: ';'|'&&'|'||'|null }] */
export function parse(tokens) {
  const list = [];
  let pipeline = [];
  let cur = { argv: [], redirects: [] };
  let pending = null;
  const syntax = (t) => new Error(`syntax error near unexpected token \`${t}'`);

  for (const t of tokens) {
    if (t.type === 'word') {
      if (pending) { cur.redirects.push({ op: pending, target: t }); pending = null; }
      else cur.argv.push(t);
      continue;
    }
    const op = t.value;
    if (REDIRECTS.has(op)) {
      if (pending) throw syntax(op);
      pending = op;
    } else if (op === '2>&1') {
      cur.redirects.push({ op });
    } else {
      if (pending) throw syntax(op);
      if (op === '|') {
        if (!cur.argv.length) throw syntax('|');
        pipeline.push(cur); cur = { argv: [], redirects: [] };
      } else {
        // ; && ||
        if (!cur.argv.length) {
          if (op === ';' && !pipeline.length) { continue; }
          throw syntax(op);
        }
        pipeline.push(cur);
        list.push({ pipeline, next: op });
        pipeline = []; cur = { argv: [], redirects: [] };
      }
    }
  }
  if (pending) throw syntax('newline');
  if (cur.argv.length) pipeline.push(cur);
  else if (pipeline.length) throw syntax('newline');
  if (pipeline.length) list.push({ pipeline, next: null });
  else if (list.length && list[list.length - 1].next !== ';') throw syntax('newline');
  return list;
}
