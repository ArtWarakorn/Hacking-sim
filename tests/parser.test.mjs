import test from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, parse, expandVars } from '../public/js/terminal/parser.js';

// Mirrors what the executor does: expand at "run time", drop unquoted words that expand to nothing.
const words = (line, env = {}, st = 0) => tokenize(line).flatMap((t) => {
  if (t.type === 'op') return [`<${t.value}>`];
  const v = expandVars(t.value, env, st);
  return v === '' && t.hasVar && !t.quoted ? [] : [v];
});

test('splits words and honours quotes', () => {
  assert.deepEqual(words(`echo 'a b' "c d" e\\ f`), ['echo', 'a b', 'c d', 'e f']);
  assert.deepEqual(words('echo ""'), ['echo', '']);
});

test('expands variables, but not inside single quotes', () => {
  const env = { USER: 'kali', EMPTY: '' };
  assert.deepEqual(words('echo $USER "${USER}x" \'$USER\' $EMPTY $NOPE', env), ['echo', 'kali', 'kalix', '$USER']);
  assert.deepEqual(words('echo $?', {}, 3), ['echo', '3']);
});

test('recognises operators and redirects', () => {
  assert.deepEqual(words('a | b && c || d ; e'), ['a', '<|>', 'b', '<&&>', 'c', '<||>', 'd', '<;>', 'e']);
  assert.deepEqual(words('a > f >> g 2> h 2>> i 2>&1 < j'), ['a', '<>>', 'f', '<>>>', 'g', '<2>>', 'h', '<2>>>', 'i', '<2>&1>', '<<>', 'j']);
  assert.deepEqual(words('a 2>/dev/null'), ['a', '<2>>', '/dev/null']);
});

test('"2" as an ordinary argument is not a redirect', () => {
  assert.deepEqual(words('echo 2 > f'), ['echo', '2', '<>>', 'f']);
});

test('comments are ignored; unterminated quote throws', () => {
  assert.deepEqual(words('ls # hi'), ['ls']);
  assert.throws(() => tokenize("echo 'oops"), /unexpected EOF/);
  assert.throws(() => tokenize('sleep 5 &'), /background/);
});

test('parse builds pipelines with redirects and chaining', () => {
  const list = parse(tokenize('cat a | grep x > out && echo ok'));
  assert.equal(list.length, 2);
  assert.equal(list[0].next, '&&');
  assert.equal(list[0].pipeline.length, 2);
  assert.equal(list[0].pipeline[1].redirects[0].op, '>');
  assert.equal(list[0].pipeline[1].redirects[0].target.value, 'out');
  assert.equal(list[1].next, null);
});

test('parse rejects malformed lines', () => {
  assert.throws(() => parse(tokenize('| ls')), /syntax error/);
  assert.throws(() => parse(tokenize('ls |')), /syntax error/);
  assert.throws(() => parse(tokenize('ls >')), /syntax error/);
  assert.throws(() => parse(tokenize('ls &&')), /syntax error/);
  assert.deepEqual(parse(tokenize('ls;')).length, 1);
});
