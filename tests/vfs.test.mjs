import test from 'node:test';
import assert from 'node:assert/strict';
import { VFS, FsError, normalize, modeString, canAccess } from '../public/js/sim/vfs.js';

const root = { name: 'root', uid: 0, groups: [{ name: 'root' }] };
const alice = { name: 'alice', uid: 1000, groups: [{ name: 'alice' }, { name: 'staff' }] };
const bob = { name: 'bob', uid: 1001, groups: [{ name: 'bob' }] };

const mk = () => new VFS({
  '/home/alice': { type: 'dir', owner: 'alice', mode: '700' },
  '/home/alice/a.txt': { content: 'hi', owner: 'alice', mode: '600' },
  '/pub/readme': { content: 'public', mode: '644' },
  '/shared/team.txt': { content: 'team', owner: 'root', group: 'staff', mode: '640' },
  '/tmp': { type: 'dir', mode: '1777' },
  '/usr/bin/su': { content: '', mode: '4755' },
});

test('normalize resolves . and ..', () => {
  assert.equal(normalize('/a/b/../c/./d'), '/a/c/d');
  assert.equal(normalize('x/y', '/home'), '/home/x/y');
  assert.equal(normalize('../..', '/a'), '/');
});

test('owner / group / other permission bits', () => {
  const v = mk();
  assert.equal(v.readFile('/home/alice/a.txt', alice), 'hi');
  assert.throws(() => v.readFile('/home/alice/a.txt', bob), (e) => e.code === 'EACCES');
  assert.equal(v.readFile('/shared/team.txt', alice), 'team'); // via group staff
  assert.throws(() => v.readFile('/shared/team.txt', bob), (e) => e.code === 'EACCES');
  assert.equal(v.readFile('/shared/team.txt', root), 'team');
});

test('directory without x blocks traversal even when file is world-readable', () => {
  const v = mk();
  v.add('/home/alice/open.txt', { content: 'x', owner: 'alice', mode: '666' });
  assert.throws(() => v.readFile('/home/alice/open.txt', bob), (e) => e.code === 'EACCES');
});

test('error codes', () => {
  const v = mk();
  assert.throws(() => v.readFile('/nope', alice), (e) => e instanceof FsError && e.code === 'ENOENT');
  assert.throws(() => v.readFile('/pub', alice), (e) => e.code === 'EISDIR');
  assert.throws(() => v.readFile('/pub/readme/x', alice), (e) => e.code === 'ENOTDIR');
});

test('write, append, and create respect permissions and ownership', () => {
  const v = mk();
  v.writeFile('/tmp/n.txt', 'a', alice);
  v.writeFile('/tmp/n.txt', 'b', alice, { append: true });
  assert.equal(v.readFile('/tmp/n.txt', alice), 'ab');
  assert.equal(v.get('/tmp/n.txt').owner, 'alice');
  assert.throws(() => v.writeFile('/pub/new', 'x', alice), (e) => e.code === 'EACCES');
  assert.throws(() => v.writeFile('/pub/readme', 'x', alice), (e) => e.code === 'EACCES');
});

test('mkdir, remove, chmod', () => {
  const v = mk();
  v.mkdir('/tmp/a/b/c', alice, { parents: true });
  assert.equal(v.get('/tmp/a/b/c').owner, 'alice');
  assert.throws(() => v.remove('/tmp/a', alice), (e) => e.code === 'EISDIR');
  v.remove('/tmp/a', alice, { recursive: true });
  assert.equal(v.exists('/tmp/a/b'), false);
  assert.throws(() => v.chmod('/pub/readme', 0o777, alice), (e) => e.code === 'EPERM');
  v.chmod('/pub/readme', 0o600, root);
  assert.equal(v.get('/pub/readme').mode, 0o600);
});

test('modeString shows suid and sticky bits', () => {
  const v = mk();
  assert.equal(modeString(v.get('/usr/bin/su')), '-rwsr-xr-x');
  assert.equal(modeString(v.get('/tmp')), 'drwxrwxrwt');
  assert.equal(modeString(v.get('/home/alice/a.txt')), '-rw-------');
});

test('walk and glob', () => {
  const v = mk();
  assert.deepEqual([...v.walk('/pub')], ['/pub/readme']);
  assert.deepEqual(v.expandGlob('/shared/*.txt', '/'), ['/shared/team.txt']);
  assert.deepEqual(v.expandGlob('*.nope', '/'), []);
  assert.equal(canAccess(v.get('/pub/readme'), bob, 4), true);
});
