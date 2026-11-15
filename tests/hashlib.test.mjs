import test from 'node:test';
import assert from 'node:assert/strict';
import { md5, sha1, sha256, ntlm } from '../public/js/sim/hashlib.js';

// Reference values are well-known, independently-verifiable test vectors (RFC 1321/3174, FIPS 180-4,
// and the widely-published NTLM("password") value) - not computed by the code under test.
test('md5 matches standard test vectors', () => {
  assert.equal(md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5('abc'), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(md5('password'), '5f4dcc3b5aa765d61d8327deb882cf99');
  assert.equal(md5('The quick brown fox jumps over the lazy dog'), '9e107d9d372bb6826bd81d3542a419d6');
});

test('sha1 matches standard test vectors', () => {
  assert.equal(sha1(''), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
  assert.equal(sha1('abc'), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(sha1('password'), '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8');
});

test('sha256 matches standard test vectors', () => {
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('password'), '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8');
});

test('ntlm matches the well-known reference hash for "password"', () => {
  assert.equal(ntlm('password'), '8846f7eaee8fb117ad06bdd830b7586c');
});

test('every algorithm is deterministic and sensitive to every character', () => {
  for (const fn of [md5, sha1, sha256, ntlm]) {
    assert.equal(fn('Summer2024!'), fn('Summer2024!'));
    assert.notEqual(fn('Summer2024!'), fn('summer2024!'));
    assert.notEqual(fn('Summer2024!'), fn('Summer2024!!'));
  }
});

test('outputs have the expected length and are lowercase hex', () => {
  assert.match(md5('x'), /^[0-9a-f]{32}$/);
  assert.match(sha1('x'), /^[0-9a-f]{40}$/);
  assert.match(sha256('x'), /^[0-9a-f]{64}$/);
  assert.match(ntlm('x'), /^[0-9a-f]{32}$/);
});

test('md5 and ntlm are both 32 hex chars but differ (same length is the real-world ambiguity hashid warns about)', () => {
  assert.equal(md5('password').length, ntlm('password').length);
  assert.notEqual(md5('password'), ntlm('password'));
});
