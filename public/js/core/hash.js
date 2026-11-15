// SHA-256 helpers. Flags/answers in mission JSON are stored as salted hashes so opening the JSON
// does not spoil them. (This is anti-spoiler, not security: the repo is public and the game is local.)

export async function sha256Hex(text) {
  const buf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Flags are case-sensitive; free-text answers ignore case, surrounding whitespace and a trailing dot (DNS style). */
export const normalizeAnswer = (type, value) => (type === 'flag' ? value.trim() : value.trim().toLowerCase().replace(/\.$/, ''));

/** Salted with mission + objective id so the same answer hashes differently everywhere. */
export const objectiveHash = (missionId, objectiveId, type, value) =>
  sha256Hex(`${missionId}:${objectiveId}:${normalizeAnswer(type, value)}`);
