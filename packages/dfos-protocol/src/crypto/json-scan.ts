/*

  JSON SCAN

  Raw-text gates on a signed JSON document (a JWS protected header or payload)
  that `JSON.parse` cannot express, because both defects are invisible once the
  text has been parsed.

*/

/**
 * Reject a signed JSON document whose raw text carries something its decoded
 * value can no longer show:
 *
 * 1. DUPLICATE KEYS — PROTOCOL: "A payload containing duplicate keys is
 *    malformed: the signature commits to the raw payload bytes while the CID
 *    derives from the decoded value." Every JSON parser silently resolves a
 *    duplicate (last wins), so the only place to see one is the text.
 * 2. LONE SURROGATE ESCAPES — a `\uD800`-class escape with no pair. TypeScript
 *    keeps it; Go's decoder replaces it with U+FFFD. Two verifiers would derive
 *    two different CIDs from the same signed bytes, so refusing the escape is
 *    the one verdict both can reach.
 *
 * This is a tokenizer, not a parser: it does not validate the grammar — the
 * caller's `JSON.parse` is the grammar judge, and this walk simply stops at the
 * first thing it cannot read. It tracks only enough structure to know which
 * strings are member names of which object.
 *
 * MUST match the Go reference (AssertCanonicalJSONText in json_scan.go).
 */
export const assertCanonicalJsonText = (text: string): void => {
  // one frame per open container; `awaitingKey` is true in an object frame
  // exactly where a member name may start (right after `{`, and after a `,`)
  const frames: { isObject: boolean; keys: Set<string>; awaitingKey: boolean }[] = [];

  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;

    if (ch === '"') {
      const end = scanStringToken(text, i);
      if (end < 0) return; // unterminated — let JSON.parse render the verdict
      const value = decodeStringToken(text.slice(i, end));
      if (value === null) return;
      if (LONE_SURROGATE_RE.test(value)) {
        throw new Error('string with an unpaired surrogate is not canonicalizable');
      }
      const frame = frames[frames.length - 1];
      if (frame && frame.isObject && frame.awaitingKey) {
        if (frame.keys.has(value)) {
          throw new Error(`duplicate JSON key is malformed: ${JSON.stringify(value)}`);
        }
        frame.keys.add(value);
        frame.awaitingKey = false;
      }
      i = end;
      continue;
    }

    if (ch === '{') {
      frames.push({ isObject: true, keys: new Set(), awaitingKey: true });
    } else if (ch === '[') {
      frames.push({ isObject: false, keys: new Set(), awaitingKey: false });
    } else if (ch === '}' || ch === ']') {
      frames.pop();
    } else if (ch === ',') {
      const frame = frames[frames.length - 1];
      if (frame && frame.isObject) frame.awaitingKey = true;
    }
    i++;
  }
};

/** Index just past the closing quote of the string token starting at `start`, or -1 */
const scanStringToken = (text: string, start: number): number => {
  let i = start + 1;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '"') return i + 1;
    i++;
  }
  return -1;
};

/** The string a raw `"…"` token denotes, or null when it does not denote one */
const decodeStringToken = (raw: string): string | null => {
  if (!raw.includes('\\')) return raw.slice(1, -1);
  try {
    const value: unknown = JSON.parse(raw);
    return typeof value === 'string' ? value : null;
  } catch {
    return null;
  }
};

/** See the same expression in crypto/multiformats.ts */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
