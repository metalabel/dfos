/*

  MULTIFORMATS

  IPLD / dag-cbor canonical encoding

*/

import * as dagCborCodec from '@ipld/dag-cbor';
import * as Block from 'multiformats/block';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

/**
 * Canonically encoded a value into an IPLD dag-cbor block
 */
export const dagCborCanonicalEncode = async (value: unknown) => {
  // enforce the DFOS canonical-value policy on the ORIGINAL value first —
  // JSON.stringify below silently turns NaN/±Infinity into null, so those must
  // be caught here before serialization
  assertCanonicalValue(value);

  // the exact shape that gets CBOR-encoded is the JSON round-trip, not the
  // original — a toJSON()/valueOf() hook can materialize a fraction (or a huge
  // integer) that the original walk never saw. Re-check the serialized shape so
  // those cannot escape the number policy. (Note: NaN/±Inf become null here, so
  // they are only catchable on the original walk above.)
  const serialized = JSON.parse(JSON.stringify(value));
  assertCanonicalValue(serialized);

  try {
    return await Block.encode({
      // removes any undefineds or other non-serializable values (and normalizes
      // -0 to 0)
      value: serialized,
      codec: dagCborCodec,
      hasher: sha256,
    });
  } catch (e) {
    // an encoder failure is a protocol rejection, not a runtime crash: every
    // caller of this library (relay, CLI, SDK) must see the module's own Error
    // vocabulary, never a raw TypeError/RangeError thrown out of the codec
    throw new Error(`value is not canonically encodable: ${(e as Error).message}`);
  }
};

/**
 * 2^53 - 1, the largest integer representable exactly as an IEEE-754 double.
 * The canonical number policy bounds integers to ±this so dag-cbor encoding is
 * byte-identical across implementations (no int>2^53 vs float64 split, no
 * shortest-float divergence — fractions are rejected outright).
 */
const MAX_SAFE_CANONICAL_INTEGER = 9007199254740991;

/**
 * Maximum nesting depth walked when canonicalizing/encoding a value. A DoS
 * resource guard (not a chain-validity rule): a pathologically nested payload
 * would otherwise recurse here and in the dag-cbor encoder until the stack
 * overflows. Generous (1024) so it never binds a legitimate operation — real
 * DFOS payloads are a handful of levels deep — while bounding stack cost. Per
 * the dag-cbor/IPLD prior art (go-ipld-prime caps at 1024), every codec picks a
 * local depth cap; this is DFOS's, applied identically in the Go reference
 * (maxCanonicalDepth in cbor.go).
 */
const MAX_CANONICAL_DEPTH = 1024;

/**
 * Matches a high surrogate not followed by a low one, or a low surrogate not
 * preceded by a high one — the `String.isWellFormed` test without the ES2024
 * lib. Same expression as the `role` guard in chain/sign-request.ts.
 */
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Walks a value and rejects anything the two reference implementations would
 * not commit to the same bytes for:
 *
 * 1. NUMBERS — NaN, ±Infinity, non-integers, and integers outside ±(2^53-1) are
 *    not canonicalizable under the DFOS number policy. Encode them as strings.
 * 2. STRINGS — an unpaired UTF-16 surrogate. `JSON.stringify` preserves a lone
 *    surrogate as an escape, but the CBOR string encoder normalizes it to
 *    U+FFFD, so two distinct payloads would otherwise share one CID. Same test
 *    the free-form-field guards already use (sign-request.ts `role`).
 * 3. CID SENTINELS — an object carrying both a `/` and a `bytes` member is the
 *    dag-cbor bytes sentinel: the JS codec either crashes on it or silently
 *    re-reads it as a byte string, while the Go reference encodes it as an
 *    ordinary map. Rejected in both languages so neither has to guess.
 * 4. DEPTH — the MAX_CANONICAL_DEPTH nesting guard.
 *
 * MUST match the Go reference (AssertCanonicalValue in cbor.go).
 */
const assertCanonicalValue = (value: unknown, depth = 0): void => {
  if (depth > MAX_CANONICAL_DEPTH) {
    throw new Error(`value nesting exceeds max depth ${MAX_CANONICAL_DEPTH}`);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`non-finite number is not canonicalizable: ${value}`);
    }
    if (!Number.isInteger(value)) {
      throw new Error(
        `non-integer number is not canonicalizable: ${value} (encode it as a string)`,
      );
    }
    if (value > MAX_SAFE_CANONICAL_INTEGER || value < -MAX_SAFE_CANONICAL_INTEGER) {
      throw new Error(
        `integer out of safe range is not canonicalizable: ${value} (encode it as a string)`,
      );
    }
    return;
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE_RE.test(value)) {
      throw new Error('string with an unpaired surrogate is not canonicalizable');
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) assertCanonicalValue(entry, depth + 1);
    return;
  }
  if (value !== null && typeof value === 'object') {
    if ('/' in value && 'bytes' in value) {
      throw new Error('object carrying both "/" and "bytes" members is not canonicalizable');
    }
    for (const [key, entry] of Object.entries(value)) {
      // keys are strings the encoder writes too, so they answer to the same rule
      if (LONE_SURROGATE_RE.test(key)) {
        throw new Error('string with an unpaired surrogate is not canonicalizable');
      }
      assertCanonicalValue(entry, depth + 1);
    }
  }
};

/**
 * Parse a string CID
 */
export const parseDagCborCID = (cid: string) => {
  return CID.parse(cid);
};

/**
 * Returns true if the canonical encoding of the two values is the same
 */
export const isCanonicallyEqual = async (data1: unknown, data2: unknown) => {
  const block1 = await dagCborCanonicalEncode(data1);
  const block2 = await dagCborCanonicalEncode(data2);
  return block1.cid.toString() === block2.cid.toString();
};
