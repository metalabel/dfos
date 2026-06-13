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
  // enforce the DFOS number policy on the ORIGINAL value first — JSON.stringify
  // below silently turns NaN/±Infinity into null, so those must be caught here
  // before serialization
  assertCanonicalNumbers(value);

  // the exact shape that gets CBOR-encoded is the JSON round-trip, not the
  // original — a toJSON()/valueOf() hook can materialize a fraction (or a huge
  // integer) that the original walk never saw. Re-check the serialized shape so
  // those cannot escape the number policy. (Note: NaN/±Inf become null here, so
  // they are only catchable on the original walk above.)
  const serialized = JSON.parse(JSON.stringify(value));
  assertCanonicalNumbers(serialized);

  return await Block.encode({
    // removes any undefineds or other non-serializable values (and normalizes
    // -0 to 0)
    value: serialized,
    codec: dagCborCodec,
    hasher: sha256,
  });
};

/**
 * 2^53 - 1, the largest integer representable exactly as an IEEE-754 double.
 * The canonical number policy bounds integers to ±this so dag-cbor encoding is
 * byte-identical across implementations (no int>2^53 vs float64 split, no
 * shortest-float divergence — fractions are rejected outright).
 */
const MAX_SAFE_CANONICAL_INTEGER = 9007199254740991;

/**
 * Walks a value and rejects any number that is not canonicalizable under the
 * DFOS number policy: NaN, ±Infinity, non-integers, and integers outside
 * ±(2^53-1). Applications must encode such values as strings.
 */
const assertCanonicalNumbers = (value: unknown): void => {
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
  if (Array.isArray(value)) {
    for (const entry of value) assertCanonicalNumbers(entry);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value)) assertCanonicalNumbers(entry);
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
