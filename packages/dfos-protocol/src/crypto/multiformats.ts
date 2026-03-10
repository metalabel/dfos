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
  return await Block.encode({
    // removes any undefineds or other non-serializable values, kinda whack but
    // it works for now
    value: JSON.parse(JSON.stringify(value)),
    codec: dagCborCodec,
    hasher: sha256,
  });
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
