/*

  HASH

  The one raw hash primitive the protocol exposes. SHA-256 is already the
  protocol's hash everywhere a CID is derived; this exports it directly for the
  callers that need a bare 32-byte digest of arbitrary octets (e.g. the API-AUTH
  request proof's `bodyHash`) without reaching for a second hash library. Keeping
  it here means downstream packages stay dependency-free on crypto — all crypto
  truth flows through `@metalabel/dfos-protocol`.

*/

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';

/** SHA-256 of the given octets, as 32 raw bytes. */
export const sha256 = (data: Uint8Array): Uint8Array => nobleSha256(data);
