/*

  KEY-PROOF ENVELOPES FOR THE RELAY'S TEST FIXTURES

  Every key-role membership past a chain's genesis is admitted by an embedded
  KEY-PROOF envelope and by nothing else (specs/KEY-PROOF.md § Chain-Walk
  Verification). So any fixture here that introduces a key to a role — a
  rotation, an added assert key, a promotion — has to carry one, or the
  membership is void and the key does not resolve.

  The ceremony's presentation-time members (`nonce`, `audience`, `timestamp`)
  are byte-fixed under the signature and inert at walk time, so a fixture can
  spell them however it likes; what a walk actually checks is the position —
  `did`, `roleSet`, and `prevCID` — plus the signature. That is the whole reason
  this helper exists as one function: getting the position right is the only part
  a test can get wrong, and it should get it wrong in exactly one place.

  Shared rather than copied per spec file for the same reason `conformance-server.ts`
  is: it is fixture machinery, not a subject under test.

*/

import {
  KEY_ADD_JWS_TYP,
  serializeRoleSet,
  signKeyProof,
} from '@metalabel/dfos-protocol/key-proof';
import type { KeyRole } from '@metalabel/dfos-protocol/key-proof';

/** All three roles, the default a rotation or a fresh key wants. */
export const ALL_ROLES: KeyRole[] = ['auth', 'assert', 'controller'];

let nonces = 0;

/**
 * One key-proof envelope binding `keypair`'s public key into `did` at `prevCID`,
 * for `roles` (all three by default).
 *
 * `prevCID` MUST be the `previousOperationCID` of the operation that will carry
 * the envelope — an envelope naming any other head is dead bytes, which is
 * precisely how standing consent is foreclosed.
 */
export const chainKeyProof = async (input: {
  /** The candidate key's raw private key — the envelope is self-proving. */
  privateKey: Uint8Array;
  did: string;
  prevCID: string;
  roles?: KeyRole[];
}): Promise<string> => {
  nonces += 1;
  const { proof } = await signKeyProof({
    typ: KEY_ADD_JWS_TYP,
    nonce: `relay-fixture-nonce-${nonces}`,
    audience: 'localhost',
    did: input.did,
    roleSet: serializeRoleSet(input.roles ?? ALL_ROLES),
    prevCID: input.prevCID,
    privateKey: input.privateKey,
  });
  return proof;
};
