/*

  REVOCATIONS — fold local revocation ops onto the credentials they invalidate

  A revocation is a standalone signed proof-plane op (typ: did:dfos:revocation)
  whose payload names the `credentialCID` its issuer permanently invalidates
  (see op-annotations.ts / protocol RevocationPayload). Revocations are synced
  into the local index like any other op, so a credential's active/revoked status
  can be folded LOCALLY — no relay round-trip — by matching revocation ops to
  credential CIDs. This is house doctrine: truth from the math you already hold.

  Relay-asserted until you open the credential; the credential detail view
  re-verifies any revocation proof (signature, CID, issuer binding). This fold
  is the discovery-index answer, not the proof.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { ExplorerOp } from './db';

/**
 * Index revocation ops by the credential CID they revoke → the revoking op's own
 * CID (so a revoked row can link to the revocation). First revocation wins on a
 * duplicate — revocation is permanent and one proof is enough.
 */
export const revokedByCredential = (revocationOps: ExplorerOp[]): Map<string, string> => {
  const byCredential = new Map<string, string>();
  for (const op of revocationOps) {
    const decoded = decodeJwsUnsafe(op.jwsToken);
    if (!decoded) continue;
    const credentialCID = decoded.payload['credentialCID'];
    if (typeof credentialCID !== 'string' || !credentialCID) continue;
    if (!byCredential.has(credentialCID)) byCredential.set(credentialCID, op.cid);
  }
  return byCredential;
};
