/*

  BOOTSTRAP RELAY IDENTITY

  Generate a JIT (just-in-time) relay identity and profile artifact. Used when
  createRelay is called without a pre-created identity.

*/

import {
  encodeEd25519Multikey,
  signArtifact,
  signIdentityOperation,
  type ArtifactPayload,
  type IdentityOperation,
} from '@metalabel/dfos-protocol/chain';
import {
  createNewEd25519Keypair,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { ingestOperations } from './ingest';
import type { RelayIdentity, RelayStore } from './types';

/**
 * Generate a relay identity and profile artifact, ingest both into the store
 *
 * Creates an Ed25519 keypair, signs an identity genesis operation, derives
 * the DID, then signs a profile artifact with the relay's name. Both the
 * identity genesis and profile artifact are ingested into the store so
 * they are available via the relay's proof plane routes.
 */
export const bootstrapRelayIdentity = async (store: RelayStore): Promise<RelayIdentity> => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);

  const key = { id: keyId, type: 'Multikey' as const, publicKeyMultibase: multibase };

  // --- identity genesis ---

  const identityOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key],
    assertKeys: [key],
    controllerKeys: [key],
    createdAt: new Date().toISOString(),
  };

  const { jwsToken: identityJws } = await signIdentityOperation({
    operation: identityOp,
    signer,
    keyId,
  });

  // ingest identity genesis to derive the DID
  const [identityResult] = await ingestOperations([identityJws], store);
  if (!identityResult || identityResult.status !== 'accepted' || !identityResult.chainId) {
    throw new Error(`failed to bootstrap relay identity: ${identityResult?.error ?? 'unknown'}`);
  }
  const did = identityResult.chainId;

  // --- profile artifact ---

  const profilePayload: ArtifactPayload = {
    version: 1,
    type: 'artifact',
    did,
    content: {
      $schema: 'https://schemas.dfos.com/profile/v1',
      name: 'DFOS Relay',
    },
    createdAt: new Date().toISOString(),
  };

  const kid = `${did}#${keyId}`;
  const { jwsToken: profileArtifactJws } = await signArtifact({
    payload: profilePayload,
    signer,
    kid,
  });

  // ingest profile artifact into the store
  const [artifactResult] = await ingestOperations([profileArtifactJws], store);
  if (!artifactResult || artifactResult.status !== 'accepted') {
    throw new Error(
      `failed to ingest relay profile artifact: ${artifactResult?.error ?? 'unknown'}`,
    );
  }

  return { did, profileArtifactJws };
};
