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
  importEd25519Keypair,
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
  return bootstrapWithKeyMaterial(store, {
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    keyId,
  });
};

/**
 * Bootstrap a relay identity from an EXISTING key + key ID, with optional pinned
 * timestamps and profile name. Used for deterministic bootstrap — e.g. the
 * dual-relay parity harness pins one key + one createdAt across both twins so
 * the relay's own genesis + profile log entries are byte-identical, and durable
 * relays that reload their key from storage. Mirrors the Go twin's
 * BootstrapRelayIdentityFromKey.
 */
export const bootstrapRelayIdentityFromKey = async (
  store: RelayStore,
  params: {
    privateKey: Uint8Array;
    keyId: string;
    name?: string;
    createdAt?: string;
  },
): Promise<RelayIdentity> => {
  const { publicKey } = importEd25519Keypair(params.privateKey);
  return bootstrapWithKeyMaterial(store, {
    privateKey: params.privateKey,
    publicKey,
    keyId: params.keyId,
    ...(params.name !== undefined ? { name: params.name } : {}),
    ...(params.createdAt !== undefined ? { createdAt: params.createdAt } : {}),
  });
};

/**
 * Shared bootstrap core: sign + ingest the identity genesis and profile
 * artifact for the given key material. The JIT path passes a random key and
 * lets createdAt default to now; the from-key path pins both.
 */
const bootstrapWithKeyMaterial = async (
  store: RelayStore,
  params: {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    keyId: string;
    name?: string;
    createdAt?: string;
  },
): Promise<RelayIdentity> => {
  const { privateKey, publicKey, keyId } = params;
  const name = params.name ?? 'DFOS Relay';
  const createdAt = params.createdAt ?? new Date().toISOString();
  const multibase = encodeEd25519Multikey(publicKey);
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, privateKey);

  const key = { id: keyId, type: 'Multikey' as const, publicKeyMultibase: multibase };

  // --- identity genesis ---

  const identityOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [key],
    assertKeys: [key],
    controllerKeys: [key],
    createdAt,
  };

  const { jwsToken: identityJws } = await signIdentityOperation({
    operation: identityOp,
    signer,
    keyId,
  });

  // ingest identity genesis to derive the DID
  const [identityResult] = await ingestOperations([identityJws], store);
  if (!identityResult || identityResult.status === 'rejected' || !identityResult.chainId) {
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
      name,
    },
    createdAt,
  };

  const kid = `${did}#${keyId}`;
  const { jwsToken: profileArtifactJws } = await signArtifact({
    payload: profilePayload,
    signer,
    kid,
  });

  // ingest profile artifact into the store
  const [artifactResult] = await ingestOperations([profileArtifactJws], store);
  if (!artifactResult || artifactResult.status === 'rejected') {
    throw new Error(
      `failed to ingest relay profile artifact: ${artifactResult?.error ?? 'unknown'}`,
    );
  }

  return { did, profileArtifactJws };
};
