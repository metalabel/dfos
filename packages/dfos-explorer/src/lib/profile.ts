/*

  PROFILE — decode + verify profile/v1 documents, honestly

  Two carriers of a profile in DFOS:
    - a relay's inline profile ARTIFACT (the `profile` JWS in /.well-known),
      verified against the relay's OWN identity keys (verifyArtifact).
    - an identity's profile CONTENT chain, anchored via a ContentAnchor service,
      verified by re-hashing the served bytes to the on-chain committed CID.

  This module owns the pure decode/verify primitives; the async orchestration
  (fetching the chain, the bytes) stays in the views. Nothing here fakes trust:
  a relay describing itself is a claim until its artifact signature checks out
  against its self-certifying DID.

*/

import {
  decodeMultikey,
  verifyArtifact,
  type VerifiedIdentity,
} from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

export const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';

/** profile/v1 shape — name + optional description + optional avatar (Media). */
export interface ProfileContent {
  $schema: string;
  name?: string;
  description?: string;
  avatar?: unknown;
}

export const isProfileContent = (x: unknown): x is ProfileContent =>
  typeof x === 'object' &&
  x !== null &&
  (x as Record<string, unknown>)['$schema'] === PROFILE_SCHEMA;

// -----------------------------------------------------------------------------
// relay inline profile artifact
// -----------------------------------------------------------------------------

/** Beat-1 unsafe decode of a relay's inline profile artifact JWS. */
export interface RelayProfileClaim {
  /** payload.did — the DID the artifact claims to be signed by */
  did: string;
  /** DID prefix of the header.kid */
  kidDid: string;
  /** parsed profile content when the artifact carries profile/v1 */
  profile: ProfileContent | null;
  /** did === kidDid — a cheap consistency check on the claim itself */
  selfConsistent: boolean;
}

export const decodeRelayProfile = (jws: string): RelayProfileClaim | null => {
  const decoded = decodeJwsUnsafe(jws);
  if (!decoded) return null;
  const payload = decoded.payload as Record<string, unknown>;
  const did = typeof payload['did'] === 'string' ? payload['did'] : '';
  const kid = typeof decoded.header.kid === 'string' ? decoded.header.kid : '';
  const kidDid = kid.includes('#') ? kid.slice(0, kid.indexOf('#')) : '';
  const content = payload['content'];
  return {
    did,
    kidDid,
    profile: isProfileContent(content) ? content : null,
    selfConsistent: !!did && did === kidDid,
  };
};

/** Resolve a kid to its public key bytes from a verified identity's key set. */
const keyResolver =
  (identity: VerifiedIdentity) =>
  async (kid: string): Promise<Uint8Array> => {
    const keys = [
      ...(identity.authKeys ?? []),
      ...(identity.assertKeys ?? []),
      ...(identity.controllerKeys ?? []),
    ];
    const frag = kid.includes('#') ? kid.slice(kid.indexOf('#') + 1) : kid;
    const match = keys.find((k) => k.id === kid || k.id === frag || k.id.endsWith(`#${frag}`));
    if (!match) throw new Error('kid not present in the identity key set');
    return decodeMultikey(match.publicKeyMultibase).keyBytes;
  };

export type RelayProfileVerdict =
  | { ok: true; profile: ProfileContent }
  | { ok: false; error: string };

/**
 * Fully verify a relay's inline profile artifact against its OWN verified
 * identity: signature by a key the identity actually holds, kid-DID match, and
 * self-consistent CID. The identity itself is self-certifying (its DID is the
 * hash of its genesis op), so this binds the relay's self-description to math.
 */
export const verifyRelayProfile = async (
  identity: VerifiedIdentity,
  jws: string,
): Promise<RelayProfileVerdict> => {
  try {
    const result = await verifyArtifact({ jwsToken: jws, resolveKey: keyResolver(identity) });
    const content = (result.payload as Record<string, unknown>)['content'];
    if (!isProfileContent(content)) return { ok: false, error: 'artifact is not a profile/v1 doc' };
    return { ok: true, profile: content };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
};

// -----------------------------------------------------------------------------
// identity profile via anchored content
// -----------------------------------------------------------------------------

/** ContentAnchor labels an identity uses for its profile chain, in priority order. */
const PROFILE_ANCHOR_LABELS = ['profile', 'avatar'];

/**
 * Pick the profile anchor from a verified identity's services: a ContentAnchor
 * targeting a content chain (not an artifact CID). Prefers a `profile`-labeled
 * anchor, then `avatar`, then the first content-chain ContentAnchor.
 */
export const profileAnchorOf = (
  services: { type: string; [k: string]: unknown }[] | undefined,
): string | null => {
  const anchors = (services ?? []).filter(
    (s) =>
      s.type === 'ContentAnchor' &&
      typeof s['anchor'] === 'string' &&
      // only content chains (31-char ids) carry a profile doc; artifact CIDs
      // (baf…) are out of scope for the profile card
      !(s['anchor'] as string).startsWith('baf'),
  );
  const labelOf = (s: { [k: string]: unknown }): string =>
    typeof s['label'] === 'string' ? (s['label'] as string).toLowerCase() : '';
  for (const want of PROFILE_ANCHOR_LABELS) {
    const hit = anchors.find((s) => labelOf(s) === want);
    if (hit) return hit['anchor'] as string;
  }
  const first = anchors[0];
  return first ? (first['anchor'] as string) : null;
};
