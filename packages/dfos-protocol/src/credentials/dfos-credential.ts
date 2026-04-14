/*

  DFOS CREDENTIAL

  UCAN-style credentials for protocol-level authorization. Replaces VC-JWTs
  entirely. Credentials are JWS-signed payloads with CID-addressable content,
  delegation chains via embedded parent tokens (`prf`), and monotonic
  attenuation enforcement.

  Two resource types:
  - chain:<contentId>  — exact match for a specific content chain
  - manifest:<contentId> — transitive match covering a manifest and its entries

  Two audience modes:
  - aud: "*"          — public credential, ingested into relays as standing auth
  - aud: <specific DID> — private credential, presented per-request, never stored

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { decodeMultikey } from '../chain/multikey';
import type { VerifiedIdentity } from '../chain/schemas';
import { DFOSCredentialPayload, type Attenuation } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedDFOSCredential {
  /** Issuer DID */
  iss: string;
  /** Audience DID or "*" for public */
  aud: string;
  /** Attenuations — resource + action pairs */
  att: Attenuation[];
  /** Parent credential JWS tokens */
  prf: string[];
  /** Expiry (unix seconds) */
  exp: number;
  /** Issued at (unix seconds) */
  iat: number;
  /** CID of the credential payload (for revocation references) */
  credentialCID: string;
  /** kid from the JWS header */
  signerKeyId: string;
}

export interface VerifiedDelegationChain {
  /** The leaf credential */
  credential: VerifiedDFOSCredential;
  /** All credentials in the chain, from leaf to root */
  chain: VerifiedDFOSCredential[];
  /** The root DID that ultimately authorized the chain */
  rootDID: string;
}

// -----------------------------------------------------------------------------
// key resolution helper
// -----------------------------------------------------------------------------

/**
 * Resolve a public key from a VerifiedIdentity by kid (DID URL)
 *
 * Searches across all key roles (auth, assert, controller). Returns the raw
 * Ed25519 public key bytes.
 */
const resolveKeyFromIdentity = (identity: VerifiedIdentity, kid: string): Uint8Array => {
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new CredentialVerificationError('kid must be a DID URL');
  const keyId = kid.substring(hashIdx + 1);

  const allKeys = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys];
  const key = allKeys.find((k) => k.id === keyId);
  if (!key) {
    throw new CredentialVerificationError(`key ${keyId} not found on identity ${identity.did}`);
  }

  const { keyBytes } = decodeMultikey(key.publicKeyMultibase);
  return keyBytes;
};

// -----------------------------------------------------------------------------
// create
// -----------------------------------------------------------------------------

/**
 * Create a signed DFOS credential
 *
 * The credential is a JWS with `typ: "did:dfos:credential"` and a CID in the
 * protected header for revocation addressability.
 */
export const createDFOSCredential = async (options: {
  issuerDID: string;
  /** Audience DID, or "*" for public credentials */
  audienceDID: string;
  att: Attenuation[];
  /** Parent credential JWS tokens (for delegation chains) */
  prf?: string[];
  /** Expiry — unix seconds */
  exp: number;
  /** Signer function */
  signer: (message: Uint8Array) => Promise<Uint8Array>;
  /** Key ID (without DID prefix — just the key_xxx part) */
  keyId: string;
  /** Issued-at override — unix seconds (defaults to Date.now()) */
  iat?: number;
}): Promise<string> => {
  const kid = `${options.issuerDID}#${options.keyId}`;
  const now = options.iat ?? Math.floor(Date.now() / 1000);

  const payload = {
    version: 1 as const,
    type: 'DFOSCredential' as const,
    iss: options.issuerDID,
    aud: options.audienceDID,
    att: options.att,
    prf: options.prf ?? [],
    exp: options.exp,
    iat: now,
  };

  // validate payload before signing
  const parseResult = DFOSCredentialPayload.safeParse(payload);
  if (!parseResult.success) {
    const messages = parseResult.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid credential payload: ${messages}`);
  }

  // derive CID
  const encoded = await dagCborCanonicalEncode(payload);
  const credentialCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:credential', kid, cid: credentialCID },
    payload: payload as unknown as Record<string, unknown>,
    sign: options.signer,
  });

  return jwsToken;
};

// -----------------------------------------------------------------------------
// verify (single credential)
// -----------------------------------------------------------------------------

/**
 * Verify a DFOS credential — signature, schema, expiry, CID integrity
 *
 * Does NOT verify the delegation chain. Use `verifyDelegationChain` for full
 * chain verification including attenuation enforcement.
 */
export const verifyDFOSCredential = async (
  jwsToken: string,
  options: {
    resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
    /** Current time in seconds (defaults to Date.now() / 1000) */
    now?: number;
  },
): Promise<VerifiedDFOSCredential> => {
  // decode JWS
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) throw new CredentialVerificationError('failed to decode credential JWS');

  // verify typ
  if (decoded.header.typ !== 'did:dfos:credential') {
    throw new CredentialVerificationError(`invalid typ: ${decoded.header.typ}`);
  }

  // parse payload
  const result = DFOSCredentialPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new CredentialVerificationError(`invalid credential payload: ${messages}`);
  }
  const payload = result.data;

  // verify kid DID matches issuer
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new CredentialVerificationError('credential kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.iss) {
    throw new CredentialVerificationError('credential kid DID does not match iss');
  }

  // resolve issuer identity and find signing key
  const identity = await options.resolveIdentity(payload.iss);
  if (!identity) {
    throw new CredentialVerificationError(`issuer identity not found: ${payload.iss}`);
  }
  if (identity.isDeleted) {
    throw new CredentialVerificationError(`issuer identity is deleted: ${payload.iss}`);
  }

  const publicKey = resolveKeyFromIdentity(identity, kid);

  // verify JWS signature
  try {
    verifyJws({ token: jwsToken, publicKey });
  } catch {
    throw new CredentialVerificationError('invalid credential signature');
  }

  // verify CID integrity
  const encoded = await dagCborCanonicalEncode(payload);
  const credentialCID = encoded.cid.toString();
  if (!decoded.header.cid) {
    throw new CredentialVerificationError('missing cid in credential header');
  }
  if (decoded.header.cid !== credentialCID) {
    throw new CredentialVerificationError('credential cid mismatch');
  }

  // temporal validity
  const now = options.now ?? Math.floor(Date.now() / 1000);
  if (payload.iat > now) {
    throw new CredentialVerificationError('credential not yet valid (iat is in the future)');
  }
  if (payload.exp <= now) {
    throw new CredentialVerificationError('credential expired');
  }

  return {
    iss: payload.iss,
    aud: payload.aud,
    att: payload.att,
    prf: payload.prf,
    exp: payload.exp,
    iat: payload.iat,
    credentialCID,
    signerKeyId: kid,
  };
};

// -----------------------------------------------------------------------------
// delegation chain verification
// -----------------------------------------------------------------------------

/**
 * Verify a full delegation chain — walk `prf`, confirm monotonic attenuation,
 * verify each credential's signature, and confirm the chain roots at `rootDID`.
 *
 * The chain is walked from the leaf credential upward through each parent in
 * `prf`. At each hop: the child's `iss` must match a parent's `aud` (or the
 * parent's `aud` must be `"*"`), the child's `att` must be attenuated from the
 * parent's `att`, and the child's `exp` must not exceed the parent's `exp`.
 *
 * The chain terminates when a credential has `prf: []` (root credential). The
 * root credential's `iss` must equal `rootDID`.
 */
export const verifyDelegationChain = async (
  credential: VerifiedDFOSCredential,
  options: {
    resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
    /** The expected root authority DID (e.g., content chain creator) */
    rootDID: string;
    /** Current time in seconds (defaults to Date.now() / 1000) */
    now?: number;
  },
): Promise<VerifiedDelegationChain> => {
  const chain: VerifiedDFOSCredential[] = [credential];

  let current = credential;
  const maxDepth = 16;

  for (let depth = 0; depth < maxDepth; depth++) {
    if (current.prf.length === 0) {
      // root credential — issuer must be the root DID
      if (current.iss !== options.rootDID) {
        throw new CredentialVerificationError(
          `delegation chain root issuer ${current.iss} does not match expected root ${options.rootDID}`,
        );
      }
      return { credential, chain, rootDID: options.rootDID };
    }

    // verify all parent credentials
    const parents: VerifiedDFOSCredential[] = [];
    for (const parentJws of current.prf) {
      const parent = await verifyDFOSCredential(parentJws, {
        resolveIdentity: options.resolveIdentity,
        ...(options.now !== undefined ? { now: options.now } : {}),
      });
      parents.push(parent);
    }

    // the child's issuer must be the audience of at least one parent
    const matchingParent = parents.find(
      (p) => p.aud === '*' || p.aud === current.iss,
    );
    if (!matchingParent) {
      throw new CredentialVerificationError(
        `delegation gap: no parent credential has audience matching child issuer ${current.iss}`,
      );
    }

    // child's exp must not exceed any parent's exp
    for (const parent of parents) {
      if (current.exp > parent.exp) {
        throw new CredentialVerificationError(
          'delegation chain: child credential expiry exceeds parent expiry',
        );
      }
    }

    // child's att must be attenuated from the union of all parents' att
    const parentAttUnion = parents.flatMap((p) => p.att);
    if (!isAttenuated(parentAttUnion, current.att)) {
      throw new CredentialVerificationError(
        'delegation chain: child credential scope exceeds parent scope',
      );
    }

    // add parents to chain and continue walking from the first parent
    // (multi-parent chains: we follow the first parent for the linear walk,
    // but all parents have been verified above)
    chain.push(...parents);
    current = parents[0]!;
  }

  throw new CredentialVerificationError('delegation chain too deep (max 16 hops)');
};

// -----------------------------------------------------------------------------
// attenuation
// -----------------------------------------------------------------------------

/** Parse a resource string into type and id */
const parseResource = (resource: string): { type: string; id: string } | null => {
  const colonIdx = resource.indexOf(':');
  if (colonIdx < 0) return null;
  return { type: resource.substring(0, colonIdx), id: resource.substring(colonIdx + 1) };
};

/** Parse action string into a set of individual actions */
const parseActions = (action: string): Set<string> => {
  return new Set(action.split(',').map((a) => a.trim()));
};

/**
 * Check if `childAtt` is a valid attenuation of `parentAtt`
 *
 * Every entry in `childAtt` must be covered by at least one entry in
 * `parentAtt`. Coverage rules:
 *
 * - `chain:X` covered by `chain:X` (exact match)
 * - `chain:X` covered by `manifest:M` (narrowing from manifest — valid structurally)
 * - `manifest:M` covered by `manifest:M` (exact match)
 * - `manifest:M` NOT covered by `chain:X` (widening — invalid)
 * - Actions: child action set must be a subset of parent action set
 */
export const isAttenuated = (parentAtt: Attenuation[], childAtt: Attenuation[]): boolean => {
  return childAtt.every((childEntry) => {
    const childRes = parseResource(childEntry.resource);
    if (!childRes) return false;
    const childActions = parseActions(childEntry.action);

    return parentAtt.some((parentEntry) => {
      const parentRes = parseResource(parentEntry.resource);
      if (!parentRes) return false;
      const parentActions = parseActions(parentEntry.action);

      // check action coverage — child actions must be subset of parent actions
      for (const a of childActions) {
        if (!parentActions.has(a)) return false;
      }

      // check resource coverage
      if (childRes.type === 'chain' && parentRes.type === 'chain') {
        // chain:X covered by chain:X (exact match)
        return childRes.id === parentRes.id;
      }
      if (childRes.type === 'chain' && parentRes.type === 'manifest') {
        // chain:X covered by manifest:M (narrowing — valid structurally)
        return true;
      }
      if (childRes.type === 'manifest' && parentRes.type === 'manifest') {
        // manifest:M covered by manifest:M (exact match)
        return childRes.id === parentRes.id;
      }
      // manifest:M NOT covered by chain:X (widening)
      return false;
    });
  });
};

// -----------------------------------------------------------------------------
// resource matching
// -----------------------------------------------------------------------------

/**
 * Check if an `att` array covers a requested resource
 *
 * Used at the relay to determine if a credential authorizes access to a
 * specific content chain.
 *
 * For `manifest:` resources, requires a `manifestLookup` callback to resolve
 * which contentIds the manifest indexes. Without the callback, `manifest:`
 * resources can only match exact `manifest:` requests, not `chain:` requests.
 */
export const matchesResource = async (
  att: Attenuation[],
  resource: string,
  action: string,
  options?: {
    manifestLookup?: (manifestContentId: string) => Promise<string[]>;
  },
): Promise<boolean> => {
  const requestedRes = parseResource(resource);
  if (!requestedRes) return false;
  const requestedActions = parseActions(action);

  for (const entry of att) {
    const entryRes = parseResource(entry.resource);
    if (!entryRes) continue;
    const entryActions = parseActions(entry.action);

    // check action coverage
    let actionsCovered = true;
    for (const a of requestedActions) {
      if (!entryActions.has(a)) {
        actionsCovered = false;
        break;
      }
    }
    if (!actionsCovered) continue;

    // exact resource match (chain:X == chain:X, manifest:M == manifest:M)
    if (entryRes.type === requestedRes.type && entryRes.id === requestedRes.id) {
      return true;
    }

    // manifest covers chain transitively
    if (entryRes.type === 'manifest' && requestedRes.type === 'chain') {
      if (options?.manifestLookup) {
        const indexed = await options.manifestLookup(entryRes.id);
        if (indexed.includes(requestedRes.id)) return true;
      }
      // without lookup, manifest: can't resolve to chain: — fall through
    }
  }

  return false;
};

// -----------------------------------------------------------------------------
// decode (unsafe)
// -----------------------------------------------------------------------------

/**
 * Decode a DFOS credential JWS without verifying the signature
 *
 * Returns null if the token is malformed or payload is invalid.
 */
export const decodeDFOSCredentialUnsafe = (
  jwsToken: string,
): {
  header: { alg: string; typ: string; kid: string; cid: string };
  payload: DFOSCredentialPayload;
} | null => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return null;

  const result = DFOSCredentialPayload.safeParse(decoded.payload);
  if (!result.success) return null;

  return {
    header: decoded.header as { alg: string; typ: string; kid: string; cid: string },
    payload: result.data,
  };
};

// -----------------------------------------------------------------------------
// errors
// -----------------------------------------------------------------------------

export class CredentialVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialVerificationError';
  }
}

// -----------------------------------------------------------------------------
// re-export types
// -----------------------------------------------------------------------------

export type { Attenuation, DFOSCredentialPayload } from './schemas';
