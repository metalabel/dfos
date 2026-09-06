/*

  DFOS CREDENTIAL

  UCAN-style credentials for protocol-level authorization. Replaces VC-JWTs
  entirely. Credentials are JWS-signed payloads with CID-addressable content,
  delegation chains via embedded parent tokens (`prf`), and monotonic
  attenuation enforcement.

  Resource types:
  - chain:*            — wildcard covering all content chains
  - chain:<contentId>  — exact match for a specific content chain

  Two audience modes:
  - aud: "*"          — public credential, ingested into relays as standing auth
  - aud: <specific DID> — private credential, presented per-request, never stored

*/

import { decodeMultikey } from '../chain/multikey';
import type { VerifiedIdentity } from '../chain/schemas';
import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { markDependencyMissing } from '../dependency';
import { DFOSCredentialPayload, MAX_CREDENTIAL_SIZE, type Attenuation } from './schemas';

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

/**
 * Check whether a credential (leaf or any parent) has been revoked.
 *
 * `asOfUnix` selects WHICH question is being asked, and the two are different
 * decisions: **acceptance is a freshness decision; verification at a basis is a
 * validity decision.**
 *
 * - **Omitted, or `<= 0` (timeless)** — "is this credential revoked as far as you
 *   know right now?". The freshness question. Used by acceptance gates: relay
 *   ingest (do not admit a NEW operation authorized by a credential we already
 *   know to be revoked) and live read-path authorization. Non-positive instants
 *   are timeless because the Go twin uses `0` as its in-band sentinel and cannot
 *   express "as of epoch 0"; the degenerate case (an operation dated at or before
 *   1970) therefore gets the stricter answer in both languages.
 * - **Positive (as-of)** — "was this credential already revoked at `asOfUnix`?".
 *   The validity question. Return true only if a revocation exists AND its
 *   signed `createdAt` is ≤ `asOfUnix`. Used when verifying an artifact against
 *   a basis, where `asOfUnix` is the basis in integer Unix seconds. A revocation
 *   signed AFTER the basis does not invalidate the artifact — see CREDENTIALS.md
 *   "Revocation against the basis".
 *
 * An implementation that ignores `asOfUnix` degrades to the timeless answer,
 * which is always the stricter (safe) direction — it can only reject history
 * that as-of semantics would accept.
 */
export type RevocationChecker = (
  issuerDID: string,
  credentialCID: string,
  asOfUnix?: number,
) => Promise<boolean>;

// -----------------------------------------------------------------------------
// key resolution helper
// -----------------------------------------------------------------------------

/**
 * Resolve a public key from a VerifiedIdentity by kid (DID URL)
 *
 * Searches the identity's EFFECTIVE key arrays across all three roles (auth,
 * assert, controller) and returns the raw Ed25519 public key bytes.
 *
 * THE CALLER OWNS THE BASIS, THIS FUNCTION OWNS THE SEARCH. The single time
 * basis is satisfied by handing this the identity's state AS OF the basis, so
 * `provedKeys` — the has-ever-proved union — is never consulted here: a key
 * effective at the basis is in these arrays, and a key rotated out before it is
 * not. Widening the search to has-ever would re-open forward issuance by a key
 * the identity has already retired.
 */
const resolveKeyFromIdentity = (
  identity: VerifiedIdentity,
  kid: string,
  /** True when the caller resolved this identity against an explicit basis. */
  atBasis: boolean,
): Uint8Array => {
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new CredentialVerificationError('kid must be a DID URL');
  const keyId = kid.substring(hashIdx + 1);

  const allKeys = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys];
  const key = allKeys.find((k) => k.id === keyId);
  if (!key) {
    const miss = new CredentialVerificationError(
      `key ${keyId} not found on identity ${identity.did}`,
    );
    // At a basis the identity's key state is determinate, so the miss is a
    // verdict. Without one the caller resolved head state, where a fuller chain
    // can still change the answer — see `markDependencyMissing`.
    throw atBasis ? miss : markDependencyMissing(miss);
  }

  const { keyBytes } = decodeMultikey(key.publicKeyMultibase);
  return keyBytes;
};

/**
 * The basis in integer Unix seconds — the form `exp` and revocation compare
 * against.
 *
 * TRUNCATES, never rounds (PROTOCOL, Time basis). Rounding up would push an
 * operation's basis into the second after the one it was signed in, and two
 * implementations disagreeing by one second on the `exp` boundary fork
 * authorization.
 */
const basisUnixSeconds = (basis: string): number => {
  const ms = Date.parse(basis);
  if (Number.isNaN(ms)) throw new CredentialVerificationError(`invalid basis time: ${basis}`);
  return Math.floor(ms / 1000);
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
 * Every check runs against ONE basis time (PROTOCOL, Time basis): the issuer's
 * key must be effective in the identity's state as of the basis, and `exp` must
 * be strictly greater than the basis in integer Unix seconds. `iat` is
 * informational and gates nothing.
 *
 * Does NOT verify the delegation chain. Use `verifyDelegationChain` for full
 * chain verification including attenuation enforcement.
 */
export const verifyDFOSCredential = async (
  jwsToken: string,
  options: {
    /**
     * Resolve a DID to its verified identity state AS OF `basis`. Called with
     * the basis this verification runs at, or with none when the presentation is
     * ephemeral and the answer is head state.
     */
    resolveIdentity: (did: string, basis?: string) => Promise<VerifiedIdentity | undefined>;
    /**
     * The basis time, in the `createdAt` grammar — the operation's own
     * `createdAt` for a credential carried inline in a committed operation.
     * Omitted for an ephemeral presentation, where the basis is now.
     */
    basis?: string;
  },
): Promise<VerifiedDFOSCredential> => {
  // bound credential size — the credential's analog of MAX_OPERATION_SIZE. The
  // leaf token embeds the entire nested delegation chain (each parent is carried
  // in `prf`), so this one cap bounds the whole chain. Checked before any decode
  // or recursion as a DoS guard. (JWS tokens are base64url + dots = ASCII, so
  // string length equals byte length.)
  if (jwsToken.length > MAX_CREDENTIAL_SIZE) {
    throw new CredentialVerificationError(
      `credential exceeds max size: ${jwsToken.length} > ${MAX_CREDENTIAL_SIZE}`,
    );
  }

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

  // resolve the issuer identity as of the basis and find the signing key
  const identity = await options.resolveIdentity(payload.iss, options.basis);
  if (!identity) {
    // MARKED: the caller's resolver does not hold the issuer's chain. A relay
    // keeps such an operation pending; the issuer may still be syncing.
    throw markDependencyMissing(
      new CredentialVerificationError(`issuer identity not found: ${payload.iss}`),
    );
  }
  // Deletion is the one credential rule that does not run against the basis: a
  // deleted issuer authorizes nothing, retroactively (CREDENTIALS, Deleted
  // issuers). The resolver reports head deletion state whatever basis it was
  // asked for.
  if (identity.isDeleted) {
    throw new CredentialVerificationError(`issuer identity is deleted: ${payload.iss}`);
  }

  const publicKey = resolveKeyFromIdentity(identity, kid, options.basis !== undefined);

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

  // Temporal validity against the one basis. `iat` is informational: a
  // credential dated after the basis is not a rejection, because the basis, not
  // the issuer's clock, decides when authority applies.
  const basisSeconds =
    options.basis !== undefined ? basisUnixSeconds(options.basis) : Math.floor(Date.now() / 1000);
  if (payload.exp <= basisSeconds) {
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
 *
 * ONE BASIS FOR THE WHOLE WALK. Every hop — each parent's signing key, each
 * `exp`, each revocation — resolves against the same basis the leaf did, so a
 * chain either held at that instant or it did not.
 */
export const verifyDelegationChain = async (
  credential: VerifiedDFOSCredential,
  options: {
    /** Resolve a DID to its verified identity state as of `basis`. */
    resolveIdentity: (did: string, basis?: string) => Promise<VerifiedIdentity | undefined>;
    /** The expected root authority DID (e.g., content chain creator) */
    rootDID: string;
    /** Check if a credential has been revoked (checked at every level of the chain) */
    isRevoked?: RevocationChecker;
    /**
     * The basis time, in the `createdAt` grammar. Omitted for an ephemeral
     * presentation: `exp` runs against the wall clock and revocation is asked
     * timelessly, which is the stricter direction (see `RevocationChecker`).
     */
    basis?: string;
  },
): Promise<VerifiedDelegationChain> => {
  const chain: VerifiedDFOSCredential[] = [credential];
  const revocationBasis = options.basis !== undefined ? basisUnixSeconds(options.basis) : undefined;

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

    // DFOS delegation is LINEAR: exactly one parent per hop. Multi-parent
    // proofs are rejected. A union-of-authority model (att taken from the
    // union of all parents, but the root walk continuing only through the
    // first parent) let a self-issued secondary parent contribute scope that
    // was never rooted at rootDID — an authority-escalation. Linear delegation
    // removes the class entirely.
    if (current.prf.length > 1) {
      throw new CredentialVerificationError(
        'delegation chain: multi-parent credentials are not supported (prf must have at most one entry)',
      );
    }

    // verify the single parent credential
    const parent = await verifyDFOSCredential(current.prf[0]!, {
      resolveIdentity: options.resolveIdentity,
      ...(options.basis !== undefined ? { basis: options.basis } : {}),
    });

    // Revocation at every level of the chain, on the SAME basis as the leaf: a
    // parent revoked after the basis does not reach back past it, and the whole
    // chain is evaluated at one instant. MUST stay in sync with the Go twin
    // (delegation.go).
    if (options.isRevoked) {
      const revoked = await options.isRevoked(parent.iss, parent.credentialCID, revocationBasis);
      if (revoked) {
        throw new CredentialVerificationError('parent credential in delegation chain is revoked');
      }
    }

    // the child's issuer must be the parent's audience
    if (parent.aud !== '*' && parent.aud !== current.iss) {
      throw new CredentialVerificationError(
        `delegation gap: parent credential audience ${parent.aud} does not match child issuer ${current.iss}`,
      );
    }

    // child's exp must not exceed the parent's exp
    if (current.exp > parent.exp) {
      throw new CredentialVerificationError(
        'delegation chain: child credential expiry exceeds parent expiry',
      );
    }

    // child's att must be attenuated from the parent's att
    if (!isAttenuated(parent.att, current.att)) {
      throw new CredentialVerificationError(
        'delegation chain: child credential scope exceeds parent scope',
      );
    }

    // add parent to chain and continue walking
    chain.push(parent);
    current = parent;
  }

  throw new CredentialVerificationError('delegation chain too deep (max 16 credentials)');
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

/** Parse action string into a set of individual actions.
 *
 * Splits on comma, trims each element, and DROPS empty elements so the action
 * set is canonical: "write," / "read,,write" / "  read , write " all reduce to
 * their non-empty token sets. This converges TS onto the Go ParseActions
 * (delegation.go) so isAttenuated and matchesResource reach identical verdicts
 * across implementations — a divergent empty-string element would otherwise
 * make a child action "write," covered by parent "write" on Go but not TS. */
const parseActions = (action: string): Set<string> =>
  new Set(
    action
      .split(',')
      .map((a) => a.trim())
      .filter((a) => a !== ''),
  );

/**
 * Check if `childAtt` is a valid attenuation of `parentAtt`
 *
 * Every entry in `childAtt` must be covered by at least one entry in
 * `parentAtt`. Coverage rules:
 *
 * - `chain:X` covered by `chain:X` (exact match)
 * - `chain:X` covered by `chain:*` (narrowing from wildcard — valid)
 * - `chain:*` covered by `chain:*` (exact match)
 * - `chain:*` NOT covered by `chain:X` (widening — invalid)
 * - Non-`chain` types (`mailbox:<id>`, and any form a future capability
 *   registers): exact byte equality of the full resource string, nothing else.
 *   The wildcard is a `chain:`-only concept — a literal `*` id in any other
 *   type is an ordinary id covering only itself — and coverage never crosses
 *   resource types. See CREDENTIALS.md "Resource Types".
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
      if (parentRes.type === 'chain' && parentRes.id === '*') {
        // chain:* covers chain:X and chain:*
        return childRes.type === 'chain';
      }
      if (childRes.type === 'chain' && childRes.id === '*') {
        // chain:* can only be covered by chain:* (checked above)
        return false;
      }
      if (childRes.type === 'chain' && parentRes.type === 'chain') {
        // chain:X covered by chain:X (exact match)
        return childRes.id === parentRes.id;
      }
      if (childRes.type !== 'chain' && parentRes.type !== 'chain') {
        // non-chain forms narrow by exact byte equality only — no wildcard
        return childEntry.resource === parentEntry.resource;
      }
      // coverage never crosses resource types
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
 */
export const matchesResource = async (
  att: Attenuation[],
  resource: string,
  action: string,
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

    // chain:* covers any chain: request
    if (entryRes.type === 'chain' && entryRes.id === '*' && requestedRes.type === 'chain') {
      return true;
    }

    // exact resource match (chain:X == chain:X)
    if (entryRes.type === requestedRes.type && entryRes.id === requestedRes.id) {
      return true;
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
