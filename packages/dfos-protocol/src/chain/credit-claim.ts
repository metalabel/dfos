/*

  CREDIT CLAIM

  A claimant's standalone signed assertion that it holds a named role on a
  content chain — "I, did:dfos:alice, am the photographer of chain X."

  Attribution, not authorization. A credit claim grants nothing and authorizes
  nothing; it is a statement about who made a thing. The authorization story is
  credentials (see ../credentials), and the multi-writer story is delegated
  content operations — neither is the attribution story.

  A credit claim is a DOCUMENT-PLANE artifact. It is not gossiped and relays are
  not credit-claim aware: a claim travels inside the document bytes that embed
  it, in the `claim` field of a `credits[]` entry. This keeps attribution on the
  same side of the trust boundary as the content it attributes — chain metadata
  is public, document bytes are gated — so a claim on gated content is no more
  visible than the content itself.

  The bind is two-way. The space-signed document asserts the entry (assertion by
  commitment); the claimant signs the claim (assertion by signature); the two are
  bound by the exact match of (contentId, did, role) between the entry plaintext
  and the signed payload. See `specs/CREDITS.md` for the four verification states
  and the full algorithm.

  Verification deliberately does NOT consult the claimant's isDeleted state —
  historical attribution survives a claimant tombstone. This is the opposite of
  the credential rule, and it is intentional: see verifyCreditClaim below.

  ENTRY POINTS. `verifyCreditEntry` is the one most callers want: it resolves a
  whole `credits[]` entry to one of the four spec states and performs the FULL
  three-component bind. `verifyCreditClaim` verifies a claim token in isolation
  and checks only the `contentId` component — reach for it only when there is no
  entry to bind against.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { markDependencyMissing } from '../dependency';
import { decodeMultikey } from './multikey';
import { CreditClaimPayload, MAX_CREDIT_CLAIM_SIZE } from './schemas';
import type { Signer, VerifiedIdentity } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedCreditClaim {
  /** The claimant DID that signed this claim */
  did: string;
  /** The content chain this claim binds to — the 31-char contentId */
  contentId: string;
  /** The claimed role, compared by exact byte equality */
  role: string;
  /** Timestamp of the claim */
  createdAt: string;
  /** Optional pinned document state the claimant credited itself on */
  asOfDocumentCID?: string;
  /** kid from the JWS header */
  signerKeyId: string;
  /** CID of the claim artifact itself */
  claimCID: string;
}

/**
 * The four states a `credits[]` entry resolves to (see `specs/CREDITS.md`).
 *
 * `invalid` and `unverifiable` are deliberately distinct and MUST NOT be
 * collapsed: `invalid` means "checked and failed" (a positive signal that
 * something is wrong), `unverifiable` means "could not check" (the claim may be
 * perfectly valid). Rendering `invalid` as `unclaimed` launders a failure into
 * the ordinary case.
 */
export type CreditEntryState = 'claimed' | 'unclaimed' | 'invalid' | 'unverifiable';

/** Why a credit-claim verification failed — the consumer-visible verdict split */
export type CreditClaimFailureReason = 'invalid' | 'unverifiable';

/**
 * Thrown by `verifyCreditClaim`, carrying the spec's verdict as a FIELD.
 *
 * Consumers MUST branch on `reason`, never on the message text. The message is
 * diagnostic prose and may be reworded at any time; `reason` is the contract.
 */
export class CreditClaimVerifyError extends Error {
  readonly reason: CreditClaimFailureReason;

  constructor(reason: CreditClaimFailureReason, message: string) {
    super(message);
    this.name = 'CreditClaimVerifyError';
    this.reason = reason;
  }
}

const invalid = (message: string) => new CreditClaimVerifyError('invalid', message);
const unverifiable = (message: string) => new CreditClaimVerifyError('unverifiable', message);

/** A `credits[]` entry as it appears in document bytes — every field untrusted */
export interface CreditEntry {
  did?: unknown;
  role?: unknown;
  name?: unknown;
  claim?: unknown;
}

export interface VerifiedCreditEntry {
  /** The resolved state of this entry */
  state: CreditEntryState;
  /** Human-readable diagnosis — display prose, never a branch target */
  note: string;
  /** The verified claim, present only when `state` is 'claimed' */
  claim?: VerifiedCreditClaim;
}

// -----------------------------------------------------------------------------
// key resolution helper
// -----------------------------------------------------------------------------

/**
 * Resolve a public key from a VerifiedIdentity by kid (DID URL)
 *
 * Searches across all key roles (auth, assert, controller) — the protocol does
 * not restrict which role may sign a claim, matching the credential rule.
 *
 * KEY HISTORY IS THE RESOLVER'S CONTRACT, not this function's. A claim is a
 * permanent historical attribution, so a `resolveIdentity` passed to
 * `verifyCreditClaim` MUST supply every key the claimant's identity chain has
 * ever held, not only its current head state — exactly as the credential path
 * already requires (see `createIdentityResolver` in `@metalabel/dfos-client`,
 * which merges historical keys so credential validity persists across
 * rotations). A resolver that returns only current-state keys reports `invalid`
 * for every claim signed before the claimant's most recent rotation, silently
 * un-crediting real work. `verifyIdentityChain`'s `VerifiedIdentity` is a
 * CURRENT-state projection — do not hand it to this verifier unmerged.
 */
const resolveKeyFromIdentity = (identity: VerifiedIdentity, kid: string): Uint8Array => {
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw invalid('credit claim kid must be a DID URL');
  const keyId = kid.substring(hashIdx + 1);

  const allKeys = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys];
  const key = allKeys.find((k) => k.id === keyId);
  if (!key) {
    // MARKED: the resolver produced this identity but not this key. A resolver
    // that returns only current-state keys reports this for every claim signed
    // before a rotation, so the answer changes with what the caller holds.
    throw markDependencyMissing(invalid(`key ${keyId} not found on identity ${identity.did}`));
  }

  const { keyBytes } = decodeMultikey(key.publicKeyMultibase);
  return keyBytes;
};

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Normalize a claim `createdAt` to the canonical `.000Z` form
 *
 * A signed claim's `createdAt` is ALWAYS whole seconds with a zeroed millisecond
 * component — the `signRevocation` convention this envelope family follows. The
 * normalization applies to a caller-supplied override too, not just to `now`:
 * `createdAt` is inside the signed payload, so it is part of the claim's bytes and
 * therefore of its CID. Letting an override carry real milliseconds through would
 * mean the same logical override produced different claim CIDs on this
 * implementation and the Go twin (whose signer truncates), which is a
 * cross-implementation identity fork over a field nothing reads for ordering.
 *
 * MUST match the Go reference (`SignCreditClaimWithOptions`, which truncates
 * `CreatedAt` to whole seconds).
 */
const normalizeClaimCreatedAt = (createdAt?: string): string => {
  if (createdAt === undefined) {
    return new Date().toISOString().replace(/\d{3}Z$/, '000Z');
  }
  const ms = Date.parse(createdAt);
  if (Number.isNaN(ms)) {
    throw new Error(`invalid credit claim payload: unparseable createdAt: ${createdAt}`);
  }
  // floor, never round — a sub-second component is discarded, matching Go's
  // Truncate(time.Second) for every timestamp this protocol carries
  return new Date(Math.floor(ms / 1000) * 1000).toISOString();
};

/**
 * Sign a credit claim as a JWS
 *
 * The claim binds to the content chain's stable `contentId`, not to a document —
 * so a signed claim stays valid verbatim across every subsequent edit of the
 * chain. Callers SHOULD sign a given (contentId, did, role) triple exactly once
 * and reuse the token: re-signing mints a fresh `createdAt`, which changes the
 * claim bytes, which changes the embedding document's CID. Pass `createdAt` to
 * re-derive a previously issued claim's exact bytes (the same override register
 * as `createDFOSCredential`'s `iat`).
 *
 * The `kid` is derived from `did` + `keyId` here rather than accepted from the
 * caller, so a claim whose kid DID disagrees with its payload DID — the shape
 * every verifier MUST reject — is unrepresentable at sign time.
 */
export const signCreditClaim = async (input: {
  contentId: string;
  did: string;
  role: string;
  /** Optional document state the claimant pins its credit to */
  asOfDocumentCID?: string;
  /**
   * ISO 8601 override; defaults to now. NORMALIZED to whole seconds either way —
   * a sub-second component you pass is discarded, not signed. See
   * `normalizeClaimCreatedAt`.
   */
  createdAt?: string;
  signer: Signer;
  keyId: string;
}): Promise<{ jwsToken: string; claimCID: string }> => {
  const kid = `${input.did}#${input.keyId}`;
  const now = normalizeClaimCreatedAt(input.createdAt);

  // An empty-string flavor is a DIFFERENT signed encoding from an absent one (the
  // key is present, so the CID differs). Refuse it rather than minting a claim the
  // verifiers reject — callers meaning "no flavor" omit the field.
  if (input.asOfDocumentCID === '') {
    throw new Error(
      'invalid credit claim payload: asOfDocumentCID must be non-empty when present (omit the field instead)',
    );
  }

  const payload = {
    version: 1 as const,
    type: 'credit-claim' as const,
    contentId: input.contentId,
    did: input.did,
    role: input.role,
    createdAt: now,
    // omitted when absent — undefined strips under canonical CBOR, so a claim
    // without the flavor encodes identically to one that never had the field
    ...(input.asOfDocumentCID !== undefined ? { asOfDocumentCID: input.asOfDocumentCID } : {}),
  };

  // validate before signing — a malformed contentId must never reach the wire
  const parseResult = CreditClaimPayload.safeParse(payload);
  if (!parseResult.success) {
    const messages = parseResult.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid credit claim payload: ${messages}`);
  }

  const encoded = await dagCborCanonicalEncode(payload);
  const claimCID = encoded.cid.toString();

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:credit-claim', kid, cid: claimCID },
    payload: payload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  // enforce the aggregate cap on the SIGN path too. A signer that mints a token
  // over the cap has produced a claim every verifier — including this one — MUST
  // reject, so failing here beats embedding dead bytes in a document.
  if (jwsToken.length > MAX_CREDIT_CLAIM_SIZE) {
    throw new Error(`credit claim exceeds max size: ${jwsToken.length} > ${MAX_CREDIT_CLAIM_SIZE}`);
  }

  return { jwsToken, claimCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a credit claim JWS — size, signature, CID, payload schema, signer match
 *
 * Prefer `verifyCreditEntry` when you have a `credits[]` entry: this function
 * checks only the `contentId` component of the three-component bind, leaving
 * `did` and `role` to the caller.
 *
 * Pass `expectedContentId` to enforce the anti-replay half of the bind: without
 * it, a valid claim lifted from one chain's document verifies when replayed in
 * another chain's document. A consumer verifying a credits entry ALWAYS knows
 * which chain it is reading, so it should always pass it. Omit the option
 * entirely to skip the check; passing an EMPTY STRING is an error, never a skip
 * (a zero-valued content id is a bug, not a request for unbound semantics).
 *
 * `resolveIdentity` MUST supply the claimant's historical keys — see
 * `resolveKeyFromIdentity` above for why, and what breaks if it does not.
 *
 * Failures throw `CreditClaimVerifyError` carrying `reason: 'invalid' |
 * 'unverifiable'`. Branch on that field, never on the message.
 *
 * **A deleted claimant still verifies.** This function does not consult
 * `identity.isDeleted`, and that omission is the doctrine, not an oversight: a
 * credit claim is a statement of historical fact, and the fact does not stop
 * having happened when the claimant tombstones its identity. Credentials take
 * the opposite rule (a deleted issuer's credentials are dead) because a
 * credential is a live grant of authority, and authority must die with the
 * identity that holds it. Attribution is history; authorization is standing.
 */
export const verifyCreditClaim = async (
  jwsToken: string,
  options: {
    resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
    /** The content chain the embedding document belongs to — enforces the binder */
    expectedContentId?: string;
  },
): Promise<VerifiedCreditClaim> => {
  // An empty string is a zero value, not the unset sentinel. Treating it as "skip
  // the binder" is how a consumer reading the hosting chain id from an unhydrated
  // field silently gets unbound semantics from a call that promised binding.
  if (options.expectedContentId === '') {
    throw invalid(
      'expectedContentId must be a non-empty contentId — omit the option for the unbound form',
    );
  }

  // bound claim size before any decode — a DoS guard, and the single byte
  // arbiter for the payload's open-namespace `role`. (JWS tokens are base64url +
  // dots = ASCII, so string length equals byte length.)
  if (jwsToken.length > MAX_CREDIT_CLAIM_SIZE) {
    throw invalid(`credit claim exceeds max size: ${jwsToken.length} > ${MAX_CREDIT_CLAIM_SIZE}`);
  }

  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) throw invalid('failed to decode credit claim JWS');

  // Validate the header SHAPE before touching any field. decodeJwsUnsafe
  // JSON.parses the protected header and CASTS it to JwsHeader — a compile-time
  // assertion, not a runtime guarantee — so on a decodable-but-malformed token
  // `kid` may be absent, null, or a number. Reading it unguarded raises a raw
  // TypeError out of `kid.indexOf('#')`, which is not a CreditClaimVerifyError and
  // so lands in verifyCreditEntry's catch-all as **unverifiable** — reporting a
  // malformed claim as "could not check" when we did check and it is malformed.
  // A bad header is invalid.
  const rawHeader = decoded.header as unknown as Record<string, unknown>;
  if (typeof rawHeader['typ'] !== 'string' || typeof rawHeader['kid'] !== 'string') {
    throw invalid('credit claim header must carry a string typ and kid');
  }

  // verify typ
  if (decoded.header.typ !== 'did:dfos:credit-claim') {
    throw invalid(`invalid credit claim typ: ${decoded.header.typ}`);
  }

  // parse payload
  const result = CreditClaimPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw invalid(`invalid credit claim payload: ${messages}`);
  }
  const payload = result.data;

  // verify kid DID matches payload did (only the claimant can claim its credit)
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw invalid('credit claim kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw invalid('credit claim kid DID does not match payload did');
  }

  // resolve the claimant identity and find the signing key. NOTE the absence of
  // an isDeleted gate here — see the doctrine paragraph above.
  //
  // A resolver that THROWS (relay unreachable, transport failure) is in the same
  // epistemic position as one returning undefined: we could not check. Both are
  // 'unverifiable', never 'invalid' — a network failure must never be presented
  // as a failed signature.
  let identity: VerifiedIdentity | undefined;
  try {
    identity = await options.resolveIdentity(payload.did);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw unverifiable(`could not resolve claimant identity ${payload.did}: ${detail}`);
  }
  if (!identity) {
    // MARKED: same fact as the credential path's missing issuer — the caller's
    // resolver does not hold this chain, which is not a verdict on the claim.
    throw markDependencyMissing(unverifiable(`claimant identity not found: ${payload.did}`));
  }
  const publicKey = resolveKeyFromIdentity(identity, kid);

  // verify signature
  try {
    verifyJws({ token: jwsToken, publicKey });
  } catch {
    throw invalid('invalid credit claim signature');
  }

  // verify CID
  const encoded = await dagCborCanonicalEncode(payload);
  const claimCID = encoded.cid.toString();
  if (!decoded.header.cid) throw invalid('missing cid in credit claim header');
  if (decoded.header.cid !== claimCID) throw invalid('credit claim cid mismatch');

  // enforce the binder — a claim is only about the chain it names
  if (options.expectedContentId !== undefined && payload.contentId !== options.expectedContentId) {
    throw invalid(
      `credit claim contentId ${payload.contentId} does not match expected ${options.expectedContentId}`,
    );
  }

  return {
    did: payload.did,
    contentId: payload.contentId,
    role: payload.role,
    createdAt: payload.createdAt,
    ...(payload.asOfDocumentCID !== undefined ? { asOfDocumentCID: payload.asOfDocumentCID } : {}),
    signerKeyId: kid,
    claimCID,
  };
};

// -----------------------------------------------------------------------------
// entry verification (the full bind)
// -----------------------------------------------------------------------------

/**
 * Resolve one `credits[]` entry to its spec state, performing the FULL bind
 *
 * This is the call most consumers want. `verifyCreditClaim` alone checks only
 * the `contentId` component; the `did` and `role` comparisons are what make a
 * claim an assertion about THIS entry, and skipping them verifies the wrong
 * proposition — that some valid claim exists, not that it is about this credit.
 * Shipping the whole comparison here is deliberate: the safe call should be the
 * easy one.
 *
 * `contentId` is the chain whose document contains the entry. It is REQUIRED,
 * because a consumer reading an entry always knows it, and without it the claim
 * is replayable across chains.
 *
 * Never throws for claim-level problems — every outcome is one of the four
 * states. It throws only when `contentId` is missing, which is a caller bug
 * rather than a verdict about the entry.
 */
export const verifyCreditEntry = async (
  entry: CreditEntry,
  options: {
    resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
    contentId: string;
  },
): Promise<VerifiedCreditEntry> => {
  if (!options.contentId) {
    throw new Error('verifyCreditEntry requires the hosting chain contentId');
  }

  // `claim` absent entirely — the ordinary case, and not a defect
  if (entry.claim === undefined) {
    return {
      state: 'unclaimed',
      note: 'the document signer asserts this credit; the claimant has not signed it',
    };
  }

  if (typeof entry.claim !== 'string' || entry.claim === '') {
    return { state: 'invalid', note: 'claim is present but is not a JWS string' };
  }
  if (typeof entry.did !== 'string' || entry.did === '') {
    return { state: 'invalid', note: 'claim-bearing entry has no credited DID to bind to' };
  }
  // The claim-requires-role rule. An absent entry role is a BIND MISMATCH, not a
  // wildcard: payload.role is always present and non-empty, so there is nothing
  // for it to equal. Never 'unclaimed' — a claim is present and failing.
  if (typeof entry.role !== 'string' || entry.role === '') {
    return { state: 'invalid', note: 'claim-bearing entry has no role to bind to' };
  }

  let verified: VerifiedCreditClaim;
  try {
    verified = await verifyCreditClaim(entry.claim, {
      resolveIdentity: options.resolveIdentity,
      expectedContentId: options.contentId,
    });
  } catch (error) {
    if (error instanceof CreditClaimVerifyError) {
      return { state: error.reason, note: error.message };
    }
    // an unexpected throw is not evidence the claim itself is bad
    const detail = error instanceof Error ? error.message : String(error);
    return { state: 'unverifiable', note: `verification could not complete: ${detail}` };
  }

  // the remaining two components of the bind, byte-exact, no normalization
  if (verified.did !== entry.did) {
    return { state: 'invalid', note: 'signed claimant DID does not match the credited DID' };
  }
  if (verified.role !== entry.role) {
    return { state: 'invalid', note: 'signed role does not match the credited role' };
  }

  return {
    state: 'claimed',
    note: 'signature and the exact (contentId, did, role) bind verified',
    claim: verified,
  };
};
