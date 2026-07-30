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

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
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

// -----------------------------------------------------------------------------
// key resolution helper
// -----------------------------------------------------------------------------

/**
 * Resolve a public key from a VerifiedIdentity by kid (DID URL)
 *
 * Searches across all key roles (auth, assert, controller) — the protocol does
 * not restrict which role may sign a claim, matching the credential rule. Key
 * HISTORY is the resolver's business: a caller that supplies every key the
 * identity chain has ever held lets claims survive key rotation, which is the
 * right default for a permanent historical attribution.
 */
const resolveKeyFromIdentity = (identity: VerifiedIdentity, kid: string): Uint8Array => {
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('credit claim kid must be a DID URL');
  const keyId = kid.substring(hashIdx + 1);

  const allKeys = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys];
  const key = allKeys.find((k) => k.id === keyId);
  if (!key) {
    throw new Error(`key ${keyId} not found on identity ${identity.did}`);
  }

  const { keyBytes } = decodeMultikey(key.publicKeyMultibase);
  return keyBytes;
};

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign a credit claim as a JWS
 *
 * The claim binds to the content chain's stable `contentId`, not to a document —
 * so a signed claim stays valid verbatim across every subsequent edit of the
 * chain. Callers SHOULD sign a given (contentId, did, role) triple exactly once
 * and reuse the token: re-signing mints a fresh `createdAt`, which changes the
 * claim bytes, which changes the embedding document's CID.
 */
export const signCreditClaim = async (input: {
  contentId: string;
  did: string;
  role: string;
  /** Optional document state the claimant pins its credit to */
  asOfDocumentCID?: string;
  signer: Signer;
  keyId: string;
}): Promise<{ jwsToken: string; claimCID: string }> => {
  const kid = `${input.did}#${input.keyId}`;
  const now = new Date().toISOString().replace(/\d{3}Z$/, '000Z');

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

  return { jwsToken, claimCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a credit claim JWS — size, signature, CID, payload schema, signer match
 *
 * Pass `expectedContentId` to enforce the anti-replay half of the bind: without
 * it, a valid claim lifted from one chain's document verifies when replayed in
 * another chain's document. A consumer verifying a credits entry ALWAYS knows
 * which chain it is reading, so it should always pass it. The remaining two
 * components of the bind — `did` and `role` — are compared by the caller against
 * the entry plaintext (exact byte equality, no normalization).
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
  // bound claim size before any decode — a DoS guard, and the single byte
  // arbiter for the payload's open-namespace `role`. (JWS tokens are base64url +
  // dots = ASCII, so string length equals byte length.)
  if (jwsToken.length > MAX_CREDIT_CLAIM_SIZE) {
    throw new Error(`credit claim exceeds max size: ${jwsToken.length} > ${MAX_CREDIT_CLAIM_SIZE}`);
  }

  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) throw new Error('failed to decode credit claim JWS');

  // verify typ
  if (decoded.header.typ !== 'did:dfos:credit-claim') {
    throw new Error(`invalid credit claim typ: ${decoded.header.typ}`);
  }

  // parse payload
  const result = CreditClaimPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid credit claim payload: ${messages}`);
  }
  const payload = result.data;

  // verify kid DID matches payload did (only the claimant can claim its credit)
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('credit claim kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw new Error('credit claim kid DID does not match payload did');
  }

  // resolve the claimant identity and find the signing key. NOTE the absence of
  // an isDeleted gate here — see the doctrine paragraph above.
  const identity = await options.resolveIdentity(payload.did);
  if (!identity) {
    throw new Error(`claimant identity not found: ${payload.did}`);
  }
  const publicKey = resolveKeyFromIdentity(identity, kid);

  // verify signature
  try {
    verifyJws({ token: jwsToken, publicKey });
  } catch {
    throw new Error('invalid credit claim signature');
  }

  // verify CID
  const encoded = await dagCborCanonicalEncode(payload);
  const claimCID = encoded.cid.toString();
  if (!decoded.header.cid) throw new Error('missing cid in credit claim header');
  if (decoded.header.cid !== claimCID) throw new Error('credit claim cid mismatch');

  // enforce the binder — a claim is only about the chain it names
  if (options.expectedContentId !== undefined && payload.contentId !== options.expectedContentId) {
    throw new Error(
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
