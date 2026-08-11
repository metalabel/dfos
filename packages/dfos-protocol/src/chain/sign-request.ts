/*

  SIGN REQUEST

  A requester's signed, transport-agnostic ask that one subject sign exactly
  these bytes as one named DFOS artifact type before a bounded deadline.

  A sign request is ephemeral courier-plane state, never proof-plane state. Its
  signing key resolves against the requester's CURRENT identity state: rotated-
  out keys and deleted identities cannot mint standing asks. The target payload
  remains opaque bytes during envelope build and verification; only the explicit
  signer-side canonical-payload check parses them.

  See `specs/SIGNING.md` for the verification algorithm and the WYSIWYS signer
  obligations. This file MUST stay in sync with the Go twin
  (`dfos-protocol-go/sign_request.go`).

*/

import {
  assertJwsProfile,
  base64urlDecode,
  base64urlEncode,
  createJws,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  verifyJws,
} from '../crypto';
import { decodeMultikey } from './multikey';
import {
  CreditClaimPayload,
  MAX_SIGN_REQUEST_PAYLOAD_SIZE,
  MAX_SIGN_REQUEST_SIZE,
  SignRequestPayload,
} from './schemas';
import type { Signer, VerifiedIdentity } from './schemas';

// -----------------------------------------------------------------------------
// types and verdicts
// -----------------------------------------------------------------------------

export interface VerifiedSignRequest {
  /** Requester DID */
  did: string;
  /** The one identity being asked to sign */
  subject: string;
  /** JWS typ the produced artifact must carry */
  payloadTyp: string;
  /** Exact decoded target bytes; never re-serialized by the envelope path */
  payloadBytes: Uint8Array;
  createdAt: string;
  expiresAt: string;
  /** kid from the JWS header */
  signerKeyId: string;
  /** CID of the sign-request payload */
  requestCID: string;
}

export type SignRequestFailureReason = 'invalid' | 'unverifiable';

/**
 * Thrown by sign-request verification and canonical-payload refusal paths.
 * Consumers branch on `reason`, never on diagnostic message text.
 */
export class SignRequestVerifyError extends Error {
  readonly reason: SignRequestFailureReason;

  constructor(reason: SignRequestFailureReason, message: string) {
    super(message);
    this.name = 'SignRequestVerifyError';
    this.reason = reason;
  }
}

const invalid = (message: string) => new SignRequestVerifyError('invalid', message);
const unverifiable = (message: string) => new SignRequestVerifyError('unverifiable', message);

// -----------------------------------------------------------------------------
// shared helpers
// -----------------------------------------------------------------------------

const normalizeSignRequestTimestamp = (value: string | undefined, field: string): string => {
  if (value === undefined) {
    return new Date().toISOString().replace(/\d{3}Z$/, '000Z');
  }
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) {
    throw new Error(`invalid sign request payload: unparseable ${field}: ${value}`);
  }
  // Floor, never round — the Go twin uses UTC().Truncate(time.Second).
  return new Date(Math.floor(ms / 1000) * 1000).toISOString();
};

const assertTemporalWindow = (
  createdAt: string,
  expiresAt: string,
  makeError: (message: string) => Error,
): void => {
  const createdMs = Date.parse(createdAt);
  const expiresMs = Date.parse(expiresAt);
  if (expiresMs <= createdMs) {
    throw makeError('sign request expiresAt must be strictly after createdAt');
  }
  if (expiresMs - createdMs > 604_800_000) {
    throw makeError('sign request validity window exceeds 604800 seconds');
  }
};

const decodeTargetPayload = (encoded: string): Uint8Array => {
  // The shared decoder intentionally accepts padded input for general JWS use.
  // SIGNING is stricter: target bytes have one canonical, unpadded spelling.
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw invalid('sign request payload must be unpadded base64url');
  }

  let decoded: Uint8Array;
  try {
    decoded = base64urlDecode(encoded);
  } catch {
    throw invalid('sign request payload is not valid base64url');
  }
  if (base64urlEncode(decoded) !== encoded) {
    throw invalid('sign request payload is not canonical unpadded base64url');
  }
  if (decoded.length === 0) {
    throw invalid('sign request payload must decode to non-empty bytes');
  }
  if (decoded.length > MAX_SIGN_REQUEST_PAYLOAD_SIZE) {
    throw invalid(
      `sign request payload exceeds max decoded size: ${decoded.length} > ${MAX_SIGN_REQUEST_PAYLOAD_SIZE}`,
    );
  }
  return decoded;
};

const resolveCurrentKey = (identity: VerifiedIdentity, kid: string): Uint8Array => {
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw invalid('sign request kid must be a DID URL');
  const keyId = kid.substring(hashIdx + 1);
  const key = [...identity.authKeys, ...identity.assertKeys, ...identity.controllerKeys].find(
    (candidate) => candidate.id === keyId,
  );
  if (!key) throw invalid(`key ${keyId} not found on current identity ${identity.did}`);

  try {
    return decodeMultikey(key.publicKeyMultibase).keyBytes;
  } catch {
    throw invalid(`key ${keyId} on identity ${identity.did} is not a valid Ed25519 multikey`);
  }
};

// -----------------------------------------------------------------------------
// build
// -----------------------------------------------------------------------------

/**
 * Build a sign-request envelope around exact target bytes.
 *
 * The kid is derived from `did` + `keyId`, so a requester mismatch is
 * unrepresentable on the build path. Both timestamps, including overrides, are
 * floor-normalized to whole seconds before signing.
 */
export const buildSignRequest = async (input: {
  did: string;
  subject: string;
  payloadTyp: string;
  payload: Uint8Array;
  expiresAt: string;
  createdAt?: string;
  signer: Signer;
  keyId: string;
}): Promise<{ jwsToken: string; requestCID: string }> => {
  if (input.payload.length === 0) {
    throw new Error('invalid sign request payload: target payload must be non-empty');
  }
  if (input.payload.length > MAX_SIGN_REQUEST_PAYLOAD_SIZE) {
    throw new Error(
      `sign request payload exceeds max decoded size: ${input.payload.length} > ${MAX_SIGN_REQUEST_PAYLOAD_SIZE}`,
    );
  }

  const createdAt = normalizeSignRequestTimestamp(input.createdAt, 'createdAt');
  const expiresAt = normalizeSignRequestTimestamp(input.expiresAt, 'expiresAt');
  assertTemporalWindow(createdAt, expiresAt, (message) => new Error(message));

  const payload = {
    version: 1 as const,
    type: 'sign-request' as const,
    did: input.did,
    subject: input.subject,
    payloadTyp: input.payloadTyp,
    payload: base64urlEncode(input.payload),
    createdAt,
    expiresAt,
  };
  const parsed = SignRequestPayload.safeParse(payload);
  if (!parsed.success) {
    const messages = parsed.error.issues.map((issue) => issue.message).join(', ');
    throw new Error(`invalid sign request payload: ${messages}`);
  }

  const encoded = await dagCborCanonicalEncode(payload);
  const requestCID = encoded.cid.toString();
  const jwsToken = await createJws({
    header: {
      alg: 'EdDSA',
      typ: 'did:dfos:sign-request',
      kid: `${input.did}#${input.keyId}`,
      cid: requestCID,
    },
    payload,
    sign: input.signer,
  });

  if (new TextEncoder().encode(jwsToken).length > MAX_SIGN_REQUEST_SIZE) {
    throw new Error(
      `sign request exceeds max size: ${new TextEncoder().encode(jwsToken).length} > ${MAX_SIGN_REQUEST_SIZE}`,
    );
  }
  return { jwsToken, requestCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify a sign-request envelope in SIGNING.md's exact 1–9 order.
 *
 * `resolveIdentity` supplies CURRENT identity state. A missing identity or
 * resolver failure is `unverifiable`; a deleted identity, missing current key,
 * or any checked-and-failed condition is `invalid`.
 */
export const verifySignRequest = async (
  jwsToken: string,
  options: {
    resolveIdentity: (did: string) => Promise<VerifiedIdentity | undefined>;
    /** Unix milliseconds; defaults to Date.now() */
    now?: number;
  },
): Promise<VerifiedSignRequest> => {
  try {
    // 1. Size — before any decode.
    const tokenSize = new TextEncoder().encode(jwsToken).length;
    if (tokenSize > MAX_SIGN_REQUEST_SIZE) {
      throw invalid(`sign request exceeds max size: ${tokenSize} > ${MAX_SIGN_REQUEST_SIZE}`);
    }

    // 2. Decode, header shape, and profile gates.
    const decoded = decodeJwsUnsafe(jwsToken);
    if (!decoded) throw invalid('failed to decode sign request JWS');
    const rawHeader = decoded.header as unknown;
    if (typeof rawHeader !== 'object' || rawHeader === null || Array.isArray(rawHeader)) {
      throw invalid('sign request protected header must be an object');
    }
    assertJwsProfile(rawHeader as Record<string, unknown>, invalid);
    if (
      typeof (rawHeader as Record<string, unknown>)['typ'] !== 'string' ||
      typeof (rawHeader as Record<string, unknown>)['kid'] !== 'string'
    ) {
      throw invalid('sign request header must carry a string typ and kid');
    }
    if (decoded.header.typ !== 'did:dfos:sign-request') {
      throw invalid(`invalid sign request typ: ${decoded.header.typ}`);
    }

    // 3. Envelope payload schema (loose: preserve-and-ignore unknown fields).
    const parsed = SignRequestPayload.safeParse(decoded.payload);
    if (!parsed.success) {
      const messages = parsed.error.issues.map((issue) => issue.message).join(', ');
      throw invalid(`invalid sign request payload: ${messages}`);
    }
    const payload = parsed.data;

    // 4. Exact target bytes.
    const payloadBytes = decodeTargetPayload(payload.payload);

    // 5. kid ↔ requester DID.
    const kid = decoded.header.kid;
    const hashIdx = kid.indexOf('#');
    if (hashIdx < 0) throw invalid('sign request kid must be a DID URL');
    if (kid.substring(0, hashIdx) !== payload.did) {
      throw invalid('sign request kid DID does not match payload did');
    }

    // 6. Current-state requester resolution.
    let identity: VerifiedIdentity | undefined;
    try {
      identity = await options.resolveIdentity(payload.did);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw unverifiable(`could not resolve requester identity ${payload.did}: ${detail}`);
    }
    if (!identity) throw unverifiable(`requester identity not found: ${payload.did}`);
    if (identity.isDeleted) throw invalid(`requester identity is deleted: ${payload.did}`);
    const publicKey = resolveCurrentKey(identity, kid);

    // 7. Signature.
    try {
      verifyJws({ token: jwsToken, publicKey });
    } catch {
      throw invalid('invalid sign request signature');
    }

    // 8. CID integrity.
    let encoded: Awaited<ReturnType<typeof dagCborCanonicalEncode>>;
    try {
      encoded = await dagCborCanonicalEncode(payload);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw invalid(`failed to derive sign request CID: ${detail}`);
    }
    const requestCID = encoded.cid.toString();
    if (decoded.header.cid !== requestCID) throw invalid('sign request cid mismatch');

    // 9. Temporal validity.
    assertTemporalWindow(payload.createdAt, payload.expiresAt, invalid);
    if ((options.now ?? Date.now()) >= Date.parse(payload.expiresAt)) {
      throw invalid('sign request is expired');
    }

    return {
      did: payload.did,
      subject: payload.subject,
      payloadTyp: payload.payloadTyp,
      payloadBytes,
      createdAt: payload.createdAt,
      expiresAt: payload.expiresAt,
      signerKeyId: kid,
      requestCID,
    };
  } catch (error) {
    if (error instanceof SignRequestVerifyError) throw error;
    const detail = error instanceof Error ? error.message : String(error);
    throw unverifiable(`sign request verification could not complete: ${detail}`);
  }
};

// -----------------------------------------------------------------------------
// signer-side WYSIWYS check
// -----------------------------------------------------------------------------

/**
 * Assert that exact target bytes are the unique canonical representation the
 * signer understands. SIGNING 0.1 implements only `did:dfos:credit-claim`.
 */
export const assertCanonicalSignRequestPayload = (
  payloadTyp: string,
  payloadBytes: Uint8Array,
  context: { subject: string },
): void => {
  if (payloadTyp !== 'did:dfos:credit-claim') {
    throw invalid(`unsupported sign request payloadTyp: ${payloadTyp}`);
  }

  let source: string;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
  } catch {
    throw invalid('sign request payload is not valid UTF-8 JSON');
  }
  if (source.startsWith('\uFEFF')) {
    throw invalid('sign request payload must not carry a UTF-8 BOM');
  }

  let raw: unknown;
  try {
    raw = JSON.parse(source);
  } catch {
    throw invalid('sign request payload is not valid JSON');
  }

  // Signer-side strictness is intentionally opposite envelope verification's
  // forward-compatible loose schema: never sign a field the signer cannot show.
  const parsed = CreditClaimPayload.strict().safeParse(raw);
  if (!parsed.success) {
    const messages = parsed.error.issues.map((issue) => issue.message).join(', ');
    throw invalid(`invalid canonical credit-claim payload: ${messages}`);
  }
  const payload = parsed.data;

  if (!payload.createdAt.endsWith('.000Z')) {
    throw invalid('credit-claim createdAt must be normalized to whole seconds');
  }
  if (payload.asOfDocumentCID !== undefined && payload.asOfDocumentCID.length === 0) {
    throw invalid('credit-claim asOfDocumentCID must be non-empty when present');
  }
  if (payload.did !== context.subject) {
    throw invalid('credit-claim payload did does not match sign request subject');
  }
  // `role` is the one free-form UTF-8 field. A lone surrogate has no convergent
  // canonical form across implementations — `JSON.stringify` round-trips it to a
  // `\uXXXX` escape here, but the Go twin cannot hold it (its UTF-8 string would
  // already carry U+FFFD) and refuses the byte-compare. Refuse it on this side
  // too so the WYSIWYS verdict is identical on both, rather than signable in TS
  // and rejected in Go. (Matches a high surrogate not followed by a low one, or a
  // low surrogate not preceded by a high one — the `String.isWellFormed` test
  // without the ES2024 lib.)
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(payload.role)) {
    throw invalid('credit-claim role is not well-formed unicode (lone surrogate)');
  }

  const canonical = JSON.stringify({
    version: payload.version,
    type: payload.type,
    contentId: payload.contentId,
    did: payload.did,
    role: payload.role,
    createdAt: payload.createdAt,
    ...(payload.asOfDocumentCID !== undefined
      ? { asOfDocumentCID: payload.asOfDocumentCID }
      : {}),
  });
  const canonicalBytes = new TextEncoder().encode(canonical);
  if (
    canonicalBytes.length !== payloadBytes.length ||
    !canonicalBytes.every((byte, index) => byte === payloadBytes[index])
  ) {
    throw invalid('credit-claim payload bytes are not canonical');
  }
};
