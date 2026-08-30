/*

  KEY PROOF — THE CHALLENGE-BOUND, SINGLE-SHOT PROOF THAT A KEY IS HELD.

  A KEY PROOF is a compact JWS over exactly four members — `{nonce, audience,
  publicKeyMultibase, timestamp}` — signed by the candidate key ITSELF, scoped by
  a registered `typ` to exactly one ceremony purpose. It proves one fact: the
  named key was held, and consented to this ceremony at this verifier, inside
  this window. It never conveys intent, content, or authority. See
  specs/KEY-PROOF.md.

  WHY THIS IS ITS OWN SUBPATH AND NOT A MEMBER OF `credentials`. KEY-PROOF is an
  optional capability on its own `0.x` clock, independent of the Protocol v1
  freeze, and the spec is explicit that a key proof is NOT a credential: it
  conveys no authority and delegates nothing. Filing it under `credentials`
  would put the envelope under a name the spec spends a section disclaiming.
  It lives in `dfos-protocol` rather than `dfos-client` for the same reason
  `api-auth.ts` does — a ceremony operator (a relay, an API) is a first-class
  VERIFIER here, and `@metalabel/dfos-client` peer-depends on the relay, so a
  relay importing a client-side verifier would close a dependency cycle.

  THREE THINGS ARE STRUCTURALLY DIFFERENT FROM THE API-AUTH ENVELOPES, and each
  one is load-bearing:

  1. NO `kid`. The candidate key is in no chain, so there is no DID URL to name;
     the verification key rides in the SIGNED PAYLOAD. A present `kid` REJECTS —
     an envelope that named a chain key would be claiming something else.
  2. THE PAYLOAD IS CLOSED. Unlike API-AUTH's MUST-ignore-unknown envelope, an
     extra member REJECTS. There is deliberately no room to smuggle intent.
  3. NO RESOLVER SEAM. The signature verifies against the payload's own
     `publicKeyMultibase`. That circularity IS the proof.

  STEP 6 IS NOT HERE. KEY-PROOF.md's verification algorithm has seven steps;
  `verifyKeyProof` performs 1–5 and 7. Step 6 — the nonce MUST be one this
  verifier minted, for this ceremony, not yet consumed, checked and consumed
  ATOMICALLY — is the CALLER'S, because only the caller holds the store the
  check-and-delete runs against. A verified proof hands back its payload so the
  caller can do exactly that. A deployment that skips step 6 has a replayable
  proof for the length of its freshness window; nothing in this file can
  substitute for it.

  There is one canonical-bytes implementation per language: this file, and its
  byte-twin `key_proof.go` in dfos-protocol-go.

*/

import { decodeMultikey, ED25519_PUB_MULTICODEC, encodeEd25519Multikey } from '../chain/multikey';
import {
  base64urlDecode,
  base64urlEncode,
  importEd25519Keypair,
  isValidEd25519Signature,
  signPayloadEd25519,
} from '../crypto';

// -----------------------------------------------------------------------------
// the byte contract
// -----------------------------------------------------------------------------

/**
 * The first registered purpose in KEY-PROOF.md's purpose registry: the candidate
 * key presents for addition to a ceremony-named identity's `authKeys`/
 * `assertKeys` sets.
 *
 * The `typ` is a PARAMETER everywhere in this module, not a constant baked into
 * the algorithm — the grammar and the verification steps are identical for every
 * registered row, and a new purpose lands by registering a value, never by
 * minting an envelope. This constant is the one row that exists.
 */
export const KEY_ADD_JWS_TYP = 'did:dfos:key-add';

/** Size cap on the serialized envelope, checked BEFORE any decode. */
export const MAX_KEY_PROOF_SIZE = 4096;

/**
 * RECOMMENDED acceptance window, in seconds, EITHER SIDE of the verifier's clock
 * — matching a ceremony's own lifetime (KEY-PROOF.md, Verification step 5).
 */
export const DEFAULT_KEY_PROOF_SKEW_SECONDS = 300;

/**
 * The closed payload. Exactly these four members, each a string, in exactly this
 * order — the member set is EXHAUSTIVE and no amendment may introduce a member
 * that carries intent or content.
 */
export interface KeyProofPayload {
  /** The verifier-minted, single-use challenge, exactly as the carriage delivered it. */
  nonce: string;
  /** The completion endpoint's lowercase authority — `host`, or `host:port` off 443. */
  audience: string;
  /** The candidate key's Multikey — and the key that signs this envelope. */
  publicKeyMultibase: string;
  /** ISO 8601 creation time, floor-normalized to whole seconds (`.000Z`). */
  timestamp: string;
}

/** The verification step a failure arose in. Branch on this, never on message text. */
export type KeyProofFailureReason =
  | 'size'
  | 'header'
  | 'schema'
  | 'audience'
  | 'freshness'
  | 'signature';

/** Thrown by `verifyKeyProof`. Branch on `reason`, never on message text. */
export class KeyProofVerifyError extends Error {
  readonly reason: KeyProofFailureReason;

  constructor(reason: KeyProofFailureReason, message: string) {
    super(message);
    this.name = 'KeyProofVerifyError';
    this.reason = reason;
  }
}

const invalid = (reason: KeyProofFailureReason, message: string): KeyProofVerifyError =>
  new KeyProofVerifyError(reason, `invalid key proof: ${message}`);

const encoder = new TextEncoder();

/** The canonical member order — the ONLY order these bytes are ever emitted in. */
const KEY_PROOF_MEMBERS = ['nonce', 'audience', 'publicKeyMultibase', 'timestamp'] as const;

// A lone surrogate has no convergent serialization: `JSON.stringify` round-trips
// it to a `\uXXXX` escape that the Go byte-twin's UTF-8 strings cannot hold, so
// it is refused on both sides rather than signable on one.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// The whole-second `.000Z` spelling — literal zeros, not "any three digits". A
// millisecond component the signer did not floor is not this grammar.
const WHOLE_SECOND_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/;
// What a `timestamp` OVERRIDE may be spelled as before flooring: the protocol's
// fixed 3-digit-fraction UTC grammar. Deliberately narrower than `Date.parse`,
// which accepts numeric offsets and a missing `Z` that some runtimes then read as
// LOCAL time — the Go twin's `ParseProtocolTimestamp` accepts exactly this and no
// more, and the two signers must not disagree about what they will floor.
const PROTOCOL_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * KEY-PROOF.md step 3, and the producer-side member rules, in ONE place: exactly
 * the four members, each a non-empty string. Any absent, any EXTRA, or any
 * non-string member rejects — this envelope is CLOSED, so unlike API-AUTH's
 * MUST-ignore-unknown payload there is no forward-compatible slack here by
 * design. Anything that wants to say more is a different artifact.
 *
 * The grammar checks past "is a string" are the ones a mismatch would otherwise
 * surface later and less usefully: an `audience` that is not an authority could
 * never byte-equal a verifier's configured authority, and a `timestamp` outside
 * the canonical spelling could never be compared to a clock.
 */
const validateKeyProofPayload = (value: unknown): KeyProofPayload => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalid('schema', 'expected a JSON object');
  }
  const raw = value as Record<string, unknown>;

  for (const member of Object.keys(raw)) {
    if (!(KEY_PROOF_MEMBERS as readonly string[]).includes(member)) {
      throw invalid('schema', `unknown member ${JSON.stringify(member)} — the payload is closed`);
    }
  }
  for (const member of KEY_PROOF_MEMBERS) {
    if (typeof raw[member] !== 'string' || raw[member] === '') {
      throw invalid('schema', `${member} must be a non-empty string`);
    }
    if (LONE_SURROGATE.test(raw[member] as string)) {
      throw invalid('schema', `${member} must be well-formed Unicode`);
    }
  }

  const nonce = raw['nonce'] as string;
  const audience = raw['audience'] as string;
  const publicKeyMultibase = raw['publicKeyMultibase'] as string;
  const timestamp = raw['timestamp'] as string;

  // The API-AUTH authority grammar, verbatim: lowercase, no scheme, no path.
  if (audience !== audience.toLowerCase() || /[\s/\\?#]/.test(audience)) {
    throw invalid('schema', 'audience must be a lowercase authority, without a scheme or path');
  }

  // THE ROUND-TRIP IS THE CALENDAR CHECK, and it is not optional. The regex fixes
  // the SPELLING and says nothing about whether the date EXISTS:
  // `Date.parse('2026-02-30T00:00:00.000Z')` NORMALIZES to March 2 and returns a
  // finite number, so a finiteness test alone VERIFIES a correctly-signed proof
  // that the Go byte-twin's `time.Parse` refuses outright. Two byte-twins that
  // disagree about whether a proof verifies is the one thing the twin contract
  // forbids, so the parsed instant is re-emitted and byte-compared: `toISOString`
  // always spells a whole-second UTC instant `.000Z`, which makes this both the
  // calendar check (an impossible date round-trips to a DIFFERENT day) and a
  // re-pin of the canonical spelling, with Go-equivalent semantics. The regex
  // stays the cheap first gate — a miss short-circuits to NaN before any Date.
  const parsedMs = WHOLE_SECOND_TIMESTAMP.test(timestamp) ? Date.parse(timestamp) : Number.NaN;
  if (!Number.isFinite(parsedMs) || new Date(parsedMs).toISOString() !== timestamp) {
    throw invalid('schema', 'timestamp must be ISO-8601 UTC whole-second .000Z');
  }

  return { nonce, audience, publicKeyMultibase, timestamp };
};

/**
 * THE BYTE CONTRACT. Serializes a payload to the canonical bytes that ARE the
 * JWS payload segment: minimal UTF-8 JSON, no insignificant whitespace, members
 * in exactly the order `nonce, audience, publicKeyMultibase, timestamp`.
 *
 * PURE and clientless: import it in a holder's signing tool and in a ceremony
 * operator's verifier alike. Byte-for-byte identical to Go's
 * `KeyProofSigningInput`.
 */
export const keyProofSigningInput = (payload: KeyProofPayload): Uint8Array =>
  encoder.encode(JSON.stringify(keyProofPayloadObject(validateKeyProofPayload(payload))));

/**
 * The payload object in canonical member order. `JSON.stringify` preserves
 * insertion order for string keys, so building the object in order IS the byte
 * contract — which is why `signKeyProof`'s emitted payload segment equals
 * `keyProofSigningInput(payload)` exactly.
 */
const keyProofPayloadObject = (payload: KeyProofPayload): Record<string, string> => ({
  nonce: payload.nonce,
  audience: payload.audience,
  publicKeyMultibase: payload.publicKeyMultibase,
  timestamp: payload.timestamp,
});

/**
 * Plain byte equality. Not constant-time on purpose: both operands are public —
 * one is the payload the presenter handed over, the other is that same payload
 * re-serialized — so there is no secret for a timing channel to leak.
 */
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, index) => byte === b[index]);

/** Floor a wall-clock instant to the canonical whole-second `.000Z` spelling. */
const normalizeTimestamp = (ms: number): string =>
  new Date(Math.floor(ms / 1000) * 1000).toISOString();

// -----------------------------------------------------------------------------
// produce
// -----------------------------------------------------------------------------

export interface SignKeyProofInput {
  /** The registered purpose this proof is scoped to — e.g. `KEY_ADD_JWS_TYP`. */
  typ: string;
  /** The verifier-minted nonce, exactly as the carriage delivered it. */
  nonce: string;
  /** The completion endpoint's lowercase authority — the one the human confirmed. */
  audience: string;
  /**
   * The candidate key's raw 32-byte Ed25519 private key. `publicKeyMultibase` is
   * DERIVED from it rather than accepted as an input: this envelope is
   * self-proving, and a signer that could name a key it does not hold would be
   * the one construction the artifact exists to foreclose.
   */
  privateKey: Uint8Array;
  /** Timestamp override; floor-normalized to `.000Z` if it carries milliseconds. */
  timestamp?: string;
  /** Clock injection (unix ms) for the default timestamp. Default `Date.now()`. */
  now?: () => number;
}

/**
 * Sign one key proof. The producer half of the byte contract.
 *
 * The protected header is EXACTLY `{"alg":"EdDSA","typ":"<purpose>"}` — two
 * members, no `kid` (the key is in no chain and rides in the payload) and no
 * `cid` (there is no operation to bind). It is assembled by hand rather than
 * through `createJws`, whose `JwsHeader` requires a `kid` this envelope must not
 * carry.
 *
 * HOLDER OBLIGATIONS THIS FUNCTION CANNOT DISCHARGE (KEY-PROOF.md, Holder
 * Obligations). A holder MUST show its human the audience and the purpose before
 * calling this, and SHOULD refuse to sign for a key any identity's chain has
 * ever declared — the `key=` reverse index is has-ever-declared, and one key in
 * two chains publishes an irreversible public link between them. Both are
 * decisions about a human and a network, made before there is a signature to
 * make; neither belongs to a pure signer.
 */
export const signKeyProof = async (
  input: SignKeyProofInput,
): Promise<{ proof: string; payload: KeyProofPayload }> => {
  if (input.typ === '') {
    throw new Error('invalid key proof: typ must be a registered purpose value');
  }
  const { publicKey } = importEd25519Keypair(input.privateKey);

  let timestamp: string;
  if (input.timestamp === undefined) {
    timestamp = normalizeTimestamp(input.now ? input.now() : Date.now());
  } else {
    const ms = Date.parse(input.timestamp);
    // The round-trip is the calendar check: `Date.parse` happily reads
    // 2026-02-30 as March 2, where the Go twin's `time.Parse` refuses it.
    if (
      !PROTOCOL_TIMESTAMP.test(input.timestamp) ||
      !Number.isFinite(ms) ||
      new Date(ms).toISOString() !== input.timestamp
    ) {
      throw new Error(`invalid key proof: unparseable timestamp: ${input.timestamp}`);
    }
    timestamp = normalizeTimestamp(ms);
  }

  const payload = validateKeyProofPayload({
    nonce: input.nonce,
    audience: input.audience,
    publicKeyMultibase: encodeEd25519Multikey(publicKey),
    timestamp,
  });

  const headerB64 = base64urlEncode(JSON.stringify({ alg: 'EdDSA', typ: input.typ }));
  const payloadB64 = base64urlEncode(keyProofSigningInput(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = signPayloadEd25519(encoder.encode(signingInput), input.privateKey);
  const proof = `${signingInput}.${base64urlEncode(signature)}`;

  if (proof.length > MAX_KEY_PROOF_SIZE) {
    throw new Error(`key proof exceeds max size: ${proof.length} > ${MAX_KEY_PROOF_SIZE}`);
  }
  return { proof, payload };
};

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

export interface VerifyKeyProofOptions {
  /**
   * The registered `typ` THIS ceremony requires. The gate is absolute: it is what
   * keeps a proof signed for one ceremony from ever being presented for another.
   */
  expectedTyp: string;
  /**
   * THE VERIFIER'S OWN CONFIGURED AUTHORITY — a value the deployment holds, NEVER
   * one read from the request. `Host`, `X-Forwarded-Host`, and the request URL's
   * authority are all attacker-supplied; a verifier that compared against one of
   * them would have no audience binding at all, and audience binding is the whole
   * defense against challenge relay.
   */
  expectedAudience: string;
  /** Acceptance window, seconds, EITHER SIDE. Default `DEFAULT_KEY_PROOF_SKEW_SECONDS`. */
  maxSkewSeconds?: number;
  /** Clock injection (unix ms). Default `Date.now()`. */
  now?: () => number;
}

/** What a verified key proof hands back. */
export interface VerifiedKeyProof {
  /**
   * The validated payload. THE CALLER MUST NOW RUN STEP 6 against `payload.nonce`:
   * check that it is a nonce this verifier minted, for this ceremony, not yet
   * consumed, and consume it ATOMICALLY (check-and-delete) so two racing
   * completions cannot both pass.
   */
  payload: KeyProofPayload;
  /** The header `typ` — equal to `expectedTyp`, since anything else rejected. */
  typ: string;
  /** The integer unix seconds the freshness check used. */
  now: number;
}

/**
 * Verify a key proof — KEY-PROOF.md's verification algorithm steps 1–5 and 7:
 * size cap, header gates, the closed payload schema over CANONICAL bytes,
 * audience byte-equality, freshness, and the signature against the payload's OWN
 * `publicKeyMultibase`.
 *
 * STEP 6 (NONCE) IS THE CALLER'S, and this function cannot stand in for it. The
 * nonce MUST be one this verifier minted, for this ceremony, not yet consumed,
 * checked and consumed ATOMICALLY — a check-and-delete against the verifier's
 * own store, which is state this pure function does not hold. It is returned on
 * `payload.nonce` precisely so the caller can run that step next. Without it a
 * proof is replayable for the length of the freshness window.
 *
 * What the seven steps together establish is exactly one fact: THE NAMED KEY WAS
 * HELD, AND CONSENTED TO THIS CEREMONY AT THIS VERIFIER, INSIDE THIS WINDOW.
 * Everything after — appending the key to a chain, custody policy, notification
 * — is the ceremony operator's.
 */
export const verifyKeyProof = (jws: string, options: VerifyKeyProofOptions): VerifiedKeyProof => {
  // THE TYP GATE IS ONLY A GATE WHEN THE EXPECTATION NAMES A PURPOSE. An empty
  // `expectedTyp` byte-equals an artifact carrying `"typ":""`, so a verifier
  // configured with one admits an envelope scoped to no ceremony at all — the
  // gate reads as satisfied while gating nothing. That is a MISCONFIGURATION, not
  // a verdict about a proof: it throws a plain Error like the skew guard below
  // and never a `KeyProofVerifyError`, so a caller branching on `reason` cannot
  // mistake a broken deployment for a bad envelope. Non-empty is the whole rule —
  // the purpose registry is KEY-PROOF.md's, and hardcoding its rows here would
  // make registering a new purpose a library release. `signKeyProof` refuses an
  // empty `typ` on the producer side for the same reason.
  if (options.expectedTyp === '') {
    throw new Error('invalid key proof verifier: expectedTyp must be a registered purpose value');
  }

  const maxSkew = options.maxSkewSeconds ?? DEFAULT_KEY_PROOF_SKEW_SECONDS;
  if (!Number.isSafeInteger(maxSkew) || maxSkew < 0) {
    throw new Error('invalid key proof verifier: maxSkewSeconds must be a non-negative integer');
  }

  // 1. Size cap — before any decode. A DoS guard at the header layer.
  if (jws.length > MAX_KEY_PROOF_SIZE) {
    throw invalid('size', `envelope exceeds max size: ${jws.length} > ${MAX_KEY_PROOF_SIZE}`);
  }

  const parts = jws.split('.');
  if (parts.length !== 3) throw invalid('header', 'failed to decode JWS');
  const [headerB64, payloadB64] = parts as [string, string, string];

  // 2. Header gates — the Signature Verification Profile, plus the two this
  // envelope adds. Applied to the RAW header object so a member present with any
  // value is observable, not to a typed struct that would silently drop it.
  let header: Record<string, unknown>;
  try {
    const decoded: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(base64urlDecode(headerB64)),
    );
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
      throw new Error('protected header must be an object');
    }
    header = decoded as Record<string, unknown>;
  } catch (err) {
    throw invalid('header', err instanceof Error ? err.message : 'failed to decode header');
  }

  if (header['alg'] !== 'EdDSA') {
    throw invalid('header', `unsupported algorithm: ${String(header['alg'])}`);
  }
  if ('crit' in header) throw invalid('header', 'crit header is not supported');
  // Embedded key material, and the references that fetch it. `jwk`/`x5c` are the
  // profile's; `jku`/`x5u` are named by KEY-PROOF.md's "an embedded key member
  // (`jwk`, `jku`, `x5c`, …) rejects" — a URL that FETCHES a key is header key
  // trust with an extra hop, which is the thing being refused.
  for (const member of ['jwk', 'jku', 'x5c', 'x5u']) {
    if (member in header) {
      throw invalid('header', `${member} header is not allowed (the key rides in the payload)`);
    }
  }
  // A PRESENT kid REJECTS. The candidate key is in no chain, so there is no DID
  // URL to name; an envelope carrying one is claiming something this artifact
  // does not say, and admitting it would create a second place a verifier might
  // look for a key.
  if ('kid' in header) {
    throw invalid('header', 'kid must be absent — the candidate key is in no chain');
  }
  // THE TYP GATE, ABSOLUTE. A proof signed for one ceremony is dead bytes at
  // every other.
  const typ = header['typ'];
  if (typeof typ !== 'string' || typ !== options.expectedTyp) {
    throw invalid('header', `invalid typ: expected ${options.expectedTyp}, got ${String(typ)}`);
  }

  // 3. Payload schema — closed, exactly four string members — AND the canonical
  // bytes. The parse runs against the ORIGINAL payload octets, because those are
  // the bytes the signature covers; the canonical serialization is then
  // RECOMPUTED from the parsed members and byte-compared against them.
  //
  // THE CANONICAL RULE BINDS THE VERIFIER, NOT ONLY THE PRODUCER. A signature
  // covers whatever octets arrived, so without this comparison a payload whose
  // four members are REORDERED — or re-spelled with insignificant whitespace —
  // and signed over that serialization verifies exactly like the canonical one.
  // The envelope's bytes would stop being a function of its members, and one
  // proof would have many spellings for a caller to key, log, or cache against.
  // Conformant producers already emit these bytes, so nothing that could be
  // signed correctly is refused here.
  let payload: KeyProofPayload;
  try {
    const payloadBytes = base64urlDecode(payloadB64);
    const source = new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes);
    payload = validateKeyProofPayload(JSON.parse(source) as unknown);
    if (!bytesEqual(keyProofSigningInput(payload), payloadBytes)) {
      throw invalid('schema', 'payload is not the canonical signing input for its members');
    }
  } catch (err) {
    if (err instanceof KeyProofVerifyError) throw err;
    throw invalid('schema', err instanceof Error ? err.message : 'payload is not valid UTF-8 JSON');
  }

  // 4. Audience — BYTE EQUALITY against the verifier's own configured authority.
  // This is what defeats challenge relay: a proof audienced to the host the
  // victim confirmed is unusable at every other host.
  if (payload.audience !== options.expectedAudience) {
    throw invalid('audience', 'audience does not match this verifier authority');
  }

  // 5. Freshness — integer unix seconds on both sides, symmetric, because a
  // ceremony's window is its own lifetime in both directions.
  const now = Math.floor((options.now ? options.now() : Date.now()) / 1000);
  const issued = Math.floor(Date.parse(payload.timestamp) / 1000);
  if (Math.abs(now - issued) > maxSkew) {
    throw invalid('freshness', 'timestamp is outside the acceptance window');
  }

  // 6. NONCE — THE CALLER'S. See the doc comment: check-and-delete, atomically.

  // 7. Signature, against the payload's OWN publicKeyMultibase. The circularity
  // is the point: a valid envelope is possession demonstrated over fresh
  // verifier-minted bytes.
  let keyBytes: Uint8Array;
  try {
    const decoded = decodeMultikey(payload.publicKeyMultibase);
    if (decoded.codec !== ED25519_PUB_MULTICODEC) {
      throw new Error('publicKeyMultibase is not an Ed25519 public key');
    }
    keyBytes = decoded.keyBytes;
  } catch (err) {
    throw invalid(
      'signature',
      err instanceof Error ? err.message : 'undecodable publicKeyMultibase',
    );
  }
  // A malformed signature segment (wrong length, undecodable base64url) makes the
  // underlying verifier THROW rather than answer false; a proof that fails to
  // parse is an invalid proof, never an exception escaping the verifier.
  let verified = false;
  try {
    verified = isValidEd25519Signature(
      encoder.encode(`${headerB64}.${payloadB64}`),
      base64urlDecode(parts[2] as string),
      keyBytes,
    );
  } catch {
    verified = false;
  }
  if (!verified) throw invalid('signature', 'signature does not verify against publicKeyMultibase');

  return { payload, typ, now };
};
