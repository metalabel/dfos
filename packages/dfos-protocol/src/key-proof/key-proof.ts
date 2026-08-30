/*

  KEY PROOF — THE CHALLENGE-BOUND, POSITION-BOUND, SINGLE-SHOT PROOF THAT A KEY
  IS HELD.

  A KEY PROOF is a compact JWS over exactly seven members — `{nonce, audience,
  did, roleSet, prevCID, publicKeyMultibase, timestamp}` — signed by the
  candidate key ITSELF, scoped by a registered `typ` to exactly one ceremony
  purpose. It proves one fact: the named key was held, and consented to THIS
  POSITION — this chain, these roles, this head — at this verifier, inside this
  window. It never conveys intent, content, or authority. See specs/KEY-PROOF.md.

  WHAT THE THREE POSITIONAL MEMBERS BUY. `nonce`, `audience` and `timestamp` bind
  a proof to one ceremony at one verifier in one window; they say nothing about
  WHERE the key was going. `did`, `roleSet` and `prevCID` say exactly that, and
  each closes a distinct standing-consent hole:

    - `did` — the chain the key is introduced to. Without it, a proof collected
      for one identity is spendable against another.
    - `roleSet` — the roles consented to, from the closed set {auth, assert,
      controller} in one canonical spelling (see role-set.ts). Without it,
      consent to sign as an author is consent to become a controller.
    - `prevCID` — the head the introduction builds on. This is the one that kills
      STANDING CONSENT: an envelope is bound to a chain state that has already
      moved on by the time a second introduction could reuse it, so re-adding a
      removed key, or promoting a key to a new role, needs a FRESH envelope every
      time. There is no such thing as an envelope held in reserve.

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

  TWO VERIFICATION MODES OVER ONE ENVELOPE. The same bytes are read twice in a
  key's life, by parties in different positions:

    - PRESENTATION-TIME (`verifyKeyProof`) — a ceremony operator completing a
      live ceremony. It holds a clock, a configured audience, and a nonce store,
      so it checks freshness and audience, and its caller runs step 6.
    - CHAIN-WALK (`verifyChainKeyProof`) — anyone replaying the chain later. The
      ceremony is long over; the operator's authority, clock and nonce store are
      not the walker's, and a proof embedded in a signed operation is FIXED
      TRANSPORT, not a live presentation. So the walk checks NEITHER freshness
      NOR audience: those two members are bytes the signature covers and the
      walk carries. What the walk does check is the position — the chain, the
      head, the roles, the key — which is the part that must still hold.

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
import { isCanonicalRoleSet, roleSetCovers, type KeyRole } from './role-set';

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
 * The closed payload. Exactly these seven members, each a string, in exactly this
 * order — the member set is EXHAUSTIVE and no amendment may introduce a member
 * that carries intent or content.
 */
export interface KeyProofPayload {
  /** The verifier-minted, single-use challenge, exactly as the carriage delivered it. */
  nonce: string;
  /**
   * The completing authority's lowercase authority — `host`, or `host:port` off
   * 443. Held here as an opaque string: a leg whose completing authority IS a
   * chain rather than a host audiences to that chain's DID, byte-equal to `did`,
   * and this module does not special-case the two spellings. The VERIFIER
   * supplies the expectation; the envelope only carries what it was signed for.
   */
  audience: string;
  /** The chain this key is introduced to. */
  did: string;
  /** The canonical role set (see role-set.ts) this envelope consents to. */
  roleSet: string;
  /**
   * The chain head the introduction builds on — equal to the introducing
   * operation's `previousOperationCID`. The member that forecloses standing
   * consent.
   */
  prevCID: string;
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
  | 'did'
  | 'roleSet'
  | 'prevCID'
  | 'key'
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
const KEY_PROOF_MEMBERS = [
  'nonce',
  'audience',
  'did',
  'roleSet',
  'prevCID',
  'publicKeyMultibase',
  'timestamp',
] as const;

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
 * the seven members, each a non-empty string. Any absent, any EXTRA, or any
 * non-string member rejects — this envelope is CLOSED, so unlike API-AUTH's
 * MUST-ignore-unknown payload there is no forward-compatible slack here by
 * design. Anything that wants to say more is a different artifact.
 *
 * The grammar checks past "is a string" are the ones a mismatch would otherwise
 * surface later and less usefully: an `audience` that is not an authority could
 * never byte-equal a verifier's configured authority, a `timestamp` outside the
 * canonical spelling could never be compared to a clock, and a `roleSet` outside
 * its one canonical spelling would give the same set of roles more than one
 * payload — which is the malleability the canonical-bytes rule exists to refuse,
 * one level down.
 *
 * `did` and `prevCID` carry NO grammar past non-empty. They are compared by byte
 * equality against values the verifier already holds — the chain's DID, the
 * carrying operation's `previousOperationCID` — so a malformed one cannot match
 * anything, and a shape rule here would only be a second place for the two
 * language twins to disagree.
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
  const did = raw['did'] as string;
  const roleSet = raw['roleSet'] as string;
  const prevCID = raw['prevCID'] as string;
  const publicKeyMultibase = raw['publicKeyMultibase'] as string;
  const timestamp = raw['timestamp'] as string;

  // The API-AUTH authority grammar, verbatim: lowercase, no scheme, no path. A
  // `did:dfos:…` identifier satisfies it as written — lowercase, no separators —
  // which is why the DID-audienced leg needs no second grammar here.
  if (audience !== audience.toLowerCase() || /[\s/\\?#]/.test(audience)) {
    throw invalid('schema', 'audience must be a lowercase authority, without a scheme or path');
  }

  // The role set has ONE spelling. `assert,auth`, `auth, assert`, `auth,auth`,
  // `auth,owner` and `` all name nothing this envelope can be signed for.
  if (!isCanonicalRoleSet(roleSet)) {
    throw invalid(
      'schema',
      'roleSet must be a canonical, non-empty subset of auth,assert,controller in that order',
    );
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

  return { nonce, audience, did, roleSet, prevCID, publicKeyMultibase, timestamp };
};

/**
 * THE BYTE CONTRACT. Serializes a payload to the canonical bytes that ARE the
 * JWS payload segment: minimal UTF-8 JSON, no insignificant whitespace, members
 * in exactly the order `nonce, audience, did, roleSet, prevCID,
 * publicKeyMultibase, timestamp`.
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
  did: payload.did,
  roleSet: payload.roleSet,
  prevCID: payload.prevCID,
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
  /** The completing authority — the one the human confirmed. */
  audience: string;
  /** The chain this key is being introduced to. */
  did: string;
  /**
   * The canonical role set — build it with `serializeRoleSet` rather than by
   * hand; a non-canonical spelling is refused here, not silently normalized.
   */
  roleSet: string;
  /** The chain head the introduction builds on. */
  prevCID: string;
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
 * Obligations). A holder MUST show its human — before calling this — the
 * audience, the purpose, the adopting identity, and the roles. A proof is
 * consent, and consent that was never displayed was never given.
 *
 * It SHOULD also refuse to sign for a key some identity's chain has already
 * PROVED, its own included: the `key=` reverse index is has-ever-proved across
 * all three key sets, its rows survive rotation and deletion, and proving one
 * key into two chains publishes an irreversible public link between them. An
 * unproved DECLARATION of the key elsewhere is neither a link nor a burn — it is
 * void, it never indexes, and it never obligates the true holder, which is
 * precisely why the index counts proofs and not claims.
 *
 * Every one of those is a decision about a human and a network, made before
 * there is a signature to make; none belongs to a pure signer.
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
    did: input.did,
    roleSet: input.roleSet,
    prevCID: input.prevCID,
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
// decode — the steps BOTH verification modes share
// -----------------------------------------------------------------------------

/** The envelope, split and validated as far as the two modes agree. */
interface DecodedKeyProof {
  payload: KeyProofPayload;
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  typ: string;
}

/**
 * KEY-PROOF.md verification steps 1–3: size cap, header gates, and the closed
 * payload schema over CANONICAL bytes. Everything both modes do identically,
 * because these three steps are about the ARTIFACT and not about the position
 * the reader occupies.
 */
const decodeKeyProof = (jws: string, expectedTyp: string): DecodedKeyProof => {
  // 1. Size cap — before any decode. A DoS guard at the header layer.
  if (jws.length > MAX_KEY_PROOF_SIZE) {
    throw invalid('size', `envelope exceeds max size: ${jws.length} > ${MAX_KEY_PROOF_SIZE}`);
  }

  const parts = jws.split('.');
  if (parts.length !== 3) throw invalid('header', 'failed to decode JWS');
  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

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
  // look for a key. It stays absent in the chain-walk mode too: by the time the
  // walk reads the envelope the key IS in a chain, but the envelope is the same
  // bytes it always was, and re-reading them under a looser rule would mean an
  // artifact that verifies at replay and not at presentation.
  if ('kid' in header) {
    throw invalid('header', 'kid must be absent — the candidate key is in no chain');
  }
  // THE TYP GATE, ABSOLUTE. A proof signed for one ceremony is dead bytes at
  // every other.
  const typ = header['typ'];
  if (typeof typ !== 'string' || typ !== expectedTyp) {
    throw invalid('header', `invalid typ: expected ${expectedTyp}, got ${String(typ)}`);
  }

  // 3. Payload schema — closed, exactly seven string members — AND the canonical
  // bytes. The parse runs against the ORIGINAL payload octets, because those are
  // the bytes the signature covers; the canonical serialization is then
  // RECOMPUTED from the parsed members and byte-compared against them.
  //
  // THE CANONICAL RULE BINDS THE VERIFIER, NOT ONLY THE PRODUCER. A signature
  // covers whatever octets arrived, so without this comparison a payload whose
  // seven members are REORDERED — or re-spelled with insignificant whitespace —
  // and signed over that serialization verifies exactly like the canonical one,
  // and the payload stops being a function of its members. The same argument one
  // level down is why `roleSet` has a single spelling: `assert,auth` names the
  // set `auth,assert` names, so admitting both would restore the malleability
  // this comparison removes.
  //
  // WHAT THIS PINS IS THE PAYLOAD'S OCTETS, AND NOTHING PAST THEM. The compact
  // envelope around them is not canonicalized: `base64urlDecode` is
  // padding-tolerant (a family-wide choice), and no rule pins the protected
  // header's serialization — so one proof still has more than one envelope
  // spelling, and a caller must not treat the envelope string as an identity.
  // Nothing here needs it to be: what a completion spends is the NONCE, consumed
  // atomically and once by the caller's step 6. Conformant producers already emit
  // these bytes, so nothing that could be signed correctly is refused here.
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

  return { payload, headerB64, payloadB64, signatureB64, typ };
};

/**
 * KEY-PROOF.md verification step 7: the signature, against the payload's OWN
 * `publicKeyMultibase`. The circularity is the point — a valid envelope is
 * possession demonstrated over bytes the signer did not choose alone.
 */
const verifyKeyProofSignature = (decoded: DecodedKeyProof): void => {
  let keyBytes: Uint8Array;
  try {
    const key = decodeMultikey(decoded.payload.publicKeyMultibase);
    if (key.codec !== ED25519_PUB_MULTICODEC) {
      throw new Error('publicKeyMultibase is not an Ed25519 public key');
    }
    keyBytes = key.keyBytes;
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
      encoder.encode(`${decoded.headerB64}.${decoded.payloadB64}`),
      base64urlDecode(decoded.signatureB64),
      keyBytes,
    );
  } catch {
    verified = false;
  }
  if (!verified) throw invalid('signature', 'signature does not verify against publicKeyMultibase');
};

// -----------------------------------------------------------------------------
// verify — presentation time
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
  /**
   * THE CHAIN THIS CEREMONY IS COMPLETING FOR. Like the audience, it is the
   * completing authority's own value — the identity whose ceremony this is — and
   * never a DID read back out of the envelope being checked.
   */
  expectedDid: string;
  /**
   * THE ROLES THIS CEREMONY GRANTS, in canonical spelling (`serializeRoleSet`).
   * Byte-equality, not coverage: a ceremony that will write `auth,assert` MUST
   * NOT accept an envelope consenting to `auth` alone, and MUST NOT accept one
   * consenting to `auth,assert,controller` either — the second is the holder
   * conceding more than was asked, which a completing authority has no business
   * banking. A non-canonical expectation is a MISCONFIGURATION and throws.
   */
  expectedRoleSet: string;
  /**
   * THE HEAD THE INTRODUCTION WILL BUILD ON — the `previousOperationCID` the
   * completing authority is about to write. A chain that moved between minting
   * the challenge and completing it invalidates the proof here rather than
   * writing an operation whose embedded envelope no walker will accept.
   */
  expectedPrevCID: string;
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
 * Verify a key proof AT PRESENTATION TIME — KEY-PROOF.md's verification algorithm
 * steps 1–5 and 7: size cap, header gates, the closed payload schema over
 * CANONICAL bytes, the four expectation arms (audience, did, roleSet, prevCID),
 * freshness, and the signature against the payload's OWN `publicKeyMultibase`.
 *
 * EVERY EXPECTATION IS THE DEPLOYMENT'S OWN VALUE. There is no arm here that
 * compares the envelope to itself. `expectedDid`, `expectedRoleSet` and
 * `expectedPrevCID` are the position the completing authority is about to WRITE;
 * if the envelope names a different one, the holder consented to something else.
 *
 * STEP 6 (NONCE) IS THE CALLER'S, and this function cannot stand in for it. The
 * nonce MUST be one this verifier minted, for this ceremony, not yet consumed,
 * checked and consumed ATOMICALLY — a check-and-delete against the verifier's
 * own store, which is state this pure function does not hold. It is returned on
 * `payload.nonce` precisely so the caller can run that step next. Without it a
 * proof is replayable for the length of the freshness window.
 *
 * What the steps together establish is exactly one fact: THE NAMED KEY WAS HELD,
 * AND CONSENTED TO THIS POSITION IN THIS CHAIN AT THIS VERIFIER, INSIDE THIS
 * WINDOW. Everything after — appending the key to a chain, custody policy,
 * notification — is the ceremony operator's.
 */
export const verifyKeyProof = (jws: string, options: VerifyKeyProofOptions): VerifiedKeyProof => {
  // THE TYP GATE IS ONLY A GATE WHEN THE EXPECTATION NAMES A PURPOSE. An empty
  // `expectedTyp` byte-equals an artifact carrying `"typ":""`, so a verifier
  // configured with one admits an envelope scoped to no ceremony at all — the
  // gate reads as satisfied while gating nothing. That is a MISCONFIGURATION, not
  // a verdict about a proof: it throws a plain Error like the guards below and
  // never a `KeyProofVerifyError`, so a caller branching on `reason` cannot
  // mistake a broken deployment for a bad envelope. Non-empty is the whole rule —
  // the purpose registry is KEY-PROOF.md's, and hardcoding its rows here would
  // make registering a new purpose a library release. `signKeyProof` refuses an
  // empty `typ` on the producer side for the same reason.
  //
  // The same argument covers the other four expectations, and it is why none of
  // them is optional: an omitted or empty positional expectation is an arm that
  // reads as satisfied while binding nothing, which is precisely the standing
  // consent this envelope revision exists to foreclose.
  if (options.expectedTyp === '') {
    throw new Error('invalid key proof verifier: expectedTyp must be a registered purpose value');
  }
  if (options.expectedAudience === '') {
    throw new Error('invalid key proof verifier: expectedAudience must name this authority');
  }
  if (options.expectedDid === '') {
    throw new Error('invalid key proof verifier: expectedDid must name the chain');
  }
  if (options.expectedPrevCID === '') {
    throw new Error('invalid key proof verifier: expectedPrevCID must name the chain head');
  }
  if (!isCanonicalRoleSet(options.expectedRoleSet)) {
    throw new Error(
      'invalid key proof verifier: expectedRoleSet must be a canonical role set — ' +
        'build it with serializeRoleSet',
    );
  }

  const maxSkew = options.maxSkewSeconds ?? DEFAULT_KEY_PROOF_SKEW_SECONDS;
  if (!Number.isSafeInteger(maxSkew) || maxSkew < 0) {
    throw new Error('invalid key proof verifier: maxSkewSeconds must be a non-negative integer');
  }

  // 1–3. Size, header gates, closed schema over canonical bytes.
  const decoded = decodeKeyProof(jws, options.expectedTyp);
  const payload = decoded.payload;

  // 4. Audience — BYTE EQUALITY against the verifier's own configured authority.
  // This is what defeats challenge relay: a proof audienced to the host the
  // victim confirmed is unusable at every other host.
  if (payload.audience !== options.expectedAudience) {
    throw invalid('audience', 'audience does not match this verifier authority');
  }

  // 4b. The three POSITIONAL arms, each byte equality against a value the
  // completing authority already holds. Audience binding says WHERE the proof may
  // be spent; these say WHAT it may be spent on.
  if (payload.did !== options.expectedDid) {
    throw invalid('did', 'did does not match the chain this ceremony completes for');
  }
  if (payload.roleSet !== options.expectedRoleSet) {
    throw invalid('roleSet', 'roleSet does not match the roles this ceremony grants');
  }
  if (payload.prevCID !== options.expectedPrevCID) {
    throw invalid('prevCID', 'prevCID does not match the chain head this introduction builds on');
  }

  // 5. Freshness — integer unix seconds on both sides, symmetric, because a
  // ceremony's window is its own lifetime in both directions.
  const now = Math.floor((options.now ? options.now() : Date.now()) / 1000);
  const issued = Math.floor(Date.parse(payload.timestamp) / 1000);
  if (Math.abs(now - issued) > maxSkew) {
    throw invalid('freshness', 'timestamp is outside the acceptance window');
  }

  // 6. NONCE — THE CALLER'S. See the doc comment: check-and-delete, atomically.

  // 7. Signature, against the payload's OWN publicKeyMultibase.
  verifyKeyProofSignature(decoded);

  return { payload, typ: decoded.typ, now };
};

// -----------------------------------------------------------------------------
// verify — chain walk
// -----------------------------------------------------------------------------

export interface VerifyChainKeyProofOptions {
  /** The registered `typ` the introduction requires — `KEY_ADD_JWS_TYP`. */
  expectedTyp: string;
  /** The DID of the chain being walked. */
  did: string;
  /** The carrying operation's `previousOperationCID`. */
  prevCID: string;
  /** The Multikey of the key this envelope is being read as the proof FOR. */
  publicKeyMultibase: string;
  /** The role the introduction needs covered. Coverage, not equality — see below. */
  role: KeyRole;
}

/**
 * Verify a key proof AT CHAIN-WALK TIME — the mode a replayer uses on an envelope
 * embedded in a signed identity operation.
 *
 * WHAT IT CHECKS: the signature, the `typ`, the closed schema over canonical
 * bytes, and the four position arms — `publicKeyMultibase` is the key being
 * introduced, `did` is this chain, `prevCID` is the carrying operation's
 * `previousOperationCID`, and `roleSet` COVERS the role in question.
 *
 * WHAT IT DELIBERATELY DOES NOT CHECK, AND WHY. Neither FRESHNESS nor AUDIENCE.
 * Both are properties of a live ceremony, and the walk is not one: the envelope
 * was fresh when it was presented, against a clock and an authority that belonged
 * to the completing operator and not to whoever replays the chain a year later.
 * Checking freshness at walk time would make every chain expire; checking
 * audience would make a chain verifiable only by the relay that wrote it. The two
 * members still travel, still sign, and are still returned — they are FIXED
 * TRANSPORT the signature covers, evidence of which ceremony this was, not gates
 * a walker is positioned to run.
 *
 * COVERAGE, NOT EQUALITY, ON THE ROLE. Presentation-time takes byte equality
 * because the completing authority knows exactly which roles it is about to
 * write. The walk asks a narrower question, once per (key, role) introduction:
 * did the holder consent to THIS role? One envelope consenting to
 * `auth,assert,controller` therefore proves three introductions in one operation,
 * which is the ordinary rotation case.
 *
 * Returns the validated payload. Throws `KeyProofVerifyError` — a chain walker
 * treats every throw as "this introduction is not proved", never as "this chain
 * is invalid": an unproved introduction voids a key-role membership and nothing
 * more.
 */
/**
 * The `publicKeyMultibase` an envelope NAMES, read WITHOUT verifying anything —
 * no signature, no schema, no gates. `null` when the bytes do not decode to an
 * object carrying a string there.
 *
 * UNSAFE IS IN THE NAME BECAUSE THE ANSWER PROVES NOTHING. The only sound use is
 * as an INDEX HINT. An operation carrying several envelopes and introducing
 * several keys would otherwise be a quadratic scan — every envelope gated
 * against every candidate — so the chain walk uses this to pick WHICH candidate
 * an envelope is about, then runs the full `verifyChainKeyProof` against that
 * candidate's real, DECLARED Multikey. The gate's own `publicKeyMultibase` arm
 * is what makes the pairing sound: a wrong or forged hint routes the envelope to
 * a candidate it then fails against, which is exactly the verdict the exhaustive
 * scan would have reached. Never read this value as an assertion about a key.
 */
export const unsafeKeyProofSubject = (jws: string): string | null => {
  const parts = jws.split('.');
  if (parts.length !== 3) return null;
  try {
    const decoded: unknown = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(base64urlDecode(parts[1] as string)),
    );
    if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) return null;
    const subject = (decoded as Record<string, unknown>)['publicKeyMultibase'];
    return typeof subject === 'string' ? subject : null;
  } catch {
    return null;
  }
};

export const verifyChainKeyProof = (
  jws: string,
  options: VerifyChainKeyProofOptions,
): KeyProofPayload => {
  if (options.expectedTyp === '') {
    throw new Error('invalid key proof verifier: expectedTyp must be a registered purpose value');
  }

  // 1–3. Size, header gates, closed schema over canonical bytes.
  const decoded = decodeKeyProof(jws, options.expectedTyp);
  const payload = decoded.payload;

  // The key arm FIRST: an envelope for some other key is not evidence about this
  // one, whatever else it says.
  if (payload.publicKeyMultibase !== options.publicKeyMultibase) {
    throw invalid('key', 'publicKeyMultibase is not the key being introduced');
  }
  if (payload.did !== options.did) {
    throw invalid('did', 'did is not this chain');
  }
  if (payload.prevCID !== options.prevCID) {
    throw invalid('prevCID', 'prevCID is not the carrying operation previousOperationCID');
  }
  if (!roleSetCovers(payload.roleSet, options.role)) {
    throw invalid('roleSet', `roleSet does not cover the ${options.role} role`);
  }

  // Freshness and audience are NOT checked here. See the doc comment.

  verifyKeyProofSignature(decoded);

  return payload;
};
