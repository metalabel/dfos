import { z } from 'zod';
import { KEY_ROLES } from '../key-proof/role-set';

/** Function that signs a byte array and returns a signature */
export type Signer = (message: Uint8Array) => Promise<Uint8Array>;

// --- protocol limits ---
//
// Per-field STRING-LENGTH caps (did, key id, multibase, CID) were removed
// in favor of one aggregate MAX_OPERATION_SIZE cap (below): the per-field limits
// were a TS-only defensive zoo with no spec mandate and no Go parity, so they
// forked validity across implementations. The genuine validity rules those
// fields rely on (CID re-derivation, ed25519 key decode, ISO-8601 parsing) are
// enforced directly and identically in both impls. CARDINALITY caps (keys per
// role, services entries/bytes) remain — they bound structure, not byte length.
//
// Wire-payload schemas use z.looseObject (not z.strictObject): unknown keys are
// preserved (not stripped) and ignored, honoring the protocol's MUST-ignore-
// unknown forward-compat rule and matching the Go library (which decodes into
// map[string]any and ignores extras). Preserving — not stripping — unknown keys
// is required for CID integrity: the operation CID is re-derived from the parsed
// object, so a stripped key would change the re-encoded bytes and fail the CID
// match. VerifiedIdentity stays strict — it is the verifier's internal output,
// never decoded from untrusted wire bytes.

/**
 * Max number of keys per role (auth, assert, controller) — a generous cardinality
 * ceiling on key fan-out. The operation-size cap is the real byte arbiter; a role
 * never approaches this in practice.
 */
const MAX_KEYS_PER_ROLE = 256;
/**
 * Max number of key-proof envelopes an update may carry — a cardinality ceiling
 * matching MAX_KEYS_PER_ROLE, since an operation never needs more envelopes than
 * it introduces keys. The operation-size cap is still the real byte arbiter; this
 * bounds the walk's per-operation verification work so a single 64 KiB operation
 * cannot ask a verifier for an unbounded number of signature checks.
 * VALIDITY-determining: MUST match maxKeyProofs in the Go reference.
 */
export const MAX_KEY_PROOFS = 256;
/** Max length for a countersignature relation tag (open-namespace string) */
const MAX_RELATION = 64;
/**
 * Max number of service entries in an identity's services state — a generous
 * cardinality ceiling on resolution fan-out. Individual entry fields are NOT
 * separately length-capped (no per-field length zoo): the aggregate byte cap
 * below, plus the operation-size cap, bound entry size. The op-size cap is the
 * real arbiter when services and keys are both large.
 */
export const MAX_SERVICES_ENTRIES = 256;
/**
 * Max CBOR-encoded size of the services array (bytes) — the SINGLE aggregate that
 * bounds the services manifest, replacing the former per-field length caps (the
 * same collapse the op-size cap applied at the operation level). Sized so the
 * 256-entry ceiling is genuinely reachable with realistic entries.
 */
export const MAX_SERVICES_PAYLOAD_SIZE = 32768;
/**
 * Max dag-cbor-encoded size of a single protocol operation payload (bytes) — the
 * one aggregate validity bound on operation size, measured over the exact bytes
 * the CID commits to. Generously set (64 KiB) so it never binds a legitimate
 * proof-layer operation while bounding decode/verify cost (a DoS + determinism
 * invariant). This is a VALIDITY-determining cap: it MUST be identical across
 * implementations. Large binary media does NOT travel in operation payloads —
 * it is referenced, not inlined — so this bound is about proof-layer ops only.
 */
export const MAX_OPERATION_SIZE = 65536;

// ---

export const MultikeyPublicKey = z.looseObject({
  id: z.string(),
  type: z.literal('Multikey'),
  publicKeyMultibase: z.string(),
});
export type MultikeyPublicKey = z.infer<typeof MultikeyPublicKey>;

// ---

/**
 * Anchor target shapes — a ContentAnchor references a STABLE content
 * identifier, dispatched by structural form:
 *   - 31-char contentId (content chain) → mutable, gateable
 *   - CIDv1 dag-cbor+sha256 (artifact)  → immutable, public
 * Both are stable; a chain HEAD CID (also a `bafyrei…` CID but resolves to a
 * non-artifact op) is rejected by the shape-dispatch + resolution type check,
 * never anchored.
 *
 * The artifact form is the EXACT 59-char CIDv1(dag-cbor 0x71 + sha256 0x12 0x20)
 * base32 string — 36 raw bytes → 58 base32 chars + the `b` multibase prefix,
 * fixed `bafyrei` head + 52 base32 chars. Artifact payloads are ALWAYS dag-cbor +
 * sha256 (ArtifactPayload below), so every real artifact CID is `bafyrei…`. The
 * regex is pinned to that exact length (not a loose `baf…{20,}`) so an anchor of
 * any other shape — wrong codec, wrong length — is rejected uniformly across
 * implementations. New anchor KINDS arrive via a new service `type`, never a new
 * anchor shape.
 */
export const CONTENT_ID_ANCHOR_RE = /^[2346789acdefhknrtvz]{31}$/;
export const ARTIFACT_CID_ANCHOR_RE = /^bafyrei[a-z2-7]{52}$/;

/**
 * Service entry — discovery vocabulary in identity-chain state.
 *
 * Open namespace: `type` is an arbitrary bounded string. Recognized types
 * (`DfosRelay`, `ContentAnchor`) are structurally validated; UNRECOGNIZED types
 * are preserved verbatim and ignored (MUST-ignore-unknown) — only the common
 * envelope (id + type) and the byte cap apply. New service types therefore
 * never require a protocol/cross-language change.
 */
export const ServiceEntry = z
  .object({
    id: z.string().min(1),
    type: z.string().min(1),
  })
  .catchall(z.unknown())
  .superRefine((entry, ctx) => {
    if (entry.type === 'DfosRelay') {
      const endpoint = (entry as Record<string, unknown>)['endpoint'];
      if (typeof endpoint !== 'string' || endpoint.length < 1) {
        ctx.addIssue({ code: 'custom', message: 'DfosRelay requires a non-empty endpoint string' });
      }
    } else if (entry.type === 'ContentAnchor') {
      const label = (entry as Record<string, unknown>)['label'];
      const anchor = (entry as Record<string, unknown>)['anchor'];
      if (typeof label !== 'string' || label.length < 1) {
        ctx.addIssue({
          code: 'custom',
          message: 'ContentAnchor requires a non-empty label string',
        });
      }
      if (
        typeof anchor !== 'string' ||
        !(CONTENT_ID_ANCHOR_RE.test(anchor) || ARTIFACT_CID_ANCHOR_RE.test(anchor))
      ) {
        ctx.addIssue({
          code: 'custom',
          message: 'ContentAnchor anchor must be a 31-char contentId or a CIDv1 artifact CID',
        });
      }
    }
    // unrecognized types: envelope + byte cap only (MUST-ignore-unknown)
  });
export type ServiceEntry = z.infer<typeof ServiceEntry>;

/** Identity services state — full-state, bounded, unique entry ids */
export const ServicesArray = z
  .array(ServiceEntry)
  .max(MAX_SERVICES_ENTRIES)
  .refine(
    (arr) => new Set(arr.map((e) => e.id)).size === arr.length,
    'service entry ids must be unique',
  );
export type ServicesArray = z.infer<typeof ServicesArray>;

// ---

/**
 * The canonical DFOS operation timestamp grammar: fixed 3-digit fraction, literal
 * `Z`, full calendar validation. Deliberately stricter than RFC 3339 (no numeric
 * offsets, no variable fraction) so two implementations cannot disagree about
 * whether a signed timestamp is well-formed. The Go twin is
 * `time.Parse(protocolTimeFormat, …)`; the 22-case vector set asserting they agree
 * verdict-for-verdict lives in tests/timestamp-grammar.spec.ts and
 * dfos-protocol-go/timestamp_grammar_test.go.
 */
export const Iso8601 = z.iso.datetime({ offset: false, precision: 3 });

/**
 * Parse a canonical DFOS timestamp to integer unix **seconds**, or null when it
 * does not match the grammar above.
 *
 * This is the ONE parse every consumer of a signed timestamp should use when it
 * needs a comparable instant. A lenient `new Date(value)` accepts inputs the
 * protocol rejects (numeric offsets, missing `Z` — which some runtimes then read
 * as LOCAL time), so two verifiers in different timezones could order the same two
 * signed timestamps differently. Truncates (floors) the millisecond remainder to
 * match the credential temporal basis — see CREDENTIALS.md "Time Basis Conversion
 * and Boundaries". Go twin: `ParseProtocolTimestamp`.
 */
export const parseProtocolTimestampUnix = (value: string): number | null => {
  if (!Iso8601.safeParse(value).success) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
};

const CIDString = z.string();

/** Identity chain: create — genesis operation, starts the chain */
const IdentityCreate = z.looseObject({
  version: z.literal(1),
  type: z.literal('create'),
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  // Full-state discovery vocabulary. Optional so ops without services encode
  // identically (undefined strips under canonical CBOR — CID-neutral).
  services: ServicesArray.optional(),
  createdAt: Iso8601,
});

/** Identity chain: update — key rotation or modification */
const IdentityUpdate = z.looseObject({
  version: z.literal(1),
  type: z.literal('update'),
  previousOperationCID: CIDString,
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z
    .array(MultikeyPublicKey)
    .min(1, 'update must have at least one controller key')
    .max(MAX_KEYS_PER_ROLE),
  // Full-state: an update REPLACES the entire services set (omit to clear).
  services: ServicesArray.optional(),
  createdAt: Iso8601,
  /**
   * POSSESSION PROOFS FOR THE KEYS THIS OPERATION INTRODUCES — compact key-proof
   * JWS strings (specs/KEY-PROOF.md), each signed by the key it speaks for.
   *
   * Optional, and optional in the CID-neutral sense: omitting it encodes
   * identically to an operation that never had it (undefined strips under
   * canonical CBOR), so the overwhelming majority of updates — the ones that
   * merely replay keys already in effective state — carry nothing. Proofs are
   * never replayed forward with the keys; full-state carriage applies to key
   * ARRAYS, not to the evidence that admitted them.
   *
   * PRESENT ON `update` ONLY. A `create` needs none (its single genesis key is
   * proved by signing genesis) and `delete`/`restore` introduce nothing, so an
   * envelope on any of the three is a rejected operation, not an ignored member
   * — see the carriage gate in identity-chain.ts.
   *
   * A MISSING OR BAD PROOF DOES NOT INVALIDATE THE OPERATION. It voids the
   * key-role membership it would have admitted: the operation stands, the chain
   * stands, and the key is simply absent from EFFECTIVE state for that role.
   */
  keyProofs: z.array(z.string()).max(MAX_KEY_PROOFS).optional(),
});

/** Identity chain: delete — deactivate identity */
const IdentityDelete = z.looseObject({
  version: z.literal(1),
  type: z.literal('delete'),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
});

/** Identity chain: restore — reactivate immediately after delete */
const IdentityRestore = z.looseObject({
  version: z.literal(1),
  type: z.literal('restore'),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
});

export const IdentityOperation = z.discriminatedUnion('type', [
  IdentityCreate,
  IdentityUpdate,
  IdentityDelete,
  IdentityRestore,
]);
export type IdentityOperation = z.infer<typeof IdentityOperation>;

// ---

/**
 * The key arrays exactly as the chain's operations DECLARE them, before any
 * question of possession. Structural state: what the controller wrote.
 */
export const DeclaredKeyState = z.strictObject({
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
});
export type DeclaredKeyState = z.infer<typeof DeclaredKeyState>;

/**
 * ONE DECLARED-BUT-UNPROVED KEY-ROLE MEMBERSHIP. The chain says this key holds
 * this role; no possession proof ever admitted it, so consumers do not see it.
 *
 * VOID IS NOT INVALID. The operation that declared it is valid, the chain is
 * valid, and the membership is simply absent from effective state. Enumerating
 * these loudly is the point: a controller who introduced a key without a proof
 * has a chain that verifies and a key that does not resolve, and the only way
 * they learn that is if tooling can see the list.
 */
export const VoidKeyMembership = z.strictObject({
  /** The key as declared. */
  key: MultikeyPublicKey,
  /** The role it was declared into but is not effective for. */
  role: z.enum(KEY_ROLES),
  /** The CID of the operation whose declaration is currently unproved. */
  operationCID: z.string(),
});
export type VoidKeyMembership = z.infer<typeof VoidKeyMembership>;

/**
 * THE VERIFIED IDENTITY. `authKeys`/`assertKeys`/`controllerKeys` are EFFECTIVE
 * state — the memberships a possession proof actually admitted — because
 * effective state is what every consumer wants: a void key must never resolve,
 * never index, and never enter a has-ever surface.
 *
 * `declared` and `voidKeys` carry the structural half alongside it, so the
 * surfaces that genuinely need "what does the chain SAY" can ask. There is
 * exactly one such surface in the protocol: SIGNER VALIDITY, which stays
 * declared-state-based on purpose (see identity-chain.ts). Both are optional
 * because a caller may hand a hand-built state to the extension verifier;
 * absent `declared` is read as "the arrays are also the declared arrays", which
 * is exactly true for any chain with no void memberships.
 */
export const VerifiedIdentity = z.strictObject({
  did: z.string(),
  isDeleted: z.boolean(),
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  /** Resolved discovery vocabulary — projection of the winning head's services */
  services: ServicesArray,
  /** What the chain declares, void memberships included. */
  declared: DeclaredKeyState.optional(),
  /** Declared memberships no proof admitted. Empty on a fully-proved chain. */
  voidKeys: z.array(VoidKeyMembership).optional(),
  /**
   * HAS-EVER-PROVED: the union of every effective key state this chain has held,
   * across its whole history. Monotonic — a key that was proved into a role and
   * later removed stays here forever, because the fact it names is that the
   * holder once demonstrated possession, and that does not become untrue.
   *
   * TWO SURFACES NEED EXACTLY THIS, and both are wrong without it:
   *
   *  - THE `key=` REVERSE INDEX, which is the one-key-one-DID oracle. A holder
   *    asks it before signing a key proof, and refuses when some chain already
   *    proved the key — because proving one key into two chains publishes an
   *    irreversible public link between them. A DECLARATION publishes no such
   *    link: anyone can write anyone's public key into their own chain, so
   *    indexing declarations would let a stranger burn a key they do not hold,
   *    by writing it into a chain and making every future ceremony refuse it.
   *  - HISTORICAL KEY RESOLUTION, which verifies long-lived artifacts across
   *    rotations. A credential signed by a key that was proved and later rotated
   *    out must still verify; one signed by a key no chain ever proved must not.
   *
   * Computed during the walk, where the fold already runs, so consumers stop
   * re-deriving it from the raw log under a declared-state rule that quietly
   * disagrees with this one.
   */
  provedKeys: DeclaredKeyState.optional(),
});
export type VerifiedIdentity = z.infer<typeof VerifiedIdentity>;

// ---

/** Content chain: create — genesis operation, commits initial document */
const ContentCreate = z.looseObject({
  version: z.literal(1),
  type: z.literal('create'),
  did: z.string(),
  documentCID: CIDString,
  baseDocumentCID: CIDString.nullable(),
  createdAt: Iso8601,
});

/** Content chain: update — commit new document (null documentCID = clear) */
const ContentUpdate = z.looseObject({
  version: z.literal(1),
  type: z.literal('update'),
  did: z.string(),
  previousOperationCID: CIDString,
  documentCID: CIDString.nullable(),
  baseDocumentCID: CIDString.nullable(),
  createdAt: Iso8601,
  /** DFOS credential authorizing this operation when signer is not the chain creator */
  authorization: z.string().optional(),
});

/** Content chain: delete — permanently destroy content */
const ContentDelete = z.looseObject({
  version: z.literal(1),
  type: z.literal('delete'),
  did: z.string(),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
  /** DFOS credential authorizing this operation when signer is not the chain creator */
  authorization: z.string().optional(),
});

export const ContentOperation = z.discriminatedUnion('type', [
  ContentCreate,
  ContentUpdate,
  ContentDelete,
]);
export type ContentOperation = z.infer<typeof ContentOperation>;

// ---

/** Max CBOR-encoded payload size for artifacts (bytes) — protocol constant */
export const MAX_ARTIFACT_PAYLOAD_SIZE = 16384;

/**
 * Artifact content: structured inline document with required $schema discriminator.
 * No per-field length cap on $schema (no length zoo): artifacts are bounded solely
 * by the aggregate MAX_ARTIFACT_PAYLOAD_SIZE, identical-by-construction with Go's
 * VerifyArtifact (which only requires $schema be a present string). A former TS-only
 * 256-char cap forked artifact validity from Go and is removed.
 */
const ArtifactContent = z.object({ $schema: z.string() }).catchall(z.unknown());

/** Artifact: standalone signed inline document, immutable, CID-addressable */
export const ArtifactPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('artifact'),
  did: z.string(),
  content: ArtifactContent,
  createdAt: Iso8601,
});
export type ArtifactPayload = z.infer<typeof ArtifactPayload>;

// ---

/**
 * Countersign: standalone witness attestation referencing a target operation by CID.
 *
 * `relation` is an OPEN-namespace tag naming the nature of the attestation
 * (e.g. `coauthors`, `endorses`, `witnessed`, `holds`, `received`). It is an
 * arbitrary bounded string — recognized values carry social meaning to clients,
 * unrecognized values MUST be preserved and ignored. Optional, so a bare witness
 * attestation (no relation) encodes identically (CID-neutral).
 */
export const CountersignPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('countersign'),
  did: z.string(),
  targetCID: CIDString,
  relation: z.string().min(1).max(MAX_RELATION).optional(),
  createdAt: Iso8601,
});
export type CountersignPayload = z.infer<typeof CountersignPayload>;

// ---

/** Revocation: signed credential revocation artifact, gossiped on the proof plane */
export const RevocationPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('revocation'),
  did: z.string(),
  credentialCID: CIDString,
  createdAt: Iso8601,
});
export type RevocationPayload = z.infer<typeof RevocationPayload>;

// ---

/**
 * Max byte length of a credit-claim JWS token — the claim's aggregate size bound,
 * the same register as MAX_CREDENTIAL_SIZE (measured over the serialized token,
 * checked before any decode as a DoS guard). Claims are small by construction:
 * two identifiers, a role string, and a timestamp. Deliberately tight because
 * claims travel INSIDE document bytes — a document embedding many credits carries
 * one token per claimed entry, so a generous per-claim cap would multiply into the
 * document blob. `role` therefore carries no separate length cap; this aggregate
 * is the single byte arbiter. VALIDITY-determining: MUST match the Go reference
 * (maxCreditClaimSize in credit_claim.go).
 */
export const MAX_CREDIT_CLAIM_SIZE = 4096;

/**
 * Credit claim: a claimant's signed assertion that it holds a named role on a
 * content chain. A document-plane artifact — it is NOT gossiped and relays are not
 * credit-claim aware; a claim travels inside the document bytes that embed it (see
 * `specs/CREDITS.md`).
 *
 * `contentId` is the binder — the STABLE 31-char content chain id, never a
 * documentCID or a chain head CID. Binding to the chain (not a document) is what
 * makes a claim survive edits verbatim and avoids the circularity of a claim
 * embedded in the very document it would otherwise commit to. It is shape-validated
 * against the same 31-char contentId form used for anchor dispatch, so an artifact
 * CID (immutable, chainless, and therefore unable to host a credits slot) is
 * rejected uniformly across implementations.
 *
 * `role` is an OPEN-namespace tag compared by exact, case-sensitive byte equality —
 * it is the third component of the entry↔claim bind, so no normalization of any kind
 * is applied to it.
 *
 * `asOfDocumentCID` is an OPTIONAL content-strength flavor: the claimant pins the
 * document state it is crediting itself on. Omitted by default, and omission is
 * CID-neutral (undefined strips under canonical CBOR). Consumers that ignore it are
 * conformant — the bind never depends on it. When the key IS present it MUST be a
 * non-empty string: an empty string is a distinct, CID-changing encoding from an
 * absent field, so accepting it would mean two different claim CIDs for the same
 * (absent-flavor) statement.
 *
 * `did` is constrained to the `did:` prefix and non-empty, which is STRICTER than
 * the sibling wire payloads above (`RevocationPayload.did`, `ContentOperation.did`
 * are bare strings). That is deliberate, not drift: the published
 * `credit-claim/v1` JSON Schema already mandates `^did:`, so leaving the zod schema
 * permissive forked validity between the schema, this verifier, and the Go twin.
 * The check is a PREFIX check, not full did:dfos validation — a claimant DID is not
 * required to be a did:dfos identifier.
 */
export const CreditClaimPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('credit-claim'),
  contentId: z.string().regex(CONTENT_ID_ANCHOR_RE, 'contentId must be a 31-char content chain id'),
  did: z.string().regex(/^did:/, 'did must be a DID (did: prefix)'),
  role: z.string().min(1),
  createdAt: Iso8601,
  asOfDocumentCID: CIDString.min(1, 'asOfDocumentCID must be non-empty when present').optional(),
});
export type CreditClaimPayload = z.infer<typeof CreditClaimPayload>;

// ---

/**
 * Max byte length of a sign-request JWS token. Checked before any decode on the
 * verify path and after construction on the build path. VALIDITY-determining:
 * MUST match maxSignRequestSize in the Go reference.
 */
export const MAX_SIGN_REQUEST_SIZE = 8192;

/**
 * Max decoded byte length of the exact target payload carried by a sign request.
 * This is the single aggregate cap on target bytes; there are no per-field caps.
 * VALIDITY-determining: MUST match maxSignRequestPayloadSize in Go.
 */
export const MAX_SIGN_REQUEST_PAYLOAD_SIZE = 4096;

/**
 * Sign request: a requester's signed ask that one subject sign exact target bytes
 * as one named artifact type before a bounded deadline.
 *
 * Unknown envelope fields are preserved-and-ignored, matching every other wire
 * payload in this file. The signer-side target-payload check is deliberately
 * strict instead: a signer refuses fields it cannot render (see SIGNING.md).
 */
export const SignRequestPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('sign-request'),
  did: z.string().regex(/^did:/, 'did must be a DID (did: prefix)'),
  subject: z.string().regex(/^did:/, 'subject must be a DID (did: prefix)'),
  payloadTyp: z.string().min(1),
  payload: z.string().min(1),
  createdAt: Iso8601,
  expiresAt: Iso8601,
});
export type SignRequestPayload = z.infer<typeof SignRequestPayload>;
