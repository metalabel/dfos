import { z } from 'zod';

/** Function that signs a byte array and returns a signature */
export type Signer = (message: Uint8Array) => Promise<Uint8Array>;

// --- protocol limits ---

/** Max length for key ID strings (e.g., "key_r9ev34fvc23z999veaaft83nn29zvhe") */
const MAX_KEY_ID = 64;
/** Max length for multibase-encoded public keys */
const MAX_PUBLIC_KEY_MULTIBASE = 128;
/** Max length for CID strings (CIDv1 base32lower ~60 chars typical) */
const MAX_CID = 256;
/** Max length for operation note annotations */
const MAX_NOTE = 256;
/** Max number of keys per role (auth, assert, controller) */
const MAX_KEYS_PER_ROLE = 16;
/** Max length for DID strings (did:dfos:xxx ~31 chars typical) */
const MAX_DID = 256;
/** Max length for a service entry id (did-core fragment, e.g. "profile") */
const MAX_SERVICE_ID = 64;
/** Max length for a service entry type string (recognized or open-namespace) */
const MAX_SERVICE_TYPE = 64;
/** Max length for a service entry value string (endpoint, label, anchor) */
const MAX_SERVICE_STRING = 512;
/** Max length for a countersignature relation tag (open-namespace string) */
const MAX_RELATION = 64;
/** Max number of service entries in an identity's services state */
export const MAX_SERVICES_ENTRIES = 16;
/** Max CBOR-encoded size of the services array (bytes) — protocol constant */
export const MAX_SERVICES_PAYLOAD_SIZE = 8192;

// ---

export const MultikeyPublicKey = z.strictObject({
  id: z.string().max(MAX_KEY_ID),
  type: z.literal('Multikey'),
  publicKeyMultibase: z.string().max(MAX_PUBLIC_KEY_MULTIBASE),
});
export type MultikeyPublicKey = z.infer<typeof MultikeyPublicKey>;

// ---

/**
 * Anchor target shapes — a ContentAnchor references a STABLE content
 * identifier, dispatched by structural form:
 *   - 31-char contentId (content chain) → mutable, gateable
 *   - CIDv1 base32 (artifact)           → immutable, public
 * Both are stable; a chain HEAD CID (also base32 but resolves to a non-artifact
 * op) is rejected by the shape-dispatch + resolution type check, never anchored.
 */
export const CONTENT_ID_ANCHOR_RE = /^[2346789acdefhknrtvz]{31}$/;
export const ARTIFACT_CID_ANCHOR_RE = /^baf[a-z2-7]{20,}$/;

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
    id: z.string().min(1).max(MAX_SERVICE_ID),
    type: z.string().min(1).max(MAX_SERVICE_TYPE),
  })
  .catchall(z.unknown())
  .superRefine((entry, ctx) => {
    if (entry.type === 'DfosRelay') {
      const endpoint = (entry as Record<string, unknown>)['endpoint'];
      if (
        typeof endpoint !== 'string' ||
        endpoint.length < 1 ||
        endpoint.length > MAX_SERVICE_STRING
      ) {
        ctx.addIssue({ code: 'custom', message: 'DfosRelay requires a non-empty endpoint string' });
      }
    } else if (entry.type === 'ContentAnchor') {
      const label = (entry as Record<string, unknown>)['label'];
      const anchor = (entry as Record<string, unknown>)['anchor'];
      if (typeof label !== 'string' || label.length < 1 || label.length > MAX_SERVICE_STRING) {
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

const Iso8601 = z.iso.datetime({ offset: false, precision: 3 });
const CIDString = z.string().max(MAX_CID);

/** Identity chain: create — genesis operation, starts the chain */
const IdentityCreate = z.strictObject({
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
const IdentityUpdate = z.strictObject({
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
});

/** Identity chain: delete — permanently destroy identity */
const IdentityDelete = z.strictObject({
  version: z.literal(1),
  type: z.literal('delete'),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
});

export const IdentityOperation = z.discriminatedUnion('type', [
  IdentityCreate,
  IdentityUpdate,
  IdentityDelete,
]);
export type IdentityOperation = z.infer<typeof IdentityOperation>;

// ---

export const VerifiedIdentity = z.strictObject({
  did: z.string().max(MAX_DID),
  isDeleted: z.boolean(),
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  /** Resolved discovery vocabulary — projection of the winning head's services */
  services: ServicesArray,
});
export type VerifiedIdentity = z.infer<typeof VerifiedIdentity>;

// ---

/** Content chain: create — genesis operation, commits initial document */
const ContentCreate = z.strictObject({
  version: z.literal(1),
  type: z.literal('create'),
  did: z.string().max(MAX_DID),
  documentCID: CIDString,
  baseDocumentCID: CIDString.nullable(),
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
});

/** Content chain: update — commit new document (null documentCID = clear) */
const ContentUpdate = z.strictObject({
  version: z.literal(1),
  type: z.literal('update'),
  did: z.string().max(MAX_DID),
  previousOperationCID: CIDString,
  documentCID: CIDString.nullable(),
  baseDocumentCID: CIDString.nullable(),
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
  /** DFOS credential authorizing this operation when signer is not the chain creator */
  authorization: z.string().optional(),
});

/** Content chain: delete — permanently destroy content */
const ContentDelete = z.strictObject({
  version: z.literal(1),
  type: z.literal('delete'),
  did: z.string().max(MAX_DID),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
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

/** Max length for artifact $schema strings */
const MAX_SCHEMA = 256;
/** Max CBOR-encoded payload size for artifacts (bytes) — protocol constant */
export const MAX_ARTIFACT_PAYLOAD_SIZE = 16384;

/** Artifact content: structured inline document with required $schema discriminator */
const ArtifactContent = z.object({ $schema: z.string().max(MAX_SCHEMA) }).catchall(z.unknown());

/** Artifact: standalone signed inline document, immutable, CID-addressable */
export const ArtifactPayload = z.strictObject({
  version: z.literal(1),
  type: z.literal('artifact'),
  did: z.string().max(MAX_DID),
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
export const CountersignPayload = z.strictObject({
  version: z.literal(1),
  type: z.literal('countersign'),
  did: z.string().max(MAX_DID),
  targetCID: CIDString,
  relation: z.string().min(1).max(MAX_RELATION).optional(),
  createdAt: Iso8601,
});
export type CountersignPayload = z.infer<typeof CountersignPayload>;

// ---

/** Revocation: signed credential revocation artifact, gossiped on the proof plane */
export const RevocationPayload = z.strictObject({
  version: z.literal(1),
  type: z.literal('revocation'),
  did: z.string().max(MAX_DID),
  credentialCID: CIDString,
  createdAt: Iso8601,
});
export type RevocationPayload = z.infer<typeof RevocationPayload>;
