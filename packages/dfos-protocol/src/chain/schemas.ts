import { z } from 'zod';

/** Function that signs a byte array and returns a signature */
export type Signer = (message: Uint8Array) => Promise<Uint8Array>;

// --- protocol limits ---

/** Max length for key ID strings (e.g., "key_r9ev34fvc23z999veaaft8") */
const MAX_KEY_ID = 64;
/** Max length for multibase-encoded public keys */
const MAX_PUBLIC_KEY_MULTIBASE = 128;
/** Max length for CID strings (CIDv1 base32lower ~60 chars typical) */
const MAX_CID = 256;
/** Max length for operation note annotations */
const MAX_NOTE = 256;
/** Max number of keys per role (auth, assert, controller) */
const MAX_KEYS_PER_ROLE = 16;

// ---

export const MultikeyPublicKey = z.strictObject({
  id: z.string().max(MAX_KEY_ID),
  type: z.literal('Multikey'),
  publicKeyMultibase: z.string().max(MAX_PUBLIC_KEY_MULTIBASE),
});
export type MultikeyPublicKey = z.infer<typeof MultikeyPublicKey>;

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
  did: z.string(),
  isDeleted: z.boolean(),
  authKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  assertKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
  controllerKeys: z.array(MultikeyPublicKey).max(MAX_KEYS_PER_ROLE),
});
export type VerifiedIdentity = z.infer<typeof VerifiedIdentity>;

// ---

/** Content chain: create — genesis operation, commits initial document */
const ContentCreate = z.strictObject({
  version: z.literal(1),
  type: z.literal('create'),
  documentCID: CIDString,
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
});

/** Content chain: update — commit new document (null documentCID = clear) */
const ContentUpdate = z.strictObject({
  version: z.literal(1),
  type: z.literal('update'),
  previousOperationCID: CIDString,
  documentCID: CIDString.nullable(),
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
});

/** Content chain: delete — permanently destroy entity */
const ContentDelete = z.strictObject({
  version: z.literal(1),
  type: z.literal('delete'),
  previousOperationCID: CIDString,
  createdAt: Iso8601,
  note: z.string().max(MAX_NOTE).nullable(),
});

export const ContentOperation = z.discriminatedUnion('type', [
  ContentCreate,
  ContentUpdate,
  ContentDelete,
]);
export type ContentOperation = z.infer<typeof ContentOperation>;
