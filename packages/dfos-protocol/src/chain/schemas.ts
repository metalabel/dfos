import { z } from 'zod';

/** Function that signs a byte array and returns a signature */
export type Signer = (message: Uint8Array) => Promise<Uint8Array>;

// ---

export const MultikeyPublicKey = z.strictObject({
  id: z.string(),
  type: z.literal('Multikey'),
  publicKeyMultibase: z.string(),
});
export type MultikeyPublicKey = z.infer<typeof MultikeyPublicKey>;

// ---

const Iso8601 = z.iso.datetime({ offset: false, precision: 3 });

/** Identity chain: create — genesis operation, starts the chain */
const IdentityCreate = z.strictObject({
  version: z.literal(1),
  type: z.literal('create'),
  authKeys: z.array(MultikeyPublicKey),
  assertKeys: z.array(MultikeyPublicKey),
  controllerKeys: z.array(MultikeyPublicKey),
  createdAt: Iso8601,
});

/** Identity chain: update — key rotation or modification */
const IdentityUpdate = z.strictObject({
  version: z.literal(1),
  type: z.literal('update'),
  previousOperationCID: z.string(),
  authKeys: z.array(MultikeyPublicKey),
  assertKeys: z.array(MultikeyPublicKey),
  controllerKeys: z.array(MultikeyPublicKey).min(1, 'update must have at least one controller key'),
  createdAt: Iso8601,
});

/** Identity chain: delete — permanently destroy identity */
const IdentityDelete = z.strictObject({
  version: z.literal(1),
  type: z.literal('delete'),
  previousOperationCID: z.string(),
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
  authKeys: z.array(MultikeyPublicKey),
  assertKeys: z.array(MultikeyPublicKey),
  controllerKeys: z.array(MultikeyPublicKey),
});
export type VerifiedIdentity = z.infer<typeof VerifiedIdentity>;

// ---

/** Content chain: create — genesis operation, commits initial document */
const ContentCreate = z.strictObject({
  version: z.literal(1),
  type: z.literal('create'),
  documentCID: z.string(),
  createdAt: Iso8601,
  note: z.string().nullable(),
});

/** Content chain: update — commit new document (null documentCID = clear) */
const ContentUpdate = z.strictObject({
  version: z.literal(1),
  type: z.literal('update'),
  previousOperationCID: z.string(),
  documentCID: z.string().nullable(),
  createdAt: Iso8601,
  note: z.string().nullable(),
});

/** Content chain: delete — permanently destroy entity */
const ContentDelete = z.strictObject({
  version: z.literal(1),
  type: z.literal('delete'),
  previousOperationCID: z.string(),
  createdAt: Iso8601,
  note: z.string().nullable(),
});

export const ContentOperation = z.discriminatedUnion('type', [
  ContentCreate,
  ContentUpdate,
  ContentDelete,
]);
export type ContentOperation = z.infer<typeof ContentOperation>;
