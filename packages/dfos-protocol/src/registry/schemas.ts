/*

  REGISTRY SCHEMAS

  Zod types for the DFOS Protocol registry HTTP API.
  These define the wire contract — request and response shapes
  for all registry endpoints.

*/

import { z } from 'zod';
import { MultikeyPublicKey } from '../chain/schemas';

// -----------------------------------------------------------------------------
// shared
// -----------------------------------------------------------------------------

const OperationEntry = z.strictObject({
  cid: z.string(),
  jwsToken: z.string(),
  createdAt: z.string(),
});
export type OperationEntry = z.infer<typeof OperationEntry>;

const PaginatedOperations = z.strictObject({
  operations: z.array(OperationEntry),
  nextCursor: z.string().nullable(),
});

const PaginationParams = z.object({
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});
export type PaginationParams = z.infer<typeof PaginationParams>;

// -----------------------------------------------------------------------------
// POST /identities
// -----------------------------------------------------------------------------

export const SubmitIdentityChainRequest = z.strictObject({
  chain: z.array(z.string()).min(1),
});
export type SubmitIdentityChainRequest = z.infer<typeof SubmitIdentityChainRequest>;

export const SubmitIdentityChainResponse = z.strictObject({
  did: z.string(),
  isDeleted: z.boolean(),
  authKeys: z.array(MultikeyPublicKey),
  assertKeys: z.array(MultikeyPublicKey),
  controllerKeys: z.array(MultikeyPublicKey),
});
export type SubmitIdentityChainResponse = z.infer<typeof SubmitIdentityChainResponse>;

// -----------------------------------------------------------------------------
// GET /identities/:did
// -----------------------------------------------------------------------------

export const ResolveIdentityResponse = SubmitIdentityChainResponse;
export type ResolveIdentityResponse = SubmitIdentityChainResponse;

// -----------------------------------------------------------------------------
// GET /identities/:did/operations
// -----------------------------------------------------------------------------

export const IdentityOperationsParams = PaginationParams;
export const IdentityOperationsResponse = PaginatedOperations;
export type IdentityOperationsResponse = z.infer<typeof IdentityOperationsResponse>;

// -----------------------------------------------------------------------------
// POST /entities
// -----------------------------------------------------------------------------

export const SubmitContentChainRequest = z.strictObject({
  chain: z.array(z.string()).min(1),
});
export type SubmitContentChainRequest = z.infer<typeof SubmitContentChainRequest>;

export const SubmitContentChainResponse = z.strictObject({
  entityId: z.string(),
  isDeleted: z.boolean(),
  currentDocumentCID: z.string().nullable(),
  genesisCID: z.string(),
  headCID: z.string(),
});
export type SubmitContentChainResponse = z.infer<typeof SubmitContentChainResponse>;

// -----------------------------------------------------------------------------
// GET /entities/:entityId
// -----------------------------------------------------------------------------

export const ResolveEntityResponse = SubmitContentChainResponse;
export type ResolveEntityResponse = SubmitContentChainResponse;

// -----------------------------------------------------------------------------
// GET /entities/:entityId/operations
// -----------------------------------------------------------------------------

export const EntityOperationsParams = PaginationParams;
export const EntityOperationsResponse = PaginatedOperations;
export type EntityOperationsResponse = z.infer<typeof EntityOperationsResponse>;

// -----------------------------------------------------------------------------
// GET /operations/:cid
// -----------------------------------------------------------------------------

export const ResolveOperationResponse = z.strictObject({
  cid: z.string(),
  jwsToken: z.string(),
});
export type ResolveOperationResponse = z.infer<typeof ResolveOperationResponse>;

// -----------------------------------------------------------------------------
// GET /documents/:cid
// -----------------------------------------------------------------------------

export const ResolveDocumentResponse = z.strictObject({
  cid: z.string(),
  content: z.unknown(),
});
export type ResolveDocumentResponse = z.infer<typeof ResolveDocumentResponse>;

// -----------------------------------------------------------------------------
// errors
// -----------------------------------------------------------------------------

export const RegistryError = z.strictObject({
  error: z.string(),
  message: z.string(),
});
export type RegistryError = z.infer<typeof RegistryError>;
