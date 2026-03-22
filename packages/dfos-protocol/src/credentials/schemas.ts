import { z } from 'zod';

// --- protocol limits ---

/** Max length for DID strings */
const MAX_DID = 256;
/** Max length for audience strings (relay hostnames) */
const MAX_AUD = 512;
/** Max length for content ID strings */
const MAX_CONTENT_ID = 256;

// --- VC types ---

/** VC type for authorizing content chain writes (delegated operations) */
export const VC_TYPE_CONTENT_WRITE = 'DFOSContentWrite';
/** VC type for authorizing content plane reads (relay access) */
export const VC_TYPE_CONTENT_READ = 'DFOSContentRead';

/** All known DFOS VC types */
export const DFOSCredentialType = z.enum([VC_TYPE_CONTENT_WRITE, VC_TYPE_CONTENT_READ]);
export type DFOSCredentialType = z.infer<typeof DFOSCredentialType>;

// --- auth token ---

/** Claims for a DID-signed auth token (relay AuthN) */
export const AuthTokenClaims = z.strictObject({
  /** Issuer — the DID proving identity */
  iss: z.string().max(MAX_DID),
  /** Subject — same as iss for auth tokens */
  sub: z.string().max(MAX_DID),
  /** Audience — target relay hostname (prevents cross-relay replay) */
  aud: z.string().max(MAX_AUD),
  /** Expiration — unix seconds, short-lived (minutes) */
  exp: z.number().int().positive(),
  /** Issued at — unix seconds */
  iat: z.number().int().positive(),
});
export type AuthTokenClaims = z.infer<typeof AuthTokenClaims>;

// --- credential subject ---

/** Credential subject for content write authorization */
export const ContentWriteSubject = z.strictObject({
  /** Optional content chain narrowing — if absent, grants broad write access */
  contentId: z.string().max(MAX_CONTENT_ID).optional(),
});
export type ContentWriteSubject = z.infer<typeof ContentWriteSubject>;

/** Credential subject for content read authorization */
export const ContentReadSubject = z.strictObject({
  /** Optional content chain narrowing — if absent, grants broad read access */
  contentId: z.string().max(MAX_CONTENT_ID).optional(),
});
export type ContentReadSubject = z.infer<typeof ContentReadSubject>;

// --- VC-JWT payload ---

/** The `vc` claim in a VC-JWT payload */
export const VCClaim = z.strictObject({
  '@context': z.tuple([z.literal('https://www.w3.org/ns/credentials/v2')]),
  type: z
    .tuple([z.literal('VerifiableCredential'), DFOSCredentialType])
    .transform((t) => t as [string, DFOSCredentialType]),
  credentialSubject: z.union([ContentWriteSubject, ContentReadSubject]),
});
export type VCClaim = z.infer<typeof VCClaim>;

/** Full VC-JWT payload claims */
export const CredentialClaims = z.strictObject({
  /** Issuer — the DID granting the credential */
  iss: z.string().max(MAX_DID),
  /** Subject — the DID receiving the credential */
  sub: z.string().max(MAX_DID),
  /** Expiration — unix seconds */
  exp: z.number().int().positive(),
  /** Issued at — unix seconds */
  iat: z.number().int().positive(),
  /** Verifiable credential claim */
  vc: VCClaim,
});
export type CredentialClaims = z.infer<typeof CredentialClaims>;
