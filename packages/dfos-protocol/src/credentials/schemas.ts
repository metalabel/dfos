import { z } from 'zod';

// --- protocol limits ---

/** Max length for DID strings */
const MAX_DID = 256;
/** Max length for audience strings (relay hostnames or "*") */
const MAX_AUD = 512;
/** Max length for resource strings (e.g., "chain:<contentId>") */
const MAX_RESOURCE = 512;
/** Max length for action strings (e.g., "read,write") */
const MAX_ACTION = 64;
/** Max number of attenuation entries per credential */
const MAX_ATT = 32;
/** Max number of parent credential JWS tokens in prf */
const MAX_PRF = 8;

// --- DFOS credential ---

/** Single attenuation entry — resource + action pair */
export const Attenuation = z.strictObject({
  resource: z.string().min(1).max(MAX_RESOURCE),
  action: z.string().min(1).max(MAX_ACTION),
});
export type Attenuation = z.infer<typeof Attenuation>;

/** DFOS credential payload — UCAN-style authorization token */
export const DFOSCredentialPayload = z.strictObject({
  type: z.literal('DFOSCredential'),
  /** Issuer DID */
  iss: z.string().max(MAX_DID),
  /** Audience DID or "*" for public credentials */
  aud: z.string().min(1).max(MAX_AUD),
  /** Attenuations — resource + action pairs */
  att: z.array(Attenuation).min(1).max(MAX_ATT),
  /** Parent credential JWS tokens (for delegation chains) */
  prf: z.array(z.string()).max(MAX_PRF).default([]),
  /** Expiration — unix seconds */
  exp: z.number().int().positive(),
  /** Issued at — unix seconds */
  iat: z.number().int().positive(),
});
export type DFOSCredentialPayload = z.infer<typeof DFOSCredentialPayload>;

// --- auth token (unchanged) ---

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
