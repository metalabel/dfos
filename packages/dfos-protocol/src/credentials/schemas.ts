import { z } from 'zod';

// --- protocol limits ---
//
// Per-field STRING-LENGTH caps (iss/aud/resource/action) were removed in favor
// of one aggregate MAX_CREDENTIAL_SIZE cap (below): the per-field limits were a
// TS-only defensive zoo with no Go parity, so they forked validity across
// implementations. CARDINALITY caps (att entries, prf entries) remain — they
// bound structure, not byte length, and are ported identically into Go.

/** Max number of attenuation entries per credential (cardinality, not length) */
const MAX_ATT = 32;
/**
 * Max number of parent credential JWS tokens in prf. DFOS delegation is LINEAR
 * (single-parent) — the spec MUST-rejects prf.length > 1 (multi-parent
 * authority-union was an escalation class, dropped in WP-8). Bounding the schema
 * at 1 makes standalone construction and schema-validated decode match the spec
 * (defense-in-depth; the delegation walk already rejects prf>1 at authz).
 */
const MAX_PRF = 1;
/**
 * Max byte length of a credential JWS token — the credential's analog of
 * MAX_OPERATION_SIZE. Credentials are EXEMPT from the 64 KiB operation cap (a
 * maximum-depth 16-hop delegation chain embeds each parent token in `prf` and
 * legitimately exceeds it), so they carry their own larger ceiling. Measured
 * over the serialized leaf token, which contains the entire nested chain, so one
 * bound caps the whole delegation. A DoS guard on the nested `prf` structure;
 * generous (a max-depth chain serializes to well under this). VALIDITY-
 * determining: MUST match the Go reference (maxCredentialSize in jwt.go).
 */
export const MAX_CREDENTIAL_SIZE = 262144;

// --- DFOS credential ---

/** Single attenuation entry — resource + action pair */
export const Attenuation = z.looseObject({
  resource: z.string().min(1),
  action: z.string().min(1),
});
export type Attenuation = z.infer<typeof Attenuation>;

/** DFOS credential payload — UCAN-style authorization token */
export const DFOSCredentialPayload = z.looseObject({
  version: z.literal(1),
  type: z.literal('DFOSCredential'),
  /** Issuer DID */
  iss: z.string().min(1),
  /** Audience DID or "*" for public credentials */
  aud: z.string().min(1),
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

// --- auth token ---

/** Claims for a DID-signed auth token (relay AuthN) */
export const AuthTokenClaims = z.looseObject({
  /** Issuer — the DID proving identity */
  iss: z.string(),
  /** Subject — same as iss for auth tokens */
  sub: z.string(),
  /** Audience — target relay hostname (prevents cross-relay replay) */
  aud: z.string(),
  /** Expiration — unix seconds, short-lived (minutes) */
  exp: z.number().int().positive(),
  /** Issued at — unix seconds */
  iat: z.number().int().positive(),
});
export type AuthTokenClaims = z.infer<typeof AuthTokenClaims>;
