/*

  API AUTH — THE ENVELOPE FAMILY'S BYTE CONTRACT AND PROOF PHASE.

  A REQUEST PROOF is a short-lived JWS, signed by the key of the party a DFOS
  credential was issued to, that binds ONE exact HTTP request (method, host,
  path, body) to that credential, right now. An IDENTITY PROOF is the same
  envelope minus `credentialCID`: it binds the same exact request to a bare DID,
  proving only WHO IS ASKING. See specs/API-AUTH.md.

  WHY THIS LIVES IN dfos-protocol AND NOT IN dfos-client. `@metalabel/dfos-client`
  peer-depends on `@metalabel/dfos-web-relay`, so a relay that imported the
  client's verifier would close a dependency CYCLE. The relay is a first-class
  consumer of the identity proof (blob upload, non-public blob reads, the signing
  mailbox poll, ingestion admission), so the byte contract and the proof phase
  live HERE — the same home `auth-token.ts`, the artifact this replaces, used to
  occupy — and `dfos-client/src/api-auth.ts` re-exports them and adds the
  Client-bound resolver plus the credential walk (API-AUTH steps 8–11).

  There is still exactly ONE canonical-bytes implementation per language: this
  file, and its byte-twin `api_auth.go` in dfos-protocol-go.

  The verifier here is RESOLVER-AGNOSTIC: it takes a `ResolveProofPresenter`
  callback rather than a network client, so a relay resolving against its own
  local store and a client resolving over the network run the identical algorithm.

*/

import { decodeMultikey } from '../chain/multikey';
import {
  assertJwsProfile,
  base64urlDecode,
  base64urlEncode,
  createJws,
  decodeJwsUnsafe,
  sha256,
  verifyJws,
} from '../crypto';

// -----------------------------------------------------------------------------
// the byte contract
// -----------------------------------------------------------------------------

/**
 * The normative JWS header `typ` for a request proof (API-AUTH.md). Signers MUST
 * set it; the request-proof verifier rejects anything else — it is also what lets
 * typ-routing dispatchers tell a proof apart from credentials and chain ops.
 */
export const REQUEST_PROOF_JWS_TYP = 'did:dfos:request-proof';

/**
 * The normative JWS header `typ` for an identity proof (API-AUTH.md) — the
 * request proof's credential-less sibling.
 *
 * THE TYP GATE IS ABSOLUTE, IN BOTH DIRECTIONS. "Possession of a grant's
 * audience key" and "possession of a bare identity's key" are different claims,
 * so a route requiring a credential rejects an identity proof at the header gate
 * and a route requiring bare identity rejects a request proof at the same gate.
 * No verifier ambiguity, no downgrade.
 */
export const IDENTITY_PROOF_JWS_TYP = 'did:dfos:identity-proof';

/**
 * The digest of zero octets. A request with no body hashes the empty string —
 * there is deliberately no absent-member form for bodyless requests, so every
 * proof is checked the same way.
 */
export const EMPTY_BODY_SHA256 = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';

/** Size cap on the serialized proof token, checked BEFORE any decode. */
export const MAX_REQUEST_PROOF_SIZE = 4096;

/** RECOMMENDED acceptance window `W` — how old a proof may be, in seconds. */
export const DEFAULT_PROOF_WINDOW_SECONDS = 60;

/** RECOMMENDED clock-skew allowance `S` — how forward-dated a proof may be. */
export const DEFAULT_PROOF_SKEW_SECONDS = 60;

/**
 * The binding cap on `W + S`: the total span over which any one proof is
 * accepted, and therefore its worst-case replay window. A configuration
 * exceeding it is refused rather than clamped — a deployment that silently got a
 * 10-minute replay window it did not ask for is the failure this forbids.
 */
export const MAX_PROOF_FRESHNESS_SPAN_SECONDS = 300;

/**
 * Default cap on the decoded body a verifier will hash, in bytes (1 MiB). The v0
 * action registry is bodyless, so this never binds today; it is the defensive
 * ceiling for the first body-bearing action, overridable per verifier.
 */
export const MAX_BODY_BYTES = 1_048_576;

/**
 * The `Authorization` scheme this family rides — the token `DFOS`, deliberately
 * NOT `Bearer`, because nothing carried here is a bearer token and naming it one
 * invites bearer handling (logging, caching, forwarding) the artifact exists to
 * make useless.
 */
export const DFOS_AUTH_SCHEME = 'DFOS';

export interface RequestProofPayload {
  /** The HTTP method, uppercase. */
  method: string;
  /** The API's lowercase authority — `host` on 443, `host:port` otherwise. */
  host: string;
  /** The exact origin-form request target — path plus query string, byte for byte. */
  path: string;
  /** Canonical unpadded base64url of the SHA-256 of the raw request body octets. */
  bodyHash: string;
  /** CID of the leaf credential presented alongside this proof. */
  credentialCID: string;
  /** Issued-at — unix seconds (positive integer). */
  iat: number;
}

/**
 * The identity proof's payload: the request proof's five members MINUS
 * `credentialCID`. All five are required, under the SAME member rules — there is
 * no relaxation here, only one fewer member.
 */
export interface IdentityProofPayload {
  /** The HTTP method, uppercase. */
  method: string;
  /** The API's lowercase authority — `host` on 443, `host:port` otherwise. */
  host: string;
  /** The exact origin-form request target — path plus query string, byte for byte. */
  path: string;
  /** Canonical unpadded base64url of the SHA-256 of the raw request body octets. */
  bodyHash: string;
  /** Issued-at — unix seconds (positive integer). */
  iat: number;
}

/**
 * ADDITIVE MEMBERS, appended AFTER the canonical order.
 *
 * API-AUTH.md's growth rule is additive members on this envelope, never a new
 * envelope: "additional members register additively, appended to the canonical
 * order". `jti` — the per-request uniqueness member a write-gating deployment
 * requires — is the named one.
 *
 * TWO RULES MAKE THIS A BYTE-TWIN. (1) Extra members are emitted AFTER every
 * canonical member, so a verifier that ignores them still reconstructs the same
 * prefix. (2) Among themselves they are emitted in LEXICOGRAPHIC ORDER OF MEMBER
 * NAME — not insertion order, because Go map iteration is randomized and a TS
 * signer and a Go signer must emit identical bytes from identical inputs.
 *
 * Values are strings. The registered member (`jti`) is a string, and restricting
 * the type keeps the two encoders from disagreeing about number formatting.
 */
export type ProofExtraMembers = Readonly<Record<string, string>>;

/** The internal union of both payloads; `credentialCID` is present iff credentialed. */
export interface ParsedProofPayload {
  method: string;
  host: string;
  path: string;
  bodyHash: string;
  credentialCID?: string;
  iat: number;
}

/**
 * The two artifacts of this family, as the INTERNALS see them. One member rules
 * implementation, one canonical-bytes implementation, and one proof-phase
 * implementation serve both — parameterized by the single member that differs
 * (`credentialCID`) and by the `typ` that keeps the two claims distinct.
 */
interface ProofShape {
  /** Diagnostic label — "request proof" / "identity proof". */
  label: string;
  /** The normative header `typ`. Verifiers gate on it absolutely. */
  typ: string;
  /** Whether `credentialCID` is a member of this artifact's payload. */
  credentialed: boolean;
}

const REQUEST_PROOF_SHAPE: ProofShape = {
  label: 'request proof',
  typ: REQUEST_PROOF_JWS_TYP,
  credentialed: true,
};

const IDENTITY_PROOF_SHAPE: ProofShape = {
  label: 'identity proof',
  typ: IDENTITY_PROOF_JWS_TYP,
  credentialed: false,
};

const encoder = new TextEncoder();
const EMPTY_BODY = new Uint8Array(0);

// An HTTP method token per RFC 9110 `tchar`, with the lowercase letters removed:
// the member is normatively uppercase, and "get" MUST NOT verify against "GET".
const UPPERCASE_METHOD = /^[A-Z0-9!#$%&'*+.^_`|~-]+$/;
// A lone surrogate has no convergent serialization: `JSON.stringify` round-trips
// it to a `\uXXXX` escape that the Go byte-twin's UTF-8 strings cannot hold, so
// it is refused on both sides rather than signable on one.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// ASCII space, the C0 controls, and DEL — none of which can ride an origin-form
// request line, so a `path` carrying one was never a real request target.
const CTL_OR_SPACE = /[\u0000-\u0020\u007f]/;
// 32 digest bytes are exactly 43 canonical unpadded base64url characters.
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
// Additive member names are restricted to a conservative ASCII set so that
// lexicographic ordering is IDENTICAL in TS (UTF-16 code units) and Go (bytes).
const EXTRA_MEMBER_NAME = /^[A-Za-z0-9_.-]+$/;
// The canonical members, which an additive member may never shadow.
const CANONICAL_MEMBERS = new Set(['method', 'host', 'path', 'bodyHash', 'credentialCID', 'iat']);

const assertNoLoneSurrogate = (value: string, field: string, label: string): void => {
  if (LONE_SURROGATE.test(value)) {
    throw new Error(`invalid ${label}: ${field} must be well-formed Unicode`);
  }
};

/**
 * Validate a payload against API-AUTH.md's step-3 schema — the SAME member rules
 * for both artifacts, with `credentialCID` required iff the shape is
 * credentialed. Unknown members are IGNORED (the protocol's MUST-ignore-unknown
 * rule) — the canonical rebuild below drops them rather than refusing them, so a
 * future additive member never makes today's verifier reject a well-formed
 * proof. That is also why a stray `credentialCID` on an identity proof is
 * ignored rather than refused: the `typ` gate, not member sniffing, is what tells
 * the two artifacts apart.
 */
const validateProofPayload = (value: unknown, shape: ProofShape): ParsedProofPayload => {
  const label = shape.label;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`invalid ${label}: expected a JSON object`);
  }
  const raw = value as Record<string, unknown>;

  const stringFields = ['method', 'host', 'path', 'bodyHash'];
  if (shape.credentialed) stringFields.push('credentialCID');
  for (const field of stringFields) {
    if (typeof raw[field] !== 'string' || raw[field] === '') {
      throw new Error(`invalid ${label}: ${field} must be a non-empty string`);
    }
    assertNoLoneSurrogate(raw[field] as string, field, label);
  }

  const method = raw['method'] as string;
  if (!UPPERCASE_METHOD.test(method)) {
    throw new Error(`invalid ${label}: method must be an uppercase HTTP method token`);
  }

  const host = raw['host'] as string;
  if (host !== host.toLowerCase() || /[\s/\\?#]/.test(host)) {
    throw new Error(`invalid ${label}: host must be a lowercase authority, without a scheme`);
  }

  // The wire string, not a normalization: no percent-decoding, no query
  // reordering, no trailing-slash equivalence. Only the two things that could
  // never have ridden an origin-form request line are refused.
  const path = raw['path'] as string;
  if (!path.startsWith('/')) {
    throw new Error(`invalid ${label}: path must begin with /`);
  }
  if (path.includes('#')) {
    throw new Error(`invalid ${label}: path must not carry a fragment`);
  }
  if (CTL_OR_SPACE.test(path)) {
    throw new Error(`invalid ${label}: path must not contain whitespace or control characters`);
  }

  // The bodyHash is compared as a STRING against the verifier's own re-encoding,
  // so a padded or otherwise non-canonical spelling of the right bytes must be
  // rejected here, not normalized. Re-encoding the decoded bytes and comparing is
  // the only check that catches non-zero trailing bits.
  const bodyHash = raw['bodyHash'] as string;
  if (!BASE64URL_32.test(bodyHash) || base64urlEncode(base64urlDecode(bodyHash)) !== bodyHash) {
    throw new Error(
      `invalid ${label}: bodyHash must be the canonical unpadded base64url of 32 bytes`,
    );
  }

  const iat = raw['iat'];
  if (typeof iat !== 'number' || !Number.isSafeInteger(iat) || iat <= 0) {
    throw new Error(`invalid ${label}: iat must be a positive integer`);
  }

  return shape.credentialed
    ? { method, host, path, bodyHash, credentialCID: raw['credentialCID'] as string, iat }
    : { method, host, path, bodyHash, iat };
};

const validateRequestProofPayload = (value: unknown): RequestProofPayload => {
  const parsed = validateProofPayload(value, REQUEST_PROOF_SHAPE);
  return {
    method: parsed.method,
    host: parsed.host,
    path: parsed.path,
    bodyHash: parsed.bodyHash,
    credentialCID: parsed.credentialCID as string,
    iat: parsed.iat,
  };
};

const validateIdentityProofPayload = (value: unknown): IdentityProofPayload => {
  const parsed = validateProofPayload(value, IDENTITY_PROOF_SHAPE);
  return {
    method: parsed.method,
    host: parsed.host,
    path: parsed.path,
    bodyHash: parsed.bodyHash,
    iat: parsed.iat,
  };
};

/**
 * Validate and normalize additive members into their canonical emission order:
 * lexicographic by name, after every canonical member. Returns `[]` for the
 * common (no extras) case, so the bytes are unchanged from the five/six-member
 * form when nothing additive is asked for.
 */
export const canonicalExtraMembers = (
  extra: ProofExtraMembers | undefined,
  label: string,
): [string, string][] => {
  if (!extra) return [];
  const entries: [string, string][] = [];
  for (const name of Object.keys(extra)) {
    if (!EXTRA_MEMBER_NAME.test(name)) {
      throw new Error(
        `invalid ${label}: additive member name ${JSON.stringify(name)} is not [A-Za-z0-9_.-]+`,
      );
    }
    if (CANONICAL_MEMBERS.has(name)) {
      throw new Error(`invalid ${label}: ${name} is a canonical member and cannot be added`);
    }
    const value = extra[name];
    if (typeof value !== 'string' || value === '') {
      throw new Error(`invalid ${label}: additive member ${name} must be a non-empty string`);
    }
    assertNoLoneSurrogate(value, name, label);
    entries.push([name, value]);
  }
  // Lexicographic by name — deterministic in BOTH languages, unlike insertion
  // order (which Go cannot reproduce from a map).
  entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return entries;
};

/**
 * THE BYTE CONTRACT, in ONE place for both artifacts. Serializes a validated
 * payload to the canonical bytes that ARE the JWS payload segment — a fixed key
 * order with no insignificant whitespace, and `iat` as a bare JSON integer. The
 * request proof's order is `method, host, path, bodyHash, credentialCID, iat`;
 * the identity proof's is the same with `credentialCID` elided, so the two forms
 * cannot drift apart on anything but that member. Additive members follow, in
 * lexicographic order.
 *
 * HTML ESCAPING IS OFF, by construction: `path` routinely carries `&` and admits
 * `<` and `>`, and `JSON.stringify` emits all three literally. The Go byte-twin
 * hand-rolls the same serialization precisely because `encoding/json` would emit
 * `&` / `<` / `>` instead and silently fork the signed bytes.
 */
const proofSigningInput = (
  parsed: ParsedProofPayload,
  shape: ProofShape,
  extra: [string, string][],
): Uint8Array => encoder.encode(JSON.stringify(proofPayloadObject(parsed, shape, extra)));

/**
 * The payload object in canonical member order. `JSON.stringify` preserves
 * insertion order for string keys, so building the object in order IS the byte
 * contract — the same construction `createJws` serializes, which is why the
 * emitted payload segment equals `apiIdentitySigningInput(payload)` exactly.
 */
const proofPayloadObject = (
  parsed: ParsedProofPayload,
  shape: ProofShape,
  extra: [string, string][],
): Record<string, string | number> => {
  const out: Record<string, string | number> = {
    method: parsed.method,
    host: parsed.host,
    path: parsed.path,
    bodyHash: parsed.bodyHash,
  };
  if (shape.credentialed) out['credentialCID'] = parsed.credentialCID as string;
  out['iat'] = parsed.iat;
  for (const [name, value] of extra) out[name] = value;
  return out;
};

/**
 * The request proof's canonical signing input — six members, in the fixed order
 * `method, host, path, bodyHash, credentialCID, iat`, plus any additive members
 * in lexicographic order.
 *
 * PURE and clientless: import it in a signing backend and in a verifier alike.
 */
export const apiRequestSigningInput = (
  payload: RequestProofPayload,
  extraMembers?: ProofExtraMembers,
): Uint8Array =>
  proofSigningInput(
    validateProofPayload(payload, REQUEST_PROOF_SHAPE),
    REQUEST_PROOF_SHAPE,
    canonicalExtraMembers(extraMembers, REQUEST_PROOF_SHAPE.label),
  );

/**
 * The identity proof's canonical signing input — five members, in the fixed
 * order `method, host, path, bodyHash, iat`: the request proof's bytes minus
 * `credentialCID`, from the same encoder, under the same member rules. Additive
 * members follow in lexicographic order.
 *
 * PURE and clientless: import it in a signing backend and in a verifier alike.
 */
export const apiIdentitySigningInput = (
  payload: IdentityProofPayload,
  extraMembers?: ProofExtraMembers,
): Uint8Array =>
  proofSigningInput(
    validateProofPayload(payload, IDENTITY_PROOF_SHAPE),
    IDENTITY_PROOF_SHAPE,
    canonicalExtraMembers(extraMembers, IDENTITY_PROOF_SHAPE.label),
  );

/**
 * The `bodyHash` member: canonical unpadded base64url of the SHA-256 of the
 * APPLICATION body octets — the bytes the sender handed its HTTP client, which a
 * verifier obtains after reversing transfer encoding and content encoding. Zero
 * octets hash to `EMPTY_BODY_SHA256`.
 */
export const sha256BodyHash = (body: Uint8Array): string => base64urlEncode(sha256(body));

/**
 * Parse an `Authorization: DFOS <token>` header, returning the bare token.
 *
 * The scheme is matched CASE-INSENSITIVELY per RFC 9110 §11.1 (`DFOS`, `dfos`,
 * `Dfos` are one scheme), separated from the token by one or more spaces, with
 * surrounding optional whitespace ignored. The token itself is case-sensitive
 * and is not further decoded here. Returns `null` for an absent, differently
 * schemed, or empty-token header — a `Bearer` header is NOT this family and
 * never was.
 */
export const parseDfosAuthorization = (header: string | undefined | null): string | null => {
  if (!header) return null;
  const trimmed = header.trim();
  const space = trimmed.search(/\s/);
  if (space < 0) return null;
  if (trimmed.slice(0, space).toLowerCase() !== 'dfos') return null;
  const token = trimmed.slice(space).trim();
  if (token === '' || /\s/.test(token)) return null;
  return token;
};

// -----------------------------------------------------------------------------
// produce
// -----------------------------------------------------------------------------

export interface SignApiRequestInput {
  /** The HTTP method, uppercase. */
  method: string;
  /** The API's lowercase authority — `host` on 443, `host:port` otherwise. */
  host: string;
  /** The exact origin-form request target this proof will ride. */
  path: string;
  /** Application body octets; omitted or empty hashes to `EMPTY_BODY_SHA256`. */
  body?: Uint8Array;
  /** CID of the leaf credential presented alongside this proof. */
  credentialCID: string;
  /**
   * The signing key's DID URL. Its DID portion MUST be the leaf credential's
   * `aud` — that equality IS the possession being proven.
   */
  kid: string;
  /** Raw Ed25519 signer over the JWS signing input. */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
  /** Issued-at override — unix seconds. Default `Math.floor(Date.now() / 1000)`. */
  iat?: number;
  /**
   * ADDITIVE members, appended after the canonical order in lexicographic name
   * order. `{ jti }` is the registered one — required by a deployment that gates
   * WRITES with this envelope (API-AUTH.md, Security Considerations).
   */
  extraMembers?: ProofExtraMembers;
}

/**
 * Sign one request. The producer half of the byte contract.
 *
 * `createJws` serializes the payload with `JSON.stringify`, so passing the
 * fixed-order object makes the emitted payload segment EXACTLY
 * `apiRequestSigningInput(payload, extraMembers)` — the equivalence is pinned by
 * a test rather than assumed, because it is the whole reason there is one byte
 * contract and not two.
 */
export const signApiRequest = async (
  input: SignApiRequestInput,
): Promise<{ proof: string; payload: RequestProofPayload }> => {
  const payload = validateRequestProofPayload({
    method: input.method,
    host: input.host,
    path: input.path,
    bodyHash: sha256BodyHash(input.body ?? EMPTY_BODY),
    credentialCID: input.credentialCID,
    iat: input.iat ?? Math.floor(Date.now() / 1000),
  });
  if (!input.kid.includes('#')) {
    throw new Error('invalid request proof: kid must be a DID URL');
  }
  const extra = canonicalExtraMembers(input.extraMembers, REQUEST_PROOF_SHAPE.label);

  const proof = await createJws({
    header: { alg: 'EdDSA', typ: REQUEST_PROOF_JWS_TYP, kid: input.kid },
    payload: proofPayloadObject(payload, REQUEST_PROOF_SHAPE, extra),
    sign: input.sign,
  });
  if (proof.length > MAX_REQUEST_PROOF_SIZE) {
    throw new Error(`request proof exceeds max size: ${proof.length} > ${MAX_REQUEST_PROOF_SIZE}`);
  }
  return { proof, payload };
};

export interface SignApiIdentityRequestInput {
  /** The HTTP method, uppercase. */
  method: string;
  /** The API's lowercase authority — `host` on 443, `host:port` otherwise. */
  host: string;
  /** The exact origin-form request target this proof will ride. */
  path: string;
  /** Application body octets; omitted or empty hashes to `EMPTY_BODY_SHA256`. */
  body?: Uint8Array;
  /**
   * The signing key's DID URL. Its DID portion IS THE PRINCIPAL — the identity
   * proof names no other party, and nothing is looked up from it.
   */
  kid: string;
  /** Raw Ed25519 signer over the JWS signing input. */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
  /** Issued-at override — unix seconds. Default `Math.floor(Date.now() / 1000)`. */
  iat?: number;
  /**
   * ADDITIVE members, appended after the canonical order in lexicographic name
   * order. `{ jti }` is the registered one, and a WRITE-SHAPED surface — relay
   * ingestion, blob upload — REQUIRES it (WEB-RELAY.md, Authentication).
   */
  extraMembers?: ProofExtraMembers;
}

/**
 * Sign one request as a BARE IDENTITY — `signApiRequest`'s input minus the
 * credential material, and its payload minus `credentialCID`. The producer half
 * of the identity proof's byte contract.
 *
 * The emitted payload segment is EXACTLY
 * `apiIdentitySigningInput(payload, extraMembers)`, the same
 * construction-by-fixed-order the request proof uses, and pinned by a test
 * rather than assumed.
 */
export const signApiIdentityRequest = async (
  input: SignApiIdentityRequestInput,
): Promise<{ proof: string; payload: IdentityProofPayload }> => {
  const payload = validateIdentityProofPayload({
    method: input.method,
    host: input.host,
    path: input.path,
    bodyHash: sha256BodyHash(input.body ?? EMPTY_BODY),
    iat: input.iat ?? Math.floor(Date.now() / 1000),
  });
  if (!input.kid.includes('#')) {
    throw new Error('invalid identity proof: kid must be a DID URL');
  }
  const extra = canonicalExtraMembers(input.extraMembers, IDENTITY_PROOF_SHAPE.label);

  const proof = await createJws({
    header: { alg: 'EdDSA', typ: IDENTITY_PROOF_JWS_TYP, kid: input.kid },
    payload: proofPayloadObject(payload, IDENTITY_PROOF_SHAPE, extra),
    sign: input.sign,
  });
  if (proof.length > MAX_REQUEST_PROOF_SIZE) {
    throw new Error(`identity proof exceeds max size: ${proof.length} > ${MAX_REQUEST_PROOF_SIZE}`);
  }
  return { proof, payload };
};

/**
 * The two headers a credential-gated request carries. The `Authorization` scheme
 * is the token `DFOS`, deliberately NOT `Bearer`.
 */
export const buildApiAuthHeaders = (input: {
  proof: string;
  credential: string;
}): { Authorization: string; 'X-Credential': string } => ({
  Authorization: `${DFOS_AUTH_SCHEME} ${input.proof}`,
  'X-Credential': input.credential,
});

/**
 * The ONE header an identity-proven request carries — the same `Authorization:
 * DFOS <jws>`.
 *
 * On an `api:<host>` surface an accompanying `X-Credential` is MALFORMED: the
 * two headers would assert two different claims at once. A relay content-plane
 * read is NOT that case — there the identity proof is the AuthN half and a DFOS
 * credential presentation is a separate authorization artifact (WEB-RELAY.md,
 * Authentication) — so that refusal belongs to the middleware of the surface
 * being served, never to this builder.
 */
export const buildApiIdentityHeaders = (input: { proof: string }): { Authorization: string } => ({
  Authorization: `${DFOS_AUTH_SCHEME} ${input.proof}`,
});

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

/**
 * The verdict class. Branch on `reason`, never on message text.
 *
 * - `invalid` — checked and failed.
 * - `unverifiable` — could not check (an unresolvable presenter, an unreachable
 *   revocation source). A transient resolution failure is the server's
 *   condition, not the caller's.
 * - `config` — the DEPLOYMENT is misconfigured (a `W + S` over the 300-second
 *   ceiling, or an empty required action). Not a judgment about the artifact.
 */
export type RequestProofFailureReason = 'invalid' | 'unverifiable' | 'config';

/**
 * The verification phase a failure arose in. Load-bearing for HTTP mapping: an
 * `invalid` proof-layer failure is a 401 (with a `WWW-Authenticate: DFOS`
 * challenge), an `invalid` credential-layer failure is a 403. `status` carries
 * the recommended code directly so middleware never has to re-derive it.
 */
export type RequestProofFailurePhase = 'proof' | 'credential' | 'config';

/** Branch on `reason`/`phase`/`status`, never on message text. */
export class ApiRequestVerifyError extends Error {
  readonly reason: RequestProofFailureReason;
  readonly phase: RequestProofFailurePhase;
  /** Recommended HTTP status: 401 proof-invalid, 403 credential-invalid, 503 unverifiable, 500 config. */
  readonly status: number;

  constructor(
    reason: RequestProofFailureReason,
    phase: RequestProofFailurePhase,
    status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiRequestVerifyError';
    this.reason = reason;
    this.phase = phase;
    this.status = status;
  }
}

/** invalid, proof phase → 401. */
export const invalidProof = (message: string) =>
  new ApiRequestVerifyError('invalid', 'proof', 401, message);
/** unverifiable, proof phase → 503. */
export const unverifiableProof = (message: string) =>
  new ApiRequestVerifyError('unverifiable', 'proof', 503, message);
/** the DEPLOYMENT is misconfigured → 500. Never a judgment about the artifact. */
export const misconfiguredProof = (message: string) =>
  new ApiRequestVerifyError('config', 'config', 500, message);

/**
 * A presenter's CURRENT identity state, as the proof phase needs it.
 *
 * `keys` is the union of every CURRENT key role — auth, assert, controller —
 * because API-AUTH's "key resolution is current-state" admits any of them. It is
 * the CALLER's job to build this from current state only: a resolver answering
 * from historical state would let a rotated-out key keep minting proofs, which
 * removes the only lever a compromised presenter has.
 */
export interface ProofPresenterState {
  /** Current-state deletion. A deleted presenter's proofs are INVALID (401). */
  isDeleted: boolean;
  /** Current keys, any role. */
  keys: readonly { id: string; publicKeyMultibase: string }[];
}

/**
 * Resolve a presenter DID to its CURRENT identity state.
 *
 * Return `null`, or throw, when the state could not be established — both map to
 * `unverifiable` (503), because "could not check" is the server's condition, not
 * a judgment about the caller. Returning a state with `isDeleted: true` is a
 * judgment, and maps to `invalid` (401).
 */
export type ResolveProofPresenter = (did: string) => Promise<ProofPresenterState | null>;

/**
 * What the PROOF PHASE reads — the subset of a verifier's inputs that
 * API-AUTH.md steps 1–7 touch.
 */
export interface ProofEnvelopeInput {
  /** The proof JWS — the `Authorization: DFOS <token>` token, scheme stripped. */
  proof: string;
  /**
   * THE VERIFIER'S OWN CONFIGURED AUTHORITY for the route being served — a value
   * the deployment holds, NEVER one read from the request. `Host`,
   * `X-Forwarded-Host`, and the request URL's authority are all attacker-supplied:
   * a verifier that compared the proof's `host` against a request header would
   * have no host binding at all. Include the port when it is not 443.
   */
  host: string;
  /** The received request's method. */
  method: string;
  /** The received origin-form request target — path plus query string, byte for byte. */
  path: string;
  /** The received application body octets, post-content-decoding. Omitted = no body. */
  body?: Uint8Array;
  /** Cap on the decoded body this verifier will hash. Default `MAX_BODY_BYTES`. */
  maxBodyBytes?: number;
  /** Acceptance window `W`, seconds. Default 60. `W + S` MUST NOT exceed 300. */
  windowSeconds?: number;
  /** Clock-skew allowance `S`, seconds. Default 60. `W + S` MUST NOT exceed 300. */
  skewSeconds?: number;
  /** Clock injection (unix ms). Default `Date.now()`. */
  now?: () => number;
}

/**
 * API-AUTH.md step 4's CONFIG half, hoisted so a caller can run it BEFORE any
 * request-dependent gate.
 *
 * ORDER IS LOAD-BEARING. A deployment whose freshness span is out of bounds must
 * never verify anything, and its misconfiguration must never be REPORTED as a
 * judgment about the request — a config verdict masked by a 401 for an oversized
 * token would hide the deployment bug behind the caller's mistake. Every entry
 * point calls this first.
 */
export const assertProofVerifierConfig = (input: {
  windowSeconds?: number;
  skewSeconds?: number;
  maxBodyBytes?: number;
}): { window: number; skew: number; maxBodyBytes: number } => {
  const window = input.windowSeconds ?? DEFAULT_PROOF_WINDOW_SECONDS;
  const skew = input.skewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;
  for (const [name, value] of [
    ['windowSeconds', window],
    ['skewSeconds', skew],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw misconfiguredProof(`${name} must be a non-negative integer`);
    }
  }
  if (window + skew > MAX_PROOF_FRESHNESS_SPAN_SECONDS) {
    throw misconfiguredProof(
      `proof freshness span W + S exceeds ${MAX_PROOF_FRESHNESS_SPAN_SECONDS} seconds: ` +
        `${window} + ${skew}`,
    );
  }
  const maxBodyBytes = input.maxBodyBytes ?? MAX_BODY_BYTES;
  if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 0) {
    throw misconfiguredProof('maxBodyBytes must be a non-negative integer');
  }
  return { window, skew, maxBodyBytes };
};

/** What a verified envelope hands back. */
export interface VerifiedProofEnvelope {
  /** The validated canonical members. */
  payload: ParsedProofPayload;
  /**
   * The DECODED payload object, unknown members included.
   *
   * ADDITIVE MEMBERS ARE READ FROM HERE, at the consuming layer, AFTER
   * verification — the signature already covers them, and the canonical member
   * set stays closed. `jti` is the case this exists for: the envelope verifier
   * ignores it per MUST-ignore-unknown, and a write-gating deployment reads it
   * off this object and applies its own replay discipline.
   */
  rawPayload: Record<string, unknown>;
  /** THE PRINCIPAL — the `kid`'s DID. */
  presenterDID: string;
  /** The full `kid` DID URL that signed, key fragment included. */
  kid: string;
  /** The integer unix seconds the freshness check used. */
  now: number;
}

/**
 * THE PROOF PHASE — API-AUTH.md steps 1–7, shared verbatim by both artifacts:
 * size cap, the Signature Verification Profile header gates with THIS shape's
 * `typ`, payload schema, freshness, request binding against the verifier's own
 * configured authority, current-state presenter resolution, signature.
 *
 * For the identity proof this IS the whole algorithm. For the request proof it is
 * the gate to steps 8–11: that work is unbounded and network-touching, and a
 * well-formed proof with a bad signature must not buy it.
 *
 * One implementation, so a check tightened for one artifact is tightened for
 * both — and so the `typ` gate is provably the only place they diverge.
 */
const verifyProofEnvelope = async (
  input: ProofEnvelopeInput,
  shape: ProofShape,
  resolvePresenter: ResolveProofPresenter,
): Promise<VerifiedProofEnvelope> => {
  // 4 (config half). Checked FIRST: a deployment whose window is out of bounds
  // must never verify anything, not merely fail some proofs.
  const { window, skew, maxBodyBytes } = assertProofVerifierConfig(input);

  // 1. Size — before any decode. A DoS guard at the header layer.
  if (input.proof.length > MAX_REQUEST_PROOF_SIZE) {
    throw invalidProof(
      `${shape.label} exceeds max size: ${input.proof.length} > ${MAX_REQUEST_PROOF_SIZE}`,
    );
  }

  // 2. Decode + Signature Verification Profile header gates.
  const decoded = decodeJwsUnsafe(input.proof);
  if (!decoded) throw invalidProof(`failed to decode ${shape.label} JWS`);
  const rawHeader = decoded.header as unknown;
  if (typeof rawHeader !== 'object' || rawHeader === null || Array.isArray(rawHeader)) {
    throw invalidProof(`${shape.label} protected header must be an object`);
  }
  assertJwsProfile(rawHeader as Record<string, unknown>, invalidProof);
  // THE TYP GATE, ABSOLUTE IN BOTH DIRECTIONS.
  if (decoded.header.typ !== shape.typ) {
    throw invalidProof(`invalid typ: expected ${shape.typ}, got ${decoded.header.typ}`);
  }
  const kid = decoded.header.kid;
  if (typeof kid !== 'string' || !kid.includes('#')) {
    throw invalidProof(`${shape.label} kid must be a DID URL`);
  }
  const presenterDID = kid.substring(0, kid.indexOf('#'));
  const presenterKeyId = kid.substring(kid.indexOf('#') + 1);

  // 3. Payload schema. Parsed from the ORIGINAL payload octets, not
  // decodeJwsUnsafe's lossy view — but NOT re-canonicalized: the presenter
  // self-signs and the signature covers the received bytes, so there is no
  // third-party byte substitution to defend against. The canonical rule binds
  // PRODUCERS (see specs/API-AUTH.md, Canonical Signing Input).
  const payloadSegment = input.proof.split('.')[1];
  if (payloadSegment === undefined) throw invalidProof(`failed to decode ${shape.label} payload`);
  let payload: ParsedProofPayload;
  let rawPayload: Record<string, unknown>;
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(
      base64urlDecode(payloadSegment),
    );
    const parsed = JSON.parse(source) as unknown;
    payload = validateProofPayload(parsed, shape);
    rawPayload = parsed as Record<string, unknown>;
  } catch (err) {
    throw invalidProof(err instanceof Error ? err.message : `invalid ${shape.label} payload`);
  }

  // 4. Freshness — integer Unix seconds on both sides, so the boundary does not
  // turn on sub-second precision. AGE and FORWARD SKEW are separate bounds:
  // a symmetric |now - iat| <= W would make a fully forward-dated proof
  // replayable for 2W, which is exactly what the W + S ceiling above prices.
  const now = Math.floor((input.now ? input.now() : Date.now()) / 1000);
  if (now - payload.iat > window) throw invalidProof(`${shape.label} is stale`);
  if (payload.iat - now > skew) {
    throw invalidProof(`${shape.label} iat is beyond the clock-skew allowance`);
  }

  // 5. Request binding — the non-body half first (ordering rule b), then the body
  // hash last and only up to the cap, so an over-cap body is refused (413) before
  // the SHA-256 rather than hashed to discover it does not match.
  if (payload.method !== input.method) throw invalidProof(`${shape.label} method mismatch`);
  if (payload.host !== input.host) throw invalidProof(`${shape.label} host mismatch`);
  if (payload.path !== input.path) throw invalidProof(`${shape.label} path mismatch`);
  const body = input.body ?? EMPTY_BODY;
  if (body.length > maxBodyBytes) {
    throw new ApiRequestVerifyError(
      'invalid',
      'proof',
      413,
      `request body exceeds max size: ${body.length} > ${maxBodyBytes}`,
    );
  }
  if (payload.bodyHash !== sha256BodyHash(body)) {
    throw invalidProof(`${shape.label} bodyHash mismatch`);
  }

  // 6. Resolve the presenter to its CURRENT identity state. Rotation is how a
  // presenter whose key is compromised stops that key minting proofs in its
  // name; "current keys" read from a stale cache would take that lever away.
  let state: ProofPresenterState | null;
  try {
    state = await resolvePresenter(presenterDID);
  } catch (err) {
    // A resolver that already classified its own failure (a client refusing a
    // stale cache, say) keeps its verdict verbatim; anything else is a resolution
    // failure, which is the server's condition, not the caller's.
    if (err instanceof ApiRequestVerifyError) throw err;
    throw unverifiableProof(
      `failed to resolve ${shape.label} presenter: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!state) {
    throw unverifiableProof(`failed to resolve ${shape.label} presenter: ${presenterDID}`);
  }
  if (state.isDeleted) throw invalidProof(`${shape.label} presenter identity is deleted`);

  const key = state.keys.find((candidate) => candidate.id === presenterKeyId);
  if (!key) throw invalidProof(`${shape.label} signing key is not a current key of the presenter`);

  // 7. Signature.
  try {
    verifyJws({ token: input.proof, publicKey: decodeMultikey(key.publicKeyMultibase).keyBytes });
  } catch (err) {
    throw invalidProof(err instanceof Error ? err.message : `invalid ${shape.label} signature`);
  }

  return { payload, rawPayload, presenterDID, kid, now };
};

/**
 * Verify an IDENTITY proof's envelope — for this artifact steps 1–7 ARE the whole
 * algorithm. Steps 8–11 do not exist: there is no credential to walk, so there is
 * no chain, no revocation lookup, and no attenuation coverage.
 *
 * Verdicts are two, not three: `invalid` → 401 and `unverifiable` → 503, plus
 * `config` → 500 for a deployment whose `W + S` is out of bounds. There is no 403
 * tier — nothing credential-shaped can fail.
 *
 * A request proof presented here is rejected at the header gate, and the reverse
 * holds for `verifyRequestProofEnvelope`.
 */
export const verifyIdentityProofEnvelope = (
  input: ProofEnvelopeInput,
  resolvePresenter: ResolveProofPresenter,
): Promise<VerifiedProofEnvelope> =>
  verifyProofEnvelope(input, IDENTITY_PROOF_SHAPE, resolvePresenter);

/**
 * Verify a REQUEST proof's envelope — API-AUTH.md steps 1–7 with the request
 * `typ`. The caller then performs steps 8–11 (the credential walk), for which a
 * verified proof signature is the gate.
 */
export const verifyRequestProofEnvelope = (
  input: ProofEnvelopeInput,
  resolvePresenter: ResolveProofPresenter,
): Promise<VerifiedProofEnvelope> =>
  verifyProofEnvelope(input, REQUEST_PROOF_SHAPE, resolvePresenter);
