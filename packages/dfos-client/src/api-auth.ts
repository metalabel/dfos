/*

  @metalabel/dfos-client/api-auth

  API-AUTH — the request proof. A short-lived JWS, signed by the key of the party
  a DFOS credential was issued to, that binds ONE exact HTTP request (method,
  host, path, body) to that credential, right now. The credential says what its
  holder may do; the proof says the holder is the one doing it, and doing exactly
  this. See specs/API-AUTH.md.

  As with SIWD, the load-bearing piece is NOT the fat verifier: it is
  `apiRequestSigningInput`, the PURE byte contract both halves share. It lives in
  exactly ONE place per language (this file, and `ApiRequestSigningInput` in
  dfos-protocol-go), so a TS signer and a Go signer emit identical proofs from
  identical inputs.

  `verifyApiRequest` is the other half, and it lives HERE rather than in an API
  host's middleware so that middleware is a thin adapter over the kit rather than
  a second, drifting implementation of the eleven-step algorithm.

*/

import { decodeMultikey } from '@metalabel/dfos-protocol/chain';
import {
  CredentialVerificationError,
  decodeDFOSCredentialUnsafe,
  matchesResource,
  MAX_CREDENTIAL_SIZE,
  verifyDelegationChain,
  verifyDFOSCredential,
  type VerifiedDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import {
  assertJwsProfile,
  base64urlDecode,
  base64urlEncode,
  createJws,
  decodeJwsUnsafe,
  sha256,
  verifyJws,
} from '@metalabel/dfos-protocol/crypto';
import type { Client } from './types';

// -----------------------------------------------------------------------------
// the byte contract
// -----------------------------------------------------------------------------

/**
 * The normative JWS header `typ` for a request proof (API-AUTH.md). Signers MUST
 * set it; `verifyApiRequest` rejects anything else — it is also what lets
 * typ-routing dispatchers tell a proof apart from credentials and chain ops.
 */
export const REQUEST_PROOF_JWS_TYP = 'did:dfos:request-proof';

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

/** The v0 action registry's only token. */
export const DEFAULT_API_ACTION = 'read:profile';

/** Linear delegation depth ceiling — the protocol's own chain-walk bound. */
const MAX_DELEGATION_DEPTH = 16;

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

const encoder = new TextEncoder();
const EMPTY_BODY = new Uint8Array(0);

// An HTTP method token per RFC 9110 `tchar`, with the lowercase letters removed:
// the member is normatively uppercase, and "get" MUST NOT verify against "GET".
const UPPERCASE_METHOD = /^[A-Z0-9!#$%&'*+.^_`|~-]+$/;
// A lone surrogate has no convergent serialization: `JSON.stringify` round-trips
// it to a `\uXXXX` escape that the Go byte-twin's UTF-8 strings cannot hold, so
// it is refused on both sides rather than signable on one. (Mirrors siwd.ts.)
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
// ASCII space, the C0 controls, and DEL — none of which can ride an origin-form
// request line, so a `path` carrying one was never a real request target.
const CTL_OR_SPACE = /[\u0000-\u0020\u007f]/;
// 32 digest bytes are exactly 43 canonical unpadded base64url characters.
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;

const assertNoLoneSurrogate = (value: string, field: string): void => {
  if (LONE_SURROGATE.test(value)) {
    throw new Error(`invalid request proof: ${field} must be well-formed Unicode`);
  }
};

/**
 * Validate a request-proof payload against API-AUTH.md's step-3 schema. Unknown
 * members are IGNORED (the protocol's MUST-ignore-unknown rule) — the canonical
 * rebuild below drops them rather than refusing them, so a future additive
 * member never makes today's verifier reject a well-formed proof.
 */
const validateRequestProofPayload = (value: unknown): RequestProofPayload => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('invalid request proof: expected a JSON object');
  }
  const raw = value as Record<string, unknown>;

  for (const field of ['method', 'host', 'path', 'bodyHash', 'credentialCID'] as const) {
    if (typeof raw[field] !== 'string' || raw[field] === '') {
      throw new Error(`invalid request proof: ${field} must be a non-empty string`);
    }
    assertNoLoneSurrogate(raw[field] as string, field);
  }

  const method = raw['method'] as string;
  if (!UPPERCASE_METHOD.test(method)) {
    throw new Error('invalid request proof: method must be an uppercase HTTP method token');
  }

  const host = raw['host'] as string;
  if (host !== host.toLowerCase() || /[\s/\\?#]/.test(host)) {
    throw new Error('invalid request proof: host must be a lowercase authority, without a scheme');
  }

  // The wire string, not a normalization: no percent-decoding, no query
  // reordering, no trailing-slash equivalence. Only the two things that could
  // never have ridden an origin-form request line are refused.
  const path = raw['path'] as string;
  if (!path.startsWith('/')) {
    throw new Error('invalid request proof: path must begin with /');
  }
  if (path.includes('#')) {
    throw new Error('invalid request proof: path must not carry a fragment');
  }
  if (CTL_OR_SPACE.test(path)) {
    throw new Error(
      'invalid request proof: path must not contain whitespace or control characters',
    );
  }

  // The bodyHash is compared as a STRING against the verifier's own re-encoding,
  // so a padded or otherwise non-canonical spelling of the right bytes must be
  // rejected here, not normalized. Re-encoding the decoded bytes and comparing is
  // the only check that catches non-zero trailing bits.
  const bodyHash = raw['bodyHash'] as string;
  if (!BASE64URL_32.test(bodyHash) || base64urlEncode(base64urlDecode(bodyHash)) !== bodyHash) {
    throw new Error(
      'invalid request proof: bodyHash must be the canonical unpadded base64url of 32 bytes',
    );
  }

  const iat = raw['iat'];
  if (typeof iat !== 'number' || !Number.isSafeInteger(iat) || iat <= 0) {
    throw new Error('invalid request proof: iat must be a positive integer');
  }

  return {
    method,
    host,
    path,
    bodyHash,
    credentialCID: raw['credentialCID'] as string,
    iat,
  };
};

/**
 * THE BYTE CONTRACT. Serializes a payload to the canonical bytes that ARE the
 * JWS payload segment — a fixed key order (method, host, path, bodyHash,
 * credentialCID, iat) with no insignificant whitespace, and `iat` as a bare JSON
 * integer.
 *
 * HTML ESCAPING IS OFF, by construction: `path` routinely carries `&` and admits
 * `<` and `>`, and `JSON.stringify` emits all three literally. The Go byte-twin
 * hand-rolls the same serialization (`ApiRequestSigningInput`) precisely because
 * `encoding/json` would emit `\u0026` / `\u003c` / `\u003e` instead and silently fork
 * the signed bytes.
 *
 * PURE and clientless: import it in a signing backend and in a verifier alike.
 */
export const apiRequestSigningInput = (payload: RequestProofPayload): Uint8Array => {
  const parsed = validateRequestProofPayload(payload);
  return encoder.encode(
    JSON.stringify({
      method: parsed.method,
      host: parsed.host,
      path: parsed.path,
      bodyHash: parsed.bodyHash,
      credentialCID: parsed.credentialCID,
      iat: parsed.iat,
    }),
  );
};

/**
 * The `bodyHash` member: canonical unpadded base64url of the SHA-256 of the
 * APPLICATION body octets — the bytes the sender handed its HTTP client, which a
 * verifier obtains after reversing transfer encoding and content encoding. Zero
 * octets hash to `EMPTY_BODY_SHA256`.
 */
export const sha256BodyHash = (body: Uint8Array): string => base64urlEncode(sha256(body));

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
}

/**
 * Sign one request. The producer half of the byte contract.
 *
 * `createJws` serializes the payload with `JSON.stringify`, so passing the
 * fixed-order object makes the emitted payload segment EXACTLY
 * `apiRequestSigningInput(payload)` — the equivalence is pinned by a test rather
 * than assumed, because it is the whole reason there is one byte contract and
 * not two.
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

  const proof = await createJws({
    header: { alg: 'EdDSA', typ: REQUEST_PROOF_JWS_TYP, kid: input.kid },
    payload: {
      method: payload.method,
      host: payload.host,
      path: payload.path,
      bodyHash: payload.bodyHash,
      credentialCID: payload.credentialCID,
      iat: payload.iat,
    },
    sign: input.sign,
  });
  if (proof.length > MAX_REQUEST_PROOF_SIZE) {
    throw new Error(`request proof exceeds max size: ${proof.length} > ${MAX_REQUEST_PROOF_SIZE}`);
  }
  return { proof, payload };
};

/**
 * The two headers a credential-gated request carries. The `Authorization` scheme
 * is the token `DFOS`, deliberately NOT `Bearer`: nothing carried here is a
 * bearer token, and naming it one invites bearer handling (logging, caching,
 * forwarding) that this artifact exists to make useless.
 */
export const buildApiAuthHeaders = (input: {
  proof: string;
  credential: string;
}): { Authorization: string; 'X-Credential': string } => ({
  Authorization: `DFOS ${input.proof}`,
  'X-Credential': input.credential,
});

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

/**
 * The two consumer-visible verdict classes, plus the one thing that is neither.
 *
 * - `invalid` — checked and failed. Maps to 401 for a proof-layer failure and
 *   403 for a credential-layer one.
 * - `unverifiable` — could not check (an unresolvable presenter, an unreachable
 *   revocation source). Maps to 503 regardless of the phase it arose in: a
 *   transient resolution failure is the server's condition, not the caller's.
 * - `config` — the DEPLOYMENT is misconfigured (a `W + S` over the 300-second
 *   ceiling). Not a judgment about the artifact at all, and it must not be
 *   reported as one: this is a 500.
 */
export type RequestProofFailureReason = 'invalid' | 'unverifiable' | 'config';

/** Branch on `reason`, never on message text. */
export class ApiRequestVerifyError extends Error {
  readonly reason: RequestProofFailureReason;

  constructor(reason: RequestProofFailureReason, message: string) {
    super(message);
    this.name = 'ApiRequestVerifyError';
    this.reason = reason;
  }
}

const invalid = (message: string) => new ApiRequestVerifyError('invalid', message);
const unverifiable = (message: string) => new ApiRequestVerifyError('unverifiable', message);
const misconfigured = (message: string) => new ApiRequestVerifyError('config', message);

export interface VerifyApiRequestInput {
  /** The request-proof JWS — the `Authorization: DFOS <token>` token, scheme stripped. */
  proof: string;
  /** The leaf credential JWS — the `X-Credential` value. It embeds its chain in `prf`. */
  credential: string;

  /**
   * THE VERIFIER'S OWN CONFIGURED AUTHORITY for the route being served — a value
   * the deployment holds, NEVER one read from the request. `Host`,
   * `X-Forwarded-Host`, and the request URL's authority are all attacker-supplied:
   * a verifier that compared the proof's `host` against a request header would
   * have no host binding at all. Include the port when it is not 443.
   *
   * It is also the id half of the `api:<host>` resource string this verifier
   * requires, so the request binding and the grant name the same origin.
   */
  host: string;
  /** The received request's method. */
  method: string;
  /** The received origin-form request target — path plus query string, byte for byte. */
  path: string;
  /** The received application body octets, post-content-decoding. Omitted = no body. */
  body?: Uint8Array;

  /** The action token this route requires. Default `read:profile`. */
  action?: string;

  /** Acceptance window `W`, seconds. Default 60. `W + S` MUST NOT exceed 300. */
  windowSeconds?: number;
  /** Clock-skew allowance `S`, seconds. Default 60. `W + S` MUST NOT exceed 300. */
  skewSeconds?: number;

  /**
   * Accept a presenter resolution whose tip could not be verified (cache-only or
   * empty-delta-against-cache). Default FALSE: key resolution is CURRENT-STATE,
   * and a rotated-out key must not keep minting proofs against a stale cache.
   */
  allowStale?: boolean;
  /** Clock injection (unix ms). Default `Date.now()`. */
  now?: () => number;
}

export interface VerifiedRequestProof {
  /** The chain's root `iss` — the DID whose data this request serves. */
  subjectDID: string;
  /** The authority the grant and the binding both name. */
  host: string;
  /** The action token the leaf's attenuation was found to cover. */
  action: string;
  /** The proof's issued-at, unix seconds. */
  iat: number;
  /** The leaf credential's CID, re-derived and equal to the proof's member. */
  credentialCID: string;
}

/**
 * Walk the presented `prf` chain UNVERIFIED to learn where it roots.
 *
 * API-AUTH.md step 10: the root `iss` is the DID whose data the request serves,
 * and it is deliberately NOT checked against an externally-known resource owner —
 * for the v0 action registry there is none, and the credential is what selects
 * the subject. The protocol's chain verifier takes an EXPECTED root, so the
 * expectation is discovered here and then PROVEN by the real walk: every
 * signature, delegation gap, expiry, and attenuation check still runs, and the
 * root comparison is the tautology the spec asks for rather than a check skipped.
 */
const discoverChainRoot = (leafToken: string): string => {
  let token = leafToken;
  for (let depth = 0; depth <= MAX_DELEGATION_DEPTH; depth++) {
    const decoded = decodeDFOSCredentialUnsafe(token);
    if (!decoded) throw invalid('failed to decode presented credential');
    if (decoded.payload.prf.length === 0) return decoded.payload.iss;
    if (decoded.payload.prf.length > 1) {
      throw invalid('delegation chain: multi-parent credentials are not supported');
    }
    token = decoded.payload.prf[0]!;
  }
  throw invalid('delegation chain too deep (max 16 credentials)');
};

/**
 * Verify a credential-gated request — API-AUTH.md's eleven steps, in an order
 * that honors both load-bearing ordering rules: the proof signature gates every
 * credential-chain step, and body hashing runs after the cheaper binding checks.
 *
 * `client` supplies the resolver seam (current-state identity resolution plus the
 * revocation checker) exactly as `verifySiwd` does. Everything the verifier
 * compares against — host, method, path, body, action — is passed in BY THE
 * DEPLOYMENT: this helper never reads a request object, because the one thing a
 * host binding must not be sourced from is the request.
 *
 * Throws `ApiRequestVerifyError`; branch on `reason`.
 */
export const verifyApiRequest = async (
  client: Client,
  input: VerifyApiRequestInput,
): Promise<VerifiedRequestProof> => {
  // 4 (config half). Checked FIRST: a deployment whose window is out of bounds
  // must never verify anything, not merely fail some proofs.
  const window = input.windowSeconds ?? DEFAULT_PROOF_WINDOW_SECONDS;
  const skew = input.skewSeconds ?? DEFAULT_PROOF_SKEW_SECONDS;
  for (const [name, value] of [
    ['windowSeconds', window],
    ['skewSeconds', skew],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw misconfigured(`${name} must be a non-negative integer`);
    }
  }
  if (window + skew > MAX_PROOF_FRESHNESS_SPAN_SECONDS) {
    throw misconfigured(
      `request proof freshness span W + S exceeds ${MAX_PROOF_FRESHNESS_SPAN_SECONDS} seconds: ` +
        `${window} + ${skew}`,
    );
  }

  // 1. Size — both tokens, before any decode. A DoS guard at the header layer.
  if (input.proof.length > MAX_REQUEST_PROOF_SIZE) {
    throw invalid(
      `request proof exceeds max size: ${input.proof.length} > ${MAX_REQUEST_PROOF_SIZE}`,
    );
  }
  if (input.credential.length > MAX_CREDENTIAL_SIZE) {
    throw invalid(
      `credential exceeds max size: ${input.credential.length} > ${MAX_CREDENTIAL_SIZE}`,
    );
  }

  // 2. Decode + Signature Verification Profile header gates.
  const decoded = decodeJwsUnsafe(input.proof);
  if (!decoded) throw invalid('failed to decode request proof JWS');
  const rawHeader = decoded.header as unknown;
  if (typeof rawHeader !== 'object' || rawHeader === null || Array.isArray(rawHeader)) {
    throw invalid('request proof protected header must be an object');
  }
  assertJwsProfile(rawHeader as Record<string, unknown>, invalid);
  if (decoded.header.typ !== REQUEST_PROOF_JWS_TYP) {
    throw invalid(`invalid typ: expected ${REQUEST_PROOF_JWS_TYP}, got ${decoded.header.typ}`);
  }
  const kid = decoded.header.kid;
  if (typeof kid !== 'string' || !kid.includes('#')) {
    throw invalid('request proof kid must be a DID URL');
  }
  const presenterDID = kid.substring(0, kid.indexOf('#'));
  const presenterKeyId = kid.substring(kid.indexOf('#') + 1);

  // 3. Payload schema. Parsed from the ORIGINAL payload octets, not
  // decodeJwsUnsafe's lossy view — but NOT re-canonicalized: the presenter
  // self-signs and the signature covers the received bytes, so there is no
  // third-party byte substitution to defend against. The canonical rule binds
  // PRODUCERS (see specs/API-AUTH.md, Canonical Signing Input).
  const payloadSegment = input.proof.split('.')[1];
  if (payloadSegment === undefined) throw invalid('failed to decode request proof payload');
  let payload: RequestProofPayload;
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(
      base64urlDecode(payloadSegment),
    );
    payload = validateRequestProofPayload(JSON.parse(source));
  } catch (err) {
    throw invalid(err instanceof Error ? err.message : 'invalid request proof payload');
  }

  // 4. Freshness — integer Unix seconds on both sides, so the boundary does not
  // turn on sub-second precision. AGE and FORWARD SKEW are separate bounds:
  // a symmetric |now - iat| <= W would make a fully forward-dated proof
  // replayable for 2W, which is exactly what the W + S ceiling above prices.
  const now = Math.floor((input.now ? input.now() : Date.now()) / 1000);
  if (now - payload.iat > window) throw invalid('request proof is stale');
  if (payload.iat - now > skew) {
    throw invalid('request proof iat is beyond the clock-skew allowance');
  }

  // 5. Request binding — the non-body half first (ordering rule b).
  if (payload.method !== input.method) throw invalid('request proof method mismatch');
  if (payload.host !== input.host) throw invalid('request proof host mismatch');
  if (payload.path !== input.path) throw invalid('request proof path mismatch');
  if (payload.bodyHash !== sha256BodyHash(input.body ?? EMPTY_BODY)) {
    throw invalid('request proof bodyHash mismatch');
  }

  // 6. Resolve the presenter to its CURRENT identity state, failing CLOSED when
  // the tip could not be verified. Rotation is how a presenter whose key is
  // compromised stops that key minting proofs in its name; "current keys" read
  // from a stale cache would take that lever away.
  let resolved: Awaited<ReturnType<Client['identity']>>;
  try {
    resolved = await client.identity(presenterDID);
  } catch (err) {
    throw unverifiable(
      `failed to resolve request proof presenter: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const axes = resolved.trust.unverifiable ?? [];
  if (!input.allowStale && (axes.includes('tip') || resolved.provenance.fromCache)) {
    throw unverifiable(
      'presenter identity resolution is stale (tip unverified) — refusing to authenticate ' +
        'against a cached identity state; pass allowStale: true to accept the risk',
    );
  }
  const state = resolved.value;
  if (state.isDeleted) throw invalid('request proof presenter identity is deleted');

  // Any CURRENT key role may sign a proof (API-AUTH.md, "Key resolution is
  // current-state") — auth, assert, or controller. This is wider than SIWD,
  // which is authKeys-only by its own spec.
  const key = [...state.authKeys, ...state.assertKeys, ...state.controllerKeys].find(
    (candidate) => candidate.id === presenterKeyId,
  );
  if (!key) throw invalid('request proof signing key is not a current key of the presenter');

  // 7. Signature. THE GATE to every step below: the credential work is unbounded
  // and network-touching, and a well-formed proof with a bad signature must not
  // buy it.
  try {
    verifyJws({ token: input.proof, publicKey: decodeMultikey(key.publicKeyMultibase).keyBytes });
  } catch (err) {
    throw invalid(err instanceof Error ? err.message : 'invalid request proof signature');
  }

  // 8. Credential chain — verified IN FULL by the protocol's own verifier
  // (signatures, schema, CID integrity, linear delegation, depth, audience
  // linkage, monotonic attenuation), with expiry on the wall clock (a read-path,
  // at-read decision) and revocation checked at EVERY level.
  const { isRevoked, resolveIdentity } = client.callbacks();
  const rootDID = discoverChainRoot(input.credential);
  let leaf: VerifiedDFOSCredential;
  let chain: VerifiedDFOSCredential[];
  try {
    leaf = await verifyDFOSCredential(input.credential, { resolveIdentity, now });
    // verifyDelegationChain checks PARENTS only, so the LEAF's revocation is an
    // explicit check here — without it "revocation is the user's lever" would be
    // false for the single-hop credential this surface actually issues.
    if (await isRevoked(leaf.iss, leaf.credentialCID)) {
      throw new CredentialVerificationError('credential is revoked');
    }
    const verifiedChain = await verifyDelegationChain(leaf, {
      resolveIdentity,
      rootDID,
      now,
      isRevoked,
    });
    chain = verifiedChain.chain;
  } catch (err) {
    if (err instanceof ApiRequestVerifyError) throw err;
    if (err instanceof CredentialVerificationError) throw invalid(err.message);
    // Anything else is a resolution or transport failure — the server's
    // condition, not a judgment about the credential.
    throw unverifiable(
      `credential verification could not complete: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // 9. Credential binding, and NO PUBLIC AUDIENCE ANYWHERE.
  if (leaf.credentialCID !== payload.credentialCID) {
    throw invalid('request proof credentialCID does not match the presented credential');
  }
  // The public-audience scan runs BEFORE the audience-equality check so that a
  // public LEAF is reported as what it is rather than as an ordinary mismatch.
  // The leaf case is the naive one; THIS walk closes the bypass. A public PARENT
  // satisfies audience linkage for any child issuer, so an attacker self-issues a
  // leaf audienced to their own key, presents the public parent as its `prf`, and
  // passes steps 6–8 with a key they own. One public hop anywhere un-proves the
  // possession this whole surface is built on.
  for (const hop of chain) {
    if (hop.aud === '*') {
      throw invalid('a credential in the presented chain carries a public audience (aud: "*")');
    }
  }
  if (leaf.aud !== presenterDID) {
    throw invalid('credential audience does not match the request proof signing key');
  }

  // 10. Subject selection — the root `iss`, which the chain walk above proved.
  // There is nothing external to compare it against: `read:profile` serves the
  // profile of exactly the DID that rooted the credential.
  //
  // 11. Attenuation coverage — exact byte equality of `api:<host>` against the
  // verifier's OWN configured authority, and the leaf's canonical action set
  // must contain the route's required token. No wildcard form exists for `api:`,
  // and `read:*` is a literal token that matches no real route.
  const action = input.action ?? DEFAULT_API_ACTION;
  if (!(await matchesResource(leaf.att, `api:${input.host}`, action))) {
    throw invalid(`credential does not cover ${action} on api:${input.host}`);
  }

  return {
    subjectDID: rootDID,
    host: input.host,
    action,
    iat: payload.iat,
    credentialCID: leaf.credentialCID,
  };
};
