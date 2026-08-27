/*

  @metalabel/dfos-client/api-auth

  API-AUTH — ONE ENVELOPE FAMILY WITH AN OPTIONAL CREDENTIAL.

  A REQUEST PROOF is a short-lived JWS, signed by the key of the party a DFOS
  credential was issued to, that binds ONE exact HTTP request (method, host,
  path, body) to that credential, right now. The credential says what its holder
  may do; the proof says the holder is the one doing it, and doing exactly this.

  An IDENTITY PROOF is the same envelope minus `credentialCID`: it binds the same
  exact request to a bare DID, proving only WHO IS ASKING. Authentication with no
  grant attached, for surfaces whose own policy decides what a proven identity may
  do. See specs/API-AUTH.md.

  WHERE THE BYTE CONTRACT LIVES. `apiRequestSigningInput` /
  `apiIdentitySigningInput`, the producer half, and the PROOF PHASE (API-AUTH
  steps 1–7) now live in `@metalabel/dfos-protocol/credentials` — because the
  reference relay consumes the identity proof too, and this package
  peer-depends on the relay, so a relay importing from here would close a
  dependency CYCLE. There is still exactly ONE canonical-bytes implementation per
  language; this module RE-EXPORTS it so every existing importer is unaffected.

  What stays here is what needs a `Client`: the resolver adapter (current-state
  identity resolution with the stale-cache refusal), the credential walk
  (API-AUTH steps 8–11), and the signing `fetch`.

*/

import {
  apiIdentitySigningInput,
  apiRequestSigningInput,
  ApiRequestVerifyError,
  assertProofVerifierConfig,
  buildApiAuthHeaders,
  buildApiIdentityHeaders,
  CredentialVerificationError,
  decodeDFOSCredentialUnsafe,
  DEFAULT_PROOF_SKEW_SECONDS,
  DEFAULT_PROOF_WINDOW_SECONDS,
  DFOS_AUTH_SCHEME,
  EMPTY_BODY_SHA256,
  IDENTITY_PROOF_JWS_TYP,
  matchesResource,
  MAX_BODY_BYTES,
  MAX_CREDENTIAL_SIZE,
  MAX_PROOF_FRESHNESS_SPAN_SECONDS,
  MAX_REQUEST_PROOF_SIZE,
  parseDfosAuthorization,
  REQUEST_PROOF_JWS_TYP,
  sha256BodyHash,
  signApiIdentityRequest,
  signApiRequest,
  verifyDelegationChain,
  verifyDFOSCredential,
  verifyIdentityProofEnvelope,
  verifyRequestProofEnvelope,
  type IdentityProofPayload,
  type ProofEnvelopeInput,
  type ProofExtraMembers,
  type ProofPresenterState,
  type RequestProofFailurePhase,
  type RequestProofFailureReason,
  type RequestProofPayload,
  type ResolveProofPresenter,
  type SignApiIdentityRequestInput,
  type SignApiRequestInput,
  type VerifiedDFOSCredential,
} from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { Client } from './types';

// -----------------------------------------------------------------------------
// the byte contract — re-exported from the protocol package (see header)
// -----------------------------------------------------------------------------

export {
  apiIdentitySigningInput,
  apiRequestSigningInput,
  ApiRequestVerifyError,
  assertProofVerifierConfig,
  buildApiAuthHeaders,
  buildApiIdentityHeaders,
  DEFAULT_PROOF_SKEW_SECONDS,
  DEFAULT_PROOF_WINDOW_SECONDS,
  DFOS_AUTH_SCHEME,
  EMPTY_BODY_SHA256,
  IDENTITY_PROOF_JWS_TYP,
  MAX_BODY_BYTES,
  MAX_PROOF_FRESHNESS_SPAN_SECONDS,
  MAX_REQUEST_PROOF_SIZE,
  parseDfosAuthorization,
  REQUEST_PROOF_JWS_TYP,
  sha256BodyHash,
  signApiIdentityRequest,
  signApiRequest,
  type IdentityProofPayload,
  type ProofExtraMembers,
  type RequestProofFailurePhase,
  type RequestProofFailureReason,
  type RequestProofPayload,
  type SignApiIdentityRequestInput,
  type SignApiRequestInput,
};

/** The v0 action registry's only token. */
export const DEFAULT_API_ACTION = 'read:profile';

/** Linear delegation depth ceiling — the protocol's own chain-walk bound. */
const MAX_DELEGATION_DEPTH = 16;

// -----------------------------------------------------------------------------
// the signing fetch
// -----------------------------------------------------------------------------

export interface CreateApiAuthFetchOptions {
  /**
   * The leaf credential JWS to present — the `X-Credential` value, and the
   * source of every proof's `credentialCID`. It embeds its chain in `prf`.
   */
  credential: string;
  /**
   * The signing key's DID URL. Its DID portion MUST be the credential's `aud` —
   * that equality IS the possession being proven.
   */
  kid: string;
  /** Raw Ed25519 signer over the JWS signing input. Never key material. */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
  /** The underlying transport. Default `globalThis.fetch`. */
  fetch?: typeof fetch;
}

/**
 * The `credentialCID` a proof must carry, read from the credential's OWN
 * protected header rather than passed alongside it — so the CID and the
 * credential cannot become two facts that drift (a reissued credential paired
 * with the previous CID is a 403 this shape simply cannot produce).
 *
 * The header is NOT re-derived here, deliberately. `verifyApiRequest` re-derives
 * it and refuses any credential whose header disagrees, so a divergent header is
 * refused either way: re-deriving would change which message the deployment
 * sees, never whether the request succeeds, and it would drag dag-cbor and the
 * credential schema into a producer path that today needs neither.
 *
 * A request proof deliberately carries no `cid` header (API-AUTH.md), so
 * requiring one here also catches a proof handed over in a credential's place.
 */
const credentialCIDFromHeader = (credential: string): string => {
  const decoded = decodeJwsUnsafe(credential);
  if (!decoded) throw new Error('invalid credential: failed to decode the credential JWS');
  const cid = decoded.header.cid;
  if (typeof cid !== 'string' || cid === '') {
    throw new Error('invalid credential: the credential JWS carries no cid header');
  }
  return cid;
};

/**
 * The exact hostnames a plaintext request may name. `url.hostname` returns the
 * IPv6 literal still bracketed, so `[::1]` is the form to match. An EXACT set,
 * never a suffix test: `localhost.evil.example` is an ordinary internet host.
 */
const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * A signing `fetch`. Hand it to any API client with a fetch seam and every
 * request that client composes goes out credential-gated:
 *
 * ```ts
 * createDfosApi({ fetch: createApiAuthFetch({ credential, kid, sign }) })
 * ```
 *
 * It signs EXACTLY the `Request` it receives — the method, the origin-form
 * target, and the body octets already composed — rather than a description of
 * one. That is what keeps the binding honest: the bytes the proof covers are the
 * bytes that go on the wire.
 *
 * `signApiRequest` stays exported for the backends that must NOT proxy. A
 * signing backend fronting a browser MUST authorize the coordinates it is about
 * to sign against its own session (API-AUTH.md, Security Considerations) — it
 * describes the one request it is willing to make rather than receiving one, so
 * there is no `Request` for this adapter to cover.
 *
 * Two things are deliberately absent. There is no credential-provider callback:
 * a caller whose credential rotates builds a new fetch, which is one line and
 * has no lifecycle to get wrong. And there is no host allowlist: the caller
 * composing the URL is already the party choosing the host, so an allowlist here
 * would guard a decision it does not make.
 *
 * TWO REFUSALS, both because the adapter is the last place that can see them.
 * It will not sign a plaintext request to a real host (`api:` surfaces are HTTPS
 * surfaces — the proof and the credential would go out in the clear, and the
 * proof replays over HTTPS for its whole freshness window), and it will not
 * follow redirects.
 *
 * BUFFERING IS INHERENT. The byte contract hashes the complete body before
 * signing, so a request body is buffered in full before anything is sent. This
 * adapter is for size-bounded requests; an unbounded or live stream cannot be
 * proof-signed at all, in any implementation.
 */
export const createApiAuthFetch = (options: CreateApiAuthFetchOptions): typeof fetch => {
  // Read once, at construction: a malformed credential is the caller's bug, and
  // it should surface where the credential was passed rather than as a refusal
  // on some later request.
  const credentialCID = credentialCIDFromHeader(options.credential);
  const send: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));

  return async (input, init) => {
    const request =
      init === undefined && input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    // Refused BEFORE the signature, so a misrouted call costs nothing and mints
    // nothing: a proof that was never signed cannot be captured off the wire.
    if (url.protocol !== 'https:' && !LOOPBACK_HOSTNAMES.has(url.hostname)) {
      throw new Error(
        `refusing to sign a ${url.protocol}// request to ${url.host}: api: surfaces are HTTPS ` +
          'surfaces, and a proof sent in the clear replays for its whole freshness window ' +
          '(plaintext is allowed only to localhost, 127.0.0.1, and [::1])',
      );
    }

    const { proof } = await signApiRequest({
      method: request.method,
      // `host`, never `hostname`: the authority carries the port when there is
      // one, and the verifier compares it byte for byte.
      host: url.host,
      // Path plus query, byte for byte — no normalization, because the verifier
      // compares against the request target it actually received. Dropping
      // `.search` is the classic silent 401.
      path: url.pathname + url.search,
      // Hash the CLONE and forward the original: buffering the request's own
      // stream would leave nothing to send. Buffering at all is inherent — the
      // proof covers the WHOLE body, so there is nothing to sign until the last
      // octet is in hand.
      body: new Uint8Array(await request.clone().arrayBuffer()),
      credentialCID,
      kid: options.kid,
      sign: options.sign,
    });

    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(
      buildApiAuthHeaders({ proof, credential: options.credential }),
    )) {
      headers.set(name, value);
    }
    // `manual`, so a 3xx comes back to the caller as-is. Following it would
    // re-issue the request at coordinates the proof does not cover — and carry
    // `X-Credential` to whatever authority the `Location` names.
    return send(new Request(request, { headers, redirect: 'manual' }));
  };
};

// -----------------------------------------------------------------------------
// verify
// -----------------------------------------------------------------------------

// invalid/unverifiable at the CREDENTIAL layer. The proof layer's factories live
// with the envelope in the protocol package; these are the two verdicts only a
// credential walk can produce.
const invalidProof = (message: string) =>
  new ApiRequestVerifyError('invalid', 'proof', 401, message);
const invalidCredential = (message: string) =>
  new ApiRequestVerifyError('invalid', 'credential', 403, message);
const unverifiableProof = (message: string) =>
  new ApiRequestVerifyError('unverifiable', 'proof', 503, message);
const unverifiableCredential = (message: string) =>
  new ApiRequestVerifyError('unverifiable', 'credential', 503, message);
const misconfigured = (message: string) =>
  new ApiRequestVerifyError('config', 'config', 500, message);

/**
 * The `Client`-backed presenter resolver — the one thing the proof phase cannot
 * supply itself, because "current identity state" is a network judgment here and
 * a local store lookup on a relay.
 *
 * It FAILS CLOSED on a stale tip. Key resolution is CURRENT-STATE: rotation is
 * how a presenter whose key is compromised stops that key minting proofs in its
 * name, and "current keys" read from a cache whose tip could not be verified
 * would take that lever away. `allowStale` is the deployment's explicit
 * acceptance of that risk.
 */
const clientPresenterResolver =
  (client: Client, allowStale: boolean): ResolveProofPresenter =>
  async (did: string): Promise<ProofPresenterState> => {
    const resolved = await client.identity(did);
    const axes = resolved.trust.unverifiable ?? [];
    if (!allowStale && (axes.includes('tip') || resolved.provenance.fromCache)) {
      throw unverifiableProof(
        'presenter identity resolution is stale (tip unverified) — refusing to authenticate ' +
          'against a cached identity state; pass allowStale: true to accept the risk',
      );
    }
    const state = resolved.value;
    // Any CURRENT key role may sign a proof (API-AUTH.md, "Key resolution is
    // current-state") — auth, assert, or controller. This is wider than SIWD,
    // which is authKeys-only by its own spec.
    return {
      isDeleted: state.isDeleted,
      keys: [...state.authKeys, ...state.assertKeys, ...state.controllerKeys],
    };
  };

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
  /**
   * Cap on the decoded body this verifier will hash, in bytes. Default
   * `MAX_BODY_BYTES`. A body over the cap is refused BEFORE the SHA-256 (a
   * proof-layer `413`), so a well-formed proof with a bad signature cannot force
   * an unbounded hash. NOTE: the spec's "abort decode at the cap" is a MIDDLEWARE
   * obligation — by the time the body reaches this helper it is already a buffered
   * `Uint8Array`, so this is the second, defensive cap; the middleware must still
   * bound decoding upstream (a decompression bomb inflates before the kit sees it).
   */
  maxBodyBytes?: number;

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
  // < MAX_DELEGATION_DEPTH: a 16-credential chain roots on the 16th (depth 15);
  // a 17th credential exhausts the loop and rejects, the SAME boundary the
  // protocol's verified walk enforces (so discovery and the real walk agree
  // rather than discovery admitting one the walk would then reject).
  for (let depth = 0; depth < MAX_DELEGATION_DEPTH; depth++) {
    const decoded = decodeDFOSCredentialUnsafe(token);
    if (!decoded) throw invalidCredential('failed to decode presented credential');
    if (decoded.payload.prf.length === 0) return decoded.payload.iss;
    if (decoded.payload.prf.length > 1) {
      throw invalidCredential('delegation chain: multi-parent credentials are not supported');
    }
    token = decoded.payload.prf[0]!;
  }
  throw invalidCredential('delegation chain too deep (max 16 credentials)');
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
 * Throws `ApiRequestVerifyError`; branch on `reason`/`phase`/`status`, never on
 * message text. `status` is the recommended HTTP code (401 proof-invalid, 403
 * credential-invalid, 503 unverifiable, 500 config).
 *
 * REVOCATION AND RESOLUTION AVAILABILITY — read before deploying. This helper
 * rejects a credential it KNOWS is revoked (`isRevoked` true at any chain level).
 * It does NOT, with the default client, fail closed when the revocation source is
 * unreachable: the stock `createRevocationChecker` is fail-open by design
 * ("no revocation found" and "could not reach any relay" both return false), the
 * system-wide v1 stance that "non-revocation is never provable." Likewise a
 * credential-issuer that is unresolvable because relays are down surfaces from the
 * protocol verifier as a `CredentialVerificationError` and is reported here as
 * `invalid` (403), not `unverifiable` (503) — the underlying callback cannot
 * distinguish "genuinely absent" from "transiently unreachable." The PRESENTER
 * side is availability-aware (a resolution failure or unverified/stale tip is
 * `unverifiable`, failing closed unless `allowStale`); the CREDENTIAL side inherits
 * the v1 primitives' limitation. A deployment that needs fail-closed-on-outage for
 * the credential/revocation phase MUST inject an availability-aware `isRevoked`
 * (one that THROWS when it reaches zero sources — the throw is surfaced here as
 * `unverifiable`) via the client config. Tightening the default is a client-level
 * change to the shared revocation/resolution contract (it governs SIWD and relay
 * verification too), tracked outside this kit.
 */
export const verifyApiRequest = async (
  client: Client,
  input: VerifyApiRequestInput,
): Promise<VerifiedRequestProof> => {
  // ALL CONFIG FIRST, BEFORE ANY REQUEST-DEPENDENT GATE. A misconfigured
  // deployment must be reported AS a misconfiguration, and never masked by a
  // judgment about the artifact: an out-of-bounds W + S paired with an oversized
  // credential once answered 401, which told the operator the caller was at
  // fault when the deployment was. The envelope re-checks the freshness half
  // (it is entered directly for identity proofs); running it here too is cheap
  // and makes the ORDER the property, not a coincidence of call sites.
  assertProofVerifierConfig(input);
  // The route's required action is deployment config too. An action canonicalizing
  // to the empty set is a subset of every grant's action set, so a misconfigured
  // route would authorize any api:<host> holder; a broken route must fail fast
  // and deterministically (500), never return 401/403.
  const action = input.action ?? DEFAULT_API_ACTION;
  if (action.split(',').every((token) => token.trim() === '')) {
    throw misconfigured('required action must name a non-empty token');
  }

  // 1. Size — the CREDENTIAL half, before any decode. (The proof half is the
  // envelope's, immediately below.)
  if (input.credential.length > MAX_CREDENTIAL_SIZE) {
    throw invalidProof(
      `credential exceeds max size: ${input.credential.length} > ${MAX_CREDENTIAL_SIZE}`,
    );
  }

  // 1–7. The proof phase, shared byte for byte with the identity proof. A valid
  // proof signature is THE GATE to every step below: the credential work is
  // unbounded and network-touching, and a well-formed proof with a bad signature
  // must not buy it.
  const { payload, presenterDID, now } = await verifyRequestProofEnvelope(
    input as ProofEnvelopeInput,
    clientPresenterResolver(client, input.allowStale === true),
  );
  // Present by construction: the request-proof shape requires it in step 3.
  const proofCredentialCID = payload.credentialCID as string;

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
    if (err instanceof CredentialVerificationError) throw invalidCredential(err.message);
    // Anything else is a resolution or transport failure — the server's
    // condition, not a judgment about the credential.
    throw unverifiableCredential(
      `credential verification could not complete: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // 9. Credential binding, and NO PUBLIC AUDIENCE ANYWHERE.
  if (leaf.credentialCID !== proofCredentialCID) {
    throw invalidCredential('request proof credentialCID does not match the presented credential');
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
      throw invalidCredential(
        'a credential in the presented chain carries a public audience (aud: "*")',
      );
    }
  }
  if (leaf.aud !== presenterDID) {
    throw invalidCredential('credential audience does not match the request proof signing key');
  }

  // 10. Subject selection — the root `iss`, which the chain walk above proved.
  // There is nothing external to compare it against: `read:profile` serves the
  // profile of exactly the DID that rooted the credential.
  //
  // 11. Attenuation coverage — exact byte equality of `api:<host>` against the
  // verifier's OWN configured authority, and the leaf's canonical action set
  // must contain the route's required token. No wildcard form exists for `api:`,
  // and `read:*` is a literal token that matches no real route.
  // `action` was validated as non-empty in the config block above.
  if (!(await matchesResource(leaf.att, `api:${input.host}`, action))) {
    throw invalidCredential(`credential does not cover ${action} on api:${input.host}`);
  }

  return {
    subjectDID: rootDID,
    host: input.host,
    action,
    iat: payload.iat,
    credentialCID: leaf.credentialCID,
  };
};

export interface VerifyApiIdentityRequestInput {
  /** The identity-proof JWS — the `Authorization: DFOS <token>` token, scheme stripped. */
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
  /**
   * Cap on the decoded body this verifier will hash, in bytes. Default
   * `MAX_BODY_BYTES`. A body over the cap is refused BEFORE the SHA-256 (a
   * proof-layer `413`). As in `verifyApiRequest`, aborting DECODE at the cap
   * remains a middleware obligation upstream — a decompression bomb inflates
   * before this helper sees a buffered `Uint8Array`.
   */
  maxBodyBytes?: number;

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

export interface VerifiedIdentityProof {
  /**
   * THE PRINCIPAL — the `kid`'s DID, which is who the request is from. What that
   * DID may do is the resource's local policy (quotas, reputation, self-access
   * rules, admission tiers); this kit deliberately says nothing about it.
   * Authentication travels on the wire; authorization stays home.
   */
  presenterDID: string;
  /** The full `kid` DID URL that signed, key fragment included. */
  kid: string;
  /** The authority the binding names — the verifier's own configured value. */
  host: string;
  /** The proof's issued-at, unix seconds. */
  iat: number;
  /**
   * The DECODED payload, unknown members included — where a caller reads an
   * ADDITIVE member (`jti`) the envelope verifier ignored. The signature already
   * covers it; the canonical member set stays closed.
   */
  rawPayload: Record<string, unknown>;
}

/**
 * Verify an identity-proven request — API-AUTH.md's PROOF PHASE (steps 1–7) with
 * the identity `typ`, and nothing more. Steps 8–11 do not exist for this
 * artifact: there is no credential to walk, so there is no chain, no revocation
 * lookup, and no attenuation coverage.
 *
 * The verdicts are therefore two, not three: `invalid` → 401, `unverifiable` →
 * 503 (plus `config` → 500 for a deployment whose `W + S` is out of bounds).
 * NOTHING credential-shaped can fail, so there is no 403 tier.
 *
 * A REQUEST PROOF PRESENTED HERE IS REJECTED at the header gate, and an identity
 * proof presented to `verifyApiRequest` is rejected at the same gate. The typ
 * scoping is what keeps a grant-bearing claim from ever being spent as a bare
 * one, or the reverse.
 *
 * The header-layer rule this helper cannot see: on an `api:<host>` surface a
 * request carrying `X-Credential` alongside an identity proof is MALFORMED (401)
 * — the headers assert two different claims at once and a verifier MUST NOT pick
 * one. That refusal belongs to the middleware, which is the only layer holding
 * the header bag. (A relay content-plane read is a different surface: there the
 * identity proof is the AuthN half and a DFOS credential presentation is the
 * separate authorization artifact.)
 *
 * Throws `ApiRequestVerifyError`; branch on `reason`/`phase`/`status`, never on
 * message text. `phase` is always `'proof'` or `'config'` here.
 */
export const verifyApiIdentityRequest = async (
  client: Client,
  input: VerifyApiIdentityRequestInput,
): Promise<VerifiedIdentityProof> => {
  const { payload, rawPayload, presenterDID, kid } = await verifyIdentityProofEnvelope(
    input as ProofEnvelopeInput,
    clientPresenterResolver(client, input.allowStale === true),
  );
  return { presenterDID, kid, host: input.host, iat: payload.iat, rawPayload };
};
