# @metalabel/dfos-client

The client-side kit for participating in the [DFOS protocol](https://protocol.dfos.com) — **resolve, verify, prove**. The protocol library owns the crypto truth (CID re-derivation, signature verification, chain folding); this client owns the four things it deliberately refuses to do: **fetch, resolve, verify-orchestration, and cache** — over an untrusted set of relays — plus the two proof surfaces that ride on top of them, [SIWD](#metalabeldfos-clientsiwd) and [API-AUTH](#metalabeldfos-clientapi-auth).

**It holds no keys.** Signing is always a `sign` callback the caller supplies: this kit composes the exact bytes that must be signed and hands them over, and key material never crosses into it.

If verification logic appears in this package, that is the bug: every proof comes from `@metalabel/dfos-protocol`.

## Install

```bash
npm install @metalabel/dfos-client @metalabel/dfos-protocol @metalabel/dfos-web-relay
```

`@metalabel/dfos-protocol` and `@metalabel/dfos-web-relay` are peer dependencies — one source of truth for the crypto kernel and the relay transport, no double-ship. The client imports only the relay package's lightweight `./peer-client` subpath (fetch + paging + route constants), never the relay server graph.

## The surface

```typescript
import { createClient } from '@metalabel/dfos-client';

const client = createClient({ relays: ['https://relay.example'] });

// The product: bound protocol-lib callbacks — spread straight into any verifier.
const { resolveKey, resolveIdentity, isRevoked } = client.callbacks();

// Display verbs → Resolved<T>. Trust is DATA, not exceptions.
const id = await client.identity('did:dfos:…');
const content = await client.content('…'); // contentId
const cred = await client.credential('<jws>');
const doc = await client.document('…'); // contentId → current document blob

// Paste-a-string dispatcher (did / contentId / credential JWS).
const anything = await client.resolve(userInput);

// No-throw "is this legit" one-liner.
const verdict = await client.verify('<jws>'); // VerifyResult<unknown>
```

Every resolution returns a `Resolved<T>`:

```typescript
interface Resolved<T> {
  value: T; // the protocol lib's proven type, untouched
  trust: { ok: boolean; unverifiable?: ('revocation' | 'tip')[] };
  provenance: { answeredBy; responses; agreed; fromCache };
}
```

Trust degrades honestly: `revocation` when non-revocation cannot be proven, `tip` whenever an answer's freshness rests on the cache — either the cache alone (relays unreachable) or a fully drained relay log that exactly matches the cached log. **Tip freshness is never proven in v1**: a relay's complete answer can verify the known history but cannot prove that no newer operation exists, so the client refuses to launder that claim into proof (relay head-proofs / `tipProven` are v2). Nothing is ever claimed as proven that was not.

### Quorum

```typescript
createClient({ relays: [...], quorum: 2 }); // require 2 relays to return the same log (by digest)
```

`quorum: 1` (default) is first-wins with failover. `provenance.agreed` reports whether the threshold was met.

### The free floor

```typescript
import { resolvers } from '@metalabel/dfos-client';

const { resolveKey } = resolvers(['https://relay.example']); // zero object graph, one-off verify
```

## Subpaths

### `@metalabel/dfos-client/store`

```typescript
import { indexedDbStore, memoryStore } from '@metalabel/dfos-client/store';
```

`memoryStore()` (the isomorphic default) caches the **log**. Chain reads fully drain from zero, require the fetched JWS tokens to match the trusted cached prefix, and verify forward only the suffix, so a key rotation costs one verification op and the cache is never stale-wrong. `indexedDbStore()` is the browser-only durable adapter — the only heavy dependency, quarantined behind this subpath.

### `@metalabel/dfos-client/api-auth`

API Authentication request proofs. A proof is a short-lived JWS, signed by the key a DFOS credential was issued to, that binds one exact HTTP request — method, host, path, body — to that credential. The credential says what its holder may do; the proof says the holder is the one doing it, and doing exactly this. See the [API-AUTH specification](https://protocol.dfos.com/api-auth).

**Spending a credential: a signing `fetch`.** Hand it to any API client with a fetch seam, and every request that client composes goes out credential-gated.

```typescript
import { createDfosApi } from '@metalabel/dfos-api';
import { createApiAuthFetch } from '@metalabel/dfos-client/api-auth';

const api = createDfosApi({ fetch: createApiAuthFetch({ credential, kid, sign }) });

const { data } = await api.GET('/profile');
```

Three inputs, and they are the irreducible ones: the credential JWS to present, the DID URL of the key it was issued to, and a `sign` callback over bytes. The proof's `credentialCID` is read from the credential's own header, so the two can never drift apart. Pass `fetch` to supply the underlying transport (default `globalThis.fetch`).

It signs **exactly the `Request` it receives** — the method, the origin-form target, and the body octets already composed — rather than a description of one. That is what keeps the binding honest: the bytes the proof covers are the bytes that go on the wire.

Three consequences worth knowing before you wire it up:

- **It refuses to sign a plaintext request** to anything but loopback (`localhost`, `127.0.0.1`, `[::1]`). `api:` surfaces are HTTPS surfaces, and a proof sent in the clear replays for its whole freshness window.
- **It does not follow redirects** (`redirect: 'manual'`): a 3xx comes back to you as-is, because following it would re-issue the request at coordinates the proof does not cover and carry `X-Credential` to whatever authority the `Location` names.
- **It buffers the request body before sending.** The proof covers the whole body, so there is nothing to sign until the last octet is in hand — size-bounded requests only. An unbounded or live stream cannot be proof-signed, in any implementation.

**A backend that must not proxy uses the decomposed form.** A signing backend fronting a browser must authorize the coordinates it is about to sign against its own session, not sign whatever `{method, path, body}` the browser hands it — a backend that signs blindly is an oracle for every credential it holds ([Security Considerations](https://protocol.dfos.com/api-auth#security-considerations)). Such a backend describes the one request it is willing to make, so there is no `Request` for the adapter above to cover:

```typescript
import { buildApiAuthHeaders, signApiRequest } from '@metalabel/dfos-client/api-auth';

const { proof } = await signApiRequest({
  method: 'GET',
  host: 'api.example',
  path: '/profile',
  credentialCID,
  kid,
  sign,
});
const headers = buildApiAuthHeaders({ proof, credential });
```

**Verifying** is the other half, and it lives here so that an API host's middleware is a thin adapter over the kit rather than a second implementation of the spec's eleven steps:

```typescript
import { verifyApiRequest } from '@metalabel/dfos-client/api-auth';

await verifyApiRequest(client, {
  proof,
  credential,
  method: 'GET',
  host: 'api.example', // the verifier's OWN configured authority, never a request header
  path: '/profile',
});
```

It throws `ApiRequestVerifyError`, carrying `reason` (`invalid` / `unverifiable` / `config`), `phase`, and the recommended `status` — branch on those, never on message text.

`apiRequestSigningInput(payload)` is the pure byte contract both halves share, and the one place per language the canonical bytes are built.

### `@metalabel/dfos-client/siwd`

The end-to-end integration recipe (mint an app identity, serve the app description, verify the callback) is at <https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup>.

```typescript
import {
  createSiwdLoginRequest,
  readSiwdCallback,
  siwdSigningInput,
  verifySiwd,
} from '@metalabel/dfos-client/siwd';
```

Sign In With DFOS. The three verbs above are the relying-party login kit, in the order a login uses them: `createSiwdLoginRequest` mints the challenge and builds the `/authorize` URL to redirect to, `readSiwdCallback` parses what comes back, and `verifySiwd` verifies it — mint → redirect, read → verify. The `expect` object `createSiwdLoginRequest` returns (nonce, domain, and the DID when the challenge is bound to one) is what `verifySiwd` checks against, so the relying party MUST persist it across the redirect: a verifier that takes its expectation from the callback has implemented the check and none of the protection. See [`examples/siwd-demo`](../../examples/siwd-demo) for the reference consumer.

The `nonce`/`consumeNonce` pair on the expectation (supply exactly one) is the spec's [two replay disciplines](../../specs/SIWD.md#replay-prevention), one field each:

**`expect.nonce` — flow-bound login.** For a backend granting only a browser session (`scope=identity`), source the expected nonce from state you bound to that browser at mint time — a server-side session, or the nonce sealed under your own key in an `httpOnly` cookie — and compare:

```typescript
// mint: cookie = `${nonce}.${hmacSha256(secret, nonce)}`, httpOnly, Max-Age ≤ your window
// verify: unseal the cookie back to `nonce` (full-length tag, constant-time compare), then
await verifySiwd(client, jws, { domain, nonce });
```

The seal (or the session) is what makes this a defense at all: a _bare_ cookie value is presenter-supplied, and an attacker replaying a captured JWS can read the nonce out of the artifact and send it as the cookie. Never compare against anything the presenter could have authored.

**`consumeNonce` — spend the nonce.** Required the moment success grants anything beyond a session with the presenting browser (a credential-returning scope, a portable token, a profile-B mailbox flow):

```typescript
await verifySiwd(client, jws, {
  domain,
  consumeNonce: async (nonce) => (await store.getdel(nonce)) !== null,
});
```

`consumeNonce` returns true iff **this** verifier minted the nonce and it was unspent — membership in verifier-minted state is what satisfies the spec's rule that the verifier MUST have minted the nonce it checks, and deleting it in the same operation is what makes it single-use. The atomicity is the caller's: a get-then-delete lets two concurrent replays both win, where a Redis `GETDEL` or a `DELETE … RETURNING` does not. Under either discipline the nonce check runs at most once, and only after every other check has passed, so an invalid presentation can never burn a nonce the user is still holding.

`createSiwdLoginRequest` throws rather than returning an error on the two things that are RP misconfiguration: an `authorizeUrl` or `redirectUri` that is not an absolute URL, and any scope other than `identity` over a loopback redirect that names no client identity.

**Loopback redirects** — `http://localhost`, `http://127.0.0.1`, or `http://[::1]`, on any port — come in two shapes. The **anonymous** one is unchanged: no `client_did`, `scope=identity` only, and the consent screen shows the local delivery target and nothing else. The **key-proven** one is the [loopback credential tier](../../specs/SIWD.md#loopback-clients): the request carries a `client_did`, an ask proof over its own challenge bytes, and — unless the DID is already resident on the host — the client's identity chain. That is what lets local software receive a credential. It cannot prove where it came from, but it can prove it controls the keys, and the host's consent screen says exactly that. Credentials minted this way come back in the URL **fragment** and carry a hard expiry ceiling the host enforces; 14 days is the spec's recommendation.

The fragment is what keeps the credential off every server, and it is also why a CLI needs one extra step: a browser does not send the fragment to your loopback listener either, so the request line your local server sees carries the query and nothing else. Answer it with a small page whose script reads `location.href` and posts the whole URL back to your server, then feed _that_ to `readSiwdCallback`. A browser relying party just passes `location.href`.

```typescript
import {
  createSiwdLoopbackLoginRequest,
  mintSiwdClientIdentity,
  restoreSiwdClientIdentity,
} from '@metalabel/dfos-client/siwd';

// The one place this kit generates a key. Persist `privateKey` + `chain` and
// restore them next run: a client that re-mints is a NEW did, so it re-consents
// every time and orphans the credentials the last run earned.
const app = saved
  ? await restoreSiwdClientIdentity(saved) // { privateKey, chain }
  : await mintSiwdClientIdentity();

const request = await createSiwdLoopbackLoginRequest({
  authorizeUrl: 'https://app.example.com/authorize',
  redirectUri: 'http://127.0.0.1:8976/callback',
  scope: 'read:profile',
  client: app, // did + kid + signer, and the chain to carry
});
// open request.url, hold request.expect.nonce in memory, and read back the FULL
// callback URL (see above — location.search alone would miss the credential).
const result = readSiwdCallback(callbackUrl);
if (result.kind === 'success') {
  // Consumed verification, store of size one: a credential-returning scope
  // requires it, and one outstanding nonce in memory IS the store. `client` is
  // the resolver from the setup section, not the identity above.
  let outstanding: string | undefined = request.expect.nonce;
  const session = await verifySiwd(client, result.jws, {
    domain: request.expect.domain,
    consumeNonce: (nonce) => {
      if (outstanding === undefined || nonce !== outstanding) return false;
      outstanding = undefined;
      return true;
    },
  });
  if (session.ok) {
    // only now is result.credential a credential you earned — store it, and
    // send a per-request proof signed by app.signer when you spend it
  }
}
```

`siwdSigningInput(challenge)` is the pure byte contract both the signer and the verifier share (see [SIWD.md](../../specs/SIWD.md)); `createSiwdChallenge` mints a challenge on its own for a caller building its own redirect; `verifySiwd` is a no-throw verifier that accepts only a current `authKeys` entry of a non-deleted identity.

## License

MIT
