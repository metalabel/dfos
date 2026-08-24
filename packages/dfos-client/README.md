# @metalabel/dfos-client

The high-level read client for the [DFOS protocol](https://protocol.dfos.com). The protocol library owns the crypto truth (CID re-derivation, signature verification, chain folding); this client owns the four things it deliberately refuses to do: **fetch, resolve, verify-orchestration, and cache** — over an untrusted set of relays. It holds no keys and never writes.

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

### `@metalabel/dfos-client/siwd`

```typescript
import {
  createSiwdLoginRequest,
  readSiwdCallback,
  siwdSigningInput,
  verifySiwd,
} from '@metalabel/dfos-client/siwd';
```

Sign In With DFOS. The three verbs above are the relying-party login kit, in the order a login uses them: `createSiwdLoginRequest` mints the challenge and builds the `/authorize` URL to redirect to, `readSiwdCallback` parses what comes back, and `verifySiwd` verifies it — mint → redirect, read → verify. The `expect` object `createSiwdLoginRequest` returns (nonce, domain, and the DID when the challenge is bound to one) is what `verifySiwd` checks against, so the relying party MUST persist it across the redirect: a verifier that takes its expectation from the callback has implemented the check and none of the protection. See [`examples/siwd-demo`](../../examples/siwd-demo) for the reference consumer.

`siwdSigningInput(challenge)` is the pure byte contract both the signer and the verifier share (see [SIWD.md](../../specs/SIWD.md)); `createSiwdChallenge` mints a challenge on its own for a caller building its own redirect; `verifySiwd` is a no-throw verifier that accepts only a current `authKeys` entry of a non-deleted identity.

## License

MIT
