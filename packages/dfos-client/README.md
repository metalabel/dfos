# @metalabel/dfos-client

The high-level read client for the [DFOS protocol](https://protocol.dfos.com). The protocol library owns the crypto truth (CID re-derivation, signature verification, chain folding); this client owns the four things it deliberately refuses to do: **fetch, resolve, verify-orchestration, and cache** — over an untrusted set of relays. It holds no keys and never writes.

If verification logic appears in this package, that is the bug: every proof comes from `@metalabel/dfos-protocol`.

## Install

```bash
npm install @metalabel/dfos-client @metalabel/dfos-protocol @metalabel/dfos-web-relay
```

`@metalabel/dfos-protocol` and `@metalabel/dfos-web-relay` are peer dependencies — one source of truth for the crypto kernel and the relay transport, no double-ship.

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

Trust degrades honestly: `revocation` when non-revocation cannot be proven, `tip` when an answer came from cache without a live relay confirming the head. Nothing is ever claimed as proven that was not.

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

`memoryStore()` (the isomorphic default) caches the **log** and verifies forward from the trusted prefix, so a key rotation costs one incremental op and the cache is never stale-wrong. `indexedDbStore()` is the browser-only durable adapter — the only heavy dependency, quarantined behind this subpath.

### `@metalabel/dfos-client/siwd`

```typescript
import { createSiwdChallenge, siwdSigningInput, verifySiwd } from '@metalabel/dfos-client/siwd';
```

Sign In With DFOS. `siwdSigningInput(challenge)` is the pure byte contract both the signer and the verifier share (see [SIWD.md](../../specs/SIWD.md)); `verifySiwd` is a no-throw verifier that accepts only a current `authKeys` entry of a non-deleted identity.

## License

MIT
