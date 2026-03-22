# @metalabel/dfos-web-relay

Portable HTTP relay for the [DFOS protocol](https://protocol.dfos.com). Receives, verifies, stores, and serves identity chains, content chains, beacons, countersignatures, and content blobs.

See [RELAY.md](./RELAY.md) for the full protocol specification.

## Install

```bash
npm install @metalabel/dfos-web-relay @metalabel/dfos-protocol
```

## Usage

```typescript
import { createRelay, MemoryRelayStore } from '@metalabel/dfos-web-relay';

const relay = createRelay({
  relayDID: 'did:dfos:myrelay00000000000000',
  store: new MemoryRelayStore(),
});

// Mount on any Hono-compatible runtime
export default relay;
```

## License

MIT
