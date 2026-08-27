/**
 * Boot a local TS relay for conformance testing.
 * Usage: npx tsx tests/conformance-server.ts
 */
import { createRelay } from '../src/relay';
import { serve } from '../src/serve';
import { MemoryRelayStore } from '../src/store';

const PORT = 4555;

const store = new MemoryRelayStore();
// The relay's OWN configured authority — the host binding every identity proof
// is checked against. It is configuration, never read from the request.
const relay = await createRelay({ store, authority: `localhost:${PORT}` });

console.log(`TS relay running on http://localhost:${PORT}`);
console.log(`  DID: ${relay.did}`);

serve(relay.app, { port: PORT });
