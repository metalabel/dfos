/**
 * Boot a local TS relay for conformance testing.
 * Usage: npx tsx tests/conformance-server.ts
 */
import { createRelay } from '../src/relay';
import { serve } from '../src/serve';
import { MemoryRelayStore } from '../src/store';

const PORT = 4555;

const store = new MemoryRelayStore();
const relay = await createRelay({ store });

console.log(`TS relay running on http://localhost:${PORT}`);
console.log(`  DID: ${relay.did}`);

serve(relay.app, { port: PORT });
