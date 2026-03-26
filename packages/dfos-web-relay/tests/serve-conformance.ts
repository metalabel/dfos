/**
 * Start a local relay for conformance testing.
 *
 * Usage: npx tsx tests/serve-conformance.ts [port]
 */
import { createRelay } from '../src/relay';
import { serve } from '../src/serve';
import { MemoryRelayStore } from '../src/store';

const port = parseInt(process.argv[2] || '4444', 10);

const relay = await createRelay({
  store: new MemoryRelayStore(),
});

serve(relay, { port });
