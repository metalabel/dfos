/**
 * Start a local relay for conformance testing.
 *
 * Usage: pnpm --filter @metalabel/dfos-web-relay exec tsx <path>/serve-conformance.ts [port]
 *
 * Must be run via pnpm filter so the relay package's dependencies resolve.
 */
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);

const relay = await createRelay({
  store: new MemoryRelayStore(),
});

serve(relay.app, { port });
