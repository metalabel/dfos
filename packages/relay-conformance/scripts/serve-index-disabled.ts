/**
 * Start a local TS relay with the optional /index/v0 query family disabled.
 * All adjacent relay capabilities retain their defaults.
 *
 * Usage: pnpm --filter @metalabel/dfos-web-relay exec tsx <path>/serve-index-disabled.ts [port]
 */
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);

const relay = await createRelay({
  store: new MemoryRelayStore(),
  // The relay's OWN configured authority — the host binding every identity
  // proof is checked against. Configuration, never read from the request.
  authority: `localhost:${port}`,
  index: false,
});

serve(relay.app, { port });
