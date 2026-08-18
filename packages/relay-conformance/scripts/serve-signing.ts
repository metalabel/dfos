/** Start a signing-enabled TypeScript reference relay for conformance. */
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);
const relay = await createRelay({ store: new MemoryRelayStore(), signing: true });
serve(relay.app, { port });
console.log(`signing-enabled TS relay on :${port} (did=${relay.did})`);
