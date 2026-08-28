/**
 * Boot the TS relay for the dual-relay parity harness (WP-7), pinned to the
 * SAME relay identity as the Go twin so neither relay's own bootstrap identity
 * leaks into /log or /.well-known.
 *
 * Reads the parity fixture (relayDid + relayProfileJws) and starts an HTTP
 * server. Passing `identity` to createRelay SKIPS the JIT bootstrap — no random
 * identity is ingested. The relay's own genesis + profile are replayed as
 * ordinary ops by the parity test, so the relay DID's log entries are
 * byte-identical across both twins.
 *
 * Usage: pnpm --filter @metalabel/dfos-web-relay exec tsx parity-serve.ts <port> <fixture-path>
 */
import { readFileSync } from 'node:fs';
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);
const fixturePath = process.argv[3];
if (!fixturePath) {
  console.error('usage: parity-serve.ts <port> <fixture-path>');
  process.exit(1);
}

const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  relayDid: string;
  relayProfileJws: string;
};

const relay = await createRelay({
  store: new MemoryRelayStore(),
  // The relay's OWN configured authority — the host binding every identity
  // proof is checked against. Configuration, never read from the request.
  authority: `localhost:${port}`,
  identity: {
    did: fixture.relayDid,
    profileArtifactJws: fixture.relayProfileJws,
  },
  // Serve + advertise the OpenAPI document, matching the Go twin (which serves
  // its embedded copy unconditionally) — the parity test byte-compares the
  // canonicalized well-known bodies, so both twins must advertise "/openapi.json".
  openapi: {
    document: JSON.parse(
      readFileSync(new URL('../../dfos-web-relay/openapi.json', import.meta.url), 'utf8'),
    ) as unknown,
  },
});

serve(relay.app, { port });
