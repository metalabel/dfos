/**
 * Start a TS relay whose ingestion admission is PROOF-REQUIRED: an anonymous
 * `POST /proof/v1/operations` is refused 403 and only a submission carrying an
 * identity proof is admitted.
 *
 * It also serves a SECOND relay on `port + 1` over the SAME store, with the
 * default open ingestion. That is the seeding door: a submitter's identity chain
 * has to be on the relay before its proofs can resolve, and on a proof-required
 * relay it cannot put itself there. The conformance runner points
 * PROOF_REQUIRED_SEED_URL at the open twin and PROOF_REQUIRED_RELAY_URL at the
 * gated one — the same store, two admission postures, which is exactly how a
 * deployment fronts an internal write path and a public one.
 *
 * Usage: pnpm --filter @metalabel/dfos-web-relay exec tsx <path>/serve-proof-required.ts [port]
 *
 * Must be run via pnpm filter so the relay package's dependencies resolve.
 */
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);
const seedPort = port + 1;

const store = new MemoryRelayStore();

// The relay's OWN configured authority — the host binding every identity proof
// is checked against. Configuration, never read from the request, so each door
// declares the host callers reach IT at.
const gated = await createRelay({
  store,
  authority: `localhost:${port}`,
  ingestion: 'proof-required',
});
const open = await createRelay({ store, authority: `localhost:${seedPort}` });

serve(gated.app, { port });
serve(open.app, { port: seedPort });
console.log(`proof-required TS relay on :${port} (seed door on :${seedPort}, did=${gated.did})`);
