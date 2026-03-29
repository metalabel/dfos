/**
 * Boot a local TS relay peered with a live Go relay, sync, and compare state.
 * Usage: npx tsx tests/peer-sync-test.ts [peer-url]
 */
import { createHttpPeerClient } from '../src/peer-client';
import { createRelay } from '../src/relay';
import { serve } from '../src/serve';
import { MemoryRelayStore } from '../src/store';

const PEER_URL = process.argv[2] || 'https://relay.atx.lark717.xyz';
const PORT = 4455;

const store = new MemoryRelayStore();
const peerClient = createHttpPeerClient();

console.log('Creating local TS relay...');
const relay = await createRelay({
  store,
  peers: [{ url: PEER_URL, gossip: false, readThrough: true, sync: true }],
  peerClient,
});

console.log(`  DID: ${relay.did}`);
console.log(`  Peer: ${PEER_URL}`);

// Sync
console.log('\nSyncing from peer...');
const start = Date.now();
await relay.syncFromPeers();
console.log(`  Done in ${Date.now() - start}ms`);

// Count ops
let total = 0;
let cursor: string | undefined;
while (true) {
  const url = cursor ? `/log?after=${cursor}&limit=1000` : '/log?limit=1000';
  const res = await relay.app.request(url);
  const data = (await res.json()) as { entries: { cid: string }[]; cursor: string | null };
  total += data.entries.length;
  if (!data.cursor) break;
  cursor = data.cursor;
}
console.log(`  Operations synced: ${total}`);

const unseq = await store.countUnsequenced();
console.log(`  Unsequenced: ${unseq}`);

console.log(`\nListening on http://localhost:${PORT}`);
serve(relay.app, { port: PORT });
