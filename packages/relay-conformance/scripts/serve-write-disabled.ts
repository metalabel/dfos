/**
 * Start a local WRITE-DISABLED (lite / pull-only) TS relay for read-only
 * conformance testing.
 *
 * It seeds one user identity chain OUT-OF-BAND — via ingestOperations directly
 * against the store, NOT over the POST write path (which is 501 here) — then
 * serves with write:false. It prints `SEEDED_DID=<did>` so the conformance
 * runner can point TestWriteDisabledSeededIdentity at a real served chain. The
 * relay also bootstraps its own identity in-process, so even without the seed
 * the read plane has a chain to recompute.
 *
 * Usage: pnpm --filter @metalabel/dfos-web-relay exec tsx <path>/serve-write-disabled.ts [port]
 *
 * Must be run via pnpm filter so the relay package's dependencies resolve.
 */
// Imported via relative paths into the protocol/relay package sources (not bare
// '@metalabel/dfos-protocol' specifiers), because this script lives in the Go
// relay-conformance package, which has no node_modules — same convention as
// serve-conformance.ts. The package sources resolve their own deps.
import {
  deriveChainIdentifier,
  encodeEd25519Multikey,
  signIdentityOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '../../dfos-protocol/src/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '../../dfos-protocol/src/crypto';
import { ingestOperations } from '../../dfos-web-relay/src/ingest';
import { createRelay } from '../../dfos-web-relay/src/relay';
import { serve } from '../../dfos-web-relay/src/serve';
import { MemoryRelayStore } from '../../dfos-web-relay/src/store';

const port = parseInt(process.argv[2] || '4444', 10);

// --- mint a user identity genesis op (random keys; recompute-from-log verifies
// whatever the relay serves, so determinism is not required here) ---
const keypair = createNewEd25519Keypair();
const keyId = generateId('key');
const key: MultikeyPublicKey = {
  id: keyId,
  type: 'Multikey',
  publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
};

const createOp: IdentityOperation = {
  version: 1,
  type: 'create',
  authKeys: [key],
  assertKeys: [],
  controllerKeys: [key],
  createdAt: new Date().toISOString(),
};

const { jwsToken } = await signIdentityOperation({
  operation: createOp,
  signer: async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey),
  keyId,
});

const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
const seededDID = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');

// --- seed the chain OUT-OF-BAND, then serve write-disabled ---
const store = new MemoryRelayStore();
await ingestOperations([jwsToken], store);

const relay = await createRelay({ store, write: false });

serve(relay.app, { port });
// printed last so the runner can grep it after the listener is up
console.log(`SEEDED_DID=${seededDID}`);
