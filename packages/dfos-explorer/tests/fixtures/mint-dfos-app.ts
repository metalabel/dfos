/**
 * Mints the VALID app-description fixture the well-known crypto tests run against.
 *
 * WHY A MINTED FIXTURE RATHER THAN THE REAL DEMO DOCUMENT. The repo's one real
 * carriage document — examples/siwd-demo/public/.well-known/dfos-app.json — carries
 * a chain whose genesis declares several distinct keys. That shape predates key
 * possession and no longer verifies: a genesis declares exactly ONE key, in all
 * three roles, and proves it by signing itself. The real document is therefore a
 * NEGATIVE vector now, and it is asserted as one (see wellknown.spec.ts). It is
 * left byte-untouched because it mirrors what the deployed demo actually serves;
 * the deployed demo's chain is re-minted in the platform migration, and until then
 * these tests tell the truth about it rather than papering over it.
 *
 * This fixture is what the POSITIVE path needs: a chain that exercises the same
 * parse/verify surface the real one did — a multi-operation carriage, a client_did
 * the document's own chain derives, an introduction carrying a possession proof —
 * and actually verifies.
 *
 * DETERMINISTIC. Seeds, key ids, timestamps and the proof nonce are all fixed, so
 * re-running this emits byte-identical output and the fixture never drifts under a
 * clock. Re-mint with:
 *
 *   pnpm --filter @metalabel/dfos-explorer tsx tests/fixtures/mint-dfos-app.ts
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  encodeEd25519Multikey,
  signIdentityOperation,
  verifyIdentityChain,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  generateId,
  importEd25519Keypair,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import {
  KEY_ADD_JWS_TYP,
  serializeRoleSet,
  signKeyProof,
} from '@metalabel/dfos-protocol/key-proof';

const GENESIS_AT = '2026-03-07T00:00:00.000Z';
const INTRO_AT = '2026-03-07T00:01:00.000Z';
const PROOF_AT = '2026-03-07T00:00:30.000Z';
const PROOF_NONCE = 'explorer-wellknown-fixture-nonce';

/** Seeds are hashed the same way the protocol's own example generator hashes its. */
const seedFrom = async (label: string) =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label)));

const mint = async () => {
  const seedA = await seedFrom('dfos-explorer-wellknown-fixture-key-1');
  const keypairA = importEd25519Keypair(seedA);
  const keyA: MultikeyPublicKey = {
    id: generateId('key', { seed: keypairA.publicKey }),
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypairA.publicKey),
  };
  const signA = async (msg: Uint8Array) => signPayloadEd25519(msg, keypairA.privateKey);

  const seedB = await seedFrom('dfos-explorer-wellknown-fixture-key-2');
  const keypairB = importEd25519Keypair(seedB);
  const keyB: MultikeyPublicKey = {
    id: generateId('key', { seed: keypairB.publicKey }),
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypairB.publicKey),
  };

  // --- genesis: one key, all three roles, proving itself by signing ---
  const genesisOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [keyA],
    assertKeys: [keyA],
    controllerKeys: [keyA],
    createdAt: GENESIS_AT,
  };
  const { jwsToken: genesisJws, operationCID: genesisCID } = await signIdentityOperation({
    operation: genesisOp,
    signer: signA,
    keyId: keyA.id,
  });
  const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesisJws] });

  // --- introduction: a DISTINCT auth key, carrying its own possession proof ---
  //
  // The controller-verified leg: no host mediates, so the audience is the target
  // chain's own DID, byte-equal to the payload's `did`. The role set covers exactly
  // the role the operation introduces the key to — auth, and not the two roles key A
  // keeps — because an envelope consenting to more than was asked is the holder
  // conceding ground no verifier should bank.
  const { proof } = await signKeyProof({
    typ: KEY_ADD_JWS_TYP,
    nonce: PROOF_NONCE,
    audience: identity.did,
    did: identity.did,
    roleSet: serializeRoleSet(['auth']),
    prevCID: genesisCID,
    privateKey: keypairB.privateKey,
    timestamp: PROOF_AT,
  });

  const introOp: IdentityOperation = {
    version: 1,
    type: 'update',
    previousOperationCID: genesisCID,
    authKeys: [keyA, keyB],
    assertKeys: [keyA],
    controllerKeys: [keyA],
    createdAt: INTRO_AT,
    keyProofs: [proof],
  };
  const { jwsToken: introJws } = await signIdentityOperation({
    operation: introOp,
    signer: signA,
    keyId: keyA.id,
    identityDID: identity.did,
  });

  const log = [genesisJws, introJws];

  // Verified here, at mint time, so a fixture that cannot verify never reaches a
  // test as one that supposedly can.
  const verified = await verifyIdentityChain({ didPrefix: 'did:dfos', log });
  if (verified.did !== identity.did) {
    throw new Error(`minted chain derives ${verified.did}, expected ${identity.did}`);
  }
  if (verified.authKeys.length !== 2) {
    throw new Error(
      `minted chain has ${verified.authKeys.length} effective auth key(s), expected 2 — ` +
        'the introduction went void, so its possession proof did not cover it',
    );
  }

  const document = {
    client_did: identity.did,
    identity_chain: log,
    name: 'Explorer Fixture App',
    redirect_uris: ['https://explorer-fixture.example/cb'],
  };

  const out = resolve(import.meta.dirname, 'dfos-app.minted.json');
  writeFileSync(out, `${JSON.stringify(document, null, 2)}\n`);
  console.log(`wrote ${out}`);
  console.log(`  did:        ${identity.did}`);
  console.log(`  operations: ${log.length}`);
  console.log(`  auth keys:  ${verified.authKeys.length} effective`);
};

mint().catch((err) => {
  console.error(err);
  process.exit(1);
});
