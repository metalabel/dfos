import {
  encodeEd25519Multikey,
  signIdentityOperation,
  type IdentityOperation,
  type MultikeyPublicKey,
} from '@metalabel/dfos-protocol/chain';
import {
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  generateId,
  signPayloadEd25519,
} from '@metalabel/dfos-protocol/crypto';
import { describe, expect, it } from 'vitest';
import { IDENTITY_CONFLICTING_EXTENSION_ERROR, ingestOperations } from '../src/ingest';
import { sequenceOps } from '../src/sequencer';
import { MemoryRelayStore } from '../src/store';

/*

  CHAIN-STATE SERIALIZATION

  WEB-RELAY.md requires every chain-state mutation to be serialized. Ingestion
  is read-verify-write across real yield points (the WebCrypto verify is one),
  so two overlapping ingests of children of the SAME parent both read the same
  head, both verify against it, and both write the whole chain back from their
  own stale snapshot — the second silently erasing the first. The Go twin holds
  ingestMu across that span; these tests pin the TypeScript equivalent.

  Every case here drives the two writers CONCURRENTLY (Promise.all, no await
  between the submissions) — that is the whole point. Against an unserialized
  ingest they interleave and the assertions fail.

*/

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

const createIdentity = async () => {
  const controller = makeKey();
  const createOp: IdentityOperation = {
    version: 1,
    type: 'create',
    authKeys: [controller.key],
    assertKeys: [controller.key],
    controllerKeys: [controller.key],
    createdAt: ts(),
  };
  const { jwsToken, operationCID } = await signIdentityOperation({
    operation: createOp,
    signer: controller.signer,
    keyId: controller.keyId,
  });
  const encoded = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
  const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
  const did = deriveChainIdentifier(encoded.cid.bytes, 'did:dfos');
  return { did, controller, jwsToken, operationCID };
};

/** A child identity op extending `identity`'s genesis, declaring a fresh key. */
const signChild = async (
  identity: Awaited<ReturnType<typeof createIdentity>>,
  createdAtOffset: number,
) => {
  const key = makeKey();
  return signIdentityOperation({
    operation: {
      version: 1,
      type: 'update',
      previousOperationCID: identity.operationCID,
      authKeys: [key.key],
      assertKeys: [],
      controllerKeys: [identity.controller.key],
      createdAt: ts(createdAtOffset),
    },
    signer: identity.controller.signer,
    keyId: identity.controller.keyId,
    identityDID: identity.did,
  });
};

describe('chain-state serialization', () => {
  it('accepts exactly one of two concurrent competing identity children', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);

    const childA = await signChild(identity, 2);
    const childB = await signChild(identity, 3);

    // concurrent: both submissions read the head before either writes it
    const [[resA], [resB]] = await Promise.all([
      ingestOperations([childA.jwsToken], store),
      ingestOperations([childB.jwsToken], store),
    ]);

    const statuses = [resA!.status, resB!.status].sort();
    expect(statuses).toEqual(['new', 'rejected']);

    const rejected = resA!.status === 'rejected' ? resA! : resB!;
    expect(rejected.error).toBe(IDENTITY_CONFLICTING_EXTENSION_ERROR);
    expect(rejected.dependencyMissing).toBeFalsy();

    const accepted = resA!.status === 'new' ? childA : childB;
    const chain = await store.getIdentityChain(identity.did);
    expect(chain!.log).toHaveLength(2);
    expect(chain!.log[1]).toBe(accepted.jwsToken);
    expect(chain!.headCID).toBe(accepted.operationCID);
  });

  it('does not double-append when one op is resubmitted concurrently', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);

    const child = await signChild(identity, 2);

    const [[first], [second]] = await Promise.all([
      ingestOperations([child.jwsToken], store),
      ingestOperations([child.jwsToken], store),
    ]);

    const statuses = [first!.status, second!.status].sort();
    expect(statuses).toEqual(['duplicate', 'new']);

    const chain = await store.getIdentityChain(identity.did);
    expect(chain!.log).toHaveLength(2);
    expect(chain!.log[1]).toBe(child.jwsToken);
    expect(chain!.headCID).toBe(child.operationCID);
  });

  it('does not double-append when the sequencer runs concurrently with an ingest', async () => {
    const store = new MemoryRelayStore();
    const identity = await createIdentity();
    await ingestOperations([identity.jwsToken], store);

    // the same op sits in raw_ops (awaiting the sequencer) AND arrives on the
    // direct ingest path at the same moment
    const child = await signChild(identity, 2);
    await store.putRawOp(child.operationCID, child.jwsToken, 'peer');

    await Promise.all([sequenceOps(store), ingestOperations([child.jwsToken], store)]);

    const chain = await store.getIdentityChain(identity.did);
    expect(chain!.log).toHaveLength(2);
    expect(chain!.log[1]).toBe(child.jwsToken);
    expect(chain!.headCID).toBe(child.operationCID);
  });
});
