import { describe, expect, it } from 'vitest';
import { encodeEd25519Multikey, signIdentityOperation, verifyIdentityChain } from '../src/chain';
import type { IdentityOperation, MultikeyPublicKey, ServiceEntry } from '../src/chain';
import { ServiceEntry as ServiceEntrySchema, ServicesArray } from '../src/chain/schemas';
import {
  anchorsByLabel,
  classifyAnchor,
  isRecognizedServiceType,
  relayEndpoints,
} from '../src/chain/services';
import { createNewEd25519Keypair, generateId, signPayloadEd25519 } from '../src/crypto';

// stable anchor fixtures
const CONTENT_ID = '2346789acdefhknrtvz2346789acdef'; // 31 chars, content-chain alphabet
const ARTIFACT_CID = 'bafkreieabcdefghijklmnoprstuvwxyz234567'; // CIDv1 base32 → artifact

const RELAY: ServiceEntry = {
  id: 'relay-0',
  type: 'DfosRelay',
  endpoint: 'https://relay.dfos.com',
};
const PROFILE: ServiceEntry = {
  id: 'profile',
  type: 'ContentAnchor',
  label: 'profile',
  anchor: CONTENT_ID,
};
const CARD: ServiceEntry = {
  id: 'card',
  type: 'ContentAnchor',
  label: 'card',
  anchor: ARTIFACT_CID,
};

// =============================================================================
// anchor classification (shape-dispatch)
// =============================================================================

describe('classifyAnchor', () => {
  it('classifies a 31-char contentId as a content chain', () => {
    expect(classifyAnchor(CONTENT_ID)).toBe('chain');
  });

  it('classifies a CIDv1 base32 string as an artifact', () => {
    expect(classifyAnchor(ARTIFACT_CID)).toBe('artifact');
  });

  it('classifies a chain HEAD CID as artifact-shaped (rejected later at resolution)', () => {
    // a head CID is also baf… base32 — it dispatches to 'artifact', then fails
    // the resolution-time type check (resolves to a non-artifact op). So
    // "never anchor a head CID" holds without a mode flag.
    expect(classifyAnchor('bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi')).toBe(
      'artifact',
    );
  });

  it('rejects malformed anchors', () => {
    expect(classifyAnchor('not-an-anchor')).toBe('invalid');
    expect(classifyAnchor('short')).toBe('invalid');
    expect(classifyAnchor('')).toBe('invalid');
  });
});

// =============================================================================
// service entry schema (open namespace + recognized types)
// =============================================================================

describe('ServiceEntry schema', () => {
  it('accepts a DfosRelay with an endpoint', () => {
    expect(ServiceEntrySchema.safeParse(RELAY).success).toBe(true);
  });

  it('accepts ContentAnchor for both chain and artifact targets', () => {
    expect(ServiceEntrySchema.safeParse(PROFILE).success).toBe(true);
    expect(ServiceEntrySchema.safeParse(CARD).success).toBe(true);
  });

  it('preserves and accepts an unrecognized type (MUST-ignore-unknown)', () => {
    const unknown = { id: 'x', type: 'MetalabelSpaceTag', spaceId: 'sp_1', role: 'member' };
    const parsed = ServiceEntrySchema.safeParse(unknown);
    expect(parsed.success).toBe(true);
    // extra fields are preserved verbatim
    expect((parsed.data as Record<string, unknown>).spaceId).toBe('sp_1');
    expect(isRecognizedServiceType('MetalabelSpaceTag')).toBe(false);
  });

  it('rejects a DfosRelay without an endpoint', () => {
    expect(ServiceEntrySchema.safeParse({ id: 'r', type: 'DfosRelay' }).success).toBe(false);
  });

  it('rejects a ContentAnchor with an invalid anchor', () => {
    expect(
      ServiceEntrySchema.safeParse({
        id: 'p',
        type: 'ContentAnchor',
        label: 'profile',
        anchor: 'nope',
      }).success,
    ).toBe(false);
  });

  it('rejects a ContentAnchor missing a label', () => {
    expect(
      ServiceEntrySchema.safeParse({ id: 'p', type: 'ContentAnchor', anchor: CONTENT_ID }).success,
    ).toBe(false);
  });
});

describe('ServicesArray schema', () => {
  it('rejects more than 256 entries', () => {
    const many = Array.from({ length: 257 }, (_, i) => ({ ...RELAY, id: `relay-${i}` }));
    expect(ServicesArray.safeParse(many).success).toBe(false);
  });

  it('rejects duplicate entry ids', () => {
    expect(ServicesArray.safeParse([RELAY, { ...PROFILE, id: 'relay-0' }]).success).toBe(false);
  });
});

// =============================================================================
// services projection through the identity chain
// =============================================================================

describe('services projection', () => {
  const makeKey = () => {
    const keypair = createNewEd25519Keypair();
    const keyId = generateId('key');
    const key: MultikeyPublicKey = {
      id: keyId,
      type: 'Multikey',
      publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
    };
    const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
    return { keyId, key, signer };
  };
  const ts = (offset = 0) => new Date(1750000000000 + offset * 60_000).toISOString();

  const sign = (op: IdentityOperation, k: ReturnType<typeof makeKey>, did?: string) =>
    signIdentityOperation({
      operation: op,
      signer: k.signer,
      keyId: k.keyId,
      ...(did ? { identityDID: did } : {}),
    });

  it('projects services from genesis, replaces on update, carries through delete', async () => {
    const k = makeKey();
    const create: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      services: [RELAY, PROFILE, CARD],
      createdAt: ts(0),
    };
    const genesis = await sign(create, k);
    const afterCreate = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [genesis.jwsToken],
    });
    expect(afterCreate.services).toHaveLength(3);
    expect(relayEndpoints(afterCreate.services)).toEqual(['https://relay.dfos.com']);
    expect(anchorsByLabel(afterCreate.services, 'profile')[0]?.id).toBe('profile');

    // update REPLACES the full set (drop the card)
    const update: IdentityOperation = {
      version: 1,
      type: 'update',
      previousOperationCID: genesis.operationCID,
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      services: [RELAY, PROFILE],
      createdAt: ts(1),
    };
    const upd = await sign(update, k, afterCreate.did);
    const afterUpdate = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [genesis.jwsToken, upd.jwsToken],
    });
    expect(afterUpdate.services.map((s) => s.id)).toEqual(['relay-0', 'profile']);

    // delete carries the last services state
    const del: IdentityOperation = {
      version: 1,
      type: 'delete',
      previousOperationCID: upd.operationCID,
      createdAt: ts(2),
    };
    const d = await sign(del, k, afterCreate.did);
    const afterDelete = await verifyIdentityChain({
      didPrefix: 'did:dfos',
      log: [genesis.jwsToken, upd.jwsToken, d.jwsToken],
    });
    expect(afterDelete.isDeleted).toBe(true);
    expect(afterDelete.services).toHaveLength(2);
  });

  it('defaults to empty services when the field is omitted (CID-neutral)', async () => {
    const k = makeKey();
    const create: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(0),
    };
    const genesis = await sign(create, k);
    const verified = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesis.jwsToken] });
    expect(verified.services).toEqual([]);
  });

  it('rejects an over-cap services payload at verification', async () => {
    const k = makeKey();
    // One entry with a ~33 KB endpoint — individually valid (non-empty, no
    // per-field length cap) but past the 32768-byte aggregate services cap.
    const oversized = [
      { id: 'relay', type: 'DfosRelay', endpoint: 'https://' + 'a'.repeat(33000) },
    ];
    const create: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      services: oversized,
      createdAt: ts(0),
    };
    const genesis = await sign(create, k);
    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesis.jwsToken] }),
    ).rejects.toThrow(/services payload exceeds max size/);
  });

  it('accepts a services payload just under the cap (positive control)', async () => {
    const k = makeKey();
    // Positive control pinning the byte boundary. The single-entry envelope is a
    // fixed 38 bytes (array+map+id/type keys+values+endpoint header), so an
    // endpoint of 'https://' + 32714×'a' (len 32722) encodes to 32760 bytes,
    // just under the 32768 cap. One more byte flips it over (see the test above),
    // proving the bound is exactly 32768.
    const underCap = [{ id: 'relay', type: 'DfosRelay', endpoint: 'https://' + 'a'.repeat(32714) }];
    const create: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      services: underCap,
      createdAt: ts(0),
    };
    const genesis = await sign(create, k);
    const verified = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesis.jwsToken] });
    expect(verified.services).toHaveLength(1);
  });
});
