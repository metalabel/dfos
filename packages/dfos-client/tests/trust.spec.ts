/*

  TRUST AGGREGATION

  Trust is DATA. These tests pin the rules by which `Resolved.trust` degrades:
  a fresh, verified read is { ok: true } with no unverifiable axes; a cache-only
  read (all relays down) carries `tip`; a credential that cannot be proven
  unrevoked carries `revocation`; a proven-revoked credential is { ok: false }.

*/

import { createDFOSCredential } from '@metalabel/dfos-protocol/credentials';
import { describe, expect, it } from 'vitest';
import { createClient } from '../src/client';
import { memoryStore } from '../src/store/memory';
import { buildContent, buildIdentity, fakePeerClient } from './fixtures';

const RELAY = 'https://relay.test';

describe('trust aggregation', () => {
  it('a fresh verified identity is fully trusted with no unverifiable axes', async () => {
    const id = await buildIdentity();
    const peerClient = fakePeerClient({ [RELAY]: { identities: { [id.did]: id.log } } });
    const client = createClient({ relays: [RELAY], peerClient });

    const res = await client.identity(id.did);
    expect(res.trust.ok).toBe(true);
    expect(res.trust.unverifiable).toBeUndefined();
    expect(res.provenance.fromCache).toBe(false);
    expect(res.provenance.agreed).toBe(true);
    expect(res.value.did).toBe(id.did);
  });

  it('content with no delegated writes carries no revocation axis', async () => {
    const creator = await buildIdentity();
    const content = await buildContent(creator);
    const peerClient = fakePeerClient({
      [RELAY]: {
        identities: { [creator.did]: creator.log },
        contents: { [content.contentId]: content.log },
      },
    });
    const client = createClient({ relays: [RELAY], peerClient });

    const res = await client.content(content.contentId);
    expect(res.trust.ok).toBe(true);
    expect(res.trust.unverifiable).toBeUndefined();
    expect(res.value.chain.contentId).toBe(content.contentId);
    expect(res.value.creator.did).toBe(creator.did);
  });

  it('a cache-only read (all relays down) degrades trust to tip', async () => {
    const id = await buildIdentity();
    const store = memoryStore();
    const up = fakePeerClient({ [RELAY]: { identities: { [id.did]: id.log } } });
    const warm = createClient({ relays: [RELAY], store, peerClient: up });
    await warm.identity(id.did); // warms the cache

    // now every relay is unreachable — same store, empty peer client
    const down = fakePeerClient({});
    const offline = createClient({ relays: [RELAY], store, peerClient: down });
    const res = await offline.identity(id.did);

    expect(res.trust.ok).toBe(true);
    expect(res.trust.unverifiable).toEqual(['tip']);
    expect(res.provenance.fromCache).toBe(true);
  });

  it('a credential that cannot be proven unrevoked carries the revocation axis', async () => {
    const issuer = await buildIdentity();
    const jws = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'read' }],
      exp: Math.floor(Date.now() / 1000) + 3600,
      signer: issuer.k.signer,
      keyId: issuer.k.keyId,
    });
    const peerClient = fakePeerClient({ [RELAY]: { identities: { [issuer.did]: issuer.log } } });
    const client = createClient({
      relays: [RELAY],
      peerClient,
      isRevoked: async () => false,
    });

    const res = await client.credential(jws);
    expect(res.trust.ok).toBe(true);
    expect(res.value.revoked).toBe(false);
    expect(res.trust.unverifiable).toContain('revocation');
  });

  it('a proven-revoked credential is not trusted', async () => {
    const issuer = await buildIdentity();
    const jws = await createDFOSCredential({
      issuerDID: issuer.did,
      audienceDID: '*',
      att: [{ resource: 'chain:abc', action: 'read' }],
      exp: Math.floor(Date.now() / 1000) + 3600,
      signer: issuer.k.signer,
      keyId: issuer.k.keyId,
    });
    const peerClient = fakePeerClient({ [RELAY]: { identities: { [issuer.did]: issuer.log } } });
    const client = createClient({
      relays: [RELAY],
      peerClient,
      isRevoked: async () => true,
    });

    const res = await client.credential(jws);
    expect(res.trust.ok).toBe(false);
    expect(res.value.revoked).toBe(true);
  });
});
