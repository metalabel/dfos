import { dagCborCanonicalEncode } from '@metalabel/dfos-protocol/crypto';
import { IDBFactory } from 'fake-indexeddb';
import { describe, expect, it } from 'vitest';
import { openExplorerDb, type ChainRollup, type ExplorerOp } from '../src/lib/db';
import type { BlobResult } from '../src/lib/relay-raw';
import { resolvePublicProjections } from '../src/lib/sync-projections';

const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const mkJws = (header: Record<string, unknown>, payload: Record<string, unknown>): string =>
  `${b64url(header)}.${b64url(payload)}.sig`;

const cidOf = async (obj: Record<string, unknown>): Promise<string> =>
  (await dagCborCanonicalEncode(obj)).cid.toString();

/** A content op whose CID is the REAL hash of its payload (self-CID must pass). */
const contentOp = async (opts: {
  chainId: string;
  payload: Record<string, unknown>;
  kid: string;
  createdAt: string;
  seq: number;
}): Promise<ExplorerOp> => {
  const cid = await cidOf(opts.payload);
  return {
    cid,
    jwsToken: mkJws({ typ: 'did:dfos:content-op', kid: opts.kid }, opts.payload),
    kind: 'content-op',
    chainId: opts.chainId,
    type: String(opts.payload['type'] ?? ''),
    createdAt: opts.createdAt,
    kid: opts.kid,
    seq: opts.seq,
  };
};

/** A single-op public content chain committing `doc`, signed by `kid`. */
const publicChain = async (
  contentId: string,
  kid: string,
  doc: Record<string, unknown>,
  createdAt = '2026-01-01T00:00:00.000Z',
): Promise<{ op: ExplorerOp; rollup: ChainRollup; doc: Record<string, unknown> }> => {
  const documentCID = await cidOf(doc);
  const op = await contentOp({
    chainId: contentId,
    payload: { type: 'create', createdAt, documentCID },
    kid,
    createdAt,
    seq: 0,
  });
  const rollup: ChainRollup = {
    chainId: contentId,
    kind: 'content-op',
    opCount: 1,
    firstCreatedAt: createdAt,
    lastCreatedAt: createdAt,
    headCid: op.cid,
  };
  return { op, rollup, doc };
};

/** A credential op with a STANDING public-read grant over `chain:<contentId>` —
 *  what makes an anonymous blob fetch possible at all (public-grants.ts). */
let grantSeq = 0;
const grantOp = (contentId: string, opts: { exp?: number } = {}): ExplorerOp => {
  grantSeq += 1;
  const payload: Record<string, unknown> = {
    iss: 'did:dfos:issuer',
    aud: '*',
    att: [{ resource: `chain:${contentId}`, action: 'read' }],
    ...(opts.exp !== undefined ? { exp: opts.exp } : {}),
  };
  return {
    cid: `cred-${grantSeq}`,
    jwsToken: mkJws({ typ: 'did:dfos:credential', kid: 'did:dfos:issuer#k' }, payload),
    kind: 'credential',
    chainId: 'did:dfos:issuer',
    type: 'grant',
    createdAt: '2026-01-01T00:00:00.000Z',
    kid: 'did:dfos:issuer#k',
    seq: grantSeq,
  };
};

/** A revocation op invalidating a credential by its op CID. */
const revokeOp = (credentialCid: string): ExplorerOp => ({
  cid: `rev-of-${credentialCid}`,
  jwsToken: mkJws(
    { typ: 'did:dfos:revocation', kid: 'did:dfos:issuer#k' },
    { credentialCID: credentialCid },
  ),
  kind: 'revocation',
  chainId: 'did:dfos:issuer',
  type: 'revocation',
  createdAt: '2026-03-01T00:00:00.000Z',
  kid: 'did:dfos:issuer#k',
  seq: 0,
});

const bytesOf = (obj: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(obj));
const served = (bytes: Uint8Array): BlobResult => ({
  relay: 'r',
  status: 200,
  gated: false,
  bytes,
});
const gated: BlobResult = { relay: 'r', status: 403, gated: true };

const freshDb = () => openExplorerDb('proj-test', new IDBFactory());

describe('resolvePublicProjections', () => {
  it('resolves a public profile and attributes it to the genesis signer', async () => {
    const db = await freshDb();
    const kid = 'did:dfos:creator#key1';
    const doc = { $schema: PROFILE_SCHEMA, name: 'Alice', avatar: { uri: 'attachment://a' } };
    const { op, rollup } = await publicChain('content1', kid, doc);

    // the attributed identity must already be in the index for the name to land
    await db.putBatch(
      [op, grantOp('content1')],
      [
        rollup,
        {
          chainId: 'did:dfos:creator',
          kind: 'identity-op',
          opCount: 1,
          firstCreatedAt: '',
          lastCreatedAt: '',
          headCid: 'g',
        },
      ],
    );

    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => served(bytesOf(doc)),
    });
    expect(result).toEqual({ resolved: 1, publicDocs: 1, attributed: 1 });

    const content = await db.getChain('content1');
    expect(content?.publicRead).toBe(true);
    expect(content?.docSchema).toBe(PROFILE_SCHEMA);
    expect(content?.resolvedHead).toBe(op.cid);

    const identity = await db.getChain('did:dfos:creator');
    expect(identity?.name).toBe('Alice');
    expect(identity?.nameLower).toBe('alice');
    expect(identity?.avatarRef).toBe('attachment://a');
  });

  it('marks a gated chain publicRead=false with no schema, but still resolves it once', async () => {
    const db = await freshDb();
    const doc = { $schema: PROFILE_SCHEMA, name: 'Hidden' };
    const { op, rollup } = await publicChain('c-gated', 'did:dfos:x#k', doc);
    await db.putBatch([op, grantOp('c-gated')], [rollup]);

    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => gated,
    });
    expect(result.publicDocs).toBe(0);
    const content = await db.getChain('c-gated');
    expect(content?.publicRead).toBe(false);
    expect(content?.docSchema).toBeUndefined();
    expect(content?.resolvedHead).toBe(op.cid); // resolved once — won't refetch until head drifts
  });

  it('rejects served bytes that do not re-hash to the committed doc CID', async () => {
    const db = await freshDb();
    const doc = { $schema: PROFILE_SCHEMA, name: 'Real' };
    const { op, rollup } = await publicChain('c-mismatch', 'did:dfos:x#k', doc);
    await db.putBatch([op, grantOp('c-mismatch')], [rollup]);

    // relay serves DIFFERENT bytes than the chain committed to
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => served(bytesOf({ $schema: PROFILE_SCHEMA, name: 'Forged' })),
    });
    expect(result.publicDocs).toBe(0);
    expect((await db.getChain('c-mismatch'))?.publicRead).toBe(false);
  });

  it('treats a deleted head (documentCID cleared) as no public doc', async () => {
    const db = await freshDb();
    const createdAt = '2026-01-02T00:00:00.000Z';
    const op = await contentOp({
      chainId: 'c-del',
      payload: { type: 'delete', createdAt, documentCID: null },
      kid: 'did:dfos:x#k',
      createdAt,
      seq: 0,
    });
    const rollup: ChainRollup = {
      chainId: 'c-del',
      kind: 'content-op',
      opCount: 1,
      firstCreatedAt: createdAt,
      lastCreatedAt: createdAt,
      headCid: op.cid,
    };
    await db.putBatch([op], [rollup]);

    let fetched = false;
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        fetched = true;
        return gated;
      },
    });
    expect(result.publicDocs).toBe(0);
    expect(fetched).toBe(false); // never even reaches the blob fetch
    expect((await db.getChain('c-del'))?.resolvedHead).toBe(op.cid);
  });

  it('is resumable — skips chains already resolved at their current head', async () => {
    const db = await freshDb();
    const doc = { $schema: PROFILE_SCHEMA, name: 'Once' };
    const { op, rollup } = await publicChain('c-once', 'did:dfos:x#k', doc);
    // pre-mark as already resolved at this head (grant keeps publicness in
    // agreement with the fold, so the chain stays skipped)
    await db.putBatch(
      [op, grantOp('c-once')],
      [{ ...rollup, resolvedHead: op.cid, publicRead: true, docSchema: PROFILE_SCHEMA }],
    );

    let calls = 0;
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        calls += 1;
        return served(bytesOf(doc));
      },
    });
    expect(calls).toBe(0);
    expect(result.resolved).toBe(0);
  });

  it('clears a stale identity attribution when its profile chain drifts to deleted', async () => {
    const db = await freshDb();
    const kid = 'did:dfos:creator#k';
    const doc = { $schema: PROFILE_SCHEMA, name: 'Alice' };
    const created = '2026-01-01T00:00:00.000Z';
    const { op: genesis, rollup } = await publicChain('c-drift', kid, doc, created);
    await db.putBatch(
      [genesis, grantOp('c-drift')],
      [
        rollup,
        {
          chainId: 'did:dfos:creator',
          kind: 'identity-op',
          opCount: 1,
          firstCreatedAt: '',
          lastCreatedAt: '',
          headCid: 'g',
        },
      ],
    );

    // first resolve: attributes "Alice" to did:dfos:creator
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => served(bytesOf(doc)),
    });
    expect((await db.getChain('did:dfos:creator'))?.name).toBe('Alice');

    // the profile chain drifts: a delete op (documentCID cleared) becomes the head
    const deletedAt = '2026-02-01T00:00:00.000Z';
    const del = await contentOp({
      chainId: 'c-drift',
      payload: {
        type: 'delete',
        createdAt: deletedAt,
        documentCID: null,
        previousOperationCID: genesis.cid,
      },
      kid,
      createdAt: deletedAt,
      seq: 1,
    });
    const drifted = await db.getChain('c-drift');
    await db.putBatch(
      [del],
      [{ ...drifted!, headCid: del.cid, lastCreatedAt: deletedAt, opCount: 2 }],
    );

    // re-resolve: the chain is no longer a public profile → attribution cleared
    let fetched = false;
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        fetched = true;
        return served(bytesOf(doc));
      },
    });
    expect(fetched).toBe(false); // deleted head never reaches the blob fetch
    const identity = await db.getChain('did:dfos:creator');
    expect(identity?.name).toBeUndefined();
    expect(identity?.nameLower).toBeUndefined();
    expect(identity?.publicRead).toBe(false);
    expect((await db.getChain('c-drift'))?.docSchema).toBeUndefined();
  });

  it('stops promptly when the signal is already aborted', async () => {
    const db = await freshDb();
    const doc = { $schema: PROFILE_SCHEMA, name: 'Never' };
    const { op, rollup } = await publicChain('c-abort', 'did:dfos:x#k', doc);
    await db.putBatch([op, grantOp('c-abort')], [rollup]);

    const controller = new AbortController();
    controller.abort();
    let calls = 0;
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      signal: controller.signal,
      fetchBlob: async () => {
        calls += 1;
        return served(bytesOf(doc));
      },
    });
    expect(calls).toBe(0);
    expect(result.resolved).toBe(0);
  });

  it('overlaps blob fetches through the worker pool and still resolves every chain', async () => {
    const db = await freshDb();
    const docs = new Map<string, Record<string, unknown>>();
    const ops: ExplorerOp[] = [];
    const rollups: ChainRollup[] = [];
    for (let i = 0; i < 24; i++) {
      const doc = { $schema: 'https://schemas.dfos.com/index/v1', n: i };
      const { op, rollup } = await publicChain(`c-par-${i}`, `did:dfos:w${i}#k`, doc);
      docs.set(`c-par-${i}`, doc);
      ops.push(op, grantOp(`c-par-${i}`));
      rollups.push(rollup);
    }
    await db.putBatch(ops, rollups);

    let inFlight = 0;
    let maxInFlight = 0;
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async (contentId) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight -= 1;
        return served(bytesOf(docs.get(contentId)));
      },
    });

    expect(result.resolved).toBe(24);
    expect(result.publicDocs).toBe(24);
    expect(maxInFlight).toBeGreaterThan(1); // fetches genuinely overlapped
    for (let i = 0; i < 24; i++) {
      expect((await db.getChain(`c-par-${i}`))?.publicRead).toBe(true);
    }
  });

  it('serializes same-DID attributions so concurrent profile chains do not lose updates', async () => {
    const db = await freshDb();
    const kid = 'did:dfos:shared#k';
    // two public profile chains attributing the SAME identity, resolved concurrently
    const a = await publicChain('c-att-a', kid, { $schema: PROFILE_SCHEMA, name: 'First' });
    const b = await publicChain(
      'c-att-b',
      kid,
      { $schema: PROFILE_SCHEMA, name: 'Second' },
      '2026-01-02T00:00:00.000Z',
    );
    await db.putBatch(
      [a.op, b.op, grantOp('c-att-a'), grantOp('c-att-b')],
      [
        a.rollup,
        b.rollup,
        {
          chainId: 'did:dfos:shared',
          kind: 'identity-op',
          opCount: 1,
          firstCreatedAt: '',
          lastCreatedAt: '',
          headCid: 'g',
        },
      ],
    );

    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async (contentId) => {
        await new Promise((r) => setTimeout(r, 5));
        return served(
          bytesOf(
            contentId === 'c-att-a'
              ? { $schema: PROFILE_SCHEMA, name: 'First' }
              : { $schema: PROFILE_SCHEMA, name: 'Second' },
          ),
        );
      },
    });

    expect(result.attributed).toBe(2); // both writes landed (no lost update)
    const identity = await db.getChain('did:dfos:shared');
    expect(identity?.name).toBeDefined();
    expect(identity?.profileSource).toBeDefined();
    // the surviving name must be consistent with its recorded source chain
    expect(identity?.name).toBe(identity?.profileSource === 'c-att-a' ? 'First' : 'Second');
  });

  it('never fetches a chain with no standing public grant — stamps gated from the log', async () => {
    const db = await freshDb();
    const doc = { $schema: PROFILE_SCHEMA, name: 'Ungranted' };
    const { op, rollup } = await publicChain('c-nogrant', 'did:dfos:x#k', doc);
    await db.putBatch([op], [rollup]); // NO credential op

    let fetched = false;
    const result = await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        fetched = true;
        return served(bytesOf(doc));
      },
    });
    expect(fetched).toBe(false); // the guaranteed-401 never leaves the tab
    expect(result.resolved).toBe(1);
    const chain = await db.getChain('c-nogrant');
    expect(chain?.publicRead).toBe(false);
    expect(chain?.resolvedHead).toBe(op.cid);
  });

  it('re-resolves an unmoved head when a grant is issued after it was stamped gated', async () => {
    const db = await freshDb();
    const doc = { $schema: 'https://schemas.dfos.com/index/v1', v: 1 };
    const { op, rollup } = await publicChain('c-late-grant', 'did:dfos:x#k', doc);
    await db.putBatch([op], [rollup]);

    // first run: no grant → gated without a fetch
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => served(bytesOf(doc)),
    });
    expect((await db.getChain('c-late-grant'))?.publicRead).toBe(false);

    // a public grant lands; the head has NOT drifted
    await db.putBatch([grantOp('c-late-grant')], []);
    let fetched = false;
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        fetched = true;
        return served(bytesOf(doc));
      },
    });
    expect(fetched).toBe(true);
    expect((await db.getChain('c-late-grant'))?.publicRead).toBe(true);
  });

  it('re-stamps an unmoved head gated (no fetch) when its grant is revoked', async () => {
    const db = await freshDb();
    const kid = 'did:dfos:creator#k';
    const doc = { $schema: PROFILE_SCHEMA, name: 'Revocable' };
    const { op, rollup } = await publicChain('c-revoked-grant', kid, doc);
    const grant = grantOp('c-revoked-grant');
    await db.putBatch(
      [op, grant],
      [
        rollup,
        {
          chainId: 'did:dfos:creator',
          kind: 'identity-op',
          opCount: 1,
          firstCreatedAt: '',
          lastCreatedAt: '',
          headCid: 'g',
        },
      ],
    );

    // first run: grant active → public, name attributed
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => served(bytesOf(doc)),
    });
    expect((await db.getChain('c-revoked-grant'))?.publicRead).toBe(true);
    expect((await db.getChain('did:dfos:creator'))?.name).toBe('Revocable');

    // the grant is revoked; the head has NOT drifted
    await db.putBatch([revokeOp(grant.cid)], []);
    let fetched = false;
    await resolvePublicProjections({
      db,
      relays: ['r'],
      fetchBlob: async () => {
        fetched = true;
        return served(bytesOf(doc));
      },
    });
    expect(fetched).toBe(false); // revoked in the log — nothing to ask a relay
    expect((await db.getChain('c-revoked-grant'))?.publicRead).toBe(false);
    expect((await db.getChain('did:dfos:creator'))?.name).toBeUndefined(); // stale attribution cleared
  });
});
