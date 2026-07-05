import {
  encodeEd25519Multikey,
  signContentOperation,
  signIdentityOperation,
  type ContentOperation,
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
import { ingestOperations } from '../src/ingest';
import { parseLimit } from '../src/relay';
import { MemoryRelayStore } from '../src/store';

/*

  WP-5 — parse strictness + tiebreakers (TS twin)

  parseLimit mirrors the Go relay's parseLimit (routes.go): empty → default;
  non-integer / < 1 → default; > max → clamp. The probed inputs (abc, -5, 0,
  1.5, 99999) must produce identical results across the two twins.

  The head code-point tiebreak (selectDeterministicHead) is exercised by the
  fork-acceptance integration tests in relay.spec.ts; here we lock parseLimit.

*/

describe('parseLimit (Go twin parity)', () => {
  const DEFAULT = 100;
  const MAX = 1000;
  const p = (raw: string | undefined) => parseLimit(raw, DEFAULT, MAX);

  it('returns the default for empty / undefined', () => {
    expect(p(undefined)).toBe(DEFAULT);
    expect(p('')).toBe(DEFAULT);
  });

  it('returns the default for non-numeric input (Number("abc") → NaN)', () => {
    expect(p('abc')).toBe(DEFAULT);
  });

  it('returns the default for negatives and zero', () => {
    expect(p('-5')).toBe(DEFAULT);
    expect(p('0')).toBe(DEFAULT);
  });

  it('returns the default for fractions (Atoi rejects "1.5")', () => {
    expect(p('1.5')).toBe(DEFAULT);
  });

  it('clamps values above max', () => {
    expect(p('99999')).toBe(MAX);
  });

  it('accepts valid in-range integers', () => {
    expect(p('1')).toBe(1);
    expect(p('50')).toBe(50);
    expect(p('1000')).toBe(MAX);
  });

  it('rejects non-decimal-integer forms that Go strconv.Atoi rejects', () => {
    expect(p('1e3')).toBe(DEFAULT);
    expect(p('0x10')).toBe(DEFAULT);
    expect(p(' 10')).toBe(DEFAULT);
    expect(p('10 ')).toBe(DEFAULT);
  });

  it('rejects a leading + (Go strconv.Atoi accepts it, so the Go twin guards against it)', () => {
    // A percent-encoded "+" (?limit=%2B50) decodes to a literal "+50". Go's
    // strconv.Atoi WOULD accept that as 50, so the Go parseLimit has an explicit
    // guard rejecting a leading "+" to match this regex — keeping the page size
    // identical across twins. (A bare "+" in a query string decodes to a space,
    // which both sides already reject via the whitespace path above.)
    expect(p('+50')).toBe(DEFAULT);
  });
});

// ---------------------------------------------------------------------------
// head code-point tiebreak (equal createdAt conflicting tips)
// ---------------------------------------------------------------------------

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const multibase = encodeEd25519Multikey(keypair.publicKey);
  const key: MultikeyPublicKey = { id: keyId, type: 'Multikey', publicKeyMultibase: multibase };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

describe('head code-point tiebreak (Go twin parity)', () => {
  it('selects the byte-wise highest CID when conflicting tips share createdAt', async () => {
    const store = new MemoryRelayStore();

    // identity + content genesis
    const controller = makeKey();
    const authKey = makeKey();
    const createOp: IdentityOperation = {
      version: 1,
      type: 'create',
      authKeys: [authKey.key],
      assertKeys: [],
      controllerKeys: [controller.key],
      createdAt: ts(),
    };
    const idRes = await signIdentityOperation({
      operation: createOp,
      signer: controller.signer,
      keyId: controller.keyId,
    });
    const enc = await dagCborCanonicalEncode(createOp as unknown as Record<string, unknown>);
    const { deriveChainIdentifier } = await import('@metalabel/dfos-protocol/chain');
    const did = deriveChainIdentifier(enc.cid.bytes, 'did:dfos');

    const doc0 = { type: 'post', title: 'genesis' };
    const doc0CID = (
      await dagCborCanonicalEncode(doc0 as unknown as Record<string, unknown>)
    ).cid.toString();
    const genesis: ContentOperation = {
      version: 1,
      type: 'create',
      did,
      documentCID: doc0CID,
      baseDocumentCID: null,
      createdAt: ts(1),
      note: null,
    };
    const kid = `${did}#${authKey.keyId}`;
    const genRes = await signContentOperation({ operation: genesis, signer: authKey.signer, kid });
    await ingestOperations([idRes.jwsToken, genRes.jwsToken], store);

    // two competing forks off the genesis at the SAME createdAt → equal-createdAt
    // tip conflict; only the CID tiebreak decides the head.
    const sameTime = ts(2);
    const buildFork = async (title: string) => {
      const doc = { type: 'post', title };
      const docCID = (
        await dagCborCanonicalEncode(doc as unknown as Record<string, unknown>)
      ).cid.toString();
      const op: ContentOperation = {
        version: 1,
        type: 'update',
        did,
        previousOperationCID: genRes.operationCID,
        documentCID: docCID,
        baseDocumentCID: null,
        createdAt: sameTime,
        note: null,
      };
      const { jwsToken, operationCID } = await signContentOperation({
        operation: op,
        signer: authKey.signer,
        kid,
      });
      return { jwsToken, operationCID, docCID };
    };

    const forkA = await buildFork('branch-a');
    const forkB = await buildFork('branch-b');
    expect(forkA.operationCID).not.toBe(forkB.operationCID);

    // the deterministic head = the byte-wise (code-point) HIGHEST CID
    const expectedHeadCID =
      forkA.operationCID > forkB.operationCID ? forkA.operationCID : forkB.operationCID;

    // ingest in BOTH orders on fresh stores → same head regardless of order
    const headFor = async (order: { jwsToken: string }[]) => {
      const s = new MemoryRelayStore();
      await ingestOperations([idRes.jwsToken, genRes.jwsToken], s);
      for (const op of order) await ingestOperations([op.jwsToken], s);
      const contentId = genRes.operationCID;
      const chain = await s.getContentChain((await s.getOperation(contentId))!.chainId);
      return chain!.state.headCID;
    };

    const head1 = await headFor([forkA, forkB]);
    const head2 = await headFor([forkB, forkA]);
    expect(head1).toBe(expectedHeadCID);
    expect(head2).toBe(expectedHeadCID);
  });
});
