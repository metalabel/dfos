/**
 * The pure half of the key page's SIGNED lane — what one key put a signature on.
 *
 * Three things are tested here, and all three are the same discipline from
 * different angles: the page may never present a figure or a row it did not
 * actually earn from a relay that answered the question asked.
 *
 *   - the probe classifier, on the `signerKey=` param. It shares the body-shaped
 *     classifier `key=` uses (tests/key-lookup.spec.ts covers the classifier's
 *     own edges); what matters here is that the OPERATIONS-shaped body is read
 *     the same way and that a relay with no operations route stays safe.
 *   - the count fold, which is the actual "op count" fix: a number only from a
 *     relay that honours the filter, and never the identity-chain figure wearing
 *     a key-scoped label.
 *   - the row mapping, which turns index metadata into the table's four columns
 *     without inventing a fifth.
 */

import { describe, expect, it } from 'vitest';
import {
  bodyFilterFromProbe,
  KEY_PROBE_MULTIBASE,
  supportedBodyFilterRelays,
} from '../src/lib/index-light';
import { toOperationRows } from '../src/lib/index-raw';
import { chainKindOf, signerOpCount, signerOpCountLabel } from '../src/lib/key-ops';
import { indexOpRows } from '../src/lib/log-feed';

// -----------------------------------------------------------------------------
// THE OLD-RELAY TRAP, on the operations route. A relay predating `signerKey=`
// IGNORES the param and answers with the unfiltered operations feed — every row
// of which the key page would be presenting as one this key signed. The spec
// forbids a 400 on this param (an opaque byte match, no format validation), so
// the verdict is read off the BODY exactly as it is for `key=`.
// -----------------------------------------------------------------------------

describe('signerKey= probe — the body verdict', () => {
  it('reads operations coming back for the sentinel as the param being IGNORED', () => {
    // nothing holds the sentinel's private half, so nothing can have signed with
    // it: a row in this answer is the relay ignoring the filter, never a match
    expect(bodyFilterFromProbe(200, 1)).toBe(false);
    expect(supportedBodyFilterRelays([{ relay: 'a', status: 200, rows: 20 }])).toEqual([]);
  });

  it('reads a served empty page as the param being applied', () => {
    expect(bodyFilterFromProbe(200, 0)).toBe(true);
    expect(supportedBodyFilterRelays([{ relay: 'a', status: 200, rows: 0 }])).toEqual(['a']);
  });

  // `/index/v0/operations` is NEWER than the capabilities.index flag, so a relay
  // can advertise an index and still 404/501 this route. That is indeterminate,
  // and with nothing definitive behind it the whole verdict degrades to
  // unsupported — the safe direction, reached without a second probe.
  it('degrades to unsupported when the operations route is not served at all', () => {
    expect(bodyFilterFromProbe(404, 0)).toBeNull();
    expect(bodyFilterFromProbe(501, 0)).toBeNull();
    expect(
      supportedBodyFilterRelays([
        { relay: 'a', status: 501, rows: 0 },
        { relay: 'b', status: 404, rows: 0 },
      ]),
    ).toEqual([]);
  });

  // one sentinel answers both filters: no chain has ever declared it (`key=`) and
  // nothing has ever signed with it (`signerKey=`), because its 32 bytes are a
  // published hash rather than a generated public key
  it('sends a well-formed key, so a relay can never reject it on format', () => {
    expect(KEY_PROBE_MULTIBASE).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  });
});

// -----------------------------------------------------------------------------
// THE COUNT — the fix. A key page's "ops" figure used to be an identity's whole
// chain count; the true figure is what this key signed, and it exists only where
// a relay answered that question.
// -----------------------------------------------------------------------------

const counted = {
  indexed: true,
  supported: true,
  loading: false,
  error: false,
  loaded: 7,
  hasNext: false,
  offFirst: false,
};

describe('signerOpCount — what may honestly be counted', () => {
  it('counts a page a supported relay served for this key', () => {
    expect(signerOpCount(counted)).toEqual({ kind: 'counted', loaded: 7, partial: false });
  });

  // a keyset cursor cannot report a total, so an enumeration with anything ahead
  // of it — or behind it — has LOADED rows, not counted them
  it('is partial wherever the enumeration is not known to be exhausted', () => {
    expect(signerOpCount({ ...counted, loaded: 20, hasNext: true })).toEqual({
      kind: 'counted',
      loaded: 20,
      partial: true,
    });
    expect(signerOpCount({ ...counted, offFirst: true })).toMatchObject({ partial: true });
  });

  // THE POINT OF THE WHOLE FOLD: a relay that ignores the param served the
  // unfiltered feed, and the number in that page is about the relay, not the key
  it('never produces a number from a relay that ignores the filter', () => {
    expect(signerOpCount({ ...counted, supported: false, loaded: 20 })).toEqual({
      kind: 'unsupported',
    });
    // and it says so INSTEAD of spinning — the answer is settled, just negative
    expect(signerOpCount({ ...counted, supported: false, loading: true })).toEqual({
      kind: 'unsupported',
    });
  });

  it('has no count at all without a relay index', () => {
    expect(signerOpCount({ ...counted, indexed: false })).toEqual({ kind: 'unavailable' });
  });

  it('holds at checking while either gate or the query is in flight', () => {
    expect(signerOpCount({ ...counted, indexed: null })).toEqual({ kind: 'checking' });
    expect(signerOpCount({ ...counted, supported: null })).toEqual({ kind: 'checking' });
    expect(signerOpCount({ ...counted, loading: true, loaded: 0 })).toEqual({ kind: 'checking' });
  });

  // an outage is not a zero — "0" here would read as "this key signed nothing"
  it('reports a failed query as unknown rather than as none', () => {
    expect(signerOpCount({ ...counted, error: true, loaded: 0 })).toEqual({ kind: 'unavailable' });
  });

  it('is a real zero only when a supported relay served an empty page', () => {
    expect(signerOpCount({ ...counted, loaded: 0 })).toEqual({
      kind: 'counted',
      loaded: 0,
      partial: false,
    });
  });
});

describe('signerOpCountLabel', () => {
  it('writes the pager’s own grammar for a paged enumeration', () => {
    expect(signerOpCountLabel({ kind: 'counted', loaded: 20, partial: true })).toBe(
      '20 loaded · paged',
    );
    expect(signerOpCountLabel({ kind: 'counted', loaded: 3, partial: false })).toBe('3');
  });

  // no state may render as a number, or as anything a reader could take for one
  it('never renders a non-count as a figure', () => {
    for (const label of [
      signerOpCountLabel({ kind: 'unsupported' }),
      signerOpCountLabel({ kind: 'unavailable' }),
      signerOpCountLabel({ kind: 'checking' }),
    ]) {
      expect(label).not.toMatch(/\d/);
    }
  });

  it('says which non-answer it is', () => {
    expect(signerOpCountLabel({ kind: 'unsupported' })).toBe('this relay cannot say');
    expect(signerOpCountLabel({ kind: 'unavailable' })).toBe('unknown');
    expect(signerOpCountLabel({ kind: 'checking' })).toBe('checking…');
  });
});

// -----------------------------------------------------------------------------
// THE ROWS — index metadata → the table's four columns
// -----------------------------------------------------------------------------

describe('signed-op rows', () => {
  const body = {
    operations: [
      {
        cid: 'bafyop1',
        kind: 'content-op',
        chainId: 'bafycontent1',
        createdAt: '2026-08-01T00:00:00.000Z',
        ingestedAt: '2026-08-01T00:00:03.000Z',
      },
      {
        cid: 'bafyop2',
        kind: 'credential',
        chainId: 'did:dfos:issuer',
        createdAt: '2026-07-01T00:00:00.000Z',
        ingestedAt: '2026-07-01T00:00:02.000Z',
      },
    ],
    next: 'cursor-1',
  };

  it('maps a page to the four columns the table renders', () => {
    expect(indexOpRows(toOperationRows(body))).toEqual([
      {
        cid: 'bafyop1',
        kind: 'content-op',
        chainId: 'bafycontent1',
        type: '',
        createdAt: '2026-08-01T00:00:00.000Z',
      },
      {
        cid: 'bafyop2',
        kind: 'credential',
        chainId: 'did:dfos:issuer',
        type: '',
        createdAt: '2026-07-01T00:00:00.000Z',
      },
    ]);
  });

  // the route carries no JWS, so there is no create/update/delete verb to show —
  // the cell stays empty rather than guessing one
  it('invents no payload verb the route does not carry', () => {
    expect(indexOpRows(toOperationRows(body)).every((r) => r.type === '')).toBe(true);
  });

  it('drops a row that names no operation — it could not be linked', () => {
    expect(toOperationRows({ operations: [{ kind: 'artifact' }] })).toEqual([]);
    expect(toOperationRows({ operations: 'nope' })).toEqual([]);
    expect(toOperationRows(null)).toEqual([]);
  });

  // a relay-asserted kind is a routing hint, never a verification input, so an
  // unrecognized one degrades into the standalone-op bucket
  it('buckets an unknown kind rather than throwing', () => {
    const [row] = indexOpRows(
      toOperationRows({ operations: [{ cid: 'x', kind: 'something-new' }] }),
    );
    expect(row?.kind).toBe('artifact');
  });
});

describe('chainKindOf — what the chain column links to', () => {
  it('reads an identity chain, a content chain, and a bare op CID apart', () => {
    expect(chainKindOf('did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e')).toBe('identity');
    expect(chainKindOf('bafyreiabc')).toBe('op');
    expect(chainKindOf('01HZZZ-content-id')).toBe('content');
  });

  // the index's honest blank — a row with no chainId gets a dash, never a link
  // to whatever the empty string would resolve to
  it('is none for a row carrying no chain at all', () => {
    expect(chainKindOf('')).toBe('none');
  });
});
