/**
 * Canonical fold — linearization, generic LWW-Map, and the index/v1 fold.
 *
 * These are pure functions over already-verified operations, so the fixtures
 * here are plain { cid, createdAt, document } records — no signing needed.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  byteCompare,
  compareHeadPreference,
  foldIndexV1,
  foldLwwMap,
  INDEX_V1_SCHEMA,
  linearize,
  type FoldOperation,
  type IndexDelta,
  type LwwDelta,
} from '../src/fold';

// --- helpers ----------------------------------------------------------------

/** Build an index/v1 fold operation from ordering keys + a deltas array. */
const idxOp = (cid: string, createdAt: string, deltas: unknown[]): FoldOperation => ({
  cid,
  createdAt,
  document: { $schema: INDEX_V1_SCHEMA, deltas },
});

/** Fold a set of ops and return the map as a plain object for easy assertion. */
const foldToObject = (ops: FoldOperation[]): Record<string, unknown> =>
  Object.fromEntries(foldIndexV1(ops));

/** Every permutation of a small array (used to prove order-independence). */
const permutations = <T>(items: T[]): T[][] => {
  if (items.length <= 1) return [items];
  const out: T[][] = [];
  for (let i = 0; i < items.length; i++) {
    const rest = [...items.slice(0, i), ...items.slice(i + 1)];
    for (const p of permutations(rest)) out.push([items[i]!, ...p]);
  }
  return out;
};

// --- byteCompare ------------------------------------------------------------

describe('byteCompare', () => {
  it('is a byte-wise total order returning -1 | 0 | 1', () => {
    expect(byteCompare('a', 'b')).toBe(-1);
    expect(byteCompare('b', 'a')).toBe(1);
    expect(byteCompare('a', 'a')).toBe(0);
    // uppercase sorts before lowercase (code-point order), unlike locale collation
    expect(byteCompare('Z', 'a')).toBe(-1);
  });
});

// --- linearize --------------------------------------------------------------

describe('linearize', () => {
  const a: FoldOperation = { cid: 'bafyaaa', createdAt: '2026-01-01T00:00:00.000Z', document: {} };
  const b: FoldOperation = { cid: 'bafybbb', createdAt: '2026-01-02T00:00:00.000Z', document: {} };
  const c: FoldOperation = { cid: 'bafyccc', createdAt: '2026-01-03T00:00:00.000Z', document: {} };

  it('orders by createdAt ascending', () => {
    expect(linearize([c, a, b]).map((o) => o.cid)).toEqual(['bafyaaa', 'bafybbb', 'bafyccc']);
  });

  it('tiebreaks equal createdAt by CID ascending (head-preferred sorts LAST)', () => {
    const at = '2026-01-01T00:00:00.000Z';
    const lo: FoldOperation = { cid: 'bafyaaa', createdAt: at, document: {} };
    const hi: FoldOperation = { cid: 'bafyzzz', createdAt: at, document: {} };
    expect(linearize([hi, lo]).map((o) => o.cid)).toEqual(['bafyaaa', 'bafyzzz']);
  });

  it('is deterministic across all input permutations', () => {
    const canonical = linearize([a, b, c]).map((o) => o.cid);
    for (const perm of permutations([a, b, c])) {
      expect(linearize(perm).map((o) => o.cid)).toEqual(canonical);
    }
  });

  it('does not mutate its input', () => {
    const input = [c, a, b];
    linearize(input);
    expect(input.map((o) => o.cid)).toEqual(['bafyccc', 'bafyaaa', 'bafybbb']);
  });
});

// --- consistency: linearize LAST === head selection -------------------------

describe('linearize / head-selection consistency', () => {
  /**
   * Replicate the web relay's `selectDeterministicHead`: tips (ops with no
   * child) sorted by `compareHeadPreference`, tips[0] is the head. Then assert
   * the last element of the full-log linearization equals that head. This is
   * the invariant that lets the branch-inclusive fold apply the head-preferred
   * op LAST (last-applied wins) using the SAME comparator head selection uses.
   */
  const headOf = (
    ops: { cid: string; createdAt: string; previousOperationCID?: string }[],
  ): string => {
    const hasChild = new Set(
      ops.map((o) => o.previousOperationCID).filter((p): p is string => typeof p === 'string'),
    );
    const tips = ops.filter((o) => !hasChild.has(o.cid));
    tips.sort(compareHeadPreference);
    return tips[0]!.cid;
  };

  it('linearize(...).at(-1) is the deterministically-selected head — linear chain', () => {
    const ops = [
      { cid: 'bafyg', createdAt: '2026-01-01T00:00:00.000Z' },
      { cid: 'bafyh', createdAt: '2026-01-02T00:00:00.000Z', previousOperationCID: 'bafyg' },
      { cid: 'bafyi', createdAt: '2026-01-03T00:00:00.000Z', previousOperationCID: 'bafyh' },
    ];
    const foldOps: FoldOperation[] = ops.map((o) => ({ ...o, document: {} }));
    expect(linearize(foldOps).at(-1)!.cid).toBe(headOf(ops));
  });

  it('linearize(...).at(-1) is the head across a fork — highest createdAt branch wins', () => {
    // genesis, then two concurrent forks; the later-timestamped fork is head
    const ops = [
      { cid: 'bafyg', createdAt: '2026-01-01T00:00:00.000Z' },
      { cid: 'bafyx', createdAt: '2026-01-02T00:00:00.000Z', previousOperationCID: 'bafyg' },
      { cid: 'bafyy', createdAt: '2026-01-05T00:00:00.000Z', previousOperationCID: 'bafyg' },
    ];
    const foldOps: FoldOperation[] = ops.map((o) => ({ ...o, document: {} }));
    expect(headOf(ops)).toBe('bafyy');
    expect(linearize(foldOps).at(-1)!.cid).toBe('bafyy');
  });

  it('linearize(...).at(-1) is the head when concurrent tips tie on createdAt (CID tiebreak)', () => {
    const at = '2026-01-05T00:00:00.000Z';
    const ops = [
      { cid: 'bafyg', createdAt: '2026-01-01T00:00:00.000Z' },
      { cid: 'bafyx', createdAt: at, previousOperationCID: 'bafyg' },
      { cid: 'bafyz', createdAt: at, previousOperationCID: 'bafyg' },
    ];
    const foldOps: FoldOperation[] = ops.map((o) => ({ ...o, document: {} }));
    // higher CID wins the tiebreak for head; same op sorts last in linearize
    expect(headOf(ops)).toBe('bafyz');
    expect(linearize(foldOps).at(-1)!.cid).toBe('bafyz');
  });
});

// --- generic LWW-Map --------------------------------------------------------

describe('foldLwwMap', () => {
  it('applies set/remove in order, last-write-wins per key', () => {
    const deltas: LwwDelta<string>[] = [
      { op: 'set', key: 'a', value: 'a1' },
      { op: 'set', key: 'b', value: 'b1' },
      { op: 'set', key: 'a', value: 'a2' },
      { op: 'remove', key: 'b' },
    ];
    expect(Object.fromEntries(foldLwwMap(deltas))).toEqual({ a: 'a2' });
  });

  it('a set after a remove re-adds the key', () => {
    const deltas: LwwDelta<string>[] = [
      { op: 'set', key: 'a', value: 'a1' },
      { op: 'remove', key: 'a' },
      { op: 'set', key: 'a', value: 'a3' },
    ];
    expect(Object.fromEntries(foldLwwMap(deltas))).toEqual({ a: 'a3' });
  });
});

// --- index/v1 fold ----------------------------------------------------------

describe('foldIndexV1', () => {
  it('folds set deltas into an entry map with metadata values', () => {
    const ops = [
      idxOp('bafy1', '2026-01-01T00:00:00.000Z', [
        { op: 'set', key: 'did:dfos:aaa', value: { label: 'Alpha', order: 1 } },
      ]),
      idxOp('bafy2', '2026-01-02T00:00:00.000Z', [
        { op: 'set', key: 'did:dfos:bbb', value: { label: 'Beta', order: 2 } },
      ]),
    ];
    expect(foldToObject(ops)).toEqual({
      'did:dfos:aaa': { label: 'Alpha', order: 1 },
      'did:dfos:bbb': { label: 'Beta', order: 2 },
    });
  });

  it('treats a set with no value as the degenerate set-membership case ({})', () => {
    const ops = [idxOp('bafy1', '2026-01-01T00:00:00.000Z', [{ op: 'set', key: 'k' }])];
    expect(foldToObject(ops)).toEqual({ k: {} });
  });

  it('carries an array of deltas per document', () => {
    const ops = [
      idxOp('bafy1', '2026-01-01T00:00:00.000Z', [
        { op: 'set', key: 'a', value: {} },
        { op: 'set', key: 'b', value: {} },
        { op: 'remove', key: 'a' },
      ]),
    ];
    expect(foldToObject(ops)).toEqual({ b: {} });
  });

  describe('remove-vs-set LWW ordering', () => {
    const base = (removeAt: string, setAt: string): FoldOperation[] => [
      idxOp('bafyset1', '2026-01-01T00:00:00.000Z', [
        { op: 'set', key: 'k', value: { label: 'first' } },
      ]),
      idxOp('bafyrem', removeAt, [{ op: 'remove', key: 'k' }]),
      idxOp('bafyset2', setAt, [{ op: 'set', key: 'k', value: { label: 'latest' } }]),
    ];

    it('a later set re-adds after an earlier remove', () => {
      // remove @ t2, set @ t3  → key present with the latest value
      expect(foldToObject(base('2026-01-02T00:00:00.000Z', '2026-01-03T00:00:00.000Z'))).toEqual({
        k: { label: 'latest' },
      });
    });

    it('a later remove wins over an earlier set', () => {
      // set2 @ t2, remove @ t3 → key absent
      expect(foldToObject(base('2026-01-03T00:00:00.000Z', '2026-01-02T00:00:00.000Z'))).toEqual(
        {},
      );
    });
  });

  describe('unknown delta shapes are skipped deterministically', () => {
    it('skips unknown op, non-string key, and non-object set value; keeps valid deltas', () => {
      const ops = [
        idxOp('bafy1', '2026-01-01T00:00:00.000Z', [
          { op: 'set', key: 'good', value: { label: 'ok' } },
          { op: 'toggle', key: 'weird' }, // unknown op
          { op: 'set', key: 42 }, // non-string key
          { op: 'set', key: 'scalar', value: 'not-an-object' }, // non-object value
          { op: 'remove' }, // missing key
          { op: 'set', key: 'member' }, // valid degenerate set
          'not-a-delta', // not an object
          { op: 'set', key: 'forward', value: { label: 'v', futureField: true } }, // unknown value key preserved
        ]),
      ];
      expect(foldToObject(ops)).toEqual({
        good: { label: 'ok' },
        member: {},
        forward: { label: 'v', futureField: true },
      });
    });

    it('skips documents whose $schema is not index/v1 and non-object documents', () => {
      const ops: FoldOperation[] = [
        idxOp('bafy1', '2026-01-01T00:00:00.000Z', [{ op: 'set', key: 'kept', value: {} }]),
        {
          cid: 'bafy2',
          createdAt: '2026-01-02T00:00:00.000Z',
          document: { $schema: 'x', deltas: [{ op: 'set', key: 'ignored', value: {} }] },
        },
        { cid: 'bafy3', createdAt: '2026-01-03T00:00:00.000Z', document: null }, // e.g. a delete op
      ];
      expect(foldToObject(ops)).toEqual({ kept: {} });
    });
  });

  describe('fork convergence', () => {
    // Two branches appended concurrently to the same index chain. Under the
    // branch-inclusive canonical fold, every ingest order folds to one map.
    const genesis = idxOp('bafygen', '2026-01-01T00:00:00.000Z', [
      { op: 'set', key: 'shared', value: { label: 'root' } },
    ]);
    const branchA = idxOp('bafyaaa', '2026-01-02T00:00:00.000Z', [
      { op: 'set', key: 'a', value: { label: 'from-A' } },
      { op: 'set', key: 'shared', value: { label: 'A-wins?' } },
    ]);
    const branchB = idxOp('bafybbb', '2026-01-03T00:00:00.000Z', [
      { op: 'set', key: 'b', value: { label: 'from-B' } },
      { op: 'set', key: 'shared', value: { label: 'B-wins' } },
    ]);

    it('produces the same map under every ingest order', () => {
      const canonical = foldToObject([genesis, branchA, branchB]);
      for (const perm of permutations([genesis, branchA, branchB])) {
        expect(foldToObject(perm)).toEqual(canonical);
      }
    });

    it('the highest-linearized branch wins a contended key', () => {
      // branchB has the later createdAt, so its `shared` write is applied last
      expect(foldToObject([branchB, branchA, genesis])).toEqual({
        shared: { label: 'B-wins' },
        a: { label: 'from-A' },
        b: { label: 'from-B' },
      });
    });
  });
});

// --- golden example: examples/index/ -----------------------------------------

describe('examples/index golden fixture', () => {
  /**
   * Drift guard for the worked example — folds examples/index/chain.json
   * through foldIndexV1 and asserts the result matches the hand-written
   * projected-state.json (entries AND head). If either file or the fold
   * semantics change, this fails.
   */
  const exampleDir = resolve(import.meta.dirname, '../../../examples/index');
  const chain = JSON.parse(readFileSync(resolve(exampleDir, 'chain.json'), 'utf-8')) as {
    operations: {
      sequence: number;
      operationCID: string;
      previousOperationCID?: string;
      createdAt: string;
      document: unknown;
    }[];
  };
  const projected = JSON.parse(
    readFileSync(resolve(exampleDir, 'projected-state.json'), 'utf-8'),
  ) as { entries: Record<string, unknown>; head: string };

  const foldOps: FoldOperation[] = chain.operations.map((op) => ({
    cid: op.operationCID,
    createdAt: op.createdAt,
    document: op.document,
  }));

  it('folds chain.json to the projected-state.json entries', () => {
    expect(Object.fromEntries(foldIndexV1(foldOps))).toEqual(projected.entries);
  });

  it('folds to the same entries under every ingest order', () => {
    for (const perm of permutations(foldOps)) {
      expect(Object.fromEntries(foldIndexV1(perm))).toEqual(projected.entries);
    }
  });

  it('selects the projected-state.json head (and linearize agrees)', () => {
    const hasChild = new Set(
      chain.operations
        .map((op) => op.previousOperationCID)
        .filter((p): p is string => typeof p === 'string'),
    );
    const tips = chain.operations
      .filter((op) => !hasChild.has(op.operationCID))
      .map((op) => ({ cid: op.operationCID, createdAt: op.createdAt }));
    tips.sort(compareHeadPreference);
    expect(tips[0]!.cid).toBe(projected.head);
    expect(linearize(foldOps).at(-1)!.cid).toBe(projected.head);
  });
});

// type-only smoke: IndexDelta is usable by consumers
const _delta: IndexDelta = { op: 'set', key: 'k', value: { label: 'x' } };
void _delta;
