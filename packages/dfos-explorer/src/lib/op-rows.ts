/*

  OP ROWS — decode raw log entries into display rows

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

export interface OpRow {
  cid: string;
  jwsToken: string;
  type: string;
  createdAt: string;
  kid: string;
}

export const toOpRow = (entry: { cid: string; jwsToken: string }): OpRow => {
  let type = '';
  let createdAt = '';
  let kid = '';
  const decoded = decodeJwsUnsafe(entry.jwsToken);
  if (decoded) {
    if (typeof decoded.payload['type'] === 'string') type = decoded.payload['type'];
    if (typeof decoded.payload['createdAt'] === 'string') createdAt = decoded.payload['createdAt'];
    if (typeof decoded.header.kid === 'string') kid = decoded.header.kid;
  }
  return { cid: entry.cid, jwsToken: entry.jwsToken, type, createdAt, kid };
};

export const toOpRows = (entries: { cid: string; jwsToken: string }[]): OpRow[] =>
  entries.map(toOpRow);

/** One numbered row of an operation history: `n` is the op's ABSOLUTE position
 *  on the chain, 1 = genesis, and it does not move when the display order does. */
export interface NumberedOpRow {
  n: number;
  row: OpRow;
}

/** A chain's rows as a history table reads them: newest first, each keeping the
 *  absolute position it holds on the chain. The log arrives genesis → head, so
 *  the op a reader came for is the last row of a long list; reversed, it is the
 *  first — and `n` is what keeps "op 3" meaning op 3 either way. Pure. */
export const newestFirst = (rows: readonly OpRow[]): NumberedOpRow[] =>
  rows.map((row, i) => ({ n: i + 1, row })).reverse();

/** Where one op sits on a folded chain. */
export interface OpPlacement {
  present: boolean;
  isHead: boolean;
  /** 1-based position in the log; 0 when absent. */
  position: number;
  /** The op's signed parent; `null` for a create. */
  previous: string | null;
  /** Every op in the log that names this op as its parent — several on a fork. */
  next: string[];
}

const parentOf = (row: OpRow): string | null => {
  if (row.type === 'create') return null;
  const prev = decodeJwsUnsafe(row.jwsToken)?.payload['previousOperationCID'];
  return typeof prev === 'string' ? prev : null;
};

/**
 * Place an op on a folded chain. A content log is branch-inclusive, so neither
 * the last row nor the adjacent row means anything: the head is the one the
 * fold SELECTED (`headCid`), previous is the op's signed parent, and next is
 * every op that names it as theirs. Pure.
 */
export const placeOp = (rows: readonly OpRow[], cid: string, headCid: string): OpPlacement => {
  const index = rows.findIndex((r) => r.cid === cid);
  const row = rows[index];
  return {
    present: index >= 0,
    isHead: index >= 0 && cid === headCid,
    position: index + 1,
    previous: row ? parentOf(row) : null,
    next: rows.filter((r) => parentOf(r) === cid).map((r) => r.cid),
  };
};
