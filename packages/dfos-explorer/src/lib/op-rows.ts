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
