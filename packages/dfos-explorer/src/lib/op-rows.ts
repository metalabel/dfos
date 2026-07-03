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
