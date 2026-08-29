/*

  OP TABLE — a chain's operation history, dense

  The same rows lib/op-rows.ts decodes, read as a ledger rather than a bulleted
  list: one line per operation, five columns, scannable down each of them. The
  bulleted timeline stays where it earns its shape — components/timeline.tsx
  places ONE op among its neighbours on the op page, and the domain view walks a
  short carried log — but a chain's whole history is a table.

  NEWEST FIRST, and numbered absolutely. The log arrives genesis → head, so the
  operation a reader came for sits at the bottom of a long list; reversed, it is
  the first row, and the `#` column keeps op 3 meaning op 3 either way. Paging is
  client-side over rows this tab already folded (lib/paging.ts) — twenty at a
  time, the same control every other table uses.

  The SIGNER column shows the key, not the slot name (lib/key-identity.ts). A
  `kid` resolves to its public key where the view holds the signing identity's
  document, and renders as the kid it is where it does not.

*/

import { fmtStamp } from '../lib/format';
import { EMPTY_KEY_DIRECTORY, type KeyDirectory } from '../lib/key-identity';
import { newestFirst, type OpRow } from '../lib/op-rows';
import { useClientPager } from '../lib/paging';
import { OpType } from './timeline';
import { ClientPager, OpLink, SignerKey } from './ui';

export const OpTable = (props: {
  rows: OpRow[];
  headCid?: string | undefined;
  /** identity documents this view holds, for resolving each op's signer key. */
  dir?: KeyDirectory | undefined;
}) => {
  const ordered = newestFirst(props.rows);
  const page = useClientPager(ordered);
  const dir = props.dir ?? EMPTY_KEY_DIRECTORY;
  return (
    <>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>kind</th>
            <th>operation</th>
            <th>signer key</th>
            <th>when</th>
          </tr>
        </thead>
        <tbody>
          {page.rows.map(({ n, row }) => (
            <tr key={row.cid}>
              <td class="n">
                {n}
                {row.cid === props.headCid ? (
                  <span class="lbl" style={{ color: 'var(--ok)' }}>
                    {' '}
                    head
                  </span>
                ) : null}
              </td>
              <td>
                <OpType type={row.type} />
              </td>
              <td>
                <OpLink cid={row.cid} />
              </td>
              <td>
                <SignerKey kid={row.kid} dir={dir} />
              </td>
              <td class="muted" title={row.createdAt}>
                {fmtStamp(row.createdAt)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <ClientPager page={page} noun="operations" />
    </>
  );
};
