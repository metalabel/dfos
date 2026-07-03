/*

  OP TIMELINE — genesis → head, with the head glowing

*/

import type { OpRow } from '../lib/op-rows';
import { Copyable, KidLink, OpLink } from './ui';

export const OpType = (props: { type: string }) => (
  <span class={`op-type ${props.type}`}>{props.type || '?'}</span>
);

export const OpTimeline = (props: {
  rows: OpRow[];
  headCid?: string | undefined;
  currentCid?: string | undefined;
  showSigner?: boolean;
}) => (
  <ul class="tl">
    {props.rows.map((row) => {
      const isHead = row.cid === props.headCid;
      const isCurrent = row.cid === props.currentCid;
      return (
        <li key={row.cid} class={`${isHead ? 'head' : ''} ${isCurrent ? 'cur' : ''}`}>
          <span class="node" />
          <div style={{ flex: 1 }}>
            <OpType type={row.type} />{' '}
            {isCurrent ? (
              <span class="lbl" style={{ color: 'var(--ink)' }}>
                ▸ this op
              </span>
            ) : null}{' '}
            {isHead ? (
              <span class="lbl" style={{ color: 'var(--ok)' }}>
                head
              </span>
            ) : null}
            <span class="muted"> {row.createdAt}</span>
            <br />
            <span class="lbl">op</span>{' '}
            {isCurrent ? <Copyable value={row.cid} /> : <OpLink cid={row.cid} />}
            {props.showSigner !== false ? (
              <>
                {' '}
                &nbsp; <span class="lbl">signer</span> <KidLink kid={row.kid} />
              </>
            ) : null}
          </div>
        </li>
      );
    })}
  </ul>
);
