/*

  PROVENANCE LINE — who answered, whether the set agreed, cache origin

  A compact honest line under a verified answer. The full multi-relay
  diff/quorum panel builds on this.

*/

import type { Provenance } from '@metalabel/dfos-client';

const hostOf = (url: string): string => url.replace(/^https?:\/\//, '');

export const ProvenanceLine = (props: { provenance: Provenance }) => {
  const p = props.provenance;
  const okCount = p.responses.filter((r) => r.ok).length;
  return (
    <div class="ck-note" style={{ marginTop: 8 }}>
      <span class="lbl">provenance</span> {p.fromCache ? 'cache-first (verified prefix), ' : ''}
      {p.answeredBy ? `answered by ${hostOf(p.answeredBy)}` : 'no relay answered'}
      {p.responses.length > 1 ? (
        <>
          {' '}
          · {okCount}/{p.responses.length} relays responded ·{' '}
          {p.agreed ? 'set agreed' : <span class="err">set DISAGREED</span>}
        </>
      ) : null}
    </div>
  );
};
