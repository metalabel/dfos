/*

  PROVENANCE — who answered, whether the set agreed, cache origin

  Two renders over the same trust-as-data: a compact line under a verified
  answer, and the full per-relay response table (digests + agreement) — the
  seed of the multi-relay diff. Agreement across an untrusted set is evidence
  of convergence, never proof of completeness.

*/

import type { Provenance } from '@metalabel/dfos-client';
import { short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { Panel, Term } from './ui';

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

export const ProvenancePanel = (props: { provenance: Provenance }) => {
  const p = props.provenance;
  if (p.responses.length === 0) return null;
  // group by digest to show agreement structure
  const digests = new Map<string, number>();
  for (const r of p.responses)
    if (r.ok && r.digest) digests.set(r.digest, (digests.get(r.digest) ?? 0) + 1);
  return (
    <Panel
      title="provenance"
      right={
        <span class="lbl">
          <Term word="quorum" def={GLOSSARY['quorum'] ?? ''} /> · trust as data
        </span>
      }
    >
      <table>
        <thead>
          <tr>
            <th>relay</th>
            <th>answered</th>
            <th>response digest</th>
          </tr>
        </thead>
        <tbody>
          {p.responses.map((r) => (
            <tr key={r.url}>
              <td>
                {hostOf(r.url)}
                {r.url === p.answeredBy ? <span class="lbl"> · answered</span> : null}
              </td>
              <td>
                {r.ok ? (
                  <span style={{ color: 'var(--ok)' }}>yes</span>
                ) : (
                  <span class="err">no</span>
                )}
              </td>
              <td class="muted">{r.digest ? short(r.digest, 10, 6) : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div class="ck-note" style={{ marginTop: 8 }}>
        {p.fromCache ? 'Served cache-first from the verified prefix. ' : ''}
        {p.agreed ? (
          digests.size > 1 ? (
            <span class="err">
              relays returned {digests.size} distinct answers — quorum was still met, but the set
              has not converged
            </span>
          ) : (
            'All responding relays returned byte-identical answers.'
          )
        ) : (
          <span class="err">
            The relay set did NOT meet the agreement threshold — this answer is from a single
            relay's view.
          </span>
        )}{' '}
        Agreement is convergence evidence, never completeness proof.
      </div>
    </Panel>
  );
};
