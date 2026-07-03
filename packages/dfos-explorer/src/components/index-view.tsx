/*

  INDEX PANEL — the canonical fold, visible

  Detects index/v1 content chains and folds the LWW-Map in the tab from every
  op's committed document (branch-inclusive — forks converge). Entries link
  onward by ref shape; coverage gaps (unreadable docs) are reported, never
  hidden.

*/

import { useEffect, useState } from 'preact/hooks';
import { short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { foldIndexChain, type FoldedIndex, type IndexEntry } from '../lib/index-fold';
import type { OpRow } from '../lib/op-rows';
import { getRelays } from '../lib/relays';
import { dispatchInput, routeFor } from '../lib/resolve-input';
import { OpLink, Panel, Pill, Term } from './ui';

const RefLink = (props: { refValue: string }) => {
  const target = dispatchInput(props.refValue);
  if (!target) return <span class="muted">{short(props.refValue, 20, 8)}</span>;
  return (
    <a href={routeFor(target)} title={props.refValue}>
      {short(props.refValue, 16, 6)}
    </a>
  );
};

const sortEntries = (entries: Map<string, IndexEntry>): [string, IndexEntry][] =>
  [...entries.entries()].sort((a, b) => {
    const ao = typeof a[1].order === 'number' ? a[1].order : Number.POSITIVE_INFINITY;
    const bo = typeof b[1].order === 'number' ? b[1].order : Number.POSITIVE_INFINITY;
    return ao - bo || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
  });

export const IndexPanel = (props: { contentId: string; rows: OpRow[] }) => {
  const [folded, setFolded] = useState<FoldedIndex | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let dead = false;
    setFolded(null);
    setError('');
    void foldIndexChain({ contentId: props.contentId, rows: props.rows, relays: getRelays() })
      .then((result) => {
        if (!dead) setFolded(result);
      })
      .catch((e) => {
        if (!dead) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      dead = true;
    };
  }, [props.contentId, props.rows]);

  return (
    <Panel
      title={
        <>
          index state{' '}
          {folded ? (
            folded.gaps.length === 0 ? (
              <Pill state="ok">folded locally · {folded.entries.size} entries</Pill>
            ) : (
              <Pill state="warn">partial fold · {folded.gaps.length} unreadable doc(s)</Pill>
            )
          ) : (
            <Pill state="pending">folding…</Pill>
          )}
        </>
      }
      orient={
        <>
          An <Term word="index" def={GLOSSARY['index'] ?? ''} /> — an LWW-Map of content refs
          resolved by the <Term word="canonical fold" def={GLOSSARY['canonicalFold'] ?? ''} />.{' '}
          <b>Branch-inclusive: forks converge to the same map in any arrival order.</b>
        </>
      }
    >
      {error ? (
        <span class="err">{error}</span>
      ) : !folded ? (
        <span class="muted">fetching each op's committed document…</span>
      ) : (
        <>
          {folded.entries.size === 0 ? (
            <span class="muted">the fold resolves to an empty map</span>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ref</th>
                  <th>label</th>
                  <th>order</th>
                </tr>
              </thead>
              <tbody>
                {sortEntries(folded.entries).map(([key, entry]) => (
                  <tr key={key}>
                    <td>
                      <RefLink refValue={key} />
                    </td>
                    <td>
                      {typeof entry.label === 'string' ? entry.label : <span class="muted">—</span>}
                    </td>
                    <td class="muted">{typeof entry.order === 'number' ? entry.order : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {folded.gaps.length > 0 ? (
            <div class="ck-note" style={{ marginTop: 8 }}>
              <span class="err">coverage gap:</span> {folded.gaps.length} op document(s) could not
              be read ({folded.gaps.map((g) => `${short(g.opCid)} — ${g.reason}`).join('; ')}). The
              map above folds the READABLE docs only — it may differ from the complete fold.
            </div>
          ) : null}
          <details style={{ marginTop: 10 }}>
            <summary>delta history · {folded.docs.length} index doc(s)</summary>
            <div style={{ marginTop: 6 }}>
              {folded.docs.map((doc) => (
                <div key={doc.opCid} style={{ marginBottom: 8 }}>
                  <span class="lbl">op</span> <OpLink cid={doc.opCid} />{' '}
                  <span class="muted">{doc.createdAt}</span>
                  <ul class="checks" style={{ marginTop: 2 }}>
                    {doc.deltas.map((delta, i) => {
                      const d = delta as { op?: string; key?: string; value?: IndexEntry };
                      const known = d.op === 'set' || d.op === 'remove';
                      return (
                        <li key={i}>
                          <span class={`ck ${known ? (d.op === 'set' ? 'ok' : 'warn') : 'pend'}`}>
                            {d.op === 'set' ? '+' : d.op === 'remove' ? '−' : '·'}
                          </span>
                          <span class="ck-txt">
                            {known ? (
                              <>
                                {d.op}{' '}
                                {typeof d.key === 'string' ? <RefLink refValue={d.key} /> : '?'}
                                {d.value && typeof d.value.label === 'string' ? (
                                  <span class="muted"> · "{d.value.label}"</span>
                                ) : null}
                                {d.value && typeof d.value.order === 'number' ? (
                                  <span class="muted"> · order {d.value.order}</span>
                                ) : null}
                              </>
                            ) : (
                              <span class="muted">
                                unknown delta shape — skipped deterministically (forward compat)
                              </span>
                            )}
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          </details>
        </>
      )}
    </Panel>
  );
};
