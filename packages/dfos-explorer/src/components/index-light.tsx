/*

  INDEX-LIGHT UI PRIMITIVES — the attributed→verified badge + a viewport trigger

  Shared by the browse and home surfaces that render relay-index rows. The badge
  reads a row's live verify-queue status; the ref hook enqueues a row's chain for
  a proof-plane fold the first time it scrolls into view (viewport-priority), so
  only the rows the eye reaches are ever folded.

*/

import { useEffect, useRef } from 'preact/hooks';
import type { DocLabel } from '../lib/doc-label';
import { GLOSSARY } from '../lib/glossary';
import { enqueueVerify, useVerifyStatus, type VerifyKind } from '../lib/verify-queue';
import { Badge, Term } from './ui';

/**
 * A ref to attach to a row element. The first time the element intersects the
 * viewport, its chain is enqueued for verification (then the observer detaches).
 * Where IntersectionObserver is unavailable, the row enqueues eagerly on mount —
 * correctness over laziness.
 */
export const useVerifyOnVisible = <T extends HTMLElement>(
  kind: VerifyKind,
  chainId: string,
  hintOpCount?: number,
) => {
  const ref = useRef<T | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined') {
      enqueueVerify(kind, chainId, hintOpCount);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            enqueueVerify(kind, chainId, hintOpCount);
            io.disconnect();
            return;
          }
        }
      },
      { rootMargin: '100px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [kind, chainId, hintOpCount]);
  return ref;
};

/** The honest framing shown atop an index browse surface: rows stream live from
 *  the relay index, promoted as your tab folds them, and deep sync is the audit
 *  stance that detects omission. */
export const IndexLightNote = () => (
  <div class="ck-note" style={{ marginBottom: 8 }}>
    Live rows from the relay’s <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — each is an{' '}
    <b>attributed</b> hint. As a row scrolls into view your tab folds its chain and the badge greens
    on its <b>structural facts</b> (signatures, op count, deletion) — but a projected{' '}
    <span class="attr">name/title</span> stays a relay-asserted projection until its own bytes are
    re-verified. Completeness is never proven; a <b>deep sync</b> folds the whole log for the audit
    stance (it alone catches omission).
  </div>
);

/** A content chain's standardized display name — the shared render of a
 *  {@link DocLabel} (see lib/doc-label.ts). A title/name reads plain amber
 *  (attributed, like a projected name); a body/description snippet is quoted;
 *  an unresolvable row falls back to the short contentId. Used identically on
 *  home recent-activity, the document browser, and the identity actor-ledger. */
export const DocName = (props: { label: DocLabel }) => {
  const { label } = props;
  if (label.kind === 'id') return <span class="cid">{label.text}</span>;
  return <span class="attr">{label.quoted ? `“${label.text}”` : label.text}</span>;
};

/** The one badge vocabulary for an index-light row's verification tier. */
export const VerifyBadge = (props: { kind: VerifyKind; chainId: string }) => {
  const rec = useVerifyStatus(props.kind, props.chainId);
  if (rec.status === 'verified') return <Badge state="ok">verified</Badge>;
  if (rec.status === 'error') return <Badge state="bad">unverifiable</Badge>;
  if (rec.status === 'verifying') {
    return (
      <span class="badge warn">
        <span class="spin">◍</span> verifying
      </span>
    );
  }
  return <Badge state="warn">attributed</Badge>;
};
