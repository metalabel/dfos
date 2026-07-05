/*

  INDEX-LIGHT UI PRIMITIVES — the attributed→verified badge + a viewport trigger

  Shared by the browse and home surfaces that render relay-index rows. The badge
  reads a row's live verify-queue status; the ref hook enqueues a row's chain for
  a proof-plane fold the first time it scrolls into view (viewport-priority), so
  only the rows the eye reaches are ever folded.

*/

import { useEffect, useRef } from 'preact/hooks';
import { GLOSSARY } from '../lib/glossary';
import { enqueueVerify, useVerifyStatus, type VerifyKind } from '../lib/verify-queue';
import { Badge, Term } from './ui';

/**
 * A ref to attach to a row element. The first time the element intersects the
 * viewport, its chain is enqueued for verification (then the observer detaches).
 * Where IntersectionObserver is unavailable, the row enqueues eagerly on mount —
 * correctness over laziness.
 */
export const useVerifyOnVisible = <T extends HTMLElement>(kind: VerifyKind, chainId: string) => {
  const ref = useRef<T | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined') {
      enqueueVerify(kind, chainId);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            enqueueVerify(kind, chainId);
            io.disconnect();
            return;
          }
        }
      },
      { rootMargin: '100px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [kind, chainId]);
  return ref;
};

/** The honest framing shown atop an index-light browse surface: rows are relay
 *  hints, promoted as your tab folds them, and full sync is the audit stance. */
export const IndexLightNote = () => (
  <div class="ck-note" style={{ marginBottom: 8 }}>
    Instant rows from the relay’s <Term word="index" def={GLOSSARY['indexLight'] ?? ''} /> — each is
    an <b>attributed</b> hint, promoted to <b>verified</b> as it scrolls into view and your tab
    folds its chain. Completeness is never proven; <b>sync the full log</b> for the audit stance.
  </div>
);

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
