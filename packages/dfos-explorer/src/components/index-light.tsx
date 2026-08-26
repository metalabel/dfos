/*

  INDEX-LIGHT UI PRIMITIVES — the attributed→verified badge + a viewport trigger

  Shared by the browse and home surfaces that render relay-index rows. The badge
  reads a row's live verify-queue status; the ref hook enqueues a row's chain for
  a proof-plane fold the first time it scrolls into view (viewport-priority), so
  only the rows the eye reaches are ever folded.

*/

import type { IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useRef } from 'preact/hooks';
import type { ContentLabelTier } from '../lib/content-labels';
import { useDidProfile } from '../lib/did-profiles';
import type { DocLabel } from '../lib/doc-label';
import { GLOSSARY } from '../lib/glossary';
import { projectedName } from '../lib/index-point';
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
    on its <b>structural facts</b> (signatures, op count, deletion). A projected{' '}
    <span class="attr">name/title</span> stays relay-asserted on its own track until the document
    bytes it names re-hash to the CID the chain commits to — then it turns{' '}
    <span class="did-name">plain</span>, and a chain whose bytes say nothing falls back to its id.
    Completeness is never proven; a <b>deep sync</b> folds the whole log for the audit stance (it
    alone catches omission).
  </div>
);

/**
 * A content chain's standardized display name — the shared render of a
 * {@link DocLabel} (see lib/doc-label.ts). A body/description snippet is quoted
 * so an excerpt can never be mistaken for a document's title; an unresolvable
 * row falls back to the short contentId. Used identically on home recent
 * activity, the document browser, search hits, and the identity actor ledger.
 *
 * `tier` carries WHICH TIER the label came from, and it decides the ink: the
 * amber `.attr` of every relay projection, or the plain ink a verified answer
 * earns (bytes this tab re-hashed to the chain's committed document CID) — the
 * same two-tone grammar ContentChip and DidChip use, so one label reads the same
 * whether it arrives in a table cell or a chip. Omitted, the label is amber: the
 * LOCAL-index tables have no verified tier to promote into.
 */
export const DocName = (props: { label: DocLabel; tier?: ContentLabelTier }) => {
  const { label } = props;
  if (label.kind === 'id') return <span class="cid">{label.text}</span>;
  const verified = props.tier === 'verified';
  return (
    <span
      class={verified ? 'did-name' : 'attr'}
      title={
        props.tier === undefined
          ? undefined
          : verified
            ? 'derived from document bytes that re-hash to the committed CID in your tab'
            : 'title projected by the relay index (attributed); verifying…'
      }
    >
      {label.quoted ? `“${label.text}”` : label.text}
    </span>
  );
};

/**
 * The name cell of a relay-index IDENTITY row — the sibling of {@link DocName},
 * and the same three beats a DidChip runs: the relay's projected public name
 * (amber), replaced in place by the name re-derived from the identity's own
 * signed profile bytes (plain ink). `projectedName` applies the honest-
 * degradation rule to the row the page already holds, so a name the relay does
 * not mark public never reaches the screen even as the amber beat, and handing
 * it in spares the point lookup a bare chip would spend.
 *
 * `seen` gates the verified resolve on the row having scrolled into view, like
 * every other index row. A row with nothing to show says so plainly rather than
 * falling back to its DID — the DID has its own column here.
 */
export const IdentityName = (props: { row: IndexIdentityRow; seen: boolean }) => {
  const { profile, tier } = useDidProfile(props.row.did, props.seen, projectedName(props.row));
  if (!profile) return <span class="muted">— no public profile</span>;
  return (
    <span
      class={tier === 'verified' ? 'did-name' : 'attr'}
      title={
        tier === 'verified'
          ? 'public profile, verified in your tab'
          : 'name projected by the relay index (attributed); verifying…'
      }
    >
      {profile.name}
    </span>
  );
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
