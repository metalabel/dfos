/*

  CONTENT CHIP — the standard rendering of a contentId in any row context

  A contentId is a hash. Where one appears in a feed, a table, or a cross-
  reference, this resolves it to the chain's current verified document label
  (lib/content-labels.ts) and hydrates in place as the answer lands. Until then —
  and forever, for a document with no title or snippet — it renders exactly what
  the explorer rendered before: the short contentId, linked.

  The label arrives in two tiers, and the chip shows which one it is holding. The
  relay index's public projected title can answer first and renders in the amber
  `.attr` tier. The verified resolve (content fold → anonymous current-document
  bytes → committed-CID re-hash) replaces it with plain ink. Body and description
  snippets are quoted so excerpts cannot be mistaken for document titles.

*/

import { useContentLabel } from '../lib/content-labels';
import { short } from '../lib/format';

export const ContentChip = (props: { id: string; full?: boolean }) => {
  const { label, tier } = useContentLabel(props.id);
  const title = !label
    ? props.id
    : tier === 'verified'
      ? `${props.id} — document verified in your tab (bytes re-hash to the committed CID)`
      : `${props.id} — title projected by the relay index (attributed); verifying…`;
  return (
    <a class="content-chip" href={`#/content/${props.id}`} title={title}>
      {label ? (
        <span class={tier === 'verified' ? 'did-name' : 'attr'}>
          {label.quoted ? `“${label.text}”` : label.text}
        </span>
      ) : props.full ? (
        props.id
      ) : (
        short(props.id, 14, 6)
      )}
      {label && props.full ? (
        <>
          {' '}
          <span class="muted">{props.id}</span>
        </>
      ) : null}
    </a>
  );
};
