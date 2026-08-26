/*

  DOC LABEL — one standardized name for a content chain, everywhere

  Home recent-activity, the document browser, and the identity actor-ledger all
  render a row per content chain. They diverged on what to SHOW for it: a
  projected title here, a bare id there, nothing for an untitled post. This is
  the single derivation they now share.

  The label convention (identical on every surface):
    - has a title            → the title, plain (reads as a name)
    - post/v1, no title      → a quoted body snippet ("So today I di…")
    - profile/v1             → the profile name, else a quoted description snippet
    - unknown / unresolvable → the short contentId (the pre-existing fallback)
  A short `$schema` badge (post/v1, profile/v1) sits alongside it.

  A relay's index projects `title` ONLY for a post/v1 with a non-empty title;
  everything else needs the document bytes. THIS MODULE NEVER FETCHES THEM. It is
  pure: the local index passes its own projected title/snippet straight in (see
  sync-projections.ts), and the relay-index surfaces pass the VERIFIED document
  from lib/content-labels.ts, whose bytes re-hash to the CID the chain commits to.

  An earlier draft did fetch them here — raw, from a relay, with no integrity
  check — and rendered the excerpt amber alongside projected titles. That made a
  relay the AUTHOR of a snippet on any chain it served, which no amber tier
  redeems: the projected-title tier restates a field the relay indexed, while a
  raw-bytes excerpt is prose the relay chose. The fix was not a better disclaimer
  but the integrity gate, so a snippet now arrives only as proof.

*/

import { short } from './format';

/** How many characters of a body/description snippet to show before ellipsis. */
export const SNIPPET_MAX = 48;

export interface DocLabel {
  /** the display string (already truncated; NOT pre-quoted). */
  text: string;
  /** true for a body/description snippet — render it quoted, attributed-amber. */
  quoted: boolean;
  /** title = a name/title (plain), snippet = quoted excerpt, id = fallback contentId. */
  kind: 'title' | 'snippet' | 'id';
}

const clean = (v: unknown): string => (typeof v === 'string' ? v.trim() : '');

/** Collapse whitespace/newlines to a single space and truncate — a plain-text
 *  strip (no markdown rendering), so a multi-paragraph body reads as one line.
 *  The cut prefers the last word boundary inside the limit ("…worth…" beats
 *  "…worth wri…"); a single token longer than half the budget takes the hard
 *  character cut instead, so one long URL can't collapse the whole snippet. */
export const snippet = (text: string, max = SNIPPET_MAX): string => {
  const flat = text.replace(/\s+/g, ' ').trim();
  if (flat.length <= max) return flat;
  const hard = flat.slice(0, max);
  const brk = hard.lastIndexOf(' ');
  return `${(brk > max / 2 ? hard.slice(0, brk) : hard).trimEnd()}…`;
};

/** Derive a label from a projected title/snippet (local index) and/or lazily
 *  resolved document bytes (relay index). Pure — the fetch lives in the hook. */
export const deriveDocLabel = (input: {
  title?: string | null | undefined;
  snippet?: string | null | undefined;
  docSchema?: string | null | undefined;
  contentId: string;
  doc?: Record<string, unknown> | null | undefined;
}): DocLabel => {
  const title = clean(input.title);
  if (title) return { text: title, quoted: false, kind: 'title' };

  // a pre-projected snippet (local rollup) — already stripped, just truncate
  const projected = clean(input.snippet);
  if (projected) return { text: snippet(projected), quoted: true, kind: 'snippet' };

  // lazily-resolved bytes (relay-index path): title/name plain, else a quoted excerpt
  const doc = input.doc;
  if (doc) {
    const schema = clean(doc['$schema']) || clean(input.docSchema);
    if (schema.endsWith('/profile/v1')) {
      const name = clean(doc['name']);
      if (name) return { text: name, quoted: false, kind: 'title' };
      const desc = clean(doc['description']);
      if (desc) return { text: snippet(desc), quoted: true, kind: 'snippet' };
    } else {
      const t = clean(doc['title']);
      if (t) return { text: t, quoted: false, kind: 'title' };
      const body = clean(doc['body']);
      if (body) return { text: snippet(body), quoted: true, kind: 'snippet' };
    }
  }

  return { text: short(input.contentId, 14, 5), quoted: false, kind: 'id' };
};

/**
 * The name a document states about ITSELF — the title/name half of
 * {@link deriveDocLabel}'s precedence, and nothing inferred from it. A body or
 * description snippet is an EXCERPT: right for a row label (quoted, so it can
 * never be mistaken for a title) and wrong for a `title` field on a detail page,
 * which reads as the document's own claim about what it is called. `''` when the
 * document names itself nothing — a verdict, not a gap; see {@link contentTitle}.
 * Pure.
 */
export const documentName = (doc: unknown): string => {
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return '';
  const label = deriveDocLabel({ contentId: '', doc: doc as Record<string, unknown> });
  return label.kind === 'title' ? label.text : '';
};

/** Which tier the content detail page's `title` row is entitled to render in:
 *  `verified` = the document's own name, from bytes this tab re-hashed to the
 *  committed CID · `attributed` = the relay index's projection standing in ·
 *  `none` = there is nothing anyone may say. */
export type TitleTier = 'verified' | 'attributed' | 'none';

/** The detail page's title row. `text` is meaningless when `tier` is `none`. */
export interface ContentTitle {
  tier: TitleTier;
  text: string;
}

/**
 * The title row's tier, and the whole trust ordering in one place: THE FOLD
 * ALWAYS WINS. Sibling of `creditsTier` in components/credits.tsx — the same
 * reasoning applied to the chain's name rather than its attribution.
 *
 * `verifiedName` is null only while the fold has no answer: the bytes are not
 * fetched, or not yet re-hashed to the committed document CID on a verified
 * chain. In exactly that window the relay's projected title may stand in, amber.
 * Once it is a STRING the fold has spoken, and the EMPTY string is a verdict
 * rather than a gap — this document names itself nothing. It must retire the
 * projection rather than leave it standing, or a stale (or hostile) relay keeps
 * a title on screen that bytes bound to the chain contradict, which is precisely
 * the assertion the fold exists to overrule.
 *
 * Whitespace is not a name on either side: a projection that renders as a blank
 * amber span is worse than the row it replaced. Pure, unit-tested.
 */
export const contentTitle = (verifiedName: string | null, projected: string): ContentTitle => {
  if (verifiedName !== null) {
    const verified = verifiedName.trim();
    return verified ? { tier: 'verified', text: verified } : { tier: 'none', text: '' };
  }
  const attributed = projected.trim();
  return attributed ? { tier: 'attributed', text: attributed } : { tier: 'none', text: '' };
};
