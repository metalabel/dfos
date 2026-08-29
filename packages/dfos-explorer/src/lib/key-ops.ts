/*

  KEY OPS — what a public key has signed, and what may honestly be counted

  The key page's two questions run on two different axes and only one of them is
  proof-tier. `/index/v0/identities?key=` answers "which identities have ever
  DECLARED this key" — a state-projection lookup over key arrays. This module
  serves the other one: `/index/v0/operations?signerKey=` answers "what has this
  key SIGNED", an exact match against the public key each row's signature verified
  against at ingest. A key can sign on chains no identity document of its own ever
  mentions, so the two lists are not subsets of each other.

  THE COUNT IS THE HONESTY PROBLEM. A key page that shows a number next to
  "operations" is read as "this is how many times this key signed", and there are
  exactly two wrong ways to produce that number:

    - an identity's `opCount` counts that identity's WHOLE chain, by any of its
      keys. It is a real figure and it is not this one, so the column that carries
      it says `chain ops` and never `ops`.
    - a relay that ignores `signerKey=` answers with the unfiltered operations
      feed. Counting THAT is not an over-count, it is a fabrication.

  So the count is a fold with four states, and only one of them is a number. The
  number itself is what the enumeration LOADED — the operations index serves a
  keyset cursor and no total, so a paged enumeration says "20 loaded · paged"
  rather than pretending twenty is all there is.

*/

import { fmtCount } from './format';

// -----------------------------------------------------------------------------
// chain cell — what a chainId actually is
// -----------------------------------------------------------------------------

/** What an operation row's `chainId` names. `none` is a row that carries none —
 *  the index's honest blank, not a chain of some fourth kind. */
export type ChainKind = 'identity' | 'op' | 'content' | 'none';

/**
 * Classify an operation row's chainId by its own shape. The non-chain primitives
 * (credential / countersign / revocation) ride some other primitive's chainId —
 * a credential chains under its ISSUER DID, a countersignature under its target
 * CID — which is why this is a switch over the identifier rather than a lookup
 * from the row's kind. Pure, unit-tested.
 */
export const chainKindOf = (chainId: string): ChainKind => {
  if (!chainId) return 'none';
  if (chainId.startsWith('did:dfos:')) return 'identity';
  if (chainId.startsWith('baf')) return 'op';
  return 'content';
};

// -----------------------------------------------------------------------------
// the count fold
// -----------------------------------------------------------------------------

/**
 * What the page may honestly say about how many operations this key signed.
 *
 * `counted` is the only state carrying a number, and `partial` says whether the
 * enumeration is known to be exhausted — a keyset cursor cannot report a total,
 * so a page with more behind or ahead of it is loaded, not counted.
 * `unsupported` is the relay that ignores `signerKey=`; `unavailable` is no index
 * or a failed query; `checking` is nothing asked yet.
 */
export type SignerOpCount =
  | { kind: 'counted'; loaded: number; partial: boolean }
  | { kind: 'unsupported' }
  | { kind: 'unavailable' }
  | { kind: 'checking' };

/**
 * Fold the key-scoped op count from what is actually known. The order of the
 * branches is the honesty order: a relay that cannot answer, then a relay that
 * would answer with the wrong page, then not-yet-asked, then a failed ask — and a
 * number only when a supported relay served a page for THIS key.
 *
 * `unsupported` outranks `checking` so the page never flashes a spinner for a
 * question this relay is not going to answer. Pure, unit-tested.
 */
export const signerOpCount = (args: {
  /** any configured relay advertises an index (null = still reading well-knowns). */
  indexed: boolean | null;
  /** at least one configured relay passed the `signerKey=` probe, so the query
   *  has a vetted relay to run against (null = probe in flight). */
  supported: boolean | null;
  loading: boolean;
  error: boolean;
  /** rows on the page in hand. */
  loaded: number;
  hasNext: boolean;
  offFirst: boolean;
}): SignerOpCount => {
  if (args.indexed === false) return { kind: 'unavailable' };
  if (args.supported === false) return { kind: 'unsupported' };
  if (args.indexed === null || args.supported === null || args.loading) return { kind: 'checking' };
  if (args.error) return { kind: 'unavailable' };
  return { kind: 'counted', loaded: args.loaded, partial: args.hasNext || args.offFirst };
};

/**
 * The count as a line of text — the same `N · paged` grammar the pager writes
 * under every keyset table, so the figure in a panel header and the figure in its
 * footer say the same thing the same way. Pure, unit-tested.
 */
export const signerOpCountLabel = (count: SignerOpCount): string => {
  switch (count.kind) {
    case 'counted':
      return count.partial ? `${fmtCount(count.loaded)} loaded · paged` : fmtCount(count.loaded);
    case 'unsupported':
      return 'this relay cannot say';
    case 'unavailable':
      return 'unknown';
    case 'checking':
      return 'checking…';
  }
};
