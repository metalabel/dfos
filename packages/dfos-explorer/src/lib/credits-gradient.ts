/*

  CREDITS → CLAIM GRADIENT — the pure seam (STUB, not yet wired)

  A post/v1 document MAY assert a credits[] list — DIDs the post credits for a
  contribution. Those are ASSERTION-TIER payload claims (amber): the author says
  so, and nothing structural backs it. A credit UPGRADES to claimed (green) when
  the credited DID itself ACTED in the content chain — a claim/countersign op
  signed by that DID appears in the chain's signer set. That is an actor-axis
  fact, foldable from the proof plane (or surfaced by the index `signer=` reverse
  lookup), never a payload assertion — exactly the amber→green posture the index
  rows already use.

  This module is intentionally NOT wired into any rendered surface yet, for two
  reasons that both hold today:

    - The content view keeps its `<pre>` — there is no post reader, so there is no
      credits UI to attach a gradient to. A reader is its own sanitization-gated
      lane (first injection surface), out of scope here.
    - The dev relay carries no post corpus, so there is nothing to exercise the
      gradient against.

  Leaving it as a pure, total function keeps the mechanism honest and testable the
  moment those two preconditions change.

  TODO(credits-gradient): once a post reader lands AND a post corpus exists —
    1. extract credits[] from the head document AFTER its bytes re-hash to the
       committed documentCID (never from an unverified relay projection);
    2. derive the chain's signer set — `client.log('content', id)` → the distinct
       signer DID of each op, or the index `signer=<did>` reverse lookup;
    3. render each credit with `creditTier()` driving the shared VerifyBadge
       vocabulary (asserted = amber, claimed = green);
    4. add a fixture + unit test alongside the wiring.

*/

/** asserted = a bare payload claim (amber) · claimed = the credited DID is in the
 *  chain's signer set, so it actually acted (green). */
export type CreditTier = 'asserted' | 'claimed';

/**
 * The trust tier of a single credited DID against a content chain's signer set.
 * `claimed` when that DID signed at least one op in the chain (an actor-axis fact
 * the proof plane can re-derive), else `asserted` (the author's unbacked claim).
 * Pure and total — no I/O, no relay trust; the caller supplies the folded signer
 * set. This is the whole seam: everything above it (extraction, folding, badge
 * rendering) is deferred until a post reader + corpus exist.
 */
export const creditTier = (
  creditedDID: string,
  chainSignerDIDs: ReadonlySet<string>,
): CreditTier => (chainSignerDIDs.has(creditedDID) ? 'claimed' : 'asserted');
