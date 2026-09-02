/*

  DEPENDENCY MARKER

  One fact, carried on an error: "the identity or key this artifact references
  could not be produced by the resolver you gave me."

  It is not a verdict on the artifact. Verification did not conclude that the
  signature is bad or the grammar is wrong — it could not run, because the
  caller's resolver does not hold the identity yet. A relay reads that as
  RETRYABLE: keep the operation pending, because sync or gossip may deliver the
  chain and the same operation will then verify. Every other failure is a
  verdict, and a relay durably rejects it.

  WHY A PROPERTY AND NOT AN ERROR CLASS. Two reasons, both practical.

  First, `instanceof` is unreliable across package copies. A relay lists
  `@metalabel/dfos-protocol` as both a peer dependency and a workspace
  dependency; a consumer can end up with two loaded copies, and a class from one
  fails `instanceof` against the other. A property survives that.

  Second, the marker has to sit on errors of several existing classes
  (CredentialVerificationError, the credit-claim verdicts) without changing WHICH
  class is thrown — those classes are the public contract of their own modules
  and callers already branch on them.

  WHY NOT MATCH THE MESSAGE. Because that was the bug. The relays used to
  classify by substring-matching the error text, and that text quotes
  submitter-controlled input verbatim — a kid, a typ, a credential audience all
  appear in messages here. A submitter who spelled one of the watched phrases
  inside one of those fields turned a permanent rejection into a retryable one,
  so the operation was never deleted and was re-verified on every sequencer
  cycle. Choosing a string chose the relay's control flow. A marker cannot be
  spelled from outside.

  The Go twin is `ErrDependencyMissing` in dfos-web-relay-go's ingest.go, read
  with errors.Is; the two implementations MUST classify identically, and now do
  so structurally rather than by keeping two lists of phrases in sync.

*/

/** An error carrying the marker. The member is optional everywhere it is read. */
type DependencyMarked = { dependencyMissing?: unknown };

/**
 * Mark an error as "a referenced identity or key is not resolvable HERE".
 *
 * Returns the same error so it can be marked inline at a throw site:
 * `throw markDependencyMissing(new CredentialVerificationError(...))`.
 */
export const markDependencyMissing = <E extends Error>(err: E): E =>
  Object.assign(err, { dependencyMissing: true as const });

/** True if `err` carries the marker. */
export const isDependencyMissing = (err: unknown): boolean =>
  err instanceof Error && (err as DependencyMarked).dependencyMissing === true;

/**
 * Carry the marker from a caught error onto the error that replaces it.
 *
 * This is the TypeScript spelling of Go's `%w`: a layer that re-throws with more
 * context must not eat the one fact only the inner layer knew. Every re-wrap
 * between a resolver and a relay's classifier goes through this, or the marker
 * is lost at that boundary and the classification silently reverts to a guess.
 */
export const carryDependencyMissing = <E extends Error>(cause: unknown, wrapped: E): E =>
  isDependencyMissing(cause) ? markDependencyMissing(wrapped) : wrapped;
