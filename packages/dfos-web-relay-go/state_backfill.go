package relay

/*

  IDENTITY STATE BACKFILL — RE-WALKING ROWS PERSISTED BEFORE ProvedKeys EXISTED

  A durable store persists identity state as one JSON blob (store_sqlite.go's
  identity_chains.state). That blob is written by whichever binary ingested the
  chain's last operation, and it is read back by whichever binary boots next —
  so a member added to dfos.IdentityState is absent from every row already on
  disk, and unmarshals to its zero value rather than to anything the chain walk
  would have produced.

  State.ProvedKeys is the member that makes that gap load-bearing. It is
  HAS-EVER-PROVED key state: the monotonic union of every effective key state
  the chain has held, and the reading the `key=` reverse index needs, so a search
  by a rotated-out key still finds the identity. Verification never reads it:
  every verifying surface has a basis and resolves keys in the effective state as
  of it. provedKeyState (ingest.go) reads it with a fallback: an absent union
  reads as "what is effective now was proved". That fallback is correct in the
  only direction it can be — it under-claims rather than admitting a key nothing
  proved — but on a row written before the member existed it is SILENTLY NARROW.
  A projection rebuild triggered by the same upgrade materializes a `key=` index
  missing exactly the keys the chain has rotated out. The index reports nothing:
  the fallback returns a valid, smaller answer.

  The row heals on its own the moment that chain accepts another operation —
  ingest re-folds and rewrites the whole state. That is no consolation for a
  chain whose controller has finished rotating and has nothing left to publish,
  which is precisely the chain whose history the resolver is being asked about.

  So: re-walk them at boot. backfillProvedKeyState lists the identity chains,
  re-verifies the log of each row whose union is absent, and rewrites the row
  with the freshly folded state.

  WHY IsZero IS A SOUND MARKER FOR "WRITTEN BY AN OLDER BINARY". Genesis
  declares exactly one key (assertSingleKeyGenesis) and proves it by signing
  itself with it, so the chain walk seeds provedKeys with that key
  (fullyProvedKeyState) before any update is folded, and every later fold is a
  union that can only grow. A state produced by the current walk therefore has a
  NON-EMPTY ProvedKeys for every chain shape, single-op chains included —
  DeclaredKeyState.IsZero() is true only for a state that never carried the
  member at all. There is no marker table to consult and none is needed.

  NEVER DESTROY WHAT YOU CANNOT IMPROVE. A log that fails re-verification leaves
  its row exactly as it stands — logged by DID, loudly, and skipped. The stale
  row still serves the narrow-but-honest fallback; a row emptied by a failed
  re-walk would serve nothing. The same reason applies to the whole pass: one
  unverifiable chain does not fail the boot, because the other thousand rows
  still deserve their history back.

*/

import (
	"fmt"
	"log/slog"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// backfillProvedKeyState repairs identity state rows persisted before
// dfos.IdentityState carried ProvedKeys, so the `key=` reverse index stops
// falling back to the narrower effective arrays.
//
// Ordered BEFORE rebuildIndexProjection at startup (see NewRelay). The rebuild
// reads provedKeyState(chain.State) to materialize the `key=` reverse index, so
// running it against unrepaired rows would rebuild the index narrow — and,
// because the rebuild stamps the current projection version on the way out, it
// would then stay narrow until each chain's next accepted operation. The two
// migrations belong to the same upgrade and have an order.
//
// CHEAP WHEN THERE IS NOTHING TO DO, and idempotent. The only unconditional
// work is one ListIdentityChains plus an IsZero test per row; a chain the
// current walk produced fails that test, so a second run — or a boot on a
// corpus that never saw an older binary — re-verifies nothing, writes nothing,
// and logs nothing. Signature verification is paid only for rows that are
// genuinely stale, and only once.
//
// beforeRewrite RUNS ONCE, AFTER THE SCAN FINDS WORK AND BEFORE THE FIRST
// DURABLE WRITE. The rebuild that follows decides whether to re-walk from the
// stamped projection_version alone, and a corpus that first materialized the
// `key=` index under the CURRENT version — from the narrow fallback, before this
// repair existed — carries a stamp saying the rows are already right. So the
// stamp has to be invalidated, and the ORDER of that against the rewrites is the
// whole of this hook's reason to exist.
//
// Invalidating AFTERWARDS leaves a window with no exit. A stop between the last
// rewrite and the stamp reset — a crash, a SIGKILL, a failed write — leaves
// repaired rows under a current stamp, and the next boot finds NO stale
// identities, so it has nothing to infer from and skips the rebuild. Forever:
// the evidence that a repair happened is exactly what the repair erased.
// Invalidating first makes an interrupted run resume into a rebuild, because the
// stamp is the durable record that one is owed. A rebuild that turns out to be
// unnecessary costs a bounded log re-walk and converges on the same rows; the
// other direction costs a permanently wrong index.
//
// The hook is optional — nil means the caller keeps no such stamp.
func backfillProvedKeyState(store MigratableStore, logger *slog.Logger, beforeRewrite func() error) error {
	chains, err := store.ListIdentityChains()
	if err != nil {
		return fmt.Errorf("list identity chains: %w", err)
	}

	// Collect first, write second. The scan is the common case and it must not
	// pay for a write path across a corpus that turns out to need nothing.
	stale := make([]StoredIdentityChain, 0)
	for _, chain := range chains {
		// An empty log is nothing to re-walk — there is no authoritative record
		// to fold — so such a row is left alone rather than counted as repairable.
		if !chain.State.ProvedKeys.IsZero() || len(chain.Log) == 0 {
			continue
		}
		stale = append(stale, chain)
	}
	if len(stale) == 0 {
		return nil
	}

	logger.Info("identity state: backfilling has-ever-proved keys",
		"stale", len(stale), "examined", len(chains))

	// Ahead of every durable write below, so a stop anywhere in the loop resumes
	// into a rebuild rather than into silence.
	if beforeRewrite != nil {
		if err := beforeRewrite(); err != nil {
			return err
		}
	}

	// Row by row, and that is fine: the rewrites are independent of each other,
	// and a boot interrupted midway leaves the unrepaired rows still zero, which
	// is exactly the predicate the next boot re-walks on. Idempotent by
	// construction rather than by transaction.
	rewritten, failed := 0, 0
	for _, chain := range stale {
		result, err := dfos.VerifyIdentityChain(chain.Log)
		if err != nil {
			// The row is left EXACTLY as it stands. See the file header: a stale
			// row serves a narrow answer, a cleared one serves none.
			logger.Warn("identity state: backfill could not re-verify a chain — row left as-is",
				"did", chain.DID, "ops", len(chain.Log), "error", err)
			failed++
			continue
		}
		chain.State = result.State
		// HeadCID and LastCreatedAt are deliberately re-stamped from the same walk
		// rather than carried over: they are outputs of the fold that produced the
		// state being written, and a row whose state and head came from two
		// different readings of the log is a worse row than either.
		chain.HeadCID = result.HeadCID
		chain.LastCreatedAt = result.LastCreatedAt
		if err := store.RewriteIdentityChainState(chain); err != nil {
			return fmt.Errorf("rewrite identity chain %s: %w", chain.DID, err)
		}
		rewritten++
	}

	logger.Info("identity state: backfill complete",
		"examined", len(chains),
		"rewritten", rewritten,
		"skippedClean", len(chains)-len(stale),
		"failed", failed)
	return nil
}
