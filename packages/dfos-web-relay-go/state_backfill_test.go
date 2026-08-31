package relay

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// THE STALE ROW IS THE WHOLE SUBJECT OF THIS FILE.
//
// A relay that ingested a corpus before dfos.IdentityState carried ProvedKeys
// has, on disk, identity state blobs with no has-ever-proved union in them. The
// fixtures here manufacture exactly that row — ingest a rotation with the
// current code, then zero the union back out and re-Put — because there is no
// other way to get one: every write path in this package folds the union in.
//
// What the row costs is the point. A key proved into the chain and later
// rotated out is absent from the effective arrays and present nowhere else, so
// the has-ever-proved fallback in provedKeyState returns the narrow answer and
// says nothing about it. The assertions below pin both halves: narrow before
// the backfill, whole after it.

// backfillTestLogger returns a logger and the buffer it writes into, so a test
// can assert on what the pass said as well as what it did.
func backfillTestLogger() (*slog.Logger, *bytes.Buffer) {
	var logs bytes.Buffer
	return slog.New(slog.NewTextHandler(&logs, nil)), &logs
}

// staleIdentityRow rewrites an identity row the way a pre-ProvedKeys binary
// would have written it: same log, same head, same effective arrays, no
// has-ever-proved union. Returns the row as it now stands on disk.
func staleIdentityRow(t *testing.T, store Store, did string) StoredIdentityChain {
	t.Helper()
	chain, err := store.GetIdentityChain(did)
	if err != nil || chain == nil {
		t.Fatalf("read identity chain %s: %v", did, err)
	}
	if chain.State.ProvedKeys.IsZero() {
		t.Fatalf("fixture is already stale — the rotation did not fold a union: %+v", chain.State)
	}
	chain.State.ProvedKeys = dfos.DeclaredKeyState{}
	if err := store.PutIdentityChain(*chain); err != nil {
		t.Fatalf("write stale identity chain %s: %v", did, err)
	}
	return *chain
}

// resolvesHistorically reports whether the has-ever-proved resolver knows a key.
func resolvesHistorically(t *testing.T, store Store, did, keyID string) bool {
	t.Helper()
	_, err := CreateKeyResolver(store)(did + "#" + keyID)
	return err == nil
}

// TestBackfillProvedKeyStateRestoresRotatedOutKeys is the core claim, run
// against both stores: a rotated-out key that the stale row has lost resolves
// again after the backfill, and the repaired row carries the union durably
// rather than answering from a re-walk on every lookup.
func TestBackfillProvedKeyStateRestoresRotatedOutKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		store func(t *testing.T) Store
	}{
		{"memory", func(t *testing.T) Store { return NewMemoryStore() }},
		{"sqlite", func(t *testing.T) Store {
			s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "backfill.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.store(t)
			r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
			if err != nil {
				t.Fatal(err)
			}
			id := ingestIdentity(t, r)
			rotated, _ := rotateExistingTestIdentity(t, r, id)

			// Sanity: the rotation really did leave the genesis key behind, and the
			// current code really did keep it in the union.
			if !resolvesHistorically(t, store, id.did, id.auth.keyID) {
				t.Fatal("fixture: the rotated-out key should resolve before it is staled")
			}

			before := staleIdentityRow(t, store, id.did)

			// BEFORE: the fallback answers from the effective arrays, so the key the
			// rotation retired is simply unknown — silently, with a plain error.
			if resolvesHistorically(t, store, id.did, id.auth.keyID) {
				t.Fatal("the stale row still resolved the rotated-out key — fixture is not stale")
			}
			if !resolvesHistorically(t, store, id.did, rotated.keyID) {
				t.Fatal("the stale row lost the CURRENT key too — the fallback is broken, not narrow")
			}

			logger, logs := backfillTestLogger()
			if err := backfillProvedKeyState(store, logger); err != nil {
				t.Fatalf("backfill: %v", err)
			}

			// AFTER: both keys, and the union is on the row rather than recomputed.
			if !resolvesHistorically(t, store, id.did, id.auth.keyID) {
				t.Fatal("the backfill did not restore the rotated-out key")
			}
			if !resolvesHistorically(t, store, id.did, rotated.keyID) {
				t.Fatal("the backfill lost the current key")
			}
			repaired, err := store.GetIdentityChain(id.did)
			if err != nil || repaired == nil {
				t.Fatalf("read repaired chain: %v", err)
			}
			if repaired.State.ProvedKeys.IsZero() {
				t.Fatalf("the repaired row has no persisted union: %+v", repaired.State)
			}
			if _, ok := findKeyInKeyState(repaired.State.ProvedKeys, id.auth.keyID); !ok {
				t.Fatalf("provedKeys = %+v, want the rotated-out key named", repaired.State.ProvedKeys)
			}
			// The head is re-stamped from the same walk that produced the state, so
			// the row stays internally consistent — and lands on the same value the
			// row already carried.
			if repaired.HeadCID != before.HeadCID || repaired.LastCreatedAt != before.LastCreatedAt {
				t.Fatalf("head/lastCreatedAt moved: %s/%s, want %s/%s",
					repaired.HeadCID, repaired.LastCreatedAt, before.HeadCID, before.LastCreatedAt)
			}
			if !strings.Contains(logs.String(), "backfill complete") {
				t.Fatalf("a pass that rewrote a row said nothing: %s", logs.String())
			}
		})
	}
}

// TestBackfillPrecedesTheIndexRebuild pins the ORDERING, which is the half of
// this fix that is easy to get wrong and impossible to notice: the projection
// rebuild reads provedKeyState, so a rebuild that runs against unrepaired rows
// materializes a `key=` index missing every rotated-out key — and then stamps
// the current projection version over it, so nothing rebuilds it again.
//
// Both directions are asserted on the same fixture: rebuild-without-backfill
// loses the key, and the boot path (which runs the backfill first) keeps it.
func TestBackfillPrecedesTheIndexRebuild(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "backfill-index.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, r)
	rotateExistingTestIdentity(t, r, id)
	rotatedOut := id.auth.mk.PublicKeyMultibase

	staleIdentityRow(t, store, id.did)

	// NEGATIVE CONTROL: a rebuild on its own, against the stale row.
	if err := store.ClearIndexProjection(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	logger, _ := backfillTestLogger()
	if err := rebuildIndexProjection(store, logger); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := identityDIDsMatching(t, r, keyQuery(rotatedOut)); len(got) != 0 {
		t.Fatalf("a rebuild against a stale row indexed the rotated-out key (%v) — "+
			"the fixture no longer reproduces the bug", got)
	}

	// THE BOOT PATH: NewRelay runs the backfill before the rebuild, so the same
	// upgrade that triggers the rebuild feeds it repaired state.
	if err := store.ClearIndexProjection(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetIndexProjectionVersion(0); err != nil {
		t.Fatal(err)
	}
	r2, err := NewRelay(RelayOptions{
		Store:     store,
		Authority: testAuthority,
		Identity:  &RelayIdentity{DID: r.DID(), ProfileArtifactJWS: r.ProfileArtifactJWS()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := store.GetIndexProjectionVersion(); v != IndexProjectionVersion {
		t.Fatalf("projection_version = %d, want %d", v, IndexProjectionVersion)
	}
	if got := identityDIDsMatching(t, r2, keyQuery(rotatedOut)); len(got) != 1 || got[0] != id.did {
		t.Fatalf("key= on the rotated-out key matched %v, want [%s]", got, id.did)
	}
}

// countingPutStore counts identity rewrites, so idempotency can be asserted on
// the WRITE rather than on the resulting bytes: a second pass that rewrote every
// row with identical content would be indistinguishable by content alone, and it
// is the re-verification cost — a signature check per operation, per boot — that
// makes that unacceptable.
//
// It embeds the Store interface rather than a concrete store, which also means
// it does NOT forward BeginWriteBatch: the wrapper deliberately exercises the
// no-batch path of the backfill.
type countingPutStore struct {
	Store
	identityPuts int
}

func (s *countingPutStore) PutIdentityChain(chain StoredIdentityChain) error {
	s.identityPuts++
	return s.Store.PutIdentityChain(chain)
}

// TestBackfillIsIdempotent: the repaired row fails the IsZero test, so the
// second pass re-verifies nothing and writes nothing. This is what makes the
// backfill safe to leave on the boot path forever rather than behind a flag.
func TestBackfillIsIdempotent(t *testing.T) {
	inner := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: inner, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}
	id := ingestIdentity(t, r)
	rotateExistingTestIdentity(t, r, id)
	staleIdentityRow(t, inner, id.did)

	store := &countingPutStore{Store: inner}
	logger, _ := backfillTestLogger()

	if err := backfillProvedKeyState(store, logger); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if store.identityPuts != 1 {
		t.Fatalf("first pass rewrote %d rows, want 1", store.identityPuts)
	}

	logger2, logs2 := backfillTestLogger()
	if err := backfillProvedKeyState(store, logger2); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if store.identityPuts != 1 {
		t.Fatalf("second pass rewrote rows (total %d), want none", store.identityPuts)
	}
	if logs2.Len() != 0 {
		t.Fatalf("a no-op pass logged: %s", logs2.String())
	}
}

// TestBackfillLeavesAnUnverifiableChainAlone: a log that no longer verifies is
// named and skipped, the pass still repairs everything else, and the boot does
// not fail. Destroying a row that serves a narrow-but-honest answer, in order to
// replace it with nothing, is the one outcome worse than the bug.
func TestBackfillLeavesAnUnverifiableChainAlone(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store, Authority: testAuthority})
	if err != nil {
		t.Fatal(err)
	}

	healthy := ingestIdentity(t, r)
	rotateExistingTestIdentity(t, r, healthy)
	staleIdentityRow(t, store, healthy.did)

	broken := ingestIdentity(t, r)
	rotateExistingTestIdentity(t, r, broken)
	corrupt := staleIdentityRow(t, store, broken.did)
	corrupt.Log = append(append([]string{}, corrupt.Log...), "not-a-jws")
	if err := store.PutIdentityChain(corrupt); err != nil {
		t.Fatal(err)
	}

	logger, logs := backfillTestLogger()
	if err := backfillProvedKeyState(store, logger); err != nil {
		t.Fatalf("one unverifiable chain must not fail the pass: %v", err)
	}

	// The healthy row got its history back.
	if !resolvesHistorically(t, store, healthy.did, healthy.auth.keyID) {
		t.Fatal("a healthy stale row was not repaired alongside a broken one")
	}

	// The broken row is EXACTLY as it was left: same log, still no union.
	after, err := store.GetIdentityChain(broken.did)
	if err != nil || after == nil {
		t.Fatalf("read broken chain: %v", err)
	}
	if !after.State.ProvedKeys.IsZero() {
		t.Fatalf("the unverifiable row was rewritten: %+v", after.State)
	}
	if len(after.Log) != len(corrupt.Log) || after.HeadCID != corrupt.HeadCID {
		t.Fatalf("the unverifiable row was mutated: log %d→%d, head %s→%s",
			len(corrupt.Log), len(after.Log), corrupt.HeadCID, after.HeadCID)
	}

	// And it was named, because a row this pass could not repair is the one thing
	// an operator needs to see.
	if !strings.Contains(logs.String(), broken.did) {
		t.Fatalf("the skipped DID was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("a skipped row was logged below WARN: %s", logs.String())
	}
}

// TestBackfillSkipsChainsWithNoLog: a row with no operations has nothing
// authoritative to fold, so it is left alone rather than re-walked into an
// error. Guards the cheap path as much as the safe one — an empty log would
// otherwise produce a warning on every boot forever.
func TestBackfillSkipsChainsWithNoLog(t *testing.T) {
	store := NewMemoryStore()
	empty := StoredIdentityChain{DID: "did:dfos:z6MkfakefakefakefakefakeF", Log: []string{}}
	if err := store.PutIdentityChain(empty); err != nil {
		t.Fatal(err)
	}
	logger, logs := backfillTestLogger()
	if err := backfillProvedKeyState(store, logger); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if logs.Len() != 0 {
		t.Fatalf("an empty-log row produced output: %s", logs.String())
	}
}
