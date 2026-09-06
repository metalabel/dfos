package relay

/*

  INDEX (v0) — PROJECTION WORKER

  The /index/v0 family is served from materialized rows. This is the worker that
  maintains them: it walks the global operation log from a persisted cursor, maps
  each entry to the rows it dirties, recomputes those rows through the shared
  builders (index.go), and applies them in one batch.

  IT IS NOT PART OF INGESTION, AND IT NEVER RUNS UNDER ingestMu. Maintenance used
  to run inside the accepting path, and two triggers fanned out over a
  bounded-but-large superset: a chain:* grant touched every content row, and a
  revocation the relay could not resolve touched every currently-public row. The
  second was reachable by an anonymous POST and free to mint, so an unbounded
  corpus sweep sat behind an unauthenticated request while the ingest mutex was
  held (issue #266). Three things change that:

   1. The projection reads the LOG, not the ingest result, so it runs whenever the
      operator runs it — after a commit on its own goroutine, on a timer, or in
      another process entirely. Nothing about it is inside a write transaction the
      relay opened.
   2. The unresolvable-revocation trigger is gone. A revocation names a credential
      CID, and that credential is itself an operation, so the grant it carried is
      an O(1) lookup: a revocation for a credential this relay never held, or one
      signed by anyone other than that credential's issuer, dirties NOTHING.
   3. The remaining fan-outs (a chain:* grant, an identity delete or restore) are
      a RESUMABLE SWEEP with a per-run row cap, carried on the same cursor. An
      unbounded stall becomes a bounded one that drains across runs.

  The lesson the SQLite store learned the hard way is why the cap is not optional:
  measured against the public relay's corpus (9.4k standing credentials, 9.4k
  public-read chains) one standing-grant lookup ran 17ms, which made a single
  content recompute 77ms and turned the public-read sweep a single identity delete
  triggered into a TWELVE-MINUTE stall — the sequencer pinned at 100% CPU with the
  ingest mutex held and no operation landing. Indexing the grant lookup removed
  the constant factor; the budget removes the unboundedness.

  Row VALUES are a pure function of (chain state, held blobs, standing
  credentials), so every recompute converges to the same row regardless of when it
  runs. That is what makes an incremental run and a full rebuild interchangeable,
  and what makes a deferred recompute safe.

  A materialized row is a snapshot of standing authority AT LAST TOUCH. One input
  to publicRead — a standing credential's exp, and the revocation of a credential
  further up a delegation chain — is not observable from the operation that would
  dirty the row, so a row can advertise publicRead: true after the grant behind it
  stopped holding, until the next operation touches that content or a rebuild
  runs. That is the lag the hint plane already licenses: authoritative reads
  re-verify through hasPublicStandingAuth at request time, which checks revocation
  at every delegation level. See specs/RELAY.md §Index.

  Byte-for-byte behavior twin of the TypeScript index-projection.ts.

*/

import (
	"errors"
	"log/slog"
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// IndexProjectionStore is the store shape the projection worker needs: the base
// reads, the index queries it sweeps and cascades through, and the write side it
// applies rows to.
type IndexProjectionStore interface {
	RelayReadStore
	IndexReadStore
	IndexWriteStore
}

// DefaultIndexProjectionBudget caps log entries projected and content rows swept
// per run. The cap that turns an unbounded corpus sweep into work that drains
// across runs.
const DefaultIndexProjectionBudget = 5000

// IndexProjectionRun reports one run's work.
type IndexProjectionRun struct {
	// Projected counts log entries projected in this run.
	Projected int
	// Swept counts content rows the resumable sweep recomputed in this run.
	Swept int
	// CaughtUp is true when no sweep is outstanding and the log cursor reached
	// the tip.
	CaughtUp bool
}

// logIndexProjectionError reports an error the projection swallowed.
//
// The projection is a non-authoritative hint plane, so it must never fail an
// authoritative write — but swallowed is not the same as SILENT: a persistently
// failing projection looks exactly like a quiet one otherwise. One structured
// line per failure, matching the TS twin's event string so a single query works
// across implementations.
func logIndexProjectionError(logger *slog.Logger, site string, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("relay.index.projection_failed", "site", site, "reason", err.Error())
}

// ---------------------------------------------------------------------------
// row accumulation
// ---------------------------------------------------------------------------

// projectionDirty is the content ids and DIDs one run must recompute.
type projectionDirty struct {
	contentIDs   map[string]struct{}
	identityDIDs map[string]struct{}
}

func newProjectionDirty() *projectionDirty {
	return &projectionDirty{
		contentIDs:   map[string]struct{}{},
		identityDIDs: map[string]struct{}{},
	}
}

// ---------------------------------------------------------------------------
// credential scope
// ---------------------------------------------------------------------------

// contentIdsFromCredential returns the content ids named by a public
// credential's attenuations (chain:<contentId> resources). wildcard is true when
// it grants chain:*, which covers every chain and therefore fans out to all
// content rows.
func contentIdsFromCredential(credential StoredPublicCredential) (wildcard bool, contentIds []string) {
	contentIds = []string{}
	for _, entry := range credential.Att {
		if entry.Resource == "chain:*" {
			wildcard = true
		} else if strings.HasPrefix(entry.Resource, "chain:") {
			contentIds = append(contentIds, entry.Resource[len("chain:"):])
		}
	}
	return wildcard, contentIds
}

// contentIdsFromCredentialToken is the same read against an undecoded credential
// operation.
func contentIdsFromCredentialToken(jwsToken string) (wildcard bool, contentIds []string) {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || payload == nil {
		return false, nil
	}
	att, ok := payload["att"].([]any)
	if !ok {
		return false, nil
	}
	credential := StoredPublicCredential{}
	for _, entry := range att {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		resource, ok := m["resource"].(string)
		if !ok {
			continue
		}
		credential.Att = append(credential.Att, AttenuationPair{Resource: resource})
	}
	return contentIdsFromCredential(credential)
}

// ---------------------------------------------------------------------------
// signer keys
// ---------------------------------------------------------------------------

// declaredIdentityKey is one (keyID, publicKeyMultibase) pair an identity
// operation declared, as it appeared on the wire.
type declaredIdentityKey struct {
	KeyID     string
	PublicKey string
}

// identityKeysDeclaredBy reads every key one identity operation DECLARES, across
// all three key classes. A delete/restore op carries no key arrays and yields
// nothing.
//
// ONE CALLER, AND IT IS THE ONE POSITION WHERE DECLARED AND PROVED COINCIDE: an
// identity GENESIS, whose kid is a bare key ID because the DID does not exist
// until the operation that declares it, so there is no chain to resolve against.
// Genesis declares exactly one key in all three roles and its own signature IS
// that key's possession proof — declared and proved are the same single key, so
// reading the payload here claims nothing the chain walk would not.
//
// Nothing else reads declarations. Both reverse indexes are has-ever-PROVED and
// take dfos.IdentityState.ProvedKeys; see provedKeyRows.
func identityKeysDeclaredBy(payload map[string]any) []declaredIdentityKey {
	declared := []declaredIdentityKey{}
	for _, arrayName := range []string{"authKeys", "assertKeys", "controllerKeys"} {
		entries, ok := payload[arrayName].([]any)
		if !ok {
			continue
		}
		for _, raw := range entries {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			publicKey, _ := entry["publicKeyMultibase"].(string)
			if publicKey == "" {
				continue
			}
			keyID, _ := entry["id"].(string)
			declared = append(declared, declaredIdentityKey{KeyID: keyID, PublicKey: publicKey})
		}
	}
	return declared
}

// signerKeyForOperation resolves the multibase public key ONE accepted operation
// was signed with — the value stamped on the operation-log row as the substrate
// for /index/v0/operations?signerKey=. Returns "" when the key cannot be
// resolved, which the stores leave NULL and no filter value ever matches.
//
// Uniform across every row kind, because the JWS header is: a countersign
// resolves to the witness's key, a credential to the issuer's, a revocation to
// its signer's, an artifact to the artifact signer's, a content-op to the actual
// signer (a delegate, not necessarily the chain creator), and an identity-op to
// the controlling key that signed it (self-declared in the same op at genesis).
// There is no per-kind branch to get wrong.
//
// KEY-ADDRESSED, AND THE STRING IS THE DECLARED ONE. Verification resolves a kid
// to raw ed25519 bytes; this walks the same path but returns the
// publicKeyMultibase exactly as the identity chain declared it, rather than
// re-encoding the resolved bytes. Under canonical multikey encoding the two
// coincide — but the declared string is the alphabet /index/v0/identities?key=
// matches, so a key found there can be pasted into signerKey= here and hit.
//
// HAS-EVER-PROVED, the same rule as key=, so the two columns agree on which keys
// exist. Resolving it here rather than carrying it out of ingestion is safe for
// the same reason: ProvedKeys is monotonic, so a key that resolved at acceptance
// still resolves.
//
// ONE ROW KIND CAN LEGITIMATELY RESOLVE TO NOTHING under this rule: an identity
// operation signed by a controller key the chain declared but no proof ever
// admitted. Signer validity is declared-state-based on purpose, so that operation
// is valid and sequenced — but its signing key was never proved, so it is not in
// the has-ever-proved population and the column stays NULL. The filter's honest
// answer for a key no chain proved is "no rows", not a row keyed by evidence that
// never existed.
func signerKeyForOperation(jwsToken string, store RelayReadStore) string {
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || header == nil {
		return ""
	}
	hashIdx := strings.Index(header.Kid, "#")
	if hashIdx < 0 {
		// An identity GENESIS signs with a bare key ID, not a DID URL — the DID
		// does not exist until the op that declares it. Its signing key is
		// therefore declared inline in the same payload the header points into,
		// which is exactly what verification resolves against. No store lookup:
		// the op is self-describing.
		if header.Kid == "" || payload == nil {
			return ""
		}
		for _, declared := range identityKeysDeclaredBy(payload) {
			if declared.KeyID == header.Kid {
				return declared.PublicKey
			}
		}
		return ""
	}
	did := header.Kid[:hashIdx]
	keyID := header.Kid[hashIdx+1:]
	if keyID == "" {
		return ""
	}

	identity, err := store.GetIdentityChain(did)
	if err != nil || identity == nil {
		return ""
	}

	// Has-ever-proved is a superset of head state, so one search covers both a
	// current key and a rotated-out one.
	if k, ok := findKeyInKeyState(provedKeyState(identity.State), keyID); ok {
		return k.PublicKeyMultibase
	}
	return ""
}

// ---------------------------------------------------------------------------
// row recompute
// ---------------------------------------------------------------------------

func recomputeIdentityRow(did string, store RelayReadStore, rows *IndexRowBatch) error {
	chain, err := store.GetIdentityChain(did)
	if err != nil || chain == nil {
		return err
	}
	rows.Identities = append(rows.Identities, identityIndexRow(*chain, store))
	return nil
}

// recomputeContentRow recomputes one content row and its credit rows, then marks
// every identity row anchored on it dirty — an identity's profile projection
// embeds the anchored content's publicRead, doc schema, and name, so a content
// change is also an identity change.
func recomputeContentRow(contentID string, store IndexProjectionStore, rows *IndexRowBatch, dirty *projectionDirty) error {
	chain, err := store.GetContentChain(contentID)
	if err != nil || chain == nil {
		return err
	}
	src := contentProjectionSources(*chain, store)
	rows.Content = append(rows.Content, contentIndexRow(*chain, src))
	rows.Credits = append(rows.Credits, IndexCreditRowSet{ContentID: contentID, Rows: creditIndexRows(*chain, src)})
	anchored, err := store.GetIndexIdentityDIDsByProfileAnchor(contentID)
	if err != nil {
		return err
	}
	for _, did := range anchored {
		dirty.identityDIDs[did] = struct{}{}
	}
	return nil
}

// ---------------------------------------------------------------------------
// sweep
// ---------------------------------------------------------------------------

// widenSweep folds a newly triggered sweep into an outstanding one. Any new
// trigger restarts from the beginning: it reaches rows an in-progress sweep has
// already passed. "all" absorbs "public".
func widenSweep(current *IndexSweepState, incoming IndexSweepState) *IndexSweepState {
	scope := IndexSweepPublic
	if incoming.Scope == IndexSweepAll || (current != nil && current.Scope == IndexSweepAll) {
		scope = IndexSweepAll
	}
	return &IndexSweepState{Scope: scope}
}

// advanceSweep advances a resumable sweep by at most cap content rows, marking
// each one dirty. Returns the sweep state to persist — nil once the corpus is
// drained.
//
// The "public" scope enumerates only currently-public-read rows, which is the
// affected superset for a visibility revocation; "all" enumerates everything,
// which is what a chain:* grant or an identity restore reaches (a suspended row
// is not in the public subset, so nothing narrower would find it).
func advanceSweep(sweep IndexSweepState, store IndexReadStore, cap int, dirty *projectionDirty) (*IndexSweepState, int, error) {
	if cap <= 0 {
		return &sweep, 0, nil
	}
	query := IndexContentQuery{After: sweep.After, Limit: cap}
	if sweep.Scope == IndexSweepPublic {
		publicRead := true
		query.PublicRead = &publicRead
	}
	page, err := store.QueryIndexContent(query)
	if err != nil {
		return &sweep, 0, err
	}
	for _, row := range page {
		dirty.contentIDs[row.ContentID] = struct{}{}
	}
	if len(page) == cap {
		return &IndexSweepState{Scope: sweep.Scope, After: page[len(page)-1].ContentID}, len(page), nil
	}
	return nil, len(page), nil
}

// ---------------------------------------------------------------------------
// one log entry
// ---------------------------------------------------------------------------

// projectLogEntry accumulates the rows and sweeps ONE log entry implies, and
// returns the fan-out sweep it triggers (nil for most entries).
//
// Mapping:
//   - any operation      → the signer key it verified against
//   - identity op        → dirty that identity, record its proved keys; "delete"
//     sweeps the currently-public content subset, "restore" sweeps all content (a
//     suspended row is no longer in the public subset)
//   - content op         → dirty that content row (+ anchored identities), record
//     the accepted signer
//   - artifact           → the standalone artifact row
//   - countersign        → the countersignature row
//   - credential grant   → dirty the att-named content rows; chain:* sweeps all
//   - revocation         → ISSUER-SCOPED: resolve the revoked credential through
//     its own operation, dirty exactly what that grant named, and dirty nothing at
//     all when the relay never held it or the revoker is not its issuer
func projectLogEntry(entry LogEntry, store IndexProjectionStore, rows *IndexRowBatch, dirty *projectionDirty) *IndexSweepState {
	if key := signerKeyForOperation(entry.JWSToken, store); key != "" {
		rows.OperationSignerKeys = append(rows.OperationSignerKeys, IndexOperationSignerKey{CID: entry.CID, PublicKey: key})
	}

	switch entry.Kind {
	case "identity-op":
		dirty.identityDIDs[entry.ChainID] = struct{}{}
		// HAS-EVER-PROVED, NOT HAS-EVER-DECLARED (see PROTOCOL's key-proof rules).
		// This index is the one-key-one-DID oracle a holder consults before signing
		// a key proof, and it REFUSES on a hit. Indexing declarations would hand a
		// stranger a burn: anyone can write anyone's public key into their own
		// chain, so a chain that merely LISTS a key it does not hold would make
		// every future ceremony for the true holder refuse.
		//
		// Read from the chain's CURRENT state rather than the operation's own
		// arrays: ProvedKeys is monotonic and the rows are append-only, so writing
		// the current union while projecting any of the chain's operations
		// converges on the same table.
		if chain, err := store.GetIdentityChain(entry.ChainID); err == nil && chain != nil {
			for _, key := range keysInKeyState(provedKeyState(chain.State)) {
				rows.IdentityKeys = append(rows.IdentityKeys, IndexIdentityKeyRow{
					DID: entry.ChainID, KeyID: key.ID, PublicKey: key.PublicKeyMultibase,
				})
			}
		}
		_, payload, err := dfos.DecodeJWSUnsafe(entry.JWSToken)
		if err != nil || payload == nil {
			return nil
		}
		switch payload["type"] {
		case "delete":
			return &IndexSweepState{Scope: IndexSweepPublic}
		case "restore":
			return &IndexSweepState{Scope: IndexSweepAll}
		}
		return nil

	case "content-op":
		dirty.contentIDs[entry.ChainID] = struct{}{}
		if _, payload, err := dfos.DecodeJWSUnsafe(entry.JWSToken); err == nil && payload != nil {
			if signerDID, ok := payload["did"].(string); ok && signerDID != "" {
				rows.ContentSigners = append(rows.ContentSigners, IndexContentSignerRow{ContentID: entry.ChainID, DID: signerDID})
			}
		}
		return nil

	case "artifact":
		if row := artifactIndexRow(entry.CID, entry.JWSToken, entry.IngestedAt); row != nil {
			rows.Artifacts = append(rows.Artifacts, *row)
		}
		return nil

	case "countersign":
		header, payload, err := dfos.DecodeJWSUnsafe(entry.JWSToken)
		if err != nil {
			return nil
		}
		cid := entry.CID
		if header != nil && header.CID != "" {
			cid = header.CID
		}
		var relation *string
		var witnessDID, createdAt string
		if payload != nil {
			if value, ok := payload["relation"].(string); ok {
				relation = &value
			}
			if value, ok := payload["did"].(string); ok {
				witnessDID = value
			}
			createdAt, _ = payload["createdAt"].(string)
		}
		rows.Countersignatures = append(rows.Countersignatures, storedIndexCountersignature{
			CID:        cid,
			TargetCID:  entry.ChainID,
			Relation:   relation,
			JWSToken:   entry.JWSToken,
			WitnessDID: witnessDID,
			CreatedAt:  createdAt,
			IngestedAt: entry.IngestedAt,
		})
		return nil

	case "credential":
		wildcard, contentIds := contentIdsFromCredentialToken(entry.JWSToken)
		if wildcard {
			return &IndexSweepState{Scope: IndexSweepAll}
		}
		for _, contentID := range contentIds {
			dirty.contentIDs[contentID] = struct{}{}
		}
		return nil

	case "revocation":
		// THE #266 NARROWING. A revocation names a credential CID. That credential
		// is itself an operation, so its grant is an O(1) lookup that survives the
		// held-credential row being dropped at commit. Two misses dirty nothing at
		// all, and between them they remove the anonymous, attacker-paced trigger:
		// a revocation for a credential this relay never held, and a revocation
		// signed by anyone other than that credential's issuer.
		_, payload, err := dfos.DecodeJWSUnsafe(entry.JWSToken)
		if err != nil || payload == nil {
			return nil
		}
		credentialCID, ok := payload["credentialCID"].(string)
		if !ok || credentialCID == "" {
			return nil
		}
		credentialOp, err := store.GetOperation(credentialCID)
		if err != nil || credentialOp == nil || credentialOp.ChainType != "credential" {
			return nil
		}
		if credentialOp.ChainID != entry.ChainID {
			return nil
		}
		wildcard, contentIds := contentIdsFromCredentialToken(credentialOp.JWSToken)
		if wildcard {
			return &IndexSweepState{Scope: IndexSweepPublic}
		}
		for _, contentID := range contentIds {
			dirty.contentIDs[contentID] = struct{}{}
		}
		return nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// the run
// ---------------------------------------------------------------------------

// projectIndex advances the index projection by at most one budget's worth of
// work.
//
// Sweep first (an outstanding fan-out is older than anything on the log tail),
// then as many log entries as the remaining budget allows, then one
// ApplyIndexRows and one SetIndexCursor.
//
// ON FAILURE the cursor is NOT advanced and no rows are applied, so the same work
// is retried on the next run. That is safe because every recompute is convergent,
// and it is the honest failure mode: a projection that cannot make progress
// stalls visibly at its cursor rather than skipping entries.
func projectIndex(store IndexProjectionStore, budget int, logger *slog.Logger) IndexProjectionRun {
	if budget <= 0 {
		budget = DefaultIndexProjectionBudget
	}
	cursor, err := store.GetIndexCursor()
	if err != nil {
		logIndexProjectionError(logger, "projectIndex", err)
		return IndexProjectionRun{}
	}

	rows := IndexRowBatch{}
	dirty := newProjectionDirty()

	swept := 0
	if cursor.Sweep != nil {
		next, n, err := advanceSweep(*cursor.Sweep, store, budget, dirty)
		if err != nil {
			logIndexProjectionError(logger, "advanceSweep", err)
			return IndexProjectionRun{}
		}
		cursor.Sweep = next
		swept = n
	}

	projected := 0
	reachedTip := false
	if remaining := budget - swept; remaining > 0 {
		entries, _, err := store.ReadLog(cursor.LogCursor, remaining)
		if errors.Is(err, ErrUnknownLogCursor) {
			// A cursor this log no longer contains — a wiped or rebuilt log —
			// restarts the projection from the beginning rather than stalling on it
			// forever. Recompute is convergent, so a replay costs work and changes
			// nothing.
			cursor.LogCursor = ""
			entries, _, err = store.ReadLog("", remaining)
		}
		if err != nil {
			logIndexProjectionError(logger, "readLog", err)
			return IndexProjectionRun{}
		}
		for _, entry := range entries {
			if trigger := projectLogEntry(entry, store, &rows, dirty); trigger != nil {
				cursor.Sweep = widenSweep(cursor.Sweep, *trigger)
			}
			cursor.LogCursor = entry.CID
			projected++
		}
		reachedTip = len(entries) < remaining
	}

	// recomputeContentRow adds anchored identities to the dirty set, so content
	// runs first and the identity loop reads a complete set.
	for contentID := range dirty.contentIDs {
		if err := recomputeContentRow(contentID, store, &rows, dirty); err != nil {
			logIndexProjectionError(logger, "recomputeContentRow", err)
			return IndexProjectionRun{}
		}
	}
	for did := range dirty.identityDIDs {
		if err := recomputeIdentityRow(did, store, &rows); err != nil {
			logIndexProjectionError(logger, "recomputeIdentityRow", err)
			return IndexProjectionRun{}
		}
	}

	if err := store.ApplyIndexRows(rows); err != nil {
		logIndexProjectionError(logger, "applyIndexRows", err)
		return IndexProjectionRun{}
	}
	if err := store.SetIndexCursor(cursor); err != nil {
		logIndexProjectionError(logger, "setIndexCursor", err)
		return IndexProjectionRun{}
	}

	return IndexProjectionRun{Projected: projected, Swept: swept, CaughtUp: cursor.Sweep == nil && reachedTip}
}

// indexProjectionMaxRuns bounds how many budgets one drain spends before
// returning. A drain that has not caught up simply resumes on the next call —
// the cursor is persisted, so no work is lost.
const indexProjectionMaxRuns = 100

// drainIndexProjection runs the projection until it is caught up, or until
// maxRuns budgets are spent. maxRuns <= 0 means "until caught up".
func drainIndexProjection(store IndexProjectionStore, budget, maxRuns int, logger *slog.Logger) IndexProjectionRun {
	total := IndexProjectionRun{}
	for run := 0; maxRuns <= 0 || run < maxRuns; run++ {
		result := projectIndex(store, budget, logger)
		total.Projected += result.Projected
		total.Swept += result.Swept
		total.CaughtUp = result.CaughtUp
		if result.CaughtUp {
			break
		}
		// No progress and not caught up: a failed run, or a sweep that cannot
		// advance. Stop rather than spin.
		if result.Projected == 0 && result.Swept == 0 {
			break
		}
	}
	return total
}

// projectIndexAfterBlob recomputes the content rows that project a document,
// after its blob lands.
//
// A blob arrives on its own route, often after the operation that referenced it,
// and it can turn a row's docSchema/title/profile projection from unknown to
// known. Nothing on the operation log marks that moment, so this is the one
// projection entry point the log does not drive. It is bounded by the reverse
// lookup — the rows that name this documentCID and nothing else.
func projectIndexAfterBlob(documentCID string, store IndexProjectionStore, logger *slog.Logger) {
	rows := IndexRowBatch{}
	dirty := newProjectionDirty()
	contentIDs, err := store.GetIndexContentIDsByDocumentCID(documentCID)
	if err != nil {
		logIndexProjectionError(logger, "projectIndexAfterBlob", err)
		return
	}
	for _, contentID := range contentIDs {
		dirty.contentIDs[contentID] = struct{}{}
	}
	for contentID := range dirty.contentIDs {
		if err := recomputeContentRow(contentID, store, &rows, dirty); err != nil {
			logIndexProjectionError(logger, "projectIndexAfterBlob", err)
			return
		}
	}
	for did := range dirty.identityDIDs {
		if err := recomputeIdentityRow(did, store, &rows); err != nil {
			logIndexProjectionError(logger, "projectIndexAfterBlob", err)
			return
		}
	}
	if err := store.ApplyIndexRows(rows); err != nil {
		logIndexProjectionError(logger, "projectIndexAfterBlob", err)
	}
}

// ---------------------------------------------------------------------------
// rebuild
// ---------------------------------------------------------------------------

// rebuildIndexProjection resets the projection when the store's stamped
// projection_version differs from IndexProjectionVersion — the startup migration
// for a pre-existing corpus (a redeploy with a bumped version, or an index that
// was disabled when the corpus was ingested).
//
// A rebuild is now just "clear the rows, reset the cursor": the operation log is
// the authoritative record every row derives from, so the ordinary projection
// worker re-walks it and there is no separate corpus enumeration to keep in sync
// with the incremental path. It returns immediately; the worker drains the
// backlog in budgeted runs while the relay serves, and the rows it has not
// reached yet are simply absent rather than wrong.
//
// Ephemeral stores (MemoryStore) do not implement RebuildableIndexStore — they
// have nothing durable to rebuild — so this is a no-op for them.
func rebuildIndexProjection(store IndexProjectionStore, logger *slog.Logger) error {
	rebuildable, ok := store.(RebuildableIndexStore)
	if !ok {
		return nil
	}
	current, err := rebuildable.GetIndexProjectionVersion()
	if err != nil {
		return err
	}
	if current == IndexProjectionVersion {
		return nil // projection already at the current schema — serve as-is
	}
	logger.Info("index projection: resetting for rebuild", "fromVersion", current, "toVersion", IndexProjectionVersion)
	if err := rebuildable.ClearIndexProjection(); err != nil {
		return err
	}
	if err := store.SetIndexCursor(IndexCursor{}); err != nil {
		return err
	}
	if err := rebuildable.SetIndexProjectionVersion(IndexProjectionVersion); err != nil {
		return err
	}
	logger.Info("index projection: reset complete, re-walking the log", "version", IndexProjectionVersion)
	return nil
}
