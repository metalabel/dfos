package relay

/*

  INDEX (v0) — MATERIALIZED PROJECTION MAINTENANCE

  "op applied → recompute affected rows". The ingestion pipeline records the
  affected rows for each accepted op into a per-batch indexDirtySet
  (collectIndexDirtyAfterOp), then flushes ONCE at the end of the batch
  (flushIndexMaintenance); the blob route (and the follower materializer) calls
  maintainIndexAfterBlob after a document lands. Recompute reads CURRENT store
  state through the shared row builders (index.go) — the single source of
  row-value truth — and upserts via the store's PutIndex*Row members. Because a
  row is a pure function of (chain state, held blobs, standing credentials),
  every recompute converges to the same row regardless of when it runs;
  incremental maintenance and a full rebuild are interchangeable.

  Why batch-coalesce rather than recompute per op: two triggers fan out over a
  bounded-but-large superset — a chain:* grant touches every content row, and a
  wildcard / unresolvable revocation (or an identity deletion, which removes a
  credential issuer / delegation hop) touches every currently-public-read
  content row. Running that per op means a sync batch delivering N such ops does
  N back-to-back full sweeps. Collecting dirtiness across the batch and flushing
  once collapses that to a single sweep, while the post-batch store state the
  flush reads is the same final state each per-op recompute would have converged
  to — so the projection is byte-identical, just computed once.

  The projection is a NON-AUTHORITATIVE hint plane. Maintenance therefore never
  fails an authoritative write: every entry point swallows its own errors (and
  recovers panics) so a projection hiccup can never reject an ingested op or a
  stored blob. Swallowed is not SILENT, though: each fence logs what it caught
  (see logIndexMaintenanceRecover), because a projection that is persistently
  failing looks exactly like one that is merely quiet. The logging is
  observability only — the swallow semantics are unchanged.

  A materialized row is a snapshot of standing authority AT LAST TOUCH. One input
  to publicRead — a standing credential's exp — is wall-clock-relative, so a row
  can outlive the grant that made it public until the next op happens to dirty
  that content (or a full rebuild reruns the builder). Acceptable for a
  non-authoritative hint plane: authoritative reads always re-verify at request
  time; the index only advertises a browse hint. See specs/WEB-RELAY.md §Index.

  Byte-identical to the TS twin index-maintenance.ts (enforced by the parity
  harness).

*/

import (
	"log/slog"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// logIndexMaintenanceRecover reports a panic caught by a projection-maintenance
// fence. Deferred as `defer logIndexMaintenanceRecover(site)` at each entry
// point: it calls recover() itself, so the fence still swallows the panic and
// the authoritative write still succeeds — it just stops being invisible.
//
// These are package-level functions with no relay receiver (the ingest choke
// point is the package function IngestOperations), so they log through
// slog.Default() — the same logger NewRelay falls back to when none is supplied.
func logIndexMaintenanceRecover(site string) {
	if rec := recover(); rec != nil {
		slog.Default().Error("index projection maintenance panicked — projection row(s) may be stale",
			"site", site, "recovered", rec)
	}
}

// enumerateAllLimit is the upper bound for the maintenance-time enumerate-all
// fallback used by the two fan-out triggers (a chain:* grant, and a wildcard /
// unresolvable revocation). Both can flip publicRead across many rows without
// naming a single content, so we recompute the bounded affected superset. Kept
// well above any realistic corpus.
//
// In this (SQLite) store the revocation sweep is an indexed WHERE public_read = ?
// — idx_index_content_public covers (public_read, content_id) — while the
// chain:* sweep is a full projection scan. The TS twin's in-memory store filters
// its row map linearly in both cases.
const enumerateAllLimit = 1<<31 - 1

// indexDirtySet is the rows one batch of accepted ops dirtied, collected across
// the batch and flushed once. allContent/allPublicContent are the two fan-out
// supersets (a chain:* grant → all content; a wildcard / unresolvable revocation
// or identity deletion → all currently-public-read content); when set they
// subsume the per-id sets, so a batch of N such ops flushes a single sweep
// instead of N.
type indexDirtySet struct {
	identityDIDs     map[string]struct{}
	contentIDs       map[string]struct{}
	countersigns     []storedIndexCountersignature
	artifacts        []indexArtifactRow
	allContent       bool
	allPublicContent bool
}

// newIndexDirtySet returns a fresh, empty dirty set for one ingest batch.
func newIndexDirtySet() *indexDirtySet {
	return &indexDirtySet{
		identityDIDs: map[string]struct{}{},
		contentIDs:   map[string]struct{}{},
	}
}

// recomputeIdentityRow recomputes one identity projection row from current store
// state.
func recomputeIdentityRow(did string, store Store) error {
	chain, err := store.GetIdentityChain(did)
	if err != nil || chain == nil {
		return err
	}
	return store.PutIndexIdentityRow(identityIndexRow(*chain, store))
}

// recomputeContentRow recomputes one content projection row from current store
// state, then cascades to every identity row anchored on it (profile.anchor ==
// contentID) — an identity's profile projection embeds the anchored content's
// publicRead, doc schema, and name, so a content change is also an identity
// change.
func recomputeContentRow(contentID string, store Store) error {
	chain, err := store.GetContentChain(contentID)
	if err != nil || chain == nil {
		return err
	}
	src := contentProjectionSources(*chain, store)
	if err := store.PutIndexContentRow(contentIndexRow(*chain, src)); err != nil {
		return err
	}
	if err := store.PutIndexCreditRows(contentID, creditIndexRows(*chain, src)); err != nil {
		return err
	}
	anchoredDIDs, err := store.GetIndexIdentityDIDsByProfileAnchor(contentID)
	if err != nil {
		return err
	}
	for _, did := range anchoredDIDs {
		if err := recomputeIdentityRow(did, store); err != nil {
			return err
		}
	}
	return nil
}

// recomputeAllContentRows recomputes every content row (+ anchored identities).
// Fan-out fallback for a chain:* grant.
func recomputeAllContentRows(store Store) error {
	rows, err := store.QueryIndexContent(IndexContentQuery{Limit: enumerateAllLimit})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := recomputeContentRow(row.ContentID, store); err != nil {
			return err
		}
	}
	return nil
}

// recomputePublicReadContentRows recomputes every currently-public-read content
// row (+ anchored identities). Fan-out fallback for a revocation.
func recomputePublicReadContentRows(store Store) error {
	publicRead := true
	rows, err := store.QueryIndexContent(IndexContentQuery{PublicRead: &publicRead, Limit: enumerateAllLimit})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := recomputeContentRow(row.ContentID, store); err != nil {
			return err
		}
	}
	return nil
}

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
// op. parsed reports whether every resource in the token was actually readable —
// false when the JWS didn't decode, when `att` isn't an array, or when any entry
// was unreadable and therefore could have named a resource this returned scope
// omits. The two callers deliberately differ on what to do about it: the index
// projection is a non-authoritative hint plane, so it ignores parsed and just
// dirties what it could read, while markContentFollowDirty fails open to a full
// scan rather than silently skip content-follow work.
func contentIdsFromCredentialToken(jwsToken string) (wildcard bool, contentIds []string, parsed bool) {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || payload == nil {
		return false, nil, false
	}
	att, ok := payload["att"].([]any)
	if !ok {
		return false, nil, false
	}
	parsed = true
	credential := StoredPublicCredential{}
	for _, entry := range att {
		m, ok := entry.(map[string]any)
		if !ok {
			parsed = false
			continue
		}
		resource, ok := m["resource"].(string)
		if !ok {
			parsed = false
			continue
		}
		credential.Att = append(credential.Att, AttenuationPair{Resource: resource})
	}
	wildcard, contentIds = contentIdsFromCredential(credential)
	return wildcard, contentIds, parsed
}

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
// take dfos.IdentityState.ProvedKeys; see putIndexIdentityProvedKeys.
//
// There is no key-class column: which array carried the key is the chain's
// answer, not the index's, so all three fold into one flat list.
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

// putIndexIdentityProvedKeys records every key an identity chain has EVER PROVED
// into the `key=` reverse index, as of the operation just accepted.
//
// HAS-EVER-PROVED, NOT HAS-EVER-DECLARED (KEY-PROOF.md, Holder Obligations).
// This index is the one-key-one-DID oracle a holder consults before signing a key
// proof, and it REFUSES on a hit. Indexing declarations would hand a stranger a
// burn: anyone can write anyone's public key into their own chain, so a chain
// that merely LISTS a key it does not hold would make every future ceremony for
// the true holder refuse. A declaration publishes no cross-DID link — only a
// proof does — so only a proof belongs in the oracle.
//
// MONOTONIC, WHICH IS WHY WRITING THE WHOLE UNION PER OPERATION IS RIGHT. The
// index is append-only and ProvedKeys never shrinks, so the union after
// operation N is a superset of the union after N-1. Re-writing all of it on each
// accepted op is therefore idempotent, converges on the chain's final union, and
// — unlike the per-op declaration read this replaces — can never enter a key
// before the operation that proved it. Reading head state per op rather than
// recomputing at flush still matters for the opposite reason it used to: an
// update REPLACES the key arrays, and only ProvedKeys carries the rotated-out
// keys forward.
func putIndexIdentityProvedKeys(did string, store Store) {
	chain, err := store.GetIdentityChain(did)
	if err != nil || chain == nil {
		return
	}
	for _, key := range keysInKeyState(provedKeyState(chain.State)) {
		_ = store.PutIndexIdentityKey(did, key.ID, key.PublicKeyMultibase)
	}
}

// signerKeyForOperation resolves the multibase public key ONE accepted operation
// was signed with — the value the operation-log row retains as the substrate for
// /index/v0/operations?signerKey=. Returns "" when the key cannot be resolved,
// which the stores persist as NULL and no filter value ever matches.
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
// HAS-EVER-PROVED, the same rule as `key=`, so the two columns agree on which
// keys exist. Mirrors CreateKeyResolver's lookup rather than reusing it, because
// the resolver returns decoded bytes and the multibase rendering is what the
// index stores. A rotated-out key still resolves: the row is a fact about the
// past, and possession does not become untrue.
//
// ONE ROW KIND CAN LEGITIMATELY RESOLVE TO NOTHING under this rule: an identity
// operation signed by a controller key the chain declared but no proof ever
// admitted. Signer validity is declared-state-based on purpose, so that
// operation is valid and sequenced — but its signing key was never proved, so it
// is not in the has-ever-proved population and the column stays NULL. The
// filter's honest answer for a key no chain proved is "no rows", not a row
// keyed by evidence that never existed.
func signerKeyForOperation(jwsToken string, store Store) string {
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

// appendOperationToLog is the single write path into the operation log: it
// resolves the accepted operation's signer key and hands the completed entry to
// the store. Every ingest path routes through here rather than calling
// store.AppendToLog directly, so the signer key can never be resolved at one
// call site and forgotten at another.
func appendOperationToLog(store Store, entry LogEntry) error {
	entry.SignerKey = signerKeyForOperation(entry.JWSToken, store)
	return store.AppendToLog(entry)
}

// collectIndexDirtyAfterOp collects the rows ONE accepted operation dirties into
// the batch's dirty set. Called from the single ingest choke point
// (IngestOperations) in dependency order, right after each op is applied to the
// store. Only status == "new" mutates state; a duplicate is already reflected, a
// rejection changed nothing. Nothing is recomputed here — the batch flushes once
// via flushIndexMaintenance.
//
// Mapping (identical across all implementations):
//   - identity delete/restore for D    → dirty identity row D; delete sweeps the
//     currently-public subset, while restore sweeps all content because suspended
//     rows are no longer in that subset
//   - content-op for chain C             → dirty content row C (+ anchored identities)
//   - credential grant                   → dirty the att-named content rows, or
//     all content rows on a chain:* grant
//   - revocation                         → dirty the revoked held grant's att-named
//     content rows, or all currently-public-read rows when wildcard / unresolvable
//   - countersign                        → queue the accepted countersign row
//     upsert (dedup returns status "duplicate", so a status:"new" countersign IS
//     the accepted one — never a shadowed raw op)
//   - artifact                          → queue the standalone artifact row upsert
//
// Non-authoritative: swallows its own errors and recovers panics so it never
// fails the write.
func collectIndexDirtyAfterOp(result IngestionResult, jwsToken string, store Store, dirty *indexDirtySet) {
	if result.Status != "new" || result.Kind == "" {
		return
	}
	defer logIndexMaintenanceRecover("collectIndexDirtyAfterOp")

	switch result.Kind {
	case "identity-op":
		if result.ChainID != "" {
			dirty.identityDIDs[result.ChainID] = struct{}{}
			// Has-ever-proved keys are captured HERE, per op, against the state the
			// op just produced — the row set is append-only history, and an update's
			// replacement of the key arrays would otherwise erase it.
			putIndexIdentityProvedKeys(result.ChainID, store)
			_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
			if err == nil && payload != nil {
				if payload["type"] == "delete" {
					dirty.allPublicContent = true
				}
				if payload["type"] == "restore" {
					dirty.allContent = true
				}
			}
		}
	case "artifact":
		// One op, one receipt stamp: source ingestedAt from the stored operation's
		// receipt stamp so this row and /index/v0/operations report one receipt
		// time for the same op. Wall clock only as a last-resort fallback.
		ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		if op, err := store.GetOperation(result.CID); err == nil && op != nil && op.IngestedAt != "" {
			ingestedAt = op.IngestedAt
		}
		if row := artifactIndexRow(result.CID, jwsToken, ingestedAt); row != nil {
			dirty.artifacts = append(dirty.artifacts, *row)
		}
	case "content-op":
		if result.ChainID != "" {
			dirty.contentIDs[result.ChainID] = struct{}{}
			if _, payload, err := dfos.DecodeJWSUnsafe(jwsToken); err == nil && payload != nil {
				if signerDID, ok := payload["did"].(string); ok && signerDID != "" {
					_ = store.PutIndexContentSigner(result.ChainID, signerDID)
				}
			}
		}
	case "credential":
		wildcard, contentIds, _ := contentIdsFromCredentialToken(jwsToken)
		if wildcard {
			dirty.allContent = true
		} else {
			for _, contentID := range contentIds {
				dirty.contentIDs[contentID] = struct{}{}
			}
		}
	case "revocation":
		if result.RevokedGrant != nil && !result.RevokedGrant.Wildcard {
			for _, contentID := range result.RevokedGrant.ContentIDs {
				dirty.contentIDs[contentID] = struct{}{}
			}
		} else {
			dirty.allPublicContent = true
		}
	case "countersign":
		if result.ChainID == "" {
			return
		}
		header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
		if err != nil {
			return
		}
		cid := result.CID
		if header != nil && header.CID != "" {
			cid = header.CID
		}
		var relation *string
		var witnessDID string
		var createdAt string
		if payload != nil {
			if value, ok := payload["relation"].(string); ok {
				relation = &value
			}
			if value, ok := payload["did"].(string); ok {
				witnessDID = value
			}
			createdAt, _ = payload["createdAt"].(string)
		}
		// One op, one receipt stamp: same sourcing as the artifact case above —
		// the stored operation's stamp, keyed by the ingest CID (the countersign
		// row's own CID may be the header CID), so this row and
		// /index/v0/operations report one receipt time for the same op. Wall
		// clock only as a last-resort fallback.
		ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		if op, err := store.GetOperation(result.CID); err == nil && op != nil && op.IngestedAt != "" {
			ingestedAt = op.IngestedAt
		}
		dirty.countersigns = append(dirty.countersigns, storedIndexCountersignature{
			CID:        cid,
			TargetCID:  result.ChainID,
			Relation:   relation,
			JWSToken:   jwsToken,
			WitnessDID: witnessDID,
			CreatedAt:  createdAt,
			IngestedAt: ingestedAt,
		})
	}
}

// flushIndexMaintenance flushes the batch's collected dirtiness ONCE, after
// every op has been applied to the store. All recompute reads the final
// post-batch store state, so a single pass converges to the same rows N per-op
// recomputes would have. allContent subsumes everything else; otherwise the
// public-read sweep and the per-id content rows are unioned (a per-id content may
// be brand-new and thus not yet enumerable by the sweep, so both run), then the
// identity rows (op'd identities that may anchor no recomputed content), then the
// queued countersign upserts.
//
// Non-authoritative: swallows its own errors and recovers panics so it never
// fails the write.
func flushIndexMaintenance(dirty *indexDirtySet, store Store) {
	defer logIndexMaintenanceRecover("flushIndexMaintenance")

	// Errors are still swallowed (the projection must never fail a write), but
	// they are counted and reported once for the whole flush — one aggregate line
	// instead of per-row spam on a fan-out sweep, and enough to see a projection
	// that is persistently failing rather than merely idle.
	failures := 0
	swallow := func(err error) {
		if err != nil {
			failures++
		}
	}
	defer func() {
		if failures > 0 {
			slog.Default().Warn("index projection maintenance had errors — rows may be stale",
				"failures", failures)
		}
	}()

	if dirty.allContent {
		swallow(recomputeAllContentRows(store))
	} else if dirty.allPublicContent {
		swallow(recomputePublicReadContentRows(store))
	}
	// The per-id set ALWAYS runs: the sweeps above enumerate the materialized
	// projection, so a content chain born in this very batch is invisible to
	// them — only its per-id entry can create the row. Dropping the set inside
	// the wildcard branch silently lost every chain co-batched with a chain:*
	// credential (peer sync and the sequencer batch up to 10k ops).
	for contentID := range dirty.contentIDs {
		swallow(recomputeContentRow(contentID, store))
	}
	for did := range dirty.identityDIDs {
		swallow(recomputeIdentityRow(did, store))
	}
	for _, row := range dirty.countersigns {
		swallow(store.PutIndexCountersignatureRow(row))
	}
	for _, row := range dirty.artifacts {
		swallow(store.PutIndexArtifactRow(row))
	}
}

// rebuildIndexProjection rebuilds the whole materialized projection from the
// authoritative chain/countersign tables when the store's stamped
// projection_version differs from IndexProjectionVersion — the startup migration
// path for a pre-existing corpus (a redeploy with a bumped version, or an index
// that was disabled when the corpus was ingested). Synchronous: it runs to
// completion in NewRelay BEFORE the relay serves, so the first /index/v0 request
// sees a complete projection.
//
// Ephemeral stores (MemoryStore) don't implement RebuildableIndexStore — they
// have nothing durable to rebuild, so this is a no-op and their projection is
// built purely incrementally by collectIndexDirtyAfterOp / flushIndexMaintenance.
func rebuildIndexProjection(store Store, logger *slog.Logger) error {
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
	logger.Info("index projection: rebuilding", "fromVersion", current, "toVersion", IndexProjectionVersion)

	// Wrap the rebuild in one transaction when the store supports it: 42k+ upserts
	// as autocommit statements is orders of magnitude slower, and the batch also
	// makes the version bump atomic with the row writes (a crash mid-rebuild leaves
	// the old version stamped, so the next boot retries cleanly).
	batchable, hasBatch := store.(BatchableStore)
	if hasBatch {
		if err := batchable.BeginWriteBatch(); err != nil {
			return err
		}
	}
	if err := rebuildIndexProjectionRows(store, rebuildable, logger); err != nil {
		if hasBatch {
			_ = batchable.RollbackWriteBatch()
		}
		return err
	}
	if hasBatch {
		if err := batchable.CommitWriteBatch(); err != nil {
			return err
		}
	}
	logger.Info("index projection: rebuild complete", "version", IndexProjectionVersion)
	return nil
}

const rebuildProgressEvery = 5000

func rebuildIndexProjectionRows(store Store, rebuildable RebuildableIndexStore, logger *slog.Logger) error {
	if err := rebuildable.ClearIndexProjection(); err != nil {
		return err
	}

	identities, err := store.ListIdentityChains()
	if err != nil {
		return err
	}
	for i, chain := range identities {
		if err := store.PutIndexIdentityRow(identityIndexRow(chain, store)); err != nil {
			return err
		}
		// The reverse index is has-ever-PROVED, and the chain walk already folded
		// that union onto head state — so the backfill reads ProvedKeys instead of
		// replaying the op log under a possession rule restated here. A key some
		// later update rotated out still comes back: ProvedKeys is monotonic.
		for _, key := range keysInKeyState(provedKeyState(chain.State)) {
			if err := store.PutIndexIdentityKey(chain.DID, key.ID, key.PublicKeyMultibase); err != nil {
				return err
			}
		}
		if (i+1)%rebuildProgressEvery == 0 {
			logger.Info("index projection: rebuilt identities", "count", i+1, "total", len(identities))
		}
	}

	contents, err := store.ListContentChains()
	if err != nil {
		return err
	}
	for i, chain := range contents {
		src := contentProjectionSources(chain, store)
		if err := store.PutIndexContentRow(contentIndexRow(chain, src)); err != nil {
			return err
		}
		if err := store.PutIndexCreditRows(chain.ContentID, creditIndexRows(chain, src)); err != nil {
			return err
		}
		for _, token := range chain.Log {
			_, payload, err := dfos.DecodeJWSUnsafe(token)
			if err != nil || payload == nil {
				continue
			}
			signerDID, _ := payload["did"].(string)
			if signerDID == "" {
				continue
			}
			if err := store.PutIndexContentSigner(chain.ContentID, signerDID); err != nil {
				return err
			}
		}
		if (i+1)%rebuildProgressEvery == 0 {
			logger.Info("index projection: rebuilt content", "count", i+1, "total", len(contents))
		}
	}

	countersigns, err := store.ListCountersignatures()
	if err != nil {
		return err
	}

	artifacts, err := store.ListArtifactOperations()
	if err != nil {
		return err
	}
	for _, op := range artifacts {
		if row := artifactIndexRow(op.CID, op.JWSToken, op.IngestedAt); row != nil {
			if err := store.PutIndexArtifactRow(*row); err != nil {
				return err
			}
		}
	}
	for _, cs := range countersigns {
		if err := store.PutIndexCountersignatureRow(storedIndexCountersignature{
			CID:        cs.CID,
			TargetCID:  cs.TargetCID,
			Relation:   cs.Relation,
			JWSToken:   cs.JWSToken,
			WitnessDID: cs.WitnessDID,
			CreatedAt:  cs.CreatedAt,
			IngestedAt: cs.IngestedAt,
		}); err != nil {
			return err
		}
	}

	if err := rebuildOperationLogSignerKeys(store, rebuildable, logger); err != nil {
		return err
	}

	return rebuildable.SetIndexProjectionVersion(IndexProjectionVersion)
}

// rebuildOperationLogSignerKeys backfills the signer key on operation-log rows
// that carry none — every row on a corpus ingested before the column existed.
//
// Runs LAST and in place. The identity chains it resolves against are read
// directly from the authoritative tables, not from the projection, so ordering
// against the passes above is not a dependency — but the operation log is the
// authoritative record, never a projection table, so this is a targeted UPDATE
// of the missing column rather than the clear-and-re-derive the other passes do.
//
// A row that still does not resolve (an identity chain this relay no longer
// holds, a malformed kid) is left NULL and stays invisible to signerKey= — the
// filter's honest answer is "this relay cannot say", not a wrong key.
func rebuildOperationLogSignerKeys(store Store, rebuildable RebuildableIndexStore, logger *slog.Logger) error {
	pending, err := rebuildable.ListOperationLogEntriesMissingSignerKey()
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	resolved := 0
	for i, entry := range pending {
		signerKey := signerKeyForOperation(entry.JWSToken, store)
		if signerKey == "" {
			continue
		}
		if err := rebuildable.SetOperationLogSignerKey(entry.CID, signerKey); err != nil {
			return err
		}
		resolved++
		if (i+1)%rebuildProgressEvery == 0 {
			logger.Info("index projection: rebuilt operation signer keys", "count", i+1, "total", len(pending))
		}
	}
	logger.Info("index projection: operation signer keys backfilled",
		"resolved", resolved, "unresolved", len(pending)-resolved)
	return nil
}

// maintainIndexAfterBlob maintains the index projection after a document blob
// lands. A blob arriving (often late, out of band from the op that referenced
// it) can turn a content row's docSchema/name/profile projection from unknown to
// known, so recompute every content row that projects this documentCID,
// cascading to their anchored identities.
//
// Non-authoritative: swallows its own errors and recovers panics so it never
// fails the blob write.
func maintainIndexAfterBlob(documentCID string, store Store) {
	defer logIndexMaintenanceRecover("maintainIndexAfterBlob")
	contentIds, err := store.GetIndexContentIDsByDocumentCID(documentCID)
	if err != nil {
		slog.Default().Warn("index projection: blob maintenance lookup failed — rows may be stale",
			"documentCid", documentCID, "error", err)
		return
	}
	failures := 0
	for _, contentID := range contentIds {
		if err := recomputeContentRow(contentID, store); err != nil {
			failures++
		}
	}
	if failures > 0 {
		slog.Default().Warn("index projection: blob maintenance had errors — rows may be stale",
			"documentCid", documentCID, "failures", failures)
	}
}
