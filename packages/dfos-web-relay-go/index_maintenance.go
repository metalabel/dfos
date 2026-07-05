package relay

/*

  INDEX (v0) — MATERIALIZED PROJECTION MAINTENANCE

  "op applied → recompute affected rows". The ingestion pipeline calls
  maintainIndexAfterOp synchronously after each accepted operation; the blob
  route (and the follower materializer) calls maintainIndexAfterBlob after a
  document lands. Recompute reads CURRENT store state through the shared row
  builders (index.go) — the single source of row-value truth — and upserts via
  the store's PutIndex*Row members. Because a row is a pure function of (chain
  state, held blobs, standing credentials), every recompute converges to the same
  row regardless of when it runs; incremental maintenance and a full rebuild are
  interchangeable.

  The projection is a NON-AUTHORITATIVE hint plane. Maintenance therefore never
  fails an authoritative write: every entry point swallows its own errors (and
  recovers panics) so a projection hiccup can never reject an ingested op or a
  stored blob.

  Byte-identical to the TS twin index-maintenance.ts (enforced by the parity
  harness).

*/

import (
	"log/slog"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// enumerateAllLimit is the upper bound for the maintenance-time enumerate-all
// fallback used by the two fan-out triggers (a chain:* grant, and any
// revocation). Both can flip publicRead across many rows without naming a single
// content, so we recompute the bounded affected superset. Kept well above any
// realistic corpus; the SQL store does the equivalent as an indexed
// WHERE public_read = 1 (revocation) or a full projection scan (chain:*).
const enumerateAllLimit = 1<<31 - 1

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
	if err := store.PutIndexContentRow(contentIndexRow(*chain, store)); err != nil {
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
func contentIdsFromCredential(jwsToken string) (wildcard bool, contentIds []string) {
	_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err != nil || payload == nil {
		return false, nil
	}
	att, ok := payload["att"].([]any)
	if !ok {
		return false, nil
	}
	for _, entry := range att {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		resource, ok := m["resource"].(string)
		if !ok {
			continue
		}
		if resource == "chain:*" {
			wildcard = true
		} else if len(resource) > len("chain:") && resource[:len("chain:")] == "chain:" {
			contentIds = append(contentIds, resource[len("chain:"):])
		}
	}
	return wildcard, contentIds
}

// maintainIndexAfterOp maintains the index projection after ONE accepted
// operation. Called from the single ingest choke point (IngestOperations) in
// dependency order, right after each op is applied to the store. Only
// status == "new" mutates state; a duplicate is already reflected, a rejection
// changed nothing.
//
// Mapping (identical across all implementations):
//   - identity-op / artifact for chain D → recompute identity row D
//   - content-op for chain C             → recompute content row C (+ anchored identities)
//   - credential grant                   → recompute the att-named content rows,
//     or all content rows on a chain:* grant
//   - revocation                         → recompute all currently-public-read
//     content rows (a revocation only ever turns publicRead true→false, so this
//     is the complete affected superset)
//   - countersign                        → upsert the accepted countersign row
//     (dedup returns status "duplicate", so a status:"new" countersign IS the
//     accepted one — never a shadowed raw op)
//
// Non-authoritative: swallows its own errors and recovers panics so it never
// fails the write.
func maintainIndexAfterOp(result IngestionResult, jwsToken string, store Store) {
	if result.Status != "new" || result.Kind == "" {
		return
	}
	defer func() { _ = recover() }()

	switch result.Kind {
	case "identity-op", "artifact":
		if result.ChainID != "" {
			_ = recomputeIdentityRow(result.ChainID, store)
		}
	case "content-op":
		if result.ChainID != "" {
			_ = recomputeContentRow(result.ChainID, store)
		}
	case "credential":
		wildcard, contentIds := contentIdsFromCredential(jwsToken)
		if wildcard {
			_ = recomputeAllContentRows(store)
		} else {
			for _, contentID := range contentIds {
				_ = recomputeContentRow(contentID, store)
			}
		}
	case "revocation":
		_ = recomputePublicReadContentRows(store)
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
		if payload != nil {
			if value, ok := payload["relation"].(string); ok {
				relation = &value
			}
			if value, ok := payload["did"].(string); ok {
				witnessDID = value
			}
		}
		_ = store.PutIndexCountersignatureRow(storedIndexCountersignature{
			CID:        cid,
			TargetCID:  result.ChainID,
			Relation:   relation,
			JWSToken:   jwsToken,
			WitnessDID: witnessDID,
		})
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
// built purely incrementally by maintainIndexAfterOp.
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
		if (i+1)%rebuildProgressEvery == 0 {
			logger.Info("index projection: rebuilt identities", "count", i+1, "total", len(identities))
		}
	}

	contents, err := store.ListContentChains()
	if err != nil {
		return err
	}
	for i, chain := range contents {
		if err := store.PutIndexContentRow(contentIndexRow(chain, store)); err != nil {
			return err
		}
		if (i+1)%rebuildProgressEvery == 0 {
			logger.Info("index projection: rebuilt content", "count", i+1, "total", len(contents))
		}
	}

	countersigns, err := store.ListCountersignatures()
	if err != nil {
		return err
	}
	for _, cs := range countersigns {
		if err := store.PutIndexCountersignatureRow(storedIndexCountersignature{
			CID:        cs.CID,
			TargetCID:  cs.TargetCID,
			Relation:   cs.Relation,
			JWSToken:   cs.JWSToken,
			WitnessDID: cs.WitnessDID,
		}); err != nil {
			return err
		}
	}

	return rebuildable.SetIndexProjectionVersion(IndexProjectionVersion)
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
	defer func() { _ = recover() }()
	contentIds, err := store.GetIndexContentIDsByDocumentCID(documentCID)
	if err != nil {
		return
	}
	for _, contentID := range contentIds {
		_ = recomputeContentRow(contentID, store)
	}
}
