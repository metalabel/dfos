package relay

import "testing"

// referenceStore is the full shape BOTH reference stores implement: the write
// contract, both halves of the index profile, the writer-internal bookkeeping,
// and the mailbox.
//
// It is a TEST type on purpose. No production surface asks a store to be all of
// these at once — that was the 53-member interface this package replaced, and its
// only production consumer satisfied a third of it by throwing. What a store can
// do is a fact about its type, and NewRelay narrows once. Here it is only a
// convenience so a decorator can embed one interface and override one method.
type referenceStore interface {
	RelayWriteStore
	IndexReadStore
	IndexWriteStore
	RelayWriterState
	SigningStore
	MigratableStore
}

// Both reference stores satisfy every contract they claim, checked at compile
// time rather than at the first call.
var (
	_ referenceStore        = (*MemoryStore)(nil)
	_ referenceStore        = (*SQLiteStore)(nil)
	_ MigratableStore       = (*MemoryStore)(nil)
	_ MigratableStore       = (*SQLiteStore)(nil)
	_ RebuildableIndexStore = (*SQLiteStore)(nil)
	_ IndexProjectionStore  = (*MemoryStore)(nil)
	_ IndexProjectionStore  = (*SQLiteStore)(nil)
)

// commitOne is the test seeding path: hand the store one whole operation the way
// ingestion does. Tests that need a chain, a revocation, or a held credential in
// place before the behavior under test runs use this rather than a pile of
// per-table put members, because those members no longer exist — the write
// contract is one atomic call.
func commitOne(t *testing.T, store RelayWriteStore, commit OperationCommit) {
	t.Helper()
	if _, err := store.Commit(CommitBatch{Operation: &commit}); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// commitBlob seeds one document blob.
func commitBlob(t *testing.T, store RelayWriteStore, key BlobKey, bytes []byte) {
	t.Helper()
	if _, err := store.Commit(CommitBatch{Blob: &BlobCommit{Key: key, Bytes: bytes}}); err != nil {
		t.Fatalf("commit blob: %v", err)
	}
}

// seedRevocation seeds one revocation the way ingestion commits one: the
// operation row, the revocation, and the issuer-scoped grant removal together.
func seedRevocation(t *testing.T, store RelayWriteStore, revocation StoredRevocation) error {
	t.Helper()
	_, err := store.Commit(CommitBatch{Operation: &OperationCommit{
		Operation: StoredOperation{
			CID: revocation.CID, JWSToken: revocation.JWSToken,
			ChainType: "revocation", ChainID: revocation.IssuerDID,
		},
		Revocation:             &revocation,
		RemovePublicCredential: &PublicCredentialRemoval{IssuerDID: revocation.IssuerDID, CredentialCID: revocation.CredentialCID},
	}})
	return err
}

// seedLogEntry seeds one operation and its global-log append — what a peer's log
// serves back when this store stands in for a peer.
func seedLogEntry(t *testing.T, store RelayWriteStore, entry LogEntry, chainType string) error {
	t.Helper()
	_, err := store.Commit(CommitBatch{Operation: &OperationCommit{
		Operation: StoredOperation{CID: entry.CID, JWSToken: entry.JWSToken, ChainType: chainType, ChainID: entry.ChainID},
		LogEntry:  &entry,
	}})
	return err
}

// The projection write side is one batched call, which is right for the worker
// and noisy for a test that wants a single row in place. These keep the old
// one-row ergonomics without putting a per-row member back on the contract.

func putIndexIdentityRow(s IndexWriteStore, row IndexIdentityRow) error {
	return s.ApplyIndexRows(IndexRowBatch{Identities: []IndexIdentityRow{row}})
}

func putIndexContentRow(s IndexWriteStore, row IndexContentRow) error {
	return s.ApplyIndexRows(IndexRowBatch{Content: []IndexContentRow{row}})
}

func putIndexArtifactRow(s IndexWriteStore, row IndexArtifactRow) error {
	return s.ApplyIndexRows(IndexRowBatch{Artifacts: []IndexArtifactRow{row}})
}

func putIndexCountersignatureRow(s IndexWriteStore, row StoredIndexCountersignature) error {
	return s.ApplyIndexRows(IndexRowBatch{Countersignatures: []StoredIndexCountersignature{row}})
}

func putIndexContentSigner(s IndexWriteStore, contentID, did string) error {
	return s.ApplyIndexRows(IndexRowBatch{ContentSigners: []IndexContentSignerRow{{ContentID: contentID, DID: did}}})
}

func putIndexCreditRows(s IndexWriteStore, contentID string, rows []IndexCreditRow) error {
	return s.ApplyIndexRows(IndexRowBatch{Credits: []IndexCreditRowSet{{ContentID: contentID, Rows: rows}}})
}

func putIndexIdentityKey(s IndexWriteStore, did, keyID, publicKey string) error {
	return s.ApplyIndexRows(IndexRowBatch{IdentityKeys: []IndexIdentityKeyRow{{DID: did, KeyID: keyID, PublicKey: publicKey}}})
}

func putBlob(s RelayWriteStore, key BlobKey, data []byte) error {
	_, err := s.Commit(CommitBatch{Blob: &BlobCommit{Key: key, Bytes: data}})
	return err
}
