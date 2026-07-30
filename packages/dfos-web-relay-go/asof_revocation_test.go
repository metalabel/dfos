package relay

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// AS-OF REVOCATION AT THE RELAY (Go twin)
//
// Two decisions, deliberately split:
//
//   - ACCEPTANCE (ingest) is a FRESHNESS decision. A relay must not admit a NEW
//     operation authorized by a credential it already knows to be revoked — no
//     matter how the operation is dated. Net behavior is UNCHANGED by the as-of
//     work, and the backdating test below is the guard that ingest did not
//     quietly adopt as-of semantics (which would hand a revoked delegate an
//     indefinite write window just by choosing an older createdAt).
//   - VALIDITY (historical replay via GetContentStateAtCID) is an AS-OF decision.
//     A credential revoked AFTER an operation was committed leaves that operation
//     valid, so the fork-point state it contributes to stays computable.
//
// Twin of dfos-web-relay/tests/asof-revocation.spec.ts — keep the two in lockstep.
// ===================================================================

// asOfChain is a seeded store with creator + delegate identities, a genesis
// content chain, and a write credential from creator to delegate.
type asOfChain struct {
	store         *MemoryStore
	creator       testIdentity
	delegate      testIdentity
	contentID     string
	genesisOpCID  string
	credential    string
	credentialCID string
}

// seedAsOfChain seeds the store. The genesis op and the credential's [iat, exp)
// window are both well backdated so ops dated in the recent past stay valid.
func seedAsOfChain(t *testing.T, genesisOffset time.Duration) asOfChain {
	t.Helper()
	now := time.Now()
	store := NewMemoryStore()
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	IngestOperations([]string{creator.token, delegate.token}, store)

	genesisToken, contentID, genesisOpCID := signBackdatedContentCreate(t, creator, newDocCID(t, "genesis"), now.Add(genesisOffset))
	if res := IngestOperations([]string{genesisToken}, store); res[0].Status != "new" {
		t.Fatalf("seed genesis: %s (%s)", res[0].Status, res[0].Error)
	}

	creatorKid := creator.did + "#" + creator.auth.keyID
	credential := mintCredentialWithExp(t, creator.did, creatorKid, creator.auth.priv,
		delegate.did, "chain:"+contentID, "write",
		now.Add(-2*time.Hour).Unix(), now.Add(2*time.Hour).Unix())
	credHeader, _, err := dfos.DecodeJWSUnsafe(credential)
	if err != nil {
		t.Fatalf("decode credential: %v", err)
	}

	return asOfChain{
		store:         store,
		creator:       creator,
		delegate:      delegate,
		contentID:     contentID,
		genesisOpCID:  genesisOpCID,
		credential:    credential,
		credentialCID: credHeader.CID,
	}
}

// revoke signs and ingests a revocation of the seeded credential, stamped NOW.
func (c asOfChain) revoke(t *testing.T) {
	t.Helper()
	creatorKid := c.creator.did + "#" + c.creator.auth.keyID
	token, _, err := dfos.SignRevocation(c.creator.did, c.credentialCID, creatorKid, c.creator.auth.priv)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	if res := IngestOperations([]string{token}, c.store); res[0].Status != "new" {
		t.Fatalf("ingest revocation: %s (%s)", res[0].Status, res[0].Error)
	}
}

// signBackdatedUpdate hand-builds a NON-delegated (creator-signed) update op with a
// caller-chosen createdAt. The delegated twin is signBackdatedDelegatedUpdate
// (ingest_exp_basis_test.go); this one carries no authorization, so it isolates the
// fork-state replay from ingest's own credential checks.
func signBackdatedUpdate(t *testing.T, id testIdentity, previousCID, docCID string, createdAt time.Time) (token, opCID string) {
	t.Helper()
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"did":                  id.did,
		"previousOperationCID": previousCID,
		"documentCID":          docCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt.UTC().Format(expBasisTimeFormat),
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(update): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: id.did + "#" + id.auth.keyID, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, id.auth.priv)
	if err != nil {
		t.Fatalf("CreateJWS(update): %v", err)
	}
	return token, cidStr
}

// ---------------------------------------------------------------------------
// store: the as-of compare
// ---------------------------------------------------------------------------

// TestStorePersistsRevocationCreatedAtAndAnswersBothQuestions pins the store
// contract: the signed createdAt is persisted, asOf 0 is the freshness answer, and
// a supplied asOf compares against that boundary inclusively.
func TestStorePersistsRevocationCreatedAtAndAnswersBothQuestions(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	c.revoke(t)

	stored, err := c.store.GetRevocationForCredential(c.credentialCID)
	if err != nil || stored == nil {
		t.Fatalf("GetRevocationForCredential: %v (nil=%v)", err, stored == nil)
	}
	if stored.CreatedAt == "" {
		t.Fatal("revocation createdAt was not persisted — as-of is unanswerable")
	}
	revokedAt, ok := revocationCreatedAtUnix(stored.CreatedAt)
	if !ok {
		t.Fatalf("persisted createdAt %q is unparseable", stored.CreatedAt)
	}

	// timeless — the freshness question
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, 0); !revoked {
		t.Fatal("asOf 0 must report revoked")
	}
	// as-of BEFORE the revocation
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, revokedAt-60); revoked {
		t.Fatal("a revocation must not reach back before its own createdAt")
	}
	// as-of AT the revocation — inclusive boundary
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, revokedAt); !revoked {
		t.Fatal("the as-of boundary is inclusive")
	}
	// as-of AFTER the revocation
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, revokedAt+60); !revoked {
		t.Fatal("as-of after the revocation must report revoked")
	}
}

// TestStoreUnknownCredentialNotRevokedOnEitherBasis is the negative control.
func TestStoreUnknownCredentialNotRevokedOnEitherBasis(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, 0); revoked {
		t.Fatal("no revocation ingested — must not report revoked (timeless)")
	}
	if revoked, _ := c.store.IsCredentialRevoked(c.creator.did, c.credentialCID, time.Now().Unix()); revoked {
		t.Fatal("no revocation ingested — must not report revoked (as-of)")
	}
}

// TestSQLiteStoreAsOfRevocation covers the durable store's own as-of path — a
// different implementation from MemoryStore's (SQL columns plus the lazy
// decode-on-read fallback for rows written before created_at existed).
func TestSQLiteStoreAsOfRevocation(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "asof.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	issuer := createTestIdentity(t)
	credentialCID := "bafyrei" + strings.Repeat("a", 52)
	issuerKid := issuer.did + "#" + issuer.auth.keyID
	token, revCID, err := dfos.SignRevocation(issuer.did, credentialCID, issuerKid, issuer.auth.priv)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}
	_, payload, err := dfos.DecodeJWSUnsafe(token)
	if err != nil {
		t.Fatal(err)
	}
	createdAt, _ := payload["createdAt"].(string)

	if err := store.AddRevocation(StoredRevocation{
		CID: revCID, IssuerDID: issuer.did, CredentialCID: credentialCID,
		JWSToken: token, CreatedAt: createdAt,
	}); err != nil {
		t.Fatalf("AddRevocation: %v", err)
	}

	stored, err := store.GetRevocationForCredential(credentialCID)
	if err != nil || stored == nil {
		t.Fatalf("GetRevocationForCredential: %v (nil=%v)", err, stored == nil)
	}
	if stored.CreatedAt != createdAt {
		t.Fatalf("createdAt round-trip: got %q, want %q", stored.CreatedAt, createdAt)
	}
	revokedAt, ok := revocationCreatedAtUnix(createdAt)
	if !ok {
		t.Fatalf("unparseable createdAt %q", createdAt)
	}

	for _, tc := range []struct {
		name string
		asOf int64
		want bool
	}{
		{"timeless", 0, true},
		{"before", revokedAt - 60, false},
		{"at (inclusive)", revokedAt, true},
		{"after", revokedAt + 60, true},
	} {
		got, err := store.IsCredentialRevoked(issuer.did, credentialCID, tc.asOf)
		if err != nil {
			t.Fatalf("%s: IsCredentialRevoked: %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s (asOf %d): got %v, want %v", tc.name, tc.asOf, got, tc.want)
		}
	}
}

// TestSQLiteStoreLegacyRowResolvesCreatedAtOnRead covers the upgrade path: a row
// written before the created_at column existed comes back NULL, and the boundary is
// recovered from the stored token rather than silently un-revoking history.
func TestSQLiteStoreLegacyRowResolvesCreatedAtOnRead(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "legacy.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	issuer := createTestIdentity(t)
	credentialCID := "bafyrei" + strings.Repeat("b", 52)
	issuerKid := issuer.did + "#" + issuer.auth.keyID
	token, revCID, err := dfos.SignRevocation(issuer.did, credentialCID, issuerKid, issuer.auth.priv)
	if err != nil {
		t.Fatalf("SignRevocation: %v", err)
	}

	// simulate the pre-column row: created_at left NULL
	if _, err := store.writerDB().Exec(
		"INSERT INTO revocations (cid, issuer_did, credential_cid, jws_token) VALUES (?, ?, ?, ?)",
		revCID, issuer.did, credentialCID, token,
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	stored, err := store.GetRevocationForCredential(credentialCID)
	if err != nil || stored == nil {
		t.Fatalf("GetRevocationForCredential: %v (nil=%v)", err, stored == nil)
	}
	if stored.CreatedAt == "" {
		t.Fatal("expected the legacy row's createdAt to be recovered from its token")
	}
	revokedAt, _ := revocationCreatedAtUnix(stored.CreatedAt)

	if got, _ := store.IsCredentialRevoked(issuer.did, credentialCID, revokedAt-60); got {
		t.Fatal("legacy row: a revocation must not reach back before its own createdAt")
	}
	if got, _ := store.IsCredentialRevoked(issuer.did, credentialCID, revokedAt+60); !got {
		t.Fatal("legacy row: as-of after the revocation must report revoked")
	}
}

// ---------------------------------------------------------------------------
// ingest: freshness is unchanged
// ---------------------------------------------------------------------------

// TestIngestStillRejectsWriteUnderRevokedCredential — the WP-4 leaf-revocation
// guarantee is untouched by the as-of work.
func TestIngestStillRejectsWriteUnderRevokedCredential(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	now := time.Now()

	w1, w1CID := signBackdatedDelegatedUpdate(t, c.delegate, c.genesisOpCID, newDocCID(t, "first"), c.credential, now.Add(-20*time.Minute))
	if res := IngestOperations([]string{w1}, c.store); res[0].Status != "new" {
		t.Fatalf("first delegated write: %s (%s)", res[0].Status, res[0].Error)
	}

	c.revoke(t)

	w2, _ := signBackdatedDelegatedUpdate(t, c.delegate, w1CID, newDocCID(t, "second"), c.credential, now.Add(-10*time.Minute))
	res := IngestOperations([]string{w2}, c.store)
	if res[0].Status != "rejected" {
		t.Fatalf("SECURITY: expected write under a revoked credential to be REJECTED, got %s", res[0].Status)
	}
	if !strings.Contains(res[0].Error, "revoked") {
		t.Fatalf("expected a revocation rejection, got: %s", res[0].Error)
	}
}

// TestIngestRejectsBackdatedWriteUnderRevokedCredential is the guard that ingest
// did NOT adopt as-of semantics. This op is dated BEFORE the revocation, so an
// as-of check would call the credential live and admit it.
func TestIngestRejectsBackdatedWriteUnderRevokedCredential(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	now := time.Now()

	w1, w1CID := signBackdatedDelegatedUpdate(t, c.delegate, c.genesisOpCID, newDocCID(t, "first"), c.credential, now.Add(-25*time.Minute))
	if res := IngestOperations([]string{w1}, c.store); res[0].Status != "new" {
		t.Fatalf("first delegated write: %s (%s)", res[0].Status, res[0].Error)
	}

	c.revoke(t)

	// dated 20 minutes ago — comfortably before the revocation just ingested
	backdated, _ := signBackdatedDelegatedUpdate(t, c.delegate, w1CID, newDocCID(t, "backdated"), c.credential, now.Add(-20*time.Minute))
	res := IngestOperations([]string{backdated}, c.store)
	if res[0].Status != "rejected" {
		t.Fatalf("SECURITY: a BACKDATED write under a currently-revoked credential must be REJECTED at ingest (acceptance is a freshness decision), got %s", res[0].Status)
	}
	if !strings.Contains(res[0].Error, "revoked") {
		t.Fatalf("expected a revocation rejection, got: %s", res[0].Error)
	}
}

// ---------------------------------------------------------------------------
// GetContentStateAtCID: historical replay is a validity decision
// ---------------------------------------------------------------------------

// TestGetContentStateAtCIDReplaysAfterLaterRevocation — a delegated op whose
// credential was revoked AFTER it still replays.
func TestGetContentStateAtCIDReplaysAfterLaterRevocation(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	now := time.Now()

	a, aCID := signBackdatedDelegatedUpdate(t, c.delegate, c.genesisOpCID, newDocCID(t, "A"), c.credential, now.Add(-25*time.Minute))
	if res := IngestOperations([]string{a}, c.store); res[0].Status != "new" {
		t.Fatalf("op A: %s (%s)", res[0].Status, res[0].Error)
	}
	b, _ := signBackdatedUpdate(t, c.creator, aCID, newDocCID(t, "B"), now.Add(-20*time.Minute))
	if res := IngestOperations([]string{b}, c.store); res[0].Status != "new" {
		t.Fatalf("op B: %s (%s)", res[0].Status, res[0].Error)
	}

	c.revoke(t)

	state, err := c.store.GetContentStateAtCID(c.contentID, aCID)
	if err != nil {
		t.Fatalf("expected replay to VERIFY (credential revoked after op A): %v", err)
	}
	if state == nil {
		t.Fatal("expected fork-point state at op A")
	}
	if state.State.Length != 2 {
		t.Fatalf("Length: got %d, want 2", state.State.Length)
	}
}

// TestForkExtendsFromStateWithRevokedCredential is the user-visible payoff: a
// legitimate fork off a historical op stays acceptable after the credential behind
// that op is revoked. The fork op is creator-signed, so ingest's own freshness gate
// is not what is under test — only whether the fork-point state still computes.
func TestForkExtendsFromStateWithRevokedCredential(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	now := time.Now()

	a, aCID := signBackdatedDelegatedUpdate(t, c.delegate, c.genesisOpCID, newDocCID(t, "A"), c.credential, now.Add(-25*time.Minute))
	IngestOperations([]string{a}, c.store)
	b, _ := signBackdatedUpdate(t, c.creator, aCID, newDocCID(t, "B"), now.Add(-20*time.Minute))
	IngestOperations([]string{b}, c.store)

	c.revoke(t)

	fork, _ := signBackdatedUpdate(t, c.creator, aCID, newDocCID(t, "fork"), now.Add(-22*time.Minute))
	res := IngestOperations([]string{fork}, c.store)
	if res[0].Status != "new" {
		t.Fatalf("expected the fork to be ACCEPTED after the historical credential was revoked, got %s (%s)", res[0].Status, res[0].Error)
	}
}

// TestGetContentStateAtCIDRejectsWhenRevocationPredatesOp is the mirror image: op A
// is dated AFTER the revocation, so as of its own createdAt the credential was
// already dead and the historical state does not verify. (A was admitted at ingest
// only because the revocation had not arrived yet.)
func TestGetContentStateAtCIDRejectsWhenRevocationPredatesOp(t *testing.T) {
	c := seedAsOfChain(t, -30*time.Minute)
	now := time.Now()

	a, aCID := signBackdatedDelegatedUpdate(t, c.delegate, c.genesisOpCID, newDocCID(t, "A"), c.credential, now.Add(5*time.Minute))
	if res := IngestOperations([]string{a}, c.store); res[0].Status != "new" {
		t.Fatalf("op A: %s (%s)", res[0].Status, res[0].Error)
	}

	// revoked NOW — before A's own (future-dated) createdAt
	c.revoke(t)

	if _, err := c.store.GetContentStateAtCID(c.contentID, aCID); err == nil {
		t.Fatal("expected replay to REJECT an op authorized by a credential already revoked as of that op's createdAt")
	}
}

// ---------------------------------------------------------------------------
// hardening: rejection logging
// ---------------------------------------------------------------------------

// TestRejectedOpLogsCidAndReason — MarkOpRejected DELETES the raw op and the reason
// was previously discarded, so this line is the only durable trace of why a relay
// refused an op.
func TestRejectedOpLogsCidAndReason(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}

	id := createTestIdentity(t)
	corrupt := corruptSignature(id.token)
	rawCID := computeOpCID(corrupt)
	if rawCID == "" {
		t.Fatal("expected the corrupt op to carry a storage CID")
	}

	if res := r.Ingest([]string{corrupt}); res[0].Status != "rejected" {
		t.Fatalf("expected a bad-signature op to be rejected, got %s", res[0].Status)
	}

	out := logs.String()
	if !strings.Contains(out, rawCID) {
		t.Fatalf("rejection log is missing the cid %s: %s", rawCID, out)
	}
	if !strings.Contains(out, "reason=") {
		t.Fatalf("rejection log is missing the reason: %s", out)
	}
}

// TestLiteNodeRejectsBlobUpload — blob upload is a WRITE. A node advertising
// write:false must present no write surface at all: leaving open the one route that
// accepts a 16MB body would contradict the capability and defeat the point of the
// role. The gate fires before auth, so any body suffices.
func TestLiteNodeRejectsBlobUpload(t *testing.T) {
	srv := httptest.NewServer(liteRelay(t, NewMemoryStore(), nil, nil).Handler())
	defer srv.Close()

	req, err := http.NewRequest("PUT", srv.URL+"/content/someid/blob/somecid", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fake")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT blob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 501 {
		t.Fatalf("expected 501 on a pull-only node, got %d", resp.StatusCode)
	}
}

// TestLiteNodeStillServesBlobDownload is the negative control: write:false gates
// writes only, so a blob READ must reach the route (404 for an unknown chain).
func TestLiteNodeStillServesBlobDownload(t *testing.T) {
	srv := httptest.NewServer(liteRelay(t, NewMemoryStore(), nil, nil).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/content/someid/blob")
	if err != nil {
		t.Fatalf("GET blob: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 501 {
		t.Fatal("write:false must not 501 a blob READ — reads are unaffected")
	}
}
