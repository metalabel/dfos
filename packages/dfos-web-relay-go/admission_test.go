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

type rotatedTestIdentity struct {
	identity testIdentity
	current  testKeypair
	rotation string
}

func ingestAndRotateTestIdentity(t *testing.T, relay *Relay) rotatedTestIdentity {
	t.Helper()
	id := createTestIdentity(t)
	if result := relay.Ingest([]string{id.token})[0]; result.Status != "new" {
		t.Fatalf("ingest identity: %s (%s)", result.Status, result.Error)
	}
	current, rotation := rotateExistingTestIdentity(t, relay, id)
	return rotatedTestIdentity{identity: id, current: current, rotation: rotation}
}

func rotateExistingTestIdentity(t *testing.T, relay *Relay, id testIdentity) (testKeypair, string) {
	t.Helper()
	time.Sleep(2 * time.Millisecond)
	current := newTestKeypair()
	rotation, _, err := dfos.SignIdentityUpdate(
		id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk},
		[]dfos.MultikeyPublicKey{current.mk},
		nil,
		id.did+"#"+id.controller.keyID,
		id.controller.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result := relay.Ingest([]string{rotation})[0]; result.Status != "new" {
		t.Fatalf("rotate identity: %s (%s)", result.Status, result.Error)
	}
	return current, rotation
}

func assertPermanentNoncurrentRejection(t *testing.T, result IngestionResult) {
	t.Helper()
	if result.Status != "rejected" {
		t.Fatalf("expected rejected, got %s", result.Status)
	}
	if !strings.Contains(result.Error, noncurrentSigningKeyError) {
		t.Fatalf("error = %q, want it to name %q", result.Error, noncurrentSigningKeyError)
	}
	if result.DependencyMissing {
		t.Fatal("a known rotated-out key must be a permanent rejection")
	}
}

func TestDirectAdmissionUsesCurrentSignerState(t *testing.T) {
	t.Run("artifact", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		rotated := ingestAndRotateTestIdentity(t, r)
		oldToken, _, err := dfos.SignArtifact(rotated.identity.did,
			map[string]any{"$schema": "test/v1", "title": "old"},
			rotated.identity.did+"#"+rotated.identity.auth.keyID, rotated.identity.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertPermanentNoncurrentRejection(t, r.Ingest([]string{oldToken})[0])

		currentToken, _, err := dfos.SignArtifact(rotated.identity.did,
			map[string]any{"$schema": "test/v1", "title": "current"},
			rotated.identity.did+"#"+rotated.current.keyID, rotated.current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := r.Ingest([]string{currentToken})[0]; result.Status != "new" {
			t.Fatalf("current-key artifact: %s (%s)", result.Status, result.Error)
		}
	})

	t.Run("countersignature", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		author := createTestIdentity(t)
		if result := r.Ingest([]string{author.token})[0]; result.Status != "new" {
			t.Fatalf("ingest author: %s (%s)", result.Status, result.Error)
		}
		rotated := ingestAndRotateTestIdentity(t, r)
		oldToken, _, err := dfos.SignCountersignWithRelation(rotated.identity.did, author.opCID,
			"old", rotated.identity.did+"#"+rotated.identity.auth.keyID, rotated.identity.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertPermanentNoncurrentRejection(t, r.Ingest([]string{oldToken})[0])

		currentToken, _, err := dfos.SignCountersignWithRelation(rotated.identity.did, author.opCID,
			"current", rotated.identity.did+"#"+rotated.current.keyID, rotated.current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := r.Ingest([]string{currentToken})[0]; result.Status != "new" {
			t.Fatalf("current-key countersignature: %s (%s)", result.Status, result.Error)
		}
	})

	t.Run("content operation", func(t *testing.T) {
		r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		rotated := ingestAndRotateTestIdentity(t, r)
		oldDoc := newDocCID(t, "old")
		oldToken, _, _, err := dfos.SignContentCreate(rotated.identity.did, oldDoc,
			rotated.identity.did+"#"+rotated.identity.auth.keyID, rotated.identity.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		assertPermanentNoncurrentRejection(t, r.Ingest([]string{oldToken})[0])

		currentDoc := newDocCID(t, "current")
		currentToken, _, _, err := dfos.SignContentCreate(rotated.identity.did, currentDoc,
			rotated.identity.did+"#"+rotated.current.keyID, rotated.current.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := r.Ingest([]string{currentToken})[0]; result.Status != "new" {
			t.Fatalf("current-key content operation: %s (%s)", result.Status, result.Error)
		}
	})
}

func TestCommittedOldKeyHistorySurvivesRotationAndPeerSync(t *testing.T) {
	originStore := NewMemoryStore()
	origin, err := NewRelay(RelayOptions{Store: originStore})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	contentToken, contentID, contentCID := createTestContent(t, id)
	results := origin.Ingest([]string{id.token, contentToken})
	if results[0].Status != "new" || results[1].Status != "new" {
		t.Fatalf("commit history: %+v", results)
	}

	current := newTestKeypair()
	rotation, _, err := dfos.SignIdentityUpdate(id.opCID,
		[]dfos.MultikeyPublicKey{id.controller.mk}, []dfos.MultikeyPublicKey{current.mk}, nil,
		id.did+"#"+id.controller.keyID, id.controller.priv)
	if err != nil {
		t.Fatal(err)
	}
	if result := origin.Ingest([]string{rotation})[0]; result.Status != "new" {
		t.Fatalf("rotation: %s (%s)", result.Status, result.Error)
	}

	replayed, err := originStore.GetContentStateAtCID(contentID, contentCID)
	if err != nil || replayed == nil || replayed.State.HeadCID != contentCID {
		t.Fatalf("historical replay failed: state=%+v err=%v", replayed, err)
	}
	recorder := httptest.NewRecorder()
	origin.Handler().ServeHTTP(recorder,
		httptest.NewRequest(http.MethodGet, "/proof/v1/content/"+contentID, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("serve committed content: status %d body %s", recorder.Code, recorder.Body.String())
	}

	origin.RunSequencerAndGossip()
	peer := newSyncedRelay(t, originStore)
	if err := peer.SyncFromPeers(); err != nil {
		t.Fatal(err)
	}
	peerChain, err := peer.store.GetContentChain(contentID)
	if err != nil || peerChain == nil || peerChain.State.HeadCID != contentCID {
		t.Fatalf("peer did not accept committed old-key history: chain=%+v err=%v", peerChain, err)
	}
}

func TestDelegatedContentUsesCurrentSignerAndHistoricalCredentialIssuer(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	creator := createTestIdentity(t)
	delegate := createTestIdentity(t)
	contentToken, contentID, contentCID := createTestContent(t, creator)
	results := r.Ingest([]string{creator.token, delegate.token, contentToken})
	if results[0].Status != "new" || results[1].Status != "new" || results[2].Status != "new" {
		t.Fatalf("seed delegated content: %+v", results)
	}

	creatorKid := creator.did + "#" + creator.auth.keyID
	credential, err := dfos.CreateCredential(creator.did, delegate.did, creatorKid,
		"chain:"+contentID, "write", time.Hour, creator.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	rotateExistingTestIdentity(t, r, creator)

	time.Sleep(2 * time.Millisecond)
	delegated, delegatedCID, err := dfos.SignContentUpdateWithOptions(delegate.did, contentCID,
		newDocCID(t, "delegated"), delegate.did+"#"+delegate.auth.keyID, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: credential})
	if err != nil {
		t.Fatal(err)
	}
	if result := r.Ingest([]string{delegated})[0]; result.Status != "new" {
		t.Fatalf("current signer with old-key credential issuer: %s (%s)", result.Status, result.Error)
	}

	rotateExistingTestIdentity(t, r, delegate)
	time.Sleep(2 * time.Millisecond)
	staleSigner, _, err := dfos.SignContentUpdateWithOptions(delegate.did, delegatedCID,
		newDocCID(t, "stale signer"), delegate.did+"#"+delegate.auth.keyID, delegate.auth.priv,
		dfos.ContentUpdateOptions{Authorization: credential})
	if err != nil {
		t.Fatal(err)
	}
	assertPermanentNoncurrentRejection(t, r.Ingest([]string{staleSigner})[0])
}

func TestRevocationAndCredentialAdmissionRemainHistorical(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	rotated := ingestAndRotateTestIdentity(t, r)
	oldKid := rotated.identity.did + "#" + rotated.identity.auth.keyID
	credential, err := dfos.CreateCredential(rotated.identity.did, "*", oldKid,
		"chain:*", "read", time.Hour, rotated.identity.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	credentialResult := r.Ingest([]string{credential})[0]
	if credentialResult.Status != "new" {
		t.Fatalf("old-key credential: %s (%s)", credentialResult.Status, credentialResult.Error)
	}

	revocation, _, err := dfos.SignRevocation(rotated.identity.did, credentialResult.CID,
		oldKid, rotated.identity.auth.priv)
	if err != nil {
		t.Fatal(err)
	}
	if result := r.Ingest([]string{revocation})[0]; result.Status != "new" {
		t.Fatalf("old-key revocation: %s (%s)", result.Status, result.Error)
	}
}

func TestPendingOpAdmissionProvenance(t *testing.T) {
	t.Run("direct pending stays current when identity arrives from peer", func(t *testing.T) {
		sourceStore := NewMemoryStore()
		source, err := NewRelay(RelayOptions{Store: sourceStore})
		if err != nil {
			t.Fatal(err)
		}
		rotated := ingestAndRotateTestIdentity(t, source)
		staleArtifact, staleCID, err := dfos.SignArtifact(rotated.identity.did,
			map[string]any{"$schema": "test/v1", "title": "direct pending"},
			rotated.identity.did+"#"+rotated.identity.auth.keyID, rotated.identity.auth.priv)
		if err != nil {
			t.Fatal(err)
		}

		store := NewMemoryStore()
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		target, err := NewRelay(RelayOptions{
			Store: store, Logger: logger,
			Peers: []PeerConfig{{URL: "http://peer"}}, PeerClient: newMockPeerClient(sourceStore, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result := target.Ingest([]string{staleArtifact})[0]; result.Status != "rejected" || !result.DependencyMissing {
			t.Fatalf("direct op should initially pend, got %+v", result)
		}

		if err := target.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
		if op, _ := store.GetOperation(staleCID); op != nil {
			t.Fatal("direct stale-key op bypassed current-state admission")
		}
		if pending, _ := store.CountUnsequenced(); pending != 0 {
			t.Fatalf("expected pending pool drained, got %d", pending)
		}
		if !strings.Contains(logs.String(), noncurrentSigningKeyError) {
			t.Fatalf("rejection log does not name noncurrent key: %s", logs.String())
		}
	})

	t.Run("peer pending stays historical when direct submission triggers sweep", func(t *testing.T) {
		sourceStore := NewMemoryStore()
		source, err := NewRelay(RelayOptions{Store: sourceStore})
		if err != nil {
			t.Fatal(err)
		}
		id := createTestIdentity(t)
		if result := source.Ingest([]string{id.token})[0]; result.Status != "new" {
			t.Fatalf("source identity: %s (%s)", result.Status, result.Error)
		}
		committedArtifact, artifactCID, err := dfos.SignArtifact(id.did,
			map[string]any{"$schema": "test/v1", "title": "peer committed"},
			id.did+"#"+id.auth.keyID, id.auth.priv)
		if err != nil {
			t.Fatal(err)
		}
		if result := source.Ingest([]string{committedArtifact})[0]; result.Status != "new" {
			t.Fatalf("source artifact: %s (%s)", result.Status, result.Error)
		}
		_, rotation := rotateExistingTestIdentity(t, source, id)

		peerStore := NewMemoryStore()
		if err := peerStore.AppendToLog(LogEntry{
			CID: artifactCID, JWSToken: committedArtifact, Kind: "artifact", ChainID: id.did,
		}); err != nil {
			t.Fatal(err)
		}
		store := NewMemoryStore()
		target, err := NewRelay(RelayOptions{
			Store: store,
			Peers: []PeerConfig{{URL: "http://peer"}}, PeerClient: newMockPeerClient(peerStore, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := target.SyncFromPeers(); err != nil {
			t.Fatal(err)
		}
		if pending, _ := store.CountUnsequenced(); pending != 1 {
			t.Fatalf("peer op should initially pend, got %d pending", pending)
		}

		results := target.Ingest([]string{id.token, rotation})
		if results[0].Status != "new" || results[1].Status != "new" {
			t.Fatalf("direct dependency submission failed: %+v", results)
		}
		if op, _ := store.GetOperation(artifactCID); op == nil {
			t.Fatal("peer committed artifact was not admitted historically")
		}
		if pending, _ := store.CountUnsequenced(); pending != 0 {
			t.Fatalf("expected pending pool drained, got %d", pending)
		}
	})
}

func TestSQLitePendingOpOriginPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRawOp("cid-peer", "token-peer", OpOriginPeer); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PutRawOp("cid-direct", "token-direct"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pending, err := reopened.GetUnsequencedOps(10)
	if err != nil {
		t.Fatal(err)
	}
	origins := make(map[string]OpOrigin, len(pending))
	for _, op := range pending {
		origins[op.JWSToken] = op.Origin
	}
	if origins["token-peer"] != OpOriginPeer {
		t.Fatalf("peer origin did not survive reopen: %+v", origins)
	}
	if origins["token-direct"] != OpOriginDirect {
		t.Fatalf("omitted origin did not default to direct: %+v", origins)
	}
}
