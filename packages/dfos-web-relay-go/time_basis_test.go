package relay

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// ===================================================================
// THE SINGLE TIME BASIS AT THE RELAY (specs/PROTOCOL.md "Time basis",
// specs/RELAY.md "Ingest asks freshness; re-verification asks the basis").
//
// Ingest asks freshness: first admission of a NEW operation resolves its signer
// in head state. Re-verification asks the basis: replay and peer ingest of
// committed history resolve at each operation's own createdAt. A credential
// carried inline resolves at that basis in both modes; a credential presented at
// read time resolves at the head, because a presentation's basis is now.
//
// Twin: dfos-web-relay/tests/time-basis.spec.ts — keep the two in lockstep.
// ===================================================================

// basisRotationFixture is one identity holding K1 from T0 that rotates to K2 at
// T_r, on a clock that runs entirely in the past.
type basisRotationFixture struct {
	did          string
	k1           testKeypair
	k2           testKeypair
	genesisToken string
	genesisCID   string
	rotation     string
	rotationCID  string
}

func basisTime(now time.Time, minutesAgo int) time.Time {
	return now.Add(-time.Duration(minutesAgo) * time.Minute)
}

// signBackdatedIdentityUpdate hand-builds an identity update with a
// caller-chosen createdAt, mirroring SignIdentityUpdate's payload shape.
func signBackdatedIdentityUpdate(t *testing.T, did, previousCID string, keys []dfos.MultikeyPublicKey,
	keyProofs []string, signerKid string, signerPriv ed25519.PrivateKey, createdAt time.Time) (token, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":              1,
		"type":                 "update",
		"previousOperationCID": previousCID,
		"authKeys":             keys,
		"assertKeys":           keys,
		"controllerKeys":       keys,
		"createdAt":            createdAt.UTC().Format(expBasisTimeFormat),
	}
	if len(keyProofs) > 0 {
		payload["keyProofs"] = keyProofs
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(update): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: signerKid, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, signerPriv)
	if err != nil {
		t.Fatalf("CreateJWS(update): %v", err)
	}
	return token, cidStr
}

// signBackdatedIdentityDelete hand-builds an identity delete op with a
// caller-chosen createdAt.
func signBackdatedIdentityDelete(t *testing.T, did, previousCID, signerKid string,
	signerPriv ed25519.PrivateKey, createdAt time.Time) string {
	t.Helper()
	payload := map[string]any{
		"version":              1,
		"type":                 "delete",
		"previousOperationCID": previousCID,
		"createdAt":            createdAt.UTC().Format(expBasisTimeFormat),
	}
	_, _, cidStr, err := dfos.DagCborCID(payload)
	if err != nil {
		t.Fatalf("DagCborCID(delete): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: signerKid, CID: cidStr}
	token, err := dfos.CreateJWS(header, payload, signerPriv)
	if err != nil {
		t.Fatalf("CreateJWS(delete): %v", err)
	}
	return token
}

// signBackdatedContentUpdate hand-builds a plain (non-delegated) content update.
func signBackdatedContentUpdate(t *testing.T, id testIdentity, key testKeypair,
	previousCID, docCID string, createdAt time.Time) (token, cid string) {
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
		t.Fatalf("DagCborCID(content update): %v", err)
	}
	header := dfos.JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op",
		Kid: id.did + "#" + key.keyID, CID: cidStr}
	token, err = dfos.CreateJWS(header, payload, key.priv)
	if err != nil {
		t.Fatalf("CreateJWS(content update): %v", err)
	}
	return token, cidStr
}

func newBasisRotationFixture(t *testing.T, now time.Time, t0, tr int) basisRotationFixture {
	t.Helper()
	id := createBackdatedTestIdentity(t, basisTime(now, t0))
	k2 := newTestKeypair()
	rotation, rotationCID := signBackdatedIdentityUpdate(t, id.did, id.opCID,
		[]dfos.MultikeyPublicKey{k2.mk},
		[]string{testKeyProof(t, k2.priv, id.did, id.opCID)},
		id.did+"#"+id.controller.keyID, id.controller.priv, basisTime(now, tr))
	return basisRotationFixture{
		did: id.did, k1: id.auth, k2: k2,
		genesisToken: id.token, genesisCID: id.opCID,
		rotation: rotation, rotationCID: rotationCID,
	}
}

func (f basisRotationFixture) identity() testIdentity {
	return testIdentity{token: f.genesisToken, did: f.did, opCID: f.genesisCID,
		controller: f.k1, auth: f.k1}
}

// ---------------------------------------------------------------------------
// the as-of helper
// ---------------------------------------------------------------------------

func TestResolveIdentityAsOfBranches(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	if results := IngestOperations([]string{f.genesisToken, f.rotation}, store); results[0].Status != "new" || results[1].Status != "new" {
		t.Fatalf("seed rotation: %+v", results)
	}

	// SHORTCUT: the stored chain's last operation is at or before the basis, so
	// head state IS the state as of the basis and no walk runs.
	shortcut, determinate, err := ResolveIdentityAsOf(store, f.did, basisTime(now, 30).UTC().Format(expBasisTimeFormat))
	if err != nil || shortcut == nil {
		t.Fatalf("shortcut branch: %v", err)
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(*shortcut), f.k2.keyID); !ok {
		t.Fatal("the shortcut branch must answer with head state")
	}
	if determinate {
		t.Fatal("a chain that ends at or before the basis cannot claim a final answer")
	}

	// RE-WALK: the basis names a prefix, so the log is re-verified.
	rewalk, determinate, err := ResolveIdentityAsOf(store, f.did, basisTime(now, 100).UTC().Format(expBasisTimeFormat))
	if err != nil || rewalk == nil {
		t.Fatalf("re-walk branch: %v", err)
	}
	if !determinate {
		t.Fatal("a chain that runs past the basis holds every operation the basis names")
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(*rewalk), f.k1.keyID); !ok {
		t.Fatal("the re-walk branch must answer with the prefix the basis names")
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(*rewalk), f.k2.keyID); ok {
		t.Fatal("K2 must not be effective before the rotation")
	}

	// An empty basis is the head, which is the state as of now.
	head, _, err := ResolveIdentityAsOf(store, f.did, "")
	if err != nil || head == nil {
		t.Fatalf("head: %v", err)
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(*head), f.k2.keyID); !ok {
		t.Fatal("an empty basis must answer with head state")
	}

	// An unknown chain is a miss this store may answer differently later.
	missing, _, err := ResolveIdentityAsOf(store, "did:dfos:6zc46ka3rn6dt9hkccrvt4dtzha8c8t", "")
	if err != nil || missing != nil {
		t.Fatalf("unknown chain: state=%v err=%v", missing, err)
	}
}

func TestResolveIdentityAsOfReportsDeletionFromHeadState(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	if res := IngestOperations([]string{f.genesisToken, f.rotation}, store); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("seed rotation: %+v", res)
	}

	deletion := signBackdatedIdentityDelete(t, f.did, f.rotationCID,
		f.did+"#"+f.k2.keyID, f.k2.priv, basisTime(now, 30))
	if res := IngestOperations([]string{deletion}, store); res[0].Status != "new" {
		t.Fatalf("deletion: %s (%s)", res[0].Status, res[0].Error)
	}

	// The as-of state at T1 predates the deletion, and still reports it: a
	// deleted issuer authorizes nothing at any point in history.
	state, _, err := ResolveIdentityAsOf(store, f.did, basisTime(now, 100).UTC().Format(expBasisTimeFormat))
	if err != nil || state == nil {
		t.Fatalf("as-of state: %v", err)
	}
	if !state.IsDeleted {
		t.Fatal("deletion reads HEAD state at every basis")
	}
}

func TestResolveIdentityAsOfBeforeGenesisIsAVerdict(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	IngestOperations([]string{f.genesisToken, f.rotation}, store)

	_, _, err := ResolveIdentityAsOf(store, f.did, basisTime(now, 200).UTC().Format(expBasisTimeFormat))
	if err == nil {
		t.Fatal("a basis earlier than the genesis names no state")
	}
	if !strings.Contains(err.Error(), "identity has no state as of") {
		t.Fatalf("unexpected error: %v", err)
	}
	if errors.Is(err, ErrDependencyMissing) {
		t.Fatal("an identity that did not exist at the basis is a verdict, not a dependency miss")
	}
}

// ---------------------------------------------------------------------------
// which key misses are verdicts
// ---------------------------------------------------------------------------

// TestUnsyncedKeyMissStaysRetryable pins the classification a key miss takes
// when the stored chain ends at or before the basis: the store cannot rule out
// an operation the basis names still arriving, so the operation is buffered
// rather than deleted, and it lands once the dependency arrives.
// Twin of the TS "buffers an operation whose identity dependency has not
// synced".
func TestUnsyncedKeyMissStaysRetryable(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	id := f.identity()

	// The rotation is NOT in this store yet, so the chain ends at the genesis and
	// head state has never held K2.
	early, _, earlyCID := signBackdatedContentCreate(t, id, newDocCID(t, "early"), basisTime(now, 100))
	if res := IngestOperations([]string{f.genesisToken, early}, store); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("seed: %+v", res)
	}

	late, _ := signBackdatedContentUpdate(t, id, f.k2, earlyCID, newDocCID(t, "signed by K2"), basisTime(now, 30))
	buffered := IngestOperations([]string{late}, store, WithHistoricalAdmission())[0]
	if buffered.Status != "rejected" || !strings.Contains(buffered.Error, "unknown key") {
		t.Fatalf("an operation signed by an unsynced key must be refused: %+v", buffered)
	}
	if !buffered.DependencyMissing {
		t.Fatalf("a key miss under head state must stay retryable, got %+v", buffered)
	}

	// The dependency arrives, and the same operation lands.
	if res := IngestOperations([]string{f.rotation}, store); res[0].Status != "new" {
		t.Fatalf("rotation: %s (%s)", res[0].Status, res[0].Error)
	}
	if res := IngestOperations([]string{late}, store, WithHistoricalAdmission()); res[0].Status != "new" {
		t.Fatalf("the buffered operation must land once its dependency is held: %s (%s)", res[0].Status, res[0].Error)
	}
}

// TestKeyMissPastTheBasisIsAVerdict pins the other branch: a stored operation
// dated after the basis proves the store holds every operation the basis names,
// so a key missing from the as-of state is final.
// Twin of the TS "is a verdict once an operation dated after the basis is
// stored".
func TestKeyMissPastTheBasisIsAVerdict(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	id := f.identity()

	// Two batches, because first admission asks freshness: the early op is
	// authored while K1 is still the head, and only then does the rotation land.
	early, _, earlyCID := signBackdatedContentCreate(t, id, newDocCID(t, "early"), basisTime(now, 100))
	if res := IngestOperations([]string{f.genesisToken, early}, store); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("seed: %+v", res)
	}
	if res := IngestOperations([]string{f.rotation}, store); res[0].Status != "new" {
		t.Fatalf("rotation: %s (%s)", res[0].Status, res[0].Error)
	}

	// A second rotation, dated AFTER the basis the next operation carries.
	k3 := newTestKeypair()
	second, _ := signBackdatedIdentityUpdate(t, f.did, f.rotationCID,
		[]dfos.MultikeyPublicKey{k3.mk},
		[]string{testKeyProof(t, k3.priv, f.did, f.rotationCID)},
		f.did+"#"+f.k2.keyID, f.k2.priv, basisTime(now, 10))
	if res := IngestOperations([]string{second}, store); res[0].Status != "new" {
		t.Fatalf("second rotation: %s (%s)", res[0].Status, res[0].Error)
	}

	// K1 was retired at T_r, and the basis sits between T_r and the second
	// rotation, so the as-of walk answers about a complete prefix.
	byRetiredKey, _ := signBackdatedContentUpdate(t, id, f.k1, earlyCID, newDocCID(t, "by a retired key"), basisTime(now, 20))
	verdict := IngestOperations([]string{byRetiredKey}, store, WithHistoricalAdmission())[0]
	if verdict.Status != "rejected" || !strings.Contains(verdict.Error, "unknown key") {
		t.Fatalf("an operation signed by a retired key must be refused: %+v", verdict)
	}
	if verdict.DependencyMissing {
		t.Fatalf("a key miss the as-of walk decided is a verdict, got %+v", verdict)
	}
}

// ---------------------------------------------------------------------------
// an issuer that did not exist at the basis
// ---------------------------------------------------------------------------

func TestIssuerGenesisAfterTheBasisIsAPermanentRejection(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	creator := createBackdatedTestIdentity(t, basisTime(now, 120))
	// The delegate's chain begins AFTER the write it is about to authorize.
	delegate := createBackdatedTestIdentity(t, basisTime(now, 30))
	IngestOperations([]string{creator.token, delegate.token}, store)

	genesisToken, contentID, genesisCID := signBackdatedContentCreate(t, creator,
		newDocCID(t, "genesis"), basisTime(now, 110))
	if res := IngestOperations([]string{genesisToken}, store); res[0].Status != "new" {
		t.Fatalf("seed genesis: %s (%s)", res[0].Status, res[0].Error)
	}

	credential := mintCredentialWithExp(t, delegate.did, delegate.did+"#"+delegate.auth.keyID,
		delegate.auth.priv, creator.did, "chain:"+contentID, "write",
		now.Add(-4*time.Hour).Unix(), now.Add(4*time.Hour).Unix())
	write, _ := signBackdatedDelegatedUpdate(t, delegate, genesisCID,
		newDocCID(t, "too early"), credential, basisTime(now, 100))

	result := IngestOperations([]string{write}, store, WithHistoricalAdmission())[0]
	if result.Status != "rejected" {
		t.Fatalf("a write whose credential issuer did not exist at its basis must be refused: %s", result.Status)
	}
	if !strings.Contains(result.Error, "identity has no state as of") {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.DependencyMissing {
		t.Fatalf("an issuer that did not exist at the basis is a verdict, got %+v", result)
	}
}

// ---------------------------------------------------------------------------
// peer-log ingest of committed history across a rotation
// ---------------------------------------------------------------------------

func TestPeerIngestAcrossRotationLandsInTheSameState(t *testing.T) {
	now := time.Now()
	origin := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	id := f.identity()

	// Two batches, because first admission asks freshness: the early op is
	// authored while K1 is still the head, and only then does the rotation land.
	early, contentID, earlyCID := signBackdatedContentCreate(t, id, newDocCID(t, "early"), basisTime(now, 100))
	if res := IngestOperations([]string{f.genesisToken, early}, origin); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("seed: %+v", res)
	}
	if res := IngestOperations([]string{f.rotation}, origin); res[0].Status != "new" {
		t.Fatalf("rotation: %s (%s)", res[0].Status, res[0].Error)
	}

	// A later op signed by the successor key, extending the same chain.
	late, lateCID := signBackdatedContentUpdate(t, id, f.k2, earlyCID, newDocCID(t, "late"), basisTime(now, 30))
	if res := IngestOperations([]string{late}, origin); res[0].Status != "new" {
		t.Fatalf("late op: %s (%s)", res[0].Status, res[0].Error)
	}

	// The peer receives the same log in sequence order and re-verifies it at each
	// operation's own basis.
	peer := NewMemoryStore()
	synced := IngestOperations([]string{f.genesisToken, early, f.rotation, late}, peer, WithHistoricalAdmission())
	for i, result := range synced {
		if result.Status != "new" {
			t.Fatalf("peer ingest[%d]: %s (%s)", i, result.Status, result.Error)
		}
	}

	peerChain, err := peer.GetContentChain(contentID)
	if err != nil || peerChain == nil {
		t.Fatalf("peer content chain: %v", err)
	}
	if peerChain.State.HeadCID != lateCID {
		t.Fatalf("peer head = %s, want %s", peerChain.State.HeadCID, lateCID)
	}
	peerIdentity, err := peer.GetIdentityChain(f.did)
	if err != nil || peerIdentity == nil {
		t.Fatalf("peer identity chain: %v", err)
	}
	if _, ok := findKeyInKeyState(effectiveKeyState(peerIdentity.State), f.k2.keyID); !ok {
		t.Fatal("the peer must land on the same head key state")
	}
}

// ---------------------------------------------------------------------------
// the read path
// ---------------------------------------------------------------------------

func TestStandingPublicCredentialIsCheckedAtTheHead(t *testing.T) {
	now := time.Now()
	store := NewMemoryStore()
	f := newBasisRotationFixture(t, now, 120, 60)
	id := f.identity()

	content, contentID, _ := signBackdatedContentCreate(t, id, newDocCID(t, "public"), basisTime(now, 100))
	if res := IngestOperations([]string{f.genesisToken, content}, store); res[0].Status != "new" || res[1].Status != "new" {
		t.Fatalf("seed: %+v", res)
	}

	credential := mintCredentialWithExp(t, f.did, f.did+"#"+f.k1.keyID, f.k1.priv,
		"*", "chain:"+contentID, "read", now.Add(-4*time.Hour).Unix(), now.Add(4*time.Hour).Unix())
	if res := IngestOperations([]string{credential}, store); res[0].Status != "new" {
		t.Fatalf("public credential: %s (%s)", res[0].Status, res[0].Error)
	}
	if !hasPublicStandingAuth(contentID, "read", store) {
		t.Fatal("the standing grant must hold while the issuing key is effective")
	}

	// The rotation retires the issuing key. A read-time check runs at the head,
	// so the standing grant stops granting.
	if res := IngestOperations([]string{f.rotation}, store); res[0].Status != "new" {
		t.Fatalf("rotation: %s (%s)", res[0].Status, res[0].Error)
	}
	if hasPublicStandingAuth(contentID, "read", store) {
		t.Fatal("a standing grant signed by a rotated-out key must stop granting")
	}
}
