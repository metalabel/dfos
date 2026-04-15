package dfos

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers — controlled-timestamp signing for deterministic tests
// ---------------------------------------------------------------------------

func testKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, MultikeyPublicKey, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := GenerateKeyID()
	mk := NewMultikeyPublicKey(keyID, pub)
	return priv, pub, mk, keyID
}

func testSignIdentityGenesis(t *testing.T, controllerKeys, authKeys, assertKeys []MultikeyPublicKey, keyID string, priv ed25519.PrivateKey, createdAt string) (jws, did, cid string) {
	t.Helper()
	if authKeys == nil {
		authKeys = []MultikeyPublicKey{}
	}
	if assertKeys == nil {
		assertKeys = []MultikeyPublicKey{}
	}
	payload := map[string]any{
		"version":        int64(1),
		"type":           "create",
		"authKeys":       authKeys,
		"assertKeys":     assertKeys,
		"controllerKeys": controllerKeys,
		"createdAt":      createdAt,
	}
	_, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: keyID, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, DeriveDID(cidBytes), cidStr
}

func testSignIdentityUpdate(t *testing.T, did string, controllerKeys, authKeys, assertKeys []MultikeyPublicKey, keyID string, priv ed25519.PrivateKey, previousCID, createdAt string) (jws, cid string) {
	t.Helper()
	if authKeys == nil {
		authKeys = []MultikeyPublicKey{}
	}
	if assertKeys == nil {
		assertKeys = []MultikeyPublicKey{}
	}
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "update",
		"previousOperationCID": previousCID,
		"authKeys":             authKeys,
		"assertKeys":           assertKeys,
		"controllerKeys":       controllerKeys,
		"createdAt":            createdAt,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	kid := did + "#" + keyID
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, cidStr
}

func testSignIdentityDelete(t *testing.T, did, keyID string, priv ed25519.PrivateKey, previousCID, createdAt string) (jws, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "delete",
		"previousOperationCID": previousCID,
		"createdAt":            createdAt,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	kid := did + "#" + keyID
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, cidStr
}

func testSignContentGenesis(t *testing.T, signerDID, documentCID, kid string, priv ed25519.PrivateKey, createdAt string) (jws, contentID, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":         int64(1),
		"type":            "create",
		"did":             signerDID,
		"documentCID":     documentCID,
		"baseDocumentCID": nil,
		"createdAt":       createdAt,
		"note":            nil,
	}
	_, cidBytes, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, DeriveContentID(cidBytes), cidStr
}

func testSignContentUpdate(t *testing.T, signerDID, previousCID, documentCID, kid string, priv ed25519.PrivateKey, createdAt string) (jws, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "update",
		"did":                  signerDID,
		"previousOperationCID": previousCID,
		"documentCID":          documentCID,
		"baseDocumentCID":      nil,
		"createdAt":            createdAt,
		"note":                 nil,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, cidStr
}

func testSignContentDelete(t *testing.T, signerDID, previousCID, kid string, priv ed25519.PrivateKey, createdAt string) (jws, cid string) {
	t.Helper()
	payload := map[string]any{
		"version":              int64(1),
		"type":                 "delete",
		"did":                  signerDID,
		"previousOperationCID": previousCID,
		"createdAt":            createdAt,
		"note":                 nil,
	}
	_, _, cidStr, err := DagCborCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid, CID: cidStr}
	token, err := CreateJWS(header, payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	return token, cidStr
}

// ---------------------------------------------------------------------------
// Identity chain verification tests
// ---------------------------------------------------------------------------

func TestVerifyIdentityChain_GenesisOnly(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	jws, did, cid := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	result, err := VerifyIdentityChain([]string{jws})
	if err != nil {
		t.Fatalf("VerifyIdentityChain: %v", err)
	}
	if result.State.DID != did {
		t.Errorf("DID: got %s, want %s", result.State.DID, did)
	}
	if result.State.IsDeleted {
		t.Error("expected not deleted")
	}
	if len(result.State.ControllerKeys) != 1 {
		t.Errorf("controller keys: got %d, want 1", len(result.State.ControllerKeys))
	}
	if result.HeadCID != cid {
		t.Errorf("HeadCID: got %s, want %s", result.HeadCID, cid)
	}
	if result.LastCreatedAt != "2026-03-07T00:00:00.000Z" {
		t.Errorf("LastCreatedAt: got %s", result.LastCreatedAt)
	}
}

func TestVerifyIdentityChain_GenesisAndUpdate(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, []MultikeyPublicKey{mk}, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	// create a second key for rotation
	_, _, mk2, _ := testKeys(t)

	updateJWS, updateCID := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk, mk2}, []MultikeyPublicKey{mk2}, nil,
		keyID, priv, genCID, "2026-03-07T00:01:00.000Z",
	)

	result, err := VerifyIdentityChain([]string{genJWS, updateJWS})
	if err != nil {
		t.Fatalf("VerifyIdentityChain: %v", err)
	}
	if result.State.DID != did {
		t.Errorf("DID: got %s, want %s", result.State.DID, did)
	}
	if len(result.State.ControllerKeys) != 2 {
		t.Errorf("controller keys: got %d, want 2", len(result.State.ControllerKeys))
	}
	if len(result.State.AuthKeys) != 1 {
		t.Errorf("auth keys: got %d, want 1", len(result.State.AuthKeys))
	}
	if result.HeadCID != updateCID {
		t.Errorf("HeadCID: got %s, want %s", result.HeadCID, updateCID)
	}
}

func TestVerifyIdentityChain_GenesisAndDelete(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	deleteJWS, _ := testSignIdentityDelete(t, did, keyID, priv, genCID, "2026-03-07T00:01:00.000Z")

	result, err := VerifyIdentityChain([]string{genJWS, deleteJWS})
	if err != nil {
		t.Fatalf("VerifyIdentityChain: %v", err)
	}
	if !result.State.IsDeleted {
		t.Error("expected deleted")
	}
}

func TestVerifyIdentityChain_EmptyLog(t *testing.T) {
	_, err := VerifyIdentityChain([]string{})
	if err == nil {
		t.Fatal("expected error for empty log")
	}
}

func TestVerifyIdentityChain_NoControllerKeys(t *testing.T) {
	priv, _, _, keyID := testKeys(t)

	// create genesis with no controller keys
	payload := map[string]any{
		"version":        int64(1),
		"type":           "create",
		"authKeys":       []MultikeyPublicKey{},
		"assertKeys":     []MultikeyPublicKey{},
		"controllerKeys": []MultikeyPublicKey{},
		"createdAt":      "2026-03-07T00:00:00.000Z",
	}
	_, _, cidStr, _ := DagCborCID(payload)
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:identity-op", Kid: keyID, CID: cidStr}
	jws, _ := CreateJWS(header, payload, priv)

	_, err := VerifyIdentityChain([]string{jws})
	if err == nil {
		t.Fatal("expected error for no controller keys")
	}
}

func TestVerifyIdentityChain_WrongTimestampOrder(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:01:00.000Z", // later time
	)

	// update with earlier timestamp
	updateJWS, _ := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, genCID, "2026-03-07T00:00:00.000Z", // earlier
	)

	_, err := VerifyIdentityChain([]string{genJWS, updateJWS})
	if err == nil {
		t.Fatal("expected error for wrong timestamp order")
	}
}

func TestVerifyIdentityChain_WrongPreviousCID(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	// update with wrong previous CID
	updateJWS, _ := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "wrong-cid", "2026-03-07T00:01:00.000Z",
	)

	_, err := VerifyIdentityChain([]string{genJWS, updateJWS})
	if err == nil {
		t.Fatal("expected error for wrong previous CID")
	}
}

func TestVerifyIdentityChain_CannotExtendDeleted(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)
	deleteJWS, deleteCID := testSignIdentityDelete(t, did, keyID, priv, genCID, "2026-03-07T00:01:00.000Z")
	updateJWS, _ := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, deleteCID, "2026-03-07T00:02:00.000Z",
	)

	_, err := VerifyIdentityChain([]string{genJWS, deleteJWS, updateJWS})
	if err == nil {
		t.Fatal("expected error for extending deleted identity")
	}
}

// Cross-validate: verify the existing reference genesis JWS from protocol_test.go
func TestVerifyIdentityChain_ReferenceVector(t *testing.T) {
	result, err := VerifyIdentityChain([]string{genesisJWS})
	if err != nil {
		t.Fatalf("VerifyIdentityChain(genesisJWS): %v", err)
	}
	if result.State.DID != expectedDID {
		t.Errorf("DID: got %s, want %s", result.State.DID, expectedDID)
	}
	if result.HeadCID != expectedGenCID {
		t.Errorf("HeadCID: got %s, want %s", result.HeadCID, expectedGenCID)
	}
	if len(result.State.ControllerKeys) != 1 {
		t.Fatalf("controller keys: got %d, want 1", len(result.State.ControllerKeys))
	}
	if result.State.ControllerKeys[0].PublicKeyMultibase != expectedMultikey1 {
		t.Errorf("controller key multibase: got %s, want %s",
			result.State.ControllerKeys[0].PublicKeyMultibase, expectedMultikey1)
	}
}

// ---------------------------------------------------------------------------
// Identity extension verification tests
// ---------------------------------------------------------------------------

func TestVerifyIdentityExtension_Update(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	genResult, err := VerifyIdentityChain([]string{genJWS})
	if err != nil {
		t.Fatal(err)
	}

	// create update op
	_, _, mk2, keyID2 := testKeys(t)
	updateJWS, _ := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk, mk2}, nil, nil,
		keyID, priv, genCID, "2026-03-07T00:01:00.000Z",
	)

	extResult, err := VerifyIdentityExtension(genResult.State, genResult.HeadCID, genResult.LastCreatedAt, updateJWS)
	if err != nil {
		t.Fatalf("VerifyIdentityExtension: %v", err)
	}
	if extResult.State.DID != did {
		t.Errorf("DID mismatch")
	}
	if len(extResult.State.ControllerKeys) != 2 {
		t.Errorf("controller keys: got %d, want 2", len(extResult.State.ControllerKeys))
	}
	_ = keyID2
}

func TestVerifyIdentityExtension_Delete(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	genResult, err := VerifyIdentityChain([]string{genJWS})
	if err != nil {
		t.Fatal(err)
	}

	deleteJWS, _ := testSignIdentityDelete(t, did, keyID, priv, genCID, "2026-03-07T00:01:00.000Z")

	extResult, err := VerifyIdentityExtension(genResult.State, genResult.HeadCID, genResult.LastCreatedAt, deleteJWS)
	if err != nil {
		t.Fatalf("VerifyIdentityExtension: %v", err)
	}
	if !extResult.State.IsDeleted {
		t.Error("expected deleted")
	}
}

func TestVerifyIdentityExtension_RejectsCreate(t *testing.T) {
	priv, _, mk, keyID := testKeys(t)

	genJWS, _, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	genResult, _ := VerifyIdentityChain([]string{genJWS})

	// try to extend with another genesis
	anotherGenesis, _, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, nil, nil,
		keyID, priv, "2026-03-07T00:01:00.000Z",
	)

	_, err := VerifyIdentityExtension(genResult.State, genResult.HeadCID, genResult.LastCreatedAt, anotherGenesis)
	if err == nil {
		t.Fatal("expected error for create extension")
	}
}

// ---------------------------------------------------------------------------
// Content chain verification tests
// ---------------------------------------------------------------------------

func TestVerifyContentChain_GenesisOnly(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)

	// create an identity first to get a DID
	genJWS, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)
	idResult, _ := VerifyIdentityChain([]string{genJWS})

	kid := did + "#" + keyID
	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	// make a document CID
	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})

	contentJWS, contentID, _ := testSignContentGenesis(t, did, docCID, kid, priv, "2026-03-07T00:00:01.000Z")

	result, err := VerifyContentChain([]string{contentJWS}, resolver, true)
	if err != nil {
		t.Fatalf("VerifyContentChain: %v", err)
	}
	if result.State.ContentID != contentID {
		t.Errorf("ContentID: got %s, want %s", result.State.ContentID, contentID)
	}
	if result.State.CreatorDID != did {
		t.Errorf("CreatorDID: got %s, want %s", result.State.CreatorDID, did)
	}
	if result.State.Length != 1 {
		t.Errorf("Length: got %d, want 1", result.State.Length)
	}
	if result.State.CurrentDocumentCID == nil || *result.State.CurrentDocumentCID != docCID {
		t.Errorf("CurrentDocumentCID mismatch")
	}
	_ = idResult
}

func TestVerifyContentChain_GenesisAndUpdate(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	docCID1, _, _ := DocumentCID(map[string]any{"v": int64(1)})
	docCID2, _, _ := DocumentCID(map[string]any{"v": int64(2)})

	contentJWS, _, contentCID := testSignContentGenesis(t, did, docCID1, kid, priv, "2026-03-07T00:00:01.000Z")
	updateJWS, _ := testSignContentUpdate(t, did, contentCID, docCID2, kid, priv, "2026-03-07T00:00:02.000Z")

	result, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, true)
	if err != nil {
		t.Fatalf("VerifyContentChain: %v", err)
	}
	if result.State.Length != 2 {
		t.Errorf("Length: got %d, want 2", result.State.Length)
	}
	if result.State.CurrentDocumentCID == nil || *result.State.CurrentDocumentCID != docCID2 {
		t.Errorf("CurrentDocumentCID should be docCID2")
	}
}

func TestVerifyContentChain_Delete(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, contentCID := testSignContentGenesis(t, did, docCID, kid, priv, "2026-03-07T00:00:01.000Z")
	deleteJWS, _ := testSignContentDelete(t, did, contentCID, kid, priv, "2026-03-07T00:00:02.000Z")

	result, err := VerifyContentChain([]string{contentJWS, deleteJWS}, resolver, true)
	if err != nil {
		t.Fatalf("VerifyContentChain: %v", err)
	}
	if !result.State.IsDeleted {
		t.Error("expected deleted")
	}
	if result.State.CurrentDocumentCID != nil {
		t.Error("expected nil documentCID after delete")
	}
}

func TestVerifyContentChain_DelegatedWriteRequiresCredential(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	// second identity (delegated writer)
	priv2, pub2, _, keyID2 := testKeys(t)
	_, did2, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID2, pub2)}, nil, nil,
		keyID2, priv2, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	kid2 := did2 + "#" + keyID2
	resolver := func(k string) (ed25519.PublicKey, error) {
		switch k {
		case kid:
			return pub, nil
		case kid2:
			return pub2, nil
		default:
			return nil, fmt.Errorf("unknown kid: %s", k)
		}
	}

	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, contentCID := testSignContentGenesis(t, did, docCID, kid, priv, "2026-03-07T00:00:01.000Z")

	// delegated update by did2 — no authorization credential
	docCID2, _, _ := DocumentCID(map[string]any{"v": int64(2)})
	updateJWS, _ := testSignContentUpdate(t, did2, contentCID, docCID2, kid2, priv2, "2026-03-07T00:00:02.000Z")

	// should fail with enforceAuthorization=true
	_, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, true)
	if err == nil {
		t.Fatal("expected error for delegated write without credential")
	}

	// should pass with enforceAuthorization=false
	result, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, false)
	if err != nil {
		t.Fatalf("expected success with enforceAuthorization=false: %v", err)
	}
	if result.State.Length != 2 {
		t.Errorf("Length: got %d, want 2", result.State.Length)
	}
}

func TestVerifyContentChain_DelegatedWriteWithCredential(t *testing.T) {
	// Use timestamps relative to now so the credential's iat is not "in the future"
	// relative to the operation's createdAt
	now := time.Now().UTC()
	genesisTime := now.Format(protocolTimeFormat)
	updateTime := now.Add(1 * time.Second).Format(protocolTimeFormat)

	// creator identity
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	// delegated writer identity
	priv2, pub2, _, keyID2 := testKeys(t)
	_, did2, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID2, pub2)}, nil, nil,
		keyID2, priv2, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	kid2 := did2 + "#" + keyID2
	resolver := func(k string) (ed25519.PublicKey, error) {
		switch k {
		case kid:
			return pub, nil
		case kid2:
			return pub2, nil
		default:
			return nil, fmt.Errorf("unknown kid: %s", k)
		}
	}

	// create content chain (using current time so credential iat is valid)
	docCID, _, _ := DocumentCID(map[string]any{"hello": "world"})
	contentJWS, _, contentCID := testSignContentGenesis(t, did, docCID, kid, priv, genesisTime)

	// creator issues a write credential to did2
	vc, err := CreateCredential(did, did2, kid, "chain:*", "write", 1*time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}

	// delegated update with authorization credential
	docCID2, _, _ := DocumentCID(map[string]any{"v": int64(2)})
	updatePayload := map[string]any{
		"version":              int64(1),
		"type":                 "update",
		"did":                  did2,
		"previousOperationCID": contentCID,
		"documentCID":          docCID2,
		"baseDocumentCID":      nil,
		"createdAt":            updateTime,
		"note":                 nil,
		"authorization":        vc,
	}
	_, _, updateCIDStr, _ := DagCborCID(updatePayload)
	updateHeader := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:content-op", Kid: kid2, CID: updateCIDStr}
	updateJWS, _ := CreateJWS(updateHeader, updatePayload, priv2)

	result, err := VerifyContentChain([]string{contentJWS, updateJWS}, resolver, true)
	if err != nil {
		t.Fatalf("VerifyContentChain with credential: %v", err)
	}
	if result.State.Length != 2 {
		t.Errorf("Length: got %d, want 2", result.State.Length)
	}
}

// ---------------------------------------------------------------------------
// Content extension verification tests
// ---------------------------------------------------------------------------

func TestVerifyContentExtension_Update(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	docCID1, _, _ := DocumentCID(map[string]any{"v": int64(1)})
	docCID2, _, _ := DocumentCID(map[string]any{"v": int64(2)})

	contentJWS, _, _ := testSignContentGenesis(t, did, docCID1, kid, priv, "2026-03-07T00:00:01.000Z")
	chainResult, _ := VerifyContentChain([]string{contentJWS}, resolver, true)

	updateJWS, _ := testSignContentUpdate(t, did, chainResult.State.HeadCID, docCID2, kid, priv, "2026-03-07T00:00:02.000Z")

	extResult, err := VerifyContentExtension(chainResult.State, chainResult.LastCreatedAt, updateJWS, resolver, true)
	if err != nil {
		t.Fatalf("VerifyContentExtension: %v", err)
	}
	if extResult.State.Length != 2 {
		t.Errorf("Length: got %d, want 2", extResult.State.Length)
	}
	if extResult.State.CurrentDocumentCID == nil || *extResult.State.CurrentDocumentCID != docCID2 {
		t.Error("expected updated documentCID")
	}
}

// ---------------------------------------------------------------------------
// Beacon verification tests
// ---------------------------------------------------------------------------

func TestVerifyBeacon(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	manifestContentId := DeriveContentID([]byte("test-manifest-bytes!"))
	beaconJWS, beaconCID, err := SignBeacon(did, manifestContentId, kid, priv)
	if err != nil {
		t.Fatal(err)
	}

	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	result, err := VerifyBeacon(beaconJWS, resolver)
	if err != nil {
		t.Fatalf("VerifyBeacon: %v", err)
	}
	if result.BeaconCID != beaconCID {
		t.Errorf("BeaconCID: got %s, want %s", result.BeaconCID, beaconCID)
	}
	if result.DID != did {
		t.Errorf("DID: got %s, want %s", result.DID, did)
	}
	if result.ManifestContentId != manifestContentId {
		t.Errorf("ManifestContentId mismatch")
	}
}

func TestVerifyBeacon_FutureClock(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	manifestContentId := DeriveContentID([]byte("test-manifest-future!"))
	beaconJWS, _, _ := SignBeacon(did, manifestContentId, kid, priv)

	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	// verify at a time far in the past — beacon will be "too far in the future"
	pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := VerifyBeaconAt(beaconJWS, resolver, pastTime)
	if err == nil {
		t.Fatal("expected error for future beacon")
	}
}

// ---------------------------------------------------------------------------
// Artifact verification tests
// ---------------------------------------------------------------------------

func TestVerifyArtifact(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	content := map[string]any{
		"$schema": "urn:dfos:relay-profile:v1",
		"name":    "test relay",
	}
	artifactJWS, artifactCID, err := SignArtifact(did, content, kid, priv)
	if err != nil {
		t.Fatal(err)
	}

	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	result, err := VerifyArtifact(artifactJWS, resolver)
	if err != nil {
		t.Fatalf("VerifyArtifact: %v", err)
	}
	if result.ArtifactCID != artifactCID {
		t.Errorf("ArtifactCID: got %s, want %s", result.ArtifactCID, artifactCID)
	}
	if result.DID != did {
		t.Errorf("DID: got %s, want %s", result.DID, did)
	}
	if result.Content["$schema"] != "urn:dfos:relay-profile:v1" {
		t.Error("content $schema mismatch")
	}
}

func TestVerifyArtifact_MissingSchema(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID

	// build artifact manually without $schema
	payload := map[string]any{
		"version":   int64(1),
		"type":      "artifact",
		"did":       did,
		"content":   map[string]any{"name": "no schema"},
		"createdAt": "2026-03-07T00:00:01.000Z",
	}
	_, _, cidStr, _ := DagCborCID(payload)
	header := JWSHeader{Alg: "EdDSA", Typ: "did:dfos:artifact", Kid: kid, CID: cidStr}
	jws, _ := CreateJWS(header, payload, priv)

	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	_, err := VerifyArtifact(jws, resolver)
	if err == nil {
		t.Fatal("expected error for missing $schema")
	}
}

// ---------------------------------------------------------------------------
// Countersignature verification tests
// ---------------------------------------------------------------------------

func TestVerifyCountersignature(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	targetCID := "bafyreidykglsfhoixmivffc5uwhcz4mjwdulkiu3k44wgo4ml3ds3a5yfu"

	csJWS, csCID, err := SignCountersign(did, targetCID, kid, priv)
	if err != nil {
		t.Fatal(err)
	}

	resolver := func(k string) (ed25519.PublicKey, error) {
		if k == kid {
			return pub, nil
		}
		return nil, fmt.Errorf("unknown kid: %s", k)
	}

	result, err := VerifyCountersignature(csJWS, resolver)
	if err != nil {
		t.Fatalf("VerifyCountersignature: %v", err)
	}
	if result.CountersignCID != csCID {
		t.Errorf("CountersignCID: got %s, want %s", result.CountersignCID, csCID)
	}
	if result.WitnessDID != did {
		t.Errorf("WitnessDID: got %s, want %s", result.WitnessDID, did)
	}
	if result.TargetCID != targetCID {
		t.Errorf("TargetCID: got %s, want %s", result.TargetCID, targetCID)
	}
}

func TestVerifyCountersignature_WrongKey(t *testing.T) {
	priv, pub, _, keyID := testKeys(t)
	_, did, _ := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{NewMultikeyPublicKey(keyID, pub)}, nil, nil,
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	kid := did + "#" + keyID
	csJWS, _, _ := SignCountersign(did, "some-cid", kid, priv)

	// resolver returns a different key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	resolver := func(k string) (ed25519.PublicKey, error) {
		return wrongPub, nil
	}

	_, err := VerifyCountersignature(csJWS, resolver)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

// ---------------------------------------------------------------------------
// Auth token verification tests
// ---------------------------------------------------------------------------

func TestVerifyAuthToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:test123"
	aud := "https://relay.example.com"
	kid := iss + "#key_auth_0"

	token, err := CreateAuthToken(iss, aud, kid, 1*time.Hour, priv)
	if err != nil {
		t.Fatal(err)
	}

	result, err := VerifyAuthToken(token, pub, aud)
	if err != nil {
		t.Fatalf("VerifyAuthToken: %v", err)
	}
	if result.Iss != iss {
		t.Errorf("Iss: got %s, want %s", result.Iss, iss)
	}
	if result.Sub != iss {
		t.Errorf("Sub: got %s, want %s", result.Sub, iss)
	}
	if result.Kid != kid {
		t.Errorf("Kid: got %s, want %s", result.Kid, kid)
	}
}

func TestVerifyAuthToken_WrongAudience(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:test123"
	kid := iss + "#key_auth_0"

	token, _ := CreateAuthToken(iss, "https://relay-a.com", kid, 1*time.Hour, priv)

	_, err := VerifyAuthToken(token, pub, "https://relay-b.com")
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerifyAuthToken_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:test123"
	kid := iss + "#key_auth_0"

	token, _ := CreateAuthToken(iss, "https://relay.com", kid, 1*time.Second, priv)

	futureTime := time.Now().Unix() + 10
	_, err := VerifyAuthTokenAt(token, pub, "https://relay.com", futureTime)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyAuthToken_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:test123"
	kid := iss + "#key_auth_0"

	token, _ := CreateAuthToken(iss, "https://relay.com", kid, 1*time.Hour, priv)

	_, err := VerifyAuthToken(token, otherPub, "https://relay.com")
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

// Verify that a chain built with the reference key verifies correctly
func TestVerifyIdentityChain_FullRoundTrip(t *testing.T) {
	priv, pub := refKey1()
	keyID := "key_r9ev34fvc23z999veaaft8"
	mk := NewMultikeyPublicKey(keyID, pub)

	// sign genesis with controlled timestamp
	genJWS, did, genCID := testSignIdentityGenesis(t,
		[]MultikeyPublicKey{mk}, []MultikeyPublicKey{mk}, []MultikeyPublicKey{mk},
		keyID, priv, "2026-03-07T00:00:00.000Z",
	)

	// sign update
	updateJWS, updateCID := testSignIdentityUpdate(t, did,
		[]MultikeyPublicKey{mk}, []MultikeyPublicKey{mk}, []MultikeyPublicKey{mk},
		keyID, priv, genCID, "2026-03-07T01:00:00.000Z",
	)

	// sign delete
	deleteJWS, _ := testSignIdentityDelete(t, did, keyID, priv, updateCID, "2026-03-07T02:00:00.000Z")

	// verify full chain
	result, err := VerifyIdentityChain([]string{genJWS, updateJWS, deleteJWS})
	if err != nil {
		t.Fatalf("VerifyIdentityChain: %v", err)
	}
	if !result.State.IsDeleted {
		t.Error("expected deleted")
	}
	if result.State.DID != did {
		t.Errorf("DID mismatch: got %s, want %s", result.State.DID, did)
	}
}
