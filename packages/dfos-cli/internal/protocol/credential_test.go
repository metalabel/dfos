package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestVerifyCredentialValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, sub, kid, "DFOSContentRead", 1*time.Hour, "content-xyz", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	vc, err := VerifyCredential(token, pub, sub, "DFOSContentRead")
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}

	if vc.Iss != iss {
		t.Errorf("iss: got %s, want %s", vc.Iss, iss)
	}
	if vc.Sub != sub {
		t.Errorf("sub: got %s, want %s", vc.Sub, sub)
	}
	if vc.Type != "DFOSContentRead" {
		t.Errorf("type: got %s, want DFOSContentRead", vc.Type)
	}
	if vc.Kid != kid {
		t.Errorf("kid: got %s, want %s", vc.Kid, kid)
	}
	if vc.ContentID != "content-xyz" {
		t.Errorf("contentId: got %s, want content-xyz", vc.ContentID)
	}
}

func TestVerifyCredentialValidNoScope(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, sub, kid, "DFOSContentWrite", 1*time.Hour, "", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	vc, err := VerifyCredential(token, pub, "", "")
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}

	if vc.Type != "DFOSContentWrite" {
		t.Errorf("type: got %s, want DFOSContentWrite", vc.Type)
	}
	if vc.ContentID != "" {
		t.Errorf("contentId: got %q, want empty", vc.ContentID)
	}
}

func TestVerifyCredentialExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	// create with very short TTL then verify at a time after expiry
	token, err := CreateCredential(iss, sub, kid, "DFOSContentRead", 1*time.Second, "", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// verify at a time 10 seconds in the future (past exp)
	futureTime := time.Now().Unix() + 10
	_, err = VerifyCredentialAt(token, pub, sub, "DFOSContentRead", futureTime)
	if err == nil {
		t.Fatal("expected error for expired credential, got nil")
	}
	if err.Error() != "credential expired" {
		t.Errorf("expected 'credential expired', got %q", err.Error())
	}
}

func TestVerifyCredentialWrongSubject(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, sub, kid, "DFOSContentRead", 1*time.Hour, "", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, pub, "did:dfos:wrongperson", "DFOSContentRead")
	if err == nil {
		t.Fatal("expected error for wrong subject, got nil")
	}
	expected := "subject mismatch: expected did:dfos:wrongperson, got did:dfos:reader456"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestVerifyCredentialWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, sub, kid, "DFOSContentRead", 1*time.Hour, "", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, otherPub, sub, "DFOSContentRead")
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
	if err.Error() != "invalid signature" {
		t.Errorf("expected 'invalid signature', got %q", err.Error())
	}
}

func TestVerifyCredentialWrongType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	sub := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, sub, kid, "DFOSContentRead", 1*time.Hour, "", priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, pub, sub, "DFOSContentWrite")
	if err == nil {
		t.Fatal("expected error for wrong type, got nil")
	}
	expected := "type mismatch: expected DFOSContentWrite, got DFOSContentRead"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
