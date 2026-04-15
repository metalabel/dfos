package dfos

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestVerifyCredentialValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:content-xyz", "read", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	vc, err := VerifyCredential(token, pub, aud, "read")
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}

	if vc.Iss != iss {
		t.Errorf("iss: got %s, want %s", vc.Iss, iss)
	}
	if vc.Aud != aud {
		t.Errorf("aud: got %s, want %s", vc.Aud, aud)
	}
	if vc.Action != "read" {
		t.Errorf("action: got %s, want read", vc.Action)
	}
	if len(vc.Att) != 1 || vc.Att[0].Resource != "chain:content-xyz" || vc.Att[0].Action != "read" {
		t.Errorf("att: got %+v, want [{chain:content-xyz read}]", vc.Att)
	}
	if vc.Kid != kid {
		t.Errorf("kid: got %s, want %s", vc.Kid, kid)
	}
	if vc.ContentID != "content-xyz" {
		t.Errorf("contentId: got %s, want content-xyz", vc.ContentID)
	}
}

func TestVerifyCredentialWildcard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:*", "write", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	vc, err := VerifyCredential(token, pub, "", "")
	if err != nil {
		t.Fatalf("VerifyCredential: %v", err)
	}

	if vc.Action != "write" {
		t.Errorf("action: got %s, want write", vc.Action)
	}
	if vc.ContentID != "*" {
		t.Errorf("contentId: got %q, want *", vc.ContentID)
	}
	if len(vc.Att) != 1 || vc.Att[0].Resource != "chain:*" {
		t.Errorf("att: got %+v, want [{chain:* write}]", vc.Att)
	}
}

func TestVerifyCredentialExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 1*time.Second, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	futureTime := time.Now().Unix() + 10
	_, err = VerifyCredentialAt(token, pub, aud, "read", futureTime)
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
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, pub, "did:dfos:wrongperson", "read")
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
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, otherPub, aud, "read")
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
	if err.Error() != "invalid signature" {
		t.Errorf("expected 'invalid signature', got %q", err.Error())
	}
}

func TestVerifyCredentialWrongAction(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	_, err = VerifyCredential(token, pub, aud, "write")
	if err == nil {
		t.Fatal("expected error for wrong action, got nil")
	}
	expected := "action mismatch: expected write, got read"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
