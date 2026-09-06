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

// TestVerifyCredentialTemporalBoundaries pins the exp boundary documented in
// PROTOCOL.md "Time basis": exp is closed-rejecting (exp == basis is expired),
// and iat is informational, so a credential issued after the basis is accepted.
// This is the Go twin of the TS boundary tests in
// dfos-protocol/tests/chain.spec.ts.
func TestVerifyCredentialTemporalBoundaries(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	// CreateCredential sets iat = issuance time, exp = iat + ttl. Read the
	// actual claims back rather than guessing the issuance instant, so the
	// boundary arithmetic is exact regardless of clock ticks.
	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 10*time.Second, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	probe, err := VerifyCredentialAt(token, pub, aud, "read", time.Now().Unix())
	if err != nil {
		t.Fatalf("probe verify: %v", err)
	}
	issuedAt := probe.Iat
	exp := probe.Exp

	// exp closed-rejecting: currentTime == exp MUST be expired.
	if _, err := VerifyCredentialAt(token, pub, aud, "read", exp); err == nil {
		t.Error("exp == now MUST be rejected as expired (closed boundary)")
	} else if err.Error() != "credential expired" {
		t.Errorf("exp == now: expected 'credential expired', got %q", err.Error())
	}

	// just inside exp: currentTime == exp-1 MUST be accepted.
	if _, err := VerifyCredentialAt(token, pub, aud, "read", exp-1); err != nil {
		t.Errorf("now == exp-1 MUST be accepted, got %v", err)
	}

	// basis == iat MUST be accepted.
	if _, err := VerifyCredentialAt(token, pub, aud, "read", issuedAt); err != nil {
		t.Errorf("basis == iat MUST be accepted, got %v", err)
	}

	// iat gates nothing: a basis BEFORE the credential was issued is accepted,
	// because the basis decides when authority applies, not the issuer's clock.
	if _, err := VerifyCredentialAt(token, pub, aud, "read", issuedAt-1); err != nil {
		t.Errorf("basis == iat-1 MUST be accepted (iat is informational), got %v", err)
	}
}

// TestVerifyCredentialAtBasisTruncates pins the ISO-basis entrypoint: the basis
// converts to whole seconds by truncation, so a sub-second remainder never
// pushes exp over its boundary.
func TestVerifyCredentialAtBasisTruncates(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read", 10*time.Second, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	probe, err := VerifyCredentialAt(token, pub, aud, "read", time.Now().Unix())
	if err != nil {
		t.Fatalf("probe verify: %v", err)
	}

	// A basis whose whole-second floor is exp-1 is inside the window; the .999
	// remainder is truncated away rather than rounded up onto exp.
	inside := time.Unix(probe.Exp-1, 999_000_000).UTC().Format(protocolTimeFormat)
	if _, err := VerifyCredentialAtBasis(token, pub, aud, "read", inside); err != nil {
		t.Errorf("basis floor == exp-1 MUST be accepted, got %v", err)
	}

	// A basis whose floor is exp is expired.
	atExp := time.Unix(probe.Exp, 0).UTC().Format(protocolTimeFormat)
	if _, err := VerifyCredentialAtBasis(token, pub, aud, "read", atExp); err == nil {
		t.Error("basis floor == exp MUST be rejected as expired")
	}

	// An empty basis is ephemeral: the wall clock, where the credential is live.
	if _, err := VerifyCredentialAtBasis(token, pub, aud, "read", ""); err != nil {
		t.Errorf("empty basis MUST fall to the wall clock, got %v", err)
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
	expected := `action mismatch: expected write, not granted by att ("read")`
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestVerifyCredentialCombinedAction(t *testing.T) {
	// A single att entry granting the canonical combined "read,write" action must
	// verify (and satisfy an expectedAction of either "read" or "write"). The old
	// exact-match allowlist hard-rejected this spec-valid grant; the TS reference
	// applies no action allowlist.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss := "did:dfos:abc123"
	aud := "did:dfos:reader456"
	kid := iss + "#key_auth_0"

	token, err := CreateCredential(iss, aud, kid, "chain:x", "read,write", 1*time.Hour, priv)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	for _, expectAction := range []string{"", "read", "write"} {
		vc, err := VerifyCredential(token, pub, aud, expectAction)
		if err != nil {
			t.Fatalf("combined read,write credential rejected for expectedAction=%q: %v", expectAction, err)
		}
		if vc.Action != "read,write" {
			t.Errorf("expectedAction=%q: convenience Action = %q, want %q", expectAction, vc.Action, "read,write")
		}
		if vc.ContentID != "x" {
			t.Errorf("expectedAction=%q: ContentID = %q, want %q", expectAction, vc.ContentID, "x")
		}
	}
}
