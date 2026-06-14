package relay

import (
	"crypto/ed25519"
	"testing"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// TestAuthTokenMaxTTLCeiling pins the auth-token lifetime ceiling: a token whose
// declared lifetime (exp-iat) exceeds the ceiling is rejected, one within it
// authenticates, and a disabled ceiling (<= 0) lets a long token through —
// proving the gate bounds total lifetime, not remaining time. The ceiling applies
// only to auth tokens; DFOS credentials never reach AuthenticateRequest.
func TestAuthTokenMaxTTLCeiling(t *testing.T) {
	store := NewMemoryStore()
	r, err := NewRelay(RelayOptions{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	id := createTestIdentity(t)
	if res := r.Ingest([]string{id.token}); res[0].Status != "new" {
		t.Fatalf("seed identity: %s (%s)", res[0].Status, res[0].Error)
	}
	kid := id.did + "#" + id.auth.keyID
	priv := ed25519.PrivateKey(id.auth.priv)

	mint := func(ttl time.Duration) string {
		tok, err := dfos.CreateAuthToken(id.did, r.DID(), kid, ttl, priv)
		if err != nil {
			t.Fatal(err)
		}
		return "Bearer " + tok
	}

	if auth := AuthenticateRequest(mint(1*time.Hour), r.DID(), store, 24*time.Hour); auth == nil {
		t.Fatal("expected 1h auth token to authenticate under the 24h ceiling")
	}
	if auth := AuthenticateRequest(mint(25*time.Hour), r.DID(), store, 24*time.Hour); auth != nil {
		t.Fatal("SECURITY: expected 25h auth token to be REJECTED by the 24h ceiling")
	}
	if auth := AuthenticateRequest(mint(25*time.Hour), r.DID(), store, -1); auth == nil {
		t.Fatal("expected 25h auth token to authenticate when the ceiling is disabled")
	}
}

// TestDefaultMaxAuthTokenTTLApplied confirms NewRelay defaults the ceiling to 24h
// when the option is left zero.
func TestDefaultMaxAuthTokenTTLApplied(t *testing.T) {
	r, err := NewRelay(RelayOptions{Store: NewMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	if r.maxAuthTokenTTL != DefaultMaxAuthTokenTTL {
		t.Fatalf("expected default ceiling %v, got %v", DefaultMaxAuthTokenTTL, r.maxAuthTokenTTL)
	}
}
