package dfos

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// nest wraps "x" in d nested []any layers, producing a value whose deepest leaf
// sits at recursion depth d.
func nest(d int) any {
	var v any = "x"
	for i := 0; i < d; i++ {
		v = []any{v}
	}
	return v
}

// The canonical-numbers walk carries a generous depth guard (maxCanonicalDepth)
// as a DoS resource bound — a pathologically nested payload would otherwise
// recurse until the stack overflows. The boundary holds exactly: a leaf at depth
// maxCanonicalDepth is accepted; one level deeper is rejected.
func TestCanonicalDepthGuard(t *testing.T) {
	if err := AssertCanonicalNumbers(nest(maxCanonicalDepth)); err != nil {
		t.Fatalf("nesting at the cap should be accepted, got: %v", err)
	}
	if err := AssertCanonicalNumbers(nest(maxCanonicalDepth + 1)); err == nil {
		t.Fatal("nesting past the cap should be rejected")
	}
}

// A credential token exceeding maxCredentialSize is rejected before any decode —
// the size check is the first thing verifyCredentialCore does, bounding the
// nested-prf DoS surface. Credentials carry their own (larger) ceiling because
// they are exempt from the 64 KiB operation cap.
func TestCredentialSizeCap(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	oversize := strings.Repeat("x", maxCredentialSize+1)
	_, err = VerifyCredential(oversize, pub, "", "")
	if err == nil {
		t.Fatal("an over-size credential token should be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected a max-size rejection, got: %v", err)
	}
}
