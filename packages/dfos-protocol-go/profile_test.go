package dfos

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

// signWithHeader forges a JWS whose protected header is exactly headerJSON and
// whose signature is a real Ed25519 signature over the (header.payload) signing
// input. The only thing that can reject such a token is a profile gate, not a
// bad signature — so these tests isolate the profile behavior.
func signWithHeader(headerJSON string, priv ed25519.PrivateKey) string {
	headerB64 := Base64urlEncodeString(headerJSON)
	payloadB64 := Base64urlEncodeString(`{"data":"hello"}`)
	signingInput := headerB64 + "." + payloadB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + Base64urlEncode(sig)
}

func profileTestKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("dfos-protocol-reference-key-1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

func TestProfileAcceptsInProfileJWS(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"EdDSA","typ":"test","kid":"key1"}`, priv)
	if _, _, err := VerifyJWS(token, pub); err != nil {
		t.Fatalf("in-profile JWS should verify: %v", err)
	}
}

func TestProfileRejectsAlgNone(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"none","typ":"test","kid":"key1"}`, priv)
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("alg=none must be rejected")
	} else if !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("expected algorithm rejection, got: %v", err)
	}
}

func TestProfileRejectsAlgCase(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"eddsa","typ":"test","kid":"key1"}`, priv)
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("lowercase alg=eddsa must be rejected")
	}
}

func TestProfileRejectsCrit(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"EdDSA","typ":"test","kid":"key1","crit":["exp"]}`, priv)
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("crit header must be rejected")
	} else if !strings.Contains(err.Error(), "crit") {
		t.Fatalf("expected crit rejection, got: %v", err)
	}
}

func TestProfileRejectsJWK(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"EdDSA","typ":"test","kid":"key1","jwk":{"kty":"OKP"}}`, priv)
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("jwk header must be rejected")
	} else if !strings.Contains(err.Error(), "jwk") {
		t.Fatalf("expected jwk rejection, got: %v", err)
	}
}

func TestProfileRejectsX5C(t *testing.T) {
	priv, pub := profileTestKey()
	token := signWithHeader(`{"alg":"EdDSA","typ":"test","kid":"key1","x5c":["MIIB"]}`, priv)
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("x5c header must be rejected")
	} else if !strings.Contains(err.Error(), "x5c") {
		t.Fatalf("expected x5c rejection, got: %v", err)
	}
}

func TestProfileGatesBeforeSignatureCheck(t *testing.T) {
	_, pub := profileTestKey()
	// garbage signature; profile gate (alg=none) must fire first
	headerB64 := Base64urlEncodeString(`{"alg":"none","typ":"test","kid":"key1"}`)
	payloadB64 := Base64urlEncodeString(`{"data":"hello"}`)
	token := headerB64 + "." + payloadB64 + ".AAAA"
	if _, _, err := VerifyJWS(token, pub); err == nil {
		t.Fatal("out-of-profile header must be rejected before signature check")
	} else if !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("expected algorithm rejection (profile before sig), got: %v", err)
	}
}
