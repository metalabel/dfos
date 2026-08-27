package dfos

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// MALFORMED UTF-8 IN THE PAYLOAD IS AN INVALID PROOF.
//
// encoding/json substitutes U+FFFD for an invalid byte and reports success,
// where the TS twin decodes with TextDecoder('utf-8', {fatal:true}) and throws.
// Left alone, that is a live fork: a hand-signed proof carrying a malformed byte
// in an unknown member — jti, the member a write-shaped relay keys its replay
// cache on — authenticates on the Go relay and 401s on the TS one, from the same
// octets.
//
// The splice is re-signed with the vector key, so the signature is genuine and
// the rejection can only come from the UTF-8 gate.
func TestVerifyIdentityProofRejectsInvalidUTF8Payload(t *testing.T) {
	key := apiAuthVectorKey()
	resolve := apiAuthVectorResolver(key)
	fresh := time.Unix(apiAuthVectorIat+10, 0)
	expect := IdentityProofExpectations{Method: "GET", Host: "api.dfos.com", Path: "/v0/profile"}

	proof, err := BuildIdentityProof("GET", "api.dfos.com", "/v0/profile", apiAuthVectorKid, key,
		IdentityProofOptions{Iat: apiAuthVectorIat, ExtraMembers: ProofExtraMembers{"jti": "aaaa"}})
	if err != nil {
		t.Fatal(err)
	}
	// The honest proof verifies — everything but the spliced byte is identical.
	if _, err := VerifyIdentityProof(proof, expect, resolve, fresh); err != nil {
		t.Fatalf("baseline proof: %v", err)
	}

	parts := strings.Split(proof, ".")
	payload, err := Base64urlDecode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	spliced := bytes.Replace(payload, []byte(`"aaaa"`), []byte{'"', 'a', 0xFF, 'a', 'a', '"'}, 1)
	if bytes.Equal(spliced, payload) {
		t.Fatal("splice did not land — the jti member was not found in the payload")
	}

	signingInput := parts[0] + "." + Base64urlEncode(spliced)
	tampered := signingInput + "." + Base64urlEncode(ed25519.Sign(key, []byte(signingInput)))
	if _, err := VerifyIdentityProof(tampered, expect, resolve, fresh); !errors.Is(err, ErrIdentityProofInvalid) {
		t.Fatalf("invalid UTF-8 in jti: got %v, want an invalid-proof verdict", err)
	}
}
