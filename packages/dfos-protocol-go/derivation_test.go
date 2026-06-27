package dfos

import "testing"

// TestValidateDID covers the well-formedness validator: a derived DID is accepted,
// and every malformed shape — wrong method, wrong width, out-of-alphabet character,
// trailing fragment — is rejected. There is a single canonical identifier width;
// anything narrower or wider is simply not a DID.
func TestValidateDID(t *testing.T) {
	valid := DeriveDID([]byte("conformance-seed"))
	if err := ValidateDID(valid); err != nil {
		t.Fatalf("derived DID must validate, got error: %v", err)
	}
	if !IsValidDID(valid) {
		t.Fatalf("IsValidDID must be true for a derived DID: %q", valid)
	}

	suffix := valid[len("did:dfos:"):]
	cases := []struct {
		name string
		did  string
	}{
		{"empty", ""},
		{"missing method prefix", suffix},
		{"wrong did method", "did:web:" + suffix},
		{"double prefix", "did:dfos:" + valid},
		{"too short", "did:dfos:" + suffix[:idLength-9]},
		{"too long", valid + "vz"},
		{"out-of-alphabet char", "did:dfos:b" + suffix[1:]}, // 'b' is not in idAlphabet
		{"trailing fragment", valid + "#key_abc"},
	}
	for _, tc := range cases {
		if err := ValidateDID(tc.did); err == nil {
			t.Errorf("%s: expected rejection for %q", tc.name, tc.did)
		}
		if IsValidDID(tc.did) {
			t.Errorf("%s: IsValidDID should be false for %q", tc.name, tc.did)
		}
	}
}
