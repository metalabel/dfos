package dfos

import (
	"testing"
)

// ---------------------------------------------------------------------------
// ParseResource
// ---------------------------------------------------------------------------

func TestParseResource(t *testing.T) {
	tests := []struct {
		input    string
		wantType string
		wantID   string
		wantOK   bool
	}{
		{"chain:abc", "chain", "abc", true},
		{"manifest:manifest1", "manifest", "manifest1", true},
		{"chain:*", "chain", "*", true},
		{"invalid", "", "", false},
		{":", "", "", true}, // edge: empty type and id
	}

	for _, tt := range tests {
		typ, id, ok := ParseResource(tt.input)
		if ok != tt.wantOK {
			t.Errorf("ParseResource(%q): ok=%v, want %v", tt.input, ok, tt.wantOK)
		}
		if typ != tt.wantType || id != tt.wantID {
			t.Errorf("ParseResource(%q): got (%q, %q), want (%q, %q)", tt.input, typ, id, tt.wantType, tt.wantID)
		}
	}
}

// ---------------------------------------------------------------------------
// ParseActions
// ---------------------------------------------------------------------------

func TestParseActions(t *testing.T) {
	tests := []struct {
		input string
		want  map[string]bool
	}{
		{"read", map[string]bool{"read": true}},
		{"read,write", map[string]bool{"read": true, "write": true}},
		{"read, write", map[string]bool{"read": true, "write": true}},
		{"", map[string]bool{}},
	}

	for _, tt := range tests {
		got := ParseActions(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("ParseActions(%q): got %v, want %v", tt.input, got, tt.want)
			continue
		}
		for k := range tt.want {
			if !got[k] {
				t.Errorf("ParseActions(%q): missing key %q", tt.input, k)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// ParseAtt
// ---------------------------------------------------------------------------

func TestParseAtt(t *testing.T) {
	payload := map[string]any{
		"att": []any{
			map[string]any{"resource": "chain:abc", "action": "read"},
			map[string]any{"resource": "manifest:m1", "action": "write"},
		},
	}

	att := ParseAtt(payload)
	if len(att) != 2 {
		t.Fatalf("ParseAtt: got %d entries, want 2", len(att))
	}
	if att[0].Resource != "chain:abc" || att[0].Action != "read" {
		t.Errorf("att[0]: got %+v", att[0])
	}
	if att[1].Resource != "manifest:m1" || att[1].Action != "write" {
		t.Errorf("att[1]: got %+v", att[1])
	}
}

func TestParseAttEmpty(t *testing.T) {
	att := ParseAtt(map[string]any{})
	if att != nil {
		t.Errorf("ParseAtt(empty): got %v, want nil", att)
	}
}

func TestParseAttSkipsMalformed(t *testing.T) {
	payload := map[string]any{
		"att": []any{
			"not a map",
			map[string]any{"resource": "chain:abc"}, // missing action
			map[string]any{"resource": "chain:ok", "action": "read"},
		},
	}

	att := ParseAtt(payload)
	if len(att) != 1 {
		t.Fatalf("ParseAtt: got %d entries, want 1", len(att))
	}
	if att[0].Resource != "chain:ok" {
		t.Errorf("att[0]: got %+v", att[0])
	}
}

// ---------------------------------------------------------------------------
// ParsePrf
// ---------------------------------------------------------------------------

func TestParsePrf(t *testing.T) {
	payload := map[string]any{
		"prf": []any{"token1", "token2"},
	}

	prf := ParsePrf(payload)
	if len(prf) != 2 {
		t.Fatalf("ParsePrf: got %d entries, want 2", len(prf))
	}
	if prf[0] != "token1" || prf[1] != "token2" {
		t.Errorf("ParsePrf: got %v", prf)
	}
}

func TestParsePrfEmpty(t *testing.T) {
	prf := ParsePrf(map[string]any{})
	if prf != nil {
		t.Errorf("ParsePrf(empty): got %v, want nil", prf)
	}
}

func TestParsePrfSkipsNonStrings(t *testing.T) {
	payload := map[string]any{
		"prf": []any{"valid", 42, "", "also-valid"},
	}

	prf := ParsePrf(payload)
	if len(prf) != 2 {
		t.Fatalf("ParsePrf: got %d, want 2", len(prf))
	}
}

// ---------------------------------------------------------------------------
// IsAttenuated — basic narrowing/widening
// ---------------------------------------------------------------------------

func TestIsAttenuatedNarrowScope(t *testing.T) {
	parent := []AttEntry{
		{Resource: "chain:content1", Action: "write"},
		{Resource: "chain:content2", Action: "write"},
	}
	child := []AttEntry{
		{Resource: "chain:content1", Action: "write"},
	}
	if !IsAttenuated(parent, child) {
		t.Fatal("child that narrows scope should be attenuated")
	}
}

func TestIsAttenuatedWidenScope(t *testing.T) {
	parent := []AttEntry{
		{Resource: "chain:content1", Action: "write"},
	}
	child := []AttEntry{
		{Resource: "chain:content1", Action: "write"},
		{Resource: "chain:content2", Action: "write"},
	}
	if IsAttenuated(parent, child) {
		t.Fatal("child that widens scope should NOT be attenuated")
	}
}

func TestIsAttenuatedExactMatch(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:abc", Action: "read"}}
	child := []AttEntry{{Resource: "chain:abc", Action: "read"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("exact match should be attenuated")
	}
}

func TestIsAttenuatedActionMismatch(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:abc", Action: "read"}}
	child := []AttEntry{{Resource: "chain:abc", Action: "write"}}
	if IsAttenuated(parent, child) {
		t.Fatal("child with different action should NOT be attenuated")
	}
}

func TestIsAttenuatedEmptyChild(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:abc", Action: "read"}}
	if !IsAttenuated(parent, nil) {
		t.Fatal("empty child should be attenuated from any parent")
	}
}

// ---------------------------------------------------------------------------
// IsAttenuated — chain:* wildcard
// ---------------------------------------------------------------------------

func TestIsAttenuatedChainWildcardCoversChainX(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:*", Action: "read"}}
	child := []AttEntry{{Resource: "chain:content1", Action: "read"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("chain:* should cover chain:content1")
	}
}

func TestIsAttenuatedChainWildcardCoversManifest(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:*", Action: "read"}}
	child := []AttEntry{{Resource: "manifest:manifest1", Action: "read"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("chain:* should cover manifest:M")
	}
}

func TestIsAttenuatedChainWildcardCoversChainWildcard(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:*", Action: "read"}}
	child := []AttEntry{{Resource: "chain:*", Action: "read"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("chain:* should cover chain:*")
	}
}

func TestIsAttenuatedChainXCannotCoverChainWildcard(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:content1", Action: "read"}}
	child := []AttEntry{{Resource: "chain:*", Action: "read"}}
	if IsAttenuated(parent, child) {
		t.Fatal("chain:X should NOT cover chain:* (widening)")
	}
}

func TestIsAttenuatedManifestCannotCoverChainWildcard(t *testing.T) {
	parent := []AttEntry{{Resource: "manifest:manifest1", Action: "read"}}
	child := []AttEntry{{Resource: "chain:*", Action: "read"}}
	if IsAttenuated(parent, child) {
		t.Fatal("manifest:M should NOT cover chain:* (widening)")
	}
}

// ---------------------------------------------------------------------------
// IsAttenuated — manifest / chain interactions
// ---------------------------------------------------------------------------

func TestIsAttenuatedManifestToChainNarrowing(t *testing.T) {
	parent := []AttEntry{{Resource: "manifest:manifest1", Action: "write"}}
	child := []AttEntry{{Resource: "chain:content1", Action: "write"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("manifest:M → chain:X should be valid narrowing")
	}
}

func TestIsAttenuatedChainToManifestWidening(t *testing.T) {
	parent := []AttEntry{{Resource: "chain:content1", Action: "write"}}
	child := []AttEntry{{Resource: "manifest:manifest1", Action: "write"}}
	if IsAttenuated(parent, child) {
		t.Fatal("chain:X → manifest:M should be invalid widening")
	}
}

func TestIsAttenuatedManifestExactMatch(t *testing.T) {
	parent := []AttEntry{{Resource: "manifest:m1", Action: "read"}}
	child := []AttEntry{{Resource: "manifest:m1", Action: "read"}}
	if !IsAttenuated(parent, child) {
		t.Fatal("manifest:M → manifest:M exact match should be attenuated")
	}
}

func TestIsAttenuatedManifestMismatch(t *testing.T) {
	parent := []AttEntry{{Resource: "manifest:m1", Action: "read"}}
	child := []AttEntry{{Resource: "manifest:m2", Action: "read"}}
	if IsAttenuated(parent, child) {
		t.Fatal("manifest:m1 should NOT cover manifest:m2")
	}
}
