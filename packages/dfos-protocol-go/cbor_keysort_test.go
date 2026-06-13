package dfos

import "testing"

// TestDagCborMultibyteKeySortPin pins the canonical dag-cbor map key sort
// (length-first, then byte-wise) across the TS and Go twins. The keys in each
// object are EQUAL byte-length and differ only by a multi-byte UTF-8 codepoint,
// which is exactly the case that distinguishes a byte-wise sort from a
// codepoint/collation sort. The expected CIDs are byte-identical to the TS twin
// (dfos-protocol/tests/cbor-keysort.spec.ts). If either encoder's key ordering
// drifts, this pin and its TS counterpart diverge.
func TestDagCborMultibyteKeySortPin(t *testing.T) {
	cases := []struct {
		obj  map[string]any
		want string
	}{
		// "aé" and "azz" are both 3 bytes in UTF-8 (é = 2 bytes)
		{map[string]any{"aé": 1, "azz": 2}, "bafyreihtzmqnfk5pk63tew7x2h525ntozjlduzhasiadw6fes4iqcfxcqe"},
		// "日a" and "azzz" are both 4 bytes in UTF-8 (日 = 3 bytes)
		{map[string]any{"日a": 1, "azzz": 2}, "bafyreih2na7yfz3rrvk3jrhktnb3ayr7gxtnqyqf742kb6iz3va7efwvui"},
	}
	for _, c := range cases {
		_, _, cid, err := DagCborCID(c.obj)
		if err != nil {
			t.Fatalf("DagCborCID: %v", err)
		}
		if cid != c.want {
			t.Errorf("CID mismatch: got %s, want %s", cid, c.want)
		}
	}
}
