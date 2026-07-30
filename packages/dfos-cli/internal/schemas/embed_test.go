package schemas

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedSchemasMatchCanonical ensures each embedded schema stays
// byte-identical to its canonical source in packages/dfos-protocol/schemas. After
// editing a canonical schema, run ./scripts/sync-schemas.sh.
//
// Drift here is not cosmetic: the CLI validates documents against these embedded
// bytes, so a stale copy means the CLI accepts or rejects documents that
// schemas.dfos.com does not — two different definitions of the same $id. Both
// copies were in fact stale when this guard was added (post/v1 predated the credit
// entry amendment; profile/v1 predated `avatar` and the shared media object), which
// is exactly the silent divergence the test exists to prevent.
//
// The test skips when run outside the repo tree (e.g. from the module cache),
// where the canonical files are absent — mirroring internal/skill/embed_test.go.
func TestEmbeddedSchemasMatchCanonical(t *testing.T) {
	cases := []struct {
		name     string
		embedded []byte
	}{
		{name: "post.v1.json", embedded: PostV1},
		{name: "profile.v1.json", embedded: ProfileV1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical := filepath.Join("..", "..", "..", "dfos-protocol", "schemas", tc.name)
			want, err := os.ReadFile(canonical)
			if err != nil {
				t.Skipf("canonical schema not found (%v) — skipping drift check outside repo tree", err)
			}
			if string(want) != string(tc.embedded) {
				t.Fatalf("embedded %s is out of sync with %s; run ./scripts/sync-schemas.sh", tc.name, canonical)
			}
		})
	}
}
