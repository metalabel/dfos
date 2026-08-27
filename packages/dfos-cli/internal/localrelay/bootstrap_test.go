package localrelay

import (
	"bytes"
	"path/filepath"
	"testing"

	relay "github.com/metalabel/dfos/packages/dfos-web-relay-go"
)

// The CACHED-PROFILE branch of bootstrapPersistent must return the private key
// along with the DID and profile.
//
// Without it the relay holds no signing material on any boot after the first, so
// `dfos serve --gossip-proof` silently degrades to anonymous gossip: the flag
// reads as on, gossipProofSigned computes to false, and the operator learns
// nothing. Only the FIRST boot (which returns the freshly generated identity)
// ever signed.
func TestBootstrapPersistentKeepsThePrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.db")
	store, err := relay.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first, err := bootstrapPersistent(store, "test relay")
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	if first.PrivateKey == nil {
		t.Fatal("first boot returned no private key")
	}

	// Second call takes the cached-profile branch — same identity, same key.
	second, err := bootstrapPersistent(store, "test relay")
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if second.PrivateKey == nil {
		t.Fatal("cached-profile boot dropped the private key — gossip-proof would go anonymous")
	}
	if !bytes.Equal(second.PrivateKey, first.PrivateKey) {
		t.Fatal("cached-profile boot returned a different private key")
	}
	if second.DID != first.DID || second.KeyID != first.KeyID {
		t.Fatalf("cached-profile boot returned a different identity: %s#%s vs %s#%s",
			second.DID, second.KeyID, first.DID, first.KeyID)
	}
}
