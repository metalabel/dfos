package keystore

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

// DFOS_CONFIG is the CLI's isolation mechanism: point it at a scratch directory
// and the whole of this machine's dfos state should follow. The key store used
// to be the one thing that did not — it resolved its directory from the home
// directory directly — so an invocation aimed at a temp directory still wrote
// keys into the operator's real store. These tests hold that shut.
func TestDefaultKeyDirFollowsDFOSCONFIG(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DFOS_CONFIG", filepath.Join(tmp, "config.toml"))

	if got, want := defaultKeyDir(), filepath.Join(tmp, "keys"); got != want {
		t.Fatalf("defaultKeyDir() = %s, want %s", got, want)
	}
	if got := NewFileStore("").dir; got != filepath.Join(tmp, "keys") {
		t.Fatalf("NewFileStore(\"\").dir = %s, want it under DFOS_CONFIG", got)
	}
}

func TestDefaultKeyDirIsHomeWithoutDFOSCONFIG(t *testing.T) {
	// The default is unchanged: only the DFOS_CONFIG case moves.
	t.Setenv("DFOS_CONFIG", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory in this environment: %v", err)
	}
	if got, want := defaultKeyDir(), filepath.Join(home, ".dfos", "keys"); got != want {
		t.Fatalf("defaultKeyDir() = %s, want %s", got, want)
	}
}

func TestFileStoreWritesInsideTheIsolatedConfigDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("DFOS_CONFIG", filepath.Join(tmp, "config.toml"))

	store := NewFileStore("")
	const account = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar#key_8fh3n2"
	priv, pub, err := store.GenerateKey(account)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(tmp, "keys"))
	if err != nil {
		t.Fatalf("the key did not land under DFOS_CONFIG: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("keys dir holds %d entries, want 1", len(entries))
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}

	back, err := store.GetPrivateKey(account)
	if err != nil {
		t.Fatalf("GetPrivateKey: %v", err)
	}
	if !back.Equal(priv) {
		t.Error("stored key does not round-trip")
	}
	if !back.Public().(ed25519.PublicKey).Equal(pub) {
		t.Error("round-tripped key has a different public half")
	}
}

// PutKey is how a vault-derived key reaches the keystore: the key is created
// from a seed elsewhere, and the keystore stays the one place private material
// lives, so every downstream signing path is identical.
func TestPutKeyStoresDerivedMaterial(t *testing.T) {
	stores := map[string]Store{
		"file":   NewFileStore(t.TempDir()),
		"memory": NewMemoryStore(),
	}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			seed := make([]byte, ed25519.SeedSize)
			for i := range seed {
				seed[i] = byte(i)
			}
			priv := ed25519.NewKeyFromSeed(seed)

			const account = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar#key_derived"
			pub, err := store.PutKey(account, priv)
			if err != nil {
				t.Fatalf("PutKey: %v", err)
			}
			if !pub.Equal(priv.Public().(ed25519.PublicKey)) {
				t.Error("PutKey returned a public key that is not the private key's own")
			}
			if !store.HasKey(account) {
				t.Fatal("HasKey says a just-stored key is absent")
			}
			back, err := store.GetPrivateKey(account)
			if err != nil {
				t.Fatalf("GetPrivateKey: %v", err)
			}
			if !back.Equal(priv) {
				t.Error("the key read back is not the key that was put")
			}

			if _, err := store.PutKey(account, ed25519.PrivateKey("too short")); err == nil {
				t.Error("PutKey accepted something that is not an ed25519 private key")
			}
		})
	}
}
