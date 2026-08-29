package keystore

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
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

// TestGetPrivateKeyRefusesATruncatedEntry: ed25519.NewKeyFromSeed PANICS on
// anything but 32 bytes, and every read path fed it whatever the backend held.
// A key file a crash truncated, or a keychain entry someone edited, took the
// whole CLI down with a stack trace instead of naming the bad entry.
//
// The mint-time calls are not covered here and do not need to be: they feed it
// rand.Read output and cannot be short.
func TestGetPrivateKeyRefusesATruncatedEntry(t *testing.T) {
	const account = "key:z6MkTruncated"

	// Half a seed, a seed with a byte appended, and an entry that decodes to
	// nothing. All three are "something is there and it is not a key".
	for _, tc := range []struct {
		name    string
		seedHex string
		wantLen string
	}{
		{"half a seed", "0102030405060708090a0b0c0d0e0f10", "16"},
		{"one byte over", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "33"},
		{"empty", "", "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file := NewFileStore(dir)
			if err := os.WriteFile(filepath.Join(dir, fileName(account)), []byte(tc.seedHex), 0o600); err != nil {
				t.Fatalf("write truncated key file: %v", err)
			}

			mem := NewMemoryStore()
			mem.keys[account] = tc.seedHex

			for backend, store := range map[string]Store{"file": file, "memory": mem} {
				// HasKey still says yes: something IS filed there. The error has to
				// come from the read, which is the only thing that sees the bytes.
				if !store.HasKey(account) {
					t.Fatalf("%s: HasKey should still find the entry", backend)
				}
				priv, err := store.GetPrivateKey(account)
				if err == nil {
					t.Fatalf("%s: GetPrivateKey accepted a %s-byte seed and returned %d bytes", backend, tc.wantLen, len(priv))
				}
				for _, want := range []string{account, tc.wantLen} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: the error must name %q: %v", backend, want, err)
					}
				}
			}
		})
	}
}
