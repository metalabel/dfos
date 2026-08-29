package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// englishWordlistDigest is the SHA-256 of the canonical BIP-39 English wordlist
// as published in the bitcoin/bips repository. A substituted or truncated list
// would still produce plausible-looking mnemonics that no other wallet can read,
// so the list itself is pinned rather than trusted.
const englishWordlistDigest = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

func TestEmbeddedWordlistIsCanonical(t *testing.T) {
	sum := sha256.Sum256([]byte(englishWordlist))
	if got := hex.EncodeToString(sum[:]); got != englishWordlistDigest {
		t.Fatalf("embedded wordlist digest = %s, want %s", got, englishWordlistDigest)
	}
	loadWords()
	if len(words) != 2048 {
		t.Fatalf("wordlist has %d words, want 2048", len(words))
	}
}

// The official BIP-39 English test vectors (a representative slice of the
// published set), which pin entropy → mnemonic → seed end to end. The published
// seeds use the passphrase "TREZOR"; the CLI itself always passes "".
func TestBIP39Vectors(t *testing.T) {
	tests := []struct {
		entropy  string
		mnemonic string
		seed     string // with passphrase "TREZOR", as published
	}{
		{
			entropy:  "00000000000000000000000000000000",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			seed:     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		},
		{
			entropy:  "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
			seed:     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		},
		{
			entropy:  "0000000000000000000000000000000000000000000000000000000000000000",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
			seed:     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
		},
		{
			entropy:  "8080808080808080808080808080808080808080808080808080808080808080",
			mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
			seed:     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
		},
	}

	for _, tt := range tests {
		entropy, err := hex.DecodeString(tt.entropy)
		if err != nil {
			t.Fatalf("decode entropy: %v", err)
		}
		got, err := mnemonicFromEntropy(entropy)
		if err != nil {
			t.Fatalf("mnemonicFromEntropy(%s): %v", tt.entropy, err)
		}
		if got != tt.mnemonic {
			t.Errorf("mnemonic for %s =\n  %s\nwant\n  %s", tt.entropy, got, tt.mnemonic)
			continue
		}
		if err := ValidateMnemonic(got); err != nil {
			t.Errorf("generated mnemonic failed its own validation: %v", err)
		}
		seed, err := seedWithPassphrase(got, "TREZOR")
		if err != nil {
			t.Fatalf("seedWithPassphrase: %v", err)
		}
		if hex.EncodeToString(seed) != tt.seed {
			t.Errorf("seed for %s =\n  %s\nwant\n  %s", tt.entropy, hex.EncodeToString(seed), tt.seed)
		}
	}
}

func TestMnemonicSeedUsesNoPassphrase(t *testing.T) {
	// The all-zero 12-word mnemonic with an EMPTY passphrase — the seed the CLI
	// actually derives, and the one every recovery of a dfos vault depends on.
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	const want = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed, err := MnemonicSeed(mnemonic)
	if err != nil {
		t.Fatalf("MnemonicSeed: %v", err)
	}
	if got := hex.EncodeToString(seed); got != want {
		t.Fatalf("seed =\n  %s\nwant\n  %s", got, want)
	}
}

func TestNewMnemonicIsTwentyFourValidWords(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		m, err := NewMnemonic()
		if err != nil {
			t.Fatalf("NewMnemonic: %v", err)
		}
		if n := len(strings.Fields(m)); n != 24 {
			t.Fatalf("NewMnemonic produced %d words, want 24", n)
		}
		if err := ValidateMnemonic(m); err != nil {
			t.Fatalf("NewMnemonic produced an invalid mnemonic: %v", err)
		}
		if seen[m] {
			t.Fatal("NewMnemonic repeated itself — entropy is not what it claims")
		}
		seen[m] = true
	}
}

func TestValidateMnemonicRejections(t *testing.T) {
	valid := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	tests := []struct {
		name      string
		mnemonic  string
		wantErrIs error
	}{
		{
			name: "a transposed word breaks the checksum",
			// Same words, last two swapped: every word is in the list, the
			// checksum is not.
			mnemonic:  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon",
			wantErrIs: ErrChecksum,
		},
		{
			name:      "a wrong final word breaks the checksum",
			mnemonic:  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
			wantErrIs: ErrChecksum,
		},
		{
			name:     "a word outside the list is refused",
			mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon vault",
		},
		{
			name:     "a non-standard length is refused",
			mnemonic: "abandon abandon abandon",
		},
		{
			name:     "empty is refused",
			mnemonic: "",
		},
	}

	if err := ValidateMnemonic(valid); err != nil {
		t.Fatalf("the control mnemonic did not validate: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMnemonic(tt.mnemonic)
			if err == nil {
				t.Fatal("expected a rejection, got nil")
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("error = %v, want %v", err, tt.wantErrIs)
			}
		})
	}
}

func TestNormalizeMnemonicFoldsWhitespaceAndCase(t *testing.T) {
	messy := "  ABANDON\tabandon abandon abandon  abandon abandon abandon abandon abandon abandon abandon\nAbout  "
	want := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	got, err := NormalizeMnemonic(messy)
	if err != nil {
		t.Fatalf("NormalizeMnemonic: %v", err)
	}
	if got != want {
		t.Fatalf("NormalizeMnemonic = %q, want %q", got, want)
	}

	// Normalization is what makes an imported vault's fingerprint independent of
	// how the operator happened to paste the words.
	a, err := MnemonicSeed(messy)
	if err != nil {
		t.Fatalf("MnemonicSeed(messy): %v", err)
	}
	b, err := MnemonicSeed(want)
	if err != nil {
		t.Fatalf("MnemonicSeed(clean): %v", err)
	}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("whitespace changed the fingerprint")
	}
}
