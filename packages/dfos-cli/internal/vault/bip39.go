package vault

// BIP-39 mnemonics, implemented against the canonical English wordlist embedded
// verbatim from the BIP repository (its SHA-256 is asserted in bip39_test.go, so
// a corrupted or substituted list fails the build's tests rather than silently
// producing mnemonics nothing else can read).
//
// Minting is 24 words and only 24 words: the shorter lengths are legal BIP-39
// and are accepted on import so a mnemonic written by another wallet still
// works, but there is no reason to hand an operator a weaker default. There is
// no passphrase — no 25th word — so a mnemonic maps to exactly one seed and
// there is no second secret to lose without knowing you had it.

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"sync"
)

//go:embed english.txt
var englishWordlist string

var (
	wordsOnce sync.Once
	words     []string
	wordIndex map[string]int
)

func loadWords() {
	wordsOnce.Do(func() {
		words = strings.Fields(englishWordlist)
		wordIndex = make(map[string]int, len(words))
		for i, w := range words {
			wordIndex[w] = i
		}
	})
}

// ErrChecksum is the BIP-39 checksum failure, which in practice means a typo or
// a transposed word rather than anything exotic.
var ErrChecksum = errors.New("mnemonic checksum is invalid — a word is mistyped, missing, or out of order")

// NewMnemonic generates a fresh 24-word mnemonic from 256 bits of crypto/rand
// entropy.
func NewMnemonic() (string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("read entropy: %w", err)
	}
	return mnemonicFromEntropy(entropy)
}

// mnemonicFromEntropy encodes entropy||checksum as 11-bit wordlist indices.
func mnemonicFromEntropy(entropy []byte) (string, error) {
	loadWords()
	bits := len(entropy) * 8
	if bits < 128 || bits > 256 || bits%32 != 0 {
		return "", fmt.Errorf("entropy must be 128–256 bits in 32-bit steps, got %d", bits)
	}
	checksumBits := bits / 32
	sum := sha256.Sum256(entropy)

	// At most 8 checksum bits are ever consumed (256/32), so one digest byte
	// appended to the entropy holds the whole bit string being chunked.
	data := make([]byte, 0, len(entropy)+1)
	data = append(data, entropy...)
	data = append(data, sum[0])

	out := make([]string, 0, (bits+checksumBits)/11)
	for i := 0; i < bits+checksumBits; i += 11 {
		idx := 0
		for j := 0; j < 11; j++ {
			bit := i + j
			idx = idx<<1 | int((data[bit/8]>>(7-uint(bit%8)))&1)
		}
		out = append(out, words[idx])
	}
	return strings.Join(out, " "), nil
}

// NormalizeMnemonic validates a mnemonic and returns it in the one spelling this
// CLI stores: lowercase words joined by single spaces. Storing the normalized
// form means the fingerprint of an imported vault does not depend on how the
// operator happened to paste it.
func NormalizeMnemonic(mnemonic string) (string, error) {
	parts, _, err := decodeMnemonic(mnemonic)
	if err != nil {
		return "", err
	}
	return strings.Join(parts, " "), nil
}

// ValidateMnemonic reports whether a mnemonic is well-formed English BIP-39 with
// a correct checksum.
func ValidateMnemonic(mnemonic string) error {
	_, _, err := decodeMnemonic(mnemonic)
	return err
}

// decodeMnemonic returns the normalized words and the entropy they encode,
// rejecting unknown words and checksum failures.
func decodeMnemonic(mnemonic string) ([]string, []byte, error) {
	loadWords()
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(mnemonic)))
	switch len(parts) {
	case 12, 15, 18, 21, 24:
	default:
		return nil, nil, fmt.Errorf("a mnemonic is 12, 15, 18, 21, or 24 words; got %d", len(parts))
	}

	total := len(parts) * 11
	bits := total * 32 / 33
	checksumBits := total - bits

	data := make([]byte, (total+7)/8)
	pos := 0
	for _, w := range parts {
		idx, ok := wordIndex[w]
		if !ok {
			return nil, nil, fmt.Errorf("not a word in the BIP-39 English list: %q", w)
		}
		for j := 10; j >= 0; j-- {
			if (idx>>uint(j))&1 == 1 {
				data[pos/8] |= 1 << (7 - uint(pos%8))
			}
			pos++
		}
	}

	entropy := data[:bits/8]
	sum := sha256.Sum256(entropy)
	for i := 0; i < checksumBits; i++ {
		bit := bits + i
		want := (sum[0] >> (7 - uint(i))) & 1
		got := (data[bit/8] >> (7 - uint(bit%8))) & 1
		if want != got {
			return nil, nil, ErrChecksum
		}
	}
	return parts, entropy, nil
}

// MnemonicSeed derives the 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512, 2048
// iterations, salt "mnemonic" — no passphrase).
func MnemonicSeed(mnemonic string) ([]byte, error) {
	normalized, err := NormalizeMnemonic(mnemonic)
	if err != nil {
		return nil, err
	}
	return seedWithPassphrase(normalized, "")
}

// seedWithPassphrase is the full BIP-39 stretch. The passphrase parameter exists
// so the tests can check this against the official vectors, which are published
// with the passphrase "TREZOR"; nothing in the CLI passes anything but "".
func seedWithPassphrase(normalizedMnemonic, passphrase string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, normalizedMnemonic, []byte("mnemonic"+passphrase), 2048, 64)
}
