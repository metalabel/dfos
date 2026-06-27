package dfos

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"regexp"
)

const (
	idAlphabet = "2346789acdefhknrtvz"
	// 31 chars over the 19-symbol alphabet ≈ 2^131.6 targeted second-preimage —
	// above the 128-bit floor for this registry-free self-certifying identifier.
	idLength = 31
)

// didRe matches a well-formed did:dfos identifier: the method prefix followed by
// exactly idLength characters of the protocol alphabet. The protocol has a single
// identifier width — any other length or character set is not a DID.
var didRe = regexp.MustCompile(fmt.Sprintf(`^did:dfos:[%s]{%d}$`, idAlphabet, idLength))

// ValidateDID returns an error if did is not a well-formed did:dfos identifier.
func ValidateDID(did string) error {
	if !didRe.MatchString(did) {
		return fmt.Errorf("malformed did:dfos identifier: %q", did)
	}
	return nil
}

// IsValidDID reports whether did is a well-formed did:dfos identifier.
func IsValidDID(did string) bool {
	return didRe.MatchString(did)
}

// DeriveID derives a 31-char identifier from raw bytes using sha256 + modular alphabet encoding.
func DeriveID(seed []byte) string {
	hash := sha256.Sum256(seed)
	result := make([]byte, idLength)
	for i := 0; i < idLength; i++ {
		result[i] = idAlphabet[hash[i]%19]
	}
	return string(result)
}

// DeriveDID derives a did:dfos DID from CID bytes.
func DeriveDID(cidBytes []byte) string {
	return "did:dfos:" + DeriveID(cidBytes)
}

// DeriveContentID derives a bare content ID from CID bytes.
func DeriveContentID(cidBytes []byte) string {
	return DeriveID(cidBytes)
}

// GenerateKeyID generates a random key_xxxx identifier.
func GenerateKeyID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "key_" + DeriveID(b)
}
