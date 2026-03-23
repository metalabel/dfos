package protocol

import (
	"crypto/rand"
	"crypto/sha256"
)

const (
	idAlphabet = "2346789acdefhknrtvz"
	idLength   = 22
)

// DeriveID derives a 22-char identifier from raw bytes using sha256 + modular alphabet encoding.
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
