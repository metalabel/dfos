package protocol

import (
	"fmt"

	"github.com/mr-tron/base58"
)

// EncodeMultikey encodes an Ed25519 public key as a Multikey multibase string.
// Format: "z" + base58btc(0xed 0x01 || pubkey)
func EncodeMultikey(pub []byte) string {
	raw := append([]byte{0xed, 0x01}, pub...)
	return "z" + base58.Encode(raw)
}

// DecodeMultikey decodes a Multikey multibase string to raw Ed25519 public key bytes.
func DecodeMultikey(multibase string) ([]byte, error) {
	if len(multibase) == 0 || multibase[0] != 'z' {
		return nil, fmt.Errorf("expected base58btc prefix 'z'")
	}
	raw, err := base58.Decode(multibase[1:])
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}
	if len(raw) < 2 || raw[0] != 0xed || raw[1] != 0x01 {
		return nil, fmt.Errorf("expected ed25519-pub multicodec prefix (0xed01)")
	}
	return raw[2:], nil
}
