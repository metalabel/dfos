package dfos

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"math"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// maxSafeInteger is 2^53 - 1, the largest integer representable exactly as an
// IEEE-754 double. The canonical number policy bounds integers to ±this so that
// dag-cbor encoding is byte-identical across implementations (no int>2^53 vs
// float64 split, and no shortest-float divergence — fractions are rejected).
const maxSafeInteger = 9007199254740991

// AssertCanonicalNumbers walks v and rejects any number that is not
// canonicalizable under the DFOS policy: NaN, ±Inf, non-integers, and integers
// outside ±(2^53-1). Applications must encode such values as strings. A
// whole, in-range float64 is accepted (it normalizes to int64). This keeps the
// dag-cbor number encoding deterministic and identical across languages.
func AssertCanonicalNumbers(v any) error {
	switch val := v.(type) {
	case map[string]any:
		for _, vv := range val {
			if err := AssertCanonicalNumbers(vv); err != nil {
				return err
			}
		}
	case []any:
		for _, vv := range val {
			if err := AssertCanonicalNumbers(vv); err != nil {
				return err
			}
		}
	case float64:
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("non-finite number is not canonicalizable: %v", val)
		}
		if val != math.Trunc(val) {
			return fmt.Errorf("non-integer number is not canonicalizable: %v (encode it as a string)", val)
		}
		if val > maxSafeInteger || val < -maxSafeInteger {
			return fmt.Errorf("integer out of safe range is not canonicalizable: %v (encode it as a string)", val)
		}
	case int64:
		if val > maxSafeInteger || val < -maxSafeInteger {
			return fmt.Errorf("integer out of safe range is not canonicalizable: %d (encode it as a string)", val)
		}
	case int:
		if int64(val) > maxSafeInteger || int64(val) < -maxSafeInteger {
			return fmt.Errorf("integer out of safe range is not canonicalizable: %d (encode it as a string)", val)
		}
	}
	return nil
}

// NormalizeJSONNumbers recursively converts float64 values that are whole numbers
// to int64 for correct CBOR encoding (JSON decodes all numbers as float64).
func NormalizeJSONNumbers(v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, vv := range val {
			val[k] = NormalizeJSONNumbers(vv)
		}
		return val
	case []any:
		for i, vv := range val {
			val[i] = NormalizeJSONNumbers(vv)
		}
		return val
	case float64:
		if val == float64(int64(val)) {
			return int64(val)
		}
		return val
	default:
		return v
	}
}

// DagCborEncode encodes a value in dag-cbor canonical form.
// Uses CoreDetEncOptions which sorts map keys by length-first then lexicographic.
func DagCborEncode(v any) ([]byte, error) {
	if err := AssertCanonicalNumbers(v); err != nil {
		return nil, err
	}
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor enc mode: %w", err)
	}
	b, err := em.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cbor marshal: %w", err)
	}
	return b, nil
}

// MakeCIDBytes derives a CIDv1 (dag-cbor + sha-256) from CBOR-encoded bytes.
// Returns the raw CID bytes: 0x01 0x71 0x12 0x20 || sha256(cborBytes)
func MakeCIDBytes(cborBytes []byte) []byte {
	digest := sha256.Sum256(cborBytes)
	cid := []byte{0x01, 0x71, 0x12, 0x20}
	return append(cid, digest[:]...)
}

// CIDToBase32 encodes raw CID bytes to base32lower multibase string.
func CIDToBase32(cidBytes []byte) string {
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cidBytes)
	return "b" + strings.ToLower(encoded)
}

// DagCborCID encodes a value to dag-cbor and returns (cborBytes, cidBytes, cidString, error).
// Automatically normalizes JSON number types (float64 → int64 for whole numbers).
func DagCborCID(v any) (cborBytes []byte, cidBytes []byte, cidStr string, err error) {
	v = NormalizeJSONNumbers(v)
	cborBytes, err = DagCborEncode(v)
	if err != nil {
		return nil, nil, "", err
	}
	cidBytes = MakeCIDBytes(cborBytes)
	cidStr = CIDToBase32(cidBytes)
	return
}
