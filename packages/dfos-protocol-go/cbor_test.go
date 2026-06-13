package dfos

import (
	"math"
	"testing"
)

// TestAssertCanonicalNumbers covers the WP-0 number policy: integers in
// ±(2^53-1) are accepted; non-integers, NaN, ±Inf, and out-of-range integers
// are rejected so dag-cbor encoding stays byte-identical across languages.
func TestAssertCanonicalNumbers(t *testing.T) {
	valid := []any{
		map[string]any{"version": float64(1), "n": float64(maxSafeInteger)},
		map[string]any{"neg": float64(-maxSafeInteger)},
		map[string]any{"nested": []any{float64(0), float64(42)}},
		map[string]any{"str": "1.5", "b": true, "nul": nil},
		int64(123),
	}
	for i, v := range valid {
		if err := AssertCanonicalNumbers(v); err != nil {
			t.Errorf("valid[%d]: unexpected error %v", i, err)
		}
	}

	invalid := []any{
		map[string]any{"frac": float64(1.5)},
		map[string]any{"nan": math.NaN()},
		map[string]any{"inf": math.Inf(1)},
		map[string]any{"big": float64(maxSafeInteger + 1)},
		map[string]any{"bigneg": float64(-maxSafeInteger - 1)},
		map[string]any{"nested": []any{map[string]any{"x": float64(0.1)}}},
		int64(maxSafeInteger + 1),
	}
	for i, v := range invalid {
		if err := AssertCanonicalNumbers(v); err == nil {
			t.Errorf("invalid[%d]: expected rejection, got nil", i)
		}
	}
}

func TestDagCborEncodeRejectsNonCanonicalNumbers(t *testing.T) {
	if _, err := DagCborEncode(map[string]any{"x": 1.5}); err == nil {
		t.Error("DagCborEncode should reject a fractional number")
	}
	if _, err := DagCborEncode(map[string]any{"x": float64(1)}); err != nil {
		t.Errorf("DagCborEncode should accept a whole number: %v", err)
	}
}
