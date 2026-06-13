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

// TestAssertCanonicalNumbersWideTypeCoverage confirms the widened type coverage
// (uint64/int32/float32/etc.) matches the TS reference: in-range values of any
// Go numeric kind are accepted, and out-of-range / fractional values are
// rejected on every kind rather than slipping through a missing case.
func TestAssertCanonicalNumbersWideTypeCoverage(t *testing.T) {
	valid := []any{
		map[string]any{"u8": uint8(255)},
		map[string]any{"u16": uint16(65535)},
		map[string]any{"u32": uint32(4294967295)},
		map[string]any{"u64": uint64(maxSafeInteger)},
		map[string]any{"i8": int8(-128)},
		map[string]any{"i16": int16(-32768)},
		map[string]any{"i32": int32(-2147483648)},
		map[string]any{"f32": float32(42)},
		map[string]any{"uint": uint(123)},
	}
	for i, v := range valid {
		if err := AssertCanonicalNumbers(v); err != nil {
			t.Errorf("valid[%d]: unexpected error %v", i, err)
		}
	}

	invalid := []any{
		map[string]any{"u64big": uint64(maxSafeInteger + 1)},
		map[string]any{"f32frac": float32(1.5)},
		map[string]any{"nested": []any{map[string]any{"u": uint64(1 << 60)}}},
	}
	for i, v := range invalid {
		if err := AssertCanonicalNumbers(v); err == nil {
			t.Errorf("invalid[%d]: expected rejection, got nil", i)
		}
	}
}
