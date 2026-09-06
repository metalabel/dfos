package dfos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Shared reference vectors.
//
// packages/protocol-verify/vectors.json is the one artifact the five standalone
// verification suites and this twin's reference tests read their expected values
// from. It is generated from the protocol's fixed seeds by
// packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
// checked-in file is byte-identical to a fresh generation — so an expected value
// asserted here cannot drift away from the TypeScript reference without CI
// noticing.
//
// Only test files read it: nothing in the published module depends on a path
// outside its own module.

var loadVectorsOnce = sync.OnceValue(func() map[string]map[string]any {
	path := filepath.Join("..", "protocol-verify", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read %s: %v", path, err))
	}
	var file struct {
		Vectors []struct {
			ID     string         `json:"id"`
			Values map[string]any `json:"values"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		panic(fmt.Sprintf("parse %s: %v", path, err))
	}
	byID := make(map[string]map[string]any, len(file.Vectors))
	for _, v := range file.Vectors {
		byID[v.ID] = v.Values
	}
	return byID
})

// vec returns one string field of one shared vector.
func vec(id, field string) string {
	values, ok := loadVectorsOnce()[id]
	if !ok {
		panic(fmt.Sprintf("vectors.json has no vector %q", id))
	}
	value, ok := values[field]
	if !ok {
		panic(fmt.Sprintf("vectors.json %s has no field %s", id, field))
	}
	s, ok := value.(string)
	if !ok {
		panic(fmt.Sprintf("vectors.json %s.%s is not a string", id, field))
	}
	return s
}
