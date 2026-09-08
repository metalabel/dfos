package dfos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The api: resource hierarchy, from the SHARED fixture.
//
// packages/dfos-protocol/examples/api-resource-coverage.json is the contract
// between the two twins: every row below is also a test in
// packages/dfos-protocol/tests, so a verdict that differs between TypeScript and
// Go is a failing row here rather than a divergence discovered in production.
// Neither side inlines a row — the file is read, the same way vectors_test.go
// reads the five-language vectors.
//
// The hierarchy is api:-only and TS↔Go only; the Python, Rust, and Swift suites
// implement no attenuation logic, so this file is not part of the five-language
// sweep (see packages/protocol-verify/README.md).

type apiResourceFixture struct {
	Parse []struct {
		Resource string  `json:"resource"`
		Valid    bool    `json:"valid"`
		Host     string  `json:"host"`
		SpaceID  *string `json:"spaceId"`
		Note     string  `json:"note"`
	} `json:"parse"`
	Covers []struct {
		Entry    string `json:"entry"`
		Required string `json:"required"`
		Covers   bool   `json:"covers"`
		Note     string `json:"note"`
	} `json:"covers"`
	Attenuation []struct {
		Note   string     `json:"note"`
		Parent []AttEntry `json:"parent"`
		Child  []AttEntry `json:"child"`
		Valid  bool       `json:"valid"`
	} `json:"attenuation"`
	Matches []struct {
		Note     string     `json:"note"`
		Att      []AttEntry `json:"att"`
		Resource string     `json:"resource"`
		Action   string     `json:"action"`
		Covers   bool       `json:"covers"`
	} `json:"matches"`
}

var loadApiResourceFixtureOnce = sync.OnceValue(func() apiResourceFixture {
	path := filepath.Join("..", "dfos-protocol", "examples", "api-resource-coverage.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("read %s: %v", path, err))
	}
	var fixture apiResourceFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(fmt.Sprintf("parse %s: %v", path, err))
	}
	return fixture
})

// name labels a subtest by the row's own note, falling back to the row itself —
// a failure should say which rule broke, not which array index did.
func fixtureName(note, fallback string) string {
	if note != "" {
		return note
	}
	return fallback
}

func TestApiResourceParseFixture(t *testing.T) {
	rows := loadApiResourceFixtureOnce().Parse
	if len(rows) == 0 {
		t.Fatal("fixture carries no parse rows")
	}
	for _, row := range rows {
		t.Run(fixtureName(row.Note, row.Resource), func(t *testing.T) {
			host, spaceID, ok := ParseApiResource(row.Resource)
			if ok != row.Valid {
				t.Fatalf("ParseApiResource(%q) ok = %v, want %v", row.Resource, ok, row.Valid)
			}
			if !row.Valid {
				return
			}
			if host != row.Host {
				t.Errorf("host = %q, want %q", host, row.Host)
			}
			wantSpace := ""
			if row.SpaceID != nil {
				wantSpace = *row.SpaceID
			}
			if spaceID != wantSpace {
				t.Errorf("spaceId = %q, want %q", spaceID, wantSpace)
			}
		})
	}
}

func TestApiResourceCoversFixture(t *testing.T) {
	rows := loadApiResourceFixtureOnce().Covers
	if len(rows) == 0 {
		t.Fatal("fixture carries no covers rows")
	}
	for _, row := range rows {
		t.Run(fixtureName(row.Note, row.Entry+" → "+row.Required), func(t *testing.T) {
			if got := ApiResourceCovers(row.Entry, row.Required); got != row.Covers {
				t.Fatalf("ApiResourceCovers(%q, %q) = %v, want %v",
					row.Entry, row.Required, got, row.Covers)
			}
		})
	}
}

func TestApiResourceAttenuationFixture(t *testing.T) {
	rows := loadApiResourceFixtureOnce().Attenuation
	if len(rows) == 0 {
		t.Fatal("fixture carries no attenuation rows")
	}
	for _, row := range rows {
		t.Run(fixtureName(row.Note, ""), func(t *testing.T) {
			if got := IsAttenuated(row.Parent, row.Child); got != row.Valid {
				t.Fatalf("IsAttenuated(%v, %v) = %v, want %v",
					row.Parent, row.Child, got, row.Valid)
			}
		})
	}
}

func TestApiResourceMatchesFixture(t *testing.T) {
	rows := loadApiResourceFixtureOnce().Matches
	if len(rows) == 0 {
		t.Fatal("fixture carries no matches rows")
	}
	for _, row := range rows {
		t.Run(fixtureName(row.Note, row.Resource+" "+row.Action), func(t *testing.T) {
			if got := MatchesResource(row.Att, row.Resource, row.Action); got != row.Covers {
				t.Fatalf("MatchesResource(%v, %q, %q) = %v, want %v",
					row.Att, row.Resource, row.Action, got, row.Covers)
			}
		})
	}
}

// The hierarchy is api:-only. chain: keeps its wildcard, and every other type
// keeps exact byte equality — a rule this file would otherwise only assert from
// the api: side.
func TestOtherResourceTypesAreUnchangedByTheApiHierarchy(t *testing.T) {
	chainParent := []AttEntry{{Resource: "chain:*", Action: "read"}}
	chainChild := []AttEntry{{Resource: "chain:9ctvrdn9vedda7efetrhcdakfh4cr2k", Action: "read"}}
	if !IsAttenuated(chainParent, chainChild) {
		t.Error("chain:* no longer carries a chain id")
	}
	if !MatchesResource(chainParent, "chain:9ctvrdn9vedda7efetrhcdakfh4cr2k", "read") {
		t.Error("chain:* no longer covers a chain request")
	}
	mailbox := []AttEntry{{Resource: "mailbox:9ctvrdn9vedda7efetrhcdakfh4cr2k", Action: "deposit"}}
	if !MatchesResource(mailbox, "mailbox:9ctvrdn9vedda7efetrhcdakfh4cr2k", "deposit") {
		t.Error("an exact mailbox: match no longer covers")
	}
	if MatchesResource(mailbox, "mailbox:cv7n8vkvr64cctf3294h9k4eanhff8z", "deposit") {
		t.Error("mailbox: covered a different id")
	}
}
