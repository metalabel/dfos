package skill

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEmbeddedSkillMatchesCanonical ensures the embedded SKILL.md stays
// byte-identical to the canonical source at /skills/dfos/SKILL.md. After editing
// the canonical file, run ./scripts/sync-skill.sh. The test skips when run outside
// the repo tree (e.g. from the module cache), where the canonical file is absent.
func TestEmbeddedSkillMatchesCanonical(t *testing.T) {
	canonical := filepath.Join("..", "..", "..", "..", "skills", "dfos", "SKILL.md")
	want, err := os.ReadFile(canonical)
	if err != nil {
		t.Skipf("canonical skill not found (%v) — skipping drift check outside repo tree", err)
	}
	if string(want) != Markdown {
		t.Fatalf("embedded SKILL.md is out of sync with %s; run ./scripts/sync-skill.sh", canonical)
	}
}

// TestEmbeddedSkillHasFrontmatter is a cheap sanity check that the embedded skill
// is present and carries the YAML frontmatter Claude Code requires.
func TestEmbeddedSkillHasFrontmatter(t *testing.T) {
	if len(Markdown) == 0 {
		t.Fatal("embedded skill is empty")
	}
	if got := Markdown[:4]; got != "---\n" {
		t.Fatalf("embedded skill must start with YAML frontmatter (---), got %q", got)
	}
}
