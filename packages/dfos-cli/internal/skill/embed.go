package skill

import _ "embed"

// Markdown is the canonical DFOS Claude Code skill (SKILL.md), embedded at build
// time so `dfos skill` always emits the skill that matches this binary's version.
//
// It is kept byte-identical to the canonical source at /skills/dfos/SKILL.md by
// scripts/sync-skill.sh and guarded by embed_test.go. Edit the canonical file,
// then run `./scripts/sync-skill.sh` — never edit this copy directly.
//
//go:embed SKILL.md
var Markdown string
