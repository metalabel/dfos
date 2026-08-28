# Agent canon — metalabel/dfos

Rules that agents (and humans) authoring PRs in this repo enforce on themselves.
Build/verify commands and the extension-family checklist live in
[`CONTRIBUTING.md`](CONTRIBUTING.md); this file holds the hard rules that have
been silently skipped before and are therefore written down.

## Derivative-docs rule (any PR touching `specs/*.md`)

The specs are a corpus, not a pile of files: `specs/THREAT-MODEL.md` and
`specs/CONFORMANCE.md` are **derivative documents** that restate the other
specs' security posture and MUST surfaces. A spec change that leaves them stale
is a spec change that lies by omission.

Every PR touching `specs/*.md` MUST, for **each** derivative surface —
`specs/THREAT-MODEL.md`, `specs/CONFORMANCE.md`, and any other derivative
surface named by CONTRIBUTING.md item 7 that the change reaches (WEB-RELAY.md's
route/auth quick-start table, the OpenAPI document) — do one of:

1. **Sync it** — update that derivative in the same PR, or
2. **State the waiver** — include one explicit sentence in the PR body saying
   why that surface is unaffected. When no derivative is affected, a single
   blanket sentence covers them all, e.g. _"No derivative impact: editorial
   clarification only — no new MUST surface, no new residual risk."_ Partial
   impact takes the split form: sync the affected docs, waive the rest by name.

The waiver sentence is the mechanism: it converts a silent omission into a
challengeable claim a reviewer can see and contest. A spec PR with neither the
sync nor the sentence is incomplete — do not merge it.

## Register rule (any prose served on protocol.dfos.com)

The published corpus speaks in the **present tense about what is**. Progression
language never lands in it: no "planned", "upcoming", "for now", "eventually",
"not yet built", "will ship", no roadmap voice, and no reference to an unbuilt
feature as forthcoming. A capability either is specified — write it as it
stands, with its status block naming its clock — or it is absent, and absence
is stated as a present fact ("X is not defined", a deferred-list bullet),
never as a promise.

**Scope is the served surface, not the directory.** A page published at
protocol.dfos.com is read as the project speaking, whatever path its file
happens to live at. Mechanically that is: every `source` in the site registry
(`packages/site-protocol/src/content/specs.ts` — today `specs/*.md` and
`packages/dfos-cli/CLI.md`), the markdown a page reads directly
(`deploy/QUICKSTART.md` at `/deploy`, `skills/dfos/SKILL.md` at `/skill`), and
the site's own prose in `packages/site-protocol/src/content/` and `src/pages/`.
A package README that the site does not serve is a dev doc, where present-tense
absence is preferred but not required.

Two futures are exempt because they are not roadmap:

1. **Versioning discipline.** Status-block clock rules ("a break becomes v1.1
   or v2", "the five-language sweep is a freeze requirement", "when the family
   exits `0.x` it re-mounts at `/v1`") state the change contract, not a plan.
2. **Technical semantics.** Temporal mechanics ("a timestamp in the future",
   "eventually consistent", "authorized-but-not-yet-materialized", "the DID
   does not yet exist" mid-algorithm) are the subject matter, not iteration.

The test: would the sentence be false if the project stopped shipping
tomorrow? A rule or mechanism stays true; a promise goes stale. Promises don't
belong in the corpus.
