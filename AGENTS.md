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

Every PR touching `specs/*.md` MUST do exactly one of:

1. **Sync the derivatives** — update `specs/THREAT-MODEL.md` and
   `specs/CONFORMANCE.md` (and any other derivative surface named by
   CONTRIBUTING.md item 7 that the change reaches: WEB-RELAY.md's route/auth
   quick-start table, the OpenAPI document), or
2. **State the waiver** — include one explicit sentence in the PR body saying
   why the change has no derivative impact, e.g. _"No derivative impact:
   editorial clarification only — no new MUST surface, no new residual risk."_

The waiver sentence is the mechanism: it converts a silent omission into a
challengeable claim a reviewer can see and contest. A spec PR with neither the
sync nor the sentence is incomplete — do not merge it.
