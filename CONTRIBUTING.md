# Contributing

This repo is the canonical source for the DFOS protocol specs (`specs/`) and the
published packages (`@metalabel/dfos-protocol`, `@metalabel/dfos-web-relay`,
`@metalabel/dfos-client`, the Go twins, and the verification/conformance corpora). The corpus
iterates in place and carries the version of the release it ships with: one corpus version, one
package version. Wire-visible surfaces (the `/proof/v1` relay plane, the v1 credential machinery)
change by clarification in place or additive capability beside them; a break moves the path.

## Build & verify

- `pnpm build` — tsup bundles each subpath entrypoint (ESM + declarations)
- `pnpm typecheck` / `pnpm test` — strict tsc on the TypeScript 7 native compiler
  (`typescript7`, invoked by path so it never shadows the `typescript` that tsup emits
  with); protocol + relay vitest suites
- `pnpm lint && pnpm lint:specs` — prettier + spec lint
- `pnpm lint:anchors` — every `protocol.dfos.com` link resolves to a page and, when
  it carries a fragment, to a heading that page actually renders
- `packages/protocol-verify/` — five-language standalone vector verification
- `packages/relay-conformance/` — Go integration suite against any live relay

If a change touches `PROTOCOL.md`, run the protocol-reference test
(`tests/protocol-reference.spec.ts`) and the cross-language verification suites — a
vector change must land in all languages together.

## Adding an envelope family or relay route family

Every extension family that has landed (credits, index, revocations, signing) pays the
same registration tax. Work through this list before review — it is the difference
between a family that reads as part of the corpus and one that reads as bolted on:

1. **Clock in the path.** A `0.x` route family mounts at `v0`
   (`/index/v0`, `/signing/v0`); `v1` in a path is a stability declaration
   (`/proof/v1`, `/revocations/v1`). The owning spec and the path must agree.
2. **Register the name.** A new JWS envelope adds its row — `typ`, owner spec,
   `cid`-header carriage, one-sentence semantics — to the extension registry
   ([`specs/PROTOCOL.md` → Extension registry](specs/PROTOCOL.md#extension-registry)),
   even when relays never ingest
   it (the credit-claim precedent — registered for typ-routing, no ingestion
   path). A new service type does the same in the registry's service-type table.
   Names are never minted locally: the owner spec defines, the registry indexes.
3. **One pagination envelope.** List routes use `limit` (default 100, max 1000,
   clamp above max) + `after` + `next`, keyset where the cursor is the sort key,
   opaque tokens where the key is composite, and the relay-local/400 rule where the
   order is positional
   ([RELAY.md → Pagination envelope](specs/RELAY.md#pagination-envelope)). No new shapes.
4. **Capability discipline.** Optional families are gated by a `capabilities.<name>`
   flag; absent reads `false` only for opt-in families; unsupported routes return
   **501, never 404**, with the gate firing before auth, body parsing, or store
   lookups
   ([RELAY.md → The well-known document](specs/RELAY.md#the-well-known-document)).
5. **Uniform error body.** `{ "error": "<prose>" }`; callers branch on status codes.
   Exceptions require their own contract (the DIF resolver envelope is the only one)
   ([RELAY.md → Error body](specs/RELAY.md#error-body)).
6. **Verdicts, not prose.** Verification failures split structurally into
   `invalid` vs `unverifiable` (typed reason / `errors.Is` sentinels) — never
   string-matched messages
   ([CONTENT-MODEL.md → Verification states](specs/CONTENT-MODEL.md#verification-states)
   is the model).
7. **Sync the derivative docs.** GUARANTEES.md (any new residual risk, accepted
   bound, or adversary the family reaches), RELAY.md's full route surface table,
   and the OpenAPI document — including its 501 responses. Enforcement for every
   spec PR (not just new families): see the derivative-docs rule in
   [`AGENTS.md`](AGENTS.md) — sync these docs or state in the PR body why there is
   no derivative impact.
8. **Vectors are the spec's teeth.** Ship deterministic reference vectors with the
   reference implementations; adversarial vectors for any byte-contract (the WYSIWYS
   canonicalization set is the model). A vector change lands in all five languages
   together.

## Releases

Releases are cut from `main` via `./scripts/release.sh <version>` (maintainers). The
`v*` tag publishes npm packages with provenance, the Go CLI, the Docker image, and
deploys protocol.dfos.com.
