# Contributing

This repo is the canonical source for the DFOS protocol specs (`specs/`) and the
published packages (`@metalabel/dfos-protocol`, `@metalabel/dfos-web-relay`,
`@metalabel/dfos-client`, the Go twins, and the verification/conformance corpora). The frozen surfaces — Protocol v1,
the `/proof/v1` relay plane, the v1 credential machinery — change only by the rules in
each spec's own status block: clarifications in place, additive capability beside them,
breaks become a new major.

## Build & verify

- `pnpm build` — tsup bundles each subpath entrypoint (ESM + declarations)
- `pnpm typecheck` / `pnpm test` — strict tsc; protocol + relay vitest suites
- `pnpm lint && pnpm lint:specs` — prettier + spec lint
- `packages/protocol-verify/` — five-language standalone vector verification
- `packages/relay-conformance/` — Go integration suite against any live relay

If a change touches `PROTOCOL.md`, run the protocol-reference test
(`tests/protocol-reference.spec.ts`) and the cross-language verification suites — a
vector change must land in all languages together.

## Adding an envelope family or relay route family

Every extension family that has landed (credits, index, revocations, signing) pays the
same registration tax. Work through this list before review — it is the difference
between a family that reads as part of the corpus and one that reads as bolted on:

1. **Clock in the path.** An unfrozen (`0.x`) route family mounts at `v0`
   (`/index/v0`, `/signing/v0`); `v1` in a path is a freeze declaration
   (`/proof/v1`, `/revocations/v1`). The spec's status block and the path must agree.
2. **Register the `typ`.** A new JWS envelope adds its row to PROTOCOL.md's `typ`
   registry and to the `cid`-header inventory, even when relays never ingest it
   (the credit-claim precedent — registered for typ-routing, no ingestion path).
3. **One pagination envelope.** List routes use `limit` (default 100, max 1000,
   clamp above max) + `after` + `next`, keyset where the cursor is the sort key,
   opaque tokens where the key is composite, and the relay-local/400 rule where the
   order is positional
   ([WEB-RELAY.md → Error Responses](specs/WEB-RELAY.md#error-responses)). No new shapes.
4. **Capability discipline.** Optional families are gated by a `capabilities.<name>`
   flag; absent reads `false` only for opt-in families; unsupported routes return
   **501, never 404**, with the gate firing before auth, body parsing, or store
   lookups
   ([WEB-RELAY.md → Well-Known Endpoint](specs/WEB-RELAY.md#well-known-endpoint-get-well-knowndfos-relay)).
5. **Uniform error body.** `{ "error": "<prose>" }`; callers branch on status codes.
   Exceptions require their own contract (the DIF resolver envelope is the only one)
   ([WEB-RELAY.md → Error Responses](specs/WEB-RELAY.md#error-responses)).
6. **Verdicts, not prose.** Verification failures split structurally into
   `invalid` vs `unverifiable` (typed reason / `errors.Is` sentinels) — never
   string-matched messages
   ([CONFORMANCE.md → Conformance Tiers](specs/CONFORMANCE.md#conformance-tiers)).
7. **Sync the derivative docs.** CONFORMANCE.md (doc list + the tier bullets your
   MUST sets belong to), THREAT-MODEL.md (any new residual risk), WEB-RELAY.md's
   route/auth quick-start table, and the OpenAPI document — including its 501
   responses. Enforcement for every spec PR (not just new families): see the
   derivative-docs rule in [`AGENTS.md`](AGENTS.md) — sync these docs or state in
   the PR body why there is no derivative impact.
8. **Vectors are the spec's teeth.** Ship deterministic reference vectors with the
   reference implementations; adversarial vectors for any byte-contract (the WYSIWYS
   canonicalization set is the model). The five-language sweep is required at freeze,
   not at `0.x`.

## Releases

Releases are cut from `main` via `./scripts/release.sh <version>` (maintainers). The
`v*` tag publishes npm packages with provenance, the Go CLI, the Docker image, and
deploys protocol.dfos.com.
