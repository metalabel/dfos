# Security Policy

DFOS is a cryptographic protocol: Ed25519-signed identity and content chains,
JWS operations, verifiable credentials, and verifying relays. A defect in the
signing, encoding, or verification path can compromise the integrity guarantees
the protocol exists to provide. We take such reports seriously and ask
researchers to disclose them responsibly.

## Supported versions

DFOS is pre-1.0 and ships in lockstep across all published packages (the npm
`@metalabel/*` packages and the Go modules share a single version). Security
fixes are made against the latest released minor only. We do not backport to
older minors before 1.0.

| Version | Supported |
| ------- | --------- |
| 0.9.x   | Yes       |
| < 0.9   | No        |

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
report.** Public disclosure of an unpatched defect in the cryptographic path
puts every relay and identity at risk.

Report privately through one of:

1. **GitHub private vulnerability reporting** (preferred) — use the
   **Report a vulnerability** button under the **Security** tab of
   <https://github.com/metalabel/dfos>. This opens a private advisory thread
   visible only to you and the maintainers.
2. **Email** — <security@metalabel.com> with the subject line
   `DFOS SECURITY`. Encrypt with our PGP key on request.

Please include:

- The affected package(s) and version(s) or commit SHA.
- A description of the vulnerability and its impact (e.g. signature forgery,
  verification bypass, chain-fork acceptance, key disclosure, DoS).
- Reproduction steps, a proof-of-concept, or a failing test vector if you have
  one. For protocol-level issues, a deterministic test vector is the gold
  standard.

## What to expect

- **Acknowledgement** within 3 business days.
- **Triage and initial assessment** within 10 business days, including a
  severity rating and whether we accept the report.
- **Coordinated disclosure.** We will agree on a disclosure timeline with you,
  publish a fix and advisory, and credit you (unless you prefer to remain
  anonymous). Our default embargo target is 90 days from acknowledgement, sooner
  if a fix ships earlier.

## Scope

In scope: anything that breaks the protocol's integrity, authenticity, or
authorization guarantees — signing, JWS construction/verification, DAG-CBOR
canonical encoding, CID derivation, chain state-machine transitions, credential
verification, relay authentication and authorization, and the cross-language
verification vectors.

Out of scope: vulnerabilities in third-party dependencies (report those
upstream, though we welcome a heads-up), and issues that require a compromised
host or a user's own private keys.

For the consolidated adversary model and trust-boundary reference — adversary
classes, the trustless proof plane vs. honest-host content plane split, and the
explicitly-accepted v1 residual risks — see
[specs/THREAT-MODEL.md](specs/THREAT-MODEL.md).

## Safe harbor

We will not pursue or support legal action against researchers who act in good
faith, follow this policy, avoid privacy violations and service degradation, and
give us a reasonable window to remediate before public disclosure.
