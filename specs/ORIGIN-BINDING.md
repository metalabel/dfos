# DFOS Origin Binding

A bidirectional, independently verifiable binding between a DFOS identity and a web domain. The identity's chain names the domain — a `DfosOrigin` [services](https://protocol.dfos.com/spec#services) entry, signed by a controller key and ordered by the chain. The domain attests the DID back — a well-known HTTPS document or a DNS TXT record, whichever the operator can serve. Each half alone is a claim anyone could publish; together they prove one party controls both, and any consumer can check the pair with a chain resolution and an HTTPS or DNS lookup — no DFOS server in the loop, no registry, no verification authority.

> **Status — ORIGIN-BINDING 0.1, an optional capability on its own `0.x` clock, independent of the Protocol v1 freeze.** The `DfosOrigin` service type, the attestation formats, and the verification rules below are published for review and early implementation — they are **not part of the frozen protocol surface**, and the frozen protocol never depends on them. Origin binding is additive by construction: the services namespace is [open](https://protocol.dfos.com/spec#services), so a `DfosOrigin` entry rides identity chains today as an opaque extension every conformant verifier already preserves verbatim and ignores — registering the type here requires **no protocol or cross-language change**, exactly as the core promises. Reference tooling ships in the [CLI](https://protocol.dfos.com/cli) (`dfos identity bind-domain`, `dfos identity verify-binding`). Discuss in the [DFOS](https://nce.dfos.com) space.

---

## Motivation

A DID proves continuity — the same key lineage that signed yesterday signs today — but it is unreadable and unmemorable by design. A domain is the opposite: human-legible, already owned, already displayed on every surface the identity's operator cares about, and governed by the web's one decentralized, accountable namespace. Binding the two gives every consumer of a DFOS identity a display name backed by something checkable rather than asserted: **domain control is the credential**, the same doctrine [SIWD](https://protocol.dfos.com/siwd) applies to application registration, where serving a file from the origin _is_ the registration.

The attestation shape deliberately copies the prior art that proved it at web scale — [atproto handle resolution](https://atproto.com/specs/handle): an HTTPS well-known document and a DNS TXT record, either one sufficient, so a static-hosting deployment that cannot touch DNS and a DNS operator that cannot serve files are both first-class. Where DFOS differs is the reverse half. The identity's domain claim does not live in a mutable profile or a platform database — it lives **inside the signed identity chain**, so it inherits everything chains already guarantee: only a current controller key can change it, every change is ordered, and [anti-rollback](https://protocol.dfos.com/spec) makes the history replayable. A re-bind is a chain event, not a field overwrite.

---

## The `DfosOrigin` Service Entry

```typescript
{ id: string, type: "DfosOrigin", domain: string }
```

The entry is a [service entry](https://protocol.dfos.com/spec#services) under the core's open type namespace, registered by this spec the way [SIGNING](https://protocol.dfos.com/signing) and [API-AUTH](https://protocol.dfos.com/api-auth) register their credential resource forms: the core carries it, this document gives it meaning. To a core verifier it is an unrecognized type — preserved verbatim, never structurally validated. Structural validation is a consumer obligation under this spec.

| Member   | Description                                                                                                                                                                                                                                            |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `domain` | The identity's canonical domain — a bare lowercase hostname: no scheme, no port, no path, no trailing dot. An internationalized name appears in its A-label (Punycode) form. Every comparison in this spec is an exact byte comparison of this string. |

The member set is deliberately minimal — the domain is the claim, and everything else this capability needs (ordering, authorship, history) the chain already provides. New members are added by amending this table, never ad hoc.

**One entry, or none.** An identity claims at most one canonical domain. A consumer encountering a services set carrying more than one `DfosOrigin` entry MUST treat the set as claiming **no** binding — an ambiguous claim is no claim. (This is deliberately not `broken`: contradiction verdicts are reserved for the domain's side, below, where a second party is being contradicted.) Likewise an entry whose `domain` is missing, empty, or not a bare hostname in the form above claims nothing and is ignored.

Setting, changing, and clearing the entry is ordinary services machinery — [full-state replacement](https://protocol.dfos.com/spec#full-state-semantics) in an identity `update`, signed by a current controller key. Nothing here adds an operation type, a field, or a verification rule to the core.

> Non-normative — on the name: the type is named for what the binding proves control of. The attestation is served from the domain's HTTPS **origin** (or the DNS zone that origin sits in), and control of that origin is the fact being demonstrated — not a display handle, not an account, not a person.

---

## Attest-Back: The Domain's Half

The domain answers the chain's claim by publishing the DID. Two methods are defined; **either one suffices**, and an operator serves whichever their hosting allows. Both are copied from atproto's handle-resolution shape on purpose — operators and tooling already understand them.

### HTTPS — `/.well-known/dfos-did`

```
GET https://<domain>/.well-known/dfos-did
```

A `200` response whose body — after trimming ASCII whitespace — is **exactly one DFOS DID** (`did:dfos:<31-char id>`) attests that DID. The response SHOULD be served as `text/plain`, but verifiers judge the trimmed body, not the media type. Origins SHOULD serve the document with `Access-Control-Allow-Origin: *` — like the [app description document](https://protocol.dfos.com/siwd), it is public by construction, and the header's absence only blocks browser-based tooling from reading what every other client already can.

Verifiers MUST fetch over HTTPS with ordinary TLS validation, MUST NOT follow a redirect to a different origin (the attestation must come from the named domain — a cross-origin redirect attests nothing; same-origin redirects MAY be followed), and SHOULD bound the read: a conforming body is under a hundred bytes, so a small cap (e.g. 1024 bytes) rejects garbage before reading it.

**App-description fallback.** If `/.well-known/dfos-did` is **absent** (a `404`), a verifier MUST fall back to fetching the [SIWD app description](https://protocol.dfos.com/siwd) at `/.well-known/dfos-app.json`: a structurally valid document whose `client_did` names the candidate DID attests it, exactly as the well-known file would. This makes every existing SIWD application attest-back-capable with zero changes — the origin already publishes its DID; this spec just reads it. The fallback applies only on **absence**: a `dfos-did` file that is present but names a different DID is a contradiction (below), and MUST NOT be fallen through.

### DNS — TXT at `_dfos.<domain>`

A TXT record at the name `_dfos.<domain>` whose value is exactly:

```
did=did:dfos:<31-char id>
```

attests that DID. TXT records at that name not beginning `did=` are ignored. **More than one** `did=` record at the name is a contradiction — the domain is attesting two answers, and a verifier MUST treat the binding as broken, never pick one.

### Agreement

If both methods yield an answer, the answers MUST agree. Disagreement between them renders the binding **broken** — never either-wins, never first-checked-wins. A domain that says two things is contradicting itself, and a contradiction is a verdict, not a tiebreak.

---

## Verification

Verification is bidirectional and runs entirely on public surfaces. Starting from a DID:

1. **Resolve the chain** to current identity state under the core's [verification rules](https://protocol.dfos.com/spec) and read the `DfosOrigin` entry. No valid entry → the identity claims no binding, and verification ends: there is nothing to check. (Attestation without a chain claim is equally not a binding — the chain entry is the identity's signed consent to be named by the domain, and half a binding is no binding.)
2. **Query the domain**: the DNS method, the HTTPS method (with its app-description fallback), or both.
3. **Deliver one of three verdicts:**

| Verdict    | Condition                                                                                                                                                                                    |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **bound**  | The chain names the domain, at least one method attests exactly the chain's DID, and no method answers with anything else                                                                    |
| **stale**  | The chain names the domain and the domain is **silent** — no TXT record, no well-known document and no app fallback, or the queries fail (network error, TLS failure, timeout, server error) |
| **broken** | Any method answers with a **different** DID, the two methods disagree, or the DNS name carries multiple `did=` records                                                                       |

Starting from a domain, the walk runs the other way — obtain the candidate DID from the domain's attestation, resolve its chain, and require a `DfosOrigin` entry naming this exact domain — and delivers the same verdicts.

**Silence is not contradiction.** The stale/broken split is this corpus's standing verdict discipline — [invalid versus unverifiable](https://protocol.dfos.com/api-auth) — applied to domains: `broken` is _checked and contradicted_; `stale` is _could not check_. DNS and web hosting fail routinely and recover routinely, so staleness is legal: a consumer MAY keep displaying the last successfully verified binding, marked as stale, for as long as its own policy tolerates. What a consumer MUST NOT do is display a broken binding as bound, or report a transient resolution failure as a contradiction.

---

## Lapse, Transfer, and Re-binding

Domains change hands; the design makes every outcome of that fact visible rather than exploitable.

- **A lapsed domain's new registrant cannot touch the old identity.** The chain half of the binding is signed by controller keys the registrant does not hold. Control of the domain buys control of the attestation — nothing more.
- **A fresh identity claiming the domain breaks the old binding _visibly_.** If the new registrant mints their own identity and points the domain's attestation at it, their binding may verify `bound` — and the old identity's binding immediately verifies `broken`, because the domain now attests a different DID. The old identity survives untouched, with its whole history; only its domain claim is contradicted, and every verifier sees the contradiction. Nothing transfers silently. This is correct by construction — no revocation ceremony, no dispute process, no policy layer.
- **Re-binding within one identity needs no policy at all.** The `DfosOrigin` entry rides services full-state replacement, so "which domain does this identity claim" has exactly one answer per chain state, and the chain's ordering — anti-rollback, deterministic head selection — orders every move. A chain-ordered domain history structurally supersedes any last-write-wins re-bind policy: the moves are already ordered by signatures, so there is no write race to adjudicate.

---

## Display Discipline

This section is normative, because the value of a binding is destroyed at the display layer more easily than anywhere else.

A verified binding proves **control of a domain at verification time — never personhood, endorsement, notability, or trustworthiness**. Consumers rendering a binding MUST display the bound domain itself, and MUST NOT collapse the verdict into a generic verified badge, checkmark, or tier divorced from the domain — a bare checkmark asserts exactly the thing this binding cannot prove, and launders domain control into implied identity vetting. The domain is the credential; show the credential.

The binding is **exact**: a binding to `example.org` says nothing about `sub.example.org`, and vice versa — no inheritance in either direction. Consumers displaying internationalized domains SHOULD apply their platform's standard homograph-safe rendering; the `domain` member's A-label form exists so that the comparison layer never depends on display-layer Unicode choices.

---

## Custody

A hosting platform MAY append and maintain `DfosOrigin` entries on behalf of the custodial identities it hosts, exactly as it signs their other identity operations; how it exposes that to users is platform policy outside this spec. The format above and the verification rules above are the whole public surface — a self-custodied identity binds a domain with nothing but its own keys and the [CLI](https://protocol.dfos.com/cli).

---

## Security Considerations

- **Domain compromise is attestation compromise, not identity compromise.** An attacker controlling a domain (registrar account, DNS, or web hosting) can silence or contradict the attestation — breaking the binding, visibly — or attest an identity of their own. They cannot extend the bound identity's chain, and they cannot make the old identity's binding read `bound` to a DID they control. The blast radius of the web-side compromise is the web-side half.
- **DNS answers are only as trustworthy as the resolver.** A verifier SHOULD query a resolver it trusts (its own recursive resolver, or DNS-over-HTTPS to one it chooses); a spoofed TXT answer can forge the DNS half of an attestation for that verifier. The HTTPS method rides TLS and is not affected by resolver spoofing beyond redirection-to-refusal.
- **Bounded work.** Both lookups are single round-trips with small caps (one TXT query; one bounded GET, with at most one bounded fallback GET). A verifier never fetches chains from the domain — chain resolution stays on relays under the core's rules, so a hostile domain cannot feed a verifier unbounded or forged chain data.
- **Verdicts must stay machine-distinguishable.** Reporting `stale` as `broken` turns every hosting blip into a public accusation of contradiction; reporting `broken` as `stale` hides a hijack behind a shrug. The three states carry different consequences and MUST NOT be conflated — see [Verification](#verification).
