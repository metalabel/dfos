# DFOS Guarantees

What this protocol guarantees, and what it does not. Authorship is verifiable
without trusting any server. Which view of an identity you follow is a choice of
relay.

This is the corpus's one derivative document. It states no rule of its own: every
line points at the section that makes it true, and where this page and that
section disagree, the section is right.

---

## What is verifiable without trust

These hold from any copy of the bytes, offline, with no server consulted and no
DFOS software involved. A verifier needs an Ed25519 implementation, a dag-cbor
encoder, and SHA-256.

**Authorship of a signed record.** Every operation, artifact, countersignature,
credential, and revocation is a compact JWS over canonical bytes. The signature
is checked under one pinned profile: `alg` is exactly `EdDSA`, a `crit` member
rejects, an embedded or fetched header key rejects, and the signature check
applies the canonical-scalar gate (`S < L`) and the 64-byte length check. There
is no algorithm agility and nothing to negotiate
([PROTOCOL, Signature verification profile](https://protocol.dfos.com/spec#signature-verification-profile)).

**The identifier derives from the chain.** A `did:dfos` is
`customAlpha(SHA-256(genesis CID bytes))`, and a contentId is the same derivation
without the prefix. Re-deriving the identifier from the genesis operation is the
check: a chain that does not derive the identifier it claims is rejected, whatever
served it ([PROTOCOL, Addressing](https://protocol.dfos.com/spec#addressing);
[DID-METHOD §5.2.3](https://protocol.dfos.com/did-method#523-self-certification)).
The binding strength of the identifier is a number, stated under
[Binding strength of the identifier](#binding-strength-of-the-identifier).

**Chain integrity.** Each operation after genesis names its predecessor by CID,
carries its own CID in its protected header, and carries a `createdAt` strictly
greater than its parent's. An identity chain, as verified, is one sequence; a
content chain is a DAG whose branches all verify. Terminal states are enforced
from the operations themselves
([PROTOCOL, Chain validity](https://protocol.dfos.com/spec#chain-validity),
[Terminal states](https://protocol.dfos.com/spec#terminal-states)).

**Possession of every key a chain lists.** The genesis key proves possession by
signing genesis. Every other key proves possession by an envelope that key itself
signed, binding the chain DID, the role set, and the chain position. A membership
with no valid covering envelope is void: excluded from effective state, never
resolved for signature verification, never indexed, never surfaced in recovery. A
chain cannot hold a key its holder never gave it, and a proof is spent at the
position it names, so no stored envelope re-adds a removed key later
([PROTOCOL, Key possession](https://protocol.dfos.com/spec#key-possession)).

**The commitment to a document.** A content operation commits to its document by
`documentCID`. A reader re-canonicalizes served bytes through the same decode and
dag-cbor path the upload check uses and compares, so integrity holds against a
hostile host: it can withhold the bytes, and it cannot substitute them
([RELAY, What a 200 from the content plane means](https://protocol.dfos.com/relay#what-a-200-from-the-content-plane-means)).

The commitment binds; it does not hide. A `documentCID` is an unsalted hash of
the document, so anyone holding the CID can test a candidate document against it
and learn whether the guess was right. A document drawn from a small or guessable
space is not confidential against a party that holds its CID, and two chains that
committed the same bytes are visibly the same bytes.

**Verification is a pure function of the chains.** A signed chain and the
identity chains it names give valid or invalid. Nothing in the answer depends on
which relay supplied the bytes, on the reader's network, or on the reader's
clock, except the two clock-bound checks named under
[Time and ordering](#time-and-ordering).

---

## What is a chosen view

An identity chain is linear per view. Two identity operations that claim the same
chain position are two views of that identity, not an invalid log
([PROTOCOL, Views](https://protocol.dfos.com/spec#views)).

**Admission is first-seen.** A relay admits the first successor it sees for a
position and refuses later ones, so the log it serves is one linear chain. The
refusal is that relay's admission verdict. It is not a claim that the refused
operation is invalid
([RELAY, Identity linearity and admission](https://protocol.dfos.com/relay#identity-linearity-and-admission)).

**Nothing arbitrates.** No rule in this corpus arbitrates between relays that
admitted different successors at one position. There is no consensus layer, no
tiebreak, and no reconciliation procedure. Which relay you read is which view you
get, and comparing views is out-of-band work a consumer does or does not do
([DID-METHOD §5.2.4](https://protocol.dfos.com/did-method#524-resolution-is-relay-relative)).

**Resolution is relay-relative, and so is currency.** A signature proves who
signed, forever, from anywhere. Whether a key is still effective, whether an
identity is deleted, and what the head is, are statements about the freshest
state a relay has. That is served, not proven. An identity's own `services` relay
list is the set of sources the subject stands behind
([PROTOCOL, Services](https://protocol.dfos.com/spec#services)).

**Choosing peers chooses a view.** Peer-log ingestion inherits the peer's
admission discipline, so which peers a relay syncs from decides which view of a
divergent identity it ends up serving
([RELAY, Peering](https://protocol.dfos.com/relay#peering-convention)).

**A rotated-out key can still open a second view.** Removal ends a key's authoring
window at every relay that already committed a successor. A relay holding no
successor at an earlier position admits an operation that key signs there and
serves a different view. What closes a compromise is rotating and then reading
relays that already hold the extended chain.

**Recovery needs a relay.** Recovering the identities a seed phrase controls asks
a relay's `key=` index which identities each derived key has ever been proved
into. Everything else in this protocol runs offline; recovery is the one
operation that needs a relay
([RELAY, Index](https://protocol.dfos.com/relay#index-capability-index)).

**Served order is trusted, not auditable.** A relay's committed log is the
identity order that relay serves. There are no signed tree heads, no inclusion or
consistency proofs, and no Merkle transparency structure anywhere in this corpus.
A relay that serves one committed order to one consumer and a different one to
another is detectable by comparison between consumers, never from a single
response. The known construction for making a log's ordering verifiable without
trusting the log is Certificate Transparency
([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)) and the log designs built on
it. This corpus does not build it. Content chains sit outside the question: their
head converges by deterministic selection over signed operations, so no relay's
admission order is load-bearing for them.

**A relay's log is its own.** Append-only names a serving discipline, not a
promise that a relay holds everything. Retention is the relay's, culled logs have
permanent gaps, and cross-relay operation counts are not comparable
([RELAY, Retention](https://protocol.dfos.com/relay#retention)).

---

## What the operator can do and see

**The operator reads every blob it stores.** The protocol commits to content
hashes, not plaintext. It does not encrypt. Content-plane access control is
host-cooperative: it protects an honest host from mis-serving, and it is not a
vault. Anything that must stay confidential against the operator is withheld or
encrypted above the protocol
([RELAY, Two planes](https://protocol.dfos.com/relay#two-planes)).

**There is no end-to-end encryption in this protocol.** No key exchange, no
envelope encryption, no private-document primitive. The security posture of a
document is the security posture of the party serving it.

**Custody is custodial by default on the reference platform.** The DFOS platform
holds a signing key for your account by default, so ordinary use needs no key
management. You can add keys it never holds.

**Any controller key can change the key set.** Whoever holds a controller key can
update, delete, and restore the identity. Where custody is split, each holder has
that full power independently, and there is no threshold, no protected
membership, and no key that cannot be removed by another. The platform's default
key is a controller key
([DID-METHOD §6.3](https://protocol.dfos.com/did-method#63-who-can-extend-a-chain)).

**No holder has silence.** Every change is a signed operation in the log,
addressed by CID and held by every relay that took it. A key removal, a deletion,
or a restore is visible to anyone reading the chain, and copies already held
cannot be recalled.

**The platform cannot forge a signature from a key it does not hold.** That is
the whole of what custody buys and the whole of what it cannot buy.

**A compromise of custody is indistinguishable on the chain.** A signature made
with a custodied key is a valid Ed25519 signature by a key the chain declares, so
it verifies exactly like a self-custodied one. The chain shows what was signed,
never who was at the keyboard.

**A relay can refuse.** It can withhold a chain, serve stale state, reorder
delivery, serve different views to different readers, censor what it dislikes,
and refuse to admit an operation at all. A refusal is that relay's verdict;
another relay may admit the same operation, and the result is two views.

**Ingestion cost is a deployment concern.** `POST /proof/v1/operations` accepts
self-authenticating operations, and an aggregate operation-size cap plus
cardinality caps bound per-operation abuse. Rate limiting, anti-spam, and blob
size limits are set per deployment, not by this protocol
([RELAY, Not defined here](https://protocol.dfos.com/relay#not-defined-here)).

---

## Continuity

A controller key you hold is a fork right: from the last operation it controlled,
you can continue the same identity on another relay, and who follows you there is
a choice of relay.

The right is a right to continue, not a right against an uncooperative platform.
It does not compel a relay to admit anything, and a platform holding a controller
key can remove the key you hold. What it cannot do is remove it silently: the
removal is a signed operation on the chain, and anyone reading the chain sees it.

**The documents do not travel.** The proof plane replicates and the content plane
does not. Blobs are never pushed on the operation log, and a blob enters a relay
by upload to the relay that holds the chain. What continues is the proof of your
history. The documents live wherever they were served
([RELAY, Content plane](https://protocol.dfos.com/relay#content-plane-capability-content)).

**Proofs survive where a copy was kept.** Identity operations are public and
anyone can mirror them, and nothing obliges any relay to hold yours. Keep your own
copies of your chain and your documents.

**Rotation revokes going forward and leaves history valid.** An operation
committed while a key was effective still verifies after that key is rotated out.
The same key signs nothing new: an ephemeral presentation resolves against a basis
of now, so a rotated-out key's sign-in, request proof, and freshly presented
credential all fail
([PROTOCOL, Time basis](https://protocol.dfos.com/spec#time-basis)).

**Rotate first, then delete.** A `restore` operation needs only a controller key
of the deleted head state, so an identity deleted while a compromised key is still
current is reopenable by exactly that key. A key rotated out before the delete is
not in the deleted state and cannot restore it
([PROTOCOL, Terminal states](https://protocol.dfos.com/spec#terminal-states)).

---

## Time and ordering

`createdAt` is asserted by the signer. Nothing else vouches for it. Two bounds
constrain it and nothing more: it is strictly greater than its parent's, enforced
per branch on a content chain, and a relay rejects an operation more than 24 hours
in the future against its own clock
([PROTOCOL, Timestamp ordering](https://protocol.dfos.com/spec#timestamp-ordering),
[Future timestamp bound](https://protocol.dfos.com/spec#future-timestamp-bound)).

**Head selection is convergence, not truth.** On a content chain, the highest
`createdAt` with a lexicographic CID tiebreak makes every implementation holding
the same operations compute the same head. It answers which tip honest verifiers
agree on. It does not answer which tip is true or which happened first, and the
semantics of a fork are the application's
([PROTOCOL, Chain validity](https://protocol.dfos.com/spec#chain-validity)).

**Identity chains are outside that mechanism.** They have no head selection and no
timestamp competition: the head is the last operation of the sequence one relay
serves.

**What a skewed clock changes, and what it does not.** Chain linkage, per-branch
monotonic `createdAt`, and every signature check read only the operations, so a
verifier with any clock reaches the same verdict on them. Basis-time checks on a
committed operation resolve against that operation's own `createdAt`, so two
relays reach the same temporal verdict on it regardless of when each ingests it.
The clock enters in exactly two places: the 24-hour future bound at admission, and
the freshness window on an ephemeral presentation. A skewed verifier can therefore
refuse to admit an operation another verifier admits, and can refuse a sign-in or
request proof another host accepts. It cannot reach a different verdict on
committed history.

**Comparisons are byte-wise.** Both ordering comparisons compare raw strings
left to right, never a parsed epoch and never a locale-aware collation
([PROTOCOL, Comparison basis](https://protocol.dfos.com/spec#comparison-basis)).

---

## Adversaries

| Adversary                                               | What holds against it                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A relay serving you**                                 | It can withhold, serve stale state, reorder, serve different views to different readers, censor, refuse to admit, and read every blob it stores. It cannot forge a chain or an operation: every ingest path re-derives the CID and checks the signature, and every read is re-derivable by the reader.                                                                                                      |
| **The platform holding a controller key on your chain** | Acting entirely within the rules, it can remove any key including one you hold, delete and restore the identity, refuse to sequence your writes, and serve the view it admitted. It cannot forge a signature from a key it does not hold, act silently (every change is a signed operation on the chain), or recall copies peers already hold.                                                              |
| **A peer relay**                                        | Its operations are fully re-verified locally before storage, so it cannot get an invalid operation accepted. Peer-log ingestion inherits the peer's admission discipline, so a peer does influence which view of a divergent identity a relay serves, and it can impose cost and noise. Choosing peers is a trust decision.                                                                                 |
| **An unauthenticated submitter**                        | Operations self-authenticate, so malformed or unsigned submissions are rejected. It can impose CPU and storage cost, and a carried identity chain reaches ingestion through a consumer's own fetch with no POST. Size and cardinality caps bound one operation; rate limiting is the deployment's.                                                                                                          |
| **A holder of a public write credential**               | An `aud: "*"` credential granting `write` is a bearer grant: anyone holding the bytes can attach it and write to the covered chains, and a public `chain:*` write grant is world-writable across every chain rooted at the issuer. Public credentials are read-scoped by convention, and revocation is the remedy ([CREDENTIALS](https://protocol.dfos.com/credentials#aud--plus-write-is-a-bearer-grant)). |
| **A party who captured a credential**                   | Without the audience key the credential authorizes nothing: a request proof binds `{method, host, path, bodyHash, credentialCID, iat}` to the audience key, which never crosses a channel. A captured proof replays only as the byte-identical request, to the same host, inside the freshness window.                                                                                                      |
| **A party who compromised a domain**                    | It can silence or contradict an origin binding, which reads `stale` or `broken`, both visible verdicts. It cannot extend the bound identity's chain or move the binding to itself unseen ([INTEGRATIONS, Origin binding](https://protocol.dfos.com/integrations#origin-binding)).                                                                                                                           |
| **A party who intercepts a ceremony code**              | Resolving a code discloses the ceremony context, including which public identity it adopts into, and lets the interceptor attempt one presentation with a key of its own. The gates are the operator's ceremony authorization and the human's fingerprint comparison, and the disclosure is the price of consent ([INTEGRATIONS, Key ceremonies](https://protocol.dfos.com/integrations#key-ceremonies)).   |

### Adversaries this corpus is not designed against

- **A holder of your keys.** A compromised custody service or a stolen device
  signs as you, and the chain cannot tell the difference.
- **A host of your plaintext.** There is no end-to-end encryption, so a host that
  reads or leaks what it stores is outside what any protocol rule reaches.
- **A Byzantine network.** There is no consensus, no quorum, and no fault
  threshold. This is a selectively trusting design: you choose your relays and
  peers, and you can be your own.
- **The software you run.** Client libraries, signer interfaces, and the package
  registries that deliver them are trusted by whoever installs them. Consent
  obligations such as render-before-signing live in that software, and nothing on
  the wire shows whether it honored them.
- **Traffic analysis.** `did:dfos` identifiers are persistent and public, chain
  history including rotation timestamps is public, and resolving through a relay
  tells that operator which DIDs you are interested in
  ([DID-METHOD §7](https://protocol.dfos.com/did-method#7-privacy-considerations)).

### Binding strength of the identifier

```
Identifier space:         19^31 ≈ 2^131.6
Birthday collision:       ≈ 2^65.8
Targeted second-preimage: ≈ 2^131.6
```

Forging a chain that encodes to a chosen victim's DID costs about `2^131.6`.
Finding any two genesis chains that encode to the same identifier costs about
`2^65.8`, which is below a 128-bit floor and is the accepted consequence of a
31-character identifier. These numbers bound the identifier only: the 32-byte
genesis CID and the Ed25519 signatures are unaffected by the truncation
([DID-METHOD §6.1](https://protocol.dfos.com/did-method#61-self-certifying-identifiers)).

### Accepted bounds

- **Revocation reaches a verifier through configured peering or an explicit
  query.** There is no mandatory bridge and no maximum `exp`, so the exposure of a
  regretted credential runs until every relay that ingested it holds the
  revocation. An API host resolving revocations from the relays its users' chains
  list, on a cache interval it chooses, is choosing its revocation latency.
- **Within-window replay of an identical proven request is accepted** on
  read-shaped surfaces. Write-shaped surfaces close it with the required `jti`
  replay cache.
- **Sign-in controls live in the relying party.** Nonce, redirect-URI validation,
  challenge-DID binding, and timestamp windows are the verifying party's, and
  nothing on the wire reveals a party that skipped them.
- **Loopback client provenance is unverifiable.** The loopback tier proves
  ask-time control of a client identity's keys, never what the software is. The
  controls are honest consent language and a hard expiry ceiling.
- **A signing mailbox operator reads pending payloads.** The mailbox is an
  optional relay capability, default off, and where it is on the courier holds
  request payloads in the clear until they expire.
- **A list route's `400` on an unknown cursor is a membership signal** over a set
  the same route already enumerates publicly: no new disclosure, a cheaper probe.

---

## Conformance

**The executable suites are the definition.** There are no tiers and no
certificate.

- [`packages/protocol-verify`](https://github.com/metalabel/dfos/tree/main/packages/protocol-verify)
  is the verifier and signer definition. Five standalone suites (TypeScript, Go,
  Python, Rust, Swift) read expected values from
  `packages/protocol-verify/vectors.json` and use native crypto only, with no DFOS
  library imports. Agreement across languages is the proof that the wire is
  unambiguous.
- [`packages/relay-conformance`](https://github.com/metalabel/dfos/tree/main/packages/relay-conformance)
  is the relay definition. It is a Go integration suite that runs against any live
  relay over HTTP: set `RELAY_URL` and run it. Capability-gated variants self-skip
  unless the relay advertises the matching flag, and the parity harness compares
  the two reference relays over the same fixture
  ([RELAY, Conformance](https://protocol.dfos.com/relay#conformance)).

A passing run proves that your bytes and your routes agree with the reference
implementations on the cases the suites cover: derivation, signature acceptance
and rejection, envelope structure, ingestion, admission, capability semantics, and
the served shapes. It does not prove that your deployment is secure, that your
custody is sound, that your key handling is correct, or that anything above the
wire behaves. It proves interoperability, and interoperability is all a
conformance suite can prove.

---

## Source

Every claim here is owned by another document:
[PROTOCOL](https://protocol.dfos.com/spec),
[CREDENTIALS](https://protocol.dfos.com/credentials),
[RELAY](https://protocol.dfos.com/relay),
[INTEGRATIONS](https://protocol.dfos.com/integrations),
[DID-METHOD](https://protocol.dfos.com/did-method), and
[CONTENT-MODEL](https://protocol.dfos.com/content-model). Report a defect in the
cryptographic path privately, per
[SECURITY.md](https://github.com/metalabel/dfos/blob/main/SECURITY.md).
