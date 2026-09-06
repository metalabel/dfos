# DFOS Threat Model

> **Status — companion document, no clock of its own.** This document defines no protocol rules; it assembles the adversary model already specified across the normative specs, and is corrected in place as they evolve.

A consolidated map of the DFOS adversary model and trust boundaries. This document
does not introduce new protocol rules — it assembles the threat surface that is
already specified, in prose, across [PROTOCOL.md](https://protocol.dfos.com/spec),
[CREDENTIALS.md](https://protocol.dfos.com/credentials),
[RELAY.md](https://protocol.dfos.com/relay),
[DID-METHOD.md](https://protocol.dfos.com/did-method), and
[INTEGRATIONS.md](https://protocol.dfos.com/integrations), and links each claim back to its source.

This spec is under active review. Discuss it in the [DFOS](https://nce.dfos.com) space.

---

## Trust Boundaries

DFOS has two replicated planes with fundamentally different trust models. The
optional signing mailbox's courier state sits outside both.

### Proof plane — self-authenticating

The crypto core is the trust boundary (PROTOCOL.md "Overview", `specs/PROTOCOL.md`).
Identity chains, content chains, artifacts, countersignatures, credentials,
and revocations are all signed, content-addressed objects that anyone can verify with
a public key and any standard EdDSA + dag-cbor library. There is no privileged registry,
blockchain, or consensus layer; the identifier _is_ the trust anchor (DID-METHOD.md
"Abstract", `specs/DID-METHOD.md`). Verification is against the chain, not the source
— a `did:dfos` is verified by re-deriving it from the genesis CID (DID-METHOD.md §5.2.3,
`specs/DID-METHOD.md`). All proof-plane relay routes are unauthenticated; the
operations carry their own authentication (RELAY.md "Two planes", `specs/RELAY.md`).

Everything below the crypto core is cryptographically verified. Nothing above it needs
to be trusted to verify a proof.

One property is deliberately **not** carried by the crypto core alone: **currency**. A
signature proves who signed and that the bytes are intact — forever, from anywhere. Whether
a key is _still_ the signer's current key, or a head is _still_ the chain's current head, is
a statement about the freshest state a resolver has seen, and freshness is served, not
proven. Authorship is verifiable without trusting any server; currency is host-mediated — see
_Authority currency_ below.

### Content plane — honest-host, undisclosed-by-default

The protocol commits to content _hashes_, not plaintext — it does not encrypt
(README.md, `README.md`; PROTOCOL.md "Overview", `specs/PROTOCOL.md`).
Confidentiality of the underlying documents is enforced at the application layer by
whoever serves them. **The relay operator can read what it stores.** This is
undisclosed-by-default, _not_ end-to-end encrypted. The content plane never gossips;
blobs are stored by the relay that received them and served only to authorized readers
(RELAY.md "Content plane", `specs/RELAY.md`). Content-plane access is
gated by an identity proof plus (for non-creators) a read credential
(RELAY.md "Authentication" / "Content plane",
`specs/RELAY.md`).

The security posture of a document is therefore the security posture of the relay
operator that holds it.

### Authority currency — honest-host arbitrated

The same honest-host split that governs content confidentiality governs **how current an
identity's authority is**. An identity chain's proofs verify without trusting any
server, but its _current state_ — which keys are live, whether it is deleted — is resolved from whatever log the
chosen relay serves, as fresh as that relay's ingestion (INTEGRATIONS.md "Verifying a sign-in",
`specs/INTEGRATIONS.md`). The subject's own `services` relay list is the designated trust anchor:
resolving a subject through the relays it lists yields the currency the subject stands
behind, and running your own relay makes your authority fully self-sovereign — the
"own your data" escape hatch is structural, not aspirational.

Hosts enforce currency at the door: first admission of a new operation resolves its signer
against **current state** (RELAY.md "Authentication", `specs/RELAY.md`), so a
rotated-out key's authoring window ends at rotation, while committed history re-verifies
historically forever. Peer-log ingestion inherits the peer's admission discipline —
choosing peers is a trust decision, which is the model working as intended: this protocol
is **selectively trusting** (you pick your hosts and peers, and can be your own), not a
Byzantine-consensus network, and its guarantees are stated accordingly.

Relay resolution is not the only currency source: an identity chain can also arrive by
**carriage** inside an application's own well-known document — a second source with a
different trust texture, covered next.

### Carried identity chains — controller-attested currency

SIWD's app description MAY carry the application identity's full operation log in place
(INTEGRATIONS.md "`identity_chain`: chain carriage", `specs/INTEGRATIONS.md`), and any consumer that
encounters the document MAY fetch, verify, ingest, and re-serve that chain with no
registration or approval precondition. Signatures verify identically to a relay-fetched
chain — forgery is a non-issue — but the source is **controller-attested**: the consumer
holds identity state fetched on its own clock from an origin the application itself
controls, with no independent arbiter in the path. A carried chain is one view of the
identity, and reading it is a choice of source the way reading a relay is a choice of
relay (PROTOCOL.md "Views", `specs/PROTOCOL.md`).
The operational consequences are specified as the five carried-chain disciplines
(INTEGRATIONS.md "Carried identity chains", `specs/INTEGRATIONS.md`):

- **Rollback by prefix omission.** Serving yesterday's shorter chain resurrects a
  rotated-out key by omitting the rotation. The defense is monotonicity compared on the
  ordered operation-log CIDs — a fetch that is a proper prefix of previously observed
  state SHOULD be ignored; derived-state comparison does not catch this.
- **Signed divergence.** Two chains sharing a prefix and disagreeing after it both
  verify — the controller's key contradicting itself, indistinguishable from a
  compromised key. Acceptance is operator discretion; observed divergence SHOULD be
  logged. Nothing outside the consumer picks a branch: both are views of the same
  identity.
- **Staleness in both directions.** A carried chain is a snapshot at fetch time: the
  consumer's re-fetch cadence bounds new-key usability and rotated-key death at once.
- **Chain substitution at first encounter.** Identity operations are public data:
  HTTPS proves which origin served the document, never that the origin controls the
  identity the chain derives. A consumer ingesting into a store that also holds
  identities under its own authority MUST refuse or segregate a carried chain whose
  derived DID it already holds under that authority — re-fetches of previously carried
  state are the monotonicity discipline's ordinary case, but monotonicity begins only
  after a first accepted state and cannot defend the first encounter.
- **Discretionary retention.** Nothing obliges any consumer to ingest, retain, or keep
  re-serving a carried chain; removal — including abuse removal — is operator policy.

### Signing mailbox — ephemeral courier state outside both planes

Signing mailbox state is on neither plane: it is never gossiped, never folded, and
its retention is bounded by each request's own expiry. See
[RELAY.md "Signing mailbox"](https://protocol.dfos.com/relay#signing-mailbox-capability-signing)
for the detailed analysis.

### API request authentication — possession proves audience, not the credential

The credential-gated API surface (INTEGRATIONS.md "API authentication") splits
authorization from authentication deliberately: a [DFOS credential](https://protocol.dfos.com/credentials)
names the grant, and a per-request **request proof** — a short-lived JWS signed by the
credential's audience key, binding `{method, host, path, bodyHash, credentialCID, iat}`
— proves the presenter _is_ that audience, making the credential useless as a bearer
token (INTEGRATIONS.md "API authentication", `specs/INTEGRATIONS.md`). The threat consequences the
surface is built around:

- **A stolen credential is a metadata leak, not an access leak.** Without the audience
  key, a captured credential authorizes nothing; the artifact that must never leak is
  the key, which never crosses a channel (INTEGRATIONS.md "API security notes").
- **Public audience is refused at every level of the chain.** A single `aud: "*"`
  credential anywhere in the presented delegation chain would let a stranger self-issue
  a passing leaf audienced to their own key — a full proof-of-possession bypass — so the
  verifier scans the whole chain, not just the leaf (INTEGRATIONS.md verification step 9).
- **Within-window identical-request replay is an explicitly-accepted bound**, which is
  why the v0 registry is read-only; write-bearing actions require a per-request
  uniqueness seam (INTEGRATIONS.md "API security notes").
- **The host binding is only as strong as its source.** The verifier compares against
  its own configured hostname, never a request-supplied `Host`/`X-Forwarded-Host`; a
  verifier that derived the host from the request would have no cross-host binding at
  all (INTEGRATIONS.md verification step 5).
- **The browser BFF is a signing surface, not a blind oracle** — a backend that signs
  the coordinates a browser hands it is a confused deputy (INTEGRATIONS.md "The browser is
  not a keyholder").

### Origin binding — domain control is the web-side half, nothing more

Origin binding (INTEGRATIONS.md "Origin binding") ties an identity to a
domain bidirectionally: a `DfosOrigin` services entry inside the signed chain, answered
by a well-known HTTPS document or DNS TXT record the domain serves back
(INTEGRATIONS.md "Attest-back: the domain's half", `specs/INTEGRATIONS.md`). The threat consequences
the surface is built around:

- **Compromising the domain compromises the attestation, never the identity.** A
  registrant, registrar, DNS, or hosting attacker can silence or contradict the
  web-side half — rendering the binding `stale` or `broken`, both visible verdicts —
  but cannot extend the bound identity's chain or transfer the binding to themselves
  silently (INTEGRATIONS.md "Lapse, transfer, and re-binding").
- **A lapsed domain's new registrant claiming it breaks the old binding visibly.**
  Their fresh identity may verify `bound`; the old identity's binding verifies
  `broken` the moment the domain attests a different DID. The old identity and its
  history survive untouched (INTEGRATIONS.md "Lapse, transfer, and re-binding").
- **Silence and contradiction are machine-distinguishable verdicts** — `stale`
  ("could not check") versus `broken` ("checked and contradicted"), the corpus's
  standing invalid/unverifiable split. Conflating them either turns hosting blips
  into public accusations or hides hijacks behind shrugs (INTEGRATIONS.md
  "Binding verification").
- **A binding proves domain control at verification time, never personhood.**
  Consumers MUST render the domain itself, never a generic verified badge — the
  display layer is where the binding's meaning is most easily laundered into implied
  identity vetting (INTEGRATIONS.md "Display discipline").
- **DNS answers are resolver-trust; HTTPS answers are TLS-trust.** A spoofed resolver
  can forge the DNS half for that verifier; the HTTPS method is unaffected by
  resolver spoofing beyond denial (INTEGRATIONS.md "Origin-binding security notes").

### Key proofs — possession is the whole claim

A key proof is a challenge-bound JWS in which a candidate key signs `{nonce,
audience, chain DID, role set, chain position, its own public key, timestamp}` to
demonstrate possession and consent to one named introduction (PROTOCOL.md "The envelope",
`specs/PROTOCOL.md`) — presented once during a ceremony, then carried
forever by the chain operation that adopted it (PROTOCOL.md "Key Possession").
The threat consequences the surface is built around:

- **A chain cannot hold a key its holder never gave it.** Every non-genesis
  key-role membership is backed by the key's own embedded signature over
  `{chain, roles, position}`; genesis proves its single key by signing itself.
  A membership without that backing is **void** — never effective, never
  resolved, never indexed, never a burn against the true holder — so the
  preemptive-claim and hostile-listing class (declare a victim's key to pollute
  recovery, forge association, or spend its one-key-one-DID slot) produces
  nothing but a loudly-surfaced dead claim (PROTOCOL.md "Key Possession",
  RELAY.md's has-ever-proved `key=` index).
- **Consent is spent at the position it names.** The envelope binds the chain
  head the introduction builds on, so no stored proof re-adds a removed key at a
  later head — the chain's own controller included. There is no standing consent
  and nothing to revoke: each introduction costs a fresh signature from the key
  itself (PROTOCOL.md "Position binding").
- **Challenge relay is defeated by audience binding, not carriage secrecy.** The
  signer names the completing authority its human confirmed inside the signed bytes,
  and the verifier compares against its own configured authority — so a phished or
  re-displayed challenge yields a proof that is dead bytes everywhere but the host
  the victim actually initiated (PROTOCOL.md "The two legs"). The
  controller-verified leg has no host, and its audience is the chain's own DID —
  the two value domains never overlap, so neither leg's envelope verifies in the
  other (PROTOCOL.md "The two legs").
- **The code is the capability, and resolving it names the identity — deliberately.**
  A shoulder-surfed code or intercepted QR yields the ability to resolve one
  short-lived ceremony's context — including which public identity it adopts into —
  and to attempt one presentation, which still requires the candidate key's
  signature plus the operator's own ceremony authorization. The disclosure is the
  price of consent: a holder who cannot see whom they are joining cannot refuse it,
  and the named facts are public identity facts (PROTOCOL.md "Carriage and resolution").
- **The payload is closed, so a key proof cannot be socially engineered into
  "signing something".** There is no member in which to smuggle a transaction or an
  instruction; a proof proves a key and conveys no intent (PROTOCOL.md "The envelope").
- **The payload's bytes are a function of its members.** A signature covers whatever
  octets arrived, not member semantics, so the verifier recomputes the canonical signing
  input from the parsed payload and byte-compares it against the octets it was handed — a
  reordered or re-spaced payload signed over its own serialization rejects.
  Canonicalization binds the verifier as it binds the signer. What it binds is the
  payload, not the envelope: padding-tolerant base64url decoding and an unpinned header
  serialization leave one proof more than one envelope spelling, and nothing rests on
  envelope uniqueness — at presentation the nonce is what is spent, atomically and
  once, and on the chain the carrying operation's CID pins one spelling of the whole
  operation (PROTOCOL.md "Presentation verification" steps 3 and 8,
  "Chain-walk verification").
- **Nothing persists to hijack.** Ceremonies are single-shot: no session, pairing, or
  channel outlives adoption, and the nonce is consumed atomically. The envelope's
  afterlife on the chain is a fact about one introduction, inert at every other
  position (PROTOCOL.md "Position binding").
- **Cross-DID key reuse is a permanent public link.** The has-ever-proved `key=`
  index survives rotation and deletion, so proving one key into two chains publishes
  their association irreversibly — which is why holder tooling refuses by default
  before any signature exists (PROTOCOL.md "Holder obligations"). An unproved
  declaration creates no link: void memberships never index.
- **The operator may name the pre-flight's oracle, and that adds no trust the ceremony
  does not already extend.** The short-code resolution's optional `relay` member reaches
  only a holder with no configured relay of its own — a holder's own oracle always takes
  precedence, the member is ceremony-scoped, and adopting it as a standing peer is
  refused by rule. The party it defers to is the one that already decides what the
  adoption effects (PROTOCOL.md "Carriage and resolution").

### Countersignatures live on the public proof plane

A countersignature is a proof-plane object (PROTOCOL.md "Countersignatures",
`specs/PROTOCOL.md`). Publishing one permanently and publicly links the witness
DID to its target: anyone can see that this identity attested to that operation. A
countersignature therefore MUST NOT be used to cross a public/private boundary —
witnessing a target that is meant to stay confined to a private context leaks the
witness↔target association onto the public plane, where it is immutable and gossiped.
If the fact of the attestation is itself sensitive, do not countersign.

---

## Adversary Classes

| Adversary                   | Can                                                                                                                                                                      | Cannot                                                                                                                    | Pointer                                                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Malicious/Byzantine relay   | Withhold, reorder, equivocate, censor, serve stale state, read stored content-plane blobs                                                                                | Forge a chain or operation                                                                                                | DID-METHOD.md §6.4 `specs/DID-METHOD.md`                                                                                   |
| Malicious peer              | Push invalid/spam operations to peers                                                                                                                                    | Have invalid operations accepted (each peer re-verifies)                                                                  | RELAY.md "Peering" `specs/RELAY.md`                                                                                        |
| Unauthenticated submitter   | POST arbitrary JWS to `/proof/v1/operations`; publish a carried chain and let encounter-triggered fetch ingest it (a write path with no POST); impose CPU + storage cost | Have malformed/unsigned ops accepted                                                                                      | RELAY.md "The write contract" `specs/RELAY.md`; INTEGRATIONS.md "`identity_chain`: chain carriage" `specs/INTEGRATIONS.md` |
| Compromised custody/KMS key | Full, indistinguishable impersonation of the user                                                                                                                        | Be detected on-chain (signature is valid Ed25519)                                                                         | INTEGRATIONS.md "The signing agent" `specs/INTEGRATIONS.md`                                                                |
| Loopback port-squatter      | Listen on the port a local SIWD client named; capture the callback (signed challenge, credential bytes)                                                                  | Redeem the credential (PoP-bound to the ask-proven `client_did`); pass the ask-time client proof without the client's key | INTEGRATIONS.md "Loopback clients" `specs/INTEGRATIONS.md`                                                                 |
| Lost key                    | —                                                                                                                                                                        | — (1-of-N availability vs. total loss)                                                                                    | DID-METHOD.md §6.2 `specs/DID-METHOD.md`                                                                                   |

### Malicious / Byzantine relay

A relay is untrusted by construction. It can **withhold** a chain (denial of service),
**serve stale** state, **reorder** delivery, **equivocate** (serve different views to
different clients), and **censor** operations it dislikes. It can also **read** any
content-plane blob it stores (see Trust Boundaries).

What it **cannot** do is **forge**. Every ingest path re-derives the operation CID and
verifies the Ed25519 signature over the signed bytes (RELAY.md "Verification",
`specs/RELAY.md`); peers verify independently (RELAY.md
"Peering", `specs/RELAY.md`). An attacker who intercepts a chain request can
withhold, serve a stale chain, or serve a completely different chain — but a modified
or forged chain fails the self-certification check (DID-METHOD.md §6.4,
`specs/DID-METHOD.md`).

### Malicious peer

Authorship is verifiable without trusting any server, and which view of an identity a
relay follows is its choice of peers (RELAY.md "What a relay is", `specs/RELAY.md`). A peer that gossips, is read
through, or is synced from has its operations fully re-verified locally before storage
(RELAY.md "Peering", `specs/RELAY.md`, `specs/RELAY.md`).
A malicious peer can therefore only impose cost and noise, not corrupt state.

### Malicious / unauthenticated submitter

`POST /proof/v1/operations` is unauthenticated (RELAY.md "Full route surface",
`specs/RELAY.md`); operations self-authenticate. An attacker can submit
arbitrary JWS tokens, imposing CPU (verification) and storage (store-then-verify
buffering, `specs/RELAY.md`) cost. One aggregate 64 KiB operation-size cap plus
a small set of cardinality caps bound per-operation abuse — there is deliberately no
per-field string-length table (PROTOCOL.md "Size and cardinality limits",
`specs/PROTOCOL.md`) — but **protocol-layer rate limiting is explicitly deferred** to
the deployment layer (RELAY.md "Not defined here", `specs/RELAY.md`).

The same class reaches ingestion **without POSTing anything**: SIWD chain carriage is
encounter-triggered — a consumer that meets an app description MAY fetch and ingest its
carried chain on the consumer's own initiative, so the write path is the consumer's
outbound fetch, not an inbound submission (INTEGRATIONS.md "`identity_chain`: chain carriage",
`specs/INTEGRATIONS.md`). The submitter's cost-imposition surface is the same — every carried
operation is verified like any other — and it is bounded by the 100-operation carriage
cap (a consumer MAY refuse a longer chain unexamined) with ingestion and retention
entirely at the consumer's discretion, including abuse removal (INTEGRATIONS.md "Carried
identity chains", `specs/INTEGRATIONS.md`).

### Compromised custody / KMS key

Where a hosting platform holds the user's key material and signs on their behalf — the
custodial posture profile A works against, and the custodial signer agent that
polls a mailbox for a keyless subject under profile B (INTEGRATIONS.md "Profile A: web redirect" / "The signing agent", `specs/INTEGRATIONS.md`) — a compromise of that
custody is **full impersonation** and is **indistinguishable on-chain**: the signature
is a valid Ed25519 signature by a key declared in the identity chain, so it verifies
identically to a self-custodied one (INTEGRATIONS.md "Sign in", `specs/INTEGRATIONS.md`). Self-custody
avoids this by never letting the platform touch the key: the subject holds the key and
polls the mailbox, so the signature is produced where the key lives (INTEGRATIONS.md "Profile B: sign-request mailbox", `specs/INTEGRATIONS.md`).

### Lost key

There is no key pre-rotation and no recovery mechanism (DID-METHOD.md §6.2,
`specs/DID-METHOD.md`). The mitigation is **1-of-N availability**: each role set
holds up to 256 keys per role, and any one current key can authorize an operation, so an identity
can spread controller/auth keys across devices and rotate out a lost one from a survivor
(DID-METHOD.md §6.2, `specs/DID-METHOD.md`). This is availability, not recovery — it
requires registering additional keys _in advance_ while a controller key is still held.
It is symmetric with the compromise surface: every additional device key is also another
key to keep safe. Total loss of every key in a role set is unrecoverable.

---

## Self-Certification Binding Strength

`did:dfos` identifiers and content IDs are 31-character strings over a 19-symbol
alphabet (`2346789acdefhknrtvz`), derived as `customAlpha(SHA-256(genesis CID bytes))`
(PROTOCOL.md "ID Alphabet" / "Addressing", `specs/PROTOCOL.md`, `specs/PROTOCOL.md`;
DID-METHOD.md §3.1–§3.2, `specs/DID-METHOD.md`).

```
Identifier space:        19^31 ≈ 2^131.6 bits
Birthday collision:      ≈ 2^65.8
Targeted second-preimage ≈ 2^131.6
```

This is the binding strength **of the identifier**, which is below SHA-256's full
256-bit strength: the identifier truncates and re-encodes the hash. The full 32-byte
genesis CID and the operation signatures are unaffected — this parameter bounds only
how hard it is to find a _second_ chain that encodes to the same 31-character DID/content
ID, or two chains that collide.

This parameter (alphabet size × length) is settled for v1, not an open one: at this
width the targeted second-preimage cost (≈ 2^131.6) sits above the 128-bit floor, and
the birthday-collision cost of ≈ 2^65.8 is the accepted consequence. See PROTOCOL.md
"ID Alphabet" (`specs/PROTOCOL.md`) and DID-METHOD.md §3.1 (`specs/DID-METHOD.md`).

---

## Head Selection Is Convergent, Not Canonical — and Content-Only

Deterministic head selection — highest `createdAt`, lexicographic-highest-CID tiebreak —
applies to **content chains** and guarantees that any implementation with the same set of
operations computes the same head, regardless of ingestion order (PROTOCOL.md "Chain
Validity", `specs/PROTOCOL.md`; RELAY.md "Content-chain forks and head selection", `specs/RELAY.md`).
That is its entire job: **convergence across implementations.**

It is **not** a canonical-truth or causal-ordering mechanism. `createdAt` is signer-asserted
and bounded only by the relay-enforced +24h future bound (PROTOCOL.md "Future timestamp
bound", `specs/PROTOCOL.md`; RELAY.md "The 24-hour future bound", `specs/RELAY.md`).
Head selection answers "which tip do all honest verifiers agree on?" — not "which tip is
true?" or "which happened first?". Semantic interpretation of content-chain forks
(concurrency glitch, intentional recovery) is application-defined (PROTOCOL.md "Chain
Validity", `specs/PROTOCOL.md`).

**Identity chains are outside this mechanism entirely.** An identity chain is linear per
view (PROTOCOL.md "Views", `specs/PROTOCOL.md`): the head is the last operation of the
sequence one relay serves, and there is no timestamp competition to win. No once-current
key can bid the head from an ancestor, whatever its `createdAt` claims. Head selection
runs exactly where a merge function exists, and key state has none. Undeletion is the
explicit `restore` operation, signed by a controller key of the deleted head state
(RELAY.md "Deletion and restore", `specs/RELAY.md`; DID-METHOD.md §5.5,
`specs/DID-METHOD.md`). A relay keeps its own log linear by admitting the first successor
it sees for a chain position and refusing later ones. Two operations signed at the same
position are a divergence between relay views, not a proof of invalidity (DID-METHOD.md
§6.3, `specs/DID-METHOD.md`). Which view of an identity you follow is a choice of relay,
and that choice is a trust decision.

---

## Explicitly-Accepted Residual Risks (v1)

These are known and deliberately accepted for v1.

- **Rotation is not revocation.** Rotating a key ends its authoring window for freshly
  admitted operations, but committed facts it signed re-verify forever — their invalidation
  mechanism is revocation or deletion, never rotation (RELAY.md "Authentication",
  `specs/RELAY.md`). A rotated-out key was effective at every chain position before
  its removal, so an operation it signs at one of those positions is structurally valid.
  What stops it is admission, not validity: a relay that already committed a successor at
  that position refuses a later one (PROTOCOL.md "Views", `specs/PROTOCOL.md`). A relay
  holding no successor there admits it and serves a different view of the identity, so
  the remedy for a compromised key is rotation plus reading relays that already hold the
  extended chain.
- **Delete is not a substitute for rotation.** `restore` requires only a controller key of
  the **deleted head state** (PROTOCOL.md "Identity Operations", `specs/PROTOCOL.md`). A
  thief holding a still-current controller key can therefore restore a deleted identity —
  and then rotate the legitimate holder out. The remedy for key compromise is **rotate
  first, then delete** if desired: deleting while a compromised key is still current
  leaves the chain reopenable by exactly that key. (A key rotated out _before_ the delete
  is not in the deleted state and cannot restore.)
- **Identity resolution is relay-relative.** An identity chain is linear per view, and no
  rule in the corpus arbitrates between views (PROTOCOL.md "Views", `specs/PROTOCOL.md`).
  A holder who extends the same chain position through two relays leaves two views
  standing, each internally linear and each fully signed. A consumer reading one relay
  sees no sign the other exists, and comparing views is out-of-band work a consumer does
  or does not do. Which view you follow is a choice of relay.

- **Relay-served order is trusted, not transparency-logged.** A relay's committed log is the
  identity order that relay serves, and nothing in the corpus makes that ordering _auditable_:
  there are no signed tree heads, no inclusion or consistency proofs, no Merkle transparency
  structure anywhere in the specs. A relay that equivocates about identity-chain order, serving
  one committed order to one consumer and another to another, is
  detectable only by out-of-band comparison between consumers, never from any single response.
  Certificate Transparency ([RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)) and the log designs
  built on its construction (Trillian, sigstore's Rekor) are the known mitigation — making a log
  server's ordering verifiable without trusting it — and it is deliberately not built: the corpus is
  honest that choosing relays and peers is a trust decision (see _Authority currency_ above), and
  this bullet names the standard construction that trust decision declines. (Content chains sit
  outside the risk: their order converges by deterministic head selection over signed operations,
  so no relay's admission order is load-bearing for them.)
- **No end-to-end encryption.** Content confidentiality is an application-layer concern;
  the relay operator can read stored blobs (README.md, `README.md`; PROTOCOL.md
  "Overview", `specs/PROTOCOL.md`; RELAY.md "Content plane", `specs/RELAY.md`).
- **No protocol-layer rate limiting.** Anti-spam / rate limiting is an operational concern,
  pushed to the deployment layer (RELAY.md "Not defined here", `specs/RELAY.md`).
  Blob size limits are likewise unenforced by the protocol (`specs/RELAY.md`).
- **Public (`aud: "*"`) write credential is a world-writable bearer.** Because `aud: "*"`
  matches any signer, a public credential granting `write` authorizes the _bearer_, not a
  named audience — anyone can attach it inline and write to the covered chains. Public
  credentials SHOULD be read-scoped (CREDENTIALS.md "Security: `aud: "*"` + write",
  `specs/CREDENTIALS.md`).
- **Within-window replay of an identical proven request.** A request proof replays only
  as the byte-identical request, against the same host, inside the verifier-owned
  freshness window — the accepted bound for read-shaped surfaces (INTEGRATIONS.md "API security
  notes", `specs/INTEGRATIONS.md`). Write-shaped relay surfaces (ingestion, blob
  upload) close even that with the REQUIRED `jti` replay cache (RELAY.md
  "Admission", `specs/RELAY.md`).
- **SIWD security controls live in the relying party.** Replay prevention (nonce),
  redirect-URI validation, challenge-DID binding, and timestamp windows are obligations
  on the verifying third party — no relay and no signer can enforce them on its behalf.
  The client library ships a conforming path (`createSiwdLoginRequest`,
  `readSiwdCallback`, `verifySiwd` in
  [`@metalabel/dfos-client/siwd`](https://www.npmjs.com/package/@metalabel/dfos-client)); a
  relying party that hand-rolls verification instead forfeits these controls silently,
  and nothing on the wire reveals that it did (INTEGRATIONS.md "Replay prevention",
  `specs/INTEGRATIONS.md`).
- **Loopback client provenance is unverifiable.** The loopback credential tier proves
  ask-time control of the client identity's keys, never what the software is: malicious
  local software holding its own legitimately minted DID passes every check the tier
  defines. The accepted controls are honest consent language (the host is required to say
  origin and authorship are unverifiable) and the hard credential-expiry ceiling — not
  provenance, which no loopback flow can establish (INTEGRATIONS.md "Loopback clients" /
  "Consent provenance", `specs/INTEGRATIONS.md`).
- **Cursor validation is a cheap membership signal over already-public sets.** The
  list routes' 400-on-unknown-cursor answers "does this relay hold X at this position"
  with one status code — information already derivable by paging the same public
  enumeration, so no new disclosure, but a lower-cost probe than the enumeration it
  shortcuts (RELAY.md "Error body", `specs/RELAY.md`).
- **The signing-mailbox courier reads pending payloads, and bundle deposits admit on
  depositor-attested state** (the signing mailbox is an optional capability,
  default-off; listed here because it adds adversary surface wherever enabled). A relay
  serving `capabilities.signing` can read every pending sign-request payload in the
  clear, and a deposit `chain` bundle for a
  foreign requester can hide a rotation, deletion, or revocation from the **relay** — a
  chain prefix verifies, and head-ness is unprovable from the chain alone. The exposure
  is bounded to **relay spam-admission** by the subject-rooted, expiring deposit
  credential; integrity holds at the signer, which independently re-resolves the
  requester to current state (RELAY.md "Courier, not ledger"; the bundle
  trust-boundary paragraphs under "POST /signing/v0/requests", `specs/RELAY.md`).

---

## Out of Scope

Mirroring [SECURITY.md](../SECURITY.md) "Scope": out of scope are vulnerabilities in
third-party dependencies (report upstream), and any issue that requires a compromised
host or a user's own private keys (`SECURITY.md` "Scope"). A compromised custody/KMS
key and a lost key are _modeled_ above as adversary classes for completeness, but their
_remediation_ (key hygiene, custody choice) is outside the protocol's integrity
guarantees. In scope for security reporting is anything that breaks integrity,
authenticity, or authorization — signing, JWS construction/verification, dag-cbor
canonical encoding, CID derivation, chain state-machine transitions, credential
verification, and relay auth (see SECURITY.md).
