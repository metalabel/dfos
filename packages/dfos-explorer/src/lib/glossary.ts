/*

  GLOSSARY — wording matches THIS protocol's mechanics (no blockchain analogies)

*/

export interface GlossaryTerm {
  key: string;
  term: string;
  def: string;
}

export const GLOSSARY_TERMS: readonly GlossaryTerm[] = [
  {
    key: 'operation',
    term: 'operation',
    def: 'A single signed JWS statement whose CID is the SHA-256 of its own canonical dag-cbor bytes — the atom every chain is built from.',
  },
  {
    key: 'chain',
    term: 'chain',
    def: 'An append-only linked list of operations, each naming its parent by CID and signed by a current key; identity chains are self-sovereign, content chains are owned by a creator DID.',
  },
  {
    key: 'cid',
    term: 'CID',
    def: 'Content identifier: the dag-cbor bytes hashed with SHA-256 and wrapped as a CIDv1 (bafyrei…); identical bytes always produce the identical CID, so it both names and fingerprints the data.',
  },
  {
    key: 'dagcbor',
    term: 'dag-cbor',
    def: 'The one canonical binary encoding operations are hashed in — deterministic (sorted keys, bounded integers, no floats) so every implementation computes byte-identical CIDs.',
  },
  {
    key: 'did',
    term: 'DID',
    def: 'did:dfos: + the hash of the genesis operation’s CID; the identifier is derived from its own first op, so no registry issues it and holding the controller key is the only authority.',
  },
  {
    key: 'head',
    term: 'head',
    def: 'The current tip of a chain; when forks exist every implementation selects the same head — highest createdAt, ties broken by highest CID — so the same op set yields the same head regardless of arrival order.',
  },
  {
    key: 'keyRoles',
    term: 'key roles',
    def: 'An identity separates keys by use: controller keys sign the chain’s own operations and rotate keys, auth keys authenticate to services, assert keys sign statements (content ops, credentials, countersignatures).',
  },
  {
    key: 'services',
    term: 'services',
    def: 'Discovery vocabulary in identity state: DfosRelay entries advertise a relay endpoint holding this identity’s data; ContentAnchor entries pin a stable contentId or artifact CID (e.g. a profile); DfosAuthorizationServer entries name the server where this identity’s person signs in, so a client holding only the DID can find it. The vocabulary is open — an unrecognized type is still a legible claim, just one this explorer has no special reading for.',
  },
  {
    key: 'originBinding',
    term: 'origin binding',
    def: 'A bidirectional binding between an identity and a web domain: a DfosOrigin services entry names the domain on the signed chain, and the domain attests the DID back at /.well-known/dfos-did or in a _dfos TXT record. It proves control of that domain — never personhood or endorsement.',
  },
  {
    key: 'bindingBound',
    term: 'bound (origin binding)',
    def: 'Domain confirms it: the domain answered back with exactly this identity’s DID, over HTTPS or DNS.',
  },
  {
    key: 'bindingStale',
    term: 'stale (origin binding)',
    def: 'Domain silent: the chain claims the domain, but the domain is not confirming it right now. Hosting and DNS fail and recover routinely — silence is not contradiction, and this is not a claim the binding is wrong.',
  },
  {
    key: 'bindingBroken',
    term: 'broken (origin binding)',
    def: 'Domain contradicts it: the domain answered with a different identity’s DID. Only the domain claim is contradicted — the identity and its history are untouched.',
  },
  {
    key: 'appDescription',
    term: 'app description',
    def: 'The document at /.well-known/dfos-app.json: a domain describes an app (name, client DID, optionally its identity chain). Checked on the domain page. Distinct from the domain attestation.',
  },
  {
    key: 'domainAttestation',
    term: 'domain attestation',
    def: 'The answer at /.well-known/dfos-did or the _dfos DNS TXT record: a domain attests a DID back. Checked in the identity page’s origin-binding panel. Distinct from the app description.',
  },
  {
    key: 'relayDiverged',
    term: 'origin verified · relay log diverged',
    def: 'The chain the origin carries verifies here, and the relays’ ordered log for that same DID signs a different history — a signed contradiction from the relay side, not a lag. The origin’s half stands; the two logs cannot both be the whole story.',
  },
  {
    key: 'noCarriage',
    term: 'app document present · no chain carried',
    def: 'The origin serves a valid app description that omits identity_chain — legal, since the member is optional, but the origin alone then proves no DID. Nothing here is contradicted; nothing here is verified either.',
  },
  {
    key: 'logAheadBehindDiverged',
    term: 'ahead / behind / diverged',
    def: 'How the origin’s carried log relates to the relays’ log, positionally: ahead means the origin carries newer operations the relays have not ingested (benign lag); behind means the document has shed operations the relays still hold (a rollback signal); diverged means the two sides sign different operations at the same position (a signed contradiction). Only the last one accuses anybody.',
  },
  {
    key: 'artifact',
    term: 'artifact',
    def: 'A standalone signed immutable document addressed by its own CID, with no predecessor or successor — where a chain is a history, an artifact is a single fixed statement.',
  },
  {
    key: 'credential',
    term: 'credential',
    def: 'A UCAN-style JWS capability (typ: did:dfos:credential): the issuer grants an audience a set of attenuations (resource + action), optionally rooted through a single parent in prf.',
  },
  {
    key: 'creditClaim',
    term: 'credit claim',
    def: 'A claimant-signed document-plane JWS (typ: did:dfos:credit-claim) that binds its DID and byte-exact role to a content chain — independently agreeing with the document signer’s credit; attribution, not authorization.',
  },
  {
    key: 'attenuation',
    term: 'attenuation',
    def: 'One resource+action grant (e.g. chain:<id> / read); a delegated child’s attenuations must be a subset of its parent’s — scope only narrows down a delegation, never widens.',
  },
  {
    key: 'standingGrant',
    term: 'standing public-read grant',
    def: 'A public credential (aud: "*") with read access, ingested into a relay as standing authorization — this is what makes a content chain’s document bytes servable to anyone.',
  },
  {
    key: 'countersignature',
    term: 'countersignature',
    def: 'A standalone signed statement referencing another op by CID — "I, this DID, witness that op" — with an optional relation tag; the protocol’s only inter-subjective primitive.',
  },
  {
    key: 'revocation',
    term: 'revocation',
    def: 'A signed proof-plane artifact (typ: did:dfos:revocation) by which a credential’s own issuer permanently invalidates it — there is no un-revoke, you issue a new credential.',
  },
  {
    key: 'planes',
    term: 'proof plane vs content plane',
    def: 'The proof plane is the public, gossiped layer of signed chains anyone can verify with a public key; the content plane is the access-controlled document bytes a relay serves only to the authorized — the protocol commits to hashes, not plaintext.',
  },
  {
    key: 'verifiedLocal',
    term: 'verified locally vs relay-asserted',
    def: '"Verified locally" means your browser recomputed the signatures and CIDs itself and they matched; "relay-asserted" means the relay claims it and you are trusting its word.',
  },
  {
    key: 'noCanonical',
    term: 'no canonical state',
    def: 'There is no global truth — you are seeing one relay’s view of the operations it happens to hold, and another relay may hold a different or forked set.',
  },
  {
    key: 'quorum',
    term: 'quorum',
    def: 'How many relays independently returned byte-identical answers to the same read — agreement across an untrusted set is evidence of convergence, never proof of completeness.',
  },
  {
    key: 'index',
    term: 'index',
    def: 'A content chain whose documents are streams of set/remove deltas over content refs — folded into a last-write-wins map by the canonical fold, it is a signed, portable collection (a shelf, a blogroll, a catalog).',
  },
  {
    key: 'canonicalFold',
    term: 'canonical fold',
    def: 'The deterministic total order over ALL operations in a chain log — createdAt ascending, op-CID tiebreak, branch-INCLUSIVE — so every implementation folds the same op set to the identical result regardless of arrival order or forks.',
  },
  {
    key: 'media',
    term: 'media object',
    def: 'A {uri, cid?, href?} reference to bytes outside the proof plane: uri is the identity (often an opaque attachment:// ref), cid commits to the exact bytes (CIDv1/raw/sha2-256), href is a non-normative fetch hint — verify the bytes, never trust the host.',
  },
  {
    key: 'localIndex',
    term: 'local index',
    def: 'Your browser’s own copy of every operation it has synced from relay logs, stored in IndexedDB — chains fold offline from it, and it persists across visits.',
  },
  {
    key: 'publicProjection',
    term: 'public projection',
    def: 'A browse field (a content chain’s type, an identity’s name) materialized once at sync time by fetching the content-plane blob and re-hashing its bytes to the on-chain committed document CID — so browse is instant and offline, and only PUBLIC (anonymously served) documents ever appear.',
  },
  {
    key: 'attributed',
    term: 'attributed',
    def: 'A cheap discovery heuristic: a public profile is attributed to the DID that signed its content chain’s genesis op (author == subject by convention, not by proof). Browse rows are labelled "attributed"; open the identity to fold the rigorous services→anchor→profile proof.',
  },
  {
    key: 'indexLight',
    term: 'relay index (hints) vs audit sync',
    def: 'When a relay advertises an index, the explorer ALWAYS enumerates browse and home from it — instantly, and even after a deep sync, because the live index is fresher than any past sync. Every row is an ATTRIBUTED hint the relay asserts, promoted to VERIFIED as your tab folds that row’s chain (re-checking every signature and CID); the local index is a sparse verified cache that catches up to whatever you look at. An index cannot lie by assertion — a fabricated row fails the fold — but it CAN lie by omission, silently withholding rows you can never notice are missing. So a deep sync, which folds every operation locally, is the audit posture: the exhaustive stance that detects what an index leaves out.',
  },
];

export const GLOSSARY: Record<string, string> = Object.fromEntries(
  GLOSSARY_TERMS.map((t) => [t.key, t.def]),
);
