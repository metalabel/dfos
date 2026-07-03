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
    def: 'Discovery vocabulary in identity state: DfosRelay entries advertise a relay endpoint holding this identity’s data; ContentAnchor entries pin a stable contentId or artifact CID (e.g. a profile).',
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
    key: 'localIndex',
    term: 'local index',
    def: 'Your browser’s own copy of every operation it has synced from relay logs, stored in IndexedDB — chains fold offline from it, and it persists across visits.',
  },
];

export const GLOSSARY: Record<string, string> = Object.fromEntries(
  GLOSSARY_TERMS.map((t) => [t.key, t.def]),
);
