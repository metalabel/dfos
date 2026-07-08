/*

  OP PAYLOAD ANNOTATIONS — field-level teaching notes for the op view

  Each note explains what a payload field MEANS in the protocol, in the words
  of this protocol (no blockchain analogies). Rendering stays in the view;
  this is just the vocabulary.

*/

export const PAYLOAD_NOTES: Record<string, string> = {
  previousOperationCID: 'the parent op — this link IS the chain',
  documentCID: 'content-plane pointer — the hash the bytes must produce',
  baseDocumentCID: "edit base — normally the prior op's documentCID",
  authKeys: 'full replacement of this role set, not a delta',
  assertKeys: 'full replacement of this role set, not a delta',
  controllerKeys: 'full replacement of this role set, not a delta',
  services: 'discovery vocabulary — full replacement (omit = clear)',
  createdAt: 'self-asserted signing time; chain order comes from prev-links, not this clock',
  targetCID: 'the operation this statement witnesses',
  relation: 'open-namespace tag naming the witness relation',
  credentialCID: 'the credential this revocation permanently invalidates',
  authorization:
    "a non-creator signer's delegated-write credential — its chain must root at the content creator",
};

/** Operation kinds by JWS envelope typ. */
export const KIND_OF_TYP: Record<string, string> = {
  'did:dfos:identity-op': 'identity-op',
  'did:dfos:content-op': 'content-op',
  'did:dfos:credential': 'credential',
  'did:dfos:countersign': 'countersign',
  'did:dfos:artifact': 'artifact',
  'did:dfos:revocation': 'revocation',
};
