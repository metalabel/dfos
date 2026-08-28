export { bootstrapRelayIdentity, bootstrapRelayIdentityFromKey } from './bootstrap';
export { createHttpPeerClient } from './peer-client';
export { createRelay, chunkOps, type CreatedRelay } from './relay';
export {
  isValidDfosDid,
  identityToDidDocument,
  resolveDidDocument,
  type DidDocument,
  type DidVerificationMethod,
  type DidServiceEntry,
  type DidDocumentMetadata,
  type DidResolutionResult,
} from './did-document';
export {
  isValidCredentialCid,
  credentialRevocationStatus,
  issuerRevocationList,
  REVOCATIONS_BASE_PATH,
  type CredentialRevocationStatus,
  type IssuerRevocationEntry,
  type IssuerRevocationList,
} from './revocations';
export {
  INDEX_BASE_PATH,
  identityIndexRow,
  contentIndexRow,
  creditIndexRows,
  countersignatureIndexRow,
  type IndexContentRow,
  type IndexCreditRow,
  type IndexCountersignatureRow,
  type IndexCredentialRow,
  type IndexIdentityRow,
  type IndexOperationRow,
  type IndexArtifactRow,
  type IndexRecencyOrder,
  type IndexProfile,
} from './index-routes';
export { MemoryRelayStore } from './store';
export {
  ingestOperations,
  createKeyResolver,
  createCurrentKeyResolver,
  createHistoricalIdentityResolver,
} from './ingest';
export { sequenceOps, isDependencyFailure, computeOpCID } from './sequencer';
export {
  authenticateIdentityProof,
  createCurrentStateProofResolver,
  createJtiReplayCache,
  hasPublicStandingAuth,
  verifyContentAccess,
  DEFAULT_PROOF_SKEW_SECONDS,
  DEFAULT_PROOF_WINDOW_SECONDS,
  MAX_JTI_BYTES,
  type AuthenticatedPrincipal,
  type IdentityProofOutcome,
  type JtiReplayCache,
} from './auth';
export { INGESTION_MODES } from './types';
export type {
  AdmissionPolicy,
  GossipProofSigner,
  IngestionMode,
  RelayIdentity,
  RelayOpenApiOption,
  RelayOptions,
  RelayStore,
  RelayPeerInfo,
  RelayStats,
  StoredIdentityChain,
  StoredContentChain,
  StoredOperation,
  StoredCountersignature,
  StoredRevocation,
  StoredSignRequest,
  SigningPutResult,
  SigningDeclineResult,
  BlobKey,
  LogEntry,
  OperationKind,
  IngestionResult,
  SequenceResult,
  PeerConfig,
  PeerClient,
  PeerLogEntry,
} from './types';
