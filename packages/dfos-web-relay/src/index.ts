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
  type IndexContentRow,
  type IndexCountersignatureRow,
  type IndexIdentityRow,
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
export type {
  RelayIdentity,
  RelayOptions,
  RelayStore,
  RelayPeerInfo,
  RelayStats,
  StoredIdentityChain,
  StoredContentChain,
  StoredOperation,
  StoredCountersignature,
  StoredRevocation,
  BlobKey,
  LogEntry,
  OperationKind,
  IngestionResult,
  SequenceResult,
  PeerConfig,
  PeerClient,
  PeerLogEntry,
} from './types';
