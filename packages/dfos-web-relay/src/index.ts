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
  StoredIdentityChain,
  StoredContentChain,
  StoredOperation,
  BlobKey,
  LogEntry,
  OperationKind,
  IngestionResult,
  SequenceResult,
  PeerConfig,
  PeerClient,
  PeerLogEntry,
} from './types';
