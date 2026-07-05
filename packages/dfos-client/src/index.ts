/*

  @metalabel/dfos-client

  The missing high-level TS client. The protocol lib owns the crypto truth
  (folds, CID re-derive, sig verify); this client owns the four things it
  deliberately refuses to do: fetch, resolve, verify-orchestration, cache. If a
  fifth concern shows up here, it is probably wrong. If verification logic
  appears in this package, that is the bug.

*/

export { createClient, resolvers } from './client';
export { createRevocationChecker } from './revocation';
export { memoryStore } from './store/memory';

export type {
  Callbacks,
  CallOptions,
  Client,
  ClientConfig,
  DocumentBlob,
  GlobalLogOptions,
  GlobalLogPage,
  IndexCapabilities,
  IndexContentPage,
  IndexContentRow,
  IndexCountersignatureRow,
  IndexCountersignaturesPage,
  IndexIdentitiesPage,
  IndexIdentityProfile,
  IndexIdentityRow,
  LogOp,
  Provenance,
  RelayHealth,
  RelayResponse,
  Resolution,
  Resolved,
  ResolvedContent,
  ResolvedCredential,
  RevChecker,
  Store,
  Trust,
  UnverifiableAxis,
  VerifyResult,
} from './types';
