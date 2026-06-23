/*

  SERVICES

  Discovery vocabulary carried in identity-chain state. Helpers for resolving
  service entries — classifying a ContentAnchor's target by structural form.

  An anchor references a STABLE content identifier, dispatched by shape:

    31-char contentId (alphabet 2346789acdefhknrtvz) → content chain (mutable, gateable)
    59-char CIDv1 dag-cbor+sha256 ("bafyrei…")       → artifact (immutable, public)

  A chain HEAD CID is also a bafyrei CID but is NOT a stable anchor: it dispatches to
  'artifact', and artifact resolution requires the fetched op to be type:"artifact"
  — a head CID resolves to a non-artifact op and is rejected. So "never anchor a
  head CID" holds without a mode flag.

*/

import { dagCborCanonicalEncode } from '../crypto';
import {
  ARTIFACT_CID_ANCHOR_RE,
  CONTENT_ID_ANCHOR_RE,
  MAX_SERVICES_PAYLOAD_SIZE,
  type ServiceEntry,
} from './schemas';

export type AnchorKind = 'chain' | 'artifact' | 'invalid';

/**
 * Enforce the services byte cap on the CBOR-encoded array — same encoding the
 * wire uses, so the bound is identical across implementations. Mirrors the
 * artifact payload size check.
 */
export const assertServicesWithinCap = async (services: ServiceEntry[]): Promise<void> => {
  const encoded = await dagCborCanonicalEncode(services);
  if (encoded.bytes.length > MAX_SERVICES_PAYLOAD_SIZE) {
    throw new Error(
      `services payload exceeds max size: ${encoded.bytes.length} > ${MAX_SERVICES_PAYLOAD_SIZE}`,
    );
  }
};

/**
 * Classify a ContentAnchor target by structural form. Resolvers dispatch on the
 * result: 'chain' → resolve a content chain by contentId; 'artifact' → fetch by
 * CID and require type:"artifact"; 'invalid' → reject (e.g. a bare head CID is
 * 'artifact'-shaped but fails the resolution-time type check).
 */
export const classifyAnchor = (anchor: string): AnchorKind => {
  if (CONTENT_ID_ANCHOR_RE.test(anchor)) return 'chain';
  if (ARTIFACT_CID_ANCHOR_RE.test(anchor)) return 'artifact';
  return 'invalid';
};

/** Recognized (core-blessed) service types. All other types are valid but opaque. */
export const RECOGNIZED_SERVICE_TYPES = ['DfosRelay', 'ContentAnchor'] as const;

/** Whether the core assigns structural semantics to this service type. */
export const isRecognizedServiceType = (type: string): boolean =>
  (RECOGNIZED_SERVICE_TYPES as readonly string[]).includes(type);

/** Select the DfosRelay transport endpoints from a services set, in entry order. */
export const relayEndpoints = (services: ServiceEntry[]): string[] =>
  services
    .filter((e) => e.type === 'DfosRelay')
    .map((e) => (e as Record<string, unknown>)['endpoint'])
    .filter((v): v is string => typeof v === 'string');

/** Select ContentAnchor entries matching a client label (e.g. "profile"). */
export const anchorsByLabel = (services: ServiceEntry[], label: string): ServiceEntry[] =>
  services.filter(
    (e) => e.type === 'ContentAnchor' && (e as Record<string, unknown>)['label'] === label,
  );
