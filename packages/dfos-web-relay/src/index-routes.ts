/*

  INDEX (v0)

  Read-only, non-authoritative projections over relay-held identity chains,
  content chains, and countersignatures. Rows are hints: clients re-derive
  authority from the proof plane.

*/

import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { hasPublicStandingAuth } from './auth';
import type {
  RelayStore,
  StoredContentChain,
  StoredCountersignature,
  StoredIdentityChain,
} from './types';

export const INDEX_BASE_PATH = '/index/v0';

const CONTENT_ID_RE = /^[2346789acdefhknrtvz]{31}$/;
const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';

export interface IndexProfile {
  anchor: string;
  publicRead: boolean;
  docSchema: string | null;
  name: string | null;
}

export interface IndexIdentityRow {
  did: string;
  headCID: string;
  opCount: number;
  genesisAt: string;
  headAt: string;
  isDeleted: boolean;
  profile: IndexProfile | null;
}

export interface IndexContentRow {
  contentId: string;
  genesisCID: string;
  headCID: string;
  creatorDID: string;
  isDeleted: boolean;
  opCount: number;
  genesisAt: string;
  headAt: string;
  currentDocumentCID: string | null;
  publicRead: boolean;
  docSchema: string | null;
}

export interface IndexCountersignatureRow {
  cid: string;
  targetCID: string;
  relation: string | null;
  jwsToken: string;
}

export const parseBooleanQuery = (raw: string | undefined): boolean | undefined => {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return undefined;
};

export const identityIndexRow = async (
  chain: StoredIdentityChain,
  store: RelayStore,
): Promise<IndexIdentityRow> => {
  const profile = await profileProjection(chain, store);
  return {
    did: chain.did,
    headCID: chain.headCID,
    opCount: chain.log.length,
    genesisAt: createdAtOf(chain.log[0]),
    headAt: chain.lastCreatedAt,
    isDeleted: chain.state.isDeleted,
    profile,
  };
};

export const contentIndexRow = async (
  chain: StoredContentChain,
  store: RelayStore,
): Promise<IndexContentRow> => {
  const { docSchema } = await headDocumentProjection(chain, store);
  return {
    contentId: chain.contentId,
    genesisCID: chain.genesisCID,
    headCID: chain.state.headCID,
    creatorDID: chain.state.creatorDID,
    isDeleted: chain.state.isDeleted,
    opCount: chain.log.length,
    genesisAt: createdAtOf(chain.log[0]),
    headAt: chain.lastCreatedAt,
    currentDocumentCID: chain.state.currentDocumentCID,
    publicRead: await hasPublicStandingAuth(chain.contentId, 'read', store),
    docSchema,
  };
};

export const countersignatureIndexRow = (
  row: StoredCountersignature,
): IndexCountersignatureRow => ({
  cid: row.cid,
  targetCID: row.targetCID,
  relation: row.relation,
  jwsToken: row.jwsToken,
});

const profileProjection = async (
  chain: StoredIdentityChain,
  store: RelayStore,
): Promise<IndexProfile | null> => {
  const candidates = chain.state.services.filter((service) => {
    const entry = service as Record<string, unknown>;
    return (
      entry['type'] === 'ContentAnchor' &&
      typeof entry['label'] === 'string' &&
      entry['label'].toLowerCase() === 'profile' &&
      typeof entry['anchor'] === 'string' &&
      CONTENT_ID_RE.test(entry['anchor'])
    );
  });
  candidates.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const service = candidates[0] as Record<string, unknown> | undefined;
  const anchor = typeof service?.['anchor'] === 'string' ? service['anchor'] : null;
  if (!anchor) return null;

  const content = await store.getContentChain(anchor);
  const { doc, docSchema } = content
    ? await headDocumentProjection(content, store)
    : { doc: null, docSchema: null };
  const name =
    docSchema === PROFILE_SCHEMA && doc && typeof doc['name'] === 'string' && doc['name'].length > 0
      ? doc['name']
      : null;

  return {
    anchor,
    publicRead: await hasPublicStandingAuth(anchor, 'read', store),
    docSchema,
    name,
  };
};

const headDocumentProjection = async (
  chain: StoredContentChain,
  store: RelayStore,
): Promise<{ doc: Record<string, unknown> | null; docSchema: string | null }> => {
  const documentCID = chain.state.currentDocumentCID;
  if (!documentCID) return { doc: null, docSchema: null };

  const blob = await store.getBlob({ creatorDID: chain.state.creatorDID, documentCID });
  if (!blob) return { doc: null, docSchema: null };

  try {
    const decoded = JSON.parse(new TextDecoder().decode(blob)) as unknown;
    if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) {
      return { doc: null, docSchema: null };
    }
    const doc = decoded as Record<string, unknown>;
    const docSchema = typeof doc['$schema'] === 'string' ? doc['$schema'] : null;
    return { doc, docSchema };
  } catch {
    return { doc: null, docSchema: null };
  }
};

const createdAtOf = (jwsToken: string | undefined): string => {
  if (!jwsToken) return '';
  const createdAt = decodeJwsUnsafe(jwsToken)?.payload?.createdAt;
  return typeof createdAt === 'string' ? createdAt : '';
};
