/*

  INDEX (v0)

  Read-only, non-authoritative projections over relay-held identity chains,
  content chains, and countersignatures. Rows are hints: clients re-derive
  authority from the proof plane.

*/

import type { Attenuation } from '@metalabel/dfos-protocol/credentials';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { hasPublicStandingAuth } from './auth';
import type {
  OperationKind,
  RelayStore,
  StoredContentChain,
  StoredCountersignature,
  StoredIdentityChain,
} from './types';

export const INDEX_BASE_PATH = '/index/v0';

const CONTENT_ID_RE = /^[2346789acdefhknrtvz]{31}$/;
const PROFILE_SCHEMA = 'https://schemas.dfos.com/profile/v1';
const POST_SCHEMA = 'https://schemas.dfos.com/post/v1';

export type IndexOrder = 'genesisAt.desc' | 'headAt.desc';
export type IndexRecencyOrder = 'createdAt.desc' | 'ingestedAt.desc';

export interface IndexOrderedCursor {
  timestamp: string;
  key: string;
}

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
  title: string | null;
}

export interface IndexCreditRow {
  contentId: string;
  did: string;
  role: string | null;
  position: number;
  hasClaim: boolean;
}

export interface IndexCreditCursor {
  contentId: string;
  position: number;
}

export interface IndexCountersignatureRow {
  cid: string;
  targetCID: string;
  relation: string | null;
  jwsToken: string;
}

export interface IndexCountersignatureQueryRow extends IndexCountersignatureRow {
  createdAt: string;
  ingestedAt: string;
}

export interface IndexOperationRow {
  cid: string;
  kind: OperationKind;
  chainId: string;
  createdAt: string;
  ingestedAt: string;
}

export interface IndexArtifactRow {
  cid: string;
  signerDID: string;
  createdAt: string;
  ingestedAt: string;
  docSchema: string | null;
}

export interface IndexCredentialRow {
  cid: string;
  issuerDID: string;
  aud: '*';
  att: Attenuation[];
  exp: number;
  jwsToken: string;
}

export interface IndexCredentialQueryRow extends IndexCredentialRow {
  createdAt: string;
  ingestedAt: string;
}

export const parseBooleanQuery = (raw: string | undefined): boolean | undefined | null => {
  if (raw === undefined) return undefined;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  return null;
};

export const parseIndexOrder = (raw: string | undefined): IndexOrder | undefined | null => {
  if (raw === undefined || raw === '') return undefined;
  if (raw === 'genesisAt.desc' || raw === 'headAt.desc') return raw;
  return null;
};

export const parseIndexRecencyOrder = (
  raw: string | undefined,
  defaultOrder?: IndexRecencyOrder,
): IndexRecencyOrder | undefined | null => {
  if (raw === undefined || raw === '') return defaultOrder;
  if (raw === 'createdAt.desc' || raw === 'ingestedAt.desc') return raw;
  return null;
};

export const encodeIndexOrderedCursor = (timestamp: string, key: string): string =>
  Buffer.from(`${timestamp}~${key}`, 'utf8').toString('base64url');

export const decodeIndexOrderedCursor = (raw: string): IndexOrderedCursor | null => {
  try {
    const bytes = Buffer.from(raw, 'base64url');
    // canonicality round-trip: reject non-canonical encodings (padding,
    // whitespace) so both twins agree on exactly which cursors are valid
    if (bytes.toString('base64url') !== raw) return null;
    const decoded = bytes.toString('utf8');
    const sep = decoded.indexOf('~');
    if (sep <= 0 || sep !== decoded.lastIndexOf('~') || sep === decoded.length - 1) return null;
    const timestamp = decoded.slice(0, sep);
    const key = decoded.slice(sep + 1);
    if (!/^\d{4}-\d{2}-\d{2}T/.test(timestamp)) return null;
    return { timestamp, key };
  } catch {
    return null;
  }
};

export const encodeIndexCreditCursor = (contentId: string, position: number): string =>
  Buffer.from(`${contentId}~${position}`, 'utf8').toString('base64url');

export const decodeIndexCreditCursor = (raw: string): IndexCreditCursor | null => {
  try {
    const bytes = Buffer.from(raw, 'base64url');
    if (bytes.toString('base64url') !== raw) return null;
    const decoded = bytes.toString('utf8');
    const sep = decoded.indexOf('~');
    if (sep <= 0 || sep !== decoded.lastIndexOf('~') || sep === decoded.length - 1) return null;
    const contentId = decoded.slice(0, sep);
    const positionRaw = decoded.slice(sep + 1);
    if (!CONTENT_ID_RE.test(contentId) || !/^(0|[1-9]\d*)$/.test(positionRaw)) return null;
    const position = Number(positionRaw);
    if (!Number.isSafeInteger(position)) return null;
    return { contentId, position };
  } catch {
    return null;
  }
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
  const { doc, docSchema, publicRead } = await contentProjectionSources(chain, store);
  // Confidentiality is enforced at the application layer by whoever serves: a
  // non-public document MUST NOT project its extracted display-name field onto
  // the anonymous index surface. Compute publicRead first and gate title on it.
  const title =
    publicRead &&
    docSchema === POST_SCHEMA &&
    doc &&
    typeof doc['title'] === 'string' &&
    doc['title'].length > 0
      ? doc['title']
      : null;
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
    publicRead,
    docSchema,
    title,
  };
};

/** Complete public-head credit projection for one content chain. */
export const creditIndexRows = async (
  chain: StoredContentChain,
  store: RelayStore,
): Promise<IndexCreditRow[]> => {
  const { doc, docSchema, publicRead } = await contentProjectionSources(chain, store);
  if (chain.state.isDeleted || !publicRead || docSchema !== POST_SCHEMA || !doc) return [];
  const credits = doc['credits'];
  if (!Array.isArray(credits)) return [];

  const rows: IndexCreditRow[] = [];
  for (let position = 0; position < credits.length; position++) {
    const entry = credits[position];
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const credit = entry as Record<string, unknown>;
    if (typeof credit['did'] !== 'string') continue;
    rows.push({
      contentId: chain.contentId,
      did: credit['did'],
      role: typeof credit['role'] === 'string' ? credit['role'] : null,
      position,
      hasClaim: typeof credit['claim'] === 'string',
    });
  }
  return rows;
};

/**
 * Strip the extracted display-name field from a non-public identity row before
 * serialization — defense in depth against a row persisted by a pre-gate builder
 * (the current builder already withholds it). Returns a fresh row/profile so it
 * never mutates a shared in-memory projection row.
 */
export const redactNonPublicIdentityRow = (row: IndexIdentityRow): IndexIdentityRow =>
  row.profile && !row.profile.publicRead && row.profile.name !== null
    ? { ...row, profile: { ...row.profile, name: null } }
    : row;

/**
 * Strip the extracted title from a non-public content row before serialization —
 * the content-side twin of the identity redaction.
 */
export const redactNonPublicContentRow = (row: IndexContentRow): IndexContentRow =>
  !row.publicRead && row.title !== null ? { ...row, title: null } : row;

export const countersignatureIndexRow = (
  row: StoredCountersignature,
): IndexCountersignatureRow => ({
  cid: row.cid,
  targetCID: row.targetCID,
  relation: row.relation,
  jwsToken: row.jwsToken,
});

export const artifactIndexRow = (
  cid: string,
  jwsToken: string,
  ingestedAt: string,
): IndexArtifactRow | null => {
  const decoded = decodeJwsUnsafe(jwsToken);
  if (!decoded) return null;
  const kid = typeof decoded.header.kid === 'string' ? decoded.header.kid : '';
  const signerDID = kid.includes('#') ? kid.slice(0, kid.indexOf('#')) : kid;
  const payload = decoded.payload as Record<string, unknown>;
  const content = payload['content'];
  const docSchema =
    content !== null && typeof content === 'object' && !Array.isArray(content)
      ? typeof (content as Record<string, unknown>)['$schema'] === 'string'
        ? ((content as Record<string, unknown>)['$schema'] as string)
        : null
      : null;
  const createdAt = typeof payload['createdAt'] === 'string' ? payload['createdAt'] : '';
  if (!signerDID || !createdAt) return null;
  return { cid, signerDID, createdAt, ingestedAt, docSchema };
};

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
  // Confidentiality is enforced at the application layer by whoever serves: a
  // non-public profile document MUST NOT project its extracted name onto the
  // anonymous index surface. Compute publicRead first and gate name on it.
  const publicRead = await hasPublicStandingAuth(anchor, 'read', store);
  const name =
    publicRead &&
    docSchema === PROFILE_SCHEMA &&
    doc &&
    typeof doc['name'] === 'string' &&
    doc['name'].length > 0
      ? doc['name']
      : null;

  return {
    anchor,
    publicRead,
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

const contentProjectionSources = async (
  chain: StoredContentChain,
  store: RelayStore,
): Promise<{
  doc: Record<string, unknown> | null;
  docSchema: string | null;
  publicRead: boolean;
}> => {
  const { doc, docSchema } = await headDocumentProjection(chain, store);
  const publicRead = await hasPublicStandingAuth(chain.contentId, 'read', store);
  return { doc, docSchema, publicRead };
};

const createdAtOf = (jwsToken: string | undefined): string => {
  if (!jwsToken) return '';
  const createdAt = decodeJwsUnsafe(jwsToken)?.payload?.createdAt;
  return typeof createdAt === 'string' ? createdAt : '';
};
