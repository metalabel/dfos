/*

  MEDIA OBJECT — {uri, cid?, href?}

  Per CONTENT-MODEL: `uri` is the identity (often an opaque host-scoped
  attachment:// ref), `cid` is the integrity commitment (CIDv1 / raw 0x55 /
  sha2-256 / base32), `href` is a non-normative fetch hint. When bytes are
  reachable via href, the cid is re-derivable in the tab — that's the whole
  point of carrying it.

*/

import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';

const RAW_CODEC = 0x55;

export interface MediaObject {
  uri: string;
  cid?: string;
  href?: string;
}

/** CIDv1 / raw / sha2-256 over the bytes exactly as served. */
export const rawCidOf = async (bytes: Uint8Array): Promise<string> => {
  const digest = await sha256.digest(bytes);
  return CID.createV1(RAW_CODEC, digest).toString();
};

export const parseMediaObject = (value: unknown): MediaObject | null => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const rec = value as Record<string, unknown>;
  if (typeof rec['uri'] !== 'string' || rec['uri'].length === 0) return null;
  const media: MediaObject = { uri: rec['uri'] };
  if (typeof rec['cid'] === 'string') media.cid = rec['cid'];
  if (typeof rec['href'] === 'string') media.href = rec['href'];
  return media;
};

export const isAttachmentUri = (uri: string): boolean => uri.startsWith('attachment://');
