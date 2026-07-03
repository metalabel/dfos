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

/**
 * Fetch bytes from an untrusted host with a HARD cap enforced during the
 * stream, not after. The content-length header is a hint a hostile host can
 * omit or forge, so we also count bytes as they arrive and abort the moment the
 * cap is exceeded — never materializing an unbounded body into tab memory.
 * Returns null on any failure (non-ok, over-cap, network) — callers treat a
 * null as "no verifiable bytes", never as an error to surface.
 */
export const fetchBoundedBytes = async (
  url: string,
  maxBytes: number,
  timeoutMs = 20000,
): Promise<{ bytes: Uint8Array; mediaType: string } | null> => {
  try {
    const res = await fetch(url, { mode: 'cors', signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    if (Number(res.headers.get('content-length') ?? '0') > maxBytes) return null;
    const mediaType = res.headers.get('content-type') ?? '';
    const reader = res.body?.getReader();
    if (!reader) {
      const buf = new Uint8Array(await res.arrayBuffer());
      return buf.length > maxBytes ? null : { bytes: buf, mediaType };
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return { bytes, mediaType };
  } catch {
    return null;
  }
};

/**
 * A relay-controlled href/uri is only safe to render as a clickable/fetchable
 * link if it is http(s). Anything else — notably `javascript:` and `data:` —
 * is rejected to `null` so it can never reach an anchor href or a fetch.
 */
export const safeHttpUrl = (value: string | undefined): string | null => {
  if (!value) return null;
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.toString() : null;
  } catch {
    return null;
  }
};
