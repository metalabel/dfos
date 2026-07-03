import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchBoundedBytes } from '../src/lib/media';

const chunk = (n: number): Uint8Array => new Uint8Array(n);

/** Minimal Response stub with a streaming body reader. */
const mkRes = (opts: {
  ok?: boolean;
  contentLength?: string | null;
  contentType?: string;
  chunks?: Uint8Array[];
}) => {
  const chunks = opts.chunks ?? [];
  let i = 0;
  let cancelled = false;
  return {
    ok: opts.ok ?? true,
    headers: {
      get: (k: string) =>
        k === 'content-length'
          ? (opts.contentLength ?? null)
          : k === 'content-type'
            ? (opts.contentType ?? '')
            : null,
    },
    body: {
      getReader: () => ({
        read: async () =>
          !cancelled && i < chunks.length
            ? { done: false, value: chunks[i++] }
            : { done: true, value: undefined },
        cancel: async () => {
          cancelled = true;
        },
      }),
    },
    arrayBuffer: async () => {
      const total = chunks.reduce((n, c) => n + c.length, 0);
      const b = new Uint8Array(total);
      let o = 0;
      for (const c of chunks) {
        b.set(c, o);
        o += c.length;
      }
      return b.buffer;
    },
  };
};

const stubFetch = (res: unknown): void => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => res),
  );
};

afterEach(() => vi.unstubAllGlobals());

describe('fetchBoundedBytes', () => {
  it('returns bytes under the cap with the media type', async () => {
    stubFetch(mkRes({ contentType: 'image/png', chunks: [chunk(100), chunk(100)] }));
    const out = await fetchBoundedBytes('https://host/x', 1000);
    expect(out?.bytes.length).toBe(200);
    expect(out?.mediaType).toBe('image/png');
  });

  it('rejects when the declared content-length exceeds the cap (no download)', async () => {
    stubFetch(mkRes({ contentLength: '999999', chunks: [chunk(10)] }));
    expect(await fetchBoundedBytes('https://host/x', 1000)).toBeNull();
  });

  it('aborts mid-stream when actual bytes exceed the cap despite an absent/forged content-length', async () => {
    // no content-length header, but the stream delivers well over the cap
    stubFetch(mkRes({ contentLength: null, chunks: [chunk(600), chunk(600)] }));
    expect(await fetchBoundedBytes('https://host/x', 1000)).toBeNull();
  });

  it('returns null on a non-ok response', async () => {
    stubFetch(mkRes({ ok: false }));
    expect(await fetchBoundedBytes('https://host/x', 1000)).toBeNull();
  });

  it('returns null on a thrown fetch', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('network');
      }),
    );
    expect(await fetchBoundedBytes('https://host/x', 1000)).toBeNull();
  });
});
