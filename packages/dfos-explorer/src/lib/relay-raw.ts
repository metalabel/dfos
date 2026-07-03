/*

  RAW RELAY READS — the relay-asserted beat

  Direct, untrusted GETs against the relay read surface. Everything returned
  here is a CLAIM: the UI renders it instantly, marked relay-asserted, and the
  dfos-client verification beat flips it to verified (or MISMATCH). These stay
  raw fetches on purpose — status classification (gated vs missing vs down) is
  part of the honest rendering, and the client deliberately doesn't do claims.

*/

const PROOF = '/proof/v1';

export interface ClaimResult {
  relay: string;
  status: number; // 0 = network error / no relay reachable
  gated: boolean; // 401/403 — exists but content-plane gated
  body?: Record<string, unknown>;
  error?: string;
}

const tryJson = async (url: string): Promise<Response> =>
  fetch(url, { mode: 'cors', signal: AbortSignal.timeout(10000) });

/** First relay that answers 2xx wins; otherwise the most informative failure. */
export const fetchClaim = async (
  kind: 'identities' | 'content',
  id: string,
  relays: string[],
): Promise<ClaimResult> => {
  let last: ClaimResult = { relay: '', status: 0, gated: false, error: 'no relay reachable' };
  for (const relay of relays) {
    try {
      const res = await tryJson(`${relay}${PROOF}/${kind}/${encodeURIComponent(id)}`);
      if (res.ok) {
        return {
          relay,
          status: res.status,
          gated: false,
          body: (await res.json()) as Record<string, unknown>,
        };
      }
      last = {
        relay,
        status: res.status,
        gated: res.status === 401 || res.status === 403,
        error: await res.text().catch(() => ''),
      };
    } catch (e) {
      last = {
        relay,
        status: 0,
        gated: false,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }
  return last;
};

/** Fetch a single operation's JWS from the first relay that serves it. */
export const fetchOpRaw = async (
  cid: string,
  relays: string[],
): Promise<{ relay: string; jwsToken: string } | null> => {
  for (const relay of relays) {
    try {
      const res = await tryJson(`${relay}${PROOF}/operations/${encodeURIComponent(cid)}`);
      if (!res.ok) continue;
      const body = (await res.json()) as unknown;
      const jwsToken =
        typeof body === 'string'
          ? body
          : typeof (body as Record<string, unknown>)['jwsToken'] === 'string'
            ? ((body as Record<string, unknown>)['jwsToken'] as string)
            : typeof (body as Record<string, unknown>)['jws'] === 'string'
              ? ((body as Record<string, unknown>)['jws'] as string)
              : null;
      if (jwsToken) return { relay, jwsToken };
    } catch {
      continue;
    }
  }
  return null;
};

/** Countersignatures targeting an op CID — a list of JWS tokens. */
export const fetchCountersigs = async (cid: string, relays: string[]): Promise<string[]> => {
  for (const relay of relays) {
    try {
      const res = await tryJson(
        `${relay}${PROOF}/operations/${encodeURIComponent(cid)}/countersignatures`,
      );
      if (!res.ok) continue;
      const body = (await res.json()) as { countersignatures?: unknown };
      if (Array.isArray(body.countersignatures))
        return body.countersignatures.filter((v): v is string => typeof v === 'string');
    } catch {
      continue;
    }
  }
  return [];
};

export interface RevocationFeedProbe {
  relay: string;
  /** 'live' = feed answered; 'absent' = 404/501 (relay predates the route); 'down' = unreachable */
  feed: 'live' | 'absent' | 'down';
  revoked: boolean;
  /** the self-proving revocation JWS when the relay returned one */
  revocation?: string;
}

/**
 * Probe each relay's /revocations/v1 credential-status route — for DISPLAY.
 * The trust decision lives in dfos-client's checker (which re-verifies any
 * positive proof); this exists so the UI can distinguish "no feed available
 * anywhere — a revocation would be invisible here" from "feeds consulted,
 * no revocation seen".
 */
export const probeRevocationFeeds = async (
  credentialCID: string,
  relays: string[],
): Promise<RevocationFeedProbe[]> => {
  return Promise.all(
    relays.map(async (relay): Promise<RevocationFeedProbe> => {
      try {
        const res = await tryJson(
          `${relay}/revocations/v1/credential/${encodeURIComponent(credentialCID)}`,
        );
        if (!res.ok) return { relay, feed: 'absent', revoked: false };
        const body = (await res.json()) as { revoked?: boolean; revocation?: string };
        return {
          relay,
          feed: 'live',
          revoked: body.revoked === true,
          ...(typeof body.revocation === 'string' ? { revocation: body.revocation } : {}),
        };
      } catch {
        return { relay, feed: 'down', revoked: false };
      }
    }),
  );
};

export interface BlobResult {
  relay: string;
  status: number; // 0 = network error
  gated: boolean;
  bytes?: Uint8Array;
  servedDocCid?: string;
  mediaType?: string;
}

/** Content-plane blob fetch with honest status classification. */
export const fetchBlobRaw = async (contentId: string, relays: string[]): Promise<BlobResult> => {
  let last: BlobResult = { relay: '', status: 0, gated: false };
  for (const relay of relays) {
    try {
      const res = await fetch(`${relay}/content/${encodeURIComponent(contentId)}/blob`, {
        mode: 'cors',
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const bytes = new Uint8Array(await res.arrayBuffer());
        const servedDocCid = res.headers.get('x-document-cid') ?? undefined;
        const mediaType = res.headers.get('content-type') ?? undefined;
        return {
          relay,
          status: res.status,
          gated: false,
          bytes,
          ...(servedDocCid ? { servedDocCid } : {}),
          ...(mediaType ? { mediaType } : {}),
        };
      }
      last = { relay, status: res.status, gated: res.status === 401 || res.status === 403 };
    } catch {
      last = { relay, status: 0, gated: false };
    }
  }
  return last;
};
