/*

  INDEX LIGHT — browse straight off a relay's /index/v0, no full sync

  When a relay advertises capabilities.index, the explorer can populate browse
  and home surfaces INSTANTLY from the relay's index projections instead of
  waiting for a full-log sync. These rows are relay-asserted discovery hints —
  ATTRIBUTED, never authority — and the verify-queue promotes the visible ones to
  VERIFIED by folding their chains in the tab. Full-corpus sync stays untouched
  and is the audit posture (it can detect a relay's omissions; a light client
  cannot). A relay WITHOUT the capability yields `false` here and every surface
  falls back to exactly its pre-index behavior.

  The gate is SYNC COMPLETION, not corpus emptiness: verifying light rows lands
  their chains in the local index (jitIndexChain), so an emptiness gate would be
  destroyed by its own verify queue. Light mode instead ends only when a real
  full-log sync has run against the configured relays (see useLightMode).

  Enumeration is intrinsically incomplete under "completeness is outside the
  proof": these loaders page up to a cap, and any name search filters the LOADED
  rows only — the relay has no search, and this never pretends otherwise.

*/

import type { IndexContentRow, IndexIdentityRow } from '@metalabel/dfos-client';
import { useEffect, useState } from 'preact/hooks';
import { getClient } from './client';
import { getDb } from './db-instance';
import { getRelays } from './relays';
import { useSyncState } from './sync-store';

/** Per-page size and a hard page ceiling — the light view is a fast first look,
 *  not an exhaustive mirror; the audit stance (full sync) is the exhaustive path. */
const PAGE = 200;
const MAX_PAGES = 5;

/**
 * Whether any configured relay advertises the index capability. `null` while the
 * well-known is still being read (callers hold today's behavior until it settles),
 * then a stable boolean. Recomputed on mount — a relay switch re-navigates.
 */
export const useIndexCapable = (): boolean | null => {
  const [capable, setCapable] = useState<boolean | null>(null);
  useEffect(() => {
    let dead = false;
    void getClient()
      .capabilities()
      .then((c) => {
        if (!dead) setCapable(c.index);
      })
      .catch(() => {
        if (!dead) setCapable(false);
      });
    return () => {
      dead = true;
    };
  }, []);
  return capable;
};

/**
 * The one light-mode gate every index-light surface shares. Light mode is active
 * when a relay advertises the index capability AND no full-log sync has ever run
 * against the currently-configured relays.
 *
 * The "has synced" signal is per-relay sync-CURSOR existence (sync.ts writes a
 * cursor only while paging the global log) — NOT corpus emptiness. A JIT-folded
 * chain (a detail visit, the verify queue promoting a light row) lands ops in
 * the corpus but never writes a cursor, so verifying light rows cannot flip this
 * gate out from under itself. A wipe clears the cursors, so light mode returns
 * over an emptied index. `null` while either probe is still settling — callers
 * hold their current framing until it resolves. Recomputed on every db epoch.
 */
export const useLightMode = (): boolean | null => {
  const cap = useIndexCapable();
  const sync = useSyncState();
  const [synced, setSynced] = useState<boolean | null>(null);
  useEffect(() => {
    let dead = false;
    void (async () => {
      const db = await getDb();
      const cursors = await Promise.all(getRelays().map((r) => db.getCursor(r)));
      if (!dead) setSynced(cursors.some((c) => c !== undefined));
    })().catch(() => {
      if (!dead) setSynced(false);
    });
    return () => {
      dead = true;
    };
  }, [sync.dbEpoch, sync.phase]);
  if (cap === false) return false;
  if (synced === true) return false;
  if (cap === null || synced === null) return null;
  return true;
};

export interface IndexLoad<T> {
  rows: T[];
  loading: boolean;
}

/** Drain up to MAX_PAGES of the identity index (optionally public-profile-only). */
export const useIndexIdentities = (
  enabled: boolean,
  publicOnly: boolean,
): IndexLoad<IndexIdentityRow> => {
  const [rows, setRows] = useState<IndexIdentityRow[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let dead = false;
    setLoading(true);
    void (async () => {
      const client = getClient();
      const out: IndexIdentityRow[] = [];
      let after: string | undefined;
      for (let p = 0; p < MAX_PAGES; p++) {
        const page = await client.indexIdentities({
          ...(publicOnly ? { hasPublicProfile: true } : {}),
          ...(after ? { after } : {}),
          limit: PAGE,
        });
        out.push(...page.identities);
        if (!page.next) break;
        after = page.next;
      }
      if (!dead) {
        setRows(out);
        setLoading(false);
      }
    })().catch(() => {
      if (!dead) {
        setRows([]);
        setLoading(false);
      }
    });
    return () => {
      dead = true;
    };
  }, [enabled, publicOnly]);
  return { rows, loading };
};

/** Drain up to MAX_PAGES of the content index (optionally public-read-only). */
export const useIndexContent = (
  enabled: boolean,
  publicOnly: boolean,
): IndexLoad<IndexContentRow> => {
  const [rows, setRows] = useState<IndexContentRow[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let dead = false;
    setLoading(true);
    void (async () => {
      const client = getClient();
      const out: IndexContentRow[] = [];
      let after: string | undefined;
      for (let p = 0; p < MAX_PAGES; p++) {
        const page = await client.indexContent({
          ...(publicOnly ? { publicRead: true } : {}),
          ...(after ? { after } : {}),
          limit: PAGE,
        });
        out.push(...page.content);
        if (!page.next) break;
        after = page.next;
      }
      if (!dead) {
        setRows(out);
        setLoading(false);
      }
    })().catch(() => {
      if (!dead) {
        setRows([]);
        setLoading(false);
      }
    });
    return () => {
      dead = true;
    };
  }, [enabled, publicOnly]);
  return { rows, loading };
};
