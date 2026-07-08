/*

  DB INSTANCE — one shared local index handle for the app

*/

import { openExplorerDb, type ExplorerDb } from './db';

let dbPromise: Promise<ExplorerDb> | null = null;

/**
 * The one shared handle. We memoize the OPEN promise so every caller shares a
 * single connection — but we must NOT memoize a REJECTED open. A blocked or
 * timed-out open (another tab holding an older version across a version bump) is
 * transient: caching that rejection would poison the tab for its whole lifetime,
 * and callers await this exact promise, so a hung/rejected handle stalls the
 * verify queue and every local read. On rejection we drop the cache so the next
 * call retries (the blocker may have closed). The `.catch` is a side-branch that
 * only resets state — callers still see their own rejection from the returned
 * promise; it is not swallowed.
 *
 * We also drop the cache when the connection CLOSES to yield to another tab's
 * version upgrade (onClosed): the handle is then dead — every transaction on it
 * throws — so the next call must reopen. In the outdated-tab case that reopen
 * rejects with a VersionError and degrades honestly, which is correct; without
 * this the tab could never recover short of a reload. Both resets guard on
 * `dbPromise === p` so a retry already in flight is never clobbered.
 */
export const getDb = (): Promise<ExplorerDb> => {
  if (!dbPromise) {
    const p: Promise<ExplorerDb> = openExplorerDb('dfos-explorer', undefined, () => {
      if (dbPromise === p) dbPromise = null;
    });
    p.catch(() => {
      if (dbPromise === p) dbPromise = null;
    });
    dbPromise = p;
  }
  return dbPromise;
};
