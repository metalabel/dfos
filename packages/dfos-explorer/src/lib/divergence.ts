/*

  DIVERGENCE — does the local mirror still describe the relays' corpus?

  The local index is APPEND-ONLY: it unions every operation it has ever seen and
  never retracts one. That is the right shape for an audit cache — a relay must
  not be able to make you forget what it served you — but it means a relay that
  DROPS operations (a corpus rebuild, a re-mint under new CIDs) leaves the tab
  holding a history no relay carries any more. Nothing errors; the local figures
  simply stop describing the network, and since a locally-counted figure is
  trusted over a relay-asserted one, the stale number is the one that wins.

  So we ask, cheaply and directly: take a spread of operation CIDs the local
  index holds and fetch each one back from the configured relays.

    every sampled op resolves            → aligned
    an op is definitively ABSENT (404)   → diverged
    anything we could not settle         → unknown

  ABSENCE MUST BE DEFINITIVE. A timeout, a 5xx, a CORS failure, a 401/403 — none
  of those say the operation is gone, they say we could not look. Only a relay
  that answers, and answers "not found", is evidence; and it must be EVERY
  configured relay, because one relay's gap is not the corpus's. One inconclusive
  probe makes the whole check inconclusive rather than quietly reading as clean.

  The verdict is advisory. It recommends a reset; it never performs one.

*/

import type { ChainRollup, ExplorerDb } from './db';

const PROOF = '/proof/v1';

/** How many operations a check samples. Small — this is a spot-check, not a scan. */
export const SAMPLE_SIZE = 12;

const PROBE_TIMEOUT_MS = 8000;

/** One sampled operation's fate. `unknown` is a failure to look, not a finding. */
export type ProbeOutcome = 'present' | 'absent' | 'unknown';

export interface DivergenceReport {
  /**
   * `aligned`   every sampled op still resolves upstream
   * `diverged`  at least one op the local index holds is gone from every relay
   * `unknown`   at least one probe was inconclusive and none was a definite absence
   * `empty`     nothing local to sample
   */
  verdict: 'aligned' | 'diverged' | 'unknown' | 'empty';
  sampled: number;
  present: number;
  absent: number;
  unknown: number;
  /** ms epoch the check finished — a verdict without a clock is a rumour. */
  checkedAt: number;
}

/** A status a relay ANSWERED with that means "this operation is not here". */
const isDefiniteAbsence = (status: number): boolean => status === 404 || status === 410;

/**
 * Fold one operation's per-relay HTTP statuses into an outcome. Status `0` means
 * the fetch never produced a response (network error / timeout / CORS) and is
 * therefore inconclusive, as are 401/403 (gated: it may well be there) and 5xx.
 */
export const classifyStatuses = (statuses: readonly number[]): ProbeOutcome => {
  if (statuses.some((s) => s >= 200 && s < 300)) return 'present';
  if (statuses.length > 0 && statuses.every(isDefiniteAbsence)) return 'absent';
  return 'unknown';
};

/** Tally probe outcomes into the advisory verdict. Pure. */
export const summarize = (
  outcomes: readonly ProbeOutcome[],
  checkedAt: number,
): DivergenceReport => {
  const count = (o: ProbeOutcome): number => outcomes.filter((x) => x === o).length;
  const present = count('present');
  const absent = count('absent');
  const unknown = count('unknown');
  const sampled = outcomes.length;
  const verdict: DivergenceReport['verdict'] =
    sampled === 0 ? 'empty' : absent > 0 ? 'diverged' : unknown > 0 ? 'unknown' : 'aligned';
  return { verdict, sampled, present, absent, unknown, checkedAt };
};

/**
 * Pick which operations to probe: the HEAD op of an evenly-spaced slice of the
 * local chains, ordered oldest-first by when the chain began. Even spacing is
 * what makes a 12-op sample worth anything — a corpus rebuild replaces the OLD
 * history under new CIDs, so a sample crowded at the recent end would sail
 * straight past it. Deterministic (no randomness) so a re-check is comparable.
 */
export const sampleChainHeads = (chains: readonly ChainRollup[], size: number): string[] => {
  const usable = chains.filter((c) => c.headCid);
  if (usable.length === 0 || size <= 0) return [];
  const ordered = [...usable].sort(
    (a, b) =>
      (a.firstCreatedAt < b.firstCreatedAt ? -1 : a.firstCreatedAt > b.firstCreatedAt ? 1 : 0) ||
      (a.chainId < b.chainId ? -1 : a.chainId > b.chainId ? 1 : 0),
  );
  if (ordered.length <= size) return ordered.map((c) => c.headCid);
  const out: string[] = [];
  const step = (ordered.length - 1) / (size - 1);
  for (let i = 0; i < size; i++) {
    const row = ordered[Math.round(i * step)];
    if (row && !out.includes(row.headCid)) out.push(row.headCid);
  }
  return out;
};

/** GET one operation from one relay, reporting only its status (0 = no answer). */
const probeStatus = async (relay: string, cid: string, signal?: AbortSignal): Promise<number> => {
  try {
    const res = await fetch(`${relay}${PROOF}/operations/${encodeURIComponent(cid)}`, {
      mode: 'cors',
      signal: signal ?? AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    return res.status;
  } catch {
    return 0;
  }
};

/** Ask every configured relay about one op, then classify. */
export const probeOp = async (
  cid: string,
  relays: readonly string[],
  signal?: AbortSignal,
): Promise<ProbeOutcome> => {
  if (relays.length === 0) return 'unknown';
  const statuses = await Promise.all(relays.map((relay) => probeStatus(relay, cid, signal)));
  return classifyStatuses(statuses);
};

/**
 * Spot-check the local index against the relays. Reads only chain rollups (no
 * scan) and issues at most SAMPLE_SIZE × relays requests.
 */
export const checkDivergence = async (options: {
  db: ExplorerDb;
  relays: readonly string[];
  sampleSize?: number;
  signal?: AbortSignal;
}): Promise<DivergenceReport> => {
  const { db, relays, signal } = options;
  const cids = sampleChainHeads(await db.allChains(), options.sampleSize ?? SAMPLE_SIZE);
  const outcomes = await Promise.all(cids.map((cid) => probeOp(cid, relays, signal)));
  return summarize(outcomes, Date.now());
};
