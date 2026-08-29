/*

  DIVERGENCE STORE — one verdict, shared by every surface that shows it

  lib/divergence.ts is the check itself: a spot-check that issues up to
  SAMPLE_SIZE × relays requests. Two surfaces want its answer — the local-sync
  page, which shows the whole report, and the home stat band, which shows a one
  line notice when the figures it is printing describe a corpus the relays have
  dropped — and a probe volley per surface, per render, would be absurd for a
  question whose answer does not change between two navigations.

  So the verdict lives here for the session (same split as sync.ts /
  sync-store.ts: the engine, then the observable module singleton around it).
  `ensureDivergenceCheck` runs it AT MOST ONCE — a second caller, or a caller
  arriving after the first finished, gets the standing verdict and issues no
  requests. `runDivergenceCheck` is the explicit re-check behind the button, and
  still collapses onto an in-flight run rather than doubling it.

  Nothing here is persisted. A verdict is an observation of a moment, and a
  reload should look again rather than repeat what a previous tab saw.

*/

import { useEffect, useState } from 'preact/hooks';
import { getDb } from './db-instance';
import { checkDivergence, type DivergenceReport } from './divergence';
import { getRelays } from './relays';

let report: DivergenceReport | null = null;
let inFlight: Promise<DivergenceReport | null> | null = null;

type Listener = (r: DivergenceReport | null) => void;
const listeners = new Set<Listener>();

const emit = (): void => {
  for (const fn of listeners) fn(report);
};

export const getDivergenceReport = (): DivergenceReport | null => report;

/** Retire the standing verdict — what it was about no longer exists (a reset). */
export const clearDivergenceReport = (): void => {
  report = null;
  emit();
};

/** Run the check now, whatever is already known. Collapses onto an in-flight run
 *  so a double-click is one volley, not two. */
export const runDivergenceCheck = async (): Promise<DivergenceReport | null> => {
  if (inFlight) return inFlight;
  inFlight = (async () => {
    // a local-index open failure (another tab blocking an upgrade) leaves the
    // verdict unset rather than throwing — an unanswerable question, not a finding
    const db = await getDb().catch(() => null);
    if (!db) return null;
    const next = await checkDivergence({ db, relays: getRelays() });
    report = next;
    emit();
    return next;
  })().finally(() => {
    inFlight = null;
  });
  return inFlight;
};

/** The check, at most once this session. Callers that merely want to KNOW — the
 *  home notice — use this; nothing they do re-probes what is already answered. */
export const ensureDivergenceCheck = async (): Promise<DivergenceReport | null> => {
  if (report) return report;
  if (inFlight) return inFlight;
  return runDivergenceCheck();
};

/** Subscribe a component to the standing verdict. */
export const useDivergenceReport = (): DivergenceReport | null => {
  const [snap, setSnap] = useState<DivergenceReport | null>(getDivergenceReport);
  useEffect(() => {
    setSnap(getDivergenceReport());
    listeners.add(setSnap);
    return () => {
      listeners.delete(setSnap);
    };
  }, []);
  return snap;
};
