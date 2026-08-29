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

  A STANDING VERDICT ONLY STANDS WHILE ITS QUESTION DOES. "Does the local mirror
  still describe the relays' corpus?" names two things, and either one changing
  retires the answer:

    the RELAY SET changed  — the verdict was about different relays. A relay added
                             or removed makes "the relays" a different set, and an
                             `aligned` from the old one says nothing about the new.
    the LOCAL CORPUS grew  — a sync that added operations changed the mirror the
                             verdict was about. The ops it sampled were not these.
    the local index was WIPED — handled by the reset caller (views/sync.tsx).

  Each of those clears the report rather than re-running the check: nobody is
  waiting on it, and the surfaces that want an answer ask for one
  (`ensureDivergenceCheck`) the next time they render. A cleared verdict shows as
  no notice, which is honest — we have not looked since the question changed.

*/

import { useEffect, useState } from 'preact/hooks';
import { getDb } from './db-instance';
import { checkDivergence, type DivergenceReport } from './divergence';
import { getRelays, subscribeRelays } from './relays';

let report: DivergenceReport | null = null;
let inFlight: Promise<DivergenceReport | null> | null = null;
/** the relay set the standing verdict was about, as a comparable key. */
let reportRelays = '';

type Listener = (r: DivergenceReport | null) => void;
const listeners = new Set<Listener>();

const emit = (): void => {
  for (const fn of listeners) fn(report);
};

export const getDivergenceReport = (): DivergenceReport | null => report;

/** Retire the standing verdict — what it was about no longer exists (a reset, a
 *  relay-set change, a sync that added operations). A no-op when nothing stands,
 *  so it never wakes subscribers for nothing. */
export const clearDivergenceReport = (): void => {
  if (report === null) return;
  report = null;
  reportRelays = '';
  emit();
};

const relayKey = (relays: readonly string[]): string => relays.join('|');

// The relay set is user-editable at any time, and it is half of the question the
// verdict answers. Registered once, for the module's life: divergence-store is a
// session singleton and there is no unsubscribe to run. (relays.ts also notifies
// on a quorum change, which is not a relay-set change — hence the key compare
// rather than clearing on every notification.)
subscribeRelays(() => {
  if (relayKey(getRelays()) !== reportRelays) clearDivergenceReport();
});

/** Run the check now, whatever is already known. Collapses onto an in-flight run
 *  so a double-click is one volley, not two. */
export const runDivergenceCheck = async (): Promise<DivergenceReport | null> => {
  if (inFlight) return inFlight;
  inFlight = (async () => {
    // a local-index open failure (another tab blocking an upgrade) leaves the
    // verdict unset rather than throwing — an unanswerable question, not a finding
    const db = await getDb().catch(() => null);
    if (!db) return null;
    // the set as it stands when the check RUNS is the set the verdict is about
    const relays = getRelays();
    const next = await checkDivergence({ db, relays });
    // the set moved while the volley was out — this answer is about relays that
    // are no longer the configured ones, so it stands for nothing and is dropped
    // rather than filed (the subscription above already cleared, and had nothing
    // to clear)
    if (relayKey(getRelays()) !== relayKey(relays)) return null;
    report = next;
    reportRelays = relayKey(relays);
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
