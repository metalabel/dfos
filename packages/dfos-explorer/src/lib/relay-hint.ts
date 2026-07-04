/*

  RELAY HINT — optional /.well-known corpus advertisement

  A relay MAY advertise `stats.opCount` and `stats.countsByKind` in its
  /.well-known/dfos-relay (lane B ships these separately). When present they let a
  browse header say "~N available — sync to browse" so a full download is an
  informed choice. This is a RELAY-ASSERTED hint, never proof — completeness is
  outside the proof, and the honest local count always wins once synced.

  Everything here degrades to `{}`: a relay that predates the fields, or none
  configured, simply yields no hint and the UI shows only what is locally known.

*/

import type { RelayHealth } from '@metalabel/dfos-client';
import { getClient } from './client';

export interface RelayHint {
  /** max advertised total op count across healthy relays (relay-asserted). */
  opCount?: number;
  /** max advertised per-kind counts across healthy relays (relay-asserted). */
  countsByKind?: Record<string, number>;
}

const readStats = (h: RelayHealth): { opCount?: number; countsByKind?: Record<string, number> } => {
  const stats = h['stats'];
  if (typeof stats !== 'object' || stats === null) return {};
  const rec = stats as Record<string, unknown>;
  const opCount = typeof rec['opCount'] === 'number' ? rec['opCount'] : undefined;
  const raw = rec['countsByKind'];
  let countsByKind: Record<string, number> | undefined;
  if (typeof raw === 'object' && raw !== null) {
    countsByKind = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof v === 'number') countsByKind[k] = v;
    }
  }
  return {
    ...(opCount !== undefined ? { opCount } : {}),
    ...(countsByKind ? { countsByKind } : {}),
  };
};

/**
 * Aggregate the optional corpus hints across the configured relays. Takes the
 * MAX per field — the most any single relay claims to hold (a relay never proves
 * completeness, so the largest advertisement is the most useful upper hint).
 */
export const fetchRelayHint = async (): Promise<RelayHint> => {
  let health: RelayHealth[];
  try {
    health = await getClient().health();
  } catch {
    return {};
  }
  const hint: RelayHint = {};
  for (const h of health) {
    if (!h.ok) continue;
    const s = readStats(h);
    if (s.opCount !== undefined) hint.opCount = Math.max(hint.opCount ?? 0, s.opCount);
    if (s.countsByKind) {
      hint.countsByKind ??= {};
      for (const [k, v] of Object.entries(s.countsByKind)) {
        hint.countsByKind[k] = Math.max(hint.countsByKind[k] ?? 0, v);
      }
    }
  }
  return hint;
};
