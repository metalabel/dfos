/*

  NOT FOUND — honest absence

  A 404 is a statement about THE RELAYS YOU ASKED, never about the network: there
  is no canonical state and no relay is authoritative on absence. The copy below
  is careful not to overrun that, and in particular not to promise that a chain
  exists somewhere for the reader to go find. A relay may never have held this
  chain, may have held it and pruned it, or may hold it and decline to serve it —
  the answer looks identical from here, and the honest sentence covers all three.

*/

import { Panel } from '../components/ui';
import type { ClaimResult } from '../lib/relay-raw';

/** The 404 line, per kind. `content` gets its own because a content chain is the
 *  one primitive a relay may deliberately not carry (retention is a relay's own
 *  business), so "try adding another relay" reads as a promise the network may
 *  have no way to keep — this chain may not be published anywhere you can reach.
 *  Identity and credential keep the general form. */
const absenceNote = (kind: string): string =>
  kind === 'content'
    ? 'No configured relay serves this chain. It may never have been published here, or a relay that held it may no longer carry it — a relay is never authoritative on absence, and there is no canonical state to appeal to.'
    : 'These relays have not seen this chain. Try adding another relay — there is no canonical state.';

export const NotFound = (props: { kind: string; id: string; claim?: ClaimResult | undefined }) => (
  <Panel title={`${props.kind} not found`}>
    <div class="kv">
      <div class="k">id</div>
      <div class="v">{props.id}</div>
      <div class="k">relay says</div>
      <div class="v err">
        {props.claim
          ? props.claim.status === 0
            ? (props.claim.error ?? 'network error')
            : `HTTP ${props.claim.status}${props.claim.error ? ` — ${props.claim.error.slice(0, 200)}` : ''}`
          : 'not resolvable'}
      </div>
    </div>
    <div class="ck-note" style={{ marginTop: 8 }}>
      {props.claim?.gated
        ? 'gated · this resource is on the content plane and needs authorization'
        : absenceNote(props.kind)}
    </div>
  </Panel>
);
