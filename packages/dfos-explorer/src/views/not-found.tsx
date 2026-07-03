/*

  NOT FOUND — honest absence

*/

import { Panel } from '../components/ui';
import type { ClaimResult } from '../lib/relay-raw';

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
        : 'These relays have not seen this chain. Try adding another relay — there is no canonical state.'}
    </div>
  </Panel>
);
