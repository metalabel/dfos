/*

  PENDING — placeholder for detail views still landing

*/

import { Panel } from '../components/ui';

export const Pending = (props: { kind: string; id: string }) => (
  <Panel title={props.kind}>
    <div class="kv">
      <div class="k">id</div>
      <div class="v">{props.id}</div>
    </div>
    <div class="ck-note" style={{ marginTop: 8 }}>
      This detail view is landing in the next changeset. The identifier above is routed and
      preserved — reload once views ship.
    </div>
  </Panel>
);
