/*

  DID CHIP — the standard rendering of a DID in any row context

  A DID is a hash. Where one appears in a feed, a table, or a cross-reference,
  this resolves it to the identity's PUBLIC profile name (lib/did-profiles.ts:
  verified identity fold → controller-signed anchor → anonymous bytes → cid
  re-hash) and hydrates in place as the answer lands. Until then — and forever,
  for an identity with no public profile — it renders exactly what the explorer
  rendered before: the short DID, linked.

  A resolved name renders in plain ink, NOT the amber `.attr` used for relay
  projections: this name came from bytes bound to the chain by math in your tab.

*/

import { useDidProfile } from '../lib/did-profiles';
import { short } from '../lib/format';

export const DidChip = (props: { did: string }) => {
  const { profile } = useDidProfile(props.did);
  return (
    <a
      class="did-chip"
      href={`#/did/${props.did}`}
      title={profile ? `${props.did} — public profile, verified in your tab` : props.did}
    >
      {profile ? <span class="did-name">{profile.name}</span> : short(props.did, 14, 6)}
    </a>
  );
};
