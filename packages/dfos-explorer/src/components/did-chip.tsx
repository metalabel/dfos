/*

  DID CHIP — the standard rendering of a DID in any row context

  A DID is a hash. Where one appears in a feed, a table, or a cross-reference,
  this resolves it to the identity's PUBLIC profile name (lib/did-profiles.ts) and
  hydrates in place as the answer lands. Until then — and forever, for an identity
  with no public profile — it renders exactly what the explorer rendered before:
  the short DID, linked.

  The name arrives in two tiers, and the chip shows which one it is holding. The
  relay index's point lookup answers first, in one round trip, and renders in the
  amber `.attr` used for every relay projection. The verified resolve (identity
  fold → controller-signed anchor → anonymous bytes → cid re-hash) replaces it
  with plain ink: that name came from bytes bound to the chain by math in your tab.

*/

import { useDidProfile } from '../lib/did-profiles';
import { short } from '../lib/format';

export const DidChip = (props: { did: string }) => {
  const { profile, tier } = useDidProfile(props.did);
  const title = !profile
    ? props.did
    : tier === 'verified'
      ? `${props.did} — public profile, verified in your tab`
      : `${props.did} — name projected by the relay index (attributed); verifying…`;
  return (
    <a class="did-chip" href={`#/did/${props.did}`} title={title}>
      {profile ? (
        <span class={tier === 'verified' ? 'did-name' : 'attr'}>{profile.name}</span>
      ) : (
        short(props.did, 14, 6)
      )}
    </a>
  );
};
