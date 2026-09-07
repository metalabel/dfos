import { signIdentityOperation } from '@metalabel/dfos-protocol/chain';
import { describe, expect, it } from 'vitest';
import type { Callbacks, EffectiveIdentity, EverProvedIdentity } from '../src';
import { createClient } from '../src/client';
import { buildIdentity, fakePeerClient, ts } from './fixtures';

// Checked by the package typecheck, without invoking a resolver at runtime.
const checkResolutionTypes = (
  callbacks: Callbacks,
  effective: EffectiveIdentity,
  historical: EverProvedIdentity,
) => {
  // @ts-expect-error Ever-proved keys cannot authorize at a time basis.
  const asOf: Callbacks['resolveIdentity'] = callbacks.resolveClaimantIdentity;
  // @ts-expect-error Effective state does not include all historically proved keys.
  const claimant: Callbacks['resolveClaimantIdentity'] = callbacks.resolveIdentity;
  // @ts-expect-error Historical state cannot be used as head state.
  const head: EffectiveIdentity = historical;
  // @ts-expect-error Effective state is not an ever-proved projection.
  const proved: EverProvedIdentity = effective;
  return { asOf, claimant, head, proved };
};
void checkResolutionTypes;

describe('identity resolution contexts', () => {
  it('retains a proved-then-voided key only in the ever-proved projection', async () => {
    const identity = await buildIdentity({ rotate: true });
    const removed = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: identity.headCID,
        authKeys: [identity.k.key],
        assertKeys: [identity.k.key],
        controllerKeys: [identity.k.key],
        createdAt: ts(-4),
      },
      signer: identity.k.signer,
      keyId: identity.k.keyId,
      identityDID: identity.did,
    });
    // Reintroduction without a fresh possession proof is void even though this
    // key was proved at an earlier position in the chain.
    const voided = await signIdentityOperation({
      operation: {
        version: 1,
        type: 'update',
        previousOperationCID: removed.operationCID,
        authKeys: [identity.k.key, identity.rotatedKey!.key],
        assertKeys: [identity.k.key],
        controllerKeys: [identity.k.key],
        createdAt: ts(-3),
      },
      signer: identity.k.signer,
      keyId: identity.k.keyId,
      identityDID: identity.did,
    });
    const relay = 'https://relay.test';
    const client = createClient({
      relays: [relay],
      peerClient: fakePeerClient({
        [relay]: {
          identities: {
            [identity.did]: [...identity.log, removed.jwsToken, voided.jwsToken],
          },
        },
      }),
    });
    const callbacks = client.callbacks();
    const effective = await callbacks.resolveIdentity(identity.did);
    const historical = await callbacks.resolveClaimantIdentity(identity.did);
    expect(effective).toBeDefined();
    expect(historical?.resolution).toBe('ever-proved');
    expect(effective?.authKeys.map((key) => key.id)).toEqual([identity.k.keyId]);
    expect(effective?.voidKeys).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: identity.rotatedKey!.key, role: 'auth' }),
      ]),
    );
    expect(historical?.authKeys.map((key) => key.id)).toEqual([
      identity.k.keyId,
      identity.rotatedKey!.keyId,
    ]);
    expect((await client.identity(identity.did)).value.authKeys).toEqual(effective?.authKeys);
  });
});
