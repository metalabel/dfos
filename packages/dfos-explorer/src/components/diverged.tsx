/*

  DIVERGED CHAIN — the one way out of a pinned prefix

  When this tab verifies a chain it keeps the operations it folded, and every
  later read of that chain has to extend them. A relay that answers with a
  DIFFERENT operation at a position the pin already covers is contradicting
  proof, not carrying news, and the client refuses it (`DivergenceError`). That
  refusal is correct and stays: it is how a rewritten history becomes something a
  reader can see rather than something that silently replaces what they read
  before.

  But refusing alone strands the reader. A chain whose history was deliberately
  rewritten leaves every browser holding the old prefix permanently unable to
  render that chain — and before this panel the only fix was clearing site data
  by hand, which forgets every other chain too.

  So the way out is EXPLICIT, INFORMED, and PER-CHAIN, and it is all three on
  purpose:

    explicit   a person clicks; nothing here discards a pin on its own. A tab
               that healed itself would repair the symptom and erase the
               evidence in the same move, which is the one outcome the pin
               exists to prevent.
    informed   both tips are on screen and both open — the operation this
               browser proved, and the operation the relays serve now. Deciding
               without seeing them is not deciding.
    per-chain  one chain's cache entry. Not the local operation index, not the
               other chains, and nothing on any relay.

  There is no dismiss. A control that hid this state without acting on it would
  leave the reader exactly as stuck and less informed.

*/

import type { DivergenceError } from '@metalabel/dfos-client';
import { useState } from 'preact/hooks';
import { discardChainPin } from '../lib/client';
import { DidLink, OpLink, Panel, Pill, TruncId } from './ui';

export const DivergedPanel = (props: { err: DivergenceError; onDiscarded: () => void }) => {
  const [working, setWorking] = useState(false);
  const [failed, setFailed] = useState('');
  const { chainType, chainId, cachedHeadCID, liveHeadCID } = props.err;

  const discard = async (): Promise<void> => {
    setWorking(true);
    setFailed('');
    try {
      const dropped = await discardChainPin(chainType, chainId);
      if (dropped) {
        props.onDiscarded();
        return;
      }
      setFailed('This browser’s cache offers no per-chain discard, so nothing was dropped.');
    } catch {
      setFailed('The pin could not be discarded — this browser refused the write.');
    } finally {
      setWorking(false);
    }
  };

  return (
    <Panel
      title={
        <>
          verification <Pill state="bad">chain pin diverged</Pill>
        </>
      }
      accent="bad"
      right={<span class="lbl">this browser holds a different history</span>}
      orient={
        <>
          This browser verified this chain earlier and kept the operations it folded. The relays now
          serve a history that <b>contradicts</b> them — at a position the pin already covers, the
          operation they answer with is not the operation this tab proved. There is no way to verify
          forward across a contradiction, so the client stops here rather than fold a history it
          cannot reconcile with the one it proved.
        </>
      }
    >
      <div class="ck-note">
        Two situations land here and this page cannot tell them apart. A relay may be serving a
        rewritten history, in which case the pin is the evidence that it changed. Or the chain’s
        history was rewritten deliberately and this browser’s pin predates the rewrite, in which
        case the relays’ log is the current one. The pin exists to make the difference visible; the
        reading is yours.
      </div>

      <div class="kv" style={{ marginTop: 8 }}>
        <div class="k">
          chain <span class="lbl">{chainType}</span>
        </div>
        <div class="v">
          {chainType === 'identity' ? (
            <DidLink did={chainId} full />
          ) : (
            <TruncId value={chainId} head={31} tail={0} />
          )}
        </div>
        {cachedHeadCID ? (
          <>
            <div class="k">
              pinned tip <span class="lbl">verified here</span>
            </div>
            <div class="v">
              <OpLink cid={cachedHeadCID} />
            </div>
          </>
        ) : null}
        {liveHeadCID ? (
          <>
            <div class="k">
              relay tip <span class="lbl">served now</span>
            </div>
            <div class="v">
              <OpLink cid={liveHeadCID} />
            </div>
          </>
        ) : null}
      </div>

      <div class="ck-note" style={{ marginTop: 8 }}>
        Discarding drops this browser’s verified prefix for <b>this chain alone</b> — no other
        chain, none of the synced operation log, and nothing on any relay. The next read folds from
        the genesis operation and recomputes every signature and CID, so whatever the relays serve
        has to prove itself from scratch.
      </div>

      <div class="bar" style={{ marginTop: 8 }}>
        <button class="primary" onClick={() => void discard()} disabled={working}>
          {working ? 'discarding…' : 'discard this chain’s local pin and re-verify'}
        </button>
        {failed ? <span class="err">{failed}</span> : null}
      </div>
    </Panel>
  );
};
