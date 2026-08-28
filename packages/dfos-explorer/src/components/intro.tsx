/*

  HOME INTRO — the one banner a cold visitor gets

  Mounted at the top of home and nowhere else. It says what the explorer is,
  where its data comes from, where the verification happens, and what the two
  trust colors mean — using the SAME badges every row on the site uses, so the
  legend teaches the real vocabulary rather than a second one.

  Dismiss is one-way and permanent: it writes a flag to localStorage and the
  banner never renders again. No re-show schedule, no animation, no reserved
  space left behind. Storage that throws (private windows) simply means the
  dismiss lasts the session — the state hook still hides it.

*/

import { useState } from 'preact/hooks';
import { dismissIntro, getIntroDismissed } from '../lib/settings';
import { Badge, Panel } from './ui';

const REPO = 'https://github.com/metalabel/dfos';

export const HomeIntro = () => {
  const [dismissed, setDismissed] = useState(getIntroDismissed);
  if (dismissed) return null;

  const dismiss = (): void => {
    dismissIntro();
    setDismissed(true);
  };

  return (
    <Panel
      title="the explorer"
      right={
        <button class="intro-x" aria-label="dismiss this introduction" onClick={dismiss}>
          ✕ dismiss
        </button>
      }
    >
      <div class="intro">
        <p>
          An explorer for the DFOS protocol — identities, content chains, operations, and
          credentials.
        </p>
        <p>
          It reads from <code>relay.dfos.com</code> by default and works against any relay: add or
          swap your own on the <a href="#/relays">relays page</a>.
        </p>
        <p>
          Everything runs in your browser. Signatures and CIDs are recomputed here, so a relay is an
          input, never an authority.
        </p>
        <div class="intro-legend">
          <span>
            <Badge state="ok">verified</Badge> recomputed in this tab
          </span>
          <span>
            <Badge state="warn">attributed</Badge> asserted by a relay, not yet checked here
          </span>
        </div>
        <p>
          The explorer is{' '}
          <a href={REPO} rel="noreferrer noopener" target="_blank">
            open source
          </a>
          . The only server-side code is a small probe that reads DNS records and well-known
          documents for domain bindings, which a browser cannot do itself. It lives in the repo
          under <code>packages/dfos-explorer/api</code> as plain Node with no platform APIs, and
          runs on any Node host.
        </p>
      </div>
    </Panel>
  );
};
