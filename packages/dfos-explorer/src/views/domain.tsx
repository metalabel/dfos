/*

  DOMAIN VIEW — what an origin says about itself, checked

  The other detail views start from an identifier and ask the relays. This one
  starts from a DOMAIN and asks the domain, because an app description document
  is the one artifact where a domain vouches for a DFOS identity: serving
  `/.well-known/dfos-app.json` IS the registration (SIWD.md). The explorer then
  does what it always does — re-verifies the claim in the tab, and compares it
  against what the untrusted relays hold.

  Four beats, and each one can fail differently:

    1. the ORIGIN served a document        → unreachable / no-app-description
    2. it is a valid app description       → malformed
    3. its carried chain verifies + derives its client_did  → malformed
    4. the relays' log for that DID agrees  → relay-diverged

  The reachability beat runs through the explorer's one serverless route, so a
  failure there is OUR failure, and says so — never "this origin has no app
  description", which is a claim about someone else's server we did not observe.

*/

import type { Resolved } from '@metalabel/dfos-client';
import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks } from '../components/checks';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import { Badge, DidLink, Panel, Pill, Related, Term, TruncId } from '../components/ui';
import { getClient } from '../lib/client';
import { GLOSSARY } from '../lib/glossary';
import { toOpRows, type OpRow } from '../lib/op-rows';
import {
  assessDocument,
  compareLogs,
  fetchAppDocument,
  originVerified,
  withRelayLog,
  type AppDescription,
  type DomainVerdict,
  type LogComparison,
} from '../lib/wellknown';

/** The relay beat, kept separate from the document beat: the relays may hold
 *  nothing at all for a DID the origin carries, which is an ABSENCE, not a
 *  disagreement, and must not be compared as though it were an empty log. */
type RelayBeat =
  | { phase: 'idle' }
  | { phase: 'loading' }
  | { phase: 'absent'; error: string }
  | { phase: 'held'; log: string[]; rows: OpRow[]; resolved: Resolved<VerifiedIdentity> };

export const Domain = (props: { host: string }) => {
  const [document, setDocument] = useState<DomainVerdict | null>(null);
  const [relay, setRelay] = useState<RelayBeat>({ phase: 'idle' });

  // beat 1-3: the origin's document, fetched through the proxy and verified here
  useEffect(() => {
    let dead = false;
    setDocument(null);
    setRelay({ phase: 'idle' });
    void (async () => {
      const outcome = await fetchAppDocument(props.host);
      const assessed = await assessDocument(outcome);
      if (!dead) setDocument(assessed);
    })();
    return () => {
      dead = true;
    };
  }, [props.host]);

  // beat 4: resolve the DERIVED did on the relays — the same two-beat machinery
  // every other view uses. Only runs once a chain has actually verified, because
  // only then is there a DID the ORIGIN has proven it controls.
  const did = document?.kind === 'verified' ? document.did : '';
  useEffect(() => {
    let dead = false;
    setRelay({ phase: 'idle' });
    if (!did) return;
    setRelay({ phase: 'loading' });
    void (async () => {
      const client = getClient();
      try {
        const [resolved, log] = await Promise.all([
          client.identity(did),
          client.log('identity', did),
        ]);
        if (dead) return;
        setRelay({
          phase: 'held',
          log: log.value.map((e) => e.jwsToken),
          rows: toOpRows(log.value),
          resolved,
        });
      } catch (e) {
        // the relays do not hold this identity — an absence, and a completely
        // ordinary one for a freshly minted app identity that lives only in
        // carriage. NOT a divergence.
        if (!dead) setRelay({ phase: 'absent', error: e instanceof Error ? e.message : String(e) });
      }
    })();
    return () => {
      dead = true;
    };
  }, [did]);

  // the relay beat folds INTO the verdict: an origin-verified document whose
  // relay log disagrees is `relay-diverged`, one of the four top-level states,
  // not a green page with a footnote.
  const verdict: DomainVerdict | null =
    document !== null && relay.phase === 'held' ? withRelayLog(document, relay.log) : document;

  const proven = originVerified(verdict);
  const comparison: LogComparison | null =
    verdict?.kind === 'relay-diverged'
      ? verdict.comparison
      : proven !== null && relay.phase === 'held'
        ? compareLogs(proven.log, relay.log)
        : null;

  return (
    <>
      <Panel
        title={
          <>
            domain <StatePill verdict={verdict} />
          </>
        }
        accent={accentFor(verdict)}
        orient={
          <>
            An application's <code>/.well-known/dfos-app.json</code> — the one document where a{' '}
            <b>domain vouches for a DFOS identity</b>. Serving the file is the registration: there
            is no developer portal and no client secret,{' '}
            <Term word="domain control" def={GLOSSARY['did'] ?? ''} /> is the credential. What the
            document <i>claims</i> is checked here; what the relays hold is compared below.
          </>
        }
      >
        <div class="kv">
          <div class="k">origin</div>
          <div class="v">
            <a href={`https://${props.host}/.well-known/dfos-app.json`} rel="noreferrer noopener">
              {props.host}
            </a>
          </div>
          {proven !== null ? (
            <>
              <div class="k">
                client_did <span class="lbl">derived from the carried chain</span>
              </div>
              <div class="v">
                <DidLink did={proven.did} full />
              </div>
            </>
          ) : null}
        </div>
      </Panel>

      {verdict === null ? (
        <Panel title="verification">
          <Checks>
            <Check state="pend">reading the origin's app description…</Check>
          </Checks>
        </Panel>
      ) : (
        <Verification host={props.host} verdict={verdict} relay={relay} comparison={comparison} />
      )}

      {proven !== null ? <AppPanel app={proven.app} /> : null}
      {verdict?.kind === 'no-carriage' ? <AppPanel app={verdict.app} /> : null}

      {relay.phase === 'held' && proven !== null ? (
        <Panel title="operation history" right={<span class="lbl">as the relays serve it</span>}>
          <OpTimeline rows={relay.rows} headCid={relay.rows[relay.rows.length - 1]?.cid ?? ''} />
          <ProvenanceLine provenance={relay.resolved.provenance} />
        </Panel>
      ) : null}

      {proven !== null ? (
        <Related
          rows={[
            {
              k: 'identity',
              v: <DidLink did={proven.did} full />,
            },
            {
              k: 'redirect targets',
              v: proven.app.redirect_uris.map((uri) => (
                <div key={uri} class="muted">
                  {uri}
                </div>
              )),
            },
          ]}
        />
      ) : null}
    </>
  );
};

// -----------------------------------------------------------------------------
// the top-level pill — green ONLY for a verified chain
// -----------------------------------------------------------------------------

const StatePill = (props: { verdict: DomainVerdict | null }) => {
  const { verdict } = props;
  if (verdict === null) return <Pill state="pending">checking origin…</Pill>;
  switch (verdict.kind) {
    case 'verified':
      return <Pill state="ok">verified</Pill>;
    case 'relay-diverged':
      return <Pill state="warn">origin verified · relay log diverged</Pill>;
    case 'no-carriage':
      return <Pill state="warn">app document present · no chain carried</Pill>;
    case 'malformed':
      return <Pill state="bad">malformed app description</Pill>;
    case 'unreachable':
      return <Pill state="bad">unreachable</Pill>;
    case 'no-app-description':
      return <Pill state="warn">no app description</Pill>;
  }
};

const accentFor = (verdict: DomainVerdict | null): 'ok' | 'warn' | 'bad' | undefined => {
  if (verdict === null) return undefined;
  if (verdict.kind === 'verified') return 'ok';
  if (verdict.kind === 'malformed' || verdict.kind === 'unreachable') return 'bad';
  return 'warn';
};

// -----------------------------------------------------------------------------
// the verification ladder
// -----------------------------------------------------------------------------

const Verification = (props: {
  host: string;
  verdict: DomainVerdict;
  relay: RelayBeat;
  comparison: LogComparison | null;
}) => {
  const { verdict, relay, comparison } = props;
  const proven = originVerified(verdict);

  return (
    <Panel title="verification" right={<span class="lbl">re-run in your browser</span>}>
      <Checks>
        {/* ---------------------------------------------------------------- */}
        {/* beat 1 — did the ORIGIN answer                                     */}
        {/* ---------------------------------------------------------------- */}
        {verdict.kind === 'unreachable' ? (
          <>
            <Check
              state="bad"
              note={
                verdict.httpStatus !== null
                  ? `HTTP ${verdict.httpStatus} — ${verdict.reason}`
                  : verdict.reason
              }
            >
              {verdict.proxyDown
                ? "the explorer's own lookup route did not answer"
                : `couldn't reach ${props.host}`}
            </Check>
            <Check state="pend">
              {verdict.proxyDown
                ? 'nothing was learned about this origin — this is our failure, not a statement about the domain'
                : 'no document was served, so nothing below could be checked'}
            </Check>
          </>
        ) : verdict.kind === 'no-app-description' ? (
          <Check
            state="warn"
            note={
              verdict.httpStatus !== null
                ? `HTTP ${verdict.httpStatus} — the origin answered, and has no such document`
                : 'the origin answered, and has no such document'
            }
          >
            {props.host} serves no app description
          </Check>
        ) : (
          <>
            <Check state="ok" note={`fetched from https://${props.host}/.well-known/dfos-app.json`}>
              the origin served a document
            </Check>

            {/* -------------------------------------------------------------- */}
            {/* beat 2 — structural validity, against the canonical schema      */}
            {/* -------------------------------------------------------------- */}
            {verdict.kind === 'malformed' ? (
              <>
                <Check state="bad" note={verdict.errors.join(' · ')}>
                  the document is not a valid app description
                </Check>
                <Check state="pend">
                  a document that fails here makes no claim at all — nothing about an identity
                  follows from it
                </Check>
              </>
            ) : (
              <Check
                state="ok"
                note="closed member set, required members present and non-empty, carriage cap respected"
              >
                structurally valid against{' '}
                <a
                  href="https://schemas.dfos.com/dfos-app/v1"
                  rel="noreferrer noopener"
                  target="_blank"
                >
                  dfos-app/v1
                </a>
              </Check>
            )}

            {/* -------------------------------------------------------------- */}
            {/* beat 3 — the chain, where the binding becomes math              */}
            {/* -------------------------------------------------------------- */}
            {verdict.kind === 'no-carriage' ? (
              <Check
                state="warn"
                note="identity_chain is optional — but without it the origin proves no DID here"
              >
                no chain carried — <b>identity not verifiable from the origin alone</b>
              </Check>
            ) : proven !== null ? (
              <>
                <Check
                  state="ok"
                  note={`${proven.log.length} operation(s) — every signature and CID recomputed here`}
                >
                  the carried chain verifies
                </Check>
                <Check state="ok" note={proven.did}>
                  <code>client_did</code> equals the DID its genesis operation derives
                </Check>
              </>
            ) : null}

            {/* -------------------------------------------------------------- */}
            {/* beat 4 — the relays' ordered log                                */}
            {/* -------------------------------------------------------------- */}
            {proven !== null ? <RelayChecks relay={relay} comparison={comparison} /> : null}
          </>
        )}
      </Checks>

      {verdict.kind === 'unreachable' && verdict.proxyDown ? (
        <div class="ck-note" style={{ marginTop: 10 }}>
          The explorer reaches third-party origins through one serverless route, because origins
          don't reliably send CORS headers on well-knowns. That route isn't answering here (it does
          not exist on a local <code>vite dev</code> server), so this says nothing about{' '}
          {props.host}.
        </div>
      ) : null}
    </Panel>
  );
};

/** Beat 4's rows. An absent relay log is an ABSENCE — the honest amber — and
 *  never rendered as agreement or as a divergence. */
const RelayChecks = (props: { relay: RelayBeat; comparison: LogComparison | null }) => {
  const { relay, comparison } = props;
  if (relay.phase === 'idle' || relay.phase === 'loading') {
    return <Check state="pend">resolving the derived DID on your relays…</Check>;
  }
  if (relay.phase === 'absent') {
    return (
      <Check state="warn" note={relay.error}>
        no relay you've configured holds this identity — carriage is the only source here
      </Check>
    );
  }
  if (comparison === null) return null;

  switch (comparison.verdict) {
    case 'identical':
      return (
        <Check state="ok" note={`${comparison.shared} operation(s), same order`}>
          the relays' log and the carried chain are identical
        </Check>
      );
    case 'ahead':
      return (
        <Check
          state="warn"
          note={`the origin carries ${comparison.originOnly} operation(s) past the ${comparison.shared} the relays hold`}
        >
          the origin's chain is <b>ahead</b> of the relays — they haven't ingested the newest
          operations
        </Check>
      );
    case 'behind':
      return (
        <Check
          state="warn"
          note={`the relays hold ${comparison.relayOnly} operation(s) the document no longer carries`}
        >
          <b>rollback signal</b> — the carried chain is a strict prefix of the relays' log
        </Check>
      );
    case 'diverged':
      return (
        <Check
          state="bad"
          note={`the logs agree for ${comparison.shared} operation(s), then contradict`}
        >
          <b>signed contradiction</b> — the origin and the relays serve different operations at the
          same position
        </Check>
      );
  }
};

// -----------------------------------------------------------------------------
// the document itself
// -----------------------------------------------------------------------------

/** What the document SAYS. Every field here is the application's own claim —
 *  amber by construction. `name` in particular is vouched for by nothing: the
 *  serving domain is the phishing-relevant binding, and the spec says so. */
const AppPanel = (props: { app: AppDescription }) => (
  <Panel
    title="app description"
    accent="warn"
    right={<span class="lbl">the origin's own claims</span>}
    orient={
      <>
        The document's contents, <b>as served</b>. Nothing vouches for <code>name</code> — an
        application naming itself anything is not evidence of anything; the domain that served the
        file is the binding that matters.
      </>
    }
  >
    <div class="kv">
      <div class="k">name</div>
      <div class="v">
        <span class="attr">{props.app.name}</span> <Badge state="warn">claimed</Badge>
      </div>
      <div class="k">client_did</div>
      <div class="v">
        {props.app.client_did ? (
          <TruncId value={props.app.client_did} head={40} tail={0} />
        ) : (
          <span class="muted">not declared</span>
        )}
      </div>
      <div class="k">
        redirect_uris <span class="lbl">exact-match allowlist</span>
      </div>
      <div class="v">
        {props.app.redirect_uris.map((uri) => (
          <div key={uri}>{uri}</div>
        ))}
      </div>
      <div class="k">identity_chain</div>
      <div class="v">
        {props.app.identity_chain && props.app.identity_chain.length > 0 ? (
          `${props.app.identity_chain.length} operation(s) carried`
        ) : (
          <span class="muted">not carried</span>
        )}
      </div>
    </div>
  </Panel>
);
