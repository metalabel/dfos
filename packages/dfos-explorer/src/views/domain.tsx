/*

  DOMAIN VIEW — what an origin says about itself, checked

  The other detail views start from an identifier and ask the relays. This one
  starts from a DOMAIN and asks the domain, because two of the artifacts a domain
  can serve say something about a DFOS identity, and this page checks both.

  ORIGIN BINDING (ORIGIN-BINDING.md), the headline when it resolves. The domain
  attests a DID — a `_dfos` TXT record or `/.well-known/dfos-did` — and that DID's
  chain must name this exact domain back. It is the domain-first walk
  `dfos identity verify-binding <hostname>` runs, and it is the one thing on this
  page that binds an identity to the domain in both directions.

  APP DESCRIPTION (SIWD.md), four beats, each failing differently:

    1. the ORIGIN served a document        → unreachable / no-app-description
    2. it is a valid app description       → malformed
    3. its carried chain verifies + derives its client_did  → malformed
    4. the relays' log for that DID agrees  → relay-diverged

  The two are independent claims and a domain may make either, both, or neither.
  So an absent app description on a bound origin is a NEUTRAL fact, not a failure
  headline — this origin describes no app, which is nothing at all to fix.

  The binding's two channels are checked from the TAB wherever a tab can: `_dfos`
  TXT over DNS-over-HTTPS, and `/.well-known/dfos-did` fetched directly from
  origins that permit a cross-origin read. The explorer's own serverless routes
  fill in what the browser cannot reach — the app-description beats above, and
  whichever binding channel came back unreadable — so each binding row says its
  vantage, and a channel NEITHER could read says exactly that.

  Whatever the vantage, a failure to reach is OUR failure and says so — never
  "this origin has no app description" or "this domain is silent", which are
  claims about someone else's server we did not observe.

*/

import type { Resolved } from '@metalabel/dfos-client';
import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { BindingEvidence } from '../components/binding-evidence';
import { Check, Checks } from '../components/checks';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import {
  Badge,
  DidLink,
  DocsLink,
  Panel,
  Pill,
  Related,
  SETUP_GUIDE,
  Term,
  TROUBLESHOOTING_GUIDE,
  TruncId,
  type PillState,
} from '../components/ui';
import {
  probeBindingChannels,
  probeFromChannels,
  type DualChannelProbe,
} from '../lib/binding-browser';
import { getClient } from '../lib/client';
import { GLOSSARY } from '../lib/glossary';
import { toOpRows, type OpRow } from '../lib/op-rows';
import {
  assessDomainBinding,
  attestedCandidate,
  domainBindingSpeaks,
  fallbackEligible,
  readAppAttestation,
  type AppAttestation,
  type AttestedChain,
  type DomainBinding,
} from '../lib/origin-binding';
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

/** The origin-binding beat. The channels are kept beside the verdict because the
 *  panel renders BOTH — the verdict, and the per-channel evidence it was folded
 *  from — and a verdict without its evidence is the bare checkmark the spec's
 *  display discipline forbids. Each channel carries its VANTAGE, so a row can say
 *  whether the tab read it or the explorer's route did. */
type BindingBeat =
  | { phase: 'checking' }
  | {
      phase: 'done';
      binding: DomainBinding;
      channels: DualChannelProbe;
      fallback: AppAttestation | null;
    };

export const Domain = (props: { host: string }) => {
  const [document, setDocument] = useState<DomainVerdict | null>(null);
  const [relay, setRelay] = useState<RelayBeat>({ phase: 'idle' });
  const [binding, setBinding] = useState<BindingBeat>({ phase: 'checking' });
  // re-check nonce. Most of the amber and red states here are TRANSIENT — a
  // hosting blip, a deploy mid-flight, our own route flapping — and the explorer
  // is stateless, so the only honest answer to "is this still true?" is to ask
  // the origin again. Bumping this re-runs beat 1 from nothing: no cache, no
  // remembered verdict, no "last confirmed" date we were never in a position to
  // know.
  const [nonce, setNonce] = useState(0);

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
  }, [props.host, nonce]);

  // the origin-binding walk, domain-first: probe both attest-back channels, take
  // the DID they attest, resolve and VERIFY that identity here, and require its
  // chain to name this exact host back. Independent of the document beats above —
  // a domain can be a bound origin, an app host, both, or neither.
  //
  // Both channels are checked from the TAB first — `_dfos` TXT over
  // DNS-over-HTTPS, and the well-known document directly wherever the origin
  // permits a cross-origin read — and the explorer's own route fills in only what
  // the browser could not reach. A channel neither vantage could read is neutral,
  // never a verdict about the domain (src/lib/binding-browser.ts).
  useEffect(() => {
    let dead = false;
    setBinding({ phase: 'checking' });
    void (async () => {
      const channels = await probeBindingChannels(props.host);
      const probe = probeFromChannels(channels);
      // the app-description fallback is a MUST, and ONLY on absence. Here it can
      // also SUPPLY the candidate: an origin that publishes nothing but a SIWD
      // app description already publishes its DID, and this reads it.
      const fallback = fallbackEligible(probe) ? await readAppAttestation(props.host) : undefined;
      const candidate = attestedCandidate(probe, fallback);

      let chain: AttestedChain | null = null;
      if (candidate !== null) {
        try {
          const resolved = await getClient().identity(candidate);
          chain = {
            kind: 'verified',
            did: resolved.value.did,
            services: resolved.value.services,
          };
        } catch (e) {
          // no relay served this identity, or it failed verification here. COULD
          // NOT CHECK — never folded into "the chain claims nothing", which is a
          // chain we actually read.
          chain = {
            kind: 'unavailable',
            did: candidate,
            reason: e instanceof Error ? e.message : String(e),
          };
        }
      }
      if (dead) return;
      setBinding({
        phase: 'done',
        binding: assessDomainBinding(props.host, probe, fallback, chain),
        channels,
        fallback: fallback ?? null,
      });
    })();
    return () => {
      dead = true;
    };
  }, [props.host, nonce]);

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

  // a binding that SPOKE earns the headline panel; silence and our own route
  // failing stay one quiet line in the header, because neither is an observation
  // about this domain's binding. The flag also neutralizes the app-description
  // states below: with a binding on the page, "no app description" is a fact
  // about what this origin does, not a failure to lead with.
  const speaks = binding.phase === 'done' && domainBindingSpeaks(binding.binding);

  return (
    <>
      <Panel
        title={
          <>
            domain <StatePill verdict={verdict} neutralAbsence={speaks} />
          </>
        }
        accent={accentFor(verdict, speaks)}
        orient={
          <>
            What a domain publishes about DFOS identities, checked here. Two independent claims: the{' '}
            <Term word="origin binding" def={GLOSSARY['originBinding'] ?? ''} /> — the domain
            attests a DID and that identity's chain names the domain back — and the{' '}
            <Term word="app description" def={GLOSSARY['appDescription'] ?? ''} /> at{' '}
            <code>/.well-known/dfos-app.json</code>, where{' '}
            <b>a domain vouches for a DFOS identity</b> and serving the file is the registration: no
            developer portal, no client secret,{' '}
            <Term word="domain control" def={GLOSSARY['did'] ?? ''} /> is the credential. A domain
            may make either claim, both, or neither. Everything on this page is recomputed in your
            browser — relays are inputs, not authorities. <a href="#/">how this works</a>
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
          {speaks ? null : (
            <>
              <div class="k">origin binding</div>
              <div class="v">
                <QuietBinding beat={binding} />
              </div>
            </>
          )}
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

      {binding.phase === 'done' && speaks ? (
        <OriginBindingPanel
          host={props.host}
          beat={binding}
          onRecheck={() => setNonce((n) => n + 1)}
        />
      ) : null}

      {verdict === null ? (
        <Panel title="verification">
          <Checks>
            <Check state="pend">reading the origin's app description…</Check>
          </Checks>
        </Panel>
      ) : (
        <Verification
          host={props.host}
          verdict={verdict}
          relay={relay}
          comparison={comparison}
          neutralAbsence={speaks}
          onRecheck={() => setNonce((n) => n + 1)}
        />
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

/**
 * The plain-language layer under the pill. The verdict WORD is unchanged and
 * stays primary — it is the thing that stays machine-distinguishable — and this
 * is what it means, said plainly, one hover or tap away.
 *
 * Nothing here softens a state into a neighbouring one: an unreachable origin is
 * still an origin we learned nothing about, an absent document is still not a
 * contradiction, and a divergence is still signed.
 */
const STATE_DEFS: Record<Exclude<DomainVerdict['kind'], 'unreachable'>, string> = {
  verified:
    'The origin served an app description, the identity chain it carries verifies in your browser, and that chain derives the exact client_did the document claims.',
  'relay-diverged': GLOSSARY['relayDiverged'] ?? '',
  'no-carriage': GLOSSARY['noCarriage'] ?? '',
  malformed:
    'The origin served something at this path and it is not a valid app description — a document that fails here makes no claim at all, so nothing about an identity follows from it.',
  'no-app-description':
    'The origin answered, and has no such document — it describes no DFOS app. An absence, not a contradiction: nothing here says the domain got anything wrong.',
};

/** The two flavours of `unreachable` mean opposite things about WHOSE fault it
 *  is, so they never share a definition. */
const PROXY_DOWN_DEF =
  'The explorer’s own lookup route did not answer, so nothing at all was learned about this domain. This is our failure, not a statement about the origin.';
const ORIGIN_DOWN_DEF =
  'Nothing was served, so nothing below could be checked. A transport failure — not a statement about what the domain publishes.';

const StatePill = (props: { verdict: DomainVerdict | null; neutralAbsence: boolean }) => {
  const { verdict } = props;
  if (verdict === null) return <Pill state="pending">checking origin…</Pill>;
  // an origin with a binding on the page and no app description is describing no
  // app — a complete answer, and amber would read as a shortfall
  if (verdict.kind === 'no-app-description' && props.neutralAbsence) {
    return (
      <Pill state="neutral" def={STATE_DEFS['no-app-description']}>
        no app description
      </Pill>
    );
  }
  switch (verdict.kind) {
    case 'verified':
      return (
        <Pill state="ok" def={STATE_DEFS.verified}>
          verified
        </Pill>
      );
    case 'relay-diverged':
      return (
        <Pill state="warn" def={STATE_DEFS['relay-diverged']}>
          origin verified · relay log diverged
        </Pill>
      );
    case 'no-carriage':
      return (
        <Pill state="warn" def={STATE_DEFS['no-carriage']}>
          app document present · no chain carried
        </Pill>
      );
    case 'malformed':
      return (
        <Pill state="bad" def={STATE_DEFS.malformed}>
          malformed app description
        </Pill>
      );
    case 'unreachable':
      return (
        <Pill state="bad" def={verdict.proxyDown ? PROXY_DOWN_DEF : ORIGIN_DOWN_DEF}>
          unreachable
        </Pill>
      );
    case 'no-app-description':
      return (
        <Pill state="warn" def={STATE_DEFS['no-app-description']}>
          no app description
        </Pill>
      );
  }
};

const accentFor = (
  verdict: DomainVerdict | null,
  neutralAbsence: boolean,
): 'ok' | 'warn' | 'bad' | undefined => {
  if (verdict === null) return undefined;
  if (verdict.kind === 'no-app-description' && neutralAbsence) return undefined;
  if (verdict.kind === 'verified') return 'ok';
  if (verdict.kind === 'malformed' || verdict.kind === 'unreachable') return 'bad';
  return 'warn';
};

// -----------------------------------------------------------------------------
// ORIGIN BINDING — the domain-first walk, and the page's headline when it speaks
//
// Display discipline here is NORMATIVE (ORIGIN-BINDING.md, "Display Discipline"):
// a binding proves control of a DOMAIN at check time — never personhood,
// endorsement, or notability — so the panel always shows the domain AND the
// identity together, and never collapses the verdict into a checkmark divorced
// from them. The evidence rows sit under the verdict for the same reason: a
// silent channel beside an attesting one is the ordinary shape of a healthy
// binding, and it is rendered as what it is rather than as a warning.
// -----------------------------------------------------------------------------

/** The pill, and the same verdict said plainly. The precise word stays the label
 *  — bound / stale / broken are what stay machine-distinguishable — and the plain
 *  rendering is one hover or tap away. The two half-states below the three spec
 *  verdicts keep could-not-check and checked-and-absent apart, which is the same
 *  discipline the stale/broken split enforces one level up. */
const bindingPill = (binding: DomainBinding): { state: PillState; text: string; def: string } => {
  switch (binding.kind) {
    case 'bound':
      return { state: 'ok', text: 'bound', def: GLOSSARY['bindingBound'] ?? '' };
    case 'broken':
      return {
        state: 'bad',
        text: 'broken — the domain contradicts itself',
        def: GLOSSARY['bindingBroken'] ?? '',
      };
    case 'chain-unavailable':
      return {
        state: 'warn',
        text: 'attested identity unresolved',
        def: 'The domain attests a DID, and no relay you have configured resolved that identity — so the chain half of the binding could not be checked. Could not check: nothing here says the binding is wrong.',
      };
    case 'no-chain-claim':
      return {
        state: 'warn',
        text: 'attested, not claimed back',
        def: 'The domain attests an identity and that identity’s verified chain names no domain, so there is no binding. Half a binding is no binding — the chain entry is the identity’s signed consent to be named by the domain.',
      };
    case 'stale':
      return {
        state: 'neutral',
        text: 'no attestation published',
        def: GLOSSARY['bindingStale'] ?? '',
      };
    case 'proxy-unavailable':
      return {
        state: 'warn',
        text: 'not checkable from here',
        def: GLOSSARY['bindingNotCheckable'] ?? '',
      };
  }
};

/** The one-line binding state for the header, where the binding has nothing to
 *  say: the domain published nothing, or our own route failed. Deliberately
 *  quiet — an origin that publishes no attestation is not missing anything. */
const QuietBinding = (props: { beat: BindingBeat }) => {
  if (props.beat.phase === 'checking') {
    return <span class="muted">asking the domain…</span>;
  }
  const binding = props.beat.binding;
  if (binding.kind === 'proxy-unavailable') {
    return (
      <span class="muted">
        neither channel could be checked — your browser could not read them and the explorer's
        lookup route did not answer either, so nothing was learned about this domain
      </span>
    );
  }
  return <span class="muted">none — this domain attests no identity</span>;
};

/** Everything the domain-first walk established, in the order it establishes it:
 *  what each channel answered, whether the attested identity resolves, and
 *  whether its chain names this exact host back. */
const OriginBindingPanel = (props: {
  host: string;
  beat: Extract<BindingBeat, { phase: 'done' }>;
  onRecheck: () => void;
}) => {
  const { binding, channels, fallback } = props.beat;
  const pill = bindingPill(binding);
  // the DID the rows are judged against. Null on a domain that contradicts
  // ITSELF: there is no identity yet to compare answers to, and each answer is
  // rendered as an answer rather than as a match or a mismatch.
  const did = binding.kind === 'stale' || binding.kind === 'proxy-unavailable' ? null : binding.did;
  // the header rule takes the verdict's colour; `neutral` and `pending` carry no
  // rule, and neither reaches this panel
  const accent =
    pill.state === 'ok' || pill.state === 'bad' || pill.state === 'warn' ? pill.state : undefined;

  return (
    <Panel
      title={
        <>
          origin binding{' '}
          <Pill state={pill.state} def={pill.def} word={pill.text}>
            {pill.text}
          </Pill>
        </>
      }
      accent={accent}
      right={<span class="lbl">browser first, route where it can't reach</span>}
      orient={
        <>
          The domain attests an identity and that identity's chain names the domain back — an{' '}
          <Term word="origin binding" def={GLOSSARY['originBinding'] ?? ''} />. It proves{' '}
          <b>control of this domain</b> at check time: never personhood, endorsement, or notability.
          The domain is the credential, so both halves are shown, never summarized into a badge.
          Each channel below says its <Term word="vantage" def={GLOSSARY['bindingVantage'] ?? ''} />{' '}
          — whether your browser read it, or the explorer's lookup route read it for you where a
          browser can't.
        </>
      }
    >
      <div class="kv">
        <div class="k">
          domain <span class="lbl">the host you looked up</span>
        </div>
        <div class="v">{props.host}</div>
        <div class="k">
          identity <span class="lbl">attested by this domain</span>
        </div>
        <div class="v">
          {did !== null ? (
            <DidLink did={did} full />
          ) : (
            <span class="muted">
              the channels name different identities — the domain attests no single one
            </span>
          )}
        </div>
      </div>

      <Checks>
        <BindingEvidence
          https={channels.https.result}
          dns={channels.dns.result}
          fallback={fallback}
          did={did}
          settled={binding.kind === 'bound'}
          vantage={{ https: channels.https.vantage, dns: channels.dns.vantage }}
        />
        <BindingChainChecks binding={binding} />
      </Checks>

      {binding.kind === 'bound' ? (
        // the two well-known documents are constantly mistaken for one another,
        // and this page now checks both — so name which is which, here, once.
        <div class="ck-note" style={{ marginTop: 10 }}>
          This is the <Term word="domain attestation" def={GLOSSARY['domainAttestation'] ?? ''} /> (
          <code>dfos-did</code> / <code>_dfos</code> TXT), checked against the identity's signed
          chain. The panels below check this domain's{' '}
          <Term word="app description" def={GLOSSARY['appDescription'] ?? ''} /> (
          <code>dfos-app.json</code>) — a different claim, which neither confirms nor denies this
          binding.
        </div>
      ) : null}
      {binding.kind === 'broken' ? (
        <div class="ck-note" style={{ marginTop: 10 }}>
          {binding.details.join(' · ')}. A domain that answers with something else contradicts the
          identity's claim — the identity and its history are untouched, only the domain claim is
          contradicted.
        </div>
      ) : null}
      {binding.kind === 'chain-unavailable' ? (
        <div class="ck-note" style={{ marginTop: 10 }}>
          The domain's half was read; the chain half was not. Add a relay that serves this identity
          — or check it later — and the walk completes. Nothing here is a statement that the binding
          is wrong.
        </div>
      ) : null}

      <BindingNextStep binding={binding} onRecheck={props.onRecheck} />
    </Panel>
  );
};

/** The chain half's rows: did the attested identity resolve, and does its chain
 *  name this exact host back. Byte-exact — a binding to `example.org` says
 *  nothing about `sub.example.org`, in either direction. */
const BindingChainChecks = (props: { binding: DomainBinding }) => {
  const { binding } = props;
  switch (binding.kind) {
    case 'stale':
    case 'proxy-unavailable':
      return null;
    case 'broken':
      // a domain contradicting ITSELF never reached a chain; the other broken
      // shape is a chain that resolved and claims somewhere else
      return binding.did === null ? null : (
        <>
          <Check state="ok" note={binding.did}>
            the attested identity's chain verifies in your browser
          </Check>
          <Check state="bad" note={binding.details.join(' · ')}>
            its chain claims a <b>different domain</b>
          </Check>
        </>
      );
    case 'chain-unavailable':
      return (
        <Check state="warn" note={binding.reason}>
          the attested identity did not resolve — <b>could not check</b> the chain half
        </Check>
      );
    case 'no-chain-claim':
      return (
        <>
          <Check state="ok" note={binding.did}>
            the attested identity's chain verifies in your browser
          </Check>
          <Check
            state="warn"
            note={
              binding.claim === 'ambiguous'
                ? 'more than one DfosOrigin entry — an ambiguous claim is no claim'
                : 'no DfosOrigin entry in this identity’s services'
            }
          >
            its chain claims no domain —{' '}
            <b>an attestation without a chain claim is not a binding</b>
          </Check>
        </>
      );
    case 'bound':
      return (
        <>
          <Check state="ok" note={binding.did}>
            the attested identity's chain verifies in your browser
          </Check>
          <Check state="ok" note={`DfosOrigin service entry — ${binding.domain}`}>
            its chain claims this exact domain back
          </Check>
        </>
      );
  }
};

/** The action line under an amber or red binding. A domain that has published
 *  nothing yet is setup-shaped and never reaches here (it stays a quiet header
 *  line); everything that does reach here is a failure or a contradiction. */
const BindingNextStep = (props: { binding: DomainBinding; onRecheck: () => void }) => {
  if (props.binding.kind === 'bound') return null;
  return (
    <div class="ck-note" style={{ marginTop: 10 }}>
      {props.binding.kind === 'no-chain-claim' ? (
        <>
          if this is your domain, the <DocsLink href={SETUP_GUIDE}>setup guide ↗</DocsLink> covers
          claiming it on the identity's chain. troubleshooting:{' '}
          <DocsLink href={TROUBLESHOOTING_GUIDE}>what can go wrong ↗</DocsLink>.
        </>
      ) : (
        <>
          what this means and what to do:{' '}
          <DocsLink href={TROUBLESHOOTING_GUIDE}>the troubleshooting guide ↗</DocsLink>.
        </>
      )}{' '}
      <button onClick={props.onRecheck}>re-check</button>
    </div>
  );
};

// -----------------------------------------------------------------------------
// the verification ladder
// -----------------------------------------------------------------------------

const Verification = (props: {
  host: string;
  verdict: DomainVerdict;
  relay: RelayBeat;
  comparison: LogComparison | null;
  /** an origin binding already resolved above, so an absent app description is a
   *  neutral fact about this origin rather than something it fell short of */
  neutralAbsence: boolean;
  onRecheck: () => void;
}) => {
  const { verdict, relay, comparison } = props;
  const proven = originVerified(verdict);

  return (
    <Panel
      title="verification"
      right={<span class="lbl">re-run in your browser</span>}
      // TWO well-known documents exist and they are constantly confused for one
      // another, so wherever either is checked BOTH are named — and the panel
      // says which one it is looking at, and where the other one is checked.
      orient={
        <>
          This checks the domain's{' '}
          <Term word="app description" def={GLOSSARY['appDescription'] ?? ''} /> (
          <code>dfos-app.json</code>) — how a domain describes an app. Separately, a domain attests
          an identity back (the{' '}
          <Term word="domain attestation" def={GLOSSARY['domainAttestation'] ?? ''} />,{' '}
          <code>dfos-did</code> / <code>_dfos</code> TXT): that is the origin-binding check, which
          runs above and on the identity page. Neither claim confirms or denies the other.
        </>
      }
    >
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
            state={props.neutralAbsence ? 'pend' : 'warn'}
            note={
              verdict.httpStatus !== null
                ? `HTTP ${verdict.httpStatus} — the origin answered, and has no such document`
                : 'the origin answered, and has no such document'
            }
          >
            this origin serves no app description
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
          The explorer reaches third-party origins through a stateless serverless route, because
          origins don't reliably send CORS headers on well-knowns. That route isn't answering here
          (it does not exist on a local <code>vite dev</code> server), so this says nothing about{' '}
          {props.host}.
        </div>
      ) : null}

      <NextStep
        verdict={verdict}
        neutralAbsence={props.neutralAbsence}
        onRecheck={props.onRecheck}
      />
    </Panel>
  );
};

/**
 * WHAT TO DO ABOUT IT — the one muted line every amber and red verdict earns.
 *
 * Deliberately separate from the checks above it: the ladder says what was
 * OBSERVED, this says where to go next, and mixing them would let an action hint
 * soften an observation. Setup-shaped states (the domain has not published
 * something yet) point at the setup guide; failure and contradiction states point
 * at troubleshooting. A re-check sits beside both, because the explorer keeps no
 * history and half of these states are a minute old.
 */
const SETUP_HINT: Partial<Record<DomainVerdict['kind'], string>> = {
  'no-app-description': 'covers serving the app description',
  malformed: "covers the app description's required members",
  'no-carriage': 'covers carrying the identity chain in the app description',
};

const NextStep = (props: {
  verdict: DomainVerdict;
  neutralAbsence: boolean;
  onRecheck: () => void;
}) => {
  if (props.verdict.kind === 'verified') return null;
  // an origin that describes no app, on a page that already carries its binding,
  // is not mid-setup — pointing at the setup guide would invent a shortfall
  if (props.verdict.kind === 'no-app-description' && props.neutralAbsence) return null;
  const hint = SETUP_HINT[props.verdict.kind];
  return (
    <div class="ck-note" style={{ marginTop: 10 }}>
      {hint !== undefined ? (
        <>
          if this is your domain, the <DocsLink href={SETUP_GUIDE}>setup guide ↗</DocsLink> {hint}.
          troubleshooting: <DocsLink href={TROUBLESHOOTING_GUIDE}>what can go wrong ↗</DocsLink>.
        </>
      ) : (
        <>
          what this means and what to do:{' '}
          <DocsLink href={TROUBLESHOOTING_GUIDE}>the troubleshooting guide ↗</DocsLink>.
        </>
      )}{' '}
      <button onClick={props.onRecheck}>re-check</button>
    </div>
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
        {props.app.name !== undefined ? (
          <>
            <span class="attr">{props.app.name}</span> <Badge state="warn">claimed</Badge>
          </>
        ) : (
          <span class="muted">not claimed — the domain leads</span>
        )}
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
