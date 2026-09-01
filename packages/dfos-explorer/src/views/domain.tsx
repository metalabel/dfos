/*

  DOMAIN VIEW — what an origin says about itself, checked

  The other detail views start from an identifier and ask the relays. This one
  starts from a DOMAIN and asks the domain, because two of the artifacts a domain
  can serve say something about a DFOS identity, and this page checks both.

  TWO BLOCKS, in this order, under a header that carries the binding's verdict:

    identity binding   which identity this domain is bound to, and the evidence
    domain app         whether this domain describes an app, whether that claim
                       holds, and what the document actually says

  The two blocks are the page's two questions, and each is answered in one place.
  The panel titles are the plain question; the spec nouns — origin binding, app
  description — live in the orienting prose with their glossary definitions, where
  a reader who wants the exact term finds it.

  ORIGIN BINDING (ORIGIN-BINDING.md) is the HEADLINE, whatever it says. The domain
  attests a DID — a `_dfos` TXT record or `/.well-known/dfos-did` — and that DID's
  chain must name this exact domain back. It is the domain-first walk
  `dfos identity verify-binding <hostname>` runs, and it is the one thing on this
  page that binds an identity to the domain in both directions. The page is about
  a DOMAIN, so the domain's own claim about its identity is what the title pill
  and the page's accent speak, and every app-description state below is a
  subordinate claim that colours its own panel and no more.

  APP DESCRIPTION (SIWD.md), four beats, each failing differently:

    1. the ORIGIN served a document        → unreachable / no-app-description /
                                             redirected
    2. it is a valid app description       → malformed
    3. its carried chain verifies + derives its client_did  → malformed
    4. the relays' log for that DID agrees  → relay-diverged

  The two are independent claims and a domain may make either, both, or neither.
  So an absent app description is a NEUTRAL fact wherever it appears — a 404 is an
  affirmative, complete answer that this origin describes no app, and there is
  nothing at all in it to fix. A REDIRECT is the opposite and is never neutral: the
  document must be served at the fixed path and redirects are not followed, so a
  redirect is a NON-ANSWER — nothing was learned, which is not the same as having
  learned that nothing is there.

  The binding's two channels are checked from the TAB wherever a tab can: `_dfos`
  TXT over DNS-over-HTTPS, and `/.well-known/dfos-did` fetched directly from
  origins that permit a cross-origin read. The explorer's own serverless routes
  fill in what the browser cannot reach — the app-description beats above, and
  whichever binding channel came back unreadable — so each binding row says its
  vantage, and a channel NEITHER could read says exactly that.

  Whatever the vantage, a failure to reach is OUR failure and says so — never
  "this origin has no app description" or "this domain is silent", which are
  claims about someone else's server we did not observe.

  WHAT THIS PAGE DELIBERATELY DOES NOT RENDER: the operation history of the DID an
  app description proves. Those operations belong to the APP's identity, which is
  routinely a DIFFERENT identity from the one bound to the domain — so a timeline
  of them under this page's headline is evidence captioned by the wrong subject.
  It is one click away on that identity's own page, where the caption is true.

  What this page CAN say, and no other page is in a position to say, is how the
  two identities relate — the one bound to the domain, and the one the app
  description proved. It says it, once, as a plain fact, and it colours nothing:
  the two being different is the ordinary arrangement, not a finding.

*/

import { useEffect, useState } from 'preact/hooks';
import { BindingEvidence } from '../components/binding-evidence';
import { Check, Checks } from '../components/checks';
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
  type OriginVerified,
} from '../lib/wellknown';

/** The relay beat, kept separate from the document beat: the relays may hold
 *  nothing at all for a DID the origin carries, which is an ABSENCE, not a
 *  disagreement, and must not be compared as though it were an empty log.
 *
 *  It carries the LOG and nothing else. The relays' operations for this DID are
 *  not rendered on this page: they are the history of the APP's identity, and
 *  this page's subject is the domain and the identity BOUND to it — which is
 *  routinely a different identity. That history is one click away on the app
 *  identity's own page, where it is captioned by the identity it belongs to. */
type RelayBeat =
  | { phase: 'idle' }
  | { phase: 'loading' }
  | { phase: 'absent'; error: string }
  | { phase: 'held'; log: string[] };

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
        const [, log] = await Promise.all([
          // asked, and its answer deliberately not kept. The question this beat
          // answers is whether the relays HOLD this identity, and a log served
          // for an identity that does not resolve and verify is not a holding —
          // so the call stays even though nothing on this page renders it.
          client.identity(did),
          client.log('identity', did),
        ]);
        if (dead) return;
        setRelay({ phase: 'held', log: log.value.map((e) => e.jwsToken) });
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

  // a binding that SPOKE earns the panel below the header; silence and our own
  // route failing stay one quiet line in the header, because neither is an
  // observation about this domain's binding worth a panel of evidence. The
  // headline pill speaks either way — an origin that attests nothing is a
  // perfectly ordinary domain, and saying so is the answer, not the absence of one.
  const speaks = binding.phase === 'done' && domainBindingSpeaks(binding.binding);

  return (
    <>
      <Panel
        title={
          <>
            domain <BindingHeadline beat={binding} />
          </>
        }
        accent={headlineAccent(binding)}
        orient={
          <>
            What a domain publishes about DFOS identities, checked here. The headline is the{' '}
            <Term word="origin binding" def={GLOSSARY['originBinding'] ?? ''} /> — the domain
            attests a DID and that identity's chain names the domain back — which is the one claim
            here that binds an identity to this domain in both directions. Under it sits a second,
            independent claim: the{' '}
            <Term word="app description" def={GLOSSARY['appDescription'] ?? ''} /> at{' '}
            <code>/.well-known/dfos-app.json</code>, where{' '}
            <b>a domain vouches for a DFOS identity</b> and serving the file is the registration: no
            developer portal, no client secret,{' '}
            <Term word="domain control" def={GLOSSARY['did'] ?? ''} /> is the credential. A domain
            may make either claim, both, or neither, and neither confirms or denies the other.
            Everything on this page is recomputed in your browser — relays are inputs, not
            authorities. <a href="#/">how this works</a>
          </>
        }
      >
        <div class="kv">
          <div class="k">origin</div>
          <div class="v">
            {/* the site root, because this page is about the DOMAIN — the
                app-description path is one of the two things checked on it, and
                linking it here would make the page look like it is about the app */}
            <a href={`https://${props.host}/`} rel="noreferrer noopener">
              {props.host}
            </a>
          </div>
          <div class="k">
            app <span class="lbl">checked below</span>
          </div>
          <div class="v">
            <span class="muted">{appWord(verdict)}</span>
          </div>
          {binding.phase === 'done' && !speaks ? (
            <>
              <div class="k">origin binding</div>
              <div class="v">
                <QuietBinding binding={binding.binding} />
              </div>
            </>
          ) : null}
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
        <Panel
          title={
            <>
              domain app <Pill state="pending">checking origin…</Pill>
            </>
          }
        >
          <Checks>
            <Check state="pend">reading the origin's app description…</Check>
          </Checks>
        </Panel>
      ) : (
        <DomainApp
          host={props.host}
          verdict={verdict}
          binding={binding}
          relay={relay}
          comparison={comparison}
          onRecheck={() => setNonce((n) => n + 1)}
        />
      )}

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
// THE HEADLINE — the domain's own claim about its identity
//
// The page is about a DOMAIN, so the title pill and the page's accent speak the
// ORIGIN BINDING and nothing else. Every app-description state, green and red
// alike, is a claim about one document this origin may or may not serve, and it
// colours the panel that reports it rather than the page: whether an app document
// is absent, malformed, or unreadable has never been evidence about whether this
// domain attests an identity, and a red headline over a bound domain says
// something about the domain that nobody checked.
// -----------------------------------------------------------------------------

/**
 * The domain-first `stale` verdict, said in the header. The panel's wording is
 * written for the chain-first walk, where a claim stands and the domain has not
 * confirmed it; read domain-first the same verdict means something far more
 * ordinary — this domain published no attestation, which is what almost every
 * domain on the internet does — and it is stated as the complete answer it is.
 */
const NO_ATTESTATION_DEF =
  'This domain publishes no origin-binding attestation — no `_dfos` TXT record and no /.well-known/dfos-did document. A complete, ordinary answer, and the one most domains give: an absent attestation is not a failure, and nothing here is missing.';

/**
 * The binding verdict, as the page's headline. Every state speaks here, including
 * the two the evidence panel below stays quiet about, because "this domain
 * attests no identity" is an ANSWER and the header is where the answer goes.
 */
const BindingHeadline = (props: { beat: BindingBeat }) => {
  if (props.beat.phase === 'checking') return <Pill state="pending">asking the domain…</Pill>;
  const binding = props.beat.binding;
  if (binding.kind === 'stale') {
    return (
      <Pill state="neutral" def={NO_ATTESTATION_DEF}>
        attests no identity
      </Pill>
    );
  }
  const pill = bindingPill(binding);
  return (
    <Pill state={pill.state} def={pill.def} word={pill.text}>
      {pill.text}
    </Pill>
  );
};

/** The page's accent, taken from the binding and only from the binding. No rule
 *  at all is the right rendering for a domain that attests nothing and for a check
 *  still in flight: neither is a state with a colour to earn. */
const headlineAccent = (beat: BindingBeat): 'ok' | 'warn' | 'bad' | undefined => {
  if (beat.phase === 'checking') return undefined;
  switch (beat.binding.kind) {
    case 'bound':
      return 'ok';
    case 'broken':
      return 'bad';
    case 'chain-unavailable':
    case 'no-chain-claim':
    case 'proxy-unavailable':
      return 'warn';
    case 'stale':
      return undefined;
  }
};

/**
 * The app-description state in one or two words, for the header's kv row. It is a
 * POINTER to the panel below rather than a verdict — each of these is said in
 * full, with its evidence and its plain definition, in the domain-app block —
 * and nothing is softened on the way up: a redirect says it answered nothing, an
 * unreachable origin says it was not reached, and an absence says this origin
 * describes no app.
 */
const appWord = (verdict: DomainVerdict | null): string => {
  if (verdict === null) return 'checking…';
  switch (verdict.kind) {
    case 'verified':
      return 'verified';
    case 'relay-diverged':
      return 'relay log diverged';
    case 'no-carriage':
      return 'no chain carried';
    case 'malformed':
      return 'malformed';
    case 'unreachable':
      return 'unreachable';
    case 'no-app-description':
      return 'describes no app';
    case 'redirected':
      return 'redirect — no answer';
  }
};

// -----------------------------------------------------------------------------
// the app-description pill — green ONLY for a verified chain
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
  redirected:
    'The origin answered the fixed path with a redirect. A redirect is a non-answer — the document must be served at the path itself and redirects are never followed — so nothing was learned about what this origin serves there.',
};

/** The two flavours of `unreachable` mean opposite things about WHOSE fault it
 *  is, so they never share a definition. */
const PROXY_DOWN_DEF =
  'The explorer’s own lookup route did not answer, so nothing at all was learned about this domain. This is our failure, not a statement about the origin.';
const ORIGIN_DOWN_DEF =
  'Nothing was served, so nothing below could be checked. A transport failure — not a statement about what the domain publishes.';

const StatePill = (props: { verdict: DomainVerdict }) => {
  const { verdict } = props;
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
    // NEUTRAL in every case. A 404 at this path is an affirmative, complete
    // answer — this origin describes no app — and amber would render a domain
    // that answered plainly as one that fell short of something.
    case 'no-app-description':
      return (
        <Pill state="neutral" def={STATE_DEFS['no-app-description']}>
          no app description
        </Pill>
      );
    // AMBER in every case, and never neutral: a non-answer is not an absence.
    // Nothing at all was established here, and rendering that as quietly as a
    // clean 404 would claim we checked something we did not.
    case 'redirected':
      return (
        <Pill state="warn" def={STATE_DEFS.redirected}>
          redirect — no answer at the fixed path
        </Pill>
      );
  }
};

/** The domain-app block's accent — the app verdict's own colour, scoped to the
 *  panel that reports it and no longer the page's. `no-app-description` carries
 *  none, for the same reason its pill is neutral: a rule down the side would read
 *  as a shortfall where the origin gave a complete answer. */
const appAccent = (verdict: DomainVerdict): 'ok' | 'warn' | 'bad' | undefined => {
  switch (verdict.kind) {
    case 'verified':
      return 'ok';
    case 'malformed':
    case 'unreachable':
      return 'bad';
    case 'relay-diverged':
    case 'no-carriage':
    case 'redirected':
      return 'warn';
    case 'no-app-description':
      return undefined;
  }
};

// -----------------------------------------------------------------------------
// IDENTITY BINDING — the domain-first walk, and the evidence behind the headline
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

/** The reason line under the header for the two states with no evidence panel to
 *  open: the domain published nothing, or our own route failed. The title pill
 *  already names the state; this carries the WHY, which a two-word pill cannot,
 *  and it stays deliberately quiet — an origin that publishes no attestation is
 *  not missing anything. */
const QuietBinding = (props: { binding: DomainBinding }) => {
  const { binding } = props;
  if (binding.kind === 'proxy-unavailable') {
    return (
      <span class="muted">
        neither channel could be checked — your browser could not read them and the explorer's
        lookup route did not answer either, so nothing was learned about this domain
      </span>
    );
  }
  // WHAT EACH CHANNEL SAID, not a second telling of the verdict. The title pill
  // above already says this domain attests no identity; repeating that sentence
  // here would spend the one line the header gives us saying nothing new, when
  // the useful thing is which channel was asked and what came back.
  const reasons = binding.kind === 'stale' ? binding.reasons : [];
  return (
    <span class="muted">
      {reasons.length > 0 ? reasons.join(' · ') : 'none — this domain attests no identity'}
    </span>
  );
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
        // `identity binding` in the title, `origin binding` as the term of art in
        // the orient below. The panel answers a plain question — which identity is
        // this domain bound to — and the spec noun, with its glossary definition,
        // is where a reader who wants the exact term finds it.
        <>
          identity binding{' '}
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
          chain. The block below checks this domain's{' '}
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
// DOMAIN APP — one block, one story
//
// The four-beat ladder and the document's own contents were two panels, and the
// split asked the reader to hold a question open across a panel boundary: the
// ladder said whether the claim holds, and the next panel said what the claim
// WAS. They are one story — does this domain describe an app, and does the claim
// hold — so they are one block, in that order, under one verdict pill.
//
// The document's contents keep their own framing inside it. Everything in them is
// the application's own claim and none of it is vouched for by the checks above:
// the ladder proving a chain says nothing about whether `name` is honest, and the
// two must not blur into one another just because they now share a panel.
// -----------------------------------------------------------------------------

const DomainApp = (props: {
  host: string;
  verdict: DomainVerdict;
  binding: BindingBeat;
  relay: RelayBeat;
  comparison: LogComparison | null;
  onRecheck: () => void;
}) => {
  const { verdict, relay, comparison } = props;
  const proven = originVerified(verdict);
  // the document's own claims, shown whenever there IS a document to show them
  // from — a chain that proved a DID, or a structurally valid one that carried no
  // chain. A malformed document has no claims to render: it makes no claim at all.
  const app: AppDescription | null =
    proven !== null ? proven.app : verdict.kind === 'no-carriage' ? verdict.app : null;

  return (
    <Panel
      // the app verdict's pill and its accent live HERE, on the panel that
      // reports the app description, rather than on the page — this claim is
      // about one document, and it colours the section that checked it
      title={
        <>
          domain app <StatePill verdict={verdict} />
        </>
      }
      accent={appAccent(verdict)}
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
        ) : verdict.kind === 'redirected' ? (
          <>
            <Check
              state="warn"
              note="the document must be served at the path itself; redirects are not followed"
            >
              the origin redirected at the fixed path
              {verdict.httpStatus !== null ? ` (HTTP ${verdict.httpStatus})` : ''}
            </Check>
            <Check state="pend">a redirect is a non-answer — nothing below could be checked</Check>
          </>
        ) : verdict.kind === 'no-app-description' ? (
          <Check
            state="pend"
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

      {app !== null ? <AppClaims app={app} /> : null}

      <RelationalLine binding={props.binding} proven={proven} />

      <NextStep verdict={verdict} onRecheck={props.onRecheck} />
    </Panel>
  );
};

/**
 * THE ONE FACT ONLY THIS PAGE IS IN A POSITION TO STATE.
 *
 * The identity page knows an identity; the app document names an identity. Only
 * here are BOTH in hand at once — the identity this domain is bound to, and the
 * identity its app description proved — and so only here can they be compared.
 *
 * Neither answer is a verdict, and the wording is careful to make that so: two
 * different identities is the ORDINARY arrangement (an organization binds the
 * domain, an app carries its own identity, and nothing in either spec asks them
 * to be the same), and one identity doing both is equally ordinary. This states
 * the relation and stops, because a page that colours this fact would be
 * inventing a rule out of a coincidence.
 *
 * It renders only when both halves genuinely exist: a `bound` binding, and an app
 * document whose carried chain derived a DID. Anything less and there is no
 * comparison to make — only two absences that would be dressed as a finding.
 */
const RelationalLine = (props: { binding: BindingBeat; proven: OriginVerified | null }) => {
  const { binding, proven } = props;
  if (binding.phase !== 'done' || binding.binding.kind !== 'bound' || proven === null) return null;
  // byte-exact, like every other DID comparison in this codebase
  const same = binding.binding.did === proven.did;
  return (
    <div class="ck-note" style={{ marginTop: 10 }}>
      {same
        ? 'the app’s identity is the same identity this domain is bound to.'
        : 'the app’s identity is a different identity than the one bound to this domain — ordinary: an organization binds the domain, and an app carries its own identity.'}
    </div>
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
  redirected:
    'covers serving the app description at the fixed path — a host that redirects (apex to www, say) must serve the document before the redirect',
};

const NextStep = (props: { verdict: DomainVerdict; onRecheck: () => void }) => {
  if (props.verdict.kind === 'verified') return null;
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

/** What the document SAYS, as a subsection of the block that checked it. Every
 *  field here is the application's own claim, and the ladder above vouches for
 *  none of it: `name` in particular is vouched for by nothing at all — the
 *  serving domain is the phishing-relevant binding, and the spec says so. Sharing
 *  a panel with the checks makes saying that MORE necessary, not less, so the
 *  framing line stays attached to the claims it qualifies. */
const AppClaims = (props: { app: AppDescription }) => (
  <>
    <div class="ck-note" style={{ marginTop: 14 }}>
      The document's contents, <b>as served</b>. Nothing vouches for <code>name</code> — an
      application naming itself anything is not evidence of anything; the domain that served the
      file is the binding that matters.
    </div>
    <div class="kv" style={{ marginTop: 8 }}>
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
  </>
);
