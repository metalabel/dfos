/*

  IDENTITY VIEW — two beats

  Beat 1: the relay's claim (instant, relay-asserted). Beat 2: dfos-client
  re-folds the whole op log in the tab and the page flips to verified — or
  the tip drifts and we say so. Keys and services re-render from the VERIFIED
  state once it lands.

*/

import type {
  IndexContentRow,
  IndexCountersignatureRow,
  IndexCredentialRow,
  Resolved,
} from '@metalabel/dfos-client';
import type { ServiceEntry, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { classifyAnchor } from '@metalabel/dfos-protocol/chain';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Check, Checks, type CheckState } from '../components/checks';
import { ContentChip } from '../components/content-chip';
import { DocName, useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { ProfileCard } from '../components/profile';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import {
  Badge,
  CredLink,
  CredStatus,
  DidLink,
  DocsLink,
  OpLink,
  Pager,
  Panel,
  Pill,
  Related,
  SETUP_GUIDE,
  Term,
  TROUBLESHOOTING_GUIDE,
  TruncId,
} from '../components/ui';
import { contributedFromSignerPage, ledgerCounts } from '../lib/actor-ledger';
import { getClient } from '../lib/client';
import { useIndexRowLabel } from '../lib/content-labels';
import type { ExplorerOp } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  indexCredSource,
  indexListState,
  indexListStateFor,
  useIndexCapable,
  useIndexIter2,
} from '../lib/index-light';
import { useIndexCredits, type IndexCreditRow } from '../lib/index-raw';
import { parseMediaObject } from '../lib/media';
import { toOpRows, type OpRow } from '../lib/op-rows';
import {
  assessBinding,
  fallbackEligible,
  fetchBindingAttestation,
  isBareHostname,
  readOriginClaim,
  runAppFallback,
  type BindingMethodResult,
  type BindingVerdict,
  type FallbackResult,
  type OriginClaim,
} from '../lib/origin-binding';
import { isProfileContent, profileAnchorOf } from '../lib/profile';
import { fetchBlobRaw, fetchClaim, type ClaimResult } from '../lib/relay-raw';
import { addRelay, getRelays } from '../lib/relays';
import {
  emptyRevocations,
  fetchIssuerRevocations,
  localRevocations,
  mergeRevocations,
  revocationStatus,
  type RevocationView,
} from '../lib/revocations';
import { jitIndexChain } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';
import { useHashParam } from '../router';
import { NotFound } from './not-found';

/** Ceiling on the offline revocation fold. Revocations are the rarest primitive
 *  (46 across the public relay's whole corpus at time of writing). This lane only
 *  ever ADDS positives — it never licenses "active" — so the ceiling can at worst
 *  cost a red chip we would otherwise have shown, never paint a false green. */
const LOCAL_REVOCATION_SCAN = 5000;

/** Rows per page for the two accumulating actor-ledger content lanes. Large
 *  enough that most identities land whole in one round trip; a space with
 *  hundreds of chains pages through the relay's own cursor instead. */
const LEDGER_PAGE = 200;

/**
 * One accumulating content lane of the actor ledger (Created / Contributed).
 *
 * `rows === null` is "nothing asked yet / still in flight"; `err` is "a lookup
 * REJECTED", which is never the same statement as a served empty page. `next` is
 * the relay's own cursor — its statement that more exists, which replaced the old
 * "did this page come back exactly `limit` long" guess. It survives a failed
 * load-more on purpose, so the button stays a retry rather than reading as an end.
 */
interface ContentLane {
  rows: IndexContentRow[] | null;
  err: boolean;
  next: string | null;
  loadingMore: boolean;
}

const emptyLane = (): ContentLane => ({ rows: null, err: false, next: null, loadingMore: false });

interface IdentityClaimState {
  isDeleted?: boolean;
  authKeys?: { id: string; publicKeyMultibase: string }[];
  assertKeys?: { id: string; publicKeyMultibase: string }[];
  controllerKeys?: { id: string; publicKeyMultibase: string }[];
  services?: ServiceEntry[];
}

export const Identity = (props: { did: string }) => {
  const indexed = useIndexCapable();
  // does the serving relay honour `signer=`? (ships with `order=`, one probe).
  // Contributed is the ONLY actor-ledger lane on the signer axis; Created
  // (creator=), Witnessed (witness=), Issued (issuer=) predate iteration 2.
  const iter2 = useIndexIter2();
  const [claim, setClaim] = useState<ClaimResult | null>(null);
  const [verified, setVerified] = useState<Resolved<VerifiedIdentity> | null>(null);
  const [rows, setRows] = useState<OpRow[]>([]);
  const [creds, setCreds] = useState<ExplorerOp[] | null>(null);
  // credentials issued BY this DID off the relay's /index/v0/credentials?issuer=<did>
  // — the always-fresh, no-sync path (relay-asserted; open a credential to fold it).
  const [issuedIndex, setIssuedIndex] = useState<IndexCredentialRow[] | null>(null);
  // relay advertises index but /index/v0/credentials errored (e.g. a relay predating
  // the route): capability.index does NOT imply this sub-route, so fall back to the
  // local scan rather than showing a false-empty "issued no credentials".
  const [issuedIndexErr, setIssuedIndexErr] = useState(false);
  // credentialCID → revoking op CID, folded from synced revocation ops (local-first)
  const [revoked, setRevoked] = useState<RevocationView>(emptyRevocations);
  // operations this identity has WITNESSED — a relay-index reverse lookup by
  // witness DID (attributed hint; open a target op to fold the real proof)
  const [witnessed, setWitnessed] = useState<IndexCountersignatureRow[] | null>(null);
  const [witnessRelation, setWitnessRelation] = useState<string | null>(null);
  const [witnessRelations, setWitnessRelations] = useState<string[]>([]);
  // content chains this identity CREATED (creator=did) and CONTRIBUTED to
  // (signer=did minus the rows it created — the client-side subtraction the spec
  // prescribes). Both are index-only reverse lookups, so they key on [did, indexed],
  // and both ACCUMULATE pages off the relay's cursor (see ContentLane). Their
  // error flags say a lookup REJECTED (relay unreachable / route declined), which
  // must render as an honest error and never a confirmed-empty — absence is not
  // proof of absence (the index can lie by omission).
  const [created, setCreated] = useState<ContentLane>(emptyLane);
  const [contributed, setContributed] = useState<ContentLane>(emptyLane);
  // generation token for those two lanes. A load-more is fired from a button, not
  // from the effect, so the effect's `dead` closure cannot reach it — this ref is
  // what a landing page compares against before appending, so a page requested
  // for one DID can never append into another's lane.
  const laneRun = useRef(0);
  const [witnessedErr, setWitnessedErr] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let dead = false;
    setClaim(null);
    setVerified(null);
    setRows([]);
    setCreds(null);
    setRevoked(emptyRevocations());
    setWitnessRelation(null);
    setWitnessRelations([]);
    setError('');
    const relays = getRelays();

    void fetchClaim('identities', props.did, relays).then((c) => {
      if (!dead) setClaim(c);
    });

    const client = getClient();
    void (async () => {
      try {
        const [res, log] = await Promise.all([
          client.identity(props.did),
          client.log('identity', props.did),
        ]);
        if (dead) return;
        setVerified(res);
        setRows(toOpRows(log.value));
        // JIT: land this identity's verified ops in the local index so it shows
        // up there without a full sync (relay-asserted routing metadata only)
        void jitIndexChain(props.did, 'identity-op', log.value);
      } catch (e) {
        if (!dead) setError(e instanceof Error ? e.message : String(e));
      }
    })();

    void getDb()
      .then((db) => db.chainOps(props.did, 'credential'))
      // the index groups credentials under a relay-asserted chainId; only keep
      // tokens whose OWN payload.iss is this DID (the token itself is the claim)
      .then((ops) =>
        ops.filter((op) => {
          const decoded = decodeJwsUnsafe(op.jwsToken);
          return decoded?.payload['iss'] === props.did;
        }),
      )
      .then((ops) => {
        if (!dead) setCreds(ops);
      })
      .catch(() => {
        if (!dead) setCreds([]);
      });

    // Status for the credentials this DID issued, from BOTH sources UNIONED —
    // never one-or-the-other. The relay's /revocations/v1/issuer feed is swept
    // across the whole relay set (a relay serving an empty feed is not evidence
    // that another isn't holding the revocation), and the local fold is always
    // added on top so a revocation this tab already holds still shows red when
    // no relay answers. Only a served feed licenses "active"; with none reachable
    // every credential renders UNKNOWN, which is the honest state — absence of an
    // answer is not absence of a revocation.
    void (async () => {
      const [fromRelay, db] = await Promise.all([
        fetchIssuerRevocations(props.did, relays),
        getDb().catch(() => null),
      ]);
      const local = db
        ? localRevocations(await db.opsOfKind('revocation', LOCAL_REVOCATION_SCAN))
        : emptyRevocations();
      if (dead) return;
      setRevoked(mergeRevocations(fromRelay, local));
    })();

    return () => {
      dead = true;
    };
  }, [props.did]);

  // separate lane: the countersignatures-by-witness reverse lookup only exists on
  // an index-capable relay, so it stands apart from the proof-plane fold above
  // (never gates it). The relation filter is a server-side exact-match re-query,
  // reaching past the first page of other relations. Its buttons come only from
  // the unfiltered page: an open-namespace tag absent from that page is not offered.
  useEffect(() => {
    let dead = false;
    setWitnessed(null);
    setWitnessedErr(false);
    if (indexed !== true) return;
    void getClient()
      .indexCountersignatures(props.did, {
        limit: 200,
        ...(witnessRelation ? { relation: witnessRelation } : {}),
      })
      .then((p) => {
        if (dead) return;
        // A relay predating relation= ignores it and answers unfiltered, so keep
        // only rows that answer the exact question — the index-point.ts rule.
        const rows = witnessRelation
          ? p.countersignatures.filter((row) => row.relation === witnessRelation)
          : p.countersignatures;
        setWitnessed(rows);
        if (!witnessRelation) {
          setWitnessRelations(
            [
              ...new Set(
                p.countersignatures
                  .map((row) => row.relation)
                  .filter((relation): relation is string => !!relation),
              ),
            ].sort(),
          );
        }
      })
      .catch(() => {
        // rejected — an error, NOT a confirmed "witnessed nothing"
        if (!dead) {
          setWitnessedErr(true);
          setWitnessed([]);
        }
      });
    return () => {
      dead = true;
    };
  }, [props.did, indexed, witnessRelation]);

  // separate index lane: EVERY content chain this DID CREATED (`creator=did`) and
  // CONTRIBUTED TO (`signer=did` minus the rows it created — the spec's
  // client-side subtraction), gated chains INCLUDED.
  //
  // The relay index already answers the actor axis in full, and answers it
  // honestly: a gated row comes back with `publicRead: false` and no projected
  // title, and `useIndexRowLabel` holds it to a bare id pill with no name, no
  // snippet, no bytes. Passing `publicRead: true` here was the EXPLORER hiding
  // what the index tells truthfully — a creator with hundreds of chains reading
  // as the handful it made public. So the filter is gone: on an actor-centric
  // listing, the existence of a chain someone signed is not the secret. What is
  // gated stays gated, and authorship of a WORK is obscured by the credits living
  // inside the content hash, never by omitting the row.
  //
  // Both lanes ACCUMULATE off the relay's `next` cursor (load-more below) rather
  // than stopping at one page. `signer=` exists ONLY on an iteration-2 relay: an
  // older relay IGNORES it and returns an unfiltered page, so on `iter2 !== true`
  // we do NOT fetch it (the tab renders an honest note instead).
  // Keyed [did, indexed, iter2].
  useEffect(() => {
    let dead = false;
    const cleanup = (): void => {
      dead = true;
      laneRun.current += 1; // and cancel any load-more still in flight
    };
    setCreated(emptyLane());
    setContributed(emptyLane());
    if (indexed !== true) return cleanup;
    const client = getClient();
    // order= combines with creator=/signer= on an iteration-2 relay (the store
    // filters, then orders) — so newest-first, but ONLY where honoured; a
    // pre-iteration-2 relay would 400 on order=, so gate it on iter2.
    const newest = iter2 === true ? ({ order: 'genesisAt.desc' } as const) : {};
    void client
      .indexContent({ creator: props.did, limit: LEDGER_PAGE, ...newest })
      .then((p) => {
        if (!dead) setCreated({ rows: p.content, err: false, next: p.next, loadingMore: false });
      })
      .catch(() => {
        // rejected (unreachable / declined) — an error, NOT a confirmed-empty
        if (!dead) setCreated({ rows: [], err: true, next: null, loadingMore: false });
      });
    // no signer support — leave `contributed` unasked (rows null); the tab shows
    // the note rather than a page the relay would have fabricated.
    if (iter2 !== true) return cleanup;
    void client
      // this branch runs only when iter2 === true (guarded above), so order= is safe
      .indexContent({
        signer: props.did,
        limit: LEDGER_PAGE,
        order: 'genesisAt.desc',
      })
      .then((p) => {
        if (dead) return;
        // subtract the DID's own creations — row-local, so it applies per page
        setContributed({
          rows: contributedFromSignerPage(p.content, props.did),
          err: false,
          next: p.next,
          loadingMore: false,
        });
      })
      .catch(() => {
        if (!dead) setContributed({ rows: [], err: true, next: null, loadingMore: false });
      });
    return cleanup;
  }, [props.did, indexed, iter2]);

  /**
   * Append the next page of an actor-ledger content lane. One appender serves
   * both: the lane carries its own cursor, and `derive` is the only difference
   * (identity for Created, the creator-subtraction for Contributed — which is
   * row-local, so filtering each page and concatenating equals filtering the
   * concatenation).
   *
   * A page that REJECTS raises the lane's error flag and keeps both the rows
   * already loaded and the cursor: a failed reach says nothing about whether more
   * exists, so the button stays a retry rather than quietly becoming an end.
   */
  const loadMoreLane = (
    lane: ContentLane,
    setLane: (update: (lane: ContentLane) => ContentLane) => void,
    params: { creator: string } | { signer: string },
    derive: (rows: IndexContentRow[]) => IndexContentRow[],
  ): void => {
    const after = lane.next;
    if (!after || lane.loadingMore) return;
    const run = laneRun.current;
    setLane((l) => ({ ...l, loadingMore: true }));
    // same iter2 gate as the first page — a cursor minted under one ordering is
    // only ever handed back under that same query
    const newest = iter2 === true ? ({ order: 'genesisAt.desc' } as const) : {};
    void getClient()
      .indexContent({ ...params, after, limit: LEDGER_PAGE, ...newest })
      .then((p) => {
        if (run !== laneRun.current) return;
        setLane((l) => ({
          rows: [...(l.rows ?? []), ...derive(p.content)],
          err: false,
          next: p.next,
          loadingMore: false,
        }));
      })
      .catch(() => {
        if (run !== laneRun.current) return;
        setLane((l) => ({ ...l, err: true, loadingMore: false }));
      });
  };

  // separate index lane: credentials ISSUED by this DID (iss === did) — a relay
  // reverse lookup that exists only on an index-capable relay, so it keys on
  // [did, indexed]. Amber (relay-asserted); open a credential to fold it.
  useEffect(() => {
    let dead = false;
    setIssuedIndex(null);
    setIssuedIndexErr(false);
    if (indexed !== true) return;
    void getClient()
      .indexCredentials({ issuer: props.did, limit: 200 })
      .then((p) => {
        if (!dead) setIssuedIndex(p.credentials);
      })
      .catch(() => {
        // index-capable relay, but this route errored — fall back to the local scan
        if (!dead) setIssuedIndexErr(true);
      });
    return () => {
      dead = true;
    };
  }, [props.did, indexed]);

  if (claim && !claim.body && !verified && !error) {
    // relay had nothing and verification hasn't concluded — wait for the client
    // (another relay may still serve it); a hard client error renders below
  }
  if (claim && !claim.body && error) {
    return <NotFound kind="identity" id={props.did} claim={claim} />;
  }

  const claimState = (claim?.body?.['state'] ?? {}) as IdentityClaimState;
  const claimHead =
    typeof claim?.body?.['headCID'] === 'string' ? (claim.body['headCID'] as string) : '';
  const state: IdentityClaimState | VerifiedIdentity = verified?.value ?? claimState;
  const stateVerified = verified !== null;

  const localHead = rows.length > 0 ? rows[rows.length - 1]?.cid : undefined;
  const headMatch = !!localHead && !!claimHead && localHead === claimHead;

  const pill = error
    ? { state: 'bad' as CheckState, text: 'verification failed' }
    : !verified
      ? { state: 'pend' as CheckState, text: 'verifying locally…' }
      : !claimHead || headMatch
        ? { state: 'ok' as CheckState, text: 'verified locally' }
        : { state: 'warn' as CheckState, text: 'verified · tip drift' };

  const services = ('services' in state ? state.services : undefined) ?? [];

  // the chain half of an origin binding (ORIGIN-BINDING.md). The claim is only
  // ever acted on once the chain has VERIFIED here — a relay-asserted services
  // set is not a signed claim, and the domain half is checked against a signed
  // claim or not at all.
  const originClaim = readOriginClaim(services);

  // credential list source: the live relay index when the relay is index-capable AND
  // the credentials route answered (always fresh, no sync needed), else the local
  // synced scan. Both expose {cid, jwsToken}, so the row renders identically.
  const credFromRelayIndex = indexCredSource(indexed, issuedIndexErr);
  const credSource: { cid: string; jwsToken: string }[] | null = credFromRelayIndex
    ? issuedIndex
    : creds;

  // crosslinks from already-loaded state: content chains this identity anchors
  // (ContentAnchor services) + the credentials it issued.
  const contentAnchors = services
    .filter((e) => e.type === 'ContentAnchor')
    .map((e) => (e as Record<string, unknown>)['anchor'])
    .filter((a): a is string => typeof a === 'string' && classifyAnchor(a) === 'chain');

  return (
    <>
      <IdentityProfile
        anchor={stateVerified ? profileAnchorOf(services) : null}
        chainVerified={stateVerified}
      />
      <Panel
        title={
          <>
            identity{' '}
            <Pill state={pill.state === 'pend' ? 'pending' : (pill.state as 'ok' | 'bad' | 'warn')}>
              {pill.text}
            </Pill>
          </>
        }
        orient={
          <>
            A self-sovereign <Term word="identity" def={GLOSSARY['did'] ?? ''} /> — its{' '}
            <Term word="DID" def={GLOSSARY['did'] ?? ''} /> is the hash of its own genesis op, so{' '}
            <b>no registry issues it and no server can revoke it.</b> Everything on this page is
            recomputed in your browser — relays are inputs, not authorities.{' '}
            <a href="#/">how this works</a>
          </>
        }
      >
        <div class="kv">
          <div class="k">did</div>
          <div class="v">
            <TruncId value={props.did} head={40} tail={0} />
          </div>
          <div class="k">
            head <span class="lbl">{stateVerified ? 'verified fold' : 'relay-asserted'}</span>
          </div>
          <div class="v">
            {localHead ? <OpLink cid={localHead} /> : claimHead ? <OpLink cid={claimHead} /> : '…'}
          </div>
          <div class="k">status</div>
          <div class="v">
            {'isDeleted' in state && state.isDeleted ? <span class="err">deleted</span> : 'active'}
          </div>
        </div>
        {verified ? <ProvenanceLine provenance={verified.provenance} /> : null}
      </Panel>

      <Panel title="verification" right={<span class="lbl">re-run in your browser</span>}>
        <Checks>
          {error ? (
            <Check state="bad" note={error}>
              verification failed
            </Check>
          ) : !verified ? (
            <Check state="pend">folding op log…</Check>
          ) : (
            <>
              <Check state="ok" note="did re-derived from genesis op CID — matches">
                DID self-certifies
              </Check>
              <Check
                state="ok"
                note={
                  verified.provenance.fromCache
                    ? 'verified prefix from cache + verified forward'
                    : 'fetched and verified live'
                }
              >
                {rows.length} operation(s) — every signature and CID recomputed here
              </Check>
              {/* one amber bucket, several very different underlying situations.
                  The domain view splits the same comparison into ahead / behind /
                  diverged because it holds two ORDERED logs; here we hold one tip
                  and one asserted tip, and a tip mismatch alone cannot tell a
                  relay that is simply behind from one signing a contradiction. So
                  the note says so rather than implying the amber means one thing. */}
              {claimHead ? (
                <Check
                  state={headMatch ? 'ok' : 'warn'}
                  note={
                    headMatch
                      ? undefined
                      : `local ${short(localHead)} vs relay ${short(claimHead)}. drift covers everything from benign lag to a signed contradiction — the operation history below, and the domain page's relay checks, are what tell those apart`
                  }
                >
                  {headMatch
                    ? 'local tip == relay-asserted tip'
                    : 'local tip differs from relay-asserted tip'}
                </Check>
              ) : null}
            </>
          )}
        </Checks>
      </Panel>

      {stateVerified && originClaim.kind === 'claimed' ? (
        <OriginBindingPanel did={props.did} claim={originClaim} />
      ) : null}

      <KeysPanel state={state} verified={stateVerified} />
      <ServicesPanel services={services} claim={originClaim} />

      <ActorLedger
        indexed={indexed}
        iter2={iter2}
        created={created}
        onLoadMoreCreated={() =>
          loadMoreLane(created, setCreated, { creator: props.did }, (rows) => rows)
        }
        contributed={contributed}
        onLoadMoreContributed={() =>
          loadMoreLane(contributed, setContributed, { signer: props.did }, (rows) =>
            contributedFromSignerPage(rows, props.did),
          )
        }
        witnessed={witnessed}
        witnessedErr={witnessedErr}
        witnessRelation={witnessRelation}
        witnessRelations={witnessRelations}
        onWitnessRelation={setWitnessRelation}
        credSource={credSource}
        credFromRelayIndex={credFromRelayIndex}
        revoked={revoked}
      />

      <CreditedOn did={props.did} indexed={indexed} />

      <Panel title="operation history">
        {rows.length === 0 ? (
          <span class="muted">{error ? <span class="err">{error}</span> : 'loading log…'}</span>
        ) : (
          <OpTimeline rows={rows} headCid={localHead ?? claimHead} />
        )}
      </Panel>

      <Related
        rows={[
          {
            k: 'claimed origin',
            v:
              originClaim.kind === 'claimed' ? (
                <a href={`#/domain/${originClaim.domain}`}>{originClaim.domain}</a>
              ) : null,
          },
          {
            k: 'content chains',
            v:
              contentAnchors.length > 0 ? (
                contentAnchors.map((a) => (
                  <div key={a}>
                    <ContentChip id={a} full />
                  </div>
                ))
              ) : (
                <span class="related-empty">none anchored on the verified chain</span>
              ),
          },
          {
            k: 'credentials issued',
            v:
              credSource && credSource.length > 0 ? (
                <>
                  {credSource.length}
                  {credSource.slice(0, 3).map((op) => (
                    <span key={op.cid}>
                      {' · '}
                      <CredLink cid={op.cid} />
                    </span>
                  ))}
                </>
              ) : null,
          },
        ]}
      />
    </>
  );
};

// -----------------------------------------------------------------------------
// CREDITED ON — public works whose head document says this identity made them
//
// A different KIND of claim from the actor ledger below, which is why it is its
// own panel and not a fifth tab there. The ledger is proof-tier and actor-axis:
// this DID's key actually signed something, re-derivable from the proof plane.
// This is assertion-tier: other people's documents SAY so, and the signer of
// each document staked its signature on that statement — real, but a different
// thing entirely, and collapsing them would launder one into the other.
//
// PUBLIC BY CONSTRUCTION. The credit projection derives only from publicly
// readable head documents, so a private work crediting this DID has zero rows.
// That is the condition under which the enumeration was sanctioned at all:
// attribution is never more public than the content it attributes. An empty
// panel therefore means "no PUBLIC work here credits this DID" — never "this
// identity made nothing."
// -----------------------------------------------------------------------------

/** One credited work: the work's own label, the role, and whether a claim token
 *  is ATTACHED — byte-presence, which is equally true of a token that fails to
 *  verify or binds to a different role. None of the four verification words
 *  appear here; opening the work is where the fold happens.
 *
 *  THE WORK CELL RUNS THE FULL THREE BEATS, like every other surface that names
 *  a content chain: short id → the relay index's projected public title (amber)
 *  → a verified label derived from bytes this tab re-hashed to the committed CID
 *  (plain ink; a body excerpt renders quoted). It used to render the projection
 *  ALONE, which meant a public post with a body and no title — the relay index
 *  projects `title` only for a post/v1 that has one — sat as a bare id pill
 *  forever, on the one panel whose entire subject is works.
 *
 *  `ContentChip` links to the same `#/content/…` target the row click navigates
 *  to, so the anchor and the row handler agree and a click through either lands
 *  in the same place. */
const CreditedRow = (props: { row: IndexCreditRow }) => {
  const { row } = props;
  return (
    <tr onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <ContentChip id={row.contentId} />
        {row.position === 0 ? <span class="lbl"> primary</span> : null}
      </td>
      <td>
        {row.role !== null ? (
          <span class="k-role">{row.role || 'empty role'}</span>
        ) : (
          <span class="muted">no role</span>
        )}
      </td>
      <td>
        {row.hasClaim ? (
          <Badge state="warn">claim attached</Badge>
        ) : (
          <Badge state="neutral">no claim</Badge>
        )}
      </td>
    </tr>
  );
};

const CreditedOn = (props: { did: string; indexed: boolean | null }) => {
  const [cursor, setCursor] = useHashParam('cafter');
  const page = useIndexCredits(props.indexed === true, {
    did: props.did,
    cursor,
    onCursor: setCursor,
  });
  const state = indexListStateFor(props.indexed, page.loading, page.error, page.rows.length);

  // A relay whose index predates `/index/v0/credits` has nothing to say here, and
  // credits are enrichment rather than primary content — so the section is simply
  // absent rather than explaining its own absence. A TRANSIENT failure still says
  // so below: that one is worth a retry.
  if (props.indexed === false || page.routeAbsent) return null;

  return (
    <Panel
      title="credited on"
      accent="warn"
      right={<span class="lbl">public works · from relay index</span>}
      orient={
        <>
          Publicly readable works whose current head document credits this identity — the relay's{' '}
          <Term word="credit" def={GLOSSARY['creditClaim'] ?? ''} /> projection, <b>amber</b>: the
          document's signer asserts each one, and it is <b>the credit</b> that is relay-asserted
          here — each work names itself, promoting to a <span class="did-name">verified</span> label
          once your tab has re-hashed its bytes. Open a work to fold its claim and see whether the
          credited party signed too. Private works crediting this identity are <b>never</b> listed.
        </>
      }
    >
      {state === 'error' ? (
        <div class="ck-note">
          couldn’t reach the relay index for credits.{' '}
          <button onClick={page.retry} disabled={page.loading}>
            {page.loading ? 'retrying…' : 'retry'}
          </button>
          {/* a stale or hand-edited `?cafter=` is REJECTED by the relay, and
              retrying re-sends the same bad cursor forever — so a deep link that
              has gone bad always offers a way back to the top. */}
          {page.offFirst ? <button onClick={page.first}> start over</button> : null}
        </div>
      ) : state === 'loading' ? (
        <span class="muted">reading credited works…</span>
      ) : state === 'empty' ? (
        <span class="muted">
          no public work these relays hold credits this identity — omission is always possible, so
          this is not a claim that none exists.
        </span>
      ) : (
        <>
          <div class="index-rows">
            <table>
              <thead>
                <tr>
                  <th>work</th>
                  <th>role</th>
                  <th>claim</th>
                </tr>
              </thead>
              <tbody>
                {page.rows.map((row) => (
                  <CreditedRow key={`${row.contentId}:${row.position}`} row={row} />
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            count={page.rows.length}
            noun="credits"
            loading={page.loading}
            hasNext={page.hasNext}
            hasPrev={page.hasPrev}
            offFirst={page.offFirst}
            onFirst={page.first}
            onPrev={page.prev}
            onNext={page.next}
          />
        </>
      )}
    </Panel>
  );
};

// -----------------------------------------------------------------------------
// ACTOR LEDGER — the four ways this DID appears in the chain, as relay-index
// reverse lookups over the actor axis: what it Created (creator=), Contributed
// to (signer= minus created — the spec's client-side subtraction), Witnessed
// (countersignatures?witness=), and Issued (credentials?issuer=). Every row is
// attributed: content rows green as the tab folds their chain, credentials and
// countersignatures fold on open. Empty states are omission-aware — "none the
// relay holds," never "none exist" (the index can lie by omission).
//
// The two content lanes list EVERY chain on their axis, gated ones included, and
// say so under the table: a gated row is a bare id with a `gated` marker and no
// title, which is the index's own posture rather than a softening of it. The
// counts are of rows LOADED — the relay's cursor says "more exists", never "how
// many" — so a lane still holding a cursor reads "loaded so far" and offers to
// walk further.
// -----------------------------------------------------------------------------

type LedgerTab = 'created' | 'contributed' | 'witnessed' | 'issued';

/** One content row in the actor ledger (Created / Contributed): the chain's
 *  label + type + when, with a live verify badge that greens as the tab folds the
 *  chain. The label runs the same three beats as every other index row (see
 *  `useIndexRowLabel`) — short id → amber projected title → verified label —
 *  which also puts this row behind the public-read honesty rule it used to sit
 *  outside of: it passed the relay's `title` through ungated, so a non-public
 *  chain on an unupgraded relay could surface one. That rule is what lets these
 *  lanes list gated chains at all — a gated row is a bare id pill and stays one.
 *
 *  The `gated` marker is the browse/home grammar verbatim, and it asks the WIDER
 *  question of the two on this panel: "can a projected title render here at all",
 *  which an untyped row fails too (the index projects `title` only for a typed
 *  public chain). The count line under the table asks the narrower one —
 *  `publicRead` alone — so an untyped public chain can carry the marker while
 *  counting as public. Both are true; neither is worth collapsing into the other. */
const LedgerContentRow = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const opCount = rec.facts?.opCount ?? row.opCount;
  const gated = !(row.docSchema && row.publicRead);
  const { label, tier } = useIndexRowLabel(row, rec.status !== 'attributed');
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        <DocName label={label} tier={tier} /> <VerifyBadge kind="content" chainId={row.contentId} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td>
        {row.docSchema ? (
          <span class="k-role">{schemaLabel(row.docSchema)}</span>
        ) : (
          <span class="muted">untyped</span>
        )}
        {gated ? <span class="err"> gated</span> : null}
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

/** A content-chain ledger table (Created / Contributed tabs) over relay-index
 *  rows. Distinguishes a REJECTED lookup (honest "couldn't reach") from a genuine
 *  200-with-zero-rows (the confirmed-empty `empty` copy) — a rejection labelled
 *  empty would violate the omission-can-lie posture.
 *
 *  Under the table sits the count line, which says how many rows are LOADED (not
 *  how many exist — the relay's cursor only ever says "more"), and how that
 *  splits public/gated. It replaces the old "showing the first 200" heuristic:
 *  a lane with a live cursor says so and offers `load more`, and one without has
 *  walked the whole listing the relay serves. */
const LedgerContentTable = (props: {
  lane: ContentLane;
  indexed: boolean | null;
  onLoadMore: () => void;
  empty: string;
}) => {
  const { lane } = props;
  if (props.indexed === null) return <span class="muted">checking relay capabilities…</span>;
  if (props.indexed !== true) return <span class="muted">requires an index-capable relay.</span>;
  const state = indexListState(lane.rows === null, lane.err, lane.rows?.length ?? 0);
  if (state === 'loading') return <span class="muted">reading relay index…</span>;
  if (state === 'error') return <span class="muted">couldn’t reach the relay index.</span>;
  if (state === 'empty') return <span class="muted">{props.empty}</span>;
  const counts = ledgerCounts(lane.rows!);
  const more = lane.next !== null;
  return (
    <>
      <table>
        <thead>
          <tr>
            <th>name / title</th>
            <th>type</th>
            <th>updated</th>
            <th>ops</th>
          </tr>
        </thead>
        <tbody>
          {lane.rows!.map((row) => (
            <LedgerContentRow key={row.contentId} row={row} />
          ))}
        </tbody>
      </table>
      <div class="ck-note" style={{ marginTop: 8 }}>
        {more
          ? `${counts.total} loaded so far`
          : `${counts.total} chain${counts.total === 1 ? '' : 's'}`}{' '}
        — {counts.publicCount} public · {counts.gatedCount} gated. relay-asserted index hints — open
        a chain to fold its proof.
      </div>
      {more ? (
        <div style={{ marginTop: 8 }}>
          <button onClick={props.onLoadMore} disabled={lane.loadingMore}>
            {lane.loadingMore ? 'loading…' : 'load more'}
          </button>{' '}
          <span class="lbl">the relay index surfaces more beyond these</span>
          {/* a page that REJECTED is not an end: the rows above stand, the cursor
              stands, and the button above is the retry. */}
          {lane.err ? (
            <span class="err"> · couldn’t reach the relay index for the next page.</span>
          ) : null}
        </div>
      ) : null}
    </>
  );
};

const ActorLedger = (props: {
  indexed: boolean | null;
  iter2: boolean | null;
  created: ContentLane;
  onLoadMoreCreated: () => void;
  contributed: ContentLane;
  onLoadMoreContributed: () => void;
  witnessed: IndexCountersignatureRow[] | null;
  witnessedErr: boolean;
  witnessRelation: string | null;
  witnessRelations: string[];
  onWitnessRelation: (relation: string | null) => void;
  credSource: { cid: string; jwsToken: string }[] | null;
  credFromRelayIndex: boolean;
  revoked: RevocationView;
}) => {
  const [tab, setTab] = useState<LedgerTab>('created');
  // suppress the count while loading (rows null) OR when the lane errored holding
  // nothing (rows []) so a tab never reads "contributed 0" over an unreachable
  // relay — a false-empty too. A lane that errored on a LATER page still knows
  // exactly how many rows it holds, so it keeps its count.
  const cnt = (rows: unknown[] | null, err = false): string =>
    !rows || (err && rows.length === 0) ? '' : ` ${rows.length}`;
  // a content lane counts what it has LOADED, and `+` says the relay's cursor is
  // still live — the count is a floor, never a corpus total.
  const laneCnt = (lane: ContentLane): string => {
    const n = cnt(lane.rows, lane.err);
    return n && lane.next !== null ? `${n}+` : n;
  };
  const rightLabel =
    tab === 'issued' && !props.credFromRelayIndex ? 'from local index' : 'relay index · attributed';
  return (
    <Panel title="actor ledger" right={<span class="lbl">{rightLabel}</span>}>
      <div class="filters" style={{ marginBottom: 10 }}>
        <button class={tab === 'created' ? 'on' : ''} onClick={() => setTab('created')}>
          created{laneCnt(props.created)}
        </button>
        <button class={tab === 'contributed' ? 'on' : ''} onClick={() => setTab('contributed')}>
          contributed{laneCnt(props.contributed)}
        </button>
        <button class={tab === 'witnessed' ? 'on' : ''} onClick={() => setTab('witnessed')}>
          witnessed{cnt(props.witnessed, props.witnessedErr)}
        </button>
        <button class={tab === 'issued' ? 'on' : ''} onClick={() => setTab('issued')}>
          issued{cnt(props.credSource)}
        </button>
      </div>

      {tab === 'created' ? (
        <LedgerContentTable
          lane={props.created}
          indexed={props.indexed}
          onLoadMore={props.onLoadMoreCreated}
          empty="no content chains this identity created that the relay index holds."
        />
      ) : tab === 'contributed' ? (
        props.indexed !== true ? (
          <LedgerContentTable
            lane={props.contributed}
            indexed={props.indexed}
            onLoadMore={props.onLoadMoreContributed}
            empty="no chains this identity signed but did not create that the relay index holds."
          />
        ) : props.iter2 === null ? (
          <span class="muted">checking relay capabilities…</span>
        ) : props.iter2 === false ? (
          // signer= is IGNORED by a pre-iteration-2 relay, returning an unfiltered
          // page — never render that fabrication. Keep the tab, tell the truth.
          <span class="muted">
            this relay doesn’t serve signer lookups yet — “contributed to but did not create” needs
            an iteration-2 index. (Created, witnessed, and issued below don’t.)
          </span>
        ) : (
          <LedgerContentTable
            lane={props.contributed}
            indexed={props.indexed}
            onLoadMore={props.onLoadMoreContributed}
            empty="no chains this identity signed but did not create that the relay index holds."
          />
        )
      ) : tab === 'witnessed' ? (
        <WitnessedTable
          indexed={props.indexed}
          witnessed={props.witnessed}
          error={props.witnessedErr}
          relations={props.witnessRelations}
          relation={props.witnessRelation}
          onRelation={props.onWitnessRelation}
        />
      ) : (
        <IssuedTable
          credSource={props.credSource}
          credFromRelayIndex={props.credFromRelayIndex}
          revoked={props.revoked}
        />
      )}
    </Panel>
  );
};

/** Witnessed tab — countersignatures this DID signed, a relay-index reverse
 *  lookup by witness. Each carries the full JWS; open the target op to fold it. */
const WitnessedTable = (props: {
  indexed: boolean | null;
  witnessed: IndexCountersignatureRow[] | null;
  error: boolean;
  relations: string[];
  relation: string | null;
  onRelation: (relation: string | null) => void;
}) => {
  if (props.indexed === null) return <span class="muted">checking relay capabilities…</span>;
  if (props.indexed !== true) return <span class="muted">requires an index-capable relay.</span>;
  const filters =
    props.relations.length > 0 ? (
      <div class="filters" style={{ marginBottom: 8 }}>
        <span class="lbl">relation</span>
        {props.relations.map((relation) => (
          <button
            key={relation}
            class={props.relation === relation ? 'on' : ''}
            onClick={() => props.onRelation(props.relation === relation ? null : relation)}
          >
            {relation}
          </button>
        ))}
      </div>
    ) : null;
  const state = indexListState(props.witnessed === null, props.error, props.witnessed?.length ?? 0);
  if (state === 'loading')
    return (
      <>
        {filters}
        <span class="muted">reading relay index…</span>
      </>
    );
  if (state === 'error')
    return (
      <>
        {filters}
        <span class="muted">couldn’t reach the relay index.</span>
      </>
    );
  if (state === 'empty')
    return (
      <>
        {filters}
        <span class="muted">
          {props.relation
            ? 'no witnessed operations with this relation the relay index surfaces.'
            : 'this identity has witnessed no operations the relay index surfaces.'}
        </span>
      </>
    );
  return (
    <>
      {filters}
      <table>
        <thead>
          <tr>
            <th>relation</th>
            <th>witnessed op</th>
            <th>countersignature</th>
          </tr>
        </thead>
        <tbody>
          {props.witnessed!.map((r) => (
            <tr key={r.cid}>
              <td>
                {r.relation ? (
                  <span class="k-role">{r.relation}</span>
                ) : (
                  <span class="muted">—</span>
                )}
              </td>
              <td>
                <OpLink cid={r.targetCID} />
              </td>
              <td class="cid">
                <OpLink cid={r.cid} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div class="ck-note" style={{ marginTop: 8 }}>
        relay-asserted index hints — open a witnessed op to fold its countersignature proof.
        {props.witnessed!.length === 200 ? ' showing the first 200 the relay index surfaces.' : ''}
      </div>
    </>
  );
};

/** Issued tab — credentials issued by this DID. The live relay index when the
 *  relay is index-capable AND the credentials route answered, else the local
 *  synced scan; both expose {cid, jwsToken} so the row renders identically. */
const IssuedTable = (props: {
  credSource: { cid: string; jwsToken: string }[] | null;
  credFromRelayIndex: boolean;
  revoked: RevocationView;
}) => {
  const { credSource, credFromRelayIndex } = props;
  if (credSource === null)
    return (
      <span class="muted">
        {credFromRelayIndex ? 'reading relay index…' : 'reading local index…'}
      </span>
    );
  if (credSource.length === 0)
    return (
      <span class="muted">
        {credFromRelayIndex
          ? 'this identity has issued no credentials the relay index surfaces.'
          : 'none in local index — sync the full log to populate.'}
      </span>
    );
  return (
    <>
      <table>
        <thead>
          <tr>
            <th>credential</th>
            <th>status</th>
            <th>audience</th>
            <th>grants</th>
          </tr>
        </thead>
        <tbody>
          {credSource.map((op) => {
            const decoded = decodeJwsUnsafe(op.jwsToken);
            const aud = typeof decoded?.payload['aud'] === 'string' ? decoded.payload['aud'] : '?';
            const att = Array.isArray(decoded?.payload['att'])
              ? (decoded.payload['att'] as { resource?: string; action?: string }[])
              : [];
            const first = att[0];
            return (
              <tr key={op.cid}>
                <td>
                  <CredLink cid={op.cid} />
                </td>
                <td>
                  <CredStatus
                    status={revocationStatus(props.revoked, op.cid)}
                    revokedByOp={props.revoked.revoked.get(op.cid)}
                  />
                </td>
                <td>
                  {aud === '*' ? (
                    <span class="k-role">public · anyone</span>
                  ) : (
                    <DidLink did={aud} />
                  )}
                </td>
                <td class="muted">
                  {first ? `${first.action ?? ''} ${first.resource ?? ''}` : ''}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {credFromRelayIndex && credSource.length > 0 && (
        <div class="ck-note" style={{ marginTop: 8 }}>
          relay-asserted index hints — open a credential to fold its signature and authority.
          {credSource.length === 200 ? ' showing the first 200 the relay index surfaces.' : ''}
        </div>
      )}
    </>
  );
};

interface ResolvedProfile {
  name?: string | undefined;
  description?: string | undefined;
  avatar: ReturnType<typeof parseMediaObject>;
  publicRead: boolean;
}

/**
 * Profile header — renders an identity's profile when it anchors one via a
 * ContentAnchor service and the doc is publicly readable. The bytes are
 * re-hashed to the on-chain committed CID before anything renders, so a relay
 * cannot dress arbitrary bytes up as someone's profile. The "public" pill means
 * exactly what was observed: the bytes were served to an UNAUTHENTICATED fetch
 * (the empirical effect of a public-read grant) — not a verified grant object.
 */
const IdentityProfile = (props: { anchor: string | null; chainVerified: boolean }) => {
  const [profile, setProfile] = useState<ResolvedProfile | null>(null);

  useEffect(() => {
    let dead = false;
    setProfile(null);
    if (!props.anchor || !props.chainVerified) return;
    const anchor = props.anchor;
    const relays = getRelays();
    void (async () => {
      try {
        const [res, blob] = await Promise.all([
          getClient().content(anchor),
          fetchBlobRaw(anchor, relays),
        ]);
        if (dead || !blob.bytes) return; // gated / absent → no public profile to show
        const committedCid = res.value.chain.currentDocumentCID;
        const text = new TextDecoder('utf-8', { fatal: false }).decode(blob.bytes);
        const parsed: unknown = JSON.parse(text);
        const derived = (
          await dagCborCanonicalEncode(parsed as Record<string, unknown>)
        ).cid.toString();
        // integrity gate — the served bytes MUST hash to the committed doc CID
        if (dead || derived !== committedCid || !isProfileContent(parsed)) return;
        setProfile({
          name: parsed.name,
          description: parsed.description,
          avatar: parseMediaObject(parsed.avatar),
          publicRead: !blob.gated,
        });
      } catch {
        // no renderable public profile — the identity view stands on its own
      }
    })();
    return () => {
      dead = true;
    };
  }, [props.anchor, props.chainVerified]);

  if (!profile) return null;
  return (
    <ProfileCard
      name={profile.name}
      description={profile.description}
      avatar={profile.avatar}
      verify="verified"
      publicRead={profile.publicRead}
    />
  );
};

// -----------------------------------------------------------------------------
// ORIGIN BINDING — the chain's domain claim, checked against the domain's answer
//
// The chain half is already proven when this renders: a `DfosOrigin` entry in the
// VERIFIED services state, signed by a controller key and ordered by the chain.
// The domain half is checked JIT, in this tab, through `/api/binding` (a browser
// cannot query DNS, and origins do not reliably send CORS headers on well-knowns).
//
// Display discipline here is NORMATIVE (ORIGIN-BINDING.md, "Display Discipline"):
// a binding proves control of a DOMAIN at verification time — never personhood,
// endorsement, or notability — so the panel leads with the domain string itself
// and never collapses the verdict into a bare checkmark divorced from it.
// -----------------------------------------------------------------------------

/** One method's row state. An answer that names a DIFFERENT DID is red; every
 *  form of silence is amber; only an exact match is green. */
const methodState = (result: BindingMethodResult, did: string): CheckState => {
  if (result.status === 'ok') return result.did === did ? 'ok' : 'bad';
  if (result.status === 'contradiction') return 'bad';
  return 'warn';
};

/** The mechanical note under a method row — what was actually observed. */
const methodNote = (result: BindingMethodResult, did: string): string => {
  switch (result.status) {
    case 'ok':
      return result.did === did
        ? `attests ${result.did} — exactly this identity`
        : `attests ${result.did} — a DIFFERENT identity`;
    case 'contradiction':
      return result.reason;
    case 'malformed':
      return `${result.reason} — present, but not an attestation`;
    case 'none':
      return result.reason ?? 'nothing published';
    case 'error':
      return `${result.reason ?? 'the lookup failed'}${
        result.httpStatus !== undefined ? ` (HTTP ${result.httpStatus})` : ''
      } — could not check`;
    case 'refused':
      return `${result.reason} — refused before it left the explorer`;
  }
};

/**
 * The pill, and the PLAIN rendering of the same verdict.
 *
 * The precise word is the label and does not move — bound / stale / broken are
 * what stay machine-distinguishable, and the whole discipline rests on them not
 * collapsing into each other. `def` is the second layer: the same verdict said in
 * words that need no spec, one hover or tap away. It preserves every distinction
 * the word carries, in particular that silence is not contradiction and that our
 * own route failing is a statement about US.
 *
 * Note what the plain layer does NOT say: no "last confirmed" date. The explorer
 * is stateless and has never seen this binding before this page load, so there is
 * no such date to render, and inventing one would be the only dishonest sentence
 * on the page.
 */
const bindingPill = (
  verdict: BindingVerdict,
): { state: 'ok' | 'warn' | 'bad'; text: string; def: string } => {
  switch (verdict.kind) {
    case 'bound':
      return { state: 'ok', text: 'bound', def: GLOSSARY['bindingBound'] ?? '' };
    case 'stale':
      return {
        state: 'warn',
        text: 'bound (stale) — domain silent',
        def: GLOSSARY['bindingStale'] ?? '',
      };
    case 'broken':
      return {
        state: 'bad',
        text: 'broken — domain contradicts',
        def: GLOSSARY['bindingBroken'] ?? '',
      };
    case 'proxy-unavailable':
      return {
        state: 'warn',
        text: 'verifier unavailable',
        def: 'The explorer’s own route failed, so nothing at all was learned about the domain. This is our failure — it says nothing either way about whether the domain attests this identity.',
      };
    case 'none':
      return {
        state: 'warn',
        text: 'no claim',
        def: 'This chain names no domain, so there is no binding to check. Nothing is missing and nothing is wrong — the identity simply claims no origin.',
      };
  }
};

/** The action line under an amber/red binding. Setup-shaped states (the domain
 *  has published nothing yet — a visitor who owns the domain can fix that) point
 *  at the setup guide; failure and contradiction states point at troubleshooting.
 *  Never restates the verdict: the checks above own that. */
const BindingNextStep = (props: { verdict: BindingVerdict; onRecheck: () => void }) => {
  const kind = props.verdict.kind;
  if (kind === 'bound') return null;
  const setupShaped = kind === 'stale' || kind === 'none';
  return (
    <div class="ck-note" style={{ marginTop: 10 }}>
      {setupShaped ? (
        <>
          if this is your domain, the <DocsLink href={SETUP_GUIDE}>setup guide ↗</DocsLink> covers
          publishing the attestation. troubleshooting:{' '}
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

const OriginBindingPanel = (props: {
  did: string;
  claim: Extract<OriginClaim, { kind: 'claimed' }>;
}) => {
  const domain = props.claim.domain;
  const [verdict, setVerdict] = useState<BindingVerdict | null>(null);
  const [probe, setProbe] = useState<{
    https: BindingMethodResult;
    dns: BindingMethodResult;
  } | null>(null);
  const [fallback, setFallback] = useState<FallbackResult | null>(null);
  // re-check nonce. `stale` in particular is a live, moment-to-moment reading of
  // someone else's DNS and hosting — both of which fail and recover routinely —
  // and the explorer remembers nothing between page loads, so the only honest way
  // to answer "is it still silent?" is to ask again. Bumping this clears the
  // verdict back to pending and re-runs the probe from nothing.
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let dead = false;
    setVerdict(null);
    setProbe(null);
    setFallback(null);
    const claim = props.claim;
    void (async () => {
      const answer = await fetchBindingAttestation(domain);
      // the app-description fallback is a MUST, and ONLY on absence: a dfos-did
      // document that is present but says something else is a contradiction, and
      // must not be fallen through
      const fell = fallbackEligible(answer) ? await runAppFallback(domain, props.did) : undefined;
      if (dead) return;
      if (answer.kind === 'answered') setProbe({ https: answer.https, dns: answer.dns });
      setFallback(fell ?? null);
      setVerdict(assessBinding(props.did, claim, answer, fell));
    })();
    return () => {
      dead = true;
    };
  }, [props.did, domain, nonce]);

  const pill = verdict ? bindingPill(verdict) : null;

  return (
    <Panel
      title={
        <>
          origin binding{' '}
          {pill ? (
            <Pill state={pill.state} def={pill.def} word={pill.text}>
              {pill.text}
            </Pill>
          ) : (
            <Pill state="pending">asking the domain…</Pill>
          )}
        </>
      }
      accent={pill ? pill.state : undefined}
      right={<span class="lbl">checked in your browser</span>}
      orient={
        <>
          The chain names a domain and the domain answers back — an{' '}
          <Term word="origin binding" def={GLOSSARY['originBinding'] ?? ''} />. It proves{' '}
          <b>control of that domain</b> at check time: never personhood, endorsement, or notability.
          The domain is the credential, so it is shown, not summarized.
        </>
      }
    >
      <div class="kv">
        <div class="k">
          domain <span class="lbl">claimed on the verified chain</span>
        </div>
        <div class="v">
          <a href={`#/domain/${domain}`}>{domain}</a>{' '}
          <a
            href={`https://${domain}/.well-known/dfos-did`}
            rel="noreferrer noopener"
            target="_blank"
            class="lbl"
          >
            attestation ↗
          </a>
          {/* the two well-known documents are constantly mistaken for one another,
              and the crosslink is exactly where that mistake gets made — so name
              both systems at the point of the click. */}
          <div class="ck-note">
            this panel checks the{' '}
            <Term word="domain attestation" def={GLOSSARY['domainAttestation'] ?? ''} /> (
            <code>dfos-did</code> / <code>_dfos</code> TXT). Opening the domain page checks the
            domain's <Term word="app description" def={GLOSSARY['appDescription'] ?? ''} /> (
            <code>dfos-app.json</code>) instead — a different claim, which neither confirms nor
            denies this binding.
          </div>
        </div>
      </div>

      <Checks>
        <Check state="ok" note={`DfosOrigin service entry — ${domain}`}>
          the chain names a domain
        </Check>
        {verdict === null ? (
          <Check state="pend">checking the domain's attest-back…</Check>
        ) : verdict.kind === 'proxy-unavailable' ? (
          <Check state="warn" note={verdict.reason}>
            the explorer's own binding route did not answer — <b>nothing was learned</b> about{' '}
            {domain}
          </Check>
        ) : probe === null ? null : (
          <>
            <Check
              state={methodState(probe.https, props.did)}
              note={methodNote(probe.https, props.did)}
            >
              https attest-back <code>/.well-known/dfos-did</code>
            </Check>
            <Check
              state={methodState(probe.dns, props.did)}
              note={methodNote(probe.dns, props.did)}
            >
              dns attest-back <code>_dfos</code> TXT
            </Check>
            {fallback !== null ? (
              <Check
                state={
                  fallback.kind === 'attests'
                    ? 'ok'
                    : fallback.kind === 'answers-other'
                      ? 'bad'
                      : 'warn'
                }
                note={
                  fallback.kind === 'attests'
                    ? `client_did is ${fallback.did} — exactly this identity`
                    : fallback.kind === 'answers-other'
                      ? `client_did is ${fallback.did} — a DIFFERENT identity`
                      : fallback.reason
                }
              >
                app-description fallback <code>/.well-known/dfos-app.json</code>
              </Check>
            ) : null}
          </>
        )}
      </Checks>

      {verdict?.kind === 'stale' ? (
        <div class="ck-note" style={{ marginTop: 10 }}>
          The domain is <b>silent</b>, not contradicting — DNS and web hosting fail routinely and
          recover routinely, so staleness is legal. It is not a claim that the binding is wrong.
        </div>
      ) : null}
      {verdict?.kind === 'broken' ? (
        <div class="ck-note" style={{ marginTop: 10 }}>
          {verdict.details.join(' · ')}. A domain that answers with something else contradicts this
          identity's claim — the identity and its history are untouched, only the domain claim is
          contradicted.
        </div>
      ) : null}

      {verdict !== null ? (
        <BindingNextStep verdict={verdict} onRecheck={() => setNonce((n) => n + 1)} />
      ) : null}
    </Panel>
  );
};

const KeysPanel = (props: { state: IdentityClaimState | VerifiedIdentity; verified: boolean }) => {
  const rows = new Map<string, { publicKeyMultibase: string; roles: string[] }>();
  const add = (
    keys: { id: string; publicKeyMultibase: string }[] | undefined,
    role: string,
  ): void => {
    for (const key of keys ?? []) {
      const row = rows.get(key.id) ?? { publicKeyMultibase: key.publicKeyMultibase, roles: [] };
      row.roles.push(role);
      rows.set(key.id, row);
    }
  };
  add(props.state.authKeys, 'auth');
  add(props.state.assertKeys, 'assert');
  add(props.state.controllerKeys, 'controller');
  return (
    <Panel
      title="keys"
      right={
        <span class="lbl">
          <Term word="roles" def={GLOSSARY['keyRoles'] ?? ''} /> ·{' '}
          {props.verified ? 'verified head state' : 'relay-asserted'}
        </span>
      }
    >
      {rows.size === 0 ? (
        <span class="muted">none</span>
      ) : (
        <table>
          <thead>
            <tr>
              <th>key id</th>
              <th>roles</th>
              <th>public key (multibase)</th>
            </tr>
          </thead>
          <tbody>
            {[...rows.entries()].map(([id, row]) => (
              <tr key={id}>
                <td>{id}</td>
                <td>
                  {row.roles.map((role) => (
                    <span key={role} class="k-role">
                      {role}
                    </span>
                  ))}
                </td>
                <td>
                  <TruncId value={row.publicKeyMultibase} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
};

const ServicesPanel = (props: { services: ServiceEntry[]; claim: OriginClaim }) => (
  <Panel
    title="services"
    right={
      <span class="lbl">
        <Term word="discovery" def={GLOSSARY['services'] ?? ''} />
      </span>
    }
  >
    {/* an identity claims AT MOST ONE canonical domain: more than one DfosOrigin
        entry claims none at all ("an ambiguous claim is no claim"), which is
        deliberately not `broken` — nobody is being contradicted, the claim is
        simply unreadable. So the binding panel is absent and this says why. */}
    {props.claim.kind === 'ambiguous' ? (
      <div class="ck-note" style={{ marginBottom: 10 }}>
        ⚠ {props.claim.count} <code>DfosOrigin</code> entries — an identity claims at most one
        canonical domain, so this set claims <b>no</b> origin binding at all.
      </div>
    ) : null}
    {props.services.length === 0 ? (
      <span class="muted">none declared</span>
    ) : (
      <table>
        <thead>
          <tr>
            <th>type</th>
            <th>label / id</th>
            <th>target</th>
          </tr>
        </thead>
        <tbody>
          {props.services.map((entry) => (
            <tr key={entry.id}>
              <td>{entry.type}</td>
              <td>{String((entry as Record<string, unknown>)['label'] ?? entry.id ?? '')}</td>
              <td>
                <ServiceTarget entry={entry} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    )}
  </Panel>
);

const ServiceTarget = (props: { entry: ServiceEntry }) => {
  const rec = props.entry as Record<string, unknown>;
  if (props.entry.type === 'DfosRelay' && typeof rec['endpoint'] === 'string') {
    const endpoint = rec['endpoint'];
    return (
      <>
        <a
          onClick={() => {
            addRelay(endpoint);
            location.hash = '#/relays';
          }}
        >
          {endpoint}
        </a>{' '}
        <span class="lbl">add as relay</span>
      </>
    );
  }
  if (props.entry.type === 'DfosOrigin') {
    const domain = rec['domain'];
    // the entry's `domain` is an exact byte comparison everywhere in
    // ORIGIN-BINDING.md, so anything that is not already a bare lowercase
    // hostname claims nothing — and is rendered as the dead letter it is
    if (isBareHostname(domain)) {
      return (
        <>
          <a href={`#/domain/${domain}`}>{domain}</a> <span class="lbl">claimed origin</span>
        </>
      );
    }
    return (
      <span class="err">
        {typeof domain === 'string' ? domain : JSON.stringify(props.entry)}{' '}
        <span class="lbl">not a bare hostname — claims nothing</span>
      </span>
    );
  }
  if (props.entry.type === 'ContentAnchor' && typeof rec['anchor'] === 'string') {
    const anchor = rec['anchor'];
    const kind = classifyAnchor(anchor);
    if (kind === 'chain') return <ContentChip id={anchor} full />;
    if (kind === 'artifact')
      return (
        <>
          <OpLink cid={anchor} /> <span class="lbl">artifact</span>
        </>
      );
    return <span class="err">{anchor}</span>;
  }
  // an authorize origin, not a relay: nothing to add, nothing to navigate to —
  // the endpoint is where this identity's person signs in, and that is all it says
  if (props.entry.type === 'DfosAuthorizationServer' && typeof rec['endpoint'] === 'string') {
    return (
      <>
        {rec['endpoint']} <span class="lbl">sign-in server</span>
      </>
    );
  }
  // the services namespace is deliberately open (DID-METHOD.md §4.5), so new
  // endpoint-bearing types keep arriving. An unknown one still reads as its
  // endpoint under its own type name rather than degrading to a raw blob; only
  // an entry with no recognizable target falls through to the JSON.
  if (typeof rec['endpoint'] === 'string') {
    return (
      <span class="muted">
        {rec['endpoint']} <span class="lbl">{props.entry.type}</span>
      </span>
    );
  }
  return <span class="muted">{JSON.stringify(props.entry)}</span>;
};
