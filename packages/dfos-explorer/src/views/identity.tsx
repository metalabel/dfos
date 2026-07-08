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
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks, type CheckState } from '../components/checks';
import { useVerifyOnVisible, VerifyBadge } from '../components/index-light';
import { ProfileCard } from '../components/profile';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import {
  ContentLink,
  CredLink,
  CredStatus,
  DidLink,
  OpLink,
  Panel,
  Pill,
  Related,
  Term,
  TruncId,
} from '../components/ui';
import { contributedFromSignerPage } from '../lib/actor-ledger';
import { getClient } from '../lib/client';
import type { ExplorerOp } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtAge, schemaLabel, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import {
  indexCredSource,
  indexListState,
  useIndexCapable,
  useIndexIter2,
} from '../lib/index-light';
import { parseMediaObject } from '../lib/media';
import { toOpRows, type OpRow } from '../lib/op-rows';
import { isProfileContent, profileAnchorOf } from '../lib/profile';
import { fetchBlobRaw, fetchClaim, type ClaimResult } from '../lib/relay-raw';
import { addRelay, getRelays } from '../lib/relays';
import { revokedByCredential } from '../lib/revocations';
import { jitIndexChain } from '../lib/sync-store';
import { useVerifyStatus } from '../lib/verify-queue';
import { NotFound } from './not-found';

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
  const [revoked, setRevoked] = useState<Map<string, string>>(new Map());
  // operations this identity has WITNESSED — a relay-index reverse lookup by
  // witness DID (attributed hint; open a target op to fold the real proof)
  const [witnessed, setWitnessed] = useState<IndexCountersignatureRow[] | null>(null);
  // content chains this identity CREATED (creator=did) and CONTRIBUTED to
  // (signer=did minus the rows it created — the client-side subtraction the spec
  // prescribes). Both are index-only reverse lookups, so they key on [did, indexed].
  const [created, setCreated] = useState<IndexContentRow[] | null>(null);
  const [contributed, setContributed] = useState<IndexContentRow[] | null>(null);
  // per-lane error flags: an index-only reverse lookup that REJECTED (relay
  // unreachable / route declined) must render as an honest error, never a
  // confirmed-empty — absence is not proof of absence (the index can lie by
  // omission). `contributedTruncated` keys the "first 200" note off the RAW
  // signer page length, before the creator-subtraction shrinks the array.
  const [createdErr, setCreatedErr] = useState(false);
  const [contributedErr, setContributedErr] = useState(false);
  const [contributedTruncated, setContributedTruncated] = useState(false);
  const [witnessedErr, setWitnessedErr] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let dead = false;
    setClaim(null);
    setVerified(null);
    setRows([]);
    setCreds(null);
    setRevoked(new Map());
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

    // fold revocation status locally: every synced revocation op names the
    // credentialCID it invalidates, so an issued credential's active/revoked
    // state comes from the math already in the index (no relay round-trip).
    void getDb()
      .then((db) => db.opsOfKind('revocation', 100000))
      .then((ops) => {
        if (!dead) setRevoked(revokedByCredential(ops));
      })
      .catch(() => {
        if (!dead) setRevoked(new Map());
      });

    return () => {
      dead = true;
    };
  }, [props.did]);

  // separate lane: the countersignatures-by-witness reverse lookup only exists on
  // an index-capable relay, so it keys on [did, indexed] and stands apart from the
  // proof-plane fold above (never gates it).
  useEffect(() => {
    let dead = false;
    setWitnessed(null);
    setWitnessedErr(false);
    if (indexed !== true) return;
    void getClient()
      .indexCountersignatures(props.did, { limit: 200 })
      .then((p) => {
        if (!dead) setWitnessed(p.countersignatures);
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
  }, [props.did, indexed]);

  // separate index lane: content chains CREATED and CONTRIBUTED TO by this DID.
  // Created is `creator=did` (predates iteration 2 — always fetched). Contributed
  // is `signer=did` (branch-inclusive "has signed in this chain") minus the rows
  // this DID created — the spec's client-side subtraction — and `signer=` exists
  // ONLY on an iteration-2 relay: an older relay IGNORES it and returns an
  // unfiltered page, so on `iter2 !== true` we do NOT fetch it (the tab renders an
  // honest note instead). Keyed [did, indexed, iter2].
  useEffect(() => {
    let dead = false;
    setCreated(null);
    setContributed(null);
    setCreatedErr(false);
    setContributedErr(false);
    setContributedTruncated(false);
    if (indexed !== true) return;
    const client = getClient();
    void client
      .indexContent({ creator: props.did, limit: 200 })
      .then((p) => {
        if (!dead) setCreated(p.content);
      })
      .catch(() => {
        // rejected (unreachable / declined) — an error, NOT a confirmed-empty
        if (!dead) {
          setCreatedErr(true);
          setCreated([]);
        }
      });
    if (iter2 !== true) {
      // no signer support — leave `contributed` null; the tab shows the note.
      return () => {
        dead = true;
      };
    }
    void client
      .indexContent({ signer: props.did, limit: 200 })
      .then((p) => {
        if (dead) return;
        // subtract the DID's own creations; truncation keys off the RAW page
        const page = contributedFromSignerPage(p.content, props.did, 200);
        setContributedTruncated(page.truncated);
        setContributed(page.rows);
      })
      .catch(() => {
        if (!dead) {
          setContributedErr(true);
          setContributed([]);
        }
      });
    return () => {
      dead = true;
    };
  }, [props.did, indexed, iter2]);

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
            <b>no registry issues it and no server can revoke it.</b>
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
            {'isDeleted' in state && state.isDeleted ? (
              <span class="err">deleted (tombstoned)</span>
            ) : (
              'active'
            )}
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
              {claimHead ? (
                <Check
                  state={headMatch ? 'ok' : 'warn'}
                  note={
                    headMatch ? undefined : `local ${short(localHead)} vs relay ${short(claimHead)}`
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

      <KeysPanel state={state} verified={stateVerified} />
      <ServicesPanel services={services} />

      <ActorLedger
        indexed={indexed}
        iter2={iter2}
        created={created}
        createdErr={createdErr}
        contributed={contributed}
        contributedErr={contributedErr}
        contributedTruncated={contributedTruncated}
        witnessed={witnessed}
        witnessedErr={witnessedErr}
        credSource={credSource}
        credFromRelayIndex={credFromRelayIndex}
        revoked={revoked}
      />

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
            k: 'content chains',
            v:
              contentAnchors.length > 0 ? (
                contentAnchors.map((a) => (
                  <div key={a}>
                    <ContentLink id={a} full />
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
// ACTOR LEDGER — the four ways this DID appears in the chain, as relay-index
// reverse lookups over the actor axis: what it Created (creator=), Contributed
// to (signer= minus created — the spec's client-side subtraction), Witnessed
// (countersignatures?witness=), and Issued (credentials?issuer=). Every row is
// attributed: content rows green as the tab folds their chain, credentials and
// countersignatures fold on open. Empty states are omission-aware — "none the
// relay holds," never "none exist" (the index can lie by omission).
// -----------------------------------------------------------------------------

type LedgerTab = 'created' | 'contributed' | 'witnessed' | 'issued';

/** One content row in the actor ledger (Created / Contributed): the projected
 *  title (attributed) + type + when, with a live verify badge that greens as the
 *  tab folds the chain — the same amber→verified posture as the browse rows. */
const LedgerContentRow = (props: { row: IndexContentRow }) => {
  const { row } = props;
  const ref = useVerifyOnVisible<HTMLTableRowElement>('content', row.contentId, row.opCount);
  const rec = useVerifyStatus('content', row.contentId);
  const opCount = rec.facts?.opCount ?? row.opCount;
  return (
    <tr ref={ref} onClick={() => (location.hash = `#/content/${row.contentId}`)}>
      <td>
        {row.title ? <span class="attr">{row.title}</span> : <span class="muted">—</span>}{' '}
        <VerifyBadge kind="content" chainId={row.contentId} />
        {rec.facts?.isDeleted ? <span class="err"> · deleted</span> : null}
      </td>
      <td>
        {row.docSchema ? (
          <span class="k-role">{schemaLabel(row.docSchema)}</span>
        ) : (
          <span class="muted">untyped</span>
        )}
      </td>
      <td class="n">{fmtAge(row.headAt)}</td>
      <td class="n">{opCount}</td>
    </tr>
  );
};

/** A content-chain ledger table (Created / Contributed tabs) over relay-index
 *  rows. Distinguishes a REJECTED lookup (honest "couldn't reach") from a genuine
 *  200-with-zero-rows (the confirmed-empty `empty` copy) — a rejection labelled
 *  empty would violate the omission-can-lie posture. `truncated` keys the
 *  first-200 note off the raw page (the Contributed array is post-subtraction). */
const LedgerContentTable = (props: {
  rows: IndexContentRow[] | null;
  indexed: boolean | null;
  error: boolean;
  truncated: boolean;
  empty: string;
}) => {
  if (props.indexed === null) return <span class="muted">checking relay capabilities…</span>;
  if (props.indexed !== true) return <span class="muted">requires an index-capable relay.</span>;
  const state = indexListState(props.rows === null, props.error, props.rows?.length ?? 0);
  if (state === 'loading') return <span class="muted">reading relay index…</span>;
  if (state === 'error') return <span class="muted">couldn’t reach the relay index.</span>;
  if (state === 'empty') return <span class="muted">{props.empty}</span>;
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
          {props.rows!.map((row) => (
            <LedgerContentRow key={row.contentId} row={row} />
          ))}
        </tbody>
      </table>
      <div class="ck-note" style={{ marginTop: 8 }}>
        relay-asserted index hints — open a chain to fold its proof.
        {props.truncated ? ' showing the first 200 the relay index surfaces.' : ''}
      </div>
    </>
  );
};

const ActorLedger = (props: {
  indexed: boolean | null;
  iter2: boolean | null;
  created: IndexContentRow[] | null;
  createdErr: boolean;
  contributed: IndexContentRow[] | null;
  contributedErr: boolean;
  contributedTruncated: boolean;
  witnessed: IndexCountersignatureRow[] | null;
  witnessedErr: boolean;
  credSource: { cid: string; jwsToken: string }[] | null;
  credFromRelayIndex: boolean;
  revoked: Map<string, string>;
}) => {
  const [tab, setTab] = useState<LedgerTab>('created');
  // suppress the count while loading (rows null) OR errored (rows []) so a tab
  // never reads "contributed 0" over an unreachable relay — a false-empty too.
  const cnt = (rows: unknown[] | null, err = false): string =>
    err || !rows ? '' : ` ${rows.length}`;
  const rightLabel =
    tab === 'issued' && !props.credFromRelayIndex ? 'from local index' : 'relay index · attributed';
  return (
    <Panel title="actor ledger" right={<span class="lbl">{rightLabel}</span>}>
      <div class="filters" style={{ marginBottom: 10 }}>
        <button class={tab === 'created' ? 'on' : ''} onClick={() => setTab('created')}>
          created{cnt(props.created, props.createdErr)}
        </button>
        <button class={tab === 'contributed' ? 'on' : ''} onClick={() => setTab('contributed')}>
          contributed{cnt(props.contributed, props.contributedErr)}
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
          rows={props.created}
          indexed={props.indexed}
          error={props.createdErr}
          truncated={(props.created?.length ?? 0) === 200}
          empty="no content chains this identity created that the relay index holds."
        />
      ) : tab === 'contributed' ? (
        props.indexed !== true ? (
          <LedgerContentTable
            rows={props.contributed}
            indexed={props.indexed}
            error={props.contributedErr}
            truncated={props.contributedTruncated}
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
            rows={props.contributed}
            indexed={props.indexed}
            error={props.contributedErr}
            truncated={props.contributedTruncated}
            empty="no chains this identity signed but did not create that the relay index holds."
          />
        )
      ) : tab === 'witnessed' ? (
        <WitnessedTable
          indexed={props.indexed}
          witnessed={props.witnessed}
          error={props.witnessedErr}
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
}) => {
  if (props.indexed === null) return <span class="muted">checking relay capabilities…</span>;
  if (props.indexed !== true) return <span class="muted">requires an index-capable relay.</span>;
  const state = indexListState(props.witnessed === null, props.error, props.witnessed?.length ?? 0);
  if (state === 'loading') return <span class="muted">reading relay index…</span>;
  if (state === 'error') return <span class="muted">couldn’t reach the relay index.</span>;
  if (state === 'empty')
    return (
      <span class="muted">this identity has witnessed no operations the relay index surfaces.</span>
    );
  return (
    <>
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
  revoked: Map<string, string>;
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
                  <CredStatus revokedByOp={props.revoked.get(op.cid)} />
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

const ServicesPanel = (props: { services: ServiceEntry[] }) => (
  <Panel
    title="services"
    right={
      <span class="lbl">
        <Term word="discovery" def={GLOSSARY['services'] ?? ''} />
      </span>
    }
  >
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
  if (props.entry.type === 'ContentAnchor' && typeof rec['anchor'] === 'string') {
    const anchor = rec['anchor'];
    const kind = classifyAnchor(anchor);
    if (kind === 'chain') return <ContentLink id={anchor} full />;
    if (kind === 'artifact')
      return (
        <>
          <OpLink cid={anchor} /> <span class="lbl">artifact</span>
        </>
      );
    return <span class="err">{anchor}</span>;
  }
  return <span class="muted">{JSON.stringify(props.entry)}</span>;
};
