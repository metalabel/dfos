/*

  CONTENT VIEW — chain + document bytes, two beats

  The chain commits to a HASH, not the bytes. The bytes live on the content
  plane and may be gated — the honest states (public / gated / not
  materialized) are all first-class renders, never faked. When bytes ARE
  public, they are re-encoded canonically and re-hashed here, and the result
  is compared to the CID committed on the verified chain.

*/

import type { Resolved, ResolvedContent } from '@metalabel/dfos-client';
import { dagCborCanonicalEncode } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks } from '../components/checks';
import { IndexPanel } from '../components/index-view';
import { MediaPanel } from '../components/media';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import {
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
import { getClient } from '../lib/client';
import { grantsForChain, type GrantSummary } from '../lib/credentials';
import { getDb } from '../lib/db-instance';
import { fmtUnixDate, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { isIndexDocument } from '../lib/index-fold';
import { parseMediaObject } from '../lib/media';
import { toOpRows, type OpRow } from '../lib/op-rows';
import { fetchBlobRaw, fetchClaim, type BlobResult, type ClaimResult } from '../lib/relay-raw';
import { getRelays } from '../lib/relays';
import { revokedByCredential } from '../lib/revocations';
import { jitIndexChain } from '../lib/sync-store';
import { NotFound } from './not-found';

interface DocState {
  blob: BlobResult;
  /** re-derived CID of the served bytes (JSON → canonical dag-cbor → CID) */
  derivedCid?: string;
  parsed?: unknown;
  pretty?: string;
  binary?: boolean;
}

export const Content = (props: { id: string }) => {
  const [claim, setClaim] = useState<ClaimResult | null>(null);
  const [resolved, setResolved] = useState<Resolved<ResolvedContent> | null>(null);
  const [rows, setRows] = useState<OpRow[]>([]);
  const [doc, setDoc] = useState<DocState | null>(null);
  const [grants, setGrants] = useState<GrantSummary[] | null>(null);
  // credentialCID → revoking op CID, folded from synced revocation ops (local-first)
  const [revoked, setRevoked] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState('');

  useEffect(() => {
    let dead = false;
    setClaim(null);
    setResolved(null);
    setRows([]);
    setDoc(null);
    setGrants(null);
    setRevoked(new Map());
    setError('');
    const relays = getRelays();
    const client = getClient();

    // related grants — scan the synced credential ops for any naming this chain,
    // and fold local revocation ops so each grant shows active/revoked
    void getDb()
      .then((db) =>
        Promise.all([db.opsOfKind('credential', 100000), db.opsOfKind('revocation', 100000)]),
      )
      .then(([credOps, revOps]) => {
        if (dead) return;
        setGrants(grantsForChain(credOps, props.id));
        setRevoked(revokedByCredential(revOps));
      })
      .catch(() => {
        if (!dead) setGrants([]);
      });

    void fetchClaim('content', props.id, relays).then((c) => {
      if (!dead) setClaim(c);
    });

    void (async () => {
      try {
        const [res, log] = await Promise.all([
          client.content(props.id),
          client.log('content', props.id),
        ]);
        if (dead) return;
        setResolved(res);
        setRows(toOpRows(log.value));
        // JIT: land the content chain in the local index…
        void jitIndexChain(props.id, 'content-op', log.value);
        // …and pull the creator's identity (its keys/services) into the index
        // too, so navigating a chain fills in the actors around it
        const creator = res.value.chain.creatorDID;
        if (creator) {
          void client
            .log('identity', creator)
            .then((idLog) => {
              if (!dead) void jitIndexChain(creator, 'identity-op', idLog.value);
            })
            .catch(() => {
              // best-effort prefetch — the creator link still resolves on click
            });
        }
      } catch (e) {
        if (!dead) setError(e instanceof Error ? e.message : String(e));
      }
    })();

    void (async () => {
      const blob = await fetchBlobRaw(props.id, relays);
      if (dead) return;
      if (!blob.bytes) {
        setDoc({ blob });
        return;
      }
      const text = new TextDecoder('utf-8', { fatal: false }).decode(blob.bytes);
      try {
        const parsed: unknown = JSON.parse(text);
        const encoded = await dagCborCanonicalEncode(parsed as Record<string, unknown>);
        if (dead) return;
        setDoc({
          blob,
          derivedCid: encoded.cid.toString(),
          parsed,
          pretty: JSON.stringify(parsed, null, 2).slice(0, 4000),
        });
      } catch {
        const printable = /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text);
        if (!dead)
          setDoc(printable ? { blob, pretty: text.slice(0, 4000) } : { blob, binary: true });
      }
    })();

    return () => {
      dead = true;
    };
  }, [props.id]);

  if (claim && !claim.body && error) {
    return <NotFound kind="content" id={props.id} claim={claim} />;
  }

  const chain = resolved?.value.chain;
  const claimHead =
    typeof claim?.body?.['headCID'] === 'string' ? (claim.body['headCID'] as string) : '';
  const claimGenesis =
    typeof claim?.body?.['genesisCID'] === 'string' ? (claim.body['genesisCID'] as string) : '';
  const claimState = (claim?.body?.['state'] ?? {}) as {
    creatorDID?: string;
    length?: number;
    isDeleted?: boolean;
    currentDocumentCID?: string | null;
  };

  const creatorDID = chain?.creatorDID ?? claimState.creatorDID ?? '';
  const docCid = chain ? chain.currentDocumentCID : (claimState.currentDocumentCID ?? null);
  const isDeleted = chain?.isDeleted ?? claimState.isDeleted ?? false;
  const headMatch = !!chain && (!claimHead || chain.headCID === claimHead);
  const revAxis = resolved?.trust.unverifiable?.includes('revocation') ?? false;

  const pill = error
    ? { state: 'bad' as const, text: 'verification failed' }
    : !resolved
      ? { state: 'pending' as const, text: 'verifying locally…' }
      : headMatch
        ? { state: 'ok' as const, text: 'verified locally' }
        : { state: 'warn' as const, text: 'verified · tip drift' };

  return (
    <>
      <Panel
        title={
          <>
            content chain <Pill state={pill.state}>{pill.text}</Pill>
          </>
        }
        orient={
          <>
            A <Term word="content chain" def={GLOSSARY['chain'] ?? ''} /> — a signed history of
            document-hash commitments owned by a creator DID.{' '}
            <b>It commits to a hash, not the bytes.</b>
          </>
        }
      >
        <div class="kv">
          <div class="k">contentId</div>
          <div class="v">
            <TruncId value={props.id} head={31} tail={0} />
          </div>
          <div class="k">creator</div>
          <div class="v">{creatorDID ? <DidLink did={creatorDID} full /> : '…'}</div>
          <div class="k">ops</div>
          <div class="v">{chain?.length ?? claimState.length ?? '…'}</div>
          <div class="k">genesis</div>
          <div class="v">
            {chain?.genesisCID ? (
              <OpLink cid={chain.genesisCID} />
            ) : claimGenesis ? (
              <OpLink cid={claimGenesis} />
            ) : (
              '…'
            )}
          </div>
          <div class="k">
            head <span class="lbl">{chain ? 'verified fold' : 'relay-asserted'}</span>
          </div>
          <div class="v">
            {chain?.headCID ? (
              <OpLink cid={chain.headCID} />
            ) : claimHead ? (
              <OpLink cid={claimHead} />
            ) : (
              '…'
            )}
          </div>
          <div class="k">
            document CID <span class="lbl">committed on-chain</span>
          </div>
          <div class="v">
            {docCid ? <TruncId value={docCid} /> : <span class="muted">null (cleared)</span>}
          </div>
          <div class="k">status</div>
          <div class="v">{isDeleted ? <span class="err">deleted</span> : 'active'}</div>
        </div>
        {resolved ? <ProvenanceLine provenance={resolved.provenance} /> : null}
      </Panel>

      <Panel title="verification" right={<span class="lbl">re-run in your browser</span>}>
        <Checks>
          {error ? (
            <Check state="bad" note={error}>
              verification failed
            </Check>
          ) : !resolved ? (
            <Check state="pend">resolving creator identity + folding chain…</Check>
          ) : (
            <>
              <Check state="ok" note={short(creatorDID)}>
                creator identity verified locally
              </Check>
              <Check state="ok" note="signatures, CIDs, and linkage recomputed here">
                {rows.length} content op(s) re-verified
              </Check>
              {claimHead ? (
                <Check
                  state={headMatch ? 'ok' : 'warn'}
                  note={
                    headMatch
                      ? undefined
                      : `local ${short(chain?.headCID)} vs relay ${short(claimHead)}`
                  }
                >
                  {headMatch
                    ? 'local tip == relay-asserted tip'
                    : 'local tip differs from relay-asserted tip'}
                </Check>
              ) : null}
              {revAxis ? (
                <Check
                  state="warn"
                  note="this chain contains delegated ops; non-revocation of the authorizing credential is not provable"
                >
                  revocation status unverifiable
                </Check>
              ) : null}
            </>
          )}
        </Checks>
      </Panel>

      <SchemaPanels
        contentId={props.id}
        doc={doc}
        rows={rows}
        committedCid={docCid}
        verified={!!chain}
      />

      <DocPanel doc={doc} committedCid={docCid} verified={!!chain} />

      <GrantsPanel
        grants={grants}
        revoked={revoked}
        publicBytes={!!doc?.blob.bytes}
        gated={!!doc?.blob.gated}
      />

      <Panel title="operation history">
        {rows.length === 0 ? (
          <span class="muted">{error ? <span class="err">{error}</span> : 'loading…'}</span>
        ) : (
          <OpTimeline rows={rows} headCid={chain?.headCID ?? claimHead} />
        )}
      </Panel>

      <Related
        rows={[
          {
            k: 'attributed identity',
            v: creatorDID ? <DidLink did={creatorDID} full /> : null,
          },
          {
            k: 'genesis op',
            v: chain?.genesisCID ? (
              <OpLink cid={chain.genesisCID} />
            ) : claimGenesis ? (
              <OpLink cid={claimGenesis} />
            ) : null,
          },
          {
            k: 'head op',
            v: chain?.headCID ? <OpLink cid={chain.headCID} /> : null,
          },
        ]}
      />
    </>
  );
};

/** Schema-aware extras: index chains get the fold, profile avatars get media. */
const SchemaPanels = (props: {
  contentId: string;
  doc: DocState | null;
  rows: OpRow[];
  committedCid: string | null;
  verified: boolean;
}) => {
  const parsed = props.doc?.parsed;
  if (parsed === undefined || props.rows.length === 0) return null;

  // The index fold fetches + integrity-checks each op's document itself, so it
  // is safe to run from the chain alone (it does not trust props.doc bytes).
  if (isIndexDocument(parsed)) {
    return <IndexPanel contentId={props.contentId} rows={props.rows} />;
  }

  // The avatar path reads THIS doc's bytes. Only surface it once the served
  // bytes have been re-hashed to the committed document CID AND the chain
  // verified — otherwise a relay could dress up arbitrary bytes as the profile.
  const bytesTrusted =
    props.verified && !!props.doc?.derivedCid && props.doc.derivedCid === props.committedCid;
  const rec =
    typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  if (
    bytesTrusted &&
    rec &&
    rec['$schema'] === 'https://schemas.dfos.com/profile/v1' &&
    rec['avatar']
  ) {
    const media = parseMediaObject(rec['avatar']);
    if (media) return <MediaPanel title="avatar" media={media} />;
  }
  return null;
};

/**
 * Related grants — the public-read (and any scoped) credentials the local index
 * holds that name this chain as a resource. Relay-asserted until opened; the
 * credential view verifies the signature + that the delegation roots at the
 * creator. Only rendered when there's something to say (grants found, or the
 * bytes are publicly served / gated).
 */
const GrantsPanel = (props: {
  grants: GrantSummary[] | null;
  revoked: Map<string, string>;
  publicBytes: boolean;
  gated: boolean;
}) => {
  const { grants } = props;
  const has = grants && grants.length > 0;
  // nothing to surface: no grants in the index and byte state is unknown/private
  if (!has && !props.publicBytes && !props.gated) return null;

  return (
    <Panel
      title="access"
      right={
        <span class="lbl">
          <Term word="public-read grant" def={GLOSSARY['standingGrant'] ?? ''} />
        </span>
      }
    >
      {has ? (
        <>
          <table>
            <thead>
              <tr>
                <th>credential</th>
                <th>status</th>
                <th>audience</th>
                <th>grants</th>
                <th>expires</th>
              </tr>
            </thead>
            <tbody>
              {grants.map((g) => (
                <tr key={g.cid}>
                  <td>
                    <CredLink cid={g.cid} />
                  </td>
                  <td>
                    <CredStatus revokedByOp={props.revoked.get(g.cid)} />
                  </td>
                  <td>
                    {g.isPublic ? (
                      <span class="k-role">public · anyone</span>
                    ) : (
                      <DidLink did={g.aud} />
                    )}
                  </td>
                  <td class="muted">{g.actions.join(', ')} chain</td>
                  <td class="muted">{g.exp ? fmtUnixDate(g.exp) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div class="ck-note" style={{ marginTop: 8 }}>
            From the local index — a standing <code>read</code> grant with audience <code>*</code>{' '}
            is what makes the document bytes anonymously servable. Open a credential to verify its
            signature and that it roots at this chain's creator.
          </div>
        </>
      ) : props.publicBytes ? (
        <div class="ck-note">
          The bytes are served publicly (an anonymous read succeeded), so a standing public-read
          grant exists on the relay — but it isn't in your local index yet. <b>Sync the full log</b>{' '}
          to surface the credential here.
        </div>
      ) : (
        <div class="ck-note">
          No public-read grant in your local index. The document bytes are gated — reads need a
          credential or an auth token.
        </div>
      )}
    </Panel>
  );
};

const DocPanel = (props: {
  doc: DocState | null;
  committedCid: string | null;
  verified: boolean;
}) => {
  const { doc, committedCid } = props;
  return (
    <Panel
      title="document bytes"
      right={
        <span class="lbl">
          <Term word="content plane" def={GLOSSARY['planes'] ?? ''} />
        </span>
      }
    >
      {!doc ? (
        <span class="muted">checking…</span>
      ) : doc.blob.bytes ? (
        <>
          <Pill state="ok">content plane · {doc.blob.bytes.length} bytes (public-read)</Pill>{' '}
          {doc.derivedCid && committedCid ? (
            doc.derivedCid === committedCid ? (
              <Pill state="ok">✓ bytes re-hash to the committed doc CID</Pill>
            ) : (
              <Pill state="bad">✗ served bytes ≠ committed CID — MISMATCH</Pill>
            )
          ) : doc.derivedCid ? (
            <span class="lbl"> re-derived {short(doc.derivedCid)}</span>
          ) : null}
          {!props.verified && doc.derivedCid ? (
            <div class="ck-note" style={{ marginTop: 4 }}>
              (comparison against the relay-asserted committed CID until the chain fold lands)
            </div>
          ) : null}
          {doc.pretty ? (
            <pre style={{ whiteSpace: 'pre-wrap', margin: '8px 0 0', fontSize: 11 }}>
              {doc.pretty}
            </pre>
          ) : doc.binary ? (
            <div class="muted" style={{ marginTop: 6 }}>
              binary payload — not rendered
            </div>
          ) : null}
        </>
      ) : doc.blob.gated ? (
        <>
          <Pill state="warn">gated · HTTP {doc.blob.status}</Pill>
          <div class="ck-note" style={{ marginTop: 6 }}>
            Document bytes are on the content plane and require a{' '}
            <Term word="standing public-read grant" def={GLOSSARY['standingGrant'] ?? ''} /> or an
            auth token. The committed document CID above is verified, so you know exactly what the
            bytes must hash to.
          </div>
        </>
      ) : doc.blob.status === 404 ? (
        <>
          <Pill state="warn">not materialized · HTTP 404</Pill>
          <div class="ck-note" style={{ marginTop: 6 }}>
            This relay proves the chain but does not hold (or does not serve) the bytes.
          </div>
        </>
      ) : (
        <>
          <Pill state="warn">
            byte fetch failed{doc.blob.status ? ` · HTTP ${doc.blob.status}` : ''}
          </Pill>
        </>
      )}
    </Panel>
  );
};
