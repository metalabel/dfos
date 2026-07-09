/*

  OPERATION VIEW — one op, two tiers of proof

  Alone, an operation proves only that its payload hashes to its CID and (once
  the signer's key resolves) that this key signed it. Whether the key was
  AUTHORIZED, whether the op sits on canonical history, whether it was
  superseded — that takes folding the whole chain, which happens here too.

  Standalone statements (artifact, countersignature, revocation) carry no
  container chain — their authority is that the signing key was authorized on
  its OWN identity chain, folded JIT here via resolveKey, then the canonical
  protocol verify runs under that key.

  Credentials get their own richer view; this one forwards.

*/

import {
  verifyArtifact,
  verifyCountersignature,
  verifyRevocation,
} from '@metalabel/dfos-protocol/chain';
import { decodeDFOSCredentialUnsafe } from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode, decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useMemo, useState } from 'preact/hooks';
import { Check, Checks, type CheckState } from '../components/checks';
import { JsonView } from '../components/json-view';
import { OpTimeline, OpType } from '../components/timeline';
import {
  ContentLink,
  CredLink,
  DidLink,
  KidLink,
  OpLink,
  Panel,
  Pill,
  Related,
  Term,
  TruncId,
} from '../components/ui';
import { getClient } from '../lib/client';
import { deriveCredentialCid, summarizeAuthorization } from '../lib/credentials';
import { getDb } from '../lib/db-instance';
import { didOfKid, fmtUnixDate, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { KIND_OF_TYP, PAYLOAD_NOTES } from '../lib/op-annotations';
import { toOpRows, type OpRow } from '../lib/op-rows';
import { fetchCountersigs, fetchOpRaw } from '../lib/relay-raw';
import { getRelays } from '../lib/relays';

interface OpState {
  jwsToken?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  kind: string;
  chainId: string;
  /** How chainId was obtained — governs whether chain placement is trustworthy. */
  chainSource: 'derived' | 'relay-hint' | 'none';
  source: 'local' | 'relay' | 'missing';
  /** props.cid re-derived from the payload bytes (real integrity check). */
  selfCidOk: boolean;
}

interface ChainVerify {
  state: CheckState;
  present: boolean;
  isHead: boolean;
  position: number; // 1-based; 0 = unknown
  total: number;
  headCid: string;
  note?: string;
  rows: OpRow[];
}

interface WitnessRow {
  did: string;
  relation: string;
  createdAt: string;
  targetsThis: boolean;
  sig: CheckState;
}

/*
  Standalone statements — artifact, countersignature, revocation — carry no
  container chain of their own. Their AUTHORITY is that the signing key was
  authorized on its OWN identity chain at fold time. We prove that JIT: fold the
  signer's owning identity chain (resolveKey), then run the canonical protocol
  verify (signature + payload schema + issuer binding + CID) under that key.
*/
type ResolveKey = (kid: string) => Promise<Uint8Array>;

const STANDALONE_VERIFY: Record<
  string,
  (input: { jwsToken: string; resolveKey: ResolveKey }) => Promise<unknown>
> = {
  artifact: verifyArtifact,
  countersign: verifyCountersignature,
  revocation: verifyRevocation,
};

const STANDALONE_LABEL: Record<string, string> = {
  artifact: 'artifact',
  countersign: 'countersignature',
  revocation: 'revocation',
};

interface Standalone {
  /** resolveKey folded the signer's owning identity chain and authorized the key. */
  authorized: CheckState;
  authNote?: string;
  /** the canonical protocol verify: signature + schema + issuer binding + CID. */
  proof: CheckState;
  proofNote?: string;
  /** the identity that owns the signing key. */
  signer: string;
}

export const Op = (props: { cid: string }) => {
  const [op, setOp] = useState<OpState | null>(null);
  const [chain, setChain] = useState<ChainVerify | null>(null);
  const [chainPending, setChainPending] = useState(false);
  const [witnesses, setWitnesses] = useState<WitnessRow[] | null>(null);
  const [standalone, setStandalone] = useState<Standalone | null>(null);

  useEffect(() => {
    let dead = false;
    setOp(null);
    setChain(null);
    setChainPending(false);
    setWitnesses(null);
    setStandalone(null);
    const relays = getRelays();
    const client = getClient();

    void (async () => {
      // find the JWS: local index first, relay fallback. A local-index open
      // failure (another tab blocking an upgrade) degrades to a relay-only
      // lookup rather than a hung "decoding…" pill.
      const local = await getDb()
        .then((db) => db.getOp(props.cid))
        .catch(() => undefined);
      let jwsToken = local?.jwsToken;
      let source: OpState['source'] = local ? 'local' : 'missing';
      if (!jwsToken) {
        const raw = await fetchOpRaw(props.cid, relays);
        if (raw) {
          jwsToken = raw.jwsToken;
          source = 'relay';
        }
      }
      if (dead) return;

      const decoded = jwsToken ? decodeJwsUnsafe(jwsToken) : null;
      const typ = typeof decoded?.header.typ === 'string' ? decoded.header.typ : '';

      // Credentials get the dedicated view — but ONLY hand off a token that
      // actually decodes as a credential, else the cred view bounces it right
      // back here and we spin. replace() (not push) so Back isn't trapped.
      if (typ === 'did:dfos:credential' && jwsToken && decodeDFOSCredentialUnsafe(jwsToken)) {
        location.replace(`#/cred/${props.cid}`);
        return;
      }

      const payload = decoded?.payload ?? {};
      // kind from the JWS envelope is authoritative over the relay index hint
      const kind = KIND_OF_TYP[typ] ?? local?.kind ?? '';

      // Real self-CID integrity: re-derive the CID from the payload bytes and
      // compare to the routed CID — NOT a trust of the relay-supplied header.cid.
      let selfCidOk = false;
      if (decoded) {
        try {
          const encoded = await dagCborCanonicalEncode(payload);
          selfCidOk = encoded.cid.toString() === props.cid;
        } catch {
          selfCidOk = false;
        }
      }
      if (dead) return;

      // chainId provenance:
      //  - identity-op: a non-genesis op's kid IS did:dfos:<chain>#<key> — the
      //    chain is cryptographically named by the op itself (derived).
      //  - content-op: the contentId is NOT in the payload (payload.did is the
      //    SIGNER, not the chain) — it is only knowable from the local index
      //    hint (relay-asserted) or not at all.
      let chainId = '';
      let chainSource: OpState['chainSource'] = 'none';
      if (kind === 'identity-op') {
        const derived = didOfKid(typeof decoded?.header.kid === 'string' ? decoded.header.kid : '');
        if (derived) {
          chainId = derived;
          chainSource = 'derived';
        } else if (local?.chainId) {
          chainId = local.chainId;
          chainSource = 'relay-hint';
        }
      } else if (kind === 'content-op' && local?.chainId) {
        chainId = local.chainId;
        chainSource = 'relay-hint';
      }

      const state: OpState = {
        ...(jwsToken ? { jwsToken } : {}),
        ...(decoded
          ? { header: decoded.header as unknown as Record<string, unknown>, payload }
          : {}),
        kind,
        chainId,
        chainSource,
        source,
        selfCidOk,
      };
      setOp(state);

      // tier 2: fold the whole chain and place this op on it
      if (chainId && (kind === 'identity-op' || kind === 'content-op')) {
        setChainPending(true);
        try {
          const log = await client.log(kind === 'identity-op' ? 'identity' : 'content', chainId);
          if (dead) return;
          const rows = toOpRows(log.value);
          const index = rows.findIndex((r) => r.cid === props.cid);
          const isHead = index >= 0 && index === rows.length - 1;
          setChain({
            state: index < 0 ? 'bad' : isHead ? 'ok' : 'warn',
            present: index >= 0,
            isHead,
            position: index + 1,
            total: rows.length,
            headCid: rows[rows.length - 1]?.cid ?? '',
            rows,
          });
        } catch (e) {
          if (!dead)
            setChain({
              state: 'warn',
              present: false,
              isHead: false,
              position: 0,
              total: 0,
              headCid: '',
              note: e instanceof Error ? e.message : String(e),
              rows: [],
            });
        } finally {
          if (!dead) setChainPending(false);
        }
      } else if (jwsToken) {
        // standalone statement (artifact / countersign / revocation): prove
        // authority by folding the SIGNER's own identity chain JIT — the key must
        // be authorized there — then run the canonical protocol verify under it.
        const verify = STANDALONE_VERIFY[kind];
        if (verify) {
          const resolveKey = client.callbacks().resolveKey;
          const signerKid = typeof decoded?.header.kid === 'string' ? decoded.header.kid : '';
          const signer = didOfKid(signerKid);
          let authorized: CheckState = 'warn';
          let authNote: string | undefined;
          try {
            await resolveKey(signerKid);
            authorized = 'ok';
          } catch (e) {
            authNote = e instanceof Error ? e.message : String(e);
          }
          if (dead) return;
          let proof: CheckState;
          let proofNote: string | undefined;
          if (authorized === 'ok') {
            try {
              await verify({ jwsToken, resolveKey });
              proof = 'ok';
            } catch (e) {
              proof = 'bad';
              proofNote = e instanceof Error ? e.message : String(e);
            }
          } else {
            proof = 'warn';
            proofNote = 'signer unresolved — cannot assess the statement';
          }
          if (dead) return;
          setStandalone({
            authorized,
            ...(authNote ? { authNote } : {}),
            proof,
            ...(proofNote ? { proofNote } : {}),
            signer,
          });
        }
      }
    })();

    // countersignature web — independent of op resolvability
    void (async () => {
      const all = await fetchCountersigs(props.cid, relays);
      if (dead) return;
      if (all.length === 0) {
        setWitnesses([]);
        return;
      }
      // a hostile relay can return an unbounded witness list; cap the per-op
      // verification work (each row resolves an identity + verifies a sig)
      const MAX_WITNESSES = 200;
      const tokens = all.slice(0, MAX_WITNESSES);
      const callbacks = getClient().callbacks();
      const rows: WitnessRow[] = [];
      for (const token of tokens) {
        const decoded = decodeJwsUnsafe(token);
        const payload = decoded?.payload ?? {};
        const did = typeof payload['did'] === 'string' ? payload['did'] : '?';
        const relation =
          typeof payload['relation'] === 'string' ? payload['relation'] : 'witnessed';
        const createdAt = typeof payload['createdAt'] === 'string' ? payload['createdAt'] : '';
        const target = typeof payload['targetCID'] === 'string' ? payload['targetCID'] : '';
        let sig: CheckState = 'pend';
        try {
          await verifyCountersignature({ jwsToken: token, resolveKey: callbacks.resolveKey });
          sig = 'ok';
        } catch {
          sig = 'bad';
        }
        rows.push({ did, relation, createdAt, targetsThis: target === props.cid, sig });
      }
      if (!dead) setWitnesses(rows);
    })();

    return () => {
      dead = true;
    };
  }, [props.cid]);

  const typ = typeof op?.header?.['typ'] === 'string' ? (op.header['typ'] as string) : '';
  const kid = typeof op?.header?.['kid'] === 'string' ? (op.header['kid'] as string) : '';
  const selfCidOk = op?.selfCidOk ?? false;
  const payload = op?.payload ?? {};
  const isStandalone = op ? STANDALONE_LABEL[op.kind] !== undefined : false;

  const pill = !op
    ? { state: 'pending' as const, text: 'decoding…' }
    : !op.jwsToken
      ? { state: 'warn' as const, text: 'not resolvable' }
      : isStandalone
        ? !standalone
          ? { state: 'pending' as const, text: 'proving authorization…' }
          : standalone.authorized !== 'ok'
            ? { state: 'warn' as const, text: 'signer authorization unproven' }
            : standalone.proof === 'ok'
              ? { state: 'ok' as const, text: 'authorized signer · verified' }
              : { state: 'bad' as const, text: 'signer authorized · statement invalid' }
        : chainPending
          ? { state: 'pending' as const, text: 'verifying in chain…' }
          : !chain
            ? // no fold ran: honest terminal state keyed on the real self-CID check
              selfCidOk
              ? { state: 'warn' as const, text: 'bytes verified · chain not placed' }
              : { state: 'bad' as const, text: 'cid mismatch' }
            : chain.note
              ? { state: 'warn' as const, text: 'decoded · chain verify failed' }
              : !chain.present
                ? op.chainSource === 'relay-hint'
                  ? { state: 'warn' as const, text: 'not in relay-asserted chain' }
                  : { state: 'bad' as const, text: 'not in chain' }
                : chain.isHead
                  ? { state: 'ok' as const, text: 'verified in chain' }
                  : { state: 'warn' as const, text: 'verified · superseded' };

  const chainLink = op?.chainId ? (
    op.kind === 'content-op' ? (
      <ContentLink id={op.chainId} />
    ) : (
      <DidLink did={op.chainId} />
    )
  ) : (
    <span class="muted">unknown</span>
  );

  return (
    <>
      <Panel
        title={
          <>
            operation <Pill state={pill.state}>{pill.text}</Pill>
          </>
        }
        orient={
          <>
            One signed <Term word="operation" def={GLOSSARY['operation'] ?? ''} />, named by the{' '}
            <Term word="CID" def={GLOSSARY['cid'] ?? ''} /> of its own bytes.{' '}
            <b>
              {isStandalone
                ? "Alone it proves a signature — fold its signer's chain for authority."
                : 'Alone it proves little — fold the chain for authority.'}
            </b>
          </>
        }
      >
        <div style={{ marginBottom: 8 }}>
          {typeof payload['type'] === 'string' && payload['type'] !== op?.kind ? (
            <OpType type={payload['type']} />
          ) : null}{' '}
          {op?.kind ? <span class={`kind ${op.kind}`}>{op.kind.replace('-op', '')}</span> : null}{' '}
          {isStandalone ? (
            <>
              <span class="lbl">by</span>{' '}
              {kid && didOfKid(kid) ? (
                <DidLink did={didOfKid(kid)} />
              ) : (
                <span class="muted">unknown signer</span>
              )}
            </>
          ) : (
            <>
              <span class="lbl">in chain</span> {chainLink}
            </>
          )}
          {chain?.present ? (
            <>
              {' '}
              · op {chain.position} of {chain.total}{' '}
              {chain.isHead ? (
                <span class="lbl" style={{ color: 'var(--ok)' }}>
                  head
                </span>
              ) : null}
            </>
          ) : null}
        </div>
        <div class="kv">
          <div class="k">cid</div>
          <div class="v">
            <TruncId value={props.cid} head={40} tail={8} />
          </div>
          <div class="k">envelope</div>
          <div class="v">
            <span class="muted">{typ || '?'}</span>
            {op?.source === 'local' ? <span class="lbl"> · from local index</span> : null}
          </div>
          <div class="k">signer</div>
          <div class="v">{op?.header ? <KidLink kid={kid} /> : <span class="muted">?</span>}</div>
          <div class="k">createdAt</div>
          <div class="v">
            {typeof payload['createdAt'] === 'string' ? payload['createdAt'] : ''}
          </div>
          <div class="k">self-CID</div>
          <div class="v">
            {op?.header ? (
              selfCidOk ? (
                <Pill state="ok">bytes re-hash to this CID</Pill>
              ) : (
                <Pill state="bad">✗ bytes do NOT hash to this CID</Pill>
              )
            ) : (
              <span class="muted">n/a</span>
            )}
          </div>
        </div>
      </Panel>

      {op && !op.jwsToken ? (
        <Panel title="not resolvable">
          <span class="muted">
            These relays do not serve this op directly, and it isn't in your local index. Its
            countersignatures below still resolve.
          </span>
        </Panel>
      ) : null}

      {op?.payload ? (
        <Panel title="decoded payload" right={<span class="lbl">annotated</span>}>
          <div class="kv">
            {Object.entries(payload).map(([key, value]) => (
              <PayloadRow key={key} k={key} value={value} kind={op.kind} />
            ))}
          </div>
          <details style={{ marginTop: 8 }}>
            <summary>payload json</summary>
            <div style={{ marginTop: 6 }}>
              <JsonView value={payload} />
            </div>
          </details>
        </Panel>
      ) : null}

      {op?.jwsToken ? (
        <Panel
          title="verification"
          right={
            <span class="lbl">
              {isStandalone ? 'signature + owning-chain fold' : 'op alone vs whole chain'}
            </span>
          }
        >
          <div class="ck-note" style={{ marginBottom: 8 }}>
            {isStandalone ? (
              <>
                A standalone statement carries a signature and a self-certifying CID. To prove the
                signing key was <b>authorized</b>, its owning identity chain is folded here (JIT) —
                the key must appear in that identity's authorized set. The signature and payload are
                then verified under that key. There is no container chain to place it on.
              </>
            ) : (
              <>
                Alone, an operation proves only that its payload hashes to this CID (recomputed
                here). It cannot prove the signer's key was authorized, that the op sits on
                canonical history, or that it wasn't superseded — that takes folding the whole
                chain. The signature itself is checked only via the chain fold, where the signing
                key resolves.
              </>
            )}
          </div>
          <Checks>
            <Check state="ok" note={typ}>
              envelope decodes
            </Check>
            <Check
              state={selfCidOk ? 'ok' : 'bad'}
              note={
                selfCidOk
                  ? 'payload re-encoded (canonical dag-cbor) and re-hashed here — matches the CID'
                  : 'payload does NOT hash to the requested CID — forged or corrupted'
              }
            >
              self-certifying CID (recomputed)
            </Check>
            {op.kind === 'identity-op' || op.kind === 'content-op' ? (
              !chain ? (
                <Check state="pend">folding chain…</Check>
              ) : (
                <>
                  <Check state={chain.note ? 'warn' : 'ok'} note={chain.note ?? short(op.chainId)}>
                    {op.kind === 'identity-op'
                      ? 'chain self-certifies from genesis'
                      : 'creator identity verified'}
                  </Check>
                  {!chain.note ? (
                    <>
                      <Check
                        state={chain.present ? 'ok' : 'bad'}
                        note={
                          chain.present
                            ? `position ${chain.position} of ${chain.total}`
                            : 'not on the canonical fold'
                        }
                      >
                        this op is present in the verified chain
                      </Check>
                      <Check
                        state={chain.isHead ? 'ok' : 'warn'}
                        note={chain.isHead ? undefined : `head is ${short(chain.headCid)}`}
                      >
                        {chain.isHead ? 'this op is the current head' : 'superseded by a later op'}
                      </Check>
                    </>
                  ) : null}
                </>
              )
            ) : isStandalone ? (
              !standalone ? (
                <Check state="pend">folding the signer's identity chain…</Check>
              ) : (
                <>
                  <Check
                    state={standalone.authorized}
                    note={
                      standalone.authorized === 'ok'
                        ? `owning identity chain folded here — key authorized on ${short(standalone.signer)}`
                        : (standalone.authNote ?? 'could not resolve the signing key')
                    }
                  >
                    {standalone.authorized === 'ok'
                      ? 'signer authorized — owning chain folded'
                      : 'signer authorization unproven'}
                  </Check>
                  <Check state={standalone.proof} note={standalone.proofNote}>
                    {standalone.proof === 'ok'
                      ? `${STANDALONE_LABEL[op.kind] ?? 'statement'} verified`
                      : standalone.proof === 'bad'
                        ? `${STANDALONE_LABEL[op.kind] ?? 'statement'} failed verification`
                        : 'statement unverified'}
                  </Check>
                </>
              )
            ) : (
              <Check
                state="warn"
                note="a key signed this — fold the owning chain to prove authorization"
              >
                signer authorization unproven standalone
              </Check>
            )}
          </Checks>
        </Panel>
      ) : null}

      {chain && chain.rows.length > 1 ? (
        <Panel title="position in chain">
          <OpTimeline
            rows={chain.rows}
            headCid={chain.headCid}
            currentCid={props.cid}
            showSigner={false}
          />
          <div
            class="nav"
            style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}
          >
            {chain.position > 1 && chain.rows[chain.position - 2] ? (
              <a href={`#/op/${chain.rows[chain.position - 2]?.cid}`}>← previous op</a>
            ) : (
              <span class="muted">← previous op</span>
            )}
            {chain.present && chain.position < chain.total && chain.rows[chain.position] ? (
              <a href={`#/op/${chain.rows[chain.position]?.cid}`}>next op →</a>
            ) : (
              <span class="muted">next op →</span>
            )}
          </div>
        </Panel>
      ) : null}

      <Panel title="countersignatures" right={<span class="lbl">inter-subjective</span>}>
        {witnesses === null ? (
          <span class="muted">loading witnesses…</span>
        ) : witnesses.length === 0 ? (
          <div class="ck-note">
            No witnesses. A{' '}
            <Term word="countersignature" def={GLOSSARY['countersignature'] ?? ''} /> is a separate
            signed statement by another party — "I, witness W, attest to operation X." None have
            been published to these relays for this op.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>witness</th>
                <th>relation</th>
                <th>when</th>
                <th>targets this op</th>
                <th>sig</th>
              </tr>
            </thead>
            <tbody>
              {witnesses.map((w, i) => (
                <tr key={i}>
                  <td>
                    <DidLink did={w.did} />
                  </td>
                  <td>
                    <span class="k-role">{w.relation}</span>
                  </td>
                  <td class="muted">{w.createdAt}</td>
                  <td>
                    {w.targetsThis ? (
                      <span class="ck ok">✓</span>
                    ) : (
                      <span class="err">✗ different target</span>
                    )}
                  </td>
                  <td>
                    <span class={`ck ${w.sig}`}>
                      {w.sig === 'ok' ? '✓' : w.sig === 'bad' ? '✗' : '·'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Related
        rows={[
          { k: 'parent chain', v: op?.chainId ? chainLink : null },
          {
            k: 'signer identity',
            v: kid && didOfKid(kid) ? <DidLink did={didOfKid(kid)} full /> : null,
          },
          {
            k: 'previous op',
            v:
              chain && chain.position > 1 && chain.rows[chain.position - 2] ? (
                <OpLink cid={chain.rows[chain.position - 2]?.cid ?? ''} />
              ) : null,
          },
          {
            k: 'next op',
            v:
              chain &&
              chain.present &&
              chain.position < chain.total &&
              chain.rows[chain.position] ? (
                <OpLink cid={chain.rows[chain.position]?.cid ?? ''} />
              ) : null,
          },
        ]}
      />
    </>
  );
};

const PayloadRow = (props: { k: string; value: unknown; kind: string }) => {
  const { k, value } = props;
  const note = PAYLOAD_NOTES[k];
  const rendered = (() => {
    if (k === 'type' && typeof value === 'string') return <OpType type={value} />;
    if (k === 'previousOperationCID' && typeof value === 'string')
      return <OpLink cid={value} full />;
    if (k === 'targetCID' && typeof value === 'string') return <OpLink cid={value} full />;
    if (k === 'did' && typeof value === 'string') return <DidLink did={value} full />;
    if (
      (k === 'documentCID' || k === 'baseDocumentCID' || k === 'credentialCID') &&
      typeof value === 'string'
    )
      return <TruncId value={value} />;
    if (k === 'documentCID' && value === null) return <span class="muted">null (cleared)</span>;
    if (k === 'authorization' && typeof value === 'string')
      return <AuthorizationRow token={value} />;
    if ((k === 'authKeys' || k === 'assertKeys' || k === 'controllerKeys') && Array.isArray(value))
      return <>{value.length} key(s)</>;
    if (k === 'services' && Array.isArray(value))
      return (
        <>
          {value.length} entr{value.length === 1 ? 'y' : 'ies'}
        </>
      );
    if (typeof value === 'string') return <>{value}</>;
    return <span class="muted">{JSON.stringify(value)?.slice(0, 200)}</span>;
  })();
  return (
    <>
      <div class="k">{k}</div>
      <div class="v">
        {rendered}
        {note ? <span class="ck-note"> — {note}</span> : null}
      </div>
    </>
  );
};

/*
  AUTHORIZATION — the embedded delegated-authority credential

  A non-creator's update/delete op carries a `authorization` DFOS credential
  proving the signer was delegated write authority rooted at the chain creator.
  Rather than dump the raw JWS, decode it (unsafe — display only) into a compact
  summary and link to the credential page, which folds the real proof (signature,
  delegation root, temporal window). The CID is re-derived from the payload bytes
  the same way credential.tsx does, so the link addresses the credential by its
  own content hash — not a relay-supplied header value.
*/
const AuthorizationRow = (props: { token: string }) => {
  // memoized so the decode isn't redone (and the CID effect doesn't refire) on
  // every unrelated Op-page re-render — the effect depends on props.token alone.
  const summary = useMemo(() => summarizeAuthorization(props.token), [props.token]);
  // undefined = deriving · null = derivation failed (fail visibly) · string = cid
  const [cid, setCid] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    let dead = false;
    setCid(undefined);
    // deriveCredentialCid swallows decode/encode failure into null, so this never
    // rejects unhandled — a failure shows an error, not a stuck "deriving…".
    void deriveCredentialCid(props.token).then((c) => {
      if (!dead) setCid(c);
    });
    return () => {
      dead = true;
    };
  }, [props.token]);

  if (!summary) {
    // not a well-formed credential — show the raw token, truncated + copyable,
    // rather than pretend to summarize something we couldn't decode.
    return <TruncId value={props.token} head={40} tail={8} />;
  }
  return (
    <div class="authz">
      <span class="lbl">issuer</span> <DidLink did={summary.iss} />{' '}
      <span class="lbl">audience</span>{' '}
      {summary.aud === '*' ? (
        <span class="k-role">public · anyone</span>
      ) : (
        <DidLink did={summary.aud} />
      )}
      <div style={{ marginTop: 2 }}>
        {summary.att.map((a, i) => (
          <span key={i} class="k-role">
            {a.action} · <AuthResource resource={a.resource} />
          </span>
        ))}
      </div>
      <div class="lbl" style={{ marginTop: 2 }}>
        valid {fmtUnixDate(summary.iat)} → {fmtUnixDate(summary.exp)} ·{' '}
        {cid === undefined ? (
          'deriving credential id…'
        ) : cid === null ? (
          <span class="err">credential id unavailable</span>
        ) : (
          <CredLink cid={cid} />
        )}
      </div>
    </div>
  );
};

/** A credential attenuation resource, linkified when it names a content chain. */
const AuthResource = (props: { resource: string }) => {
  const r = props.resource;
  if (r === 'chain:*') return <span class="muted">chain:*</span>;
  if (r.startsWith('chain:')) return <ContentLink id={r.slice('chain:'.length)} />;
  return <span class="muted">{r}</span>;
};
