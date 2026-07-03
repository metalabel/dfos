/*

  OPERATION VIEW — one op, two tiers of proof

  Alone, an operation proves only that its payload hashes to its CID and (once
  the signer's key resolves) that this key signed it. Whether the key was
  AUTHORIZED, whether the op sits on canonical history, whether it was
  superseded — that takes folding the whole chain, which happens here too.

  Credentials get their own richer view; this one forwards.

*/

import { verifyCountersignature } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks, type CheckState } from '../components/checks';
import { OpTimeline, OpType } from '../components/timeline';
import {
  ContentLink,
  Copyable,
  DidLink,
  KidLink,
  OpLink,
  Panel,
  Pill,
  Term,
} from '../components/ui';
import { getClient } from '../lib/client';
import { getDb } from '../lib/db-instance';
import { short } from '../lib/format';
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
  source: 'local' | 'relay' | 'missing';
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

const didOfKid = (kid: string): string => {
  const i = kid.indexOf('#');
  return i > 0 ? kid.slice(0, i) : '';
};

export const Op = (props: { cid: string }) => {
  const [op, setOp] = useState<OpState | null>(null);
  const [chain, setChain] = useState<ChainVerify | null>(null);
  const [witnesses, setWitnesses] = useState<WitnessRow[] | null>(null);

  useEffect(() => {
    let dead = false;
    setOp(null);
    setChain(null);
    setWitnesses(null);
    const relays = getRelays();
    const client = getClient();

    void (async () => {
      // find the JWS: local index first, relay fallback
      const db = await getDb();
      const local = await db.getOp(props.cid);
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

      // credentials get the dedicated view
      if (typ === 'did:dfos:credential') {
        location.hash = `#/cred/${props.cid}`;
        return;
      }

      const payload = decoded?.payload ?? {};
      const kind = local?.kind ?? KIND_OF_TYP[typ] ?? '';
      const chainId =
        local?.chainId ??
        (kind === 'identity-op'
          ? didOfKid(typeof decoded?.header.kid === 'string' ? decoded.header.kid : '')
          : typeof payload['did'] === 'string'
            ? payload['did']
            : '');

      const state: OpState = {
        ...(jwsToken ? { jwsToken } : {}),
        ...(decoded
          ? { header: decoded.header as unknown as Record<string, unknown>, payload }
          : {}),
        kind,
        chainId,
        source,
      };
      setOp(state);

      // tier 2: fold the whole chain and place this op on it
      if (chainId && (kind === 'identity-op' || kind === 'content-op')) {
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
        }
      }
    })();

    // countersignature web — independent of op resolvability
    void (async () => {
      const tokens = await fetchCountersigs(props.cid, relays);
      if (dead) return;
      if (tokens.length === 0) {
        setWitnesses([]);
        return;
      }
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
  const headerCid = typeof op?.header?.['cid'] === 'string' ? (op.header['cid'] as string) : '';
  const selfCidOk = !!op?.header && headerCid === props.cid;
  const payload = op?.payload ?? {};

  const pill = !op
    ? { state: 'pending' as const, text: 'decoding…' }
    : !op.jwsToken
      ? { state: 'warn' as const, text: 'not resolvable' }
      : !chain
        ? op.kind === 'identity-op' || op.kind === 'content-op'
          ? { state: 'pending' as const, text: 'verifying in chain…' }
          : { state: 'warn' as const, text: 'decoded · not chain-verified' }
        : !chain.present
          ? chain.note
            ? { state: 'warn' as const, text: 'decoded · chain verify failed' }
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
            <b>Alone it proves little — fold the chain for authority.</b>
          </>
        }
      >
        <div style={{ marginBottom: 8 }}>
          {typeof payload['type'] === 'string' ? <OpType type={payload['type']} /> : null}{' '}
          {op?.kind ? <span class={`kind ${op.kind}`}>{op.kind.replace('-op', '')}</span> : null}{' '}
          <span class="lbl">in chain</span> {chainLink}
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
            <Copyable value={props.cid} head={40} tail={8} />
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
                <Pill state="ok">names its own hash</Pill>
              ) : (
                <Pill state="bad">cid mismatch</Pill>
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
            <summary>raw json</summary>
            <pre style={{ whiteSpace: 'pre-wrap', margin: '6px 0 0', fontSize: 11 }}>
              {JSON.stringify(payload, null, 2).slice(0, 3000)}
            </pre>
          </details>
        </Panel>
      ) : null}

      {op?.jwsToken ? (
        <Panel title="verification" right={<span class="lbl">op alone vs whole chain</span>}>
          <div class="ck-note" style={{ marginBottom: 8 }}>
            Alone, an operation proves only that its payload hashes to this CID, and — once you
            fetch the signer's key — that this key signed it. It cannot prove the key was
            authorized, that the op sits on canonical history, or that it wasn't superseded. That
            takes folding the whole chain.
          </div>
          <Checks>
            <Check state="ok" note={typ}>
              envelope decodes
            </Check>
            <Check
              state={selfCidOk ? 'ok' : 'bad'}
              note={
                selfCidOk
                  ? 'header.cid == requested cid — the op names its own hash'
                  : 'header.cid differs from requested cid'
              }
            >
              self-certifying CID
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
      return <Copyable value={value} />;
    if (k === 'documentCID' && value === null) return <span class="muted">null (cleared)</span>;
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
