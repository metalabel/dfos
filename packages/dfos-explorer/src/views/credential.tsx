/*

  CREDENTIAL VIEW — a capability, verified from all four sides

  Signature + CID integrity + issuer identity (dfos-client), temporal window,
  root authority (does the issuer actually own the granted chain?), delegation
  (scope only narrows), and revocation — the one axis that can never be fully
  proven. Revocation display separates "no feed available anywhere — a
  revocation would be invisible here" from "feeds consulted, no verified
  revocation seen — absence is not proof".

*/

import type { Resolved, ResolvedCredential } from '@metalabel/dfos-client';
import {
  decodeDFOSCredentialUnsafe,
  verifyDelegationChain,
  type VerifiedDelegationChain,
} from '@metalabel/dfos-protocol/credentials';
import { dagCborCanonicalEncode } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks } from '../components/checks';
import { ProvenancePanel } from '../components/provenance';
import { ContentLink, Copyable, DidLink, KidLink, Panel, Pill, Term } from '../components/ui';
import { getClient } from '../lib/client';
import { getDb } from '../lib/db-instance';
import { fmtUnixDate, short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { fetchOpRaw, probeRevocationFeeds, type RevocationFeedProbe } from '../lib/relay-raw';
import { getRelays } from '../lib/relays';
import { NotFound } from './not-found';

interface RootCheck {
  state: 'ok' | 'bad' | 'warn';
  note: string;
  text: string;
  delegation?: VerifiedDelegationChain;
}

export const Credential = (props: { cid: string }) => {
  const [jws, setJws] = useState<string | null | undefined>(undefined); // undefined = loading
  const [resolved, setResolved] = useState<Resolved<ResolvedCredential> | null>(null);
  const [verifyError, setVerifyError] = useState('');
  const [bindError, setBindError] = useState('');
  const [root, setRoot] = useState<RootCheck | null>(null);
  const [feeds, setFeeds] = useState<RevocationFeedProbe[] | null>(null);

  useEffect(() => {
    let dead = false;
    setJws(undefined);
    setResolved(null);
    setVerifyError('');
    setBindError('');
    setRoot(null);
    setFeeds(null);
    const relays = getRelays();
    const client = getClient();

    void (async () => {
      const db = await getDb();
      const local = await db.getOp(props.cid);
      let token = local?.jwsToken ?? null;
      if (!token) token = (await fetchOpRaw(props.cid, relays))?.jwsToken ?? null;
      if (dead) return;

      const decoded = token ? decodeDFOSCredentialUnsafe(token) : null;
      if (token && !decoded) {
        // token exists but isn't a well-formed credential — hand to the op
        // view via replace() (not push) so this doesn't ping-pong with op.tsx.
        location.replace(`#/op/${props.cid}`);
        return;
      }

      // BIND the served token to the routed CID: re-derive the CID from the
      // payload bytes and require it to equal props.cid. A relay serving a
      // different (valid) credential under this CID must not render as this CID.
      if (token && decoded) {
        try {
          const encoded = await dagCborCanonicalEncode(decoded.payload);
          if (encoded.cid.toString() !== props.cid) {
            if (!dead) setBindError(encoded.cid.toString());
            setJws(null);
            return;
          }
        } catch {
          if (!dead) setBindError('unencodable payload');
          setJws(null);
          return;
        }
      }
      if (dead) return;
      setJws(token);
      if (!token || !decoded) return;

      // full client resolution: issuer + signature + revocation checker
      void (async () => {
        try {
          const res = await client.credential(token);
          if (!dead) setResolved(res);
        } catch (e) {
          if (!dead) setVerifyError(e instanceof Error ? e.message : String(e));
        }
      })();

      // root authority: single non-wildcard chain grant → issuer must own the chain
      void (async () => {
        const att = decoded.payload.att;
        const first = att[0];
        const single = att.length === 1 && first && /^chain:[^*]/.test(first.resource);
        if (!single || !first) {
          if (!dead)
            setRoot({
              state: 'warn',
              text: 'root authority not checked',
              note:
                att.length > 1
                  ? 'multi-resource grant'
                  : att[0]?.resource === 'chain:*'
                    ? 'wildcard grant — no single owning chain'
                    : 'non-chain resource',
            });
          return;
        }
        const contentId = first.resource.slice('chain:'.length);
        // Resolve the granted chain through the CLIENT (binds contentId + verifies
        // the creator), NOT a raw relay claim — the delegation root must be a
        // VERIFIED creatorDID, or a relay could name any DID as root.
        let creatorDID: string | undefined;
        try {
          const contentRes = await client.content(contentId);
          creatorDID = contentRes.value.creator.did;
        } catch {
          creatorDID = undefined;
        }
        if (dead) return;
        if (!creatorDID) {
          setRoot({
            state: 'warn',
            text: 'granted chain not resolvable on these relays',
            note: contentId,
          });
          return;
        }
        try {
          const callbacks = client.callbacks();
          const verified = await client.credential(token);
          const delegation = await verifyDelegationChain(verified.value.credential, {
            resolveIdentity: callbacks.resolveIdentity,
            rootDID: creatorDID,
            isRevoked: callbacks.isRevoked,
          });
          if (!dead)
            setRoot({
              state: 'ok',
              text: 'issuer authority verified to the chain creator',
              note: `root ${short(creatorDID)}`,
              delegation,
            });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          // temporal / revocation / transport failures are NOT an authority
          // denial — only a genuine root-mismatch is "issuer lacks authority"
          const authFailure =
            /root|delegation|attenuat|not the (issuer|creator)|does not (own|match)/i.test(msg);
          if (!dead)
            setRoot(
              authFailure
                ? {
                    state: 'bad',
                    text: 'issuer does not hold authority over the granted chain',
                    note: msg,
                  }
                : { state: 'warn', text: 'root authority unproven (not denied)', note: msg },
            );
        }
      })();

      // revocation feed availability probe (display-only)
      void probeRevocationFeeds(decoded.header.cid, relays).then((probes) => {
        if (!dead) setFeeds(probes);
      });
    })();

    return () => {
      dead = true;
    };
  }, [props.cid]);

  if (jws === undefined) {
    return (
      <Panel title="credential">
        <span class="muted">resolving…</span>
      </Panel>
    );
  }
  if (bindError) {
    return (
      <Panel title="credential CID mismatch">
        <div class="kv">
          <div class="k">requested</div>
          <div class="v">{props.cid}</div>
          <div class="k">relay served</div>
          <div class="v err">{bindError}</div>
        </div>
        <div class="ck-note" style={{ marginTop: 8 }}>
          A relay returned a credential whose bytes hash to a DIFFERENT CID than the one requested —
          it is not the credential at this address. Not rendering it as this CID.
        </div>
      </Panel>
    );
  }
  if (jws === null) {
    return <NotFound kind="credential" id={props.cid} />;
  }

  const decoded = decodeDFOSCredentialUnsafe(jws);
  if (!decoded) return null; // redirecting to #/op
  const p = decoded.payload;

  const nowSec = Math.floor(Date.now() / 1000);
  const notYet = p.iat > nowSec;
  const expired = p.exp <= nowSec;
  const farFuture = p.exp - nowSec > 10 * 365 * 24 * 3600;
  const revoked = resolved?.value.revoked ?? false;
  const anyFeedLive = feeds?.some((f) => f.feed === 'live') ?? false;

  const pill = revoked
    ? { state: 'bad' as const, text: 'REVOKED' }
    : verifyError
      ? /expired/i.test(verifyError)
        ? { state: 'warn' as const, text: 'expired' }
        : /not yet/i.test(verifyError)
          ? { state: 'warn' as const, text: 'not yet valid' }
          : { state: 'bad' as const, text: 'verification failed' }
      : !resolved || root === null
        ? { state: 'pending' as const, text: 'verifying locally…' }
        : root.state === 'bad'
          ? { state: 'warn' as const, text: 'verified · authority unproven' }
          : { state: 'ok' as const, text: 'verified locally' };

  const actions = p.att.map((a) => a.action).join(', ');
  const firstAtt = p.att[0];

  return (
    <>
      <Panel
        title={
          <>
            credential <Pill state={pill.state}>{pill.text}</Pill>
          </>
        }
        orient={
          <>
            A <Term word="credential" def={GLOSSARY['credential'] ?? ''} /> — an issuer grants an
            audience an action on a resource.{' '}
            <b>
              Delegation only <Term word="narrows" def={GLOSSARY['attenuation'] ?? ''} />; a child
              never widens its parent.
            </b>
          </>
        }
      >
        <div class="kv">
          <div class="k">credential</div>
          <div class="v">
            <Copyable value={props.cid} head={40} tail={8} />
          </div>
          <div class="k">issuer</div>
          <div class="v">
            <DidLink did={p.iss} full />
          </div>
          <div class="k">audience</div>
          <div class="v">
            {p.aud === '*' ? (
              <span class="k-role">public · anyone</span>
            ) : (
              <DidLink did={p.aud} full />
            )}
          </div>
          <div class="k">signer</div>
          <div class="v">
            <KidLink kid={decoded.header.kid} />
          </div>
          <div class="k">delegation</div>
          <div class="v">
            {p.prf && p.prf.length > 0 ? `${p.prf.length} hop(s)` : 'root — self-issued, no parent'}
          </div>
        </div>
        <div class="ck-note" style={{ marginTop: 8 }}>
          {p.aud === '*' ? 'Anyone' : short(p.aud, 16, 4)} may <b>{actions || '—'}</b>{' '}
          <ResourceLabel resource={firstAtt?.resource ?? '?'} />
          {p.att.length > 1 ? <span class="muted"> (+{p.att.length - 1} more)</span> : null},
          granted by {short(p.iss, 16, 4)}
          {p.exp ? (
            <>
              {' '}
              until <b>{fmtUnixDate(p.exp)}</b>
            </>
          ) : null}
          .
        </div>
      </Panel>

      <Panel title="verification" right={<span class="lbl">re-run in your browser</span>}>
        <Checks>
          {verifyError && !/expired|not yet/i.test(verifyError) ? (
            <Check state="bad" note={verifyError}>
              signature / integrity check failed
            </Check>
          ) : !resolved && !verifyError ? (
            <Check state="pend">verifying signature + resolving issuer…</Check>
          ) : resolved ? (
            <>
              <Check state="ok" note={short(decoded.header.kid, 20, 8)}>
                signature valid — Ed25519 over JWS
              </Check>
              <Check state="ok" note="header.cid matches dag-cbor re-hash of payload">
                credential CID integrity
              </Check>
              <Check state="ok" note={short(p.iss)}>
                issuer identity resolved & verified
              </Check>
            </>
          ) : null}
          <Check state={notYet ? 'bad' : 'ok'} note={fmtUnixDate(p.iat)}>
            {notYet ? 'not yet valid — iat is in the future' : 'issued'}
          </Check>
          <Check state={expired ? 'bad' : 'ok'} note={`expires ${fmtUnixDate(p.exp)}`}>
            {expired ? 'expired' : 'within validity window'}
          </Check>
          {root ? (
            <Check state={root.state} note={root.note}>
              {root.text}
            </Check>
          ) : (
            <Check state="pend">checking root authority…</Check>
          )}
          {p.prf && p.prf.length > 0 ? (
            root?.delegation ? (
              <Check state="ok" note={`root ${short(root.delegation.rootDID)}`}>
                delegation chain verified — {root.delegation.chain.length} credential(s), scope only
                narrows
              </Check>
            ) : root?.state === 'bad' ? (
              <Check state="bad" note={root.note}>
                delegation chain invalid
              </Check>
            ) : (
              <Check state="pend">walking delegation chain…</Check>
            )
          ) : (
            <Check state="ok">no delegation — self-issued root credential</Check>
          )}
          {revoked ? (
            <Check state="bad" note="a verified revocation proof binds this exact credential">
              REVOKED by its issuer
            </Check>
          ) : resolved ? (
            <Check
              state="warn"
              note={
                anyFeedLive
                  ? 'feeds consulted, no verified revocation seen — absence is not proof'
                  : 'no configured relay serves a revocation feed — a revocation would be invisible here'
              }
            >
              revocation: not observed
            </Check>
          ) : null}
        </Checks>
      </Panel>

      <Panel
        title="grants"
        right={
          <span class="lbl">
            <Term word="attenuations" def={GLOSSARY['attenuation'] ?? ''} /> · resource → action
          </span>
        }
      >
        <table>
          <thead>
            <tr>
              <th>resource</th>
              <th>action</th>
            </tr>
          </thead>
          <tbody>
            {p.att.map((a, i) => (
              <tr key={i}>
                <td>
                  <ResourceLabel resource={a.resource} />
                </td>
                <td>
                  {String(a.action)
                    .split(',')
                    .map((x) => (
                      <span key={x} class="k-role">
                        {x.trim()}
                      </span>
                    ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <Panel title="validity" right={<span class="lbl">temporal</span>}>
        <div class="kv">
          <div class="k">issued (iat)</div>
          <div class="v">
            {fmtUnixDate(p.iat)} <span class="muted">({p.iat})</span>
          </div>
          <div class="k">expires (exp)</div>
          <div class="v">
            {fmtUnixDate(p.exp)} <span class="muted">({p.exp})</span>
            {farFuture ? <span class="muted"> — effectively non-expiring</span> : null}
          </div>
          <div class="k">now</div>
          <div class="v">
            {notYet ? (
              <span class="err">not yet valid</span>
            ) : expired ? (
              <span class="err">expired</span>
            ) : (
              'active'
            )}
          </div>
        </div>
      </Panel>

      {root?.delegation && root.delegation.chain.length > 1 ? (
        <Panel title="delegation chain" right={<span class="lbl">leaf → root</span>}>
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>issuer</th>
                <th>audience</th>
                <th>credential</th>
              </tr>
            </thead>
            <tbody>
              {root.delegation.chain.map((c, i) => (
                <tr key={c.credentialCID}>
                  <td class="muted">
                    {i === 0 ? 'leaf' : i === (root.delegation?.chain.length ?? 0) - 1 ? 'root' : i}
                  </td>
                  <td>
                    <DidLink did={c.iss} />
                  </td>
                  <td>
                    {c.aud === '*' ? <span class="k-role">public</span> : <DidLink did={c.aud} />}
                  </td>
                  <td class="muted">{short(c.credentialCID, 12, 8)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div class="ck-note" style={{ marginTop: 6 }}>
            Each hop attenuates its parent — scope narrows, expiry never extends.
          </div>
        </Panel>
      ) : null}

      <Panel
        title="revocation"
        right={
          <span class="lbl">
            <Term word="revocation" def={GLOSSARY['revocation'] ?? ''} /> · per-relay feeds
          </span>
        }
      >
        {revoked ? (
          <Pill state="bad">REVOKED — verified proof</Pill>
        ) : feeds === null ? (
          <span class="muted">probing feeds…</span>
        ) : (
          <>
            <Pill state={anyFeedLive ? 'warn' : 'warn'}>
              {anyFeedLive ? 'not observed' : 'unknown — no feed available'}
            </Pill>
            <table style={{ marginTop: 8 }}>
              <thead>
                <tr>
                  <th>relay</th>
                  <th>feed</th>
                  <th>answer</th>
                </tr>
              </thead>
              <tbody>
                {feeds.map((f) => (
                  <tr key={f.relay}>
                    <td>{f.relay.replace(/^https?:\/\//, '')}</td>
                    <td>
                      {f.feed === 'live' ? (
                        <span style={{ color: 'var(--ok)' }}>live</span>
                      ) : f.feed === 'absent' ? (
                        <span class="muted">not served</span>
                      ) : (
                        <span class="err">unreachable</span>
                      )}
                    </td>
                    <td class="muted">
                      {f.feed === 'live' ? (f.revoked ? 'revocation returned' : 'none seen') : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div class="ck-note" style={{ marginTop: 6 }}>
              A relay can only attest to what it has ingested, and can withhold — a negative answer
              is honest absence-of-evidence, never proof of validity. Any positive answer is
              re-verified in the tab (signature, CID, issuer binding) before it is believed.
            </div>
          </>
        )}
      </Panel>

      {resolved ? <ProvenancePanel provenance={resolved.provenance} /> : null}
    </>
  );
};

const ResourceLabel = (props: { resource: string }) => {
  const r = props.resource;
  if (r === 'chain:*')
    return (
      <>
        <span class="k-role">chain:*</span> <span class="muted">all content chains</span>
      </>
    );
  if (r.startsWith('chain:'))
    return (
      <>
        <span class="muted">chain:</span>
        <ContentLink id={r.slice('chain:'.length)} />
      </>
    );
  return <>{r}</>;
};
