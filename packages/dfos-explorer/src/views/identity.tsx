/*

  IDENTITY VIEW — two beats

  Beat 1: the relay's claim (instant, relay-asserted). Beat 2: dfos-client
  re-folds the whole op log in the tab and the page flips to verified — or
  the tip drifts and we say so. Keys and services re-render from the VERIFIED
  state once it lands.

*/

import type { Resolved } from '@metalabel/dfos-client';
import type { ServiceEntry, VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { classifyAnchor } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import { useEffect, useState } from 'preact/hooks';
import { Check, Checks, type CheckState } from '../components/checks';
import { ProvenanceLine } from '../components/provenance';
import { OpTimeline } from '../components/timeline';
import {
  ContentLink,
  Copyable,
  CredLink,
  DidLink,
  OpLink,
  Panel,
  Pill,
  Term,
} from '../components/ui';
import { getClient } from '../lib/client';
import type { ExplorerOp } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { short } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { toOpRows, type OpRow } from '../lib/op-rows';
import { fetchClaim, type ClaimResult } from '../lib/relay-raw';
import { addRelay, getRelays } from '../lib/relays';
import { NotFound } from './not-found';

interface IdentityClaimState {
  isDeleted?: boolean;
  authKeys?: { id: string; publicKeyMultibase: string }[];
  assertKeys?: { id: string; publicKeyMultibase: string }[];
  controllerKeys?: { id: string; publicKeyMultibase: string }[];
  services?: ServiceEntry[];
}

export const Identity = (props: { did: string }) => {
  const [claim, setClaim] = useState<ClaimResult | null>(null);
  const [verified, setVerified] = useState<Resolved<VerifiedIdentity> | null>(null);
  const [rows, setRows] = useState<OpRow[]>([]);
  const [creds, setCreds] = useState<ExplorerOp[] | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let dead = false;
    setClaim(null);
    setVerified(null);
    setRows([]);
    setCreds(null);
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
      } catch (e) {
        if (!dead) setError(e instanceof Error ? e.message : String(e));
      }
    })();

    void getDb()
      .then((db) => db.chainOps(props.did, 'credential'))
      .then((ops) => {
        if (!dead) setCreds(ops);
      })
      .catch(() => {
        if (!dead) setCreds([]);
      });

    return () => {
      dead = true;
    };
  }, [props.did]);

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
  const tipAxis = verified?.trust.unverifiable?.includes('tip') ?? false;

  const pill = error
    ? { state: 'bad' as CheckState, text: 'verification failed' }
    : !verified
      ? { state: 'pend' as CheckState, text: 'verifying locally…' }
      : !claimHead || headMatch
        ? { state: 'ok' as CheckState, text: 'verified locally' }
        : { state: 'warn' as CheckState, text: 'verified · tip drift' };

  return (
    <>
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
            <Copyable value={props.did} head={40} tail={0} />
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
              {tipAxis ? (
                <Check
                  state="warn"
                  note="cached head + relay empty-delta claim; freshness is never proven in v1"
                >
                  tip freshness unproven
                </Check>
              ) : null}
            </>
          )}
        </Checks>
      </Panel>

      <KeysPanel state={state} verified={stateVerified} />
      <ServicesPanel services={('services' in state ? state.services : undefined) ?? []} />

      <Panel title="credentials issued" right={<span class="lbl">from local index</span>}>
        {creds === null ? (
          <span class="muted">reading local index…</span>
        ) : creds.length === 0 ? (
          <span class="muted">
            none in local index — sync the full log to populate (no relay endpoint lists an issuer's
            credentials)
          </span>
        ) : (
          <table>
            <thead>
              <tr>
                <th>credential</th>
                <th>audience</th>
                <th>grants</th>
              </tr>
            </thead>
            <tbody>
              {creds.map((op) => {
                const decoded = decodeJwsUnsafe(op.jwsToken);
                const aud =
                  typeof decoded?.payload['aud'] === 'string' ? decoded.payload['aud'] : '?';
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
        )}
      </Panel>

      <Panel title="operation history">
        {rows.length === 0 ? (
          <span class="muted">{error ? <span class="err">{error}</span> : 'loading log…'}</span>
        ) : (
          <OpTimeline rows={rows} headCid={localHead ?? claimHead} />
        )}
      </Panel>
    </>
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
                  <Copyable value={row.publicKeyMultibase} />
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
