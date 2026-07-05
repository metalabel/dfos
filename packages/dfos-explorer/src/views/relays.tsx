/*

  RELAYS — the relay browser

  Reads fan out across every relay here; the client reports which one answered
  and whether the set agreed. Each relay's /.well-known carries an inline profile
  ARTIFACT and a capability set — we decode the profile immediately (relay-
  asserted) and then verify it against the relay's OWN self-certifying identity
  (verifyArtifact), so a relay's self-description is bound to math, not taken on
  faith. Relays remain parameters, never authorities.

*/

import type { RelayHealth } from '@metalabel/dfos-client';
import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { useEffect, useState } from 'preact/hooks';
import { ProfileCard, type ProfileVerify } from '../components/profile';
import { Copyable, DidLink, Panel, Term } from '../components/ui';
import { getClient } from '../lib/client';
import { fmtAge, fmtCount } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { decodeRelayProfile, verifyRelayProfile, type ProfileContent } from '../lib/profile';
import {
  addRelay,
  DEFAULT_RELAYS,
  getQuorum,
  getRelays,
  removeRelay,
  setQuorum,
  subscribeRelays,
} from '../lib/relays';

const CAP_LABELS: { key: string; label: string }[] = [
  { key: 'proof', label: 'proof' },
  { key: 'content', label: 'content' },
  { key: 'log', label: 'log' },
  // revocation-status query routes (/revocations/v1) — a relay advertising this
  // serves the credential/issuer revocation feeds the credential view consults.
  { key: 'revocations', label: 'revocations' },
  { key: 'write', label: 'write' },
];

const Caps = (props: { capabilities: Record<string, unknown> | undefined }) => {
  const caps = props.capabilities ?? {};
  return (
    <div class="caps">
      {CAP_LABELS.map((c) => {
        const on = caps[c.key] === true;
        return (
          <span
            key={c.key}
            class={`cap ${on ? 'on' : 'off'}`}
            title={on ? 'supported' : 'disabled'}
          >
            {c.label} {on ? '✓' : '✕'}
          </span>
        );
      })}
    </div>
  );
};

// the six primitive buckets a 0.17+ relay advertises in stats.countsByKind
const KIND_ORDER = [
  'identity',
  'content',
  'artifact',
  'credential',
  'countersign',
  'revocation',
] as const;

interface RelayStats {
  pendingOps?: number;
  opCount?: number;
  countsByKind?: Record<string, number>;
  oldestOpAt?: string | null;
  headCid?: string | null;
}

/** The enriched corpus telemetry from a relay's /.well-known (0.17+). Degrades
 *  gracefully: a pre-0.17 relay omits everything but pendingOps, so each field
 *  is rendered only when present. */
const RelayStatsBlock = (props: { stats: RelayStats; peers: string[] }) => {
  const { stats } = props;
  const counts = stats.countsByKind;
  const hasCorpus = typeof stats.opCount === 'number';

  return (
    <>
      {hasCorpus ? (
        <div class="kv relay-kv">
          <div class="k">operations</div>
          <div class="v">{fmtCount(stats.opCount ?? 0)}</div>
          {stats.oldestOpAt ? (
            <>
              <div class="k">oldest op</div>
              <div class="v">{fmtAge(stats.oldestOpAt)} ago</div>
            </>
          ) : null}
          {stats.headCid ? (
            <>
              <div class="k">head</div>
              <div class="v">
                <Copyable value={stats.headCid} head={12} tail={8} />
              </div>
            </>
          ) : null}
        </div>
      ) : null}
      {counts ? (
        <div class="caps" style={{ marginTop: 6 }}>
          {KIND_ORDER.map((k) => (
            <span key={k} class="k-role" title={`${k} operations`}>
              {k} {fmtCount(counts[k] ?? 0)}
            </span>
          ))}
        </div>
      ) : null}
      <div class="kv relay-kv">
        <div class="k">peers</div>
        <div class="v">
          {props.peers.length === 0 ? (
            <span class="muted">no peers</span>
          ) : (
            props.peers.map((p) => (
              <span key={p} class="k-role">
                {p.replace(/^https?:\/\//, '')}
              </span>
            ))
          )}
        </div>
      </div>
    </>
  );
};

const RelayCard = (props: { url: string; health: RelayHealth | undefined }) => {
  const { url, health } = props;
  const [profile, setProfile] = useState<ProfileContent | null>(null);
  const [verify, setVerify] = useState<ProfileVerify>('pending');

  const jws = typeof health?.['profile'] === 'string' ? (health['profile'] as string) : '';
  const did = typeof health?.did === 'string' ? health.did : '';

  useEffect(() => {
    let dead = false;
    setProfile(null);
    setVerify('pending');
    if (health === undefined) return; // still probing
    const claim = jws ? decodeRelayProfile(jws) : null;
    // beat 1 — the relay's own claim, shown immediately as relay-asserted
    if (claim?.profile) {
      setProfile(claim.profile);
      setVerify('relay-asserted');
    } else {
      setVerify(health.ok ? 'unverified' : 'pending');
    }
    // beat 2 — verify the artifact against the relay's self-certifying identity
    if (!did || !jws || !claim?.selfConsistent) return;
    void getClient()
      .identity(did)
      .then((res) => verifyRelayProfile(res.value as VerifiedIdentity, jws))
      .then((v) => {
        if (dead) return;
        if (v.ok) {
          setProfile(v.profile);
          setVerify('verified');
        }
        // a failed verify leaves the relay-asserted claim standing (honest: we
        // showed it, we just couldn't bind it to the relay's key)
      })
      .catch(() => {
        // identity unresolvable — the claim stays relay-asserted
      });
    return () => {
      dead = true;
    };
  }, [url, jws, did, health]);

  const stats = (health?.['stats'] as RelayStats | undefined) ?? {};
  const peers = Array.isArray(health?.['peers'])
    ? (health['peers'] as { endpoint?: unknown }[])
        .map((p) => (typeof p?.endpoint === 'string' ? p.endpoint : ''))
        .filter((p): p is string => p.length > 0)
    : [];
  const version = typeof health?.['version'] === 'string' ? (health['version'] as string) : '';
  const host = url.replace(/^https?:\/\//, '');

  return (
    <div class="relay-card">
      <div class="relay-card-hd">
        <div class="relay-host">
          {health === undefined ? (
            <span class="dot" />
          ) : health.ok ? (
            <span class="dot up" />
          ) : (
            <span class="dot down" />
          )}
          <b>{host}</b>
          {version ? <span class="lbl">v{version}</span> : null}
          {health && !health.ok ? <span class="err">unreachable</span> : null}
        </div>
        <a class="relay-remove" onClick={() => removeRelay(url)}>
          remove
        </a>
      </div>

      {health?.ok ? (
        <>
          <ProfileCard
            name={profile?.name}
            description={profile?.description}
            avatar={null}
            verify={verify}
            meta={
              <Caps capabilities={health.capabilities as Record<string, unknown> | undefined} />
            }
          />
          <div class="kv relay-kv">
            <div class="k">relay DID</div>
            <div class="v">{did ? <DidLink did={did} full /> : <span class="muted">—</span>}</div>
            {typeof stats.pendingOps === 'number' && stats.pendingOps >= 0 ? (
              <>
                <div class="k">pending ops</div>
                <div class="v">
                  {stats.pendingOps}
                  {stats.pendingOps > 0 ? <span class="lbl"> · sequencer backlog</span> : null}
                </div>
              </>
            ) : null}
          </div>
          <RelayStatsBlock stats={stats} peers={peers} />
        </>
      ) : null}
    </div>
  );
};

export const Relays = () => {
  const [relays, setRelays] = useState(getRelays());
  const [quorum, setQuorumState] = useState(getQuorum());
  const [health, setHealth] = useState<Map<string, RelayHealth>>(new Map());
  const [input, setInput] = useState('');
  const [error, setError] = useState('');

  useEffect(
    () =>
      subscribeRelays(() => {
        setRelays(getRelays());
        setQuorumState(getQuorum());
      }),
    [],
  );

  useEffect(() => {
    let cancelled = false;
    void getClient()
      .health()
      .then((results) => {
        if (cancelled) return;
        setHealth(new Map(results.map((r) => [r.url, r])));
      });
    return () => {
      cancelled = true;
    };
  }, [relays]);

  const add = (): void => {
    const url = addRelay(input);
    if (!url) {
      setError('not a usable relay url');
      return;
    }
    setError('');
    setInput('');
  };

  return (
    <>
      <Panel
        title="relays"
        right={<span class="lbl">{relays.length} configured</span>}
        orient={
          <>
            Relays are <b>parameters, not authorities</b> — everything re-verifies locally (
            <Term word="what that means" def={GLOSSARY['verifiedLocal'] ?? ''} />
            ).
          </>
        }
      >
        <div class="relay-cards">
          {relays.map((url) => (
            <RelayCard key={url} url={url} health={health.get(url)} />
          ))}
        </div>
        <div class="bar" style={{ marginTop: 12 }}>
          <input
            placeholder="add relay url…"
            style={{ flex: 1 }}
            value={input}
            onInput={(e) => setInput((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') add();
            }}
          />
          <button onClick={add}>add</button>
        </div>
        {error ? (
          <div class="err" style={{ marginTop: 6 }}>
            {error}
          </div>
        ) : null}
        <div class="lbl" style={{ marginTop: 10 }}>
          default seed: {DEFAULT_RELAYS.join(', ')} — remove it any time.
        </div>
      </Panel>

      <Panel title="quorum" right={<span class="lbl">agreement threshold</span>}>
        <div class="filters">
          {[1, 2, 3].map((n) => (
            <button
              key={n}
              class={quorum === n ? 'on' : ''}
              disabled={n > relays.length}
              onClick={() => setQuorum(n)}
            >
              {n} relay{n === 1 ? '' : 's'}
            </button>
          ))}
        </div>
        <div class="ck-note" style={{ marginTop: 8 }}>
          How many distinct relays must return <b>byte-identical</b> answers before a read counts as
          agreed — convergence evidence across an untrusted set, never completeness proof.
        </div>
      </Panel>
    </>
  );
};
