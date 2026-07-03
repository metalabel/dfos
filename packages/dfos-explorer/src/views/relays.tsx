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
import { DidLink, Panel } from '../components/ui';
import { getClient } from '../lib/client';
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

  const stats = health?.['stats'] as { pendingOps?: number } | undefined;
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
            {stats && typeof stats.pendingOps === 'number' ? (
              <>
                <div class="k">pending ops</div>
                <div class="v">{stats.pendingOps}</div>
              </>
            ) : null}
          </div>
          {verify === 'verified' ? (
            <div class="ck-note">
              Profile artifact verified — signed by a key the advertised DID holds, CID
              self-consistent. This authenticates the <b>artifact</b>, not that this host controls
              the DID (relays are parameters, never authorities). Open the DID to fold its identity
              in-tab.
            </div>
          ) : verify === 'relay-asserted' ? (
            <div class="ck-note">
              Showing the relay's self-described profile — not yet bound to its identity key (open
              the relay DID to fold its identity in-tab).
            </div>
          ) : null}
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
            Relays are <b>parameters, not authorities</b> — reads fan out across this set and
            everything re-verifies locally. Each relay advertises a signed profile and a capability
            set; the profile verifies against the relay's own self-certifying identity. Adding more
            independent relays strengthens convergence evidence; it never changes the math.
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
        <div class="ck-note" style={{ marginTop: 10 }}>
          The default seed ({DEFAULT_RELAYS.join(', ')}) is a pragmatic starting point, not a
          blessing — remove it any time. Each relay's local-index sync cursor is tracked
          independently; the op pool is a union across relays.
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
          How many distinct relays must return <b>byte-identical</b> answers before a read is
          treated as agreed. 1 = first-wins (fastest). Higher thresholds need that many configured,
          reachable relays — agreement is convergence evidence across an untrusted set, never
          completeness proof. Every answer is still fully re-verified locally regardless.
        </div>
      </Panel>
    </>
  );
};
