/*

  HOME — orientation, sync hero, samples

  The hero adapts to the local index: empty → a prominent invitation to sync;
  syncing → live counts + an indeterminate progress pulse (globalLog has no known
  total, so we never fake a percent); synced → a compact summary with a jump-in.
  The sync itself runs in the global store, so navigating away mid-sync keeps it
  going and the hero re-attaches to the same run when you come back.

*/

import { useEffect, useState } from 'preact/hooks';
import { Panel, Term } from '../components/ui';
import type { OpKind } from '../lib/db';
import { getDb } from '../lib/db-instance';
import { fmtCount } from '../lib/format';
import { GLOSSARY } from '../lib/glossary';
import { startSync, stopSync, useSyncState } from '../lib/sync-store';

const SAMPLES: { label: string; q: string }[] = [
  { label: 'identity', q: 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e' },
  { label: 'public content', q: 'dn2nc79k7z6ekzfhd43he4v8tr6h236' },
  { label: 'issuer (has credential)', q: 'did:dfos:tz49rzd68z98dfvre622nv2ta3a28vt' },
];

const ago = (ms: number): string => {
  if (!ms) return '';
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
};

const SyncHero = () => {
  const sync = useSyncState();
  const [counts, setCounts] = useState<{
    ops: number;
    chains: number;
    byKind: Partial<Record<OpKind, number>>;
  } | null>(null);

  useEffect(() => {
    let dead = false;
    void getDb()
      .then((db) => db.counts())
      .then((c) => {
        if (!dead) setCounts(c);
      });
    return () => {
      dead = true;
    };
  }, [sync.dbEpoch, sync.phase]);

  const syncing = sync.phase === 'syncing';
  const populated = (counts?.chains ?? 0) > 0;

  const kindLine = (() => {
    const k = counts?.byKind ?? {};
    const parts: string[] = [];
    if (k['identity-op']) parts.push(`${fmtCount(k['identity-op'])} identities`);
    if (k['content-op']) parts.push(`${fmtCount(k['content-op'])} content`);
    if (k['credential']) parts.push(`${fmtCount(k['credential'])} credentials`);
    return parts.join(' · ');
  })();

  return (
    <Panel
      title="local chain index"
      right={
        populated ? (
          <span class="lbl">
            {fmtCount(counts?.chains ?? 0)} chains{' '}
            {sync.lastSyncAt ? `· synced ${ago(sync.lastSyncAt)}` : ''}
          </span>
        ) : null
      }
    >
      {syncing ? (
        <div class="hero">
          <div class="hero-row">
            <span class="spin">◍</span>
            <b>syncing the global log</b>
            <span class="muted">
              {sync.relay ? `${sync.relay} · ` : ''}
              {fmtCount(sync.ops)} ops · {fmtCount(sync.chains)} chains
            </span>
          </div>
          <div class="syncbar" />
          <div class="hero-actions">
            <button onClick={() => stopSync()}>stop</button>
            <span class="muted">
              runs in the background — navigate freely, it keeps going. Completeness is outside the
              proof; this pulls what these relays hold.
            </span>
          </div>
        </div>
      ) : populated ? (
        <div class="hero">
          <div class="hero-row">
            <b>{fmtCount(counts?.ops ?? 0)} ops</b>
            <span class="muted">{kindLine}</span>
          </div>
          <div class="hero-actions">
            <button onClick={() => void startSync('manual')}>re-sync</button>
            <span class="muted">
              Browse chains in the <b>index</b> panel, or paste an identifier above. Everything
              folds offline from your local db and re-verifies in-tab.
            </span>
          </div>
        </div>
      ) : (
        <div class="hero">
          <div class="hero-row">
            <b>nothing synced yet</b>
            <span class="muted">
              Pull the full operation log from your relays into a local IndexedDB store. Chains then
              fold offline; your index persists across visits.
            </span>
          </div>
          <div class="hero-actions">
            <button class="primary" onClick={() => void startSync('manual')}>
              sync full log
            </button>
            <span class="muted">
              or paste a <Term word="DID" def={GLOSSARY['did'] ?? ''} /> / contentId /{' '}
              <Term word="CID" def={GLOSSARY['cid'] ?? ''} /> above to jump straight to a chain.
            </span>
          </div>
          {sync.error ? <div class="err">{sync.error}</div> : null}
        </div>
      )}
    </Panel>
  );
};

export const Home = (props: { onSample: (q: string) => void }) => (
  <>
    <Panel
      title="explorer"
      orient={
        <>
          Paste a <Term word="DID" def={GLOSSARY['did'] ?? ''} />, a contentId, or an operation{' '}
          <Term word="CID" def={GLOSSARY['cid'] ?? ''} /> above. Everything is fetched over plain
          HTTP from untrusted relays and <b>re-verified in your browser</b> — speed from the relay,
          truth from the math.
        </>
      }
    >
      <div class="placeholder">
        <div class="samples" style={{ justifyContent: 'center', marginBottom: 10 }}>
          <span class="lbl">try</span>
          {SAMPLES.map((s) => (
            <span key={s.q} class="chip" onClick={() => props.onSample(s.q)}>
              {s.label}
            </span>
          ))}
        </div>
        <span class="muted">
          New here? Read the <a href="#/glossary">glossary</a>.
        </span>
      </div>
    </Panel>

    <SyncHero />

    <Panel title="what this is">
      <div class="kv about">
        <div class="k">no backend</div>
        <div class="v muted">
          A static page. Relays are swappable parameters, like RPC endpoints — never authorities.
        </div>
        <div class="k">verify-in-tab</div>
        <div class="v muted">
          Signatures, CIDs, and chain linkage are recomputed locally via{' '}
          <code>@metalabel/dfos-client</code>. The relay's claims render first, then flip to
          verified (or MISMATCH — loudly).
        </div>
        <div class="k">local db</div>
        <div class="v muted">
          The full operation log syncs into IndexedDB in your browser. Chains fold offline; your
          index persists across visits.
        </div>
        <div class="k">no canonical state</div>
        <div class="v muted">
          Completeness is outside the proof. You are seeing what these relays hold — another relay
          may hold more, less, or a fork.
        </div>
      </div>
    </Panel>
  </>
);
