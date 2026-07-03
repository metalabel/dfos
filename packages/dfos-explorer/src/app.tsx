/*

  APP SHELL — header, search, layout, router outlet

*/

import { useEffect, useRef, useState } from 'preact/hooks';
import { TermBar } from './components/ui';
import { getClient } from './lib/client';
import { fmtCount } from './lib/format';
import { getRelays, subscribeRelays } from './lib/relays';
import { dispatchInput, routeFor } from './lib/resolve-input';
import { startAutoSyncScheduler, useSyncState } from './lib/sync-store';
import { navigate, useRoute } from './router';
import { Content } from './views/content';
import { Credential } from './views/credential';
import { Glossary } from './views/glossary';
import { Home } from './views/home';
import { Identity } from './views/identity';
import { LocalIndex } from './views/local-index';
import { Op } from './views/op';
import { Relays } from './views/relays';

const SyncTicker = () => {
  const sync = useSyncState();
  if (sync.phase !== 'syncing') return null;
  const auto = sync.trigger === 'auto';
  return (
    <a class="synctick" href="#/" title={`${auto ? 'auto-' : ''}syncing — ${sync.status}`}>
      <span class="spin">◍</span>
      {auto ? <span class="synctick-auto">auto</span> : null}
      <span class="synctick-n">{fmtCount(sync.ops)}</span>
    </a>
  );
};

const Header = (props: { onToggleIndex: () => void; indexOpen: boolean }) => {
  const [relays, setRelays] = useState(getRelays());
  const [status, setStatus] = useState<'probing' | 'up' | 'mixed' | 'down'>('probing');

  useEffect(() => subscribeRelays(() => setRelays(getRelays())), []);

  useEffect(() => {
    let cancelled = false;
    setStatus('probing');
    void getClient()
      .health()
      .then((results) => {
        if (cancelled) return;
        const up = results.filter((r) => r.ok).length;
        setStatus(up === results.length ? 'up' : up > 0 ? 'mixed' : 'down');
      });
    return () => {
      cancelled = true;
    };
  }, [relays]);

  const dotClass =
    status === 'up'
      ? 'dot up'
      : status === 'down'
        ? 'dot down'
        : status === 'mixed'
          ? 'dot mixed'
          : 'dot';

  return (
    <header>
      <div class="hbar">
        <div class="brand">
          <a href="#/">
            <b>dfos</b> <span>· explorer</span>
          </a>
        </div>
        <div class="hnav">
          <a href="#/glossary">glossary</a>
        </div>
        <div class="hstatus">
          <SyncTicker />
          <span class={dotClass} />
          <a href="#/relays">
            {relays.length} relay{relays.length === 1 ? '' : 's'}
          </a>
          <a class="index-toggle" onClick={props.onToggleIndex}>
            {props.indexOpen ? '✕ index' : '☰ index'}
          </a>
        </div>
      </div>
    </header>
  );
};

const SearchBar = () => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState('');

  const go = (): void => {
    const value = inputRef.current?.value ?? '';
    const target = dispatchInput(value);
    if (!target) {
      setError(
        value.trim()
          ? 'unrecognized identifier — expected did:dfos:…, a contentId, or a baf… CID'
          : '',
      );
      return;
    }
    setError('');
    navigate(routeFor(target));
  };

  return (
    <>
      <div class="search">
        <input
          ref={inputRef}
          placeholder="paste a did:dfos:… / contentId / operation CID (baf…)"
          autocomplete="off"
          spellcheck={false}
          onInput={() => setError('')}
          onKeyDown={(e) => {
            if (e.key === 'Enter') go();
          }}
        />
        <button onClick={go}>resolve</button>
      </div>
      {error ? (
        <div class="err" style={{ marginBottom: 10, fontSize: 11 }}>
          {error}
        </div>
      ) : null}
    </>
  );
};

const Foot = () => (
  <div class="foot">
    client-side only · verification via <code>@metalabel/dfos-client</code> +{' '}
    <code>@metalabel/dfos-protocol</code> · the full log syncs into a normalized IndexedDB store —
    chains fold offline · document bytes live on the content plane (relay-gated) · no canonical
    state — this is the view of the relays you configured
  </div>
);

export const App = () => {
  const route = useRoute();
  const [indexOpen, setIndexOpen] = useState(false);

  // the auto-sync heartbeat lives for the life of the app
  useEffect(() => startAutoSyncScheduler(), []);

  // navigating (tapping an index row) closes the mobile drawer
  useEffect(() => {
    setIndexOpen(false);
  }, [route]);

  const onSample = (q: string): void => {
    const target = dispatchInput(q);
    if (target) navigate(routeFor(target));
  };

  const view = (() => {
    switch (route.view) {
      case 'glossary':
        return <Glossary />;
      case 'relays':
        return <Relays />;
      case 'did':
        return <Identity did={route.id} />;
      case 'content':
        return <Content id={route.id} />;
      case 'op':
        return <Op cid={route.id} />;
      case 'cred':
        return <Credential cid={route.id} />;
      default:
        return <Home onSample={onSample} />;
    }
  })();

  return (
    <>
      <Header onToggleIndex={() => setIndexOpen((v) => !v)} indexOpen={indexOpen} />
      <div class="wrap">
        <SearchBar />
        <div class="cols">
          <main>{view}</main>
          <aside class={indexOpen ? 'open' : ''}>
            {indexOpen ? (
              <div class="drawer-close">
                <a onClick={() => setIndexOpen(false)}>✕ close</a>
              </div>
            ) : null}
            <LocalIndex />
          </aside>
        </div>
        <Foot />
      </div>
      <TermBar />
    </>
  );
};
