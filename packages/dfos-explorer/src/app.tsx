/*

  APP SHELL — header, search, layout, router outlet

*/

import { useEffect, useRef, useState } from 'preact/hooks';
import { TermModal } from './components/ui';
import { getClient } from './lib/client';
import { fmtCount } from './lib/format';
import { getRelays, subscribeRelays } from './lib/relays';
import { dispatchInput, routeFor } from './lib/resolve-input';
import { startAutoSyncScheduler, useSyncState } from './lib/sync-store';
import { navigate, useRoute } from './router';
import { BrowseArtifacts } from './views/artifacts';
import { BrowseDocuments, BrowseIdentities } from './views/browse';
import { Content } from './views/content';
import { Credential } from './views/credential';
import { Domain } from './views/domain';
import { Glossary } from './views/glossary';
import { Home } from './views/home';
import { Identity } from './views/identity';
import { Key } from './views/key';
import { Op } from './views/op';
import { Relays } from './views/relays';
import { Search } from './views/search';
import { LocalSync } from './views/sync';

const SyncTicker = () => {
  const sync = useSyncState();
  const active = sync.phase === 'syncing' || sync.phase === 'resolving';
  if (!active) return null;
  const auto = sync.trigger === 'auto';
  const resolving = sync.phase === 'resolving';
  return (
    <a
      class="synctick"
      href="#/sync"
      title={`${auto ? 'auto-' : ''}${resolving ? 'resolving projections' : 'syncing'} — ${sync.status}`}
    >
      <span class="spin">◍</span>
      {auto ? <span class="synctick-auto">auto</span> : null}
      <span class="synctick-n">{resolving ? fmtCount(sync.resolved) : fmtCount(sync.ops)}</span>
    </a>
  );
};

const THEME_KEY = 'dfos-explorer:theme';
type Theme = 'dark' | 'light';

const currentTheme = (): Theme =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

const applyTheme = (t: Theme): void => {
  document.documentElement.setAttribute('data-theme', t);
  document.documentElement.style.colorScheme = t;
  try {
    localStorage.setItem(THEME_KEY, t);
  } catch {
    // storage unavailable — the in-session attribute still holds
  }
};

/** Terminal-idiom light/dark switch: shows the theme you'd flip TO. */
const ThemeToggle = () => {
  const [theme, setTheme] = useState<Theme>(currentTheme);
  const flip = (): void => {
    // read the DOM attribute (the source of truth), not component state — a
    // rapid double-click would otherwise flip against a stale snapshot
    const next: Theme = currentTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    setTheme(next);
  };
  return (
    <button
      class="theme-toggle"
      onClick={flip}
      title={`switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      [{theme === 'dark' ? 'light' : 'dark'}]
    </button>
  );
};

const Header = () => {
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
          <a href="#/identities">identities</a>
          <a href="#/documents">documents</a>
          <a href="#/artifacts">artifacts</a>
          <a href="#/relays">relays</a>
          <a href="#/sync">sync</a>
          <a href="#/glossary">glossary</a>
        </div>
        <div class="hstatus">
          <SyncTicker />
          <span class={dotClass} />
          <a href="#/relays">
            {relays.length} relay{relays.length === 1 ? '' : 's'}
          </a>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
};

/**
 * One box, two outcomes. A pasted IDENTIFIER dispatches straight to its view (a
 * DID, a contentId, a CID, a public KEY, or a DOMAIN — the resolve-in-one-step
 * the explorer has always had). Anything else is a NAME, and goes to the grouped
 * search results, where the relay's server-side name filter answers and the
 * content group says honestly what the index cannot do. There is no dead end.
 */
const SearchBar = () => {
  const inputRef = useRef<HTMLInputElement>(null);

  const go = (): void => {
    const value = (inputRef.current?.value ?? '').trim();
    if (!value) return;
    const target = dispatchInput(value);
    navigate(target ? routeFor(target) : `#/search?q=${encodeURIComponent(value)}`);
  };

  return (
    <div class="search">
      <input
        ref={inputRef}
        placeholder="search names, or paste a did:dfos:… / contentId / CID (baf…) / key (z6Mk…) / domain"
        autocomplete="off"
        spellcheck={false}
        onKeyDown={(e) => {
          if (e.key === 'Enter') go();
        }}
      />
      <button onClick={go}>search</button>
    </div>
  );
};

// "client-side only" used to lead this strip, which overclaims — two serverless
// routes do the DNS and well-known lookups a browser cannot (home's "what this
// is" panel states them). Every VERDICT is still computed in the tab, and that
// is the claim worth making here.
const Foot = () => (
  <div class="foot">
    every verdict computed in your tab via <code>@metalabel/dfos-client</code> · no canonical state
    — the view of the relays you configured · <a href="#/glossary">glossary</a>
  </div>
);

export const App = () => {
  const route = useRoute();

  // the auto-sync heartbeat lives for the life of the app
  useEffect(() => startAutoSyncScheduler(), []);

  const view = (() => {
    switch (route.view) {
      case 'glossary':
        return <Glossary />;
      case 'relays':
        return <Relays />;
      case 'sync':
        return <LocalSync />;
      case 'search':
        return <Search />;
      case 'identities':
        return <BrowseIdentities />;
      case 'documents':
        return <BrowseDocuments />;
      case 'artifacts':
        return <BrowseArtifacts />;
      case 'did':
        return <Identity did={route.id} />;
      case 'key':
        return <Key multibase={route.key} />;
      case 'domain':
        return <Domain host={route.host} />;
      case 'content':
        return <Content id={route.id} />;
      case 'op':
        return <Op cid={route.id} />;
      case 'cred':
        return <Credential cid={route.id} />;
      default:
        return <Home />;
    }
  })();

  // IA: the local-index sidebar used to ride along beside home and the browse
  // pages, costing every view 340px to carry a control panel. It is a page now
  // (#/sync), so EVERY route is full width and the mobile drawer is gone with it.
  return (
    <>
      <Header />
      <div class="wrap">
        <SearchBar />
        <main>{view}</main>
        <Foot />
      </div>
      <TermModal />
    </>
  );
};
