/*

  ROUTER — hash routes + hash query state, zero dependencies

    #/                 home
    #/search           grouped search results (?q=)
    #/identities       browse public identities
    #/documents        browse public documents
    #/artifacts        browse standalone signed artifacts
    #/did/<did>        identity
    #/key/<multibase>  a public key, and the identities it has been proved into
    #/domain/<host>    an origin's app description document
    #/content/<id>     content chain
    #/op/<cid>         operation
    #/cred/<cid>       credential
    #/glossary         glossary
    #/relays           relay management
    #/sync             local sync — the local index's controls and footprint

  A route may carry a QUERY STRING after the path (`#/documents?after=…&pub=0`).
  Every pageable / filterable surface writes its position there so a view can be
  linked and restored — an explorer whose views can't be shared is broken at the
  concept level. Query writes use history.replaceState (no history entry, no
  `hashchange`), so they never spam the back button and never remount the route;
  the module's own listener set is what re-renders the readers.

*/

import { useEffect, useState } from 'preact/hooks';

export type Route =
  | { view: 'home' }
  | { view: 'search' }
  | { view: 'glossary' }
  | { view: 'relays' }
  | { view: 'sync' }
  | { view: 'identities' }
  | { view: 'documents' }
  | { view: 'artifacts' }
  | { view: 'did'; id: string }
  | { view: 'key'; key: string }
  | { view: 'domain'; host: string }
  | { view: 'content'; id: string }
  | { view: 'op'; id: string }
  | { view: 'cred'; id: string };

/** Split a raw location.hash into its path and its query string (both bare). */
export const splitHash = (hash: string): { path: string; query: string } => {
  const raw = hash.replace(/^#/, '');
  const i = raw.indexOf('?');
  return i < 0 ? { path: raw, query: '' } : { path: raw.slice(0, i), query: raw.slice(i + 1) };
};

export const parseRoute = (hash: string): Route => {
  const path = splitHash(hash).path.replace(/^\/?/, '');
  const [head = '', ...rest] = path.split('/');
  const id = rest.join('/');
  if (head === 'search') return { view: 'search' };
  if (head === 'glossary') return { view: 'glossary' };
  if (head === 'relays') return { view: 'relays' };
  if (head === 'sync') return { view: 'sync' };
  if (head === 'identities') return { view: 'identities' };
  if (head === 'documents') return { view: 'documents' };
  if (head === 'artifacts') return { view: 'artifacts' };
  if (head === 'did' && id) return { view: 'did', id };
  if (head === 'key' && id) return { view: 'key', key: id };
  if (head === 'domain' && id) return { view: 'domain', host: id };
  if (head === 'content' && id) return { view: 'content', id };
  if (head === 'op' && id) return { view: 'op', id };
  if (head === 'cred' && id) return { view: 'cred', id };
  return { view: 'home' };
};

export const navigate = (hash: string): void => {
  location.hash = hash;
};

export const useRoute = (): Route => {
  const [route, setRoute] = useState<Route>(() => parseRoute(location.hash));
  useEffect(() => {
    const onChange = (): void => setRoute(parseRoute(location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
};

// -----------------------------------------------------------------------------
// hash query state — the deep-link layer
// -----------------------------------------------------------------------------

type Listener = () => void;
const listeners = new Set<Listener>();

/** Read one query param off a hash. Pure, unit-tested. */
export const readHashParam = (hash: string, key: string): string =>
  new URLSearchParams(splitHash(hash).query).get(key) ?? '';

/**
 * Rewrite one query param on a hash, returning the new hash. An empty value
 * DROPS the param so a default-valued view links as the bare route (`#/documents`,
 * not `#/documents?after=`). Pure, unit-tested.
 */
export const writeHashParam = (hash: string, key: string, value: string): string => {
  const { path, query } = splitHash(hash);
  const params = new URLSearchParams(query);
  if (value) params.set(key, value);
  else params.delete(key);
  const qs = params.toString();
  return `#${path}${qs ? `?${qs}` : ''}`;
};

/** Replace the current hash query WITHOUT a history entry or a `hashchange`. */
const replaceHash = (next: string): void => {
  if (next === location.hash) return;
  history.replaceState(null, '', next);
  for (const fn of listeners) fn();
};

export const setHashParam = (key: string, value: string): void => {
  replaceHash(writeHashParam(location.hash, key, value));
};

/**
 * One deep-linkable query param as state. Reads the live hash (so a pasted link
 * restores on load), re-reads on back/forward AND on this module's own
 * replaceState writes, and writes through {@link setHashParam}.
 */
export const useHashParam = (key: string): [string, (value: string) => void] => {
  const [value, setValue] = useState<string>(() => readHashParam(location.hash, key));
  useEffect(() => {
    const read = (): void => setValue(readHashParam(location.hash, key));
    read();
    listeners.add(read);
    window.addEventListener('hashchange', read);
    return () => {
      listeners.delete(read);
      window.removeEventListener('hashchange', read);
    };
  }, [key]);
  return [value, (next: string) => setHashParam(key, next)];
};
