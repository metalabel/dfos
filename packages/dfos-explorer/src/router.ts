/*

  ROUTER — hash routes, zero dependencies

    #/                 home
    #/identities       browse public identities
    #/documents        browse public documents
    #/artifacts        browse public artifacts
    #/did/<did>        identity
    #/content/<id>     content chain
    #/op/<cid>         operation
    #/cred/<cid>       credential
    #/glossary         glossary
    #/relays           relay management

*/

import { useEffect, useState } from 'preact/hooks';

export type Route =
  | { view: 'home' }
  | { view: 'glossary' }
  | { view: 'relays' }
  | { view: 'identities' }
  | { view: 'documents' }
  | { view: 'artifacts' }
  | { view: 'did'; id: string }
  | { view: 'content'; id: string }
  | { view: 'op'; id: string }
  | { view: 'cred'; id: string };

export const parseRoute = (hash: string): Route => {
  const path = hash.replace(/^#\/?/, '');
  const [head = '', ...rest] = path.split('/');
  const id = rest.join('/');
  if (head === 'glossary') return { view: 'glossary' };
  if (head === 'relays') return { view: 'relays' };
  if (head === 'identities') return { view: 'identities' };
  if (head === 'documents') return { view: 'documents' };
  if (head === 'artifacts') return { view: 'artifacts' };
  if (head === 'did' && id) return { view: 'did', id };
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
