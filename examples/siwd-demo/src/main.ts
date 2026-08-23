/*

  Sign In With DFOS — demo relying party

  The smallest possible SIWD client: one page, no server, no secrets, no session
  backend. The load-bearing fact is that verification is PURE CLIENT-SIDE CRYPTO
  against a public relay — `verifySiwd` resolves the signer's identity chain and
  checks the signing key is a CURRENT authKey, so nothing here has to trust the
  platform that ran the consent screen. The second: the nonce lives in
  sessionStorage because the whole "session" is this tab — minted on the sign-in
  click, consumed on the way back, never sent anywhere. See specs/SIWD.md
  §Profile A.

*/

import { createClient } from '@metalabel/dfos-client';
import type { VerifyResult } from '@metalabel/dfos-client';
import { createSiwdChallenge, verifySiwd, type SiwdSession } from '@metalabel/dfos-client/siwd';

// deployment coordinates — edit these when forking the demo
const AUTHORIZE_URL = 'https://app.dfos.com/authorize';
const RELAY_URL = 'https://relay.dfos.com';
const PUBLIC_API_URL = 'https://api.dfos.com/v1';

/** This demo's own app identity — asserted in public/.well-known/dfos-app.json. */
const CLIENT_DID = 'did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke';

const NONCE_KEY = 'siwd-demo-nonce';

/** The public profile shape we read; everything but the DID may be absent. */
interface PublicProfile {
  did: string;
  username?: string | null;
  displayName?: string | null;
  avatarUrl?: string | null;
  bio?: string | null;
}

const errorMessage = (err: unknown): string => (err instanceof Error ? err.message : String(err));

// -----------------------------------------------------------------------------
// dom
// -----------------------------------------------------------------------------

/**
 * Every dynamic string in this demo came from the URL, the API, or the JWS —
 * all third-party text. It is set with `textContent`, never `innerHTML`.
 */
const el = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};

const card = (...children: Node[]): HTMLElement => {
  const node = el('div', 'card');
  node.replaceChildren(...children);
  return node;
};

const render = (...nodes: Node[]): void => {
  const app = document.getElementById('app');
  if (app === null) return;
  app.replaceChildren(...nodes);
};

/** Avatar URLs are third-party strings too — only ever load one over https. */
const httpsUrl = (value: string | null | undefined): string | undefined => {
  if (value === null || value === undefined || value === '') return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? url.toString() : undefined;
  } catch {
    return undefined;
  }
};

// -----------------------------------------------------------------------------
// views
// -----------------------------------------------------------------------------

const renderStatus = (text: string): void => {
  render(el('h1', undefined, 'Sign In With DFOS'), card(el('p', 'dim', text)));
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', signIn);
  render(
    el('h1', undefined, 'Sign In With DFOS'),
    el(
      'p',
      undefined,
      'Prove control of a DFOS identity to a third-party site — no password, no OAuth provider, no server.',
    ),
    ...(notice !== undefined ? [el('p', 'notice', notice)] : []),
    card(button),
    el(
      'p',
      'dim',
      'The whole flow runs client-side in this tab, and every line of it is open source.',
    ),
  );
};

const renderSignedIn = (did: string, profile: PublicProfile | null): void => {
  const signOut = el('button', undefined, 'Sign out');
  signOut.addEventListener('click', () => {
    sessionStorage.clear();
    renderSignedOut();
  });

  const body: Node[] = [];

  const avatar = httpsUrl(profile?.avatarUrl);
  if (avatar !== undefined) {
    const image = el('img', 'avatar');
    image.src = avatar;
    image.alt = '';
    body.push(image);
  }

  if (profile === null) {
    const line = el('p');
    line.append('Signed in as ', el('code', undefined, did));
    body.push(line);
    body.push(
      el(
        'p',
        'dim',
        'This identity has no public profile — the sign-in is still cryptographically verified.',
      ),
    );
  } else {
    body.push(el('h2', undefined, profile.displayName || profile.username || did));
    if (profile.username) body.push(el('p', 'dim', `@${profile.username}`));
    if (profile.bio) body.push(el('p', undefined, profile.bio));
    const didLine = el('p', 'dim');
    didLine.append(el('code', undefined, did));
    body.push(didLine);
  }

  body.push(signOut);
  render(el('h1', undefined, 'Signed in with DFOS'), card(...body));
};

// -----------------------------------------------------------------------------
// flow
// -----------------------------------------------------------------------------

const signIn = (): void => {
  const { encoded, nonce } = createSiwdChallenge({
    domain: location.hostname,
    statement: 'Sign in to the SIWD demo',
  });
  sessionStorage.setItem(NONCE_KEY, nonce);

  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('challenge', encoded);
  // trailing slash: the platform exact-matches this against the well-known allowlist
  url.searchParams.set('redirect_uri', `${location.origin}/`);
  url.searchParams.set('scope', 'identity');
  url.searchParams.set('client_did', CLIENT_DID);
  location.href = url.toString();
};

/** Verification and the network hop to the relay share one error channel. */
const verify = async (jws: string, nonce: string): Promise<VerifyResult<SiwdSession>> => {
  try {
    const client = createClient({ relays: [RELAY_URL] });
    return await verifySiwd(client, jws, { domain: location.hostname, nonce });
  } catch (err) {
    return { ok: false, error: `could not reach ${RELAY_URL}: ${errorMessage(err)}` };
  }
};

const handleCallback = async (jws: string): Promise<void> => {
  // the nonce is single-use: consumed here, pass or fail
  const nonce = sessionStorage.getItem(NONCE_KEY);
  sessionStorage.removeItem(NONCE_KEY);
  if (nonce === null) {
    renderSignedOut('There is no pending sign-in in this tab — start over.');
    return;
  }

  renderStatus('Verifying…');
  const result = await verify(jws, nonce);
  if (!result.ok || result.value === undefined) {
    renderSignedOut(`Verification failed: ${result.error ?? 'unknown error'}`);
    return;
  }

  await renderProfile(result.value.did);
};

/**
 * The DID here comes from the VERIFIED session. The callback's `?did=` param is
 * unauthenticated courier convenience and is deliberately never read.
 */
const renderProfile = async (did: string): Promise<void> => {
  renderStatus('Loading profile…');

  let response: Response;
  try {
    response = await fetch(`${PUBLIC_API_URL}/users/${encodeURIComponent(did)}`);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile lookup failed: ${errorMessage(err)}`);
    return;
  }

  if (response.status === 404) {
    renderSignedIn(did, null);
    return;
  }
  if (!response.ok) {
    renderSignedOut(`Signed in, but the profile lookup returned ${response.status}.`);
    return;
  }

  try {
    const profile = (await response.json()) as PublicProfile;
    renderSignedIn(did, profile);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile response was unreadable: ${errorMessage(err)}`);
  }
};

const boot = (): void => {
  const params = new URLSearchParams(location.search);
  const jws = params.get('jws');
  const error = params.get('error');

  // single-use artifacts must not survive a refresh
  if (jws !== null || error !== null) {
    history.replaceState(null, '', location.pathname);
  }

  if (error !== null) {
    renderSignedOut(`Sign-in was denied or failed at the platform: ${error}`);
    return;
  }
  if (jws !== null) {
    void handleCallback(jws);
    return;
  }
  renderSignedOut();
};

boot();
