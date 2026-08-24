/*

  Sign In With DFOS — demo relying party

  The smallest possible SIWD client: one page, no server, no secrets, no session
  backend. The load-bearing fact is that verification is PURE CLIENT-SIDE CRYPTO
  against a public relay — `verifySiwd` resolves the signer's identity chain and
  checks the signing key is a CURRENT authKey, so nothing here has to trust the
  platform that ran the consent screen. The second: `expect` lives in
  sessionStorage because the whole "session" is this tab — minted on the sign-in
  click, consumed on the way back, never sent anywhere. See specs/SIWD.md
  §Profile A.

  Three kit functions carry the whole flow: `createSiwdLoginRequest` mints and
  builds the redirect, `readSiwdCallback` reads the return, `verifySiwd` decides
  whether to believe it. Everything else in this file is DOM.

*/

import { createClient } from '@metalabel/dfos-client';
import type { VerifyResult } from '@metalabel/dfos-client';
import {
  createSiwdLoginRequest,
  readSiwdCallback,
  verifySiwd,
  type SiwdLoginRequest,
  type SiwdSession,
} from '@metalabel/dfos-client/siwd';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

// deployment coordinates — edit these when forking the demo
const AUTHORIZE_URL = 'https://app.dfos.com/authorize';
const RELAY_URL = 'https://relay.dfos.com';
const PUBLIC_API_URL = 'https://api.dfos.com/v1';
const EXPLORER_URL = 'https://explore.dfos.com';

/** This demo's own app identity — asserted in public/.well-known/dfos-app.json. */
const CLIENT_DID = 'did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke';

/** Where the source of the two files that ARE this flow lives. */
const REPO = 'https://github.com/metalabel/dfos/blob/main';

const EXPECT_KEY = 'siwd-demo-expect';

/**
 * Hosts that ride the platform's loopback tier (`npm run dev`). A local port
 * cannot prove a client identity, so the platform REJECTS a `client_did` on a
 * loopback redirect. The kit applies this rule itself off the redirect URI —
 * the demo only decides whether it has a DID to offer in the first place.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

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

const link = (href: string, text: string): HTMLAnchorElement => {
  const node = el('a', undefined, text);
  node.href = href;
  return node;
};

/** A labelled external link with a one-line caption under it. */
const linkNote = (href: string, text: string, caption: string): HTMLElement => {
  const wrap = el('p');
  wrap.append(link(href, text), el('br'), el('span', 'dim', caption));
  return wrap;
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

/** The four steps this page is about to run, in the order it runs them. */
const whatHappensNext = (): HTMLElement => {
  const list = el('ol', 'steps');
  for (const step of [
    'This page mints a challenge (domain + nonce + timestamp) and redirects you to your DFOS host.',
    "You approve on the host's consent screen; your custodial key signs the challenge bytes server-side.",
    'The browser returns here with the signed JWS.',
    'This page re-verifies everything client-side against your public identity chain on a relay — no server involved.',
  ]) {
    list.append(el('li', undefined, step));
  }
  return list;
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', signIn);
  const aside = el('p', 'dim');
  aside.append(
    'This site has no server and no secrets — verification is pure client-side crypto against a public relay. ',
    link(
      'https://github.com/metalabel/dfos/tree/main/examples/siwd-demo',
      'This demo site is open source',
    ),
    '.',
  );
  render(
    el('h1', undefined, 'Sign In With DFOS'),
    el(
      'p',
      undefined,
      'Sign in to this demo with your DFOS identity. You approve the sign-in on ' +
        'your platform’s consent screen; this page then verifies the signed ' +
        'challenge in your browser against your public identity chain.',
    ),
    ...(notice !== undefined ? [el('p', 'notice', notice)] : []),
    card(button, whatHappensNext()),
    aside,
  );
};

// -----------------------------------------------------------------------------
// receipts
// -----------------------------------------------------------------------------

const receiptSection = (heading: string, ...body: Node[]): Node[] => [
  el('h3', undefined, heading),
  ...body,
];

/**
 * The signed artifact, decoded for reading. `decodeJwsUnsafe` is exactly what
 * its name says — it does NO verification. That already happened; this is the
 * same bytes shown back to you.
 */
const artifactReceipt = (jws: string): Node[] => {
  const decoded = decodeJwsUnsafe(jws);
  const body: Node[] = [el('pre', 'wrap', jws)];

  if (decoded === null) return receiptSection('The signed artifact', ...body);

  const { alg, typ, kid } = decoded.header;
  body.push(
    el('p', 'dim', 'Protected header'),
    el('pre', 'wrap', JSON.stringify({ alg, typ, kid }, null, 2)),
    el(
      'p',
      'dim',
      'The kid is a DID URL: it names WHICH key in the signer’s identity chain ' +
        'produced this signature, which is what makes "is that key still current?" ' +
        'a question with an answer.',
    ),
    el('p', 'dim', 'Payload'),
    el('pre', 'wrap', JSON.stringify(decoded.payload, null, 2)),
    el(
      'p',
      'dim',
      'That payload IS the canonical challenge — byte for byte the bytes this ' +
        'page minted before the redirect, and byte for byte what the signature covers.',
    ),
  );
  return receiptSection('The signed artifact', ...body);
};

/**
 * One line per check `verifySiwd` ran. These are rendered FROM the verified
 * session — the checks already happened inside the kit, and re-running them
 * here would be theatre, not evidence.
 */
const checklistReceipt = (session: SiwdSession): Node[] => {
  const keyId = session.kid.slice(session.kid.indexOf('#') + 1);
  const list = el('ul', 'checks');
  for (const line of [
    'Identity chain resolved from the relay and replayed to current state — fresh, not cached (a stale resolution fails closed).',
    `Signing key is a CURRENT authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile (EdDSA, canonical scalar, no embedded key).',
    `Nonce matches the one this page minted, single use and now consumed: ${session.nonce}`,
    `Domain binding: the signed domain is this site — ${session.domain}`,
    `Timestamp inside the acceptance window: ${session.timestamp}`,
  ]) {
    list.append(el('li', undefined, line));
  }
  return receiptSection('What was checked', list);
};

/** Every claim above, independently checkable by the reader. */
const lookItUpReceipt = (did: string): Node[] =>
  receiptSection(
    'Look it up yourself',
    linkNote(
      `${RELAY_URL}/proof/v1/identities/${encodeURIComponent(did)}/log`,
      'The raw signed operation log',
      'What this page verified — the relay’s claim, in full, before any replay.',
    ),
    linkNote(
      // NOT encoded: the explorer's hash router takes the DID literally, and a
      // did:dfos identifier is fragment-safe as-is.
      `${EXPLORER_URL}/#/did/${did}`,
      'The same chain in the DFOS explorer',
      'Re-verified in YOUR tab — the same trust move this page just made.',
    ),
    linkNote(
      `${PUBLIC_API_URL}/users/${encodeURIComponent(did)}`,
      'The public profile lookup',
      'What this page rendered below. A 404 means a verified identity with no public profile.',
    ),
  );

const sourceReceipt = (): Node[] =>
  receiptSection(
    'Read the source',
    linkNote(
      `${REPO}/examples/siwd-demo/src/main.ts`,
      'examples/siwd-demo/src/main.ts',
      'This page: the relying party, DOM and all.',
    ),
    linkNote(
      `${REPO}/packages/dfos-client/src/siwd.ts`,
      'packages/dfos-client/src/siwd.ts',
      'The kit: mint, read, verify. The whole flow is those two files.',
    ),
  );

const receipts = (jws: string, session: SiwdSession): HTMLElement => {
  const details = el('details');
  details.append(
    el('summary', undefined, 'Show the receipts'),
    ...artifactReceipt(jws),
    ...checklistReceipt(session),
    ...lookItUpReceipt(session.did),
    ...sourceReceipt(),
  );
  return details;
};

const renderSignedIn = (session: SiwdSession, jws: string, profile: PublicProfile | null): void => {
  const signOut = el('button', undefined, 'Sign out');
  signOut.addEventListener('click', () => {
    sessionStorage.clear();
    renderSignedOut();
  });

  const did = session.did;
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
  render(el('h1', undefined, 'Signed in with DFOS'), card(...body), receipts(jws, session));
};

// -----------------------------------------------------------------------------
// flow
// -----------------------------------------------------------------------------

/**
 * A sign-in request is only valid for a few minutes at the host, so an expired
 * one is a NORMAL outcome (a tab left open, a slow consent). The remedy is
 * always the same: mint a fresh one. Say so rather than leaving the reader to
 * guess whether something is broken.
 */
const EXPIRED_NOTICE =
  'That sign-in request expired — they are only valid for a few minutes. ' +
  'Click sign in again; the second pass is quick since you are already logged in.';

const isExpiredReason = (reason: string): boolean =>
  reason.includes('expired') || reason.includes('challenge has expired');

const signIn = (): void => {
  const request: SiwdLoginRequest = createSiwdLoginRequest({
    authorizeUrl: AUTHORIZE_URL,
    domain: location.hostname,
    // trailing slash: the platform exact-matches this against the well-known allowlist
    redirectUri: `${location.origin}/`,
    scope: 'identity',
    statement: 'Sign in to the SIWD demo',
    // the kit drops this for a loopback redirect on its own; the demo only
    // decides whether it has a provable DID to assert at all
    ...(LOOPBACK_HOSTS.has(location.hostname) ? {} : { clientDid: CLIENT_DID }),
  });

  // `expect` is the one thing that must survive the redirect: domain + nonce
  // (+ did when bound), which is exactly what `verifySiwd` takes back.
  sessionStorage.setItem(EXPECT_KEY, JSON.stringify(request.expect));
  location.href = request.url;
};

/** Verification and the network hop to the relay share one error channel. */
const verify = async (
  jws: string,
  expect: SiwdLoginRequest['expect'],
): Promise<VerifyResult<SiwdSession>> => {
  try {
    const client = createClient({ relays: [RELAY_URL] });
    return await verifySiwd(client, jws, expect);
  } catch (err) {
    return { ok: false, error: `could not reach ${RELAY_URL}: ${errorMessage(err)}` };
  }
};

const handleCallback = async (jws: string): Promise<void> => {
  // the expectation is single-use: consumed here, pass or fail
  const saved = sessionStorage.getItem(EXPECT_KEY);
  sessionStorage.removeItem(EXPECT_KEY);
  if (saved === null) {
    renderSignedOut('There is no pending sign-in in this tab — start over.');
    return;
  }

  renderStatus('Verifying…');
  const result = await verify(jws, JSON.parse(saved) as SiwdLoginRequest['expect']);
  if (!result.ok || result.value === undefined) {
    const reason = result.error ?? 'unknown error';
    renderSignedOut(isExpiredReason(reason) ? EXPIRED_NOTICE : `Verification failed: ${reason}`);
    return;
  }

  await renderProfile(result.value, jws);
};

/**
 * The DID here comes from the VERIFIED session. The callback's `?did=` param is
 * unauthenticated courier convenience and is deliberately never read.
 */
const renderProfile = async (session: SiwdSession, jws: string): Promise<void> => {
  renderStatus('Loading profile…');

  let response: Response;
  try {
    response = await fetch(`${PUBLIC_API_URL}/users/${encodeURIComponent(session.did)}`);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile lookup failed: ${errorMessage(err)}`);
    return;
  }

  if (response.status === 404) {
    renderSignedIn(session, jws, null);
    return;
  }
  if (!response.ok) {
    renderSignedOut(`Signed in, but the profile lookup returned ${response.status}.`);
    return;
  }

  try {
    const profile = (await response.json()) as PublicProfile;
    renderSignedIn(session, jws, profile);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile response was unreadable: ${errorMessage(err)}`);
  }
};

const boot = (): void => {
  const callback = readSiwdCallback(location.search);

  // single-use artifacts must not survive a refresh. The kit deliberately does
  // not do this for us: `history` is the environment's, not the library's.
  if (callback.kind !== 'none') {
    history.replaceState(null, '', location.pathname);
  }

  if (callback.kind === 'denied') {
    renderSignedOut(
      isExpiredReason(callback.error)
        ? EXPIRED_NOTICE
        : `Sign-in was denied or failed at the platform: ${callback.error}`,
    );
    return;
  }
  if (callback.kind === 'success') {
    void handleCallback(callback.jws);
    return;
  }
  renderSignedOut();
};

boot();
