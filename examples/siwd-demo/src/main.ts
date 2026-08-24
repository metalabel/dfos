/*

  Sign In With DFOS — demo relying party

  The smallest possible SIWD client: one page, no secrets, no session store. The
  load-bearing fact is that verification is CRYPTO AGAINST A PUBLIC RELAY —
  `verifySiwd` resolves the signer's identity chain and checks the signing key is
  a CURRENT authKey, so nothing here has to trust the platform that ran the
  consent screen. See specs/SIWD.md §Profile A.

  TWO SIGN-IN PATHS, which are the two tiers of the README's trust ladder:

    client  — the nonce is minted in this tab and the JWS is verified in this
              tab. `expect` rides through the redirect in sessionStorage,
              because the whole "session" is this tab: minted on the click,
              consumed on the way back, never sent anywhere.

    backend — the nonce is minted by `api/nonce.ts` and held in an HttpOnly
              cookie; the JWS is POSTed to `api/verify.ts` and verified in Node.
              The browser is the party being authenticated, so it cannot also be
              the party deciding it passed — which is the whole reason tier 2
              exists the moment a backend grants anything.

  Three kit functions carry both paths: `createSiwdLoginRequest` mints and builds
  the redirect, `readSiwdCallback` reads the return, `verifySiwd` decides whether
  to believe it. The only thing that changes between tiers is WHERE the last one
  runs. Everything else in this file is DOM.

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

const PENDING_KEY = 'siwd-demo-pending';

/**
 * The two tiers of the README's trust ladder, both wired up for real.
 *
 * `client` — the nonce is minted in this tab and the JWS is verified in this
 * tab. Sound exactly when nothing is granted on the strength of the DID.
 *
 * `backend` — the nonce is minted by this demo's serverless function and kept
 * in an HttpOnly cookie; the JWS is POSTed there and verified in Node. This is
 * the shape any app with a real API behind it needs, because the browser is
 * the party being authenticated and cannot also be the one deciding it passed.
 */
type SignInMode = 'client' | 'backend';

/** What survives the redirect: which tier started it, and (tier 1) what to expect. */
interface PendingSignIn {
  mode: SignInMode;
  expect: SiwdLoginRequest['expect'];
}

/**
 * Hosts that ride the platform's loopback tier (`npm run dev`). A local port
 * cannot prove a client identity, so the platform REJECTS a `client_did` on a
 * loopback redirect. The kit applies this rule itself off the redirect URI —
 * the demo only decides whether it has a DID to offer in the first place.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * `location.hostname` brackets an IPv6 literal — on `http://[::1]:5173/` it is
 * the string `[::1]`. The brackets are URL grammar, not part of the name, and
 * every verifier compares the signed `domain` EXACTLY:
 *
 *   - the platform requires the challenge domain to already be in bare form and
 *     compares it to the bracket-stripped redirect host, so `[::1]` is refused
 *     outright as non-canonical;
 *   - `api/verify.ts` strips brackets off the Host header, so it would expect
 *     `::1` while the browser had signed `[::1]`.
 *
 * Both mismatches vanish by signing the bare form. Only the IPv6 dev host is
 * affected — `localhost` and `127.0.0.1` are already bare.
 */
const bareHostname = (hostname: string): string =>
  hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

/** The domain this page signs into challenges, and expects back in them. */
const SIGNING_DOMAIN = bareHostname(location.hostname);

/** The public profile shape we read; everything but the DID may be absent. */
interface PublicProfile {
  did: string;
  username?: string | null;
  displayName?: string | null;
  avatarUrl?: string | null;
  bio?: string | null;
}

/**
 * A verified sign-in, from either tier — the shape the signed-in view and the
 * receipts render. The backend tier deliberately returns less than the client
 * tier holds: the nonce lived in a cookie this page could never read, and
 * echoing it back would hand the browser the one value it was never allowed to
 * choose.
 */
interface VerifiedSignIn {
  mode: SignInMode;
  did: string;
  domain: string;
  timestamp: string;
  kid: string;
  /** Tier 1 only — the nonce this tab minted and consumed. */
  nonce?: string;
  /** Tier 2 only — what the backend says about where a session would be minted. */
  note?: string;
}

/** The success shape of `POST /api/verify`. */
interface BackendVerifyResponse {
  ok: boolean;
  session?: { did: string; domain: string; timestamp: string; kid: string };
  note?: string;
  error?: string;
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

/**
 * Tier 2, offered quietly under the main path. Same redirect, same artifact —
 * the difference is entirely in WHO mints the nonce and WHO verifies, which is
 * the only difference that matters once a backend starts granting things.
 */
const backendOption = (): HTMLElement => {
  const wrap = el('p', 'secondary-option');
  const button = el('button', 'secondary', 'Sign in with backend verification');
  button.addEventListener('click', () => {
    void startSignIn('backend');
  });

  const caption = el('span', 'dim');
  caption.textContent =
    'Same flow, but the nonce comes from — and the signed challenge is verified ' +
    'by — this demo’s serverless backend. Tier 2 of the trust ladder in the README.';

  wrap.append(button, el('br'), caption);

  if (LOOPBACK_HOSTS.has(SIGNING_DOMAIN)) {
    wrap.append(
      el('br'),
      el(
        'span',
        'dim',
        'Locally this one needs `vercel dev` — the plain dev server serves the ' +
          'static page only, so the functions are not running.',
      ),
    );
  }
  return wrap;
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', () => {
    void startSignIn('client');
  });
  const aside = el('p', 'dim');
  aside.append(
    'This site has no secrets and no session store — the default path verifies entirely in your browser, against a public relay. ',
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
    card(button, whatHappensNext(), backendOption()),
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
 * result — the checks already happened inside the kit, and re-running them here
 * would be theatre, not evidence.
 *
 * The same six checks run in both tiers, because it is the same function. Only
 * WHERE it ran, and where the nonce lived, differ.
 */
const checklistReceipt = (verified: VerifiedSignIn): Node[] => {
  const backend = verified.mode === 'backend';
  const keyId = verified.kid.slice(verified.kid.indexOf('#') + 1);

  const nonceLine = backend
    ? 'Nonce matches the one the backend minted, carried in an HttpOnly cookie this page never got to choose or read. Making that nonce single-use needs a server-side store, which this demo does not run — see the PRODUCTION note in api/verify.ts.'
    : `Nonce matches the one this page minted, removed from this tab before verifying: ${verified.nonce}`;

  const list = el('ul', 'checks');
  for (const line of [
    'Identity chain resolved from the relay and replayed to current state — fresh, not cached (a stale resolution fails closed).',
    `Signing key is a CURRENT authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile (EdDSA, canonical scalar, no embedded key).',
    nonceLine,
    `Domain binding: the signed domain is this site — ${verified.domain}`,
    `Timestamp inside the acceptance window: ${verified.timestamp}`,
  ]) {
    list.append(el('li', undefined, line));
  }

  const body: Node[] = [list];
  if (backend) {
    if (verified.note !== undefined) body.push(el('p', 'dim', verified.note));
  } else {
    body.push(
      el(
        'p',
        'dim',
        'This same verification, run server-side instead: the second sign-in ' +
          'button on the signed-out page.',
      ),
    );
  }

  return receiptSection(
    backend ? 'What was checked — in Node, on the backend' : 'What was checked — in this tab',
    ...body,
  );
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

const receipts = (jws: string, verified: VerifiedSignIn): HTMLElement => {
  const details = el('details');
  details.append(
    el('summary', undefined, 'Show the receipts'),
    ...artifactReceipt(jws),
    ...checklistReceipt(verified),
    ...lookItUpReceipt(verified.did),
    ...sourceReceipt(),
  );
  return details;
};

const renderSignedIn = (
  verified: VerifiedSignIn,
  jws: string,
  profile: PublicProfile | null,
): void => {
  const signOut = el('button', undefined, 'Sign out');
  signOut.addEventListener('click', () => {
    sessionStorage.clear();
    renderSignedOut();
  });

  const did = verified.did;
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
  render(el('h1', undefined, 'Signed in with DFOS'), card(...body), receipts(jws, verified));
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

/**
 * Tier 2 step 1: ask the backend for a nonce. It also sets that nonce in an
 * HttpOnly cookie, which is how it remembers what it issued across the
 * redirect. What that buys is real but narrow: this page did not get to CHOOSE
 * the value it will later be checked against. It is not a replay defense — see
 * the note in api/verify.ts for what would be.
 */
const mintBackendNonce = async (): Promise<string> => {
  const response = await fetch('/api/nonce', { credentials: 'same-origin' });
  if (!response.ok) throw new Error(`/api/nonce returned ${response.status}`);
  const body = (await response.json()) as { nonce?: unknown };
  if (typeof body.nonce !== 'string' || body.nonce === '') {
    throw new Error('/api/nonce did not return a nonce');
  }
  return body.nonce;
};

const startSignIn = async (mode: SignInMode): Promise<void> => {
  let nonce: string | undefined;
  if (mode === 'backend') {
    try {
      nonce = await mintBackendNonce();
    } catch (err) {
      renderSignedOut(
        `Could not reach the demo backend: ${errorMessage(err)}. ` +
          'The backend path needs the deployed demo or `vercel dev`.',
      );
      return;
    }
  }

  const request: SiwdLoginRequest = createSiwdLoginRequest({
    authorizeUrl: AUTHORIZE_URL,
    domain: SIGNING_DOMAIN,
    // trailing slash: the platform exact-matches this against the well-known allowlist
    redirectUri: `${location.origin}/`,
    scope: 'identity',
    statement: 'Sign in to the SIWD demo',
    // the kit drops this for a loopback redirect on its own; the demo only
    // decides whether it has a provable DID to assert at all
    ...(LOOPBACK_HOSTS.has(SIGNING_DOMAIN) ? {} : { clientDid: CLIENT_DID }),
    // tier 2: the challenge carries the nonce the BACKEND minted, so the
    // signature comes back bound to a value only the backend ever chose
    ...(nonce !== undefined ? { nonce } : {}),
  });

  // `expect` is the one thing tier 1 needs to survive the redirect: domain +
  // nonce (+ did when bound), which is exactly what `verifySiwd` takes back.
  // Tier 2 keeps it only for display — its verification uses the cookie.
  const pending: PendingSignIn = { mode, expect: request.expect };
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending));
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

/**
 * Tier 2 step 2: hand the artifact to the backend. The body carries the JWS and
 * NOTHING else — no DID, no nonce. `credentials: 'same-origin'` is what lets
 * the nonce cookie ride along, and it is the only way the backend learns what
 * to expect.
 */
const verifyOnBackend = async (jws: string): Promise<VerifiedSignIn | string> => {
  let response: Response;
  try {
    response = await fetch('/api/verify', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jws }),
    });
  } catch (err) {
    return `could not reach the demo backend: ${errorMessage(err)}`;
  }

  let body: BackendVerifyResponse;
  try {
    body = (await response.json()) as BackendVerifyResponse;
  } catch {
    return `the backend returned an unreadable response (${response.status})`;
  }

  if (!response.ok || !body.ok || body.session === undefined) {
    return body.error ?? `verification failed (${response.status})`;
  }

  return {
    mode: 'backend',
    ...body.session,
    ...(body.note !== undefined ? { note: body.note } : {}),
  };
};

const handleCallback = async (jws: string): Promise<void> => {
  // read and removed together, so a reload cannot re-run this callback against
  // the same pending sign-in — tab hygiene, not a replay defense
  const saved = sessionStorage.getItem(PENDING_KEY);
  sessionStorage.removeItem(PENDING_KEY);
  if (saved === null) {
    renderSignedOut('There is no pending sign-in in this tab — start over.');
    return;
  }
  const pending = JSON.parse(saved) as PendingSignIn;

  renderStatus(pending.mode === 'backend' ? 'Verifying on the backend…' : 'Verifying in this tab…');

  if (pending.mode === 'backend') {
    const verified = await verifyOnBackend(jws);
    if (typeof verified === 'string') {
      renderSignedOut(
        isExpiredReason(verified) ? EXPIRED_NOTICE : `Verification failed: ${verified}`,
      );
      return;
    }
    await renderProfile(verified, jws);
    return;
  }

  const result = await verify(jws, pending.expect);
  if (!result.ok || result.value === undefined) {
    const reason = result.error ?? 'unknown error';
    renderSignedOut(isExpiredReason(reason) ? EXPIRED_NOTICE : `Verification failed: ${reason}`);
    return;
  }

  const { did, domain, timestamp, kid, nonce } = result.value;
  await renderProfile({ mode: 'client', did, domain, timestamp, kid, nonce }, jws);
};

/**
 * The DID here comes from the VERIFIED session. The callback's `?did=` param is
 * unauthenticated courier convenience and is deliberately never read.
 */
const renderProfile = async (verified: VerifiedSignIn, jws: string): Promise<void> => {
  renderStatus('Loading profile…');

  let response: Response;
  try {
    response = await fetch(`${PUBLIC_API_URL}/users/${encodeURIComponent(verified.did)}`);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile lookup failed: ${errorMessage(err)}`);
    return;
  }

  if (response.status === 404) {
    renderSignedIn(verified, jws, null);
    return;
  }
  if (!response.ok) {
    renderSignedOut(`Signed in, but the profile lookup returned ${response.status}.`);
    return;
  }

  try {
    const profile = (await response.json()) as PublicProfile;
    renderSignedIn(verified, jws, profile);
  } catch (err) {
    renderSignedOut(`Signed in, but the profile response was unreadable: ${errorMessage(err)}`);
  }
};

const boot = (): void => {
  const callback = readSiwdCallback(location.search);

  // get the JWS out of the address bar, history, and the referrer of anything
  // this page loads next. The kit deliberately does not do this for us:
  // `history` is the environment's, not the library's.
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
