/*

  Sign In With DFOS — demo relying party

  This page never decides whether to believe a signed challenge. It hands the
  JWS to `/api/verify`, where the session is granted, and renders the answer.
  specs/SIWD.md requires that: a bare DID is an address, not a proof, so the
  JWS MUST be verified wherever a session is granted.

  The browser's half is three moves:

    1. ask `/api/login` where to go, and go there
    2. come back with a JWS and hand it to `/api/verify`
    3. render `/api/me`

  The JWS is also decoded here, for display. `decodeJwsUnsafe` does no
  verification — the panel says so, and so does the name.

  The authorize request carries `challenge`, `redirect_uri`, and
  `scope=identity`, built server-side in `api/login.ts`. No `client_did`: the
  platform learns who this app is by fetching `/.well-known/dfos-app.json` from
  the redirect's own origin, so that file is the app identity.

  That file is the one thing a fork has to get right, so this page checks its
  own at boot and says what it found — on the page, before the click, instead
  of one redirect later at the host.

*/

import { readSiwdCallback } from '@metalabel/dfos-client/siwd';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

// deployment coordinates — the backend's live in api/_lib.ts
const RELAY_URL = 'https://relay.dfos.com';
const EXPLORER_URL = 'https://explore.dfos.com';

/** Where the source of the files in this flow lives. */
const REPO = 'https://github.com/metalabel/dfos/blob/main';

/** This origin's own registration, served as a static file out of `public/`. */
const WELL_KNOWN_PATH = '/.well-known/dfos-app.json';

/** Bounded, so a stalled endpoint shows a message rather than a spinner. */
const API_TIMEOUT_MS = 3000;

/** Verification is longer: the server makes a relay hop inside this call. */
const VERIFY_TIMEOUT_MS = 15_000;

/**
 * The exact redirect target, trailing slash included: the host EXACT-MATCHES
 * this string against the `redirect_uris` allowlist it fetches. `api/login.ts`
 * derives the same string from the request's own origin, so the string this
 * page checks and the string the server sends cannot drift apart.
 */
const REDIRECT_URI = `${location.origin}/`;

/**
 * Hosts on the platform's loopback tier (`npm run dev`). A local port holds no
 * domain, so no well-known file is required and the self-check below skips.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * `location.hostname` brackets an IPv6 literal: on `http://[::1]:5173/` it is
 * the string `[::1]`. The brackets are URL grammar, not part of the name, and
 * the platform compares the signed `domain` EXACTLY against the
 * bracket-stripped redirect host — so `[::1]` would be refused as
 * non-canonical. Only the IPv6 dev host is affected; `localhost` and
 * `127.0.0.1` are already bare.
 */
const bareHostname = (hostname: string): string =>
  hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;

/** The domain the backend signs into challenges, derived here the same way. */
const SIGNING_DOMAIN = bareHostname(location.hostname);

/** A verified sign-in, as the server reads it back out of its own cookie. */
interface Session {
  did: string;
  /** The DID URL of the key that signed the challenge. */
  kid: string;
  /** Issued-at and expiry, unix seconds. */
  iat: number;
  exp: number;
}

/**
 * True once any endpoint has reported a per-instance secret. Sticky for the
 * life of the page: it is a property of the deployment, not of one response.
 */
let ephemeral = false;

// -----------------------------------------------------------------------------
// the backend
// -----------------------------------------------------------------------------

interface ApiResult {
  status: number;
  body: Record<string, unknown>;
}

/**
 * One shape for all four endpoints. `null` means the request never completed —
 * offline, aborted, dev server down — which is a different fact from a refusal
 * and is said differently on the page.
 *
 * Every call is same-origin and `fetch` sends same-origin credentials by
 * default, so cookies ride along. That is the whole session mechanism here.
 */
const call = async (
  path: string,
  options: { method?: string; body?: unknown; timeoutMs?: number } = {},
): Promise<ApiResult | null> => {
  const { method = 'GET', body, timeoutMs = API_TIMEOUT_MS } = options;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      signal: AbortSignal.timeout(timeoutMs),
      ...(body !== undefined
        ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        : {}),
    });
  } catch {
    return null;
  }

  let parsed: unknown = null;
  if (response.status !== 204) {
    try {
      parsed = await response.json();
    } catch {
      parsed = null;
    }
  }
  const jsonBody =
    typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};

  if (jsonBody['ephemeral'] === true) ephemeral = true;
  return { status: response.status, body: jsonBody };
};

/** A 200 from `/api/me`, shape-checked — anything else is "nobody is signed in". */
const sessionFrom = (result: ApiResult | null): Session | null => {
  if (result === null || result.status !== 200) return null;
  const { did, kid, iat, exp } = result.body;
  if (typeof did !== 'string' || typeof kid !== 'string') return null;
  if (typeof iat !== 'number' || typeof exp !== 'number') return null;
  return { did, kid, iat, exp };
};

/** The server's own words for a refusal, or a fallback. */
const reasonFrom = (result: ApiResult, fallback: string): string =>
  typeof result.body['reason'] === 'string' ? result.body['reason'] : fallback;

// -----------------------------------------------------------------------------
// registration self-check
// -----------------------------------------------------------------------------

/**
 * What this origin's own `/.well-known/dfos-app.json` says about it:
 *
 *   loopback   — dev run; no file is needed and none is looked for.
 *   registered — the file lists this page's exact redirect target.
 *   unlisted   — the file is served but that exact string is not in it.
 *   missing    — no file, no network, or nothing parseable.
 *
 * Only `registered` carries the file's claims, since only then does the host
 * have something it will stand behind at consent.
 */
interface Registration {
  state: 'loopback' | 'registered' | 'unlisted' | 'missing';
  name?: string;
  clientDid?: string;
}

/**
 * One same-origin fetch, best-effort: no retries and no spinner. Every failure
 * collapses to `missing` — from the host's side they are the same fact. Bounded
 * because boot awaits this before the first render and a browser fetch has no
 * timeout of its own: a stalled request (a misbehaving service worker, a proxy)
 * must degrade to `missing` rather than hold the page, and the callback
 * verification behind it, hostage.
 */
const checkRegistration = async (): Promise<Registration> => {
  if (LOOPBACK_HOSTS.has(SIGNING_DOMAIN)) return { state: 'loopback' };

  let parsed: unknown;
  try {
    const response = await fetch(WELL_KNOWN_PATH, { signal: AbortSignal.timeout(3000) });
    if (!response.ok) return { state: 'missing' };
    parsed = await response.json();
  } catch {
    return { state: 'missing' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { state: 'missing' };
  }

  const raw = parsed as Record<string, unknown>;
  const listed = Array.isArray(raw['redirect_uris'])
    ? raw['redirect_uris'].filter((value): value is string => typeof value === 'string')
    : [];
  if (!listed.includes(REDIRECT_URI)) return { state: 'unlisted' };

  return {
    state: 'registered',
    ...(typeof raw['name'] === 'string' ? { name: raw['name'] } : {}),
    ...(typeof raw['client_did'] === 'string' ? { clientDid: raw['client_did'] } : {}),
  };
};

/**
 * The verdict, resolved once before anything renders. `null` only exists
 * before that one fetch settles, and no view runs that early.
 */
let registration: Registration | null = null;

/** The one edit a fork needs, said before the click rather than after it. */
const registrationNotice = (found: Registration): string | undefined => {
  if (found.state === 'unlisted') {
    return (
      'This origin is not in its own redirect allowlist, so the host will refuse ' +
      `the sign-in. Add this exact string — trailing slash included — to ` +
      `redirect_uris in public/.well-known/dfos-app.json: ${REDIRECT_URI}`
    );
  }
  if (found.state === 'missing') {
    return (
      'This origin serves no registration, so the host will refuse the sign-in. ' +
      `Add public/.well-known/dfos-app.json with two members: name, and ` +
      `redirect_uris containing this exact string: ${REDIRECT_URI}`
    );
  }
  return undefined;
};

/** The other configuration a fork can forget — this one degrades rather than fails. */
const EPHEMERAL_NOTICE =
  'No SESSION_SECRET is set, so this server signs cookies with a random key ' +
  'minted at startup: sessions die with the process. The fallback is dev-server ' +
  'only — deployed, sign-in refuses until the variable is set. Set ' +
  'SESSION_SECRET to any long random string, 32+ characters.';

// -----------------------------------------------------------------------------
// dom
// -----------------------------------------------------------------------------

/**
 * Every dynamic string here comes from the URL, the API, the JWS, or a served
 * JSON file — all untrusted text. Set with `textContent`, never `innerHTML`.
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

/** The notices that belong above every view, in the order they matter. */
const notices = (notice?: string): Node[] => [
  ...(notice !== undefined ? [el('p', 'notice', notice)] : []),
  ...(ephemeral ? [el('p', 'notice', EPHEMERAL_NOTICE)] : []),
];

// -----------------------------------------------------------------------------
// views
// -----------------------------------------------------------------------------

const renderStatus = (text: string, ...extra: Node[]): void => {
  render(
    el('h1', undefined, 'Sign In With DFOS'),
    ...notices(),
    card(el('p', 'dim', text)),
    ...extra,
  );
};

/** The four steps this page is about to run, in the order it runs them. */
const whatHappensNext = (): HTMLElement => {
  const list = el('ol', 'steps');
  for (const step of [
    'This page asks its backend to start a sign-in. The server mints the challenge (domain, nonce, timestamp), seals the nonce into an httpOnly cookie, and answers with a URL.',
    "You approve on your DFOS host's consent screen, where your custodial key signs the challenge bytes.",
    'The browser returns here with the signed JWS and posts it to this site’s backend.',
    'The server unseals the nonce it minted, verifies the JWS against your public identity chain on a relay, and mints a session cookie.',
  ]) {
    list.append(el('li', undefined, step));
  }
  return list;
};

/**
 * What registration is, written once and rendered twice — under the sign-in
 * button, and again in the receipts. It is a file this origin serves, and the
 * reader can open it from here.
 */
const registrationNote = (found: Registration): Node[] => {
  if (found.state === 'loopback') {
    return [
      el(
        'p',
        'dim',
        'This is a loopback host, so the page is registered nowhere and does not ' +
          'need to be: http://localhost is an accepted redirect target for ' +
          'scope=identity under the platform’s loopback tier (the RFC 8252 posture ' +
          '— a local port holds no domain to prove). Deployed to a domain, this app ' +
          'registers itself by serving one JSON file.',
      ),
    ];
  }

  const body: Node[] = [
    linkNote(
      WELL_KNOWN_PATH,
      WELL_KNOWN_PATH,
      'This origin’s registration, live — the same file the host fetches.',
    ),
    el(
      'p',
      'dim',
      'Serving that file over https from the domain you control IS the ' +
        'registration: domain control is the credential. There is no developer ' +
        'portal and no client secret. The host fetches the file at authorize time ' +
        'and exact-matches redirect_uris against this page’s redirect target, ' +
        'trailing slash included.',
    ),
  ];

  if (found.name !== undefined) {
    const line = el('p', 'dim');
    line.append(
      'Name shown at consent: ',
      el('code', undefined, found.name),
      ' — the app’s own claim about itself, which the consent screen labels as self-asserted.',
    );
    body.push(line);
  }
  if (found.clientDid !== undefined) {
    const line = el('p', 'dim');
    line.append(
      'Declared client_did: ',
      el('code', undefined, found.clientDid),
      ' — optional at identity scope, and this app does not send it. The file names the app.',
    );
    body.push(line);
  }

  return body;
};

/** The registration note as a quieter block inside the sign-in card. */
const registrationSection = (found: Registration): HTMLElement => {
  const wrap = el('div', 'section');
  wrap.append(...registrationNote(found));
  return wrap;
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', () => void startSignIn());

  const aside = el('p', 'dim');
  aside.append(
    'Verification runs on this site’s own backend, against a public relay. No DFOS ' +
      'platform server is asked whether to believe the signature. ',
    link(
      'https://github.com/metalabel/dfos/tree/main/examples/siwd-demo',
      'This demo site is open source',
    ),
    '.',
  );

  const found = registration;
  const warning = found === null ? undefined : registrationNotice(found);

  render(
    el('h1', undefined, 'Sign In With DFOS'),
    el(
      'p',
      undefined,
      'Sign in to this demo with your DFOS identity. You approve on your platform’s ' +
        'consent screen; this site’s backend verifies the signed challenge against ' +
        'your public identity chain before granting a session.',
    ),
    ...notices(notice),
    ...(warning !== undefined ? [el('p', 'notice', warning)] : []),
    card(button, whatHappensNext(), ...(found !== null ? [registrationSection(found)] : [])),
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
 * The signed artifact, decoded for reading. DECODING IS NOT VERIFYING:
 * `decodeJwsUnsafe` parses base64url and hands back whatever was in there,
 * signature unchecked, and anyone can author those bytes. What makes this one a
 * sign-in is that `/api/verify` resolved the signer's identity chain and
 * matched its own sealed nonce — on the server, not here.
 */
const artifactReceipt = (jws: string): Node[] => {
  const decoded = decodeJwsUnsafe(jws);
  const body: Node[] = [
    el('p', 'dim', 'Decoded in your browser for display only — the server does the verifying.'),
    el('pre', 'wrap', jws),
  ];

  if (decoded === null) return receiptSection('The signed artifact', ...body);

  const { alg, typ, kid } = decoded.header;
  body.push(
    el('p', 'dim', 'Protected header'),
    el('pre', 'wrap', JSON.stringify({ alg, typ, kid }, null, 2)),
    el(
      'p',
      'dim',
      'The kid is a DID URL: it names which key in the signer’s identity chain ' +
        'produced this signature, so "is that key still current?" has an answer.',
    ),
    el('p', 'dim', 'Payload'),
    el('pre', 'wrap', JSON.stringify(decoded.payload, null, 2)),
    el(
      'p',
      'dim',
      'That payload IS the canonical challenge: byte for byte what the backend ' +
        'minted before the redirect, and what the signature covers. Its nonce is ' +
        'the one the server had already sealed into an httpOnly cookie.',
    ),
  );
  return receiptSection('The signed artifact', ...body);
};

/**
 * One line per check the server ran before it minted the session. Rendered
 * FROM the granted session — the checks happened in `api/verify.ts`, and
 * re-running them here would prove nothing.
 */
const checklistReceipt = (session: Session): Node[] => {
  const keyId = session.kid.slice(session.kid.indexOf('#') + 1);

  const list = el('ul', 'checks');
  for (const line of [
    'The expected nonce came from the server’s own sealed cookie, not from the callback or anything else the presenter could author.',
    'Identity chain resolved fresh from the relay and replayed to current state.',
    `Signing key is a current authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile (EdDSA, canonical scalar, no embedded key).',
    `Domain binding: the signed domain is this site — ${SIGNING_DOMAIN}`,
    'Timestamp inside the acceptance window, checked against the server’s clock.',
    'Nonce checked LAST, after every other check passed — the spec’s step 6.',
  ]) {
    list.append(el('li', undefined, line));
  }

  return receiptSection(
    'What the server checked, before it minted this session',
    list,
    el(
      'p',
      'dim',
      'This is the FLOW-BOUND replay discipline. Its guarantee: the signed ' +
        'challenge redeems only through the browser that started the flow, inside ' +
        'the timestamp window. Not global single-use — success here grants a session ' +
        'with this browser and nothing else. Grant anything portable and the ' +
        'discipline changes; see "The two replay disciplines" in the README.',
    ),
  );
};

/** Every claim above, independently checkable by the reader. */
const lookItUpReceipt = (did: string): Node[] =>
  receiptSection(
    'Look it up yourself',
    linkNote(
      `${RELAY_URL}/proof/v1/identities/${encodeURIComponent(did)}/log`,
      'The raw signed operation log',
      'What the backend verified — the relay’s claim, in full, before any replay.',
    ),
    linkNote(
      // NOT encoded: the explorer's hash router takes the DID literally, and a
      // did:dfos identifier is fragment-safe as-is.
      `${EXPLORER_URL}/#/did/${did}`,
      'The same chain in the DFOS explorer',
      'Re-verified in your own tab — the same check the backend just made.',
    ),
  );

const sourceReceipt = (): Node[] =>
  receiptSection(
    'Read the source',
    linkNote(
      `${REPO}/examples/siwd-demo/api/verify.ts`,
      'examples/siwd-demo/api/verify.ts',
      'The verifier: where the session is granted, and so where the checking happens.',
    ),
    linkNote(
      `${REPO}/examples/siwd-demo/api/_lib.ts`,
      'examples/siwd-demo/api/_lib.ts',
      'The seal that binds the nonce to this browser.',
    ),
    linkNote(
      `${REPO}/examples/siwd-demo/src/main.ts`,
      'examples/siwd-demo/src/main.ts',
      'This page: three fetches and a lot of DOM.',
    ),
    linkNote(
      `${REPO}/packages/dfos-client/src/siwd.ts`,
      'packages/dfos-client/src/siwd.ts',
      'The kit: mint, read, verify.',
    ),
  );

const receipts = (session: Session, jws?: string): HTMLElement => {
  const details = el('details');
  const found = registration;
  details.append(
    el('summary', undefined, 'Show the receipts'),
    ...(jws !== undefined ? artifactReceipt(jws) : []),
    ...checklistReceipt(session),
    ...(found !== null
      ? receiptSection('How this app is registered', ...registrationNote(found))
      : []),
    ...lookItUpReceipt(session.did),
    ...sourceReceipt(),
  );
  return details;
};

const renderSignedIn = (session: Session, jws?: string): void => {
  const signOutButton = el('button', undefined, 'Sign out');
  signOutButton.addEventListener('click', () => void signOut());

  const who = el('p');
  who.append('Signed in as ', el('code', undefined, session.did));

  const key = el('p', 'dim');
  key.append('Verified against signing key ', el('code', undefined, session.kid));

  render(
    el('h1', undefined, 'Signed in with DFOS'),
    ...notices(),
    card(
      who,
      key,
      el('p', 'dim', `Session expires ${new Date(session.exp * 1000).toLocaleString()}`),
      el('p', 'dim', 'Read from the server’s sealed session cookie via /api/me.'),
      signOutButton,
    ),
    receipts(session, jws),
  );
};

// -----------------------------------------------------------------------------
// flow
// -----------------------------------------------------------------------------

/**
 * A sign-in request is only valid for a few minutes at the host, so an expired
 * one is a normal outcome (a tab left open, a slow consent) with one remedy:
 * mint a fresh one. Say so, rather than leave the reader guessing.
 */
const EXPIRED_NOTICE =
  'That sign-in request expired — they are only valid for a few minutes. ' +
  'Click sign in again; the second pass is quick since you are already logged in.';

/**
 * Narrow on purpose. `verifySiwd` says `challenge expired` and the platform
 * says `challenge has expired`; matching the bare word would also swallow "no
 * sign-in in flight (or it expired)", a different situation the server already
 * words for a reader.
 */
const isExpiredReason = (reason: string): boolean =>
  reason.includes('challenge expired') || reason.includes('challenge has expired');

const startSignIn = async (): Promise<void> => {
  renderStatus('Starting sign-in…');

  // The server mints the challenge, so the server's clock authors the
  // timestamp — a browser with a skewed clock no longer produces sign-ins that
  // are born stale and refused on the way back.
  const result = await call('/api/login', { method: 'POST' });
  if (result === null) {
    renderSignedOut('Could not reach this site’s backend to start the sign-in.');
    return;
  }
  const url = result.body['url'];
  if (result.status !== 200 || typeof url !== 'string') {
    renderSignedOut(`Could not start the sign-in: ${reasonFrom(result, `HTTP ${result.status}`)}`);
    return;
  }
  location.assign(url);
};

const signOut = async (): Promise<void> => {
  renderStatus('Signing out…');
  const result = await call('/api/logout', { method: 'POST' });
  renderSignedOut(
    result !== null && result.status === 204 ? undefined : 'Sign-out did not complete — reload.',
  );
};

/**
 * The callback: decode for the reader, then let the server decide. The panel
 * goes up first, so what is being verified is on screen while it happens.
 */
const handleCallback = async (jws: string): Promise<void> => {
  const panel = el('details');
  panel.open = true;
  panel.append(el('summary', undefined, 'What just came back'), ...artifactReceipt(jws));
  renderStatus('Verifying on the server…', panel);

  const result = await call('/api/verify', {
    method: 'POST',
    body: { jws },
    timeoutMs: VERIFY_TIMEOUT_MS,
  });
  if (result === null) {
    renderSignedOut('The verification request did not complete — the backend did not answer.');
    return;
  }
  if (result.status !== 200 || result.body['ok'] !== true) {
    const reason = reasonFrom(result, `the server answered HTTP ${result.status}`);
    renderSignedOut(
      isExpiredReason(reason) ? EXPIRED_NOTICE : `The server refused the sign-in: ${reason}`,
    );
    return;
  }

  // Verified — read the session back the same way every other page load does,
  // so there is one signed-in view rendered from one source.
  const session = sessionFrom(await call('/api/me'));
  if (session === null) {
    renderSignedOut(
      'The server verified the sign-in but the session did not come back — check that ' +
        'cookies are not blocked for this site.',
    );
    return;
  }
  renderSignedIn(session, jws);
};

const boot = async (): Promise<void> => {
  const callback = readSiwdCallback(location.search);

  // get the JWS out of the address bar, history, and the referrer of anything
  // this page loads next. The kit deliberately leaves this to us: `history`
  // belongs to the environment, not the library.
  if (callback.kind !== 'none') {
    history.replaceState(null, '', location.pathname);
  }

  // settled before the first render, so no view has to handle a half-known
  // registration and no view triggers a second fetch
  registration = await checkRegistration();

  if (callback.kind === 'denied') {
    renderSignedOut(
      isExpiredReason(callback.error)
        ? EXPIRED_NOTICE
        : `Sign-in was denied or failed at the platform: ${callback.error}`,
    );
    return;
  }
  if (callback.kind === 'success') {
    await handleCallback(callback.jws);
    return;
  }

  const result = await call('/api/me');
  if (result === null) {
    renderSignedOut(
      'This site’s backend did not answer, so there is no session to show. If you are ' +
        'running it locally, check that `npm run dev` is up.',
    );
    return;
  }
  const session = sessionFrom(result);
  if (session === null) {
    renderSignedOut();
    return;
  }
  renderSignedIn(session);
};

void boot();
