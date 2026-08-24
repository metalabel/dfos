/*

  Sign In With DFOS — demo relying party

  The smallest possible SIWD client: one static page, no secrets, no session
  store, no backend at all. The load-bearing fact is that verification is CRYPTO
  AGAINST A PUBLIC RELAY — `verifySiwd` resolves the signer's identity chain and
  checks the signing key is a CURRENT authKey, so nothing here has to trust the
  platform that ran the consent screen. See specs/SIWD.md §Profile A.

  Three kit functions carry the whole flow: `createSiwdLoginRequest` mints and
  builds the redirect, `readSiwdCallback` reads the return, `verifySiwd` decides
  whether to believe it. Everything else in this file is DOM.

  THE AUTHORIZE REQUEST CARRIES THREE PARAMS: `challenge`, `redirect_uri`, and
  `scope=identity`. No `client_did` — the platform resolves who this app is by
  fetching `/.well-known/dfos-app.json` from the redirect's own origin, so the
  file is the app identity and the request param is only an optional assertion
  that has to agree with it. What `client_did` actually determines is the `aud`
  of a returned credential, and an identity-scope sign-in returns none.

  Which makes that served file the one thing a fork has to get right, so this
  page CHECKS ITS OWN at boot and says what it found. A missing or unlisted
  redirect is refused at the host, several seconds and one redirect away from
  the mistake; the self-check moves that sentence back onto the page you are
  standing on, before the click.

*/

import { createClient } from '@metalabel/dfos-client';
import {
  createSiwdLoginRequest,
  readSiwdCallback,
  verifySiwd,
  type SiwdLoginRequest,
} from '@metalabel/dfos-client/siwd';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

// deployment coordinates — edit these when forking the demo
const AUTHORIZE_URL = 'https://app.dfos.com/authorize';
const RELAY_URL = 'https://relay.dfos.com';
const PUBLIC_API_URL = 'https://api.dfos.com/v1';
const EXPLORER_URL = 'https://explore.dfos.com';

/** Where the source of the two files that ARE this flow lives. */
const REPO = 'https://github.com/metalabel/dfos/blob/main';

/** This origin's own registration, served as a static file out of `public/`. */
const WELL_KNOWN_PATH = '/.well-known/dfos-app.json';

const PENDING_KEY = 'siwd-demo-pending';

/**
 * The exact redirect target, trailing slash included, because the host
 * EXACT-MATCHES this string against the `redirect_uris` allowlist it fetches.
 * It is also the string the boot self-check looks for, so the check and the
 * request it is checking can never drift apart.
 */
const REDIRECT_URI = `${location.origin}/`;

/**
 * Hosts that ride the platform's loopback tier (`npm run dev`). A local port
 * holds no domain, so there is nothing for a well-known file to vouch for and
 * none is required: the platform consents to a loopback target under its own
 * tier for `scope=identity`. The self-check below skips entirely on these.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * `location.hostname` brackets an IPv6 literal — on `http://[::1]:5173/` it is
 * the string `[::1]`. The brackets are URL grammar, not part of the name, and
 * every verifier compares the signed `domain` EXACTLY: the platform requires
 * the challenge domain to already be in bare form and compares it to the
 * bracket-stripped redirect host, so `[::1]` is refused outright as
 * non-canonical. Signing the bare form makes the mismatch vanish. Only the IPv6
 * dev host is affected — `localhost` and `127.0.0.1` are already bare.
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

/** A verified sign-in — what the signed-in view and the receipts render. */
interface VerifiedSignIn {
  did: string;
  domain: string;
  timestamp: string;
  kid: string;
  /** The nonce this tab minted and consumed. */
  nonce: string;
}

const errorMessage = (err: unknown): string => (err instanceof Error ? err.message : String(err));

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
 * Only `registered` carries the file's own claims, because only then has the
 * host got something it will actually stand behind at consent.
 */
interface Registration {
  state: 'loopback' | 'registered' | 'unlisted' | 'missing';
  name?: string;
  clientDid?: string;
}

/**
 * One same-origin fetch, best-effort: no retries and no spinner. Every failure
 * mode collapses to `missing`, because from the host's side they are the same
 * fact — this origin does not serve a registration it can check.
 */
const checkRegistration = async (): Promise<Registration> => {
  if (LOOPBACK_HOSTS.has(SIGNING_DOMAIN)) return { state: 'loopback' };

  let parsed: unknown;
  try {
    const response = await fetch(WELL_KNOWN_PATH);
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
 * The verdict, resolved once before anything renders. `null` is only the state
 * before that one fetch settles, and no view runs that early — a page that
 * failed the check has already said so and will not quietly try again.
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
      'This origin serves no registration, so the host has nothing to validate ' +
      'the redirect against and will refuse the sign-in. Add ' +
      `public/.well-known/dfos-app.json with two members: name, and redirect_uris ` +
      `containing this exact string: ${REDIRECT_URI}`
    );
  }
  return undefined;
};

// -----------------------------------------------------------------------------
// dom
// -----------------------------------------------------------------------------

/**
 * Every dynamic string in this demo came from the URL, the API, the JWS, or a
 * served JSON file — all third-party text. It is set with `textContent`, never
 * `innerHTML`.
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
 * What registration IS, written once and rendered twice — under the sign-in
 * button, and again in the receipts. There is no portal screenshot to show and
 * no client secret to redact, which is the whole point: the registration is a
 * file this origin serves, and the reader can open it from here.
 */
const registrationNote = (found: Registration): Node[] => {
  if (found.state === 'loopback') {
    return [
      el(
        'p',
        'dim',
        'This is a loopback host, so this page is registered nowhere and does not ' +
          'need to be: http://localhost is an accepted redirect target for scope=identity ' +
          'under the platform’s loopback tier — the RFC 8252 posture, where a local ' +
          'port cannot be hijacked from off the machine and could not prove a domain ' +
          'if it tried. Deployed to a domain, this app registers itself by serving ' +
          'one JSON file.',
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
        'registration: domain control is the credential, and there is no developer ' +
        'portal and no client secret anywhere in this flow. The host fetches it at ' +
        'authorize time and exact-matches redirect_uris against this page’s redirect ' +
        'target, trailing slash included.',
    ),
  ];

  if (found.name !== undefined) {
    const line = el('p', 'dim');
    line.append(
      'Name shown at consent: ',
      el('code', undefined, found.name),
      ' — the app’s own claim about itself, which the consent screen renders as self-asserted.',
    );
    body.push(line);
  }
  if (found.clientDid !== undefined) {
    const line = el('p', 'dim');
    line.append(
      'Declared client_did: ',
      el('code', undefined, found.clientDid),
      ' — optional at identity scope, and this page does not send it. The file is what names the app.',
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
  button.addEventListener('click', startSignIn);

  const aside = el('p', 'dim');
  aside.append(
    'This site has no secrets, no backend, and no session store — it verifies entirely in your browser, against a public relay. ',
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
      'Sign in to this demo with your DFOS identity. You approve the sign-in on ' +
        'your platform’s consent screen; this page then verifies the signed ' +
        'challenge in your browser against your public identity chain.',
    ),
    ...(notice !== undefined ? [el('p', 'notice', notice)] : []),
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
 */
const checklistReceipt = (verified: VerifiedSignIn): Node[] => {
  const keyId = verified.kid.slice(verified.kid.indexOf('#') + 1);

  const list = el('ul', 'checks');
  for (const line of [
    'Identity chain resolved from the relay and replayed to current state — fresh, not cached (a stale resolution fails closed).',
    `Signing key is a CURRENT authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile (EdDSA, canonical scalar, no embedded key).',
    `Nonce matches the one this page minted, removed from this tab before verifying: ${verified.nonce}`,
    `Domain binding: the signed domain is this site — ${verified.domain}`,
    `Timestamp inside the acceptance window: ${verified.timestamp}`,
  ]) {
    list.append(el('li', undefined, line));
  }

  return receiptSection(
    'What was checked — in this tab',
    list,
    el(
      'p',
      'dim',
      'Verifying here is sound exactly because nothing is granted here. The moment ' +
        'a backend grants something, this same function has to run where the grant ' +
        'happens — and the nonce has to be consumed atomically there. See "When your ' +
        'backend grants anything" in the README.',
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
  const found = registration;
  details.append(
    el('summary', undefined, 'Show the receipts'),
    ...artifactReceipt(jws),
    ...checklistReceipt(verified),
    ...(found !== null
      ? receiptSection('How this app is registered', ...registrationNote(found))
      : []),
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

const startSignIn = (): void => {
  const request: SiwdLoginRequest = createSiwdLoginRequest({
    authorizeUrl: AUTHORIZE_URL,
    domain: SIGNING_DOMAIN,
    redirectUri: REDIRECT_URI,
    scope: 'identity',
    statement: 'Sign in to the SIWD demo',
  });

  // `expect` is the one thing that has to survive the redirect: domain + nonce,
  // which is exactly what `verifySiwd` takes back. The whole "session" is this
  // tab — minted on the click, consumed on the way back, never sent anywhere.
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(request.expect));
  location.href = request.url;
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
  const expect = JSON.parse(saved) as SiwdLoginRequest['expect'];

  renderStatus('Verifying in this tab…');

  // `verifySiwd` is no-throw: the relay hop, the decode, and every check share
  // one result channel, so its own error string is the honest one to show.
  const client = createClient({ relays: [RELAY_URL] });
  const result = await verifySiwd(client, jws, expect);
  if (!result.ok || result.value === undefined) {
    const reason = result.error ?? 'unknown error';
    renderSignedOut(isExpiredReason(reason) ? EXPIRED_NOTICE : `Verification failed: ${reason}`);
    return;
  }

  const { did, domain, timestamp, kid, nonce } = result.value;
  await renderProfile({ did, domain, timestamp, kid, nonce }, jws);
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

const boot = async (): Promise<void> => {
  const callback = readSiwdCallback(location.search);

  // get the JWS out of the address bar, history, and the referrer of anything
  // this page loads next. The kit deliberately does not do this for us:
  // `history` is the environment's, not the library's.
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
  renderSignedOut();
};

void boot();
