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

  THE PAGE SHOWS BEFORE IT EXPLAINS. Signed in with a credential, it reads the
  user's profile from the DFOS API immediately — no button to press — because
  that data is what the sign-in bought, and a demo that hides the payoff behind
  one more click has buried it. The session and the credential sit above it as a
  status bar, the way an app shows who is signed in. Everything mechanical — the
  decoded artifact, the checks the server ran, the signing seam, how this app is
  registered — is still here in full, one disclosure down.

  The JWS is also decoded here, for display. `decodeJwsUnsafe` does no
  verification — the panel says so, and so does the name.

  TWO SCOPES, AND THE PAGE LETS YOU PICK. `identity` proves who you are and
  returns nothing else. `read:profile` also returns a credential, and that one
  difference changes the replay discipline the backend owes, adds a `client_did`
  to the authorize request, and makes a live credential-gated API call possible
  afterwards. Both run side by side so the difference is something you can watch
  rather than read about.

  The authorize request is built server-side in `api/login.ts`. At identity scope
  it carries no `client_did`: the platform learns who this app is by fetching
  `/.well-known/dfos-app.json` from the redirect's own origin, so that file is
  the app identity. At `read:profile` the DID is required as well, because the
  credential has to be issued to a named party.

  That file is the one thing a fork has to get right, so this page checks its
  own at boot and says what it found — on the page, before the click, instead
  of one redirect later at the host.

  WHAT THIS PAGE NEVER HOLDS: the credential, and the key that exercises it. The
  credential arrives in the callback's URL fragment, is handed straight to the
  backend, and is never stored here. A browser cannot hold a signing key safely,
  so the backend holds it and signs — the backend-for-frontend shape
  specs/API-AUTH.md describes.

*/

import { readSiwdCallback } from '@metalabel/dfos-client/siwd';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';

// deployment coordinates — the backend's live in api/_lib.ts
const RELAY_URL = 'https://relay.dfos.com';
const EXPLORER_URL = 'https://explore.dfos.com';

/** Where the source of the files in this flow lives. */
const REPO = 'https://github.com/metalabel/dfos/blob/main';

/**
 * Where the long form lives. This page carries the walkthrough, not the whole
 * argument: the specs say what is required of any implementation, and the kit's
 * README says how the two subpaths this demo uses are meant to be wired.
 */
const DOCS = {
  siwd: 'https://protocol.dfos.com/siwd',
  apiAuth: 'https://protocol.dfos.com/api-auth',
  credentials: 'https://protocol.dfos.com/credentials',
  clientSiwd: `${REPO}/packages/dfos-client/README.md#metalabeldfos-clientsiwd`,
  clientApiAuth: `${REPO}/packages/dfos-client/README.md#metalabeldfos-clientapi-auth`,
  demo: 'https://github.com/metalabel/dfos/tree/main/examples/siwd-demo',
};

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

/** The two scopes, matching `api/_lib.ts`. */
const SCOPE_IDENTITY = 'identity';
const SCOPE_READ_PROFILE = 'read:profile';

/**
 * A credential this app holds, as the server read it out AFTER verifying it.
 * Every field was checked before it got here — signature, schema, CID integrity,
 * expiry, and that this app is the audience.
 */
interface CredentialFacts {
  issuer: string;
  audience: string;
  resource: string;
  action: string;
  issuedAt: number;
  expiresAt: number;
  credentialCID: string;
}

/** A verified sign-in, as the server reads it back out of its own cookie. */
interface Session {
  did: string;
  /** The DID URL of the key that signed the challenge. */
  kid: string;
  /** Issued-at and expiry, unix seconds. */
  iat: number;
  exp: number;
  /** Which scope this sign-in was granted under. */
  scope: string;
  /** Present only when the scope returned one. */
  credential?: CredentialFacts;
}

/** One scope as `/api/config` describes it, verdict included. */
interface ScopeOption {
  scope: string;
  discipline: string;
  available: boolean;
  summary: string;
  /** Why not, when `available` is false. */
  unavailable?: string;
}

/** What this deployment can do, asked once at boot. */
interface Config {
  scopes: ScopeOption[];
  api: { host: string; resource: string; action: string };
  app: { did?: string; publicKeyMultibase?: string };
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
  const { did, kid, iat, exp, scope, credential } = result.body;
  if (typeof did !== 'string' || typeof kid !== 'string') return null;
  if (typeof iat !== 'number' || typeof exp !== 'number') return null;
  if (typeof scope !== 'string') return null;
  return {
    did,
    kid,
    iat,
    exp,
    scope,
    ...(isCredentialFacts(credential) ? { credential } : {}),
  };
};

/** Shape-checked like everything else off the wire, even from our own backend. */
const isCredentialFacts = (value: unknown): value is CredentialFacts => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const raw = value as Record<string, unknown>;
  const strings = ['issuer', 'audience', 'resource', 'action', 'credentialCID'];
  return (
    strings.every((field) => typeof raw[field] === 'string') &&
    typeof raw['issuedAt'] === 'number' &&
    typeof raw['expiresAt'] === 'number'
  );
};

/**
 * What this deployment can do. `null` means the question could not be asked —
 * a backend that did not answer — and the page then offers the identity scope
 * alone rather than guessing at the other one's preconditions.
 */
let config: Config | null = null;

const fetchConfig = async (): Promise<Config | null> => {
  const result = await call('/api/config');
  if (result === null || result.status !== 200) return null;

  const { scopes, api, app } = result.body;
  if (!Array.isArray(scopes)) return null;
  if (typeof api !== 'object' || api === null) return null;
  const apiRaw = api as Record<string, unknown>;
  if (
    typeof apiRaw['host'] !== 'string' ||
    typeof apiRaw['resource'] !== 'string' ||
    typeof apiRaw['action'] !== 'string'
  ) {
    return null;
  }

  const options: ScopeOption[] = [];
  for (const entry of scopes) {
    if (typeof entry !== 'object' || entry === null) continue;
    const raw = entry as Record<string, unknown>;
    if (
      typeof raw['scope'] !== 'string' ||
      typeof raw['discipline'] !== 'string' ||
      typeof raw['available'] !== 'boolean' ||
      typeof raw['summary'] !== 'string'
    ) {
      continue;
    }
    options.push({
      scope: raw['scope'],
      discipline: raw['discipline'],
      available: raw['available'],
      summary: raw['summary'],
      ...(typeof raw['unavailable'] === 'string' ? { unavailable: raw['unavailable'] } : {}),
    });
  }
  if (options.length === 0) return null;

  const appRaw = typeof app === 'object' && app !== null ? (app as Record<string, unknown>) : {};
  return {
    scopes: options,
    api: { host: apiRaw['host'], resource: apiRaw['resource'], action: apiRaw['action'] },
    app: {
      ...(typeof appRaw['did'] === 'string' ? { did: appRaw['did'] } : {}),
      ...(typeof appRaw['publicKeyMultibase'] === 'string'
        ? { publicKeyMultibase: appRaw['publicKeyMultibase'] }
        : {}),
    },
  };
};

/**
 * Which scope the next sign-in will ask for. Sticky across re-renders of the
 * signed-out view so a refused sign-in comes back with the choice still made.
 */
let selectedScope: string = SCOPE_IDENTITY;

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
  /**
   * The app's own signed operation log, as carried in the file. Read here only
   * to count and label it — decoding is not verifying, and the panel says so.
   */
  identityChain?: string[];
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

  const chain = Array.isArray(raw['identity_chain'])
    ? raw['identity_chain'].filter((value): value is string => typeof value === 'string')
    : [];

  return {
    state: 'registered',
    ...(typeof raw['name'] === 'string' ? { name: raw['name'] } : {}),
    ...(typeof raw['client_did'] === 'string' ? { clientDid: raw['client_did'] } : {}),
    ...(chain.length > 0 ? { identityChain: chain } : {}),
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
      `Add public/.well-known/dfos-app.json with its two required members: name, and ` +
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

/** One fact in the status bar. `tone` colors the live ones: a grant, or a dead one. */
const chip = (text: string, tone?: 'ok' | 'warn'): HTMLElement =>
  el('span', tone === undefined ? 'chip' : `chip ${tone}`, text);

/** A row of links on one line, separated the way the footer already is. */
const linkRow = (...items: [string, string][]): HTMLElement => {
  const wrap = el('p', 'links');
  items.forEach(([href, text], index) => {
    if (index > 0) wrap.append(' · ');
    wrap.append(link(href, text));
  });
  return wrap;
};

/** The notices that belong above every view, in the order they matter. */
const notices = (notice?: string): Node[] => [
  ...(notice !== undefined ? [el('p', 'notice', notice)] : []),
  ...(ephemeral ? [el('p', 'notice', EPHEMERAL_NOTICE)] : []),
];

// -----------------------------------------------------------------------------
// this app's own identity
// -----------------------------------------------------------------------------

/**
 * The carried chain, counted and labelled. DECODING IS NOT VERIFYING: these
 * bytes are read with `decodeJwsUnsafe` for display, exactly like the sign-in
 * artifact. What makes the chain real is a host verifying it derives the
 * declared `client_did` — which happens at first consent, not here.
 */
interface ChainSummary {
  ops: number;
  /** The operation types in order, e.g. `create`, `update`. */
  types: string[];
  /** Auth keys in the terminal operation — the keys that can sign as this app today. */
  authKeys: number;
  /** The terminal operation's CID: the head this chain replays to. */
  headCID?: string;
}

const summarizeChain = (chain: string[]): ChainSummary | null => {
  const types: string[] = [];
  let authKeys = 0;
  let headCID: string | undefined;

  for (const token of chain) {
    const decoded = decodeJwsUnsafe(token);
    if (decoded === null) return null;
    const { type } = decoded.payload;
    types.push(typeof type === 'string' ? type : 'unknown');
    const keys = decoded.payload['authKeys'];
    authKeys = Array.isArray(keys) ? keys.length : 0;
    headCID = decoded.header.cid;
  }
  if (types.length === 0) return null;

  return { ops: types.length, types, authKeys, ...(headCID !== undefined ? { headCID } : {}) };
};

/**
 * Who THIS app is, from the file this app serves about itself. The user side of
 * a sign-in gets a DID, a chain, and an explorer to check it in; so does the app
 * side, and this panel is that symmetry made visible rather than asserted.
 */
const appIdentityCard = (found: Registration): HTMLElement => {
  const body: Node[] = [el('h2', undefined, 'This app’s own identity')];

  if (found.state === 'loopback') {
    body.push(
      el(
        'p',
        'dim',
        'This is a loopback host, so this app publishes no registration and needs ' +
          'none: http://localhost is an accepted redirect target for scope=identity ' +
          'under the platform’s loopback tier. Deployed to a domain, the app is ' +
          'whatever its /.well-known/dfos-app.json says it is.',
      ),
    );
    return card(...body);
  }

  if (found.name !== undefined) {
    const line = el('p');
    line.append('Name: ', el('code', undefined, found.name));
    body.push(line);
  }

  if (found.clientDid === undefined) {
    body.push(
      el(
        'p',
        'dim',
        'This origin declares no client_did, so it has no identity of its own to ' +
          'show. That is fine for the identity scope — the served file names the ' +
          'app — but a credential has to be issued to someone, so read:profile ' +
          'needs one.',
      ),
    );
  } else {
    const did = el('p');
    did.append('DID: ', el('code', undefined, found.clientDid));
    body.push(did);
  }

  const summary = found.identityChain === undefined ? null : summarizeChain(found.identityChain);
  if (summary === null) {
    body.push(
      el(
        'p',
        'dim',
        'The file carries no identity_chain. Without it, a host meeting this app ' +
          'for the first time has no way to resolve its key, and a credential-gated ' +
          'API call would have nothing to verify the app’s request proofs against.',
      ),
    );
  } else {
    const line = el('p', 'dim');
    line.append(
      `Carried identity chain: ${summary.ops} signed ${summary.ops === 1 ? 'operation' : 'operations'} (`,
      el('code', undefined, summary.types.join(' → ')),
      `), ${summary.authKeys} current auth ${summary.authKeys === 1 ? 'key' : 'keys'}.`,
    );
    body.push(line);

    if (summary.headCID !== undefined) {
      const head = el('p', 'dim');
      head.append('Head operation: ', el('code', undefined, summary.headCID));
      body.push(head);
    }

    body.push(
      el(
        'p',
        'dim',
        'The chain travels in the file so a host that has never seen this app can ' +
          'verify it derives the declared DID and ingest it at first consent. ' +
          'After that the host’s own API resolves this app’s key like any other ' +
          'resident identity. Counted here for display only — this page does no ' +
          'verifying.',
      ),
    );
  }

  const links: [string, string][] = [[WELL_KNOWN_PATH, 'The served file']];
  if (found.clientDid !== undefined) {
    // NOT encoded: the explorer's hash router takes the DID literally.
    links.push([`${EXPLORER_URL}/#/did/${found.clientDid}`, 'This app in the explorer']);
  }
  links.push([DOCS.siwd, 'SIWD: app registration']);
  body.push(linkRow(...links));

  return card(...body);
};

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

/** The steps this page is about to run, in the order it runs them. */
const whatHappensNext = (scope: string): HTMLElement => {
  const credentialScope = scope === SCOPE_READ_PROFILE;
  const list = el('ol', 'steps');
  for (const step of [
    credentialScope
      ? 'Mint and redirect. This page asks its backend to start a sign-in. The server mints the challenge (domain, nonce, timestamp) and records the nonce in its store so it can be spent exactly once. The URL it answers with carries the app’s client_did, because a credential has to be issued to someone.'
      : 'Mint and redirect. This page asks its backend to start a sign-in. The server mints the challenge (domain, nonce, timestamp), seals the nonce into an httpOnly cookie, and answers with a URL.',
    credentialScope
      ? 'Consent and sign. You approve on your DFOS host’s consent screen, which names what the app is asking to read. Your custodial key signs the challenge bytes and issues the credential — and if the host is meeting this app for the first time, it ingests the identity chain the app carries in its well-known file, so its API can later resolve the app’s key.'
      : 'Consent and sign. You approve on your DFOS host’s consent screen, where your custodial key signs the challenge bytes.',
    credentialScope
      ? 'Come back signed. The browser returns here with the signed JWS in the query string and the credential in the URL fragment, and posts both to this site’s backend.'
      : 'Come back signed. The browser returns here with the signed JWS and posts it to this site’s backend.',
    credentialScope
      ? 'Verify where the grant happens. The server spends the nonce with one atomic delete, verifies the JWS against your public identity chain on a relay, verifies the credential in full, and mints a session cookie.'
      : 'Verify where the grant happens. The server unseals the nonce it minted, verifies the JWS against your public identity chain on a relay, and mints a session cookie.',
    ...(credentialScope
      ? [
          'Use the grant. From then on the backend can call the DFOS API on your behalf — signing each request with its own key and presenting the credential alongside — until the credential expires or you revoke it at your DFOS host.',
        ]
      : []),
  ]) {
    list.append(el('li', undefined, step));
  }
  return list;
};

/**
 * The toggle. Two scopes, each with the replay discipline it obliges, because
 * the discipline is not a preference — specs/SIWD.md decides it from what
 * success grants, and this is the cheapest place to see that happen.
 *
 * A scope this deployment cannot serve is rendered disabled with the reason
 * next to it, rather than hidden: a missing precondition is the most useful
 * thing a fork can be told.
 */
const scopeChooser = (found: Config, onChange: () => void): HTMLElement => {
  const wrap = el('div', 'scopes');
  wrap.append(el('p', 'dim', 'Ask for:'));

  for (const option of found.scopes) {
    const row = el('label', option.available ? 'scope' : 'scope disabled');

    const input = document.createElement('input');
    input.type = 'radio';
    input.name = 'scope';
    input.value = option.scope;
    input.checked = option.scope === selectedScope;
    input.disabled = !option.available;
    input.addEventListener('change', () => {
      selectedScope = option.scope;
      onChange();
    });

    const text = el('span');
    text.append(
      el('code', undefined, option.scope),
      ' — ',
      el('span', undefined, `${option.discipline} replay discipline`),
      el('br'),
      el('span', 'dim', option.summary),
    );
    if (option.unavailable !== undefined) {
      text.append(el('br'), el('span', 'notice', option.unavailable));
    }

    row.append(input, text);
    wrap.append(row);
  }

  // The two strings the credential will carry, shown verbatim: this is what the
  // consent screen will describe, what the credential's attenuation will say,
  // and what the API verifier will byte-match. Three places, one string.
  if (selectedScope === SCOPE_READ_PROFILE) {
    const grant = el('div', 'section');
    const line = el('p', 'dim');
    line.append(
      'The credential will carry exactly one attenuation: resource ',
      el('code', undefined, found.api.resource),
      ', action ',
      el('code', undefined, found.api.action),
      '. That resource string is matched by exact byte equality — there is no wildcard form for an API host — and the action is a registry token, not a pattern.',
    );
    grant.append(line);

    if (found.app.did !== undefined) {
      const audience = el('p', 'dim');
      audience.append(
        'It will be issued to ',
        el('code', undefined, found.app.did),
        ' — this app’s DID, and the only key that can ever exercise it.',
      );
      grant.append(audience);
    }
    wrap.append(grant);
  }

  return wrap;
};

/**
 * What registration is, written once and rendered twice — under the sign-in
 * button, and again in the receipts. It is a file this origin serves, and the
 * reader can open it from here.
 */
const registrationNote = (found: Registration, scope: string): Node[] => {
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
      scope === SCOPE_READ_PROFILE
        ? ' — required for a credential-returning scope, and this flow sends it in the authorize URL. The credential is issued to this DID, and only its key can exercise the grant.'
        : ' — optional at identity scope, and this flow does not send it: the file names the app. (A file that carries identity_chain must name it, whatever the scope.)',
    );
    body.push(line);
  }

  return body;
};

/**
 * The mechanism, one disclosure down. Nothing here was cut when the page was
 * turned around to lead with the demonstration — the steps, the registration
 * note, and the links out are the same content, just no longer standing between
 * the reader and the button.
 */
const walkthrough = (found: Registration | null, scope: string): HTMLElement => {
  const details = el('details');
  details.append(
    el('summary', undefined, 'What happens when you click'),
    whatHappensNext(scope),
    ...(found !== null
      ? receiptSection('How this app is registered', ...registrationNote(found, scope))
      : []),
    ...docsReceipt(),
  );
  return details;
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', () => void startSignIn(selectedScope));

  const aside = el('p', 'dim');
  aside.append(
    'Verification runs on this site’s own backend, against a public relay. No DFOS ' +
      'platform server is asked whether to believe the signature. ',
    link(DOCS.demo, 'This demo site is open source'),
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
    card(
      // Re-rendering the whole view on a scope change is the cheapest way to
      // keep every dependent string — the grant, the walkthrough, the button —
      // in agreement with the choice.
      ...(config !== null ? [scopeChooser(config, () => renderSignedOut(notice))] : []),
      button,
    ),
    walkthrough(found, selectedScope),
    ...(found !== null ? [appIdentityCard(found)] : []),
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
  const consumed = session.scope === SCOPE_READ_PROFILE;

  const list = el('ul', 'checks');
  for (const line of [
    consumed
      ? 'The nonce was spent against the server’s own store — one atomic delete that either found the value this server minted or found nothing. Never from the callback or anything else the presenter could author.'
      : 'The expected nonce came from the server’s own sealed cookie, not from the callback or anything else the presenter could author.',
    'Identity chain resolved fresh from the relay and replayed to current state.',
    `Signing key is a current authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile (EdDSA, canonical scalar, no embedded key).',
    `Domain binding: the signed domain is this site — ${SIGNING_DOMAIN}`,
    'Timestamp inside the acceptance window, checked against the server’s clock.',
    'Nonce checked last, after every other check passed — SIWD’s verification step 6.',
    ...(consumed
      ? [
          'The returned credential verified in full — signature, schema, CID integrity, expiry — and checked to be issued by this signer, audienced to this app, and covering the resource and action that were asked for.',
        ]
      : []),
  ]) {
    list.append(el('li', undefined, line));
  }

  return receiptSection(
    'What the server checked, before it minted this session',
    list,
    el(
      'p',
      'dim',
      consumed
        ? 'This is the consumed replay discipline, and it was not a choice. Success here ' +
            'returned a credential — something portable, redeemable outside this browser — so ' +
            'the SIWD spec (protocol.dfos.com/siwd) requires the nonce be retired globally rather than bound to a ' +
            'channel. The server spent it with one atomic delete, as the last step before ' +
            'granting anything. A second presentation of this same signed challenge, from ' +
            'anywhere, now finds nothing to spend.'
        : 'This is the flow-bound replay discipline. Its guarantee: the signed ' +
            'challenge redeems only through the browser that started the flow, inside ' +
            'the timestamp window. Not global single-use — success here grants a session ' +
            'with this browser and nothing else. Grant anything portable and the ' +
            'discipline changes — see the SIWD spec (protocol.dfos.com/siwd) on replay prevention.',
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

/**
 * THE SIGNING SEAM, shown rather than summarized. This is the composition
 * `api/profile.ts` actually runs: the API client composes a `Request`, and the
 * wrapper signs exactly that request. `@metalabel/dfos-client/api-auth` also
 * ships `createApiAuthFetch`, which is this wrapper as one call — but a backend
 * fronting a browser writes the long form on purpose, because it must authorize
 * the coordinates it is about to sign against its own session rather than sign
 * whatever the page hands it.
 */
const signingSeamReceipt = (host: string): Node[] =>
  receiptSection(
    'How the request was signed',
    el(
      'p',
      'dim',
      `Reading the profile above meant calling GET /v1/profile on ${host} — real ` +
        'private data, served only to a caller that proves possession of the key this ' +
        'credential was issued to. The backend signed a fresh proof over that exact ' +
        'method, host, path, and body, and sent it alongside the credential.',
    ),
    el(
      'pre',
      'wrap',
      `const api = createDfosApi({
  baseUrl: \`https://${host}/v1/\`,
  fetch: async (request) => {
    const url = new URL(request.url);
    const { proof } = await signApiRequest({
      method: request.method,
      host: url.host,
      path: url.pathname + url.search,
      body: new Uint8Array(await request.clone().arrayBuffer()),
      credentialCID,
      kid,
      sign,
    });
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(
      buildApiAuthHeaders({ proof, credential }),
    )) {
      headers.set(name, value);
    }
    return fetch(new Request(request, { headers }));
  },
});

await api.GET('/profile');`,
    ),
    el(
      'p',
      'dim',
      'Two packages meet at that seam and neither had to learn about the other. ' +
        '@metalabel/dfos-api knows the API’s shape, generated from its OpenAPI ' +
        'document; @metalabel/dfos-client knows the byte contract. The client hands ' +
        'the wrapper one fully-composed request, and the wrapper signs the bytes that ' +
        'are about to go on the wire rather than a description of them.',
    ),
    el(
      'p',
      'dim',
      'The endpoint that runs this takes no parameters, and that is the design. A ' +
        'backend that signs whatever method, path, and body a browser hands it is a ' +
        'confused deputy holding a key: an XSS on the page, or simply a hostile ' +
        'client, would obtain proofs for arbitrary requests against every credential ' +
        'the backend holds. POST /api/profile signs one request, and the only thing ' +
        'the caller supplies is a session cookie saying which credential to use.',
    ),
    el(
      'p',
      'dim',
      'No path parameter named you, either. The credential’s root issuer selects the ' +
        'subject, which is why there is no way to ask this endpoint for anybody else.',
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
    linkNote(
      `${REPO}/examples/siwd-demo/api/profile.ts`,
      'examples/siwd-demo/api/profile.ts',
      'The signing seam: one credential-gated call, and nothing the browser gets to name.',
    ),
  );

/** Where the argument is made in full, for a reader who wants more than a panel. */
const docsReceipt = (): Node[] =>
  receiptSection(
    'Where the details live',
    linkNote(
      DOCS.siwd,
      'SIWD',
      'The sign-in protocol: the challenge, the two replay disciplines, registration.',
    ),
    linkNote(
      DOCS.apiAuth,
      'API Authentication',
      'The request proof: what a credential-gated call carries, and the eleven checks it faces.',
    ),
    linkNote(
      DOCS.credentials,
      'Credentials',
      'What a credential is, how it attenuates, and how revocation works.',
    ),
    linkNote(
      DOCS.clientSiwd,
      '@metalabel/dfos-client/siwd',
      'The login kit this page uses, with both replay disciplines written out.',
    ),
    linkNote(
      DOCS.clientApiAuth,
      '@metalabel/dfos-client/api-auth',
      'The signing side, including createApiAuthFetch and why a browser-fronting backend does not use it.',
    ),
    linkNote(
      DOCS.demo,
      'This demo, in full',
      'The README: every route, every variable, and how to fork it.',
    ),
  );

const receipts = (session: Session, jws?: string): HTMLElement => {
  const details = el('details');
  const found = registration;
  const facts = session.credential;
  details.append(
    el('summary', undefined, 'Show the receipts'),
    ...(facts !== undefined ? credentialReceipt(facts) : []),
    ...(facts !== undefined ? signingSeamReceipt(config?.api.host ?? 'the DFOS API') : []),
    ...(jws !== undefined ? artifactReceipt(jws) : []),
    ...checklistReceipt(session),
    ...(found !== null
      ? receiptSection('How this app is registered', ...registrationNote(found, session.scope))
      : []),
    ...lookItUpReceipt(session.did),
    ...sourceReceipt(),
    ...docsReceipt(),
  );
  return details;
};

// -----------------------------------------------------------------------------
// the credential, and exercising it
// -----------------------------------------------------------------------------

/**
 * VERIFY BEFORE TRUST. The credential in full — who issued it, to whom, over
 * what, until when — because a grant you cannot read is a grant you cannot
 * judge. Every field here was verified on the server before the credential was
 * stored and so before anything was ever signed against it: signature, schema,
 * CID integrity, expiry, and that this app is the audience. That ordering is the
 * load-bearing one, not this panel's place on the page. Displaying an unverified
 * grant would teach the opposite habit.
 */
const credentialReceipt = (facts: CredentialFacts): Node[] => {
  const row = (label: string, value: string, note?: string): HTMLElement => {
    const line = el('p', 'dim');
    line.append(`${label}: `, el('code', undefined, value));
    if (note !== undefined) line.append(el('br'), el('span', undefined, note));
    return line;
  };

  const expired = facts.expiresAt * 1000 <= Date.now();

  return receiptSection(
    'The credential you granted',
    row(
      'Issuer',
      facts.issuer,
      'You. And, because this grant has no delegation above it, also the subject whose profile the API will serve — the credential is what selects that, not a path parameter.',
    ),
    row(
      'Audience',
      facts.audience,
      'This app. A credential audienced elsewhere would be unusable here, key or no key.',
    ),
    row(
      'Resource',
      facts.resource,
      'Matched by exact byte equality. There is no wildcard form for an API host.',
    ),
    row(
      'Action',
      facts.action,
      'A registry token, not a pattern. Narrowing a grant means dropping tokens.',
    ),
    row('Issued', new Date(facts.issuedAt * 1000).toLocaleString()),
    row(
      'Expires',
      new Date(facts.expiresAt * 1000).toLocaleString(),
      expired
        ? 'This credential has expired. Expiry is checked at read time, so the API will refuse it.'
        : 'Expiry is generous on purpose; revocation is the timely lever, and the API re-checks it on every request.',
    ),
    row(
      'CID',
      facts.credentialCID,
      'Every request proof names this CID, under its signature. That is what binds one exact request to this one grant.',
    ),
    el(
      'p',
      'dim',
      'Using it does not use it up: the credential is a standing grant, presented request after request until it expires or you revoke it. What is single-use is each request proof, minted fresh per call.',
    ),
    el(
      'p',
      'dim',
      'The credential itself stays on the backend. This page never receives it — and could not ' +
        'use it if it did, since exercising one takes the app’s signing key.',
    ),
  );
};

/** What the last call to the gated endpoint did, if anything. */
type ProfileState =
  | { kind: 'idle' }
  | { kind: 'pending' }
  | { kind: 'ok'; profile: Record<string, unknown>; host: string }
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

/**
 * The profile as the API served it, read defensively. Every member is optional
 * here even though the OpenAPI document says otherwise: this is untrusted text
 * off the wire, and a hero that throws on a missing field is a worse demo than
 * one that renders what it got.
 */
const profileText = (raw: Record<string, unknown>, field: string): string | undefined => {
  const value = raw[field];
  return typeof value === 'string' && value !== '' ? value : undefined;
};

/**
 * THE HERO — the thing the sign-in bought, rendered first and without a button.
 * A relying party's whole reason for running this flow is the data at the end of
 * it, so the page reads it on arrival the way an app would and shows the profile
 * itself rather than an invitation to go fetch one.
 *
 * The raw response stays one disclosure down: this is a protocol demo, and the
 * exact JSON is worth being able to see.
 */
const profileHero = (state: ProfileState, onReload: () => void): HTMLElement => {
  const body: Node[] = [];

  if (state.kind === 'idle' || state.kind === 'pending') {
    body.push(
      el('h2', undefined, 'Reading your profile…'),
      el('p', 'dim', 'The backend is signing a request proof and calling the DFOS API with it.'),
    );
    return card(...body);
  }

  if (state.kind === 'ok') {
    const raw = state.profile;
    const name = profileText(raw, 'displayName');
    const username = profileText(raw, 'username');
    const description = profileText(raw, 'description');
    const email = profileText(raw, 'email');
    const created = profileText(raw, 'createdAt');

    body.push(
      el('h2', undefined, name ?? (username !== undefined ? `@${username}` : 'Your profile')),
    );
    if (name !== undefined && username !== undefined) {
      body.push(el('p', 'handle', `@${username}`));
    }
    if (description !== undefined) body.push(el('p', undefined, description));

    const meta = el('div', 'meta');
    if (email !== undefined) {
      const line = el('p', 'dim');
      line.append('Email ', el('code', undefined, email));
      meta.append(line);
    }
    if (created !== undefined) {
      const joined = new Date(created);
      meta.append(
        el(
          'p',
          'dim',
          Number.isNaN(joined.getTime())
            ? `Joined ${created}`
            : `Joined ${joined.toLocaleDateString()}`,
        ),
      );
    }
    if (meta.childNodes.length > 0) body.push(meta);

    body.push(
      el(
        'p',
        'dim',
        `Served by ${state.host} under the credential below — private data, released only ` +
          'to a caller that proved possession of the key it was issued to.',
      ),
    );

    const rawPanel = el('details');
    rawPanel.append(
      el('summary', undefined, 'The raw response'),
      el('pre', 'wrap', JSON.stringify(raw, null, 2)),
    );
    body.push(rawPanel);

    const again = el('button', 'quiet', 'Read it again');
    again.addEventListener('click', onReload);
    body.push(again);
    body.push(
      el(
        'p',
        'dim',
        'Reading again mints a fresh request proof against the same standing grant. ' +
          'Revoke the grant at your DFOS host and press it once more: the same call ' +
          'answers 403, because the API re-checks revocation on every request.',
      ),
    );
    return card(...body);
  }

  // A refusal or an unreachable backend is the honest hero too: this is what the
  // credential path looks like when the grant is gone or the API cannot answer.
  body.push(el('h2', undefined, 'Your profile did not load'));
  if (state.kind === 'refused') {
    body.push(el('p', 'notice', `The API refused: HTTP ${state.status}`));
    if (state.code !== undefined) {
      const line = el('p', 'dim');
      line.append(
        'Machine-readable code: ',
        el('code', undefined, state.code),
        state.message !== undefined ? ` — ${state.message}` : '',
      );
      body.push(line);
    }
    body.push(el('p', 'dim', state.reason));
  } else {
    body.push(el('p', 'notice', state.reason));
  }

  const retry = el('button', 'quiet', 'Try again');
  retry.addEventListener('click', onReload);
  body.push(retry);
  return card(...body);
};

/** The hero when the sign-in granted no credential: what was proved, and what was not. */
const identityHero = (session: Session): HTMLElement =>
  card(
    el('h2', undefined, 'You are signed in'),
    el(
      'p',
      undefined,
      'This sign-in proved who you are and nothing else. The identity scope returns ' +
        'no credential, so this app holds no standing grant and has nothing to read ' +
        'on your behalf.',
    ),
    el(
      'p',
      'dim',
      `Verified against signing key ${session.kid} — a current authentication key of ` +
        'your identity chain, resolved from a public relay.',
    ),
    el(
      'p',
      'dim',
      'Sign out and sign in again asking for read:profile to see the other half: a ' +
        'credential this app keeps, and a live credential-gated API call made with it.',
    ),
  );

/**
 * The session indicator, the way an application shows one — who is signed in,
 * under what scope, and whether the grant behind it is still good. Everything
 * here is a fact the server read back out of its own sealed cookie.
 */
const sessionBar = (session: Session): HTMLElement => {
  const signOutButton = el('button', 'quiet', 'Sign out');
  signOutButton.addEventListener('click', () => void signOut());

  const who = el('p', 'who');
  who.append(el('span', 'dim', 'Signed in as '), el('code', undefined, session.did));

  const chips = el('div', 'chips');
  chips.append(chip(session.scope));

  const facts = session.credential;
  if (facts === undefined) {
    chips.append(chip('no credential'));
  } else {
    const remaining = facts.expiresAt * 1000 - Date.now();
    const days = Math.floor(remaining / 86_400_000);
    chips.append(
      remaining <= 0
        ? chip('credential expired', 'warn')
        : chip(`credential active · ${days}d left`, 'ok'),
    );
  }

  const body: Node[] = [who, chips];

  if (facts !== undefined) {
    const grant = el('p', 'dim');
    grant.append(
      'Grant: ',
      el('code', undefined, facts.action),
      ' on ',
      el('code', undefined, facts.resource),
      `, expires ${new Date(facts.expiresAt * 1000).toLocaleString()}.`,
    );
    body.push(grant);
  }

  body.push(
    el(
      'p',
      'dim',
      `Session expires ${new Date(session.exp * 1000).toLocaleString()} — read from the ` +
        'server’s sealed session cookie via /api/me.',
    ),
    signOutButton,
  );

  const bar = el('div', 'card session');
  bar.replaceChildren(...body);
  return bar;
};

const renderSignedIn = (
  session: Session,
  jws?: string,
  profile: ProfileState = { kind: 'idle' },
): void => {
  const facts = session.credential;
  const found = registration;

  render(
    ...notices(),
    sessionBar(session),
    facts !== undefined
      ? profileHero(profile, () => void callProfile(session, jws))
      : identityHero(session),
    ...(found !== null ? [appIdentityCard(found)] : []),
    receipts(session, jws),
  );
};

/**
 * Enter the signed-in view. On the credential path the profile call starts
 * immediately — no click — so the payoff is on screen as soon as there is a
 * session to render it from.
 */
const enterSignedIn = (session: Session, jws?: string): void => {
  if (session.credential === undefined) {
    renderSignedIn(session, jws);
    return;
  }
  void callProfile(session, jws);
};

/**
 * Ask the backend to present the credential once. The page sends nothing but the
 * request itself: which credential, which endpoint, and what may be signed are
 * all the server's to decide from the session it already holds.
 */
const callProfile = async (session: Session, jws?: string): Promise<void> => {
  renderSignedIn(session, jws, { kind: 'pending' });

  const result = await call('/api/profile', { method: 'POST', timeoutMs: VERIFY_TIMEOUT_MS });
  if (result === null) {
    renderSignedIn(session, jws, {
      kind: 'unreachable',
      reason: 'The request to this site’s backend did not complete.',
    });
    return;
  }
  if (result.status !== 200) {
    renderSignedIn(session, jws, {
      kind: 'unreachable',
      reason: reasonFrom(result, `this site’s backend answered HTTP ${result.status}`),
    });
    return;
  }

  const body = result.body;
  if (body['ok'] === true && typeof body['profile'] === 'object' && body['profile'] !== null) {
    renderSignedIn(session, jws, {
      kind: 'ok',
      profile: body['profile'] as Record<string, unknown>,
      host: typeof body['host'] === 'string' ? body['host'] : 'the DFOS API',
    });
    return;
  }

  renderSignedIn(session, jws, {
    kind: 'refused',
    status: typeof body['status'] === 'number' ? body['status'] : 0,
    reason: reasonFrom(result, 'the API refused the request'),
    ...(typeof body['code'] === 'string' ? { code: body['code'] } : {}),
    ...(typeof body['message'] === 'string' ? { message: body['message'] } : {}),
  });
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

const startSignIn = async (scope: string): Promise<void> => {
  renderStatus('Starting sign-in…');

  // The server mints the challenge, so the server's clock authors the
  // timestamp — a browser with a skewed clock no longer produces sign-ins that
  // are born stale and refused on the way back. The scope goes with it, because
  // the server is the one that has to owe the matching replay discipline.
  const result = await call('/api/login', { method: 'POST', body: { scope } });
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
 *
 * The credential, when there is one, is forwarded and then forgotten. This page
 * does not keep it and could not use it if it did: exercising one takes the app's
 * signing key, which lives on the backend.
 */
const handleCallback = async (jws: string, credential?: string): Promise<void> => {
  const panel = el('details');
  panel.open = true;
  panel.append(el('summary', undefined, 'What just came back'), ...artifactReceipt(jws));
  renderStatus('Verifying on the server…', panel);

  const result = await call('/api/verify', {
    method: 'POST',
    body: { jws, ...(credential !== undefined ? { credential } : {}) },
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
  enterSignedIn(session, jws);
};

/**
 * The credential rides in the URL FRAGMENT, not the query string. A fragment is
 * never sent to a server, so it lands in no access log, no proxy log, and no
 * `Referer` header — which is why a durable grant is delivered there while the
 * one-shot challenge JWS stays a query parameter.
 *
 * It is read here and handed to the backend, and this page keeps no copy.
 */
const credentialFromFragment = (hash: string): string | undefined => {
  const value = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash).get('credential');
  return value === null || value === '' ? undefined : value;
};

const boot = async (): Promise<void> => {
  const callback = readSiwdCallback(location.search);
  const credential = credentialFromFragment(location.hash);

  // get the JWS and the credential out of the address bar, history, and the
  // referrer of anything this page loads next. The kit deliberately leaves this
  // to us: `history` belongs to the environment, not the library. Replacing with
  // the bare path drops the query and the fragment together.
  if (callback.kind !== 'none' || credential !== undefined) {
    history.replaceState(null, '', location.pathname);
  }

  // Both settled before the first render, so no view has to handle a half-known
  // registration or an unknown scope list, and no view triggers a second fetch.
  [registration, config] = await Promise.all([checkRegistration(), fetchConfig()]);

  if (callback.kind === 'denied') {
    renderSignedOut(
      isExpiredReason(callback.error)
        ? EXPIRED_NOTICE
        : `Sign-in was denied or failed at the platform: ${callback.error}`,
    );
    return;
  }
  if (callback.kind === 'success') {
    // Keep the chooser on the scope this callback belongs to, so a refused
    // credential sign-in offers a retry of the same thing rather than silently
    // dropping back to identity.
    if (credential !== undefined) selectedScope = SCOPE_READ_PROFILE;
    await handleCallback(callback.jws, credential);
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
  enterSignedIn(session);
};

void boot();
