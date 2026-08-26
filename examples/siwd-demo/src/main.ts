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

  THE PAGE SHOWS BEFORE IT EXPLAINS, and it explains less than it used to. The
  demo demonstrates; the spec explains. Signed in with a credential, this page
  reads the user's profile, the spaces and groups they belong to, and the
  credential's own description from the DFOS API immediately — four calls, no
  button to press — because that data is what the sign-in bought. Status sits
  under it, this app's own identity below that, and everything mechanical is one
  disclosure down.

  Where the reader wants the protocol argument — replay prevention, the byte
  contracts, the verification algorithm — the receipts link out to the specs
  rather than restating them here. A demo that teaches the spec inline goes stale
  the moment the spec moves, and it buries the thing it was built to show.

  TWO OPTIONS. `identity` proves who you are and returns nothing else. The other
  is a SCOPE SET — `read:profile read:email read:memberships`, space-separated
  per the OAuth convention SIWD adopts — which additionally returns one
  credential carrying all three action tokens. The consent screen names every
  token in the set.

  The authorize request is built server-side in `api/login.ts`. At identity scope
  it carries no `client_did`: the platform learns who this app is by fetching
  `/.well-known/dfos-app.json` from the redirect's own origin, so that file is
  the app identity. On the credential set the DID is required as well, because a
  credential has to be issued to a named party.

  That file is the one thing a fork has to get right, so this page checks its
  own at boot and says what it found — on the page, before the click, instead
  of one redirect later at the host.

  WHAT THIS PAGE NEVER HOLDS: the credential, and the key that exercises it. The
  credential arrives in the callback's URL fragment, is handed straight to the
  backend, and is never stored here. A browser cannot hold a signing key safely,
  so the backend holds it and signs — the backend-for-frontend shape
  specs/API-AUTH.md describes.

  The JWS is decoded here for display only. `decodeJwsUnsafe` does no
  verification — the panel says so, and so does the name.

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
  replayPrevention: 'https://protocol.dfos.com/siwd#replay-prevention',
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

/**
 * The two options, matching `api/_lib.ts`. The second is a space-separated
 * scope SET, and all three of its tokens land in one credential.
 */
const SCOPE_IDENTITY = 'identity';
const SCOPE_API = 'read:profile read:email read:memberships';

/**
 * A credential this app holds, as the server read it out AFTER verifying it.
 * Every field was checked before it got here — signature, schema, CID integrity,
 * expiry, and that this app is the audience.
 */
interface CredentialFacts {
  issuer: string;
  audience: string;
  resource: string;
  /** The action list, comma-joined — the form the credential's own machinery matches. */
  action: string;
  issuedAt: number;
  expiresAt: number;
  credentialCID: string;
}

/** The action list as separate tokens, for display. */
const actionTokens = (facts: CredentialFacts): string[] =>
  facts.action
    .split(',')
    .map((token) => token.trim())
    .filter((token) => token !== '');

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

/** One option as `/api/config` describes it, verdict included. */
interface ScopeOption {
  scope: string;
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
 * One shape for every endpoint here. `null` means the request never completed —
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
      typeof raw['available'] !== 'boolean' ||
      typeof raw['summary'] !== 'string'
    ) {
      continue;
    }
    options.push({
      scope: raw['scope'],
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
 *   loopback    — dev run; no file is needed and none is looked for.
 *   registered  — the file parsed and lists this page's exact redirect target.
 *   unlisted    — the file parsed but that exact string is not in it.
 *   missing     — the origin answered, and there is no usable file to read.
 *   unreachable — the request did not complete. NOTHING was learned.
 *
 * `missing` and `unreachable` are kept apart on purpose. Collapsing them lets
 * the page report an absence it never established — "this app declares no
 * identity" when the truth was "this page could not ask". A failed request is
 * not evidence about the file's contents, and this page does not get to say
 * otherwise.
 *
 * A parsed file carries its claims under BOTH `registered` and `unlisted`. What
 * the file declares about the app — its name, its DID, the chain it carries —
 * is a fact about the file; whether THIS origin may redirect here is a separate
 * question with a separate answer. Reading only one of them off a `registered`
 * verdict is what made a preview deployment, whose origin is deliberately not in
 * the production allowlist, render as an app with no identity at all.
 */
interface Registration {
  state: 'loopback' | 'registered' | 'unlisted' | 'missing' | 'unreachable';
  name?: string;
  clientDid?: string;
  /**
   * The app's own signed operation log, as carried in the file. Read here only
   * to count and label it — decoding is not verifying, and the panel says so.
   */
  identityChain?: string[];
}

/**
 * One same-origin fetch, best-effort: no retries and no spinner. Bounded because
 * boot awaits this before the first render and a browser fetch has no timeout of
 * its own: a stalled request (a misbehaving service worker, a proxy) must
 * degrade rather than hold the page, and the callback verification behind it,
 * hostage. It degrades to `unreachable`, which claims nothing.
 */
const checkRegistration = async (): Promise<Registration> => {
  if (LOOPBACK_HOSTS.has(SIGNING_DOMAIN)) return { state: 'loopback' };

  let response: Response;
  try {
    response = await fetch(WELL_KNOWN_PATH, { signal: AbortSignal.timeout(3000) });
  } catch {
    // Offline, aborted, timed out. We asked and got no answer, which is not the
    // same as asking and being told there is nothing.
    return { state: 'unreachable' };
  }

  // A 404 is the origin answering definitively: there is no file here. Any other
  // failure status is the origin failing to answer, which settles nothing.
  if (response.status === 404) return { state: 'missing' };
  if (!response.ok) return { state: 'unreachable' };

  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    return { state: 'missing' };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { state: 'missing' };
  }

  const raw = parsed as Record<string, unknown>;
  const chain = Array.isArray(raw['identity_chain'])
    ? raw['identity_chain'].filter((value): value is string => typeof value === 'string')
    : [];

  // Read off the parsed file, before the allowlist question is asked, because
  // these are answers to a different question than that one.
  const claims = {
    ...(typeof raw['name'] === 'string' ? { name: raw['name'] } : {}),
    ...(typeof raw['client_did'] === 'string' ? { clientDid: raw['client_did'] } : {}),
    ...(chain.length > 0 ? { identityChain: chain } : {}),
  };

  const listed = Array.isArray(raw['redirect_uris'])
    ? raw['redirect_uris'].filter((value): value is string => typeof value === 'string')
    : [];
  if (!listed.includes(REDIRECT_URI)) return { state: 'unlisted', ...claims };

  return { state: 'registered', ...claims };
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
  if (found.state === 'unreachable') {
    return (
      'This page could not fetch its own registration, so it cannot tell you ' +
      'whether the sign-in will be accepted. The file may be fine and the request ' +
      `may simply have failed. Open ${WELL_KNOWN_PATH} and check that redirect_uris ` +
      `contains this exact string: ${REDIRECT_URI}`
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

/**
 * A DID inline, in the page's small-mono style and linked to the explorer, so
 * every identity the page names comes with a second verifier to check it in.
 * NOT encoded: the explorer's hash router takes the DID literally.
 */
const didLink = (did: string): HTMLAnchorElement => {
  const anchor = link(`${EXPLORER_URL}/#/did/${did}`, '');
  anchor.append(el('code', undefined, did));
  return anchor;
};

/** An object off the wire, or not. Nothing here trusts a shape it did not check. */
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** One fact in the status bar. `tone` colors the live ones: a grant, or a dead one. */
const chip = (text: string, tone?: 'ok' | 'warn'): HTMLElement =>
  el('span', tone === undefined ? 'chip' : `chip ${tone}`, text);

/** One entry in a link list: where it goes, what it is called, and optionally why. */
type LinkItem = [href: string, text: string, note?: string];

/**
 * A scannable list of links. Every place this page hands the reader somewhere
 * else — the explorer, the raw JSON, the served file, the specs — uses this one
 * shape, so the links read as a list to run down rather than as prose to mine.
 */
const linkList = (...items: LinkItem[]): HTMLElement => {
  const list = el('ul', 'linklist');
  for (const [href, text, note] of items) {
    const row = el('li');
    row.append(link(href, text));
    if (note !== undefined) row.append(el('span', 'dim', ` — ${note}`));
    list.append(row);
  }
  return list;
};

/**
 * One label/value pair in a fact list. A value may carry a short trailing note.
 * A plain string renders in the page's small-mono style; a node renders as it
 * is, which is how a DID in a fact list gets its explorer link.
 */
type Fact = [label: string, value: string | Node, note?: string];

/**
 * A compact label/value block. This replaces the paragraph-per-field annotation
 * the page used to carry: the value is the point, and where a field genuinely
 * needs a caveat it gets a clause, not an essay.
 */
const factList = (...facts: Fact[]): HTMLElement => {
  const list = el('dl', 'facts');
  for (const [label, value, note] of facts) {
    list.append(el('dt', undefined, label));
    const dd = el('dd');
    dd.append(typeof value === 'string' ? el('code', undefined, value) : value);
    if (note !== undefined) dd.append(el('span', 'dim', ` ${note}`));
    list.append(dd);
  }
  return list;
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
 *
 * The panel reports only what it actually read. "This page could not load the
 * file" and "the file declares nothing" are different sentences, and saying the
 * second when the first is true would be the page inventing evidence about its
 * own app — the precise habit the receipts elsewhere on this page exist to
 * discourage.
 */
const appIdentityCard = (found: Registration): HTMLElement => {
  const heading = el('h2', undefined, 'This app');
  const wrap = el('div', 'card quiet');

  if (found.state === 'loopback') {
    wrap.replaceChildren(
      heading,
      el(
        'p',
        'dim',
        'Loopback host — this app publishes no registration and needs none. ' +
          'Deployed to a domain, it is whatever its dfos-app.json says it is.',
      ),
    );
    return wrap;
  }

  if (found.state === 'unreachable') {
    wrap.replaceChildren(
      heading,
      el(
        'p',
        'notice',
        'Could not load this app’s registration file. That is a request that ' +
          'failed, not a file that is empty.',
      ),
      linkList([WELL_KNOWN_PATH, 'dfos-app.json', 'try it directly']),
    );
    return wrap;
  }

  if (found.state === 'missing') {
    wrap.replaceChildren(
      heading,
      el(
        'p',
        'notice',
        'This origin serves no dfos-app.json, so this app declares no identity. ' +
          'A host asked to consent to it has nothing to fetch.',
      ),
      linkList([DOCS.siwd, 'SIWD', 'how an app registers']),
    );
    return wrap;
  }

  const body: Node[] = [heading];

  if (found.state === 'unlisted') {
    body.push(
      el(
        'p',
        'notice',
        'This origin is not in the file’s redirect_uris, so a sign-in started ' +
          'here will be refused. What the file declares is below, unaffected.',
      ),
    );
  }

  const facts: Fact[] = [];
  if (found.name !== undefined) facts.push(['Name', found.name, '(self-asserted)']);
  if (found.clientDid !== undefined) facts.push(['DID', found.clientDid]);

  // Three outcomes, kept apart for the same reason the fetch states are: a chain
  // this page failed to decode is not a chain the file failed to carry.
  const carried = found.identityChain;
  const summary = carried === undefined ? null : summarizeChain(carried);
  if (summary !== null) {
    facts.push([
      'Chain',
      `${summary.ops} ${summary.ops === 1 ? 'op' : 'ops'} (${summary.types.join(' → ')})`,
      `${summary.authKeys} current auth ${summary.authKeys === 1 ? 'key' : 'keys'}`,
    ]);
    if (summary.headCID !== undefined) facts.push(['Head', summary.headCID]);
  }
  if (facts.length > 0) body.push(factList(...facts));

  if (found.clientDid === undefined) {
    body.push(el('p', 'dim', 'The file declares no client_did, so this app has no DID to show.'));
  }
  if (carried === undefined) {
    body.push(
      el(
        'p',
        'dim',
        'The file carries no identity_chain, so a host meeting this app for the ' +
          'first time cannot resolve its key.',
      ),
    );
  } else if (summary === null) {
    body.push(
      el(
        'p',
        'dim',
        `The file carries an identity_chain of ${carried.length} ${carried.length === 1 ? 'entry' : 'entries'}, ` +
          'which this page could not decode to summarize. Open the file and look.',
      ),
    );
  } else {
    body.push(el('p', 'dim', 'Read off the served file. Decoding is not verifying.'));
  }

  const links: LinkItem[] = [[WELL_KNOWN_PATH, 'dfos-app.json', 'the file a host fetches']];
  if (found.clientDid !== undefined) {
    // NOT encoded: the explorer's hash router takes the DID literally.
    links.push([
      `${EXPLORER_URL}/#/did/${found.clientDid}`,
      'This app in the explorer',
      'verify the chain yourself',
    ]);
  }
  body.push(linkList(...links));

  wrap.replaceChildren(...body);
  return wrap;
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

/** The steps this page runs, in order. Short on purpose: the specs explain. */
const whatHappensNext = (scope: string): HTMLElement => {
  const credentialScope = scope === SCOPE_API;
  const list = el('ol', 'steps');
  for (const step of [
    'This page asks its backend to start a sign-in. The server mints the challenge and answers with a URL.',
    credentialScope
      ? 'You approve at your DFOS host. The consent screen names each scope you are being asked for, one line per token, and your key signs the challenge.'
      : 'You approve at your DFOS host, and your key signs the challenge.',
    credentialScope
      ? 'The browser comes back with the signed challenge and the credential, and hands both to this site’s backend.'
      : 'The browser comes back with the signed challenge and hands it to this site’s backend.',
    credentialScope
      ? 'The backend verifies the signature against your identity chain on a public relay, verifies the credential, and grants a session.'
      : 'The backend verifies the signature against your identity chain on a public relay and grants a session.',
    ...(credentialScope
      ? [
          'The backend reads your profile, your spaces and groups, and the credential’s own description from the DFOS API, signing each request with its own key and presenting the same credential alongside it.',
        ]
      : []),
  ]) {
    list.append(el('li', undefined, step));
  }
  return list;
};

/**
 * The toggle. A scope this deployment cannot serve is rendered disabled with the
 * reason next to it, rather than hidden: a missing precondition is the most
 * useful thing a fork can be told.
 */
const scopeChooser = (found: Config, onChange: () => void): HTMLElement => {
  const wrap = el('div', 'scopes');

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
    text.append(el('code', undefined, option.scope), el('br'), el('span', 'dim', option.summary));
    if (option.unavailable !== undefined) {
      text.append(el('br'), el('span', 'notice', option.unavailable));
    }

    row.append(input, text);
    wrap.append(row);
  }

  return wrap;
};

/**
 * What registration is, said once. The file this origin serves IS the
 * registration — there is no portal and no client secret.
 */
const registrationNote = (found: Registration, scope: string): Node[] => {
  if (found.state === 'loopback') {
    return [
      el(
        'p',
        'dim',
        'Loopback host: http://localhost is an accepted redirect target for ' +
          'scope=identity, so nothing is registered anywhere. Deployed to a domain, ' +
          'an app registers itself by serving one JSON file.',
      ),
    ];
  }

  const body: Node[] = [
    el(
      'p',
      'dim',
      'Serving dfos-app.json over https from the domain you control IS the ' +
        'registration: domain control is the credential. The host fetches it at ' +
        'authorize time and exact-matches redirect_uris against this page’s ' +
        'redirect target, trailing slash included.',
    ),
  ];

  if (found.clientDid !== undefined) {
    body.push(
      el(
        'p',
        'dim',
        scope === SCOPE_API
          ? 'client_did is required here: the credential is issued to that DID, and only its key can exercise the grant.'
          : 'client_did is optional at identity scope and this flow does not send it. (A file carrying identity_chain must name it either way.)',
      ),
    );
  }

  return body;
};

/**
 * The mechanism, one disclosure down. The steps and the registration note live
 * here so the sign-in card can lead.
 */
const walkthrough = (found: Registration | null, scope: string): HTMLElement => {
  const details = el('details');
  details.append(
    el('summary', undefined, 'How it works'),
    whatHappensNext(scope),
    ...(found !== null ? registrationNote(found, scope) : []),
    linkList(
      [DOCS.siwd, 'SIWD', 'the sign-in protocol'],
      [DOCS.apiAuth, 'API-AUTH', 'the request proof'],
      [DOCS.demo, 'This demo’s source', 'every route and variable'],
    ),
  );
  return details;
};

const renderSignedOut = (notice?: string): void => {
  const button = el('button', undefined, 'Sign in with DFOS');
  button.addEventListener('click', () => void startSignIn(selectedScope));

  const found = registration;
  const warning = found === null ? undefined : registrationNotice(found);

  render(
    el('h1', undefined, 'Sign In With DFOS'),
    el(
      'p',
      'lede',
      'Sign in with your DFOS identity. You approve at your own platform; this ' +
        'site’s backend verifies the signed challenge against your public identity ' +
        'chain before granting a session.',
    ),
    ...notices(notice),
    ...(warning !== undefined ? [el('p', 'notice', warning)] : []),
    card(
      // Re-rendering the whole view on a scope change keeps every dependent
      // string in agreement with the choice.
      ...(config !== null ? [scopeChooser(config, () => renderSignedOut(notice))] : []),
      button,
    ),
    walkthrough(found, selectedScope),
    ...(found !== null ? [appIdentityCard(found)] : []),
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
 * signature unchecked. What makes this one a sign-in is that `/api/verify`
 * checked it — on the server, not here.
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
    el('p', 'dim', 'Payload — the canonical challenge the signature covers'),
    el('pre', 'wrap', JSON.stringify(decoded.payload, null, 2)),
  );
  return receiptSection('The signed artifact', ...body);
};

/**
 * One line per check the server ran before it minted the session. Rendered FROM
 * the granted session — the checks happened in `api/verify.ts`, and re-running
 * them here would prove nothing.
 */
const checklistReceipt = (session: Session): Node[] => {
  const keyId = session.kid.slice(session.kid.indexOf('#') + 1);

  const list = el('ul', 'checks');
  for (const line of [
    'Identity chain resolved fresh from a public relay and replayed to current state.',
    `Signing key is a current authentication key of a non-deleted identity: ${keyId}`,
    'Signature valid under the DFOS JWS profile.',
    `Domain binding: the signed domain is this site — ${SIGNING_DOMAIN}`,
    'Timestamp inside the acceptance window, on the server’s clock.',
    'Replay check passed, last.',
    ...(session.credential !== undefined
      ? [
          'Credential verified in full, and checked to be issued by this signer, audienced to this app, and covering the actions asked for.',
        ]
      : []),
  ]) {
    list.append(el('li', undefined, line));
  }

  return receiptSection('What the server checked', list);
};

/**
 * THE SIGNING SEAM. This is the composition `api/profile.ts` runs: the API
 * client composes a `Request`, and the wrapper signs exactly that request.
 */
const signingSeamReceipt = (host: string): Node[] =>
  receiptSection(
    'How the request was signed',
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
      'Every gated call on this page rides that seam, one credential under three ' +
        'tokens: the profile, both membership walks, the credential’s own ' +
        'description, and the single membership checks — each backend route signing ' +
        'its own fixed request. The check route is the one place a value from the ' +
        'browser reaches the coordinates, and it is confined to a single validated ' +
        'path segment of a fixed template.',
    ),
    el(
      'p',
      'dim',
      'Two packages meet at that seam. @metalabel/dfos-api composes the request; ' +
        '@metalabel/dfos-client signs the bytes that are about to go on the wire. ' +
        'The kit also ships createApiAuthFetch, which is this wrapper in one call — ' +
        'the long form is here because a backend fronting a browser must authorize ' +
        'the coordinates it signs against its own session, so it never signs a ' +
        'request a browser composed.',
    ),
  );

/** Everything the reader can go check, in one list. */
const receiptLinks = (session: Session): Node[] =>
  receiptSection(
    'Check it yourself',
    linkList(
      [
        `${RELAY_URL}/proof/v1/identities/${encodeURIComponent(session.did)}/log`,
        'Your signed operation log',
        'raw JSON from the relay',
      ],
      // NOT encoded: the explorer's hash router takes the DID literally.
      [`${EXPLORER_URL}/#/did/${session.did}`, 'Your chain in the explorer', 'a second verifier'],
      [WELL_KNOWN_PATH, 'This app’s dfos-app.json', 'raw JSON, as a host fetches it'],
    ),
  );

/** Where the protocol is specified, and where this demo's code lives. */
const docsReceipt = (): Node[] =>
  receiptSection(
    'Read more',
    linkList(
      [DOCS.siwd, 'SIWD', 'the sign-in protocol'],
      [DOCS.replayPrevention, 'SIWD: replay prevention', 'why the nonce is handled the way it is'],
      [DOCS.apiAuth, 'API-AUTH', 'the request proof and its verification'],
      [DOCS.credentials, 'Credentials', 'attenuation, action sets, revocation'],
      [DOCS.clientSiwd, '@metalabel/dfos-client/siwd', 'the login kit'],
      [DOCS.clientApiAuth, '@metalabel/dfos-client/api-auth', 'the signing side'],
    ),
    linkList(
      [`${REPO}/examples/siwd-demo/api/verify.ts`, 'api/verify.ts', 'where the session is granted'],
      [`${REPO}/examples/siwd-demo/api/profile.ts`, 'api/profile.ts', 'the signing seam'],
      [`${REPO}/examples/siwd-demo/api/_gated.ts`, 'api/_gated.ts', 'the signing seam, factored'],
      [
        `${REPO}/examples/siwd-demo/api/memberships.ts`,
        'api/memberships.ts',
        'the membership walks',
      ],
      [`${REPO}/examples/siwd-demo/api/check.ts`, 'api/check.ts', 'the one parameterized request'],
      [`${REPO}/examples/siwd-demo/src/main.ts`, 'src/main.ts', 'this page'],
      [DOCS.demo, 'The demo README', 'routes, variables, forking'],
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
    ...receiptLinks(session),
    ...docsReceipt(),
  );
  return details;
};

// -----------------------------------------------------------------------------
// the credential, and exercising it
// -----------------------------------------------------------------------------

/**
 * VERIFY BEFORE TRUST. Every field here was verified on the server before the
 * credential was stored, and so before anything was ever signed against it —
 * signature, schema, CID integrity, expiry, audience. That ordering is the
 * load-bearing one, not this panel's place on the page.
 */
const credentialReceipt = (facts: CredentialFacts): Node[] => {
  const tokens = actionTokens(facts);
  const expired = facts.expiresAt * 1000 <= Date.now();

  return receiptSection(
    'The credential you granted',
    factList(
      ['Issuer', facts.issuer, '(you — and the subject the API serves)'],
      ['Audience', facts.audience, '(this app, and only this app)'],
      ['Resource', facts.resource],
      [tokens.length === 1 ? 'Action' : 'Actions', tokens.join(', ')],
      ['Issued', new Date(facts.issuedAt * 1000).toLocaleString()],
      [
        'Expires',
        new Date(facts.expiresAt * 1000).toLocaleString(),
        expired ? '(expired)' : undefined,
      ],
      ['CID', facts.credentialCID, '(named in every request proof)'],
    ),
    el(
      'p',
      'dim',
      tokens.length > 1
        ? 'Every action token rides in one credential, not one credential each — so ' +
            'revoking it severs the whole API grant at once. Using it does not use it ' +
            'up; what is single-use is each request proof.'
        : 'Using it does not use it up: the credential is a standing grant. What is ' +
            'single-use is each request proof, minted fresh per call.',
    ),
    el(
      'p',
      'dim',
      'The credential stays on the backend. This page never receives it, and could ' +
        'not use it if it did.',
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
 * A response member as the API served it, read defensively. Every member is
 * optional here even though the OpenAPI document says otherwise: this is
 * untrusted text off the wire, and a view that throws on a missing field is a
 * worse demo than one that renders what it got.
 */
const textField = (raw: Record<string, unknown>, field: string): string | undefined => {
  const value = raw[field];
  return typeof value === 'string' && value !== '' ? value : undefined;
};

/** The same tolerance for a nested object: the member, or `null`. */
const objectField = (
  raw: Record<string, unknown>,
  field: string,
): Record<string, unknown> | null => {
  const value = raw[field];
  return isRecord(value) ? value : null;
};

/** The same tolerance for a list: the member, or nothing to iterate. */
const arrayField = (raw: Record<string, unknown>, field: string): unknown[] => {
  const value = raw[field];
  return Array.isArray(value) ? value : [];
};

/** The same tolerance for a count. `Infinity` is a "number" and is not one. */
const numberField = (raw: Record<string, unknown>, field: string): number | undefined => {
  const value = raw[field];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
};

/**
 * An ISO timestamp off the wire, as a local date — or the raw string when it
 * will not parse. The hero does the same with `createdAt`: a field this page
 * could not read is still a field the API served, and showing it is more honest
 * than dropping it or printing `Invalid Date`.
 */
const dateText = (raw: Record<string, unknown>, field: string): string | undefined => {
  const value = textField(raw, field);
  if (value === undefined) return undefined;
  const when = new Date(value);
  return Number.isNaN(when.getTime()) ? value : when.toLocaleDateString();
};

/** The same, to the minute — for the credential's own issued and expires stamps. */
const stampText = (raw: Record<string, unknown>, field: string): string | undefined => {
  const value = textField(raw, field);
  if (value === undefined) return undefined;
  const when = new Date(value);
  return Number.isNaN(when.getTime()) ? value : when.toLocaleString();
};

/**
 * The two ways a gated read fails, worded the same wherever it is rendered. A
 * refusal is a verdict the API reached and gets its status and envelope; an
 * unreachable backend reached no verdict at all, and gets one line saying so.
 */
type ReadFailure =
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

const failureLines = (state: ReadFailure): Node[] => {
  if (state.kind === 'unreachable') return [el('p', 'notice', state.reason)];

  const lines: Node[] = [el('p', 'notice', `The API refused: HTTP ${state.status}`)];
  if (state.code !== undefined) {
    const line = el('p', 'dim');
    line.append(
      el('code', undefined, state.code),
      state.message !== undefined ? ` — ${state.message}` : '',
    );
    lines.push(line);
  }
  lines.push(el('p', 'dim', state.reason));
  return lines;
};

/**
 * THE HERO — the thing the sign-in bought, rendered first and without a button.
 * The raw response stays one disclosure down: this is a protocol demo, and the
 * exact JSON is worth being able to see.
 */
const profileHero = (state: ProfileState, onReload: () => void): HTMLElement => {
  const hero = el('div', 'card hero');

  if (state.kind === 'idle' || state.kind === 'pending') {
    hero.replaceChildren(el('h2', undefined, 'Reading your profile…'));
    return hero;
  }

  if (state.kind === 'ok') {
    const raw = state.profile;
    const name = textField(raw, 'displayName');
    const username = textField(raw, 'username');
    const description = textField(raw, 'description');
    const email = textField(raw, 'email');
    const created = textField(raw, 'createdAt');

    const identity: Node[] = [
      el('h2', undefined, name ?? (username !== undefined ? `@${username}` : 'Your profile')),
    ];
    if (name !== undefined && username !== undefined) {
      identity.push(el('p', 'handle', `@${username}`));
    }

    // `read:profile` is what puts the avatar here, alongside the name. It is a
    // resolved public CDN URL, not a signed one, so it is an ordinary <img> —
    // and decorative, since the name it sits next to already says who this is.
    const body: Node[] = [];
    const image = avatarImage(textField(raw, 'avatarUrl'));
    if (image === null) {
      body.push(...identity);
    } else {
      const names = el('div');
      names.append(...identity);
      const idrow = el('div', 'idrow');
      idrow.append(image, names);
      body.push(idrow);
    }

    if (description !== undefined) body.push(el('p', 'bio', description));

    // `read:email` is what puts this here. Without that token in the set the API
    // serves the profile without it, and the row simply does not appear.
    const meta = el('div', 'meta');
    if (email !== undefined) {
      const line = el('p');
      line.append(el('span', 'dim', 'Email '), el('code', undefined, email));
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

    const rawPanel = el('details', 'rawjson');
    rawPanel.append(
      el('summary', undefined, 'Raw response'),
      el('pre', 'wrap', JSON.stringify(raw, null, 2)),
    );
    body.push(rawPanel);

    const again = el('button', 'quiet', 'Read it again');
    again.addEventListener('click', onReload);
    body.push(again);

    hero.replaceChildren(...body);
    return hero;
  }

  // A refusal or an unreachable backend is the honest hero too: this is what the
  // credential path looks like when the grant is gone or the API cannot answer.
  const body: Node[] = [el('h2', undefined, 'Your profile did not load'), ...failureLines(state)];

  const retry = el('button', 'quiet', 'Try again');
  retry.addEventListener('click', onReload);
  body.push(retry);
  hero.replaceChildren(...body);
  return hero;
};

/** What the last call to the memberships endpoint did, if anything. */
type MembershipsState =
  | { kind: 'idle' }
  | { kind: 'pending' }
  | { kind: 'ok'; memberships: Record<string, unknown>; host: string }
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

/**
 * The same, for the second walk. The API serves the membership graph as TWO
 * flat pages rather than one nested one — the spaces here, the groups there,
 * each group carrying the id of the space it belongs to — so the two calls move
 * independently and the section renders from both.
 */
type GroupMembershipsState =
  | { kind: 'idle' }
  | { kind: 'pending' }
  | { kind: 'ok'; groupMemberships: Record<string, unknown>; host: string }
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

/** And for the credential's own description of itself. */
type CredentialState =
  | { kind: 'idle' }
  | { kind: 'pending' }
  | { kind: 'ok'; credential: Record<string, unknown>; host: string }
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

/**
 * A group's `color` is a named palette TOKEN, not a CSS value: the API names a
 * color and the client decides what that looks like. A token this page does not
 * know renders with no dot rather than with a guess.
 */
const GROUP_COLORS: Record<string, string> = {
  red: '#ef4444',
  orange: '#f97316',
  amber: '#f59e0b',
  yellow: '#eab308',
  lime: '#84cc16',
  green: '#22c55e',
  emerald: '#10b981',
  teal: '#14b8a6',
  cyan: '#06b6d4',
  sky: '#0ea5e9',
  blue: '#3b82f6',
  indigo: '#6366f1',
  violet: '#8b5cf6',
  purple: '#a855f7',
  fuchsia: '#d946ef',
  pink: '#ec4899',
  rose: '#f43f5e',
};

/** A resolved avatar URL, when there is one. Decorative, so the alt text is empty. */
const avatarImage = (url: string | undefined): HTMLImageElement | null => {
  if (url === undefined || !url.startsWith('https://')) return null;
  const image = el('img', 'avatar');
  image.src = url;
  image.alt = '';
  return image;
};

/**
 * One group membership: the dot, the name, the role, the counts, and the DID.
 * The entry is a row off the group walk — `{ group, role, joinedAt }` — so the
 * group's own fields and this user's relationship to it are read from two
 * different objects.
 */
const groupRow = (entry: Record<string, unknown>): HTMLElement => {
  const row = el('li');
  const group = objectField(entry, 'group') ?? {};
  const name = el('p', 'name');

  const token = textField(group, 'color');
  const color = token === undefined ? undefined : GROUP_COLORS[token];
  if (color !== undefined) {
    const dot = el('span', 'dot');
    dot.style.background = color;
    name.append(dot);
  }
  name.append(el('span', undefined, textField(group, 'name') ?? 'A group'));

  // Roles are an open enumeration: an unrecognized one is rendered, not dropped.
  const role = textField(entry, 'role');
  if (role !== undefined) name.append(el('span', 'dim', ` · ${role}`));
  row.append(name);

  // A group's member count is EXACT where a space's is a worded bucket. That is
  // the API's own design — a room's population is ambient, a group is an
  // operational unit whose size has a real answer — so both are rendered as
  // served rather than made to match each other.
  const members = numberField(group, 'memberCount');
  const joined = dateText(entry, 'joinedAt');
  const aside = [
    members === undefined ? undefined : `${members} ${members === 1 ? 'member' : 'members'}`,
    joined === undefined ? undefined : `joined ${joined}`,
  ]
    .filter((part): part is string => part !== undefined)
    .join(' · ');
  if (aside !== '') row.append(el('p', 'dim', aside));

  const did = textField(group, 'did');
  if (did !== undefined) {
    const line = el('p');
    line.append(didLink(did));
    row.append(line);
  }
  return row;
};

/**
 * One membership: the space, this user's role in it, and the groups correlated
 * to it. The groups are a parameter rather than a member of `item` — the API
 * stopped nesting them, and this row renders what the caller matched up.
 */
const spaceRow = (
  item: Record<string, unknown>,
  groups: Record<string, unknown>[],
): HTMLElement => {
  const row = el('li');
  const space = objectField(item, 'space') ?? {};
  const domain = textField(space, 'domain');

  const name = el('p', 'name');
  const image = avatarImage(textField(space, 'avatarUrl'));
  if (image !== null) name.append(image);
  name.append(el('span', undefined, textField(space, 'displayName') ?? domain ?? 'A space'));
  const role = textField(item, 'role');
  if (role !== undefined) name.append(el('span', 'dim', ` · ${role}`));
  row.append(name);

  // `domain` is a mutable alias and may not resolve publicly, so it is text here
  // and never a link — `id` and `did` are the canonical names. The member count
  // is a worded bucket the API deliberately keeps inexact; it is rendered as it
  // arrived rather than turned into a number this page does not have.
  const joined = dateText(item, 'joinedAt');
  const groupCount = numberField(item, 'groupCount');
  const aside = [
    domain,
    textField(space, 'memberCountSummary'),
    joined === undefined ? undefined : `joined ${joined}`,
    groupCount === undefined || groupCount <= 0
      ? undefined
      : `${groupCount} ${groupCount === 1 ? 'group' : 'groups'}`,
  ]
    .filter((part): part is string => part !== undefined)
    .join(' · ');
  if (aside !== '') row.append(el('p', 'dim', aside));

  const did = textField(space, 'did');
  if (did !== undefined) {
    const line = el('p');
    line.append(didLink(did));
    row.append(line);
  }

  if (groups.length > 0) {
    const list = el('ul', 'groups');
    for (const entry of groups) list.append(groupRow(entry));
    row.append(list);
  }
  return row;
};

/** Which question the check affordance is asking, or last asked. */
type CheckKind = 'space' | 'group';

/** What the last single-membership check did, if anything. */
type CheckState =
  | { kind: 'idle' }
  | { kind: 'pending'; asked: CheckKind; target: string }
  | { kind: 'member'; asked: CheckKind; target: string; entry: Record<string, unknown> }
  | { kind: 'absent'; asked: CheckKind; target: string }
  | { kind: 'refused'; status: number; reason: string; code?: string; message?: string }
  | { kind: 'unreachable'; reason: string };

/**
 * The check affordance's own state, module-level for the same reason
 * `selectedScope` is: the whole signed-in view re-renders on every state move,
 * so what the reader typed and what came back have to outlive the nodes that
 * showed them.
 */
let checkTarget = '';
let check: CheckState = { kind: 'idle' };

/**
 * A ticket for the newest check. Two checks can be in flight at once — the
 * reader asked again before the first answered — and without this the LAST
 * answer to arrive would render, even when it answers the older question.
 */
let checkSeq = 0;

/**
 * Ask about ONE membership rather than walking the list. This is the gating
 * primitive a relying party actually needs — "is this user in our space" — and
 * the one place on the page where a value the reader typed reaches the signed
 * coordinates, confined by `api/check.ts` to a single path segment of a fixed
 * template.
 */
const checkBlock = (onCheck: (kind: CheckKind, target: string) => void): HTMLElement => {
  const block = el('div', 'section');
  const body: Node[] = [
    el(
      'p',
      'dim',
      'Ask about one membership instead of walking the list — the gating primitive ' +
        'a relying party actually needs.',
    ),
  ];

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = 'space or group — id, DID, or domain';
  input.value = checkTarget;
  input.addEventListener('input', () => {
    checkTarget = input.value;
  });
  body.push(input);

  const buttons = el('div', 'checkrow');
  for (const [label, kind] of [
    ['Check space', 'space'],
    ['Check group', 'group'],
  ] as [string, CheckKind][]) {
    const button = el('button', 'quiet', label);
    button.addEventListener('click', () => {
      const target = checkTarget.trim();
      if (target !== '') onCheck(kind, target);
    });
    buttons.append(button);
  }
  body.push(buttons);

  if (check.kind === 'pending') {
    body.push(el('p', 'dim', `Asking about ${check.target}…`));
  } else if (check.kind === 'member') {
    const role = textField(check.entry, 'role');
    const joined = dateText(check.entry, 'joinedAt');
    body.push(
      el(
        'p',
        undefined,
        `Member${role === undefined ? '' : ` — ${role}`}${joined === undefined ? '' : `, joined ${joined}`}`,
      ),
    );
    const rawPanel = el('details', 'rawjson');
    rawPanel.append(
      el('summary', undefined, 'Raw response'),
      el('pre', 'wrap', JSON.stringify(check.entry, null, 2)),
    );
    body.push(rawPanel);
  } else if (check.kind === 'absent') {
    // The 404 is collapsed on purpose, and this line is the page refusing to
    // read more into it than the API said.
    body.push(
      el(
        'p',
        'dim',
        `Not a member — or no such ${check.asked}. The API deliberately cannot tell you which.`,
      ),
    );
  } else if (check.kind === 'refused' || check.kind === 'unreachable') {
    body.push(...failureLines(check));
  }

  block.replaceChildren(...body);
  return block;
};

/**
 * THE SECOND READ — one credential, two more endpoints, under a third token. The
 * profile says who you are; this says where you are, and private spaces are in
 * it because that is what `read:memberships` granted.
 *
 * The API serves the graph as two flat walks rather than one nested page, so
 * this section correlates them: the groups are matched to their spaces here, on
 * `group.spaceId`. The space walk stands on its own — a group walk that is still
 * in flight, or that refused, costs the groups and nothing else.
 */
const membershipsSection = (
  state: MembershipsState,
  groups: GroupMembershipsState,
  onReload: () => void,
  onCheck: (kind: CheckKind, target: string) => void,
): HTMLElement => {
  const section = el('div', 'card memberships');
  const heading = el('h2', undefined, 'Your spaces');

  if (state.kind === 'idle' || state.kind === 'pending') {
    section.replaceChildren(
      heading,
      el('p', 'dim', 'Reading your memberships…'),
      checkBlock(onCheck),
    );
    return section;
  }

  if (state.kind === 'ok') {
    const raw = state.memberships;
    const items = arrayField(raw, 'items').filter(isRecord);
    const body: Node[] = [heading];

    // The correlation, read as defensively as everything else off the wire: an
    // entry whose group names no space is one this page cannot place, and it
    // falls through to the leftovers below rather than being dropped.
    const groupItems =
      groups.kind === 'ok' ? arrayField(groups.groupMemberships, 'items').filter(isRecord) : [];
    const spaceIdOf = (entry: Record<string, unknown>): string | undefined =>
      textField(objectField(entry, 'group') ?? {}, 'spaceId');

    const bySpace = new Map<string, Record<string, unknown>[]>();
    for (const entry of groupItems) {
      const spaceId = spaceIdOf(entry);
      if (spaceId === undefined) continue;
      const bucket = bySpace.get(spaceId);
      if (bucket === undefined) bySpace.set(spaceId, [entry]);
      else bucket.push(entry);
    }

    const rendered = new Set<string>();
    if (items.length === 0) {
      // A normal answer, not a failure: an account can belong to nothing.
      body.push(el('p', 'dim', 'No space memberships.'));
    } else {
      const list = el('ul', 'spaces');
      for (const item of items) {
        const spaceId = textField(objectField(item, 'space') ?? {}, 'id');
        if (spaceId !== undefined) rendered.add(spaceId);
        list.append(spaceRow(item, spaceId === undefined ? [] : (bySpace.get(spaceId) ?? [])));
      }
      body.push(list);

      // The endpoint signs one fixed request, so there is no page-two coordinate
      // to send. The default page is what there is, and the line says so.
      if (textField(raw, 'nextCursor') !== undefined) body.push(el('p', 'dim', '…and more.'));
    }

    // Two walks page independently, so a group can arrive whose space is on a
    // page of the space walk this call never asked for. Showing it under its own
    // heading is more honest than hiding it or inventing a space to nest it in.
    const orphans = groupItems.filter((entry) => {
      const spaceId = spaceIdOf(entry);
      return spaceId === undefined || !rendered.has(spaceId);
    });
    if (orphans.length > 0) {
      body.push(el('p', 'dim', 'Groups in spaces not listed above:'));
      const list = el('ul', 'groups');
      for (const entry of orphans) list.append(groupRow(entry));
      body.push(list);
    }

    if (groups.kind === 'ok') {
      if (textField(groups.groupMemberships, 'nextCursor') !== undefined) {
        body.push(el('p', 'dim', '…and more groups.'));
      }
    } else if (groups.kind === 'refused' || groups.kind === 'unreachable') {
      // One line, not a panel: the spaces above are a complete answer to the
      // question they answer, and the group walk failing does not unmake them.
      body.push(el('p', 'dim', `The group walk did not complete: ${groups.reason}`));
    }

    const rawPanel = el('details', 'rawjson');
    rawPanel.append(
      el('summary', undefined, 'Raw response — spaces'),
      el('pre', 'wrap', JSON.stringify(raw, null, 2)),
    );
    body.push(rawPanel);

    if (groups.kind === 'ok') {
      const groupPanel = el('details', 'rawjson');
      groupPanel.append(
        el('summary', undefined, 'Raw response — group memberships'),
        el('pre', 'wrap', JSON.stringify(groups.groupMemberships, null, 2)),
      );
      body.push(groupPanel);
    }

    const again = el('button', 'quiet', 'Read them again');
    again.addEventListener('click', onReload);
    body.push(again, checkBlock(onCheck));

    section.replaceChildren(...body);
    return section;
  }

  // Compact, and worded exactly as the hero words the same two outcomes: this is
  // a section, so it gets a line rather than a panel. The walks are independent
  // and each outcome is said for itself, so a group walk that answered is not
  // unrendered by a space walk that did not.
  const failed: Node[] = [heading, ...failureLines(state)];
  if (groups.kind === 'ok') {
    const groupItems = arrayField(groups.groupMemberships, 'items').filter(isRecord);
    if (groupItems.length > 0) {
      failed.push(el('p', 'dim', 'The group walk did answer:'));
      const list = el('ul', 'groups');
      for (const entry of groupItems) list.append(groupRow(entry));
      failed.push(list);
    }
    const groupPanel = el('details', 'rawjson');
    groupPanel.append(
      el('summary', undefined, 'Raw response — group memberships'),
      el('pre', 'wrap', JSON.stringify(groups.groupMemberships, null, 2)),
    );
    failed.push(groupPanel);
  }
  const retry = el('button', 'quiet', 'Try again');
  retry.addEventListener('click', onReload);
  failed.push(retry, checkBlock(onCheck));
  section.replaceChildren(...failed);
  return section;
};

/** How the app was resolved when the grant was issued, said in one clause. */
const TIER_NOTES: Record<string, string> = {
  approved: '(a registered app)',
  jit: '(resolved live from this origin’s dfos-app.json)',
  loopback: '(a local, key-proven client)',
};

/**
 * THE THIRD READ — the credential describing itself. `/api/me` reports what this
 * server verified and stored at sign-in; this reports what the API says it holds
 * right now, which is a different question with a different answer the moment a
 * grant is revoked.
 *
 * It needs no scope at all: a credential may always describe itself. So a 403
 * here is the revocation story arriving in the one place it cannot be mistaken
 * for a missing permission.
 */
const credentialCard = (state: CredentialState, onReload: () => void): HTMLElement => {
  const section = el('div', 'card credential');
  const heading = el('h2', undefined, 'What this app holds');

  if (state.kind === 'idle' || state.kind === 'pending') {
    section.replaceChildren(heading, el('p', 'dim', 'Asking the API about the credential…'));
    return section;
  }

  if (state.kind !== 'ok') {
    const retry = el('button', 'quiet', 'Try again');
    retry.addEventListener('click', onReload);
    section.replaceChildren(heading, ...failureLines(state), retry);
    return section;
  }

  const raw = state.credential;
  const facts: Fact[] = [];

  const subject = textField(raw, 'subjectDid');
  if (subject !== undefined) facts.push(['Subject', didLink(subject)]);
  const client = textField(raw, 'clientDid');
  if (client !== undefined) facts.push(['Held by', didLink(client)]);

  // The authoritative action list, as served. A token this page does not
  // recognize is an opaque string and is shown as one.
  const scopes = arrayField(raw, 'scopes').filter(
    (token): token is string => typeof token === 'string',
  );
  if (scopes.length > 0) facts.push([scopes.length === 1 ? 'Scope' : 'Scopes', scopes.join(', ')]);

  // An open enum: a tier this page has no note for is rendered bare rather than
  // described with a guess.
  const tier = textField(raw, 'tier');
  if (tier !== undefined) {
    const note = TIER_NOTES[tier];
    facts.push(note === undefined ? ['Tier', tier] : ['Tier', tier, note]);
  }

  // A null domain is the API saying LOCAL APPLICATION, not saying nothing: the
  // loopback tier proves a key rather than an origin, so there is no hostname
  // that would be true to show and none is invented.
  const domain = textField(raw, 'domain');
  facts.push(
    domain !== undefined
      ? ['Domain', domain]
      : ['Domain', el('span', 'dim', 'none — a local application')],
  );

  const issued = stampText(raw, 'issuedAt');
  if (issued !== undefined) facts.push(['Issued', issued]);
  const expires = stampText(raw, 'expiresAt');
  if (expires !== undefined) facts.push(['Expires', expires]);

  const body: Node[] = [heading];
  if (facts.length > 0) body.push(factList(...facts));
  body.push(
    el(
      'p',
      'dim',
      'Read live from the API just now, under no scope at all — a credential may ' +
        'always describe itself. The facts under “Show the receipts” are the same ' +
        'grant as this app verified and stored it at sign-in; this is what the API ' +
        'says it holds right now.',
    ),
  );

  const rawPanel = el('details', 'rawjson');
  rawPanel.append(
    el('summary', undefined, 'Raw response'),
    el('pre', 'wrap', JSON.stringify(raw, null, 2)),
  );
  body.push(rawPanel);

  const again = el('button', 'quiet', 'Read it again');
  again.addEventListener('click', onReload);
  body.push(again);

  section.replaceChildren(...body);
  return section;
};

/** The hero when the sign-in granted no credential: what was proved, and what was not. */
const identityHero = (session: Session): HTMLElement => {
  const hero = el('div', 'card hero');
  hero.replaceChildren(
    el('h2', undefined, 'You are signed in'),
    el(
      'p',
      'bio',
      'This sign-in proved who you are and nothing else. There is no credential, ' +
        'so this app has nothing to read on your behalf.',
    ),
    el(
      'p',
      'dim',
      `Verified against ${session.kid}, a current authentication key of your identity chain.`,
    ),
    el(
      'p',
      'dim',
      'Sign out and choose the credential scope to see the other half: live ' +
        'credential-gated API calls.',
    ),
  );
  return hero;
};

/**
 * The credential chip. Expiry is a fact this page can read on its own; whether
 * the API will HONOR the grant is not, and the difference showed up in
 * production as a chip reading "active" above a 403. So the chip claims only
 * what it knows: before the call it says `unexpired`, which is all an expiry
 * date supports, and once the live call answers it defers to that outcome.
 */
const credentialChip = (facts: CredentialFacts, profile: ProfileState): HTMLElement => {
  const remaining = facts.expiresAt * 1000 - Date.now();
  if (remaining <= 0) return chip('credential expired', 'warn');

  if (profile.kind === 'ok') return chip('credential accepted', 'ok');
  if (profile.kind === 'refused') return chip(`credential refused · ${profile.status}`, 'warn');

  // idle, pending, or a call that never completed: nothing was learned from the
  // API, so the chip stays on the one thing the expiry date actually supports.
  const days = Math.floor(remaining / 86_400_000);
  return chip(`credential unexpired · ${days}d left`);
};

/**
 * The session indicator, the way an application shows one: who is signed in,
 * under what scope, and whether the grant behind it is good.
 */
const sessionBar = (session: Session, profile: ProfileState): HTMLElement => {
  const signOutButton = el('button', 'quiet', 'Sign out');
  signOutButton.addEventListener('click', () => void signOut());

  const who = el('p', 'who');
  who.append(el('span', 'dim', 'Signed in as '), el('code', undefined, session.did));

  const chips = el('div', 'chips');
  for (const token of session.scope.split(' ').filter((entry) => entry !== '')) {
    chips.append(chip(token));
  }

  const facts = session.credential;
  if (facts === undefined) chips.append(chip('no credential'));
  else chips.append(credentialChip(facts, profile));

  const bar = el('div', 'card session');
  bar.replaceChildren(who, chips, signOutButton);
  return bar;
};

/**
 * The credential-gated reads that start on arrival, carried as one set. They are
 * separate calls against separate endpoints and any of them can answer first, so
 * the view renders from all of them at once: a memberships call that finishes
 * late must not paint over the profile the hero is already showing, and the
 * reverse. (The single-membership checks are not in here — those are on demand,
 * and `check` holds their state.)
 */
interface Reads {
  profile: ProfileState;
  memberships: MembershipsState;
  groupMemberships: GroupMembershipsState;
  credential: CredentialState;
}

const NOTHING_READ: Reads = {
  profile: { kind: 'idle' },
  memberships: { kind: 'idle' },
  groupMemberships: { kind: 'idle' },
  credential: { kind: 'idle' },
};

/** The latest pair, so whichever call renders next renders the other's result too. */
let reads: Reads = NOTHING_READ;

const renderSignedIn = (session: Session, jws?: string, state: Reads = NOTHING_READ): void => {
  const facts = session.credential;
  const found = registration;

  render(
    ...notices(),
    facts !== undefined
      ? profileHero(state.profile, () => void callProfile(session, jws))
      : identityHero(session),
    ...(facts !== undefined
      ? [
          membershipsSection(
            state.memberships,
            state.groupMemberships,
            () => {
              // One button, both walks: the section renders them as one answer,
              // so re-reading half of it would leave the page half stale.
              void callMemberships(session, jws);
              void callGroupMemberships(session, jws);
            },
            (kind, target) => void callCheck(session, jws, kind, target),
          ),
          credentialCard(state.credential, () => void callCredential(session, jws)),
        ]
      : []),
    sessionBar(session, state.profile),
    ...(found !== null ? [appIdentityCard(found)] : []),
    receipts(session, jws),
  );
};

/** One of the reads moves, and the view re-renders from all of them. */
const showRead = (session: Session, jws: string | undefined, moved: Partial<Reads>): void => {
  reads = { ...reads, ...moved };
  renderSignedIn(session, jws, reads);
};

/** The same, for the check — which is a state move outside `Reads`. */
const showCheck = (session: Session, jws: string | undefined, moved: CheckState): void => {
  check = moved;
  renderSignedIn(session, jws, reads);
};

/**
 * Enter the signed-in view. On the credential path all four calls start
 * immediately — no click — so the payoff is on screen as soon as there is a
 * session to render it from.
 */
const enterSignedIn = (session: Session, jws?: string): void => {
  reads = NOTHING_READ;
  checkTarget = '';
  check = { kind: 'idle' };
  // Advancing the ticket orphans any check still in flight from the session
  // this one replaces, so its answer cannot land on the fresh view.
  checkSeq += 1;
  if (session.credential === undefined) {
    renderSignedIn(session, jws, reads);
    return;
  }
  void callProfile(session, jws);
  void callMemberships(session, jws);
  void callGroupMemberships(session, jws);
  void callCredential(session, jws);
};

/** What one gated read came back with, before it is filed under a state name. */
type ReadOutcome = { kind: 'ok'; data: Record<string, unknown>; host: string } | ReadFailure;

/**
 * Ask the backend to present the credential once. The page sends nothing but the
 * request itself: which credential, which endpoint, and what may be signed are
 * all the server's to decide from the session it already holds.
 *
 * Every gated route answers in the same envelope — `{ ok: true, <member>, host }`
 * or a refusal — so the four callers below differ only in which member they read
 * and which state they file it under. Three failures are kept apart: a request
 * that never landed, a backend that answered something other than 200, and the
 * API's own refusal, which is the only one carrying a status worth showing.
 */
const gatedRead = async (path: string, member: string): Promise<ReadOutcome> => {
  const result = await call(path, { method: 'POST', timeoutMs: VERIFY_TIMEOUT_MS });
  if (result === null) {
    return { kind: 'unreachable', reason: 'The request to this site’s backend did not complete.' };
  }
  if (result.status !== 200) {
    return {
      kind: 'unreachable',
      reason: reasonFrom(result, `this site’s backend answered HTTP ${result.status}`),
    };
  }

  const body = result.body;
  const served = body[member];
  if (body['ok'] === true && isRecord(served)) {
    return {
      kind: 'ok',
      data: served,
      host: typeof body['host'] === 'string' ? body['host'] : 'the DFOS API',
    };
  }

  return {
    kind: 'refused',
    status: typeof body['status'] === 'number' ? body['status'] : 0,
    reason: reasonFrom(result, 'the API refused the request'),
    ...(typeof body['code'] === 'string' ? { code: body['code'] } : {}),
    ...(typeof body['message'] === 'string' ? { message: body['message'] } : {}),
  };
};

const callProfile = async (session: Session, jws?: string): Promise<void> => {
  showRead(session, jws, { profile: { kind: 'pending' } });
  const outcome = await gatedRead('/api/profile', 'profile');
  showRead(session, jws, {
    profile:
      outcome.kind === 'ok' ? { kind: 'ok', profile: outcome.data, host: outcome.host } : outcome,
  });
};

/**
 * The same shape against the other endpoints. Separate calls rather than one
 * combined route: separate API reads, and the page shows each one's outcome for
 * itself.
 */
const callMemberships = async (session: Session, jws?: string): Promise<void> => {
  showRead(session, jws, { memberships: { kind: 'pending' } });
  const outcome = await gatedRead('/api/memberships', 'memberships');
  showRead(session, jws, {
    memberships:
      outcome.kind === 'ok'
        ? { kind: 'ok', memberships: outcome.data, host: outcome.host }
        : outcome,
  });
};

const callGroupMemberships = async (session: Session, jws?: string): Promise<void> => {
  showRead(session, jws, { groupMemberships: { kind: 'pending' } });
  const outcome = await gatedRead('/api/group-memberships', 'groupMemberships');
  showRead(session, jws, {
    groupMemberships:
      outcome.kind === 'ok'
        ? { kind: 'ok', groupMemberships: outcome.data, host: outcome.host }
        : outcome,
  });
};

const callCredential = async (session: Session, jws?: string): Promise<void> => {
  showRead(session, jws, { credential: { kind: 'pending' } });
  const outcome = await gatedRead('/api/credential', 'credential');
  showRead(session, jws, {
    credential:
      outcome.kind === 'ok'
        ? { kind: 'ok', credential: outcome.data, host: outcome.host }
        : outcome,
  });
};

/**
 * The one call that carries a value the reader typed. It goes to the backend as
 * a kind and an identifier, never as a path — `api/check.ts` owns the two
 * templates and fills exactly one segment of one of them.
 *
 * A `member: false` answer arrives as `ok: true`, because the collapsed 404 is
 * the answer to the question rather than a failure of the call, and this page
 * renders it that way.
 */
const callCheck = async (
  session: Session,
  jws: string | undefined,
  kind: CheckKind,
  target: string,
): Promise<void> => {
  // This call holds the newest ticket for as long as nobody asks again; an
  // answer arriving after the ticket moved on belongs to a superseded question
  // and is dropped rather than rendered against the newer one.
  const seq = ++checkSeq;
  const file = (state: CheckState): void => {
    if (seq === checkSeq) showCheck(session, jws, state);
  };

  file({ kind: 'pending', asked: kind, target });

  const result = await call('/api/check', {
    method: 'POST',
    body: { kind, target },
    timeoutMs: VERIFY_TIMEOUT_MS,
  });
  if (result === null) {
    file({
      kind: 'unreachable',
      reason: 'The request to this site’s backend did not complete.',
    });
    return;
  }
  if (result.status !== 200) {
    file({
      kind: 'unreachable',
      reason: reasonFrom(result, `this site’s backend answered HTTP ${result.status}`),
    });
    return;
  }

  const body = result.body;
  if (body['ok'] === true) {
    const entry = body['entry'];
    file(
      body['member'] === true && isRecord(entry)
        ? { kind: 'member', asked: kind, target, entry }
        : { kind: 'absent', asked: kind, target },
    );
    return;
  }

  file({
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
    if (credential !== undefined) selectedScope = SCOPE_API;
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
