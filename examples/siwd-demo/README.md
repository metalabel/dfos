# Sign In With DFOS — demo relying party

## What this is

A complete Sign In With DFOS login — challenge minted server-side, JWS verified
server-side, session cookie granted server-side — small enough to read in one
sitting, and a live credential-gated API call that runs the moment you are
signed in. One static page, six serverless functions, no database beyond a small
key-value store, and no SDK beyond the two DFOS packages installed from npm like
any third party would. Deployed at <https://dfos-siwd-demo.vercel.app>.

The load-bearing decision is **where verification happens**. It happens in
`api/verify.ts`, because that is where the session is granted.
[SIWD.md §Security Considerations](../../specs/SIWD.md#a-did-is-an-address-not-a-proof)
states the rule: a bare DID is an address, not a proof, and the JWS MUST be
verified wherever a session is granted.

Verification contacts **no DFOS platform server**. The only network hop is to a
public relay, to resolve the signer's identity chain to its current state. The
relay is untrusted; the crypto is what convinces us.

**You pick the scope before you sign in, and the choice changes what the backend
owes.** `identity` proves who you are and returns nothing else. `read:profile`
also returns a **credential** — a durable, audience-bound authorization the app
keeps and presents to the DFOS API. That one difference obliges a stricter
replay discipline, requires the app to name its own DID, and unlocks the live
credential-gated API call. Both run side by side so the difference is something
you can watch rather than read about.

## What you see

The page demonstrates before it explains, and from here on so does this README.

**Signed in at `read:profile`, the first thing on screen is your profile** —
display name, handle, bio, email, joined date — read live from `GET /v1/profile`
the moment there is a session to read it with. No button. That data is what the
sign-in bought, and a demo that makes you press one more thing to see it has
buried its own point. The raw JSON is one disclosure down, because this is still
a protocol demo, and **Read it again** re-runs the call against the same
standing grant — which is the cheapest way to watch that using a credential does
not use it up.

**Above it sits the session indicator**, the way an application shows one: the
signed-in DID, a chip for the scope, and a chip for the credential —
`credential active · 89d left`, or `credential expired` — plus the grant's
action and resource and when the session runs out. Every value there was read
back out of the server's own sealed cookie, never out of anything the browser
supplied.

At `identity` scope there is no credential and so nothing to read, and the page
says that rather than showing an empty panel.

**Then this app's own identity.** The user side of a sign-in gets a DID, a
signed chain, and an explorer to check it in; so does the app side, and that
symmetry is worth seeing rather than being told about. The panel shows what
`public/.well-known/dfos-app.json` says about this app — its `name`, its
`client_did`, and a summary of the `identity_chain` it carries: how many signed
operations, of which types, how many current auth keys, and the head CID — with
links to the served file and to this app's own page in the explorer. Those bytes
are decoded for display and nothing more. What makes the chain real is a host
verifying that it derives the declared DID, which happens at first consent.

The panel reports only what it actually read. "This page could not load the
file", "the origin serves no file", and "the file declares nothing" are three
different sentences, and the panel never substitutes one for another — a request
that failed is not evidence about a file's contents. Whether this origin is in
the file's `redirect_uris` is asked separately and answered separately, because
what an app declares about itself and where it may be redirected to are
different questions.

**Everything mechanical is one disclosure down, under "Show the receipts":** the
credential in full, the signing seam that exercised it, the decoded sign-in
artifact, the checks the server ran before it granted anything, how this app is
registered, links to look the same chain up in a second verifier, the source of
every file in the flow, and the specs. Nothing was cut to lead with the
demonstration — it moved.

The rest of this README is that material in long form.

## How it works

| Endpoint        | What it does                                                                                                                     |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `GET /config`   | What this deployment can serve — which scopes are available, and why not when they are not                                       |
| `POST /login`   | Mints the challenge, remembers the nonce (sealed cookie or store, per scope), returns the `/authorize` URL                       |
| `POST /verify`  | Recovers that nonce, runs `verifySiwd` against a relay, verifies any returned credential, grants the session cookie              |
| `GET /me`       | Reads the session cookie back — the one source the signed-in view renders from                                                   |
| `POST /profile` | Exercises the credential: signs one request proof and calls `GET /v1/profile` on the DFOS API. Called on arrival, not on a click |
| `POST /logout`  | Expires the session and drops the stored credential                                                                              |

### The two scopes

| Scope          | Returns                | Replay discipline | `client_did` | Needs                        |
| -------------- | ---------------------- | ----------------- | ------------ | ---------------------------- |
| `identity`     | a signed challenge     | flow-bound        | not sent     | `SESSION_SECRET`             |
| `read:profile` | …plus a **credential** | **consumed**      | **required** | …plus an app key and a store |

At `identity` scope the authorize request carries `challenge`, `redirect_uri`,
and `scope` and does **not** send `client_did`. The platform learns who this app
is by fetching `/.well-known/dfos-app.json` from the redirect's own origin — the
served file _is_ the app identity. What `client_did` determines is the `aud` of a
returned credential
([SIWD.md §Client identity](../../specs/SIWD.md#client-identity-client_did)), and
an identity-scope sign-in returns none.

At `read:profile` it is **required**, and for the same reason: a credential has
to be issued _to_ someone. The DID this demo sends is derived from its own
signing key, so the app cannot ask for a credential it would be unable to exercise.

### The flow, step by step

1. **Mint and redirect.** The sign-in click posts to `/api/login` with the chosen
   scope. `createSiwdLoginRequest` returns the `/authorize` URL — carrying
   `challenge`, `redirect_uri`, `scope`, and (at `read:profile`) `client_did` —
   plus the nonce it minted. Where that nonce is remembered depends on the
   discipline the scope obliges: sealed into the `siwd_flight` cookie, or written
   to the store. Minting here also puts the timestamp on **the server's clock**,
   which retires a failure mode: a browser whose clock was minutes off produced
   challenges that were born stale and correctly refused on the way back.
2. **Come back signed.** The platform authenticates the user, shows consent,
   signs the canonical challenge bytes with a key from the user's identity chain,
   and redirects back with `?jws=<signed challenge>&did=<did>`. On a
   credential scope it appends `#credential=<credential JWS>` — in the **URL
   fragment**, which is never sent to a server and so lands in no access log, no
   proxy log, and no `Referer` header. `readSiwdCallback(location.search)` sorts
   the return into success, denied, or "not a callback at all", the page reads
   the fragment itself, and both are scrubbed out of the address bar immediately.
3. **Verify where the grant happens.** The page posts `{ jws }` — plus
   `credential` when there was one — to `/api/verify`, and nothing else: no
   nonce, no DID. The server recovers its own expectation, then
   `verifySiwd` resolves the signer's identity chain from a public relay,
   replays it to current state, and checks that the signing key is a **current**
   `authKeys` entry of a non-deleted identity — plus the domain, the timestamp
   window, and the nonce last.
4. **Answer for the credential too.** On the credential path the server verifies
   the returned credential in full before storing it — signature, schema, CID
   integrity, expiry — and then checks it is the grant that was actually asked
   for: issued by the identity that just signed in, audienced to **this** app,
   and covering `read:profile` on `api:api.dfos.com`. An RP that files away an
   unverified grant has learned nothing from having a verifier.
5. **Grant.** The flight cookie is cleared in the same response that sets
   `siwd_session` — the DID, the `kid`, the scope, and an expiry, sealed under
   the same key. The JWS is discarded: a signed challenge is a one-shot
   authentication proof, not a bearer token. The **credential is not** discarded;
   holding it is the point.

6. **Read something with it.** On the credential path the page does not wait to
   be asked: as soon as the session exists it posts to `/api/profile`, which
   signs one request proof and calls `GET /v1/profile`. What comes back is the
   hero of the signed-in page.

The browser still **decodes** the returned JWS and shows it, in a panel labelled
for what it is: `decodeJwsUnsafe` does no verification and says so in its name.
Sign in and open **"Show the receipts"** for the credential in full, the signing
seam that exercised it, the decoded artifact, the list of checks the server ran,
and links to look the same chain up yourself.

Spec: [`specs/SIWD.md`](../../specs/SIWD.md) · <https://protocol.dfos.com/siwd>

## The two replay disciplines

SIWD admits two, and
[which one you owe is decided by what success grants](../../specs/SIWD.md#replay-prevention).
This demo runs **both**, one per scope, because the rule is easier to believe
when you can switch between them:

- **`identity` → flow-bound.** Success grants a session with the browser standing
  in front of it, and nothing else. The sealed cookie is the whole mechanism.
- **`read:profile` → consumed.** Success also hands back a credential, which is
  portable and outlives this browser. Flow-binding is no longer admissible, and
  the nonce must be spent by an atomic check-and-delete in the store.

The difference in code is one field on `verifySiwd` — `nonce` becomes
`consumeNonce` — which is exactly the claim the section below makes, now
exercised rather than asserted.

**What the sealed cookie is.** At mint time the server binds the nonce to the
agent that started the flow, statelessly. The value is
`nonce.exp.base64url(HMAC-SHA256(SESSION_SECRET, "flight:" + nonce + "." + exp))`
— the expiry sits inside the sealed bytes so the server's own clock enforces it
(`Max-Age` is only the honest browser's copy), and the tag is domain-separated by
purpose so a seal of one class cannot be replayed as another. It rides in an
`httpOnly` cookie scoped to `/api`, expiring with the acceptance window. At
verification the expectation is recovered from that seal and from nowhere else.

**Why the seal and not just a cookie.** A bare cookie value is no defense.
Cookies are presenter-supplied on every request: an attacker holding a captured
JWS reads the nonce out of the payload and sends it back in a `Cookie` header of
their own, since `HttpOnly` constrains a browser's scripts and not `curl`. The
tag is what binds — only this server's key can produce it, so the expectation is
recoverable only from the server's own prior act of minting it.

**What it guarantees, exactly.** _The artifact redeems only through the channel
that initiated the flow, inside the timestamp window._ It is **not** global
single-use: a party holding both the artifact and the cookie jar can redeem again
within the window. That is the accepted trade for a session-only grant, since a
party holding the cookie jar already holds the session they would gain. It is
also what the surrounding ecosystem applies to browser login: OpenID Connect's
`state` and `nonce` verified against browser-carried session state, Sign in with
Ethereum's session-bound nonce.

**When you must switch.** The moment success yields anything beyond a session
with the presenting browser — a credential-returning scope, a token or grant
redeemable outside the originating channel, any of profile B (a mailbox flow has
no presenting channel to bind) — flow-binding is no longer admissible and
**consumed verification is REQUIRED**. Store each minted nonce server-side and
consume it atomically:

```js
const result = await verifySiwd(client, jws, {
  domain,
  // Redis GETDEL, KV, a DELETE … RETURNING row — but atomic, and answering as a boolean
  consumeNonce: async (nonce) => (await store.getdel(nonce)) !== null,
});
```

That is literally what `api/verify.ts` does on the credential path, against the
store in `api/_kv.ts` — three Redis commands over the REST API, no client
library. The kit runs the nonce check last under both disciplines — after
signature, key currency, domain, and timestamp — so an invalid presentation never
spends a nonce its legitimate holder is still carrying. A non-atomic
read-then-delete is not a substitute: it is a race with a login in it.
`consumeNonce` ships in `@metalabel/dfos-client` ≥ 0.31.

**Which discipline a callback owes is itself sealed.** The `siwd_flight` cookie
is written under one of two HMAC purposes — `flight` for the flow-bound path,
`flight-credential` for the consumed one — and `/api/verify` learns the scope by
seeing which one unseals. Because the tag is domain-separated by purpose, a
presenter cannot relabel a credential callback into the weaker check.

**Either way, the expectation must be something only the verifier could have
produced.** A nonce handed to the verifier by the party presenting the artifact —
in a callback parameter, a request body, or an unsealed cookie — is not a replay
defense at all.

## Why sign every request

The easy design is a bearer token: the login hands the app a string, and the
string **is** the authorization — whoever presents it, wins. Every stolen-token
attack lives inside that one property. A bearer token in a log line, a crash
report, a proxy cache, or an exfiltrated database is the grant itself, and the
only remedies are short lifetimes (which trade away durability) or revocation
races (which trade away certainty).

This demo's credential deliberately does not have that property. It is a signed
statement that **a grant exists** — issued by the user, audience-bound to this
app's DID, scoped to `read:profile` on `api:api.dfos.com` — and presenting it
proves nothing by itself. What exercises it is a **request proof**: a short-lived
signature by this app's own key over the exact request being made — method,
host, path, body hash, right now — carrying the credential's CID inside the
signed bytes. The API checks both. Steal the credential and you hold metadata;
steal a proof and you hold one request that has already happened. The two
artifacts only compose into authority in the hands of the party holding the
key, which is the definition of proof-of-possession.

That is why the backend signs, and the browser never sees a key. A browser
cannot hold a signing key non-extractably, so the supported shape is the
backend-for-frontend this demo is: the browser holds an ordinary session
cookie, and the server — which can keep a secret — signs one fixed request on
its behalf. "Sign every request" costs one Ed25519 signature per call, and it
buys retiring the entire category of replayed-authorization bugs rather than
patching instances of it.

The deeper point is that none of this is platform machinery. The user's
identity is a self-verifying chain any relay can serve; the credential and the
proof are byte contracts published in [CREDENTIALS](../../specs/CREDENTIALS.md)
and [API-AUTH](../../specs/API-AUTH.md); verification is a pure function of
public keys, and revocation is the user's standing lever, re-checked on every
request. The resource form is `api:<host>` — host-as-identifier — so **any API
on any domain** can gate itself the same way with no registry, no OAuth server,
and no coordination with anyone: publish which host you are, verify the two
headers, honor revocation. The DFOS API is simply the first host doing it.

## Exercising the credential

A credential says a grant exists. It does **not** say the party presenting it is
the party it was granted to — and closing that gap is what
[API-AUTH](../../specs/API-AUTH.md) is for. Every credential-gated request
carries two headers:

```
Authorization: DFOS <request-proof JWS>
X-Credential: <leaf credential JWS>
```

The proof is a short-lived JWS signed by the app's own key, binding the
credential's CID to **this** method, host, path, and body, right now. A captured
credential is inert without that key; a captured proof authorizes nothing but the
one request it already described. Neither is a bearer token, which is why the
scheme is `DFOS` and not `Bearer`.

`api/profile.ts` is where the two packages meet, through one seam:

```ts
const api = createDfosApi({
  baseUrl: `https://${API_HOST}/v1/`,
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
    for (const [name, value] of Object.entries(buildApiAuthHeaders({ proof, credential }))) {
      headers.set(name, value);
    }
    return fetch(new Request(request, { headers }));
  },
});

await api.GET('/profile');
```

[`@metalabel/dfos-api`](https://www.npmjs.com/package/@metalabel/dfos-api) knows
the API's shape — paths and response types generated from the live OpenAPI spec.
[`@metalabel/dfos-client`](https://www.npmjs.com/package/@metalabel/dfos-client)
knows the byte contract. Neither had to learn about the other: the client hands
the wrapper one fully-composed `Request`, and the wrapper signs exactly that.

**Why the long form, when the kit ships a one-liner.**
`@metalabel/dfos-client/api-auth` also exports
[`createApiAuthFetch`](../../packages/dfos-client/README.md#metalabeldfos-clientapi-auth),
which is that whole wrapper as a single call — hand it a credential, a `kid`,
and a `sign` callback and every request the API client composes goes out
credential-gated. It is the right answer for a process signing on its own
behalf. It is the wrong answer here, and the next paragraph is why: a backend
fronting a browser must authorize the coordinates it is about to sign against
its own session, so there is no browser-composed `Request` for the adapter to
cover in the first place. The demo writes the seam out, and the page shows it
under "Show the receipts", because the composition is the thing worth seeing.

**The endpoint takes no parameters, and that is the design.** API-AUTH's
[Security Considerations](../../specs/API-AUTH.md#security-considerations) name
the trap: a backend that signs whatever `{method, path, body}` a browser hands it
is a confused deputy — an XSS on the page, or simply a hostile client, obtains
proofs for arbitrary requests against every credential the backend holds. So
`POST /api/profile` signs one request, `GET /v1/profile`, and the only thing the
caller supplies is a session cookie saying which credential to use. There is
nothing to ask with.

**There is no route parameter naming the user, either.** The credential's root
issuer selects the subject
([API-AUTH step 10](../../specs/API-AUTH.md#verification-algorithm)), so the
endpoint serves the profile of exactly the DID that granted the credential and
offers no way to name anybody else.

### What the failures mean

| Status | Meaning                                                                                                                               |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| `401`  | The **proof** layer refused — a bad signature, a stale `iat`, a binding mismatch, or a key that is no longer current for this app.    |
| `403`  | The proof was fine; the **credential** layer refused. Revocation is the usual cause, and the API re-checks it on every request.       |
| `503`  | The check could not complete — a resolution or revocation source was unreachable. The server's condition, not a verdict on the grant. |

Branch on the status and on the typed envelope's `code`, never on the challenge
header. A `401` is specified to carry `WWW-Authenticate: DFOS`, but at the time of
writing `api.dfos.com` serves it as **`x-amzn-remapped-www-authenticate`**:
CloudFront Functions viewer-response handlers do not run for origin responses
≥ 400, so the header the spec names never gets restored. That is a deployment
gap being closed on the platform side, and it is exactly why the machine signals
are the status code and the envelope.

### Revoking

The credential's `exp` is 90 days out; **revocation is the timely lever**, and it
is checked in the verify path on every request rather than cached anywhere. Revoke
the grant at your DFOS host and press **Read it again** under the profile — the
same call that filled the page a moment ago now answers `403`. Nothing about this
demo changed; the API simply asked a question whose answer moved.

## Configuration

| Variable               | Needed for     | What it is                                                                   |
| ---------------------- | -------------- | ---------------------------------------------------------------------------- |
| `SESSION_SECRET`       | everything     | The key both cookie seals use. 32+ characters.                               |
| `DFOS_APP_KID`         | `read:profile` | The DID URL of a current key of the app's own identity.                      |
| `DFOS_APP_PRIVATE_KEY` | `read:profile` | That key's Ed25519 secret, 43 base64url characters.                          |
| `KV_REST_API_URL`      | `read:profile` | A Redis-compatible REST endpoint, for the consumed nonce and the credential. |
| `KV_REST_API_TOKEN`    | `read:profile` | Its bearer token.                                                            |

Only `SESSION_SECRET` is required. Without the other four the identity scope works
exactly as before and the credential scope renders **disabled, with the reason
next to it** — the page asks `/api/config` at boot, so a missing precondition is
something you read before the click rather than discover three redirects later.

`UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` are accepted as aliases, so
a database connected directly at Upstash works with no edit. On Vercel, the
store that writes the `KV_*` pair is the **Upstash for Redis** marketplace
integration — `vc i upstash/upstash-kv`, or Marketplace → Upstash → Upstash for
Redis in the dashboard. Mind the lookalike: the "Redis" product on Vercel's own
storage screen is Redis Cloud, which provides a `REDIS_URL` for the TCP
protocol and **no REST endpoint** — this demo's store client speaks only the
Upstash REST protocol, on purpose (three commands over `fetch`, no dependency),
so Redis Cloud will not work here.

### `SESSION_SECRET`

The key both seals use. Set it to any long random string, 32+ characters (the
deploy button prompts you for it):

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

**Deployed without it, sign-in refuses by name** — the click answers
`SESSION_SECRET is not set — add it in your Vercel project settings` rather than
failing three redirects later as a mystery. It has to: on Vercel every file in
`api/` is its own function with its own module instance, so a per-instance random
key would mean `/api/login` seals with one key and `/api/verify` unseals with
another, and every deployed sign-in would die as "no sign-in in flight" — while
local dev, one process, concealed it. A fallback that only fails in production is
one this demo does not carry.

**Locally the dev server does fall back.** One process is guaranteed there, so it
mints a random key at startup and keeps running. What that loses is durability —
sessions die with the process — so the page renders a notice and every response
carries `ephemeral: true` while it holds. A secret shorter than 32 characters is
refused outright, in dev too: a guessable key makes every cookie forgeable
offline.

### The app's own key

This is a second key of a different kind. `SESSION_SECRET` is a secret this
server keeps from everyone; the app key is a **DFOS identity key** whose public
half is published in an identity chain. It exists because a credential is issued
_to_ someone, and exercising one means proving on every request that you are that
someone.

`DFOS_APP_KID` is the full DID URL — `did:dfos:<id>#key_<id>`. Its DID half is
the app's `client_did`, and it **must match the `client_did` in
`public/.well-known/dfos-app.json`**, because the platform issues the credential
to the DID it resolves from that file, and the API checks that the proof's signer
is that same DID.

`DFOS_APP_PRIVATE_KEY` is that key's Ed25519 secret as 43 base64url characters.
Nothing derives it for you; a secret that does not belong to the key `KID` names
is the one misconfiguration whose only other symptom is a `401` from the API,
arriving several steps later with nothing local to compare against. So
`/api/config` reports the **public** key it derived from whatever you set —
compare it against `dfos identity keys` and the mismatch is visible immediately.

The key never leaves the server. A browser cannot hold one non-extractably, so
the supported shape is the backend-for-frontend this demo is: the browser holds
an ordinary session, and the backend signs.

### The store

The consumed discipline needs an atomic check-and-delete, which is one `GETDEL`.
`api/_kv.ts` speaks the Upstash REST protocol directly — a JSON array of command
arguments in, a `{ result }` back — because the whole surface this demo needs is
three commands, and that is not worth a dependency.

It holds two things: the outstanding nonce (300s), and the verified credential
keyed by session (24h, dropped on sign-out). The credential is there rather than
in a cookie because it is a durable authorization that belongs on the RP's side
of the wire, and because a browser has no key to exercise it with anyway.

## Registration = a JSON file

`public/.well-known/dfos-app.json`:

```json
{
  "name": "SIWD Demo",
  "client_did": "did:dfos:8zk83zez862n6ahnvt3h3e4kc4n2dke",
  "redirect_uris": ["https://dfos-siwd-demo.vercel.app/"],
  "identity_chain": ["<genesis identity-op JWS>", "<add-key identity-op JWS>"]
}
```

There is no developer portal and no client secret. Serving that file over https
from the domain you control **is** the registration — domain control is the
credential. The platform fetches it live at authorize time (the JIT tier of
[SIWD.md §Redirect URI validation](../../specs/SIWD.md#redirect-uri-validation-profile-a)),
and `redirect_uris` is an **exact-match** allowlist, trailing slash included.
`name` is rendered on the consent screen as the app's own claim about itself, and
the consent screen labels it that way — nothing in the protocol vouches for it.
The domain is what the user is being asked to trust.

`identity_chain` is the app's own signed operation log, carried in the file so a
host that has never seen this identity can verify and ingest it on first
encounter — [SIWD.md §chain
carriage](../../specs/SIWD.md#identity_chain--chain-carriage). The CLI writes it
for you: `dfos identity well-known --patch public/.well-known/dfos-app.json`
fills `client_did` and `identity_chain` from your local identity and refuses a
mismatched rebind.

`client_did` is optional at identity scope — though a file that carries
`identity_chain` must name it, whatever the scope. It becomes **required** for
`read:profile`, because a credential has to be issued _to_ someone — and it must
name the same identity as `DFOS_APP_KID`, since the platform issues to the DID it
resolves from this file and the API checks the proof was signed by that DID's
key.

**The page checks its own registration at boot.** It fetches its
`/.well-known/dfos-app.json` and looks for its exact redirect target in
`redirect_uris`. If the file is missing, or the string is not in it, the page
says so — naming the exact string and the exact file — before you click anything.
The sign-in button stays live either way, so you can watch the host refuse it.

**And it renders what it found**, in the "This app's own identity" panel
described under [What you see](#what-you-see): the `name` and `client_did` this
app claims, a count and summary of the carried `identity_chain`, and a link to
this app's own page in the explorer. An app asking a user to trust it can afford
to be as inspectable as the user it is asking about.

The server derives the same string from the request's own origin rather than
hardcoding it, so the target the page checks and the target the server sends
cannot drift apart.

## Fork it

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fmetalabel%2Fdfos%2Ftree%2Fmain%2Fexamples%2Fsiwd-demo&project-name=dfos-siwd-demo&repository-name=dfos-siwd-demo&env=SESSION_SECRET&envDescription=Signs%20login%20sessions%20-%20set%20to%20any%20long%20random%20string)

That clones this directory alone into your own repo, prompts you for
`SESSION_SECRET`, and deploys it. Then make **one edit** — put your deployment's
origin in `redirect_uris`, exactly, with the trailing slash:

```json
{ "redirect_uris": ["https://your-app.example.com/"] }
```

Commit, redeploy, done. If you forget, the boot self-check renders the exact
string it needs to see. Update `name` too while you are there — it is what your
users read at consent.

(That one edit is the identity scope's whole story; the credential scope's
extra members — `client_did` and `identity_chain` — are step 1 below.)

Preview-deploy URLs are **not** in the allowlist, by design. Each preview gets a
fresh hostname, and an allowlist that admitted arbitrary subdomains would be an
open redirector. Sign-in works on the origins you listed; everywhere else the
page says which string is missing. The identity panel still renders the app's
declared identity there — being outside the redirect allowlist says nothing
about what the file declares, and the panel keeps the two apart.

That gets you the identity scope. For `read:profile`, three more steps. These
are not hypothetical — the canonical deployment was provisioned by exactly this
sequence, and the wrinkles below are the ones it actually hit.

1. **Give the app an identity and a delegate key.** Two keys, two homes, on
   purpose: the identity's controller key stays in your OS keychain, where the
   [`dfos` CLI](https://protocol.dfos.com) puts it and will not export it; the
   server gets its **own** key, added to the chain's auth set, so a compromised
   deployment is a revoke-and-re-add, never a new identity.

   ```sh
   # the identity — controller + first auth key land in your OS keychain
   dfos identity create --name my-app

   # a second auth key whose secret you can actually hold: file-based key
   # storage writes the seed to ~/.dfos/keys/ (chmod 600) instead of the
   # keychain, and prints the id + public Multikey to hand to add-key
   DFOS_NO_KEYCHAIN=1 dfos identity device-pubkey --identity my-app --json

   # graft it into the chain's auth set, signed by the keychain controller key
   dfos identity add-key --auth-key --id key_<from above> --pubkey z6Mk<from above>
   ```

   The DID goes in `client_did` above; `DFOS_APP_KID` is
   `did:dfos:<id>#key_<id>` for the **new** key. The seed file at
   `~/.dfos/keys/<did>__<key>` holds 64 hex characters; `DFOS_APP_PRIVATE_KEY`
   wants the same 32 bytes as 43 base64url characters:

   ```sh
   node -e "console.log(Buffer.from(require('fs').readFileSync(process.argv[1],'utf8').trim(),'hex').toString('base64url'))" \
     ~/.dfos/keys/<did>__<key> \
     | vercel env add DFOS_APP_PRIVATE_KEY production --sensitive
   ```

   Then delete the seed file — the deployment's env is now the only copy that
   matters, and `/api/config` proves it landed intact by deriving the public
   key back from it.

   Then carry the chain in the well-known:
   `dfos identity well-known --patch public/.well-known/dfos-app.json` writes
   `client_did` and `identity_chain` — the full signed op log, genesis first —
   into the file. Commit that too: it is how a host that has never seen your
   identity verifies and ingests it at first consent.

2. **Add the store** — the **Upstash for Redis** marketplace integration
   (`vc i upstash/upstash-kv`), Free plan, connected to your project. It writes
   `KV_REST_API_URL` and `KV_REST_API_TOKEN` for you. Not the Redis Cloud
   product on the storage screen — see [The store](#the-store).

3. **Redeploy, then check `/api/config`.** Environment changes do not touch
   running functions until the next deployment. The config endpoint reports
   which scopes are live, and for the app key it reports the derived **public**
   key — diff it against `dfos identity keys my-app` before anything is
   clicked.

**How the API learns your app's key.** The API's verifier resolves your app
identity's chain locally at request time — it never fetches your well-known
during verification. What closes the loop is chain carriage: at the first
credential-returning consent, the platform reads `identity_chain` from your
well-known file, verifies it derives your `client_did`, and ingests it — from
then on its verifier resolves your key like any other resident identity. That is
why step 1 ends with `dfos identity well-known --patch`: a CLI-minted identity
that carries its chain clears the full gated round trip, mint through `GET
/v1/profile`.

## Run it locally

```sh
npm install
npm run dev
```

The identity flow works locally, backend included and with **no well-known file
at all**: `http://localhost:5173/` is accepted as a redirect target for
`scope=identity` under the loopback tier. That is the RFC 8252 posture — an
application on the user's own machine holds no domain, so the binding a hosted
redirect asserts is one no host could check; rather than refuse the case, the
host consents to it under its own tier and says so. The boot self-check knows
this and skips itself on a loopback host.

**`read:profile` cannot run on a loopback host, and the page says so rather than
letting you try.** The same fact that makes the loopback tier possible rules the
credential scope out: a local port holds no domain, so it can prove no
`client_did`, so there is nobody to issue a credential to. The kit refuses to
build the request and the platform would refuse it too. Exercising that path
means deploying to a domain.

There is no `vercel` CLI in the loop. Vercel's Node runtime adds exactly two
things to Node's own request/response pair — a pre-parsed JSON `body` and
`status()` / `send()` — so `vite.config.ts` carries a ~50-line plugin that shims
those two and mounts the **same handler files** as dev-server middleware. Nothing
is reimplemented, so nothing can drift.

## Security notes

- **The verifier minted the nonce it checks.** It comes out of a cookie sealed
  under this server's key, or out of this server's own store, never out of the
  callback, the request body, or an unsealed cookie. See "The two replay
  disciplines" above for what that buys.
- **The nonce is checked last** — after signature, key currency, domain, and
  timestamp — which is [SIWD.md's step 6](../../specs/SIWD.md#third-party-verification)
  and what makes the move to `consumeNonce` a one-field change.
- **Which discipline a callback owes is sealed too**, as an HMAC purpose, so it
  is not a label the presenter can edit.
- **The `?did=` callback param is never trusted.** The DID in the session is the
  one inside the verified JWS.
- **A returned credential is verified before it is stored** — and checked to be
  issued by the signer, audienced to this app, and covering the resource and
  action asked for. Nothing is ever signed against a credential that has not
  cleared that check first, and the page renders it in full under the receipts
  so it can be read.
- **The signing seam takes no coordinates from the browser.** `POST /api/profile`
  signs one fixed request, authorized by the session alone. A backend that signs
  what a browser asks it to is a confused deputy holding a key.
- **The app's signing key never reaches the browser, and neither does the
  credential.** The browser holds an ordinary session; the backend holds both.
- **Every POST is origin-checked.** A present `Origin` header that is not this
  deployment's own is refused with a 403; an absent one means a non-browser
  caller, which is riding nobody's cookie jar. The gated call is a POST for a read
  precisely so this check applies to it — browsers omit `Origin` on GET.
- **Cookies are `HttpOnly; Secure; SameSite=Lax; Path=/api`.** `Secure` is set
  even in dev — browsers treat `http://localhost` as a secure context — and
  `Path=/api` keeps them off every static asset request.
- **The JWS and the credential are scrubbed** out of the address bar with
  `history.replaceState` the moment they are read, so neither lingers in history
  or in the referrer of anything the page loads next. The credential arrives in
  the fragment, which never reached a server log in the first place.
- **Everything that reaches the DOM is untrusted text.** Strings from the URL,
  the API, the JWS, and the served well-known file are set with `textContent`,
  never `innerHTML`.
- **A signed challenge is a one-shot authentication proof, not a bearer token.**
  The server establishes its own session after verification and discards the JWS.
  Neither is the credential a bearer token — without the app's key it authorizes
  nothing anywhere.

## Coordinates

The backend's live at the top of `api/_lib.ts`:

| Constant        | Value                            |
| --------------- | -------------------------------- |
| `AUTHORIZE_URL` | `https://app.dfos.com/authorize` |
| `RELAY_URL`     | `https://relay.dfos.com`         |
| `API_HOST`      | `api.dfos.com`                   |

`API_HOST` is one constant because it is two strings that must agree: the
`<host>` half of the `api:<host>` the credential names, and the `host` member of
every request proof. [API-AUTH](../../specs/API-AUTH.md) requires them to name
the same origin, so they are one expression here rather than two that can drift.

`src/main.ts` holds `RELAY_URL` and `EXPLORER_URL` for the receipts panel alone,
to hand you a second, independent verifier for the same chain.

SIWD and API-AUTH are each on their own `0.x` clock, independent of the frozen
protocol surface, so the hosted consent page URL may move before 1.0. When it
does, it is one constant in `api/_lib.ts` — the challenge bytes, the request
proof's byte contract, and the verification rules do not change.

Specs: [`SIWD.md`](../../specs/SIWD.md) · [`API-AUTH.md`](../../specs/API-AUTH.md)
