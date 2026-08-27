# Sign In With DFOS — demo relying party

A complete Sign In With DFOS login — challenge minted server-side, JWS verified
server-side, session cookie granted server-side — plus four live
credential-gated API calls that run the moment you are signed in. One static
page, ten serverless functions, no database beyond a small key-value store, and
no SDK beyond the DFOS packages installed from npm like any third party would.
Deployed at <https://dfos-siwd-demo.vercel.app>.

Integrating sign-in into your own app? The step-by-step guide is at
<https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup> — this demo is
its worked example. The security model the demo exercises — why every request
is signed, proof-of-possession, the confused-deputy discipline for a signing
backend — is covered in
[Why signed requests](https://docs.dfos.com/docs/developers/sign-in-with-dfos/why-signed-requests).

**You pick what to ask for before you sign in.** `identity` proves who you are
and returns nothing else. `read:profile read:email read:memberships` also
returns a **credential** — a durable, audience-bound authorization the app
keeps and presents to the DFOS API. Both run side by side so the difference is
something you can watch rather than read about.

| Option                                     | Returns                | `client_did` | Needs                        |
| ------------------------------------------ | ---------------------- | ------------ | ---------------------------- |
| `identity`                                 | a signed challenge     | not sent     | `SESSION_SECRET`             |
| `read:profile read:email read:memberships` | …plus a **credential** | **required** | …plus an app key and a store |

## Endpoints

| Endpoint                  | What it does                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| `GET /config`             | What this deployment can serve, and why not when it cannot                                              |
| `POST /login`             | Mints the challenge and returns the `/authorize` URL                                                    |
| `POST /verify`            | Runs `verifySiwd` against a relay, verifies any returned credential, grants the session                 |
| `GET /me`                 | Reads the session cookie back — the one source the signed-in view renders from                          |
| `POST /profile`           | Signs one request proof and calls `GET /v1/profile`, avatar included. Called on arrival, not on a click |
| `POST /memberships`       | Signs one request proof and calls `GET /v1/memberships`. Called on arrival too                          |
| `POST /group-memberships` | The same, for `GET /v1/group-memberships` — the second walk the page correlates against the first       |
| `POST /credential`        | The same, for `GET /v1/credential` — the credential describing itself, under no scope                   |
| `POST /check`             | Fills one path segment of `GET /v1/membership/{space}` or `GET /v1/group-membership/{group}`. On demand |
| `POST /logout`            | Expires the session and drops the stored credential                                                     |

Verification lives in `api/verify.ts`, because that is where the session is
granted. The only network hop is to a public relay, to resolve the signer's
identity chain — the relay is untrusted; the crypto is what convinces us.
Replay prevention follows
[SIWD § Replay prevention](https://protocol.dfos.com/siwd#replay-prevention);
each gated route signs one fixed request via the seam in `api/_gated.ts`
(`api/profile.ts` is the same seam written out long-form), per
[API-AUTH](https://protocol.dfos.com/api-auth).

## Configuration

| Variable               | Needed for     | What it is                                                                |
| ---------------------- | -------------- | ------------------------------------------------------------------------- |
| `SESSION_SECRET`       | everything     | The key both cookie seals use. 32+ characters.                            |
| `DFOS_APP_KID`         | the credential | The DID URL of a current key of the app's own identity.                   |
| `DFOS_APP_PRIVATE_KEY` | the credential | That key's Ed25519 secret, 43 base64url characters.                       |
| `KV_REST_API_URL`      | the credential | A Redis-compatible REST endpoint, for challenge state and the credential. |
| `KV_REST_API_TOKEN`    | the credential | Its bearer token.                                                         |

Only `SESSION_SECRET` is required. Without the other four the identity scope
works as normal and the credential scope renders disabled, with the reason next
to it — the page asks `/api/config` at boot.

Generate a `SESSION_SECRET`:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

`DFOS_APP_KID` is the full DID URL — `did:dfos:<id>#key_<id>`. Its DID half
must match the `client_did` in `public/.well-known/dfos-app.json`.
`/api/config` reports the **public** key derived from `DFOS_APP_PRIVATE_KEY` —
compare it against `dfos identity keys` to catch a mismatched secret early.

The store is any Upstash-REST-compatible Redis (`UPSTASH_REDIS_REST_URL` /
`UPSTASH_REDIS_REST_TOKEN` are accepted as aliases). On Vercel, use the
**Upstash for Redis** marketplace integration (`vc i upstash/upstash-kv`) —
not the Redis Cloud product on Vercel's storage screen, which exposes no REST
endpoint.

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

There is no developer portal and no client secret: serving this file over https
from the domain you control **is** the registration, and `redirect_uris` is an
exact-match allowlist, trailing slash included. See
[SIWD § Redirect URI validation](https://protocol.dfos.com/siwd#redirect-uri-validation-profile-a)
and [SIWD § chain carriage](https://protocol.dfos.com/siwd#identity_chain--chain-carriage).
The CLI writes the identity members for you:
`dfos identity well-known --patch public/.well-known/dfos-app.json`.

## Fork it

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https%3A%2F%2Fgithub.com%2Fmetalabel%2Fdfos%2Ftree%2Fmain%2Fexamples%2Fsiwd-demo&project-name=dfos-siwd-demo&repository-name=dfos-siwd-demo&env=SESSION_SECRET&envDescription=Signs%20login%20sessions%20-%20set%20to%20any%20long%20random%20string)

That clones this directory into your own repo, prompts for `SESSION_SECRET`,
and deploys it. Then make one edit — put your deployment's origin in
`redirect_uris`, exactly, with the trailing slash — commit, redeploy. If you
forget, the boot self-check renders the exact string it needs to see. Update
`name` too; it is what your users read at consent.

That gets you the identity scope. For the credential set, three more steps:

1. **Give the app an identity and a delegate key.** The controller key stays in
   your OS keychain; the server gets its own auth key, so a compromised
   deployment is a revoke-and-re-add, never a new identity.

   ```sh
   dfos identity create --name my-app
   DFOS_NO_KEYCHAIN=1 dfos identity device-pubkey --identity my-app --json
   dfos identity add-key --auth-key --id key_<from above> --pubkey z6Mk<from above>
   ```

   The DID goes in `client_did`; `DFOS_APP_KID` is `did:dfos:<id>#key_<id>` for
   the new key. Convert the seed file to the env var and store it:

   ```sh
   node -e "console.log(Buffer.from(require('fs').readFileSync(process.argv[1],'utf8').trim(),'hex').toString('base64url'))" \
     ~/.dfos/keys/<did>__<key> \
     | vercel env add DFOS_APP_PRIVATE_KEY production --sensitive
   ```

   Then carry the chain in the well-known:
   `dfos identity well-known --patch public/.well-known/dfos-app.json`, and
   commit the file — it is how a host that has never seen your identity
   verifies and ingests it at first consent.

2. **Add the store** — the Upstash for Redis marketplace integration, Free
   plan, connected to your project. It writes `KV_REST_API_URL` and
   `KV_REST_API_TOKEN` for you.

3. **Redeploy, then check `/api/config`.** Environment changes do not touch
   running functions until the next deployment. Diff the reported public key
   against `dfos identity keys my-app` before anything is clicked.

## Run it locally

```sh
npm install
npm run dev
```

The identity flow works locally with no well-known file at all:
`http://localhost:5173/` is accepted for `scope=identity` under SIWD's
loopback tier. The credential scope cannot run on a loopback host in this demo
— it is a hosted web relying party and does not implement the
[loopback credential tier](https://protocol.dfos.com/siwd#loopback-clients) —
so exercising the credential scope means deploying to a domain.

There is no `vercel` CLI in the loop: `vite.config.ts` mounts the same handler
files as dev-server middleware, so nothing is reimplemented and nothing can
drift.

## Links

- [Setup guide](https://docs.dfos.com/docs/developers/sign-in-with-dfos/setup) — integrate sign-in into your own app
- [Why signed requests](https://docs.dfos.com/docs/developers/sign-in-with-dfos/why-signed-requests) — the security model this demo exercises
- [SIWD specification](https://protocol.dfos.com/siwd) · [API-AUTH specification](https://protocol.dfos.com/api-auth)
- [`@metalabel/dfos-client`](../../packages/dfos-client) — the relying-party kit this demo consumes
- [Chain explorer](https://explore.dfos.com) — inspect any identity chain, this app's included
