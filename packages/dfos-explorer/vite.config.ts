import { defineConfig, type Plugin, type ViteDevServer } from 'vite';

// no @preact/preset-vite: esbuild's automatic JSX transform targets preact
// directly, which keeps babel (and its supply chain) out of the tree entirely.
// Costs prefresh HMR; plain live-reload is plenty for this app.

// -----------------------------------------------------------------------------
// DEV /api — run the REAL handlers, not a stub
//
// In production Vercel serves `api/*.ts` as functions. `vite dev` knows nothing
// about that, so a request the app actually makes — `/api/binding?host=x.com` —
// used to fall through to Vite's own file server, which tried to transform
// `api/binding.ts` as a browser module and died with
// `[plugin:vite:esbuild] Invalid loader value: "com"` (the `?host=…` query read
// as the file extension). The failure surfaced as a full-screen error overlay
// that swallows pointer events, so the domain view was undebuggable locally.
//
// The fix loads the handler THROUGH Vite (so it is the same TypeScript, with the
// same `./wellknown.js` specifier resolving to the `.ts` source) and adapts
// Node's req/res to the three-method shape `api/*.ts` declares. Dev therefore
// exercises the production code path — a stub would only hide drift.
// -----------------------------------------------------------------------------

/** The minimal response surface the api/ handlers use (they carry no @vercel/node). */
interface NodeishResponse {
  status(code: number): NodeishResponse;
  setHeader(name: string, value: string): void;
  json(body: unknown): void;
}

type ApiHandler = (
  req: {
    method?: string | undefined;
    query?: Record<string, string | string[]> | undefined;
    url?: string | undefined;
  },
  res: NodeishResponse,
) => Promise<void>;

/** `/api/binding` → `api/binding.ts`. Anything else is not ours to serve. */
const ROUTES: Record<string, string> = {
  '/api/binding': '/api/binding.ts',
  '/api/wellknown': '/api/wellknown.ts',
};

const devApi = (): Plugin => ({
  name: 'dfos-dev-api',
  // registered in the hook BODY, so it runs BEFORE Vite's own middlewares —
  // which is the whole point: the transform middleware is what was crashing
  configureServer(server: ViteDevServer) {
    server.middlewares.use((req, res, next) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const modulePath = ROUTES[url.pathname];
      if (!modulePath) {
        next();
        return;
      }

      void (async () => {
        try {
          const mod = await server.ssrLoadModule(modulePath);
          const handler = mod.default as ApiHandler;
          const query: Record<string, string | string[]> = {};
          for (const key of new Set(url.searchParams.keys())) {
            const all = url.searchParams.getAll(key);
            query[key] = all.length > 1 ? all : (all[0] as string);
          }
          const shim: NodeishResponse = {
            status(code) {
              res.statusCode = code;
              return shim;
            },
            setHeader(name, value) {
              res.setHeader(name, value);
            },
            json(body) {
              if (!res.getHeader('content-type')) res.setHeader('content-type', 'application/json');
              res.end(JSON.stringify(body));
            },
          };
          await handler({ method: req.method, query, url: req.url }, shim);
        } catch (e) {
          // a dev-time failure is reported AS a failure, in the transport, not
          // dressed up as an envelope the client would read as a real verdict
          res.statusCode = 500;
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify({ error: 'dev api handler failed', detail: String(e) }));
        }
      })();
    });
  },
});

export default defineConfig({
  plugins: [devApi()],
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'preact',
  },
  build: {
    target: 'es2022',
  },
});
