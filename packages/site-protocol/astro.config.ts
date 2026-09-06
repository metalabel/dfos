import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
  // Folded specs keep their old URLs resolving. KEY-PROOF and EXTENSIONS folded
  // into PROTOCOL, and CREDITS into CONTENT-MODEL (2026-09). RELAY-CONTRACT,
  // WEB-RELAY, DOCUMENT-GATEWAY, and SIGNING folded into RELAY; SIWD, API-AUTH,
  // and ORIGIN-BINDING into INTEGRATIONS (2026-09). THREAT-MODEL and
  // CONFORMANCE folded into GUARANTEES (2026-09).
  redirects: {
    '/key-proof': '/spec#key-possession',
    '/extensions': '/spec#extension-registry',
    '/credits': '/content-model#credits',
    '/relay-contract': '/relay',
    '/web-relay': '/relay',
    '/document-gateway': '/relay#content-plane-capability-content',
    '/signing': '/relay#signing-mailbox-capability-signing',
    '/siwd': '/integrations#sign-in',
    '/api-auth': '/integrations#api-authentication',
    '/origin-binding': '/integrations#origin-binding',
    '/threat-model': '/guarantees',
    '/conformance': '/guarantees#conformance',
  },
});
