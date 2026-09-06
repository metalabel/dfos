import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
  // Folded specs keep their old URLs resolving. DOCUMENT-GATEWAY folded into
  // WEB-RELAY (2026-08). KEY-PROOF and EXTENSIONS folded into PROTOCOL, and
  // CREDITS into CONTENT-MODEL (2026-09).
  redirects: {
    '/document-gateway': '/web-relay#content-plane--document-gateway',
    '/key-proof': '/spec#key-possession',
    '/extensions': '/spec#extension-registry',
    '/credits': '/content-model#credits',
  },
});
