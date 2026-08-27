import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
  // The standalone DOCUMENT-GATEWAY spec folded into WEB-RELAY (2026-08); the
  // old URL keeps resolving.
  redirects: {
    '/document-gateway': '/web-relay#content-plane--document-gateway',
  },
});
