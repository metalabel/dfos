import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
  vite: {
    resolve: {
      alias: {
        '@dfos-protocol': new URL('../dfos-protocol', import.meta.url).pathname,
      },
    },
  },
});
