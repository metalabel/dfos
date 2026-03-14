import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
});
