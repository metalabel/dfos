import sitemap from '@astrojs/sitemap';
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://protocol.dfos.com',
  integrations: [sitemap()],
  // Browser floor: Safari 16.4+ / Chrome 111+ / Firefox 114+ (decided 2026-09-08).
  //
  // Vite 8 minifies CSS with Lightning CSS, which rewrites `(max-width:768px)`
  // into Media Queries Level 4 range syntax `(width<=768px)` the moment every
  // targeted browser supports it. Safari 16.4 is exactly that threshold, and
  // Vite's own default target ('baseline-widely-available') sits right on it —
  // so leaving this unset makes our public browser floor an accident of Vite's
  // default, free to move under us whenever Vite advances its baseline. The list
  // below is that default, written down, so the floor is a decision this repo
  // owns and a future Vite major cannot raise it silently.
  //
  // `build.cssTarget` is the key that governs the minifier: it takes precedence
  // over `css.lightningcss.targets`, which has no effect on the minification pass.
  vite: {
    build: {
      cssTarget: ['chrome111', 'edge111', 'firefox114', 'safari16.4', 'ios16.4'],
    },
  },
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
