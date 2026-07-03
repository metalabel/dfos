import { defineConfig } from 'vite';

// no @preact/preset-vite: esbuild's automatic JSX transform targets preact
// directly, which keeps babel (and its supply chain) out of the tree entirely.
// Costs prefresh HMR; plain live-reload is plenty for this app.
export default defineConfig({
  esbuild: {
    jsx: 'automatic',
    jsxImportSource: 'preact',
  },
  build: {
    target: 'es2022',
  },
});
