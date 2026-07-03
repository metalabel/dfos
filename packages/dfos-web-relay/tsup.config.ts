import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    serve: 'src/serve.ts',
    'peer-client': 'src/peer-client.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  splitting: true,
  target: 'es2022',
});
