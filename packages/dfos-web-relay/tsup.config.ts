import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    serve: 'src/serve.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  splitting: true,
  target: 'es2022',
});
