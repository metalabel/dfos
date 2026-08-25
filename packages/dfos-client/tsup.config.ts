import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'api-auth': 'src/api-auth.ts',
    siwd: 'src/siwd.ts',
    'store/index': 'src/store/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  outDir: 'dist',
  splitting: true,
  target: 'es2022',
});
