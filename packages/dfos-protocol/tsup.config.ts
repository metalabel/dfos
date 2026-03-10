import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'crypto/index': 'src/crypto/index.ts',
    'chain/index': 'src/chain/index.ts',
    'registry/index': 'src/registry/index.ts',
  },
  format: 'esm',
  dts: true,
  clean: true,
  target: 'node24',
});
