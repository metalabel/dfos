/*

  MEMORY STORE

  The default cache: a plain in-process Map. Zero dependencies, isomorphic,
  discarded on reload. Good for a CLI run, a server request, or a page session.

*/

import type { Store } from '../types';

export const memoryStore = (): Store => {
  const map = new Map<string, unknown>();
  return {
    async get(key: string): Promise<unknown | undefined> {
      return map.get(key);
    },
    async set(key: string, value: unknown): Promise<void> {
      map.set(key, value);
    },
  };
};
