/*

  INDEXEDDB STORE

  The only heavy, browser-only adapter — quarantined behind the `./store`
  subpath so node/CLI consumers never pull a browser dependency. Durable across
  reloads: an explorer that has synced tens of thousands of ops keeps its
  verified prefix and only verifies forward on the next visit.

  Typed against a minimal structural view of the IndexedDB surface we use, so the
  package compiles without pulling the DOM lib into the shared tsconfig.

*/

import type { Store } from '../types';

// --- minimal structural IndexedDB shims (only what we touch) -----------------

interface IdbRequest<T> {
  result: T;
  error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}

interface IdbObjectStore {
  get(key: string): IdbRequest<unknown>;
  put(value: unknown, key: string): IdbRequest<unknown>;
}

interface IdbTransaction {
  objectStore(name: string): IdbObjectStore;
}

interface IdbDatabase {
  objectStoreNames: { contains(name: string): boolean };
  createObjectStore(name: string): unknown;
  transaction(store: string, mode: 'readonly' | 'readwrite'): IdbTransaction;
}

interface IdbOpenRequest extends IdbRequest<IdbDatabase> {
  onupgradeneeded: (() => void) | null;
}

interface IdbFactory {
  open(name: string, version?: number): IdbOpenRequest;
}

const STORE_NAME = 'dfos-cache';

const getFactory = (): IdbFactory => {
  const idb = (globalThis as { indexedDB?: IdbFactory }).indexedDB;
  if (!idb) throw new Error('indexedDbStore requires a browser IndexedDB environment');
  return idb;
};

const promisify = <T>(req: IdbRequest<T>): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb request failed'));
  });

/**
 * A durable, browser-only cache backed by a single IndexedDB object store.
 * `dbName` defaults to `dfos-client`; pass a distinct name to isolate caches
 * (e.g. per relay set) since a relay switch is a new client.
 */
export const indexedDbStore = (dbName = 'dfos-client'): Store => {
  let dbPromise: Promise<IdbDatabase> | undefined;

  const open = (): Promise<IdbDatabase> => {
    if (!dbPromise) {
      dbPromise = new Promise<IdbDatabase>((resolve, reject) => {
        const req = getFactory().open(dbName, 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error ?? new Error('failed to open indexeddb'));
      });
    }
    return dbPromise;
  };

  return {
    async get(key: string): Promise<unknown | undefined> {
      const db = await open();
      const store = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME);
      const value = await promisify(store.get(key));
      return value ?? undefined;
    },
    async set(key: string, value: unknown): Promise<void> {
      const db = await open();
      const store = db.transaction(STORE_NAME, 'readwrite').objectStore(STORE_NAME);
      await promisify(store.put(value, key));
    },
  };
};
