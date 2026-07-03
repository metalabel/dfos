/*

  STORE SUBPATH — @metalabel/dfos-client/store

  `memoryStore()` is the isomorphic default (also re-exported from the root).
  `indexedDbStore()` is the browser-only durable adapter, kept here so importing
  it is an explicit opt-in — node and CLI consumers never touch a DOM dependency.

*/

export { memoryStore } from './memory';
export { indexedDbStore } from './indexeddb';
export type { Store } from '../types';
