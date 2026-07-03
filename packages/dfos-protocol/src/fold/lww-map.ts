/*

  CANONICAL FOLD — GENERIC LWW-MAP

  A last-write-wins map folded from an ordered stream of deltas. `set` writes a
  key; `remove` deletes it; the last delta touching a key (in the given order)
  wins. Positional last-wins — replaying `set`/`remove` in order is the whole
  semantics, so a `remove` followed later by a `set` re-adds the key, and a
  `set` followed later by a `remove` drops it.

  Pure — a fold over an in-order sequence. The ordering is the caller's job
  (see `linearize`); this module does not sort.

*/

/** A single LWW-Map delta over key `key`. */
export type LwwDelta<V = unknown> =
  | { readonly op: 'set'; readonly key: string; readonly value: V }
  | { readonly op: 'remove'; readonly key: string };

/**
 * Fold an ordered sequence of deltas into a Map. Deltas are applied in the
 * order given — the caller linearizes first. Insertion order of the returned
 * Map reflects last-set position, but equality is by (key → value) content, so
 * two ingest orders that linearize identically produce equal maps.
 */
export const foldLwwMap = <V = unknown>(deltas: Iterable<LwwDelta<V>>): Map<string, V> => {
  const map = new Map<string, V>();
  for (const delta of deltas) {
    if (delta.op === 'set') map.set(delta.key, delta.value);
    else map.delete(delta.key);
  }
  return map;
};
