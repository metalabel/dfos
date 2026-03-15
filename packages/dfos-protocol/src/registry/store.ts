/*

  IN-MEMORY CHAIN STORE

  Reference implementation of chain storage with linear enforcement.
  Accept same or longer chain, reject forks.

*/

import type { OperationEntry } from './schemas';

export interface StoredChain {
  /** Ordered array of operations, genesis first */
  operations: OperationEntry[];
}

export class ChainStore {
  private identityChains = new Map<string, StoredChain>();
  private contentChains = new Map<string, StoredChain>();
  // --- identityChains ---

  getIdentityChain(did: string): StoredChain | undefined {
    return this.identityChains.get(did);
  }

  /**
   * Submit an identity chain. Returns 'accepted' | 'noop' | 'conflict'.
   * - accepted: chain was stored or extended
   * - noop: submitted chain is same as or prefix of stored chain
   * - conflict: submitted chain diverges from stored chain (fork)
   */
  submitIdentityChain(did: string, operations: OperationEntry[]): 'accepted' | 'noop' | 'conflict' {
    return this.submitChain(this.identityChains, did, operations);
  }

  // --- contentChains ---

  getContentChain(contentId: string): StoredChain | undefined {
    return this.contentChains.get(contentId);
  }

  submitContentChain(
    contentId: string,
    operations: OperationEntry[],
  ): 'accepted' | 'noop' | 'conflict' {
    return this.submitChain(this.contentChains, contentId, operations);
  }

  // --- operations (lookup across all chains) ---

  getOperation(cid: string): OperationEntry | undefined {
    for (const chain of this.identityChains.values()) {
      const op = chain.operations.find((o) => o.cid === cid);
      if (op) return op;
    }
    for (const chain of this.contentChains.values()) {
      const op = chain.operations.find((o) => o.cid === cid);
      if (op) return op;
    }
    return undefined;
  }

  // --- shared chain submission logic ---

  private submitChain(
    store: Map<string, StoredChain>,
    id: string,
    operations: OperationEntry[],
  ): 'accepted' | 'noop' | 'conflict' {
    const existing = store.get(id);

    if (!existing) {
      store.set(id, { operations });
      return 'accepted';
    }

    // check if submitted chain is same or prefix of stored
    if (operations.length <= existing.operations.length) {
      for (let i = 0; i < operations.length; i++) {
        if (operations[i]!.cid !== existing.operations[i]!.cid) {
          return 'conflict';
        }
      }
      return 'noop';
    }

    // submitted chain is longer — verify it extends the stored chain
    for (let i = 0; i < existing.operations.length; i++) {
      if (operations[i]!.cid !== existing.operations[i]!.cid) {
        return 'conflict';
      }
    }

    // accept the extension
    store.set(id, { operations });
    return 'accepted';
  }
}
