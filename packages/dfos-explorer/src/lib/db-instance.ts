/*

  DB INSTANCE — one shared local index handle for the app

*/

import { openExplorerDb, type ExplorerDb } from './db';

let dbPromise: Promise<ExplorerDb> | null = null;

export const getDb = (): Promise<ExplorerDb> => (dbPromise ??= openExplorerDb());
