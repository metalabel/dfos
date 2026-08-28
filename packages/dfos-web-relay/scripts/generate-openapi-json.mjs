#!/usr/bin/env node

/**
 * openapi.yaml → openapi.json.
 *
 * THE YAML IS THE SOURCE; the JSON is a committed derived artifact, and the two
 * are byte-compared by tests/openapi.spec.ts so an edit that skips this script
 * fails CI rather than shipping a stale document.
 *
 * WHY A COMMITTED JSON AND NOT A RUNTIME READ: the document is served by
 * `createRelay({ openapi: { document } })`, and the consumers that serve it are
 * bundled (Lambda, Workers) with no yaml loader and no filesystem assets. A JSON
 * artifact behind a real `exports` entry is importable from every one of those
 * runtimes; an fs-read of the yaml is importable from none.
 *
 * Run via: pnpm --filter @metalabel/dfos-web-relay gen:openapi (also the first
 * half of that package's `build`, and re-run by scripts/version-sync.mjs).
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const document = parse(readFileSync(resolve(packageRoot, 'openapi.yaml'), 'utf8'));
const target = resolve(packageRoot, 'openapi.json');

writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`);
console.log(`  openapi.yaml → openapi.json (${document.info.version})`);
