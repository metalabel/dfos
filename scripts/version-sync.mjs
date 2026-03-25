#!/usr/bin/env node

/**
 * Propagate the root package.json version to all published (non-private)
 * workspace packages. Run via: pnpm version:sync
 */
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rootPkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const version = rootPkg.version;

const out = execSync('pnpm -r --json list --depth -1', { cwd: root });
const packages = JSON.parse(out);

let changed = 0;
for (const pkg of packages) {
  if (pkg.private || pkg.path === root) continue;
  const pkgPath = resolve(pkg.path, 'package.json');
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));
  if (pkgJson.version === version) continue;
  pkgJson.version = version;
  writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + '\n');
  console.log(`  ${pkgJson.name} → ${version}`);
  changed++;
}

if (changed === 0) {
  console.log(`All packages already at ${version}`);
} else {
  console.log(`\nSynced ${changed} package(s) to ${version}`);
}
