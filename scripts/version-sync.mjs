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

// Rewrite any range that targets a workspace @metalabel/* package to track the
// current version. We keep the published packages in lockstep (identical
// versions), so a caret floor pinned to the live version always matches the
// paired release. Skip `workspace:*` specifiers — pnpm resolves those at publish
// time and they must not be rewritten to a concrete range here.
function syncMetalabelRanges(deps) {
  if (!deps) return false;
  let touched = false;
  for (const name of Object.keys(deps)) {
    if (!name.startsWith('@metalabel/')) continue;
    if (deps[name].startsWith('workspace:')) continue;
    const next = `^${version}`;
    if (deps[name] !== next) {
      deps[name] = next;
      touched = true;
    }
  }
  return touched;
}

let changed = 0;
for (const pkg of packages) {
  if (pkg.path === root) continue;
  const pkgPath = resolve(pkg.path, 'package.json');
  const pkgJson = JSON.parse(readFileSync(pkgPath, 'utf8'));

  let touched = false;
  // private packages are excluded from the version bump (they don't publish),
  // but their @metalabel/* ranges still sync below — otherwise a pre-release
  // package's peer ranges rot against the moving lockstep version.
  if (!pkgJson.private && pkgJson.version !== version) {
    pkgJson.version = version;
    touched = true;
  }
  // keep @metalabel/* dependency, peerDependency, and optionalDependency ranges
  // aligned with the version so a matched pair always installs (no ERESOLVE).
  for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    if (syncMetalabelRanges(pkgJson[field])) touched = true;
  }

  if (!touched) continue;
  writeFileSync(pkgPath, JSON.stringify(pkgJson, null, 2) + '\n');
  console.log(`  ${pkgJson.name} → ${version}`);
  changed++;
}

const openapiPath = resolve(root, 'packages/dfos-web-relay/openapi.yaml');
const openapiText = readFileSync(openapiPath, 'utf8');
const nextOpenapiText = openapiText.replace(
  /(title: DFOS Web Relay\n  version: ).*/,
  `$1${version}`,
);

if (nextOpenapiText !== openapiText) {
  writeFileSync(openapiPath, nextOpenapiText);
  console.log(`  dfos-web-relay/openapi.yaml → ${version}`);
  changed++;
}

if (changed === 0) {
  console.log(`All packages already at ${version}`);
} else {
  console.log(`\nSynced ${changed} package(s) to ${version}`);
}
