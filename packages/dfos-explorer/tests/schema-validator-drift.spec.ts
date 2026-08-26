/**
 * Generated-validator drift guard.
 *
 * src/lib/generated/dfos-app-validator.js is compiled from the canonical
 * schemas/dfos-app.v1.json at build time and committed (the repo idiom — see
 * scripts/sync-schemas.sh, whose embedded copies are guarded the same way). A
 * schema edit that lands without a regenerated module means the explorer
 * validates against a definition the schema no longer states, so this fails
 * loudly and names the fix.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const pkg = resolve(import.meta.dirname, '..');
const committed = resolve(pkg, 'src/lib/generated/dfos-app-validator.js');

/** Regenerate through the script's own CLI — the exact path `prebuild` takes. */
const regenerate = (): string =>
  execFileSync('node', ['scripts/build-schema-validator.mjs', '--print'], {
    cwd: pkg,
    encoding: 'utf-8',
  });

describe('generated dfos-app validator', () => {
  it('matches the canonical schema', () => {
    expect(
      readFileSync(committed, 'utf-8'),
      'run: pnpm --filter @metalabel/dfos-explorer schema:build',
    ).toBe(regenerate());
  });

  it('carries no runtime imports — the bundle must not pull ajv in', () => {
    const source = readFileSync(committed, 'utf-8');
    expect(source).not.toMatch(/\brequire\s*\(/);
    expect(source).not.toMatch(/^import\s/m);
  });
});
