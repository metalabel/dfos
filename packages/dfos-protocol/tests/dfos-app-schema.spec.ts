/**
 * DFOS app JSON Schema validation tests — ensures the schema compiles,
 * accepts every valid fixture, rejects every invalid fixture, and covers the live demo document.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import addFormats from 'ajv-formats';
import Ajv from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

const schema = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../../../schemas/dfos-app.v1.json'), 'utf-8'),
);
const fixturesDir = resolve(import.meta.dirname, '../../../schemas/dfos-app.v1.fixtures');
const ajv = new Ajv({ strict: true, allErrors: true });
addFormats(ajv);

// ---------------------------------------------------------------------------
// Schema compilation
// ---------------------------------------------------------------------------

describe('dfos-app schema compilation', () => {
  it('dfos-app.v1.json compiles', () => {
    expect(() => ajv.compile(schema)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Fixture corpus
// ---------------------------------------------------------------------------

describe('dfos-app schema validation', () => {
  const validate = ajv.compile(schema);

  describe('valid fixtures', () => {
    const dir = resolve(fixturesDir, 'valid');
    const files = readdirSync(dir).sort();
    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      it(file, () => {
        const document = JSON.parse(readFileSync(resolve(dir, file), 'utf-8'));
        expect(validate(document), JSON.stringify(validate.errors, null, 2)).toBe(true);
      });
    }
  });

  describe('invalid fixtures', () => {
    const dir = resolve(fixturesDir, 'invalid');
    const files = readdirSync(dir).sort();
    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      it(file, () => {
        const document = JSON.parse(readFileSync(resolve(dir, file), 'utf-8'));
        expect(validate(document)).toBe(false);
      });
    }
  });

  it('accepts the live SIWD demo document', () => {
    const document = JSON.parse(
      readFileSync(
        resolve(
          import.meta.dirname,
          '../../../examples/siwd-demo/public/.well-known/dfos-app.json',
        ),
        'utf-8',
      ),
    );
    expect(validate(document), JSON.stringify(validate.errors, null, 2)).toBe(true);
  });
});
