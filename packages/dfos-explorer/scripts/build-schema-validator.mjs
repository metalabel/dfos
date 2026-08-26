/*

  SCHEMA VALIDATOR CODEGEN — schemas/dfos-app.v1.json -> a plain JS validator

  The explorer validates app description documents against the CANONICAL schema,
  not against a hand-rolled restatement of it. But ajv is a compiler: shipping it
  to the browser costs ~120KB and builds validators with `new Function`, which a
  content-security policy would refuse. So the compile happens HERE, at build
  time, and the browser gets the compiled output — a dependency-free ES module.

  Generated output is COMMITTED (the repo idiom — see scripts/sync-schemas.sh):
  `prebuild` regenerates it so a deployed bundle always matches the schema, and
  tests/schema-validator-drift.spec.ts fails when a schema edit lands without a
  regenerated module.

  Usage:
    node scripts/build-schema-validator.mjs           # write the module
    node scripts/build-schema-validator.mjs --print   # emit to stdout (drift test)

*/

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import addFormats from 'ajv-formats';
import Ajv from 'ajv/dist/2020.js';
import ucs2lengthModule from 'ajv/dist/runtime/ucs2length.js';
import standaloneCode from 'ajv/dist/standalone/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const SCHEMA = resolve(here, '../../../schemas/dfos-app.v1.json');
const OUT = resolve(here, '../src/lib/generated/dfos-app-validator.js');

const BANNER = `/* GENERATED — do not edit.
 * Source: schemas/dfos-app.v1.json
 * Regenerate: pnpm --filter @metalabel/dfos-explorer schema:build
 */
`;

// ajv emits each runtime helper it needs by that helper's own `.code` string,
// which by default is a `require("ajv/…")` — a runtime ajv import, and invalid
// in an ES module besides. `minLength` needs exactly one helper (surrogate-aware
// string length), so we hand ajv an inline source for it and the generated
// module comes out with no imports at all.
const UCS2LENGTH_INLINE = `(str) => {
  const len = str.length;
  let length = 0;
  let pos = 0;
  while (pos < len) {
    length++;
    let value = str.charCodeAt(pos++);
    if (value >= 0xd800 && value <= 0xdbff && pos < len) {
      value = str.charCodeAt(pos);
      if ((value & 0xfc00) === 0xdc00) pos++;
    }
  }
  return length;
}`;

export const generate = () => {
  const schema = JSON.parse(readFileSync(SCHEMA, 'utf-8'));
  const ucs2length = ucs2lengthModule.default ?? ucs2lengthModule;
  ucs2length.code = UCS2LENGTH_INLINE;
  // `uri` is the only format the schema uses. Defining it here as a bare regex
  // — rather than pulling in ajv-formats' table — is what keeps the generated
  // module free of runtime imports: ajv inlines a regex format into the output.
  const ajv = new Ajv({
    strict: true,
    allErrors: true,
    code: { source: true, esm: true, lines: true },
  });
  addFormats(ajv, { mode: 'fast', formats: ['uri'], keywords: false });
  return BANNER + standaloneCode(ajv, ajv.compile(schema));
};

const source = generate();
if (process.argv.includes('--print')) process.stdout.write(source);
else {
  writeFileSync(OUT, source);
  console.log(`generated -> ${OUT.slice(OUT.indexOf('packages/'))}`);
}
