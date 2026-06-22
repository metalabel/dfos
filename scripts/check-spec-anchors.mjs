#!/usr/bin/env node
// Guards against brittle line-number cross-references in the specs.
//
// References like `specs/PROTOCOL.md:449` rot silently the moment any spec is
// edited above the cited line — the pointer keeps resolving, just to the wrong
// place. Cite the file plus its section title instead (e.g. PROTOCOL.md
// "Signature Verification Profile", `specs/PROTOCOL.md`), which survives edits.
//
// Fails CI if any `specs/<FILE>.md:<N>` line anchor reappears.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SPECS_DIR = 'specs';
const LINE_ANCHOR = /[A-Za-z0-9_./-]+\.md:\d+/g;

const offenders = [];
for (const name of readdirSync(SPECS_DIR)) {
  if (!name.endsWith('.md')) continue;
  const path = join(SPECS_DIR, name);
  const lines = readFileSync(path, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const hits = line.match(LINE_ANCHOR);
    if (hits) offenders.push({ path, line: i + 1, hits });
  });
}

if (offenders.length > 0) {
  console.error('Brittle line-number spec anchors found (these rot on any spec edit):\n');
  for (const o of offenders) {
    console.error(`  ${o.path}:${o.line}  →  ${o.hits.join(', ')}`);
  }
  console.error(
    '\nCite the file + section title instead (e.g. `specs/PROTOCOL.md` "Section Title"),' +
      '\nnot a line number. Drop the `:<N>` suffix.',
  );
  process.exit(1);
}

console.log('spec anchors OK — no brittle line-number cross-references.');
