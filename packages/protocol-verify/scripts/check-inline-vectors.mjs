#!/usr/bin/env node
/**
 * Drift tripwire for the shared vector artifact.
 *
 * vectors.json is the one place the five standalone suites read their expected
 * values from. Nothing stops a future edit from pasting a value back inline —
 * and that is exactly how the services-genesis and content-create vectors
 * drifted apart before: two self-consistent sets, five green suites, no signal.
 *
 * So: every expected value in vectors.json 25 characters or longer must not
 * appear as a literal in any suite's source. The seed phrases are exempt —
 * they are the vectors' INPUT, deliberately literal in every suite, which is
 * what makes each one reproducible from nothing but the spec's fixed seeds.
 *
 * Run: node packages/protocol-verify/scripts/check-inline-vectors.mjs
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/** Values shorter than this are protocol constants (`did:dfos:identity-op`), not vectors. */
const MIN_LENGTH = 25;

/** Vector fields that are inputs, not expected values. */
const INPUT_FIELDS = new Set(['seedPhrase']);

const SUITES = [
  'go/main_test.go',
  'python/verify_protocol.py',
  'rust/src/main.rs',
  'swift/Tests/VerifyProtocolTests/VerifyProtocolTests.swift',
  'ts/verify.ts',
];

const root = new URL('../', import.meta.url);
const vectors = JSON.parse(readFileSync(new URL('vectors.json', root), 'utf-8'));

/** Every expected string value in the artifact, with the vector path that owns it. */
const expected = new Map();
const collect = (path, value) => {
  if (typeof value === 'string') {
    if (value.length >= MIN_LENGTH && !expected.has(value)) expected.set(value, path);
  } else if (Array.isArray(value)) {
    value.forEach((entry, index) => collect(`${path}.${index}`, entry));
  } else if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) collect(`${path}.${key}`, entry);
  }
};
for (const vector of vectors.vectors) {
  for (const [field, value] of Object.entries(vector.values)) {
    if (INPUT_FIELDS.has(field)) continue;
    collect(`${vector.id}.${field}`, value);
  }
}

const findings = [];
for (const suite of SUITES) {
  const source = readFileSync(new URL(suite, root), 'utf-8');
  for (const [value, path] of expected) {
    if (source.includes(value)) findings.push({ suite, path, value });
  }
}

if (findings.length > 0) {
  console.error(
    `${findings.length} vector value(s) hardcoded in a suite instead of read from vectors.json:\n`,
  );
  for (const { suite, path, value } of findings) {
    console.error(`  ${suite}: ${path} — ${value.slice(0, 60)}${value.length > 60 ? '…' : ''}`);
  }
  console.error('\nRead the value with that suite’s vector accessor instead.');
  process.exit(1);
}

console.log(
  `OK: ${expected.size} shared vector values, none hardcoded across ${SUITES.length} suites.`,
);
console.log(`  ${fileURLToPath(new URL('vectors.json', root))}`);
