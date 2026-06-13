import { describe, expect, it } from 'vitest';
import { z } from 'zod';

/*

  WP-5 — strict createdAt grammar parity (TS twin)

  The strict gate is TS z.iso.datetime({offset:false, precision:3}) vs the Go
  twin's time.Parse("2006-01-02T15:04:05.000Z") — fixed 3-digit fraction +
  literal Z, NOT RFC3339Nano. These 22 cases are asserted byte-for-byte
  identical in the Go twin (dfos-protocol-go/timestamp_grammar_test.go). Keep
  the two vector lists in lockstep.

*/

const Iso8601Strict = z.iso.datetime({ offset: false, precision: 3 });

const vectors: { input: string; valid: boolean }[] = [
  { input: '2026-03-07T00:00:00.000Z', valid: true }, // canonical
  { input: '2026-03-07T00:00:00Z', valid: false }, // no fraction
  { input: '2026-03-07T00:00:00.00Z', valid: false }, // 2-digit fraction
  { input: '2026-03-07T00:00:00.0000Z', valid: false }, // 4-digit fraction
  { input: '2026-03-07T00:00:00.000+00:00', valid: false }, // numeric offset
  { input: '2026-03-07T00:00:00.000', valid: false }, // missing Z
  { input: '2026-03-07T00:00:00.000z', valid: false }, // lowercase z
  { input: '2026-13-07T00:00:00.000Z', valid: false }, // month 13
  { input: '2026-02-30T00:00:00.000Z', valid: false }, // Feb 30
  { input: '2026-03-07T24:00:00.000Z', valid: false }, // hour 24
  { input: '2026-03-07T00:60:00.000Z', valid: false }, // minute 60
  { input: '2026-03-07T00:00:60.000Z', valid: false }, // second 60 (non leap-second)
  { input: '2026-03-07T00:00:00.000 Z', valid: false }, // space before Z
  { input: '2026-3-7T00:00:00.000Z', valid: false }, // non-zero-padded
  { input: '0000-01-01T00:00:00.000Z', valid: true }, // year 0
  { input: '9999-12-31T23:59:59.999Z', valid: true }, // year 9999
  { input: '2024-02-29T00:00:00.000Z', valid: true }, // valid leap day
  { input: '2023-02-29T00:00:00.000Z', valid: false }, // invalid leap day
  { input: '2026-03-07T00:00:00.000Z ', valid: false }, // trailing space
  { input: ' 2026-03-07T00:00:00.000Z', valid: false }, // leading space
  { input: '2026-03-07 00:00:00.000Z', valid: false }, // space instead of T
  { input: '2026-03-07T23:59:60.000Z', valid: false }, // leap second
];

describe('strict createdAt grammar (Go twin parity)', () => {
  it.each(vectors)('$input → valid=$valid', ({ input, valid }) => {
    expect(Iso8601Strict.safeParse(input).success).toBe(valid);
  });
});
