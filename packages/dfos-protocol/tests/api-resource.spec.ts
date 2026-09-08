/*

  THE `api:` RESOURCE HIERARCHY, from the fixture both twins read.

  Every row of `examples/api-resource-coverage.json` is a test here and a subtest
  in the Go delegation suite. Neither side inlines a row: a coverage rule that
  moved in one language and not the other is exactly the divergence a shared
  answer sheet makes visible.

*/

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  apiResourceCovers,
  isAttenuated,
  matchesResource,
  parseApiResource,
} from '../src/credentials';
import type { Attenuation } from '../src/credentials';

interface CoverageFixture {
  parse: { resource: string; valid: boolean; host?: string; spaceId?: string | null }[];
  covers: { entry: string; required: string; covers: boolean; note?: string }[];
  attenuation: { note: string; parent: Attenuation[]; child: Attenuation[]; valid: boolean }[];
  matches: {
    note: string;
    att: Attenuation[];
    resource: string;
    action: string;
    covers: boolean;
  }[];
}

const fixture = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', 'examples', 'api-resource-coverage.json'), 'utf-8'),
) as CoverageFixture;

describe('parseApiResource', () => {
  for (const row of fixture.parse) {
    it(`${row.valid ? 'parses' : 'refuses'} ${row.resource}`, () => {
      const parsed = parseApiResource(row.resource);
      if (!row.valid) {
        expect(parsed).toBeNull();
        return;
      }
      expect(parsed).not.toBeNull();
      expect(parsed?.host).toBe(row.host);
      expect(parsed?.spaceId ?? null).toBe(row.spaceId ?? null);
    });
  }

  it('refuses every non-api: type — the hierarchy is api:-only', () => {
    expect(parseApiResource('chain:*')).toBeNull();
    expect(parseApiResource('mailbox:9ctvrdn9vedda7efetrhcdakfh4cr2k')).toBeNull();
    expect(parseApiResource('api.dfos.com')).toBeNull();
  });
});

describe('apiResourceCovers', () => {
  for (const row of fixture.covers) {
    it(`${row.entry} ${row.covers ? 'covers' : 'does not cover'} ${row.required}`, () => {
      expect(apiResourceCovers(row.entry, row.required)).toBe(row.covers);
    });
  }
});

describe('isAttenuated over api: resources', () => {
  for (const row of fixture.attenuation) {
    it(row.note, () => {
      expect(isAttenuated(row.parent, row.child)).toBe(row.valid);
    });
  }
});

describe('matchesResource over api: resources', () => {
  for (const row of fixture.matches) {
    it(row.note, async () => {
      expect(await matchesResource(row.att, row.resource, row.action)).toBe(row.covers);
    });
  }

  it('leaves chain: and mailbox: matching exactly as they were', async () => {
    const att: Attenuation[] = [
      { resource: 'chain:*', action: 'write' },
      { resource: 'mailbox:9ctvrdn9vedda7efetrhcdakfh4cr2k', action: 'deposit' },
    ];
    expect(await matchesResource(att, 'chain:9ctvrdn9vedda7efetrhcdakfh4cr2k', 'write')).toBe(true);
    expect(await matchesResource(att, 'mailbox:9ctvrdn9vedda7efetrhcdakfh4cr2k', 'deposit')).toBe(
      true,
    );
    expect(await matchesResource(att, 'mailbox:cv7n8vkvr64cctf3294h9k4eanhff8z', 'deposit')).toBe(
      false,
    );
  });
});
