/**
 * JSON Schema validation tests — ensures all standard document schemas
 * compile, validate conforming documents, and reject non-conforming ones.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import addFormats from 'ajv-formats';
import Ajv from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';

const schemasDir = resolve(import.meta.dirname, '../schemas');

const loadSchema = (name: string) => JSON.parse(readFileSync(resolve(schemasDir, name), 'utf-8'));

const postSchema = loadSchema('post.v1.json');
const profileSchema = loadSchema('profile.v1.json');
const manifestSchema = loadSchema('manifest.v1.json');
const ajv = new Ajv({ strict: true, allErrors: true });
addFormats(ajv);

// ---------------------------------------------------------------------------
// Schema compilation
// ---------------------------------------------------------------------------

describe('schema compilation', () => {
  it('post.v1.json compiles', () => {
    expect(() => ajv.compile(postSchema)).not.toThrow();
  });

  it('profile.v1.json compiles', () => {
    expect(() => ajv.compile(profileSchema)).not.toThrow();
  });

  it('manifest.v1.json compiles', () => {
    expect(() => ajv.compile(manifestSchema)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Post schema
// ---------------------------------------------------------------------------

describe('post schema validation', () => {
  const validate = ajv.compile(postSchema);

  it('accepts a minimal short-post', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
      }),
    ).toBe(true);
  });

  it('accepts a full long-post', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'long-post',
        title: 'Hello World',
        body: 'This is a long post with content.',
        cover: { id: 'media_abc', uri: 'https://cdn.example.com/img.jpg' },
        attachments: [{ id: 'media_def' }],
        topics: ['announcements', 'engineering'],
      }),
    ).toBe(true);
  });

  it('accepts a post with createdByDID', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        body: 'Hello world.',
        createdByDID: 'did:dfos:abc123',
      }),
    ).toBe(true);
  });

  it('rejects createdByDID without did: prefix', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        createdByDID: 'not-a-did',
      }),
    ).toBe(false);
  });

  it('accepts a comment', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'comment',
        body: 'Great post!',
      }),
    ).toBe(true);
  });

  it('accepts a reply', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'reply',
        body: 'Thanks!',
      }),
    ).toBe(true);
  });

  it('rejects missing format', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        body: 'No format specified',
      }),
    ).toBe(false);
  });

  it('rejects invalid format value', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'tweet',
      }),
    ).toBe(false);
  });

  it('rejects missing $schema', () => {
    expect(validate({ format: 'short-post' })).toBe(false);
  });

  it('rejects wrong $schema value', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        format: 'short-post',
      }),
    ).toBe(false);
  });

  it('rejects additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        extra: 'not allowed',
      }),
    ).toBe(false);
  });

  it('rejects media with additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: { id: 'media_abc', extra: true },
      }),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Profile schema
// ---------------------------------------------------------------------------

describe('profile schema validation', () => {
  const validate = ajv.compile(profileSchema);

  it('accepts a minimal profile (just $schema)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
      }),
    ).toBe(true);
  });

  it('accepts a full profile', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        name: 'Alice',
        description: 'Building cool things',
        avatar: { id: 'media_avatar', uri: 'https://cdn.example.com/avatar.jpg' },
        banner: { id: 'media_banner' },
        background: { id: 'media_bg' },
      }),
    ).toBe(true);
  });

  it('accepts a profile with createdByDID', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        name: 'Alice',
        createdByDID: 'did:dfos:abc123',
      }),
    ).toBe(true);
  });

  it('rejects missing $schema', () => {
    expect(validate({ name: 'Alice' })).toBe(false);
  });

  it('rejects additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        name: 'Alice',
        email: 'alice@example.com',
      }),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Manifest schema
// ---------------------------------------------------------------------------

describe('manifest schema validation', () => {
  const validate = ajv.compile(manifestSchema);

  it('accepts a minimal manifest', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {},
      }),
    ).toBe(true);
  });

  it('accepts a manifest with contentId entries', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {
          profile: '67t27rzc83v7c22n9t6z7c',
          posts: 'a4b8c2d3e5f6g7h8i9j0k1',
        },
      }),
    ).toBe(true);
  });

  it('accepts a manifest with DID entries', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {
          'dark-publisher': 'did:dfos:e3vvtck42d4eacdnzvtrn6',
        },
      }),
    ).toBe(true);
  });

  it('accepts a manifest with CID entries', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {
          'pinned-charter': 'bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy',
        },
      }),
    ).toBe(true);
  });

  it('accepts path-like keys', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {
          'drafts/post-1': '67t27rzc83v7c22n9t6z7c',
          'collaborators/vinny': 'did:dfos:e3vvtck42d4eacdnzvtrn6',
          'v1.0/release-notes': 'a4b8c2d3e5f6g7h8i9j0k1',
          'my_content.main': '67t27rzc83v7c22n9t6z7c',
        },
      }),
    ).toBe(true);
  });

  it('rejects keys starting with special characters', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { '/leading-slash': '67t27rzc83v7c22n9t6z7c' },
      }),
    ).toBe(false);
  });

  it('rejects keys ending with special characters', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { 'trailing-slash/': '67t27rzc83v7c22n9t6z7c' },
      }),
    ).toBe(false);
  });

  it('rejects single-character keys', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { x: '67t27rzc83v7c22n9t6z7c' },
      }),
    ).toBe(false);
  });

  it('rejects uppercase keys', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { Profile: '67t27rzc83v7c22n9t6z7c' },
      }),
    ).toBe(false);
  });

  it('rejects keys with spaces', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { 'my posts': '67t27rzc83v7c22n9t6z7c' },
      }),
    ).toBe(false);
  });

  it('rejects empty string values', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { profile: '' },
      }),
    ).toBe(false);
  });

  it('rejects missing entries', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
      }),
    ).toBe(false);
  });

  it('rejects missing $schema', () => {
    expect(
      validate({
        entries: { profile: 'abc123' },
      }),
    ).toBe(false);
  });

  it('rejects non-string entry values', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { profile: 123 },
      }),
    ).toBe(false);
  });

  it('rejects additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: {},
        extra: 'not allowed',
      }),
    ).toBe(false);
  });

  it('rejects prose values (not identifier-shaped)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { profile: 'Hello World' },
      }),
    ).toBe(false);
  });

  it('rejects values starting with uppercase', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/manifest/v1',
        entries: { profile: 'NotAnIdentifier' },
      }),
    ).toBe(false);
  });
});
