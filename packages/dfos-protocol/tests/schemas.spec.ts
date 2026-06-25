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
        links: [
          { uri: 'https://x.com/alice', label: 'x', description: 'My posts on X.' },
          { uri: 'https://alice.example.com' },
        ],
      }),
    ).toBe(true);
  });

  it('accepts a profile with links', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        links: [{ uri: 'https://example.com', label: 'home' }],
      }),
    ).toBe(true);
  });

  it('rejects a link missing uri', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        links: [{ label: 'no uri' }],
      }),
    ).toBe(false);
  });

  it('rejects more than 20 links', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        links: Array.from({ length: 21 }, (_, i) => ({ uri: `https://example.com/${i}` })),
      }),
    ).toBe(false);
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
