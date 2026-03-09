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
const envelopeSchema = loadSchema('document-envelope.v1.json');
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

  it('document-envelope.v1.json compiles', () => {
    expect(() => ajv.compile(envelopeSchema)).not.toThrow();
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
// Document envelope schema
// ---------------------------------------------------------------------------

describe('document envelope schema validation', () => {
  const validate = ajv.compile(envelopeSchema);

  it('accepts a minimal envelope with post content', () => {
    expect(
      validate({
        content: {
          $schema: 'https://schemas.dfos.com/post/v1',
          format: 'short-post',
          body: 'Hello world.',
        },
        baseDocumentCID: null,
        createdByDID: 'did:dfos:e3vvtck42d4eacdnzvtrn6',
        createdAt: '2026-03-07T00:02:00.000Z',
      }),
    ).toBe(true);
  });

  it('accepts an envelope with edit lineage', () => {
    expect(
      validate({
        content: {
          $schema: 'https://schemas.dfos.com/post/v1',
          format: 'short-post',
          title: 'Edited',
          body: 'Updated content.',
        },
        baseDocumentCID: 'bafyreifpvwuarml62sfogdpi2vlltvg2ev6o4xtw74zfud7cpkg7426zne',
        createdByDID: 'did:dfos:e3vvtck42d4eacdnzvtrn6',
        createdAt: '2026-03-07T00:03:00.000Z',
      }),
    ).toBe(true);
  });

  it('accepts an envelope with profile content', () => {
    expect(
      validate({
        content: {
          $schema: 'https://schemas.dfos.com/profile/v1',
          name: 'Alice',
        },
        baseDocumentCID: null,
        createdByDID: 'did:example:alice',
        createdAt: '2026-03-07T00:00:00.000Z',
      }),
    ).toBe(true);
  });

  it('accepts an envelope with custom content schema', () => {
    expect(
      validate({
        content: {
          $schema: 'https://schemas.example.com/custom/v1',
          whatever: 'custom fields are fine',
        },
        baseDocumentCID: null,
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(true);
  });

  it('rejects content missing $schema', () => {
    expect(
      validate({
        content: { format: 'short-post', body: 'No schema' },
        baseDocumentCID: null,
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });

  it('rejects missing content', () => {
    expect(
      validate({
        baseDocumentCID: null,
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });

  it('rejects missing baseDocumentCID', () => {
    expect(
      validate({
        content: { $schema: 'https://schemas.dfos.com/post/v1' },
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });

  it('rejects missing createdByDID', () => {
    expect(
      validate({
        content: { $schema: 'https://schemas.dfos.com/post/v1' },
        baseDocumentCID: null,
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });

  it('rejects createdByDID without did: prefix', () => {
    expect(
      validate({
        content: { $schema: 'https://schemas.dfos.com/post/v1' },
        baseDocumentCID: null,
        createdByDID: 'not-a-did',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });

  it('rejects additional properties on envelope', () => {
    expect(
      validate({
        content: { $schema: 'https://schemas.dfos.com/post/v1' },
        baseDocumentCID: null,
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
        extra: 'not allowed',
      }),
    ).toBe(false);
  });

  it('rejects non-object content', () => {
    expect(
      validate({
        content: 'not an object',
        baseDocumentCID: null,
        createdByDID: 'did:dfos:abc',
        createdAt: '2026-01-01T00:00:00.000Z',
      }),
    ).toBe(false);
  });
});
