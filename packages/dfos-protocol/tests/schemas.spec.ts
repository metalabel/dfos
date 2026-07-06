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
const indexSchema = loadSchema('index.v1.json');
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

  it('index.v1.json compiles', () => {
    expect(() => ajv.compile(indexSchema)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Post schema
// ---------------------------------------------------------------------------

describe('post schema validation', () => {
  const validate = ajv.compile(postSchema);
  const mediaCid = 'bafkreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli';

  it('accepts a minimal short-post', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
      }),
    ).toBe(true);
  });

  it('accepts a full long-post with Media objects', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'long-post',
        title: 'Hello World',
        body: 'This is a long post with content.',
        cover: {
          uri: 'attachment://media_abc123',
          cid: mediaCid,
          href: 'https://cdn.example.com/media/abc123.jpg',
        },
        attachments: [
          { uri: 'attachment://media_def456' },
          { uri: 'attachment://media_ghi789', cid: mediaCid },
        ],
        topics: ['announcements', 'engineering'],
      }),
    ).toBe(true);
  });

  it('accepts post media with only uri (cid and href truly optional)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: { uri: 'attachment://media_abc123' },
        attachments: [{ uri: 'attachment://media_def456' }],
      }),
    ).toBe(true);
  });

  it('accepts a post with one credit', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        body: 'Hello world.',
        credits: [{ did: 'did:dfos:abc123' }],
      }),
    ).toBe(true);
  });

  it('accepts ordered labeled credits', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [
          { did: 'did:dfos:abc123', label: 'author' },
          { did: 'did:dfos:def456', label: 'editor' },
        ],
      }),
    ).toBe(true);
  });

  it('accepts empty credits', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [],
      }),
    ).toBe(true);
  });

  it('rejects legacy media shape', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: { id: 'media_abc' },
      }),
    ).toBe(false);
  });

  it('rejects media with additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: { uri: 'attachment://media_abc123', extra: true },
      }),
    ).toBe(false);
  });

  it('rejects media missing uri', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: { cid: mediaCid },
      }),
    ).toBe(false);
  });

  it('rejects media cid that is not a raw-codec CIDv1', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        cover: {
          uri: 'attachment://media_abc123',
          cid: 'bafyreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli',
        },
      }),
    ).toBe(false);
  });

  it('rejects createdByDID', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        createdByDID: 'did:dfos:abc123',
      }),
    ).toBe(false);
  });

  it('rejects credit missing did', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [{ label: 'author' }],
      }),
    ).toBe(false);
  });

  it('rejects credit did without did: prefix', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [{ did: 'not-a-did' }],
      }),
    ).toBe(false);
  });

  it('rejects credit with additional properties', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [{ did: 'did:dfos:abc123', extra: true }],
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

  // --- avatar (Media object) — additive profile/v1 field ---

  // real raw-codec CIDv1: sha2-256 over "DFOS example avatar bytes\n"
  const avatarCid = 'bafkreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli';

  it('accepts a profile with a full avatar Media object', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        name: 'Alice',
        avatar: {
          uri: 'attachment://media_abc123',
          cid: avatarCid,
          href: 'https://cdn.example.com/media/abc123.jpg',
        },
      }),
    ).toBe(true);
  });

  it('accepts an avatar with only uri (cid and href truly optional)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        avatar: { uri: 'attachment://media_abc123' },
      }),
    ).toBe(true);
  });

  it('accepts a profile without avatar (additive — pre-avatar docs stay valid)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        name: 'Alice',
        description: 'No avatar here.',
        links: [{ uri: 'https://example.com' }],
      }),
    ).toBe(true);
  });

  it('rejects an avatar missing uri', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        avatar: { cid: avatarCid },
      }),
    ).toBe(false);
  });

  it('rejects an avatar with a non-string cid', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        avatar: { uri: 'attachment://media_abc123', cid: 42 },
      }),
    ).toBe(false);
  });

  it('rejects an avatar cid that is not a raw-codec CIDv1 (dag-cbor bafyrei… rejected)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        avatar: {
          uri: 'attachment://media_abc123',
          cid: 'bafyreibovzpnn2y6dquvxhidhx64hg7smduemox7drjs4vprjhlbmivfli',
        },
      }),
    ).toBe(false);
  });

  it('rejects unknown fields on the avatar Media object', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/profile/v1',
        avatar: { uri: 'attachment://media_abc123', id: 'media_abc123' },
      }),
    ).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Index schema
// ---------------------------------------------------------------------------

describe('index schema validation', () => {
  const validate = ajv.compile(indexSchema);

  it('accepts a set delta with entry metadata', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [
          {
            op: 'set',
            key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            value: { label: 'First', order: 1 },
          },
        ],
      }),
    ).toBe(true);
  });

  it('accepts the degenerate set-membership delta (no value)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set', key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }],
      }),
    ).toBe(true);
  });

  it('accepts a remove delta', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'remove', key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }],
      }),
    ).toBe(true);
  });

  it('accepts unknown delta ops (validators MUST NOT reject additional delta shapes)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'reorder', key: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', anything: true }],
      }),
    ).toBe(true);
  });

  it('accepts entry metadata with unknown fields (forward compat)', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set', key: 'k', value: { label: 'x', futureField: 'y' } }],
      }),
    ).toBe(true);
  });

  it('validates every document in the examples/index worked chain', () => {
    const chain = JSON.parse(
      readFileSync(resolve(import.meta.dirname, '../../../examples/index/chain.json'), 'utf-8'),
    ) as { operations: { sequence: number; document: unknown }[] };
    for (const op of chain.operations) {
      expect(validate(op.document), `sequence ${op.sequence} should validate`).toBe(true);
    }
  });

  it('rejects a set delta missing key', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set' }],
      }),
    ).toBe(false);
  });

  it('rejects a remove delta missing key', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'remove' }],
      }),
    ).toBe(false);
  });

  it('rejects a set delta with a non-string key', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set', key: 42 }],
      }),
    ).toBe(false);
  });

  it('rejects a set delta with a non-object value', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set', key: 'k', value: 'scalar' }],
      }),
    ).toBe(false);
  });

  it('rejects a non-integer order', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/index/v1',
        deltas: [{ op: 'set', key: 'k', value: { order: 1.5 } }],
      }),
    ).toBe(false);
  });

  it('rejects missing deltas', () => {
    expect(validate({ $schema: 'https://schemas.dfos.com/index/v1' })).toBe(false);
  });

  it('rejects missing $schema', () => {
    expect(validate({ deltas: [] })).toBe(false);
  });
});
