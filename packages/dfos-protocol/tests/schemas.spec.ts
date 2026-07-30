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
const creditClaimSchema = loadSchema('credit-claim.v1.json');
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

  it('credit-claim.v1.json compiles', () => {
    expect(() => ajv.compile(creditClaimSchema)).not.toThrow();
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
        publishedAt: '2026-03-07T00:02:00.000Z',
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
      }),
    ).toBe(true);
  });

  it('rejects invalid publishedAt date-time', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        publishedAt: '2026-03-07',
      }),
    ).toBe(false);
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

  it('accepts ordered roled credits', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [
          { did: 'did:dfos:abc123', role: 'author' },
          { did: 'did:dfos:def456', role: 'editor' },
        ],
      }),
    ).toBe(true);
  });

  it('accepts a claimed credit', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [
          {
            did: 'did:dfos:abc123',
            role: 'photography',
            name: 'Alice',
            claim: 'header.payload.signature',
          },
        ],
      }),
    ).toBe(true);
  });

  it('rejects a claim without a role to bind to', () => {
    // role is a component of the credit claim's bind — a claim with no role in
    // the entry has nothing to bind to, so it is invalid rather than unclaimed
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [{ did: 'did:dfos:abc123', claim: 'header.payload.signature' }],
      }),
    ).toBe(false);
  });

  it('rejects the pre-amendment label field', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        credits: [{ did: 'did:dfos:abc123', label: 'author' }],
      }),
    ).toBe(false);
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
        credits: [{ role: 'author' }],
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

  it('rejects topics', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'short-post',
        topics: ['announcements'],
      }),
    ).toBe(false);
  });

  it('rejects comment format', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'comment',
        body: 'Great post!',
      }),
    ).toBe(false);
  });

  it('rejects reply format', () => {
    expect(
      validate({
        $schema: 'https://schemas.dfos.com/post/v1',
        format: 'reply',
        body: 'Thanks!',
      }),
    ).toBe(false);
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

// ---------------------------------------------------------------------------
// Credit claim schema
// ---------------------------------------------------------------------------

describe('credit claim schema validation', () => {
  const validate = ajv.compile(creditClaimSchema);
  const contentId = 'cv7n8vkvr64cctf3294h9k4eanhff8z';
  const did = 'did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr';

  const claim = (overrides: Record<string, unknown> = {}) => ({
    version: 1,
    type: 'credit-claim',
    contentId,
    did,
    role: 'photography',
    createdAt: '2026-03-07T00:00:00.000Z',
    ...overrides,
  });

  it('accepts a minimal claim payload', () => {
    expect(validate(claim())).toBe(true);
  });

  it('accepts the optional asOfDocumentCID flavor', () => {
    expect(
      validate(
        claim({ asOfDocumentCID: 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne' }),
      ),
    ).toBe(true);
  });

  it('preserves unknown top-level fields (MUST-ignore-unknown wire payload)', () => {
    // NOT additionalProperties:false — the CID commits to the exact bytes, so a
    // verifier that stripped unknown keys would fail its own CID check
    expect(validate(claim({ futureField: 'whatever' }))).toBe(true);
  });

  it('rejects a documentCID in place of the contentId binder', () => {
    expect(
      validate({
        ...claim(),
        contentId: 'bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne',
      }),
    ).toBe(false);
  });

  it('rejects an empty role', () => {
    expect(validate(claim({ role: '' }))).toBe(false);
  });

  it('rejects a did without the did: prefix', () => {
    expect(validate(claim({ did: 'cnnnft9f8a2rn938d6nkz38r847v2kr' }))).toBe(false);
  });

  it('rejects the wrong type discriminator', () => {
    expect(validate(claim({ type: 'revocation' }))).toBe(false);
  });

  it('rejects a missing createdAt', () => {
    const { createdAt: _omit, ...withoutCreatedAt } = claim();
    expect(validate(withoutCreatedAt)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Credit entry shape (the credits[] embedding, published in credit-claim/v1)
// ---------------------------------------------------------------------------

describe('credit entry shape', () => {
  // the entry shape is published as a $def of credit-claim/v1, so validate it
  // through a ref into the registered schema rather than a doctored copy
  const validate = ajv.compile({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $ref: 'https://schemas.dfos.com/credit-claim/v1#/$defs/creditEntry',
  });

  it('accepts a bare (unclaimed) entry', () => {
    expect(validate({ did: 'did:dfos:abc123' })).toBe(true);
  });

  it('accepts a fully claimed entry', () => {
    expect(
      validate({
        did: 'did:dfos:abc123',
        role: 'photography',
        name: 'Alice',
        claim: 'header.payload.signature',
      }),
    ).toBe(true);
  });

  it('rejects a claim with no role to bind to', () => {
    expect(validate({ did: 'did:dfos:abc123', claim: 'header.payload.signature' })).toBe(false);
  });

  it('rejects the pre-amendment label field', () => {
    expect(validate({ did: 'did:dfos:abc123', label: 'author' })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Published-artifact drift guards
// ---------------------------------------------------------------------------

describe('credit entry shape is published once, copied verbatim', () => {
  // The credits-entry shape is published in TWO normative artifacts:
  // credit-claim/v1#/$defs/creditEntry (the declared-canonical definition) and
  // post/v1#/$defs/credit (the inline copy the post schema actually validates
  // against). They are copied rather than $ref'd on purpose — a cross-document
  // $ref would make offline validation of post/v1 require fetching a second
  // schema. The cost of copying is drift, so it is pinned here: the two MUST be
  // deep-equal, and a change to one is a change to both.
  it('post/v1 $defs.credit deep-equals credit-claim/v1 $defs.creditEntry', () => {
    expect(postSchema.$defs.credit).toEqual(creditClaimSchema.$defs.creditEntry);
  });

  it('neither copy uses a remote $ref', () => {
    // a $ref to another hosted schema would make post/v1 validation require a
    // network fetch; the copies exist precisely to avoid that
    const serialized = JSON.stringify(postSchema.$defs.credit);
    expect(serialized).not.toContain('https://schemas.dfos.com/credit-claim');
  });
});
