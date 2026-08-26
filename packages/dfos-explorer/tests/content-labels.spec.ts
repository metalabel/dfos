import { describe, expect, it } from 'vitest';
import { verifiedContentLabel } from '../src/lib/content-labels';

const CONTENT_ID = 'ct7kkfz7ehzvv6fzvate9rz2874nc3e';
const POST = 'https://schemas.dfos.com/post/v1';
const PROFILE = 'https://schemas.dfos.com/profile/v1';

describe('verifiedContentLabel — only integral document bytes name a content chain', () => {
  it('an integral post/v1 with a title yields its plain title', () => {
    expect(
      verifiedContentLabel(
        CONTENT_ID,
        { $schema: POST, title: 'The verified document', body: 'ignored when titled' },
        true,
      ),
    ).toEqual({ text: 'The verified document', quoted: false, kind: 'title' });
  });

  it('an integral untitled post/v1 yields a quoted, truncated body snippet', () => {
    expect(
      verifiedContentLabel(
        CONTENT_ID,
        {
          $schema: POST,
          body: 'So today I did a whole bunch of things worth writing down at length',
        },
        true,
      ),
    ).toEqual({
      // truncation breaks on the last word boundary inside the limit — never mid-word
      text: 'So today I did a whole bunch of things worth…',
      quoted: true,
      kind: 'snippet',
    });
  });

  it('an integral profile/v1 uses its name, else a quoted description snippet', () => {
    expect(verifiedContentLabel(CONTENT_ID, { $schema: PROFILE, name: 'Alice' }, true)).toEqual({
      text: 'Alice',
      quoted: false,
      kind: 'title',
    });
    expect(
      verifiedContentLabel(
        CONTENT_ID,
        { $schema: PROFILE, description: 'a maker of things' },
        true,
      ),
    ).toEqual({ text: 'a maker of things', quoted: true, kind: 'snippet' });
  });

  it('NEVER yields a label when the bytes do not re-hash to the committed CID', () => {
    // However well-formed the document, mismatched bytes are the relay's claim,
    // not the content chain's — rendering their title would erase the trust gate.
    expect(
      verifiedContentLabel(CONTENT_ID, { $schema: POST, title: 'Relay-written title' }, false),
    ).toBeNull();
  });

  it('non-object decoded values yield nothing', () => {
    expect(verifiedContentLabel(CONTENT_ID, 'not a document', true)).toBeNull();
    expect(verifiedContentLabel(CONTENT_ID, null, true)).toBeNull();
    expect(verifiedContentLabel(CONTENT_ID, undefined, true)).toBeNull();
    expect(verifiedContentLabel(CONTENT_ID, [{ title: 'array title' }], true)).toBeNull();
  });

  it('an integral document with no derivable text yields a cacheable bare-id verdict', () => {
    expect(verifiedContentLabel(CONTENT_ID, { $schema: POST }, true)).toBeNull();
  });
});
