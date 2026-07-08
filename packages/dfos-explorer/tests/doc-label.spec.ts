import { describe, expect, it } from 'vitest';
import { deriveDocLabel, schemaBadge, snippet, SNIPPET_MAX } from '../src/lib/doc-label';

const POST = 'https://schemas.dfos.com/post/v1';
const PROFILE = 'https://schemas.dfos.com/profile/v1';
const CID = 'dn2nc79k7z6ekzfhd43he4v8tr6h236';

describe('snippet', () => {
  it('collapses whitespace/newlines to single spaces', () => {
    expect(snippet('so   today\n\ni  did')).toBe('so today i did');
  });

  it('truncates past the max with an ellipsis', () => {
    const long = 'a'.repeat(SNIPPET_MAX + 20);
    const out = snippet(long);
    expect(out.endsWith('…')).toBe(true);
    expect(out.length).toBe(SNIPPET_MAX + 1); // max chars + the ellipsis
  });

  it('leaves a short string untouched', () => {
    expect(snippet('hello')).toBe('hello');
  });
});

describe('schemaBadge', () => {
  it('shortens a dfos schema URL to its path tail', () => {
    expect(schemaBadge(POST)).toBe('post/v1');
    expect(schemaBadge(PROFILE)).toBe('profile/v1');
  });

  it('is empty for a missing schema and truncates a long unrecognized one', () => {
    expect(schemaBadge(null)).toBe('');
    expect(schemaBadge(undefined)).toBe('');
    expect(schemaBadge('short:schema')).toBe('short:schema');
    expect(schemaBadge(`urn:${'x'.repeat(40)}`)).toContain('…');
  });
});

describe('deriveDocLabel', () => {
  it('prefers a plain title (not quoted)', () => {
    expect(deriveDocLabel({ title: 'My Post', contentId: CID })).toEqual({
      text: 'My Post',
      quoted: false,
      kind: 'title',
    });
  });

  it('uses a pre-projected snippet, quoted and truncated', () => {
    const body = 'So today I did a whole bunch of things worth writing down at length';
    const label = deriveDocLabel({ snippet: body, contentId: CID });
    expect(label.kind).toBe('snippet');
    expect(label.quoted).toBe(true);
    expect(label.text.endsWith('…')).toBe(true);
  });

  it('reads a post/v1 title from resolved doc bytes', () => {
    const label = deriveDocLabel({
      docSchema: POST,
      contentId: CID,
      doc: { $schema: POST, title: 'Resolved Title', body: 'ignored when titled' },
    });
    expect(label).toEqual({ text: 'Resolved Title', quoted: false, kind: 'title' });
  });

  it('falls back to a quoted body snippet for an untitled post/v1', () => {
    const label = deriveDocLabel({
      docSchema: POST,
      contentId: CID,
      doc: { $schema: POST, body: 'a short body' },
    });
    expect(label).toEqual({ text: 'a short body', quoted: true, kind: 'snippet' });
  });

  it('reads a profile/v1 name, else a quoted description', () => {
    expect(
      deriveDocLabel({ docSchema: PROFILE, contentId: CID, doc: { $schema: PROFILE, name: 'Alice' } }),
    ).toEqual({ text: 'Alice', quoted: false, kind: 'title' });
    expect(
      deriveDocLabel({
        docSchema: PROFILE,
        contentId: CID,
        doc: { $schema: PROFILE, description: 'a maker of things' },
      }),
    ).toEqual({ text: 'a maker of things', quoted: true, kind: 'snippet' });
  });

  it('falls back to the short contentId when nothing resolves', () => {
    const label = deriveDocLabel({ contentId: CID });
    expect(label.kind).toBe('id');
    expect(label.quoted).toBe(false);
    expect(label.text).toContain('…');
  });

  it('ignores blank/whitespace titles and snippets', () => {
    expect(deriveDocLabel({ title: '   ', snippet: '  ', contentId: CID }).kind).toBe('id');
  });
});
