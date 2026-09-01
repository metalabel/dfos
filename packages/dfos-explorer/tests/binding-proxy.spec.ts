import { describe, expect, it } from 'vitest';
import { classifyDidStatus, parseDidBody, parseTxtRecords } from '../api/binding';

// The binding route's judgement lives in these two pure parsers: what a TXT name
// is saying, and what a /.well-known/dfos-did body is saying. Everything else in
// the route is transport around them. The line they must hold is the spec's:
// SILENCE (nothing published, nothing readable) is never CONTRADICTION.

const DID = 'did:dfos:tn7kkfz7ehzvv6fzvate9rz2874nc3e';
const OTHER = 'did:dfos:2346789acdefhknrtvz2346789acdef';

describe('parseTxtRecords', () => {
  it('reads a single well-formed did= record', () => {
    expect(parseTxtRecords([[`did=${DID}`]])).toEqual({ status: 'ok', did: DID });
  });

  // a TXT record over 255 bytes arrives as several chunks; the record is the
  // JOIN of its chunks, never the chunks read separately
  it('joins the chunks of one record before reading it', () => {
    expect(parseTxtRecords([['did=', DID.slice(0, 10), DID.slice(10)]])).toEqual({
      status: 'ok',
      did: DID,
    });
  });

  it('ignores records that do not begin did=', () => {
    expect(
      parseTxtRecords([['v=spf1 -all'], [`did=${DID}`], ['google-site-verification=x']]),
    ).toEqual({ status: 'ok', did: DID });
  });

  it('is silent when the name carries no did= record at all', () => {
    expect(parseTxtRecords([]).status).toBe('none');
    expect(parseTxtRecords([['v=spf1 -all']]).status).toBe('none');
  });

  // the spec is explicit: more than one did= record is a contradiction and a
  // verifier MUST NOT pick one
  it('reports multiple did= records as a contradiction', () => {
    const out = parseTxtRecords([[`did=${DID}`], [`did=${OTHER}`]]);
    expect(out).toEqual({ status: 'contradiction', reason: 'multiple did= records' });
  });

  // "they happen to agree" is a tiebreak by another name — still a contradiction
  it('contradicts on duplicates even when the values match', () => {
    expect(parseTxtRecords([[`did=${DID}`], [`did=${DID}`]]).status).toBe('contradiction');
  });

  // a single record that is not a DID says NOTHING — it is not a second answer
  it('treats one malformed did= record as silence, not contradiction', () => {
    for (const bad of [
      'did=',
      'did=not-a-did',
      'did=did:dfos:tooshort',
      `did=did:dfos:${'b'.repeat(31)}`, // right length, outside the id alphabet
      `did=${DID} `, // trailing space — TXT values are exact
      `did=${DID}extra`,
      `DID=${DID}`, // wrong case: not a did= record at all
    ]) {
      const out = parseTxtRecords([[bad]]);
      expect(out.status, bad).toBe('none');
    }
  });
});

describe('parseDidBody', () => {
  it('accepts exactly one DID', () => {
    expect(parseDidBody(DID)).toEqual({ status: 'ok', did: DID });
  });

  it('trims ASCII whitespace around it', () => {
    expect(parseDidBody(`\n  ${DID}\t\r\n`)).toEqual({ status: 'ok', did: DID });
  });

  // present but not an attestation: `malformed` rather than `none`, because the
  // document EXISTS and the evidence row says so. Both are non-answers and both
  // license the app-description fallback — the STATUS is what keeps "there is no
  // document" and "there is a document that says nothing" distinguishable.
  it('reports a non-DID body as malformed, never as absence', () => {
    for (const body of [
      '',
      '   ',
      '<!doctype html><title>404</title>',
      'did:dfos:tooshort',
      `${DID} ${DID}`,
      `did=${DID}`,
      `{"did":"${DID}"}`,
      'did:web:example.com',
    ]) {
      const out = parseDidBody(body);
      expect(out.status, JSON.stringify(body)).toBe('malformed');
    }
  });

  it('rejects a body carrying more than the DID even on one line', () => {
    expect(parseDidBody(`${DID}\nnot a did`).status).toBe('malformed');
  });
});

// The status half of the same judgement, and the line ORIGIN-BINDING.md draws
// through it: a redirect and a 404 are both NON-ANSWERS (the fallback fires on
// either), while a 5xx is a QUERY FAILURE — the spec's own separate class — and
// licenses nothing, because a path we never saw never declined to answer.
describe('classifyDidStatus', () => {
  it('reads every redirect as a non-answer carrying its status', () => {
    for (const status of [301, 302, 303, 307, 308]) {
      expect(classifyDidStatus(status), String(status)).toEqual({
        status: 'redirected',
        httpStatus: status,
        reason: 'the origin redirected; redirects are not followed',
      });
    }
  });

  // the regression this whole change closes: a redirect used to arrive as
  // `error`, which is the query-failure class, and the fallback stayed shut
  it('never reports a redirect as a query failure', () => {
    for (const status of [301, 308]) {
      expect(classifyDidStatus(status)?.status).not.toBe('error');
    }
  });

  it('reads a 404 or a 410 as an absence the origin demonstrated', () => {
    expect(classifyDidStatus(404)?.status).toBe('none');
    expect(classifyDidStatus(410)?.status).toBe('none');
  });

  it('keeps every other non-2xx status a query failure', () => {
    for (const status of [400, 403, 429, 500, 503]) {
      const out = classifyDidStatus(status);
      expect(out?.status, String(status)).toBe('error');
      if (out?.status === 'error') expect(out.httpStatus).toBe(status);
    }
  });

  // a 2xx settles nothing on its own — the answer is the trimmed body
  it('leaves a success status to the body', () => {
    expect(classifyDidStatus(200)).toBeNull();
    expect(classifyDidStatus(204)).toBeNull();
  });
});
