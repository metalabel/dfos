import { describe, expect, it } from 'vitest';
import { isDependencyFailure } from '../src/sequencer';

/*

  SEQUENCER — dependency-failure classification

  Regression guard for the colon-mismatch bug: ingest.ts emits
  "failed to compute state at fork point: <cid>" (colon + detail, mirroring
  the Go relay's `fmt.Sprintf("...fork point: %v", err)`), and the sequencer's
  retryable pattern must classify those strings as transient dependency
  failures so they are retried rather than permanently rejected.

*/

describe('isDependencyFailure', () => {
  it('classifies unknown previous operation as retryable', () => {
    expect(isDependencyFailure('unknown previous operation in identity chain')).toBe(true);
    expect(isDependencyFailure('unknown previous operation in content chain')).toBe(true);
  });

  it('classifies unknown identity as retryable', () => {
    expect(isDependencyFailure('unknown identity: did:dfos:abc123')).toBe(true);
  });

  it('classifies content chain not found as retryable', () => {
    expect(isDependencyFailure('content chain not found: baf...')).toBe(true);
  });

  it('classifies the identity fork-point failure string emitted by ingest.ts as retryable', () => {
    // exact shape produced at ingest.ts (identity fork path)
    const emitted = `failed to compute state at fork point: bafyreigenesiscidexample`;
    expect(isDependencyFailure(emitted)).toBe(true);
  });

  it('classifies the content fork-point failure string emitted by ingest.ts as retryable', () => {
    // exact shape produced at ingest.ts (content fork path)
    const emitted = `failed to compute state at fork point: bafyreicontentcidexample`;
    expect(isDependencyFailure(emitted)).toBe(true);
  });

  it('does not classify genuine permanent rejections as retryable', () => {
    expect(isDependencyFailure('signature verification failed')).toBe(false);
    expect(isDependencyFailure('invalid operation payload')).toBe(false);
    expect(isDependencyFailure('blob bytes do not match documentCID')).toBe(false);
  });
});
