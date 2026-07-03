import { describe, expect, it } from 'vitest';
import {
  decodeRelayProfile,
  isProfileContent,
  PROFILE_SCHEMA,
  profileAnchorOf,
} from '../src/lib/profile';

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const mkArtifact = (did: string, kidDid: string, content: unknown): string =>
  `${b64url({ typ: 'did:dfos:artifact', kid: `${kidDid}#key_1`, cid: 'bafyreiexample' })}.${b64url({ version: 1, type: 'artifact', did, content })}.sig`;

describe('isProfileContent', () => {
  it('accepts profile/v1 docs and rejects others', () => {
    expect(isProfileContent({ $schema: PROFILE_SCHEMA, name: 'x' })).toBe(true);
    expect(isProfileContent({ $schema: 'https://schemas.dfos.com/post/v1' })).toBe(false);
    expect(isProfileContent(null)).toBe(false);
    expect(isProfileContent('nope')).toBe(false);
  });
});

describe('decodeRelayProfile', () => {
  it('decodes name + flags self-consistency when did === kid DID', () => {
    const did = 'did:dfos:aaa';
    const jws = mkArtifact(did, did, { $schema: PROFILE_SCHEMA, name: 'DFOS Relay' });
    const claim = decodeRelayProfile(jws);
    expect(claim?.did).toBe(did);
    expect(claim?.kidDid).toBe(did);
    expect(claim?.selfConsistent).toBe(true);
    expect(claim?.profile?.name).toBe('DFOS Relay');
  });

  it('flags NOT self-consistent when the kid DID differs from the payload did', () => {
    const claim = decodeRelayProfile(
      mkArtifact('did:dfos:aaa', 'did:dfos:evil', { $schema: PROFILE_SCHEMA, name: 'spoof' }),
    );
    expect(claim?.selfConsistent).toBe(false);
  });

  it('returns a null profile when the artifact is not profile/v1', () => {
    const claim = decodeRelayProfile(
      mkArtifact('did:dfos:aaa', 'did:dfos:aaa', { $schema: 'other', name: 'x' }),
    );
    expect(claim?.profile).toBeNull();
  });

  it('returns null on undecodable input', () => {
    expect(decodeRelayProfile('garbage')).toBeNull();
  });
});

describe('profileAnchorOf', () => {
  const anchor = (label: string, target: string) => ({
    type: 'ContentAnchor',
    id: 'svc',
    label,
    anchor: target,
  });

  it('prefers a profile-labeled content anchor', () => {
    const services = [
      { type: 'DfosRelay', id: 'r', endpoint: 'https://x' },
      anchor('avatar', 'aaacontent1'),
      anchor('profile', 'bbbcontent2'),
    ];
    expect(profileAnchorOf(services)).toBe('bbbcontent2');
  });

  it('falls back to the first content anchor when none is labeled profile/avatar', () => {
    expect(profileAnchorOf([anchor('banner', 'ccccontent3')])).toBe('ccccontent3');
  });

  it('ignores artifact-CID anchors (baf…) — only content chains carry a profile', () => {
    expect(profileAnchorOf([anchor('profile', 'bafyreiwhatever')])).toBeNull();
  });

  it('returns null when there are no content anchors', () => {
    expect(profileAnchorOf([{ type: 'DfosRelay', id: 'r', endpoint: 'https://x' }])).toBeNull();
    expect(profileAnchorOf(undefined)).toBeNull();
  });
});
