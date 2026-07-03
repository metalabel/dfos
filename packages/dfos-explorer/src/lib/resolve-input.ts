/*

  INPUT DISPATCH — paste-a-string → route

  Purely syntactic: dfos-client's resolve() does the network dispatch; this
  decides which view a pasted identifier belongs to before any fetch happens.

*/

export type InputTarget =
  | { kind: 'identity'; id: string }
  | { kind: 'content'; id: string }
  | { kind: 'op'; id: string }
  | null;

// 31-char base32 (protocol id alphabet: lowercase letters + digits 2-9ish);
// stay permissive — the view renders an honest not-found for a bad guess
const CONTENT_ID = /^[a-z0-9]{31}$/;

// CIDv1 base32 (bafy… op/dag-cbor, bafk… raw, etc.)
const CID_V1 = /^baf[a-z2-7]+$/;

export const dispatchInput = (raw: string): InputTarget => {
  const value = raw.trim();
  if (!value) return null;
  if (value.startsWith('did:dfos:')) return { kind: 'identity', id: value };
  if (CID_V1.test(value)) return { kind: 'op', id: value };
  if (CONTENT_ID.test(value)) return { kind: 'content', id: value };
  return null;
};

export const routeFor = (target: NonNullable<InputTarget>): string => {
  switch (target.kind) {
    case 'identity':
      return `#/did/${target.id}`;
    case 'content':
      return `#/content/${target.id}`;
    case 'op':
      return `#/op/${target.id}`;
  }
};
