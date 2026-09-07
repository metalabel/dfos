import { base58btc } from 'multiformats/bases/base58';
import { describe, expect, it } from 'vitest';
import {
  decodeEd25519PublicMultikey,
  encodeEd25519Multikey,
  verifyIdentityChain,
  verifyIdentityExtensionFromTrustedState,
} from '../src/chain';
import type { MultikeyPublicKey, VerifiedIdentity } from '../src/chain';
import {
  ContentOperation as ContentOperationSchema,
  CountersignPayload,
  IdentityOperation as IdentityOperationSchema,
} from '../src/chain/schemas';
import { isAttenuated, verifyDFOSCredential } from '../src/credentials';
import {
  base64urlEncode,
  createJws,
  createNewEd25519Keypair,
  dagCborCanonicalEncode,
  decodeJwsUnsafe,
  generateId,
  signPayloadEd25519,
  verifyJws,
} from '../src/crypto';

/*

  Wire agreement

  The two reference verifiers must commit to the same bytes and reach the same
  verdict on the same signed token. Each case here is one place where they did
  not: a payload member one side hashes and the other does not, a length counted
  in different units, a malformed document one side quietly repairs. The Go twin
  of each assertion lives in dfos-protocol-go/agreement_test.go.

*/

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

const makeKey = () => {
  const keypair = createNewEd25519Keypair();
  const keyId = generateId('key');
  const key: MultikeyPublicKey = {
    id: keyId,
    type: 'Multikey',
    publicKeyMultibase: encodeEd25519Multikey(keypair.publicKey),
  };
  const signer = async (msg: Uint8Array) => signPayloadEd25519(msg, keypair.privateKey);
  return { keypair, keyId, key, signer };
};

const ts = (offset = 0) => new Date(Date.now() + offset * 60_000).toISOString();

/** Sign a JWS over EXACTLY these payload members, with the cid header they derive */
const signRaw = async (input: {
  typ: string;
  kid: string;
  payload: Record<string, unknown>;
  signer: (msg: Uint8Array) => Promise<Uint8Array>;
  withCid?: boolean;
}): Promise<string> => {
  const encoded = await dagCborCanonicalEncode(input.payload);
  return createJws({
    header: {
      alg: 'EdDSA',
      typ: input.typ,
      kid: input.kid,
      ...(input.withCid === false ? {} : { cid: encoded.cid.toString() }),
    },
    payload: input.payload,
    sign: input.signer,
  });
};

/** A JWS whose protected header and payload are the given raw BYTES */
const signRawBytes = async (
  headerBytes: Uint8Array,
  payloadBytes: Uint8Array,
  keypair: ReturnType<typeof createNewEd25519Keypair>,
): Promise<string> => {
  const signingInput = `${base64urlEncode(headerBytes)}.${base64urlEncode(payloadBytes)}`;
  const sig = await signPayloadEd25519(new TextEncoder().encode(signingInput), keypair.privateKey);
  return `${signingInput}.${base64urlEncode(sig)}`;
};

/** A JWS whose protected header and payload are the given raw JSON TEXT */
const signRawText = async (
  headerText: string,
  payloadText: string,
  keypair: ReturnType<typeof createNewEd25519Keypair>,
): Promise<string> =>
  signRawBytes(
    new TextEncoder().encode(headerText),
    new TextEncoder().encode(payloadText),
    keypair,
  );

/** An own `__proto__` DATA property — the only way to make one is through JSON */
const withOwnProto = (value: Record<string, unknown>): Record<string, unknown> =>
  JSON.parse(`{"__proto__":{"evil":1},${JSON.stringify(value).slice(1)}`);

// -----------------------------------------------------------------------------
// H2 — the CID commits to the decoded payload, not the schema's output
// -----------------------------------------------------------------------------

describe('operation CID derives from the decoded payload', () => {
  it('an operation carrying a __proto__ member verifies, at the CID the signer signed', async () => {
    const k = makeKey();
    const op = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(),
    };
    const raw = withOwnProto(op);
    expect(Object.keys(raw)).toContain('__proto__');

    // the fork this closes: zod's parse DROPS the member, so hashing its output
    // gives a different CID than hashing the bytes the signer committed to
    const parsed = IdentityOperationSchema.parse(raw);
    expect(Object.keys(parsed)).not.toContain('__proto__');
    const rawCid = (await dagCborCanonicalEncode(raw)).cid.toString();
    const parsedCid = (await dagCborCanonicalEncode(parsed)).cid.toString();
    expect(rawCid).not.toBe(parsedCid);

    const jws = await signRaw({
      typ: 'did:dfos:identity-op',
      kid: k.keyId,
      payload: raw,
      signer: k.signer,
    });
    const identity = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [jws] });
    expect(identity.did).toMatch(/^did:dfos:/);

    // and the DID derives from the raw bytes, the ones Go hashes too
    const header = decodeJwsUnsafe(jws)!.header;
    expect(header.cid).toBe(rawCid);
  });
});

// -----------------------------------------------------------------------------
// H7 — an omitted credential `prf` is not a `prf: []` on the wire
// -----------------------------------------------------------------------------

describe('credential CID derives from the decoded payload', () => {
  it('a credential that omits prf verifies at the CID it was signed with', async () => {
    const k = makeKey();
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const identity: VerifiedIdentity = {
      did,
      isDeleted: false,
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      services: [],
    };
    // no `prf` member at all — the schema would inject `[]`, Go would not
    const payload = {
      version: 1,
      type: 'DFOSCredential',
      iss: did,
      aud: `did:dfos:${generateId('test').substring(5)}`,
      att: [{ resource: 'chain:abc', action: 'write' }],
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
    };
    expect(Object.keys(payload)).not.toContain('prf');

    const jws = await signRaw({
      typ: 'did:dfos:credential',
      kid: `${did}#${k.keyId}`,
      payload,
      signer: k.signer,
    });
    const verified = await verifyDFOSCredential(jws, {
      resolveIdentity: async () => identity,
    });
    expect(verified.iss).toBe(did);
    expect(verified.credentialCID).toBe((await dagCborCanonicalEncode(payload)).cid.toString());
  });
});

// -----------------------------------------------------------------------------
// H4 — a private-key multikey is not a public key
// -----------------------------------------------------------------------------

describe('multikey codec assertion', () => {
  it('rejects an ed25519-priv-prefixed multikey where a public key is required', () => {
    const priv = new Uint8Array(34);
    priv[0] = 0x80;
    priv[1] = 0x26;
    const multibase = base58btc.encode(priv);
    expect(() => decodeEd25519PublicMultikey(multibase)).toThrow(/not an Ed25519 public key/);
  });

  it('a genesis whose only key is private-tagged does not verify', async () => {
    const k = makeKey();
    const priv = new Uint8Array(34);
    priv[0] = 0x80;
    priv[1] = 0x26;
    priv.set(k.keypair.publicKey, 2);
    const key: MultikeyPublicKey = {
      id: k.keyId,
      type: 'Multikey',
      publicKeyMultibase: base58btc.encode(priv),
    };
    const jws = await signRaw({
      typ: 'did:dfos:identity-op',
      kid: k.keyId,
      payload: {
        version: 1,
        type: 'create',
        authKeys: [key],
        assertKeys: [key],
        controllerKeys: [key],
        createdAt: ts(),
      },
      signer: k.signer,
    });
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [jws] })).rejects.toThrow(
      /not an Ed25519 public key/,
    );
  });
});

// -----------------------------------------------------------------------------
// M2 / M9 — the protected header is an object with a string kid, or it is not a header
// -----------------------------------------------------------------------------

describe('protected header shape', () => {
  const keypair = createNewEd25519Keypair();

  it('a JSON null protected header decodes to null, not a TypeError', async () => {
    const token = await signRawText('null', '{"v":1}', keypair);
    expect(decodeJwsUnsafe(token)).toBeNull();
    expect(() => verifyJws({ token, publicKey: keypair.publicKey })).toThrow(
      /Failed to decode token/,
    );
  });

  it('an array protected header is refused the same way', async () => {
    const token = await signRawText('[]', '{"v":1}', keypair);
    expect(decodeJwsUnsafe(token)).toBeNull();
  });

  it('a header with no kid decodes for envelope-specific validation', async () => {
    const token = await signRawText('{"alg":"EdDSA","typ":"did:dfos:credential"}', '{}', keypair);
    expect(decodeJwsUnsafe(token)).toEqual({
      header: { alg: 'EdDSA', typ: 'did:dfos:credential' },
      payload: {},
    });
  });

  it('a header with a non-string kid is refused', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"did:dfos:credential","kid":42}',
      '{}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
  });

  it('a header with a non-string cid is refused', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k","cid":{"a":1}}',
      '{}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
  });

  it('a JSON null payload is refused', async () => {
    const token = await signRawText('{"alg":"EdDSA","typ":"t","kid":"k"}', 'null', keypair);
    expect(decodeJwsUnsafe(token)).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// M5 — duplicate JSON keys are malformed, and H1 at the wire
// -----------------------------------------------------------------------------

describe('raw-text gates on a signed document', () => {
  const keypair = createNewEd25519Keypair();

  it('rejects a payload with a duplicate key', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k"}',
      '{"a":1,"b":2,"a":3}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
    expect(() => verifyJws({ token, publicKey: keypair.publicKey })).toThrow(/duplicate JSON key/);
  });

  it('rejects a duplicate key spelled through an escape', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k"}',
      '{"a":1,"\\u0061":2}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
  });

  it('rejects a duplicate key in the protected header', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k","kid":"other"}',
      '{"a":1}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
  });

  it('rejects a lone surrogate escape in a payload string', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k"}',
      '{"a":"\\ud800"}',
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
    expect(() => verifyJws({ token, publicKey: keypair.publicKey })).toThrow(/unpaired surrogate/);
  });

  it('accepts a well-formed surrogate PAIR, and repeated keys in sibling objects', async () => {
    const token = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k"}',
      '{"a":"\\ud83d\\ude00","b":[{"x":1},{"x":2}],"c":{"a":1}}',
      keypair,
    );
    const decoded = decodeJwsUnsafe(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.payload['a']).toBe('😀');
  });

  it('rejects invalid UTF-8 in a payload string rather than repairing it', async () => {
    // a raw 0xFF inside a JSON string. A lenient TextDecoder turns it into
    // U+FFFD and this side would then scan, parse and verify a payload whose
    // bytes Go refuses outright (utf8.Valid in AssertCanonicalJSONText) — the
    // same signed bytes, two verdicts. Go twin:
    // TestInvalidUTF8InASignedDocumentIsMalformed.
    const payloadBytes = new Uint8Array([
      ...new TextEncoder().encode('{"a":"'),
      0xff,
      ...new TextEncoder().encode('"}'),
    ]);
    const token = await signRawBytes(
      new TextEncoder().encode('{"alg":"EdDSA","typ":"t","kid":"k"}'),
      payloadBytes,
      keypair,
    );
    expect(decodeJwsUnsafe(token)).toBeNull();
    expect(() => verifyJws({ token, publicKey: keypair.publicKey })).toThrow(
      /Failed to decode token/,
    );
  });

  it('rejects invalid UTF-8 in the protected header', async () => {
    const headerBytes = new Uint8Array([
      ...new TextEncoder().encode('{"alg":"EdDSA","typ":"'),
      0xff,
      ...new TextEncoder().encode('","kid":"k"}'),
    ]);
    const token = await signRawBytes(headerBytes, new TextEncoder().encode('{"a":1}'), keypair);
    expect(decodeJwsUnsafe(token)).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// M1 — the authorization discount counts bytes, and belongs to update/delete
// -----------------------------------------------------------------------------

describe('operation size cap', () => {
  it('measures a multibyte authorization in UTF-8 bytes, as Go does', async () => {
    // 200_000 two-byte characters: 200_000 UTF-16 units (under the 262_144 cap
    // if you count those) but 400_000 UTF-8 bytes (over it, which is the answer)
    const auth = 'é'.repeat(200_000);
    expect(auth.length).toBeLessThan(262_144);
    expect(new TextEncoder().encode(auth).length).toBeGreaterThan(262_144);

    const k = makeKey();
    const did = `did:dfos:${generateId('test').substring(5)}`;
    const jws = await signRaw({
      typ: 'did:dfos:content-op',
      kid: `${did}#${k.keyId}`,
      payload: {
        version: 1,
        type: 'update',
        did,
        previousOperationCID: 'bafyprev',
        documentCID: 'bafydoc',
        baseDocumentCID: null,
        createdAt: ts(),
        authorization: auth,
      },
      signer: k.signer,
    });
    const { verifyContentExtensionFromTrustedState } = await import('../src/chain/content-chain');
    await expect(
      verifyContentExtensionFromTrustedState({
        currentState: {
          contentId: 'c'.repeat(31),
          genesisCID: 'bafygen',
          headCID: 'bafyprev',
          isDeleted: false,
          currentDocumentCID: null,
          length: 1,
          creatorDID: did,
        },
        lastCreatedAt: ts(-10),
        newOp: jws,
        resolveKey: async () => k.keypair.publicKey,
      }),
    ).rejects.toThrow(/authorization credential exceeds max size/);
  });
});

// -----------------------------------------------------------------------------
// M3 — the relation cap counts bytes
// -----------------------------------------------------------------------------

describe('countersignature relation cap', () => {
  const base = {
    version: 1 as const,
    type: 'countersign' as const,
    did: 'did:dfos:abc',
    targetCID: 'bafytarget',
    createdAt: ts(),
  };

  it('rejects 40 two-byte characters — 40 UTF-16 units, 80 UTF-8 bytes', () => {
    const result = CountersignPayload.safeParse({ ...base, relation: 'é'.repeat(40) });
    expect(result.success).toBe(false);
  });

  it('accepts 64 ASCII characters and rejects 65', () => {
    expect(CountersignPayload.safeParse({ ...base, relation: 'a'.repeat(64) }).success).toBe(true);
    expect(CountersignPayload.safeParse({ ...base, relation: 'a'.repeat(65) }).success).toBe(false);
  });

  it('accepts 32 two-byte characters — exactly 64 bytes', () => {
    expect(CountersignPayload.safeParse({ ...base, relation: 'é'.repeat(32) }).success).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// M4 — an empty CID string is not a CID
// -----------------------------------------------------------------------------

describe('CID-valued fields', () => {
  it('rejects an empty documentCID on a create, as Go hard-errors on it', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'create',
      did: 'did:dfos:abc',
      documentCID: '',
      baseDocumentCID: null,
      createdAt: ts(),
    });
    expect(result.success).toBe(false);
  });

  it('still accepts a null documentCID on an update — cleared is not empty', () => {
    const result = ContentOperationSchema.safeParse({
      version: 1,
      type: 'update',
      did: 'did:dfos:abc',
      previousOperationCID: 'bafyprev',
      documentCID: null,
      baseDocumentCID: null,
      createdAt: ts(),
    });
    expect(result.success).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// M8 — action canonicalization trims ASCII whitespace and nothing else
// -----------------------------------------------------------------------------

describe('action canonicalization', () => {
  const parent = [{ resource: 'chain:abc', action: 'write' }];

  it('does not trim U+FEFF, which Go does not trim either', () => {
    expect(isAttenuated(parent, [{ resource: 'chain:abc', action: '﻿write' }])).toBe(false);
  });

  it('does not trim NBSP', () => {
    expect(isAttenuated(parent, [{ resource: 'chain:abc', action: ' write' }])).toBe(false);
  });

  it('still trims every ASCII whitespace character', () => {
    expect(
      isAttenuated(parent, [{ resource: 'chain:abc', action: ' \t\n\v\f\rwrite \t\n\v\f\r' }]),
    ).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// The services cap measures the RAW decoded payload, like every other cap
// -----------------------------------------------------------------------------

/** One service entry whose bulk lives in an own `__proto__` DATA member. */
const smuggledServices = (): unknown[] =>
  JSON.parse(
    `[{"__proto__":${JSON.stringify('a'.repeat(33000))},"id":"relay","type":"DfosRelay","endpoint":"https://r.example"}]`,
  ) as unknown[];

describe('services byte cap', () => {
  it('measures a __proto__ member the schema drops, as Go measures the wire array', async () => {
    const k = makeKey();
    // `ServiceEntry` is a `catchall(z.unknown())`, so the member is nominally
    // passed through — but zod builds a FRESH output object, and an own
    // `__proto__` data property does not survive being copied into one.
    // Measuring the parsed output saw 19 bytes; the signed array is 33,032, and
    // Go's parseServices — reading the wire map — rejects it.
    const services = smuggledServices();
    expect(Object.keys(services[0] as object)).toContain('__proto__');
    expect((await dagCborCanonicalEncode(services)).bytes.length).toBeGreaterThan(32768);

    const genesis = await signRaw({
      typ: 'did:dfos:identity-op',
      kid: k.keyId,
      payload: {
        version: 1,
        type: 'create',
        authKeys: [k.key],
        assertKeys: [k.key],
        controllerKeys: [k.key],
        services,
        createdAt: ts(),
      },
      signer: k.signer,
    });
    await expect(verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesis] })).rejects.toThrow(
      /services payload exceeds max size/,
    );
  });

  it('measures it on the incremental path too', async () => {
    const k = makeKey();
    const create = {
      version: 1,
      type: 'create',
      authKeys: [k.key],
      assertKeys: [k.key],
      controllerKeys: [k.key],
      createdAt: ts(0),
    };
    const genesisJws = await signRaw({
      typ: 'did:dfos:identity-op',
      kid: k.keyId,
      payload: create,
      signer: k.signer,
    });
    const state = await verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesisJws] });
    const genesisCID = decodeJwsUnsafe(genesisJws)!.header.cid!;

    const updateJws = await signRaw({
      typ: 'did:dfos:identity-op',
      kid: `${state.did}#${k.keyId}`,
      payload: {
        version: 1,
        type: 'update',
        previousOperationCID: genesisCID,
        authKeys: [k.key],
        assertKeys: [k.key],
        controllerKeys: [k.key],
        services: smuggledServices(),
        createdAt: ts(1),
      },
      signer: k.signer,
    });

    await expect(
      verifyIdentityChain({ didPrefix: 'did:dfos', log: [genesisJws, updateJws] }),
    ).rejects.toThrow(/services payload exceeds max size/);
    await expect(
      verifyIdentityExtensionFromTrustedState({
        currentState: state,
        headCID: genesisCID,
        lastCreatedAt: create.createdAt,
        newOp: updateJws,
      }),
    ).rejects.toThrow(/services payload exceeds max size/);
  });
});

// -----------------------------------------------------------------------------
// A BOM is not canonicalizable, in either language
// -----------------------------------------------------------------------------

describe('byte order mark', () => {
  const BOM = '﻿';

  it('rejects a BOM-prefixed protected header, which Go rejects too', async () => {
    const k = makeKey();
    // `fatal: true` governs malformed byte sequences; BOM stripping is the
    // separate `ignoreBOM` option, which defaults to STRIPPING — so this token
    // used to verify here and fail Go's json.Unmarshal on identical bytes.
    const jws = await signRawText(
      `${BOM}{"alg":"EdDSA","typ":"t","kid":"k"}`,
      '{"v":1}',
      k.keypair,
    );
    expect(() => decodeJwsUnsafe(jws)).not.toThrow();
    expect(decodeJwsUnsafe(jws)).toBeNull();
    expect(() => verifyJws({ token: jws, publicKey: k.keypair.publicKey })).toThrow(
      /byte order mark/,
    );
  });

  it('rejects a BOM-prefixed payload', async () => {
    const k = makeKey();
    const jws = await signRawText(
      '{"alg":"EdDSA","typ":"t","kid":"k"}',
      `${BOM}{"v":1}`,
      k.keypair,
    );
    expect(decodeJwsUnsafe(jws)).toBeNull();
    expect(() => verifyJws({ token: jws, publicKey: k.keypair.publicKey })).toThrow(
      /byte order mark/,
    );
  });

  it('still accepts the same document without one', async () => {
    const k = makeKey();
    const jws = await signRawText('{"alg":"EdDSA","typ":"t","kid":"k"}', '{"v":1}', k.keypair);
    expect(decodeJwsUnsafe(jws)?.payload).toEqual({ v: 1 });
  });
});
