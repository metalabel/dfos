import { describe, expect, it } from 'vitest';
import {
  createJws,
  createNewEd25519Keypair,
  decodeJwsUnsafe,
  importEd25519Keypair,
  isValidEd25519Signature,
  JwsVerificationError,
  signPayloadEd25519,
  verifyJws,
} from '../src/crypto';

describe('ed25519', () => {
  it('should create a keypair that can sign and verify', () => {
    const pair1 = createNewEd25519Keypair();
    const pair2 = createNewEd25519Keypair();
    const payload = new TextEncoder().encode('hello world');
    const signature = signPayloadEd25519(payload, pair1.privateKey);
    expect(isValidEd25519Signature(payload, signature, pair1.publicKey)).toBe(true);
    expect(isValidEd25519Signature(payload, signature, pair2.publicKey)).toBe(false);
  });

  it('should allow importing a keypair from a private key', () => {
    const pair1 = createNewEd25519Keypair();
    const pair2 = importEd25519Keypair(pair1.privateKey);
    expect(pair1.publicKey).toEqual(pair2.publicKey);
  });

  it('should produce deterministic signatures', () => {
    const pair = createNewEd25519Keypair();
    const payload = new TextEncoder().encode('deterministic test');
    const sig1 = signPayloadEd25519(payload, pair.privateKey);
    const sig2 = signPayloadEd25519(payload, pair.privateKey);
    expect(sig1).toEqual(sig2);
  });

  it('should reject tampered signatures', () => {
    const pair = createNewEd25519Keypair();
    const payload = new TextEncoder().encode('hello');
    const signature = signPayloadEd25519(payload, pair.privateKey);
    const tampered = new Uint8Array(signature);
    tampered[0] = tampered[0]! ^ 0xff;
    expect(isValidEd25519Signature(payload, tampered, pair.publicKey)).toBe(false);
  });

  it('should reject signature for wrong payload', () => {
    const pair = createNewEd25519Keypair();
    const payload1 = new TextEncoder().encode('hello');
    const payload2 = new TextEncoder().encode('world');
    const signature = signPayloadEd25519(payload1, pair.privateKey);
    expect(isValidEd25519Signature(payload2, signature, pair.publicKey)).toBe(false);
  });

  it('should produce 64-byte signatures and 32-byte keys', () => {
    const pair = createNewEd25519Keypair();
    const payload = new TextEncoder().encode('test');
    const signature = signPayloadEd25519(payload, pair.privateKey);
    expect(signature.length).toBe(64);
    expect(pair.privateKey.length).toBe(32);
    expect(pair.publicKey.length).toBe(32);
  });
});

describe('jws', () => {
  const createTestSigner = (privateKey: Uint8Array) => {
    return async (message: Uint8Array) => signPayloadEd25519(message, privateKey);
  };

  it('should create and verify a JWS round-trip', async () => {
    const keypair = createNewEd25519Keypair();

    const token = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:catalog-op', kid: 'did:dfos:abc123#key_1' },
      payload: { type: 'create', version: 1, documentCID: 'bafyrei...' },
      sign: createTestSigner(keypair.privateKey),
    });

    expect(token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

    const result = verifyJws({ token, publicKey: keypair.publicKey });
    expect(result.header.alg).toBe('EdDSA');
    expect(result.header.typ).toBe('did:dfos:catalog-op');
    expect(result.header.kid).toBe('did:dfos:abc123#key_1');
    expect(result.payload.type).toBe('create');
    expect(result.payload.version).toBe(1);
  });

  it('should reject signature from wrong key', async () => {
    const keypair1 = createNewEd25519Keypair();
    const keypair2 = createNewEd25519Keypair();

    const token = await createJws({
      header: { alg: 'EdDSA', typ: 'test', kid: 'key1' },
      payload: { data: 'hello' },
      sign: createTestSigner(keypair1.privateKey),
    });

    expect(() => verifyJws({ token, publicKey: keypair2.publicKey })).toThrow(JwsVerificationError);
  });

  it('should reject tampered payload', async () => {
    const keypair = createNewEd25519Keypair();

    const token = await createJws({
      header: { alg: 'EdDSA', typ: 'test', kid: 'key1' },
      payload: { data: 'original' },
      sign: createTestSigner(keypair.privateKey),
    });

    const parts = token.split('.');
    const tamperedPayloadB64 = btoa(JSON.stringify({ data: 'tampered' }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

    expect(() => verifyJws({ token: tamperedToken, publicKey: keypair.publicKey })).toThrow(
      JwsVerificationError,
    );
  });

  it('should decode JWS without verification', async () => {
    const keypair = createNewEd25519Keypair();

    const token = await createJws({
      header: { alg: 'EdDSA', typ: 'did:dfos:identity-op', kid: 'key_abc' },
      payload: { type: 'update', previousCID: null },
      sign: createTestSigner(keypair.privateKey),
    });

    const decoded = decodeJwsUnsafe(token);
    expect(decoded).not.toBeNull();
    expect(decoded!.header.kid).toBe('key_abc');
    expect(decoded!.payload.type).toBe('update');
  });

  it('should return null for malformed tokens', () => {
    expect(decodeJwsUnsafe('not-a-jws')).toBeNull();
    expect(decodeJwsUnsafe('a.b')).toBeNull();
    expect(decodeJwsUnsafe('')).toBeNull();
  });

  it('should reject non-EdDSA algorithm', () => {
    const keypair = createNewEd25519Keypair();
    const headerB64 = btoa(JSON.stringify({ alg: 'ES256K', typ: 'test', kid: 'key1' }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const payloadB64 = btoa(JSON.stringify({ data: 'test' }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    const fakeToken = `${headerB64}.${payloadB64}.fakesig`;

    expect(() => verifyJws({ token: fakeToken, publicKey: keypair.publicKey })).toThrow(
      'Unsupported algorithm',
    );
  });

  it('should reject invalid token format', () => {
    const keypair = createNewEd25519Keypair();
    expect(() => verifyJws({ token: 'not.valid', publicKey: keypair.publicKey })).toThrow(
      'Invalid token format',
    );
  });
});

describe('id', () => {
  // dynamic imports since these are not in the crypto barrel via jws/ed25519
  const getId = () => import('../src/crypto/id');

  describe('isValidId', () => {
    it('should accept a valid prefixed ID', async () => {
      const { generateId, isValidId } = await getId();
      const id = generateId('msg');
      expect(isValidId('msg', id)).toBe(true);
    });

    it('should reject wrong prefix', async () => {
      const { generateId, isValidId } = await getId();
      const id = generateId('msg');
      expect(isValidId('post', id)).toBe(false);
    });

    it('should reject wrong length', async () => {
      const { isValidId } = await getId();
      expect(isValidId('msg', 'msg_tooshort')).toBe(false);
      expect(isValidId('msg', 'msg_')).toBe(false);
    });

    it('should reject missing prefix separator', async () => {
      const { isValidId } = await getId();
      expect(isValidId('msg', 'msgxxxxxxxxxxxxxxxxxxxxxxxx')).toBe(false);
    });
  });

  describe('normalizedId', () => {
    it('should return lowered ID when prefix matches', async () => {
      const { normalizedId } = await getId();
      const result = normalizedId('msg', 'MSG_ABCDEF1234567890ABCDEF');
      expect(result).toBe('msg_abcdef1234567890abcdef');
    });

    it('should prepend prefix when ID has no underscore', async () => {
      const { normalizedId } = await getId();
      const result = normalizedId('msg', 'abcdef1234567890abcdef');
      expect(result).toBe('msg_abcdef1234567890abcdef');
    });

    it('should throw on wrong prefix', async () => {
      const { normalizedId } = await getId();
      expect(() => normalizedId('msg', 'post_abcdef1234567890abcdef')).toThrow(
        'unexpected id prefix',
      );
    });
  });
});

describe('jwt', () => {
  const getJwt = () => import('../src/crypto/jwt');

  describe('decodeJwtUnsafe', () => {
    it('should decode a valid JWT', async () => {
      const { createJwt, decodeJwtUnsafe } = await getJwt();
      const keypair = createNewEd25519Keypair();
      const token = await createJwt({
        header: { alg: 'EdDSA', typ: 'JWT', kid: 'did:dfos:test#key_1' },
        payload: {
          iss: 'did:dfos:test',
          sub: 'did:dfos:test',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
        },
        sign: async (msg) => signPayloadEd25519(msg, keypair.privateKey),
      });
      const result = decodeJwtUnsafe(token);
      expect(result).not.toBeNull();
      expect(result!.header.alg).toBe('EdDSA');
      expect(result!.header.typ).toBe('JWT');
      expect(result!.payload.iss).toBe('did:dfos:test');
    });

    it('should return null for malformed tokens', async () => {
      const { decodeJwtUnsafe } = await getJwt();
      expect(decodeJwtUnsafe('not-a-jwt')).toBeNull();
      expect(decodeJwtUnsafe('a.b')).toBeNull();
      expect(decodeJwtUnsafe('')).toBeNull();
      expect(decodeJwtUnsafe('x.y.z')).toBeNull(); // invalid base64
    });
  });
});

describe('multiformats utilities', () => {
  it('parseDagCborCID should parse a valid CID string', async () => {
    const { dagCborCanonicalEncode, parseDagCborCID } = await import('../src/crypto/multiformats');
    const block = await dagCborCanonicalEncode({ hello: 'world' });
    const cidStr = block.cid.toString();
    const parsed = parseDagCborCID(cidStr);
    expect(parsed.toString()).toBe(cidStr);
  });

  it('parseDagCborCID should throw on invalid CID', async () => {
    const { parseDagCborCID } = await import('../src/crypto/multiformats');
    expect(() => parseDagCborCID('not-a-cid')).toThrow();
  });

  it('isCanonicallyEqual should return true for equivalent objects', async () => {
    const { isCanonicallyEqual } = await import('../src/crypto/multiformats');
    expect(await isCanonicallyEqual({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(true);
  });

  it('isCanonicallyEqual should return false for different objects', async () => {
    const { isCanonicallyEqual } = await import('../src/crypto/multiformats');
    expect(await isCanonicallyEqual({ a: 1 }, { a: 2 })).toBe(false);
  });
});

describe('number encoding determinism', () => {
  it('should encode integers as CBOR integers, producing the correct CID', async () => {
    const { dagCborCanonicalEncode } = await import('../src/crypto/multiformats');
    const payload = { version: 1, type: 'test' };
    const result = await dagCborCanonicalEncode(payload);

    const cborHex = Buffer.from(result.bytes).toString('hex');
    expect(cborHex).toBe('a2647479706564746573746776657273696f6e01');
    expect(result.cid.toString()).toBe(
      'bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa',
    );

    // byte at offset 19 should be 0x01 (CBOR integer), not 0xf9 (float header)
    expect(result.bytes[19]).toBe(0x01);
  });

  it('should produce the same CID when payload is round-tripped through JSON', async () => {
    const { dagCborCanonicalEncode } = await import('../src/crypto/multiformats');

    // simulate JSON round-trip (as happens when decoding a JWS payload)
    const jsonStr = '{"version": 1, "type": "test"}';
    const decoded = JSON.parse(jsonStr);
    const result = await dagCborCanonicalEncode(decoded);

    expect(result.cid.toString()).toBe(
      'bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa',
    );
  });

  it('should handle version 1 and 1.0 identically in JS (no float distinction)', async () => {
    const { dagCborCanonicalEncode } = await import('../src/crypto/multiformats');

    // JS does not distinguish 1 and 1.0 — both are the same number
    const result1 = await dagCborCanonicalEncode({ version: 1, type: 'test' });
    const result2 = await dagCborCanonicalEncode({ version: 1.0, type: 'test' });

    expect(result1.cid.toString()).toBe(result2.cid.toString());
  });
});
