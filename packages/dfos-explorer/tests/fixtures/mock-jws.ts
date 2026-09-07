const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

/** A decodable JWS with a complete protected header and a placeholder signature. */
export const mockJws = (
  header: { typ: string; kid?: string; cid?: string },
  payload: Record<string, unknown>,
): string =>
  `${b64url({ alg: 'EdDSA', kid: 'did:dfos:issuer#key_test', ...header })}.${b64url(payload)}.sig`;
