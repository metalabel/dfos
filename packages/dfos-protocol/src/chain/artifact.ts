/*

  ARTIFACT

  Standalone signed inline document. Proof plane only.

  An artifact is a JWS-signed structured document published by a DID,
  addressed by CID, and immutable once published. Unlike beacons (which
  reference content by CID), artifacts carry their content inline with a
  $schema discriminator.

  Artifacts are bounded by MAX_ARTIFACT_PAYLOAD_SIZE (CBOR-encoded). Content
  that exceeds this limit belongs on the content plane via content chains.

*/

import { createJws, dagCborCanonicalEncode, decodeJwsUnsafe, verifyJws } from '../crypto';
import { ArtifactPayload, MAX_ARTIFACT_PAYLOAD_SIZE } from './schemas';
import type { Signer } from './schemas';

// -----------------------------------------------------------------------------
// types
// -----------------------------------------------------------------------------

export interface VerifiedArtifact {
  payload: ArtifactPayload;
  artifactCID: string;
}

// -----------------------------------------------------------------------------
// signing
// -----------------------------------------------------------------------------

/**
 * Sign an artifact as a JWS
 *
 * Enforces the protocol size limit on the CBOR-encoded payload.
 */
export const signArtifact = async (input: {
  payload: ArtifactPayload;
  signer: Signer;
  kid: string;
}): Promise<{ jwsToken: string; artifactCID: string }> => {
  const encoded = await dagCborCanonicalEncode(input.payload);
  const artifactCID = encoded.cid.toString();

  if (encoded.bytes.length > MAX_ARTIFACT_PAYLOAD_SIZE) {
    throw new Error(
      `artifact payload exceeds max size: ${encoded.bytes.length} > ${MAX_ARTIFACT_PAYLOAD_SIZE}`,
    );
  }

  const jwsToken = await createJws({
    header: { alg: 'EdDSA', typ: 'did:dfos:artifact', kid: input.kid, cid: artifactCID },
    payload: input.payload as unknown as Record<string, unknown>,
    sign: input.signer,
  });

  return { jwsToken, artifactCID };
};

// -----------------------------------------------------------------------------
// verification
// -----------------------------------------------------------------------------

/**
 * Verify an artifact JWS — signature, CID, payload schema, size limit
 */
export const verifyArtifact = async (input: {
  jwsToken: string;
  resolveKey: (kid: string) => Promise<Uint8Array>;
}): Promise<VerifiedArtifact> => {
  const decoded = decodeJwsUnsafe(input.jwsToken);
  if (!decoded) throw new Error('failed to decode artifact JWS');

  // parse payload
  const result = ArtifactPayload.safeParse(decoded.payload);
  if (!result.success) {
    const messages = result.error.issues.map((e) => e.message).join(', ');
    throw new Error(`invalid artifact payload: ${messages}`);
  }
  const payload = result.data;

  // verify typ
  if (decoded.header.typ !== 'did:dfos:artifact') {
    throw new Error(`invalid artifact typ: ${decoded.header.typ}`);
  }

  // verify kid DID matches payload did
  const kid = decoded.header.kid;
  const hashIdx = kid.indexOf('#');
  if (hashIdx < 0) throw new Error('artifact kid must be a DID URL');
  const kidDid = kid.substring(0, hashIdx);
  if (kidDid !== payload.did) {
    throw new Error('artifact kid DID does not match payload did');
  }

  // verify signature
  const publicKey = await input.resolveKey(kid);
  try {
    verifyJws({ token: input.jwsToken, publicKey });
  } catch {
    throw new Error('invalid artifact signature');
  }

  // verify CID — use original decoded payload to preserve all content keys
  const encoded = await dagCborCanonicalEncode(decoded.payload);
  const artifactCID = encoded.cid.toString();
  if (!decoded.header.cid) throw new Error('missing cid in artifact header');
  if (decoded.header.cid !== artifactCID) throw new Error('artifact cid mismatch');

  // enforce size limit
  if (encoded.bytes.length > MAX_ARTIFACT_PAYLOAD_SIZE) {
    throw new Error(
      `artifact payload exceeds max size: ${encoded.bytes.length} > ${MAX_ARTIFACT_PAYLOAD_SIZE}`,
    );
  }

  return { payload, artifactCID };
};
