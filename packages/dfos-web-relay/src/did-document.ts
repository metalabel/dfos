/*

  DID DOCUMENT PROJECTION

  Pure, read-only projection of a verified identity chain's terminal state into
  a W3C DID Document + DIF resolution result. This is the DID-core view of the
  same self-certified state the proof plane serves at
  `${PROOF_BASE_PATH}/identities/:did`.

  The mapping is NORMATIVELY specified and FROZEN in specs/DID-METHOD.md §4:
    - §4.1 document structure + @context
    - §4.2 verification-method mapping (authKeys→authentication,
      assertKeys→assertionMethod, controllerKeys→capabilityInvocation),
      dedup by DID-URL id across roles
    - §4.3 controller is always the DID itself
    - §4.5 service[] mapping (DfosRelay→serviceEndpoint,
      ContentAnchor→serviceEndpoint+label, unknown types preserved verbatim)
    - §5.2.2 resolution metadata (created/updated/deactivated/operationCount)
    - §5.4 deactivated identity → empty verification-method set

  No crypto here: VerifiedIdentity already carries publicKeyMultibase on every
  key and a resolved services array. Verification happened at ingest.

*/

import type { VerifiedIdentity } from '@metalabel/dfos-protocol/chain';
import { decodeJwsUnsafe } from '@metalabel/dfos-protocol/crypto';
import type { StoredIdentityChain } from './types';

// -----------------------------------------------------------------------------
// did:dfos identifier validation (DID-METHOD.md §3.1, line 63)
// -----------------------------------------------------------------------------

/**
 * A valid did:dfos is EXACTLY `did:dfos:` + 31 chars over the 19-symbol
 * alphabet `2346789acdefhknrtvz`. Any other length or charset is not a valid
 * did:dfos identifier — resolvers MUST reject it (DID-METHOD.md:63). Note the
 * proof-plane `/identities` route does not width-validate its input; the
 * resolver ADDS this check per the DID-core method contract.
 */
const DFOS_DID_RE = /^did:dfos:[2346789acdefhknrtvz]{31}$/;

export const isValidDfosDid = (did: string): boolean => DFOS_DID_RE.test(did);

// -----------------------------------------------------------------------------
// DID Document + DIF resolution result types (local — no external DID-core dep)
// -----------------------------------------------------------------------------

export interface DidVerificationMethod {
  id: string;
  type: 'Multikey';
  controller: string;
  publicKeyMultibase: string;
}

export interface DidServiceEntry {
  id: string;
  type: string;
  serviceEndpoint?: unknown;
  [key: string]: unknown;
}

export interface DidDocument {
  '@context': [string, string];
  id: string;
  controller: string;
  verificationMethod: DidVerificationMethod[];
  authentication?: string[];
  assertionMethod?: string[];
  capabilityInvocation?: string[];
  service?: DidServiceEntry[];
}

export interface DidDocumentMetadata {
  created?: string;
  updated?: string;
  deactivated: boolean;
  operationCount: number;
}

export interface DidResolutionResult {
  '@context': string;
  didDocument: DidDocument;
  didResolutionMetadata: { contentType: string };
  didDocumentMetadata: DidDocumentMetadata;
}

// -----------------------------------------------------------------------------
// projection
// -----------------------------------------------------------------------------

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/multikey/v1',
] as const;

/** Build a DID-URL verification-method / service id: `did#fragment`. */
const didUrl = (did: string, fragment: string): string => `${did}#${fragment}`;

/**
 * Project a single service entry into its DID Document form (DID-METHOD.md §4.5).
 * Recognized types get an explicit `serviceEndpoint` mapping; unrecognized types
 * are preserved verbatim (envelope + all extra fields) so downstream consumers
 * (e.g. the document gateway's DfosDocumentGateway / DfosProfile) survive a relay
 * that does not recognize them.
 */
const projectService = (
  did: string,
  entry: VerifiedIdentity['services'][number],
): DidServiceEntry => {
  const id = didUrl(did, entry.id);
  if (entry.type === 'DfosRelay') {
    return {
      id,
      type: entry.type,
      serviceEndpoint: (entry as Record<string, unknown>)['endpoint'],
    };
  }
  if (entry.type === 'ContentAnchor') {
    return {
      id,
      type: entry.type,
      serviceEndpoint: (entry as Record<string, unknown>)['anchor'],
      label: (entry as Record<string, unknown>)['label'],
    };
  }
  // unrecognized type: preserve verbatim (MUST-ignore-unknown), re-anchor id
  const { id: _id, type: _type, ...rest } = entry as Record<string, unknown>;
  return { id, type: entry.type, ...rest };
};

/**
 * Build a W3C DID Document from a verified identity's terminal state
 * (DID-METHOD.md §4). A deactivated identity resolves to a minimal document with
 * an empty verification-method set and no verification relationships (§5.4:275).
 */
export const identityToDidDocument = (state: VerifiedIdentity): DidDocument => {
  const did = state.did;

  // deactivated: empty VM set, omit all relationships + services (§5.4)
  if (state.isDeleted) {
    return {
      '@context': [...DID_CONTEXT],
      id: did,
      controller: did,
      verificationMethod: [],
    };
  }

  // dedup verification methods by DID-URL id across roles (§4.2:136), preserving
  // deterministic first-seen order: auth → assert → controller
  const vmById = new Map<string, DidVerificationMethod>();
  for (const key of [...state.authKeys, ...state.assertKeys, ...state.controllerKeys]) {
    const id = didUrl(did, key.id);
    if (!vmById.has(id)) {
      vmById.set(id, {
        id,
        type: 'Multikey',
        controller: did,
        publicKeyMultibase: key.publicKeyMultibase,
      });
    }
  }

  const doc: DidDocument = {
    '@context': [...DID_CONTEXT],
    id: did,
    controller: did,
    verificationMethod: [...vmById.values()],
    authentication: state.authKeys.map((k) => didUrl(did, k.id)),
    assertionMethod: state.assertKeys.map((k) => didUrl(did, k.id)),
    capabilityInvocation: state.controllerKeys.map((k) => didUrl(did, k.id)),
  };

  // service[] is optional in DID-core — omit entirely when empty
  if (state.services.length > 0) {
    doc.service = state.services.map((entry) => projectService(did, entry));
  }

  return doc;
};

/**
 * Build a DIF Universal Resolver resolution result from a resolved chain
 * (DID-METHOD.md §5.2.2). Pure — the chain is already verified terminal state.
 */
export const resolveDidDocument = (chain: StoredIdentityChain): DidResolutionResult => {
  const genesis = chain.log[0] ? decodeJwsUnsafe(chain.log[0]) : null;
  const created = genesis?.payload['createdAt'];

  return {
    '@context': 'https://w3id.org/did-resolution/v1',
    didDocument: identityToDidDocument(chain.state),
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocumentMetadata: {
      ...(typeof created === 'string' ? { created } : {}),
      updated: chain.lastCreatedAt,
      deactivated: chain.state.isDeleted,
      operationCount: chain.log.length,
    },
  };
};
