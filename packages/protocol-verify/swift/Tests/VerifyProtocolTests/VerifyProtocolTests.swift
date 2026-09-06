// DFOS Protocol — Independent verification in Swift
//
// Verifies all deterministic reference artifacts from the protocol specification.
// Uses Apple's swift-crypto for Ed25519.
//
// Run: swift test

import Crypto
import Foundation
import Testing

// =============================================================================
// Shared reference vectors
// =============================================================================
//
// Every expected value below is read from the package's vectors.json — the one
// artifact all five suites share, generated from the protocol's fixed seeds by
// packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
// checked-in file is byte-identical to a fresh generation.
//
// Reading a JSON fixture is not a library import. This suite still uses only
// the language's native Ed25519, CBOR and SHA-256, and a third party can run it
// with nothing but this file and vectors.json.

private func loadVectors() -> [String: [String: Any]] {
    let vectorsURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // VerifyProtocolTests/
        .deletingLastPathComponent()  // Tests/
        .deletingLastPathComponent()  // swift/
        .deletingLastPathComponent()  // protocol-verify/
        .appendingPathComponent("vectors.json")
    guard let data = try? Data(contentsOf: vectorsURL),
        let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let entries = parsed["vectors"] as? [[String: Any]]
    else {
        fatalError("cannot read \(vectorsURL.path)")
    }
    var byID: [String: [String: Any]] = [:]
    for entry in entries {
        guard let id = entry["id"] as? String, let values = entry["values"] as? [String: Any] else {
            fatalError("malformed vector entry in vectors.json")
        }
        byID[id] = values
    }
    return byID
}

// Read once at first use and never mutated afterwards, so the unchecked global
// is safe: every accessor below only reads it.
nonisolated(unsafe) let vectorsByID = loadVectors()

/// All values of one vector, by id.
func vectorValues(_ id: String) -> [String: Any] {
    guard let values = vectorsByID[id] else {
        fatalError("vectors.json has no vector \"\(id)\"")
    }
    return values
}

/// One string field of one vector.
func vec(_ id: String, _ field: String) -> String {
    guard let value = vectorValues(id)[field] as? String else {
        fatalError("vectors.json \(id).\(field) is not a string")
    }
    return value
}

/// One object field of one vector (a document, an operation payload).
func vecObject(_ id: String, _ field: String) -> [String: Any] {
    guard let value = vectorValues(id)[field] as? [String: Any] else {
        fatalError("vectors.json \(id).\(field) is not an object")
    }
    return value
}

/// One string-array field of one vector.
func vecStrings(_ id: String, _ field: String) -> [String] {
    guard let value = vectorValues(id)[field] as? [String] else {
        fatalError("vectors.json \(id).\(field) is not a string array")
    }
    return value
}

/// One string→string map field of one vector, as id-sorted pairs.
func vecStringPairs(_ id: String, _ field: String) -> [(String, String)] {
    guard let value = vectorValues(id)[field] as? [String: String] else {
        fatalError("vectors.json \(id).\(field) is not a string map")
    }
    return value.keys.sorted().map { ($0, value[$0]!) }
}

// =============================================================================
// Constants from the reference doc
// =============================================================================

let genesisJWS = vec("identity-genesis", "jws")
let rotationJWS = vec("identity-rotation", "jws")
let deleteJWS = vec("identity-delete", "jws")
let restoreJWS = vec("identity-restore", "jws")
let contentCreateJWS = vec("content-create", "jws")
let jwtToken = vec("jwt", "token")

let expectedGenCID = vec("identity-genesis", "cid")
let expectedDID = vec("identity-genesis", "did")
let expectedMultikey1 = vec("key-1", "multikey")
let expectedMultikey2 = vec("key-2", "multikey")

/// The possession proof the rotation carries. The envelope's payload is CLOSED:
/// exactly these seven members, in exactly this order — and the octets are the
/// only serialization those members are ever signed as. The envelope is signed
/// by key 2 (the key being introduced) while the operation carrying it is signed
/// by key 1.
let keyProofMembers = vecStrings("key-proof", "members")
let keyProofRoleSet = vec("key-proof", "roleSet")
let keyProofCanonicalPayload = vec("key-proof", "canonicalPayload")

let expectedCBORHex = vec("identity-genesis", "cborHex")
let expectedCIDHex = vec("identity-genesis", "cidBytesHex")

let alphabet = "2346789acdefhknrtvz"
let idLength = 31

// =============================================================================
// Helpers
// =============================================================================

/// Decode base64url (no padding) to Data.
func b64urlDecode(_ s: String) -> Data {
    var b64 = s
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = b64.count % 4
    if remainder != 0 {
        b64 += String(repeating: "=", count: 4 - remainder)
    }
    guard let data = Data(base64Encoded: b64) else {
        fatalError("base64url decode failed")
    }
    return data
}

/// Base58 Bitcoin alphabet.
private let b58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

/// Base58 encode bytes.
func base58Encode(_ bytes: [UInt8]) -> String {
    var digits: [UInt8] = [0]
    for byte in bytes {
        var carry = Int(byte)
        for j in 0..<digits.count {
            carry += Int(digits[j]) * 256
            digits[j] = UInt8(carry % 58)
            carry /= 58
        }
        while carry > 0 {
            digits.append(UInt8(carry % 58))
            carry /= 58
        }
    }
    let leadingZeros = bytes.prefix(while: { $0 == 0 }).count
    let prefix = String(repeating: b58Alphabet[0], count: leadingZeros)
    return prefix + digits.reversed().map({ b58Alphabet[Int($0)] }).map(String.init).joined()
}

/// Base58 decode string to bytes.
func base58Decode(_ s: String) -> [UInt8] {
    var digits: [UInt8] = [0]
    for c in s {
        guard let idx = b58Alphabet.firstIndex(of: c) else { fatalError("invalid base58 char") }
        var carry = idx
        for j in 0..<digits.count {
            carry += Int(digits[j]) * 58
            digits[j] = UInt8(carry % 256)
            carry /= 256
        }
        while carry > 0 {
            digits.append(UInt8(carry % 256))
            carry /= 256
        }
    }
    let leadingOnes = s.prefix(while: { $0 == b58Alphabet[0] }).count
    return Array(repeating: UInt8(0), count: leadingOnes) + digits.reversed().drop(while: { $0 == 0 })
}

/// Encode raw Ed25519 public key bytes as a multikey string (base58btc with 0xed01 prefix).
func encodeMultikey(_ pubBytes: [UInt8]) -> String {
    let raw: [UInt8] = [0xed, 0x01] + pubBytes
    return "z" + base58Encode(raw)
}

/// Decode a multikey string to raw Ed25519 public key bytes.
func decodeMultikey(_ multibase: String) -> [UInt8] {
    precondition(multibase.first == "z", "expected base58btc multibase prefix 'z'")
    let raw = base58Decode(String(multibase.dropFirst()))
    precondition(raw[0] == 0xed && raw[1] == 0x01, "expected ed25519-pub multicodec prefix")
    return Array(raw[2...])
}

/// Build CIDv1 bytes from CBOR bytes: version(0x01) + codec(0x71=dag-cbor) + multihash(sha256).
func makeCIDBytes(_ cborBytes: [UInt8]) -> [UInt8] {
    let digest = SHA256.hash(data: cborBytes)
    return [0x01, 0x71, 0x12, 0x20] + Array(digest)
}

/// Encode CID bytes as base32lower multibase (prefix 'b', no padding).
func cidToBase32(_ cidBytes: [UInt8]) -> String {
    let data = Data(cidBytes)
    let encoded = base32Encode(data)
    return "b" + encoded.lowercased()
}

/// RFC 4648 base32 encode (no padding).
func base32Encode(_ data: Data) -> String {
    let alphabet: [Character] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    var result = ""
    var buffer: UInt64 = 0
    var bitsLeft = 0

    for byte in data {
        buffer = (buffer << 8) | UInt64(byte)
        bitsLeft += 8
        while bitsLeft >= 5 {
            bitsLeft -= 5
            let index = Int((buffer >> bitsLeft) & 0x1f)
            result.append(alphabet[index])
        }
    }
    if bitsLeft > 0 {
        let index = Int((buffer << (5 - bitsLeft)) & 0x1f)
        result.append(alphabet[index])
    }
    return result
}

/// Decode hex string to bytes.
func hexDecode(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        let byteString = hex[index..<nextIndex]
        bytes.append(UInt8(byteString, radix: 16)!)
        index = nextIndex
    }
    return bytes
}

/// Encode bytes to hex string.
func hexEncode(_ bytes: some Sequence<UInt8>) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Encode DID suffix from hash bytes using custom alphabet.
func encodeID(_ hashBytes: [UInt8]) -> String {
    let chars = Array(alphabet)
    return String(hashBytes.prefix(idLength).map { chars[Int($0) % 19] })
}

/// Ed25519 group order L (little-endian 32 bytes) — the canonical S < L bound.
let ed25519L: [UInt8] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]

/// Returns true iff the 32-byte little-endian scalar s is < L.
func scalarIsCanonical(_ s: [UInt8]) -> Bool {
    if s.count != 32 { return false }
    for i in stride(from: 31, through: 0, by: -1) {
        if s[i] < ed25519L[i] { return true }
        if s[i] > ed25519L[i] { return false }
    }
    return false  // s == L is non-canonical
}

struct JWSRejected: Error { let reason: String }

/// DFOS Signature Verification Profile (pragmatic v1) header gates — applied
/// BEFORE any signature check. Throws JWSRejected on any violation.
func assertJWSProfile(_ header: [String: Any]) throws {
    guard header["alg"] as? String == "EdDSA" else {
        throw JWSRejected(reason: "unsupported algorithm")
    }
    if header["crit"] != nil { throw JWSRejected(reason: "crit header is not supported") }
    if header["jwk"] != nil { throw JWSRejected(reason: "jwk header is not allowed") }
    if header["x5c"] != nil { throw JWSRejected(reason: "x5c header is not allowed") }
}

/// Profile-aware JWS verification — applies alg pin, crit, no header-key-trust,
/// 64-byte length, and the canonical S < L gate BEFORE the signature check.
/// Throws on any violation so the reject corpus can assert rejection.
func verifyJWSProfiled(_ token: String, pubKey: Curve25519.Signing.PublicKey) throws -> (header: [String: Any], payload: [String: Any]) {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    guard parts.count == 3 else { throw JWSRejected(reason: "invalid JWS format") }

    let headerData = b64urlDecode(parts[0])
    guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
        throw JWSRejected(reason: "parse header")
    }

    // profile gates run before any signature work
    try assertJWSProfile(header)

    let signingInput = Data((parts[0] + "." + parts[1]).utf8)
    let signature = b64urlDecode(parts[2])

    // length + canonical-scalar (S < L) gates
    guard signature.count == 64 else { throw JWSRejected(reason: "signature must be 64 bytes") }
    if !scalarIsCanonical(Array(signature[32..<64])) {
        throw JWSRejected(reason: "non-canonical signature scalar (S >= L)")
    }

    guard pubKey.isValidSignature(signature, for: signingInput) else {
        throw JWSRejected(reason: "signature verification failed")
    }

    let payloadData = b64urlDecode(parts[1])
    let payload = try! JSONSerialization.jsonObject(with: payloadData) as! [String: Any]
    return (header, payload)
}

/// Verify a JWS (or JWT) token with an Ed25519 public key, returning parsed header and payload.
func verifyJWS(_ token: String, pubKey: Curve25519.Signing.PublicKey) -> (header: [String: Any], payload: [String: Any]) {
    return try! verifyJWSProfiled(token, pubKey: pubKey)
}

// =============================================================================
// Tests
// =============================================================================

@Test func keyDerivation() {
    // Key 1
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)
    let pub1 = Array(priv1.publicKey.rawRepresentation)

    #expect(hexEncode(seed1) == vec("key-1", "privateKeyHex"))
    #expect(hexEncode(pub1) == vec("key-1", "publicKeyHex"))

    // Key 2
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)
    let pub2 = Array(priv2.publicKey.rawRepresentation)

    #expect(hexEncode(seed2) == vec("key-2", "privateKeyHex"))
    #expect(hexEncode(pub2) == vec("key-2", "publicKeyHex"))
}

@Test func multikeyEncoding() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)
    let pub1 = Array(priv1.publicKey.rawRepresentation)

    let encoded = encodeMultikey(pub1)
    #expect(encoded == expectedMultikey1)

    let decoded = decodeMultikey(expectedMultikey1)
    #expect(decoded == pub1)
}

@Test func jwsGenesisVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(genesisJWS, pubKey: priv1.publicKey)
    #expect(header["alg"] as? String == "EdDSA")
    #expect(header["typ"] as? String == vec("identity-genesis", "typ"))
    #expect(header["kid"] as? String == vec("identity-genesis", "kid"))
    #expect(header["cid"] as? String == expectedGenCID)
    #expect(payload["type"] as? String == "create")
    #expect(payload["version"] as? Int == 1)
}

@Test func jwsRotationVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(rotationJWS, pubKey: priv1.publicKey)
    #expect(header["kid"] as? String == vec("identity-rotation", "kid"))
    #expect(header["cid"] as? String == vec("identity-rotation", "cid"))
    #expect(payload["type"] as? String == "update")
    #expect(payload["previousOperationCID"] as? String == expectedGenCID)
}

/// Verify the possession proof embedded in the rotation operation. The
/// OPERATION is signed by key 1; the envelope inside it is signed by key 2 — the
/// key being introduced — against the key named in the envelope's own payload.
/// That circularity is the possession proof. The payload is closed: exactly
/// seven members, one order, one serialization.
@Test func keyProofCarriedByRotation() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)
    let pub2 = Array(priv2.publicKey.rawRepresentation)

    let (_, payload) = verifyJWS(rotationJWS, pubKey: priv1.publicKey)
    let proofs = payload["keyProofs"] as? [String]
    #expect(proofs?.count == 1, "rotation must carry exactly one key proof")
    let envelope = proofs![0]

    let parts = envelope.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    #expect(parts.count == 3, "key proof must be a compact JWS")

    let headerText = String(data: b64urlDecode(parts[0]), encoding: .utf8)!
    let payloadText = String(data: b64urlDecode(parts[1]), encoding: .utf8)!
    let header = try! JSONSerialization.jsonObject(with: Data(headerText.utf8)) as! [String: Any]
    let proof = try! JSONSerialization.jsonObject(with: Data(payloadText.utf8)) as! [String: Any]

    #expect(header["alg"] as? String == "EdDSA")
    #expect(header["typ"] as? String == "did:dfos:key-add")
    #expect(header.count == 2, "key proof header must be exactly {alg, typ}")

    // The load-bearing check: the presented octets ARE the canonical
    // serialization. The bytes bind the verifier, not only the signer.
    #expect(payloadText == keyProofCanonicalPayload, "key proof payload is not the canonical serialization")
    #expect(proof.count == 7, "key proof payload must have exactly seven members")

    var cursor = -1
    var ordered = true
    for member in keyProofMembers {
        let at = payloadText.range(of: "\"\(member)\":").map {
            payloadText.distance(from: payloadText.startIndex, to: $0.lowerBound)
        } ?? -1
        if at <= cursor { ordered = false }
        cursor = at
    }
    #expect(ordered, "key proof members are not in canonical order")

    #expect(proof["did"] as? String == expectedDID)
    #expect(proof["prevCID"] as? String == expectedGenCID)
    #expect(proof["roleSet"] as? String == keyProofRoleSet)
    #expect(proof["publicKeyMultibase"] as? String == expectedMultikey2)

    // The signature verifies against the key the payload itself names — there is
    // no resolver seam here.
    let proofKey = decodeMultikey(proof["publicKeyMultibase"] as! String)
    #expect(proofKey == pub2, "key proof key is not reference key 2")
    let proofPub = try! Curve25519.Signing.PublicKey(rawRepresentation: Data(proofKey))

    let sig = b64urlDecode(parts[2])
    #expect(sig.count == 64, "key proof signature must be 64 bytes")
    #expect(scalarIsCanonical(Array(sig[32..<64])), "non-canonical key proof signature scalar (S >= L)")
    let signingInput = Data((parts[0] + "." + parts[1]).utf8)
    #expect(
        proofPub.isValidSignature(sig, for: signingInput),
        "key proof signature verification failed under its own named key")
}

@Test func jwsDeleteRestoreVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (deleteHeader, deletePayload) = verifyJWS(deleteJWS, pubKey: priv2.publicKey)
    #expect(deletePayload["type"] as? String == "delete")
    #expect(
        deletePayload["previousOperationCID"] as? String
            == vec("identity-delete", "previousOperationCID"))
    let deleteCID = cidToBase32(makeCIDBytes(encodeCBOR(deletePayload)))
    #expect(deleteCID == deleteHeader["cid"] as? String)
    #expect(deleteCID == vec("identity-delete", "cid"))

    let (restoreHeader, restorePayload) = verifyJWS(restoreJWS, pubKey: priv2.publicKey)
    #expect(restorePayload["type"] as? String == "restore")
    #expect(restorePayload["previousOperationCID"] as? String == deleteCID)
    let restoreCID = cidToBase32(makeCIDBytes(encodeCBOR(restorePayload)))
    #expect(restoreCID == restoreHeader["cid"] as? String)
    #expect(restoreCID == vec("identity-restore", "cid"))
}

@Test func jwsContentCreateVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(contentCreateJWS, pubKey: priv2.publicKey)
    #expect(header["typ"] as? String == vec("content-create", "typ"))
    #expect(header["kid"] as? String == vec("content-create", "kid"))
    #expect(header["cid"] as? String == vec("content-create", "cid"))
    #expect(payload["type"] as? String == "create")
}

@Test func jwtVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(jwtToken, pubKey: priv2.publicKey)
    #expect(header["alg"] as? String == "EdDSA")
    #expect(header["typ"] as? String == "JWT")
    #expect(payload["iss"] as? String == "dfos")
    #expect(payload["sub"] as? String == expectedDID)
    #expect(payload["aud"] as? String == "dfos-api")
}

@Test func cidDerivation() {
    let cborBytes = hexDecode(expectedCBORHex)
    let cidBytes = makeCIDBytes(cborBytes)
    #expect(hexEncode(cidBytes) == expectedCIDHex)

    let cidStr = cidToBase32(cidBytes)
    #expect(cidStr == expectedGenCID)
}

@Test func didDerivation() {
    let cidBytes = hexDecode(expectedCIDHex)
    let didHash = Array(SHA256.hash(data: cidBytes))
    let suffix = encodeID(didHash)
    #expect(suffix == "cnnnft9f8a2rn938d6nkz38r847v2kr")

    let did = "did:dfos:\(suffix)"
    #expect(did == expectedDID)
}

// =========================================================================
// Services-genesis and credential tests
// =========================================================================

/// The canonical services-genesis identity-op: a create op carrying a full-state
/// services array (relay locator + content/artifact anchors), signed by
/// reference key 1.
let servicesGenesisJWS = vec("services-genesis", "jws")

let expectedServicesGenCID = vec("services-genesis", "cid")
let expectedServicesDID = vec("services-genesis", "did")

let broadWriteVC = vec("credential-write", "jws")

let readVC = vec("credential-read", "jws")

/// Verify the canonical services-genesis identity-op: signature check with
/// reference key 1, then an independent recomputation of the operation CID over
/// the decoded payload (services fields ride along in the payload map — no
/// services-validation logic required here), asserting it equals the JWS header
/// cid and that the derived DID matches.
@Test func servicesGenesisVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(servicesGenesisJWS, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == vec("services-genesis", "typ"))
    #expect(header["kid"] as? String == vec("services-genesis", "kid"))
    #expect(header["cid"] as? String == expectedServicesGenCID)
    #expect(payload["type"] as? String == "create")

    // Recompute the operation CID over the decoded payload and assert it matches
    // the value committed in the JWS header.
    let cborBytes = encodeCBOR(payload)
    let cidBytes = makeCIDBytes(cborBytes)
    #expect(cidToBase32(cidBytes) == expectedServicesGenCID)

    // Derive the DID from the operation CID bytes and assert it matches.
    let didHash = Array(SHA256.hash(data: Data(cidBytes)))
    let did = "did:dfos:\(encodeID(didHash))"
    #expect(did == expectedServicesDID)
}

@Test func writeCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    expectCredential(broadWriteVC, pubKey: priv1.publicKey, id: "credential-write")
}

@Test func readCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    expectCredential(readVC, pubKey: priv1.publicKey, id: "credential-read")
}

/// Check one credential JWS against the shared vector of the given id: signature
/// under the issuer key, then every published header and payload field.
func expectCredential(_ token: String, pubKey: Curve25519.Signing.PublicKey, id: String) {
    let (header, payload) = verifyJWS(token, pubKey: pubKey)
    #expect(header["typ"] as? String == vec(id, "typ"))
    #expect(header["kid"] as? String == vec(id, "kid"))
    #expect(header["cid"] as? String == vec(id, "cid"))
    #expect(payload["type"] as? String == "DFOSCredential")
    #expect(payload["iss"] as? String == vec(id, "iss"))
    #expect(payload["aud"] as? String == vec(id, "aud"))

    let att = payload["att"] as! [[String: Any]]
    #expect(att.count == 1)
    #expect(att[0]["resource"] as? String == vec(id, "resource"))
    #expect(att[0]["action"] as? String == vec(id, "action"))
}

/// Re-derive the CID of the content document the create operation commits to.
/// The document itself is the shared vector: encode it as canonical dag-cbor and
/// the published CID must come back out.
@Test func documentCIDVerification() {
    let document = vecObject("document", "value")
    let cid = cidToBase32(makeCIDBytes(encodeCBOR(document)))
    #expect(cid == vec("document", "cid"))
}

// =============================================================================
// Minimal DAG-CBOR encoder (map + text + uint + float64 only)
// =============================================================================

/// Encode a single CBOR value. Supported types: String, Int, Double, [String: Any],
/// [Any] (arrays), and NSNull. Map keys are sorted by (length, lexicographic) per
/// RFC 7049 canonical ordering.
func encodeCBOR(_ value: Any) -> [UInt8] {
    switch value {
    case is NSNull:
        // major type 7, value 22 = null
        return [0xf6]
    case let arr as [Any]:
        precondition(arr.count < 24, "only small arrays supported")
        var result = [UInt8(0x80 | arr.count)]
        for e in arr { result += encodeCBOR(e) }
        return result
    case let s as String:
        let bytes = Array(s.utf8)
        // major type 3 (text), canonical length head — handles strings ≥ 24 bytes
        return cborHead(major: 3, length: UInt64(bytes.count)) + bytes
    case let u as UInt64:
        return encodeCBORUInt(u)
    case let i as Int:
        if i >= 0 { return encodeCBORUInt(UInt64(i)) }
        precondition(false, "negative integers not needed by these vectors")
        return []
    case let d as Double:
        // major type 7, additional 27 = 64-bit IEEE 754
        let bits = d.bitPattern
        var result: [UInt8] = [0xfb]
        for shift in stride(from: 56, through: 0, by: -8) {
            result.append(UInt8((bits >> shift) & 0xff))
        }
        return result
    case let m as [String: Any]:
        precondition(m.count < 24, "only small maps supported")
        var header = [UInt8(0xa0 | m.count)]
        // DAG-CBOR canonical key order: sort by encoded key bytes (length, then lexicographic)
        let sortedKeys = m.keys.sorted { a, b in
            let ab = Array(a.utf8), bb = Array(b.utf8)
            if ab.count != bb.count { return ab.count < bb.count }
            return ab.lexicographicallyPrecedes(bb)
        }
        var body: [UInt8] = []
        for key in sortedKeys {
            body += encodeCBOR(key)
            body += encodeCBOR(m[key]!)
        }
        return header + body
    default:
        fatalError("unsupported CBOR value type: \(type(of: value))")
    }
}

/// Encode an unsigned integer as a CBOR major-type-0 value using the shortest
/// canonical form (matches dag-cbor / RFC 8949 deterministic encoding).
func encodeCBORUInt(_ u: UInt64) -> [UInt8] {
    if u < 24 {
        return [UInt8(u)]
    } else if u <= UInt64(UInt8.max) {
        return [0x18, UInt8(u)]
    } else if u <= UInt64(UInt16.max) {
        return [0x19, UInt8((u >> 8) & 0xff), UInt8(u & 0xff)]
    } else if u <= UInt64(UInt32.max) {
        var out: [UInt8] = [0x1a]
        for shift in stride(from: 24, through: 0, by: -8) { out.append(UInt8((u >> shift) & 0xff)) }
        return out
    } else {
        var out: [UInt8] = [0x1b]
        for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((u >> shift) & 0xff)) }
        return out
    }
}

/// Emit a CBOR head byte (and any trailing length bytes) for the given major
/// type and argument, using the shortest canonical length encoding per RFC 8949
/// deterministic rules. Reuses encodeCBORUInt's length-byte logic, OR-ing the
/// major type into the leading byte.
func cborHead(major: UInt8, length: UInt64) -> [UInt8] {
    var head = encodeCBORUInt(length)
    head[0] |= (major << 5)
    return head
}

// MARK: - Number encoding determinism tests

@Test func testNumberEncodingDeterminism() {
    // Integer 1 must encode as CBOR uint, not float — keys sorted: "type" (4) before "version" (7)
    let payload: [String: Any] = ["version": 1, "type": "test"]
    let cborBytes = encodeCBOR(payload)

    #expect(hexEncode(cborBytes) == vec("number-integer", "cborHex"))

    let cidBytes = makeCIDBytes(cborBytes)
    let cid = cidToBase32(cidBytes)
    #expect(cid == vec("number-integer", "cid"))
}

@Test func testNumberEncodingFromJSON() {
    // JSONSerialization must preserve integer type (not promote to Double) through the pipeline
    let jsonData = Data(#"{"version": 1, "type": "test"}"#.utf8)
    let parsed = try! JSONSerialization.jsonObject(with: jsonData) as! [String: Any]

    // Confirm Swift parsed "1" as Int (not Double) — this is the invariant being tested
    #expect(parsed["version"] is Int)

    let cborBytes = encodeCBOR(parsed)
    let cidBytes = makeCIDBytes(cborBytes)
    let cid = cidToBase32(cidBytes)
    #expect(cid == vec("number-integer", "cid"))
}

@Test func testNumberEncodingFloatProducesWrongCID() {
    // The float serialization a conforming encoder MUST NOT emit, and the CID it
    // yields — the shared vector every suite pins as the known-wrong answer.
    let floatCBOR = hexDecode(vec("number-integer", "floatCborHex"))
    let floatCID = cidToBase32(makeCIDBytes(floatCBOR))
    #expect(floatCID == vec("number-integer", "floatCid"))
    #expect(floatCID != vec("number-integer", "cid"))
}

// =============================================================================
// Reject corpus — every conformant verifier MUST reject all of these.
// Byte-identical inputs across all five language suites. Reference key 1 signs.
// =============================================================================

let rejectPub1Hex = vec("reject-corpus", "publicKeyHex")

let rejectVectors: [(String, String)] = vecStringPairs("reject-corpus", "tokens")

@Test func rejectCorpus() {
    let pubBytes = hexDecode(rejectPub1Hex)
    let pubKey = try! Curve25519.Signing.PublicKey(rawRepresentation: Data(pubBytes))
    for (name, token) in rejectVectors {
        var rejected = false
        do {
            _ = try verifyJWSProfiled(token, pubKey: pubKey)
        } catch {
            rejected = true
        }
        #expect(rejected, "\(name): expected rejection, got accept")
    }
}

// =============================================================================
// WP-0 number-policy vectors. CIDs are byte-identical across all five suites.
// =============================================================================

let maxSafeCanonicalInteger: UInt64 = 9007199254740991  // 2^53 - 1

/// Reject NaN, ±Inf, non-integers, and integers outside ±(2^53-1).
func assertCanonicalNumber(_ val: Double) -> Bool {
    if !val.isFinite { return false }
    if val.truncatingRemainder(dividingBy: 1) != 0 { return false }
    if val > Double(maxSafeCanonicalInteger) || val < -Double(maxSafeCanonicalInteger) { return false }
    return true
}

@Test func testNumberPolicyAcceptMaxSafe() {
    // { "n": 2^53-1 } — accepted, encodes to the reference CID
    #expect(assertCanonicalNumber(Double(maxSafeCanonicalInteger)))
    let payload: [String: Any] = ["n": maxSafeCanonicalInteger]
    let cborBytes = encodeCBOR(payload)
    let cid = cidToBase32(makeCIDBytes(cborBytes))
    #expect(cid == vec("number-max-safe", "cid"))
}

@Test func testNumberPolicyRejects() {
    #expect(!assertCanonicalNumber(9007199254740992.0))  // 2^53
    #expect(!assertCanonicalNumber(1.5))
    #expect(!assertCanonicalNumber(Double.nan))
    #expect(!assertCanonicalNumber(Double.infinity))
    #expect(!assertCanonicalNumber(-Double.infinity))
}

@Test func testNumberPolicyNullVector() {
    // { "documentCID": null, "note": null, "prf": [] }
    let payload: [String: Any] = [
        "documentCID": NSNull(),
        "note": NSNull(),
        "prf": [Any](),
    ]
    let cborBytes = encodeCBOR(payload)
    let cid = cidToBase32(makeCIDBytes(cborBytes))
    #expect(cid == vec("number-null-vector", "cid"))
}
