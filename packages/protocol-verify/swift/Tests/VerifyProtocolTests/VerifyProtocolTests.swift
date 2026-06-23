// DFOS Protocol — Independent verification in Swift
//
// Verifies all deterministic reference artifacts from the TypeScript implementation.
// Uses Apple's swift-crypto for Ed25519.
//
// Run: swift test

import Crypto
import Foundation
import Testing

// =============================================================================
// Constants from the reference doc
// =============================================================================

let genesisJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg"

let rotationJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw"

let contentCreateJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWQyNmJhZ241Y2ZlZTN4cHRhZmptYmx4d3VkdzQzNXA2cms1ZzNwNGdqdGtudXlscnhzc3kifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.mTRCvPga89hVeu-gNowrL8TApoGJlxVQBw3CzrvEA-LxAQaSp03Uyn0JwdhPWh22UtwZTe2d27IIuJ7P-5PtAA"

let jwtToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4In0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.VdrDMOQoFAboxK165ZDOe5YXTgILUDO_bHuGHinupqEd4dptibATmyI9YrjseMaJHS4gggzX1st9qO5eoVJdCQ"

let expectedGenCID = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
let expectedDID = "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
let expectedMultikey1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
let expectedCBORHex = "a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
let expectedCIDHex = "017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69"

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

    #expect(hexEncode(seed1) == "132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac")
    #expect(hexEncode(pub1) == "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32")

    // Key 2
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)
    let pub2 = Array(priv2.publicKey.rawRepresentation)

    #expect(hexEncode(seed2) == "384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8")
    #expect(hexEncode(pub2) == "0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c")
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
    #expect(header["typ"] as? String == "did:dfos:identity-op")
    #expect(header["kid"] as? String == "key_r9ev34fvc23z999veaaft83nn29zvhe")
    #expect(header["cid"] as? String == expectedGenCID)
    #expect(payload["type"] as? String == "create")
    #expect(payload["version"] as? Int == 1)
}

@Test func jwsRotationVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(rotationJWS, pubKey: priv1.publicKey)
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft83nn29zvhe")
    #expect(header["cid"] as? String == "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei")
    #expect(payload["type"] as? String == "update")
    #expect(payload["previousOperationCID"] as? String == expectedGenCID)
}

@Test func jwsContentCreateVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(contentCreateJWS, pubKey: priv2.publicKey)
    #expect(header["typ"] as? String == "did:dfos:content-op")
    #expect(header["kid"] as? String == "\(expectedDID)#key_ez9a874tckr3dv933d3ckdn7z6zrct8")
    #expect(header["cid"] as? String == "bafyreid26bagn5cfee3xptafjmblxwudw435p6rk5g3p4gjtknuylrxssy")
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

/// servicesGenesisJWS is the canonical services-genesis identity-op: a create
/// op carrying a full-state services array (relay locator + content/artifact
/// anchors). Signed by reference key 1. Sourced from
/// packages/dfos-protocol/examples/identity-services.json chain[0].
let servicesGenesisJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpZGkzcXBzM3F0dHFwMjJtM3kzM2JkYmYyaXlrYnE1cjQ1ampod2EzN21nZXNvdjdzZGd6ZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJzZXJ2aWNlcyI6W3siaWQiOiJyZWxheSIsInR5cGUiOiJEZm9zUmVsYXkiLCJlbmRwb2ludCI6Imh0dHBzOi8vcmVsYXkuZGZvcy5jb20ifSx7ImlkIjoicHJvZmlsZSIsInR5cGUiOiJDb250ZW50QW5jaG9yIiwibGFiZWwiOiJwcm9maWxlIiwiYW5jaG9yIjoiY3Y3bjh2a3ZyNjRjY3RmMzI5NGg5azRlYW5oZmY4eiJ9LHsiaWQiOiJhdmF0YXIiLCJ0eXBlIjoiQ29udGVudEFuY2hvciIsImxhYmVsIjoiYXZhdGFyIiwiYW5jaG9yIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.HCzVJXcUzL62lxtC8omBlit1JNSWk4b4kQKjjjWT00honzZ9-k3dKusIRuhTV6gjT1M74bLVZYUxPb8kJvhHAw"

let expectedServicesGenCID = "bafyreidi3qps3qttqp22m3y33bdbf2iykbq5r45jjhwa37mgesov7sdgze"
let expectedServicesDID = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar"

let broadWriteVC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWZ5aW5ieGhicml0NTZtM2FhdjY2bXc0eGQ2YWRxamFzdmNmaG11NjZnNnRudXFncnljbG0ifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.A-EygURAN2bALVwI2AZKFEuy30ZnWJFBaD4jCTf1d7A90rYELStjTWJ1iI7OulihTCfaVtlvj5HtX6Dwv1VxAg"

let readVC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWN0aGNiaXp4dmdlbXN4djdrc2NvbzdhcGllYWFsM2Z5ZTM3bzQ1Zmt5a25lN2I0aG9icmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.UvTItuWFriA39FZIdB5TuXa_b07eyNLc-iR0cej2litSkjBYAZaLlDJUmyDQ-3dB7TmNVXDbB3SMbpvLnWW9Dw"

/// Verify the canonical services-genesis identity-op: signature check with
/// reference key 1, then an independent recomputation of the operation CID over
/// the decoded payload (services fields ride along in the payload map — no
/// services-validation logic required here), asserting it equals the JWS header
/// cid and that the derived DID matches.
@Test func servicesGenesisVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(servicesGenesisJWS, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:identity-op")
    #expect(header["kid"] as? String == "key_r9ev34fvc23z999veaaft83nn29zvhe")
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

    let (header, payload) = verifyJWS(broadWriteVC, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:credential")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft83nn29zvhe")
    #expect(payload["type"] as? String == "DFOSCredential")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["aud"] as? String == "did:dfos:94ah7963n223k8c9884hh27ekh42nea")

    let att = payload["att"] as! [[String: Any]]
    #expect(att.count == 1)
    #expect(att[0]["resource"] as? String == "chain:*")
    #expect(att[0]["action"] as? String == "write")
}

@Test func readCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(readVC, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:credential")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft83nn29zvhe")
    #expect(payload["type"] as? String == "DFOSCredential")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["aud"] as? String == "did:dfos:94ah7963n223k8c9884hh27ekh42nea")

    let att = payload["att"] as! [[String: Any]]
    #expect(att.count == 1)
    #expect(att[0]["resource"] as? String == "chain:*")
    #expect(att[0]["action"] as? String == "read")
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

    #expect(hexEncode(cborBytes) == "a2647479706564746573746776657273696f6e01")

    let cidBytes = makeCIDBytes(cborBytes)
    let cid = cidToBase32(cidBytes)
    #expect(cid == "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa")
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
    #expect(cid == "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa")
}

@Test func testNumberEncodingFloatProducesWrongCID() {
    // Explicitly using Double 1.0 produces a different (wrong) CID — documents the failure mode.
    // The exact wrong CID depends on float precision (float16/32/64) which varies by CBOR library.
    // The important invariant: float encoding MUST NOT produce the correct (integer) CID.
    let correctCID = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"

    let payload: [String: Any] = ["version": Double(1.0), "type": "test"]
    let cborBytes = encodeCBOR(payload)
    let cidBytes = makeCIDBytes(cborBytes)
    let cid = cidToBase32(cidBytes)

    #expect(cid != correctCID)
}

// =============================================================================
// Reject corpus — every conformant verifier MUST reject all of these.
// Byte-identical inputs across all five language suites. Reference key 1 signs.
// =============================================================================

let rejectPub1Hex = "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32"

let rejectVectors: [(String, String)] = [
    ("RV-LEN-SHORT", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2"),
    ("RV-LEN-LONG", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQA"),
    ("RV-S-NONCANON-PLUSL", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAFq4vaNrS7wPMIBVCWm3qp0JC5obhbU0QOP589IkS2GQ"),
    ("RV-S-NONCANON-FF", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAD__________________________________________w"),
    ("RV-ALG-NONE", "eyJhbGciOiJub25lIiwidHlwIjoiZGlkOmRmb3M6cmVqZWN0LXZlY3RvciIsImtpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4In0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
    ("RV-ALG-CASE", "eyJhbGciOiJlZGRzYSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
    ("RV-CRIT-PRESENT", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNyaXQiOlsiZXhwIl19.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
    ("RV-HEADER-KEY-TRUST", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFBQUEifX0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
    ("RV-SIG-BITFLIP", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CA"),
]

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
    #expect(cid == "bafyreieak45zq2337oaadtvk2vwtdqfvfg26hd7olnf275qiv5hrh3vywq")
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
    #expect(cid == "bafyreign22f4jiww2ywlssx7r2l76z32suj5ufvwl354hsp4xrm26cw7ue")
}
