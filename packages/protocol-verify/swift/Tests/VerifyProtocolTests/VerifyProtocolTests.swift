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

let genesisJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw"

let rotationJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg"

let contentCreateJWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWFlZGhqcTY0YWFqcHdvY2lhaGw1dzM3ajZ1b3hyNW1vam9xNWRuYWg2ZnB2eHI1ZDRseHUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWh6d3VvdXBmZzNkeGlwNnhtZ3pteHN5d3lpaTJqZW94eHpiZ3gzenhtMmluN2tub2kzZzQiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.Rv6vlz5MfrwqDUrSVIGs4ZfeBbkQUSBcXhxwZ6hfudSr5MxhYl08hTqLDOA0W1NMjN0Hs0IW9jXTwLwP1dMDBg"

let jwtToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIn0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.zhKeXJHHF7a1-MwF4QoUTRptCplAwh20-rLnuWGDFT6uJheN4E_SA5NhqvMNflLHxd7h97gdaVnMZGE67SXEBA"

let expectedGenCID = "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy"
let expectedDID = "did:dfos:e3vvtck42d4eacdnzvtrn6"
let expectedMultikey1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
let expectedCBORHex = "a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
let expectedCIDHex = "01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486"

let alphabet = "2346789acdefhknrtvz"
let idLength = 22

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

/// Verify a JWS (or JWT) token with an Ed25519 public key, returning parsed header and payload.
func verifyJWS(_ token: String, pubKey: Curve25519.Signing.PublicKey) -> (header: [String: Any], payload: [String: Any]) {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    precondition(parts.count == 3, "invalid JWS format")

    let signingInput = Data((parts[0] + "." + parts[1]).utf8)
    let signature = b64urlDecode(parts[2])

    guard pubKey.isValidSignature(signature, for: signingInput) else {
        fatalError("signature verification failed")
    }

    let headerData = b64urlDecode(parts[0])
    let payloadData = b64urlDecode(parts[1])
    let header = try! JSONSerialization.jsonObject(with: headerData) as! [String: Any]
    let payload = try! JSONSerialization.jsonObject(with: payloadData) as! [String: Any]
    return (header, payload)
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
    #expect(header["kid"] as? String == "key_r9ev34fvc23z999veaaft8")
    #expect(header["cid"] as? String == expectedGenCID)
    #expect(payload["type"] as? String == "create")
    #expect(payload["version"] as? Int == 1)
}

@Test func jwsRotationVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(rotationJWS, pubKey: priv1.publicKey)
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(header["cid"] as? String == "bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm")
    #expect(payload["type"] as? String == "update")
    #expect(payload["previousOperationCID"] as? String == expectedGenCID)
}

@Test func jwsContentCreateVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(contentCreateJWS, pubKey: priv2.publicKey)
    #expect(header["typ"] as? String == "did:dfos:content-op")
    #expect(header["kid"] as? String == "\(expectedDID)#key_ez9a874tckr3dv933d3ckd")
    #expect(header["cid"] as? String == "bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu")
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
    #expect(suffix == "e3vvtck42d4eacdnzvtrn6")

    let did = "did:dfos:\(suffix)"
    #expect(did == expectedDID)
}

// =========================================================================
// Beacon and credential tests
// =========================================================================

let beaconJWSToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYzJtdXg0cGxpNXFmZDVzYnAyeXh5MmdqbTU0Zmc1Z2NpNm02YnBldm9pdXdmZGc2cG91NCJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1hbmlmZXN0Q29udGVudElkIjoiYTgyejkyYTNobmRrNmM5N3RoY3JuOCIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9._EKV036utOU-oMHwMyJ1Om1QhJzN-g9DTRbMz0U7L9SzQR-sHIeC6iNreYN-oV-mBvo5RPLg4TJ0UNv-PNBzDQ"

let expectedBeaconCID = "bafyreic2mux4pli5qfd5sbp2yxy2gjm54fg5gci6m6bpevoiuwfdg6pou4"

let beaconWitnessJWSToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X2V6OWE4NzR0Y2tyM2R2OTMzZDNja2QiLCJjaWQiOiJiYWZ5cmVpYzJtdXg0cGxpNXFmZDVzYnAyeXh5MmdqbTU0Zmc1Z2NpNm02YnBldm9pdXdmZGc2cG91NCJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1hbmlmZXN0Q29udGVudElkIjoiYTgyejkyYTNobmRrNmM5N3RoY3JuOCIsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.a2BN31Mqi296FJ8wIVOwy7zdTR4fEL2TVy2A6xG6SGUBmJdUdnlqro5JbjIOF-h5RSA1SW0i4WvIK-AeiB27BQ"

let broadWriteVC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwiY2lkIjoiYmFmeXJlaWh6dDV3Nmt4YnlsZWZ1N2R3ZDRmbnZxdnlueHphNnhud3N6bXpoYml6anVjNnhjeHFkNmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42IiwiYXVkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6ayIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.brsN3WSdTLhN5-c0mhDriiKa2FuDD3eW5Mlj3KJYcj0cKQH0RDSACMp3qLeN2DGop-kfOtqtxlS7SAMIuCZGAw"

let readVC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwiY2lkIjoiYmFmeXJlaWMzbmJxemFicmxtbnl2a3o3cXI3Znk2cGd4NGFwdm52eWJvNWtzaGN6bXViaXFzemdod2EifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42IiwiYXVkIjoiZGlkOmRmb3M6bnprZjgzOGVmcjQyNDQzM3JuMnJ6ayIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.QB-qK89S-sYXaDUkJJSF5ZbsV2djFFvRQlHCj6UDyl-47LZI-ISwwyqRV-zi6MEGdHb0seSkPxpE4if6HHvvCw"

@Test func beaconJWSVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(beaconJWSToken, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:beacon")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(header["cid"] as? String == expectedBeaconCID)
    #expect(payload["type"] as? String == "beacon")
    #expect(payload["manifestContentId"] as? String == "a82z92a3hndk6c97thcrn8")
}

@Test func beaconCountersignatureVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(beaconWitnessJWSToken, pubKey: priv2.publicKey)
    #expect(header["typ"] as? String == "did:dfos:beacon")
    #expect(header["kid"] as? String == "\(expectedDID)#key_ez9a874tckr3dv933d3ckd")
    #expect(header["cid"] as? String == expectedBeaconCID)
    #expect(payload["manifestContentId"] as? String == "a82z92a3hndk6c97thcrn8")
}

@Test func writeCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(broadWriteVC, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:credential")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(payload["type"] as? String == "DFOSCredential")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["aud"] as? String == "did:dfos:nzkf838efr424433rn2rzk")

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
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(payload["type"] as? String == "DFOSCredential")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["aud"] as? String == "did:dfos:nzkf838efr424433rn2rzk")

    let att = payload["att"] as! [[String: Any]]
    #expect(att.count == 1)
    #expect(att[0]["resource"] as? String == "chain:*")
    #expect(att[0]["action"] as? String == "read")
}

// =============================================================================
// Minimal DAG-CBOR encoder (map + text + uint + float64 only)
// =============================================================================

/// Encode a single CBOR value. Supported types: String, Int, Double, [String: Any].
/// Map keys are sorted by (length, lexicographic) per RFC 7049 canonical ordering.
func encodeCBOR(_ value: Any) -> [UInt8] {
    switch value {
    case let s as String:
        let bytes = Array(s.utf8)
        return [UInt8(0x60 | bytes.count)] + bytes
    case let i as Int:
        precondition(i >= 0 && i < 24, "only small non-negative integers supported")
        return [UInt8(i)]
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
