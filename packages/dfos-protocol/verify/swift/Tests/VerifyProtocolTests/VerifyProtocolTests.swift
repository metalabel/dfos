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
// Merkle tree, beacon, and countersignature tests
// =========================================================================

let expectedMerkleRoot = "7e80d4780f454e0fca0b090d8c646f572b49354f54154531606105aad2fda28e"

let beaconJWSToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0._1RgZpMv63-M3ZUeTNX679xkAeX3TY0PJ0ImH7422cKA7I88Hf8bBVQMVVhP3oNdvX7i7Q4se5EP3kk5aEuxDQ"

let expectedBeaconCID = "bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu"

let beaconWitnessJWSToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X2V6OWE4NzR0Y2tyM2R2OTMzZDNja2QiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0.awA8ctmLHjJCHZcH0lav7HpadkIoGiG2WR-pCf-0XfPVi9dD8Z2at0E7iAnOUnVEc5VthBo-mMklSIJFK28IDw"

let broadWriteVC = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgifQ.eyJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42Iiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRGT1NDb250ZW50V3JpdGUiXSwiY3JlZGVudGlhbFN1YmplY3QiOnt9fX0.KoN20I8kerQAg7qjDN1Ju-IFi2gMjGhG2v6crWMGxheJdsY6OhfjvLu5LM_zty3IRVdmaBN-4fJngt3yscSJCg"

let readVC = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgifQ.eyJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42Iiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRGT1NDb250ZW50UmVhZCJdLCJjcmVkZW50aWFsU3ViamVjdCI6e319fQ.07JK8NPIzcoWRXqT961znL1642OF2xBVaJsBZ0CP6LTBF96IYtAX8_Xch2SgmrCzhZQN1XgbiIcgSmuTUQtsCA"

@Test func merkleTree() {
    let ids = ["alpha", "bravo", "charlie", "delta", "echo"].sorted()

    // hash leaves
    let leaves = ids.map { id -> [UInt8] in
        Array(SHA256.hash(data: Data(id.utf8)))
    }

    // verify alpha leaf
    #expect(hexEncode(leaves[0]) == "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8")

    // build tree bottom-up
    var level = leaves
    while level.count > 1 {
        var next: [[UInt8]] = []
        var i = 0
        while i < level.count {
            if i + 1 < level.count {
                let combined = level[i] + level[i + 1]
                next.append(Array(SHA256.hash(data: combined)))
            } else {
                next.append(level[i])
            }
            i += 2
        }
        level = next
    }

    #expect(hexEncode(level[0]) == expectedMerkleRoot)
}

@Test func merkleProofVerification() {
    let proofPath: [(hash: String, position: String)] = [
        ("4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398", "right"),
        ("90d39555bb3c223e12f5a375c3011d2462fe2e1e36b8416a0b623d5831a9b4f3", "left"),
        ("092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d", "right"),
    ]

    var current = Array(SHA256.hash(data: Data("charlie".utf8)))

    for step in proofPath {
        let sibling = hexDecode(step.hash)
        let combined: [UInt8]
        if step.position == "left" {
            combined = sibling + current
        } else {
            combined = current + sibling
        }
        current = Array(SHA256.hash(data: combined))
    }

    #expect(hexEncode(current) == expectedMerkleRoot)
}

@Test func beaconJWSVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(beaconJWSToken, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "did:dfos:beacon")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(header["cid"] as? String == expectedBeaconCID)
    #expect(payload["type"] as? String == "beacon")
    #expect(payload["merkleRoot"] as? String == expectedMerkleRoot)
}

@Test func beaconCountersignatureVerification() {
    let seed2 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-2".utf8)))
    let priv2 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed2)

    let (header, payload) = verifyJWS(beaconWitnessJWSToken, pubKey: priv2.publicKey)
    #expect(header["typ"] as? String == "did:dfos:beacon")
    #expect(header["kid"] as? String == "\(expectedDID)#key_ez9a874tckr3dv933d3ckd")
    #expect(header["cid"] as? String == expectedBeaconCID)
    #expect(payload["merkleRoot"] as? String == expectedMerkleRoot)
}

@Test func vcjwtWriteCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(broadWriteVC, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "vc+jwt")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["sub"] as? String == expectedDID)

    let vcClaim = payload["vc"] as! [String: Any]
    let types = vcClaim["type"] as! [String]
    #expect(types.contains("VerifiableCredential"))
    #expect(types.contains("DFOSContentWrite"))
}

@Test func vcjwtReadCredentialVerification() {
    let seed1 = Array(SHA256.hash(data: Data("dfos-protocol-reference-key-1".utf8)))
    let priv1 = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed1)

    let (header, payload) = verifyJWS(readVC, pubKey: priv1.publicKey)
    #expect(header["typ"] as? String == "vc+jwt")
    #expect(header["kid"] as? String == "\(expectedDID)#key_r9ev34fvc23z999veaaft8")
    #expect(payload["iss"] as? String == expectedDID)
    #expect(payload["sub"] as? String == expectedDID)

    let vcClaim = payload["vc"] as! [String: Any]
    let types = vcClaim["type"] as! [String]
    #expect(types.contains("VerifiableCredential"))
    #expect(types.contains("DFOSContentRead"))
}
