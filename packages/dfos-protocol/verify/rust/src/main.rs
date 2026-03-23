// DFOS Protocol — Independent verification in Rust
//
// Verifies all deterministic reference artifacts from the TypeScript implementation.
// Uses only standard crypto libraries.
//
// Run: cargo test

fn main() {
    println!("Run `cargo test` to verify the DFOS protocol.");
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ciborium::Value;
    use data_encoding::BASE32;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    // =========================================================================
    // Constants from the reference doc
    // =========================================================================

    const GENESIS_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw";

    const ROTATION_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg";

    const CONTENT_CREATE_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWFlZGhqcTY0YWFqcHdvY2lhaGw1dzM3ajZ1b3hyNW1vam9xNWRuYWg2ZnB2eHI1ZDRseHUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWh6d3VvdXBmZzNkeGlwNnhtZ3pteHN5d3lpaTJqZW94eHpiZ3gzenhtMmluN2tub2kzZzQiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.Rv6vlz5MfrwqDUrSVIGs4ZfeBbkQUSBcXhxwZ6hfudSr5MxhYl08hTqLDOA0W1NMjN0Hs0IW9jXTwLwP1dMDBg";

    const JWT_TOKEN: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIn0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.zhKeXJHHF7a1-MwF4QoUTRptCplAwh20-rLnuWGDFT6uJheN4E_SA5NhqvMNflLHxd7h97gdaVnMZGE67SXEBA";

    const EXPECTED_GENESIS_CID: &str = "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy";
    const EXPECTED_DID: &str = "did:dfos:e3vvtck42d4eacdnzvtrn6";
    const EXPECTED_MULTIKEY1: &str = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb";

    const EXPECTED_CBOR_HEX: &str = "a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62";

    const EXPECTED_CID_HEX: &str = "01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486";

    const ALPHABET: &[u8] = b"2346789acdefhknrtvz";
    const ID_LENGTH: usize = 22;

    // =========================================================================
    // Helpers
    // =========================================================================

    fn derive_public_key(seed_phrase: &[u8]) -> (Vec<u8>, VerifyingKey) {
        let seed_bytes: [u8; 32] = Sha256::digest(seed_phrase).into();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        let verifying_key = signing_key.verifying_key();
        (seed_bytes.to_vec(), verifying_key)
    }

    fn encode_id(hash_bytes: &[u8]) -> String {
        (0..ID_LENGTH)
            .map(|i| ALPHABET[(hash_bytes[i] % 19) as usize] as char)
            .collect()
    }

    fn decode_multikey(multibase: &str) -> Vec<u8> {
        assert!(multibase.starts_with('z'), "expected base58btc prefix");
        let raw = bs58::decode(&multibase[1..]).into_vec().unwrap();
        assert!(
            raw[0] == 0xed && raw[1] == 0x01,
            "expected ed25519-pub multicodec prefix"
        );
        raw[2..].to_vec()
    }

    fn encode_multikey(pub_bytes: &[u8]) -> String {
        let mut raw = vec![0xed, 0x01];
        raw.extend_from_slice(pub_bytes);
        format!("z{}", bs58::encode(&raw).into_string())
    }

    fn make_cid_bytes(cbor_bytes: &[u8]) -> Vec<u8> {
        let digest: [u8; 32] = Sha256::digest(cbor_bytes).into();
        let mut cid = vec![0x01, 0x71, 0x12, 0x20];
        cid.extend_from_slice(&digest);
        cid
    }

    fn cid_to_base32(cid_bytes: &[u8]) -> String {
        let encoded = BASE32.encode(cid_bytes);
        format!("b{}", encoded.to_lowercase().trim_end_matches('='))
    }

    /// Encode a value in dag-cbor canonical form.
    /// dag-cbor sorts map keys by byte-length first, then lexicographic.
    /// Entries must already be provided in dag-cbor key order.
    fn dag_cbor_encode_map(entries: Vec<(&str, Value)>) -> Vec<u8> {
        let map: Vec<(Value, Value)> = entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v))
            .collect();
        let value = Value::Map(map);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        buf
    }

    fn verify_jws(
        token: &str,
        pub_key: &VerifyingKey,
    ) -> (serde_json::Value, serde_json::Value) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "invalid JWS format");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();

        pub_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature verification failed");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

        (header, payload)
    }

    // =========================================================================
    // Tests
    // =========================================================================

    #[test]
    fn test_key_derivation() {
        let (seed1, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        assert_eq!(
            hex::encode(&seed1),
            "132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac",
            "Key 1 seed mismatch"
        );
        assert_eq!(
            hex::encode(pub1.as_bytes()),
            "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32",
            "Key 1 public mismatch"
        );

        let (seed2, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        assert_eq!(
            hex::encode(&seed2),
            "384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8",
            "Key 2 seed mismatch"
        );
        assert_eq!(
            hex::encode(pub2.as_bytes()),
            "0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c",
            "Key 2 public mismatch"
        );
    }

    #[test]
    fn test_multikey_encoding() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");

        let encoded = encode_multikey(pub1.as_bytes());
        assert_eq!(encoded, EXPECTED_MULTIKEY1, "multikey encode mismatch");

        let decoded = decode_multikey(EXPECTED_MULTIKEY1);
        assert_eq!(decoded, pub1.as_bytes(), "multikey decode mismatch");
    }

    #[test]
    fn test_dag_cbor_encoding() {
        // Build key entry in dag-cbor key order (length-first, then lex)
        // Key lengths: "id" (2), "type" (4), "publicKeyMultibase" (18)
        let make_key_entry = || {
            Value::Map(vec![
                (
                    Value::Text("id".to_string()),
                    Value::Text("key_r9ev34fvc23z999veaaft8".to_string()),
                ),
                (
                    Value::Text("type".to_string()),
                    Value::Text("Multikey".to_string()),
                ),
                (
                    Value::Text("publicKeyMultibase".to_string()),
                    Value::Text(EXPECTED_MULTIKEY1.to_string()),
                ),
            ])
        };

        // Genesis payload in dag-cbor key order:
        // "type" (4), "version" (7), "authKeys" (8), "createdAt" (9),
        // "assertKeys" (10), "controllerKeys" (14)
        let cbor_bytes = dag_cbor_encode_map(vec![
            ("type", Value::Text("create".to_string())),
            ("version", Value::Integer(1.into())),
            ("authKeys", Value::Array(vec![make_key_entry()])),
            ("createdAt", Value::Text("2026-03-07T00:00:00.000Z".to_string())),
            ("assertKeys", Value::Array(vec![make_key_entry()])),
            ("controllerKeys", Value::Array(vec![make_key_entry()])),
        ]);

        let got = hex::encode(&cbor_bytes);
        assert_eq!(got, EXPECTED_CBOR_HEX, "CBOR bytes mismatch");
    }

    #[test]
    fn test_cid_derivation() {
        let cbor_bytes = hex::decode(EXPECTED_CBOR_HEX).unwrap();
        let cid_bytes = make_cid_bytes(&cbor_bytes);

        assert_eq!(
            hex::encode(&cid_bytes),
            EXPECTED_CID_HEX,
            "CID bytes mismatch"
        );

        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(cid_str, EXPECTED_GENESIS_CID, "CID string mismatch");
    }

    #[test]
    fn test_did_derivation() {
        let cid_bytes = hex::decode(EXPECTED_CID_HEX).unwrap();
        let did_hash: [u8; 32] = Sha256::digest(&cid_bytes).into();
        let suffix = encode_id(&did_hash);
        assert_eq!(suffix, "e3vvtck42d4eacdnzvtrn6", "DID suffix mismatch");

        let did = format!("did:dfos:{}", suffix);
        assert_eq!(did, EXPECTED_DID, "DID mismatch");
    }

    #[test]
    fn test_jws_genesis_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(GENESIS_JWS, &pub1);

        assert_eq!(header["alg"], "EdDSA", "wrong alg");
        assert_eq!(header["typ"], "did:dfos:identity-op", "wrong typ");
        assert_eq!(header["kid"], "key_r9ev34fvc23z999veaaft8", "wrong kid");
        assert_eq!(header["cid"], EXPECTED_GENESIS_CID, "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");
        assert_eq!(payload["version"], 1, "wrong payload version");
    }

    #[test]
    fn test_jws_rotation_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(ROTATION_JWS, &pub1);

        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft8", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(
            header["cid"], "bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm",
            "wrong cid"
        );
        assert_eq!(payload["type"], "update", "wrong type");
        assert_eq!(
            payload["previousOperationCID"], EXPECTED_GENESIS_CID,
            "wrong previousOperationCID"
        );
    }

    #[test]
    fn test_jws_content_create_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (header, payload) = verify_jws(CONTENT_CREATE_JWS, &pub2);

        assert_eq!(header["typ"], "did:dfos:content-op", "wrong typ");
        let expected_kid = format!("{}#key_ez9a874tckr3dv933d3ckd", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(
            header["cid"], "bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu",
            "wrong cid"
        );
        assert_eq!(payload["type"], "create", "wrong payload type");
    }

    #[test]
    fn test_jwt_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (header, payload) = verify_jws(JWT_TOKEN, &pub2);

        assert_eq!(header["alg"], "EdDSA", "wrong alg");
        assert_eq!(header["typ"], "JWT", "wrong typ");
        assert_eq!(payload["iss"], "dfos", "wrong iss");
        assert_eq!(payload["sub"], EXPECTED_DID, "wrong sub");
        assert_eq!(payload["aud"], "dfos-api", "wrong aud");
    }

    // =========================================================================
    // Merkle tree, beacon, and countersignature tests
    // =========================================================================

    const EXPECTED_MERKLE_ROOT: &str =
        "7e80d4780f454e0fca0b090d8c646f572b49354f54154531606105aad2fda28e";

    const BEACON_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0._1RgZpMv63-M3ZUeTNX679xkAeX3TY0PJ0ImH7422cKA7I88Hf8bBVQMVVhP3oNdvX7i7Q4se5EP3kk5aEuxDQ";

    const EXPECTED_BEACON_CID: &str =
        "bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu";

    const BEACON_WITNESS_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X2V6OWE4NzR0Y2tyM2R2OTMzZDNja2QiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0.awA8ctmLHjJCHZcH0lav7HpadkIoGiG2WR-pCf-0XfPVi9dD8Z2at0E7iAnOUnVEc5VthBo-mMklSIJFK28IDw";

    const BROAD_WRITE_VC: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgifQ.eyJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42Iiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRGT1NDb250ZW50V3JpdGUiXSwiY3JlZGVudGlhbFN1YmplY3QiOnt9fX0.KoN20I8kerQAg7qjDN1Ju-IFi2gMjGhG2v6crWMGxheJdsY6OhfjvLu5LM_zty3IRVdmaBN-4fJngt3yscSJCg";

    const READ_VC: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6InZjK2p3dCIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgifQ.eyJpc3MiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42Iiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRGT1NDb250ZW50UmVhZCJdLCJjcmVkZW50aWFsU3ViamVjdCI6e319fQ.07JK8NPIzcoWRXqT961znL1642OF2xBVaJsBZ0CP6LTBF96IYtAX8_Xch2SgmrCzhZQN1XgbiIcgSmuTUQtsCA";

    #[test]
    fn test_merkle_tree() {
        let mut ids = vec!["alpha", "bravo", "charlie", "delta", "echo"];
        ids.sort();

        let leaves: Vec<[u8; 32]> = ids.iter().map(|id| Sha256::digest(id.as_bytes()).into()).collect();

        // verify leaf hash
        assert_eq!(
            hex::encode(leaves[0]),
            "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
            "alpha leaf mismatch"
        );

        // build tree bottom-up
        let mut level: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    let mut combined = level[i].clone();
                    combined.extend_from_slice(&level[i + 1]);
                    let h: [u8; 32] = Sha256::digest(&combined).into();
                    next.push(h.to_vec());
                } else {
                    next.push(level[i].clone());
                }
                i += 2;
            }
            level = next;
        }

        assert_eq!(
            hex::encode(&level[0]),
            EXPECTED_MERKLE_ROOT,
            "merkle root mismatch"
        );
    }

    #[test]
    fn test_merkle_proof_verification() {
        let proof_path = vec![
            ("4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398", "right"),
            ("90d39555bb3c223e12f5a375c3011d2462fe2e1e36b8416a0b623d5831a9b4f3", "left"),
            ("092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d", "right"),
        ];

        let leaf: [u8; 32] = Sha256::digest(b"charlie").into();
        let mut current = leaf.to_vec();

        for (hash_hex, position) in &proof_path {
            let sibling = hex::decode(hash_hex).unwrap();
            let combined = if *position == "left" {
                [sibling.as_slice(), current.as_slice()].concat()
            } else {
                [current.as_slice(), sibling.as_slice()].concat()
            };
            let h: [u8; 32] = Sha256::digest(&combined).into();
            current = h.to_vec();
        }

        assert_eq!(
            hex::encode(&current),
            EXPECTED_MERKLE_ROOT,
            "merkle proof verification failed"
        );
    }

    #[test]
    fn test_beacon_jws_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(BEACON_JWS, &pub1);

        assert_eq!(header["typ"], "did:dfos:beacon", "wrong typ");
        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft8", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(header["cid"], EXPECTED_BEACON_CID, "wrong cid");
        assert_eq!(payload["type"], "beacon", "wrong payload type");
        assert_eq!(payload["merkleRoot"], EXPECTED_MERKLE_ROOT, "wrong merkleRoot");
    }

    #[test]
    fn test_beacon_countersignature_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (header, payload) = verify_jws(BEACON_WITNESS_JWS, &pub2);

        assert_eq!(header["typ"], "did:dfos:beacon", "wrong typ");
        let expected_kid = format!("{}#key_ez9a874tckr3dv933d3ckd", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(
            header["cid"], EXPECTED_BEACON_CID,
            "countersignature CID should match original beacon CID"
        );
        assert_eq!(
            payload["merkleRoot"], EXPECTED_MERKLE_ROOT,
            "countersignature payload should match original"
        );
    }

    #[test]
    fn test_vcjwt_write_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(BROAD_WRITE_VC, &pub1);

        assert_eq!(header["typ"], "vc+jwt", "wrong typ");
        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft8", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(payload["iss"], EXPECTED_DID, "wrong iss");
        assert_eq!(payload["sub"], EXPECTED_DID, "wrong sub");

        let vc = payload["vc"].as_object().expect("vc should be an object");
        let types = vc["type"].as_array().expect("type should be an array");
        assert!(
            types.iter().any(|t| t.as_str() == Some("DFOSContentWrite")),
            "vc type should contain DFOSContentWrite"
        );
    }

    #[test]
    fn test_vcjwt_read_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(READ_VC, &pub1);

        assert_eq!(header["typ"], "vc+jwt", "wrong typ");
        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft8", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(payload["iss"], EXPECTED_DID, "wrong iss");
        assert_eq!(payload["sub"], EXPECTED_DID, "wrong sub");

        let vc = payload["vc"].as_object().expect("vc should be an object");
        let types = vc["type"].as_array().expect("type should be an array");
        assert!(
            types.iter().any(|t| t.as_str() == Some("DFOSContentRead")),
            "vc type should contain DFOSContentRead"
        );
    }

    // =========================================================================
    // Number encoding determinism tests
    // =========================================================================

    #[test]
    fn test_number_encoding_determinism() {
        // dag-cbor key order: "type" (4) before "version" (7)
        let cbor_bytes = dag_cbor_encode_map(vec![
            ("type", Value::Text("test".to_string())),
            ("version", Value::Integer(1.into())),
        ]);

        assert_eq!(
            hex::encode(&cbor_bytes),
            "a2647479706564746573746776657273696f6e01",
            "CBOR bytes mismatch for integer 1"
        );

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(
            cid_str,
            "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa",
            "CID mismatch for integer 1"
        );
    }

    #[test]
    fn test_number_encoding_from_json() {
        // Parse JSON and convert to ciborium Value, mimicking the
        // JSON deserialization → CBOR encoding pipeline.
        let json: serde_json::Value =
            serde_json::from_str(r#"{"version": 1, "type": "test"}"#).unwrap();

        // Extract fields and build CBOR map in dag-cbor key order
        // ("type" length 4 before "version" length 7)
        let type_str = json["type"].as_str().unwrap().to_string();
        let version_int = json["version"].as_i64().unwrap();

        let cbor_bytes = dag_cbor_encode_map(vec![
            ("type", Value::Text(type_str)),
            ("version", Value::Integer(version_int.into())),
        ]);

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(
            cid_str,
            "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa",
            "CID from JSON deserialization should match integer-encoded CID"
        );
    }

    #[test]
    fn test_number_encoding_float_produces_wrong_cid() {
        // Using a CBOR float (1.0) instead of integer (1) produces a different,
        // known-wrong CID — demonstrating why float encoding must be rejected.
        // dag-cbor key order: "type" (4) before "version" (7)
        let cbor_bytes = dag_cbor_encode_map(vec![
            ("type", Value::Text("test".to_string())),
            ("version", Value::Float(1.0)),
        ]);

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);

        let correct_cid = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa";
        let wrong_cid = "bafyreiawbms4476m5jlrmqtyvtwe5ta3eo2bh7mdprtomfgfype7j57o4q";

        assert_eq!(cid_str, wrong_cid, "float 1.0 should produce the known-wrong CID");
        assert_ne!(cid_str, correct_cid, "float 1.0 must NOT produce the correct integer CID");
    }
}
