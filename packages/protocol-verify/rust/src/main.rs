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

    const GENESIS_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg";

    const ROTATION_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw";

    const CONTENT_CREATE_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWQyNmJhZ241Y2ZlZTN4cHRhZmptYmx4d3VkdzQzNXA2cms1ZzNwNGdqdGtudXlscnhzc3kifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.mTRCvPga89hVeu-gNowrL8TApoGJlxVQBw3CzrvEA-LxAQaSp03Uyn0JwdhPWh22UtwZTe2d27IIuJ7P-5PtAA";

    const JWT_TOKEN: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4In0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.VdrDMOQoFAboxK165ZDOe5YXTgILUDO_bHuGHinupqEd4dptibATmyI9YrjseMaJHS4gggzX1st9qO5eoVJdCQ";

    const EXPECTED_GENESIS_CID: &str = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne";
    const EXPECTED_DID: &str = "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr";
    const EXPECTED_MULTIKEY1: &str = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb";

    const EXPECTED_CBOR_HEX: &str = "a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62";

    const EXPECTED_CID_HEX: &str = "017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69";

    const ALPHABET: &[u8] = b"2346789acdefhknrtvz";
    const ID_LENGTH: usize = 31;

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

    /// Recursively convert a decoded JSON value into a ciborium value in dag-cbor
    /// canonical form. Map keys are sorted length-first, then lexicographic (the
    /// dag-cbor rule), and whole-number floats are normalized to integers so the
    /// CBOR uses integer major types. Used to recompute an operation CID over a
    /// decoded JWS payload (e.g. the services-genesis op, whose services fields
    /// ride along in the payload map).
    fn json_to_dag_cbor(json: &serde_json::Value) -> Value {
        match json {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Integer(i.into())
                } else if let Some(u) = n.as_u64() {
                    Value::Integer(u.into())
                } else {
                    let f = n.as_f64().unwrap();
                    if f.fract() == 0.0
                        && f >= -(MAX_SAFE_CANONICAL_INTEGER as f64)
                        && f <= MAX_SAFE_CANONICAL_INTEGER as f64
                    {
                        Value::Integer((f as i64).into())
                    } else {
                        Value::Float(f)
                    }
                }
            }
            serde_json::Value::String(s) => Value::Text(s.clone()),
            serde_json::Value::Array(arr) => {
                Value::Array(arr.iter().map(json_to_dag_cbor).collect())
            }
            serde_json::Value::Object(obj) => {
                // dag-cbor key order: length-first, then lexicographic.
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
                let entries: Vec<(Value, Value)> = keys
                    .into_iter()
                    .map(|k| (Value::Text(k.clone()), json_to_dag_cbor(&obj[k])))
                    .collect();
                Value::Map(entries)
            }
        }
    }

    fn dag_cbor_encode_json(json: &serde_json::Value) -> Vec<u8> {
        let value = json_to_dag_cbor(json);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        buf
    }

    // Ed25519 group order L (little-endian 32 bytes) — the canonical S < L bound.
    // ed25519-dalek's verify (even verify_strict) does NOT reject non-canonical S,
    // so this gate is mandatory for the DFOS profile and is the whole reason the
    // Rust suite carries an explicit scalar check.
    const ED25519_L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Constant-time-ish little-endian compare: returns true iff s < L.
    fn scalar_is_canonical(s: &[u8]) -> bool {
        if s.len() != 32 {
            return false;
        }
        for i in (0..32).rev() {
            if s[i] < ED25519_L[i] {
                return true;
            }
            if s[i] > ED25519_L[i] {
                return false;
            }
        }
        false // s == L is non-canonical
    }

    /// DFOS Signature Verification Profile (pragmatic v1) header gates — applied
    /// BEFORE any signature check. Returns Err on any violation.
    fn assert_jws_profile(header: &serde_json::Value) -> Result<(), String> {
        if header["alg"] != "EdDSA" {
            return Err(format!("unsupported algorithm: {}", header["alg"]));
        }
        if !header["crit"].is_null() {
            return Err("crit header is not supported".to_string());
        }
        if !header["jwk"].is_null() {
            return Err("jwk header is not allowed".to_string());
        }
        if !header["x5c"].is_null() {
            return Err("x5c header is not allowed".to_string());
        }
        Ok(())
    }

    /// Profile-aware JWS verification returning Result so the reject corpus can
    /// assert rejection. Applies alg pin, crit, no header-key-trust, 64-byte
    /// length, and the canonical S < L gate BEFORE the signature check.
    fn verify_jws_profiled(
        token: &str,
        pub_key: &VerifyingKey,
    ) -> Result<(serde_json::Value, serde_json::Value), String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("invalid JWS format".to_string());
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| "decode header".to_string())?;
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| "parse header".to_string())?;

        // profile gates run before any signature work
        assert_jws_profile(&header)?;

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| "decode signature".to_string())?;

        // length + canonical-scalar (S < L) gates
        if sig_bytes.len() != 64 {
            return Err(format!("signature must be 64 bytes, got {}", sig_bytes.len()));
        }
        if !scalar_is_canonical(&sig_bytes[32..64]) {
            return Err("non-canonical signature scalar (S >= L)".to_string());
        }

        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| "bad signature bytes".to_string())?;
        pub_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| "signature verification failed".to_string())?;

        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

        Ok((header, payload))
    }

    fn verify_jws(
        token: &str,
        pub_key: &VerifyingKey,
    ) -> (serde_json::Value, serde_json::Value) {
        verify_jws_profiled(token, pub_key).expect("verification failed")
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
                    Value::Text("key_r9ev34fvc23z999veaaft83nn29zvhe".to_string()),
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
        assert_eq!(suffix, "cnnnft9f8a2rn938d6nkz38r847v2kr", "DID suffix mismatch");

        let did = format!("did:dfos:{}", suffix);
        assert_eq!(did, EXPECTED_DID, "DID mismatch");
    }

    #[test]
    fn test_jws_genesis_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(GENESIS_JWS, &pub1);

        assert_eq!(header["alg"], "EdDSA", "wrong alg");
        assert_eq!(header["typ"], "did:dfos:identity-op", "wrong typ");
        assert_eq!(header["kid"], "key_r9ev34fvc23z999veaaft83nn29zvhe", "wrong kid");
        assert_eq!(header["cid"], EXPECTED_GENESIS_CID, "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");
        assert_eq!(payload["version"], 1, "wrong payload version");
    }

    #[test]
    fn test_jws_rotation_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(ROTATION_JWS, &pub1);

        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft83nn29zvhe", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(
            header["cid"], "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei",
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
        let expected_kid = format!("{}#key_ez9a874tckr3dv933d3ckdn7z6zrct8", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(
            header["cid"], "bafyreid26bagn5cfee3xptafjmblxwudw435p6rk5g3p4gjtknuylrxssy",
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
    // Services-genesis and credential tests
    // =========================================================================

    // Canonical services-genesis identity-op: a create op carrying a full-state
    // services array (relay locator + content/artifact anchors), signed by
    // reference key 1. Sourced from
    // packages/dfos-protocol/examples/identity-services.json chain[0]. The
    // services fields ride along in the payload map, so recomputing the operation
    // CID over the decoded payload requires no services-validation logic here.
    const SERVICES_GENESIS_JWS: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpZGkzcXBzM3F0dHFwMjJtM3kzM2JkYmYyaXlrYnE1cjQ1ampod2EzN21nZXNvdjdzZGd6ZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJzZXJ2aWNlcyI6W3siaWQiOiJyZWxheSIsInR5cGUiOiJEZm9zUmVsYXkiLCJlbmRwb2ludCI6Imh0dHBzOi8vcmVsYXkuZGZvcy5jb20ifSx7ImlkIjoicHJvZmlsZSIsInR5cGUiOiJDb250ZW50QW5jaG9yIiwibGFiZWwiOiJwcm9maWxlIiwiYW5jaG9yIjoiY3Y3bjh2a3ZyNjRjY3RmMzI5NGg5azRlYW5oZmY4eiJ9LHsiaWQiOiJhdmF0YXIiLCJ0eXBlIjoiQ29udGVudEFuY2hvciIsImxhYmVsIjoiYXZhdGFyIiwiYW5jaG9yIjoiYmFmeXJlaWV2Y3FybXZ0ejJwaXM1dGRpenQ3c2pvdG9xcW9nbDZ2cnJxZ2E2NHcydG53a3Eycm51ZHkifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.HCzVJXcUzL62lxtC8omBlit1JNSWk4b4kQKjjjWT00honzZ9-k3dKusIRuhTV6gjT1M74bLVZYUxPb8kJvhHAw";

    const EXPECTED_SERVICES_GEN_CID: &str =
        "bafyreidi3qps3qttqp22m3y33bdbf2iykbq5r45jjhwa37mgesov7sdgze";
    const EXPECTED_SERVICES_DID: &str = "did:dfos:zhkrrzrd7z623ha8tt7dt699de8r3ar";

    const BROAD_WRITE_VC: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWZ5aW5ieGhicml0NTZtM2FhdjY2bXc0eGQ2YWRxamFzdmNmaG11NjZnNnRudXFncnljbG0ifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.A-EygURAN2bALVwI2AZKFEuy30ZnWJFBaD4jCTf1d7A90rYELStjTWJ1iI7OulihTCfaVtlvj5HtX6Dwv1VxAg";

    const READ_VC: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWN0aGNiaXp4dmdlbXN4djdrc2NvbzdhcGllYWFsM2Z5ZTM3bzQ1Zmt5a25lN2I0aG9icmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.UvTItuWFriA39FZIdB5TuXa_b07eyNLc-iR0cej2litSkjBYAZaLlDJUmyDQ-3dB7TmNVXDbB3SMbpvLnWW9Dw";

    const EXPECTED_CREDENTIAL_AUDIENCE: &str = "did:dfos:94ah7963n223k8c9884hh27ekh42nea";

    #[test]
    fn test_services_genesis_verification() {
        // Verify the canonical services-genesis identity-op: signature check with
        // reference key 1, then an independent recomputation of the operation CID
        // over the decoded payload (services fields ride along in the payload map —
        // no services-validation logic required here), asserting it equals the JWS
        // header cid and that the derived DID matches.
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(SERVICES_GENESIS_JWS, &pub1);

        assert_eq!(header["typ"], "did:dfos:identity-op", "wrong typ");
        assert_eq!(header["kid"], "key_r9ev34fvc23z999veaaft83nn29zvhe", "wrong kid");
        assert_eq!(header["cid"], EXPECTED_SERVICES_GEN_CID, "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");

        // Recompute the operation CID over the decoded payload and assert it
        // matches the value committed in the JWS header.
        let cbor_bytes = dag_cbor_encode_json(&payload);
        let cid_str = cid_to_base32(&make_cid_bytes(&cbor_bytes));
        assert_eq!(
            cid_str, EXPECTED_SERVICES_GEN_CID,
            "recomputed CID mismatch"
        );

        // Derive the DID from the operation CID bytes and assert it matches.
        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let did_hash: [u8; 32] = Sha256::digest(&cid_bytes).into();
        let did = format!("did:dfos:{}", encode_id(&did_hash));
        assert_eq!(did, EXPECTED_SERVICES_DID, "DID mismatch");
    }

    #[test]
    fn test_write_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(BROAD_WRITE_VC, &pub1);

        assert_eq!(header["typ"], "did:dfos:credential", "wrong typ");
        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft83nn29zvhe", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(payload["type"], "DFOSCredential", "wrong type");
        assert_eq!(payload["iss"], EXPECTED_DID, "wrong iss");
        assert_eq!(payload["aud"], EXPECTED_CREDENTIAL_AUDIENCE, "wrong aud");

        let att = payload["att"].as_array().expect("att should be an array");
        assert_eq!(att.len(), 1, "att should have one entry");
        assert_eq!(att[0]["resource"], "chain:*", "wrong resource");
        assert_eq!(att[0]["action"], "write", "wrong action");
    }

    #[test]
    fn test_read_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(READ_VC, &pub1);

        assert_eq!(header["typ"], "did:dfos:credential", "wrong typ");
        let expected_kid = format!("{}#key_r9ev34fvc23z999veaaft83nn29zvhe", EXPECTED_DID);
        assert_eq!(header["kid"], expected_kid, "wrong kid");
        assert_eq!(payload["type"], "DFOSCredential", "wrong type");
        assert_eq!(payload["iss"], EXPECTED_DID, "wrong iss");
        assert_eq!(payload["aud"], EXPECTED_CREDENTIAL_AUDIENCE, "wrong aud");

        let att = payload["att"].as_array().expect("att should be an array");
        assert_eq!(att.len(), 1, "att should have one entry");
        assert_eq!(att[0]["resource"], "chain:*", "wrong resource");
        assert_eq!(att[0]["action"], "read", "wrong action");
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

    // =========================================================================
    // Reject corpus — every conformant verifier MUST reject all of these.
    // Byte-identical inputs across all five language suites. The S < L gate
    // above is what makes RV-S-NONCANON-* fail under dalek.
    // =========================================================================

    const REJECT_PUB1_HEX: &str =
        "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32";

    const REJECT_VECTORS: &[(&str, &str)] = &[
        ("RV-LEN-SHORT", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2"),
        ("RV-LEN-LONG", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQA"),
        ("RV-S-NONCANON-PLUSL", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAFq4vaNrS7wPMIBVCWm3qp0JC5obhbU0QOP589IkS2GQ"),
        ("RV-S-NONCANON-FF", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAD__________________________________________w"),
        ("RV-ALG-NONE", "eyJhbGciOiJub25lIiwidHlwIjoiZGlkOmRmb3M6cmVqZWN0LXZlY3RvciIsImtpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4In0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
        ("RV-ALG-CASE", "eyJhbGciOiJlZGRzYSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
        ("RV-CRIT-PRESENT", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNyaXQiOlsiZXhwIl19.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
        ("RV-HEADER-KEY-TRUST", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFBQUEifX0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ"),
        ("RV-SIG-BITFLIP", "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CA"),
    ];

    #[test]
    fn test_reject_corpus() {
        let pub_bytes: [u8; 32] = hex::decode(REJECT_PUB1_HEX).unwrap().try_into().unwrap();
        let pub_key = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        for (name, token) in REJECT_VECTORS {
            assert!(
                verify_jws_profiled(token, &pub_key).is_err(),
                "{name}: expected rejection, got accept"
            );
        }
    }

    // =========================================================================
    // WP-0 number-policy vectors. CIDs are byte-identical across all five suites.
    // =========================================================================

    const MAX_SAFE_CANONICAL_INTEGER: i64 = 9007199254740991; // 2^53 - 1

    /// Reject NaN, ±Inf, non-integers, and integers outside ±(2^53-1).
    fn assert_canonical_number_f64(val: f64) -> Result<(), String> {
        if !val.is_finite() {
            return Err("non-finite".to_string());
        }
        if val.fract() != 0.0 {
            return Err("non-integer".to_string());
        }
        if val > MAX_SAFE_CANONICAL_INTEGER as f64 || val < -(MAX_SAFE_CANONICAL_INTEGER as f64) {
            return Err("out of safe range".to_string());
        }
        Ok(())
    }

    fn make_cid_string(cbor_bytes: &[u8]) -> String {
        cid_to_base32(&make_cid_bytes(cbor_bytes))
    }

    #[test]
    fn test_number_policy_accept_max_safe() {
        // { "n": 2^53-1 } — accepted, encodes to the reference CID
        assert!(assert_canonical_number_f64(MAX_SAFE_CANONICAL_INTEGER as f64).is_ok());
        let cbor = dag_cbor_encode_map(vec![(
            "n",
            Value::Integer(MAX_SAFE_CANONICAL_INTEGER.into()),
        )]);
        assert_eq!(
            make_cid_string(&cbor),
            "bafyreieak45zq2337oaadtvk2vwtdqfvfg26hd7olnf275qiv5hrh3vywq",
            "max-safe CID mismatch"
        );
    }

    #[test]
    fn test_number_policy_rejects() {
        // 2^53, 1.5, NaN, +Inf, -Inf must all be rejected
        assert!(assert_canonical_number_f64(9007199254740992.0).is_err(), "2^53");
        assert!(assert_canonical_number_f64(1.5).is_err(), "1.5");
        assert!(assert_canonical_number_f64(f64::NAN).is_err(), "NaN");
        assert!(assert_canonical_number_f64(f64::INFINITY).is_err(), "+Inf");
        assert!(assert_canonical_number_f64(f64::NEG_INFINITY).is_err(), "-Inf");
    }

    #[test]
    fn test_number_policy_null_vector() {
        // { "documentCID": null, "note": null, "prf": [] }
        // dag-cbor key order: "prf" (3), "note" (4), "documentCID" (11)
        let cbor = dag_cbor_encode_map(vec![
            ("prf", Value::Array(vec![])),
            ("note", Value::Null),
            ("documentCID", Value::Null),
        ]);
        assert_eq!(
            make_cid_string(&cbor),
            "bafyreign22f4jiww2ywlssx7r2l76z32suj5ufvwl354hsp4xrm26cw7ue",
            "null vector CID mismatch"
        );
    }
}
