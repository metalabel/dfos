// DFOS Protocol — Independent verification in Rust
//
// Verifies all deterministic reference artifacts from the protocol specification.
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
    use std::path::Path;
    use std::sync::OnceLock;

    // =========================================================================
    // Shared reference vectors
    // =========================================================================
    //
    // Every expected value below is read from ../vectors.json — the one artifact
    // all five suites share, generated from the protocol's fixed seeds by
    // packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
    // checked-in file is byte-identical to a fresh generation.
    //
    // Reading a JSON fixture is not a library import. This suite still uses only
    // the language's native Ed25519, CBOR and SHA-256, and a third party can run
    // it with nothing but this file and vectors.json.

    fn vectors_document() -> &'static serde_json::Value {
        static VECTORS: OnceLock<serde_json::Value> = OnceLock::new();
        VECTORS.get_or_init(|| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors.json");
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            serde_json::from_str(&raw).expect("parse vectors.json")
        })
    }

    /// All values of one vector, by id.
    fn vector_values(id: &str) -> &'static serde_json::Value {
        vectors_document()["vectors"]
            .as_array()
            .expect("vectors.json has no vectors array")
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("vectors.json has no vector {id:?}"))
            .get("values")
            .unwrap_or_else(|| panic!("vectors.json vector {id:?} has no values"))
    }

    /// One field of one vector (a document, an operation payload, a token map).
    fn vec_value(id: &str, field: &str) -> &'static serde_json::Value {
        vector_values(id)
            .get(field)
            .unwrap_or_else(|| panic!("vectors.json {id} has no field {field}"))
    }

    /// One string field of one vector.
    fn vec(id: &str, field: &str) -> &'static str {
        vec_value(id, field)
            .as_str()
            .unwrap_or_else(|| panic!("vectors.json {id}.{field} is not a string"))
    }

    /// One string-array field of one vector.
    fn vec_strings(id: &str, field: &str) -> Vec<&'static str> {
        vec_value(id, field)
            .as_array()
            .unwrap_or_else(|| panic!("vectors.json {id}.{field} is not an array"))
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("vectors.json {id}.{field} is not a string array"))
            })
            .collect()
    }

    // =========================================================================
    // Constants from the reference doc
    // =========================================================================

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
            vec("key-1", "privateKeyHex"),
            "Key 1 seed mismatch"
        );
        assert_eq!(
            hex::encode(pub1.as_bytes()),
            vec("key-1", "publicKeyHex"),
            "Key 1 public mismatch"
        );

        let (seed2, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        assert_eq!(
            hex::encode(&seed2),
            vec("key-2", "privateKeyHex"),
            "Key 2 seed mismatch"
        );
        assert_eq!(
            hex::encode(pub2.as_bytes()),
            vec("key-2", "publicKeyHex"),
            "Key 2 public mismatch"
        );
    }

    #[test]
    fn test_multikey_encoding() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");

        let encoded = encode_multikey(pub1.as_bytes());
        assert_eq!(encoded, vec("key-1", "multikey"), "multikey encode mismatch");

        let decoded = decode_multikey(vec("key-1", "multikey"));
        assert_eq!(decoded, pub1.as_bytes(), "multikey decode mismatch");
    }

    #[test]
    fn test_dag_cbor_encoding() {
        // The genesis payload is the shared vector, not a local transcription.
        // json_to_dag_cbor applies the dag-cbor key order (length-first, then
        // lexicographic), so the sorting itself is under test here.
        let cbor_bytes = dag_cbor_encode_json(vec_value("identity-genesis", "payload"));
        let got = hex::encode(&cbor_bytes);
        assert_eq!(
            got,
            vec("identity-genesis", "cborHex"),
            "CBOR bytes mismatch"
        );
    }

    #[test]
    fn test_cid_derivation() {
        let cbor_bytes = hex::decode(vec("identity-genesis", "cborHex")).unwrap();
        let cid_bytes = make_cid_bytes(&cbor_bytes);

        assert_eq!(
            hex::encode(&cid_bytes),
            vec("identity-genesis", "cidBytesHex"),
            "CID bytes mismatch"
        );

        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(cid_str, vec("identity-genesis", "cid"), "CID string mismatch");
    }

    #[test]
    fn test_did_derivation() {
        let cid_bytes = hex::decode(vec("identity-genesis", "cidBytesHex")).unwrap();
        let did_hash: [u8; 32] = Sha256::digest(&cid_bytes).into();
        let did = format!("did:dfos:{}", encode_id(&did_hash));
        assert_eq!(did, vec("identity-genesis", "did"), "DID mismatch");
    }

    #[test]
    fn test_jws_genesis_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(vec("identity-genesis", "jws"), &pub1);

        assert_eq!(header["alg"], "EdDSA", "wrong alg");
        assert_eq!(header["typ"], "did:dfos:identity-op", "wrong typ");
        assert_eq!(header["kid"], vec("identity-genesis", "kid"), "wrong kid");
        assert_eq!(header["cid"], vec("identity-genesis", "cid"), "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");
        assert_eq!(payload["version"], 1, "wrong payload version");
    }

    #[test]
    fn test_jws_rotation_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(vec("identity-rotation", "jws"), &pub1);

        assert_eq!(header["kid"], vec("identity-rotation", "kid"), "wrong kid");
        assert_eq!(header["cid"], vec("identity-rotation", "cid"), "wrong cid");
        assert_eq!(payload["type"], "update", "wrong type");
        assert_eq!(
            payload["previousOperationCID"],
            vec("identity-rotation", "previousOperationCID"),
            "wrong previousOperationCID"
        );
    }

    /// Verify the possession proof embedded in the rotation operation. The
    /// OPERATION is signed by key 1; the envelope inside it is signed by key 2 —
    /// the key being introduced — against the key named in the envelope's own
    /// payload. That circularity is the possession proof. The payload is closed:
    /// exactly seven members, one order, one serialization.
    #[test]
    fn test_key_proof_carried_by_rotation() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (_, payload) = verify_jws(vec("identity-rotation", "jws"), &pub1);

        let proofs = payload["keyProofs"]
            .as_array()
            .expect("rotation must carry keyProofs");
        assert_eq!(proofs.len(), 1, "rotation must carry exactly one key proof");
        let envelope = proofs[0].as_str().expect("key proof must be a JWS string");

        let parts: Vec<&str> = envelope.split('.').collect();
        assert_eq!(parts.len(), 3, "key proof must be a compact JWS");

        let header_text =
            String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let payload_text =
            String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();

        let header: serde_json::Value = serde_json::from_str(&header_text).unwrap();
        assert_eq!(header["alg"], "EdDSA", "wrong key proof alg");
        assert_eq!(header["typ"], vec("key-proof", "typ"), "wrong key proof typ");
        assert_eq!(
            header.as_object().unwrap().len(),
            2,
            "key proof header must be exactly {{alg, typ}}"
        );

        // The load-bearing check: the presented octets ARE the canonical
        // serialization. The bytes bind the verifier, not only the signer.
        assert_eq!(
            payload_text,
            vec("key-proof", "canonicalPayload"),
            "key proof payload is not the canonical serialization"
        );

        let proof: serde_json::Value = serde_json::from_str(&payload_text).unwrap();
        assert_eq!(
            proof.as_object().unwrap().len(),
            7,
            "key proof payload must have exactly seven members"
        );

        let mut cursor: isize = -1;
        for member in vec_strings("key-proof", "members") {
            let at = payload_text
                .find(&format!("\"{member}\":"))
                .map(|i| i as isize)
                .unwrap_or(-1);
            assert!(at > cursor, "key proof member {member} is out of canonical order");
            cursor = at;
        }

        assert_eq!(proof["did"], vec("key-proof", "did"), "wrong key proof did");
        assert_eq!(
            proof["prevCID"],
            vec("key-proof", "prevCID"),
            "key proof prevCID is not the genesis CID"
        );
        assert_eq!(
            proof["roleSet"],
            vec("key-proof", "roleSet"),
            "wrong key proof roleSet"
        );
        assert_eq!(
            proof["publicKeyMultibase"],
            vec("key-proof", "publicKeyMultibase"),
            "key proof does not name key 2"
        );

        // The signature verifies against the key the payload itself names —
        // there is no resolver seam here.
        let proof_key_bytes = decode_multikey(proof["publicKeyMultibase"].as_str().unwrap());
        assert_eq!(
            proof_key_bytes,
            pub2.as_bytes(),
            "key proof key is not reference key 2"
        );
        let key_array: [u8; 32] = proof_key_bytes.try_into().unwrap();
        let proof_pub = VerifyingKey::from_bytes(&key_array).unwrap();

        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64, "key proof signature must be 64 bytes");
        assert!(
            scalar_is_canonical(&sig_bytes[32..64]),
            "non-canonical key proof signature scalar (S >= L)"
        );
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        assert!(
            proof_pub.verify(signing_input.as_bytes(), &signature).is_ok(),
            "key proof signature verification failed under its own named key"
        );
    }

    #[test]
    fn test_jws_delete_restore_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (delete_header, delete_payload) = verify_jws(vec("identity-delete", "jws"), &pub2);
        assert_eq!(delete_payload["type"], "delete");
        assert_eq!(
            delete_payload["previousOperationCID"],
            vec("identity-delete", "previousOperationCID")
        );
        let delete_cid = cid_to_base32(&make_cid_bytes(&dag_cbor_encode_json(&delete_payload)));
        assert_eq!(delete_cid, delete_header["cid"]);
        assert_eq!(delete_cid, vec("identity-delete", "cid"));

        let (restore_header, restore_payload) = verify_jws(vec("identity-restore", "jws"), &pub2);
        assert_eq!(restore_payload["type"], "restore");
        assert_eq!(restore_payload["previousOperationCID"], delete_header["cid"]);
        let restore_cid = cid_to_base32(&make_cid_bytes(&dag_cbor_encode_json(&restore_payload)));
        assert_eq!(restore_cid, restore_header["cid"]);
        assert_eq!(restore_cid, vec("identity-restore", "cid"));
    }

    #[test]
    fn test_jws_content_create_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (header, payload) = verify_jws(vec("content-create", "jws"), &pub2);

        assert_eq!(header["typ"], vec("content-create", "typ"), "wrong typ");
        assert_eq!(header["kid"], vec("content-create", "kid"), "wrong kid");
        assert_eq!(header["cid"], vec("content-create", "cid"), "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");
        assert_eq!(
            payload["documentCID"],
            vec("content-create", "documentCID"),
            "wrong documentCID"
        );
    }

    /// Re-derive the CID of the content document the create operation commits
    /// to. The document itself is the shared vector: encode it as canonical
    /// dag-cbor and the published CID must come back out.
    #[test]
    fn test_document_cid() {
        let cbor_bytes = dag_cbor_encode_json(vec_value("document", "value"));
        let cid = cid_to_base32(&make_cid_bytes(&cbor_bytes));
        assert_eq!(cid, vec("document", "cid"), "document CID mismatch");
    }

    #[test]
    fn test_jwt_verification() {
        let (_, pub2) = derive_public_key(b"dfos-protocol-reference-key-2");
        let (header, payload) = verify_jws(vec("jwt", "token"), &pub2);

        assert_eq!(header["alg"], "EdDSA", "wrong alg");
        assert_eq!(header["typ"], "JWT", "wrong typ");
        assert_eq!(payload["iss"], vec("jwt", "iss"), "wrong iss");
        assert_eq!(payload["sub"], vec("jwt", "sub"), "wrong sub");
        assert_eq!(payload["aud"], vec("jwt", "aud"), "wrong aud");
    }

    // =========================================================================
    // Services-genesis and credential tests
    // =========================================================================

    // The canonical services-genesis identity-op is a create op carrying a
    // full-state services array (relay locator + content/artifact anchors),
    // signed by reference key 1, alongside the two credential vectors it shares
    // a DID with. The services fields ride along in the payload map, so
    // recomputing the operation CID over the decoded payload requires no
    // services-validation logic here.

    #[test]
    fn test_services_genesis_verification() {
        // Verify the canonical services-genesis identity-op: signature check with
        // reference key 1, then an independent recomputation of the operation CID
        // over the decoded payload (services fields ride along in the payload map —
        // no services-validation logic required here), asserting it equals the JWS
        // header cid and that the derived DID matches.
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        let (header, payload) = verify_jws(vec("services-genesis", "jws"), &pub1);

        assert_eq!(header["typ"], vec("services-genesis", "typ"), "wrong typ");
        assert_eq!(header["kid"], vec("services-genesis", "kid"), "wrong kid");
        assert_eq!(header["cid"], vec("services-genesis", "cid"), "wrong cid");
        assert_eq!(payload["type"], "create", "wrong payload type");

        // Recompute the operation CID over the decoded payload and assert it
        // matches the value committed in the JWS header.
        let cbor_bytes = dag_cbor_encode_json(&payload);
        let cid_str = cid_to_base32(&make_cid_bytes(&cbor_bytes));
        assert_eq!(
            cid_str,
            vec("services-genesis", "cid"),
            "recomputed CID mismatch"
        );

        // Derive the DID from the operation CID bytes and assert it matches.
        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let did_hash: [u8; 32] = Sha256::digest(&cid_bytes).into();
        let did = format!("did:dfos:{}", encode_id(&did_hash));
        assert_eq!(did, vec("services-genesis", "did"), "DID mismatch");
    }

    /// Check one credential JWS against the shared vector of the given id:
    /// signature under the issuer key, then every published header and payload
    /// field.
    fn assert_credential(token: &str, pub_key: &VerifyingKey, id: &str) {
        let (header, payload) = verify_jws(token, pub_key);

        assert_eq!(header["typ"], vec(id, "typ"), "wrong typ");
        assert_eq!(header["kid"], vec(id, "kid"), "wrong kid");
        assert_eq!(header["cid"], vec(id, "cid"), "wrong cid");
        assert_eq!(payload["type"], "DFOSCredential", "wrong type");
        assert_eq!(payload["iss"], vec(id, "iss"), "wrong iss");
        assert_eq!(payload["aud"], vec(id, "aud"), "wrong aud");

        let att = payload["att"].as_array().expect("att should be an array");
        assert_eq!(att.len(), 1, "att should have one entry");
        assert_eq!(att[0]["resource"], vec(id, "resource"), "wrong resource");
        assert_eq!(att[0]["action"], vec(id, "action"), "wrong action");
    }

    #[test]
    fn test_write_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        assert_credential(vec("credential-write", "jws"), &pub1, "credential-write");
    }

    #[test]
    fn test_read_credential_verification() {
        let (_, pub1) = derive_public_key(b"dfos-protocol-reference-key-1");
        assert_credential(vec("credential-read", "jws"), &pub1, "credential-read");
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
            vec("number-integer", "cborHex"),
            "CBOR bytes mismatch for integer 1"
        );

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(
            cid_str,
            vec("number-integer", "cid"),
            "CID mismatch for integer 1"
        );
    }

    #[test]
    fn test_number_encoding_from_json() {
        // Parse JSON and convert to ciborium Value, mimicking the
        // JSON deserialization → CBOR encoding pipeline.
        let cbor_bytes = dag_cbor_encode_json(vec_value("number-integer", "value"));

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);
        assert_eq!(
            cid_str,
            vec("number-integer", "cid"),
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

        // The float serialization is itself a shared vector: these are the exact
        // bytes a conforming encoder must never emit.
        assert_eq!(
            hex::encode(&cbor_bytes),
            vec("number-integer", "floatCborHex"),
            "float CBOR bytes mismatch"
        );

        let cid_bytes = make_cid_bytes(&cbor_bytes);
        let cid_str = cid_to_base32(&cid_bytes);

        assert_eq!(
            cid_str,
            vec("number-integer", "floatCid"),
            "float 1.0 should produce the known-wrong CID"
        );
        assert_ne!(
            cid_str,
            vec("number-integer", "cid"),
            "float 1.0 must NOT produce the correct integer CID"
        );
    }

    // =========================================================================
    // Reject corpus — every conformant verifier MUST reject all of these.
    // Byte-identical inputs across all five language suites. The S < L gate
    // above is what makes RV-S-NONCANON-* fail under dalek.
    // =========================================================================

    #[test]
    fn test_reject_corpus() {
        let pub_bytes: [u8; 32] = hex::decode(vec("reject-corpus", "publicKeyHex"))
            .unwrap()
            .try_into()
            .unwrap();
        let pub_key = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let tokens = vec_value("reject-corpus", "tokens")
            .as_object()
            .expect("reject-corpus.tokens is not an object");
        assert!(!tokens.is_empty(), "reject corpus is empty");
        for (name, token) in tokens {
            let token = token
                .as_str()
                .unwrap_or_else(|| panic!("reject vector {name} is not a string"));
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
        let cbor = dag_cbor_encode_json(vec_value("number-max-safe", "value"));
        assert_eq!(
            make_cid_string(&cbor),
            vec("number-max-safe", "cid"),
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
        let cbor = dag_cbor_encode_json(vec_value("number-null-vector", "value"));
        assert_eq!(
            make_cid_string(&cbor),
            vec("number-null-vector", "cid"),
            "null vector CID mismatch"
        );
    }
}
