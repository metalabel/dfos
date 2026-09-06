"""
DFOS Protocol — Independent verification in Python

Verifies all deterministic reference artifacts from the protocol specification.
Uses only standard crypto libraries (pynacl, dag-cbor, base58).

Run: uv run --python 3.14 --with pynacl --with dag-cbor --with base58 -- python3.14 verify_protocol.py
"""

import base64
import hashlib
import json
import pathlib
import sys

import dag_cbor
import nacl.signing
from base58 import b58decode, b58encode

# =============================================================================
# Shared reference vectors
# =============================================================================
#
# Every expected value below is read from ../vectors.json — the one artifact all
# five suites share, generated from the protocol's fixed seeds by
# packages/dfos-protocol/tests/protocol-reference.spec.ts, which asserts the
# checked-in file is byte-identical to a fresh generation.
#
# Reading a JSON fixture is not a library import. This suite still uses only the
# language's native Ed25519, dag-cbor and SHA-256, and a third party can run it
# with nothing but this file and vectors.json.

VECTORS_PATH = pathlib.Path(__file__).resolve().parent.parent / "vectors.json"
VECTORS_BY_ID = {
    v["id"]: v["values"] for v in json.loads(VECTORS_PATH.read_text())["vectors"]
}


def vector_values(vector_id: str) -> dict:
    """All values of one vector, by id."""
    if vector_id not in VECTORS_BY_ID:
        raise KeyError(f'vectors.json has no vector "{vector_id}"')
    return VECTORS_BY_ID[vector_id]


def vec(vector_id: str, field: str):
    """One field of one vector."""
    values = vector_values(vector_id)
    if field not in values:
        raise KeyError(f"vectors.json {vector_id} has no field {field}")
    return values[field]


ALPHABET = "2346789acdefhknrtvz"
ID_LENGTH = 31

GENESIS_JWS = vec("identity-genesis", "jws")
ROTATION_JWS = vec("identity-rotation", "jws")
DELETE_JWS = vec("identity-delete", "jws")
RESTORE_JWS = vec("identity-restore", "jws")
CONTENT_CREATE_JWS = vec("content-create", "jws")
JWT_TOKEN = vec("jwt", "token")
BROAD_WRITE_VC = vec("credential-write", "jws")
READ_VC = vec("credential-read", "jws")

# Services genesis: an identity create whose payload carries a full-state
# services discovery array (relay locator + content/artifact anchors). The
# services fields ride along in the payload map, so recomputing the operation
# CID over the decoded payload yields the published CID unchanged.
SERVICES_GENESIS_JWS = vec("services-genesis", "jws")

EXPECTED_GENESIS_CID = vec("identity-genesis", "cid")
EXPECTED_DID = vec("identity-genesis", "did")
EXPECTED_MULTIKEY1 = vec("key-1", "multikey")
EXPECTED_MULTIKEY2 = vec("key-2", "multikey")

# The possession proof the rotation carries. Its payload is CLOSED: exactly these
# seven members, in exactly this order — and the octets below are the only
# serialization those members are ever signed as. The envelope is signed by key 2
# (the key being introduced) while the operation carrying it is signed by key 1.
KEY_PROOF_MEMBERS = vec("key-proof", "members")
KEY_PROOF_ROLE_SET = vec("key-proof", "roleSet")
KEY_PROOF_CANONICAL_PAYLOAD = vec("key-proof", "canonicalPayload")

EXPECTED_CBOR_HEX = vec("identity-genesis", "cborHex")
EXPECTED_CID_HEX = vec("identity-genesis", "cidBytesHex")

# =============================================================================
# Helpers
# =============================================================================

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)

def encode_id(hash_bytes: bytes) -> str:
    return "".join(ALPHABET[b % 19] for b in hash_bytes[:ID_LENGTH])

def decode_multikey(multibase: str) -> bytes:
    assert multibase[0] == "z", "expected base58btc multibase prefix 'z'"
    raw = b58decode(multibase[1:])
    assert raw[0] == 0xED and raw[1] == 0x01, f"expected ed25519-pub multicodec prefix, got {raw[:2].hex()}"
    return bytes(raw[2:])

def encode_multikey(pub_bytes: bytes) -> str:
    raw = bytes([0xED, 0x01]) + pub_bytes
    return "z" + b58encode(raw).decode()

def make_cid_bytes(cbor_bytes: bytes) -> bytes:
    digest = hashlib.sha256(cbor_bytes).digest()
    # CIDv1: version(0x01) + codec(0x71=dag-cbor) + multihash(0x12=sha256, 0x20=32 bytes, digest)
    return bytes([0x01, 0x71, 0x12, 0x20]) + digest

def cid_to_base32(cid_bytes: bytes) -> str:
    # base32lower multibase (prefix 'b')
    return "b" + base64.b32encode(cid_bytes).decode().lower().rstrip("=")

# Ed25519 group order L (little-endian 32 bytes) — the canonical S < L bound.
ED25519_L = bytes([
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
])


def scalar_is_canonical(s: bytes) -> bool:
    """True iff the 32-byte little-endian scalar s is < L."""
    if len(s) != 32:
        return False
    for i in range(31, -1, -1):
        if s[i] < ED25519_L[i]:
            return True
        if s[i] > ED25519_L[i]:
            return False
    return False  # s == L is non-canonical


def assert_jws_profile(header: dict) -> None:
    """DFOS Signature Verification Profile (pragmatic v1) header gates.
    Applied BEFORE any signature check. See PROTOCOL.md."""
    if header.get("alg") != "EdDSA":
        raise ValueError(f"unsupported algorithm: {header.get('alg')}")
    if "crit" in header:
        raise ValueError("crit header is not supported")
    if "jwk" in header:
        raise ValueError("jwk header is not allowed")
    if "x5c" in header:
        raise ValueError("x5c header is not allowed")


def verify_jws(token: str, pub_key_bytes: bytes) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid JWS format")
    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(b64url_decode(header_b64))

    # profile gates run before any signature work
    assert_jws_profile(header)

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = b64url_decode(sig_b64)

    # length + canonical-scalar (S < L) gates
    if len(signature) != 64:
        raise ValueError(f"signature must be 64 bytes, got {len(signature)}")
    if not scalar_is_canonical(signature[32:64]):
        raise ValueError("non-canonical signature scalar (S >= L)")

    verify_key = nacl.signing.VerifyKey(pub_key_bytes)
    # nacl verify expects signature + message concatenated
    verify_key.verify(signing_input, signature)
    payload = json.loads(b64url_decode(payload_b64))
    return {"header": header, "payload": payload}

# =============================================================================
# Tests
# =============================================================================

passed = 0
failed = 0

def check(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name} {detail}")

print("=" * 70)
print("DFOS Protocol — Python Verification")
print("=" * 70)

# --- 1. Deterministic key derivation ---
print("\n1. Key Derivation")
seed1 = hashlib.sha256(b"dfos-protocol-reference-key-1").digest()
signing_key1 = nacl.signing.SigningKey(seed1)
pub1 = signing_key1.verify_key.encode()
check("Key 1 private", seed1.hex() == vec("key-1", "privateKeyHex"))
check("Key 1 public", pub1.hex() == vec("key-1", "publicKeyHex"))

seed2 = hashlib.sha256(b"dfos-protocol-reference-key-2").digest()
signing_key2 = nacl.signing.SigningKey(seed2)
pub2 = signing_key2.verify_key.encode()
check("Key 2 private", seed2.hex() == vec("key-2", "privateKeyHex"))
check("Key 2 public", pub2.hex() == vec("key-2", "publicKeyHex"))

# --- 2. Multikey encoding ---
print("\n2. Multikey Encoding")
multikey1 = encode_multikey(pub1)
check("Multikey 1 encode", multikey1 == EXPECTED_MULTIKEY1, f"got {multikey1}")
decoded_pub1 = decode_multikey(EXPECTED_MULTIKEY1)
check("Multikey 1 decode", decoded_pub1 == pub1)

# --- 3. dag-cbor canonical encoding ---
print("\n3. dag-cbor Canonical Encoding")
genesis_payload = vec("identity-genesis", "payload")
cbor_bytes = dag_cbor.encode(genesis_payload)
check("CBOR bytes match", cbor_bytes.hex() == EXPECTED_CBOR_HEX,
      f"\ngot:      {cbor_bytes.hex()[:80]}...\nexpected: {EXPECTED_CBOR_HEX[:80]}...")

# --- 4. CID derivation ---
print("\n4. CID Derivation")
cid_bytes = make_cid_bytes(cbor_bytes)
check("CID bytes match", cid_bytes.hex() == EXPECTED_CID_HEX, f"got {cid_bytes.hex()}")
cid_string = cid_to_base32(cid_bytes)
check("CID string match", cid_string == EXPECTED_GENESIS_CID, f"got {cid_string}")

# --- 5. DID derivation ---
print("\n5. DID Derivation")
did_hash = hashlib.sha256(cid_bytes).digest()
check("DID hash", did_hash.hex() == vec("identity-genesis", "didHashHex"), f"got {did_hash.hex()}")
did_suffix = encode_id(did_hash)
full_did = f"did:dfos:{did_suffix}"
check("Full DID", full_did == EXPECTED_DID, f"got {full_did}")

# --- 6. JWS verification: genesis ---
print("\n6. JWS Verification: Genesis (key 1)")
result = verify_jws(GENESIS_JWS, pub1)
check("Genesis signature valid", True)
check("Genesis header alg", result["header"]["alg"] == "EdDSA")
check("Genesis header typ", result["header"]["typ"] == "did:dfos:identity-op")
check("Genesis header kid", result["header"]["kid"] == vec("identity-genesis", "kid"))
check("Genesis header cid", result["header"]["cid"] == EXPECTED_GENESIS_CID)
check("Genesis payload type", result["payload"]["type"] == "create")
check("Genesis payload version", result["payload"]["version"] == 1)

# --- 7. JWS verification: rotation (signed by key 1) ---
print("\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)")
result = verify_jws(ROTATION_JWS, pub1)
check("Rotation signature valid", True)
check("Rotation kid is DID URL", result["header"]["kid"] == vec("identity-rotation", "kid"))
check("Rotation header cid", result["header"]["cid"] == vec("identity-rotation", "cid"))
check("Rotation payload type", result["payload"]["type"] == "update")
check("Rotation previousOperationCID", result["payload"]["previousOperationCID"] == EXPECTED_GENESIS_CID)

# --- 7b. JWS verification: delete + restore (signed by key 2) ---
print("\n7b. JWS Verification: Delete + Restore (key 2)")
result = verify_jws(DELETE_JWS, pub2)
check("Delete payload type", result["payload"]["type"] == "delete")
check("Delete header cid", result["header"]["cid"] == vec("identity-delete", "cid"))
check("Delete parent is rotation", result["payload"]["previousOperationCID"] == vec("identity-delete", "previousOperationCID"))
check("Delete CID re-derived", cid_to_base32(make_cid_bytes(dag_cbor.encode(result["payload"]))) == result["header"]["cid"])
result = verify_jws(RESTORE_JWS, pub2)
check("Restore payload type", result["payload"]["type"] == "restore")
check("Restore header cid", result["header"]["cid"] == vec("identity-restore", "cid"))
check("Restore parent is delete", result["payload"]["previousOperationCID"] == vec("identity-restore", "previousOperationCID"))
check("Restore CID re-derived", cid_to_base32(make_cid_bytes(dag_cbor.encode(result["payload"]))) == result["header"]["cid"])

# --- 7c. Possession proof: the key proof the rotation carries ---
# The rotation OPERATION is signed by key 1; the envelope embedded in it is
# signed by key 2 — the key being introduced — against the key named in the
# envelope's own payload. That circularity is the possession proof. The payload
# is closed: exactly seven members, one order, one serialization.
print("\n7c. Key Proof carried by the Rotation (envelope signed by key 2)")
rotation_result = verify_jws(ROTATION_JWS, pub1)
key_proofs = rotation_result["payload"].get("keyProofs")
check("Rotation carries exactly one key proof", isinstance(key_proofs, list) and len(key_proofs) == 1)

kp_parts = key_proofs[0].split(".")
check("Key proof is a compact JWS", len(kp_parts) == 3)
kp_header_text = b64url_decode(kp_parts[0]).decode("utf-8")
kp_payload_text = b64url_decode(kp_parts[1]).decode("utf-8")
kp_header = json.loads(kp_header_text)
kp_payload = json.loads(kp_payload_text)

check("Key proof header alg", kp_header.get("alg") == "EdDSA", f"got {kp_header.get('alg')}")
check("Key proof header typ", kp_header.get("typ") == "did:dfos:key-add", f"got {kp_header.get('typ')}")
check("Key proof header is exactly {alg, typ}", len(kp_header) == 2)

# The load-bearing check: the presented octets ARE the canonical serialization.
check("Key proof payload octets are canonical", kp_payload_text == KEY_PROOF_CANONICAL_PAYLOAD,
      f"got {kp_payload_text}")
check("Key proof payload has exactly 7 members", len(kp_payload) == 7)

kp_cursor = -1
kp_ordered = True
for member in KEY_PROOF_MEMBERS:
    at = kp_payload_text.find(f'"{member}":')
    if at <= kp_cursor:
        kp_ordered = False
    kp_cursor = at
check("Key proof members are in canonical order", kp_ordered)

check("Key proof binds the reference DID", kp_payload["did"] == EXPECTED_DID, f"got {kp_payload['did']}")
check("Key proof prevCID is the genesis CID", kp_payload["prevCID"] == EXPECTED_GENESIS_CID,
      f"got {kp_payload['prevCID']}")
check("Key proof roleSet", kp_payload["roleSet"] == KEY_PROOF_ROLE_SET, f"got {kp_payload['roleSet']}")
check("Key proof names key 2", kp_payload["publicKeyMultibase"] == EXPECTED_MULTIKEY2,
      f"got {kp_payload['publicKeyMultibase']}")

# The signature verifies against the key the payload itself names — there is no
# resolver seam here.
kp_pub = decode_multikey(kp_payload["publicKeyMultibase"])
check("Key proof key decodes to key 2", kp_pub == pub2)
kp_sig = b64url_decode(kp_parts[2])
check("Key proof signature is 64 bytes", len(kp_sig) == 64, f"got {len(kp_sig)}")
check("Key proof signature scalar is canonical", scalar_is_canonical(kp_sig[32:64]))
kp_signing_input = f"{kp_parts[0]}.{kp_parts[1]}".encode("ascii")
kp_valid = True
try:
    nacl.signing.VerifyKey(kp_pub).verify(kp_signing_input, kp_sig)
except Exception:
    kp_valid = False
check("Key proof signature valid under its own named key", kp_valid)

# --- 8. JWS verification: content create (signed by key 2) ---
print("\n8. JWS Verification: Content Create (key 2)")
result = verify_jws(CONTENT_CREATE_JWS, pub2)
check("Content create signature valid", True)
check("Content create typ", result["header"]["typ"] == "did:dfos:content-op")
check("Content create kid", result["header"]["kid"] == vec("content-create", "kid"))
check("Content create header cid", result["header"]["cid"] == vec("content-create", "cid"))
check("Content create payload type", result["payload"]["type"] == "create")

# --- 9. JWT verification (signed by key 2) ---
print("\n9. JWT Verification (key 2)")
result = verify_jws(JWT_TOKEN, pub2)  # JWT uses same signing as JWS
check("JWT signature valid", True)
check("JWT header alg", result["header"]["alg"] == "EdDSA")
check("JWT payload iss", result["payload"]["iss"] == vec("jwt", "iss"))
check("JWT payload sub", result["payload"]["sub"] == vec("jwt", "sub"))
check("JWT payload aud", result["payload"]["aud"] == vec("jwt", "aud"))

# --- 10. Document CID ---
print("\n10. Document CID Verification")
document = vec("document", "value")
doc_cbor = dag_cbor.encode(document)
doc_cid_bytes = make_cid_bytes(doc_cbor)
doc_cid = cid_to_base32(doc_cid_bytes)
check("Document CID", doc_cid == vec("document", "cid"), f"got {doc_cid}")

# --- 11. Services-genesis JWS verification ---
# Identity genesis carrying a services discovery set (relay locator + content/
# artifact anchors). Signed by reference key 1 — the same key as the genesis
# vector. The services fields ride along in the payload map, so recomputing the
# operation CID over the decoded payload yields the published CID unchanged.
print("\n11. Services-Genesis JWS Verification (key 1)")
SERVICES_GENESIS_JWS = vec("services-genesis", "jws")
EXPECTED_SERVICES_CID = vec("services-genesis", "cid")
EXPECTED_SERVICES_DID = vec("services-genesis", "did")

result = verify_jws(SERVICES_GENESIS_JWS, pub1)
check("Services-genesis signature valid", True)
check("Services-genesis header typ", result["header"]["typ"] == "did:dfos:identity-op")
check("Services-genesis header kid", result["header"]["kid"] == vec("services-genesis", "kid"))
check("Services-genesis header cid", result["header"]["cid"] == EXPECTED_SERVICES_CID)
check("Services-genesis payload type", result["payload"]["type"] == "create")

# Recompute the operation CID over the decoded payload (services fields ride
# along in the payload map) and assert it equals the published CID + DID.
services_cbor = dag_cbor.encode(result["payload"])
services_cid = cid_to_base32(make_cid_bytes(services_cbor))
check("Services-genesis recomputed CID", services_cid == EXPECTED_SERVICES_CID, f"got {services_cid}")
services_did = f"did:dfos:{encode_id(hashlib.sha256(make_cid_bytes(services_cbor)).digest())}"
check("Services-genesis derived DID", services_did == EXPECTED_SERVICES_DID, f"got {services_did}")

# --- 13. DFOS Credential Verification ---
print("\n13. DFOS Credential Verification (key 1)")
EXPECTED_CREDENTIAL_AUD = vec("credential-write", "aud")

result = verify_jws(BROAD_WRITE_VC, pub1)
check("Write credential signature valid", True)
check("Write credential header typ", result["header"]["typ"] == "did:dfos:credential")
check("Write credential header kid", result["header"]["kid"] == vec("credential-write", "kid"))
check("Write credential payload type", result["payload"]["type"] == "DFOSCredential")
check("Write credential payload iss", result["payload"]["iss"] == EXPECTED_DID)
check("Write credential payload aud", result["payload"]["aud"] == EXPECTED_CREDENTIAL_AUD)
att = result["payload"]["att"]
check("Write credential att is list", isinstance(att, list) and len(att) > 0)
check("Write credential att resource", att[0]["resource"] == vec("credential-write", "resource"))
check("Write credential att action", att[0]["action"] == vec("credential-write", "action"))

result = verify_jws(READ_VC, pub1)
check("Read credential signature valid", True)
check("Read credential payload type", result["payload"]["type"] == "DFOSCredential")
check("Read credential att action", result["payload"]["att"][0]["action"] == vec("credential-read", "action"))

# Number encoding determinism tests
print("\n14. Number Encoding Determinism")

def test_number_encoding_determinism():
    payload = vec("number-integer", "value")
    cbor_bytes = dag_cbor.encode(payload)
    check("Integer CBOR hex", cbor_bytes.hex() == vec("number-integer", "cborHex"),
          f"got {cbor_bytes.hex()}")
    cid_string = cid_to_base32(make_cid_bytes(cbor_bytes))
    check("Integer CID", cid_string == vec("number-integer", "cid"), f"got {cid_string}")

def test_number_encoding_from_json():
    payload = json.loads('{"version": 1, "type": "test"}')
    cbor_bytes = dag_cbor.encode(payload)
    cid_string = cid_to_base32(make_cid_bytes(cbor_bytes))
    check("JSON int parsed as int (not float)", cid_string == vec("number-integer", "cid"),
          f"got {cid_string}")

def test_number_encoding_float_produces_wrong_cid():
    # The float serialization a conforming encoder MUST NOT emit, and the CID it
    # yields — the shared vector every suite pins as the known-wrong answer.
    float_cbor = bytes.fromhex(vec("number-integer", "floatCborHex"))
    cid_string = cid_to_base32(make_cid_bytes(float_cbor))
    check("Float CBOR yields the known-wrong CID",
          cid_string == vec("number-integer", "floatCid"), f"got {cid_string}")
    check("Float CID differs from the integer CID",
          cid_string != vec("number-integer", "cid"),
          "unexpectedly matched the integer CID")

test_number_encoding_determinism()
test_number_encoding_from_json()
test_number_encoding_float_produces_wrong_cid()

# --- 15. Reject corpus (profile + signature gates) ---
# Every conformant verifier MUST reject all of these. Byte-identical inputs
# across all five language suites. Reference key 1 signs the base vector.
print("\n15. Reject Corpus (all MUST be rejected)")

reject_pub = bytes.fromhex(vec("reject-corpus", "publicKeyHex"))

REJECT_VECTORS = vec("reject-corpus", "tokens")

for name, token in REJECT_VECTORS.items():
    rejected = False
    try:
        verify_jws(token, reject_pub)
    except Exception:
        rejected = True
    check(f"{name} rejected", rejected, "was accepted")

# --- 16. WP-0 number-policy vectors ---
print("\n16. WP-0 Number Policy")

MAX_SAFE = 9007199254740991  # 2^53 - 1


def assert_canonical_numbers(value):
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if value > MAX_SAFE or value < -MAX_SAFE:
            raise ValueError("out of safe range")
        return
    if isinstance(value, float):
        import math as _math
        if not _math.isfinite(value):
            raise ValueError("non-finite")
        if value != int(value):
            raise ValueError("non-integer")
        if value > MAX_SAFE or value < -MAX_SAFE:
            raise ValueError("out of safe range")
        return
    if isinstance(value, list):
        for e in value:
            assert_canonical_numbers(e)
        return
    if isinstance(value, dict):
        for e in value.values():
            assert_canonical_numbers(e)


def number_cid(value) -> str:
    assert_canonical_numbers(value)
    cbor = dag_cbor.encode(value)
    return cid_to_base32(make_cid_bytes(cbor))


# accept: 2^53-1
check("accept int 2^53-1",
      number_cid(vec("number-max-safe", "value")) == vec("number-max-safe", "cid"),
      "wrong CID")

# reject: 2^53, 1.5, NaN, +Inf, -Inf
for name, bad in [
    ("2^53", 9007199254740992),
    ("1.5", 1.5),
    ("NaN", float("nan")),
    ("+Inf", float("inf")),
    ("-Inf", float("-inf")),
]:
    rejected = False
    try:
        number_cid({"x": bad})
    except Exception:
        rejected = True
    check(f"reject {name}", rejected, "was accepted")

# null vector: { documentCID: null, note: null, prf: [] }
check("null vector CID",
      number_cid(vec("number-null-vector", "value")) == vec("number-null-vector", "cid"),
      "wrong CID")

# --- Summary ---
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed")
print(f"{'=' * 70}")
sys.exit(1 if failed > 0 else 0)
