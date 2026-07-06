"""
DFOS Protocol — Independent verification in Python

Verifies all deterministic reference artifacts from the TypeScript implementation.
Uses only standard crypto libraries (pynacl, dag-cbor, base58).

Run: uv run --python 3.14 --with pynacl --with dag-cbor --with base58 -- python3.14 verify_protocol.py
"""

import base64
import hashlib
import json
import sys

import dag_cbor
import nacl.signing
from base58 import b58decode, b58encode

# =============================================================================
# Constants from the reference doc
# =============================================================================

ALPHABET = "2346789acdefhknrtvz"
ID_LENGTH = 31

GENESIS_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.TeznHnzrtKOGTr0FzkDL2z-luMWnAbKXrmDbi-Exgw_xMPCnYwGHORMjw-BM28f0RoTirIAeD7d20W5RSuGuBg"

ROTATION_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0ODNubjI5enZoZSIsImNpZCI6ImJhZnlyZWliZnVoNjN1djMzaTJpNWVvb2UzYm9pdDJydXlqZWh1YnNyeWVtdXV6Nm1ydGxlajI2cmVpIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpY29naHZqem52bGl1bG94eG1iZjU0dHB6cXdhaG5xcGlsazduY3hlcGppbmVkcGtnYTNuZSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZG43ejZ6cmN0OCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.7fqvWGEVYW9atA1uqpp7lIUOWp4dATLpLjOmFWzJN-8gTL-QnXDCeyGcBu5AXhHzO52fauwUavh1KrB6wBYuCw"

CONTENT_CREATE_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4IiwiY2lkIjoiYmFmeXJlaWZ3ZW1ybnR1cG92M3dsZXVib3plMzIyYnAzYnRwYmZzZDJ5d2pwZnJka3VkandyNGpxb2UifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWhxN2I2d2JwZXhlcHhubW0yNXJzY2RzNXB1bm53M2tuZ2RqM3ZtMmg1d3p1b2lxbHRlcmkiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiJ9.hwRdbbOdyl4noERFW28YfurNF-5tlpuWBj_gm_9u0iKI17r98s0mO_7DSdD7b4B0rwcfnOHyVYPUCHttmUYdCg"

JWT_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkbjd6NnpyY3Q4In0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6Y25ubmZ0OWY4YTJybjkzOGQ2bmt6MzhyODQ3djJrciIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.VdrDMOQoFAboxK165ZDOe5YXTgILUDO_bHuGHinupqEd4dptibATmyI9YrjseMaJHS4gggzX1st9qO5eoVJdCQ"

BROAD_WRITE_VC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWZ5aW5ieGhicml0NTZtM2FhdjY2bXc0eGQ2YWRxamFzdmNmaG11NjZnNnRudXFncnljbG0ifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoid3JpdGUifV0sInByZiI6W10sImV4cCI6MTc5ODc2MTYwMCwiaWF0IjoxNzcyODQxNjAwfQ.A-EygURAN2bALVwI2AZKFEuy30ZnWJFBaD4jCTf1d7A90rYELStjTWJ1iI7OulihTCfaVtlvj5HtX6Dwv1VxAg"

READ_VC = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNyZWRlbnRpYWwiLCJraWQiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyI2tleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwiY2lkIjoiYmFmeXJlaWN0aGNiaXp4dmdlbXN4djdrc2NvbzdhcGllYWFsM2Z5ZTM3bzQ1Zmt5a25lN2I0aG9icmEifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiREZPU0NyZWRlbnRpYWwiLCJpc3MiOiJkaWQ6ZGZvczpjbm5uZnQ5ZjhhMnJuOTM4ZDZua3ozOHI4NDd2MmtyIiwiYXVkIjoiZGlkOmRmb3M6OTRhaDc5NjNuMjIzazhjOTg4NGhoMjdla2g0Mm5lYSIsImF0dCI6W3sicmVzb3VyY2UiOiJjaGFpbjoqIiwiYWN0aW9uIjoicmVhZCJ9XSwicHJmIjpbXSwiZXhwIjoxNzk4NzYxNjAwLCJpYXQiOjE3NzI4NDE2MDB9.UvTItuWFriA39FZIdB5TuXa_b07eyNLc-iR0cej2litSkjBYAZaLlDJUmyDQ-3dB7TmNVXDbB3SMbpvLnWW9Dw"

EXPECTED_GENESIS_CID = "bafyreicoghvjznvliuloxxmbf54tpzqwahnqpilk7ncxepjinedpkga3ne"
EXPECTED_DID = "did:dfos:cnnnft9f8a2rn938d6nkz38r847v2kr"
EXPECTED_MULTIKEY1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
EXPECTED_CBOR_HEX = "a66474797065666372656174656776657273696f6e0168617574684b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a362696478236b65795f72396576333466766332337a39393976656161667438336e6e32397a7668656474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
EXPECTED_CID_HEX = "017112204e31ea9cb6ab4516ebdd812f7937e61601db07a16afb45723d286906f5181b69"

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
check("Key 1 private", seed1.hex() == "132d4bebdb6e62359afb930fe15d756a92ad96e6b0d47619988f5a1a55272aac")
check("Key 1 public", pub1.hex() == "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32")

seed2 = hashlib.sha256(b"dfos-protocol-reference-key-2").digest()
signing_key2 = nacl.signing.SigningKey(seed2)
pub2 = signing_key2.verify_key.encode()
check("Key 2 private", seed2.hex() == "384f5626906db84f6a773ec46475ff2d4458e92dd4dd13fe03dbb7510f4ca2a8")
check("Key 2 public", pub2.hex() == "0f350f994f94d675f04a325bd316ebedd740ca206eaaf609bdb641b5faa0f78c")

# --- 2. Multikey encoding ---
print("\n2. Multikey Encoding")
multikey1 = encode_multikey(pub1)
check("Multikey 1 encode", multikey1 == EXPECTED_MULTIKEY1, f"got {multikey1}")
decoded_pub1 = decode_multikey(EXPECTED_MULTIKEY1)
check("Multikey 1 decode", decoded_pub1 == pub1)

# --- 3. dag-cbor canonical encoding ---
print("\n3. dag-cbor Canonical Encoding")
genesis_payload = {
    "version": 1,
    "type": "create",
    "authKeys": [{"id": "key_r9ev34fvc23z999veaaft83nn29zvhe", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
    "assertKeys": [{"id": "key_r9ev34fvc23z999veaaft83nn29zvhe", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
    "controllerKeys": [{"id": "key_r9ev34fvc23z999veaaft83nn29zvhe", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
    "createdAt": "2026-03-07T00:00:00.000Z",
}
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
check("DID hash", did_hash.hex() == "c66d21f27dceea0b05534c225ad7018ac7d4dfded0609dcd18022a3739a5488c")
did_suffix = encode_id(did_hash)
check("DID suffix", did_suffix == "cnnnft9f8a2rn938d6nkz38r847v2kr", f"got {did_suffix}")
full_did = f"did:dfos:{did_suffix}"
check("Full DID", full_did == EXPECTED_DID)

# --- 6. JWS verification: genesis ---
print("\n6. JWS Verification: Genesis (key 1)")
result = verify_jws(GENESIS_JWS, pub1)
check("Genesis signature valid", True)
check("Genesis header alg", result["header"]["alg"] == "EdDSA")
check("Genesis header typ", result["header"]["typ"] == "did:dfos:identity-op")
check("Genesis header kid", result["header"]["kid"] == "key_r9ev34fvc23z999veaaft83nn29zvhe")
check("Genesis header cid", result["header"]["cid"] == EXPECTED_GENESIS_CID)
check("Genesis payload type", result["payload"]["type"] == "create")
check("Genesis payload version", result["payload"]["version"] == 1)

# --- 7. JWS verification: rotation (signed by key 1) ---
print("\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)")
result = verify_jws(ROTATION_JWS, pub1)
check("Rotation signature valid", True)
check("Rotation kid is DID URL", result["header"]["kid"] == f"{EXPECTED_DID}#key_r9ev34fvc23z999veaaft83nn29zvhe")
check("Rotation header cid", result["header"]["cid"] == "bafyreibfuh63uv33i2i5eooe3boit2ruyjehubsryemuuz6mrtlej26rei")
check("Rotation payload type", result["payload"]["type"] == "update")
check("Rotation previousOperationCID", result["payload"]["previousOperationCID"] == EXPECTED_GENESIS_CID)

# --- 8. JWS verification: content create (signed by key 2) ---
print("\n8. JWS Verification: Content Create (key 2)")
result = verify_jws(CONTENT_CREATE_JWS, pub2)
check("Content create signature valid", True)
check("Content create typ", result["header"]["typ"] == "did:dfos:content-op")
check("Content create kid", result["header"]["kid"] == f"{EXPECTED_DID}#key_ez9a874tckr3dv933d3ckdn7z6zrct8")
check("Content create header cid", result["header"]["cid"] == "bafyreifwemrntupov3wleuboze322bp3btpbfsd2ywjpfrdkudjwr4jqoe")
check("Content create payload type", result["payload"]["type"] == "create")

# --- 9. JWT verification (signed by key 2) ---
print("\n9. JWT Verification (key 2)")
result = verify_jws(JWT_TOKEN, pub2)  # JWT uses same signing as JWS
check("JWT signature valid", True)
check("JWT header alg", result["header"]["alg"] == "EdDSA")
check("JWT payload iss", result["payload"]["iss"] == "dfos")
check("JWT payload sub", result["payload"]["sub"] == EXPECTED_DID)
check("JWT payload aud", result["payload"]["aud"] == "dfos-api")

# --- 10. Document CID ---
print("\n10. Document CID Verification")
document = {
    "$schema": "https://schemas.dfos.com/post/v1",
    "format": "short-post",
    "title": "Hello World",
    "body": "First post on the protocol.",
    "credits": [{"did": EXPECTED_DID, "label": "author"}],
}
doc_cbor = dag_cbor.encode(document)
doc_cid_bytes = make_cid_bytes(doc_cbor)
doc_cid = cid_to_base32(doc_cid_bytes)
check("Document CID", doc_cid == "bafyreihq7b6wbpexepxnmm25rscds5punnw3kngdj3vm2h5wzuoiqlteri", f"got {doc_cid}")

# --- 11. Services-genesis JWS verification ---
# Identity genesis carrying a services discovery set (relay locator + content/
# artifact anchors). Signed by reference key 1 — the same key as the genesis
# vector. The services fields ride along in the payload map, so recomputing the
# operation CID over the decoded payload yields the published CID unchanged.
print("\n11. Services-Genesis JWS Verification (key 1)")
SERVICES_GENESIS_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJjaWQiOiJiYWZ5cmVpYnZxZDdmM2hqMzI3ZG9kbXBseDUzeGh2NHdnZXZiNjNmYWl1ZXF0eW9qNmlyb2x1N25qaSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgzbm4yOXp2aGUiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4M25uMjl6dmhlIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJzZXJ2aWNlcyI6W3siaWQiOiJyZWxheSIsInR5cGUiOiJEZm9zUmVsYXkiLCJlbmRwb2ludCI6Imh0dHBzOi8vcmVsYXkuZGZvcy5jb20ifSx7ImlkIjoicHJvZmlsZSIsInR5cGUiOiJDb250ZW50QW5jaG9yIiwibGFiZWwiOiJwcm9maWxlIiwiYW5jaG9yIjoiOTQzdjhyemRyOWZkcjR6Nzd0ZjhkZThobjNhZmVkNCJ9LHsiaWQiOiJhdmF0YXIiLCJ0eXBlIjoiQ29udGVudEFuY2hvciIsImxhYmVsIjoiYXZhdGFyIiwiYW5jaG9yIjoiYmFmeXJlaWhxN2I2d2JwZXhlcHhubW0yNXJzY2RzNXB1bm53M2tuZ2RqM3ZtMmg1d3p1b2lxbHRlcmkifV0sImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDU6MDAuMDAwWiJ9.ORU6Gad1tOiPihC-UN94PlBzccpFz8HbTPLrMmjz87El0MqD4J_61s3BVc-NjY9ARh7gpLZL2hwzwzO-GOl3AQ"
EXPECTED_SERVICES_CID = "bafyreibvqd7f3hj327dodmplx53xhv4wgevb63faiueqtyoj6irolu7nji"
EXPECTED_SERVICES_DID = "did:dfos:4ve48tvhnvzd9zt9n3tctr93afzczvz"

result = verify_jws(SERVICES_GENESIS_JWS, pub1)
check("Services-genesis signature valid", True)
check("Services-genesis header typ", result["header"]["typ"] == "did:dfos:identity-op")
check("Services-genesis header kid", result["header"]["kid"] == "key_r9ev34fvc23z999veaaft83nn29zvhe")
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
EXPECTED_CREDENTIAL_AUD = "did:dfos:94ah7963n223k8c9884hh27ekh42nea"

result = verify_jws(BROAD_WRITE_VC, pub1)
check("Write credential signature valid", True)
check("Write credential header typ", result["header"]["typ"] == "did:dfos:credential")
check("Write credential header kid", result["header"]["kid"] == f"{EXPECTED_DID}#key_r9ev34fvc23z999veaaft83nn29zvhe")
check("Write credential payload type", result["payload"]["type"] == "DFOSCredential")
check("Write credential payload iss", result["payload"]["iss"] == EXPECTED_DID)
check("Write credential payload aud", result["payload"]["aud"] == EXPECTED_CREDENTIAL_AUD)
att = result["payload"]["att"]
check("Write credential att is list", isinstance(att, list) and len(att) > 0)
check("Write credential att resource", att[0]["resource"] == "chain:*")
check("Write credential att action", att[0]["action"] == "write")

result = verify_jws(READ_VC, pub1)
check("Read credential signature valid", True)
check("Read credential payload type", result["payload"]["type"] == "DFOSCredential")
check("Read credential att action", result["payload"]["att"][0]["action"] == "read")

# Number encoding determinism tests
print("\n14. Number Encoding Determinism")

def test_number_encoding_determinism():
    payload = {"version": 1, "type": "test"}
    cbor_bytes = dag_cbor.encode(payload)
    expected_hex = "a2647479706564746573746776657273696f6e01"
    check("Integer CBOR hex", cbor_bytes.hex() == expected_hex,
          f"got {cbor_bytes.hex()}")
    cid_bytes = make_cid_bytes(cbor_bytes)
    cid_string = cid_to_base32(cid_bytes)
    expected_cid = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"
    check("Integer CID", cid_string == expected_cid, f"got {cid_string}")

def test_number_encoding_from_json():
    payload = json.loads('{"version": 1, "type": "test"}')
    cbor_bytes = dag_cbor.encode(payload)
    cid_bytes = make_cid_bytes(cbor_bytes)
    cid_string = cid_to_base32(cid_bytes)
    expected_cid = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"
    check("JSON int parsed as int (not float)", cid_string == expected_cid,
          f"got {cid_string}")

def test_number_encoding_float_produces_wrong_cid():
    payload = {"version": 1.0, "type": "test"}
    cbor_bytes = dag_cbor.encode(payload)
    cid_bytes = make_cid_bytes(cbor_bytes)
    cid_string = cid_to_base32(cid_bytes)
    correct_cid = "bafyreihp6omsp6icc6ee63ox2ovsaxm6s7ikd2a7k5eh2qz2qd5soh5bsa"
    # The exact wrong CID depends on float precision (float16/32/64) which varies
    # by CBOR library. The important invariant: float encoding MUST NOT produce
    # the correct (integer) CID.
    check("Float CID differs from correct CID", cid_string != correct_cid,
          f"unexpectedly matched correct CID")

test_number_encoding_determinism()
test_number_encoding_from_json()
test_number_encoding_float_produces_wrong_cid()

# --- 15. Reject corpus (profile + signature gates) ---
# Every conformant verifier MUST reject all of these. Byte-identical inputs
# across all five language suites. Reference key 1 signs the base vector.
print("\n15. Reject Corpus (all MUST be rejected)")

REJECT_PUB1_HEX = "ba421e272fad4f941c221e47f87d9253bdc04f7d4ad2625ae667ab9f0688ce32"
reject_pub = bytes.fromhex(REJECT_PUB1_HEX)

REJECT_VECTORS = {
    "RV-LEN-SHORT": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2",
    "RV-LEN-LONG": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQA",
    "RV-S-NONCANON-PLUSL": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAFq4vaNrS7wPMIBVCWm3qp0JC5obhbU0QOP589IkS2GQ",
    "RV-S-NONCANON-FF": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAD__________________________________________w",
    "RV-ALG-NONE": "eyJhbGciOiJub25lIiwidHlwIjoiZGlkOmRmb3M6cmVqZWN0LXZlY3RvciIsImtpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4In0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
    "RV-ALG-CASE": "eyJhbGciOiJlZGRzYSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
    "RV-CRIT-PRESENT": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNyaXQiOlsiZXhwIl19.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
    "RV-HEADER-KEY-TRUST": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFBQUEifX0.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CQ",
    "RV-SIG-BITFLIP": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOnJlamVjdC12ZWN0b3IiLCJraWQiOiJrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCJ9.eyJ2IjoxfQ.nfzkdNEd-E3btZXK6c-xvLcJoZAm0XEWobzsB7-9lAAY15V9HFGpaB1sDa23oZuU0JC5obhbU0QOP589IkS2CA",
}

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
      number_cid({"n": MAX_SAFE}) == "bafyreieak45zq2337oaadtvk2vwtdqfvfg26hd7olnf275qiv5hrh3vywq",
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
      number_cid({"documentCID": None, "note": None, "prf": []}) ==
      "bafyreign22f4jiww2ywlssx7r2l76z32suj5ufvwl354hsp4xrm26cw7ue",
      "wrong CID")

# --- Summary ---
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed")
print(f"{'=' * 70}")
sys.exit(1 if failed > 0 else 0)
