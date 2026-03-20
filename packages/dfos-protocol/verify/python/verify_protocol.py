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
ID_LENGTH = 22

GENESIS_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiYXV0aEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImFzc2VydEtleXMiOlt7ImlkIjoia2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJ0eXBlIjoiTXVsdGlrZXkiLCJwdWJsaWNLZXlNdWx0aWJhc2UiOiJ6Nk1rcnpMTU53b0pTVjRQM1ljY1djYnRrOHZkOUx0Z01LbkxlYURMVXFMdUFTamIifV0sImNvbnRyb2xsZXJLZXlzIjpbeyJpZCI6ImtleV9yOWV2MzRmdmMyM3o5OTl2ZWFhZnQ4IiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa3J6TE1Od29KU1Y0UDNZY2NXY2J0azh2ZDlMdGdNS25MZWFETFVxTHVBU2piIn1dLCJjcmVhdGVkQXQiOiIyMDI2LTAzLTA3VDAwOjAwOjAwLjAwMFoifQ.EDryDK1uvtix-17cHun9t6MacFIx2rMmMF1QLzfD5TFlSsOvMcue97pCgGn3CXeLVFtVxgpCoh0kGSXioKKzAw"

ROTATION_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmlkZW50aXR5LW9wIiwia2lkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiNrZXlfcjlldjM0ZnZjMjN6OTk5dmVhYWZ0OCIsImNpZCI6ImJhZnlyZWljeW00Y3lpZWRubGQ3M3NtYngzMnN6YWVpN3hkdWxxbjRnM3N0ZTVlMncydWxhanIzb3FtIn0.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoidXBkYXRlIiwicHJldmlvdXNPcGVyYXRpb25DSUQiOiJiYWZ5cmVpYmFuanBnY3FmZmNmaHI0c3B0empmdGhoNXN6b2hoYm81dGpmdWxlbWt3N3VoZGVuNXVxeSIsImF1dGhLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJhc3NlcnRLZXlzIjpbeyJpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwidHlwZSI6Ik11bHRpa2V5IiwicHVibGljS2V5TXVsdGliYXNlIjoiejZNa2ZVZDY1SnJBaGZkZ0Z1TUNjY1U5VGhRdmpCMmZKQU1VSGt1dWFqRjk5MmdLIn1dLCJjb250cm9sbGVyS2V5cyI6W3siaWQiOiJrZXlfZXo5YTg3NHRja3IzZHY5MzNkM2NrZCIsInR5cGUiOiJNdWx0aWtleSIsInB1YmxpY0tleU11bHRpYmFzZSI6Ino2TWtmVWQ2NUpyQWhmZGdGdU1DY2NVOVRoUXZqQjJmSkFNVUhrdXVhakY5OTJnSyJ9XSwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowMTowMC4wMDBaIn0.MScuoBlgOK3j5QX9tFcw1ou0o4LgJziGJEsZ5pvqiBr1SagAyAv5h-wajQhtg8IP7dLlM0U4leW2iRra945cDg"

CONTENT_CREATE_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmNvbnRlbnQtb3AiLCJraWQiOiJkaWQ6ZGZvczplM3Z2dGNrNDJkNGVhY2RuenZ0cm42I2tleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIiwiY2lkIjoiYmFmeXJlaWFlZGhqcTY0YWFqcHdvY2lhaGw1dzM3ajZ1b3hyNW1vam9xNWRuYWg2ZnB2eHI1ZDRseHUifQ.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiY3JlYXRlIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImRvY3VtZW50Q0lEIjoiYmFmeXJlaWh6d3VvdXBmZzNkeGlwNnhtZ3pteHN5d3lpaTJqZW94eHpiZ3gzenhtMmluN2tub2kzZzQiLCJiYXNlRG9jdW1lbnRDSUQiOm51bGwsImNyZWF0ZWRBdCI6IjIwMjYtMDMtMDdUMDA6MDI6MDAuMDAwWiIsIm5vdGUiOm51bGx9.Rv6vlz5MfrwqDUrSVIGs4ZfeBbkQUSBcXhxwZ6hfudSr5MxhYl08hTqLDOA0W1NMjN0Hs0IW9jXTwLwP1dMDBg"

JWT_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6ImtleV9lejlhODc0dGNrcjNkdjkzM2QzY2tkIn0.eyJpc3MiOiJkZm9zIiwic3ViIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsImF1ZCI6ImRmb3MtYXBpIiwiZXhwIjoxNzcyOTAyODAwLCJpYXQiOjE3NzI4OTkyMDAsImp0aSI6InNlc3Npb25fcmVmX2V4YW1wbGVfMDEifQ.zhKeXJHHF7a1-MwF4QoUTRptCplAwh20-rLnuWGDFT6uJheN4E_SA5NhqvMNflLHxd7h97gdaVnMZGE67SXEBA"

EXPECTED_GENESIS_CID = "bafyreibanjpgcqffcfhr4sptzjfthh5szohhbo5tjfulemkw7uhden5uqy"
EXPECTED_DID = "did:dfos:e3vvtck42d4eacdnzvtrn6"
EXPECTED_MULTIKEY1 = "z6MkrzLMNwoJSV4P3YccWcbtk8vd9LtgMKnLeaDLUqLuASjb"
EXPECTED_CBOR_HEX = "a66474797065666372656174656776657273696f6e0168617574684b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62696372656174656441747818323032362d30332d30375430303a30303a30302e3030305a6a6173736572744b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a626e636f6e74726f6c6c65724b65797381a3626964781a6b65795f72396576333466766332337a393939766561616674386474797065684d756c74696b6579727075626c69634b65794d756c74696261736578307a364d6b727a4c4d4e776f4a5356345033596363576362746b387664394c74674d4b6e4c6561444c55714c7541536a62"
EXPECTED_CID_HEX = "01711220206a5e6140a5114f1e49f3ca4b339fb2cb8e70bbb34968b23156fd0e3237b486"

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

def verify_jws(token: str, pub_key_bytes: bytes) -> dict:
    parts = token.split(".")
    assert len(parts) == 3
    header_b64, payload_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = b64url_decode(sig_b64)
    verify_key = nacl.signing.VerifyKey(pub_key_bytes)
    # nacl verify expects signature + message concatenated
    verify_key.verify(signing_input, signature)
    header = json.loads(b64url_decode(header_b64))
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
    "authKeys": [{"id": "key_r9ev34fvc23z999veaaft8", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
    "assertKeys": [{"id": "key_r9ev34fvc23z999veaaft8", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
    "controllerKeys": [{"id": "key_r9ev34fvc23z999veaaft8", "type": "Multikey", "publicKeyMultibase": EXPECTED_MULTIKEY1}],
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
check("DID hash", did_hash.hex() == "4360cfbcbbb3f1614c8e02dbfe8d55935e1195cd2129820ab8aef94bde12ea8a")
did_suffix = encode_id(did_hash)
check("DID suffix", did_suffix == "e3vvtck42d4eacdnzvtrn6", f"got {did_suffix}")
full_did = f"did:dfos:{did_suffix}"
check("Full DID", full_did == EXPECTED_DID)

# --- 6. JWS verification: genesis ---
print("\n6. JWS Verification: Genesis (key 1)")
result = verify_jws(GENESIS_JWS, pub1)
check("Genesis signature valid", True)
check("Genesis header alg", result["header"]["alg"] == "EdDSA")
check("Genesis header typ", result["header"]["typ"] == "did:dfos:identity-op")
check("Genesis header kid", result["header"]["kid"] == "key_r9ev34fvc23z999veaaft8")
check("Genesis header cid", result["header"]["cid"] == EXPECTED_GENESIS_CID)
check("Genesis payload type", result["payload"]["type"] == "create")
check("Genesis payload version", result["payload"]["version"] == 1)

# --- 7. JWS verification: rotation (signed by key 1) ---
print("\n7. JWS Verification: Rotation (key 1 signs rotation to key 2)")
result = verify_jws(ROTATION_JWS, pub1)
check("Rotation signature valid", True)
check("Rotation kid is DID URL", result["header"]["kid"] == f"{EXPECTED_DID}#key_r9ev34fvc23z999veaaft8")
check("Rotation header cid", result["header"]["cid"] == "bafyreicym4cyiednld73smbx32szaei7xdulqn4g3ste5e2w2ulajr3oqm")
check("Rotation payload type", result["payload"]["type"] == "update")
check("Rotation previousOperationCID", result["payload"]["previousOperationCID"] == EXPECTED_GENESIS_CID)

# --- 8. JWS verification: content create (signed by key 2) ---
print("\n8. JWS Verification: Content Create (key 2)")
result = verify_jws(CONTENT_CREATE_JWS, pub2)
check("Content create signature valid", True)
check("Content create typ", result["header"]["typ"] == "did:dfos:content-op")
check("Content create kid", result["header"]["kid"] == f"{EXPECTED_DID}#key_ez9a874tckr3dv933d3ckd")
check("Content create header cid", result["header"]["cid"] == "bafyreiaedhjq64aajpwociahl5w37j6uoxr5mojoq5dnah6fpvxr5d4lxu")
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
    "createdByDID": EXPECTED_DID,
}
doc_cbor = dag_cbor.encode(document)
doc_cid_bytes = make_cid_bytes(doc_cbor)
doc_cid = cid_to_base32(doc_cid_bytes)
check("Document CID", doc_cid == "bafyreihzwuoupfg3dxip6xmgzmxsywyii2jeoxxzbgx3zxm2in7knoi3g4", f"got {doc_cid}")

# --- 11. Merkle tree ---
print("\n11. Merkle Tree")
merkle_ids = ["alpha", "bravo", "charlie", "delta", "echo"]
merkle_sorted = sorted(merkle_ids)

# leaf hashes
leaf_hashes = {}
for cid in merkle_sorted:
    leaf_hashes[cid] = hashlib.sha256(cid.encode("utf-8")).digest()

check("Leaf alpha", leaf_hashes["alpha"].hex() == "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8")
check("Leaf echo", leaf_hashes["echo"].hex() == "092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d")

# build tree bottom-up
level = [leaf_hashes[cid] for cid in merkle_sorted]
while len(level) > 1:
    next_level = []
    i = 0
    while i < len(level):
        if i + 1 < len(level):
            next_level.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        else:
            next_level.append(level[i])  # odd node promoted
        i += 2
    level = next_level

merkle_root = level[0].hex()
EXPECTED_MERKLE_ROOT = "7e80d4780f454e0fca0b090d8c646f572b49354f54154531606105aad2fda28e"
check("Merkle root", merkle_root == EXPECTED_MERKLE_ROOT, f"got {merkle_root}")

# verify inclusion proof for "charlie"
proof_path = [
    {"hash": "4f4a9410ffcdf895c4adb880659e9b5c0dd1f23a30790684340b3eaacb045398", "position": "right"},
    {"hash": "90d39555bb3c223e12f5a375c3011d2462fe2e1e36b8416a0b623d5831a9b4f3", "position": "left"},
    {"hash": "092c79e8f80e559e404bcf660c48f3522b67aba9ff1484b0367e1a4ddef7431d", "position": "right"},
]
current = hashlib.sha256(b"charlie").digest()
for step in proof_path:
    sibling = bytes.fromhex(step["hash"])
    if step["position"] == "left":
        current = hashlib.sha256(sibling + current).digest()
    else:
        current = hashlib.sha256(current + sibling).digest()
check("Merkle proof charlie", current.hex() == EXPECTED_MERKLE_ROOT, f"got {current.hex()}")

# --- 12. Beacon JWS verification ---
print("\n12. Beacon JWS Verification (key 1)")
BEACON_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X3I5ZXYzNGZ2YzIzejk5OXZlYWFmdDgiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0._1RgZpMv63-M3ZUeTNX679xkAeX3TY0PJ0ImH7422cKA7I88Hf8bBVQMVVhP3oNdvX7i7Q4se5EP3kk5aEuxDQ"
EXPECTED_BEACON_CID = "bafyreihholuui7s7ns74iem6ahfxsb472hwogbqd32yrrp5fztc3kxa5qu"

result = verify_jws(BEACON_JWS, pub1)
check("Beacon signature valid", True)
check("Beacon header typ", result["header"]["typ"] == "did:dfos:beacon")
check("Beacon header kid", result["header"]["kid"] == f"{EXPECTED_DID}#key_r9ev34fvc23z999veaaft8")
check("Beacon header cid", result["header"]["cid"] == EXPECTED_BEACON_CID)
check("Beacon payload type", result["payload"]["type"] == "beacon")
check("Beacon payload merkleRoot", result["payload"]["merkleRoot"] == EXPECTED_MERKLE_ROOT)

# --- 13. Beacon countersignature verification ---
print("\n13. Beacon Countersignature Verification (key 2 witnesses key 1's beacon)")
BEACON_WITNESS_JWS = "eyJhbGciOiJFZERTQSIsInR5cCI6ImRpZDpkZm9zOmJlYWNvbiIsImtpZCI6ImRpZDpkZm9zOmUzdnZ0Y2s0MmQ0ZWFjZG56dnRybjYja2V5X2V6OWE4NzR0Y2tyM2R2OTMzZDNja2QiLCJjaWQiOiJiYWZ5cmVpaGhvbHV1aTdzN25zNzRpZW02YWhmeHNiNDcyaHdvZ2JxZDMyeXJycDVmenRjM2t4YTVxdSJ9.eyJ2ZXJzaW9uIjoxLCJ0eXBlIjoiYmVhY29uIiwiZGlkIjoiZGlkOmRmb3M6ZTN2dnRjazQyZDRlYWNkbnp2dHJuNiIsIm1lcmtsZVJvb3QiOiI3ZTgwZDQ3ODBmNDU0ZTBmY2EwYjA5MGQ4YzY0NmY1NzJiNDkzNTRmNTQxNTQ1MzE2MDYxMDVhYWQyZmRhMjhlIiwiY3JlYXRlZEF0IjoiMjAyNi0wMy0wN1QwMDowNTowMC4wMDBaIn0.awA8ctmLHjJCHZcH0lav7HpadkIoGiG2WR-pCf-0XfPVi9dD8Z2at0E7iAnOUnVEc5VthBo-mMklSIJFK28IDw"

result = verify_jws(BEACON_WITNESS_JWS, pub2)
check("Beacon countersig valid", True)
check("Beacon countersig typ", result["header"]["typ"] == "did:dfos:beacon")
check("Beacon countersig kid", result["header"]["kid"] == f"{EXPECTED_DID}#key_ez9a874tckr3dv933d3ckd")
check("Beacon countersig same CID", result["header"]["cid"] == EXPECTED_BEACON_CID)
check("Beacon countersig same payload", result["payload"]["merkleRoot"] == EXPECTED_MERKLE_ROOT)

# --- Summary ---
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed")
print(f"{'=' * 70}")
sys.exit(1 if failed > 0 else 0)
