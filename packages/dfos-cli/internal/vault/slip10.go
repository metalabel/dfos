package vault

// SLIP-0010 ed25519 derivation, implemented here rather than pulled in, because
// it is forty lines of HMAC-SHA512 and the recovery story depends on this exact
// chain forever. The official SLIP-0010 ed25519 test vectors are asserted in
// slip10_test.go; a change that breaks them is a change that orphans every seed
// ever written down.
//
// ed25519 has no public-key child derivation, so SLIP-0010 defines only hardened
// children for it. This implementation offers nothing else: child() hardens the
// index it is given, so there is no non-hardened path to take by accident.

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// hardenedOffset is the index bit that marks a hardened child (SLIP-0010/BIP-32).
const hardenedOffset uint32 = 0x80000000

// DfosPurpose is the fixed first level of the dfos derivation path: the four
// ASCII bytes of "dfos" read as a big-endian uint32 (0x64666f73 = 1684434803).
// It is arbitrary the way every BIP-43 purpose number is arbitrary; what matters
// is that it never changes, because a recovery scan derives against it.
const DfosPurpose uint32 = 0x64666f73

// ed25519MasterKey is the HMAC key SLIP-0010 fixes for the ed25519 curve.
var ed25519MasterKey = []byte("ed25519 seed")

// node is one level of the derivation tree: 32 bytes of key material plus the
// chain code that seeds its children.
type node struct {
	key       [32]byte
	chainCode [32]byte
}

func splitDigest(sum []byte) node {
	var out node
	copy(out.key[:], sum[:32])
	copy(out.chainCode[:], sum[32:])
	return out
}

func masterNode(seed []byte) node {
	mac := hmac.New(sha512.New, ed25519MasterKey)
	mac.Write(seed)
	return splitDigest(mac.Sum(nil))
}

// child derives the HARDENED child at index. index is passed unhardened (0, 1,
// 2, …) and hardened here; callers guarantee it is below hardenedOffset.
func (n node) child(index uint32) node {
	var data [37]byte
	data[0] = 0x00
	copy(data[1:33], n.key[:])
	binary.BigEndian.PutUint32(data[33:], index|hardenedOffset)
	mac := hmac.New(sha512.New, n.chainCode[:])
	mac.Write(data[:])
	return splitDigest(mac.Sum(nil))
}

// keypair expands the node's 32 bytes into an ed25519 keypair. SLIP-0010 makes
// the derived material the ed25519 SEED, not a scalar, so the expansion is the
// ordinary one and the result is an ordinary ed25519 key.
func (n node) keypair() (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(n.key[:])
	return priv, priv.Public().(ed25519.PublicKey)
}

// DerivationPath renders the path for index in the standard notation. This is
// the string CLI.md documents and `vault show` prints.
func DerivationPath(index uint32) string {
	return fmt.Sprintf("m/%d'/%d'", DfosPurpose, index)
}

// DeriveKey derives the ed25519 keypair at m/1684434803'/index' from a BIP-39
// seed. Indices are dense and ascending from 0, which is what lets a scan
// rederive an identity's keys from the mnemonic alone.
func DeriveKey(seed []byte, index uint32) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if index >= hardenedOffset {
		return nil, nil, fmt.Errorf("derivation index out of range: %d (hardened indices stop at %d)", index, hardenedOffset-1)
	}
	priv, pub := masterNode(seed).child(DfosPurpose).child(index).keypair()
	return priv, pub, nil
}

// Fingerprint is the deterministic short identifier for a seed: the first four
// bytes of SHA-256 over the SLIP-0010 master key, hex-encoded.
//
// It is LOCAL provenance and nothing else. It never enters an operation, a
// signed payload, or a request to a peer. Identities minted from one seed are
// unlinkable on the wire by construction, and a stable per-seed identifier on
// the wire is precisely what would undo that.
func Fingerprint(seed []byte) string {
	master := masterNode(seed)
	sum := sha256.Sum256(master.key[:])
	return hex.EncodeToString(sum[:4])
}
