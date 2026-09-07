package cmd

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// Adoption receipts survive independently of a vault or a cached chain.
type keyAdoption struct {
	DID   string `json:"did"`
	KeyID string `json:"keyId"`
}

func keyAdoptionPath(publicKey string) string {
	return filepath.Join(config.ConfigDir(), "key-adoptions", fmt.Sprintf("%x.json", sha256.Sum256([]byte(publicKey))))
}

func readKeyAdoption(publicKey string) (*keyAdoption, error) {
	data, err := os.ReadFile(keyAdoptionPath(publicKey))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record keyAdoption
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(record.DID, "did:dfos:") || !keyIDShape.MatchString(record.KeyID) {
		return nil, fmt.Errorf("corrupt key adoption record")
	}
	return &record, nil
}

func recordKeyAdoption(publicKey, did, keyID string) error {
	if !strings.HasPrefix(did, "did:dfos:") || !keyIDShape.MatchString(keyID) {
		return fmt.Errorf("invalid key adoption")
	}
	existing, err := readKeyAdoption(publicKey)
	if err != nil {
		return err
	}
	if existing != nil && existing.DID != did {
		return fmt.Errorf("key adoption already names another DID")
	}
	path := keyAdoptionPath(publicKey)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(keyAdoption{DID: did, KeyID: keyID})
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// The caller verifies the chain and binds it to did before promoting any key.
func promoteCandidateKeys(did string, state protocol.IdentityState) error {
	for _, row := range stateKeyRoles(did, state) {
		if row.Void {
			continue
		}
		pub := row.Key.PublicKeyMultibase
		candidate := candidateAccountPrefix + pub
		if !keys.HasKey(candidate) {
			continue
		}
		if err := recordKeyAdoption(pub, did, row.Key.ID); err != nil {
			return fmt.Errorf("record fetched key adoption: %w", err)
		}
		if !keys.HasKey(keyAccount(pub)) {
			if err := keys.RenameKey(candidate, keyAccount(pub)); err != nil {
				return fmt.Errorf("promote fetched candidate: %w", err)
			}
		}
	}
	return nil
}
