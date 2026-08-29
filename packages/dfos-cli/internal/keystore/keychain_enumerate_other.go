//go:build !darwin

package keystore

// Entries reports that this platform's keychain cannot be listed.
//
// The backends go-keyring uses off macOS — the freedesktop secret-service over
// D-Bus, the Windows credential manager — expose get/set/delete and no search,
// so there is no honest way to ask them what they hold. Saying so is the point:
// a caller can then name the accounts it already knows about and report the
// limit, instead of presenting a derived list as if it were the whole store.
func (k *KeychainStore) Entries() ([]Entry, error) {
	return nil, ErrNoEnumeration
}
