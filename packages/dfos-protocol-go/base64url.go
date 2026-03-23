package dfos

import (
	"encoding/base64"
	"strings"
)

// Base64urlEncode encodes bytes to base64url without padding.
func Base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64urlEncodeString encodes a string to base64url without padding.
func Base64urlEncodeString(s string) string {
	return Base64urlEncode([]byte(s))
}

// Base64urlDecode decodes base64url (with or without padding).
func Base64urlDecode(s string) ([]byte, error) {
	// handle both padded and unpadded
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}
