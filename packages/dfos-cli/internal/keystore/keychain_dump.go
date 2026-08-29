package keystore

// Parsing `security dump-keychain` output.
//
// The macOS keychain backend this CLI links (zalando/go-keyring) drives
// /usr/bin/security for every operation and offers no listing at all, so
// enumerating what is stored under the "dfos" service means reading the same
// tool's dump. The parser lives here, apart from the exec, because it is the
// part worth testing everywhere rather than only on a Mac.
//
// The dump is attributes only — no secret is printed and none is asked for, so
// nothing here unlocks anything or prompts. Items are separated by their
// `class:` header; each one's account and service are collected inside its own
// block and emitted together, so a mis-read cannot pair one item's account with
// another's service.

import (
	"bufio"
	"io"
	"strings"
)

// parseKeychainDump returns the accounts of every generic-password item whose
// service attribute equals service, in the order they appear.
//
// It is deliberately forgiving: an attribute spelling it does not recognize is
// skipped rather than treated as a parse failure, because the cost of a missed
// item is an entry the ledger does not list, and the cost of a hard failure is
// no ledger at all.
func parseKeychainDump(r io.Reader, service string) []string {
	var accounts []string
	account, svce := "", ""
	flush := func() {
		if svce == service && account != "" && !IsReservedAccount(account) {
			accounts = append(accounts, account)
		}
		account, svce = "", ""
	}

	scanner := bufio.NewScanner(r)
	// Attribute values can be long (a chain, a blob); the default 64KiB token
	// limit is generous for an account name but not for every line in a dump.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// A new item starts at its class header; the keychain header starts a new
		// file. Either way the previous item is complete.
		if strings.HasPrefix(line, "class:") || strings.HasPrefix(line, "keychain:") {
			flush()
			continue
		}
		if v, ok := attributeValue(line, "acct"); ok {
			account = v
			continue
		}
		if v, ok := attributeValue(line, "svce"); ok {
			svce = v
		}
	}
	flush()
	return accounts
}

// attributeValue reads one `"acct"<blob>="value"` line. `security` prints a
// value as a quoted string when it is printable, as `0x…` hex when it is not
// (sometimes followed by the quoted form), and as `<NULL>` when it is unset —
// only the quoted form names an account this store could ever address, so the
// other spellings report "no value" rather than a guess.
func attributeValue(line, name string) (string, bool) {
	prefix := `"` + name + `"`
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", false
	}
	rest := strings.TrimSpace(line[eq+1:])
	quote := strings.Index(rest, `"`)
	if quote < 0 {
		return "", false
	}
	rest = rest[quote+1:]
	end := strings.LastIndex(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}
