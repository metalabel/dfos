package cmd

// `dfos recover` — the disaster path. The machine is gone; what survives is a
// vault's 24-word phrase. This command rebuilds what that phrase controls.
//
// It is a two-stage walk, and the second stage is the whole difficulty:
//
//	Stage 1 — DERIVE. Rederive keypairs from the seed at m/1684434803'/i' for
//	  i = 0, 1, 2, … . This is pure local arithmetic and it can go on forever, so
//	  something has to say when to stop.
//	Stage 2 — ASK. For each derived PUBLIC key, ask a relay's identity index
//	  which identities have ever declared it. That answer is what makes an index
//	  "used" or "unused", and a run of unused indices is what stops the scan.
//
// The predicate "index i is unused" is NOT locally decidable. A key exists the
// moment it is derived; what makes it MEAN anything is an identity operation
// that declared it, and that lives on a chain, in an index, somewhere else. So
// this command is built around one rule, which every branch below serves:
//
//	NEVER conclude "no more keys" from silence.
//
// A relay that does not serve the index (501), a relay that cannot be reached, a
// relay that answers something unreadable, and — worst of all — a relay
// predating the `key=` filter, which IGNORES the unknown parameter and answers
// with an unfiltered page that would make every derived key look used: each of
// these is a loud failure naming the relay and what went wrong. None of them is
// an empty result. The operator can then point at a different relay, or ask
// explicitly for the degraded manifest-only recovery with --manifest-only, which
// announces in a banner that the scan did not run.
//
// The oracle is always NAMED in the output. "Used" and "unused" here are one
// relay's answers, and one relay's index-absence is not global absence.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/client"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/localrelay"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// defaultScanDepth is N: the number of CONSECUTIVE unused indices that ends a
// scan. It is a gap limit, not a ceiling — a hole shorter than N does not stop
// the walk, which is what makes it safe against the gaps the burn-on-failure
// counter leaves behind. 20 is the BIP-44 convention and is generous against a
// mint-side counter that allocates sequentially and never reuses.
const defaultScanDepth = 20

// maxScanIndices bounds the walk against a relay that answers "used" to
// everything. The sentinel probe below is the real defense; this is the backstop
// that keeps a pathological answer from turning into an unbounded loop, and it
// fails loudly rather than truncating silently.
const maxScanIndices = 10000

// indexKeyProbeSeed is hashed into the sentinel public key. The string is
// arbitrary; what matters is that it is fixed and published, so the 32 bytes are
// demonstrably a hash rather than a generated public key.
const indexKeyProbeSeed = "dfos-cli:index-key-filter-probe:v1"

// indexKeyProbeMultibase is a syntactically REAL multikey that no chain can have
// declared: `z` + base58btc of the ed25519 multicodec prefix over
// SHA-256(indexKeyProbeSeed). A relay sees a well-formed key rather than
// something it might one day reject, and nobody holds the private key because
// there is none — the bytes are a published hash.
//
// It exists for one query, made once per run before the scan: ask for a key
// nothing ever declared and see whether rows come back. Rows mean the relay
// ignored `key=` entirely, which is the failure mode with no status code to
// catch (WEB-RELAY.md specifies `key=` as an opaque match with no format
// validation, so there is no invalid value to provoke a 400 with).
func indexKeyProbeMultibase() string {
	sum := sha256.Sum256([]byte(indexKeyProbeSeed))
	return protocol.EncodeMultikey(ed25519.PublicKey(sum[:]))
}

// --- result shapes ---

// recoveredKey is one derived index that something declared, and what became of
// the private key it produced.
type recoveredKey struct {
	Index     uint32   `json:"index"`
	Path      string   `json:"derivationPath"`
	PublicKey string   `json:"publicKey"`
	DID       string   `json:"did"`
	KeyID     string   `json:"keyId,omitempty"`
	Account   string   `json:"account,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	// Outcome is what this run did with the key: "recovered" (written into the
	// keystore), "already-present" (the keystore already held it), or
	// "not-installed" (the chain that would name it could not be read, so there
	// is no account to store it under).
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// Superseded records that the chain no longer names this key in any current
	// role. It is still real and still recovered: the index answers
	// has-ever-declared precisely so a rotated-out key is findable.
	Superseded bool `json:"superseded,omitempty"`
	// BeyondScan marks a key the derivation scan never reached. The oracle was
	// never asked about this index; a chain this run FETCHED named the public
	// key, and deriving forward from the seed proved which index of this vault
	// produced it. Its presence is proof --scan-depth was too small.
	BeyondScan bool `json:"beyondScan,omitempty"`
}

// recoveredIdentity is one identity the scan found, and its end state locally.
type recoveredIdentity struct {
	DID     string `json:"did"`
	Name    string `json:"name,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
	// Status: "recovered" (the chain was pulled and at least one key installed),
	// "already-present" (chain and keys were already here), or
	// "found-but-not-fetched" (the index named it and the chain could not be
	// read — the identity is real, and this machine still cannot act as it).
	Status     string   `json:"status"`
	Operations int      `json:"operations,omitempty"`
	Keys       []string `json:"keys,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	// FromManifest marks an identity this machine's own vault records named,
	// independently of what the oracle said.
	FromManifest bool `json:"fromManifest,omitempty"`
}

// recoverResult is the whole run: what was asked, who answered, what was found,
// and what was written.
type recoverResult struct {
	Vault            string `json:"vault"`
	VaultSource      string `json:"vaultSource"`
	Fingerprint      string `json:"fingerprint"`
	DerivationPath   string `json:"derivationPathTemplate"`
	Oracle           string `json:"oracle,omitempty"`
	OracleURL        string `json:"oracleURL,omitempty"`
	OracleSource     string `json:"oracleSource,omitempty"`
	ScanDepth        int    `json:"scanDepth"`
	IndicesScanned   int    `json:"indicesScanned"`
	HighestUsedIndex int64  `json:"highestUsedIndex"`
	// Scanned is false when the derivation scan did not run at all — the
	// manifest-only degradation. Nothing in this document then says anything
	// about indices this machine has no record of.
	Scanned bool `json:"scanned"`
	// BeyondScanIndices are the derivation indices a FETCHED CHAIN proved this
	// vault declared, at or past the index the scan stopped on. Non-empty means
	// the gap limit ended the walk short of what the seed actually minted: these
	// keys were installed and the counter cleared them, and the same shortfall
	// can hide an identity whose every key sits past the gap.
	BeyondScanIndices []uint32 `json:"beyondScanIndices,omitempty"`
	// ScanComplete is the machine form of that finding: true only when a scan ran,
	// every identity it found was read, and nothing in those chains proved the
	// walk stopped short. A caller deciding whether this vault is safe to mint
	// from reads this field, not the prose.
	//
	// False with a non-empty BeyondScanIndices is the proven shortfall. False
	// with an empty one is the unproven kind — a chain this run could not read,
	// so what it declares was never checked against a derivation at all.
	ScanComplete bool `json:"scanComplete"`
	// RecommendedScanDepth is the --scan-depth that would have walked far enough
	// to reach the highest beyond-scan index. Zero when the scan was complete.
	RecommendedScanDepth int `json:"recommendedScanDepth,omitempty"`

	ManifestOnly  bool                `json:"manifestOnly,omitempty"`
	DryRun        bool                `json:"dryRun,omitempty"`
	Keys          []recoveredKey      `json:"keys"`
	Identities    []recoveredIdentity `json:"identities"`
	MintedAdded   int                 `json:"mintedRecordsAdded"`
	CounterBefore uint32              `json:"counterBefore"`
	CounterAfter  uint32              `json:"counterAfter"`
	Backend       string              `json:"keystoreBackend"`
}

// --- the command ---

func newRecoverCmd() *cobra.Command {
	var vaultName string
	var peerName string
	var scanDepth int
	var dryRun bool
	var manifestOnly bool

	cmd := &cobra.Command{
		Use:     "recover",
		Short:   "Rebuild the identities and keys a vault's recovery phrase controls",
		GroupID: "identity",
		Long: "Rederive a vault's keys from its seed and ask a relay's identity index which of them any " +
			"identity has ever declared, then pull those identities' chains into the local relay and put " +
			"the matching private keys back in the keystore.\n\n" +
			"The scan walks m/1684434803'/<index>' from 0 and stops after --scan-depth consecutive " +
			"UNUSED indices. Used and unused are one relay's answers, and that relay is named in the " +
			"output: a relay that does not serve the index, cannot be reached, or predates the key lookup " +
			"is a loud failure, never an empty result.\n\n" +
			"After a machine is lost the whole path is: 'dfos vault import <name>' to adopt the phrase, " +
			"then 'dfos recover --vault <name>'. It writes by default and is idempotent — re-running " +
			"converges. --dry-run scans and reports without writing anything.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanDepth < 1 {
				return fmt.Errorf("--scan-depth must be at least 1, got %d", scanDepth)
			}
			return runRecover(recoverOptions{
				vaultFlag:    vaultName,
				peerFlag:     peerName,
				scanDepth:    scanDepth,
				dryRun:       dryRun,
				manifestOnly: manifestOnly,
			})
		},
	}
	cmd.Flags().StringVar(&vaultName, "vault", "", "Vault whose phrase is being recovered from (default: config default-vault)")
	cmd.Flags().StringVar(&peerName, "peer", "", "Relay to ask the used/unused question — the oracle (default: the resolved peer)")
	cmd.Flags().IntVar(&scanDepth, "scan-depth", defaultScanDepth, "Stop after this many consecutive unused indices")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Scan and report, writing nothing: no keys, no config, no chain pulls")
	cmd.Flags().BoolVar(&manifestOnly, "manifest-only", false, "Skip the scan entirely and recover only what this vault's own minted-key records name")
	return cmd
}

type recoverOptions struct {
	vaultFlag    string
	peerFlag     string
	scanDepth    int
	dryRun       bool
	manifestOnly bool
}

func runRecover(opts recoverOptions) error {
	name, source, err := resolveVault(opts.vaultFlag, false)
	if err != nil {
		return err
	}
	if name == "" {
		return errNoVaultToRecover()
	}
	meta, err := getVaults().Load(name)
	if err != nil {
		return err
	}

	// The seed is read once and used by both walks: the oracle scan, and the
	// local probe that explains chain keys the scan never reached.
	mnemonic, err := getVaults().Mnemonic(name)
	if err != nil {
		return fmt.Errorf("read vault '%s': %w", name, err)
	}
	seed, err := vault.MnemonicSeed(mnemonic)
	if err != nil {
		return err
	}

	result := &recoverResult{
		Vault:            name,
		VaultSource:      source,
		Fingerprint:      meta.Fingerprint,
		DerivationPath:   vault.DerivationPath(0),
		ScanDepth:        opts.scanDepth,
		HighestUsedIndex: -1,
		ManifestOnly:     opts.manifestOnly,
		DryRun:           opts.dryRun,
		CounterBefore:    meta.NextIndex,
		CounterAfter:     meta.NextIndex,
		Backend:          keys.Backend(),
		Keys:             []recoveredKey{},
		Identities:       []recoveredIdentity{},
	}

	// The oracle. Resolved and PROVEN before a single index is derived: a scan
	// that starts against a relay it has not verified can answer the question is
	// a scan whose result means nothing.
	var oracle *client.Client
	if !opts.manifestOnly {
		ctx, c, err := requirePeer(opts.peerFlag)
		if err != nil {
			return err
		}
		result.Oracle, result.OracleURL, result.OracleSource = ctx.RelayName, ctx.RelayURL, ctx.RelaySource
		if err := proveOracle(c, result.Oracle, result.OracleURL); err != nil {
			return err
		}
		oracle = c
	}

	// Stage 1 + 2. Every hit carries the private key so the write phase can
	// install it once the chain has named the account it belongs under.
	hits, scanned, err := scanVault(seed, meta, oracle, opts)
	if err != nil {
		return err
	}
	result.IndicesScanned = scanned
	result.Scanned = !opts.manifestOnly
	result.ScanComplete = result.Scanned
	for _, h := range hits {
		if int64(h.index) > result.HighestUsedIndex {
			result.HighestUsedIndex = int64(h.index)
		}
	}

	if err := restoreFromHits(result, hits, seed, oracle, meta, name, opts); err != nil {
		return err
	}

	if jsonFlag {
		outputJSON(result)
		return nil
	}
	printRecoverResult(result, opts)
	return nil
}

// errNoVaultToRecover is the no-vault refusal, worded for the one moment an
// operator reaches this command: they hold a phrase and a bare machine.
func errNoVaultToRecover() error {
	return fmt.Errorf("no vault to recover from — name one:\n" +
		"  --vault <name>                       for this invocation\n" +
		"  dfos config set default-vault <name> as the standing default\n" +
		"Holding a recovery phrase and nothing else? Adopt it first:\n" +
		"  dfos vault import <name>             reads the phrase from stdin, then 'dfos recover --vault <name>'")
}

// --- the oracle ---

// proveOracle establishes, before any scan, that this relay can actually answer
// "has any identity ever declared this key". Three ways it cannot, all loud:
//
//	501            — it does not serve the index family at all.
//	any other error — it is unreachable, or answered something unreadable.
//	rows returned   — it IGNORED `key=` and answered with an unfiltered page.
//
// The third is the dangerous one and the reason this probe exists. A relay
// predating the `key=` filter returns 200 with a page of identities that have
// nothing to do with the key asked about. Every index would then look used,
// every identity on that relay would be reported as one this phrase controls,
// and a scan would never stop. There is no status code to catch it by, so the
// probe reads the BODY: query a sentinel key no chain can have declared, and
// treat rows coming back as proof the filter was not applied.
//
// A served empty page means the filter WAS applied — including on a relay that
// simply holds no identities, where the answer is empty either way and the
// eventual report states a true absence rather than inventing rows.
func proveOracle(c *client.Client, name, url string) error {
	rows, err := c.IdentitiesByKey(indexKeyProbeMultibase(), 1)
	if errors.Is(err, client.ErrIndexUnavailable) {
		return oracleFailure(oracleReasonNoIndex, name, url,
			"it answered 501 Not Implemented — capabilities.index is off, or this relay predates the index family",
			"GET /index/v0/identities?key=")
	}
	if err != nil {
		return oracleFailure(oracleReasonUnreachable, name, url, err.Error(), "GET /index/v0/identities?key=")
	}
	if len(rows) > 0 {
		return oracleFailure(oracleReasonParamIgnored, name, url,
			"it answered an UNFILTERED page to a key no chain can have declared, which means it ignored the 'key=' parameter entirely — this relay predates the key lookup (needs web-relay >= 0.39.0)",
			"the 'key=' filter on GET /index/v0/identities")
	}
	return nil
}

// The three ways an oracle cannot answer, as codes a script can branch on. The
// prose beside them says the same thing at length and is free to be reworded;
// these are not. They are distinct because the operator's next move differs for
// each: turn the index on, fix the network, or upgrade the relay.
const (
	// oracleReasonNoIndex: a clean 501. The relay serves no identity index.
	oracleReasonNoIndex = "oracle-no-index"
	// oracleReasonUnreachable: no readable answer at all — a partition, a
	// timeout, a body that did not parse.
	oracleReasonUnreachable = "oracle-unreachable"
	// oracleReasonParamIgnored: 200 with an unfiltered page. The relay predates
	// `key=` and answers as though the filter were not there — the failure with
	// no status code, and the one that would otherwise make every index look used.
	oracleReasonParamIgnored = "oracle-key-param-ignored"
)

// oracleFailure is the one shape every "the oracle cannot answer" error takes.
// It names the relay, names the capability, and says out loud that the failure
// is not an absence of keys — because the whole hazard of this command is a
// silence being read as an answer.
// The reason code rides along so --json distinguishes the three causes without
// parsing the sentence: a caller that must tell "this relay has no index" from
// "the network is down" cannot do it on free text.
func oracleFailure(reason, name, url, why, missing string) error {
	label := url
	if name != "" {
		label = fmt.Sprintf("%s (%s)", name, url)
	}
	return &CodedError{
		Reason: reason,
		Fields: map[string]string{"oracle": name, "oracleURL": url},
		Err: fmt.Errorf("the oracle cannot answer the used/unused question, so no scan was run.\n"+
			"  Oracle:  %s\n"+
			"  Needs:   %s\n"+
			"  Got:     %s\n"+
			"This is NOT 'no keys found'. Nothing here says anything about what this phrase controls.\n"+
			"Point --peer at a relay that serves the identity index, or re-run with --manifest-only to\n"+
			"recover only what this machine's own vault records already name.", label, missing, why),
	}
}

// --- the scan ---

// scanHit is one derivation index something declared, with the key material
// that index produced.
type scanHit struct {
	index     uint32
	publicKey string
	private   ed25519.PrivateKey
	// rows is the oracle's answer. Empty on a manifest-only hit.
	rows []client.IndexIdentityRow
	// minted are this vault's own records at this index — what the manifest
	// already knew, which is primary and needs no oracle to be true.
	minted []vault.MintedKey
	// chainDIDs are the DIDs a FETCHED CHAIN declared this public key under, as
	// opposed to the index rows above. Only the beyond-scan probe sets it: those
	// hits exist because a chain named the key, never because the oracle did.
	chainDIDs []string
	// beyondScan marks a hit the derivation walk never reached.
	beyondScan bool
}

// scanVault runs the walk and returns every used index. In manifest-only mode it
// does not walk at all: it folds the vault's own records, which is a different
// and much smaller claim, and the caller banners it as such.
func scanVault(seed []byte, meta *vault.Metadata, oracle *client.Client, opts recoverOptions) ([]scanHit, int, error) {
	// This machine's own record of what the seed minted, keyed by index. The
	// manifest is the PRIMARY record: a key it names is used whatever any relay
	// says, and a hole it fills does not end the scan.
	mintedAt := map[uint32][]vault.MintedKey{}
	for _, r := range meta.Minted {
		mintedAt[r.Index] = append(mintedAt[r.Index], r)
	}

	if opts.manifestOnly {
		indices := make([]uint32, 0, len(mintedAt))
		for i := range mintedAt {
			indices = append(indices, i)
		}
		sort.Slice(indices, func(a, b int) bool { return indices[a] < indices[b] })
		hits := make([]scanHit, 0, len(indices))
		for _, i := range indices {
			priv, pub, err := vault.DeriveKey(seed, i)
			if err != nil {
				return nil, 0, err
			}
			hits = append(hits, scanHit{index: i, publicKey: protocol.EncodeMultikey(pub), private: priv, minted: mintedAt[i]})
		}
		return hits, 0, nil
	}

	var hits []scanHit
	gap := 0
	scanned := 0
	for i := uint32(0); gap < opts.scanDepth; i++ {
		if scanned >= maxScanIndices {
			return nil, scanned, fmt.Errorf("scanned %d indices without %d consecutive unused ones — stopping rather than walking forever.\n"+
				"A relay answering 'used' to every key would look exactly like this; check the oracle before trusting a partial result", scanned, opts.scanDepth)
		}
		priv, pub, err := vault.DeriveKey(seed, i)
		if err != nil {
			return nil, scanned, err
		}
		scanned++
		mb := protocol.EncodeMultikey(pub)

		rows, err := oracle.IdentitiesByKey(mb, 100)
		if err != nil {
			// A partition mid-scan is the same class of failure as a partition
			// before it: the remaining indices are UNKNOWN, not unused. Fail on
			// the spot rather than return a prefix that reads like a whole answer.
			return nil, scanned, fmt.Errorf("the oracle stopped answering at index %d (%s), so the scan is incomplete: %w\n"+
				"Indices past %d are UNKNOWN, not unused. Re-run when the relay is reachable", i, vault.DerivationPath(i), err, i)
		}

		minted := mintedAt[i]
		if len(rows) == 0 && len(minted) == 0 {
			gap++
			continue
		}
		gap = 0
		hits = append(hits, scanHit{index: i, publicKey: mb, private: priv, rows: rows, minted: minted})
	}
	return hits, scanned, nil
}

// --- the restore ---

// restoreFromHits turns the scan's findings into local state: chains in the
// local relay, private keys in the keystore, provenance in the vault, names in
// config. Under --dry-run it computes and reports the same thing and writes
// none of it.
func restoreFromHits(result *recoverResult, hits []scanHit, seed []byte, oracle *client.Client, meta *vault.Metadata, vaultName string, opts recoverOptions) error {
	lr, err := getRelay()
	if err != nil {
		return err
	}

	// Which identities to look at, in a stable order, with the evidence for each.
	type identityWork struct {
		deleted      bool
		profileName  string
		fromManifest bool
	}
	order := []string{}
	work := map[string]*identityWork{}
	note := func(did string) *identityWork {
		if w, ok := work[did]; ok {
			return w
		}
		w := &identityWork{}
		work[did] = w
		order = append(order, did)
		return w
	}
	for _, h := range hits {
		for _, row := range h.rows {
			w := note(row.DID)
			// Sticky, not last-write-wins: several of a chain's keys produce
			// several rows, and one row omitting the flag must not un-delete an
			// identity another row reported as deleted.
			w.deleted = w.deleted || row.IsDeleted
			if row.Profile != nil && w.profileName == "" {
				w.profileName = row.Profile.Name
			}
		}
		for _, m := range h.minted {
			note(m.DID).fromManifest = true
		}
	}

	// Pull each chain, then read it back from the local relay — so every key id
	// this command installs comes from an operation the local relay ACCEPTED,
	// never from an index row.
	chains := map[string]*chainFacts{}
	for _, did := range order {
		w := work[did]
		entry := recoveredIdentity{DID: did, Deleted: w.deleted, FromManifest: w.fromManifest}
		entry.Name = config.FindIdentityName(cfg, did)

		facts, ops, err := loadChainFacts(lr, oracle, did, opts.dryRun)
		if err != nil {
			entry.Status = "found-but-not-fetched"
			entry.Reason = err.Error()
			result.Identities = append(result.Identities, entry)
			continue
		}
		chains[did] = facts
		entry.Operations = ops
		entry.Deleted = entry.Deleted || facts.deleted
		result.Identities = append(result.Identities, entry)
	}

	// What the scan REACHED and what the chains PROVE are two different sets,
	// and until this ran only the first fed the counter.
	//
	// A rotation moves an identity's current key to a fresh index. Enough
	// rotations — or enough burned indices in between — and that index sits past
	// where the gap limit stopped the walk. The oracle was never asked about it;
	// the chain fetched a moment ago names the public key anyway, and the seed in
	// hand derives it. Two things went wrong there: the key was left out of the
	// keystore even though the chain proves the vault owns it, and, far worse,
	// the counter converged past only the SCANNED indices while reporting that
	// the next mint could not reuse a recovered one. It could — the next mint
	// took an index a burn identity already spent, and two unrelated DIDs ended
	// up signing with the same Ed25519 private key.
	//
	// Closing it needs no relay. The chains are already here, and matching their
	// declared keys against forward derivations is local arithmetic.
	if extra := probeBeyondScan(seed, chains, hits, uint32(result.IndicesScanned), opts); len(extra) > 0 {
		hits = append(hits, extra...)
		for _, h := range extra {
			// Every probe hit is a spent index and feeds the counter, wherever it
			// sits. Only the ones PAST the walk say the scan depth was wrong; an
			// index the walk reached and the oracle stayed silent about is the
			// oracle's shortfall, and a deeper scan would not have helped.
			if int64(h.index) > result.HighestUsedIndex {
				result.HighestUsedIndex = int64(h.index)
			}
			if h.beyondScan {
				result.BeyondScanIndices = append(result.BeyondScanIndices, h.index)
			}
		}
		if n := len(result.BeyondScanIndices); n > 0 {
			result.ScanComplete = false
			// The walk starts at 0 and a gap limit of D reaches index D-1 in the
			// worst case, so D = highest + 1 is what would have got there.
			result.RecommendedScanDepth = int(result.BeyondScanIndices[n-1]) + 1
		}
	}

	// A chain that could not be READ is a chain whose keys were never matched
	// against a derivation, so this run has no basis for saying the scan reached
	// everything the vault spent. --dry-run pulls nothing at all, which is
	// precisely the run an operator makes before deciding to trust the vault:
	// answering it with a clean scan on the strength of having looked at nothing
	// is the same silence-read-as-an-answer this command exists to refuse.
	if len(chains) < len(order) {
		result.ScanComplete = false
	}

	// THE COUNTER GOES FIRST — before a single private key is written.
	//
	// Everything after this point can fail: a keystore write, a vault record, a
	// config.Save registering the recovered names. The old order put all of it
	// ahead of the counter, so a config.Save that returned an error left installed
	// keys standing over a counter that had never moved — and the next mint from
	// this vault handed out an index a recovered identity already spent. One
	// Ed25519 private key, two DIDs, no way to see it.
	//
	// Raising it first inverts which failure is possible. A failure after the
	// floor is on disk BURNS indices, and a burned index is a hole the gap limit
	// already walks through by design; a failure before it produces a reusable
	// one. The write is idempotent and the floor only ascends, so re-running
	// converges exactly as it did.
	minNext := uint32(0)
	if result.HighestUsedIndex >= 0 {
		minNext = uint32(result.HighestUsedIndex) + 1
	}
	if !opts.dryRun {
		next, err := getVaults().RaiseCounter(vaultName, minNext)
		if err != nil {
			return fmt.Errorf("raise the derivation counter for vault '%s' before installing keys: %w", vaultName, err)
		}
		result.CounterAfter = next
	}

	// Install the keys. A key's ACCOUNT is its own public key, which the seed
	// already derived — but the key ID a chain declares it under is not, and a key
	// this machine cannot tie to an accepted operation is a key it declines to
	// install rather than one it files under a name it invented. So the fetch
	// still comes first, and an identity that could not be fetched still leaves
	// its key uninstalled.
	var records []vault.MintedKey
	installed := map[string][]string{}
	for _, h := range hits {
		dids := map[string]bool{}
		for _, row := range h.rows {
			dids[row.DID] = true
		}
		for _, m := range h.minted {
			dids[m.DID] = true
		}
		// Beyond-scan hits are named by the chain that declared them, never by an
		// index row — the oracle was never asked about these indices at all.
		for _, did := range h.chainDIDs {
			dids[did] = true
		}
		ordered := make([]string, 0, len(dids))
		for did := range dids {
			ordered = append(ordered, did)
		}
		sort.Strings(ordered)

		if len(ordered) == 0 {
			continue
		}
		for _, did := range ordered {
			key := recoveredKey{
				Index:      h.index,
				Path:       vault.DerivationPath(h.index),
				PublicKey:  h.publicKey,
				DID:        did,
				BeyondScan: h.beyondScan,
			}
			facts, ok := chains[did]
			if !ok {
				key.Outcome = "not-installed"
				key.Reason = "the chain that names this key could not be read, so there is no account to store it under"
				result.Keys = append(result.Keys, key)
				continue
			}
			keyID, found := facts.keyIDFor(h.publicKey)
			if !found {
				// The index said this identity declared the key and the chain this
				// machine holds does not show it. Do not guess an account.
				key.Outcome = "not-installed"
				key.Reason = "no operation in the chain this machine holds declares this public key"
				result.Keys = append(result.Keys, key)
				continue
			}
			// The account is the key's own content address, which this run can
			// compute from the derived public key alone. The chain is still read
			// first, and still decides whether the key is installable at all: a
			// key no operation this machine holds declares is a key this command
			// refuses to name, whatever the seed derives.
			account := keyAccount(h.publicKey)
			key.KeyID, key.Account = keyID, account
			key.Roles = facts.currentRoles[keyID]
			key.Superseded = len(key.Roles) == 0

			// A machine that wrote this key under the pre-content-addressing
			// account may already hold it — but the LABEL is not the evidence.
			// `<did>#<key_id>` is a name a machine chose, not a claim about the
			// bytes behind it, so what the legacy entry actually holds is read and
			// compared against the key this seed derives.
			legacy := legacyKeyAccount(did, keyID)
			legacyVerdict, legacyDetail := legacyKeyVerdict(legacy, h.publicKey)

			switch {
			case keys.HasKey(account):
				key.Outcome = "already-present"
			// Same key under the old name. Recovery converges rather than writes a
			// second copy of the same seed under a second name.
			case legacyVerdict == legacyKeyMatches:
				key.Account = legacy
				key.Outcome = "already-present"
			// Something else is filed under that name. Reporting it as
			// already-present would tell an operator this key is recovered when
			// this machine holds a DIFFERENT key there, and recording provenance
			// for it would write that lie into the vault trail. Say what is there
			// and let the operator resolve it.
			case legacyVerdict == legacyKeyDiffers, legacyVerdict == legacyKeyUnreadable:
				key.Outcome = "not-installed"
				key.Reason = fmt.Sprintf("the pre-content-addressing account '%s' holds %s — this key is NOT recovered. "+
					"Resolve it ('dfos keys list' shows what this machine holds), then re-run", legacy, legacyDetail)
				result.Keys = append(result.Keys, key)
				continue
			case opts.dryRun:
				key.Outcome = "recovered"
				key.Reason = "dry run — nothing was written"
			default:
				if _, err := keys.PutKey(account, h.private); err != nil {
					key.Outcome = "not-installed"
					key.Reason = fmt.Sprintf("write to %s: %v", keys.Backend(), err)
					result.Keys = append(result.Keys, key)
					continue
				}
				key.Outcome = "recovered"
			}
			installed[did] = append(installed[did], keyID)
			records = append(records, vault.MintedKey{
				Index: h.index, DID: did, KeyID: keyID,
				Roles: key.Roles, PublicKey: h.publicKey,
			})
			result.Keys = append(result.Keys, key)
		}
	}

	// Identity end state, and the names. A DID this machine already names keeps
	// that name — recovery does not rename anything an operator chose.
	for i := range result.Identities {
		entry := &result.Identities[i]
		if entry.Status == "found-but-not-fetched" {
			continue
		}
		entry.Keys = installed[entry.DID]
		switch {
		case len(entry.Keys) == 0:
			entry.Status = "found-but-not-fetched"
			if entry.Reason == "" {
				entry.Reason = "the chain is local, and no key this phrase derives is installable under it"
			}
		case allAlreadyPresent(result.Keys, entry.DID):
			entry.Status = "already-present"
		default:
			entry.Status = "recovered"
		}
		if entry.Name != "" {
			continue
		}
		entry.Name = pickIdentityName(cfg, work[entry.DID].profileName, entry.DID)
		if !opts.dryRun {
			cfg.Identities[entry.Name] = config.IdentityConfig{DID: entry.DID}
		}
	}
	// A dry run computes the same numbers and writes none of them. The math is
	// unchanged: the floor this run would install, over the counter as it stands.
	if opts.dryRun {
		result.MintedAdded = countNewRecords(meta, records)
		result.CounterAfter = maxU32(meta.NextIndex, minNext)
		return nil
	}

	// The vault's provenance, and the floor re-applied over it. Reconcile is
	// idempotent and its counter half is the same floor RaiseCounter already
	// wrote, so this is the trail catching up to a counter that is already safe
	// — not the moment the counter becomes safe.
	added, next, err := getVaults().Reconcile(vaultName, minNext, records...)
	if err != nil {
		return fmt.Errorf("reconcile vault '%s': %w", vaultName, err)
	}
	result.MintedAdded, result.CounterAfter = added, next

	// Names LAST. It is the step most likely to fail for a reason that has
	// nothing to do with custody (a read-only config, a full disk), and it is
	// the only one whose loss costs nothing but a label: the keys are installed,
	// the provenance is written, and the counter cleared every index before any
	// of it. A re-run picks the names back up.
	if len(result.Identities) > 0 {
		if err := config.Save(cfg); err != nil {
			return fmt.Errorf("register recovered identities in config: %w", err)
		}
	}
	return nil
}

// beyondScanCeiling bounds the forward derivation walk that explains chain keys
// the scan never reached. Nothing is asked of any relay here — it is pure local
// arithmetic — so the bound exists to keep an unexplainable key (one minted
// outside this vault, which is an ordinary thing for a multi-device identity to
// hold) from turning into an unbounded loop, not to be polite to a peer.
const beyondScanCeiling = maxScanIndices

// probeBeyondScan derives forward from where the scan stopped and matches each
// derived public key against the keys the FETCHED CHAINS declare.
//
// The scan's question is "has any identity declared this key", asked of a relay.
// This walk asks the opposite and asks it locally: "which index of this vault
// produced the key this chain already showed me". A hit is chain-proven — the
// operation declaring it was accepted by the local relay — and seed-proven, so
// the index is spent whatever the oracle's gap limit concluded.
//
// It walks from zero, not from where the scan stopped, because there are two
// ways an index the chain proves goes unrecorded and both spend the index:
//
//	past scanStop — the walk never derived it. This is the scan-depth finding,
//	  and the hit is flagged beyondScan so the report can say so.
//	before scanStop — the walk derived it and the ORACLE returned no row for it,
//	  so it counted as a gap. An index whose declaring operation was never
//	  published, or a relay whose index lags its own proof plane, looks like this.
//
// It stops as soon as every unexplained key is accounted for. Keys that never
// match are left alone: a key this seed cannot derive was minted somewhere else,
// which is a fact about the identity and says nothing about this vault's counter.
//
// Manifest-only runs no scan, asks no relay, and already banners itself as
// covering only what the vault's own records name; it is left out rather than
// given a second, quieter kind of walk.
func probeBeyondScan(seed []byte, chains map[string]*chainFacts, scanned []scanHit, scanStop uint32, opts recoverOptions) []scanHit {
	if opts.manifestOnly || len(chains) == 0 {
		return nil
	}

	// Every public key a fetched chain declared, minus the ones the scan already
	// matched to an index. DIDs are sorted so a key two chains share produces one
	// hit naming both, in the same order on every run.
	explained := make(map[string]bool, len(scanned))
	for _, h := range scanned {
		explained[h.publicKey] = true
	}
	wanted := map[string][]string{}
	dids := make([]string, 0, len(chains))
	for did := range chains {
		dids = append(dids, did)
	}
	sort.Strings(dids)
	for _, did := range dids {
		for pub := range chains[did].keyIDByPublic {
			if explained[pub] {
				continue
			}
			wanted[pub] = append(wanted[pub], did)
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	var found []scanHit
	for i := uint32(0); i < beyondScanCeiling && len(wanted) > 0; i++ {
		priv, pub, err := vault.DeriveKey(seed, i)
		if err != nil {
			// The hardened range ran out. Nothing past here is derivable, so the
			// remaining keys are unexplainable rather than undiscovered.
			break
		}
		mb := protocol.EncodeMultikey(pub)
		owners, ok := wanted[mb]
		if !ok {
			continue
		}
		delete(wanted, mb)
		found = append(found, scanHit{
			index:      i,
			publicKey:  mb,
			private:    priv,
			chainDIDs:  owners,
			beyondScan: i >= scanStop,
		})
	}
	return found
}

// The four things a pre-content-addressing keystore account can be, relative to
// the key a recovery just derived.
const (
	// legacyKeyAbsent: nothing is filed under that name.
	legacyKeyAbsent = "absent"
	// legacyKeyMatches: the same key, under the old name. Converge on it.
	legacyKeyMatches = "matches"
	// legacyKeyDiffers: a DIFFERENT key under that name. The name was never
	// evidence — one key declared by two identities was two entries, and a
	// hand-edited or half-migrated store can put anything here.
	legacyKeyDiffers = "differs"
	// legacyKeyUnreadable: something is there and this machine cannot read it.
	// Indistinguishable from a conflict for our purposes: not this key.
	legacyKeyUnreadable = "unreadable"
)

// legacyKeyVerdict reads what the legacy account actually holds and compares its
// derived public key against the one this run derived from the seed. detail is
// prose for the report, empty unless the verdict is a problem.
//
// Existence is not identity. `HasKey` answers "is a name taken", and recovery's
// question is "does this machine already hold THIS key" — the two agree in the
// ordinary case and diverge in exactly the case worth catching.
func legacyKeyVerdict(account, wantPublicKey string) (verdict, detail string) {
	if !keys.HasKey(account) {
		return legacyKeyAbsent, ""
	}
	priv, err := keys.GetPrivateKey(account)
	if err != nil {
		return legacyKeyUnreadable, fmt.Sprintf("a key this machine cannot read (%v)", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return legacyKeyUnreadable, fmt.Sprintf("a key of %d bytes, which is not an ed25519 private key", len(priv))
	}
	got := protocol.EncodeMultikey(pub)
	if got == wantPublicKey {
		return legacyKeyMatches, ""
	}
	return legacyKeyDiffers, fmt.Sprintf("a DIFFERENT key (%s, not %s)", got, wantPublicKey)
}

func maxU32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func countNewRecords(meta *vault.Metadata, records []vault.MintedKey) int {
	have := map[string]bool{}
	for _, r := range meta.Minted {
		have[r.DID+"#"+r.KeyID] = true
	}
	n := 0
	for _, r := range records {
		k := r.DID + "#" + r.KeyID
		if !have[k] {
			have[k] = true
			n++
		}
	}
	return n
}

func allAlreadyPresent(all []recoveredKey, did string) bool {
	seen := false
	for _, k := range all {
		if k.DID != did || k.Account == "" {
			continue
		}
		seen = true
		if k.Outcome != "already-present" {
			return false
		}
	}
	return seen
}

// chainFacts is everything the write phase needs from one identity chain: the
// key id every public key was EVER declared under, and which of them are current.
type chainFacts struct {
	deleted bool
	// keyIDByPublic maps a public multikey to the key id an accepted operation
	// declared it under. Built from the whole log, not just current state,
	// because the index's `key=` is has-ever-declared and the keys most worth
	// recovering are exactly the ones a rotation left behind.
	keyIDByPublic map[string]string
	currentRoles  map[string][]string
}

func (f *chainFacts) keyIDFor(publicKey string) (string, bool) {
	id, ok := f.keyIDByPublic[publicKey]
	return id, ok
}

// loadChainFacts gets a DID's chain into the local relay and folds it.
//
// The pull is unconditional when there is an oracle: ingestion is idempotent, and
// a chain this machine happens to already hold may be behind the one the index
// just pointed at. Under --dry-run nothing is pulled at all — the fold runs
// against whatever the local relay already holds, so an identity the scan found
// and this machine has never seen reports as found-but-not-fetched. That is the
// honest dry-run answer: a chain it did not fetch is a chain it cannot read key
// ids out of.
func loadChainFacts(lr *localrelay.LocalRelay, oracle *client.Client, did string, dryRun bool) (*chainFacts, int, error) {
	if oracle != nil && !dryRun {
		log, err := oracle.GetIdentityLog(did)
		if err != nil {
			return nil, 0, fmt.Errorf("pull chain from the oracle: %v", err)
		}
		for _, res := range lr.Relay.Ingest(log) {
			if res.Status == "rejected" {
				fmt.Fprintf(os.Stderr, "  Warning: %s operation %s rejected by the local relay: %s\n", did, res.CID, res.Error)
			}
		}
	}

	chain, err := lr.Relay.GetIdentity(did)
	if err != nil {
		return nil, 0, fmt.Errorf("read chain from the local relay: %v", err)
	}
	if chain == nil {
		if dryRun {
			return nil, 0, fmt.Errorf("not in the local relay, and --dry-run pulls nothing")
		}
		return nil, 0, fmt.Errorf("not in the local relay after the pull")
	}

	facts := &chainFacts{
		deleted:       chain.State.IsDeleted,
		keyIDByPublic: map[string]string{},
		currentRoles:  map[string][]string{},
	}
	// Every accepted operation, not just the head. The index answers
	// has-ever-declared, and a key a rotation left behind is exactly the one an
	// operator recovering from a phrase is most likely to hold.
	for _, token := range chain.Log {
		payload, err := protocol.PayloadFromJWS(token)
		if err != nil {
			continue
		}
		for _, field := range []string{"controllerKeys", "authKeys", "assertKeys"} {
			set, ok := payload[field].([]any)
			if !ok {
				continue
			}
			for _, item := range set {
				entry, ok := item.(map[string]any)
				if !ok {
					continue
				}
				id, _ := entry["id"].(string)
				pub, _ := entry["publicKeyMultibase"].(string)
				if id == "" || pub == "" {
					continue
				}
				if _, seen := facts.keyIDByPublic[pub]; !seen {
					facts.keyIDByPublic[pub] = id
				}
			}
		}
	}
	for role, set := range map[string][]protocol.MultikeyPublicKey{
		"controller": chain.State.ControllerKeys,
		"auth":       chain.State.AuthKeys,
		"assert":     chain.State.AssertKeys,
	} {
		for _, k := range set {
			facts.currentRoles[k.ID] = append(facts.currentRoles[k.ID], role)
			if _, seen := facts.keyIDByPublic[k.PublicKeyMultibase]; !seen {
				facts.keyIDByPublic[k.PublicKeyMultibase] = k.ID
			}
		}
	}
	// Role order is fixed rather than map-iteration order, so two runs over one
	// chain print the same line.
	for id := range facts.currentRoles {
		facts.currentRoles[id] = orderRoles(facts.currentRoles[id])
	}
	return facts, len(chain.Log), nil
}

// orderRoles puts a key's roles in controller→auth→assert order.
func orderRoles(roles []string) []string {
	rank := map[string]int{"controller": 0, "auth": 1, "assert": 2}
	sort.SliceStable(roles, func(i, j int) bool { return rank[roles[i]] < rank[roles[j]] })
	return roles
}

// pickIdentityName chooses a local name for a recovered identity. It prefers the
// relay's projected profile name — amber, but it is what the operator called the
// identity — and falls back to a DID-derived label. A collision takes a numeric
// suffix rather than displacing a name already in config: recovery adds, it does
// not overwrite what an operator chose.
func pickIdentityName(c *config.Config, projected, did string) string {
	base := sanitizeIdentityName(projected)
	if base == "" {
		tail := did
		if i := strings.LastIndex(did, ":"); i >= 0 {
			tail = did[i+1:]
		}
		if len(tail) > 8 {
			tail = tail[:8]
		}
		base = "recovered-" + strings.ToLower(tail)
	}
	if _, taken := c.Identities[base]; !taken {
		return base
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", base, n)
		if _, taken := c.Identities[candidate]; !taken {
			return candidate
		}
	}
}

var identityNameUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// sanitizeIdentityName reduces a projected profile name to something usable as a
// config key and a --as argument. A projection is a relay's amber restatement of
// a document it holds; it can be anything, so it is squeezed to a conservative
// alphabet rather than trusted into config verbatim.
func sanitizeIdentityName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	// A projection that is itself a DID becomes no name at all. Registering a
	// DID-shaped config key would make `--as <that>` ambiguous between the name
	// tier and the bare-DID tier of the resolution stack.
	if strings.HasPrefix(s, "did:") {
		return ""
	}
	s = strings.Trim(identityNameUnsafe.ReplaceAllString(s, "-"), "-._")
	if len(s) > 32 {
		s = strings.Trim(s[:32], "-._")
	}
	return s
}

// --- output ---

func printRecoverResult(r *recoverResult, opts recoverOptions) {
	fmt.Printf("Recovery:\n")
	fmt.Printf("  Vault:      %s [%s] — via %s\n", r.Vault, r.Fingerprint, r.VaultSource)
	fmt.Printf("  Derivation: m/%d'/<index>'\n", vault.DfosPurpose)
	if r.Scanned {
		fmt.Printf("  Oracle:     %s (%s) — via %s\n", r.Oracle, r.OracleURL, r.OracleSource)
		fmt.Printf("  Scan:       %d indices, stopped after %d consecutive unused\n", r.IndicesScanned, r.ScanDepth)
	}
	fmt.Printf("  Keystore:   %s\n", r.Backend)
	if r.DryRun {
		fmt.Printf("  Mode:       dry run — nothing was written\n")
	}
	if !r.Scanned {
		fmt.Printf("\n! MANIFEST ONLY — the derivation scan did NOT run, and no relay was asked.\n")
		fmt.Printf("  This report covers exactly the keys this machine's vault records already name.\n")
		fmt.Printf("  It says NOTHING about keys this seed minted elsewhere. Re-run without\n")
		fmt.Printf("  --manifest-only against a relay serving the identity index for the full scan.\n")
	}
	printScanShortfall(r)

	if len(r.Keys) == 0 {
		fmt.Printf("\nNo keys found.\n")
	} else {
		fmt.Printf("\n%s %s %s %s\n", pad("INDEX", 6), pad("PUBLIC KEY", 18), pad("OUTCOME", 16), "DECLARED BY")
		for _, k := range r.Keys {
			label := truncateMiddle(k.DID, 30)
			switch {
			case len(k.Roles) > 0:
				label += " — " + strings.Join(k.Roles, ", ")
			case k.Superseded && k.Account != "":
				label += " — rotated out, still recovered"
			}
			fmt.Printf("%s %s %s %s\n",
				pad(fmt.Sprintf("%d", k.Index), 6),
				pad(truncateMiddle(k.PublicKey, 18), 18),
				pad(k.Outcome, 16),
				label)
			if k.BeyondScan {
				fmt.Printf("%s past the scan — the chain declares this key, and the seed derives it here\n", pad("", 6))
			}
			if k.Reason != "" {
				fmt.Printf("%s %s\n", pad("", 6), k.Reason)
			}
		}
	}

	if len(r.Identities) > 0 {
		fmt.Printf("\n%s %s %s %s\n", pad("IDENTITY", 20), pad("DID", 30), pad("STATUS", 22), "KEYS")
		for _, id := range r.Identities {
			label := id.Name
			if id.Deleted {
				label += " (deleted)"
			}
			fmt.Printf("%s %s %s %d\n",
				pad(truncateMiddle(orDash(label), 20), 20),
				pad(truncateMiddle(id.DID, 30), 30),
				pad(id.Status, 22),
				len(id.Keys))
			if id.Reason != "" {
				fmt.Printf("%s %s\n", pad("", 20), id.Reason)
			}
		}
	}

	verb := "added"
	if r.DryRun {
		verb = "would be added"
	}
	fmt.Printf("\nVault records: %d %s\n", r.MintedAdded, verb)
	// The claim the counter line makes is scoped to what this run LEARNED, which
	// is the scan plus the chains it fetched. Saying "cannot reuse a recovered
	// index" was true and useless; what an operator reads it as — cannot reuse
	// an index this vault has spent — is only true when the scan was complete.
	safety := "the next mint from this vault cannot reuse an index this run learned"
	if !r.ScanComplete {
		safety = "past every index this run learned — indices the scan never reached remain unknown"
	}
	switch {
	case r.CounterAfter == r.CounterBefore:
		fmt.Printf("Counter:       %d — unchanged\n", r.CounterBefore)
	case r.DryRun:
		fmt.Printf("Counter:       %d — would rise to %d: %s\n", r.CounterBefore, r.CounterAfter, safety)
	default:
		fmt.Printf("Counter:       %d → %d — %s\n", r.CounterBefore, r.CounterAfter, safety)
	}

	fmt.Printf("\nWhat this scan cannot see:\n")
	if r.Scanned {
		fmt.Printf("  - One relay answered. '%s' not knowing a key is that relay's answer, not the world's.\n", r.Oracle)
		fmt.Printf("  - A derived key no identity operation ever declared is invisible to any index. It is\n")
		fmt.Printf("    still derivable from the phrase; nothing can find it for you.\n")
		// The gap limit is the only thing that ends the walk, so the lever that
		// moves it belongs in the same breath as the limitation it causes.
		fmt.Printf("  - The walk ended on the gap limit: %d consecutive unused indices (--scan-depth %d).\n", r.ScanDepth, r.ScanDepth)
		fmt.Printf("    An identity whose every key sits past a longer run of unused indices is out of\n")
		fmt.Printf("    reach of this run. '--scan-depth N' walks through a gap that wide.\n")
	}
	fmt.Printf("  - Keys minted OUTSIDE a vault are not derivable from any phrase. This command says\n")
	fmt.Printf("    nothing about them — 'dfos keys list' shows what this machine holds.\n")
	if r.DryRun {
		fmt.Printf("\nNothing was written. Re-run without --dry-run to restore.\n")
		return
	}
	if hasOutcome(r.Keys, "recovered") {
		fmt.Fprintf(os.Stderr, "\nRecovered keys are in %s. Signing resolves the identity and uses the key this device holds, so 'dfos --as <name> …' works again.\n", keys.Backend())
	}
}

// printScanShortfall is the loud half of the counter fix. A scan that stopped
// short is not a detail of the walk: it is the one condition under which this
// vault's counter can still be behind what the seed has spent, and an operator
// reading "recovered" over a clean report would have no way to know.
//
// It fires on PROOF, never on suspicion — a chain this run fetched declared a
// key, and deriving forward from the seed found the index that produced it, past
// where the scan stopped. Keys a chain names that this seed cannot derive are
// silent here: they were minted elsewhere and say nothing about this vault.
func printScanShortfall(r *recoverResult) {
	if len(r.BeyondScanIndices) == 0 {
		return
	}
	indices := make([]string, 0, len(r.BeyondScanIndices))
	for _, i := range r.BeyondScanIndices {
		indices = append(indices, fmt.Sprintf("%d", i))
	}
	fmt.Printf("\n! SCAN DEPTH TOO SHALLOW — current key(s) beyond scan depth.\n")
	fmt.Printf("  The scan walked %d indices and stopped after %d consecutive unused ones. A chain\n", r.IndicesScanned, r.ScanDepth)
	fmt.Printf("  this run fetched declares key(s) this vault's seed derives at index %s,\n", strings.Join(indices, ", "))
	fmt.Printf("  past that stop. They are recovered here and the counter clears them.\n")
	fmt.Printf("  What the walk could NOT see is an identity whose every key sits past the same\n")
	fmt.Printf("  gap — indices included. Until this vault is scanned that deep, minting from it\n")
	fmt.Printf("  risks handing out an index another identity already spent.\n")
	fmt.Printf("  Re-run with --scan-depth %d (or more): dfos recover --vault %s --scan-depth %d\n",
		r.RecommendedScanDepth, r.Vault, r.RecommendedScanDepth)
}

func hasOutcome(all []recoveredKey, outcome string) bool {
	for _, k := range all {
		if k.Outcome == outcome {
			return true
		}
	}
	return false
}
