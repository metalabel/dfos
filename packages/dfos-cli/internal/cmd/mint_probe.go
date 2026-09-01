package cmd

// The mint-collision probe — the moment a vault-backed mint asks whether the
// index it just reserved has already been spent by somebody else.
//
// A vault's derivation counter is LOCAL, and a phrase is portable. Two machines
// holding one phrase keep two counters, neither knows what the other spent, and
// both hand out index N: one Ed25519 private key under two DIDs, with nothing on
// either chain to show it. `vault import` says so at adoption time, and
// `dfos recover` converges the counter past every index a relay can prove the
// seed spent. This is the check in between — the one that fires at the mint
// itself, after the counter has reserved an index and before anything is signed
// or stored.
//
// It is a PRE-CHECK, never a gate on minting. Every branch mirrors the oracle
// honesty `dfos recover` is built on:
//
//	no vault      — entropy keys cannot collide, so nothing is asked.
//	--no-mint-probe — the operator opted out, and an opt-out says nothing.
//	no relay      — the mint proceeds, saying out loud that nothing was asked.
//	cannot answer — the mint proceeds, naming the relay and what went wrong.
//	zero rows     — the mint proceeds SILENTLY; an unspent index is the ordinary case.
//	rows          — the mint REFUSES, before a key is stored or an operation signed.
//
// Only a well-formed positive answer refuses. A silence is never read as
// permission and never read as a hit: the notice says which of the two this run
// could not tell apart, and names `recover` as the thing that settles it.
//
// The reserved index stays burned on a refusal, and that is the safe direction.
// A burned index is a hole, and a hole is what the recovery scan's gap limit
// walks through by design; an index handed back would be one two identities can
// still both reach.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/vault"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// mintProbeReason is the code a script branches on when a mint is refused
// because the relay already knows the key the reserved index derives. The prose
// beside it is written for the operator and is free to be reworded; this is not.
const mintProbeReason = "mint-index-already-proved"

// mintProbeOptions is what a minting command tells the minter about asking a
// relay. Both fields come straight off the command's own flags.
type mintProbeOptions struct {
	// peer is the command's own --peer, which outranks the global --relay here
	// exactly as it does everywhere else (see requirePeer). Empty leaves the
	// ordinary resolution stack to name the relay, default-peer included.
	peer string
	// skip is --no-mint-probe. An operator who opted out is not warned about
	// what the opt-out cost them: they said it.
	skip bool
}

// mintProbeHit is one reserved index the relay says is already spent, and the
// identities its index rows name.
type mintProbeHit struct {
	index     uint32
	publicKey string
	dids      []string
}

// probeReservedIndices asks the resolved relay whether any key this reservation
// derived already proves somewhere, and returns an error ONLY on a hit. Every
// other outcome — no relay, a relay that cannot answer, a relay that stops
// answering halfway — leaves the mint to proceed behind a loud notice, because a
// relay's silence is a fact about the relay and not about this vault.
func probeReservedIndices(vaultName string, derived []vault.Derived, opts mintProbeOptions) error {
	if opts.skip || len(derived) == 0 {
		return nil
	}

	ctx, c, err := requirePeer(opts.peer)
	switch {
	case errors.Is(err, errNoPeerConfigured):
		// The local-first mint. Nothing is wrong here and nothing was asked.
		mintProbeSkipped(vaultName, derived, "no relay to ask")
		return nil
	case err != nil:
		// A relay WAS named and did not resolve: an unknown name, or a peer whose
		// DID pin has moved. That is a different fact from having no relay at
		// all, and it is not this command's to adjudicate — the mint is local and
		// proceeds, saying which question went unasked.
		mintProbeSkipped(vaultName, derived, "no relay could be resolved to ask — "+oneLineReason(err))
		return nil
	}

	label := mintProbeRelayLabel(ctx.RelayName, ctx.RelayURL)
	if v := oracleCapability(c); v.reason != "" {
		why := v.why
		if v.err != nil {
			why = transportCause(v.err)
		}
		mintProbeSkipped(vaultName, derived, fmt.Sprintf("%s cannot answer: %s", label, why))
		return nil
	}

	var hits []mintProbeHit
	for _, d := range derived {
		pub := protocol.EncodeMultikey(d.Public)
		rows, err := c.IdentitiesByKey(pub, 10)
		if err != nil {
			// The capability check passed and the relay stopped answering
			// anyway. Best-effort means best-effort: an unanswered question is
			// not a clean index, and it is not a hit either.
			mintProbeSkipped(vaultName, derived, fmt.Sprintf("%s stopped answering: %s", label, transportCause(err)))
			return nil
		}
		if len(rows) == 0 {
			continue
		}
		hit := mintProbeHit{index: d.Index, publicKey: pub}
		for _, row := range rows {
			hit.dids = append(hit.dids, row.DID)
		}
		hits = append(hits, hit)
	}
	// Zero rows everywhere is the ordinary case and prints nothing. An index
	// nobody has spent is not news, and announcing it on every mint would teach
	// an operator to read past the line that matters.
	if len(hits) == 0 {
		return nil
	}
	return errMintIndexAlreadyProved(vaultName, ctx.RelayName, ctx.RelayURL, hits)
}

// mintProbeSkipped is the loud half of best-effort. It names what was NOT
// established, which index the mint is spending anyway, and the one command that
// settles the question — because the failure this probe exists to catch is
// invisible on both chains, so an operator who is never told the check did not
// run has no other way to find out.
func mintProbeSkipped(vaultName string, derived []vault.Derived, cause string) {
	fmt.Fprintf(os.Stderr,
		"Note: the mint-collision probe did not run — %s. If this phrase is held on another machine, "+
			"%s may already be spent there; 'dfos recover --vault %s' converges the counter.\n",
		cause, mintProbeIndexPhrase(derived), vaultName)
}

// errMintIndexAlreadyProved is the refusal. It is a refusal rather than a
// warning because the operation it stops is irreversible in the one way that
// matters: a signed genesis or rotation publishes a key, and a key two
// identities both derive is a shared private key that no later operation can
// un-share.
//
// It names the relay, because "already spent" is one relay's answer; it names
// the identities, because the operator may recognize one as their own machine;
// and it names both ways forward — converge the counter, or mint anyway.
func errMintIndexAlreadyProved(vaultName, relayName, relayURL string, hits []mintProbeHit) error {
	label := mintProbeRelayLabel(relayName, relayURL)

	var b strings.Builder
	if len(hits) == 1 {
		fmt.Fprintf(&b, "refusing to mint from vault '%s': index %d is already spent.\n", vaultName, hits[0].index)
	} else {
		fmt.Fprintf(&b, "refusing to mint from vault '%s': indices %s are already spent.\n", vaultName, mintProbeIndexList(hits))
	}
	for i, h := range hits {
		fmt.Fprintf(&b, "%s reports the key this vault derives at index %d already proves for %s.",
			label, h.index, joinComma(h.dids))
		if i == len(hits)-1 {
			b.WriteString(" Another holder of this phrase minted here first — signing with it would put one private key under two identities.")
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "'dfos recover --vault %s' converges this machine's counter past every spent index. "+
		"The reserved index stays burned, which is safe: the recovery scan's gap limit walks through burned "+
		"indices by design. --no-mint-probe mints anyway.", vaultName)

	indices := make([]string, 0, len(hits))
	publicKeys := make([]string, 0, len(hits))
	var dids []string
	for _, h := range hits {
		indices = append(indices, fmt.Sprintf("%d", h.index))
		publicKeys = append(publicKeys, h.publicKey)
		dids = append(dids, h.dids...)
	}
	return &CodedError{
		Reason: mintProbeReason,
		Fields: map[string]string{
			"vault":     vaultName,
			"index":     strings.Join(indices, ","),
			"publicKey": strings.Join(publicKeys, ","),
			"relay":     relayName,
			"relayURL":  relayURL,
			"dids":      strings.Join(dids, ","),
		},
		Err: errors.New(b.String()),
	}
}

// mintProbeIndexPhrase renders the reserved indices as the subject of a
// sentence: one index or several, in the reservation's own ascending order.
func mintProbeIndexPhrase(derived []vault.Derived) string {
	if len(derived) == 1 {
		return fmt.Sprintf("index %d", derived[0].Index)
	}
	parts := make([]string, 0, len(derived))
	for _, d := range derived {
		parts = append(parts, fmt.Sprintf("%d", d.Index))
	}
	return "indices " + strings.Join(parts, ", ")
}

func mintProbeIndexList(hits []mintProbeHit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		parts = append(parts, fmt.Sprintf("%d", h.index))
	}
	return strings.Join(parts, ", ")
}

// mintProbeRelayLabel names a relay the way every oracle-facing message does:
// the registered name and the URL behind it, because an operator holding several
// relays needs both to know which one answered.
func mintProbeRelayLabel(name, url string) string {
	if name == "" {
		return url
	}
	return fmt.Sprintf("%s (%s)", name, url)
}

// oneLineReason folds a multi-line error into the middle of a sentence. Several
// of the errors that land here — a pin mismatch, a peer resolution failure — are
// written as indented blocks for the top-level error path, and pasting a block
// into the middle of a notice buries the notice.
func oneLineReason(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// transportCause reduces a failed round-trip to the words that identify it.
//
// Go wraps a transport failure as `Get "<url>": <cause>`, and IdentitiesByKey
// puts its own query path in front of that — so an unreachable relay's raw error
// carries the same long URL twice before it gets to "connection refused". That
// reads fine in recover's block layout, where the relay is already named on its
// own line above it; inside a one-line notice it buries the notice. The relay is
// named here too, so what is left to say is the cause.
func transportCause(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return oneLineReason(urlErr.Err)
	}
	return oneLineReason(err)
}
