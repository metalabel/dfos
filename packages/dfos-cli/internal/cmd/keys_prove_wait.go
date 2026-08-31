package cmd

// The ceremony epilogue — what `dfos keys add` does AFTER the proof is on the
// wire, and why it is the default.
//
// A presentation is not an ending. The proof lands, the operator stamps the
// ceremony `presented`, and then a human decides on the operator's own surface:
// they compare the six words their dialog shows against the six words this
// command printed, and they approve or they refuse. Everything that makes the
// ceremony matter happens in that gap. A command that stopped at `presented`
// stopped one step before the answer and left its human to discover the outcome
// by looking somewhere else — so this waits, and reports what was decided.
//
// WHAT THE WAIT IS, AND WHAT IT IS NOT. It is a status poll: one GET, repeated,
// carrying the ceremony's code and nothing else. It is NOT a retry of the
// presentation — that rule is unchanged and absolute, and nothing here re-posts
// an envelope except on the operator's own explicit invitation (see the stale
// head, below). It is not a session either: the code is the same single-shot
// capability it always was, the poll spends nothing, and the loop leaving
// changes no state anywhere.
//
// THE STATUS URL IS DERIVED, NEVER ANSWERED. It is the presentation endpoint's
// ORIGIN with a fixed path. The presentation endpoint was itself checked, at
// resolution, to byte-equal the authority the human typed — so the poll cannot
// reach a host the human did not name, and no member of any answer can move it
// there. An operator that wanted to redirect the poll would have to redirect the
// presentation first, which is the check that already refuses.
//
// LEAVING IS ALWAYS SAFE, AND THE MESSAGE SAYS SO. Ctrl-C, a network that goes
// away, an operator that stops answering: none of them undo a presentation. The
// proof is where it was, the ceremony is still open on the operator's surface,
// and the key is still held here as a candidate. Every early exit says exactly
// that, because the one wrong thing to believe at that moment is that stopping
// the command took the key back.
//
// THE STALE HEAD IS THE ONE PLACE AN ENVELOPE IS SIGNED TWICE. `prevCID` binds a
// proof to one chain position; when the chain moves under a ceremony — the
// custodian published something between the presentation and the decision — the
// envelope names a head that is no longer the head, and the operator says so with
// `stale`. The recovery is the one KEY-PROOF.md names: re-resolve the SAME code
// (a live ceremony re-resolves, answering the same nonce against the current
// head), re-sign with the SAME key, re-present. It is not a retry of a refused
// presentation — nothing was refused — and it is bounded: three re-signs, then a
// loud stop, because a head moving that often is a ceremony that is never going
// to settle and a signature is not something to spend in a loop.
//
// THE POSITION CANNOT MOVE ACROSS A RE-SIGN. What the human consented to is an
// identity, a role set, and an audience; only the head is allowed to be different
// the second time. A re-resolution that answers a different DID or a different
// role set is refused rather than signed — consent was given for a position, and
// re-signing through a moved one would be signing something nobody was shown.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// keyProofStatusPath is the poll route, appended to the presentation endpoint's
// origin. It is a fixed path by design: a status URL an answer could name would
// be a status URL an answer could move.
const keyProofStatusPath = "/v1/key-proof/status"

// The ceremony status vocabulary. `pending` and `presented` are the two states a
// ceremony sits in while a human has not decided; the other four are decisions,
// and a decision ends the wait.
const (
	ceremonyStatusPending   = "pending"
	ceremonyStatusPresented = "presented"
	ceremonyStatusAdopted   = "adopted"
	ceremonyStatusRejected  = "rejected"
	ceremonyStatusFailed    = "failed"
	ceremonyStatusExpired   = "expired"
)

// The poll cadence. Two seconds while a human is plausibly looking at the
// dialog, five once they have plainly walked away — a ceremony's decision is a
// person clicking a button, and polling faster than a person moves buys nothing
// and costs the operator a request.
//
// They are vars rather than consts so a test can drive a whole ceremony's worth
// of polls in the time a test suite can afford. Nothing else writes them.
var (
	ceremonyPollInterval     = 2 * time.Second
	ceremonyPollSlowAfter    = 30 * time.Second
	ceremonyPollSlowInterval = 5 * time.Second
	// ceremonyPollDeadline is the ceiling on the whole wait. A ceremony lives ten
	// minutes and the operator answers `expired` when its own clock says so; this
	// only covers an operator whose clock never says anything, and waiting past it
	// would be waiting on a surface that has stopped talking about this ceremony.
	ceremonyPollDeadline = 15 * time.Minute
)

// ceremonyPollFailureBudget is how many CONSECUTIVE unusable answers the wait
// tolerates before it stops. A dropped connection, a 502 from a proxy, a
// restart: none of those are the operator refusing anything, and treating the
// first one as an ending would report "no decision" for a hiccup. Five in a row
// is a surface that is down, and the honest thing then is to say so and stop
// rather than to keep asking a host that is not answering.
const ceremonyPollFailureBudget = 5

// ceremonyResignCap bounds the stale-head recovery. See the header.
const ceremonyResignCap = 3

// ceremonyStatusAnswer is what the poll route says about a ceremony.
//
// `stale` is only meaningful on `presented`: it is the operator reporting that
// the chain head the stored envelope names is no longer the chain's head, which
// is an invitation to replace the envelope, not a failure of anything.
type ceremonyStatusAnswer struct {
	Status    string            `json:"status"`
	Stale     bool              `json:"stale"`
	OnAdopted *ceremonyAdoption `json:"onAdopted"`
}

// ceremonyAdoption is the chain row an adoption produced: the identity that
// adopted the key, the key id that identity names it by, and the CID of the
// operation that introduced it.
type ceremonyAdoption struct {
	DID        string `json:"did"`
	KeyID      string `json:"keyId"`
	ChainOpCID string `json:"chainOpCID"`
}

// The two poll failures that are not simply "the operator refused". Both are
// sentinels because the loop branches on them and neither is a sentence.
var (
	// errStatusNotOpen: the operator does not have this ceremony. It is the same
	// refusal an unknown or expired code gets at presentation, and after a
	// successful presentation it says only that the ceremony is gone — never how
	// it ended.
	errStatusNotOpen = errors.New("the ceremony is not open at the operator")
	// errStatusTransient: nothing was learned. A partition, a 5xx, a body that is
	// not a status. It counts against the budget and nothing more.
	errStatusTransient = errors.New("the status could not be read")
)

// ceremonyStatusURL derives the poll URL from the presentation endpoint's
// origin. The endpoint's authority was checked at resolution against the
// authority the human typed, so this cannot name a host they did not.
func ceremonyStatusURL(cer *ceremony) (string, error) {
	u, err := url.Parse(cer.Present)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("the presentation endpoint is not a URL a status poll can be derived from: %s", cer.Present)
	}
	return u.Scheme + "://" + u.Host + keyProofStatusPath, nil
}

// pollCeremonyStatus asks once.
//
// The classification is the whole job: an answer that says a decision was made,
// an answer that says the ceremony is gone, and a non-answer that says nothing
// at all are three different things, and flattening any two of them would make
// the wait report an outcome nobody reached.
func pollCeremonyStatus(statusURL, code string) (*ceremonyStatusAnswer, error) {
	resp, err := ceremonyHTTPClient().Get(statusURL + "?code=" + url.QueryEscape(code))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errStatusTransient, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusGone:
		return nil, fmt.Errorf("%w: %s", errStatusNotOpen, ceremonyMessage(body))
	case resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: HTTP %d %s", errStatusTransient, resp.StatusCode, ceremonyMessage(body))
	default:
		return nil, fmt.Errorf("the ceremony's status route refused (HTTP %d): %s", resp.StatusCode, ceremonyMessage(body))
	}

	var answer ceremonyStatusAnswer
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("%w: HTTP 200 with something that is not a status: %s", errStatusTransient, oneLineBody(body, 200))
	}
	switch answer.Status {
	case ceremonyStatusPending, ceremonyStatusPresented, ceremonyStatusAdopted,
		ceremonyStatusRejected, ceremonyStatusFailed, ceremonyStatusExpired:
		return &answer, nil
	}
	// A word outside the vocabulary is not a state this command can act on, and
	// acting on the closest one it recognizes would be inventing an outcome. It
	// counts as an unusable answer, so a surface that only ever says it stops the
	// wait at the budget rather than holding the terminal open forever.
	return nil, fmt.Errorf("%w: the operator answered status '%s', which is not a ceremony state", errStatusTransient, answer.Status)
}

// waitOutcome is what the wait came back with.
type waitOutcome struct {
	// Status is the terminal status the operator reported, or `presented` when
	// the wait stopped without one — which is the truthful reading of every early
	// exit, because a presented proof is exactly what is still standing.
	Status string
	// Adoption is the chain row, on an adoption that named one.
	Adoption *ceremonyAdoption
	// Stopped says why the wait ended short of a decision. Empty when a decision
	// arrived.
	Stopped string
	// Resigns counts the stale-head recoveries this ceremony took.
	Resigns int
	// PrevCID is the head the envelope finally bound, which is not the head the
	// first envelope bound when a re-sign happened.
	PrevCID string
}

// waitForCeremonyDecision polls until the operator reports a decision, and
// returns a truthful outcome for every other way a wait can end.
//
// IT NEVER RETURNS AN ERROR, and that is deliberate. The presentation succeeded
// before this was called; a poll that could not be made, a human who stopped
// watching, and a head that would not settle are all facts about the WAIT, not
// failures of the command, and reporting them as errors would print a failure
// over a proof that is standing at the operator exactly as intended.
func waitForCeremonyDecision(cer *ceremony, cand *candidateKey, description string) waitOutcome {
	out := waitOutcome{Status: ceremonyStatusPresented, PrevCID: cer.PrevCID}
	statusURL, err := ceremonyStatusURL(cer)
	if err != nil {
		out.Stopped = err.Error()
		return out
	}

	// The interrupt is caught only for the length of the wait, and only to print
	// the truth on the way out. Nothing is rolled back, because there is nothing
	// to roll back: the presentation is the operator's now.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "\nWaiting for the decision at %s — approve or refuse it there.\n", cer.Audience)
	fmt.Fprintf(os.Stderr, "The six words above are what its dialog shows for this key. Ctrl-C stops watching;\n")
	fmt.Fprintf(os.Stderr, "the proof stays presented either way.\n")

	started := time.Now()
	failures := 0
	for {
		elapsed := time.Since(started)
		if elapsed > ceremonyPollDeadline {
			out.Stopped = fmt.Sprintf("no decision after %s", ceremonyPollDeadline)
			return out
		}
		delay := ceremonyPollInterval
		if elapsed >= ceremonyPollSlowAfter {
			delay = ceremonyPollSlowInterval
		}
		select {
		case <-ctx.Done():
			out.Stopped = "you stopped watching"
			return out
		case <-time.After(delay):
		}

		answer, err := pollCeremonyStatus(statusURL, cer.Code)
		switch {
		case errors.Is(err, errStatusTransient):
			failures++
			if failures >= ceremonyPollFailureBudget {
				out.Stopped = fmt.Sprintf("%s did not answer its status route %d times running — %s",
					cer.Audience, failures, firstLine(err.Error()))
				return out
			}
			continue
		case errors.Is(err, errStatusNotOpen):
			// After a successful presentation this says the ceremony is gone and
			// nothing about how it ended. Guessing `expired` here would be putting
			// a decision in the operator's mouth.
			out.Stopped = fmt.Sprintf("%s no longer has this ceremony open, and does not say how it ended", cer.Audience)
			return out
		case err != nil:
			out.Stopped = firstLine(err.Error())
			return out
		}
		failures = 0

		switch answer.Status {
		case ceremonyStatusPending:
			continue
		case ceremonyStatusPresented:
			if !answer.Stale {
				continue
			}
			if out.Resigns >= ceremonyResignCap {
				out.Stopped = fmt.Sprintf("the chain head moved under this ceremony %d times and this key was re-signed for each — "+
					"a head that will not settle is not one to keep spending signatures on", out.Resigns)
				return out
			}
			fresh, err := resignForMovedHead(cer, cand, description)
			if err != nil {
				out.Stopped = firstLine(err.Error())
				return out
			}
			out.Resigns++
			out.PrevCID = fresh.PrevCID
			cer = fresh
			fmt.Fprintf(os.Stderr, "\nThe chain moved under this ceremony, so the proof was signed again against the new head\n")
			fmt.Fprintf(os.Stderr, "%s and presented again — same key, same identity, same roles. Still waiting.\n", fresh.PrevCID)
			continue
		case ceremonyStatusAdopted:
			out.Status, out.Adoption = ceremonyStatusAdopted, answer.OnAdopted
			return out
		default:
			// rejected, failed, expired — a decision, or the operator's own report
			// that there will not be one.
			out.Status = answer.Status
			return out
		}
	}
}

// resignForMovedHead runs KEY-PROOF.md's stale recovery: re-resolve, re-sign,
// re-present.
//
// THE RE-RESOLUTION IS OF THE SAME CODE, at the same authority, through the same
// resolveCode — so every rule that made the first resolution safe applies to this
// one unchanged: the audience may not move, the presentation endpoint may not
// move, the position must be whole, the role set must be canonical.
//
// AND THE POSITION THE HUMAN CONSENTED TO MAY NOT MOVE. The head is the one
// member allowed to differ; the identity, the roles, and the audience are what
// was displayed and confirmed, and a ceremony that answers different ones the
// second time is not the ceremony that was consented to. Refusing here is the
// only honest move — nothing on this machine can ask the human again.
func resignForMovedHead(cer *ceremony, cand *candidateKey, description string) (*ceremony, error) {
	carriage := cer.carriage
	fresh, err := resolveCode(&carriage)
	if err != nil {
		return nil, fmt.Errorf("the chain head moved and this ceremony would not re-resolve: %w", err)
	}
	switch {
	case fresh.DID != cer.DID:
		return nil, fmt.Errorf("REFUSING to re-sign: the ceremony now names %s, and %s is the identity that was consented to",
			fresh.DID, cer.DID)
	case fresh.RoleSet != cer.RoleSet:
		return nil, fmt.Errorf("REFUSING to re-sign: the ceremony now grants '%s', and '%s' is the role set that was consented to",
			fresh.RoleSet, cer.RoleSet)
	case fresh.Audience != cer.Audience:
		return nil, fmt.Errorf("REFUSING to re-sign: the ceremony now audiences %s, and %s is the host that was consented to",
			fresh.Audience, cer.Audience)
	}

	envelope, _, err := protocol.SignKeyProof(protocol.SignKeyProofInput{
		Typ:        protocol.KeyAddJWSTyp,
		Nonce:      fresh.Nonce,
		Audience:   fresh.Audience,
		DID:        fresh.DID,
		RoleSet:    fresh.RoleSet,
		PrevCID:    fresh.PrevCID,
		PrivateKey: cand.Private,
	})
	if err != nil {
		return nil, fmt.Errorf("re-sign the key proof against the current head: %w", err)
	}
	// The replacement is presented by the SAME key that presented the first one,
	// which is what lets the operator take it at all: a presented ceremony admits
	// a new envelope only from the publicKeyMultibase already on it, so this path
	// cannot be walked by anyone but the holder who opened it.
	if _, err := presentEnvelope(fresh, envelope, description); err != nil {
		return nil, fmt.Errorf("the proof was re-signed against the current head and the operator would not take it: %w", err)
	}
	return fresh, nil
}

// applyWaitOutcome folds what the wait learned into the receipt, and files the
// key when an adoption named the identity the human consented to.
//
// The filing is the SAME machinery a presentation-time adoption answer runs
// through — one gate, one rename, one provenance record — because an adoption
// learned from a poll is the same fact learned a minute later.
func applyWaitOutcome(out waitOutcome, result *proveResult, cer *ceremony, cand *candidateKey) {
	result.Status = out.Status
	result.WaitStopped = out.Stopped
	result.Resigned = out.Resigns
	result.PrevCID = out.PrevCID
	if out.Adoption == nil {
		return
	}
	result.AdoptedDID, result.KeyID, result.ChainOpCID = out.Adoption.DID, out.Adoption.KeyID, out.Adoption.ChainOpCID
	fileAdoptedKey(&presentationAnswer{Status: out.Status, KeyID: out.Adoption.KeyID, DID: out.Adoption.DID}, cer, cand, result)
}

// printCeremonyEpilogue is the receipt's tail for a ceremony that reached a
// decision, or that stopped short of one.
//
// EVERY BRANCH ENDS BY SAYING WHERE THE KEY IS. That is the fact a person needs
// in all six of them, and the fact a receipt that reported only the operator's
// word would leave them to infer.
func printCeremonyEpilogue(r *proveResult) {
	switch r.Status {
	case ceremonyStatusAdopted:
		if r.AdoptedDID != r.Adopts {
			// The operator says it adopted the key into an identity nobody was
			// shown. Nothing is filed against it — the provenance would be a claim
			// the human never saw — and the mismatch is the headline, not a footnote.
			fmt.Printf("! %s says this key was adopted by %s.\n", r.Audience, orDash(r.AdoptedDID))
			fmt.Printf("  %s is the identity you consented to, so nothing was filed against either one.\n", r.Adopts)
			fmt.Printf("  The key stays a candidate here. Report this to whoever displayed the code.\n")
			return
		}
		fmt.Printf("A human approved it at %s and %s now declares this key.\n", r.Audience, r.AdoptedDID)
		fmt.Printf("The key is filed under %s. Signing resolves the identity and uses the key this device holds.\n", r.Account)
		fmt.Printf("Rename it any time in Settings → Signing keys.\n")

	case ceremonyStatusRejected:
		fmt.Printf("A human refused it at %s. No chain declares this key, and nothing was written.\n", r.Audience)
		fmt.Printf("The key stays a held candidate: 'dfos keys list' shows it, 'dfos keys prune' never removes it,\n")
		fmt.Printf("and 'dfos keys remove %s' is how it leaves the keystore.\n", truncateKey(r.PublicKey))

	case ceremonyStatusExpired:
		fmt.Printf("The ceremony lapsed at %s before anyone decided. Nothing was refused and nothing was added.\n", r.Audience)
		fmt.Printf("The key stays a held candidate. Mint a fresh code where the last one was displayed, then:\n")
		fmt.Printf("  dfos keys add <code> --key %s\n", r.PublicKey)
		fmt.Printf("That presents this same key to the new ceremony rather than minting another.\n")

	case ceremonyStatusFailed:
		fmt.Printf("%s could not finish this ceremony, and does not say the key was added or refused.\n", r.Audience)
		fmt.Printf("The key stays a held candidate. Treat the ceremony as spent: mint a fresh code where the last\n")
		fmt.Printf("one was displayed, then:\n")
		fmt.Printf("  dfos keys add <code> --key %s\n", r.PublicKey)
		fmt.Printf("Check the operator's own list of signing keys before you do — if this key is on it, the\n")
		fmt.Printf("ceremony finished after all and 'dfos identity fetch %s' brings that chain here.\n", r.Adopts)

	default:
		// The wait ended without a decision. The presentation is untouched by that,
		// and this is the sentence that has to make it impossible to believe
		// otherwise.
		fmt.Printf("The wait stopped: %s.\n", r.WaitStopped)
		fmt.Printf("THE PROOF IS STILL PRESENTED — stopping this command does not take it back. The ceremony is\n")
		fmt.Printf("open at %s, the decision is still a human's to make there, and the key is held here as a\n", r.Audience)
		fmt.Printf("candidate until a chain declares it.\n")
		if r.Vault != "" {
			fmt.Printf("Once %s declares it, 'dfos recover --vault %s' files it under that identity.\n", r.Adopts, r.Vault)
		} else {
			fmt.Printf("Once %s declares it, 'dfos identity fetch %s' brings that chain here.\n", r.Adopts, r.Adopts)
		}
	}
}

// ceremonyOutcomeHeading is what the receipt calls itself. A ceremony that
// reached a decision is not "Presented", and a wait that stopped short of one is
// not anything else.
func ceremonyOutcomeHeading(status string) string {
	switch status {
	case ceremonyStatusAdopted:
		return "Adopted:"
	case ceremonyStatusRejected:
		return "Refused:"
	case ceremonyStatusExpired:
		return "Expired:"
	case ceremonyStatusFailed:
		return "Unfinished:"
	default:
		return "Presented:"
	}
}

// ceremonyDecided reports whether a status is one of the operator's decisions,
// as opposed to the presented state a wait leaves behind when it stops early.
func ceremonyDecided(status string) bool {
	switch status {
	case ceremonyStatusAdopted, ceremonyStatusRejected, ceremonyStatusExpired, ceremonyStatusFailed:
		return true
	}
	return false
}

// keyFingerprint renders the six words a human compares this key by. It is the
// kit's function and nothing local: the operator's dialog renders the same six
// words from the same multikey string, and two surfaces that computed a
// fingerprint two ways would be comparing nothing.
func keyFingerprint(publicKeyMultibase string) string {
	return protocol.KeyWordFingerprint(publicKeyMultibase)
}

// fingerprintNote is the line beside the words, wherever they are printed. A
// fingerprint nobody knows to compare defends nobody, so the instruction travels
// with it rather than living in a manual.
func fingerprintNote() string {
	return "(the same six words the operator's dialog shows for this key)"
}
