package cmd

// THE SCOPE ASK — `dfos login --host <name-or-host>`.
//
// Without --host, a scope is whatever the operator typed: an opaque string
// handed to the authorize host verbatim, which is all `dfos login` has ever
// needed to be. --host closes the other half of the loop. An API that advertises
// under the API-AUTH OpenAPI convention already publishes the actions it grants
// — a catalog on its request-proof scheme, plus whatever its operations require
// — so a person signing in against that API can be shown what there is to ask
// for instead of guessing at token spellings.
//
// Three properties hold whatever path is taken:
//
//   - THE TOKENS STAY OPAQUE. The catalog's strings are copied document → ask →
//     scope string → credential, unchanged and uninterpreted. Descriptions are
//     display text; nothing decides anything from one.
//   - EXPLICIT BEATS ASK. A typed --scope is an instruction, and an instruction
//     is never overridden by a menu. --all-scopes takes the union without one.
//   - NOTHING IS CHOSEN SILENTLY. With no terminal and no explicit scope the
//     command errors and prints the choices, because a default scope picked on a
//     person's behalf is a grant they never made.
//
// The HOST the credential is for lives in the grant's attenuation as the
// `api:<host>` resource, not in `aud` — `aud` is this installation's login
// client DID, the party the grant was issued to. That is the shape `api call`
// selects on, and it is what resolveLoginTarget resolves so the two agree.

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/apispec"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
)

// loginTarget is the API a login is being scoped to.
type loginTarget struct {
	// Name is the local registry name, empty when --host named a host directly
	// and the registration was declined.
	Name string
	// Authority is the `<host>` of the `api:<host>` resource — resolved from the
	// document's own servers, the same rule `api call` signs a proof under.
	Authority string
	// Document is where the document was read from, for the display line.
	Document string
	Catalog  []apispec.CatalogEntry
	// Bundles are the AND-alternatives the catalog's flat list cannot express.
	Bundles []apispec.ActionBundle
}

// Label names the target the way the operator asked for it.
func (t *loginTarget) Label() string {
	if t.Name != "" {
		return t.Name + " (" + t.Authority + ")"
	}
	return t.Authority
}

// Resource is the attenuation resource a credential for this API must name.
func (t *loginTarget) Resource() string { return "api:" + t.Authority }

// stdinIsInteractive reports whether a person is at the other end of stdin. It
// is the gate on every prompt below: a pipe, a CI job, and a `< /dev/null` all
// answer no, and none of them may be asked a question.
func stdinIsInteractive() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())
}

// resolveLoginTarget reads --host as a REGISTERED NAME first and as a host or
// document URL second.
//
// Name-first is deliberate. A registry name is a local label the operator chose,
// so it can never be mistaken for something on the network; trying the network
// first would let a host that happens to share a name shadow the registration.
func resolveLoginTarget(value string, in io.Reader, out io.Writer, interactive bool) (*loginTarget, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("--host needs a registered API name or a host (e.g. --host api.dfos.com)")
	}

	if apispec.ValidateName(value) == nil {
		if registration, err := apiStore().Get(value); err == nil {
			return targetFromRegistration(registration, out)
		}
	}
	return discoverLoginTarget(value, in, out, interactive)
}

// targetFromRegistration builds the target from a cached document.
func targetFromRegistration(registration apispec.Registration, out io.Writer) (*loginTarget, error) {
	_, doc, err := loadAPI(registration.Name)
	if err != nil {
		return nil, err
	}
	authority, err := documentAuthority(doc, registration.Origin, registration.Name, out)
	if err != nil {
		return nil, err
	}
	catalog, bundles, err := documentActions(doc)
	if err != nil {
		return nil, err
	}
	return &loginTarget{
		Name:      registration.Name,
		Authority: authority,
		Document:  registration.Document,
		Catalog:   catalog,
		Bundles:   bundles,
	}, nil
}

// documentActions reads both readings of a document's action vocabulary: the
// flat catalog a person selects from, and the AND-alternatives that flat list
// cannot express.
func documentActions(doc *apispec.Doc) ([]apispec.CatalogEntry, []apispec.ActionBundle, error) {
	catalog, err := doc.ActionCatalog()
	if err != nil {
		return nil, nil, err
	}
	bundles, err := doc.ActionBundles()
	if err != nil {
		return nil, nil, err
	}
	return catalog, bundles, nil
}

// discoverLoginTarget runs the SAME resolution `api add` runs — the well-known
// probe, then the conventional path — so a host names the same document to both
// commands, and offers to keep what it found.
func discoverLoginTarget(source string, in io.Reader, out io.Writer, interactive bool) (*loginTarget, error) {
	resolution, err := apispec.Resolve(source, "", apiFetcher())
	if err != nil {
		return nil, err
	}
	authority, err := documentAuthority(resolution.Doc, resolution.Origin, source, out)
	if err != nil {
		return nil, err
	}
	catalog, bundles, err := documentActions(resolution.Doc)
	if err != nil {
		return nil, err
	}
	target := &loginTarget{
		Authority: authority, Document: resolution.Document, Catalog: catalog, Bundles: bundles,
	}

	fmt.Fprintf(out, "Found %s's OpenAPI document at %s (%s).\n", authority, resolution.Document, resolution.Kind)
	if !interactive {
		return target, nil
	}
	name, err := askToRegister(authority, in, out)
	if err != nil {
		return nil, err
	}
	if name == "" {
		return target, nil
	}
	registration, err := fetchAndStore(name, source, "")
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "Registered '%s' — 'dfos api call %s <operation>' calls it.\n", name, name)
	target.Name = registration.Name
	return target, nil
}

// askToRegister offers to keep a discovered API under a local name, returning
// "" when the operator declines. Declining is a first-class answer: a sign-in is
// not a registration, and the credential lands either way.
func askToRegister(authority string, in io.Reader, out io.Writer) (string, error) {
	suggested := suggestedAPIName(authority)
	fmt.Fprintf(out, "Register it locally? Enter a name, or press enter for '%s', or '-' to skip: ", suggested)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read the answer: %w", err)
	}
	answer := strings.TrimSpace(line)
	switch answer {
	case "-", "n", "no":
		return "", nil
	case "":
		answer = suggested
	}
	if err := apispec.ValidateName(answer); err != nil {
		return "", err
	}
	return answer, nil
}

// suggestedAPIName turns an authority into a registry name. An authority is
// already almost one — letters, digits, dots, dashes — so only the port
// separator needs replacing.
func suggestedAPIName(authority string) string {
	name := strings.ReplaceAll(authority, ":", "-")
	if apispec.ValidateName(name) != nil {
		return "api"
	}
	return name
}

// typedAuthority is the authority the operator's own --host value names, or ""
// when it names none.
func typedAuthority(source string) string {
	raw := strings.TrimSpace(source)
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return apispec.NormalizeAuthority(parsed.Scheme, parsed.Host)
}

// documentAuthority folds a document's servers into the ONE authority a
// credential for it names, or into the reason it names none.
//
// Resolution runs under the SAME fetch-origin doctrine `api call` sends under —
// an off-origin `servers` entry names no authority here either — so the
// `api:<host>` a credential is minted for is the host `api call` will look for
// it under. Minting under the document's word and spending under the origin's
// would be a grant that never matches anything.
//
// More than one is refused rather than picked. A grant is `api:<host>` for a
// single host, so a document spanning two authorities is two grants, and
// choosing one for the operator would hand them a credential for a host they
// did not name.
func documentAuthority(doc *apispec.Doc, fallbackOrigin, label string, out io.Writer) (string, error) {
	authorities, notes, err := doc.Authorities(apispec.ServerPolicy{FetchOrigin: fallbackOrigin})
	if err != nil {
		return "", err
	}
	for _, note := range notes {
		fmt.Fprintln(out, note)
	}
	switch len(authorities) {
	case 1:
		return authorities[0], nil
	case 0:
		if authority := typedAuthority(fallbackOrigin); authority != "" {
			return authority, nil
		}
		return "", fmt.Errorf("%s's document describes no operation and names no server — nothing here says which api:<host> a credential would be for", label)
	}
	return "", fmt.Errorf("%s's document spans %d authorities (%s) — a credential is for one api:<host>, so name the one you mean with --host <host>",
		label, len(authorities), strings.Join(authorities, ", "))
}

// ---------------------------------------------------------------------------
// the ask
// ---------------------------------------------------------------------------

// resolveLoginScope decides which action tokens this run asks for.
func resolveLoginScope(target *loginTarget, explicitScope string, allScopes bool,
	in io.Reader, out io.Writer, interactive bool) (string, error) {

	// EXPLICIT BEATS ASK, and it beats an empty catalog too: an operator who
	// typed a token knows something the document may not carry.
	if explicitScope != "" {
		return explicitScope, nil
	}
	if len(target.Catalog) == 0 {
		return "", fmt.Errorf("%s's document advertises no action catalog and no operation names a required action — pass --scope <token> to ask for one verbatim",
			target.Label())
	}
	if allScopes {
		return strings.Join(apispec.CatalogActions(target.Catalog), " "), nil
	}
	if !interactive {
		return "", noScopeChosenError(target)
	}
	return askForScopes(target, in, out)
}

// noScopeChosenError is what a non-interactive run with no explicit scope gets:
// the choices, and both ways to make one. Never a default — a scope picked on a
// person's behalf is a grant they never made.
func noScopeChosenError(target *loginTarget) error {
	var b strings.Builder
	fmt.Fprintf(&b, "no scope chosen for %s and nothing is attached to ask on — %s advertises:\n",
		target.Label(), target.Authority)
	b.WriteString(renderCatalog(target.Catalog, false))
	b.WriteString(renderBundles(target.Bundles, false))
	fmt.Fprintf(&b, "Name what you want with --scope '<token> <token>', or take all of it with --all-scopes.")
	return fmt.Errorf("%s", b.String())
}

// askForScopes presents the catalog and folds the answer into a scope string.
//
// The prompt goes to the writer the caller passed — stderr in a real run —
// because --json keeps stdout to one document, and a menu on stdout would be in
// the middle of it.
func askForScopes(target *loginTarget, in io.Reader, out io.Writer) (string, error) {
	fmt.Fprintf(out, "\n%s advertises %d action(s):\n", target.Authority, len(target.Catalog))
	fmt.Fprint(out, renderCatalog(target.Catalog, true))
	fmt.Fprint(out, renderBundles(target.Bundles, true))
	fmt.Fprintf(out, "Select by number (e.g. 1,3)%s or by token, or press enter for all: ",
		bundleHint(target.Bundles))

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read the selection: %w", err)
	}
	selected, err := selectCatalogActions(target.Catalog, target.Bundles, line)
	if err != nil {
		return "", err
	}
	warnPartialBundles(target.Bundles, selected, out)
	scope := strings.Join(selected, " ")
	fmt.Fprintf(out, "Asking for: %s\n\n", scope)
	return scope, nil
}

// bundleLetters are the group labels. Letters rather than more numbers so a
// group and a token can never be typed for one another.
const bundleLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// renderBundles shows the structure the flat catalog flattened away.
//
// An alphabetized list of tokens is a lie by omission about an AND-alternative:
// the tokens appear as independent choices, so a person can take one of a pair,
// see nothing wrong, and mint a grant that no route it was meant for accepts.
// The groups are printed as groups, and selectable as groups.
func renderBundles(bundles []apispec.ActionBundle, numbered bool) string {
	if len(bundles) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nSome routes need a COMBINATION — every token of the group, or the route refuses:\n")
	for i, bundle := range bundles {
		label := "  "
		if numbered && i < len(bundleLetters) {
			label = fmt.Sprintf("  %c  ", bundleLetters[i])
		}
		fmt.Fprintf(&b, "%s%s   (%s)\n", label, bundle.Label(), describeBundleOperations(bundle))
	}
	return b.String()
}

func bundleHint(bundles []apispec.ActionBundle) string {
	if len(bundles) == 0 {
		return ""
	}
	return ", by group letter (e.g. A),"
}

// describeBundleOperations names the routes a combination is for, capped: the
// evidence is that routes need it, not an inventory of every one of them.
func describeBundleOperations(bundle apispec.ActionBundle) string {
	const shown = 3
	if len(bundle.Operations) <= shown {
		return strings.Join(bundle.Operations, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(bundle.Operations[:shown], ", "), len(bundle.Operations)-shown)
}

// warnPartialBundles says so when a selection took part of a combination.
//
// It is a WARNING and not a refusal: an operator may deliberately want a subset,
// and the host — never this client — decides what a grant covers. But taking
// half a pair by accident is invisible at the moment it matters and obvious three
// commands later as a 403, which is the whole reason the line is here.
func warnPartialBundles(bundles []apispec.ActionBundle, selected []string, out io.Writer) {
	chosen := map[string]bool{}
	for _, token := range selected {
		chosen[token] = true
	}
	for _, bundle := range bundles {
		var missing []string
		covered := 0
		for _, token := range bundle.Actions {
			if chosen[token] {
				covered++
				continue
			}
			missing = append(missing, token)
		}
		if covered == 0 || len(missing) == 0 {
			continue
		}
		fmt.Fprintf(out, "Warning: %s needs %s together; this selection leaves out %s, so the grant will not cover it.\n",
			describeBundleOperations(bundle), bundle.Label(), strings.Join(missing, ", "))
	}
}

// renderCatalog is the menu. Numbers only when there is something to select by
// number; the same list doubles as the error's account of the choices.
func renderCatalog(catalog []apispec.CatalogEntry, numbered bool) string {
	width := 0
	for _, entry := range catalog {
		if len(entry.Action) > width {
			width = len(entry.Action)
		}
	}
	var b strings.Builder
	for i, entry := range catalog {
		if numbered {
			fmt.Fprintf(&b, "  %2d  ", i+1)
		} else {
			fmt.Fprintf(&b, "  ")
		}
		if entry.Description == "" {
			fmt.Fprintf(&b, "%s\n", entry.Action)
			continue
		}
		fmt.Fprintf(&b, "%-*s  %s\n", width, entry.Action, entry.Description)
	}
	return b.String()
}

// selectCatalogActions folds an answer into the tokens it names, in CATALOG
// order rather than the order they were typed — the scope string is a set, and
// keeping it in the document's order keeps two runs that chose the same actions
// spelling them the same way.
//
// A field is an index, a GROUP LETTER, or a token. All three are accepted
// because all three are in front of the operator: the numbers and letters are
// what the menu offered, and the tokens are what they will see again in the
// credential. A group letter selects every token of that combination at once,
// which is the only spelling that cannot take half of one by accident.
func selectCatalogActions(catalog []apispec.CatalogEntry, bundles []apispec.ActionBundle, answer string) ([]string, error) {
	fields := strings.FieldsFunc(answer, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) == 0 {
		return apispec.CatalogActions(catalog), nil
	}
	if len(fields) == 1 && strings.EqualFold(fields[0], "all") {
		return apispec.CatalogActions(catalog), nil
	}

	chosen := map[string]bool{}
	for _, field := range fields {
		if index, err := strconv.Atoi(field); err == nil {
			if index < 1 || index > len(catalog) {
				return nil, fmt.Errorf("%d is not one of the %d actions listed", index, len(catalog))
			}
			chosen[catalog[index-1].Action] = true
			continue
		}
		if bundle, ok := bundleForLetter(bundles, field); ok {
			for _, token := range bundle.Actions {
				chosen[token] = true
			}
			continue
		}
		found := false
		for _, entry := range catalog {
			if entry.Action == field {
				chosen[entry.Action] = true
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("%q is neither a number in the list, a group letter, nor an advertised action token", field)
		}
	}

	selected := make([]string, 0, len(chosen))
	for _, entry := range catalog {
		if chosen[entry.Action] {
			selected = append(selected, entry.Action)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("nothing selected — name at least one action, or press enter for all")
	}
	return selected, nil
}

// bundleForLetter resolves a single-letter field to the group it labels.
func bundleForLetter(bundles []apispec.ActionBundle, field string) (apispec.ActionBundle, bool) {
	if len(field) != 1 {
		return apispec.ActionBundle{}, false
	}
	index := strings.IndexByte(bundleLetters, strings.ToUpper(field)[0])
	if index < 0 || index >= len(bundles) {
		return apispec.ActionBundle{}, false
	}
	return bundles[index], true
}

// ---------------------------------------------------------------------------
// what came back
// ---------------------------------------------------------------------------

// credentialNamesResource reports whether a credential's attenuation names the
// resource — the check `api call` will make when it looks for something
// spendable against this host.
//
// The RESOURCE, never `aud`. A login credential's audience is this
// installation's client DID in every case, so an audience check says nothing
// about which host the grant is for; the host lives in `att[].resource` as
// `api:<host>`, and that is the only place it lives.
func credentialNamesResource(token, resource string) (bool, []string) {
	_, payload, err := protocol.DecodeJWSUnsafe(strings.TrimSpace(token))
	if err != nil {
		return false, nil
	}
	var resources []string
	seen := map[string]bool{}
	found := false
	for _, entry := range protocol.ParseAtt(payload) {
		if entry.Resource == resource {
			found = true
		}
		if entry.Resource != "" && !seen[entry.Resource] {
			seen[entry.Resource] = true
			resources = append(resources, entry.Resource)
		}
	}
	return found, resources
}

// warnCredentialHostMismatch says so when a stored credential does not name the
// host it was asked for.
//
// A WARNING, not a refusal. The artifact verified, it was issued to this
// installation, and it may well be spendable somewhere — but `api call` selects
// on the `api:<host>` resource, so one that names another host will not be found
// for this one, and discovering that as "no stored credential covers api:x"
// three commands later is the papercut this line exists to prevent.
func warnCredentialHostMismatch(token string, target *loginTarget, out io.Writer) {
	if target == nil || token == "" {
		return
	}
	found, resources := credentialNamesResource(token, target.Resource())
	if found {
		return
	}
	held := "nothing"
	if len(resources) > 0 {
		held = strings.Join(resources, ", ")
	}
	fmt.Fprintf(out, "Warning: the stored credential's attenuation does not name %s (it names %s).\n",
		target.Resource(), held)
	fmt.Fprintf(out, "         'dfos api call' selects a credential by that resource, so it will not find this one for %s.\n",
		target.Authority)
}
