package cmd

// Raw-passthrough tests. `dfos relay call` is the spelling, and `dfos peer call`
// is that same command under the peer group's own name.
//
// These mutate the package globals (cfg, relayFlag), so as with the
// multi-device tests they MUST NOT run with t.Parallel().

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/spf13/cobra"
)

// setupRelayCall points the resolved context at a loopback server that echoes
// the request it received as JSON. The returned counter is the number of
// requests that server has answered, so a test can assert that a command made
// no request at all rather than only that its output was empty.
func setupRelayCall(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	// The context resolves from env before config, so clear the overrides a
	// developer's shell may carry.
	t.Setenv("DFOS_AS", "")
	t.Setenv("DFOS_RELAY", "")

	hits := &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		echo, _ := json.Marshal(map[string]string{
			"method":     r.Method,
			"path":       r.URL.Path,
			"body":       string(body),
			"testHeader": r.Header.Get("X-Test"),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(echo)
	}))

	prevCfg, prevRelay, prevAs := cfg, relayFlag, asFlag
	cfg = &config.Config{
		Relays:     map[string]config.RelayConfig{"test": {URL: srv.URL}},
		Identities: map[string]config.IdentityConfig{},
	}
	relayFlag, asFlag = "test", ""
	t.Cleanup(func() {
		srv.Close()
		cfg, relayFlag, asFlag = prevCfg, prevRelay, prevAs
	})
	return srv, hits
}

// captureStdio swaps the process's stdout and stderr for pipes around fn. The
// passthrough writes its response with fmt.Printf, so it has to be intercepted
// at the process level rather than through cobra's writers.
func captureStdio(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	fn()

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	outBytes, _ := io.ReadAll(rOut)
	errBytes, _ := io.ReadAll(rErr)
	return string(outBytes), string(errBytes)
}

// runThroughRoot executes args against a bare root carrying only the command
// under test, so cobra's own dispatch runs without the real root's state lock
// and config load.
func runThroughRoot(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, runErr error) {
	t.Helper()
	root := &cobra.Command{Use: "dfos", SilenceUsage: true, SilenceErrors: true}
	// The real root's groups, so a grouped command can be attached here at all.
	for _, id := range []string{"identity", "content", "auth", "peer", "config"} {
		root.AddGroup(&cobra.Group{ID: id, Title: id})
	}
	root.AddCommand(cmd)
	root.SetArgs(args)
	stdout, stderr = captureStdio(t, func() { runErr = root.Execute() })
	return stdout, stderr, runErr
}

func TestRelayCall(t *testing.T) {
	const wantBody = "{\n  \"body\": \"\",\n  \"method\": \"GET\",\n  \"path\": \"/proof/v1/stats\",\n  \"testHeader\": \"\"\n}\n"

	t.Run("relay call performs the request", func(t *testing.T) {
		setupRelayCall(t)
		stdout, stderr, err := runThroughRoot(t, newRelayCallCmd(), "call", "GET", "/proof/v1/stats")
		if err != nil {
			t.Fatalf("relay call: %v", err)
		}
		if stdout != wantBody {
			t.Fatalf("stdout = %q, want %q", stdout, wantBody)
		}
		if stderr != "" {
			t.Fatalf("stderr = %q, want empty", stderr)
		}
	})

	t.Run("the request flags reach the wire", func(t *testing.T) {
		setupRelayCall(t)
		stdout, _, err := runThroughRoot(t, newRelayCallCmd(), "call", "POST", "/proof/v1/operations",
			"--body", `{"operations":[]}`, "-i", "-H", "X-Test: yes")
		if err != nil {
			t.Fatalf("relay call: %v", err)
		}
		if !strings.HasPrefix(stdout, "HTTP 200\n") {
			t.Fatalf("--include output = %q", stdout)
		}
		if !strings.Contains(stdout, `"body": "{\"operations\":[]}"`) {
			t.Fatalf("--body did not reach the request: %q", stdout)
		}
		if !strings.Contains(stdout, `"testHeader": "yes"`) {
			t.Fatalf("-H did not reach the request: %q", stdout)
		}
	})

	t.Run("invalid method names the command", func(t *testing.T) {
		setupRelayCall(t)
		call := newRelayCallCmd()
		err := call.RunE(call, []string{"BREW", "/x"})
		if err == nil || !strings.Contains(err.Error(), "usage: dfos relay call <METHOD> <path>") {
			t.Fatalf("relay call error = %v", err)
		}
	})
}

// `dfos api` names a registered operation. Two bare arguments are a raw HTTP
// request, which is `dfos relay call` — and a script still typing the old form
// has to hear about it in the exit code, not be handed a help page and a zero.
func TestAPITakesNoRawRequest(t *testing.T) {
	_, hits := setupRelayCall(t)
	_, _, err := runThroughRoot(t, newAPICmd(), "api", "GET", "/proof/v1/stats")
	if err == nil {
		t.Fatal("dfos api GET /x still ran")
	}
	if !strings.Contains(err.Error(), "unknown command") || !strings.Contains(err.Error(), "GET") {
		t.Fatalf("error = %v, want an unknown-command error naming GET", err)
	}
	// The refusal has to happen before the wire, not after it: a passthrough
	// that requests and then errors would still have reached the peer.
	if n := hits.Load(); n != 0 {
		t.Fatalf("the peer answered %d request(s); the old form is meant to reach nothing", n)
	}
}

// The subcommands are the whole of `api`, and they must stay discoverable: a
// deprecated or hidden parent takes its subcommands out of help with it.
func TestAPISubcommandsResolve(t *testing.T) {
	api := newAPICmd()
	if api.Deprecated != "" || api.Hidden {
		t.Fatalf("api must be visible in help (deprecated=%q hidden=%v)", api.Deprecated, api.Hidden)
	}
	for _, name := range []string{"add", "list", "rm", "refresh", "call"} {
		found, _, err := api.Find([]string{name})
		if err != nil || found.Name() != name {
			t.Fatalf("api %s did not resolve: %v", name, err)
		}
	}
}

func TestRelayCallIsReachableUnderBothSpellings(t *testing.T) {
	root := NewRootCmd()

	for _, spelling := range [][]string{{"relay", "call"}, {"peer", "call"}} {
		found, _, err := root.Find(spelling)
		if err != nil {
			t.Fatalf("find %v: %v", spelling, err)
		}
		if found.Name() != "call" {
			t.Fatalf("%v resolved to %q", spelling, found.CommandPath())
		}
	}

	// The `relay` alias of the peer group must keep resolving its other
	// subcommands — `call` is added to that group, never shadowing it.
	for _, spelling := range [][]string{{"relay", "gc"}, {"relay", "list"}, {"peer", "add"}} {
		found, _, err := root.Find(spelling)
		if err != nil {
			t.Fatalf("find %v: %v", spelling, err)
		}
		if found.Name() != spelling[1] {
			t.Fatalf("%v resolved to %q", spelling, found.CommandPath())
		}
	}
}
