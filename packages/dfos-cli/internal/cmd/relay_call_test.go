package cmd

// Raw-passthrough tests. `dfos relay call` is the spelling; `dfos api` is the
// deprecated one that forwards into the same implementation. The point of the
// pair is that the forward is byte-identical on stdout and costs exactly one
// extra line on stderr.
//
// These mutate the package globals (cfg, peerFlag), so as with the multi-device
// tests they MUST NOT run with t.Parallel().

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	"github.com/spf13/cobra"
)

// setupRelayCall points the resolved context at a loopback server that echoes
// the request it received as JSON.
func setupRelayCall(t *testing.T) *httptest.Server {
	t.Helper()

	// The context resolves from env before config, so clear the overrides a
	// developer's shell may carry.
	t.Setenv("DFOS_CONTEXT", "")
	t.Setenv("DFOS_IDENTITY", "")
	t.Setenv("DFOS_RELAY", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	prevCfg, prevPeer, prevCtx, prevID := cfg, peerFlag, ctxFlag, identityFlag
	cfg = &config.Config{
		Relays:     map[string]config.RelayConfig{"test": {URL: srv.URL}},
		Identities: map[string]config.IdentityConfig{},
		Contexts:   map[string]config.ContextConfig{},
	}
	peerFlag, ctxFlag, identityFlag = "test", "", ""
	t.Cleanup(func() {
		srv.Close()
		cfg, peerFlag, ctxFlag, identityFlag = prevCfg, prevPeer, prevCtx, prevID
	})
	return srv
}

// captureStdio swaps the process's stdout and stderr for pipes around fn. The
// passthrough writes its response with fmt.Printf and cobra writes its
// deprecation line to os.Stderr, so both have to be intercepted at the process
// level rather than through cobra's writers.
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
// under test, so cobra's own dispatch (and its deprecation notice) runs without
// the real root's state lock and config load.
func runThroughRoot(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, runErr error) {
	t.Helper()
	root := &cobra.Command{Use: "dfos", SilenceUsage: true, SilenceErrors: true}
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

	t.Run("api forwards to the same implementation and warns once", func(t *testing.T) {
		setupRelayCall(t)
		stdout, stderr, err := runThroughRoot(t, newAPICmd(), "api", "GET", "/proof/v1/stats")
		if err != nil {
			t.Fatalf("api: %v", err)
		}
		if stdout != wantBody {
			t.Fatalf("stdout = %q, want %q (identical to relay call)", stdout, wantBody)
		}
		lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("stderr = %q, want exactly one line", stderr)
		}
		if !strings.Contains(lines[0], "deprecated") || !strings.Contains(lines[0], "dfos relay call <METHOD> <path>") {
			t.Fatalf("deprecation line = %q", lines[0])
		}
	})

	t.Run("api binds the passthrough flags", func(t *testing.T) {
		setupRelayCall(t)
		stdout, _, err := runThroughRoot(t, newAPICmd(), "api", "POST", "/proof/v1/operations",
			"--body", `{"operations":[]}`, "-i", "-H", "X-Test: yes")
		if err != nil {
			t.Fatalf("api: %v", err)
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

	t.Run("invalid method names the spelling that was typed", func(t *testing.T) {
		setupRelayCall(t)
		call := newRelayCallCmd()
		err := call.RunE(call, []string{"BREW", "/x"})
		if err == nil || !strings.Contains(err.Error(), "usage: dfos relay call <METHOD> <path>") {
			t.Fatalf("relay call error = %v", err)
		}
		api := newAPICmd()
		err = api.RunE(api, []string{"BREW", "/x"})
		if err == nil || !strings.Contains(err.Error(), "usage: dfos api <METHOD> <path>") {
			t.Fatalf("api error = %v", err)
		}
	})

	t.Run("api is a command, not an alias, and stays open to subcommands", func(t *testing.T) {
		api := newAPICmd()
		if api.Deprecated == "" || !strings.Contains(api.Deprecated, "dfos relay call") {
			t.Fatalf("api Deprecated = %q", api.Deprecated)
		}
		// ArbitraryArgs is what lets a future subcommand sit beside the legacy
		// two-argument form: cobra dispatches the subcommand first and only
		// falls through to RunE for the raw form.
		if err := api.Args(api, []string{"add", "https://example.test/openapi.json"}); err != nil {
			t.Fatalf("api arg validation rejects a non-raw invocation: %v", err)
		}
		if err := api.RunE(api, []string{"GET"}); err == nil || !strings.Contains(err.Error(), "usage: dfos api") {
			t.Fatalf("wrong-arity error = %v", err)
		}
	})
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
