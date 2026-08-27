package cmd

import (
	"reflect"
	"testing"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
)

func TestForgetIdentityConfig(t *testing.T) {
	tests := []struct {
		name              string
		target            string
		cfg               *config.Config
		wantName          string
		wantDID           string
		wantContexts      []string
		wantActiveCleared bool
		wantActive        string
		wantIdentityCount int
		wantErr           bool
	}{
		{
			name:   "named identity removes referencing contexts and active selection",
			target: "alice",
			cfg: &config.Config{
				ActiveContext: "work",
				Identities: map[string]config.IdentityConfig{
					"alice": {DID: testLoginSubject},
					"bob":   {DID: testLoginOther},
				},
				Contexts: map[string]config.ContextConfig{
					"work":   {Identity: "alice", Relay: "prod"},
					"direct": {Identity: testLoginSubject, Relay: "prod"},
					"other":  {Identity: "bob", Relay: "prod"},
				},
			},
			wantName:          "alice",
			wantDID:           testLoginSubject,
			wantContexts:      []string{"direct", "work"},
			wantActiveCleared: true,
			wantActive:        "",
			wantIdentityCount: 1,
		},
		{
			name:   "bare DID leaves registrations and clears inline active context",
			target: testLoginSubject,
			cfg: &config.Config{
				ActiveContext: testLoginSubject + "@prod",
				Identities: map[string]config.IdentityConfig{
					"bob": {DID: testLoginOther},
				},
				Contexts: map[string]config.ContextConfig{
					"direct": {Identity: testLoginSubject, Relay: "prod"},
					"other":  {Identity: "bob", Relay: "prod"},
				},
			},
			wantDID:           testLoginSubject,
			wantContexts:      []string{"direct"},
			wantActiveCleared: true,
			wantActive:        "",
			wantIdentityCount: 1,
		},
		{
			name:   "unknown name is rejected",
			target: "missing",
			cfg: &config.Config{
				Identities: map[string]config.IdentityConfig{},
				Contexts:   map[string]config.ContextConfig{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := forgetIdentityConfig(tt.cfg, tt.target)
			if (err != nil) != tt.wantErr {
				t.Fatalf("forgetIdentityConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if result.Name != tt.wantName || result.DID != tt.wantDID {
				t.Fatalf("result identity = (%q, %q), want (%q, %q)", result.Name, result.DID, tt.wantName, tt.wantDID)
			}
			if !reflect.DeepEqual(result.RemovedContexts, tt.wantContexts) {
				t.Fatalf("removed contexts = %v, want %v", result.RemovedContexts, tt.wantContexts)
			}
			if result.ActiveContextCleared != tt.wantActiveCleared || tt.cfg.ActiveContext != tt.wantActive {
				t.Fatalf("active = %q, cleared=%v; want %q, %v", tt.cfg.ActiveContext, result.ActiveContextCleared, tt.wantActive, tt.wantActiveCleared)
			}
			if len(tt.cfg.Identities) != tt.wantIdentityCount {
				t.Fatalf("identity count = %d, want %d", len(tt.cfg.Identities), tt.wantIdentityCount)
			}
			for _, removed := range tt.wantContexts {
				if _, ok := tt.cfg.Contexts[removed]; ok {
					t.Fatalf("context %q was not removed", removed)
				}
			}
		})
	}
}
