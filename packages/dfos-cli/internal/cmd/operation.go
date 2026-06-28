package cmd

import (
	"fmt"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newOperationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "operation",
		Aliases: []string{"op"},
		Short:   "Inspect protocol operations",
	}
	cmd.AddCommand(newOperationShowCmd())
	return cmd
}

// newOperationShowCmd resolves a single operation by CID and renders its decoded
// header + payload. Local store first, then an explicit --peer (mirrors the
// countersigs local-then-peer pattern — the op may only exist remotely).
func newOperationShowCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "show <cid>",
		Short: "Show a single operation by CID (decoded signer, type, chain)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cid := args[0]

			// local store first
			if lr, err := getRelay(); err == nil {
				if op, err := lr.Store.GetOperation(cid); err == nil && op != nil {
					return renderOperation(op.CID, op.JWSToken, op.ChainType, op.ChainID)
				}
			}

			// peer fallback
			ctx, _ := resolveCtx()
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" && ctx != nil {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("operation %s not found locally; --peer is required to query a peer", cid)
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}
			data, err := c.GetOperation(cid)
			if err != nil {
				return fmt.Errorf("fetch operation: %w", err)
			}
			servedCID, _ := data["cid"].(string)
			if servedCID == "" {
				servedCID = cid
			}
			jws, _ := data["jwsToken"].(string)
			chainType, _ := data["chainType"].(string)
			chainID, _ := data["chainId"].(string)
			return renderOperation(servedCID, jws, chainType, chainID)
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to query when the op isn't local")
	return cmd
}

// renderOperation decodes the JWS (unverified — display only) and prints the
// operation's identifying facts. Used by both the local and peer paths.
func renderOperation(cid, jws, chainType, chainID string) error {
	h, p, _ := protocol.DecodeJWSUnsafe(jws)

	opType := ""
	previous := ""
	created := ""
	if p != nil {
		if t, ok := p["type"].(string); ok {
			opType = t
		}
		if prev, ok := p["previousOperationCID"].(string); ok {
			previous = prev
		}
		if c, ok := p["createdAt"].(string); ok {
			created = c
		}
	}
	signer := ""
	if h != nil {
		signer = didFromKid(h.Kid)
	}

	if jsonFlag {
		out := map[string]any{
			"cid":       cid,
			"chainType": chainType,
			"chainId":   chainID,
		}
		if opType != "" {
			out["type"] = opType
		}
		if signer != "" {
			out["signer"] = signer
		}
		if h != nil {
			out["kid"] = h.Kid
		}
		if previous != "" {
			out["previousOperationCID"] = previous
		}
		if p != nil {
			out["payload"] = p
		}
		outputJSON(out)
		return nil
	}

	fmt.Printf("Operation:   %s\n", cid)
	if opType != "" {
		fmt.Printf("Type:        %s\n", opType)
	}
	if chainType != "" || chainID != "" {
		fmt.Printf("Chain:       %s %s\n", chainType, chainID)
	}
	if signer != "" {
		fmt.Printf("Signer:      %s\n", signer)
	}
	if created != "" {
		fmt.Printf("Created:     %s\n", created)
	}
	if previous != "" {
		fmt.Printf("Previous:    %s\n", previous)
	}
	return nil
}
