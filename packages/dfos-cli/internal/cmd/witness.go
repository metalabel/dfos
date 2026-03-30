package cmd

import (
	"fmt"
	"strings"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newWitnessCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "witness <operationCID>",
		Short: "Countersign an operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			operationCID := args[0]

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			csToken, _, err := protocol.SignCountersign(chain.DID, operationCID, kid, privKey)
			if err != nil {
				return err
			}

			// ingest locally
			results := lr.Relay.Ingest([]string{csToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{csToken})
				if err != nil {
					return err
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "countersigned", "operationCID": operationCID, "witnessDID": chain.DID})
			} else {
				fmt.Printf("Operation %s countersigned by %s\n", operationCID, chain.DID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push countersignature to peer")
	return cmd
}

func newCountersigsCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "countersigs <cid>",
		Short: "Show countersignatures for an operation or beacon CID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cid := args[0]

			// try local relay first
			lr, lrErr := getRelay()
			if lrErr == nil {
				tokens, err := lr.Store.GetCountersignatures(cid)
				if err == nil && len(tokens) > 0 {
					if jsonFlag {
						outputJSON(map[string]any{"countersignatures": tokens})
						return nil
					}
					fmt.Printf("Countersignatures for %s (%d):\n\n", cid, len(tokens))
					for i, csStr := range tokens {
						h, _, _ := protocol.DecodeJWSUnsafe(csStr)
						witness := "?"
						if h != nil && h.Kid != "" {
							if idx := strings.Index(h.Kid, "#"); idx > 0 {
								witness = h.Kid[:idx]
							} else {
								witness = h.Kid
							}
						}
						fmt.Printf("  [%d] witness: %s\n", i, witness)
					}
					return nil
				}
			}

			// fall through to peer
			ctx, _ := resolveCtx()
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn == "" && ctx != nil {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("--peer is required")
			}

			c, _, err := getPeerClient(rn)
			if err != nil {
				return err
			}

			data, err := c.GetCountersignatures(cid)
			if err != nil {
				return fmt.Errorf("fetch countersignatures: %w", err)
			}

			csArr, _ := data["countersignatures"].([]any)

			if jsonFlag {
				outputJSON(data)
				return nil
			}

			if len(csArr) == 0 {
				fmt.Printf("No countersignatures for %s\n", cid)
				return nil
			}

			fmt.Printf("Countersignatures for %s (%d):\n\n", cid, len(csArr))
			for i, cs := range csArr {
				csStr, ok := cs.(string)
				if !ok {
					continue
				}
				h, _, _ := protocol.DecodeJWSUnsafe(csStr)
				witness := "?"
				if h != nil && h.Kid != "" {
					if idx := strings.Index(h.Kid, "#"); idx > 0 {
						witness = h.Kid[:idx]
					} else {
						witness = h.Kid
					}
				}
				fmt.Printf("  [%d] witness: %s\n", i, witness)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Peer to query")
	return cmd
}
