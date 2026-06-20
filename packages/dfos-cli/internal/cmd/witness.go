package cmd

import (
	"fmt"
	"strings"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newWitnessCmd() *cobra.Command {
	var peerName string
	var relation string
	cmd := &cobra.Command{
		Use:   "witness <operationCID>",
		Short: "Countersign an operation (solemnize it with a collective endorsement)",
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

			kid, err := selectHeldKey(chain.DID, chain.State.AuthKeys, "auth")
			if err != nil {
				return err
			}
			privKey, err := keys.GetPrivateKey(kid)
			if err != nil {
				return err
			}

			csToken, _, err := protocol.SignCountersignWithRelation(chain.DID, operationCID, relation, kid, privKey)
			if err != nil {
				return err
			}

			// push to peer first — the target may only exist remotely
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
			if rn == "" {
				return fmt.Errorf("--peer is required to submit the countersignature")
			}
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

			// best-effort local ingest — may fail if target isn't local, that's ok
			lr.Relay.Ingest([]string{csToken})

			if jsonFlag {
				out := map[string]any{"status": "countersigned", "operationCID": operationCID, "witnessDID": chain.DID}
				if relation != "" {
					out["relation"] = relation
				}
				outputJSON(out)
			} else {
				if relation != "" {
					fmt.Printf("Operation %s countersigned by %s (relation: %s)\n", operationCID, chain.DID, relation)
				} else {
					fmt.Printf("Operation %s countersigned by %s\n", operationCID, chain.DID)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push countersignature to peer")
	cmd.Flags().StringVar(&relation, "relation", "", "Open-namespace relation tag naming the nature of the endorsement (e.g. endorses, coauthors); 1..64 chars")
	return cmd
}

func newCountersigsCmd() *cobra.Command {
	var peerName string
	cmd := &cobra.Command{
		Use:   "countersigs <cid>",
		Short: "Show countersignatures for an operation CID",
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
