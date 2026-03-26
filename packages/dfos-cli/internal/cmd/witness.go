package cmd

import (
	"fmt"
	"strings"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/spf13/cobra"
)

func newWitnessCmd() *cobra.Command {
	var relayName string
	cmd := &cobra.Command{
		Use:   "witness <operationCID>",
		Short: "Countersign an operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			operationCID := args[0]

			ctx, id, err := requireIdentity()
			if err != nil {
				return err
			}

			// fetch the operation from relay
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("--relay is required to fetch the operation")
			}

			c, _, err := getRelayClient(rn)
			if err != nil {
				return err
			}

			// sign countersignature — new model only needs the target CID
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			csToken, _, err := protocol.SignCountersign(id.DID, operationCID, kid, privKey)
			if err != nil {
				return err
			}

			// submit
			results, err := c.SubmitOperations([]string{csToken})
			if err != nil {
				return err
			}
			if len(results) > 0 && results[0].Status != "accepted" {
				return fmt.Errorf("relay rejected: %s", results[0].Error)
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "countersigned", "operationCID": operationCID, "witnessDID": id.DID})
			} else {
				fmt.Printf("Operation %s countersigned by %s\n", operationCID, id.DID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&relayName, "relay", "", "Relay to fetch operation from and submit to")
	return cmd
}

func newCountersigsCmd() *cobra.Command {
	var relayName string
	cmd := &cobra.Command{
		Use:   "countersigs <cid>",
		Short: "Show countersignatures for an operation or beacon CID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cid := args[0]

			ctx, _ := resolveCtx()
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" && ctx != nil {
				rn = ctx.RelayName
			}
			if rn == "" {
				return fmt.Errorf("--relay is required")
			}

			c, _, err := getRelayClient(rn)
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
					// extract DID from kid (did:dfos:xxx#key_yyy → did:dfos:xxx)
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
	cmd.Flags().StringVar(&relayName, "relay", "", "Relay to query")
	return cmd
}
