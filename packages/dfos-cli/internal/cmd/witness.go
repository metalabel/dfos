package cmd

import (
	"fmt"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/protocol"
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

			opData, err := c.GetOperation(operationCID)
			if err != nil {
				return fmt.Errorf("fetch operation: %w", err)
			}

			jwsToken, ok := opData["jwsToken"].(string)
			if !ok {
				return fmt.Errorf("operation has no JWS token")
			}

			// sign countersignature
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			csToken, err := protocol.SignCountersignature(jwsToken, kid, privKey)
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
