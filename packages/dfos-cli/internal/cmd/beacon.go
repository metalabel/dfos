package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
	"github.com/metalabel/dfos/packages/dfos-cli/internal/store"
	"github.com/spf13/cobra"
)

func newBeaconCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "beacon",
		Short:   "Merkle root announcements",
		GroupID: "beacon",
	}
	cmd.AddCommand(newBeaconAnnounceCmd())
	cmd.AddCommand(newBeaconShowCmd())
	cmd.AddCommand(newBeaconCountersignCmd())
	return cmd
}

func newBeaconAnnounceCmd() *cobra.Command {
	var relayName string

	cmd := &cobra.Command{
		Use:   "announce <contentId...>",
		Short: "Build merkle root over content IDs, sign, and optionally submit",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			merkleRoot := protocol.BuildMerkleRoot(args)

			// use controller key for beacons
			if len(id.State.ControllerKeys) == 0 {
				return fmt.Errorf("identity has no controller keys")
			}
			controllerKeyID := id.State.ControllerKeys[0].ID
			kid := id.DID + "#" + controllerKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + controllerKeyID)
			if err != nil {
				return err
			}

			jwsToken, beaconCID, err := protocol.SignBeacon(id.DID, merkleRoot, kid, privKey)
			if err != nil {
				return err
			}

			// decode the payload for storage
			_, payload, _ := protocol.DecodeJWSUnsafe(jwsToken)

			sb := &store.StoredBeacon{
				DID:       id.DID,
				JWSToken:  jwsToken,
				BeaconCID: beaconCID,
				Payload:   payload,
				Local: store.LocalMeta{
					Origin: "created",
				},
			}

			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn != "" {
				c, _, err := getRelayClient(rn)
				if err != nil {
					return err
				}
				if err := publishIdentityIfNeeded(id, rn, c); err != nil {
					return err
				}
				results, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return err
				}
				if len(results) > 0 && results[0].Status == "rejected" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}
				sb.Local.PublishedTo = []string{rn}
			}

			store.SaveBeacon(sb)

			if jsonFlag {
				outputJSON(map[string]any{
					"beaconCID":  beaconCID,
					"merkleRoot": merkleRoot,
					"contentIds": args,
					"did":        id.DID,
				})
			} else {
				fmt.Printf("Beacon announced:\n")
				fmt.Printf("  Beacon CID:   %s\n", beaconCID)
				fmt.Printf("  Merkle root:  %s\n", merkleRoot)
				fmt.Printf("  Content IDs:  %s\n", strings.Join(args, ", "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&relayName, "relay", "", "Submit to relay")
	return cmd
}

func newBeaconShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [did|name]",
		Short: "Show latest beacon for an identity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var did string
			if len(args) > 0 {
				target := args[0]
				if idByName, _ := store.FindIdentityByName(target); idByName != nil {
					did = idByName.DID
				} else {
					did = target
					if !strings.HasPrefix(did, "did:") {
						did = "did:dfos:" + did
					}
				}
			} else {
				_, id, err := requireIdentity()
				if err != nil {
					return err
				}
				did = id.DID
			}

			// try local first
			b, _ := store.LoadBeacon(did)
			if b != nil {
				if jsonFlag {
					outputJSON(b)
				} else {
					fmt.Printf("DID:         %s\n", b.DID)
					fmt.Printf("Beacon CID:  %s\n", b.BeaconCID)
					if mr, ok := b.Payload["merkleRoot"].(string); ok {
						fmt.Printf("Merkle Root: %s\n", mr)
					}
					if ca, ok := b.Payload["createdAt"].(string); ok {
						fmt.Printf("Created:     %s\n", ca)
					}
				}
				return nil
			}

			// try relay
			ctx, _ := resolveCtx()
			if ctx != nil && ctx.RelayURL != "" {
				c, _, _ := getRelayClient(ctx.RelayName)
				data, err := c.GetBeacon(did)
				if err == nil {
					if jsonFlag {
						d, _ := json.MarshalIndent(data, "", "  ")
						fmt.Println(string(d))
					} else {
						fmt.Printf("DID:         %s\n", did)
						if cid, ok := data["beaconCID"].(string); ok {
							fmt.Printf("Beacon CID:  %s\n", cid)
						}
						if p, ok := data["payload"].(map[string]any); ok {
							if mr, ok := p["merkleRoot"].(string); ok {
								fmt.Printf("Merkle Root: %s\n", mr)
							}
						}
					}
					return nil
				}
			}

			return fmt.Errorf("no beacon found for %s", did)
		},
	}
}

func newBeaconCountersignCmd() *cobra.Command {
	var relayName string
	cmd := &cobra.Command{
		Use:   "countersign <did|name>",
		Short: "Countersign someone's beacon",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			var targetDID string
			if idByName, _ := store.FindIdentityByName(target); idByName != nil {
				targetDID = idByName.DID
			} else {
				targetDID = target
				if !strings.HasPrefix(targetDID, "did:") {
					targetDID = "did:dfos:" + targetDID
				}
			}

			_, id, err := requireIdentity()
			if err != nil {
				return err
			}

			// get the beacon CID — from local store or relay
			var beaconCID string
			b, _ := store.LoadBeacon(targetDID)
			if b != nil {
				beaconCID = b.BeaconCID
			} else {
				ctx, _ := resolveCtx()
				if ctx != nil && ctx.RelayURL != "" {
					c, _, _ := getRelayClient(ctx.RelayName)
					data, err := c.GetBeacon(targetDID)
					if err != nil {
						return fmt.Errorf("beacon not found for %s", targetDID)
					}
					cid, _ := data["beaconCID"].(string)
					beaconCID = cid
				}
			}
			if beaconCID == "" {
				return fmt.Errorf("beacon not found for %s", targetDID)
			}

			// sign countersignature with our auth key
			authKeyID := id.State.AuthKeys[0].ID
			kid := id.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(id.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			csToken, _, err := protocol.SignCountersign(id.DID, beaconCID, kid, privKey)
			if err != nil {
				return err
			}

			// submit to relay
			rn := relayName
			if rn == "" {
				rn = relayFlag
			}
			if rn == "" {
				ctx, _ := resolveCtx()
				if ctx != nil {
					rn = ctx.RelayName
				}
			}
			if rn != "" {
				c, _, _ := getRelayClient(rn)
				results, err := c.SubmitOperations([]string{csToken})
				if err != nil {
					return err
				}
				if len(results) > 0 && results[0].Status == "rejected" {
					return fmt.Errorf("relay rejected: %s", results[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "countersigned", "beaconDID": targetDID, "witnessDID": id.DID})
			} else {
				fmt.Printf("Beacon countersigned for %s\n", targetDID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&relayName, "relay", "", "Submit countersignature to relay")
	return cmd
}
