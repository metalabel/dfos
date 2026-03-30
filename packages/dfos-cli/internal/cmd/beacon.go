package cmd

import (
	"fmt"
	"strings"

	"github.com/metalabel/dfos/packages/dfos-cli/internal/config"
	protocol "github.com/metalabel/dfos/packages/dfos-protocol-go"
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
	var peerName string

	cmd := &cobra.Command{
		Use:   "announce <contentId...>",
		Short: "Build merkle root over content IDs, sign, and optionally submit",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			merkleRoot := protocol.BuildMerkleRoot(args)

			if len(chain.State.ControllerKeys) == 0 {
				return fmt.Errorf("identity has no controller keys")
			}
			controllerKeyID := chain.State.ControllerKeys[0].ID
			kid := chain.DID + "#" + controllerKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + controllerKeyID)
			if err != nil {
				return err
			}

			jwsToken, beaconCID, err := protocol.SignBeacon(chain.DID, merkleRoot, kid, privKey)
			if err != nil {
				return err
			}

			// ingest into local relay
			results := lr.Relay.Ingest([]string{jwsToken})
			if len(results) > 0 && results[0].Status == "rejected" {
				return fmt.Errorf("local relay rejected: %s", results[0].Error)
			}

			// push to peer
			rn := peerName
			if rn == "" {
				rn = peerFlag
			}
			if rn != "" {
				c, _, err := getPeerClient(rn)
				if err != nil {
					return err
				}
				if err := publishIdentityIfNeeded(chain, rn, c); err != nil {
					return err
				}
				peerResults, err := c.SubmitOperations([]string{jwsToken})
				if err != nil {
					return err
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{
					"beaconCID":  beaconCID,
					"merkleRoot": merkleRoot,
					"contentIds": args,
					"did":        chain.DID,
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
	cmd.Flags().StringVar(&peerName, "peer", "", "Push to peer")
	return cmd
}

func newBeaconShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show [did|name]",
		Short: "Show latest beacon for an identity",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lr, err := getRelay()
			if err != nil {
				return err
			}

			var did string
			if len(args) > 0 {
				did = resolveIdentityDID(args[0])
			} else {
				_, chain, err := requireIdentity()
				if err != nil {
					return err
				}
				did = chain.DID
			}

			// try local relay
			beacon, _ := lr.Relay.GetBeacon(did)
			if beacon != nil {
				if jsonFlag {
					outputJSON(beacon)
				} else {
					name := config.FindIdentityName(cfg, did)
					label := did
					if name != "" {
						label = did + " (" + name + ")"
					}
					fmt.Printf("DID:         %s\n", label)
					fmt.Printf("Beacon CID:  %s\n", beacon.BeaconCID)
					fmt.Printf("Merkle Root: %s\n", beacon.Payload.MerkleRoot)
					fmt.Printf("Created:     %s\n", beacon.Payload.CreatedAt)
				}
				return nil
			}

			// try peer
			ctx, _ := resolveCtx()
			if ctx != nil && ctx.RelayURL != "" {
				c, _, _ := getPeerClient(ctx.RelayName)
				data, err := c.GetBeacon(did)
				if err == nil {
					if jsonFlag {
						outputJSON(data)
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
	var peerName string
	cmd := &cobra.Command{
		Use:   "countersign <did|name>",
		Short: "Countersign someone's beacon",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetDID := resolveIdentityDID(args[0])

			_, chain, err := requireIdentity()
			if err != nil {
				return err
			}

			lr, err := getRelay()
			if err != nil {
				return err
			}

			// get the beacon CID — from local relay or peer
			var beaconCID string
			beacon, _ := lr.Relay.GetBeacon(targetDID)
			if beacon != nil {
				beaconCID = beacon.BeaconCID
			} else {
				ctx, _ := resolveCtx()
				if ctx != nil && ctx.RelayURL != "" {
					c, _, _ := getPeerClient(ctx.RelayName)
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

			authKeyID := chain.State.AuthKeys[0].ID
			kid := chain.DID + "#" + authKeyID
			privKey, err := keys.GetPrivateKey(chain.DID + "#" + authKeyID)
			if err != nil {
				return err
			}

			csToken, _, err := protocol.SignCountersign(chain.DID, beaconCID, kid, privKey)
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
				c, _, _ := getPeerClient(rn)
				peerResults, err := c.SubmitOperations([]string{csToken})
				if err != nil {
					return err
				}
				if len(peerResults) > 0 && peerResults[0].Status == "rejected" {
					return fmt.Errorf("peer rejected: %s", peerResults[0].Error)
				}
			}

			if jsonFlag {
				outputJSON(map[string]any{"status": "countersigned", "beaconDID": targetDID, "witnessDID": chain.DID})
			} else {
				fmt.Printf("Beacon countersigned for %s\n", targetDID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&peerName, "peer", "", "Push countersignature to peer")
	return cmd
}
