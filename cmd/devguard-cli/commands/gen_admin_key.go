package commands

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func NewGenAdminKeyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-admin-key",
		Short: "Generate an ECDSA P-256 keypair for instance admin request signing.",
		Long:  "Generates a P-256 ECDSA keypair. Write the public key to a file and set INSTANCE_ADMIN_PUB_KEY_PATH to its path. Keep the private key secret and use it to sign admin requests.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			priv, err := ecdh.P256().GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("failed to generate key: %w", err)
			}

			privHex := hex.EncodeToString(priv.Bytes())

			// Uncompressed public key: 0x04 || X[32] || Y[32]
			pubBytes := priv.PublicKey().Bytes()
			pubHex := hex.EncodeToString(pubBytes[1:33]) + hex.EncodeToString(pubBytes[33:])

			fmt.Fprintln(os.Stdout, "Private key (keep secret, use for signing):")
			fmt.Fprintln(os.Stdout, privHex)
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, "Public key (write to file, set INSTANCE_ADMIN_PUB_KEY_PATH):")
			fmt.Fprintln(os.Stdout, pubHex)
			return nil
		},
	}
}
