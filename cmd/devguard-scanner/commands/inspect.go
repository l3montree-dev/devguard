// Copyright (C) 2024 Tim Bastin, l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package commands

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/l3montree-dev/devguard/services"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func inspectCmd(cmd *cobra.Command, args []string) error {
	// get the key from the args
	key := args[0]

	privKey, pubKey, err := services.HexTokenToECDSA(key)
	if err != nil {
		return errors.Wrap(err, "could not parse key")
	}

	fmt.Println("PRIVATE KEY HEX")
	fmt.Printf("%s\n\n", key)

	fmt.Println("PRIVATE KEY PEM")

	// encode the private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		return errors.Wrap(err, "could not marshal private key")
	}
	// encode the private key to PEM
	err = pem.Encode(os.Stdout, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return errors.Wrap(err, "could not encode private key to PEM")
	}
	fmt.Print("\n\n")

	fmt.Println("PUBLIC KEY HEX")
	fmt.Printf("%s%s\n\n", hex.EncodeToString(pubKey.X.Bytes()), hex.EncodeToString(pubKey.Y.Bytes()))
	fmt.Println("PUBLIC KEY PEM")
	// encode the public key to PEM
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		return errors.Wrap(err, "could not marshal public key")
	}

	err = pem.Encode(os.Stdout, &pem.Block{Type: "EC PUBLIC KEY", Bytes: pubKeyBytes})
	if err != nil {
		return errors.Wrap(err, "could not encode public key to PEM")
	}
	return nil
}

func NewInspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "inspect-devguard-token <hex-token>",
		Short:             "Decode and display a DevGuard token's keys",
		DisableAutoGenTag: true,
		Long: `Decode a DevGuard hex token and print the corresponding private and public keys in PEM and hex formats.

This is intended for debugging and key inspection only.

Warning: the private key will be printed to stdout; handle output carefully and avoid exposing
private keys in logs or shared screens.`,
		Example: `  # Inspect a DevGuard token
  devguard-scanner inspect-devguard-token 4a6f...

  # Save output to file
  devguard-scanner inspect-devguard-token 4a6f... > keys.txt`,
		Args: cobra.ExactArgs(1),
		RunE: inspectCmd,
	}
}
