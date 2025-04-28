// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"bytes"
	"log/slog"
	"os"
	"os/exec"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/spf13/cobra"
)

func attestCmd(cmd *cobra.Command, args []string) error {

	// transform the hex private key to an ecdsa private key
	keyPath, _, err := tokenToKey(config.RuntimeBaseConfig.Token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		return err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	defer os.Remove(keyPath)

	// check if the file does exist
	predicate := args[0]
	imageName := args[1]

	if _, err := os.Stat(predicate); os.IsNotExist(err) {
		// print an error message if the file does not exist
		slog.Error("file does not exist", "file", predicate)
		return err
	}

	// use the cosign cli to sign the file
	attestCmd := exec.Command("cosign", "attest", "--tlog-upload=false", "--key", keyPath, "--predicate", predicate, imageName) // nolint:gosec
	attestCmd.Stdout = &out
	attestCmd.Stderr = &errOut
	attestCmd.Env = []string{"COSIGN_PASSWORD="}

	err = attestCmd.Run()
	if err != nil {
		slog.Error("could not attest predicate", "predicate", predicate, "image", imageName, "err", err, "out", out.String(), "errOut", errOut.String())
		return err
	}

	return nil
}

func NewAttestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest <predicate> <image>",
		Short: "Add a new attestation to an image",
		Long:  `Add a new attestation to an image`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestCmd(cmd, args)
		},
	}

	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.MarkPersistentFlagRequired("token") // nolint:errcheck

	return cmd
}
