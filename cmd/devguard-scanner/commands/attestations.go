// Copyright (C) 2025 l3montree GmbH
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
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"

	"github.com/spf13/cobra"
)

func attestationsCmd(cmd *cobra.Command, args []string) error {
	err := scanner.MaybeLoginIntoOciRegistry(cmd.Context())
	if err != nil {
		return err
	}

	// transform the hex private key to an ecdsa private key
	keyPath, _, err := scanner.TokenToKey(config.RuntimeBaseConfig.Token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		return err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	defer func() {
		// even remove the key file if a panic occurs
		err := recover()
		slog.Debug("removing key file", "keyPath", keyPath)
		os.Remove(keyPath)

		if err != nil {
			panic(err)
		}
	}()

	// check if the file does exist
	predicate := args[0]
	if _, err := os.Stat(predicate); os.IsNotExist(err) {
		// print an error message if the file does not exist
		slog.Error("file does not exist", "file", predicate)
		return err
	}

	// check if an image name is provided
	if len(args) == 2 {
		slog.Info("attesting image", "predicate", predicate, "predicateType", config.RuntimeAttestationConfig.PredicateType, "image", args[1])
		imageName := args[1]

		// use the cosign cli to sign the file
		attestCmd := exec.Command("cosign", "attest", "--type", config.RuntimeAttestationConfig.PredicateType, "--tlog-upload=false", "--key", keyPath, "--predicate", predicate, imageName) // nolint:gosec
		attestCmd.Stdout = &out
		attestCmd.Stderr = &errOut
		attestCmd.Env = []string{
			"PATH=" + os.Getenv("PATH"),
			"HOME=" + os.Getenv("HOME"),
			"DOCKER_CONFIG=" + os.Getenv("DOCKER_CONFIG"),
			"COSIGN_PASSWORD=",
		}

		err = attestCmd.Run()
		if err != nil {
			slog.Error("could not attest predicate", "predicate", predicate, "image", imageName, "err", err, "out", out.String(), "errOut", errOut.String())
		}
	}

	// upload the attestation to the backend
	return scanner.UploadAttestation(cmd.Context(), predicate)
}

func NewAttestationCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestations <oci@SHA> [optional flags] ",
		Short: "Run check against attestated image",
		Long: `retrieving and validating security attestations for container images used in Helm charts or other deployment workflows.
It automates what is normally a manual, time-consuming process of verifying that each image is properly hardened and accompanied by essential metadata such as SBOM, VEX, and SARIF.

Examples:
	devguard-scanner attestations <oci@SHA> ghcr.io/org/image:tag
	devguard-scanner attestations <oci@SHA> --policy path/to/file.rego
`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestationsCmd(cmd, args)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			config.ParseAttestationConfig()
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("policy", "p", "", "check the images attestations against policy")
	cmd.MarkFlagRequired("policy") //nolint:errcheck

	// allow username, password and registry to be provided as well as flags

	return cmd
}
