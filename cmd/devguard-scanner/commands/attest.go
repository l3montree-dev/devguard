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
	"bytes"
	"log/slog"
	"os"
	"os/exec"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"

	"github.com/spf13/cobra"
)

func attestCmd(cmd *cobra.Command, args []string) error {
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

func NewAttestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "attest <predicate> [container-image]",
		Short:             "Create and upload an attestation for an image or artifact",
		DisableAutoGenTag: true,
		Long: `Create and upload an attestation for an OCI image or a local predicate file.

The first argument is a path to a local predicate JSON file that will be used as
the attestation payload. Optionally provide a container image reference as the
second argument to attach the attestation to that image.

This command validates the predicate file exists, signs the upload using the
configured token, and sends it to the DevGuard backend. The HTTP header
X-Predicate-Type is populated from the --predicateType flag (required).`,
		Example: `  # Attest a container image with a VEX predicate
  devguard-scanner attest vex.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Attest with SLSA provenance
  devguard-scanner attest provenance.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Upload attestation without attaching to an image
  devguard-scanner attest predicate.json --predicateType https://example.com/custom/v1`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestCmd(cmd, args)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			config.ParseAttestationConfig()
		},
	}

	scanner.AddDefaultFlags(cmd)
	scanner.AddAssetRefFlags(cmd)
	cmd.Flags().StringP("predicateType", "a", "", "The predicate type (URI) for the attestation, e.g. https://slsa.dev/provenance/v1 or https://cyclonedx.org/vex/1.0")
	cmd.MarkFlagRequired("predicateType") //nolint:errcheck
	cmd.MarkFlagRequired("token")         //nolint:errcheck

	// allow username, password and registry to be provided as well as flags
	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (if required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (if required)")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to (optional)")
	cmd.Flags().String("artifactName", "", "The name of the artifact which was scanned. If empty, a name will be generated from the asset name.")

	return cmd
}
