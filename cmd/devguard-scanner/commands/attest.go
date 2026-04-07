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
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	cosignattest "github.com/sigstore/cosign/v2/cmd/cosign/cli/attest"
	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"

	"github.com/spf13/cobra"
)

func attachAttestation(ctx context.Context, regOpts cosignoptions.RegistryOptions, keyPath, predicatePath, predicateType, imageName string) error {
	return (&cosignattest.AttestCommand{
		KeyOpts: cosignoptions.KeyOpts{
			KeyRef:   keyPath,
			PassFunc: func(_ bool) ([]byte, error) { return []byte{}, nil },
		},
		RegistryOptions: regOpts,
		PredicatePath:   predicatePath,
		PredicateType:   predicateType,
		TlogUpload:      false,
		RekorEntryType:  "dsse",
	}).Exec(ctx, imageName)
}

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
	defer os.RemoveAll(path.Dir(keyPath))

	predicate := args[0]

	// if predicate is "-", read from stdin into a temp file
	if predicate == "-" {
		tmp, err := os.CreateTemp("", "devguard-predicate-*.json")
		if err != nil {
			return fmt.Errorf("failed to create temp file for stdin: %w", err)
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, os.Stdin); err != nil {
			tmp.Close()
			return fmt.Errorf("failed to read predicate from stdin: %w", err)
		}
		tmp.Close()
		predicate = tmp.Name()
	}

	if _, err := os.Stat(predicate); os.IsNotExist(err) {
		slog.Error("file does not exist", "file", predicate)
		return err
	}

	// check if an image name is provided
	if len(args) == 2 {
		imageName := args[1]
		slog.Info("attesting image", "predicate", predicate, "predicateType", config.RuntimeAttestationConfig.PredicateType, "image", imageName)

		regOpts := cosignoptions.RegistryOptions{
			AuthConfig: authn.AuthConfig{
				Username: config.RuntimeBaseConfig.Username,
				Password: config.RuntimeBaseConfig.Password,
			},
		}
		if err = attachAttestation(cmd.Context(), regOpts, keyPath, predicate, config.RuntimeAttestationConfig.PredicateType, imageName); err != nil {
			slog.Error("could not attest predicate", "predicate", predicate, "image", imageName, "err", err)
			return err
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
the attestation payload. Pass "-" to read the predicate from stdin. Optionally
provide a container image reference as the second argument to attach the
attestation to that image.

This command validates the predicate file exists, signs the upload using the
configured token, and sends it to the DevGuard backend. The HTTP header
X-Predicate-Type is populated from the --predicateType flag (required).`,
		Example: `  # Attest a container image with a VEX predicate
  devguard-scanner attest vex.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Attest with SLSA provenance
  devguard-scanner attest provenance.json ghcr.io/org/image:tag --predicateType https://slsa.dev/provenance/v1

  # Pipe curl output directly into attest (no shell needed)
  devguard-scanner curl https://api.example.com/sbom.json --token=... | devguard-scanner attest - ghcr.io/org/image:tag --predicateType https://cyclonedx.org/bom

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
