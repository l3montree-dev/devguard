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
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/spf13/cobra"
)

func attestCmd(cmd *cobra.Command, args []string) error {
	if config.RuntimeBaseConfig.Username != "" && config.RuntimeBaseConfig.Password != "" && config.RuntimeBaseConfig.Registry != "" {
		// login to the registry
		err := login(cmd.Context(), config.RuntimeBaseConfig.Username, config.RuntimeBaseConfig.Password, config.RuntimeBaseConfig.Registry)
		if err != nil {
			slog.Error("login failed", "err", err)
			return err
		}

		slog.Info("logged in", "registry", config.RuntimeBaseConfig.Registry)
	}

	// transform the hex private key to an ecdsa private key
	keyPath, _, err := tokenToKey(config.RuntimeBaseConfig.Token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		return err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	defer func() {
		// even remove the key file if a panic occurs
		err := recover()
		slog.Info("removing key file", "keyPath", keyPath)
		os.Remove(keyPath)

		if err != nil {
			panic(err)
		}
	}()

	// check if the file does exist
	predicate := args[0]
	// check if an image name is provided
	if len(args) == 2 {
		slog.Info("attesting image", "predicate", predicate, "image", args[1])
		imageName := args[1]
		if _, err := os.Stat(predicate); os.IsNotExist(err) {
			// print an error message if the file does not exist
			slog.Error("file does not exist", "file", predicate)
			return err
		}

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
	return uploadAttestation(cmd.Context(), predicate)
}

func uploadAttestation(ctx context.Context, predicate string) error {
	// read the file
	file, err := os.ReadFile(predicate)
	if err != nil {
		slog.Error("could not read file", "err", err)
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/api/v1/attestations", config.RuntimeBaseConfig.APIURL), bytes.NewReader(file))
	if err != nil {
		slog.Error("could not create request", "err", err)
		return err
	}

	err = pat.SignRequest(config.RuntimeBaseConfig.Token, req)
	if err != nil {
		return err
	}

	req.Header.Set("X-Predicate-Type", config.RuntimeAttestationConfig.PredicateType)
	// set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Artifact-Name", config.RuntimeBaseConfig.ArtifactName)
	config.SetXAssetHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("could not upload attestation", "err", err)
		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// read the body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("could not upload attestation: %s %s", resp.Status, string(body))
		}
		return fmt.Errorf("could not upload attestation: %s %s", resp.Status, string(body))
	}

	slog.Info("attestation uploaded successfully", "predicate", predicate, "predicateType", config.RuntimeAttestationConfig.PredicateType)
	return nil
}

func NewAttestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest <predicate> [container-image]",
		Short: "Add a new attestation to an image",
		Long:  `Add a new attestation to an image`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return attestCmd(cmd, args)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			config.ParseAttestationConfig()
		},
	}

	addDefaultFlags(cmd)
	addAssetRefFlags(cmd)
	cmd.Flags().StringP("predicateType", "a", "", "The type of the attestation")
	cmd.MarkFlagRequired("predicateType") //nolint:errcheck

	// allow username, password and registry to be provided as well as flags
	cmd.Flags().StringP("username", "u", "", "The username to authenticate the request")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate the request")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to")
	cmd.Flags().String("artifactName", "", "The name of the artifact which was scanned. If not specified, it will generate a name based on the asset name.")

	return cmd
}
