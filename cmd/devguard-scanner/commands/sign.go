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
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	cosignsign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"
)

func signCmd(cmd *cobra.Command, args []string) error {
	fileOrImageName := args[0]

	if err := scanner.MaybeLoginIntoOciRegistry(cmd.Context()); err != nil {
		return err
	}

	keyPath, publicKeyPath, err := scanner.TokenToKey(config.RuntimeBaseConfig.Token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		return err
	}
	defer os.RemoveAll(path.Dir(keyPath))

	if !config.RuntimeBaseConfig.Offline {
		slog.Info("uploading public key to devguard")
		err = scanner.UploadPublicKey(cmd.Context(), config.RuntimeBaseConfig.Token, config.RuntimeBaseConfig.APIURL, publicKeyPath, config.RuntimeBaseConfig.AssetName)
		if err != nil {
			slog.Error("could not upload public key", "err", err)
			return err
		}
	}

	ko := cosignoptions.KeyOpts{
		KeyRef:   keyPath,
		PassFunc: func(_ bool) ([]byte, error) { return []byte{}, nil },
	}

	if _, err := os.Stat(fileOrImageName); os.IsNotExist(err) {
		// it is an image — use cosign library directly (no CLI binary needed)
		err = cosignsign.SignCmd(
			&cosignoptions.RootOptions{},
			ko,
			cosignoptions.SignOptions{TlogUpload: false, Upload: true},
			[]string{fileOrImageName},
		)
		if err != nil {
			slog.Error("could not sign image", "err", err)
			return err
		}
		slog.Info("signed image", "image", fileOrImageName)
		return nil
	}

	// sign a local blob
	sig, err := cosignsign.SignBlobCmd(
		&cosignoptions.RootOptions{},
		ko,
		fileOrImageName,
		false, // b64
		"", "", // outputSignature, outputCertificate
		false, // tlogUpload
	)
	if err != nil {
		slog.Error("could not sign blob", "err", err)
		return err
	}

	fmt.Print(strings.TrimSpace(string(sig)))
	return nil
}

func NewSignCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "sign <file | image>",
		Short:             "Sign a file or image",
		DisableAutoGenTag: true,
		Long: `Sign a file or OCI image using cosign.

When not run with --offline the command will upload the public key to DevGuard
before creating the signature. The public key upload is signed using the
configured token.`,
		Example: `  # Sign a local file
  devguard-scanner sign ./artifact.bin

  # Sign a container image
  devguard-scanner sign ghcr.io/org/image:tag

  # Sign without uploading public key to DevGuard
  devguard-scanner sign ./artifact.bin --offline`,
		Args: cobra.ExactArgs(1),
		RunE: signCmd,
	}

	scanner.AddDefaultFlags(cmd)

	// allow username, password and registry to be provided as well as flags
	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (if required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (if required)")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to (optional)")

	cmd.Flags().BoolP("offline", "o", false, "If set, the scanner will not attempt to upload the signing key to devguard")
	return cmd
}
