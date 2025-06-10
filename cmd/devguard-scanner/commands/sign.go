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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	"github.com/spf13/cobra"
)

func uploadPublicKey(ctx context.Context, token, apiUrl, publicKeyPath, assetName string) error {
	devGuardClient := devguard.NewHTTPClient(token, apiUrl)

	var body = make(map[string]string)

	// read the public key from file
	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return err
	}

	body["publicKey"] = string(publicKey)
	// marshal
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/organizations/"+assetName+"/signing-key", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return err
	}

	resp, err := devGuardClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not upload public key: %s", resp.Status)
	}

	return nil
}

func tokenToKey(token string) (string, string, error) {
	// transform the hex private key to an ecdsa private key
	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		os.Exit(1)
	}

	// encode the private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		slog.Error("could not marshal private key", "err", err)
		return "", "", err
	}
	// create a new temporary file to store the private key - the file needs to have minimum permissions
	tempDir := path.Join(os.TempDir(), uuid.New().String())
	err = os.Mkdir(
		tempDir,
		0700,
	)
	if err != nil {
		slog.Error("could not create temp dir", "err", err)
		return "", "", err
	}

	file, err := os.OpenFile(path.Join(tempDir, "ecdsa.pem"), os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		slog.Error("could not create file", "err", err)
		return "", "", err
	}

	// encode the private key to PEM
	err = pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		slog.Error("could not encode private key to PEM", "err", err)
		return "", "", err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	// import the cosign key
	importCmd := exec.Command("cosign", "import-key-pair", "--output-key-prefix", "cosign", "--key", "ecdsa.pem")
	importCmd.Dir = tempDir
	importCmd.Stdout = &out
	importCmd.Stderr = &errOut
	importCmd.Env = []string{"COSIGN_PASSWORD="}

	err = importCmd.Run()
	if err != nil {
		slog.Error("could not import key", "err", err, "out", out.String(), "errOut", errOut.String())
		return "", "", err
	}

	return path.Join(tempDir, "cosign.key"), path.Join(tempDir, "cosign.pub"), nil
}

func signCmd(cmd *cobra.Command, args []string) error {
	// check if the argument is a file, which does exist
	fileOrImageName := args[0]

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
	keyPath, publicKeyPath, err := tokenToKey(config.RuntimeBaseConfig.Token)
	if err != nil {
		slog.Error("could not convert hex token to ecdsa private key", "err", err)
		return err
	}

	var out bytes.Buffer
	var errOut bytes.Buffer

	defer os.RemoveAll(path.Dir(keyPath))

	// upload the public key to the backend
	err = uploadPublicKey(cmd.Context(), config.RuntimeBaseConfig.Token, config.RuntimeBaseConfig.ApiUrl, publicKeyPath, config.RuntimeBaseConfig.AssetName)
	if err != nil {
		slog.Error("could not upload public key", "err", err)
		return err
	}

	// forward the current process envs as well
	envs := os.Environ()
	envs = append(envs, "COSIGN_PASSWORD=")

	if _, err := os.Stat(fileOrImageName); os.IsNotExist(err) {
		// it is an image
		signImageCmd := exec.Command("cosign", "sign", "--tlog-upload=false", "--key", keyPath, fileOrImageName) // nolint:gosec
		signImageCmd.Stdout = &out
		signImageCmd.Stderr = &errOut
		signImageCmd.Env = envs

		err = signImageCmd.Run()
		if err != nil {
			slog.Error("could not sign image", "err", err, "out", out.String(), "errOut", errOut.String())
			return err
		}

		slog.Info("signed image", "image", fileOrImageName)
		return nil
	}

	// use the cosign cli to sign the file
	signBlobCmd := exec.Command("cosign", "sign-blob", "--tlog-upload=false", "--key", keyPath, fileOrImageName) // nolint:gosec

	signBlobCmd.Stdout = &out
	signBlobCmd.Stderr = &errOut

	signBlobCmd.Env = envs

	err = signBlobCmd.Run()
	if err != nil {
		slog.Error("could not sign blob", "err", err, "out", out.String(), "errOut", errOut.String())
		return err
	}

	// print the signature
	slog.Info("signed file", "file", fileOrImageName, "signature", out.String())
	return nil
}

func NewSignCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <file | image>",
		Short: "Sign a file or image",
		Long:  `Sign a file or image`,
		Args:  cobra.ExactArgs(1),
		RunE:  signCmd,
	}

	addDefaultFlags(cmd)

	// allow username, password and registry to be provided as well as flags
	cmd.Flags().StringP("username", "u", "", "The username to authenticate the request")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate the request")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to")

	return cmd
}
