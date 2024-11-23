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

package intotocmd

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/client"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func tokenToInTotoKey(token string) (toto.Key, error) {
	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		return toto.Key{}, err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		return toto.Key{}, err
	}

	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	var key toto.Key
	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return toto.Key{}, errors.Wrap(err, "failed to load key")
	}

	return key, nil
}

func getCommitHash() (string, error) {
	// get the commit hash
	cmd := exec.Command("git", "rev-parse", "HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, "failed to run git command")
	}

	// remove the newline
	str := out.String()
	return str[:len(str)-1], nil
}

func NewInTotoRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "run",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			step, key, materials, products, ignore, err := parseCommand(cmd)
			if err != nil {
				return errors.Wrap(err, "failed to parse command")
			}

			metadata, err := toto.InTotoRun(step, ".", materials, products, []string{}, key, []string{"sha256"}, ignore, []string{}, true, true, true)
			if err != nil {
				return err
			}

			err = metadata.Sign(key)
			if err != nil {
				return errors.Wrap(err, "failed to sign metadata")
			}

			filename := fmt.Sprintf("%s.%s.link", step, key.KeyID)

			err = metadata.Dump(filename)
			if err != nil {
				return errors.Wrap(err, "failed to dump metadata")
			}

			// read the metadata.json file and remove it
			b, err := os.ReadFile(filename)
			if err != nil {
				return errors.Wrap(err, "failed to read metadata file")
			}

			err = os.Remove(filename)
			if err != nil {
				return errors.Wrap(err, "failed to remove metadata file")
			}

			// get the commit hash
			commit, err := getCommitHash()
			if err != nil {
				return errors.Wrap(err, "failed to get commit hash")
			}

			// create the request
			body := map[string]string{
				"opaqueIdentifier": commit,
				"payload":          string(b),
				"filename":         filename,
			}

			bodyjson, err := json.Marshal(body)
			if err != nil {
				return errors.Wrap(err, "failed to marshal body")
			}

			// cant error - we already called it in the parseCommand
			token, _ := getTokenFromCommandOrKeyring(cmd)

			apiUrl, err := cmd.Flags().GetString("apiUrl")
			if err != nil {
				return errors.Wrap(err, "failed to get api url")
			}

			assetName, err := cmd.Flags().GetString("assetName")
			if err != nil {
				return errors.Wrap(err, "failed to get asset name")
			}

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, fmt.Sprintf("%s/api/v1/organizations/%s/in-toto", apiUrl, assetName), bytes.NewBuffer(bodyjson))

			req.Header.Set("Content-Type", "application/json")

			if err != nil {
				return errors.Wrap(err, "failed to create request")
			}

			// send the request
			resp, err := client.NewDevGuardClient(token, apiUrl).Do(req)
			if err != nil {
				return errors.Wrap(err, "failed to send request")
			}

			if resp.StatusCode != http.StatusOK {
				return errors.Errorf("unexpected status code: %d", resp.StatusCode)
			}

			return nil
		},
	}

	cmd.Flags().String("apiUrl", "", "The devguard api url")
	cmd.Flags().String("assetName", "", "The asset name to use")

	return cmd
}
