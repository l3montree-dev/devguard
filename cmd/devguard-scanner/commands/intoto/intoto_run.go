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

package intotocmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/briandowns/spinner"
	toto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

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

func readAndUploadMetadata(cmd *cobra.Command, supplyChainID string, step string, filename string) error {
	// read the metadata.json file and remove it
	b, err := os.ReadFile(filename)
	if err != nil {
		return errors.Wrap(err, "failed to read metadata file")
	}

	err = os.Remove(filename)
	if err != nil {
		return errors.Wrap(err, "failed to remove metadata file")
	}

	outputDigest, _ := cmd.Flags().GetString("supplyChainOutputDigest")

	// create the request
	body := map[string]any{
		"step":                    step,
		"supplyChainId":           supplyChainID,
		"supplyChainOutputDigest": utils.EmptyThenNil(outputDigest),
		"payload":                 string(b),
		"filename":                filename,
	}

	bodyjson, err := json.Marshal(body)
	if err != nil {
		return errors.Wrap(err, "failed to marshal body")
	}

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost, fmt.Sprintf("%s/api/v1/organizations/%s/in-toto", config.RuntimeBaseConfig.APIURL, config.RuntimeBaseConfig.AssetName), bytes.NewBuffer(bodyjson))
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")
	config.SetXAssetHeaders(req)
	// send the request
	client, err := devguard.NewHTTPClient(config.RuntimeBaseConfig.Token, config.RuntimeBaseConfig.APIURL)
	if err != nil {
		return errors.Wrap(err, "failed to create HTTP client")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to send request")
	}

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func NewInTotoRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "run",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if config.RuntimeInTotoConfig.Disabled {
				return nil
			}
			s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = " Devguard: Recording file hashes for supply chain security"
			s.Start()

			metadata, err := toto.InTotoRun(config.RuntimeInTotoConfig.Step, ".", config.RuntimeInTotoConfig.Materials, config.RuntimeInTotoConfig.Products, []string{}, config.RuntimeInTotoConfig.Key, []string{"sha256"}, config.RuntimeInTotoConfig.Ignore, []string{}, true, true, true)
			if err != nil {
				return err
			}

			mb, ok := metadata.(*toto.Envelope)
			if !ok {
				return errors.New("failed to cast metadata to link")
			}

			link, ok := mb.GetPayload().(toto.Link)
			if !ok {
				return errors.New("failed to cast metadata to link")
			}

			if config.RuntimeInTotoConfig.GenerateSlsaProvenance {
				provenance, err := generateSlsaProvenance(link)
				if err != nil {
					return err
				}

				// save to file
				b, err := json.Marshal(provenance)
				if err != nil {
					return err
				}

				err = os.WriteFile(fmt.Sprintf("%s.provenance.json", config.RuntimeInTotoConfig.Step), b, 0644)
				if err != nil {
					return err
				}

				slog.Info("successfully generated provenance", "step", config.RuntimeInTotoConfig.Step)
			}

			err = metadata.Sign(config.RuntimeInTotoConfig.Key)
			if err != nil {
				return errors.Wrap(err, "failed to sign metadata")
			}

			filename := fmt.Sprintf("%s.%s.link", config.RuntimeInTotoConfig.Step, config.RuntimeInTotoConfig.Key.KeyID[:8])

			err = metadata.Dump(filename)
			if err != nil {
				return errors.Wrap(err, "failed to dump metadata")
			}

			err = readAndUploadMetadata(cmd, config.RuntimeInTotoConfig.SupplyChainID, config.RuntimeInTotoConfig.Step, filename)
			if err != nil {
				return errors.Wrap(err, "failed to read and upload metadata")
			}
			s.Stop()
			slog.Info("successfully uploaded in-toto link", "step", config.RuntimeInTotoConfig.Step, "filename", filename)
			return nil
		},
	}

	cmd.Flags().String("apiUrl", "", "The URL of the devguard API")
	err := cmd.MarkFlagRequired("apiUrl")
	if err != nil {
		slog.Error("failed to mark flag as required", "flag", "apiUrl", "err", err)
	}
	cmd.Flags().String("step", "", "The step to run")
	err = cmd.MarkFlagRequired("step")
	if err != nil {
		slog.Error("failed to mark flag as required", "flag", "step", "err", err)
	}
	cmd.Flags().String("supplyChainOutputDigest", "", "If defined, sends this digest to devguard. This should be the digest of the whole supply chain.")

	return cmd
}
