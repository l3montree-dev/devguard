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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func stopInTotoRecording(cmd *cobra.Command, args []string) error {
	if config.RuntimeInTotoConfig.Disabled {
		return nil
	}
	// read the unfinished link
	metadata, err := toto.LoadMetadata(fmt.Sprintf("%s.%s.link.unfinished", config.RuntimeInTotoConfig.Step, config.RuntimeInTotoConfig.Key.KeyID[:8]))

	if err != nil {
		return err
	}

	os.Remove(fmt.Sprintf("%s.%s.link.unfinished", config.RuntimeInTotoConfig.Step, config.RuntimeInTotoConfig.Key.KeyID[:8]))

	err = metadata.VerifySignature(config.RuntimeInTotoConfig.Key)
	if err != nil {
		return err
	}

	m, err := toto.InTotoRecordStop(metadata, config.RuntimeInTotoConfig.Products, config.RuntimeInTotoConfig.Key, []string{"sha256"}, config.RuntimeInTotoConfig.Ignore, []string{}, true, true, true)
	if err != nil {
		return err
	}

	err = m.Sign(config.RuntimeInTotoConfig.Key)
	if err != nil {
		return err
	}

	if config.RuntimeInTotoConfig.GenerateSlsaProvenance {
		mb := m.(*toto.Envelope)
		link, ok := mb.GetPayload().(toto.Link)
		if !ok {
			return errors.New("failed to cast metadata to link")
		}

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
		slog.Debug("successfully generated provenance", "step", config.RuntimeInTotoConfig.Step)
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil || output == "" {
		output = fmt.Sprintf("%s.%s.link", config.RuntimeInTotoConfig.Step, config.RuntimeInTotoConfig.Key.KeyID[:8])
	}

	err = m.Dump(output)
	if err != nil {
		return err
	}

	err = readAndUploadMetadata(cmd, config.RuntimeInTotoConfig.SupplyChainID, config.RuntimeInTotoConfig.Step, output)
	if err != nil {
		return err
	}

	slog.Debug("successfully uploaded in-toto link", "step", config.RuntimeInTotoConfig.Step, "filename", output)
	return nil
}

func startInTotoRecording(cmd *cobra.Command, args []string) error {
	if config.RuntimeInTotoConfig.Disabled {
		return nil
	}
	metdata, err := toto.InTotoRecordStart(config.RuntimeInTotoConfig.Step, config.RuntimeInTotoConfig.Materials, config.RuntimeInTotoConfig.Key, []string{"sha256"}, config.RuntimeInTotoConfig.Ignore, []string{}, true, true, true)

	if err != nil {
		return err
	}
	err = metdata.Sign(config.RuntimeInTotoConfig.Key)
	if err != nil {
		return err
	}

	keyID := config.RuntimeInTotoConfig.Key.KeyID
	return metdata.Dump(fmt.Sprintf("%s.%s.link.unfinished", config.RuntimeInTotoConfig.Step, keyID[:8]))
}

func NewInTotoRecordStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Snapshot input files at the beginning of a pipeline step",
		Long: `Record the cryptographic hashes of all input files (materials) before a pipeline step runs.

Use this when your step is not a single command — for example, a multi-line build script. Call
'intoto start' before the step and 'intoto stop' after it. The pair together produce a signed
in-toto link that proves which files went in and which came out.

If your entire step is a single command, use 'intoto run' instead.`,
		Example: `  # In a CI job: snapshot inputs before the build
  devguard-scanner intoto start --step build --apiUrl https://api.devguard.org --assetName org/project/app --token $TOKEN`,
		RunE: startInTotoRecording,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner intoto start — Snapshot pipeline step inputs",
			"description":     "Record the cryptographic hashes of all input files at the beginning of a pipeline step, to be paired with intoto stop into a signed in-toto link.",
			"keyword_primary": "devguard-scanner intoto start",
		},
	}

	return cmd
}

func NewInTotoRecordStopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Snapshot output files at the end of a pipeline step and upload the signed link",
		Long: `Record the cryptographic hashes of all output files (products) after a pipeline step finishes,
sign the link with the DevGuard token, and upload it to DevGuard.

This is the second half of the start/stop pair. The signed link proves which files existed before
and after this step, and that this specific token (CI identity) performed it.`,
		Example: `  # In a CI job: snapshot outputs and upload after the build
  devguard-scanner intoto stop --step build --apiUrl https://api.devguard.org --assetName org/project/app --token $TOKEN`,
		RunE: stopInTotoRecording,
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner intoto stop — Snapshot outputs and upload the link",
			"description":     "Record the cryptographic hashes of all output files at the end of a pipeline step, sign the in-toto link with the DevGuard token and upload it to DevGuard.",
			"keyword_primary": "devguard-scanner intoto stop",
		},
	}

	cmd.Flags().String("output", "", "The output file name. Default is the <step>.link.json name")
	scanner.AddAssetRefFlags(cmd)

	return cmd
}
