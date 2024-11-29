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
	"fmt"
	"log/slog"
	"os"
	"strings"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func getTokenFromCommandOrKeyring(cmd *cobra.Command) (string, error) {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		return "", err
	}

	assetName, err := cmd.Flags().GetString("assetName")
	if err != nil {
		return "", err
	}

	// if the token is not set, try to get it from the keyring
	if token == "" {
		token, err = getTokenFromKeyring(assetName)
		if err != nil {
			return "", err
		}
	}

	return token, nil
}

func parseGitIgnore(path string) ([]string, error) {
	// read .gitignore if exists
	content, err := os.ReadFile(path)
	if err == nil {
		ignorePaths := strings.Split(string(content), "\n")

		// make sure to remove new lines and empty strings
		ignorePaths = utils.Filter(
			utils.Map(utils.Map(ignorePaths, strings.TrimSpace), func(e string) string {
				// nextjs products a gitignore which contains /node_modules but we need to ignore /node_modules/
				if e == "/node_modules" {
					return e + "/"
				}
				return e
			}),
			func(e string) bool {
				return e != "" && e != "\n" && !strings.HasPrefix(strings.TrimSpace(e), "#")
			})

		return ignorePaths, nil
	}

	return nil, err
}

func parseCommand(cmd *cobra.Command) (
	step string, supplyChainId string, key toto.Key, materials, products, ignore []string, err error) {
	token, err := getTokenFromCommandOrKeyring(cmd)
	if err != nil {
		return "", "", toto.Key{}, nil, nil, nil, err
	}

	step, err = cmd.Flags().GetString("step")
	if err != nil {
		return "", "", toto.Key{}, nil, nil, nil, err
	}

	materials, _ = cmd.Flags().GetStringArray("materials")

	products, _ = cmd.Flags().GetStringArray("products")

	ignore, err = cmd.Flags().GetStringArray("ignore")
	if err != nil {
		return "", "", toto.Key{}, nil, nil, nil, err
	}

	pathsFromGitIgnore, err := parseGitIgnore(".gitignore")

	if err != nil {
		// just swallow the error
		slog.Warn("could not read .gitignore file. This is not to bad if you do not have a .gitignore file.", "error", err)
	} else {
		ignore = append(ignore, pathsFromGitIgnore...)
	}

	key, err = tokenToInTotoKey(token)
	if err != nil {
		return "", "", toto.Key{}, nil, nil, nil, err
	}

	supplyChainId, err = cmd.Flags().GetString("supplyChainId")
	if err != nil {
		return "", "", toto.Key{}, nil, nil, nil, err
	}

	if supplyChainId == "" {
		// get the commit hash
		supplyChainId, err = getCommitHash()
		if err != nil {
			return "", "", toto.Key{}, nil, nil, nil, errors.Wrap(err, "failed to get commit hash. Please provide the --supplyChainId flag")
		}
	}

	return step, supplyChainId, key, materials, products, ignore, nil
}

func stopInTotoRecording(cmd *cobra.Command, args []string) error {
	step, supplyChainId, key, _, products, ignore, err := parseCommand(cmd)
	if err != nil {
		return err
	}

	// read the unfinished link
	metadata, err := toto.LoadMetadata(fmt.Sprintf("%s.%s.link.unfinished", step, key.KeyID[:8]))

	if err != nil {
		return err
	}

	os.Remove(fmt.Sprintf("%s.%s.link.unfinished", step, key.KeyID[:8]))

	err = metadata.VerifySignature(key)
	if err != nil {
		return err
	}

	m, err := toto.InTotoRecordStop(metadata, products, key, []string{"sha256"}, ignore, []string{}, true, true, true)
	if err != nil {
		return err
	}

	err = m.Sign(key)
	if err != nil {
		return err
	}

	output, err := cmd.Flags().GetString("output")
	if err != nil || output == "" {
		output = fmt.Sprintf("%s.%s.link", step, key.KeyID[:8])
	}

	err = m.Dump(output)
	if err != nil {
		return err
	}

	err = readAndUploadMetadata(cmd, supplyChainId, step, output)
	if err != nil {
		return err
	}

	slog.Info("successfully uploaded in-toto link", "step", step, "filename", output)
	return nil
}

func startInTotoRecording(cmd *cobra.Command, args []string) error {
	step, _, key, materials, _, ignore, err := parseCommand(cmd)

	if err != nil {
		return err
	}

	metdata, err := toto.InTotoRecordStart(step, materials, key, []string{"sha256"}, ignore, []string{}, true, true, true)

	if err != nil {
		return err
	}
	err = metdata.Sign(key)
	if err != nil {
		return err
	}

	keyId := key.KeyID
	return metdata.Dump(fmt.Sprintf("%s.%s.link.unfinished", step, keyId[:8]))
}

func NewInTotoRecordStartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start in-toto recording",
		RunE:  startInTotoRecording,
	}

	return cmd
}

func NewInTotoRecordStopCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop in-toto recording",
		RunE:  stopInTotoRecording,
	}

	cmd.Flags().String("output", "", "The output file name. Default is the <step>.link.json name")

	return cmd
}
