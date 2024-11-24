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
	"github.com/spf13/cobra"
)

func getTokenFromCommandOrKeyring(cmd *cobra.Command) (string, error) {
	token, err := cmd.Flags().GetString("token")
	if err != nil {
		return "", err
	}

	// if the token is not set, try to get it from the keyring
	if token == "" {
		token, err = getTokenFromKeyring()
		if err != nil {
			return "", err
		}
	}

	return token, nil
}
func parseCommand(cmd *cobra.Command) (
	step string, key toto.Key, materials, products, ignore []string, err error) {
	token, err := getTokenFromCommandOrKeyring(cmd)
	if err != nil {
		return "", toto.Key{}, nil, nil, nil, err
	}

	step, err = cmd.Flags().GetString("step")
	if err != nil {
		return "", toto.Key{}, nil, nil, nil, err
	}

	materials, _ = cmd.Flags().GetStringArray("materials")

	products, _ = cmd.Flags().GetStringArray("products")

	ignore, err = cmd.Flags().GetStringArray("ignore")
	if err != nil {
		return "", toto.Key{}, nil, nil, nil, err
	}

	// read .gitignore if exists
	content, err := os.ReadFile(".gitignore")
	if err == nil {
		ignore = append(ignore, strings.Split(string(content), "\n")...)
	}

	key, err = tokenToInTotoKey(token)
	if err != nil {
		return "", toto.Key{}, nil, nil, nil, err
	}

	return step, key, materials, products, ignore, nil
}

func stopInTotoRecording(cmd *cobra.Command, args []string) error {
	step, key, _, products, ignore, err := parseCommand(cmd)
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

	err = readAndUploadMetadata(cmd, step, output)
	if err != nil {
		return err
	}

	slog.Info("successfully uploaded in-toto link", "step", step, "filename", output)
	return nil
}

func startInTotoRecording(cmd *cobra.Command, args []string) error {
	step, key, materials, _, ignore, err := parseCommand(cmd)

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

	cmd.Flags().String("apiUrl", "", "The devguard api url")
	cmd.Flags().String("assetName", "", "The asset name to use")

	return cmd
}
