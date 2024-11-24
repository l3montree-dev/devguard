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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/l3montree-dev/devguard/client"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func getTokenFromKeyring() (string, error) {
	service := "devguard"
	user := "devguard"

	token, err := keyring.Get(service, user)
	if err != nil {
		return "", err
	}

	return token, nil
}

func storeTokenInKeyring(token string) error {
	service := "devguard"
	user := "devguard"

	// set password
	return keyring.Set(service, user, token)
}

func newInTotoFetchCommitLinkCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch-link",
		Short: "Fetch link",
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := cmd.Flags().GetString("token")
			if err != nil {
				return err
			}

			apiUrl, err := cmd.Flags().GetString("apiUrl")
			if err != nil {
				return err
			}

			opaqueIdentifier, err := cmd.Flags().GetString("opaqueIdentifier")
			if err != nil {
				return err
			}

			if opaqueIdentifier == "" {
				opaqueIdentifier, err = getCommitHash()
				if err != nil {
					return errors.Wrap(err, "failed to get commit hash. Please provide the --opaqueIdentifier")
				}
			}

			assetName, err := cmd.Flags().GetString("assetName")
			if err != nil {
				return err
			}

			if assetName == "" {
				return errors.New("assetName is required")
			}

			if token == "" {
				return errors.New("token is required")
			}

			c := client.NewDevGuardClient(token, apiUrl)

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, fmt.Sprintf("%s/api/v1/organizations/%s/in-toto/%s/", apiUrl, assetName, opaqueIdentifier), nil)

			if err != nil {
				return errors.Wrap(err, "failed to create request")
			}

			resp, err := c.Do(req)

			if err != nil {
				return errors.Wrap(err, "failed to send request")
			}

			// unmarshal the response
			var link models.InTotoLink
			if err := json.NewDecoder(resp.Body).Decode(&link); err != nil {
				return errors.Wrap(err, "failed to unmarshal response")
			}

			// create a file with the payload
			file, err := os.Create(link.Filename)
			if err != nil {
				return errors.Wrap(err, "failed to create file")
			}

			_, err = file.Write([]byte(link.Payload))
			return err
		},
	}

	cmd.Flags().String("token", "", "The token to use to authenticate with the devguard api")
	cmd.Flags().String("apiUrl", "api.main.devguard.org", "The devguard api url")
	cmd.Flags().String("assetName", "", "The asset name to use")
	cmd.Flags().String("opaqueIdentifier", "", "The opaque identifier to fetch")

	return cmd
}

func newInTotoSetupCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Setup in-toto",
		RunE: func(cmd *cobra.Command, args []string) error {
			// write the token to a file - we need to store it somewhere
			// so we can use it later
			token, err := cmd.Flags().GetString("token")
			if err != nil {
				return err
			}

			apiUrl, err := cmd.Flags().GetString("apiUrl")
			if err != nil {
				return err
			}

			assetName, err := cmd.Flags().GetString("assetName")
			if err != nil {
				return err
			}

			if assetName == "" {
				slog.Error("assetName is required")
				return fmt.Errorf("assetName is required")
			}

			// set the token to the keyring
			err = storeTokenInKeyring(token)
			if err != nil {
				return err
			}

			commandString := fmt.Sprintf(`devguard-scanner intoto run --step=post-commit --apiUrl="%s" --assetName="%s"`, apiUrl, assetName)

			// check if a git post-commit hook exists
			if _, err := os.Stat(".git/hooks/post-commit"); os.IsNotExist(err) {
				// create the post-commit hook
				err = os.WriteFile(".git/hooks/post-commit", []byte(fmt.Sprintf("#!/bin/sh\n%s\n", commandString)), 0755) // nolint:gosec// the file needs to be executable
				if err != nil {
					return err
				}
			} else {
				// append the command to the post-commit hook
				// read the file
				content, err := os.ReadFile(".git/hooks/post-commit")
				if err != nil {
					return err
				}

				// check if the command is already in the file
				contentStr := string(content)
				// split the content by newlines
				lines := strings.Split(contentStr, "\n")
				for i, line := range lines {
					if strings.Contains(line, "devguard-scanner") {
						// the command is already in the file
						// lets overwrite that line
						lines[i] = commandString
					}
				}

				// write the content back to the file
				err = os.WriteFile(".git/hooks/post-commit", []byte(strings.Join(lines, "\n")), 0755) // nolint:gosec// the file needs to be executable
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().String("apiUrl", "api.main.devguard.org", "The devguard api url")
	cmd.Flags().String("assetName", "", "The asset name to use")

	return cmd
}

func NewInTotoCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "intoto",
		Short: "InToto commands",
	}

	// add the token to both commands as needed flag
	cmd.PersistentFlags().String("token", "", "The token to use for in-toto")
	cmd.PersistentFlags().String("step", "", "The name of the in-toto link")

	cmd.PersistentFlags().StringArray("ignore", []string{".git/**/*"}, "The ignore patterns for the in-toto link")

	cmd.PersistentFlags().StringArray("materials", []string{"."}, "The materials to include in the in-toto link. Default is the current directory")

	cmd.PersistentFlags().StringArray("products", []string{"."}, "The products to include in the in-toto link. Default is the current directory")

	cmd.AddCommand(
		NewInTotoRecordStartCommand(),
		NewInTotoRecordStopCommand(),
		NewInTotoRunCommand(),
		newInTotoSetupCommand(),
		NewInTotoVerifyCommand(),
		newInTotoFetchCommitLinkCommand(),
	)

	return cmd
}