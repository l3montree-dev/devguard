// Copyright (C) 2025 l3montree GmbH
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
	"net/http"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	"github.com/spf13/cobra"
)

func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "auth [flags]",
		Short:             "Verify a DevGuard token and store it in the system keyring",
		DisableAutoGenTag: true,
		Long: `Verify a DevGuard personal access token against the API and store it in the system keyring.

Once stored, all devguard-scanner commands will automatically use the token when
no --token flag or DEVGUARD_TOKEN environment variable is provided. This is the
recommended way to authenticate on developer machines and in git hooks.`,
		Example: `  devguard-scanner login --token <hex-token> --assetName org/project/asset --apiUrl https://devguard.example.com`,
		RunE: func(cmd *cobra.Command, args []string) error {
			token := config.RuntimeBaseConfig.Token
			assetName := config.RuntimeBaseConfig.AssetName
			apiURL := config.RuntimeBaseConfig.APIURL
			if token == "" {
				return fmt.Errorf("--token is required")
			}
			if assetName == "" {
				return fmt.Errorf("--assetName is required")
			}
			if apiURL == "" {
				return fmt.Errorf("--apiUrl is required")
			}

			client, err := devguard.NewHTTPClient(token, apiURL)
			if err != nil {
				return fmt.Errorf("could not create API client: %w", err)
			}
			resp, err := client.Get(apiURL + "/api/v1/whoami/")
			if err != nil {
				return fmt.Errorf("could not reach DevGuard at %s: %w", apiURL, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("token verification failed (HTTP %d) — check that the token is valid for %s", resp.StatusCode, apiURL)
			}

			if err := config.StoreTokenInKeyring(apiURL, assetName, token); err != nil {
				return fmt.Errorf("could not store token in keyring: %w", err)
			}
			fmt.Printf("Logged in to %s as asset %q\n", apiURL, assetName)
			return nil
		},
	}

	cmd.Flags().String("token", "", "The personal access token to authenticate the request (required)")
	cmd.Flags().String("assetName", "", "The id of the asset which is scanned (required)")
	cmd.Flags().String("apiUrl", "https://api.devguard.org", "The url of the API to send the scan request to")
	cmd.MarkFlagRequired("token")     // nolint:errcheck
	cmd.MarkFlagRequired("assetName") // nolint:errcheck

	return cmd
}
