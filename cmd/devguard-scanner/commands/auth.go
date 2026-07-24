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
		Long: `Verify a DevGuard personal access token and store it in the OS keyring so you do not have to
pass --token on every command.

This is the recommended setup for developer machines and git hooks. In CI pipelines, prefer the
DEVGUARD_TOKEN environment variable instead so the token is not written to disk.

Once stored, all devguard-scanner commands will automatically pick up the token from the keyring.`,
		Example: `  # One-time setup on a developer machine
  devguard-scanner auth --token <hex-token> --assetName org/project/asset --apiUrl https://api.devguard.org

  # Print a previously stored token, e.g. to forward it into a Docker container
  docker run --rm -e DEVGUARD_TOKEN="$(devguard-scanner auth --print-token --assetName org/project/asset --apiUrl https://api.devguard.org)" your-image scan`,
		RunE: func(cmd *cobra.Command, args []string) error {
			assetName := config.RuntimeBaseConfig.AssetName
			apiURL := config.RuntimeBaseConfig.APIURL
			if assetName == "" {
				return fmt.Errorf("--assetName is required")
			}
			if apiURL == "" {
				return fmt.Errorf("--apiUrl is required")
			}

			printToken, err := cmd.Flags().GetBool("print-token")
			if err != nil {
				return err
			}
			if printToken {
				fmt.Print(config.RuntimeBaseConfig.Token)
				return nil
			}

			token := config.RuntimeBaseConfig.Token
			if token == "" {
				return fmt.Errorf("--token is required")
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
		Annotations: map[string]string{
			"title":           "DevGuard-Scanner auth — Verify and store a token",
			"description":     "Verify a DevGuard personal access token and store it in the OS keyring with devguard-scanner auth so you no longer need to pass --token on every command.",
			"keyword_primary": "devguard-scanner auth",
		},
	}

	cmd.Flags().String("token", "", "The personal access token to authenticate the request (required unless --print-token is set)")
	cmd.Flags().String("assetName", "", "The id of the asset which is scanned (required)")
	cmd.Flags().String("apiUrl", "https://api.devguard.org", "The url of the API to send the scan request to")
	cmd.Flags().Bool("print-token", false, "Print a previously stored token from the keyring instead of storing a new one")
	cmd.MarkFlagRequired("assetName") // nolint:errcheck

	return cmd
}
