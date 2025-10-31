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
package scanner

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func AddDefaultFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("assetName", "", "The id of the asset which is scanned")
	cmd.PersistentFlags().String("token", "", "The personal access token to authenticate the request")
	cmd.PersistentFlags().String("apiUrl", "https://api.devguard.org", "The url of the API to send the scan request to")
}

func AddAssetRefFlags(cmd *cobra.Command) {
	cmd.Flags().String("ref", "", "The git reference to use. This can be a branch, tag, or commit hash. If not specified, it will first check for a git repository in the current directory. If not found, it will just use main.")
	cmd.Flags().String("defaultRef", "", "The default git reference to use. This can be a branch, tag, or commit hash. If not specified, it will check, if the current directory is a git repo. If it isn't, --ref will be used.")
	cmd.Flags().Bool("isTag", false, "If the current git reference is a tag. If not specified, it will check if the current directory is a git repo. If it isn't, it will be set to false.")
}

func AddDependencyVulnsScanFlags(cmd *cobra.Command) {
	AddDefaultFlags(cmd)
	AddAssetRefFlags(cmd)

	err := cmd.MarkPersistentFlagRequired("assetName")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}
	err = cmd.MarkPersistentFlagRequired("token")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}

	cmd.Flags().String("failOnRisk", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("failOnCVSS", "critical", "The risk level to fail the scan on. Can be 'low', 'medium', 'high' or 'critical'. Defaults to 'critical'.")
	cmd.Flags().String("webUI", "https://app.devguard.org", "The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'.")
	cmd.Flags().String("artifactName", "", "The name of the artifact which was scanned. If not specified, it will default to the empty artifact name ''.")

}
func AddFirstPartyVulnsScanFlags(cmd *cobra.Command) {
	AddDefaultFlags(cmd)
	AddAssetRefFlags(cmd)

	err := cmd.MarkPersistentFlagRequired("assetName")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}
	err = cmd.MarkPersistentFlagRequired("token")
	if err != nil {
		slog.Error("could not mark flag as required", "err", err)
		return
	}

	cmd.Flags().String("path", ".", "The path to the project to scan. Defaults to the current directory.")
	cmd.Flags().String("webUI", "https://app.devguard.org", "The url of the web UI to show the scan results in. Defaults to 'https://app.devguard.org'.")
	cmd.Flags().String("outputPath", "", "Path to save the SARIF report. If not specified, the report will only be uploaded to DevGuard.")

}
