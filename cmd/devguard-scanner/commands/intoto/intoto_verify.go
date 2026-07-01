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
	"fmt"
	"net/http"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/pkg/devguard"
	"github.com/spf13/cobra"
)

func verify(cmd *cobra.Command, args []string) error {
	if config.RuntimeInTotoConfig.Disabled {
		return nil
	}

	supplyChainOutputDigest, err := cmd.Flags().GetString("supplyChainOutputDigest")
	if err != nil || supplyChainOutputDigest == "" {
		return fmt.Errorf("--supplyChainOutputDigest is required")
	}

	c, err := devguard.NewHTTPClient(config.RuntimeBaseConfig.Token, config.RuntimeBaseConfig.APIURL)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/organizations/%s/in-toto/verify?supplyChainId=%s&supplyChainOutputDigest=%s",
		config.RuntimeBaseConfig.APIURL,
		config.RuntimeBaseConfig.AssetName,
		config.RuntimeInTotoConfig.SupplyChainID,
		supplyChainOutputDigest,
	)

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("supply chain verification failed (HTTP %d) — check that all pipeline steps uploaded their links", resp.StatusCode)
	}

	return nil
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func NewInTotoVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check with DevGuard whether a supply chain is fully verified (intended for automated deployment gates, not direct use)",
		Long: `Calls the DevGuard supply chain verification endpoint and exits 0 if the supply chain is valid,
non-zero otherwise.

This command is NOT intended to be called by human users. It exists so that automated deployment
gates — such as an OPA policy, an admission webhook, or a CI/CD quality gate — can query DevGuard
for the verification status of a specific image digest before allowing a deployment to proceed.

DevGuard performs the verification server-side: it checks that all three required pipeline steps
(post-commit, build, deploy) have uploaded signed links for the given supply chain ID, that each
step was signed by an authorized token, and that the final deploy link's output digest matches
the --supplyChainOutputDigest you provide.

The underlying endpoint is a plain HTTP GET that returns 200 on success and a non-200 status on
failure — easy to call directly from policy engines or shell scripts:

  GET /api/v1/organizations/<assetName>/in-toto/verify?supplyChainId=<id>&supplyChainOutputDigest=<digest>`,
		Example: `  # Called by an automated deployment gate (e.g. OPA external data, admission webhook, CI gate)
  devguard-scanner intoto verify \
    --supplyChainOutputDigest sha256:abc123… --token $TOKEN \
    --apiUrl https://api.devguard.org --assetName org/project/app`,
		RunE: verify,
		Args: cobra.NoArgs,
	}

	cmd.Flags().String("supplyChainOutputDigest", "", "The image supplyChainOutputDigest to verify (e.g. sha256:abc123…)")
	cmd.Flags().String("token", "", "DevGuard personal access token")

	panicOnError(cmd.MarkFlagRequired("token"))
	panicOnError(cmd.MarkFlagRequired("supplyChainOutputDigest"))

	return cmd
}
