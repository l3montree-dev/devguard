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
	"io"
	"net/http"
	"os"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/client"
	"github.com/spf13/cobra"
)

func verify(cmd *cobra.Command, args []string) error {
	// download the layout
	supplyChainId, err := cmd.Flags().GetString("supplyChainId")
	if err != nil {
		return err
	}

	token, err := getTokenFromCommandOrKeyring(cmd)
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

	// download the layout
	c := client.NewDevGuardClient(token, apiUrl)

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, apiUrl+"/api/v1/organizations/"+assetName+"/in-toto/root.layout.json", nil)
	if err != nil {
		return err
	}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// save the file to disk
	err = os.WriteFile("root.layout.json", b, 0600)
	if err != nil {
		return err
	}

	defer os.Remove("root.layout.json")

	rootLayout, err := toto.LoadMetadata("root.layout.json")
	if err != nil {
		return err
	}

	err = downloadSupplyChainLinks(cmd.Context(), c, apiUrl, assetName, supplyChainId)
	if err != nil {
		return err
	}

	defer os.RemoveAll("links")

	// read the layoutKey
	layoutKeyPath, err := cmd.Flags().GetString("layoutKey")
	if err != nil {
		return err
	}

	var layoutKey toto.Key
	err = layoutKey.LoadKey(layoutKeyPath, "ecdsa-sha2-nistp256", []string{"sha256"})
	if err != nil {
		return err
	}

	_, err = toto.InTotoVerify(rootLayout, map[string]toto.Key{
		layoutKey.KeyID: layoutKey,
	}, "links", "", nil, nil, true)
	return err
}

func NewInTotoVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a supply chain",
		RunE:  verify,
		Args:  cobra.ExactArgs(1),
	}

	cmd.Flags().String("supplyChainId", "", "Supply chain ID")
	cmd.Flags().String("token", "", "Token")
	cmd.Flags().String("apiUrl", "", "API URL")
	cmd.Flags().String("assetName", "", "Asset name")

	cmd.Flags().String("layoutKey", "", "Path to the layout key")

	return cmd
}
