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
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/pkg/devguard"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func verify(cmd *cobra.Command, args []string) error {
	if config.RuntimeInTotoConfig.Disabled {
		return nil
	}
	imageName := args[0]

	// image name regex
	// we expect the image name to be in the format of <registry>/<image>:<tag>[@digest]
	reg := regexp.MustCompile(`^([a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]+)+):([a-zA-Z0-9._-]+)(@sha256:[a-f0-9]{64})?$`)
	if !reg.MatchString(imageName) {
		return fmt.Errorf("invalid image name")
	}

	if config.RuntimeInTotoConfig.SupplyChainID == "" {
		// check if the image contains the supply chain id
		// <registry>/<image>:<branch>-<commit>-<timestamp>

		imageNameParts := strings.Split(imageName, ":")
		if len(imageNameParts) != 2 {
			return fmt.Errorf("invalid image name")
		}

		imageTag := imageNameParts[1]
		imageTagParts := strings.Split(imageTag, "-")
		if len(imageTagParts) < 3 {
			return fmt.Errorf("tag does not contain supply chain id")
		}

		supplyChainID := imageTagParts[len(imageTagParts)-2]
		if len(supplyChainID) != 8 {
			return fmt.Errorf("tag does not contain supply chain id. Expected 8 characters")
		}
	}

	// download the layout
	c, err := devguard.NewHTTPClient(config.RuntimeBaseConfig.Token, config.RuntimeBaseConfig.APIURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, fmt.Sprintf("%s/api/v1/organizations/%s/in-toto/root.layout.json", config.RuntimeBaseConfig.APIURL, config.RuntimeBaseConfig.AssetName), nil)
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
		return errors.Wrap(err, "could not write root.layout.json")
	}

	rootLayout, err := toto.LoadMetadata("root.layout.json")
	if err != nil {
		return errors.Wrap(err, "could not load root.layout.json")
	}

	// remove the layout
	os.Remove("root.layout.json")
	linkDir, err := os.MkdirTemp("", "links")
	if err != nil {
		return errors.Wrap(err, "could not create temp dir")
	}

	err = downloadSupplyChainLinks(cmd.Context(), c, linkDir, config.RuntimeBaseConfig.APIURL, config.RuntimeBaseConfig.AssetName, config.RuntimeInTotoConfig.SupplyChainID)
	if err != nil {
		return errors.Wrap(err, "could not download supply chain links")
	}

	defer os.RemoveAll(linkDir)

	// now get the digest from the layout argument - we expect it to be an image tag
	// use crane to get the digest
	craneCmd := exec.Command("sh", "-c", "crane digest "+fmt.Sprintf("\"%s\"", imageName)+"> image-digest.txt") // nolint:gosec//Checked using regex
	craneCmd.Stderr = os.Stderr
	craneCmd.Stdout = os.Stdout

	err = craneCmd.Run()
	if err != nil {
		return err
	}

	_, err = toto.InTotoVerify(rootLayout, map[string]toto.Key{
		config.RuntimeInTotoConfig.LayoutKey.KeyID: config.RuntimeInTotoConfig.LayoutKey,
	}, linkDir, "", nil, nil, true)
	if err != nil {
		return err
	}

	// if a verify-digest.link was created, delete it
	os.Remove("verify-digest.link") // nolint:errcheck
	os.Remove("image-digest.txt")   // nolint:errcheck

	return err
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
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
	cmd.Flags().String("layoutKey", "", "Path to the layout key")

	panicOnError(cmd.MarkFlagRequired("token"))
	panicOnError(cmd.MarkFlagRequired("layoutKey"))

	return cmd
}
