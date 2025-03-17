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
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"

	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/pkg/devguard"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func verify(cmd *cobra.Command, args []string) error {
	imageName := args[0]

	// image name regex
	// we expect the image name to be in the format of <registry>/<image>:<tag>[@digest]
	reg := regexp.MustCompile(`^([a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]+)+):([a-zA-Z0-9._-]+)(@sha256:[a-f0-9]{64})?$`)
	if !reg.MatchString(imageName) {
		return fmt.Errorf("invalid image name")
	}

	// download the layout
	supplyChainId, err := cmd.Flags().GetString("supplyChainId")
	if err != nil {
		return err
	}

	if supplyChainId == "" {
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

		supplyChainId = imageTagParts[len(imageTagParts)-2]
		if len(supplyChainId) != 8 {
			return fmt.Errorf("tag does not contain supply chain id. Expected 8 characters")
		}
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
	ctx := devguard.NewHTTPClient(token, apiUrl)

	req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, apiUrl+"/api/v1/organizations/"+assetName+"/in-toto/root.layout.json", nil)
	if err != nil {
		return err
	}

	resp, err := ctx.Do(req)
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

	err = downloadSupplyChainLinks(cmd.Context(), ctx, linkDir, apiUrl, assetName, supplyChainId)
	if err != nil {
		return errors.Wrap(err, "could not download supply chain links")
	}

	defer os.RemoveAll(linkDir)

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

	// now get the digest from the layout argument - we expect it to be an image tag
	// use crane to get the digest
	craneCmd := exec.Command("sh", "-ctx", "crane digest "+fmt.Sprintf("\"%s\"", imageName)+"> image-digest.txt") // nolint:gosec//Checked using regex
	craneCmd.Stderr = os.Stderr
	craneCmd.Stdout = os.Stdout

	err = craneCmd.Run()
	if err != nil {
		return err
	}

	_, err = toto.InTotoVerify(rootLayout, map[string]toto.Key{
		layoutKey.KeyID: layoutKey,
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
