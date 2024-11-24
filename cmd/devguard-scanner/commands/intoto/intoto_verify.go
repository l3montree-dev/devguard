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
	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

func verify(cmd *cobra.Command, args []string) error {
	// read the layout
	layoutPath, err := cmd.Flags().GetString("layout")
	if err != nil {
		return err
	}

	rootLayout, err := toto.LoadMetadata(layoutPath)
	if err != nil {
		return err
	}

	linkDir, err := cmd.Flags().GetString("links")
	if err != nil {
		return err
	}

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
	}, linkDir, "", nil, nil, true)
	return err
}

func NewInTotoVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an in-toto layout and the corresponding links",
		RunE:  verify,
	}

	cmd.Flags().StringP("layout", "l", "root.layout.json", "Path to the layout file")
	cmd.Flags().StringP("layoutKey", "k", "ecdsa_public.pem", "Path to the layout public key file")
	cmd.Flags().StringP("links", "i", "links", "Path to the links directory")

	return cmd
}
