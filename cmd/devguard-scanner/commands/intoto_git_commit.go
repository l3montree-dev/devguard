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

package commands

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	toto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func createLinkFileAfterCommit(token string) (toto.Metadata, error) {
	var key toto.Key

	privKey, _, err := pat.HexTokenToECDSA(token)
	if err != nil {
		return nil, err
	}
	privKeyBytes, err := x509.MarshalECPrivateKey(&privKey)
	if err != nil {
		return nil, err
	}

	// encode to pem
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// create new reader
	reader := bytes.NewReader(b)

	err = key.LoadKeyReader(reader, "ecdsa-sha2-nistp521", []string{"sha256"})
	if err != nil {
		return nil, errors.Wrap(err, "failed to load key")
	}

	// read .gitignore if exists
	content, err := os.ReadFile(".gitignore")
	gitignorePatterns := []string{
		".git/**/*",
	}
	if err == nil {
		gitignorePatterns = append(gitignorePatterns, strings.Split(string(content), "\n")...)
	}

	metadata, err := toto.InTotoRun("git-commit", ".", []string{}, []string{"."}, []string{}, key, []string{"sha256"}, gitignorePatterns, []string{}, true, true, true)
	if err != nil {
		return nil, err
	}

	err = metadata.Sign(key)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func NewInTotoGitCommit() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "intoto-git-commit",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, err := cmd.Flags().GetString("token")
			if err != nil {
				return err
			}

			metadata, err := createLinkFileAfterCommit(token)
			if err != nil {
				return err
			}

			name := uuid.NewString()

			err = metadata.Dump(name)
			if err != nil {
				return err
			}

			// read the metadata.json file and remove it
			b, err := os.ReadFile(name)
			if err != nil {
				return err
			}

			err = os.Remove(name)
			if err != nil {
				return err
			}

			fmt.Println(string(b))

			return nil
		},
	}

	cmd.Flags().String("token", "", "The token to sign the git commit")
	return cmd
}
