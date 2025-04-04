/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package commands

import (
	"context"
	"log/slog"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

func NewLoginCommand() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "login [flags] <registry>",
		Short: "Log in to a remote registry",
		Long:  `Log in to a remote registry`,
		Run:   runLogin,
	}

	cmd.Flags().StringP("username", "u", "", "username")
	cmd.Flags().StringP("password", "p", "", "password")
	return cmd
}

func login(ctx context.Context, username, password, registryUrl string) error {

	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{
		AllowPlaintextPut:        true,
		DetectDefaultNativeStore: true,
	})
	if err != nil {
		return err
	}

	return credentials.Login(ctx, store, &remote.Registry{
		RepositoryOptions: remote.RepositoryOptions{
			Reference: registry.Reference{
				Registry: registryUrl,
			},
		},
	}, auth.Credential{
		Username: username,
		Password: password,
	})
}

func runLogin(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	// extract the username
	username, _ := cmd.Flags().GetString("username")
	if username == "" {
		slog.Error("username is required")
		return
	}

	// extract the password
	password, _ := cmd.Flags().GetString("password")
	if password == "" {
		slog.Error("password is required")
		return
	}

	registryUrl := args[0]

	err := login(ctx, username, password, registryUrl)
	if err != nil {
		slog.Error("login failed", "err", err)
	}

	slog.Info("login successful")
}
