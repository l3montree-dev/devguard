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
	"log/slog"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

func NewLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "login [flags] <registry>",
		Args:              cobra.ExactArgs(1),
		Short:             "Log in to a remote registry",
		DisableAutoGenTag: true,
		Long: `Log in to a remote registry using username and password.

Provide the registry URL as a positional argument. Both --username and --password
are required by this command. Credentials will be used to authenticate with the
registry (for example to pull/push images) and may be cached per the underlying
container runtime configuration.`,
		Example: `  # Log in to GitHub Container Registry
  devguard-scanner login -u myuser -p mypass ghcr.io

  # Log in to Docker Hub
  devguard-scanner login -u myuser -p mypass docker.io

  # Log in to a private registry
  devguard-scanner login -u admin -p secret registry.example.com`,
		RunE: runLogin,
	}

	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (required)")
	// mark both flags as required
	cmd.MarkFlagRequired("username") // nolint:errcheck
	cmd.MarkFlagRequired("password") // nolint:errcheck
	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	registryURL := args[0]

	err := scanner.Login(ctx, config.RuntimeBaseConfig.Username, config.RuntimeBaseConfig.Password, registryURL)
	if err != nil {
		slog.Error("login failed", "err", err)
	}

	slog.Debug("login successful")
	return nil
}
