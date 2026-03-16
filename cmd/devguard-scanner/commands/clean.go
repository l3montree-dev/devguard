package commands

import (
	"context"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	cosignclean "github.com/sigstore/cosign/v2/cmd/cosign/cli"
	cosignoptions "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/spf13/cobra"
)

func cleanImage(ctx context.Context, regOpts cosignoptions.RegistryOptions, cleanType cosignoptions.CleanType, imageRef string) error {
	return cosignclean.CleanCmd(ctx, regOpts, cleanType, imageRef, true)
}

// NewCleanCommand returns a command that removes attestations/signatures from an OCI image.
func NewCleanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "clean <image>",
		Short:             "Remove attestations or signatures from an OCI image",
		DisableAutoGenTag: true,
		Long: `Remove attestations and/or signatures from an OCI image.

If registry credentials are provided they will be used for authentication.
Use --type to limit the cleanup to signatures, attestations, SBOMs, or all.`,
		Example: `  # Remove all attestations and signatures from an image
  devguard-scanner clean ghcr.io/org/image:tag

  # Remove only attestations
  devguard-scanner clean --type attestation ghcr.io/org/image:tag

  # Remove only signatures
  devguard-scanner clean --type signature ghcr.io/org/image:tag`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			if err := scanner.MaybeLoginIntoOciRegistry(cmd.Context()); err != nil {
				return err
			}

			ctype, _ := cmd.Flags().GetString("type")

			regOpts := cosignoptions.RegistryOptions{
				AuthConfig: authn.AuthConfig{
					Username: config.RuntimeBaseConfig.Username,
					Password: config.RuntimeBaseConfig.Password,
				},
			}

			if err := cosignclean.CleanCmd(cmd.Context(), regOpts, cosignoptions.CleanType(ctype), target, true); err != nil {
				slog.Error("could not clean image", "err", err)
				return err
			}

			slog.Info("cosign clean finished", "target", target)
			return nil
		},
	}

	scanner.AddDefaultFlags(cmd)
	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (if required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (if required)")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to (optional)")
	cmd.Flags().String("type", "all", "Type of clean to perform: signature|attestation|sbom|all")

	return cmd
}
