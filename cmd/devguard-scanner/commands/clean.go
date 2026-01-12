package commands

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/scanner"
	"github.com/spf13/cobra"
)

// NewCleanCommand returns a command that wraps `cosign remove` to clean attestations/signatures.
// It exposes the same --key and --yes flags as cosign for familiarity.
func NewCleanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "clean <image | signature-file>",
		Short:             "Remove attestations or signatures using cosign",
		DisableAutoGenTag: true,
		Long: `Run cosign remove on an image or signature object to clean attestations/signatures.

This command wraps the cosign CLI. If registry credentials are provided they will
be used for authentication. The command converts your configured token into a key
and uses it where appropriate. Use --type to limit the cleanup to signatures,
attestations, SBOMs, or all.`,
		Example: `  # Remove all attestations and signatures from an image
  devguard-scanner clean ghcr.io/org/image:tag

  # Remove only attestations
  devguard-scanner clean --type attestation ghcr.io/org/image:tag

  # Remove only signatures
  devguard-scanner clean --type signature ghcr.io/org/image:tag`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			// if credentials are provided, login to the registry first (same behavior as attest)
			if err := scanner.MaybeLoginIntoOciRegistry(cmd.Context()); err != nil {
				return err
			}

			var out bytes.Buffer
			var errOut bytes.Buffer

			// get key from token using existing helper
			keyPath, _, err := scanner.TokenToKey(config.RuntimeBaseConfig.Token)
			if err != nil {
				slog.Error("could not convert token to key", "err", err)
				return err
			}
			// ensure temporary key dir is removed
			defer os.RemoveAll(path.Dir(keyPath))

			// build cosign clean command (use 'clean' as per cosign docs)
			argsList := []string{"clean", "--force"}

			// type flag
			ctype, _ := cmd.Flags().GetString("type")
			if ctype != "" && ctype != "all" {
				argsList = append(argsList, "--type", ctype)
			}

			// use parsed config for registry auth if provided
			if config.RuntimeBaseConfig.Username != "" {
				argsList = append(argsList, "--registry-username", config.RuntimeBaseConfig.Username)
			}
			if config.RuntimeBaseConfig.Password != "" {
				argsList = append(argsList, "--registry-password", config.RuntimeBaseConfig.Password)
			}
			if config.RuntimeBaseConfig.Registry != "" {
				argsList = append(argsList, "--registry", config.RuntimeBaseConfig.Registry)
			}

			argsList = append(argsList, target)

			cleanCmd := exec.Command("cosign", argsList...) // nolint:gosec
			cleanCmd.Stdout = &out
			cleanCmd.Stderr = &errOut
			cleanCmd.Env = []string{
				"PATH=" + os.Getenv("PATH"),
				"HOME=" + os.Getenv("HOME"),
				"DOCKER_CONFIG=" + os.Getenv("DOCKER_CONFIG"),
				"COSIGN_PASSWORD=",
			}

			err = cleanCmd.Run()
			if err != nil {
				slog.Error("could not run cosign clean", "err", err, "out", out.String(), "errOut", errOut.String())
				return err
			}

			slog.Info("cosign clean finished", "target", target, "out", out.String())
			return nil
		},
	}

	scanner.AddDefaultFlags(cmd)
	// allow username, password and registry to be provided as well as flags (same as attest)
	cmd.Flags().StringP("username", "u", "", "The username to authenticate to the container registry (if required)")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate to the container registry (if required)")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to (optional)")

	cmd.Flags().String("type", "all", "Type of clean to perform: signature|attestation|sbom|all")

	return cmd
}
