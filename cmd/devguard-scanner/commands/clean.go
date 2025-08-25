package commands

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/spf13/cobra"
)

// NewCleanCommand returns a command that wraps `cosign remove` to clean attestations/signatures.
// It exposes the same --key and --yes flags as cosign for familiarity.
func NewCleanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clean <image | signature-file>",
		Short: "Remove attestations or signatures using cosign",
		Long:  `Run cosign remove on an image or signature object to clean attestations/signatures. Pass --key to specify a key reference. Use --yes to skip confirmation.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			// if credentials are provided, login to the registry first (same behavior as attest)
			if config.RuntimeBaseConfig.Username != "" && config.RuntimeBaseConfig.Password != "" && config.RuntimeBaseConfig.Registry != "" {
				err := login(cmd.Context(), config.RuntimeBaseConfig.Username, config.RuntimeBaseConfig.Password, config.RuntimeBaseConfig.Registry)
				if err != nil {
					slog.Error("login failed", "err", err)
					return err
				}

				slog.Info("logged in", "registry", config.RuntimeBaseConfig.Registry)
			}

			var out bytes.Buffer
			var errOut bytes.Buffer

			// get key from token using existing helper
			keyPath, _, err := tokenToKey(config.RuntimeBaseConfig.Token)
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

	addDefaultFlags(cmd)
	// allow username, password and registry to be provided as well as flags (same as attest)
	cmd.Flags().StringP("username", "u", "", "The username to authenticate the request")
	cmd.Flags().StringP("password", "p", "", "The password to authenticate the request")
	cmd.Flags().StringP("registry", "r", "", "The registry to authenticate to")

	cmd.Flags().String("type", "all", "Type of clean to perform: signature|attestation|sbom|all")

	return cmd
}
