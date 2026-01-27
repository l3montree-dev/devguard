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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	intotocmd "github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands/intoto"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/config"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lmittmann/tint"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var cfgFile string

// Version information - set via ldflags during build
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
	builtBy = "unknown"
)

const (
	defaultConfigFilename = ".devguard"
)

var RootCmd = &cobra.Command{
	SilenceUsage:      true,
	Use:               "devguard-scanner",
	Short:             "Secure your Software Supply Chain",
	Version:           version,
	DisableAutoGenTag: true,
	Long: `Secure your Software Supply Chain

DevGuard Scanner is a small CLI to help generate, sign and upload SBOMs, SARIF
reports and attestations to a DevGuard backend. Use commands like 'sca', 'sarif',
and 'attest' to interact with the platform. Configuration can be provided via a
./.devguard config file or environment variables (prefix DEVGUARD_).`,
	Example: `  # Run Software Composition Analysis on a container image
  devguard-scanner sca ghcr.io/org/image:tag

  # Run SCA on a local project directory
  devguard-scanner sca ./path/to/project

  # Create and upload an attestation
  devguard-scanner attest predicate.json ghcr.io/org/image:tag --predicateType https://cyclonedx.org/vex/1.0

  # Upload a SARIF report
  devguard-scanner sarif results.sarif.json`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// init the logger - get the level
		level, err := cmd.Flags().GetString("logLevel")
		if err != nil {
			return err
		}

		switch level {
		case "debug":
			initLogger(slog.LevelDebug)
		case "info":
			initLogger(slog.LevelInfo)
		case "warn":
			initLogger(slog.LevelWarn)
		case "error":
			initLogger(slog.LevelError)
		default:
			initLogger(slog.LevelInfo)
		}

		if utils.RunsInCI() {
			slog.Debug("Running in CI")
			err := utils.GitLister.MarkAllPathsAsSafe()
			if err != nil {
				slog.Debug("could not mark all paths as safe", "err", err)
			}
		}

		err = initializeConfig(cmd)
		if err != nil {
			return err
		}

		return nil
	},
}

func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Add version details command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("DevGuard Scanner\n")
			fmt.Printf("Version:    %s\n", version)
			fmt.Printf("Commit:     %s\n", commit)
			fmt.Printf("Built:      %s\n", date)
			fmt.Printf("Built by:   %s\n", builtBy)
		},
	}

	RootCmd.AddCommand(
		versionCmd,
		NewSCACommand(),
		NewContainerScanningCommand(),
		NewCleanCommand(),
		NewAttestCommand(),
		NewInspectCommand(),
		NewSignCommand(),
		NewSecretScanningCommand(),
		NewSastCommand(),
		intotocmd.NewInTotoCommand(),
		NewLoginCommand(),
		NewIaCCommand(),
		NewSarifCommand(),
		newKyvernoSarifCommand(),
		newSarifMarkdownCommand(),
		NewSlugCommand(),
		NewSbomCommand(),
		NewGetCommand(),
		NewCurlCommand(),
		NewMergeSBOMSCommand(),
		NewDiscoverBaseImageAttestationsCommand(),
		NewVexCommand(),
		NewGenerateTagCommand(),
		NewAttestationCommand(),
		NewPURLInspectCommand(),
	)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	RootCmd.PersistentFlags().StringP("logLevel", "l", "info", "Set the log level. Options: debug, info, warn, error")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// InitLogger initializes the logger with a tint handler.
// tint is a simple logging library that allows to add colors to the log output.
// this is obviously not required, but it makes the logs easier to read.
func initLogger(level slog.Leveler) {
	// slog.HandlerOptions
	w := os.Stderr

	// set global logger with custom options
	slog.SetDefault(slog.New(
		tint.NewHandler(w, &tint.Options{
			Level:      level,
			TimeFormat: time.Kitchen,
			AddSource:  true,
		}),
	))
}

func initializeConfig(cmd *cobra.Command) error {
	// Set the base name of the config file, without the file extension.
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName(defaultConfigFilename)
	}

	// Set as many paths as you like where viper should look for the
	// config file. We are only looking in the current working directory.
	viper.AddConfigPath(".")

	viper.AddConfigPath("/etc/devguard/")
	// Attempt to read the config file, gracefully ignoring errors
	// caused by a config file not being found. Return an error
	// if we cannot parse the config file.
	if err := viper.ReadInConfig(); err != nil {
		// It's okay if there isn't a config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		} else {
			slog.Debug("no config file found")
		}
	}

	viper.SetEnvPrefix("DEVGUARD")
	// Environment variables can't have dashes in them, so bind them to their equivalent
	// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Bind to environment variables
	// Works great for simple config names, but needs help for names
	// like --favorite-color which we fix in the bindFlags function
	viper.AutomaticEnv()

	// Bind the current command's flags to viper
	bindFlags(cmd)

	config.ParseBaseConfig(cmd.Use)
	return nil
}

// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command) {

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		configName := f.Name
		// If using camelCase in the config file, replace hyphens with a camelCased string.
		// Since viper does case-insensitive comparisons, we don't need to bother fixing the case, and only need to remove the hyphens.
		// configName := strings.ReplaceAll(f.Name, "-", "")

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(configName) {
			val := viper.Get(configName)
			cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)) // nolint: errcheck
		}

		// Bind the flag to viper
		if err := viper.BindPFlag(configName, f); err != nil {
			slog.Error("could not bind flag to viper", "err", err)
		}
	})
}
