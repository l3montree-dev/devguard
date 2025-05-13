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
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/lmittmann/tint"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var cfgFile string

const (
	defaultConfigFilename = ".devguard"
)

var rootCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "devguard-scanner",
	Short:        "Secure your Software Supply Chain",
	Long: `Secure your Software Supply Chain
	
Attestation-based compliance as Code, 
manage your CVEs seamlessly, 
Integrate your Vulnerability Scanners,
Security Framework Documentation made easy - 
OWASP Incubating Project`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// init the logger - get the level
		level, err := cmd.Flags().GetString("log-level")
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

		err = initializeConfig(cmd)
		if err != nil {
			return err
		}

		if utils.RunsInCI() {
			slog.Info("Running in CI")
			return utils.GitLister.MarkAllPathsAsSafe()
		}

		return nil
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(
		NewSCACommand(),
		NewContainerScanningCommand(),
		NewAttestCommand(),
		NewInspectCommand(),
		NewSignCommand(),
		NewSecretScanningCommand(),
		NewSastCommand(),
		intotocmd.NewInTotoCommand(),
		NewLoginCommand(),
		NewIaCCommand(),
		NewSarifCommand(),
		NewGetCommand(),
		NewSbomCommand(),
	)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "Set the log level. Options are: debug, info, warn, error")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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

	config.ParseBaseConfig()
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
