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

package main

import (
	"log/slog"
	"os"

	"github.com/l3montree-dev/flawfix/cmd/flawfix-cli/commands"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "flawfix",
	Short: "Vulnerability management for devs.",
	Long:  `Flawfix is a tool to manage vulnerabilities and other flaws in your software.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	err := core.LoadConfig()
	if err != nil {
		slog.Error("could not initialize config", "err", err)
		os.Exit(1)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	detectCmd := commands.DetectCommand()
	loginCmd := commands.LoginCommand()
	rootCmd.AddCommand(detectCmd)
	rootCmd.AddCommand(loginCmd)
}

func main() {
	Execute()
}
