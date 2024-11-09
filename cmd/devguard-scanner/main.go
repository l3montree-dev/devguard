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
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "devguard-scanner",
	Short: "Vulnerability management for devs.",
	Long:  `Devguard-Scanner is a tool to identify vulnerabilities and flaws in a software. It communicates the result to a devguard instance.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(
		commands.NewHealthCheckCommand(),
		commands.NewSCACommand(),
		commands.NewContainerScanningCommand(),
		commands.NewSignCommand(),
	)

}

func main() {
	Execute()
}
