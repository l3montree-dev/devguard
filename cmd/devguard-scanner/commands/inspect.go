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
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/spf13/cobra"
)

func inspectCmd(cmd *cobra.Command, args []string) {
	// get the key from the args
	key := args[0]

	_, pubKey, err := pat.HexTokenToECDSA(key)
	if err != nil {
		slog.Error("could not parse key", "err", err)
		os.Exit(1)
	}

	fmt.Println("PUBLIC KEY:")
	fmt.Printf("%s%s\n", hex.EncodeToString(pubKey.X.Bytes()), hex.EncodeToString(pubKey.Y.Bytes()))
}

func NewInspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a file or directory",
		Long:  `Inspect a file or directory for vulnerabilities`,
		Args:  cobra.ExactArgs(1),
		Run:   inspectCmd,
	}
}
