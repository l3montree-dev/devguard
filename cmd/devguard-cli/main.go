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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

package main

import (
	"log/slog"
	"os"

	"github.com/l3montree-dev/devguard/cmd/devguard-cli/commands"
	"github.com/l3montree-dev/devguard/shared"
)

func Execute() {
	err := commands.GetRootCmd().Execute()
	if err != nil {
		slog.Error("Error executing command", "err", err)
		os.Exit(1)
	}
}

func init() {
	commands.GetRootCmd().AddCommand(commands.NewVulndbCommand())
	commands.GetRootCmd().AddCommand(commands.NewDaemonCommand())
	commands.GetRootCmd().AddCommand(commands.NewLicensesCommand())
	commands.GetRootCmd().AddCommand(commands.NewMigrateCommand())
	commands.GetRootCmd().AddCommand(commands.NewSBOMCommand())
}

func main() {
	shared.InitLogger()
	Execute()
}
