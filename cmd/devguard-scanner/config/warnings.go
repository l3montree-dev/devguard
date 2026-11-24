// Copyright (C) 2025 l3montree GmbH
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
package config

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type warning struct {
	title  string
	detail string
}

// collected during the run and printed once at the end, so they are not buried in the scan output
var warnings []warning

func AddWarning(title, detail string) {
	for _, w := range warnings {
		if w.title == title {
			return
		}
	}
	warnings = append(warnings, warning{title: title, detail: detail})
}

func PrintWarnings() {
	for _, w := range warnings {
		printBox(text.FgYellow, "WARNING: "+w.title, w.detail)
	}
}

func PrintError(err error) {
	printBox(text.FgRed, "ERROR", err.Error())
}

func printBox(color text.Color, title, detail string) {
	style := table.StyleBold
	style.Color.Border = text.Colors{color, text.Bold}
	style.Box.PaddingLeft = "  "
	style.Box.PaddingRight = "  "

	tw := table.NewWriter()
	tw.SetStyle(style)
	tw.SetColumnConfigs([]table.ColumnConfig{{Number: 1, WidthMax: 100, WidthMaxEnforcer: text.WrapSoft}})
	tw.AppendRow(table.Row{text.Colors{color, text.Bold}.Sprint(title)})
	tw.AppendRow(table.Row{color.Sprint(detail)})
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, tw.Render())
}
