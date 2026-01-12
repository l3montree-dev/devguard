package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// Copyright (C) 2026 l3montree GmbH
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

// postProcessMarkdown removes "devguard-scanner " prefix from headlines and SEE ALSO section
func postProcessMarkdown(filename string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		slog.Error("could not read file for post-processing", "err", err, "file", filename)
		return
	}

	text := string(content)

	// Remove "devguard-scanner " prefix from the main headline
	// Match: ## devguard-scanner <command>
	re := regexp.MustCompile(`(?m)^## devguard-scanner (.+)$`)
	text = re.ReplaceAllString(text, "## $1")

	// Remove SEE ALSO section entirely (it's always the same and not useful)
	// Match from "### SEE ALSO" to the end of file
	seeAlsoRe := regexp.MustCompile(`(?s)\n### SEE ALSO\n.*$`)
	text = seeAlsoRe.ReplaceAllString(text, "")

	// Add shell syntax highlighting to all code blocks
	// Match opening code fence: ``` followed by newline and content (space or lowercase letter)
	// This matches opening fences but not closing ones (which are followed by ### or end of content)
	codeBlockRe := regexp.MustCompile("(?m)^```\n([ a-z])")
	text = codeBlockRe.ReplaceAllString(text, "```shell\n$1")

	// Write back
	err = os.WriteFile(filename, []byte(text), 0644)
	if err != nil {
		slog.Error("could not write post-processed file", "err", err, "file", filename)
	}
}

// generateDocsForCommand recursively generates docs for a command and all its subcommands
func generateDocsForCommand(cmd *cobra.Command, outDir string) {
	identity := func(s string) string { return s }
	emptyStr := func(s string) string { return "" }

	// Print to stdout first
	err := doc.GenMarkdownCustom(cmd, os.Stdout, emptyStr)
	if err != nil {
		slog.Error("could not generate markdown documentation", "err", err, "cmd", cmd.Name())
		return
	}

	// Generate markdown for this command
	filename := filepath.Join(outDir, cmd.Name()+".md")
	f, err := os.Create(filename)
	if err != nil {
		slog.Error("could not create file", "err", err, "file", filename)
		return
	}

	err = doc.GenMarkdownCustom(cmd, f, identity)
	f.Close()
	if err != nil {
		slog.Error("could not write markdown", "err", err, "file", filename)
		return
	}

	// Post-process the file
	postProcessMarkdown(filename)

	// Recursively generate docs for subcommands
	for _, subCmd := range cmd.Commands() {
		// Skip hidden commands
		if subCmd.Hidden {
			continue
		}
		generateDocsForCommand(subCmd, outDir)
	}
}

func main() {
	// check if no arguments were provided
	if len(os.Args) < 2 {

		if err := os.Mkdir("docs/scanner", 0755); err != nil && !os.IsExist(err) {
			slog.Error("could not create docs/scanner directory", "err", err)
			return
		}

		// Generate root command doc first
		identity := func(s string) string { return s }
		rootFilename := filepath.Join("docs/scanner", "devguard-scanner.md")
		rootFile, err := os.Create(rootFilename)
		if err != nil {
			slog.Error("could not create root file", "err", err)
		} else {
			err = doc.GenMarkdownCustom(commands.RootCmd, rootFile, identity)
			rootFile.Close()
			if err != nil {
				slog.Error("could not write root markdown", "err", err)
			} else {
				postProcessMarkdown(rootFilename)
			}
		}

		// Generate docs for all commands (including nested subcommands)
		for _, cmd := range commands.RootCmd.Commands() {
			// Skip hidden commands
			if cmd.Hidden {
				continue
			}
			generateDocsForCommand(cmd, "docs/scanner")
		}

		return
	}
}
