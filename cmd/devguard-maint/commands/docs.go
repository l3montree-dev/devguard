package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var DocsCmd = &cobra.Command{
	Use:   "docs [output-dir]",
	Short: "Generate markdown documentation for devguard-scanner into output-dir (default: docs/scanner)",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runDocs,
}

func runDocs(_ *cobra.Command, args []string) error {
	outDir := "docs/scanner"
	if len(args) == 1 {
		outDir = args[0]
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	identity := func(s string) string { return s }

	rootFilename := filepath.Join(outDir, "devguard-scanner.md")
	rootFile, err := os.Create(rootFilename)
	if err != nil {
		return err
	}
	if err := doc.GenMarkdownCustom(commands.RootCmd, rootFile, identity); err != nil {
		rootFile.Close()
		return err
	}
	rootFile.Close()
	postProcessMarkdown(rootFilename)

	for _, cmd := range commands.RootCmd.Commands() {
		if cmd.Hidden {
			continue
		}
		generateDocsForCommand(cmd, outDir)
	}

	slog.Info("docs generated", "dir", outDir)
	return nil
}

func generateDocsForCommand(cmd *cobra.Command, outDir string) {
	identity := func(s string) string { return s }
	emptyStr := func(s string) string { return "" }

	_ = doc.GenMarkdownCustom(cmd, os.Stdout, emptyStr)

	filename := filepath.Join(outDir, cmd.Name()+".md")
	f, err := os.Create(filename)
	if err != nil {
		slog.Error("could not create file", "err", err, "file", filename)
		return
	}
	if err := doc.GenMarkdownCustom(cmd, f, identity); err != nil {
		slog.Error("could not write markdown", "err", err, "file", filename)
	}
	f.Close()
	postProcessMarkdown(filename)

	for _, subCmd := range cmd.Commands() {
		if subCmd.Hidden {
			continue
		}
		generateDocsForCommand(subCmd, outDir)
	}
}

func postProcessMarkdown(filename string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		slog.Error("could not read file for post-processing", "err", err, "file", filename)
		return
	}
	text := string(content)

	re := regexp.MustCompile(`(?m)^## devguard-scanner (.+)$`)
	text = re.ReplaceAllString(text, "## $1")

	seeAlsoRe := regexp.MustCompile(`(?s)\n### SEE ALSO\n.*$`)
	text = seeAlsoRe.ReplaceAllString(text, "")

	codeBlockRe := regexp.MustCompile("(?m)^```\n([ a-z])")
	text = codeBlockRe.ReplaceAllString(text, "```shell\n$1")

	if err := os.WriteFile(filename, []byte(text), 0o644); err != nil {
		slog.Error("could not write post-processed file", "err", err, "file", filename)
	}
}
