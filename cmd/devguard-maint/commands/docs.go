package commands

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"gopkg.in/yaml.v3"
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

	if err := prependFrontmatter(rootFilename, commands.RootCmd); err != nil {
		return err
	}

	for _, cmd := range commands.RootCmd.Commands() {
		if cmd.Hidden {
			continue
		}
		generateDocsForCommand(cmd, outDir)
	}

	slog.Info("docs generated", "dir", outDir)
	return nil
}

func frontmatter(cmd *cobra.Command) string {
	var output, title, description, keywordPrimary string
	if v, ok := cmd.Annotations["title"]; ok {
		title = v
	} else {
		title = cmd.Short
	}
	if v, ok := cmd.Annotations["description"]; ok {
		description = v
	} else {
		description = cmd.Long
	}
	if v, ok := cmd.Annotations["keyword_primary"]; ok {
		keywordPrimary = v
	} else {
		keywordPrimary = cmd.CommandPath()
	}
	data := struct {
		Title       string `yaml:"title"`
		Description string `yaml:"description"`
		SEO         struct {
			Robots string `yaml:"robots"`
			OG     struct {
				Image string `yaml:"image"`
				Type  string `yaml:"type"`
			} `yaml:"og"`
			Schema struct {
				Type string `yaml:"type"`
			} `yaml:"schema"`
			KeywordPrimary string `yaml:"keyword_primary"`
		} `yaml:"seo"`
		Lang         string `yaml:"lang"`
		IgnoreChecks any    `yaml:"ignoreChecks"`
	}{
		Title:       strings.Join(strings.Fields(title), " "),
		Description: strings.Join(strings.Fields(description), " "),
		Lang:        "en-US",
	}
	data.SEO.Robots = "index,follow"
	data.SEO.OG.Image = "/og-image.png"
	data.SEO.OG.Type = "article"
	data.SEO.Schema.Type = "TechArticle"
	data.SEO.KeywordPrimary = strings.Join(strings.Fields(keywordPrimary), " ")

	out, err := yaml.Marshal(data)
	if err != nil {
		return ""
	}
	output = "---\n" + string(out) + "---"

	return output
}

func prependFrontmatter(filename string, cmd *cobra.Command) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		slog.Error("could not read file", "err", err, "file", filename)
		return err
	}
	contentString := string(content)
	frontmatter := frontmatter(cmd)

	finalText := frontmatter + "\n\n" + contentString

	if err := os.WriteFile(filename, []byte(finalText), 0o644); err != nil {
		slog.Error("could not write frontMatter file", "err", err, "file", filename)
		return err
	}
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

	if err := prependFrontmatter(filename, cmd); err != nil {
		return
	}

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
