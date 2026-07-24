package commands

import (
	"fmt"
	"os"
	"path/filepath"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseDevguardCmd = &cobra.Command{
	Use:   "devguard <tag>",
	Short: "Tag and push the devguard backend only",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseDevguard,
}

// copyScannerDocs copies the generated devguard-scanner markdown docs into the
// sibling devguard-documentation repo, keeping the reference pages in sync.
func copyScannerDocs() error {
	const docsDocumentationDir = "devguard-documentation"
	if _, err := os.Stat(docsDocumentationDir); os.IsNotExist(err) {
		return fmt.Errorf("directory %q does not exist", docsDocumentationDir)
	}

	srcDir := filepath.Join("devguard", "docs", "scanner")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}

	dstDir := filepath.Join(docsDocumentationDir, "src", "pages", "reference", "scanner")
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".md" {
			continue
		}
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstDir, entry.Name())
		if err := i.CopyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func runReleaseDevguard(_ *cobra.Command, args []string) error {
	tag := args[0]
	if _, err := i.ValidateTag(tag); err != nil {
		return err
	}

	if _, err := os.Stat("devguard"); os.IsNotExist(err) {
		return fmt.Errorf("directory %q does not exist", "devguard")
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard", "CHANGELOG.md"), tag); err != nil {
		return err
	}

	exists, err := i.GitTagExists("devguard", tag)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tag %s already exists in devguard", tag)
	}

	if err := i.GitCheckoutMain("devguard"); err != nil {
		return fmt.Errorf("checkout main in devguard: %w", err)
	}
	clean, err := i.GitIsClean("devguard")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard is not clean")
	}

	fmt.Println("\nRunning `make docs` in devguard...")
	if err := i.RunCommand("devguard", "make", "docs"); err != nil {
		return fmt.Errorf("make docs failed in devguard: %w", err)
	}

	dirty, err := i.GitDirtyPaths("devguard", "docs")
	if err != nil {
		return err
	}
	if dirty != "" {
		fmt.Println("`make docs` produced changes in devguard/docs, committing them:")
		fmt.Println(dirty)
		if err := i.GitAdd("devguard", "docs"); err != nil {
			return fmt.Errorf("git add docs in devguard: %w", err)
		}
		if err := i.GitCommit("devguard", "docs: regenerate for "+tag); err != nil {
			return fmt.Errorf("commit regenerated docs in devguard: %w", err)
		}
		if err := i.GitPush("devguard"); err != nil {
			return fmt.Errorf("push regenerated docs in devguard: %w", err)
		}
	}

	if err := copyScannerDocs(); err != nil {
		return fmt.Errorf("copy scanner docs to devguard-documentation: %w", err)
	}

	docDirty, err := i.GitDirtyPaths("devguard-documentation", "src/pages/reference/scanner")
	if err != nil {
		return err
	}
	if docDirty != "" {
		fmt.Println("Copied scanner docs produced changes in devguard-documentation, committing them:")
		fmt.Println(docDirty)
		if err := i.GitAdd("devguard-documentation", "src/pages/reference/scanner"); err != nil {
			return fmt.Errorf("git add scanner docs in devguard-documentation: %w", err)
		}
		if err := i.GitCommit("devguard-documentation", "docs: regenerate scanner reference for "+tag); err != nil {
			return fmt.Errorf("commit scanner docs in devguard-documentation: %w", err)
		}
		if err := i.GitPush("devguard-documentation"); err != nil {
			return fmt.Errorf("push scanner docs in devguard-documentation: %w", err)
		}
		fmt.Println("✓ Committed and pushed scanner docs in devguard-documentation")
	} else {
		fmt.Println("✓ Scanner docs in devguard-documentation already up to date")
	}

	fmt.Printf("\nTagging devguard with %s\n", tag)
	if !i.Confirm("Continue with tagging?") {
		fmt.Println("Operation cancelled.")
		return nil
	}

	cl := &i.Changelog{}

	if err := i.GitTagSigned("devguard", tag); err != nil {
		cl.Fail("Failed to tag devguard: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	if err := i.GitPush("devguard"); err != nil {
		cl.Fail("Failed to push devguard: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags("devguard")
	cl.Change("Tagged devguard with " + tag + " and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	fmt.Println("\n✓ Script completed successfully!")
	fmt.Printf("\nTo release the web frontend at the same tag, run:\n  devguard-maint release web %s\n", tag)
	return nil
}
