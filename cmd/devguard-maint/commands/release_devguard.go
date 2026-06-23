package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseDevguardCmd = &cobra.Command{
	Use:   "devguard <tag>",
	Short: "Tag and push devguard + devguard-web (bumps package.json version)",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseDevguard,
}

func runReleaseDevguard(_ *cobra.Command, args []string) error {
	tag := args[0]
	semver, err := i.ValidateTag(tag)
	if err != nil {
		return err
	}

	dirs := []string{"devguard", "devguard-web"}
	for _, d := range dirs {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", d)
		}
	}

	for _, d := range dirs {
		exists, err := i.GitTagExists(d, tag)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("tag %s already exists in %s", tag, d)
		}
	}

	for _, d := range dirs {
		if err := i.GitCheckoutMain(d); err != nil {
			return fmt.Errorf("checkout main in %s: %w", d, err)
		}
		clean, err := i.GitIsClean(d)
		if err != nil {
			return err
		}
		if !clean {
			return fmt.Errorf("working directory %s is not clean", d)
		}
	}

	pkgJSON := filepath.Join("devguard-web", "package.json")
	versionRe := regexp.MustCompile(`"version":\s*"[^"]*"`)
	data, err := os.ReadFile(pkgJSON)
	if err != nil {
		return fmt.Errorf("read %s: %w", pkgJSON, err)
	}
	bumped := versionRe.ReplaceAll(data, []byte(`"version": "`+semver+`"`))
	if err := os.WriteFile(pkgJSON, bumped, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", pkgJSON, err)
	}

	fmt.Printf("\n╔═════════════════════════════════════════╗\n")
	fmt.Printf("║  TAGGING SUMMARY - READY FOR APPROVAL   ║\n")
	fmt.Printf("╚═════════════════════════════════════════╝\n\n")
	fmt.Printf("Tag: %s\n", tag)
	fmt.Printf("Directories to tag:\n")
	for _, d := range dirs {
		fmt.Printf("  • %s\n", d)
	}
	fmt.Printf("\npackage.json version bumped to %s (uncommitted — will commit on confirm)\n\n", semver)

	if !i.Confirm("Continue with tagging?") {
		_ = i.GitRun("devguard-web", "checkout", "--", "package.json")
		fmt.Println("Operation cancelled.")
		return nil
	}

	cl := &i.Changelog{}

	if err := i.GitAdd("devguard-web", "package.json"); err != nil {
		return err
	}
	if err := i.GitCommit("devguard-web", "chore: bump version to "+semver); err != nil {
		return err
	}
	cl.Change("Committed devguard-web/package.json version bump to " + semver)

	for _, d := range dirs {
		if err := i.GitTagSigned(d, tag); err != nil {
			cl.Fail("Failed to tag " + d + ": " + err.Error())
			continue
		}
		if err := i.GitPush(d); err != nil {
			cl.Fail("Failed to push " + d + ": " + err.Error())
			continue
		}
		i.GitPushTags(d)
		cl.Change("Tagged " + d + " with " + tag + " and pushed")
	}

	cl.PrintSummary("FINAL SUMMARY")
	if cl.HasErrors() {
		return fmt.Errorf("completed with errors")
	}
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}
