package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	i "github.com/l3montree-dev/devguard/cmd/devguard-maint/internal"
	"github.com/spf13/cobra"
)

var ReleaseWebCmd = &cobra.Command{
	Use:   "web <tag>",
	Short: "Bump package.json, tag, and push devguard-web only",
	Args:  cobra.ExactArgs(1),
	RunE:  runReleaseWeb,
}

func runReleaseWeb(_ *cobra.Command, args []string) error {
	tag := args[0]
	semver, err := i.ValidateTag(tag)
	if err != nil {
		return err
	}

	for _, d := range []string{"devguard-web", "devguard"} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			return fmt.Errorf("directory %q does not exist", d)
		}
	}

	if err := i.CheckChangelogEntry(filepath.Join("devguard-web", "CHANGELOG.md"), tag); err != nil {
		return err
	}

	exists, err := i.GitTagExists("devguard-web", tag)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("tag %s already exists in devguard-web", tag)
	}

	if err := i.GitCheckoutMain("devguard-web"); err != nil {
		return fmt.Errorf("checkout main in devguard-web: %w", err)
	}
	clean, err := i.GitIsClean("devguard-web")
	if err != nil {
		return err
	}
	if !clean {
		return fmt.Errorf("working directory devguard-web is not clean")
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

	fmt.Printf("\npackage.json bumped to %s (uncommitted — will commit on confirm)\n", semver)
	fmt.Printf("Tag: %s → devguard-web\n\n", tag)

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

	if err := i.GitTagSigned("devguard-web", tag); err != nil {
		cl.Fail("Failed to tag devguard-web: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	if err := i.GitPush("devguard-web"); err != nil {
		cl.Fail("Failed to push devguard-web: " + err.Error())
		cl.PrintSummary("FINAL SUMMARY")
		return fmt.Errorf("completed with errors")
	}
	i.GitPushTags("devguard-web")
	cl.Change("Tagged devguard-web with " + tag + " and pushed")

	cl.PrintSummary("FINAL SUMMARY")
	fmt.Println("\n✓ Script completed successfully!")
	return nil
}
